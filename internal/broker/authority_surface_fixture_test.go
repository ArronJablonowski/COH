package broker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrokerSurfaceScanner(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		files   map[string]string
		wantBad bool
	}{
		{
			name: "safe private dependency and blank import",
			files: map[string]string{"broker.go": `package broker
import (
	_ "github.com/ArronJablonowski/COH/internal/policy"
	conn "github.com/ArronJablonowski/COH/internal/connector"
)
type Safe struct { gateway conn.Gateway }
func newSafe(gateway conn.Gateway) *Safe { return &Safe{gateway: gateway} }
`},
		},
		{
			name: "parameter name does not resolve as package type",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
func Safe(gateway int) int { return gateway }
`},
		},
		{
			name: "safe inferred call ignores private argument capability",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type Safe struct { gateway conn.Gateway }
func newSafe(gateway conn.Gateway) Safe { return Safe{gateway: gateway} }
var Default = newSafe(nil)
`},
		},
		{
			name: "aliased import",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
func Leak() conn.Gateway { return nil }
`},
			wantBad: true,
		},
		{
			name: "hidden transitive alias",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
type hidden = gateway
func Leak() hidden { return nil }
`},
			wantBad: true,
		},
		{
			name: "hidden named type",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway conn.Gateway
func Leak() gateway { panic("not implemented") }
`},
			wantBad: true,
		},
		{
			name: "hidden interface",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type hidden interface { Gateway() conn.Gateway }
func Leak() hidden { return nil }
`},
			wantBad: true,
		},
		{
			name: "exported field through hidden result",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type hidden struct { Gateway conn.Gateway }
func Leak() hidden { return hidden{} }
`},
			wantBad: true,
		},
		{
			name: "inferred private field selection",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type safe struct { gateway conn.Gateway; Count int }
var holder safe
var Leak = holder.gateway
`},
			wantBad: true,
		},
		{
			name: "inferred safe field selection",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type safe struct { gateway conn.Gateway; Count int }
var holder safe
var Count = holder.Count
`},
		},
		{
			name: "multi-hop private field selection",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type inner struct { gateway conn.Gateway }
type outer struct { child inner }
var holders []outer
var Leak = holders[0].child.gateway
`},
			wantBad: true,
		},
		{
			name: "generic field substitution",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
type box[T any] struct { value T }
var holder box[gateway]
var Leak = holder.value
`},
			wantBad: true,
		},
		{
			name: "generic receiver method substitution",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
type box[T any] struct{}
func (box[T]) get() T { panic("not implemented") }
var holder box[gateway]
var Leak = holder.get()
`},
			wantBad: true,
		},
		{
			name: "exported method through hidden result",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type hidden struct{}
func (hidden) Gateway() conn.Gateway { return nil }
func Leak() hidden { return hidden{} }
`},
			wantBad: true,
		},
		{
			name: "inferred selected method function",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type safe struct{}
func (*safe) makeGateway() conn.Gateway { return nil }
var Leak = (*safe).makeGateway
`},
			wantBad: true,
		},
		{
			name: "inferred exported value",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
var hidden gateway
var Leak = hidden
`},
			wantBad: true,
		},
		{
			name: "inferred exported function value",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
func makeGateway() conn.Gateway { return nil }
var Leak = makeGateway
`},
			wantBad: true,
		},
		{
			name: "inferred exported call result",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
func makeGateway() conn.Gateway { return nil }
var Leak = makeGateway()
`},
			wantBad: true,
		},
		{
			name: "inferred exported method call result",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type factory struct{}
func (factory) makeGateway() conn.Gateway { return nil }
var worker factory
var Leak = worker.makeGateway()
`},
			wantBad: true,
		},
		{
			name: "builtin new derives sensitive result",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
var Leak = new(gateway)
`},
			wantBad: true,
		},
		{
			name: "builtin make derives sensitive result",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
var Leak = make([]gateway, 1)
`},
			wantBad: true,
		},
		{
			name: "generic result substitution",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
func id[T any](value T) T { return value }
var Leak = id[gateway](nil)
`},
			wantBad: true,
		},
		{
			name: "generic inferred result substitution",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
var hidden gateway
func id[T any](value T) T { return value }
var Leak = id(hidden)
`},
			wantBad: true,
		},
		{
			name: "generic input does not taint scalar result",
			files: map[string]string{"broker.go": `package broker
import conn "github.com/ArronJablonowski/COH/internal/connector"
type gateway = conn.Gateway
func valid[T any](value T) bool { return value != nil }
var Safe = valid[gateway](nil)
`},
		},
		{
			name: "unresolved imported generic fails closed",
			files: map[string]string{"broker.go": `package broker
import (
	"slices"
	conn "github.com/ArronJablonowski/COH/internal/connector"
)
type gateway = conn.Gateway
var hidden []gateway
var Leak = slices.Clone(hidden)
`},
			wantBad: true,
		},
		{
			name: "generic constraint",
			files: map[string]string{"broker.go": `package broker
import pol "github.com/ArronJablonowski/COH/internal/policy"
type Leak[T pol.Decision] struct { Value T }
`},
			wantBad: true,
		},
		{
			name: "sensitive dot import",
			files: map[string]string{"broker.go": `package broker
import . "github.com/ArronJablonowski/COH/internal/connector"
var _ Gateway
`},
			wantBad: true,
		},
		{
			name: "structural connector interface",
			files: map[string]string{"broker.go": `package broker
import (
	"context"
	"github.com/ArronJablonowski/COH/internal/domain"
)
type Leak interface {
	Dispatch(context.Context, domain.ToolIntent) (domain.ActionReceipt, error)
}
`},
			wantBad: true,
		},
		{
			name: "structural policy method",
			files: map[string]string{"broker.go": `package broker
type safe struct{}
func (safe) Evaluate(value int) bool { return value > 0 }
func New() safe { return safe{} }
`},
			wantBad: true,
		},
		{
			name: "nested broker package",
			files: map[string]string{"nested/broker.go": `package nested
import conn "github.com/ArronJablonowski/COH/internal/connector"
type Leak = conn.Gateway
`},
			wantBad: true,
		},
		{
			name: "testdata broker package is still scanned",
			files: map[string]string{"testdata/nested/broker.go": `package nested
import conn "github.com/ArronJablonowski/COH/internal/connector"
type Leak = conn.Gateway
`},
			wantBad: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			for name, content := range test.files {
				filePath := filepath.Join(root, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
					t.Fatalf("MkdirAll(): %v", err)
				}
				if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
					t.Fatalf("WriteFile(): %v", err)
				}
			}
			violations, err := scanBrokerPublicSurface(root)
			if err != nil {
				t.Fatalf("scanBrokerPublicSurface(): %v", err)
			}
			if gotBad := len(violations) != 0; gotBad != test.wantBad {
				t.Fatalf("violations = %s, wantBad = %t", strings.Join(violations, "; "), test.wantBad)
			}
		})
	}
}

func TestBrokerSurfaceScannerRejectsSymlinks(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"non-Go file", "directory"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			targetRoot := t.TempDir()
			target := filepath.Join(targetRoot, "target")
			link := filepath.Join(root, "note.txt")
			if name == "directory" {
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatalf("Mkdir(): %v", err)
				}
				link = filepath.Join(root, "nested")
			} else if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
				t.Fatalf("WriteFile(): %v", err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			if _, err := scanBrokerPublicSurface(root); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("scan error = %v, want symlink denial", err)
			}
		})
	}
}
