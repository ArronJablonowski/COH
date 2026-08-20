package architecture

import (
	"context"
	"testing"
)

func TestValidateWorkspaceManifestsAcceptsPinnedRoot(t *testing.T) {
	root := newWorkspace(t)
	snapshot, err := ValidateWorkspaceManifests(context.Background(), root)
	if err != nil {
		t.Fatalf("ValidateWorkspaceManifests() error = %v", err)
	}
	if len(snapshot.Files) != 2 || snapshot.Files[0].Digest == "" || snapshot.Files[1].Digest == "" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestValidateWorkspaceManifestsRejectsIdentityAndWorkspaceDrift(t *testing.T) {
	tests := []struct {
		fixture string
		target  string
		code    ErrorCode
	}{
		{fixture: "go-mod-wrong-module.txt", target: "go.mod", code: CodeDenied},
		{fixture: "go-mod-wrong-go.txt", target: "go.mod", code: CodeUnsupportedVersion},
		{fixture: "go-mod-wrong-toolchain.txt", target: "go.mod", code: CodeUnsupportedVersion},
		{fixture: "go-mod-replace.txt", target: "go.mod", code: CodeDenied},
		{fixture: "go-work-extra-use.txt", target: "go.work", code: CodeDenied},
		{fixture: "go-work-replace.txt", target: "go.work", code: CodeDenied},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			root := newWorkspace(t)
			writeTestFile(t, root, test.target, string(readFixture(t, "invalid", test.fixture)))
			_, err := ValidateWorkspaceManifests(context.Background(), root)
			assertErrorCode(t, err, test.code)
		})
	}
}
