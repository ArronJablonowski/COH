package workflow

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestRepositorySurfaceIsNarrowAndStorageNeutral(t *testing.T) {
	repository := reflect.TypeOf((*Repository)(nil)).Elem()
	want := []string{"ClaimOutbox", "Get", "Migrate", "MigrationStatus", "SettleOutbox", "Transact"}
	got := make([]string, 0, repository.NumMethod())
	for index := 0; index < repository.NumMethod(); index++ {
		method := repository.Method(index)
		got = append(got, method.Name)
		assertStorageNeutralType(t, method.Type, make(map[reflect.Type]bool))
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Repository methods = %v, want %v", got, want)
	}
}

func TestStorageTypesContainNoAuthorityOrExecutableSurface(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(Transaction{}), reflect.TypeOf(OutboxMessage{}),
		reflect.TypeOf(MigrationPlan{}), reflect.TypeOf(MetadataRecord{}),
	}
	for _, candidate := range types {
		assertStorageNeutralType(t, candidate, make(map[reflect.Type]bool))
	}
	for _, forbidden := range []string{"credential", "password", "secret", "sql", "query", "command", "callback", "policy", "approval", "executor"} {
		for _, candidate := range types {
			if strings.Contains(strings.ToLower(candidate.String()), forbidden) {
				t.Fatalf("storage type %s exposes forbidden concept %q", candidate, forbidden)
			}
			for index := 0; index < candidate.NumField(); index++ {
				if strings.Contains(strings.ToLower(candidate.Field(index).Name), forbidden) {
					t.Fatalf("storage field %s.%s exposes forbidden concept %q", candidate, candidate.Field(index).Name, forbidden)
				}
			}
		}
	}
}

func assertStorageNeutralType(t *testing.T, candidate reflect.Type, visited map[reflect.Type]bool) {
	t.Helper()
	if candidate == nil || visited[candidate] {
		return
	}
	visited[candidate] = true
	if path := candidate.PkgPath(); strings.Contains(path, "database/sql") || strings.Contains(path, "pgx") || strings.Contains(path, "sqlite") {
		t.Fatalf("storage surface leaks database-specific type %s", candidate)
	}
	switch candidate.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
		assertStorageNeutralType(t, candidate.Elem(), visited)
	case reflect.Map:
		assertStorageNeutralType(t, candidate.Key(), visited)
		assertStorageNeutralType(t, candidate.Elem(), visited)
	case reflect.Struct:
		for index := 0; index < candidate.NumField(); index++ {
			assertStorageNeutralType(t, candidate.Field(index).Type, visited)
		}
	case reflect.Func:
		for index := 0; index < candidate.NumIn(); index++ {
			assertStorageNeutralType(t, candidate.In(index), visited)
		}
		for index := 0; index < candidate.NumOut(); index++ {
			assertStorageNeutralType(t, candidate.Out(index), visited)
		}
	case reflect.Interface:
		for index := 0; index < candidate.NumMethod(); index++ {
			assertStorageNeutralType(t, candidate.Method(index).Type, visited)
		}
	}
}

var _ Repository = (*guardedStorage)(nil)
