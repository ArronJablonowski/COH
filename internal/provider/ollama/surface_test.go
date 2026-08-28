package ollama

import (
	"reflect"
	"testing"
)

func TestFrozenNativeSurface(t *testing.T) {
	if AdapterVersion != "1.1.0" || VendorSurfaceVersion != "ollama.native.chat/v2" ||
		OllamaEndpoint != "http://127.0.0.1:11434" || VersionPath != "/api/version" || TagsPath != "/api/tags" ||
		ShowPath != "/api/show" || ChatPath != "/api/chat" {
		t.Fatal("native Ollama surface drifted")
	}
	if got := EndpointIdentityDigest(OllamaEndpoint); got != "sha256:080c034a69b43147b95d2e4429814ebbfe26d3fbe9d07bc1e768c1a035c9ab2a" {
		t.Fatalf("endpoint digest=%s", got)
	}
}

func TestConfigExposesNoCredentialOrGenericVendorSurface(t *testing.T) {
	typeOfConfig := reflect.TypeOf(Config{})
	for index := 0; index < typeOfConfig.NumField(); index++ {
		switch typeOfConfig.Field(index).Name {
		case "Credential", "Credentials", "Authorization", "Headers", "Options", "Vendor", "Passthrough":
			t.Fatalf("config exports forbidden field %s", typeOfConfig.Field(index).Name)
		}
	}
}
