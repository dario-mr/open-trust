package signer

import (
	"context"
	"path/filepath"
	"testing"
)

func TestIsKMS(t *testing.T) {
	for ref, want := range map[string]bool{
		"hashivault://otrust": true, "awskms:///alias/otrust": true, "gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k": true,
		"azurekms://vault.vault.azure.net/otrust": true, "vendor.key": false, "./awskms/vendor.key": false, "/secrets/vendor.key": false,
	} {
		if got := IsKMS(ref); got != want {
			t.Errorf("IsKMS(%q) = %v", ref, got)
		}
	}
}

// A key file still loads through LoadSigner, and signs what its public key verifies.
func TestLoadSignerKeyFile(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "vendor")
	hint, err := GenerateKey(prefix)
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadSigner(context.Background(), prefix+".key")
	if err != nil || string(s.GetHint()) != hint {
		t.Fatalf("hint %q, err %v; want %q", s.GetHint(), err, hint)
	}
	if _, err := s.Sign(context.Background(), []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)); err != nil {
		t.Fatal(err)
	}
}
