package verify

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// testdata/revocations.sigstore.json: the real list signed by revocations.yml (empty, valid until 2026-11-30T16:23:33Z).
func publicGood() (root.TrustedMaterial, error) {
	return root.NewTrustedRootFromPath("testdata/public-good-trusted-root.json")
}

var signedAt = time.Date(2026, 11, 16, 17, 0, 0, 0, time.UTC)

func TestSignedRevocationList(t *testing.T) {
	rl, note, err := loadRevocations("testdata/revocations.sigstore.json", publicGood, signedAt)
	if err != nil || rl == nil || !strings.Contains(note, "signed Open Trust list") {
		t.Fatalf("published list must verify: %v %q", err, note)
	}
}

func TestStaleSignedRevocationListIsRefused(t *testing.T) {
	b, _ := os.ReadFile("testdata/revocations.sigstore.json")
	if _, _, err := signedRevocations(b, publicGood, signedAt.AddDate(0, 0, 15)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an old copy must not be accepted: %v", err)
	}
}

func TestRevocationListFromAnotherSignerIsRefused(t *testing.T) {
	// a validly signed bundle, but not from revocations.yml on main
	b, _ := os.ReadFile("testdata/autogov-vsa.sigstore.json")
	if _, _, err := signedRevocations(b, publicGood, signedAt); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("only the Open Trust list signer is accepted: %v", err)
	}
}

func TestTamperedRevocationListIsRefused(t *testing.T) {
	b, _ := os.ReadFile("testdata/revocations.sigstore.json")
	// the payload is base64 in the bundle; swap one character of it
	i := bytes.Index(b, []byte(`"payload":"`)) + len(`"payload":"`) + 40
	b[i] ^= 1
	if _, _, err := signedRevocations(b, publicGood, signedAt); err == nil {
		t.Fatal("a tampered list must not verify")
	}
}
