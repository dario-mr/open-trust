package subject

import (
	"context"
	"testing"
	"time"
)

// A certificate attached to the image manifest is found from the index digest a buyer pulls, and
// the newest of several comes first.
func TestAttachAndFindCertificates(t *testing.T) {
	ctx := context.Background()
	repo, idx, img := push(t)
	if found, err := FindCertificates(ctx, repo+"@"+idx); err != nil || len(found) != 0 {
		t.Fatalf("before attaching: %v, %v", found, err)
	}
	first, err := Attach(ctx, repo+"@"+idx, img, []byte(`{"cert":1}`), map[string]string{"dev.open-trust.result": "FAILED"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // created has second resolution
	second, err := Attach(ctx, repo+"@"+idx, img, []byte(`{"cert":2}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{repo + "@" + idx, repo + "@" + img} {
		found, err := FindCertificates(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 2 || found[0].Digest != second || string(found[0].Bundle) != `{"cert":2}` || found[1].Digest != first {
			t.Fatalf("%s: %+v", ref, found)
		}
	}
	if _, err := FindCertificates(ctx, repo+":v1"); err == nil {
		t.Fatal("a tag must be refused")
	}
}
