package pairing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareOversizedPendingNeverRetainsCredentials(t *testing.T) {
	client, offer := fixture(t)
	offer.RootIdentity = ""
	encoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	offer.RootIdentity = strings.Repeat("r", MaxDocumentSize-len(encoded))
	trusted := trustedOffer(t, client, offer)
	for attempt := 1; attempt <= 2; attempt++ {
		intent, err := client.Prepare(context.Background(), "work", trusted)
		if err == nil || intent != (EnrollmentIntent{}) {
			t.Fatalf("attempt %d exported refused authority: %v", attempt, err)
		}
		if _, err := os.Stat(filepath.Join(client.Root, "pairings", "work", "intent.json")); !os.IsNotExist(err) {
			t.Fatalf("attempt %d retained an intent: %v", attempt, err)
		}
		if _, err := os.Stat(client.Root); !os.IsNotExist(err) {
			t.Fatalf("attempt %d published preparation state for oversized record: %v", attempt, err)
		}
		keys, err := filepath.Glob(filepath.Join(client.Root, "credentials", "*", "id_ed25519"))
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 0 {
			t.Errorf("attempt %d retained %d unreferenced credentials", attempt, len(keys))
		}
	}
}
