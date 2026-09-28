package pairing

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/sshkey"
)

func TestPreparationChild(t *testing.T) {
	root := os.Getenv("BOX_TEST_PREPARATION_ROOT")
	if root == "" {
		return
	}
	data, err := os.ReadFile(os.Getenv("BOX_TEST_PREPARATION_OFFER"))
	if err != nil {
		t.Fatal(err)
	}
	var offer HostOffer
	if err := json.Unmarshal(data, &offer); err != nil {
		t.Fatal(err)
	}
	input := bufio.NewScanner(os.Stdin)
	client := Client{Root: root, Now: func() time.Time { return offer.Expires.Add(-time.Hour) }, checkpoint: func(stage string) error {
		fmt.Println(stage)
		if !input.Scan() {
			return errors.New("checkpoint input closed")
		}
		if input.Text() == "crash" {
			os.Exit(73)
		}
		return nil
	}}
	intent, err := client.Prepare(context.Background(), "work", trustedOffer(t, client, offer))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(intent); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

type preparationChild struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
}

func startPreparationChild(t *testing.T, client Client, offer HostOffer) preparationChild {
	t.Helper()
	path := filepath.Join(t.TempDir(), "offer.json")
	data, _ := json.Marshal(offer)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPreparationChild$")
	command.Env = append(os.Environ(), "BOX_TEST_PREPARATION_ROOT="+client.Root, "BOX_TEST_PREPARATION_OFFER="+path)
	command.Stderr = os.Stderr
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Logf("owned preparation child pid=%d parent=%d started=%s command=%s", command.Process.Pid, os.Getpid(), started.Format(time.RFC3339Nano), command.Path)
	t.Cleanup(func() { input.Close() })
	return preparationChild{command, input, bufio.NewScanner(output)}
}
func (child preparationChild) stage(t *testing.T, expected string) {
	t.Helper()
	if !child.output.Scan() || child.output.Text() != expected {
		t.Fatalf("checkpoint %s missing", expected)
	}
}
func (child preparationChild) advance(t *testing.T, input string) {
	t.Helper()
	if _, err := io.WriteString(child.input, input+"\n"); err != nil {
		t.Fatal(err)
	}
}
func (child preparationChild) result(t *testing.T) EnrollmentIntent {
	t.Helper()
	if !child.output.Scan() {
		t.Fatal("missing exported intent")
	}
	var intent EnrollmentIntent
	if err := json.Unmarshal(child.output.Bytes(), &intent); err != nil {
		t.Fatal(err)
	}
	if err := child.command.Wait(); err != nil {
		t.Fatal(err)
	}
	return intent
}
func credentialCount(t *testing.T, root string) int {
	t.Helper()
	keys, err := filepath.Glob(filepath.Join(root, "credentials", "*", "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	return len(keys)
}
func assertPreparationFiles(t *testing.T, client Client, intent EnrollmentIntent) {
	t.Helper()
	if credentialCount(t, client.Root) != 1 {
		t.Fatal("expected exactly one canonical global credential")
	}
	reservation, err := client.readPreparation("work")
	if err != nil || reservation.Intent.PairID != intent.PairID || reservation.Intent.OperationID != intent.OperationID {
		t.Fatalf("reservation ownership changed: %v", err)
	}
	durable, err := client.read("work")
	if err != nil || durable.Intent != intent {
		t.Fatalf("durable intent changed: %v", err)
	}
	if err := client.verifyCredential(context.Background(), durable); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(client.Root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), ".pending-") {
			t.Errorf("normal operation retained atomic temporary %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentPreparationProcessesAdoptWinner(t *testing.T) {
	client, offer := fixture(t)
	if credentialCount(t, client.Root) != 0 {
		t.Fatal("dirty initial credentials")
	}
	children := []preparationChild{startPreparationChild(t, client, offer), startPreparationChild(t, client, offer)}
	for _, stage := range []string{"reservation", "seed", "intent", "credential"} {
		for _, child := range children {
			child.stage(t, stage)
		}
		for _, child := range children {
			child.advance(t, "continue")
		}
	}
	first, second := children[0].result(t), children[1].result(t)
	if first != second {
		t.Fatal("concurrent callers exported different identities")
	}
	assertPreparationFiles(t, client, first)
}

func TestPreparationProcessInterruptionRetainsAuthorityWithoutSystemTemporaryCopies(t *testing.T) {
	for _, stop := range []string{"reservation", "seed", "intent", "credential"} {
		t.Run(stop, func(t *testing.T) {
			client, offer := fixture(t)
			if credentialCount(t, client.Root) != 0 {
				t.Fatal("dirty initial credentials")
			}
			child := startPreparationChild(t, client, offer)
			for _, stage := range []string{"reservation", "seed", "intent", "credential"} {
				child.stage(t, stage)
				if stage == stop {
					child.advance(t, "crash")
					break
				}
				child.advance(t, "continue")
			}
			err := child.command.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("child did not exit at checkpoint: %v", err)
			}
			reservation, err := client.readPreparation("work")
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			if stop == "credential" {
				count = 1
			}
			if credentialCount(t, client.Root) != count {
				t.Fatal("unexpected interrupted credential count")
			}
			var originalPublic string
			if stop != "reservation" {
				key, err := sshkey.Reserved(context.Background(), client.Root, seedPath("work"), false)
				if err != nil {
					t.Fatal(err)
				}
				originalPublic = key.PublicKey()
			}
			t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
			view, err := client.Inspect(context.Background(), "work")
			if err != nil || view.PairID != reservation.Intent.PairID {
				t.Fatalf("interrupted preparation undiscoverable: %v", err)
			}
			if stop != "credential" && view.Access != "preparation-pending" {
				t.Fatalf("unexpected recovery view %s", view.Access)
			}
			if credentialCount(t, client.Root) != count {
				t.Fatal("inspection mutated credentials")
			}
			intent, err := client.Prepare(context.Background(), "work", trustedOffer(t, client, offer))
			if err != nil {
				t.Fatal(err)
			}
			if intent.PairID != reservation.Intent.PairID || intent.OperationID != reservation.Intent.OperationID || originalPublic != "" && originalPublic != intent.PublicKey {
				t.Fatal("retry replaced original authority")
			}
			assertPreparationFiles(t, client, intent)
		})
	}
}

func TestPreparationPublicationFailureAndDurableReconciliation(t *testing.T) {
	for _, linkedError := range []bool{false, true} {
		t.Run(fmt.Sprint(linkedError), func(t *testing.T) {
			client, offer := fixture(t)
			trusted := trustedOffer(t, client, offer)
			client.publish = func(root, path string, data []byte, replace bool) error {
				if !linkedError && filepath.Base(path) == "intent.json" {
					return errors.New("injected intent publication failure")
				}
				if err := privatefile.Publish(root, path, data, replace); err != nil {
					return err
				}
				return errors.New("injected directory sync failure after publication")
			}
			first, err := client.Prepare(context.Background(), "work", trusted)
			if !linkedError && (err == nil || first != (EnrollmentIntent{}) || credentialCount(t, client.Root) != 0) {
				t.Fatal("failed intent publication exported or orphaned authority")
			}
			if linkedError && err != nil {
				t.Fatal(err)
			}
			reservation, err := client.readPreparation("work")
			if err != nil {
				t.Fatal(err)
			}
			key, err := sshkey.Reserved(context.Background(), client.Root, seedPath("work"), false)
			if err != nil {
				t.Fatal(err)
			}
			client.publish = nil
			intent, err := client.Prepare(context.Background(), "work", trusted)
			if err != nil {
				t.Fatal(err)
			}
			if intent.PairID != reservation.Intent.PairID || intent.PublicKey != key.PublicKey() {
				t.Fatal("failed publication retry replaced retained authority")
			}
			assertPreparationFiles(t, client, intent)
		})
	}
}

func TestPreparationExactPendingBoundAndConflictBeforeSecrets(t *testing.T) {
	client, offer := fixture(t)
	if _, err := sshkey.CanonicalPublicKey(preparationPublicKeyPlaceholder); err != nil {
		t.Fatal(err)
	}
	offer.RootIdentity = ""
	skeleton := pending{1, "work", offer, EnrollmentIntent{1, strings.Repeat("0", 32), strings.Repeat("0", 32), OfferDigest(offer), preparationPublicKeyPlaceholder, offer.Expires}}
	data, _ := json.Marshal(skeleton)
	offer.RootIdentity = strings.Repeat("r", MaxDocumentSize-len(data))
	intent, err := client.Prepare(context.Background(), "work", trustedOffer(t, client, offer))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := privatefile.Read(client.Root, recordPath("work", "intent"), MaxDocumentSize)
	if err != nil || len(actual) != MaxDocumentSize {
		t.Fatalf("exact-bound pending size=%d err=%v", len(actual), err)
	}
	assertPreparationFiles(t, client, intent)
	other, small := fixture(t)
	reservation, err := other.reserve("work", small)
	if err != nil {
		t.Fatal(err)
	}
	small.Connection.Port++
	if _, err := other.Prepare(context.Background(), "work", trustedOffer(t, other, small)); err == nil {
		t.Fatal("different offer reservation accepted")
	}
	if _, err := os.Stat(filepath.Join(other.Root, seedPath("work"))); !os.IsNotExist(err) {
		t.Fatal("conflicting offer published a secret")
	}
	winner, err := other.readPreparation("work")
	if err != nil || winner.Intent != reservation.Intent {
		t.Fatal("conflict replaced reservation")
	}
}

func TestPreparationMissingSeedPreservesOriginalIntentAndCredential(t *testing.T) {
	client, offer := fixture(t)
	intent, err := client.Prepare(context.Background(), "work", trustedOffer(t, client, offer))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(client.Root, seedPath("work"))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if next, err := client.Prepare(context.Background(), "work", trustedOffer(t, client, offer)); err == nil || next != (EnrollmentIntent{}) {
			t.Fatal("missing recovery seed accepted")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("missing original seed replaced")
		}
	}
	retained, err := client.read("work")
	if err != nil || retained.Intent != intent || credentialCount(t, client.Root) != 1 {
		t.Fatal("original intent or credential changed")
	}
	view, err := client.Inspect(context.Background(), "work")
	if err != nil || view.Access != "conflict" {
		t.Fatalf("missing seed should require recovery: %v", err)
	}
}

func TestPreparationNonlocalExpirySurvivesPersistedReads(t *testing.T) {
	originalLocal := time.Local
	time.Local = time.FixedZone("test-client-local", -7*60*60)
	t.Cleanup(func() { time.Local = originalLocal })
	for _, offset := range []int{5*60*60 + 30*60, 5*60*60 + 45*60} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			client, offer := fixture(t)
			offer.Expires = offer.Expires.In(time.FixedZone("offer-offset", offset))
			trusted := trustedOffer(t, client, offer)
			ctx := context.Background()
			intent, err := client.Prepare(ctx, "work", trusted)
			if err != nil {
				t.Fatalf("first preparation with nonlocal expiry: %v", err)
			}
			originalJSON, _ := json.Marshal(intent)
			retry, err := client.Prepare(ctx, "work", trusted)
			if err != nil {
				t.Fatalf("retry with nonlocal expiry: %v", err)
			}
			retryJSON, _ := json.Marshal(retry)
			if string(originalJSON) != string(retryJSON) || IntentDigest(intent) != IntentDigest(retry) {
				t.Fatal("retry changed wire intent or digest")
			}
			view, err := client.Inspect(ctx, "work")
			if err != nil || view.Access != "prepared-unconfirmed" {
				t.Fatalf("prepared inspection failed: %v", err)
			}
			receipt := receiptFor(t, offer, intent)
			selected, err := client.Complete(ctx, "work", trustedReceipt(t, receipt))
			if err != nil {
				t.Fatalf("completion with nonlocal expiry: %v", err)
			}
			again, err := client.Complete(ctx, "work", trustedReceipt(t, receipt))
			if err != nil || selected.Fingerprint() != again.Fingerprint() {
				t.Fatalf("completion retry changed authority: %v", err)
			}
			view, err = client.Inspect(ctx, "work")
			if err != nil || view.Access != "enrolled" {
				t.Fatalf("enrolled inspection failed: %v", err)
			}
			if credentialCount(t, client.Root) != 1 {
				t.Fatal("nonlocal expiry created extra credentials")
			}
		})
	}
}
