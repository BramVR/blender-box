package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/uiaction"
)

type recoveryAuthorityHost struct {
	recoveryHost
	observe func() (RunReceipt, error)
	settle  func(RunReceipt) error
}

func (host *recoveryAuthorityHost) Observe(context.Context, target.Target, RunID) (RunReceipt, error) {
	return host.observe()
}

func (host *recoveryAuthorityHost) Settle(ctx context.Context, selected target.Target, receipt RunReceipt) (CleanupState, error) {
	cleanup, err := host.fakeHost.Settle(ctx, selected, receipt)
	return cleanup, errors.Join(err, host.settle(receipt))
}

func TestRecoveryRefreshesAuthorityBeforeShapeErrors(t *testing.T) {
	for _, shape := range []string{"schema", "ui"} {
		for _, sameSession := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-same-%t", shape, sameSession), func(t *testing.T) {
				claim := originalClaim(t)
				host := &recoveryAuthorityHost{}
				runner := recoveryRunner(t, host, claim)
				pinned := RunReceipt{SchemaVersion: 1, Claim: claim, State: StateRunning, SessionID: "bss_concurrent-pinned-session-123456"}
				host.observe = func() (RunReceipt, error) {
					if err := runner.journal.accept(testTarget(t), pinned); err != nil {
						t.Fatal(err)
					}
					receipt := pinned
					if !sameSession {
						receipt.SessionID = "bss_conflicting-observed-session-123456"
					}
					if shape == "schema" {
						receipt.SchemaVersion = 99
					} else {
						receipt.UIActions = &uiaction.Journal{SchemaVersion: 99}
					}
					return receipt, nil
				}
				_, err := runner.recoverReceipt(context.Background(), testTarget(t), claim.RunID, "")
				if err == nil || IsAuthorityError(err) == sameSession {
					t.Fatalf("concurrent pin classification: %v", err)
				}
				_, session, err := runner.journal.load(testTarget(t), claim.RunID)
				if err != nil || session != pinned.SessionID {
					t.Fatalf("malformed receipt changed pin: %s %v", session, err)
				}
			})
		}
	}
}

func TestRecoveryRetainsKnownAuthorityOnObserveError(t *testing.T) {
	for _, losePin := range []bool{false, true} {
		t.Run(fmt.Sprint(losePin), func(t *testing.T) {
			claim := originalClaim(t)
			host := &recoveryAuthorityHost{}
			runner := recoveryRunner(t, host, claim)
			pinned := RunReceipt{SchemaVersion: 1, Claim: claim, State: StateRunning, SessionID: "bss_original-pinned-session-123456"}
			if err := runner.journal.accept(testTarget(t), pinned); err != nil {
				t.Fatal(err)
			}
			observeErr := errors.New("Observe transport failed")
			host.observe = func() (RunReceipt, error) {
				if losePin {
					if err := os.Remove(filepath.Join(runner.journal.root, pinPath(claim.RunID))); err != nil {
						t.Fatal(err)
					}
				}
				return RunReceipt{Claim: LockClaim{RunID: "untrusted-partial"}, SessionID: "untrusted-partial"}, observeErr
			}
			_, err := runner.recoverReceipt(context.Background(), testTarget(t), claim.RunID, "")
			if !errors.Is(err, observeErr) || IsAuthorityError(err) != losePin {
				t.Fatalf("Observe error lost retained authority or trusted partial receipt: %v", err)
			}
			if losePin {
				if _, err := os.Stat(filepath.Join(runner.journal.root, pinPath(claim.RunID))); !os.IsNotExist(err) {
					t.Fatalf("known pin recreated: %v", err)
				}
			}
		})
	}
}

func TestRecoveryReturnsTrustedConcurrentPinOnObserveError(t *testing.T) {
	claim := originalClaim(t)
	host := &recoveryAuthorityHost{}
	runner := recoveryRunner(t, host, claim)
	pinned := RunReceipt{SchemaVersion: 1, Claim: claim, State: StateRunning, SessionID: "bss_concurrent-trusted-session-123456"}
	observeErr := errors.New("Observe transport failed")
	host.observe = func() (RunReceipt, error) {
		if err := runner.journal.accept(testTarget(t), pinned); err != nil {
			t.Fatal(err)
		}
		return RunReceipt{SessionID: "untrusted-partial"}, observeErr
	}
	receipt, err := runner.recoverReceipt(context.Background(), testTarget(t), claim.RunID, "")
	if !errors.Is(err, observeErr) || IsAuthorityError(err) || !receipt.Claim.Equal(claim) || receipt.SessionID != pinned.SessionID {
		t.Fatalf("Observe error discarded trusted concurrent authority or trusted partial receipt: %+v %v", receipt, err)
	}
}

func TestSettlementRetainsFilledAuthorityAfterHostReturn(t *testing.T) {
	for _, losePin := range []bool{false, true} {
		for _, hostFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("lost-%t-error-%t", losePin, hostFails), func(t *testing.T) {
				claim := originalClaim(t)
				pinned := RunReceipt{SchemaVersion: 1, Claim: claim, State: StateRunning, SessionID: "bss_original-pinned-session-123456"}
				host := &recoveryAuthorityHost{recoveryHost: recoveryHost{fakeHost: fakeHost{receipt: pinned}}}
				runner := recoveryRunner(t, host, claim)
				if err := runner.journal.accept(testTarget(t), pinned); err != nil {
					t.Fatal(err)
				}
				hostErr := errors.New("Settle transport failed")
				host.settle = func(receipt RunReceipt) error {
					if receipt.SessionID != pinned.SessionID {
						t.Fatal("settlement lost filled Session")
					}
					if losePin {
						if err := os.Remove(filepath.Join(runner.journal.root, pinPath(claim.RunID))); err != nil {
							t.Fatal(err)
						}
					}
					if hostFails {
						return hostErr
					}
					return nil
				}
				unfilled := pinned
				unfilled.SessionID = ""
				cleanup, err := runner.settle(context.Background(), testTarget(t), unfilled)
				if IsAuthorityError(err) != losePin || errors.Is(err, hostErr) != hostFails || !cleanup.Known() {
					t.Fatalf("settlement lost authority, host error, or cleanup: %+v %v", cleanup, err)
				}
			})
		}
	}
}
