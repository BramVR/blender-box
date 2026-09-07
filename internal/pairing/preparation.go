package pairing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/target"
)

const preparationPublicKeyPlaceholder = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func seedPath(name string) string { return filepath.Join("pairings", name, "preparation", "seed") }

func (client Client) readPreparation(name string) (pending, error) {
	if err := target.ValidateName(name); err != nil {
		return pending{}, err
	}
	data, err := privatefile.ReadDurable(client.Root, recordPath(name, "preparation"), MaxDocumentSize)
	if err != nil {
		return pending{}, err
	}
	var value pending
	if err := strictjson.Decode(data, &value); err != nil {
		return pending{}, err
	}
	if value.SchemaVersion != 1 || value.Name != name || value.Intent.SchemaVersion != 1 || !idPattern.MatchString(value.Intent.PairID) || !idPattern.MatchString(value.Intent.OperationID) || value.Intent.OfferHash != OfferDigest(value.Offer) || !value.Intent.Expires.Equal(value.Offer.Expires) || value.Intent.PublicKey != preparationPublicKeyPlaceholder {
		return pending{}, fmt.Errorf("conflicting pairing preparation")
	}
	if err := validateOffer(value.Offer); err != nil {
		return pending{}, err
	}
	return value, nil
}

func (client Client) reserve(name string, offer HostOffer) (pending, error) {
	ids := make([]byte, 32)
	if _, err := rand.Read(ids); err != nil {
		return pending{}, err
	}
	intent := EnrollmentIntent{1, hex.EncodeToString(ids[:16]), hex.EncodeToString(ids[16:]), OfferDigest(offer), preparationPublicKeyPlaceholder, offer.Expires}
	candidate := pending{1, name, offer, intent}
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return pending{}, err
	}
	if len(encoded) > MaxDocumentSize {
		return pending{}, fmt.Errorf("private record exceeds size limit")
	}
	publishErr := client.publishPreparation(client.Root, recordPath(name, "preparation"), encoded, false)
	winner, err := client.readPreparation(name)
	if err != nil {
		if publishErr != nil {
			return pending{}, publishErr
		}
		return pending{}, err
	}
	if winner.Intent.OfferHash != intent.OfferHash {
		return pending{}, fmt.Errorf("name already has a different pairing preparation")
	}
	return winner, nil
}

func (client Client) atPreparation(stage string) error {
	if client.checkpoint != nil {
		return client.checkpoint(stage)
	}
	return nil
}

func (client Client) prepareReserved(ctx context.Context, reservation pending) (EnrollmentIntent, error) {
	if err := client.atPreparation("reservation"); err != nil {
		return EnrollmentIntent{}, err
	}
	existing, readErr := client.read(reservation.Name)
	if readErr == nil {
		retainedPreparationIdentity := existing.Intent
		retainedPreparationIdentity.PublicKey = preparationPublicKeyPlaceholder
		if !sameIntent(retainedPreparationIdentity, reservation.Intent) {
			return EnrollmentIntent{}, fmt.Errorf("intent conflicts with retained preparation")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return EnrollmentIntent{}, readErr
	}
	key, err := sshkey.Reserved(ctx, client.Root, seedPath(reservation.Name), errors.Is(readErr, os.ErrNotExist))
	if err != nil {
		return EnrollmentIntent{}, err
	}
	if err := client.atPreparation("seed"); err != nil {
		return EnrollmentIntent{}, err
	}
	expected := reservation
	expected.Intent.PublicKey = key.PublicKey()
	if readErr == nil && !sameIntent(existing.Intent, expected.Intent) {
		return EnrollmentIntent{}, fmt.Errorf("intent conflicts with retained preparation key")
	}
	encoded, err := json.Marshal(expected)
	if err != nil {
		return EnrollmentIntent{}, err
	}
	publishErr := client.publishPreparation(client.Root, recordPath(reservation.Name, "intent"), encoded, false)
	durable, err := client.read(reservation.Name)
	if err != nil {
		if publishErr != nil {
			return EnrollmentIntent{}, publishErr
		}
		return EnrollmentIntent{}, err
	}
	if !sameIntent(durable.Intent, expected.Intent) {
		return EnrollmentIntent{}, fmt.Errorf("intent conflicts with retained preparation key")
	}
	if err := client.atPreparation("intent"); err != nil {
		return EnrollmentIntent{}, err
	}
	if err := ctx.Err(); err != nil {
		return EnrollmentIntent{}, err
	}
	if err := key.Publish(client.Root); err != nil {
		return EnrollmentIntent{}, err
	}
	if err := client.atPreparation("credential"); err != nil {
		return EnrollmentIntent{}, err
	}
	return durable.Intent, nil
}

func (client Client) verifyCredential(ctx context.Context, value pending) error {
	reservation, err := client.readPreparation(value.Name)
	if errors.Is(err, os.ErrNotExist) {
		fingerprint, _ := sshkey.Fingerprint(value.Intent.PublicKey)
		_, err := sshkey.Read(ctx, client.Root, fingerprint)
		return err
	}
	if err != nil {
		return err
	}
	retainedPreparationIdentity := value.Intent
	retainedPreparationIdentity.PublicKey = preparationPublicKeyPlaceholder
	if !sameIntent(retainedPreparationIdentity, reservation.Intent) {
		return fmt.Errorf("intent conflicts with retained preparation")
	}
	key, err := sshkey.Reserved(ctx, client.Root, seedPath(value.Name), false)
	if err != nil {
		return err
	}
	if key.PublicKey() != value.Intent.PublicKey {
		return fmt.Errorf("intent conflicts with retained preparation key")
	}
	return key.Verify(client.Root)
}

func preparationView(pairID string) PairView {
	return PairView{1, pairID, "preparation-pending", "unchecked", "repeat preparation with the original trusted host offer"}
}

func (client Client) publishPreparation(root, path string, data []byte, replace bool) error {
	if client.publish != nil {
		return client.publish(root, path, data, replace)
	}
	return privatefile.Publish(root, path, data, replace)
}

func sameIntent(left, right EnrollmentIntent) bool {
	return left.SchemaVersion == right.SchemaVersion && left.PairID == right.PairID && left.OperationID == right.OperationID && left.OfferHash == right.OfferHash && left.PublicKey == right.PublicKey && left.Expires.Equal(right.Expires)
}
