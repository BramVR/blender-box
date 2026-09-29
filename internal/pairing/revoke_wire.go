package pairing

import (
	"fmt"

	"github.com/BramVR/blender-box/internal/strictjson"
)

// RevokeRequest is the stdin JSON of `host pair-revoke`, sent by the paired key itself.
// The host refuses unless ClientPublicKeyHash is the fingerprint of the grant's key.
type RevokeRequest struct {
	SchemaVersion       int    `json:"schema_version"`
	PairID              string `json:"pair_id"`
	ClientPublicKeyHash string `json:"client_public_key_hash"`
}

// RevokeResult is the host's answer once the marked line is verified absent.
// KeysSHA256Before and KeysSHA256After are read back from the keys file so evidence
// can show that only the pairing line changed.
type RevokeResult struct {
	SchemaVersion    int    `json:"schema_version"`
	PairID           string `json:"pair_id"`
	State            string `json:"state"`
	KeysSHA256Before string `json:"keys_sha256_before"`
	KeysSHA256After  string `json:"keys_sha256_after"`
	TombstoneSHA256  string `json:"tombstone_sha256"`
}

func (request RevokeRequest) Validate() error {
	if request.SchemaVersion != 1 || !idPattern.MatchString(request.PairID) || !hashPattern.MatchString(request.ClientPublicKeyHash) {
		return fmt.Errorf("invalid revoke request")
	}
	return nil
}

// ParseRevokeResult accepts only a completed revocation for the expected pair.
func ParseRevokeResult(data []byte, pairID string) (RevokeResult, error) {
	var result RevokeResult
	if len(data) > MaxDocumentSize {
		return RevokeResult{}, fmt.Errorf("revoke result exceeds size limit")
	}
	if err := strictjson.Decode(data, &result); err != nil {
		return RevokeResult{}, err
	}
	if result.SchemaVersion != 1 || result.PairID != pairID || result.State != "revoked" || !hashPattern.MatchString(result.KeysSHA256Before) || !hashPattern.MatchString(result.KeysSHA256After) || !hashPattern.MatchString(result.TombstoneSHA256) {
		return RevokeResult{}, fmt.Errorf("host did not confirm revocation of pair %s", pairID)
	}
	return result, nil
}
