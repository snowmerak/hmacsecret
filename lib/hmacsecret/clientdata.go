//go:build cgo

package hmacsecret

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// MakeClientDataJSON builds a minimal WebAuthn clientDataJSON payload.
// operation is typically "webauthn.create" or "webauthn.get".
func MakeClientDataJSON(operation string, challenge []byte, rpID string) ([]byte, error) {
	if operation == "" {
		return nil, fmt.Errorf("client data operation is required")
	}
	if len(challenge) == 0 {
		return nil, fmt.Errorf("client data challenge is required")
	}
	if rpID == "" {
		return nil, fmt.Errorf("client data rpID is required")
	}

	clientData, err := json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{
		Type:        operation,
		Challenge:   base64.RawURLEncoding.EncodeToString(challenge),
		Origin:      "https://" + rpID,
		CrossOrigin: false,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal client data: %w", err)
	}
	return clientData, nil
}
