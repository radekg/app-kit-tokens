```go
package tokens

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// RealmAccess represents token realm access.
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// UMAAuthorization represents the UMA token authorization.
type UMAAuthorization struct {
	Permissions []*UMAPermission `json:"permissions"`
}

// UMAPermission represents the UMA token authorization permission.
type UMAPermission struct {
	Rsid   string   `json:"rsid"`
	Rsname string   `json:"rsname"`
	Scopes []string `json:"scopes"`
}

// UMAAccessToken represents an UMA token
// of the User-Managed Access (UMA) OAuth-based access management protocol standard.
type UMAAccessToken struct {
	Acr               string            `json:"acr"`
	AllowedOrigins    []string          `json:"allowed-origins"`
	Aud               string            `json:"aud"`
	Authorization     *UMAAuthorization `json:"authorization"`
	Azp               string            `json:"azp"`
	Email             string            `json:"email"`
	EmailVerified     bool              `json:"email_verified"`
	Exp               int64             `json:"exp"`
	FamilyName        string            `json:"family_name"`
	GivenName         string            `json:"given_name"`
	Iat               int64             `json:"iat"`
	Iss               string            `json:"iss"`
	Jti               string            `json:"jti"`
	Name              string            `json:"name"`
	Nbf               int64             `json:"nbf"`
	PreferredUsername string            `json:"preferred_username"`
	RealmAccess       *RealmAccess      `json:"realm_access"`
	Scope             string            `json:"scope"`
	SessionState      string            `json:"session_state"`
	Sub               string            `json:"sub"`
	Typ               string            `json:"typ"`
}

// UMATokenFromString attempts to parse a string as UMA token.
func UMATokenFromString(token string) (*UMAAccessToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid access token")
	}
	_, contents, _ := getTokenParts(parts)
	t := &UMAAccessToken{}
	payloadBytes, base64DecodeError := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(contents)
	if base64DecodeError != nil {
		return nil, base64DecodeError
	}
	if jsonErr := json.Unmarshal(payloadBytes, &t); jsonErr != nil {
		return nil, jsonErr
	}
	return t, nil
}
```