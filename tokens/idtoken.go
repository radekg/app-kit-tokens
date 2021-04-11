package tokens

import (
	"fmt"
	"testing"

	"gopkg.in/square/go-jose.v2/jwt"
)

// IDToken represents the ID token.
type IDToken interface {

	// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	Birthdate() (string, bool)
	Email() (string, bool)
	EmailVerified() (bool, bool)
	FamilyName() (string, bool)
	Gender() (string, bool)
	MiddleName() (string, bool)
	Name() (string, bool)
	Nickname() (string, bool)
	PhoneNumber() (string, bool)
	PhoneNumberVerified() (bool, bool)
	Picture() (string, bool)
	PreferredUsername() (string, bool)
	Profile() (string, bool)
	Sub() (string, bool)
	UpdatedAt() (int64, bool)
	Website() (string, bool)
	ZoneInfo() (string, bool)

	// Other convenient documented claims:
	// https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
	Address() (interface{}, bool)
	// https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
	AtHash() (string, bool)
	// https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
	CHash() (string, bool)
	// https://openid.net/specs/openid-connect-core-1_0.html#SelfIssuedValidation
	SubJWK() (interface{}, bool)
}

type defaultIDToken struct {
	defaultToken
	claims Claims
}

// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
func (it *defaultIDToken) Birthdate() (string, bool) {
	return it.GetClaimMustString("birthdate")
}
func (it *defaultIDToken) Email() (string, bool) {
	return it.GetClaimMustString("email")
}
func (it *defaultIDToken) EmailVerified() (bool, bool) {
	return it.claims.getBoolClaim("email_verified")
}
func (it *defaultIDToken) FamilyName() (string, bool) {
	return it.GetClaimMustString("family_name")
}
func (it *defaultIDToken) Gender() (string, bool) {
	return it.GetClaimMustString("gender")
}
func (it *defaultIDToken) MiddleName() (string, bool) {
	return it.GetClaimMustString("middle_name")
}
func (it *defaultIDToken) Name() (string, bool) {
	return it.GetClaimMustString("name")
}
func (it *defaultIDToken) Nickname() (string, bool) {
	return it.GetClaimMustString("nickname")
}
func (it *defaultIDToken) PhoneNumber() (string, bool) {
	return it.GetClaimMustString("phone_number")
}
func (it *defaultIDToken) PhoneNumberVerified() (bool, bool) {
	return it.claims.getBoolClaim("phone_number_verified")
}
func (it *defaultIDToken) Picture() (string, bool) {
	return it.GetClaimMustString("picture")
}
func (it *defaultIDToken) PreferredUsername() (string, bool) {
	return it.GetClaimMustString("preferred_username")
}
func (it *defaultIDToken) Profile() (string, bool) {
	return it.GetClaimMustString("profile")
}
func (it *defaultIDToken) Sub() (string, bool) {
	return it.GetClaimMustString("sub")
}
func (it *defaultIDToken) UpdatedAt() (int64, bool) {
	return it.claims.getInt64Claim("updated_at")
}
func (it *defaultIDToken) Website() (string, bool) {
	return it.GetClaimMustString("website")
}
func (it *defaultIDToken) ZoneInfo() (string, bool) {
	return it.GetClaimMustString("zoneinfo")
}

// Other convenient documented claims:

func (it *defaultIDToken) Address() (interface{}, bool) {
	return it.GetClaim("address")
}
func (it *defaultIDToken) AtHash() (string, bool) {
	return it.GetClaimMustString("at_hash")
}
func (it *defaultIDToken) CHash() (string, bool) {
	return it.GetClaimMustString("c_hash")
}
func (it *defaultIDToken) SubJWK() (interface{}, bool) {
	return it.GetClaim("sub_jwk")
}

// convenience:

func (it *defaultIDToken) HasClaim(claim string) bool {
	_, ok := it.claims[claim]
	return ok
}

func (it *defaultIDToken) GetClaim(claim string) (interface{}, bool) {
	value, ok := it.claims[claim]
	return value, ok
}

func (it *defaultIDToken) GetClaimMustString(claim string) (string, bool) {
	if value, ok := it.claims[claim]; ok {
		switch tvalue := value.(type) {
		case string:
			return tvalue, ok
		default:
			return fmt.Sprintf("%v", tvalue), ok
		}
	}
	return "", false
}

func (it *defaultIDToken) RawClaims() Claims {
	return it.claims
}

// DefaultIDToken returns an instacne of the ID token.
// Call this function using claims returned from jwks.Validator.ValidateToken(string).
func DefaultIDToken(claims Claims) IDToken {
	return &defaultIDToken{claims: claims}
}

func defaultInsecureIDToken(t *testing.T, rawToken string) (IDToken, error) {
	token, parseErr := jwt.ParseSigned(rawToken)
	if parseErr != nil {
		return nil, parseErr
	}
	cl := map[string]interface{}{}
	if claimsErr := token.UnsafeClaimsWithoutVerification(&cl); claimsErr != nil {
		return nil, claimsErr
	}
	return DefaultIDToken(cl), nil
}
