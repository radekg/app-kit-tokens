package jwks

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/radekg/app-kit-tokens/tokens"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// ErrSigningKeyNotKnown indicates a token where for which there is no signing key in this JWKS.
	ErrSigningKeyNotKnown = errSigningKeyNotKnown()
)

func errSigningKeyNotKnown() error { return errors.New("kid not in jwks") }

// ResolveJWKS loads JWKS configuration from the given URL.
func ResolveJWKS(location *url.URL, client *http.Client) (JWKS, error) {
	if client == nil {
		client = &http.Client{}
	}
	// construct the request:
	request, requestError := http.NewRequest("GET", location.String(), nil)
	if requestError != nil {
		return nil, requestError
	}
	// issue the request:
	resp, getErr := client.Do(request)
	if getErr != nil {
		return nil, getErr
	}
	defer resp.Body.Close()

	jwks := &jose.JSONWebKeySet{}
	// unmarshal JSON into the struct:
	if jsonErr := json.NewDecoder(resp.Body).Decode(jwks); jsonErr != nil {
		return nil, jsonErr
	}
	return &defaultJWKS{set: jwks}, nil

}

// JWKS abstracts token validation using JWKS resolved with FetchJWKS.
type JWKS interface {
	Key(kid string) []jose.JSONWebKey
	ReadSigned(rawToken string) JWTRead
}

type defaultJWKS struct {
	set *jose.JSONWebKeySet
}

func (v *defaultJWKS) Key(kid string) []jose.JSONWebKey {
	return v.set.Key(kid)
}

func (v *defaultJWKS) ReadSigned(rawToken string) JWTRead {
	cl := tokens.Claims{}
	token, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return &defaultJWTRead{
			err: err,
		}
	}
	// do we have a JWK with the ID from the header
	if token.Headers[0].KeyID != "" {
		for _, k := range v.set.Keys {
			if k.KeyID == token.Headers[0].KeyID {
				claimsErr := token.Claims(k.Public(), &cl)
				return &defaultJWTRead{
					err:     claimsErr,
					headers: token.Headers,
					claims:  cl,
				}
			}
		}
		return &defaultJWTRead{
			err: ErrSigningKeyNotKnown,
		}
	}

	// else, it's possible we have no key id, we need to try every key and return
	// on first non nil error or fail with ErrSigningKeyNotKnown

	for _, k := range v.set.Keys {
		if err := token.Claims(k.Public(), &cl); err == nil {
			return &defaultJWTRead{
				err:     nil,
				claims:  cl,
				headers: token.Headers,
			}
		}
	}

	return &defaultJWTRead{
		err: ErrSigningKeyNotKnown,
	}
}

// JWTRead abstracts the jwt token read result.
type JWTRead interface {
	Error() error
	Headers() []jose.Header
	Claims() tokens.Claims
}

type defaultJWTRead struct {
	err     error
	headers []jose.Header
	claims  tokens.Claims
}

func (rr *defaultJWTRead) Error() error {
	return rr.err
}
func (rr *defaultJWTRead) Headers() []jose.Header {
	return rr.headers
}

func (rr *defaultJWTRead) Claims() tokens.Claims {
	return rr.claims
}
