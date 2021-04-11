package webfinger

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/radekg/app-kit-tokens/jwks"
)

// UMA2Configuration represents an UMA2 Configuration webfinger
// resolved from .well-knonw/uma2-configuration.
type UMA2Configuration interface {
	// endpoints:
	AuthorizationEndpoint() string
	EndSessionEndpoint() string
	IntrospectionEndpoint() string
	JWKSURI() string
	PermissionEndpoint() string
	PolicyEndpoint() string
	RegistrationEndpoint() string
	ResourceRegistrationEndpoint() string
	TokenEndpoint() string
	TokenIntrospectionEndpoint() string
	// supports:
	GrantTypesSupported() []string
	ResponseModesSupported() []string
	ResponseTypesSupported() []string
	ScopesSupported() []string
	TokenEndpointAuthMethodsSupported() []string
	TokenEndpointAuthSigningAlgValuesSupported() []string
	// other:
	Issuer() string
	// utilities:
	ResolveJWKS() (jwks.JWKS, error)
}

// ResolveUMA2Configuration resolves the UMA2 configuration from webfinger.
// Appends .well-known/uma2-configuration to the base URL.
func ResolveUMA2Configuration(baseURL string) (UMA2Configuration, error) {
	return ResolveUMA2ConfigurationWithHTTPClient(baseURL, &http.Client{})
}

// ResolveUMA2ConfigurationWithHTTPClient resolves the UMA2 configuration from webfinger.
// Appends .well-known/uma2-configuration to the base URL.
// Uses provided HTTP client.
func ResolveUMA2ConfigurationWithHTTPClient(baseURL string, client *http.Client) (UMA2Configuration, error) {
	// construct the request:
	request, requestError := http.NewRequest("GET", fmt.Sprintf("%s/.well-known/uma2-configuration", baseURL), nil)
	if requestError != nil {
		return nil, requestError
	}
	// issue the request:
	resp, getErr := client.Do(request)
	if getErr != nil {
		return nil, getErr
	}
	defer resp.Body.Close()
	// create response:
	uma2Config := &defaultUMA2Configuration{httpClient: client}
	// unmarshal JSON into the struct:
	if jsonErr := json.NewDecoder(resp.Body).Decode(uma2Config); jsonErr != nil {
		return nil, jsonErr
	}
	return uma2Config, nil
}

type defaultUMA2Configuration struct {
	AuthorizationEndpointValue                      string   `json:"authorization_endpoint"`
	EndSessionEndpointValue                         string   `json:"end_session_endpoint"`
	GrantTypesSupportedValue                        []string `json:"grant_types_supported"`
	IntrospectionEndpointValue                      string   `json:"introspection_endpoint"`
	IssuerValue                                     string   `json:"issuer"`
	JWKSURIValue                                    string   `json:"jwks_uri"`
	PermissionEndpointValue                         string   `json:"permission_endpoint"`
	PolicyEndpointValue                             string   `json:"policy_endpoint"`
	RegistrationEndpointValue                       string   `json:"registration_endpoint"`
	ResponseModesSupportedValue                     []string `json:"response_modes_supported"`
	ResponseTypesSupportedValue                     []string `json:"response_types_supported"`
	ResourceRegistrationEndpointValue               string   `json:"resource_registration_endpoint"`
	ScopesSupportedValue                            []string `json:"scopes_supported"`
	TokenEndpointValue                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupportedValue          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupportedValue []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	TokenIntrospectionEndpointValue                 string   `json:"token_introspection_endpoint"`
	httpClient                                      *http.Client
}

// endpoints:
func (c *defaultUMA2Configuration) AuthorizationEndpoint() string {
	return c.AuthorizationEndpointValue
}
func (c *defaultUMA2Configuration) EndSessionEndpoint() string {
	return c.EndSessionEndpointValue
}
func (c *defaultUMA2Configuration) IntrospectionEndpoint() string {
	return c.IntrospectionEndpointValue
}
func (c *defaultUMA2Configuration) JWKSURI() string {
	return c.JWKSURIValue
}
func (c *defaultUMA2Configuration) PermissionEndpoint() string {
	return c.PermissionEndpointValue
}
func (c *defaultUMA2Configuration) PolicyEndpoint() string {
	return c.PolicyEndpointValue
}
func (c *defaultUMA2Configuration) RegistrationEndpoint() string {
	return c.RegistrationEndpointValue
}
func (c *defaultUMA2Configuration) ResourceRegistrationEndpoint() string {
	return c.ResourceRegistrationEndpointValue
}
func (c *defaultUMA2Configuration) TokenEndpoint() string {
	return c.TokenEndpointValue
}
func (c *defaultUMA2Configuration) TokenIntrospectionEndpoint() string {
	return c.TokenIntrospectionEndpointValue
}

// supports:
func (c *defaultUMA2Configuration) GrantTypesSupported() []string {
	return c.GrantTypesSupportedValue
}
func (c *defaultUMA2Configuration) ResponseModesSupported() []string {
	return c.ResponseModesSupportedValue
}
func (c *defaultUMA2Configuration) ResponseTypesSupported() []string {
	return c.ResponseTypesSupportedValue
}
func (c *defaultUMA2Configuration) ScopesSupported() []string {
	return c.ScopesSupportedValue
}
func (c *defaultUMA2Configuration) TokenEndpointAuthMethodsSupported() []string {
	return c.TokenEndpointAuthMethodsSupportedValue
}
func (c *defaultUMA2Configuration) TokenEndpointAuthSigningAlgValuesSupported() []string {
	return c.TokenEndpointAuthSigningAlgValuesSupportedValue
}

// other:
func (c *defaultUMA2Configuration) Issuer() string {
	return c.IssuerValue
}

func (c *defaultUMA2Configuration) ResolveJWKS() (jwks.JWKS, error) {
	u, urlparseErr := url.Parse(c.JWKSURI())
	if urlparseErr != nil {
		return nil, urlparseErr
	}
	return jwks.ResolveJWKS(u, c.httpClient)
}
