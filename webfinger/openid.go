package webfinger

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/radekg/app-kit-tokens/jwks"
)

// OpenIDConfiguration represents an OpenID Configuration webfinger
// resolved from .well-knonw/openid-configuration.
type OpenIDConfiguration interface {
	// endpoints:
	AuthorizationEndpoint() string
	EndSessionEndpoint() string
	IntrospectionEndpoint() string
	JWKSURI() string
	RegistrationEndpoint() string
	TokenEndpoint() string
	TokenIntrospectionEndpoint() string
	UserInfoEndpoint() string
	// supports:
	ClaimsParameterSupported() bool
	ClaimsSupported() []string
	ClaimTypesSupported() []string
	CodeChallengeMethodsSupported() []string
	GrantTypesSupported() []string
	IDTokenEncryptionEncValuesSupported() []string
	IDTokenSigningAlgValuesSupported() []string
	RequestObjectSigningAlgValuesSupported() []string
	RequestParameterSupported() bool
	RequestURIParameterSupported() bool
	ResponseModesSupported() []string
	ResponseTypesSupported() []string
	ScopesSupported() []string
	SubjectTypesSupported() []string
	TokenEndpointAuthMethodsSupported() []string
	TokenEndpointAuthSigningAlgValuesSupported() []string
	UserInfoSigningAlgValuesSupported() []string
	// other:
	CheckSessionIFrame() string
	Issuer() string
	TLSClientCertificateBoundAccessToken() bool
	// utilities:
	ResolveJWKS() (jwks.JWKS, error)
}

// ResolveOpenIDConfiguration resolves the OpneID configuration from webfinger.
// Appends .well-known/openid-configuration to the base URL.
func ResolveOpenIDConfiguration(baseURL string) (OpenIDConfiguration, error) {
	return ResolveOpenIDConfigurationWithHTTPClient(baseURL, &http.Client{})
}

// ResolveOpenIDConfigurationWithHTTPClient resolves the OpneID configuration from webfinger.
// Appends .well-known/openid-configuration to the base URL.
// Uses provided HTTP client.
func ResolveOpenIDConfigurationWithHTTPClient(baseURL string, client *http.Client) (OpenIDConfiguration, error) {
	// construct the request:
	request, requestError := http.NewRequest("GET", fmt.Sprintf("%s/.well-known/openid-configuration", baseURL), nil)
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
	openIDConfig := &defaultOpenIDConfiguration{httpClient: client}
	// unmarshal JSON into the struct:
	if jsonErr := json.NewDecoder(resp.Body).Decode(openIDConfig); jsonErr != nil {
		return nil, jsonErr
	}
	return openIDConfig, nil
}

// OpenIDConfiguration represents well known OpenID configuration.
type defaultOpenIDConfiguration struct {
	AuthorizationEndpointValue                      string   `json:"authorization_endpoint"`
	CheckSessionIFrameValue                         string   `json:"check_session_iframe"`
	ClaimsParameterSupportedValue                   bool     `json:"claims_parameter_supported"`
	ClaimsSupportedValue                            []string `json:"claims_supported"`
	ClaimTypesSupportedValue                        []string `json:"claim_types_supported"`
	CodeChallengeMethodsSupportedValue              []string `json:"code_challenge_methods_supported"`
	EndSessionEndpointValue                         string   `json:"end_session_endpoint"`
	GrantTypesSupportedValue                        []string `json:"grant_types_supported"`
	IDTokenEncryptionEncValuesSupportedValue        []string `json:"id_token_encryption_enc_values_supported"`
	IDTokenSigningAlgValuesSupportedValue           []string `json:"id_token_signing_alg_values_supported"`
	IntrospectionEndpointValue                      string   `json:"introspection_endpoint"`
	IssuerValue                                     string   `json:"issuer"`
	JWKSURIValue                                    string   `json:"jwks_uri"`
	RegistrationEndpointValue                       string   `json:"registration_endpoint"`
	RequestObjectSigningAlgValuesSupportedValue     []string `json:"request_object_signing_alg_values_supported"`
	RequestParameterSupportedValue                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupportedValue               bool     `json:"request_uri_parameter_supported"`
	ResponseModesSupportedValue                     []string `json:"response_modes_supported"`
	ResponseTypesSupportedValue                     []string `json:"response_types_supported"`
	ScopesSupportedValue                            []string `json:"scopes_supported"`
	SubjectTypesSupportedValue                      []string `json:"subject_types_supported"`
	TLSClientCertificateBoundAccessTokenValue       bool     `json:"tls_client_certificate_bound_access_tokens"`
	TokenEndpointValue                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupportedValue          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupportedValue []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	TokenIntrospectionEndpointValue                 string   `json:"token_introspection_endpoint"`
	UserInfoEndpointValue                           string   `json:"userinfo_endpoint"`
	UserInfoSigningAlgValuesSupportedValue          []string `json:"userinfo_signing_alg_values_supported"`
	httpClient                                      *http.Client
}

// endpoints:
func (c *defaultOpenIDConfiguration) AuthorizationEndpoint() string {
	return c.AuthorizationEndpointValue
}
func (c *defaultOpenIDConfiguration) EndSessionEndpoint() string {
	return c.EndSessionEndpointValue
}
func (c *defaultOpenIDConfiguration) IntrospectionEndpoint() string {
	return c.IntrospectionEndpointValue
}
func (c *defaultOpenIDConfiguration) JWKSURI() string {
	return c.JWKSURIValue
}
func (c *defaultOpenIDConfiguration) RegistrationEndpoint() string {
	return c.RegistrationEndpointValue
}
func (c *defaultOpenIDConfiguration) TokenEndpoint() string {
	return c.TokenEndpointValue
}
func (c *defaultOpenIDConfiguration) TokenIntrospectionEndpoint() string {
	return c.TokenIntrospectionEndpointValue
}
func (c *defaultOpenIDConfiguration) UserInfoEndpoint() string {
	return c.UserInfoEndpointValue
}

// supports:
func (c *defaultOpenIDConfiguration) ClaimsParameterSupported() bool {
	return c.ClaimsParameterSupportedValue
}
func (c *defaultOpenIDConfiguration) ClaimsSupported() []string {
	return c.ClaimsSupportedValue
}
func (c *defaultOpenIDConfiguration) ClaimTypesSupported() []string {
	return c.ClaimTypesSupportedValue
}
func (c *defaultOpenIDConfiguration) CodeChallengeMethodsSupported() []string {
	return c.CodeChallengeMethodsSupportedValue
}
func (c *defaultOpenIDConfiguration) GrantTypesSupported() []string {
	return c.GrantTypesSupportedValue
}
func (c *defaultOpenIDConfiguration) IDTokenEncryptionEncValuesSupported() []string {
	return c.IDTokenEncryptionEncValuesSupportedValue
}
func (c *defaultOpenIDConfiguration) IDTokenSigningAlgValuesSupported() []string {
	return c.IDTokenSigningAlgValuesSupportedValue
}
func (c *defaultOpenIDConfiguration) RequestObjectSigningAlgValuesSupported() []string {
	return c.RequestObjectSigningAlgValuesSupportedValue
}
func (c *defaultOpenIDConfiguration) RequestParameterSupported() bool {
	return c.RequestParameterSupportedValue
}
func (c *defaultOpenIDConfiguration) RequestURIParameterSupported() bool {
	return c.RequestURIParameterSupported()
}
func (c *defaultOpenIDConfiguration) ResponseModesSupported() []string {
	return c.ResponseModesSupportedValue
}
func (c *defaultOpenIDConfiguration) ResponseTypesSupported() []string {
	return c.ResponseTypesSupportedValue
}
func (c *defaultOpenIDConfiguration) ScopesSupported() []string {
	return c.ScopesSupportedValue
}
func (c *defaultOpenIDConfiguration) SubjectTypesSupported() []string {
	return c.SubjectTypesSupportedValue
}
func (c *defaultOpenIDConfiguration) TokenEndpointAuthMethodsSupported() []string {
	return c.TokenEndpointAuthMethodsSupportedValue
}
func (c *defaultOpenIDConfiguration) TokenEndpointAuthSigningAlgValuesSupported() []string {
	return c.TokenEndpointAuthSigningAlgValuesSupportedValue
}
func (c *defaultOpenIDConfiguration) UserInfoSigningAlgValuesSupported() []string {
	return c.UserInfoSigningAlgValuesSupportedValue
}

// other:
func (c *defaultOpenIDConfiguration) CheckSessionIFrame() string {
	return c.CheckSessionIFrameValue
}
func (c *defaultOpenIDConfiguration) Issuer() string {
	return c.IssuerValue
}
func (c *defaultOpenIDConfiguration) TLSClientCertificateBoundAccessToken() bool {
	return c.TLSClientCertificateBoundAccessTokenValue
}

func (c *defaultOpenIDConfiguration) ResolveJWKS() (jwks.JWKS, error) {
	u, urlparseErr := url.Parse(c.JWKSURI())
	if urlparseErr != nil {
		return nil, urlparseErr
	}
	return jwks.ResolveJWKS(u, c.httpClient)
}
