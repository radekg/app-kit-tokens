```go
package wellknown

import (
	"fmt"
	"net/url"
	"strings"
)

// ObtainPermissionOpt defines the interface of the option.
type ObtainPermissionOpt interface {
	Apply(values *url.Values)
}

// ObtainPermissionClaimTokenOpt is the claim_token option.
// This parameter is optional. A string representing additional claims that should be considered by the server when
// evaluating permissions for the resource(s) and scope(s) being requested. This parameter allows clients to push claims to
// Keycloak. For more details about all supported token formats see claim_token_format parameter.
type ObtainPermissionClaimTokenOpt struct {
	ClaimToken string
}

// Apply applies the option.
func (o *ObtainPermissionClaimTokenOpt) Apply(values *url.Values) {
	values.Add("claim_token", o.ClaimToken)
}

// ObtainPermissionClaimTokenFormatOpt is the claim_token_format option.
// This parameter is optional. A string indicating the format of the token specified in the claim_token parameter. Keycloak
// supports two token formats: urn:ietf:params:oauth:token-type:jwt and https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
// The urn:ietf:params:oauth:token-type:jwt format indicates that the claim_token parameter references an access token.
// The https://openid.net/specs/openid-connect-core-1_0.html#IDToken indicates that the claim_token parameter references an OpenID
// Connect ID Token.
type ObtainPermissionClaimTokenFormatOpt struct {
	ClaimTokenFormat string
}

// Apply applies the option.
func (o *ObtainPermissionClaimTokenFormatOpt) Apply(values *url.Values) {
	values.Add("claim_token_format", o.ClaimTokenFormat)
}

// ObtainPermissionPermissionsOpt is the permission option.
// This parameter is optional. A string representing a set of one or more resources and scopes the client is seeking access.
// This parameter can be defined multiple times in order to request permission for multiple resource and scopes. This parameter
// is an extension to urn:ietf:params:oauth:grant-type:uma-ticket grant type in order to allow clients to send authorization
// requests without a permission ticket. The format of the string must be: RESOURCE_ID#SCOPE_ID. For instance:
// Resource A#Scope A, Resource A#Scope A, Scope B, Scope C, Resource A, #Scope A.
// Operation notes:
// - to achieve #Scope, prefix key with ~
// - items where key is prefixed with ~ and there are no scopes are skipped
type ObtainPermissionPermissionsOpt struct {
	Permissions map[string][]string
}

// Apply applies the option.
func (o *ObtainPermissionPermissionsOpt) Apply(values *url.Values) {
	for k, v := range o.Permissions {
		key := ""
		if !strings.HasPrefix(k, "~") {
			key = k
		}
		// skip items where there is no resource and no scopes:
		if len(key) == 0 && len(v) == 0 {
			continue
		}
		values.Add("permission", fmt.Sprintf("%s#%s", k, strings.Join(v, ", ")))
	}
}

// ObtainPermissionResponseIncludeResourceNameOpt is the response_include_resource_name option.
// This parameter is optional. A boolean value indicating to the server whether resource names should be included in the RPT’s
// permissions. If false, only the resource identifier is included.
type ObtainPermissionResponseIncludeResourceNameOpt struct {
	ResponseIncludeResourceName bool
}

// Apply applies the option.
func (o *ObtainPermissionResponseIncludeResourceNameOpt) Apply(values *url.Values) {
	values.Add("response_include_resource_name", fmt.Sprintf("%v", o.ResponseIncludeResourceName))
}

// ObtainPermissionResponsePermissionsLimitOpt is the response_permissions_limit option.
// This parameter is optional. A boolean value indicating to the server whether resource names should be included in the RPT’s
// permissions. If false, only the resource identifier is included.
type ObtainPermissionResponsePermissionsLimitOpt struct {
	ResponsePermissionsLimit int
}

// Apply applies the option.
func (o *ObtainPermissionResponsePermissionsLimitOpt) Apply(values *url.Values) {
	values.Add("response_permissions_limit", fmt.Sprintf("%d", o.ResponsePermissionsLimit))
}

// ObtainPermissionRPTOpt is the rpt option.
// This parameter is optional. A previously issued RPT which permissions should also be evaluated and added in a new one.
// This parameter allows clients in possession of an RPT to perform incremental authorization where permissions are added on demand.
type ObtainPermissionRPTOpt struct {
	RPT string
}

// Apply applies the option.
func (o *ObtainPermissionRPTOpt) Apply(values *url.Values) {
	values.Add("rpt", o.RPT)
}

// ObtainPermissionSubmitRequestOpt is the submit_request option.
// This parameter is optional. A boolean value indicating whether the server should create permission requests to the resources
// and scopes referenced by a permission ticket. This parameter only have effect if used together with the ticket parameter
// as part of a UMA authorization process.
type ObtainPermissionSubmitRequestOpt struct {
	SubmitRequest bool
}

// Apply applies the option.
func (o *ObtainPermissionSubmitRequestOpt) Apply(values *url.Values) {
	values.Add("submit_request", fmt.Sprintf("%v", o.SubmitRequest))
}

// ObtainPermissionTicketOpt is the ticket option.
// This parameter is optional. The most recent permission ticket received by the client as part of the UMA authorization process.
type ObtainPermissionTicketOpt struct {
	Ticket string
}

// Apply applies the option.
func (o *ObtainPermissionTicketOpt) Apply(values *url.Values) {
	values.Add("ticket", o.Ticket)
}
```