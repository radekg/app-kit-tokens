package jwks

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type TestJWKSHandler struct{}

const validToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYzpiMWNiZDQzZi03YmY3LTRmODAtYTA0Zi02ZDFkMGFhZTIyNTMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOltdLCJjbGllbnRfaWQiOiJteS1jbGllbnQiLCJleHAiOjE2MTgxNTMyMDEsImV4dCI6e30sImlhdCI6MTYxODE0OTYwMSwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo0NDQ0LyIsImp0aSI6IjI2YzVjZDQ3LWE3NzgtNDY5ZC05NzkwLWZkOWFkNWQ0N2JjZiIsIm5iZiI6MTYxODE0OTYwMSwic2NwIjpbIm9wZW5pZCIsIm9mZmxpbmUiXSwic3ViIjoibXktY2xpZW50In0.sONnqIY8gUepilbE0edgIV8SEjlALsmA61xUNVKKXxCoLTgGesvj0m3lUXbo0SKCiPNo3ZZwLbfSMnQFWj3fWoNLFwYMVJCVIx9e-n-o91G1dlRrc2u5nW0j2spJRKqO51uETBex90UC5e67FGXWR29ikS1jLREDb06RKEHROUOsGt6FHmQat3cacFt-f7vipyPVwDgErq1OOUDFzS3kUcW356WsoVGXFP21EmXrdwYNUfyKiY8zrv7WhzkrsTrn2e60y8rmXG0RiOjCOgCtg6Gu9_PyuEFM1x5Re1WijxbUKewaIWo21UNIuCHfQe4mZQpBN5stifRi-BlciZN_B8EINaJ_rniL7v_OY6soOlV19WJarW7hVtOxHGAXNbW2_okB4oE4hGIsBJ6545t8EUEKHiul-LHa3U-Ts6dso-qucW3dvy2InbQKA1ksx7IQjezBvJJBUwvy5nk0Kr7f-WPqueCP9pYew8gfu0hUinATdLKeeHoowLXxtWChWuhCeNXvuxvZUJ72GpYOH5CpGoClFW_qg5zUjsMj3DVdveXwf_FvdegKSXr22iJgNlWCilidFMtvNlCKEPG4Saw5lJaXmSGFvCn168cIorgtjM8WV5eKc5aXg9xC0W8FxEdKUbsqGzreLrCbAPmL1ZXku9mvRajNTiaksHDiHi2mUpY"
const invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhZGUzMDc3YS05MjZlLTRiMGMtODRkZi01MTUyYzFlZTUxNGUifQ.eyJleHAiOjE2MTgxODU5NzAsImlhdCI6MTYxODE0OTk3MCwianRpIjoiZWNkZTM4ODUtMGY4My00MmI0LTgzMjYtZTVkZGIwMzJmMWJjIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjRiYTU0NzYxLWY5YTktNGRmMi1hYzQzLTcyMDU5NWRhZDk2YiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiOWJkYjA5NjYtNDA4NC00ZmFlLWE5NjMtZmRiMzc1MzAxODJiIiwic3RhdGVfY2hlY2tlciI6IjRDVlFtS1Fvd1JGQW1yNjF1VHE0Z3I4Z3lKQTBfYVcySWxodHVMdmM5VXcifQ.dyxXGCmHe1wMlO7zpeumxrVn9u6PkEU59C0hmYLe2OM"

func (t *TestJWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `{
		"keys":[
		   {
			  "use":"sig",
			  "kty":"RSA",
			  "kid":"public:7ef6c0b7-f7ff-42fb-9554-ae5aeb36a458",
			  "alg":"RS256",
			  "n":"nebBaHB4a6_f1dgFY7trjCdxRp0NlTz9_HoxSCENZpW0lyHpLWguhayK40060Pg5ttU4HssPuzyXIovHZe7cRsWmBhSgsI5rZK4DDkjvDvBC8_vWaX6QjYaNAJOPJln5hjnBQRTgeOXKr8KZhBVy_BeDW9Z37BjFnsw2mwnIYwYKjAcsKVoEUMpvDM7YTRVnWeMlOKpEp19cX4O8q2k_V9zbD8CdiubWc6G3vYKGaQQ4zJsu8cM5xfq0SY7GmZ3FxBDL_rkMvCY211lJAfIIfUk_fkm0Vb8ccpnhMQXEf_FqqpDI8fYXnBuPyCHL3-96r4SCmJVV-oG9__uWh2z85YrPZFxBuNtR8a6zTKsNg__CirE0wEBUR1vAQhGuuSPE74e32u4ps_J_55tCkw33be8Qlen_ItT8d3c0b_eO9friXM5DjoVuZUkkvIOw8v6dIKUw15T_p-z4zrzx0-L14QrqR0HtA0qtrVn7Y2e5rVhUWzfLkKfT0mLqm0ocTocKb0L6Ov9ONuQoxdBPFwY8zjbsbKm9J_xRWD5Shwwo4tB3i_cTdReG5r2J-BarwUMgR6oK3aLXbBtjjF1WH4IQknt72wE0WvTvEfKtAUSWgowtUxs9CcgMk05F1jg2NkeNy1fwgHFU_y83yxLeIq6D0FE9ZGSDHXsSP5YZ1FJBCLc",
			  "e":"AQAB"
		   },
		   {
			  "use":"sig",
			  "kty":"RSA",
			  "kid":"public:b1cbd43f-7bf7-4f80-a04f-6d1d0aae2253",
			  "alg":"RS256",
			  "n":"7h7pJIJfNPyToEOseGnVTr9lxW7ySO4Ft22laqIcNV-BDqUx0WkiuVkhqJhSdhmSlDWtCMLou4ii7ynr1ixT8Xjc-X8YD38ADQZE_3tQaxMm_vpcbZg30xvPXtXowPCDI2B2OfF4PX1vCMQMpeEKuoVcCat17iQMetQGXkTtdt8qWNK08OF0s2nvygw38PwdXCkqX-YZHrWMzg-bpVE7FHT4vp_Q7r-LjqIVEkWTptux6yXCrC53SJPEkZL6Q1AMpNf4h7i7NORvDhhP7EpnN_OrHDgH3KtyGiq7AkwlQEY8J-fQwWKPyv56SZPQmdTHe8kbyXdqU_yb_Oro1zevvNfuSbWu426ifBFDXXTLF389m4Ys7C9Eaa99QbJcg4r6YOXEWqX8BjCs3k_QbdwXtgr33pi5HBnwp_SLwrKU3q1YZdAfPHLkuYdK-A3sfk6bT8w6mmWw-IaYgJFYz4PqEiqYpLqe4MPdJuflu-AWzCS_FLEXks6fuNOSMG9XaLYbGHQkWDZeeQv-Uq8CyMdaoKVFVGhQQNnI-csS8S-JXxbOuj_6SywNZ_jz_-fx5d5TP0nXOXZgAT1D_LlZTaveVTtVoFd2qD8lA7TraSmOJP4zjtN8dmqe0VAWykJY3XmPAJKSOSeO6X1fp8EJ6fUw0q4YV3ZSkRRQOf18x3kEO8U",
			  "e":"AQAB"
		   }
		]
	 }`)
}

func TestWithFetch(t *testing.T) {
	testServerHandler := &TestJWKSHandler{}
	testServer := httptest.NewServer(testServerHandler)
	defer testServer.Close()
	fetchURL, _ := url.Parse(testServer.URL)
	jwks, jwksFetchErr := ResolveJWKS(fetchURL, nil)
	if jwksFetchErr != nil {
		t.Fatalf("expected the resolve to succeed but it failed with reason: %v", jwksFetchErr)
	}

	if validateErr := jwks.ReadSigned(validToken).Error(); validateErr != nil {
		t.Fatalf("expected token to validate but received an error: %v", validateErr)
	}

	if validateErr := jwks.ReadSigned(invalidToken).Error(); validateErr == nil {
		t.Fatalf("expected unknown JWK error but received: %v", validateErr)
	}

	// Let's tamper with the JWT
	newJWTParts := strings.Split(validToken, ".")
	tamperedContent := "the JWT content has been tampered with"
	tamperedBase64 := base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(tamperedContent))
	tamperedJWT := strings.Join([]string{newJWTParts[0], tamperedBase64, newJWTParts[2]}, ".")

	if validateErr := jwks.ReadSigned(tamperedJWT).Error(); validateErr != nil {
		if !strings.Contains(validateErr.Error(), "error in cryptographic primitive") {
			t.Fatalf("expected verification error but received: %v", validateErr)
		}
	}

	// for coverage only:

	validTokenWithheaderWithoutKid := base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(`{"alg":"RS256","typ" : "JWT"}`))
	withoutKid := strings.Join([]string{validTokenWithheaderWithoutKid, newJWTParts[1], newJWTParts[2]}, ".")
	// of course, none of the keys will validate this token because the header has been tampered with:
	if validateErr := jwks.ReadSigned(withoutKid).Error(); validateErr != nil {
		if validateErr.Error() != ErrSigningKeyNotKnown.Error() {
			t.Fatalf("expected verification error but received: %v", validateErr)
		}
	}

}
