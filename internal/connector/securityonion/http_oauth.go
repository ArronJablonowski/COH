package securityonion

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumTokenResponseBytes = 65536

type oauthToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func (client *HTTPClient) withToken(ctx context.Context, binding CallBinding,
	consumer func(string, CallReceipt) error) (CallReceipt, error) {
	var tokenReceipt CallReceipt
	leaseDigest, err := client.credentials.Use(ctx, binding, func(credential ClientCredential) error {
		if !tokenPattern.MatchString(credential.ClientID) || len(credential.Secret) == 0 || len(credential.Secret) > 4096 {
			return denied("securityonion_credential_invalid")
		}
		token, receipt, err := client.exchangeToken(ctx, binding, credential)
		if err != nil {
			return err
		}
		tokenReceipt = receipt
		defer zeroString(&token.AccessToken)
		return consumer(token.AccessToken, receipt)
	})
	if err != nil {
		return CallReceipt{}, mapHTTPError(err)
	}
	if !digestPattern.MatchString(leaseDigest) {
		return CallReceipt{}, denied("securityonion_lease_receipt_invalid")
	}
	tokenReceipt.LeaseDecisionDigest = leaseDigest
	return tokenReceipt, nil
}

func (client *HTTPClient) exchangeToken(ctx context.Context, binding CallBinding,
	credential ClientCredential) (oauthToken, CallReceipt, error) {
	form := url.Values{"grant_type": []string{"client_credentials"}}
	requestURL := *client.baseURL
	requestURL.Path, requestURL.RawQuery = "/oauth2/token", ""
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return oauthToken{}, CallReceipt{}, invalid("securityonion_token_request_invalid")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(credential.ClientID, string(credential.Secret))
	requestDigest := hash("COH-SECURITY-ONION-TOKEN-REQUEST-V1\x00", mustJSONBytes(struct {
		Binding    CallBinding
		Credential string
		Form       string
	}{binding, client.config.CredentialReference, form.Encode()}))
	response, err := client.client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return oauthToken{}, CallReceipt{}, err
	}
	defer response.Body.Close()
	transportDigest, err := client.transportDigest(response)
	if err != nil {
		return oauthToken{}, CallReceipt{}, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumTokenResponseBytes+1))
	if err != nil || len(body) > maximumTokenResponseBytes {
		return oauthToken{}, CallReceipt{}, denied("securityonion_token_response_oversized")
	}
	defer zeroBytes(body)
	responseDigest := hash("COH-SECURITY-ONION-TOKEN-RESPONSE-V1\x00", body)
	receipt := CallReceipt{RequestDigest: requestDigest, ResponseDigest: responseDigest,
		TransportDigest: transportDigest}
	if response.StatusCode != http.StatusOK || !jsonMediaType(response.Header.Get("Content-Type")) {
		return oauthToken{}, receipt, denied("securityonion_authentication_denied")
	}
	canonical, err := domaincontract.Canonicalize(body)
	if err != nil {
		return oauthToken{}, receipt, denied("securityonion_token_response_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var token oauthToken
	if decoder.Decode(&token) != nil || !validBearer(token.AccessToken) || !strings.EqualFold(token.TokenType, "bearer") ||
		token.Scope != "" || token.ExpiresIn <= 0 || token.ExpiresIn > int64((2*time.Hour)/time.Second) {
		return oauthToken{}, receipt, denied("securityonion_token_response_invalid")
	}
	return token, receipt, nil
}

func validBearer(value string) bool {
	if len(value) < 16 || len(value) > 16384 {
		return false
	}
	for _, current := range []byte(value) {
		if current < 0x21 || current > 0x7e {
			return false
		}
	}
	return true
}

func zeroString(value *string) {
	if value != nil {
		*value = ""
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func jsonMediaType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}
