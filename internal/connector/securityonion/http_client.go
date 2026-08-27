package securityonion

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"time"
)

type HTTPClient struct {
	config      Config
	credentials CredentialSource
	baseURL     *url.URL
	client      *http.Client
}

func NewHTTPClient(config Config, credentials CredentialSource, roots *x509.CertPool) (*HTTPClient, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if nilPort(credentials) || roots == nil {
		return nil, invalid("securityonion_http_configuration_invalid")
	}
	baseURL, _ := url.Parse(config.Endpoint)
	duration := time.Duration(config.HardLimits.MaximumDurationMillis) * time.Millisecond
	dialer := &net.Dialer{Timeout: duration}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext,
		DisableCompression: true, DisableKeepAlives: true, MaxConnsPerHost: 1, ResponseHeaderTimeout: duration,
		TLSClientConfig: &tls.Config{ // #nosec G402 -- TLS 1.3 and normal chain verification are mandatory.
			MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: baseURL.Hostname()}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect denied")
	}, Timeout: duration}
	return &HTTPClient{config: cloneConfig(config), credentials: credentials, baseURL: baseURL, client: client}, nil
}

func (client *HTTPClient) transportDigest(response *http.Response) (string, error) {
	if response == nil || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return "", denied("securityonion_tls_identity_missing")
	}
	spki := sha256.Sum256(response.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	digest := "sha256:" + hex.EncodeToString(spki[:])
	if digest != client.config.TransportIdentityDigest {
		return "", conflict("securityonion_tls_identity_mismatch")
	}
	return digest, nil
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
