package digest_auth_client

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type DigestRequest struct {
	Body     string
	Method   string
	Password string
	Uri      string
	Username string
}

func (dr *DigestRequest) NewRequest(
	username string, password string, method string, uri string, body string) DigestRequest {

	dr.Body = body
	dr.Method = method
	dr.Password = password
	dr.Uri = uri
	dr.Body = body

	return *dr
}

func (dr *DigestRequest) Execute() (*http.Response, error) {

	req, err := http.NewRequest(dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body)))
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)

	if resp.StatusCode == 401 {
		return dr.executeDigest(resp)
	}

	return resp, err
}

func (dr *DigestRequest) executeDigest(resp *http.Response) (*http.Response, error) {

	wwwAuthenticateHeaderString := resp.Header.Get("WWW-Authenticate")

	if strings.Compare(wwwAuthenticateHeaderString, "") == 0 {
		return nil, fmt.Errorf("Failed to get WWW-Authenticate header, please check your server configuration.")
	}

	wwwAuthenticateHeader, err = newWwwAuthenticateHeader(wwwAuthenticateHeaderString)

	return nil, nil
}
