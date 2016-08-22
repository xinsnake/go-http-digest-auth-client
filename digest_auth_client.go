package digest_auth_client

import (
	"bytes"
	"fmt"
	"net/http"
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

func (dr *DigestRequest) Execute() (resp *http.Response, err error) {
	var req *http.Request
	if req, err = http.NewRequest(dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err = client.Do(req)

	if resp.StatusCode == 401 {
		return dr.executeDigest(resp)
	}

	return
}

func (dr *DigestRequest) executeDigest(resp *http.Response) (*http.Response, error) {
	var (
		err  error
		wa   *wwwAuthenticate
		auth *authorization
		req  *http.Request
	)

	waString := resp.Header.Get("WWW-Authenticate")
	if waString == "" {
		return nil, fmt.Errorf("Failed to get WWW-Authenticate header, please check your server configuration.")
	}

	if wa, err = newWAHeader(waString); err != nil {
		return nil, err
	}

	if auth, err = newAuthorization(wa, dr); err != nil {
		return nil, err
	}

	authString := fmt.Sprintf("Digest %s", auth.toString())
	if req, err = http.NewRequest(dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", authString)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return client.Do(req)
}
