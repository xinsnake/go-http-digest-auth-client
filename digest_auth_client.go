package digest_auth_client

import (
	"bytes"
	"fmt"
	"net/http"
	"time"
)

var (
	auth *authorization
	wa   *wwwAuthenticate
)

type DigestRequest struct {
	Body     string
	Method   string
	Password string
	Uri      string
	Username string
}

func NewRequest(username string, password string, method string, uri string, body string) DigestRequest {

	dr := DigestRequest{}

	dr.Body = body
	dr.Method = method
	dr.Password = password
	dr.Uri = uri
	dr.Username = username

	return dr
}

func (dr *DigestRequest) Execute() (resp *http.Response, err error) {

	if auth == nil {
		var req *http.Request
		if req, err = http.NewRequest(dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
			return nil, err
		}

		client := &http.Client{
			Timeout: 30 * time.Second,
		}
		resp, err = client.Do(req)

		if resp.StatusCode == 401 {
			return dr.executeNewDigest(resp)
		}
		return
	}

	return dr.executeExistingDigest()
}

func (dr *DigestRequest) executeNewDigest(resp *http.Response) (*http.Response, error) {

	waString := resp.Header.Get("WWW-Authenticate")
	if waString == "" {
		return nil, fmt.Errorf("Failed to get WWW-Authenticate header, please check your server configuration.")
	}
	wa = newWwwAuthenticate(waString)

	authString := newAuthorization(dr).toString()

	return dr.executeRequest(authString)
}

func (dr *DigestRequest) executeExistingDigest() (*http.Response, error) {
	var err error

	if auth, err = auth.refreshAuthorization(dr); err != nil {
		return nil, err
	}

	authString := auth.toString()
	return dr.executeRequest(authString)
}

func (dr *DigestRequest) executeRequest(authString string) (*http.Response, error) {
	var (
		err error
		req *http.Request
	)

	if req, err = http.NewRequest(dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
		return nil, err
	}

	fmt.Printf("AUTHSTRING: %s\n\n", authString)
	req.Header.Add("Authorization", authString)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return client.Do(req)
}
