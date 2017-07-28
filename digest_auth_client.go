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
	Auth     *authorization
	Wa       *wwwAuthenticate
}

type DigestTransport struct {
	Password string
	Username string
}

// NewRequest creates a new DigestRequest object
func NewRequest(username, password, method, uri, body string) DigestRequest {
	dr := DigestRequest{}
	dr.UpdateRequest(username, password, method, uri, body)
	return dr
}

// NewTransport creates a new DigestTransport object
func NewTransport(username, password string) DigestTransport {
	dt := DigestTransport{}
	dt.Password = password
	dt.Username = username
	return dt
}

// UpdateRequest is called when you want to reuse an existing
//  DigestRequest connection with new request information
func (dr *DigestRequest) UpdateRequest(username, password, method, uri, body string) *DigestRequest {
	dr.Body = body
	dr.Method = method
	dr.Password = password
	dr.Uri = uri
	dr.Username = username
	return dr
}

// RoundTrip implements the http.RoundTripper interface
func (dt *DigestTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	username := dt.Username
	password := dt.Password
	method := req.Method
	uri := req.URL.String()

	var body string
	if req.Body != nil {
		buf := new(bytes.Buffer)
		buf.ReadFrom(req.Body)
		body = buf.String()
	}

	dr := NewRequest(username, password, method, uri, body)
	return dr.Execute()
}

// Execute initialise the request and get a response
func (dr *DigestRequest) Execute() (resp *http.Response, err error) {

	if dr.Auth != nil {
		return dr.executeExistingDigest()
	}

	var req *http.Request
	if req, err = http.NewRequest(dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	if resp, err = client.Do(req); err != nil {
		return nil, err
	}

	if resp.StatusCode == 401 {
		return dr.executeNewDigest(resp)
	}

	return resp, nil
}

func (dr *DigestRequest) executeNewDigest(resp *http.Response) (resp2 *http.Response, err error) {
	var (
		auth     *authorization
		wa       *wwwAuthenticate
		waString string
	)

	if waString = resp.Header.Get("WWW-Authenticate"); waString == "" {
		return nil, fmt.Errorf("failed to get WWW-Authenticate header, please check your server configuration")
	}
	wa = newWwwAuthenticate(waString)
	dr.Wa = wa

	if auth, err = newAuthorization(dr); err != nil {
		return nil, err
	}

	if resp2, err = dr.executeRequest(auth.toString()); err != nil {
		return nil, err
	}

	dr.Auth = auth
	return resp2, nil
}

func (dr *DigestRequest) executeExistingDigest() (resp *http.Response, err error) {
	var auth *authorization

	if auth, err = dr.Auth.refreshAuthorization(dr); err != nil {
		return nil, err
	}
	dr.Auth = auth

	return dr.executeRequest(dr.Auth.toString())
}

func (dr *DigestRequest) executeRequest(authString string) (resp *http.Response, err error) {
	var req *http.Request

	if req, err = http.NewRequest(dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", authString)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return client.Do(req)
}
