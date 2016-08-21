package digest_auth_client

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

type AuthorizationHeader struct {
	Algorithm string // unquoted
	Body      string // request value
	Cnonce    string // quoted
	Method    string // request value
	Nc        string // unquoted
	Opaque    string // quoted
	Qop       string // unquoted
	Realm     string // quoted
	Resposne  string // quoted
	Uri       string // quoted
	Userhash  string // quoted
	Username  string // quoted
	Username_ string // quoted
}

func (ah *AuthorizationHeader) ComputeResponse() AuthorizationHeader {
	return *ah
}

func (ah *AuthorizationHeader) ComputeA1() AuthorizationHeader {
	return *ah
}

func (ah *AuthorizationHeader) ComputeA2() (s string) {

	if strings.Compare(ah.Qop, "auth") == 0 || strings.Compare(ah.Qop, "") == 0 {
		s = fmt.Sprintf("%s:%s", ah.Method, ah.Uri)
	}

	if strings.Compare(ah.Qop, "auth-int") == 0 {
		s = fmt.Sprintf("%s:%s", s, ah.Hash(ah.Body))
	}

	return
}

func (ah *AuthorizationHeader) Hash(a string) (s string) {

	var h hash.Hash

	if strings.Compare(ah.Algorithm, "MD5") == 0 {
		h = md5.New()
	} else if strings.Compare(ah.Algorithm, "SHA-256") == 0 {
		h = sha256.New()
	}

	io.WriteString(h, a)
	s = string(h.Sum(nil))

	return
}
