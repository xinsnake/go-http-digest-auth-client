package digest_auth_client

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

type authorizationHeader struct {
	Algorithm string // unquoted
	Cnonce    string // quoted
	Nc        string // unquoted
	Nounce    string // quoted
	Opaque    string // quoted
	Qop       string // unquoted
	Realm     string // quoted
	Resposne  string // quoted
	Uri       string // quoted
	Userhash  string // quoted
	Username  string // quoted
	Username_ string // quoted
}

func (ah *authorizationHeader) ComputeResponse() authorizationHeader {
	return *ah
}

func (ah *authorizationHeader) ComputeA1(password string) (s string) {

	if strings.Compare(ah.Algorithm, "") == 0 ||
		strings.Compare(ah.Algorithm, "MD5") == 0 ||
		strings.Compare(ah.Algorithm, "SHA-256") == 0 {
		s = fmt.Sprintf("%s:%s:%s", ah.Username, ah.Realm, password)
	}

	if strings.Compare(ah.Algorithm, "MD5-sess") ||
		strings.Compare(ah.Algorithm, "SHA-256-sess") {
		upHash := ah.Hash(fmt.Sprintf("%s:%s:%s", ah.Username, ah.Realm, password))
		s = fmt.Sprintf("%s:%s:%s", upHash, ah.Nc)
	}

	return
}

func (ah *authorizationHeader) ComputeA2() (s string) {

	if strings.Compare(ah.Qop, "auth") == 0 || strings.Compare(ah.Qop, "") == 0 {
		s = fmt.Sprintf("%s:%s", ah.Method, ah.Uri)
	}

	if strings.Compare(ah.Qop, "auth-int") == 0 {
		s = fmt.Sprintf("%s:%s", s, ah.Hash(ah.Body))
	}

	return
}

func (ah *authorizationHeader) Hash(a string) (s string) {

	var h hash.Hash

	if strings.Compare(ah.Algorithm, "MD5") == 0 ||
		strings.Compare(ah.Algorithm, "MD5-sess") == 0 {
		h = md5.New()
	} else if strings.Compare(ah.Algorithm, "SHA-256") == 0 ||
		strings.Compare(ah.Algorithm, "SHA-256-sess") == 0 {
		h = sha256.New()
	}

	io.WriteString(h, a)
	s = string(h.Sum(nil))

	return
}
