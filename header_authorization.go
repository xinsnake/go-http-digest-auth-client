package digest_auth_client

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"regexp"
	"time"
)

type authorization struct {
	Algorithm string // unquoted
	Cnonce    string // quoted
	Nc        int    // unquoted
	Nonce     string // quoted
	Opaque    string // quoted
	Qop       string // unquoted
	Realm     string // quoted
	Response  string // quoted
	Uri       string // quoted
	Userhash  bool   // quoted
	Username  string // quoted
	Username_ string // quoted
}

func newAuthorization(wa *wwwAuthenticate, dr *DigestRequest) (*authorization, error) {

	auth := authorization{
		Algorithm: wa.Algorithm,
		Cnonce:    "",
		Nc:        1, // TODO
		Nonce:     wa.Nonce,
		Opaque:    wa.Opaque,
		Qop:       "",
		Realm:     wa.Realm,
		Response:  "",
		Uri:       dr.Uri,
		Userhash:  wa.Userhash,
		Username:  dr.Username,
		Username_: "", // TODO
	}

	auth.Cnonce = auth.hash(fmt.Sprintf("%d:%s:dfjosbn3kjd01", time.Now().UnixNano(), dr.Username))

	if auth.Userhash {
		auth.Username = auth.hash(fmt.Sprintf("%s:%s", auth.Username, auth.Realm))
	}

	auth.Response = auth.computeResponse(wa, dr)

	return &auth, nil
}

func (ah *authorization) computeResponse(wa *wwwAuthenticate, dr *DigestRequest) (s string) {

	kdSecret := ah.hash(ah.computeA1(wa, dr))
	kdData := fmt.Sprintf("%s:%s:%s:%s:%s", ah.Nonce, ah.Nc, ah.Cnonce, ah.Qop, ah.hash(ah.computeA2(wa, dr)))

	return ah.hash(fmt.Sprintf("%s:%s", kdSecret, kdData))
}

func (ah *authorization) computeA1(wa *wwwAuthenticate, dr *DigestRequest) string {

	if ah.Algorithm == "" || ah.Algorithm == "MD5" || ah.Algorithm == "SHA-256" {
		return fmt.Sprintf("%s:%s:%s", ah.Username, ah.Realm, dr.Password)
	}

	if ah.Algorithm == "MD5-sess" || ah.Algorithm == "SHA-256-sess" {
		upHash := ah.hash(fmt.Sprintf("%s:%s:%s", ah.Username, ah.Realm, dr.Password))
		return fmt.Sprintf("%s:%s:%s", upHash, ah.Nc)
	}

	return ""
}

func (ah *authorization) computeA2(wa *wwwAuthenticate, dr *DigestRequest) string {

	if matched, _ := regexp.MatchString("auth-int", wa.Qop); matched {
		ah.Qop = "auth-int"
		return fmt.Sprintf("%s:%s:%s", dr.Method, ah.Uri, ah.hash(dr.Body))
	}

	if ah.Qop == "auth" || ah.Qop == "" {
		ah.Qop = "auth"
		return fmt.Sprintf("%s:%s", dr.Method, ah.Uri)
	}

	return ""
}

func (ah *authorization) hash(a string) (s string) {

	var h hash.Hash

	if ah.Algorithm == "MD5" || ah.Algorithm == "MD5-sess" {
		h = md5.New()
	} else if ah.Algorithm == "SHA-256" || ah.Algorithm == "SHA-256-sess" {
		h = sha256.New()
	}

	io.WriteString(h, a)
	s = string(h.Sum(nil))

	return
}

func (ah *authorization) toString() string {
	return ""
}
