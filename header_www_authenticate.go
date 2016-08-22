package digest_auth_client

type wwwAuthenticate struct {
	Algorithm string // unquoted
	Domain    string // quoted
	Nonce     string // quoted
	Opaque    string // quoted
	Qop       string // quoted
	Realm     string // quoted
	Stale     bool   // unquoted
	charset   string // quoted
	userhash  bool   // quoted
}

func newWwwAuthenticateHeader(newWwwAuthenticateHeaderString string) (*wwwAuthenticate, error) {

}
