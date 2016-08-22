package digest_auth_client

type wwwAuthenticate struct {
	Algorithm string // unquoted
	Domain    string // quoted
	Nonce     string // quoted
	Opaque    string // quoted
	Qop       string // quoted
	Realm     string // quoted
	Stale     bool   // unquoted
	Charset   string // quoted
	Userhash  bool   // quoted
}

func newWAHeader(newWAHeaderString string) (*wwwAuthenticate, error) {
	return nil, nil
}

func (wa *wwwAuthenticate) fromString(s string) (*wwwAuthenticate, error) {
	return wa, nil
}
