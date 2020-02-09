package digest_auth_client

import "testing"

func TestHash(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		expRes    string
	}{
		{
			name:      "empty algorithm",
			algorithm: "",
			expRes:    "1a79a4d60de6718e8e5b326e338ae533",
		},
		{
			name:      "MD5 algorithm",
			algorithm: "MD5",
			expRes:    "1a79a4d60de6718e8e5b326e338ae533",
		},
		{
			name:      "MD5-sess algorithm",
			algorithm: "MD5",
			expRes:    "1a79a4d60de6718e8e5b326e338ae533",
		},
		{
			name:      "SHA256 algorithm",
			algorithm: "SHA-256",
			expRes:    "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
		},
		{
			name:      "SHA256-sess algorithm",
			algorithm: "SHA-256",
			expRes:    "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
		},
		{
			name:      "md5 algorithm",
			algorithm: "md5",
			expRes:    "1a79a4d60de6718e8e5b326e338ae533",
		},
		{
			name:      "unknown algorithm",
			algorithm: "unknown",
			expRes:    "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ah := &authorization{Algorithm: tc.algorithm}
			res := ah.hash("example")
			if res != tc.expRes {
				t.Errorf("got: %q, want: %q", res, tc.expRes)
			}
		})
	}
}

func TestComputeA1(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		expRes    string
	}{
		{
			name:      "empty algorithm",
			algorithm: "",
			expRes:    "username:realm:secret",
		},
		{
			name:      "MD5 algorithm",
			algorithm: "MD5",
			expRes:    "username:realm:secret",
		},
		{
			name:      "MD5-sess algorithm",
			algorithm: "MD5",
			expRes:    "username:realm:secret",
		},
		{
			name:      "SHA256 algorithm",
			algorithm: "SHA-256",
			expRes:    "username:realm:secret",
		},
		{
			name:      "SHA256-sess algorithm",
			algorithm: "SHA-256",
			expRes:    "username:realm:secret",
		},
		{
			name:      "md5 algorithm",
			algorithm: "md5",
			expRes:    "username:realm:secret",
		},
		{
			name:      "unknown algorithm",
			algorithm: "unknown",
			expRes:    "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dr := &DigestRequest{Password: "secret"}
			ah := &authorization{
				Algorithm: tc.algorithm,
				Nonce:     "nonce",
				Cnonce:    "cnonce",
				Username:  "username",
				Realm:     "realm",
			}
			res := ah.computeA1(dr)
			if res != tc.expRes {
				t.Errorf("got: %q, want: %q", res, tc.expRes)
			}
		})
	}
}

func TestComputeA2(t *testing.T) {
	testCases := []struct {
		name       string
		qop        string
		expRes     string
		expAuthQop string
	}{
		{
			name:       "empty qop",
			qop:        "",
			expRes:     "method:uri",
			expAuthQop: "auth",
		},
		{
			name:       "qop is auth",
			qop:        "auth",
			expRes:     "method:uri",
			expAuthQop: "auth",
		},
		{
			name:       "qop is auth-int",
			qop:        "qop is auth-int",
			expRes:     "method:uri:841a2d689ad86bd1611447453c22c6fc",
			expAuthQop: "auth-int",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dr := &DigestRequest{
				Method: "method",
				Body:   "body",
				Wa: &wwwAuthenticate{
					Qop: tc.qop,
				},
			}
			ah := &authorization{
				Algorithm: "MD5",
				Nonce:     "nonce",
				Cnonce:    "cnonce",
				Username:  "username",
				Realm:     "realm",
				URI:       "uri",
				Qop:       tc.qop,
			}
			res := ah.computeA2(dr)
			if res != tc.expRes {
				t.Errorf("wrong result, got: %q, want: %q", res, tc.expRes)
			}
			if ah.Qop != tc.expAuthQop {
				t.Errorf("wrong qop, got: %q, want: %q", ah.Qop, tc.expAuthQop)
			}
		})
	}
}
