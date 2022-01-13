//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const validrsa = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAx5piWVlE62NnZ0UzJ8Z6oKiKOC4dbOZ1HsNhIRtqkM+Oq4G+
25yq6P+0JU/Qvr9veOGEb3R/J9u8JBo+hv2i5X8OtgvP2V2pi6f1s6vK7L0+6uRb
4YTT/UdMshaVf97MgEqbq41Jf/cuvh+3AV0tZ1BpixZg4aXMKpY6HUP69lbsu27o
SUN1myMv7TSgZiV4CYs3l/gkEfpysBptWlcHRuw5RsB+C0RbjRtbJ/5VxmE/vd3M
lafd5t1WSpMb8yf0a84u5NFaXwZ7CweMfXeOddS0yb19ShSuW3PPRadruBM1mq15
js9GfagPxDS75Imcs+fA62lWvHxEujTGjYHxawIDAQABAoIBAH+sgLwmHa9zJfEo
klAe5NFe/QpydN/ziXbkAnzqzH9URC3wD+TpkWj4JoK3Sw635NWtasjf+3XDV9S/
9L7j/g5N91r6sziWcJykEsWaXXKQmm4lI6BdFjwsHyLKz1W7bZOiJXDWLu1rbrqu
DqEQuLoc9WXCKrYrFy0maoXNtfla/1p05kKN0bMigcnnyAQ+xBTwoyco4tkIz5se
IYxorz7qzXrkHQI+knz5BawmNe3ekoSaXUPoLoOR7TRTGsLteL5yukvWAi8S/0rE
gftC+PZCQpoQhSUYq7wXe7RowJ1f+kXb7HsSedOTfTSW1D/pUb/uW+CcRKig42ZI
I9H9TAECgYEA5XGBML6fJyWVqx64sHbUAjQsmQ0RwU6Zo7sqHIEPf6tYVYp7KtzK
KOfi8seOOL5FSy4pjCo11Dzyrh9bn45RNmtjSYTgOnVPSoCfuRNfOcpG+/wCHjYf
EjDvdrCpbg59kVUeaMeBDiyWAlM48HJAn8O7ez2U/iKQCyJmOIwFhSkCgYEA3rSz
Fi1NzqYWxWos4NBmg8iKcQ9SMkmPdgRLAs/WNnZJ8fdgJZwihevkXGytRGJEmav2
GMKRx1g6ey8fjXTQH9WM8X/kJC5fv8wLHnUCH/K3Mcp9CYwn7PFvSnBr4kQoc/el
bURhcF1+/opEC8vNX/Wk3zAG7Xs1PREXlH2SIHMCgYBV/3kgwBH/JkM25EjtO1yz
hsLAivmAruk/SUO7c1RP0fVF+qW3pxHOyztxLALOmeJ3D1JbSubqKf377Zz17O3b
q9yHDdrNjnKtxhAX2n7ytjJs+EQC9t4mf1kB761RpvTBqFnBhCWHHocLUA4jcW9v
cnmu86IIrwO2aKpPv4vCIQKBgHU9gY3qOazRSOmSlJ+hdmZn+2G7pBTvHsQNTIPl
cCrpqNHl3crO4GnKHkT9vVVjuiOAIKU2QNJFwzu4Og8Y8LvhizpTjoHxm9x3iV72
UDELcJ+YrqyJCTe2flUcy96o7Pbn50GXnwgtYD6WAW6IUszyn2ITgYIhu4wzZEt6
s6O7AoGAPTKbRA87L34LMlXyUBJma+etMARIP1zu8bXJ7hSJeMcog8zaLczN7ruT
pGAaLxggvtvuncMuTrG+cdmsR9SafSFKRS92NCxhOUonQ+NP6mLskIGzJZoQ5JvQ
qGzRVIDGbNkrVHM0IsAtHRpC0rYrtZY+9OwiraGcsqUMLwwQdCA=
-----END RSA PRIVATE KEY-----`

// RSA 2048 key encoded with PKCS#8
const validrsapkcs8 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwDtRl4McMhk4Q
UD723TzrAlYt59w73Qy6SZJLdaRKLjl0T8NY4NqnscIl/ZFTPh7SwqIF7D33riYB
sp60j6cV7ADh3fiIFtl6hYMAEpgqboJgTSlyeVX2jeyZCg25stv9AtvcT1B5ZVqa
+CY4feeUzp4LbVb4vY0nk1NHP95AJkJdcQaod44NXkc7AVb8h/atWx53AujXQsJY
0t84Z1+WCUhA+2D1ECdGJlkinwy/cBjABKtMe+4jN4z9vRXnIqHn8gpTsoBqSWRP
Ua2aNQzho/JnbDSWDu8Jzs+75llwzGxKFEIsAVpB5v63ir5lVejgf2Bs2JSCfn0W
BSqdxaLXAgMBAAECggEAUwEK3mVVMvB3CXXr2ZOAzwOxAb+Ys5iKEaHyGSWDqX2V
lOKuJM8OB5XlBOhBhc951L/yh3xT0twGCzLdZB9+FPXJjLOMIw0yx3L+yh/6Ibcs
PJ7kdZYDE1TiQVzeD7jlwqmAYqP6OuGwD/QCgQvLDPtEw/pu0KL9U7U/xA22iOM4
MpbCZgQUBYvIikUgUBnhxtq9CXf9+NZOKGrLUV7zNn2Abqyw5047hDpBRejfiOIw
a6oO3UykJyEKv4P6DmCSIZyBUbgeo+jvJ/4FsGYvCSqIYCdtvOaHqHI5w5cwgUy5
hwLuqXNG4X/sqqmvqICVB2efK+vrGmGiUFizkWDjsQKBgQDi4mbKNsa1sDMS/F4W
fx0kNlriPGAlS5+I1RgGXOh3sQ3D2hi2hDKym3KlPVXMmDBH+FqHt83uPXXSEpTo
d6jCyprw0kBgmfZCnWrWEMY1KGHPsPDO+Vx7nsrpgPA9EpftXibgTu1wQqNR+NOE
RwweniZhqOjGkjMZagMvS701UwKBgQDGpq3c9SRPJT6TD77akfrWs2nKjXsD9xzP
1mjXVN+ft6Om5olSANrH8nRsbND4BfYMfDbm/LscjM/qZ8ueC/KRZZEBoB9qy7R9
76JbqvCctFLorTy6RNIYno0JS5tivU93SOKDv1V/eXuZb3BVyixyhIaCjjjjnE7u
AP195YIH7QKBgElHVGm1XWKrQSO9rOnZLmFWyO3PEEKbdTBtmu/bLB4Ualy6YUb5
1aIIQPQLpl2JPfbQyPSSsgljgl1SMRQQKcqYQ4jKb46Dy5ziWPJAwrPCkizRekVv
Fqa6t9DJG06uZbF9ulKyS0/5xeQg2LgddlWhQMZEFsKjz6tCqTqqXLcPAoGBAIBY
FCCb6XeREpqlI6PHiQ7KH+GUAxSOxXiqiFYHKevhE8SzUak/kBp61SlwLJryDwQG
BNq8Eo/hkjtaED3ubivuOP+Z2nJ/Zf+voXAkQwybnK1jr8aQzETHu0t0I9JpiTwC
RQblyXFwpaB+VU+4LXtXkCgthyfXR0+SKDT84UQJAoGAPxwl93a6voIoTmuT1WJn
RdInSOS8J/13xjhlTHwpWBbUVVZDZyM+vGit0e3cTBSoDnF4/axKVF9veN3GF0RY
doAvTv0rhEQ8VmRQY9cZsaPMVg0q9UcSLLel9lJRRcEXa7v2aUpTNXVtar9csphX
5ybCksQRTS2adHuIdOa111g=
-----END PRIVATE KEY-----`

const invalidrsawithpubkey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx5piWVlE62NnZ0UzJ8Z6
oKiKOC4dbOZ1HsNhIRtqkM+Oq4G+25yq6P+0JU/Qvr9veOGEb3R/J9u8JBo+hv2i
5X8OtgvP2V2pi6f1s6vK7L0+6uRb4YTT/UdMshaVf97MgEqbq41Jf/cuvh+3AV0t
Z1BpixZg4aXMKpY6HUP69lbsu27oSUN1myMv7TSgZiV4CYs3l/gkEfpysBptWlcH
Ruw5RsB+C0RbjRtbJ/5VxmE/vd3Mlafd5t1WSpMb8yf0a84u5NFaXwZ7CweMfXeO
ddS0yb19ShSuW3PPRadruBM1mq15js9GfagPxDS75Imcs+fA62lWvHxEujTGjYHx
awIDAQAB
-----END PUBLIC KEY-----`

// RSA key with size 1024
const invalidrsasmallkey = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCYm7UwrM1fEsB+pOagKMRy1G9sX3A9MbC+a/G/jI+AERiNhCxa
dQUnicqs1ct78mTSH15+MJa39tYhwwh2yePUMAzP4yeiFluCAjxl8MQOqg2Q0i2+
juF72HekB1RoXj5To7j9iYL71F3+A7C+ewvMRDQZ6wsJladiM3xbx3swhwIDAQAB
AoGAKstvUgkDRmfxxxHjAoKsJC9iV5ej1+U5VQzcLAT0sMsagYTRE0TBf0bqqPED
MOzWTP4y91wUx93WSn1wwC75TjaRQ8YS9u8lFN/7ANo7zEucCSMlomEJgdvURmpS
JwsEyx03W+VCPTIz1WNFG04ICnLQvimOihU6nanDE8t4UoECQQDKFpLsipARIgVs
Zr+V7CgN33O7sduaZvakq9ymgHqd5L1B+USglCVXBCYUPTombT9Li8ecDZk69e6I
aWm1Pb9hAkEAwVHyTzI3Lu4LCx/T6mTOaJR1ads6XlFqTKUNBLd+PeL89cJhnigO
Ad0faD4hW61IF0lHjPemLo3c6nGeNPOA5wJAIHLNdpOtHEMlMcmxu4XmzItzjtC5
HSqpMbmyvT1l8tJWnTBEF7CR6k3tO1S1cJQcFKpGC8WXNANnIJokcgiPIQJAJBNs
yoaucZ2OhgbsfwNM2YtK1fRJUiyTT7ZFVaoAbwAbAKnDmcYTxxlCsStXAkq191J/
fbkBVBK5NS76vRrr5QJAGdcfJrnB9UIJQrTrXZWYSGCqkKSHhSrI4bLxrG2I+KlR
yAA/xDHlrlrCK260XFCi47rpAowtLwB1JbUwGr6x0Q==
-----END RSA PRIVATE KEY-----`

// RSA key with size 5120
const invalidrsalargekey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

const invalidkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG C# v1.6.1.0

lQOsBGGTOVkBCACbhVqCN55SElw1rZxI9LQDf91sU5FmrSybGh5r1xGV8rOhpKe+
eGirYVY3KeI6XUdZoJEIRtXtd6IJWn3msFRgO/MwkUQ4CibORSXPjCwHnseJmh5D
axgZbXpzjP90fW03R+sBqm2AvrUANaWIKIXk8bWWdK5yUhB7TubIxpOZKg/nLlIE
1j6+XdCWIfo56z0mpJWRASzZRGuncfvkHRz73YfA00FpflQykiUDi6+vDV7KTh49
7nkivRwyx5JcsAT3W1MCXNjCEXsdmdtNah3mN7SMbzSh3RF+IMaonxT4KM5nmEj/
wGKJ4xUPtKy7kgIPYP+LMOj7j1qCsndYWILzABEBAAH/AwMC5uUvFLMg8b9gVFGU
B1Ak38tCEBPtON9gSIxg9HX80WyMI8/MdfaisEsnFvy4X3UolhTlFJ9v3aqK1Zc8
JSkEw7cgY0NmFWDr6k8y8LhLN1ATjnKr9J9jzr8G9XvQfgaFbtcuFOF35ylQdeoL
IKKa8GqrXL75rolg+p/OSw52n/7fb17fDXLNyeGQ0g8wjIVTv+7vuvr9Z0kxfIgG
Y9oGIV/SeJvXjoWZWG3GbpTXx+ktmtwCY+tAlxJUt23OwWRfsnC9rS2DAsnJLlG2
r3Exfl80MUza1sQ/7u1svcHbFuZZOrJ1S9OjRQAWMsfQHFcav34Yrbb3aFweXLjs
iT9BJOMR4W/nyXvKAnMt/6vHKfO6kbxCtDFstH5qZAKbSceWX1Y6UaGimHXCnTYi
tlUMRNWlf6fFLdYBrRCh+MpLs5tSLc6NAYaQXTe3dJrjTRyzkxzYxeE/Y6Mii8KR
gF3Fu5OwkJ39jKdWZf17i/LUofgQHzW4ymuDMWcrqX1kZXPjD6WN8c8NmNCGvlsT
n1V6jPGb8tORIn8+CX+mCyJcxLpbG3ke90DIPnMol7WJ+3xV7J9peJqp0fY4jkmF
I96EUhY1HTZcy4SnhiPwKb8NDpdqwFx1qwytf7eM+65Cf+rj9Nh6ShVOjIfOT9gh
zEp0W0SFTU7p5af9ULnONCJABvRB8Gneosc6iwVclgHhTJcUzILRqNjcrJQu1j1v
oK9Ls+VANww4zEOqx8g+T/P4pHmGTIYTDErzyDmBw8aFD7fDl+kPUtanqC1oTvnJ
qZvoJ3JJ9Z2edW7Ulc1+BhnB8Cfs/jEJQHCngciUjW8yLUcVKdmFKkd9cajhoeQz
bJp6/t9dRUVXo2ulZzvdN93TWV66rTxHQAI4OBZKqbQLYm9iQGJvYi5jb22JARwE
EAECAAYFAmGTOVkACgkQSL3lExF3kQq7swf+Ndhd9iogkofT9ihMuMksoSDituN+
7hZY5zCj0UzCS8o2vHU+XJCRCpRlOc7gxl+44S60YmwqKtTjT5eqXCXrqa1XTyZz
xYpRfRjwnS6coQbdREQUvIgKapHII+b5gmnNhVX8niO11KyUHc29RWRiLFvMMcYO
urG06WshDewpqrBdq0MYBSSWO7myQLR5xEW6ld6CKkU0153LHgVdlGVIzrLM7sRo
NoHsidPbBIYv+aQxSVHxdKpFEpCHi9vckLSew+8LG5sDA/X3G4l9P3c1KusXP248
hfOiWo/4tMCN8XJpe0L+99ubcnHjQR7C8htFB4DnIA8KhMBSDdF/Vgp97g==
=8+cN
-----END PGP PRIVATE KEY BLOCK-----`

// Valid NIST P-256 key
const validecp256 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGhcmCI5F7BPMH4r3pWCpQdAsveErdU5DjvVQerErJuoAoGCCqGSM49
AwEHoUQDQgAE+9E3Qe+h25ofmz3Uo2T004Dfy49iX06MMbxf9rsGmLkOPrS0KYDl
1QMfFuSbrtf8wTWNT9HNxrW/Foz39mDhHw==
-----END EC PRIVATE KEY-----`

// Valid NIST P-384 key
const validecp384 = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDWIebxSdyJVber6J/l5MKnD0+VU0b7fcjY/RbIxuIsHLVIvwJrSohY
r3gJ/iJmIKGgBwYFK4EEACKhZANiAAQeoKZkkc1GafmIgp1tbNbMBjr2EdvX2dtT
lGhzHJgE0YB6TavazcYH1iOBNmX7/pInCopiyWbjF/5olrRKJMG6DQz80td++fYf
O4tr+Z3nyUgRGmf/fqYA4PSN30CuOMU=
-----END EC PRIVATE KEY-----`

// Valid NIST P-521 key
const validecp521 = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIA3JhHw1bhJyNnK80SPnvuIY9h++IaEhZcHR7SDHzMnFf72O5fF/RI
c+Dbd9lTfrP3Oy9BOC1opvXHvr5tqzV0MregBwYFK4EEACOhgYkDgYYABAALA20e
WqTf2chokKaCmxfnhs1lW70/J8slBzKBG6x3OjJX+yrpkDqe8zpkN08E+RZA8RSE
9TqbcXVHGtR6tj0IMgEFmybW+efJr4nz/iBvchGeIg1HtOX5V97z0bmwsCgQCD8L
4cNcYkeNJazrzzXte5Y5DK4Vm8QE4Jkux6FCw19QhQ==
-----END EC PRIVATE KEY-----`

// Valid NIST P-256 key encoded with PKCS#8
const validecpkcs8 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmKnLL81dCEYc6Spq
rFukFeTnU5JjtXfeNHAXJj3hYTahRANCAATjp4/Z4tUbZwUdId07GQeUdwLll4Br
YLP25Fk+mBY2G0lyKqjqLG5hxhimbEJH6j+lzg5tcYpQgzXtOJ66Zi0N
-----END PRIVATE KEY-----`

// We consider NIST P-224 below our standard.
const invalidecp224 = `-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHNpr8qVw+OcDrk/2aSqCGkWFKIjJSH0smeuloomgBwYFK4EEACGhPAM6
AARL+L9osuD8BYNr/aCkJiDHfDhxosXNOkcml4XPsnN88EjUqI2J7lMqmea5guwr
eu5jUfVoZzti6A==
-----END EC PRIVATE KEY-----`

// Go crypto library does not support non-NIST curves.
const invalidecunsupported = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJ6iubjORxWrzL3Z0i30s80TuLD+N6YTYVk49nzl+O1eoAcGBSuBBAAK
oUQDQgAEBadoFlV8pUuQ+WvRapCRJRGYk34h2nYkXW0BPdaCiPiEHawiVq9XXwG9
BuLB48bb77i0pTkVEefOuiNrbdBibw==
-----END EC PRIVATE KEY-----`

// PKCS#8 ED25519 key
const ed25519key = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIALEbo1EFnWFqBK/wC+hhypG/8hXEerwdNetAoFoFVdv
-----END PRIVATE KEY-----`

func pass(s string) PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}

func TestLoadECDSAPrivateKey(t *testing.T) {
	// Generate a valid keypair
	keys, err := GenerateKeyPair(pass("hello"))
	if err != nil {
		t.Fatal(err)
	}

	// Load the private key with the right password
	if _, err := LoadPrivateKey(keys.PrivateBytes, []byte("hello")); err != nil {
		t.Errorf("unexpected error decrypting key: %s", err)
	}

	// Try it with the wrong one
	if _, err := LoadPrivateKey(keys.PrivateBytes, []byte("wrong")); err == nil {
		t.Error("expected error decrypting key!")
	}

	// Try to decrypt garbage
	buf := [100]byte{}
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(buf[:], []byte("wrong")); err == nil {
		t.Error("expected error decrypting key!")
	}
}

func TestImportPrivateKey(t *testing.T) {
	testCases := []struct {
		fileName string
		pemData  string
		expected error
	}{
		// RSA tests
		{
			fileName: "validrsa.key",
			pemData:  validrsa,
			expected: nil,
		},
		{
			fileName: "validrsapkcs8.key",
			pemData:  validrsapkcs8,
			expected: nil,
		},
		{
			fileName: "invalidrsawithpubkey.key",
			pemData:  invalidrsawithpubkey,
			expected: errors.New("unsupported private key"),
		},
		{
			fileName: "invalidrsasmallkey.key",
			pemData:  invalidrsasmallkey,
			expected: errors.New("error validating rsa key: rsa key size too small, expected >= 2048"),
		},
		{
			fileName: "invalidrsalargekey.key",
			pemData:  invalidrsalargekey,
			expected: errors.New("error validating rsa key: rsa key size too large, expected <= 4096"),
		},
		// EC tests
		{
			fileName: "validecp256.key",
			pemData:  validecp256,
			expected: nil,
		},
		{
			fileName: "validecp384.key",
			pemData:  validecp384,
			expected: nil,
		},
		{
			fileName: "validecp521.key",
			pemData:  validecp521,
			expected: nil,
		},
		{
			fileName: "validecpkcs8.key",
			pemData:  validecpkcs8,
			expected: nil,
		},
		{
			fileName: "invalidecp224.key",
			pemData:  invalidecp224,
			expected: errors.New("error validating ecdsa key: unsupported ec curve, expected NIST P-256, P-384, or P-521"),
		},
		{
			fileName: "invalidecunsupported.key",
			pemData:  invalidecunsupported,
			expected: errors.New("error parsing ecdsa private key"),
		},
		// ED25519 tests
		{
			fileName: "ed25519.key",
			pemData:  ed25519key,
			expected: nil,
		},
		// Additional tests
		{
			fileName: "invalidkey.key",
			pemData:  invalidkey,
			expected: errors.New("invalid pem block"),
		},
	}
	td := t.TempDir()

	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			f := filepath.Join(td, tc.fileName)
			err := os.WriteFile(f, []byte(tc.pemData), 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ImportKeyPair(f, pass("hello"))
			if err == nil || tc.expected == nil {
				require.Equal(t, tc.expected, err)
			} else {
				require.Equal(t, tc.expected.Error(), err.Error())
			}
		})
	}
}
