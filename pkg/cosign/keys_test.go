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
	"os"
	"testing"
)

const validrsa1 = `-----BEGIN RSA PRIVATE KEY-----
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

const invalidrsa2 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx5piWVlE62NnZ0UzJ8Z6
oKiKOC4dbOZ1HsNhIRtqkM+Oq4G+25yq6P+0JU/Qvr9veOGEb3R/J9u8JBo+hv2i
5X8OtgvP2V2pi6f1s6vK7L0+6uRb4YTT/UdMshaVf97MgEqbq41Jf/cuvh+3AV0t
Z1BpixZg4aXMKpY6HUP69lbsu27oSUN1myMv7TSgZiV4CYs3l/gkEfpysBptWlcH
Ruw5RsB+C0RbjRtbJ/5VxmE/vd3Mlafd5t1WSpMb8yf0a84u5NFaXwZ7CweMfXeO
ddS0yb19ShSuW3PPRadruBM1mq15js9GfagPxDS75Imcs+fA62lWvHxEujTGjYHx
awIDAQAB
-----END PUBLIC KEY-----`

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

const validec = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGhcmCI5F7BPMH4r3pWCpQdAsveErdU5DjvVQerErJuoAoGCCqGSM49
AwEHoUQDQgAE+9E3Qe+h25ofmz3Uo2T004Dfy49iX06MMbxf9rsGmLkOPrS0KYDl
1QMfFuSbrtf8wTWNT9HNxrW/Foz39mDhHw==
-----END EC PRIVATE KEY-----`

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

	err := os.WriteFile("validrsa1.key", []byte(validrsa1), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ImportKeyPair("validrsa1.key", pass("hello"))
	if err != nil {
		t.Errorf("unexpected error importing key: %s", err)
	}

	os.Remove("validrsa1.key")

	err = os.WriteFile("ed25519.key", []byte(ed25519key), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ImportKeyPair("ed25519.key", pass("hello"))
	if err != nil {
		t.Errorf("unexpected error importing key: %s", err)
	}

	os.Remove("ed25519.key")

}
