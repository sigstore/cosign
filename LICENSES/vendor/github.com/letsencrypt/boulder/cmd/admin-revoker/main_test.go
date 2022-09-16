package notmain

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/ra"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	ira "github.com/letsencrypt/boulder/test/inmem/ra"
	isa "github.com/letsencrypt/boulder/test/inmem/sa"
	"github.com/letsencrypt/boulder/test/vars"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type mockCA struct {
	mocks.MockCA
}

func (ca *mockCA) GenerateOCSP(context.Context, *capb.GenerateOCSPRequest, ...grpc.CallOption) (*capb.OCSPResponse, error) {
	return &capb.OCSPResponse{Response: []byte("fakeocspbytes")}, nil
}

type mockPurger struct{}

func (mp *mockPurger) Purge(context.Context, *akamaipb.PurgeRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func TestRevokeBatch(t *testing.T) {
	log := blog.UseMock()
	fc := clock.NewFake()
	// Set to some non-zero time.
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	dbMap, err := sa.NewDbMap(vars.DBConnSA, sa.DbSettings{})
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	rocspIssuers, err := rocsp_config.LoadIssuers(map[string]int{
		"../../test/hierarchy/int-r3.cert.pem": 102,
	})
	test.AssertNotError(t, err, "error loading issuers")
	ssa, err := sa.NewSQLStorageAuthority(dbMap, dbMap, rocspIssuers, fc, log, metrics.NoopRegisterer, 1)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	defer test.ResetSATestDatabase(t)
	reg := satest.CreateWorkingRegistration(t, isa.SA{Impl: ssa})

	issuer, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "Failed to load test issuer")
	signer, err := test.LoadSigner("../../test/hierarchy/int-r3.key.pem")
	test.AssertNotError(t, err, "failed to load test signer")

	ra := ra.NewRegistrationAuthorityImpl(fc,
		log,
		metrics.NoopRegisterer,
		1,
		goodkey.KeyPolicy{},
		100,
		true,
		300*24*time.Hour,
		7*24*time.Hour,
		nil,
		nil,
		0,
		nil,
		&mockPurger{},
		[]*issuance.Certificate{issuer},
	)
	ra.SA = isa.SA{Impl: ssa}
	ra.CA = &mockCA{}
	rac := ira.RA{Impl: ra}

	r := revoker{
		rac:   rac,
		sac:   isa.SA{Impl: ssa},
		dbMap: dbMap,
		clk:   fc,
		log:   log,
	}

	serialFile, err := ioutil.TempFile("", "serials")
	test.AssertNotError(t, err, "failed to open temp file")
	defer os.Remove(serialFile.Name())

	serials := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	for _, serial := range serials {
		template := &x509.Certificate{
			SerialNumber: serial,
			DNSNames:     []string{"asd"},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer.Certificate, signer.Public(), signer)
		test.AssertNotError(t, err, "failed to generate test cert")
		_, err = ssa.AddPrecertificate(context.Background(), &sapb.AddCertificateRequest{
			Der:      der,
			RegID:    reg.Id,
			Issued:   time.Now().UnixNano(),
			IssuerID: 1,
		})
		test.AssertNotError(t, err, "failed to add test cert")
		_, err = ssa.AddCertificate(context.Background(), &sapb.AddCertificateRequest{
			Der:    der,
			RegID:  reg.Id,
			Issued: time.Now().UnixNano(),
		})
		test.AssertNotError(t, err, "failed to add test cert")
		_, err = serialFile.WriteString(fmt.Sprintf("%s\n", core.SerialToString(serial)))
		test.AssertNotError(t, err, "failed to write serial to temp file")
	}

	err = r.revokeBySerialBatch(context.Background(), serialFile.Name(), 0, 2)
	test.AssertNotError(t, err, "revokeBatch failed")

	for _, serial := range serials {
		status, err := ssa.GetCertificateStatus(context.Background(), &sapb.Serial{Serial: core.SerialToString(serial)})
		test.AssertNotError(t, err, "failed to retrieve certificate status")
		test.AssertEquals(t, core.OCSPStatus(status.Status), core.OCSPStatusRevoked)
	}
}

func TestBlockAndRevokeByPrivateKey(t *testing.T) {
	testCtx := setup(t)
	defer testCtx.cleanUp()

	// Unique keys for each of our test certificates.
	testKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 1")
	testKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 2")
	testKey3, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 3")

	// Write the contents of testKey1 to a temp file.
	testKey1File, err := ioutil.TempFile("", "key")
	test.AssertNotError(t, err, "failed to create temp file")
	der, err := x509.MarshalPKCS8PrivateKey(testKey1)
	test.AssertNotError(t, err, "failed to marshal testKey1 to DER")
	err = pem.Encode(testKey1File,
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		},
	)
	test.AssertNotError(t, err, "failed to PEM encode test key 1")
	test.AssertNotError(t, err, "failed to write to temp file")
	defer os.Remove(testKey1File.Name())

	// Unique JWKs so we can register each of our entries.
	testJWK1 := `{"kty":"RSA","n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ","e":"AQAB"}`
	testJWK2 := `{"kty":"RSA","n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw","e":"AQAB"}`
	testJWK3 := `{"kty":"RSA","n":"uTQER6vUA1RDixS8xsfCRiKUNGRzzyIK0MhbS2biClShbb0hSx2mPP7gBvis2lizZ9r-y9hL57kNQoYCKndOBg0FYsHzrQ3O9AcoV1z2Mq-XhHZbFrVYaXI0M3oY9BJCWog0dyi3XC0x8AxC1npd1U61cToHx-3uSvgZOuQA5ffEn5L38Dz1Ti7OV3E4XahnRJvejadUmTkki7phLBUXm5MnnyFm0CPpf6ApV7zhLjN5W-nV0WL17o7v8aDgV_t9nIdi1Y26c3PlCEtiVHZcebDH5F1Deta3oLLg9-g6rWnTqPbY3knffhp4m0scLD6e33k8MtzxDX_D7vHsg0_X1w","e":"AQAB"}`
	testJWK4 := `{"kty":"RSA","n":"qih-cx32M0wq8MhhN-kBi2xPE-wnw4_iIg1hWO5wtBfpt2PtWikgPuBT6jvK9oyQwAWbSfwqlVZatMPY_-3IyytMNb9R9OatNr6o5HROBoyZnDVSiC4iMRd7bRl_PWSIqj_MjhPNa9cYwBdW5iC3jM5TaOgmp0-YFm4tkLGirDcIBDkQYlnv9NKILvuwqkapZ7XBixeqdCcikUcTRXW5unqygO6bnapzw-YtPsPPlj4Ih3SvK4doyziPV96U8u5lbNYYEzYiW1mbu9n0KLvmKDikGcdOpf6-yRa_10kMZyYQatY1eclIKI0xb54kbluEl0GQDaL5FxLmiKeVnsapzw","e":"AQAB"}`

	type entry struct {
		jwk      string
		serial   *big.Int
		names    []string
		testKey  *rsa.PrivateKey
		spkiHash []byte
	}

	entries := []*entry{
		{jwk: testJWK1, serial: big.NewInt(1), names: []string{"example-1337.com"}, testKey: testKey1},
		{jwk: testJWK2, serial: big.NewInt(2), names: []string{"example-1338.com"}, testKey: testKey2},
		{jwk: testJWK3, serial: big.NewInt(3), names: []string{"example-1339.com"}, testKey: testKey3},
	}

	// Register and insert our first 3 certificates.
	for _, entry := range entries {
		regId := testCtx.addRegistation(t, entry.names, entry.jwk)
		cert := testCtx.addCertificate(t, entry.serial, entry.names, entry.testKey.PublicKey, regId)

		entry.spkiHash, err = getPublicKeySPKIHash(cert.PublicKey)
		test.AssertNotError(t, err, "Failed to get SPKI hash for test cert")

		count, err := testCtx.revoker.countCertsMatchingSPKIHash(entry.spkiHash)
		test.AssertNotError(t, err, "countCertsMatchingSPKIHash for entry failed")
		test.AssertEquals(t, count, 1)
	}

	// Register and insert a certificate which re-uses the same public key as
	// our first test certificate.
	regId := testCtx.addRegistation(t, []string{"example-1336.com"}, testJWK4)
	testCtx.addCertificate(t, big.NewInt(4), []string{"example-1336.com"}, testKey1.PublicKey, regId)

	// Get the SPKI hash for the provided keypair.
	spkiHash, err := getPublicKeySPKIHash(&testKey1.PublicKey)
	test.AssertNotError(t, err, "Failed to get SPKI hash for dupe.")

	// Ensure that the SPKI hash hasn't already been added to the blockedKeys
	// table.
	keyExists, err := testCtx.revoker.spkiHashInBlockedKeys(spkiHash)
	test.AssertNotError(t, err, "countCertsMatchingSPKIHash for dupe failed")
	test.Assert(t, !keyExists, "SPKI hash should not be in blockedKeys")

	// For some additional validation let's ensure that counts for all test
	// entries, except our known duplicate, are 1.
	for _, entry := range entries {
		switch entry.names[0] {
		case "example-1337.com":
			count, err := testCtx.revoker.countCertsMatchingSPKIHash(entry.spkiHash)
			test.AssertNotError(t, err, "countCertsMatchingSPKIHash for entry failed")
			test.AssertEquals(t, count, 2)

		case "example-1338.com":
			count, err := testCtx.revoker.countCertsMatchingSPKIHash(entry.spkiHash)
			test.AssertNotError(t, err, "countCertsMatchingSPKIHash for entry failed")
			test.AssertEquals(t, count, 1)

		case "example-1339.com":
			count, err := testCtx.revoker.countCertsMatchingSPKIHash(entry.spkiHash)
			test.AssertNotError(t, err, "countCertsMatchingSPKIHash for entry failed")
			test.AssertEquals(t, count, 1)
		}
	}

	// Revoke one of our two testKey1 certificates by serial. This is to test
	// that revokeByPrivateKey will continue if one of the two matching
	// certificates has already been revoked.
	err = testCtx.revoker.revokeBySerial(context.Background(), core.SerialToString(big.NewInt(1)), 1, true)
	test.AssertNotError(t, err, "While attempting to revoke 1 of our matching certificates ahead of time")

	// Revoke the certificates, but do not block issuance.
	err = testCtx.revoker.revokeByPrivateKey(context.Background(), testKey1File.Name())
	test.AssertNotError(t, err, "While attempting to revoke certificates for the provided key")

	// Ensure that the key is not blocked, yet.
	keyExists, err = testCtx.revoker.spkiHashInBlockedKeys(spkiHash)
	test.AssertNotError(t, err, "countCertsMatchingSPKIHash for dupe failed")
	test.Assert(t, !keyExists, "SPKI hash should not be in blockedKeys")

	// Block issuance for the key.
	err = testCtx.revoker.blockByPrivateKey(context.Background(), testKey1File.Name())
	test.AssertNotError(t, err, "While attempting to block issuance for the provided key")

	// Ensure that the key is now blocked.
	keyExists, err = testCtx.revoker.spkiHashInBlockedKeys(spkiHash)
	test.AssertNotError(t, err, "countCertsMatchingSPKIHash for dupe failed")
	test.Assert(t, keyExists, "SPKI hash should not be in blockedKeys")

	// Ensure that blocking issuance is idempotent.
	err = testCtx.revoker.blockByPrivateKey(context.Background(), testKey1File.Name())
	test.AssertNotError(t, err, "While attempting to block issuance for the provided key")
}

func TestPrivateKeyBlock(t *testing.T) {
	testCtx := setup(t)
	defer testCtx.cleanUp()

	// Unique keys for each of our test certificates.
	testKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 1")
	testKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 2")
	testKey3, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 3")

	// Write the contents of testKey1 to a temp file.
	testKey1File, err := ioutil.TempFile("", "key")
	test.AssertNotError(t, err, "failed to create temp file")
	der, err := x509.MarshalPKCS8PrivateKey(testKey1)
	test.AssertNotError(t, err, "failed to marshal testKey1 to DER")
	err = pem.Encode(testKey1File,
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		},
	)
	test.AssertNotError(t, err, "failed to PEM encode test key 1")
	test.AssertNotError(t, err, "failed to write to temp file")
	defer os.Remove(testKey1File.Name())

	// Unique JWKs so we can register each of our entries.
	testJWK1 := `{"kty":"RSA","n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ","e":"AQAB"}`
	testJWK2 := `{"kty":"RSA","n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw","e":"AQAB"}`
	testJWK3 := `{"kty":"RSA","n":"uTQER6vUA1RDixS8xsfCRiKUNGRzzyIK0MhbS2biClShbb0hSx2mPP7gBvis2lizZ9r-y9hL57kNQoYCKndOBg0FYsHzrQ3O9AcoV1z2Mq-XhHZbFrVYaXI0M3oY9BJCWog0dyi3XC0x8AxC1npd1U61cToHx-3uSvgZOuQA5ffEn5L38Dz1Ti7OV3E4XahnRJvejadUmTkki7phLBUXm5MnnyFm0CPpf6ApV7zhLjN5W-nV0WL17o7v8aDgV_t9nIdi1Y26c3PlCEtiVHZcebDH5F1Deta3oLLg9-g6rWnTqPbY3knffhp4m0scLD6e33k8MtzxDX_D7vHsg0_X1w","e":"AQAB"}`
	testJWK4 := `{"kty":"RSA","n":"qih-cx32M0wq8MhhN-kBi2xPE-wnw4_iIg1hWO5wtBfpt2PtWikgPuBT6jvK9oyQwAWbSfwqlVZatMPY_-3IyytMNb9R9OatNr6o5HROBoyZnDVSiC4iMRd7bRl_PWSIqj_MjhPNa9cYwBdW5iC3jM5TaOgmp0-YFm4tkLGirDcIBDkQYlnv9NKILvuwqkapZ7XBixeqdCcikUcTRXW5unqygO6bnapzw-YtPsPPlj4Ih3SvK4doyziPV96U8u5lbNYYEzYiW1mbu9n0KLvmKDikGcdOpf6-yRa_10kMZyYQatY1eclIKI0xb54kbluEl0GQDaL5FxLmiKeVnsapzw","e":"AQAB"}`

	type entry struct {
		jwk     string
		serial  *big.Int
		names   []string
		testKey *rsa.PrivateKey
	}

	entries := []*entry{
		{jwk: testJWK1, serial: big.NewInt(1), names: []string{"example-1337.com"}, testKey: testKey1},
		{jwk: testJWK2, serial: big.NewInt(2), names: []string{"example-1338.com"}, testKey: testKey2},
		{jwk: testJWK3, serial: big.NewInt(3), names: []string{"example-1339.com"}, testKey: testKey3},
	}

	// Register and insert our first 3 certificates.
	for _, entry := range entries {
		regId := testCtx.addRegistation(t, entry.names, entry.jwk)
		testCtx.addCertificate(t, entry.serial, entry.names, entry.testKey.PublicKey, regId)
	}

	// Register and insert a certificate which re-uses the same public key as
	// our first test certificate.
	regId := testCtx.addRegistation(t, []string{"example-1336.com"}, testJWK4)
	testCtx.addCertificate(t, big.NewInt(4), []string{"example-1336.com"}, testKey1.PublicKey, regId)

	// Get the SPKI hash for the provided keypair.
	spkiHash1, err := getPublicKeySPKIHash(&testKey1.PublicKey)
	test.AssertNotError(t, err, "Failed to get SPKI hash for dupe.")

	// Query the 'keyHashToSerial' table for certificates with a matching SPKI
	// hash. We expect that since this key was re-used we'll find 2 matches.
	count, err := testCtx.revoker.countCertsMatchingSPKIHash(spkiHash1)
	test.AssertNotError(t, err, "countCertsMatchingSPKIHash for dupe failed")
	test.AssertEquals(t, count, 2)

	// With dryRun=true this should not block the key.
	err = privateKeyBlock(&testCtx.revoker, true, count, spkiHash1, testKey1File.Name())
	test.AssertNotError(t, err, "While attempting to block issuance for the provided key")

	// Ensure that the key is not blocked, yet.
	keyExists, err := testCtx.revoker.spkiHashInBlockedKeys(spkiHash1)
	test.AssertNotError(t, err, "countCertsMatchingSPKIHash for dupe failed")
	test.Assert(t, !keyExists, "SPKI hash should not be in blockedKeys")

	// With dryRun=false this should block the key.
	err = privateKeyBlock(&testCtx.revoker, false, count, spkiHash1, testKey1File.Name())
	test.AssertNotError(t, err, "While attempting to block issuance for the provided key")

	// With dryRun=false this should result in an error as the key is already blocked.
	err = privateKeyBlock(&testCtx.revoker, false, count, spkiHash1, testKey1File.Name())
	test.AssertError(t, err, "Attempting to block a key which is already blocked should have failed.")

	// Ensure that the key is now blocked.
	keyExists, err = testCtx.revoker.spkiHashInBlockedKeys(spkiHash1)
	test.AssertNotError(t, err, "countCertsMatchingSPKIHash for dupe failed")
	test.Assert(t, keyExists, "SPKI hash should not be in blockedKeys")
}

func TestPrivateKeyRevoke(t *testing.T) {
	testCtx := setup(t)
	defer testCtx.cleanUp()

	// Unique keys for each of our test certificates.
	testKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 1")
	testKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 2")
	testKey3, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Failed to generate test key 3")

	// Write the contents of testKey1 to a temp file.
	testKey1File, err := ioutil.TempFile("", "key")
	test.AssertNotError(t, err, "failed to create temp file")
	der, err := x509.MarshalPKCS8PrivateKey(testKey1)
	test.AssertNotError(t, err, "failed to marshal testKey1 to DER")
	err = pem.Encode(testKey1File,
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		},
	)
	test.AssertNotError(t, err, "failed to PEM encode test key 1")
	test.AssertNotError(t, err, "failed to write to temp file")
	defer os.Remove(testKey1File.Name())

	// Unique JWKs so we can register each of our entries.
	testJWK1 := `{"kty":"RSA","n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ","e":"AQAB"}`
	testJWK2 := `{"kty":"RSA","n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw","e":"AQAB"}`
	testJWK3 := `{"kty":"RSA","n":"uTQER6vUA1RDixS8xsfCRiKUNGRzzyIK0MhbS2biClShbb0hSx2mPP7gBvis2lizZ9r-y9hL57kNQoYCKndOBg0FYsHzrQ3O9AcoV1z2Mq-XhHZbFrVYaXI0M3oY9BJCWog0dyi3XC0x8AxC1npd1U61cToHx-3uSvgZOuQA5ffEn5L38Dz1Ti7OV3E4XahnRJvejadUmTkki7phLBUXm5MnnyFm0CPpf6ApV7zhLjN5W-nV0WL17o7v8aDgV_t9nIdi1Y26c3PlCEtiVHZcebDH5F1Deta3oLLg9-g6rWnTqPbY3knffhp4m0scLD6e33k8MtzxDX_D7vHsg0_X1w","e":"AQAB"}`
	testJWK4 := `{"kty":"RSA","n":"qih-cx32M0wq8MhhN-kBi2xPE-wnw4_iIg1hWO5wtBfpt2PtWikgPuBT6jvK9oyQwAWbSfwqlVZatMPY_-3IyytMNb9R9OatNr6o5HROBoyZnDVSiC4iMRd7bRl_PWSIqj_MjhPNa9cYwBdW5iC3jM5TaOgmp0-YFm4tkLGirDcIBDkQYlnv9NKILvuwqkapZ7XBixeqdCcikUcTRXW5unqygO6bnapzw-YtPsPPlj4Ih3SvK4doyziPV96U8u5lbNYYEzYiW1mbu9n0KLvmKDikGcdOpf6-yRa_10kMZyYQatY1eclIKI0xb54kbluEl0GQDaL5FxLmiKeVnsapzw","e":"AQAB"}`

	type entry struct {
		jwk     string
		serial  *big.Int
		names   []string
		testKey *rsa.PrivateKey
	}

	entries := []*entry{
		{jwk: testJWK1, serial: big.NewInt(1), names: []string{"example-1337.com"}, testKey: testKey1},
		{jwk: testJWK2, serial: big.NewInt(2), names: []string{"example-1338.com"}, testKey: testKey2},
		{jwk: testJWK3, serial: big.NewInt(3), names: []string{"example-1339.com"}, testKey: testKey3},
	}

	// Register and insert our first 3 certificates.
	for _, entry := range entries {
		regId := testCtx.addRegistation(t, entry.names, entry.jwk)
		testCtx.addCertificate(t, entry.serial, entry.names, entry.testKey.PublicKey, regId)
	}

	// Register and insert a certificate which re-uses the same public key as
	// our first test certificate.
	regId := testCtx.addRegistation(t, []string{"example-1336.com"}, testJWK4)
	testCtx.addCertificate(t, big.NewInt(4), []string{"example-1336.com"}, testKey1.PublicKey, regId)

	// Get the SPKI hash for the provided keypair.
	spkiHash1, err := getPublicKeySPKIHash(&testKey1.PublicKey)
	test.AssertNotError(t, err, "Failed to get SPKI hash for dupe.")

	// Query the 'keyHashToSerial' table for certificates with a matching SPKI
	// hash. We expect that since this key was re-used we'll find 2 matches.
	count, err := testCtx.revoker.countCertsMatchingSPKIHash(spkiHash1)
	test.AssertNotError(t, err, "countCertsMatchingSPKIHash for dupe failed")
	test.AssertEquals(t, count, 2)

	// With dryRun=true this should not revoke certificates or block issuance.
	err = privateKeyRevoke(&testCtx.revoker, true, count, testKey1File.Name())
	test.AssertNotError(t, err, "While attempting to block issuance for the provided key")

	// Ensure that the key is not blocked, yet.
	keyExists, err := testCtx.revoker.spkiHashInBlockedKeys(spkiHash1)
	test.AssertNotError(t, err, "spkiHashInBlockedKeys failed for key that shouldn't be blocked yet")
	test.Assert(t, !keyExists, "SPKI hash should not be in blockedKeys")

	// With dryRun=false this should revoke matching certificates and block the key.
	err = privateKeyRevoke(&testCtx.revoker, false, count, testKey1File.Name())
	test.AssertNotError(t, err, "While attempting to block issuance for the provided key")

	// Ensure that the key is now blocked.
	keyExists, err = testCtx.revoker.spkiHashInBlockedKeys(spkiHash1)
	test.AssertNotError(t, err, "spkiHashInBlockedKeys failed for key that should now be blocked")
	test.Assert(t, keyExists, "SPKI hash should not be in blockedKeys")
}

type testCtx struct {
	revoker revoker
	ssa     sapb.StorageAuthorityClient
	dbMap   *db.WrappedMap
	cleanUp func()
	issuer  *issuance.Certificate
	signer  crypto.Signer
}

func (c testCtx) addRegistation(t *testing.T, names []string, jwk string) int64 {
	initialIP, err := net.ParseIP("127.0.0.1").MarshalText()
	test.AssertNotError(t, err, "Failed to create initialIP")

	reg := &corepb.Registration{
		Id:        1,
		Contact:   []string{fmt.Sprintf("hello@%s", names[0])},
		Key:       []byte(jwk),
		InitialIP: initialIP,
	}

	reg, err = c.ssa.NewRegistration(context.Background(), reg)
	test.AssertNotError(t, err, "Failed to store test registration")
	return reg.Id
}

func (c testCtx) addCertificate(t *testing.T, serial *big.Int, names []string, pubKey rsa.PublicKey, regId int64) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"tests"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		DNSNames:     names,
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, template, c.issuer.Certificate, &pubKey, c.signer)
	test.AssertNotError(t, err, "Failed to generate test cert")

	_, err = c.ssa.AddPrecertificate(
		context.Background(), &sapb.AddCertificateRequest{
			Der:      rawCert,
			RegID:    regId,
			Issued:   time.Now().UnixNano(),
			IssuerID: 1,
		},
	)
	test.AssertNotError(t, err, "Failed to add test precert")

	cert, err := x509.ParseCertificate(rawCert)
	test.AssertNotError(t, err, "Failed to parse test cert")
	return cert
}

func setup(t *testing.T) testCtx {
	log := blog.UseMock()
	fc := clock.NewFake()

	// Set some non-zero time for GRPC requests to be non-nil.
	fc.Set(time.Now())

	dbMap, err := sa.NewDbMap(vars.DBConnSA, sa.DbSettings{})
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	rocspIssuers, err := rocsp_config.LoadIssuers(map[string]int{
		"../../test/hierarchy/int-r3.cert.pem": 102,
	})
	test.AssertNotError(t, err, "error loading issuers")
	ssa, err := sa.NewSQLStorageAuthority(dbMap, dbMap, rocspIssuers, fc, log, metrics.NoopRegisterer, 1)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	cleanUp := test.ResetSATestDatabase(t)

	issuer, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "Failed to load test issuer")

	signer, err := test.LoadSigner("../../test/hierarchy/int-r3.key.pem")
	test.AssertNotError(t, err, "Failed to load test signer")

	ra := ra.NewRegistrationAuthorityImpl(
		fc,
		log,
		metrics.NoopRegisterer,
		1,
		goodkey.KeyPolicy{},
		100,
		true,
		300*24*time.Hour,
		7*24*time.Hour,
		nil,
		nil,
		0,
		nil,
		&mockPurger{},
		[]*issuance.Certificate{issuer},
	)
	ra.SA = isa.SA{Impl: ssa}
	ra.CA = &mockCA{}
	rac := ira.RA{Impl: ra}

	return testCtx{
		revoker: revoker{rac, isa.SA{Impl: ssa}, dbMap, fc, log},
		ssa:     isa.SA{Impl: ssa},
		dbMap:   dbMap,
		cleanUp: cleanUp,
		issuer:  issuer,
		signer:  signer,
	}
}
