// Pseudo-code for an example verification flow for a sigstore bundle,
// with some input parameters required from the client.
// This algorighm is written without any dependency on TUF, this implies
// that any client must *FIRST* resolve any verification materials (root
// certificates, public keys etc) and provide them upfront the Verify
// method.

type Verifier interface{
	// Verify verifier the provided data against the signatre,
	// optionally relying on the kid as hint to which key to use.
	Verify(data, sig []byte, kid string) error
}

type LogId []byte

type Options {
	// Verifier for user provided keys. May know about many keys.
	// The 'Verifier' verifies the signature of either the DSSE envelope
	// or the MessageSignature.
	Verifier Verifier
	// User provided root certificate for verifying certificate chain.
	RootCertificate *x509.Certificate
	// Map of trusted root certificates when verifying RFC3161 signed
	// timestamps. Indexex by their 'Name'.
	Rfc3162RootCertificates map[pkix.Name]*x509.Certificate
	// The minumum number of TSA's the artifact has to be witnessed by.
	Rfc3161TimestampThreshold int
	// Map of trusted public keys for verifying a transparency log entry.
	// The keys are indexed by the log's id.
	// PublicKey is expected to be the concrete representation of the
	// public key, with all parameters required (padding, hash function
	// etc.) instantiated.
	RekorPublicKeys map[LogId]*PublicKey
	// The minimum number of transparency logs the entry has to be
	// appended to.
	RekorThreshold int
	// Set to true if the transparency log entry's inclusion promise
	// (SET) is not enough, and a full inclsion proof is required.
	RequireInclusionProof bool
}

// Verify is the main verirication function.
// It accepts a required sigstore bundle, and an optional path to the blob.
// In if the attestation in the bundle is a DSSE envelope, the blob path
// is ignored.
// All cryptographic verification materials such as root certificates *MUST*
// be provided to this method.
// This function only verifies the signatures (including time of signature
// creation when using a certificate), root of trust and that the
// signatures are for the provided artifact. It does not parse the content
// in the DSSE envelope (if provided). Clients are expected to rely on this
// function to verify the authenticity of the artifact, and then resort to
// domain specific validation functions.
// Providing a bundle which contains a DSSE envelope and a path to a blob is
// an error.
func Verify(b *bundle, blobPath string, opts Options) error {
	if b.GetDsseEnvelope() != nil {
		if blobPath != nil {
			return ErrBadInput
		}

		if err = verifyDsse(b, opts); err != nil {
			return err
		}
	} else {
		if err = verifyBlob(b, blobPath, opts); err != nil {
			return err
		}
	}

	var verifiedOk = 0
	for entry = range b.TimestampVerificationData.GetTLogEntries() {
		err = verifyRekor(b, entry, blobPath, opts); err != nil {
			log(err)
		}
		verifiedOk++
	}
	if verifiedOk < opts.RekorThreshold {
		return ErrTooFewTlogs
	}

	verifiedOk = 0
	for ts = range b.TimestampVerificationData.GetRfc3161Timestamps() {
		err = verifyRfc3161Ts(b, ts, blobPath, opts); err != nil {
			log(err)
		}
		verifiedOk++
	}
	if verifiedOk < opts.Rfc3161TimestampThreshold {
		return ErrTooFewTimestamps
	}

	return nil
}

// Extract the verifier to use, either based on a set of provided keys, or
// a complete X509 chain.
func getVerifier(b *bundle, opts Options) Verifier {
	var chain = b.VerificationMaterial.GetX509CertificateChain()

	if chain == nil {
		// The verification material is a public key, return the
		// user provided verifier, which contains the set of trusted
		// public keys.
		return opts.Verifier
	} else {
		// Generic verifier that verifies:
		// * the provided signature is correct given the data and
		//   certificate (leaf certificate in the certificate chain).
		// * The entire certificate chain is consistent up to the
		//   root certificate, *and* that the root certificate
		//   matches the user provided.
		return x509Verifier(chain, opts.RootCertificate)
	}
}

// Standard DSSE verification using the provided verification material.
func verifyDsse(b *bundle, opts options) error {
	verifier = getVerifier(b, opts)
	// stdDsseVerification shall implement the first three steps of
	// DSSE verification as defined here: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#dsse-protocol
	// Verification of PAYLOAD_TYPE is expected to be performed after
	// bundle verification is done.
	return stdDsseVerification(b.GetDsseEnvelope(), verifier)
}

// Verify a blob's message signature.
// First the message digest is calculated to make sure the provided blob
// is the one being referenced.
// Then the signature is verified by the provided crypto material
func verifyBlob(b *bundle, blob string, opts Options) error {
	var signature = b.GetMessageSignature()
	var digest = calculateDigest(blob, signature.MessageDigest.Algorithm)

	if digest != signature.MessageDigest.Digest {
		return ErrDigestMismatch
	}
	var verifier = getVerifier(b, opts)
	var data = io.ReadAll(blob)
	// the keyHint is empty if the verification material is a X509 cert,
	// the prepared verifier from getVerifier is correctly configured
	// though.
	var keyHint = b.VerificationMaterial.GetPublicKey()
	return verifier.Verify(data, signature.Signature, keyHint)
}

// Verify that the rekor entry matches the provided attestation.
// As the rekor entry is partially provided, and is composed based on data
// in the sigstore bundle, the verification always makes sure that the rekor
// entry was for the provided sigsture bundle.
func verifyRekor(b *bundle, tlogEntry *TransparencyLogEntry, blob string, opts options) error {
	var entry = reconstructRekorEntry(b, tlogEntry, blob)
	var rekorPubKey = opts.RekorPublicKeys[tlogEntry.LogId]

	// Verify that the inclusion time is within the validity of the
	// certificate. This should be done by the transparency log prior
	// to appending the entry to the log. But there is no harm to verify
	// it once more.
	var chain = b.VerificationMaterial.GetX509CertificateChain()
	if chain != nil && !validCertificateChain(chain, tlogEntry.IntegrationTime) {
		return ErrCertificateExpired
	}

	if !verifySET(entry, tlogEntry.InclusionPromise, rekorPubKey) {
		return ErrSETMismatch
	}

	if opts.RequireInclusionProof {
		// Perform an online verification against the Rekor instance
		var client = getRekorClient(tlogEntry.LogId)
		return client.ProveInclusion(b, tlogEntry, blob, opts)
	}

	return nil
}

// Reconstruct the Rekor type by introspecting what kind of attestation
// type is provided.
func reconstructRekroEntry(b *bundle, entry *TransparencyLogEntry, blob string) *rekorEntry{
	switch entry.KindVersion.Kind {
	case intoto:
		return rekorTypeIntoto(
			entry.logIndex,
			entry.logId,
			...
			b.GetDsseEnvelope())
	case hashedrecord:
		var signature = b.GetMessageSignature()
		return rekorTypeRecordHash(
			entry.logIndex,
			entry.logId,
			...
			signature.Signature,
			calculateDigest(blob, signature.MessageDigest.Algorithm))
	}
}

// Verify that a provided RFC3161 signed timestamp matches the provided
// bundle.
// The argument ts is here assumed to be a TimeStampToken as defined
// here https://www.ietf.org/rfc/rfc3161.html#section-2.4.2.
// Implementation may opt to accet the raw DER bytes, and call out to an
// appropriate library.
func verifyRfc3161Ts(b *bundle, tst TimestampToken, blob string, opts Options) error {
	// Verify that the TSA is trusted
	if !verifyCertChain(tst.Content.Certificates, opts.Rfc3162RootCertificates) {
		return ErrCertChainMisMatch
	}
	// Verify that the timestamp token is valid
	if !rfc3162.Verify(ts) {
		return ErrInvalidTimestamp
	}
	// Recalculate the message digest and compare with the value in the
	// timestamp token. Note that the hash algorithm in the timestamp
	// token may differ from the one in the message signature.
	var alg = tst.TstInfo.MessageImprint.HashAlgorithm
	var digest = tst.TstInfo.MessageImprint.HashedMessage
	var data []byte
	if b.GetDsseEnvelope() != nil {
		data = b.GetDsseEnvelope().Payload
	} else {
		data = io.ReadAll(blob)
	}
	if digest != calculateDigest(data, alg) {
		return ErrDigestMismatch
	}

	// Verify that the signature was created during the time the
	// certificate was valid
	var chain = b.VerificationMaterial.GetX509CertificateChain()
	if chain != nil && !validCertificateChain(chain, tst.TstInfo.GenTime)
		return ErrCertificateExpired
	}

	return nil
}
