// Pseudo-code for an example verification flow for a sigstore bundle,
// with some input parameters required from the client.

type Verifier interface{
	// Verify verifier the provided data against the signatre,
	// optionally relying on the kid as hint to which key to use.
	Verify(data, sig []byte, kid string) error
}


type Options {
	// Verifier for user provided keys. May know about many keys.
	Verifier Verifier
	// Optional user provided Root CA
	RootCA *x509.Certificate
	// Optional Rekor URL
	RekorURL string
	// Optional Fulcio URL
	FulcioURL string
}

// Verify is the main verirication function.
// It accepts a required sigstore bundle, and an optional path to the blob.
// In if the attestation in the bundle is a DSSE envelope, the blob path
// is ignored.
func Verify(b *bundle, blob string, opts Options) error {
	if b.AttestationDsse != nil {
		if err = verifyDsse(b, opts); err != nil {
			return err
		}
	} else {
		if err = verifyBlob(b, blob, opts); err != nil {
			return err
		}
	}

	if b.rekorEntry != nil {
		err = verifyRekor(b, blob, opts); err != nil {
			return err
		}
	}

	return nil
}

// Extract the verifier to use, either based on a set of provided keys, or
// a complete X509 chain.
func getVerifier(b *bundle, opts Options) Verifier {
	if b.publicKey {
		return = opts.Verifier
	} else {
		return = x509Verifier(b.X509Cert, opts)
	}
}

// Standard DSSE verification using the provided verification material.
func verifyDsse(b *bundle, opts options) error {
	verifier = getVerifier(b, opts)
	return stdDsseVerification(b.AttestationDsse, verifier)
}

// Verify a blob attestation by first comparing the payloaddigest, and the
// the signature over the digest using the provided verification material.
func verifyBlob(b *bundle, blob string, opts Options) error {
	digest = calculateDigest(blob, b.AttestationBlob.Algorithm)
	if digest != b.AttestationBlob.PayloadHash {
		return digestMismatch
	}
	verifier = getVerifier(b, opts)
	data = io.ReadAll(blob)
	return verifier.Verify(data, b.AttestationBlob.Signature, b.PublicKey.KeyId || "")
}

// Load an X509 verifier based on the options. Either the default Fulcio CA
// is used, or a CA provided by the user. The returned verifier contains
// both the leaf certificate (signing cert) and the entire chain, including
// the CA which was provided out of bands.
func x509Verifier(x509 X509CertStruct, opts Options) Verifier {
	if opts.RootCA == nil {
		return loadCAFromTuf(opts.FulcioURL)
	}
	// the x509 variable is the struct of cert + chain.
	return x509ChainVerifier(x509, opts.RootCA)
}

// Verify that the rekor entry matches the provided attestation.
// As the rekor entry is partially provided, and is composed based on data
// in the sigstore bundle, the verification always makes sure that the rekor
// entry was for the provided sigsture bundle.
func verifyRekor(b *bundle, blob string, opts options) error {
	entry = reconstructRekorEntry(b, d)
	RekorPubKey = loadFromTuf(opts.RekorURL)

	return verifySET(entry, b.rekorEntry.SignedEntryTimestamp, o.RekorPubKey)
}

// Reconstruct the Rekor type by introspecting what kind of attestation
// type is provided.
func reconstructRekroEntry(b *bundle, blob string) *rekorEntry{
	switch b.RekorEntry.Kind {
	case intoto:
		return rekorTypeIntoto(
			b.RekorEntry.logIndex,
			b.RekorEntry.logId,
			...
			b.AttestationDsse)
	case hashedrecord:
		return rekorTypeRecordHash(
			b.RekorEntry.logIndex,
			b.RekorEntry.logId,
			...
			b.AttestationBlob.Signature,
			calculateDigest(blob, b.AttestationBlob.Algorithm))
	}
}
