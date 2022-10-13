# Sigstore bundle verification steps

## Input
* A bundle
* A path to a blob located on the filesystem (optional)
* Parameters/trust root material
  * Signature verification material. One of: a public key or a X509
    root certificate
  * A list of X509 root certificates for trust timestamp authorities.
  * A threshold in minimum number of signatures from a timestamp authority.
  * A list of public keys for the transparency log (Rekor)
  * A threshold of minimum number of transparency logs the artifact
    has been appended to.
  * Perform inclusion proof on transparency logs (true/false)

## Steps

If any step is failing, abort verification unless otherwise specified.

1. Verify the signature of the artifact.
   1. Bundle contains a DSSE envelope.
     1. Perform the three first step of the verification as defined
        [here](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#dsse-protocol).
   2. Bundle refers to a blob.
     1. Recalculate the blob's digest with the hash algoritm specified
        in the bundle.
     2. Recalculate the signature over the blob by using the algorithm
        specified by the public key<sup>1</sup> or the certificate.
2. The signature shall be verified against the provided material
   (public key or X509 certificate).
  1. If certificate is used, verify that the complete certificate
     chain is valid and trusted by the provided root certificate.
3. Verify transparency log inclusion.
  1. For each transparency log entry:
    1. Recreate the Rekor entry from the bundle and blob (if provided).
    2. Get the public key for the log. Go to next entry if no key is
       found.
    3. Verify that the entry was included onto the log during the time
       the signing certificate was valid (skip if signature was made
       with a key-pair).
    4. Verify that the inclusion proof (SET) is sound given the log's
       public key.
    5. If requested, perform an online inclusion proof against the
       log.
    6. Increment the number of successful transparency log
       verifications.
  2. Compare the number of successful transparency log verifications
     against the provided threshold.
4. Verify timestamp authority signatures.
  1. For each signed timestamp
    1. Verity that the entire chain from the timestamping authority is
       trusted by the provided root certificates. If not, proceed with
       the next signed timestamp.
    2. Verify that the timestamp token's signature is valid.
    3. Recreate the digest of the artifact using the algorithm
       specified in the timestamp token.
    4. Compare the computed digest with the one in the timestamp
       token.
    5. Verify that the artifact was witnessed by the timestamp
       authority during the time the certificate was valid.
    6. Increment the number of successful signed timestamps.
  2. Compare the number of successful signed timestamps against the
     provided threshold.
5. Return success.

<hr/>
<sup>1<sup/>: The neccesary parameters for are considered to be part of
the public key, even if they are not expressed in the encoded key
(.e.g PEM).
