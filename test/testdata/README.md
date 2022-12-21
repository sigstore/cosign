# Generate Certificate

If the `test/testdata/test_blob_cert.pem` expire you can generate a new certificate to use in the tests running the
following command:

```shell
$ openssl req -key test/testdata/test_blob_private_key -x509 -days 3650 -out cert.pem -new -nodes -subj "/" -addext "subjectAltName = email:foo@example.com"
```

and then you replace the old `test/testdata/test_blob_cert.pem` with the new certificate.

