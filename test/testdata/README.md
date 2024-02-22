# Generate Certificate

If the `test/testdata/test_blob_cert.pem` expire you can generate a new certificate to use in the tests running the
following command:

```shell
$ openssl req -key test/testdata/test_blob_private_key -x509 -days 3650 -out cert.pem -new -nodes -subj "/" -addext "subjectAltName = email:foo@example.com"
```

and then you replace the old `test/testdata/test_blob_cert.pem` with the new certificate.

# Generate Certificates and Certificate chain for Attach test
If the test/testdata/test_attach_leafcert.pem or test_attach_rootcert.pem or test_attach_certchain.pem expires than you can generate a new certificate and certificate using the given steps

1. Generate a private key for Root certificate

```shell
$ openssl genrsa -des3 -out rootCA.key 2048
```
2. Generate Root certificate

```shell
$ openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1825 -out rootCA.crt
```
   in Certificate generation set following values
   C = IN, ST = DEL, L = DEL, O = example.com, OU = sigstore, CN = sigstore, emailAddress = foo@example.com

3. Generate Private key for Intermediate certificate

```shell
$ openssl genrsa -out intermediateCA.key 2048
```
4. Generate CSR for Intermediate certificate

```shell
$ openssl req -new -key intermediateCA.key -out intermediateCA.csr
```
   in Certificate generation set following values
   C = IN, ST = DEL, L = DEL, O = example.com, OU = sigstore-sub, CN = sigstore-sub, emailAddress = foo@example.com

5. Create intermediate certificate config file by name "intermediateConfigFile" having content
   	subjectKeyIdentifier = hash
   	authorityKeyIdentifier = keyid:always,issuer
   	basicConstraints = critical, CA:true, pathlen:0
   	keyUsage = critical, digitalSignature, cRLSign, keyCertSign

6. Create intermediate certificate

```shell
$ openssl x509 -req -in intermediateCA.csr -CA rootCA.crt -CAkey rootCA.key  -CAcreateserial -CAserial intermediateca.srl -out intermediateCA.crt -days 1825 -sha256 -extfile intermediateConfigFile
```

7. Create Private key for leaf certificate

```shell
$ openssl genrsa -out leafCA.key 2048
```

8. Create CSR for Leaf certificate

```shell
$ openssl req -new -key leafCA.key -out leafCA.csr
```
   in certificate generation set following values
   C = IN, ST = DEL, L = DEL, O = example.com, OU = sigstore-leaf, CN = sigstore-leaf, emailAddress = foo@example.com

9. Create Leaf certificate config file by name "leafConfigFile" having content
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        extendedKeyUsage=codeSigning
        subjectAltName=email:copy

10. Create Leaf certificate

```shell
$ openssl x509 -req -in leafCA.csr -CA intermediateCA.crt -CAkey intermediateCA.key  -CAcreateserial -CAserial leafca.srl -out leafCA.crt -days 1825 -sha256 -extfile leafConfigFile
```

11. Generate Certificate chain by concatenating Intermediate certificate and Root certificate

```shell
$ cat intermediateCA.crt rootCA.crt > certChain.crt
```

12. copy private key of Leaf certificate to test/testdata/test_attach_private.key

```shell
$ cp leafCA.key test/testdata/test_attach_private.key
```

13. copy root certificate to test/testdata/test_attach_rootcert.pem

```shell
$ cp rootCA.crt test/testdata/test_attach_rootcert.pem
```

14. copy cert chain to test/testdata/test_attach_certchain.pem

```shell
$ cp certChain.crt test/testdata/test_attach_certchain.pem
```

15. copy Leaf certificate to test/testdata/test_attach_leafcert.pem

```shell
$ cp leafCA.crt test/testdata/test_attach_leafcert.pem
```

16. Generate a private key for Second Root certificate

```shell
$ openssl genrsa -des3 -out secondrootCA.key 2048
```
17. Generate Second Root certificate

```shell
$ openssl req -x509 -new -nodes -key secondrootCA.key -sha256 -days 1825 -out secondrootCA.crt
```
   in Certificate generation set following values
   C = IN, ST = DEL, L = DEL, O = exampleclient.com, OU = sigstore, CN = sigstore, emailAddress = foo@exampleclient.com

18. Generate Private key for second Intermediate certificate

```shell
$ openssl genrsa -out secondintermediateCA.key 2048
```
19. Generate CSR for second Intermediate certificate

```shell
$ openssl req -new -key secondintermediateCA.key -out secondintermediateCA.csr
```
   in Certificate generation set following values
   C = IN, ST = DEL, L = DEL, O = exampleclient.com, OU = sigstore-sub, CN = sigstore-sub, emailAddress = foo@exampleclient.com

20. Create intermediate certificate config file by name "intermediateConfigFile" having content
   	subjectKeyIdentifier = hash
   	authorityKeyIdentifier = keyid:always,issuer
   	basicConstraints = critical, CA:true, pathlen:0
   	keyUsage = critical, digitalSignature, cRLSign, keyCertSign

21. Create intermediate certificate

```shell
$ openssl x509 -req -in secondintermediateCA.csr -CA secondrootCA.crt -CAkey secondrootCA.key  -CAcreateserial -CAserial secondintermediateca.srl -out secondintermediateCA.crt -days 1825 -sha256 -extfile intermediateConfigFile
```

22. Create Private key for second leaf certificate

```shell
$ openssl genrsa -out secondleafCA.key 2048
```

23. Create CSR for second Leaf certificate

```shell
$ openssl req -new -key secondleafCA.key -out secondleafCA.csr
```
   in certificate generation set following values
   C = IN, ST = DEL, L = DEL, O = exampleclient.com, OU = sigstore-leaf, CN = sigstore-leaf, emailAddress = foo@exampleclient.com

24. Create Leaf certificate config file by name "leafConfigFile" having content
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        extendedKeyUsage=codeSigning
        subjectAltName=email:copy

25. Create Leaf certificate

```shell
$ openssl x509 -req -in secondleafCA.csr -CA secondintermediateCA.crt -CAkey secondintermediateCA.key  -CAcreateserial -CAserial secondleafca.srl -out secondleafCA.crt -days 1825 -sha256 -extfile leafConfigFile
```

26. Generate Certificate chain by concatenating second Intermediate certificate and second Root certificate

```shell
$ cat secondintermediateCA.crt secondrootCA.crt > secondcertChain.crt
```

27. copy private key of second Leaf certificate to test/testdata/test_attach_second_private_key

```shell
$ cp secondleafCA.key test/testdata/test_attach_second_private_key
```

28. copy root certificate to test/testdata/test_attach_second_rootcert.pem

```shell
$ cp secondrootCA.crt test/testdata/test_attach_second_rootcert.pem
```

29. copy second cert chain to test/testdata/test_attach_second_certchain.pem

```shell
$ cp secondcertChain.crt test/testdata/test_attach_second_certchain.pem
```

30. copy second Leaf certificate to test/testdata/test_attach_second_leafcert.pem

```shell
$ cp secondleafCA.crt test/testdata/test_attach_second_leafcert.pem
```
