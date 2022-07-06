# Generate Certificate

If the `test/testdata/test_blob_cert.pem` expire you can generate a new certificate to use in the tests running the
following command:

```shell
$ openssl req -key test/testdata/test_blob_private_key -x509 -days 3650 -out cert.pem -new -nodes

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:US
State or Province Name (full name) []:CA
Locality Name (eg, city) []:SF
Organization Name (eg, company) []:Company
Organizational Unit Name (eg, section) []:Unit
Common Name (eg, fully qualified host name) []:www.example.org
Email Address []:email@email.com
```

and then you replace the old `test/testdata/test_blob_cert.pem` with the new certificate.

