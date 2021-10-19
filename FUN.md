# Fun Tips And Tricks!

## Signing Git Commits - Three Ways!

You thought Git signatures were always GPG?
Think again!

### Easy Mode

Sign the commits and store the signatures and public keys somewhere else.

```
$ ./cosign sign-blob --key cosign.key <(git rev-parse HEAD)
Using payload from: /dev/fd/63
Enter password for private key:
MEUCIQDLtTbCRCW+o7Gt3WKR4b2UqT947L8JtYzQJk+R8PItxgIgXoYQg1YXw8xDmGWun6wIG2t+/J0HJs9SbscnSLMNWsM=
$ git rev-parse HEAD
455d1988360dcfdcf0fa17b0736fbbc33b4924c0
$ ./cosign verify-blob --key cosign.pub --signature MEUCIQDLtTbCRCW+o7Gt3WKR4b2UqT947L8JtYzQJk+R8PItxgIgXoYQg1YXw8xDmGWun6wIG2t+/J0HJs9SbscnSLMNWsM= <(git rev-parse HEAD)
Verified OK
```

### Medium Mode

Store the signature in the repo as notes, store the public key somewhere else.

```
$ ./cosign sign-blob --key cosign.key <(git rev-parse HEAD)
Using payload from: /dev/fd/63
Enter password for private key:
MEQCIHXN31pDrZBxs+m/HrcFruavv++oMc+pBZKgl7Hps9jjAiA9QE5uzpFNC5SGpdr4TJuCwh47C24Hwt4yHICae0J1bw==
$ git notes add -m "MEQCIHXN31pDrZBxs+m/HrcFruavv++oMc+pBZKgl7Hps9jjAiA9QE5uzpFNC5SGpdr4TJuCwh47C24Hwt4yHICae0J1bw==" HEAD
$ ./cosign verify-blob --key cosign.pub --signature <(git notes show HEAD) <(git rev-parse HEAD)
Verified OK
```


### Hard Mode

Store the signature in the Transparency Log, and store the public key somewhere else.

```
$ COSIGN_EXPERIMENTAL=1 ./cosign sign-blob --key cosign.key <(git rev-parse HEAD)
Using payload from: /dev/fd/63
Enter password for private key:
MEYCIQDWX6RjU0Z2ynd1CdiAwo/JaC2Z5+vdx8H5spuDNu/r5wIhAPnP+87+knFEwbE8FgeXCrgkjWal3aBsNR3IVaBDT2XU
tlog entry created with index: 1224
```

Now find it from the log:

```
$ uuid=$(rekor-cli search --artifact <(git rev-parse HEAD) | tail -n 1)
$ sig=$(rekor-cli get --uuid=$uuid --format=json | jq -r .Body.RekordObj.signature.content)
$ cosign verify-blob --key cosign.pub --signature <(echo $sig) <(git rev-parse HEAD)
Verified OK
```

You can also get the public key from the log:
```
$ uuid=$(rekor-cli search --artifact <(git rev-parse HEAD) | tail -n 1)
$ sig=$(rekor-cli get --uuid=$uuid --format=json | jq -r .Body.RekordObj.signature.content)
$ pubKey=$(rekor-cli get --uuid=$uuid --format=json | jq -r .Body.RekordObj.signature.publicKey.content)
$ cosign verify-blob -key <(echo $pubKey | base64 --decode) --signature <(echo $sig) <(git rev-parse HEAD)
```

### Level 11

Store the signature in the Transparency Log and don't store the keys anywhere.

```
$ COSIGN_EXPERIMENTAL=1 ./cosign sign-blob <(git rev-parse HEAD)
Using payload from: /dev/fd/63
Generating ephemeral keys...
Retrieving signed certificate...
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=online&client_id=sigstore&code_challenge=fJXMfR2VOiudrU2X1kP4UUSf3v33yyl3o2IexzIaEdc&code_challenge_method=S256&nonce=1zkBCegjVlHrfXywXu3lsT0RVP7&redirect_uri=http%3A%2F%2Flocalhost%3A5556%2Fauth%2Fcallback&response_type=code&scope=openid+email&state=1zkBCehKiBjIMt1J2hcTYhBae9s
Successfully verified SCT...
signing with ephemeral certificate:
-----BEGIN CERTIFICATE-----
MIICeDCCAf6gAwIBAgIUAPcTDhgn++dgD7008s+TuiLwUgcwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMTkyMjIxMjZaFw0yMTEwMTkyMjQxMjVaMAAwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASkOb5x7wCiyBLs7Q0ehqD31U6Lr+x0kH9WDcp5ONm7WBeGTAyth5Rz
gJBpkVtv/UzgF5BNKUfEVtm8pal7sZBso4IBKjCCASYwDgYDVR0PAQH/BAQDAgeA
MBMGA1UdJQQMMAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFAP3
+cBsWpnLMQvm0Tv6qCVQ0PYiMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1K
BtPsMIGNBggrBgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAChnBodHRwOi8vcHJpdmF0
ZWNhLWNvbnRlbnQtNjAzZmU3ZTctMDAwMC0yMjI3LWJmNzUtZjRmNWU4MGQyOTU0
LnN0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vY2EzNmExZTk2MjQyYjlmY2IxNDYvY2Eu
Y3J0MCEGA1UdEQEB/wQXMBWBE3ByaXlhdzgxOUBnbWFpbC5jb20wCgYIKoZIzj0E
AwMDaAAwZQIxAL2tZYELi3hGJS8sGTCGPKz83brdM4aak0v+SMMQGnyas7bY7tdm
DoyAJmxwWx2ntQIwPyM1A5nE+f2Pg9CkQqyZEFS2sxQTdKBmQzODDn6GqVTJ7agN
2djlcXFUJb1xFwO5
-----END CERTIFICATE-----

tlog entry created with index: 782549
MEUCIGi9CuxAceEcNkGLani2i3GdMgbl4bkGLILDhjh8n7DAAiEAhRwgfXMhnXyB38EZtOZX7fwtJBaSetMM88mZyYsV0pM=
```

Now find it from the log:

```
$ uuid=$(rekor-cli search --artifact <(git rev-parse HEAD) | tail -n 1)
$ sig=$(rekor-cli get --uuid=$uuid --format=json | jq -r .Body.RekordObj.signature.content)
$ cert=$(rekor-cli get --uuid=$uuid --format=json | jq -r .Body.RekordObj.signature.publicKey.content)

$ cosign verify-blob --cert <(echo $cert | base64 --decode) --signature <(echo $sig) <(git rev-parse HEAD)
Certificate is trusted by Fulcio Root CA
Email: [your-email@yay.com]
Verified OK
```
