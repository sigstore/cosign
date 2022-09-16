# ACMEv1 divergences from ACME draft versions

Boulder primarily supports the final version of ACME, informally called ACMEv2
and offered by Let's Encrypt at https://acme-v02.api.letsencrypt.org/. During a
transition period, Boulder still supports ACMEv1, which was developed alongside
the ACME standard as it developed. ACMEv1 doesn't exactly match any draft
version, but here we will define the ACMEv1 implementation in terms of its
divergences from draft 7 of ACME.

If you're developing a new client, or updating an existing client, you should
target the ACMEv2 API. See acme-divergences.md for details of that API.

**ACME v1 divergences from [`draft-ietf-acme-acme-07`](https://tools.ietf.org/html/draft-ietf-acme-acme-07).**

## [Section 6](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-6)

Boulder does not implement the [general JWS syntax](https://tools.ietf.org/html/rfc7515#page-20), but only accepts the [flattened syntax](https://tools.ietf.org/html/rfc7515#page-21).

## [Section 6.2](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-6.2)

Boulder enforces the presence of the `jwk` field in JWS objects, and does not support the `kid` field.

## [Section 6.3.1](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-6.3.1)

Boulder does not use the `url` field from the JWS protected resource. Instead Boulder will validate the `resource` field from the JWS payload matches the resource being requested. Boulder implements the resource types described in [draft-ietf-acme-02 Section 6.1](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.1) plus the additional "KeyChange" resource. Boulder verifies the `resource` field contains the `/directory` URI for the requested resource.

## [Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-6.5)

Boulder does not provide a `Retry-After` header when a user hits a rate-limit, nor does it provide `Link` headers to further documentation on rate-limiting.

## [Section 6.6](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-6.6)

Boulder doesn't return errors under the `urn:ietf:params:acme:error:` namespace but instead uses the `urn:acme:error:` namespace from [draft-ietf-acme-01 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4).

Boulder uses `invalidEmail` in place of the error `invalidContact` defined in [draft-ietf-acme-01 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4).

Boulder does not implement the `unsupportedContact` and `accountDoesNotExist` errors.

Boulder does not implement the `caa` and `dnssec` errors.

## [Section 7.1](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.1)

Boulder does not implement the `new-order` resource (previously referred to as `new-application`). Instead of `new-order` Boulder implements the `new-cert` resource that is defined in [draft-ietf-acme-02 Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5).

Boulder also doesn't implement the `new-nonce` endpoint.

Boulder implements the `new-account` resource only under the `new-reg` key.

Boulder implements Link: rel="next" headers from new-reg to new-authz, and
new-authz to new-cert, as specified in
[draft-02](https://tools.ietf.org/html/draft-ietf-acme-acme-02#page-15), but
these links are not provided in the latest draft, and clients should use URLs
from the directory instead.

Boulder does not provide the "index" link relation pointing at the directory URL.

## [Section 7.1.2](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.1.2)

Boulder does not implement the `terms-of-service-agreed` or `orders` fields in the registration object (nor the endpoints the latter links to).

## [Section 7.1.3](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.1.3)

Boulder does not implement orders (previously called `applications`), instead it implements the `new-cert` flow from [draft-ietf-acme-02 Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5). Instead of authorizations in the order response, Boulder currently uses authorizations that are created using the `new-authz` flow from [draft-ietf-acme-02 Section 6.4](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.4).

## [Section 7.1.4](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.1.4)

Boulder does not implement the `scope` field in authorization objects.

## [Section 7.2](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.2)

Boulder doesn't implement the `new-nonce` endpoint, instead it responds to `HEAD` requests with a valid `Replay-Nonce` header per [draft-ietf-acme-03 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-5.4).

## [Section 7.3](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.3)

Boulder only allows `mailto` URIs in the registrations `contact` list.

Boulder uses an HTTP status code 409 (Conflict) response for an already existing registration instead of 200 (OK). Boulder returns the URI of the already existing registration in a `Location` header field instead of a `Content-Location` header field.

Boulder does not return the `status` field.

Boulder does not implement the `only-return-existing` field.

## [Section 7.3.1](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.3.1)

Boulder does not implement the `only-return-existing` behaviour and will always create a new account if an account for the given key does not exist.

## [Section 7.3.6](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.3.6)

Boulder implements draft-05 style key roll-over with a few divergences. Since Boulder doesn't currently use the registration URL to identify users we do not check for that field in the JWS protected headers but do check for it in the inner payload. Boulder also requires the outer JWS payload contains the `"resource": "key-change"` field.

## [Section 7.4](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.4)

Boulder does not implement orders (previously called `applications`), instead it implements the `new-cert` flow from [draft-ietf-acme-02 Section 6.5](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5). Instead of authorizations in the order response, Boulder currently uses authorizations that are created using the `new-authz` flow from [draft-ietf-acme-02 Section 6.4](https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.4). Certificates are not proactively issued, a user must request issuance via the `new-cert` endpoint instead of assuming a certificate will be created once all required authorizations are validated.

## [Section 7.4.2](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.4.2)

Boulder does not process `Accept` headers for `Content-Type` negotiation when retrieving certificates. Boulder returns certificates with the `Content-Type` value `application/pkix-cert` instead of `application/pem-certificate-chain`.

## [Section 7.5](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.5)

Boulder returns an `uri` instead of an `url` field in challenge objects.

Boulder uses an HTTP status code 202 (Accepted) response for correct challenge responses instead of 200 (OK) as defined in [Section 7.1](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.1).

## [Section 8.2](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-8.2)

Boulder does not implement the ability to retry challenges or the `Retry-After` header.

## [Section 8.6](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-8.6)

Boulder does not implement the `oob-01` validation method.

## [Section 9.5](https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-9.6)

Boulder uses the `urn:acme:` namespace from [draft-ietf-acme-01 Section 5.4](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4) for errors instead of `urn:ietf:params:acme:`.
