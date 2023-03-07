---
title: "UserInfo Verifiable Credentials as MLS Credentials"
abbrev: "MLS UserInfo VC"
category: info

docname: draft-barnes-mls-userinfo-vc-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "bifurcation/mls-userinfo-vc"

author:
 -
    fullname: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx
 -
    fullname: Suhas Nandakumar
    organization: Cisco
    email: snandaku@cisco.com

normative:

informative:


--- abstract

This specification extends Message Layer Security (MLS) credentials framework
with a new credential type, "VerifiableCredential", based on the OpenID Connect UserInfo Verifiable Credential type  "UserInfoCredential". A UserInfo Verifiable Credential enapsulates the UserInfo claims from the OpenID provider as a Verifiable Credential that can be presented to a third-party Verifier. These credentials can be easily provisioned to MLS clients using the OpenID Connect login flows, augmented with type "UserInfoCredential". The credential itself is an object associating identity attributes to the signature public key that the client will use in MLS, signed by the OpenID Provider. In situations where the OpenID Provider is distinct from the MLS Delivery Service, these credentials provide end-to-end secure identity assurance.

--- middle

# Introduction

MLS provides end-to-end authenticated key exchange [@!I-D.ietf-mls-protocol].
As described in the MLS architecture, MLS requires an Authentication Service
(AS) as well as a Delivery Service (DS) [@!I-D.ietf-mls-architecture].  The full
security goals of MLS are only realized if the AS and DS are non-colluding.
In other worlds, applications can deploy MLS to get end-to-end encryption
(acting as MLS Delivery Service), but they need to partner with a non-colluding
Authentication Service in order to achieve full end-to-end security.

OpenID Connect is widely used to integrate identity providers with applications
XXXX, but its current core protocol doesn't provide the binding to
cryptographic keys required for end-to-end security.  When OpenID Connect is
coupled with the "Verifiable Credential" framework, however, it can be used to provision clients with signed "UserInfo VC" objects, that contain the critical elements of a credential to be used in MLS:

* Identity attributes for the user of a client
* A public key whose private key is held by a client
* A signature over the above by a trusted identity provider

The required updates to OpenID Connect are specfied in "openid-connect-userinfo-vc".  That document defines a profile of the OpenID for Verifiable Credential Issuance protocol for issuing "UserInfo VC", that allows a client to bind a signature key pair to the claims about the UserInfo. The inclusion of "UserInfo VC"
information in Credential responses is especially compelling when "UserInfo VC"
responses are signed as JWTs (see Section 5.3.2 of [!@OpenID]). A JWT "UserInfo VC"
object serves as a signed statement from the provider associating a set of identity attributes to the client's public key.

In this document, we describe a "VerifiableCredential" credential type for MLS that encapsulates a signed UserInfo object as Verifiable Credential, so that it can be used for authenticating an MLS client. We also describe the validation process that MLS clients use to verify UserInfoVC objects that they receive via MLS.


# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 [RFC2119].

## Terminology

This specification uses terms from the MLS Protocol specification.  In
particular, we refer to the MLS Credential object, which represents an
association between a client's identity and the signature key that the client
will use to messages in the MLS key exchange protocol.

# Concept

~~~ ascii-art
   +----+
   |    | (1) Generate signature key pair
   |    V
+----------+                                   +----------+
|          |<~~~(2) OpenID Connect Login~~~~~~>|          |
|          |                                   |          |
|          |                                   |          |
|          |-------(3) Credential Request----->|  OpenID  |
| Client 1 |     (type=UserInfoCredential,     | Provider |
|          |      token & proof)               |   (OP)   |
|          |                                   |          |
|          |<------(4) Credential Response-----|          |
|          |         (credential)              |          |
+----------+                                   +----------+
      :                                             ^
      : (5) UserInfo VC in MLS KeyPackage           |
      :                                             |
      v                                             |
+----------+                                        |
|          |                                        |
|          | (6) Fetch JWK set, Verify JWT          |
|          |        Signature                       |
| Client 2 |<----------------------------------------
|          |----+
|          |    | (7) Validate cnf claim using
|          |<---+     OP's JWK
+----------+

            OpenID Connect UserInfo VC MLS Credential Flow
~~~

The basic steps showing OIDC Verifiable Credential based MLS credential flow are shown above.

Client 1 acts as an Holder (in the VC model) and as an MLS client. Client 2
is an MLS client and acts as Verifier (in the VC model) and implements certain OpenID Connect operations that enable it to verify signed UserInfo VC objects.

1. Client 1 generates a signature key pair using an algorithm that is supported
   by both MLS and UserInfo VC.

2. Client 1 performs an OpenID Connect login interaction with the scope
   "userinfo_credential"  to obtain UserInfo VCs.

2. Client 1 sends a Credential Request specifying that it desires a UserInfo VC,
   together with a proof that it controls the private key of a signature key pair
   and the access token.

3. The OpenID Provider verifies the proof and create a Credential Response
   containing the "UserInfo VC", as JWT-formatted VC, attesting the claims that would have been provided by the UserInfo endpoint and public key corresponding to the private key used to compute the proof in the Credential Request.

4. Client 1 generates a `VerifiableCredential` MLS Credential object with the signed
   UserInfo VC JWT object and the signature key bound to UserInfo VC through "vc" claim. Client 1 embeds the `VerifiableCredential` in an MLS KeyPackage object and signs the KeyPackage object with the corresponding private key. Client 1 sends the KeyPackage to Client 2, e.g., by posting it to a directory from which Client 2 fetches it when it wants to add Client 1 to a group.

5. Client 2 verifies the signature on the KeyPackage and extracts the
   UserInfoVCCredential. Client 2 uses OpenID Connect Discovery to fetch the OpenID
   Provider's JWK set.

6. Client 2 verifies the signed UserInfo VC using the the appropriate key from the
   OpenID Provider's JWK set.

If all checks pass,  Client 2 has a high degree of assurance of the identity of
Client 1.  At this point Client 1's KeyPackage (including the VerifiableCredential)
will be included in the MLS group's ratchet tree and distributed to the other
members of the group.  The other members of the group can verify the
VerifiableCredential in the same way as Client 2.

# VerifiableCredential {#vc}

A new credential type called "VerifiableCredential" is defined as shown below. This
credential type is indicated with CredentialType `vc` {{iana}}

~~~~~
struct {
    opaque jwt<0..2^32-1>;
    opaque jwk<0..2^16-1>;
} VerifiableCredential;
~~~~~

The `jwt` field contains the signed JWT-formatted UserInfo VC object
(as defined in  Section 6.3.1 of [W3C.vc-data-model]), encoded using UTF-8.
The payload of object MUST provide "iss" and "vc" claims.  The "iss" claim is
used to look up the OpenID Provider's metadata.  The "id" field within the
"credentialSubject" object under the "vc" claim is used to verify the binding
to the provided signature public key.

The `jwk` contains the client's signature public key, encoded as a JWK using
UTF-8 [@!RFC7517].  The "kty" and "crv" fields of this JWK MUST reflect an
MLS-compatible signing scheme, in the sense that there MUST be a corresponding
entry in the mapping table in {{ciphersuites}}.  The credential is considered
malformed if no such mapping can be found.

## Credential Validation

An MLS client validates a VerifiableCredential with the following steps:

* Verify that the `jwt` field parses successfully into a JWT [!@RFC7519], whose
  payload parses into UserInfo object as defined in Section 5.3.2 of [!@OpenID].

* Verify that an `iss` claim is present in the UserInfo VC payload and that "iss"
  value represents and issuer that is trusted according to the client's local
  policy.

* Verify the JWT signature:
  - Fetch the issuer metadata using OIDC Discovery [@!OpenID.Discovery].
  - Use the `jwks_uri` field in the metadata to fetch the JWK set.
  - Verify that the JWT signature verifies under one of the keys in the JWK
    set.

* Verify the key binding:
  - Verify that a `vc` claim is present in the UserInfo VC payload.
  - Verify that the value of the claim is a JSON object that contains a `credentialSubject` field, as defined in Section 4 of openid-userinfo-vc.
  - Verify `id` field exists and it MUST be a a Decentralized Identifier with DID method jwk (W3c.did-core).
  - Verify that the `jwk` field parses as a JWK.
  - Compute the JWK Thumbprint of the JWK [!@RFC7638].
  - Verify that the computed JWK Thumbprint matches the `jkt` field.

If all of the above checks pass, the client can use the signature key in the JWK
for verifying MLS signatures using the signature scheme corresponding to the
`kty` and `crv` parameters in the JWK.  The identity attributes in the JWT
should be associated with the MLS client that presented the credential.


## Mapping between JWA and MLS Ciphersuites {#ciphersuites}

Below table maps JWK key types (`kty`) and elliptic curves (`crv`) to the
equivalent MLS signature scheme.

| `kty` | `crv`     | TLS/MLS signature scheme |
|:-----:|:---------:|:-------------------------|
| `EC`  | `P-256`   | `ecdsa_secp256r1_sha256` |
| `EC`  | `P-384`   | `ecdsa_secp384r1_sha384` |
| `EC`  | `P-521`   | `ecdsa_secp521r1_sha512` |
| `EC`  | `Ed25519` | `ed25519`                |
| `EC`  | `Ed448`   | `ed448`                  |


# Security Considerations

The validation procedures specified verify that a JWT came from a given issuer.
It doesn't veirfy that the issuer is authorative for the claimed attributes.
The client needs to verify that the issuer is trusted to assert the claimed
attributes.

# Privacy Considerations

UserInfo can contain sensitive info such as human names, phone numbers, and using these
credentials in MLS will expose this information to other group members, and potentially
others if used in a prepublished KeyPackage.


# IANA Considerations {#iana}

## MLS Credential Type

IANA is requested to register add the following new entry to the MLS Credential
Type registry.

| Value            | Name                     | Recommended | Reference |
|:=================|:=========================|:============|:==========|
| 0x0003           | vc                       | Y           | RFC XXXX  |



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
