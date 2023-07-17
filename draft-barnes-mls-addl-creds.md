---
title: "Additional MLS Credentials"
abbrev: "Additional MLS Credentials"
category: info

docname: draft-barnes-mls-addl-creds-latest
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
  OpenIDUserInfoVC:
    target: https://openid.net/specs/openid-connect-userinfo-vc-1_0.html
    title: "OpenID Connect UserInfo Verifiable Credentials 1.0"
    date: 2022-12-15
    author:
       - name: Morteza Ansari
       - name: Richard Barnes
       - name: Pieter Kasselman
       - name: Kristina Yasuda

informative:


--- abstract

This specification defines two new kinds of credentials for use within the
Message Layer Security (MLS) credential framework: UserInfo Verifiable
Credentials and multi-credentials.  UserInfo Verifiable Credentials allow
clients to present credentials that associate OpenID Connect attributes to a
signature key pair held by the client.  Multi-credentials allow clients to
present authenticated attributes from multiple sources, or to present
credentials in different formats to support groups with heterogeneous credential
support.

--- middle

# Introduction

MLS provides end-to-end authenticated key exchange {{!I-D.ietf-mls-protocol}}.
Each client participating in an MLS group is authenticated with a credential.
The MLS credential structure is extensible: New MLS credential formats can be
defined which support new mechanisms for authenticating clients.

In this document, we define two new types of credential:

* Credentials based on OpenID Connect UserInfo Verifiable Credentials
* Multi-credentials that present several credentials at once

UserInfo Verifiable Credentials (VCs) are a mechanism by which an OpenID
Provider can bind user attributes to a signature key pair. OpenID Connect is
already widely deployed as a mechanism for connecting authentication services to
applications, and the OpenID Foundation is in the process of standardizing the
extensions required for OpenID Providers to issue UserInfo VCs.

Multi-credentials address use cases where there might not be a single credential
that captures all of a client's authenticated attributes.  For example, an
enterprise messaging client may wish to provide attributes both from its messaging
service, to prove that its user has a given handle in that service, and from its
corporate owner, to prove that its user is an employee of the corporation.
Multi-credentials can also be used in migration scenarios, where some clients in
a group might wish to rely on a newer type of credential, but other clients
haven't yet been upgraded.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 [RFC2119].

This specification uses terms from the MLS Protocol specification.  In
particular, we refer to the MLS Credential object, which represents an
association between a client's identity and the signature key pair that the
client will use to sign messages in the MLS key exchange protocol.

# UserInfo Verifiable Credentials

As described in the MLS architecture, MLS requires an Authentication Service
(AS) as well as a Delivery Service (DS) {{!I-D.ietf-mls-architecture}}.  The full
security goals of MLS are only realized if the AS and DS are non-colluding.
In other words, applications can deploy MLS to get end-to-end encryption
(acting as MLS Delivery Service), but they need to partner with a non-colluding
Authentication Service in order to achieve full end-to-end security.

OpenID Connect is widely used to integrate identity providers with applications,
but its current core protocol doesn't provide the binding to cryptographic keys
required for use in MLS.  When OpenID Connect is coupled with the
"Verifiable Credentials" framework, however, it can be used to provision clients
with signed "UserInfo VC" objects that contain the critical elements of a
credential to be used in MLS:

* Identity attributes for the user of a client
* A public key whose private key is held by a client
* A signature over the above by a trusted identity provider

The required updates to OpenID Connect are specfied in {{OpenIDUserInfoVC}}.  That
document defines a profile of the OpenID for Verifiable Credential Issuance
protocol for issuing "UserInfo Verifiable Credentials".  These credentials bind
a signature key pair to the user attributes typically exposed through the OpenID
Connect UserInfo endpoint.

A "UserInfoVC" credential encapsulates a UserInfo Verifiable Credential object,
so that it can be used for authenticating an MLS client. We also describe the
validation process that MLS clients use to verify UserInfoVC objects that they
receive via MLS.

## UserInfo VC Life-Cycle

~~~ aasvg
   +----+
   |    | (1) Generate signature key pair
   |    V
+----------+                                   +----------+
|          |<===(2) OpenID Connect Login======>|          |
|          |                                   |          |
|          |                                   |          |
|          |-------(3) Credential Request----->|  OpenID  |
| Client 1 |     (type=UserInfoCredential,     | Provider |
|          |      token & proof)               |   (OP)   |
|          |                                   |          |
|          |<------(4) Credential Response-----|          |
|          |         (credential)              |          |
+----------+                                   +----------+
      |                                             ^
      | (5) UserInfoVC in MLS KeyPackage            |
      |                                             |
      v                                             |
+----------+                                        |
|          |                                        |
|          | (6) Fetch JWK set, Verify JWT          |
|          |        Signature                       |
| Client 2 |<---------------------------------------+
|          |----+
|          |    | (7) Validate vc claim using
|          |<---+     OP's JWK
+----------+

            OpenID Connect UserInfo VC MLS Credential Flow
~~~
{: #userinfo-vc-life title="The protocol interactions to issue and verify a UserInfo VC" }

The basic steps showing OIDC Verifiable Credential based MLS credential flow are
shown in {{userinfo-vc-life}}.

Client 1 is an MLS client that acts as a Holder in the VC model.  Client 2 is
also an MLS client, but acts in the Verifier role in the VC model.  Both clients
implement certain OpenID Connect operations to obtain and verify UserInfo VC
objects.

1. Client 1 generates a signature key pair using an algorithm that is supported
   by both MLS and UserInfo VC.

2. Client 1 performs an OpenID Connect login interaction with the scope
   "userinfo_credential"  to obtain UserInfo VCs.

2. Client 1 sends a Credential Request specifying that it desires a UserInfo VC,
   together with a proof that it controls the private key of a signature key pair
   and the access token.

3. The OpenID Provider verifies the proof and create a Credential Response
   containing the UserInfo VC attesting the claims that
   would have been provided by the UserInfo endpoint and public key
   corresponding to the private key used to compute the proof in the Credential
   Request.

4. Client 1 generates a `UserInfoVC` MLS Credential object with the
   signed UserInfo VC JWT. Client 1 embeds the `UserInfoVC` in an MLS
   KeyPackage object and signs the KeyPackage object with the corresponding
   private key.

5. Client 1 sends the KeyPackage to Client 2, e.g., by posting it to a directory
   from which Client 2 fetches it when it wants to add Client 1 to a group.

6. Client 2 verifies the signature on the KeyPackage and extracts the
   UserInfoVC credential. Client 2 uses OpenID Connect Discovery to fetch the OpenID
   Provider's JWK set.

7. Client 2 verifies the signed UserInfo VC using the the appropriate key from the
   OpenID Provider's JWK set.

If all checks pass,  Client 2 has a high degree of assurance of the identity of
Client 1.  At this point Client 1's KeyPackage (including the VerifiableCredential)
will be included in the MLS group's ratchet tree and distributed to the other
members of the group.  The other members of the group can verify the
VerifiableCredential in the same way as Client 2.

## UserInfoVC

A new credential type `UserInfoVC` is defined as shown below. This credential
type is indicated with the CredentialType value `userinfo_vc` (see {{iana}}).

~~~~~ tls-presentation
struct {
    opaque jwt<0..2^32-1>;
} UserInfoVC;
~~~~~

The `jwt` field contains the signed JWT-formatted UserInfo VC object
(as defined in {{OpenIDUserInfoVC}}), encoded using UTF-8.
The payload of object MUST provide `iss` and `vc` claims.  The `iss` claim is
used to look up the OpenID Provider's metadata.  The `vc` claim contains
authenticated user attributes and a public key binding.  Specifically, the field
`vc.credentialSubject.id` contains a `did:jwk` URI describing the subject's
public key as a JWK.

## Credential Validation

An MLS client validates a UserInfoVC credential in the context of an MLS
LeafNode with the following steps:

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
  - Verify that the value of the claim is a JSON object that contains a
    `credentialSubject` field, as defined in Section 4 of openid-userinfo-vc.
  - Verify `id` field exists and it MUST be a a Decentralized Identifier with
    DID method jwk (W3c.did-core).
  - Verify that the `jwk` field parses as a JWK.
  - Verify that the `signature_key` in the LeafNode matches the key in the `id` field.

If all of the above checks pass, the client can use the signature key in the JWK
for verifying MLS signatures using the signature scheme corresponding to the
`kty` and `crv` parameters in the JWK.  The identity attributes in the JWT
should be associated with the MLS client that presented the credential.

## Mapping between JWK Key Types and MLS Ciphersuites

Below table maps JWK key types (`kty`) and elliptic curves (`crv`) to the
equivalent MLS signature scheme.

| `kty` | `crv`     | TLS/MLS signature scheme     |
|:-----:|:---------:|:-----------------------------|
| `EC`  | `P-256`   | ECDSA with P-256 and SHA-256 |
| `EC`  | `P-384`   | ECDSA with P-384 and SHA-384 |
| `EC`  | `P-521`   | ECDSA with P-521 and SHA-512 |
| `EC`  | `Ed25519` | Ed25519                      |
| `EC`  | `Ed448`   | Ed448                        |


# Multi-Credentials

New credential types `MultiCredential` and `WeakMultiCredential` are defined as
shown below. These credential types are indicated with CredentialType values
`multi` and `weak-multi` (see {{iana}}).

~~~ tls-presentation
struct {
  CipherSuite cipher_suite;
  Credential credential;
  SignaturePublicKey credential_key;

  /* SignWithLabel(., "CredentialBindingTBS", CredentialBindingTBS) */
  opaque signature<V>;
} CredentialBinding

struct {
  CredentialBinding bindings<V>;
} MultiCredential;

struct {
  CredentialBinding bindings<V>;
} WeakMultiCredential;
~~~

The two types of credentials are processed in exactly the same way.  The only
difference is in how they are treated when evaluating support by other clients,
as discussed below.

## Credential Bindings

A multi-credential consists of a collection of "credential bindings".  Each
credential binding is a signed statement by the holder of the credential that
the signature key in the LeafNode belongs to the holder of that credential.
Specifically, the signature is computed using the MLS `SignWithLabel` function,
with label `"CredentialBindingTBS"` and with a content that covers the contents
of the CredentialBinding, plus the `signature_key` field from the LeafNode in
which this credential will be embedded.

~~~ tls-presentation
struct {
  CipherSuite cipher_suite;
  Credential credential;
  SignaturePublicKey credential_key;
  SignaturePublicKey signature_key;
} CredentialBindingTBS;
~~~

The `cipher_suite` for a credential is NOT REQUIRED to match the cipher suite
for the MLS group in which it is used, but MUST meet the support requirements
with regard to support by group members discussed below.

## Verifying a Multi-Credential

A credential binding is supported by a client if the client supports the
credential type and cipher suite of the binding.  A credential binding is valid
in the context of a given LeafNode if both of the following are true:

* The `credential` is valid according to the MLS Authentication Service.

* The `credential_key` corresponds to the specified `credential`, in the same
  way that the `signature_key` would have to correspond to the credential if
  the credential were presented in a LeafNode.

* The `signature` field is valid with respect to the `signature_key` value in
  the leaf node.

A client that receives a credential of type `multi` in a LeafNode MUST verify
that all of the following are true:

* All members of the group support credential type `multi`.

* For each credential binding in the multi-credential:

  * Every member of the group supports the cipher suite and credential type
    values for the binding.

  * The binding is valid in the context of the LeafNode.

A client that receives a credential of type `weak-multi` in a LeafNode MUST verify
that all of the following are true:

* All members of the group support credential type `multi`.

* Each member of the group supports at least one binding in the
  multi-credential.  (Different members may support different subsets.)

* Every binding that this client supports is valid in the context of the
  LeafNode.

# Security Considerations

The validation procedures for UserInfoVC credentials verify that a JWT came from
a given issuer.  It doesn't verify that the issuer is authorative for the
claimed attributes.  The client needs to verify that the issuer is trusted to
assert the claimed attributes.

# Privacy Considerations

UserInfo can contain sensitive info such as human names, phone numbers, and
using these credentials in MLS will expose this information to other group
members, and potentially others if used in a prepublished KeyPackage.

# IANA Considerations {#iana}

## MLS Credential Types

IANA is requested to register add the following new entries to the MLS Credential
Type registry.

| Value            | Name                     | Recommended | Reference |
|:=================|:=========================|:============|:==========|
| 0x0003           | userinfo-vc              | Y           | RFC XXXX  |
| 0x0004           | multi                    | Y           | RFC XXXX  |
| 0x0005           | weak-multi               | Y           | RFC XXXX  |

--- back

