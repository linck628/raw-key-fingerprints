---
title: "Session Description Protocol Fingerprints for Raw Public Keys in (Datagram) Transport Layer Security"
abbrev: "SDP Fingerprints for Raw Keys in (D)TLS"
category: std

docname: draft-lennox-raw-key-fingerprints-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "ART"
keyword:
 - sdp
 - fingerprints
 - raw public keys
venue:
  github: "JonathanLennox/raw-key-fingerprints"

author:
 -
    fullname: Jonathan Lennox
    organization: 8x8, Inc / Jitsi
    email: jonathan.lennox@8x8.com

normative:

informative:


--- abstract

When a Transport-Layer Security or Datagram Transport-Layer Security
connection is negotiated using the Session Desccription Protocol,
certificates are validated using certificate fingerprints specified in
the SDP, rather than by any information carried in the certificate.
Typically these certificates are self-signed.
The only information carried in these certificates that is used by the
process are the public keys; the rest of the information is useless.
This other information can be large, and once post-quantum
public keys are needed, the self-signed signature in particular will
be very large.

Transport-Layer Security (and Datagram Transport-Layer Security) now
support using raw keys, rather than X.509 certificates, in
circumstances such as these.  This document defines how such raw key
certificates can be negotiated in SDP.

--- middle

# Introduction

When a Transport-Layer Security {{!RFC8446}} {{!RFC5246}} or Datagram
Transport-Layer Security {{!RFC9147}} {{!RFC6347}}
connection is negotiated using the Session Desccription Protocol {{!RFC8866}},
certificates are validated using certificate fingerprints specified in
the SDP {{!RFC8122}}, rather than by any information carried in the certificate.
Typically these certificates are self-signed.
The only information carried in these certificates that is used by the
process are the public keys; the rest of the information is useless.
This other information can be large, and once post-quantum
public keys are needed, the self-signed signature in particular will
be very large.

Transport-Layer Security (and Datagram Transport-Layer Security) now
support using raw keys, rather than X.509 certificates, in
circumstances such as these {{!RFC7250}}.  This document defines how such raw key
certificates can be negotiated in SDP.

TODO: give figures on how much larger certs are than raw keys, both
for current EC-based ones and for PQ.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Protocol

## The "raw-key-fingerprint" attribute. {#sdp-attribute}

This document defines an SDP attribute, "raw-key-fingerprint".  The
content of its syntax is the same as the "fingerprint" attribute defined in
{{!RFC8122}}, as specified in {{figabnf}}.

~~~~~~~~~~

attribute /= raw-key-fingerprint-attribute

raw-key-fingerprint-attribute = \
                      "raw-key-fingerprint" ":" hash-func fingerprint
                      ; hash-func and fingerprint are defined
                      ; in [RFC8122]
~~~~~~~~~~
{: #figabnf title="ABNF for the raw-key-fingerprint attribute"}

A raw key fingerprint is a secure one-way hash of the distinguished
Encoding Rules (DER) form of the raw key, in the form specified in
{{Section 3 of !RFC7050}} when the appropriate certificate_type
value is RawPublicKey.

As in {{!RFC8122}}, the raw key fingerprint is represented as
upper-case hexidecimal bytes, separated by colons.  The number of
bytes is defined by the hash function.



## SDP Offer/Answer procedures

In SDP offer/answer {{!RFC3264}}, if the endpoint creating an SDP
offer wishes to use raw public keys for TLS or DTLS, the offerer
includes an SDP "raw-key-fingerprint" attribute describing its raw
public key at the session level or the appropriate media levels.  In
an initial offer, it SHOULD also include a valid SDP "fingerprint"
attribute for a self-signed X.509 certificate as defined in
{{!RFC8122}}, unless it knows for certain through out-of-bound means
that the peer that will be performing the answer definitely supports
raw keys.

In its answer, the answerer then includes a "raw-key-fingerprint" with
the fingerprint of its own raw public key.  It MAY omit the SDP
"fingerprint" attribute.

Either the offerer or the answerer MAY include multiple
"raw-key-fingerprint" attributes, for example if they want to provide
a fingerprint hashed with multiple different hash functions, or if the
media negotiated by the offer/answer might end up at one of several
different endpoints which have different public keys.

In subsequent offers, an offerer MUST send the same
"raw-key-fingerprint" value as long as the same TLS/DTLS session
remains.  It MAY omit "fingerprint" attributes
when the state of the connection attribute {{!RFC4145}} is "existing"
and the value of the raw key fingerprint is unchanged.
If it sends an offer with "connection:new", or the fingerprint
changes, it SHOULD include both "fingerprint" and
"raw-key-fingerprint" attributes under the same rules as it would use
for an initial offer.

### TLS/DTLS procedures for SDP Offer/Answer connections.

The TLS client and server roles are negotiated for the session
following the mechanisms defined in {{!RFC4145}}; the endpoint in the
"active" role will be the client.

If raw keys have been offered in SDP, the initial ClientHello of the
transaction MUST include both a ClientCertTypeExtension and a
ServerCertTypeExtension including RawPublicKey as one of the types.
If the client has already seen its peer's offer or answer including a
"raw-key-fingerprint" SDP attribute, this MAY be the only type listed
in the extensions; otherwise, if the client's offer or answer included
a "fingerprint" attribute, the extension lists MUST also include X509.

The server's ServerHello MUST then sends a ClientCertTypeExtension
and a ServerCertTypeExtension listing RawPublicKey as the type, as
well as its own raw public key in the Certificate and a certificate
request for the client.  The client then sends its own raw key.

Both client and server MUST verify that the raw key fingerprint
signaled in SDP matches that of the raw public key received in SDP,
and terminate the TLS or DTLS connection with a bad_certificate error
if not.  Note that in some circumstances a ClientHello or ServerHello
may outrace an SDP answer; application data MUST NOT be sent over the
TLS connection until the fingerprint has been received and validated.

If multiple raw key fingerprints are present, a certificate is valid
if at least one fingerprint is valid using a hash function that the
entity considers sufficiently secure.

## SDP Advertisements

Older uses of SDP (such as RTSP {{?RFC7826}}) use advertised SDP
rather than offer/answer.  In this mode, an entity presents an SDP
description that other endpoints can then connect to freely, without
providing a matching SDP description.

When raw key fingerprints are used in this case, the SDP describes the
TLS server.  Clients connect using the standard TLS client/server
procdure. Clients MUST validate that the raw key provided in the
connection matches the raw key fingerprint in the SDP.

# Design choices

In theory, raw key fingerprints could have been specified as another
value for the "a=fingerprint:" SDP attribute, rather than defining the
new SDP attribute "a=raw-key-fingerprint:".  {{!RFC8122}} defines how
multiple such attributes of that type are to be processed, and if
implementations followed those recommendations, backward compatibility
with implementations not implementing this specification would work
correctly.

However, as {{!RFC8122}}'s predecessor {{?RFC4572}} did not specify
processes for handling multiple fingerprint attributes, and as
multiple fingerprint attributes are not commonly used, the designers
of this specification felt that it was uncertain whether all
implementations would correctly handle multiple fingerprint
attributes.  Thus, a new attribute was defined, which would be ignored
by existing implementations under the normal SDP rules to ignore
unknown attributes.

This also allows an SDP answerer to include only the
raw-key-fingerprint attribute, omitting the fingerprint attribute, in
its answer if it has seen one in an offer, even if it has not yet seen
a TLS or DTLS ClientHello containing a CertTypeExtension.  (In the common case
where DTLS is run over ICE {{?RFC8845}}, as in WebRTC {{?RFC8835}}, a
ClientHello architecturally cannot arrive before the SDP answer is
sent, because the peer does not know the address to send it to.)

# Possible follow-ons {#follow-ons}

Two protocols have defined mechanisms by which SDP fingerprints can be
signed to ensure their end-to-end security: PASSPorT {{?RFC8225}} and
WebRTC Identity Providers {{?RFC8827}}.  Unfortunately, the latter has
seen no deployment as far as the author is aware; and the former,
while widely implemented to authenticate calling party telephone
numbers, has not seen much if any adoption of the mode that signs
certificate fingerprints.

Nonetheless, both of these mechanisms could easily be extended so as
to secure raw key fingerprints as well.

TODO: Should we actually define these extensions?  Is it worth the
trouble?

# Security Considerations

The security of a TLS or DTLS connection negotiated using the
mechanisms defined in this document is identical to that of a
connection negotiated via the mechanism in {{!RFC8122}}.  All the
security considerations of that document also apply to this one.  As
identity information is normally not used from the SDP-negotiated
certificates, this mechanism should have identical security properties
to that of {{!RFC8122}}.

As with {{!RFC8122}} fingerprints, the mechanism in this document is
vulnerable to an attacker who can modify the signaled fingerprints and
launch a meddler-in-the-middle attack.  See {{follow-ons}} for various
proposed methods to prevent this attack.


# IANA Considerations

This document defines an SDP session and media-level attribute:
'raw-key-fingerprint'.  Its format is defined in Section
{{sdp-attribute}}.  This attribute should registered by IANA under the
"att-field (both session and media level)" registry within the
"Session Description Protocol (SDP) Parameters" registry.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
