//! # A low-level X.509 parsing and certificate signature verification library.
//!
//! x509-signature can verify the signatures of X.509 certificates, as well as
//! certificates made by their private keys.  It can also verify that a
//! certificate is valid for the given time. However, it is (by design) very
//! low-level: it does not know about *any* X.509 extensions, and does not parse
//! distinguished names at all.  It also provides no path-building facilities.
//! As such, it is not intended for use with the web PKI; use webpki for that.
//!
//! x509-signature’s flexibiity is a double-edged sword: it allows it to be used
//! in situations where webpki cannot be used, but it also makes it
//! significantly more dangerous.  As a general rule, x509-signature will accept
//! any certificate that webpki will, but it will also accept certificates that
//! webpki will reject.  If you find a certificate that x509-signature rejects
//! and webpki rejects, please report it as a bug.
//!
//! x509-signature was developed for use with
//! [libp2p](https://github.com/libp2p), which uses certificates that webpki
//! cannot handle.  Its bare-bones design ensures that it can handle almost any
//! conforming X.509 certificate, but it also means that the application is
//! responsible for ensuring that the certificate has valid X.509 extensions.
//! x509-signature cannot distinguish between a certificate valid for
//! `mozilla.org` and one for `evilmalware.com`!  However, x509-signature
//! does provide the hooks needed for higher-level libraries to be built on top
//! of it.
//!
//! Like webpki, x509-signature is zero-copy and `#![no_std]` friendly.  If
//! built without the `alloc` feature, x509-signature will not rely on features
//! of *ring* that require heap allocation, specifically RSA.  x509-signature
//! should never panic on any input.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(
    const_err,
    deprecated,
    improper_ctypes,
    non_shorthand_field_patterns,
    nonstandard_style,
    no_mangle_generic_items,
    renamed_and_removed_lints,
    unknown_lints,
    type_alias_bounds,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    rust_2018_idioms,
    unused,
    future_incompatible,
    clippy::all
)]
#![forbid(
    unconditional_recursion,
    unsafe_code,
    broken_intra_doc_links,
    while_true,
    elided_lifetimes_in_paths
)]

mod das;
mod sequence;
mod time;
use ring::io::der;
mod spki;
pub use das::DataAlgorithmSignature;
pub use sequence::{ExtensionIterator, SequenceIterator};
pub use spki::{parse_algorithmid, Restrictions, SubjectPublicKeyInfo};

pub use time::{days_from_ymd, seconds_from_hms, ASN1Time, MAX_ASN1_TIMESTAMP, MIN_ASN1_TIMESTAMP};

#[cfg(feature = "rustls")]
pub use r::SignatureScheme;

/// A signature scheme supported by this library
#[cfg(not(feature = "rustls"))]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[derive(Eq, PartialEq, Debug, Hash, Clone, Copy)]
pub enum SignatureScheme {
    /// RSA PKCS#1 signatures with SHA256
    RSA_PKCS1_SHA256,
    /// RSA PKCS#1 signatures with SHA384
    RSA_PKCS1_SHA384,
    /// RSA PKCS#1 signatures with SHA512
    RSA_PKCS1_SHA512,
    /// ECDSA signatures with SHA256
    ECDSA_NISTP256_SHA256,
    /// ECDSA signatures with SHA384
    ECDSA_NISTP384_SHA384,
    /// ed25519 signatures
    ED25519,
    /// RSA-PSS signatures with SHA256
    RSA_PSS_SHA256,
    /// RSA-PSS signatures with SHA384
    RSA_PSS_SHA384,
    /// RSA-PSS signatures with SHA512
    RSA_PSS_SHA512,
    /// ed448 signatures
    ED448,
}

#[cfg(not(feature = "webpki"))]
/// Errors that can be produced when parsing a certificate or validating a
/// signature.
///
/// More errors may be added in the future.
#[non_exhaustive]
#[derive(Eq, PartialEq, Debug, Hash, Clone, Copy)]
pub enum Error {
    /// Version is not 3
    UnsupportedCertVersion,
    /// Signature algorithm unsupported
    UnsupportedSignatureAlgorithm,
    /// Signature algorithm isn’t valid for the public key
    UnsupportedSignatureAlgorithmForPublicKey,
    /// Signature forged!
    InvalidSignatureForPublicKey,
    /// Signature algorithms don’t match
    SignatureAlgorithmMismatch,
    /// Invalid DER
    BadDER,
    /// Invalid DER time
    BadDERTime,
    /// Certificate isn’t valid yet
    CertNotValidYet,
    /// Certificate has expired
    CertExpired,
    /// Certificate expired before beginning to be valid
    InvalidCertValidity,
    /// The issuer is not known.
    UnknownIssuer,
}

#[cfg(feature = "webpki")]
pub use w::Error;

/// A parsed (but not validated) X.509 version 3 certificate.
#[derive(Debug)]
pub struct X509Certificate<'a> {
    das: DataAlgorithmSignature<'a>,
    serial: &'a [u8],
    issuer: &'a [u8],
    not_before: ASN1Time,
    not_after: ASN1Time,
    subject: &'a [u8],
    subject_public_key_info: SubjectPublicKeyInfo<'a>,
    extensions: ExtensionIterator<'a>,
}

impl<'a> X509Certificate<'a> {
    /// The tbsCertificate, signatureAlgorithm, and signature
    pub fn das(&self) -> DataAlgorithmSignature<'a> { self.das }

    /// The serial number. Big-endian and non-empty. The first byte is
    /// guaranteed to be non-zero.
    pub fn serial(&self) -> &'a [u8] { self.serial }

    /// The X.509 issuer. This has not been validated and is not trusted. In
    /// particular, it is not guaranteed to be valid ASN.1 DER.
    pub fn issuer(&self) -> &'a [u8] { self.issuer }

    /// The earliest time, in seconds since the Unix epoch, that the certificate
    /// is valid.
    ///
    /// Will always be between [`MIN_ASN1_TIMESTAMP`] and
    /// [`MAX_ASN1_TIMESTAMP`], inclusive.
    pub fn not_before(&self) -> ASN1Time { self.not_before }

    /// The latest time, in seconds since the Unix epoch, that the certificate
    /// is valid.
    ///
    /// Will always be between [`MIN_ASN1_TIMESTAMP`] and
    /// [`MAX_ASN1_TIMESTAMP`], inclusive.
    pub fn not_after(&self) -> ASN1Time { self.not_after }

    /// X.509 subject. This has not been validated and is not trusted. In
    /// particular, it is not guaranteed to be valid ASN.1 DER.
    pub fn subject(&self) -> &'a [u8] { self.subject }

    /// The subjectPublicKeyInfo, encoded as ASN.1 DER. There is no guarantee
    /// that the OID or public key are valid ASN.1 DER, but if they are not,
    /// all methods that check signatures will fail.
    pub fn subject_public_key_info(&self) -> SubjectPublicKeyInfo<'a> {
        self.subject_public_key_info
    }

    /// An iterator over the certificate’s extensions.
    pub fn extensions(&self) -> ExtensionIterator<'a> { self.extensions }

    /// Verify a signature made by the certificate.
    pub fn check_signature(
        &self, algorithm: SignatureScheme, message: &[u8], signature: &[u8],
    ) -> Result<(), Error> {
        self.subject_public_key_info.check_signature(
            algorithm,
            message,
            signature,
            Restrictions::None,
        )
    }

    /// Verify a signature made by the certificate, applying the restrictions of
    /// TLSv1.3:
    ///
    /// * ECDSA algorithms where the hash has a different size than the curve
    ///   are not allowed.
    /// * RSA PKCS1.5 signatures are not allowed.
    ///
    /// This is a good choice for new protocols and applications. Note that
    /// extensions are not checked, so applications must process extensions
    /// themselves.
    pub fn check_tls13_signature(
        &self, algorithm: SignatureScheme, message: &[u8], signature: &[u8],
    ) -> Result<(), Error> {
        self.subject_public_key_info.check_signature(
            algorithm,
            message,
            signature,
            Restrictions::TLSv13,
        )
    }

    /// Verify a signature made by the certificate, applying the restrictions of
    /// TLSv1.2:
    ///
    /// * RSA-PSS signatures are not allowed.
    ///
    /// This should not be used outside of a TLSv1.2 implementation. Note that
    /// extensions are not checked, so applications must process extensions
    /// themselves.
    pub fn check_tls12_signature(
        &self, algorithm: SignatureScheme, message: &[u8], signature: &[u8],
    ) -> Result<(), Error> {
        self.subject_public_key_info.check_signature(
            algorithm,
            message,
            signature,
            Restrictions::TLSv12,
        )
    }

    /// Check that the certificate is valid at time `now`, in seconds since the
    /// Epoch.
    pub fn valid_at_timestamp(&self, now: i64) -> Result<(), Error> {
        if now < self.not_before.into() {
            Err(Error::CertNotValidYet)
        } else if now > self.not_after.into() {
            Err(Error::CertExpired)
        } else {
            Ok(())
        }
    }

    /// Check if a certificate is currently valid.
    #[cfg(feature = "std")]
    pub fn valid(&self) -> Result<(), Error> { self.valid_at_timestamp(ASN1Time::now()?.into()) }

    /// The tbsCertficate
    pub fn tbs_certificate(&self) -> &[u8] { self.das.data() }

    /// The `AlgorithmId` of the algorithm used to sign this certificate
    pub fn signature_algorithm_id(&self) -> &[u8] { self.das.algorithm() }

    /// The signature of the certificate
    pub fn signature(&self) -> &[u8] { self.das.signature() }

    /// Verify that this certificate was signed by `cert`’s secret key.
    ///
    /// This does not check that `cert` is a certificate authority.
    pub fn check_signature_from(&self, cert: &X509Certificate<'_>) -> Result<(), Error> {
        cert.check_signature(
            parse_algorithmid(self.signature_algorithm_id())?,
            self.tbs_certificate(),
            self.signature(),
        )
    }

    /// As above, but also check that `self`’s issuer is `cert`’s subject.
    pub fn check_issued_by(&self, cert: &X509Certificate<'_>) -> Result<(), Error> {
        if self.issuer != cert.subject {
            return Err(Error::UnknownIssuer);
        }
        self.check_signature_from(cert)
    }

    /// Check that this certificate is self-signed. This does not check that the
    /// subject and issuer are equal.
    #[deprecated(since = "0.3.3", note = "Use check_self_issued instead")]
    pub fn check_self_signature(&self) -> Result<(), Error> { self.check_signature_from(self) }

    /// Check that this certificate is self-signed, and that the subject and
    /// issuer are equal.
    pub fn check_self_issued(&self) -> Result<(), Error> { self.check_issued_by(self) }
}

/// Extracts the algorithm id and public key from a certificate
pub fn parse_certificate(certificate: &[u8]) -> Result<X509Certificate<'_>, Error> {
    use core::convert::TryFrom as _;
    let das = DataAlgorithmSignature::try_from(certificate)?;
    untrusted::Input::from(&*das.inner()).read_all(Error::BadDER, |input| {
        // We require extensions, which means we require version 3
        if input.read_bytes(5).map_err(|_| Error::BadDER)?
            != untrusted::Input::from(&[160, 3, 2, 1, 2])
        {
            return Err(Error::UnsupportedCertVersion);
        }
        // serialNumber
        let serial = der::positive_integer(input)
            .map_err(|_| Error::BadDER)?
            .big_endian_without_leading_zero();
        // signature
        if das::read_sequence(input)?.as_slice_less_safe() != das.algorithm() {
            // signature algorithms don’t match
            return Err(Error::SignatureAlgorithmMismatch);
        }
        // issuer
        let issuer = das::read_sequence(input)?.as_slice_less_safe();
        // validity
        let (not_before, not_after) =
            der::nested(input, der::Tag::Sequence, Error::BadDER, |input| {
                Ok((time::read_time(input)?, time::read_time(input)?))
            })?;
        if not_before > not_after {
            return Err(Error::InvalidCertValidity);
        }
        let subject = das::read_sequence(input)?.as_slice_less_safe();
        let subject_public_key_info = SubjectPublicKeyInfo::read(input)?;
        // subjectUniqueId and issuerUniqueId are unsupported

        let extensions = if !input.at_end() {
            let tag = der::Tag::ContextSpecificConstructed3;
            der::nested(input, tag, Error::BadDER, |input| {
                der::nested(input, der::Tag::Sequence, Error::BadDER, |input| {
                    if input.at_end() {
                        return Err(Error::BadDER);
                    }
                    Ok(ExtensionIterator(SequenceIterator::read(input)))
                })
            })
        } else {
            Ok(ExtensionIterator(SequenceIterator::read(input)))
        }?;

        Ok(X509Certificate {
            das,
            serial,
            issuer,
            not_before,
            not_after,
            subject,
            subject_public_key_info,
            extensions,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_openssl_generated_cert() {
        let signature = include_bytes!("../testing.sig");
        let invalid_signature = include_bytes!("../testing.bad-sig");
        let forged_message = include_bytes!("../forged-message.txt");
        let message = include_bytes!("../gen-bad-cert.sh");
        let certificate = include_bytes!("../testing.crt");
        #[cfg(feature = "rsa")]
        let ca_certificate = include_bytes!("../ca.crt");

        let cert = parse_certificate(certificate).unwrap();
        #[cfg(feature = "rsa")]
        let ca_cert = parse_certificate(ca_certificate).unwrap();
        assert_eq!(
            cert.subject_public_key_info.algorithm(),
            include_bytes!("data/alg-ecdsa-p256.der")
        );
        assert_eq!(cert.subject_public_key_info.key().len(), 65);
        cert.valid_at_timestamp(1587492766).unwrap();
        assert_eq!(cert.valid_at_timestamp(0), Err(Error::CertNotValidYet));
        assert_eq!(
            cert.valid_at_timestamp(i64::max_value()),
            Err(Error::CertExpired)
        );

        cert.check_signature(SignatureScheme::ECDSA_NISTP256_SHA256, message, signature)
            .expect("OpenSSL generates syntactically valid certificates");
        assert_eq!(
            cert.check_signature(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                message,
                invalid_signature,
            )
            .expect_err("corrupting a signature invalidates it"),
            Error::InvalidSignatureForPublicKey
        );
        assert_eq!(
            cert.check_signature(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                message,
                invalid_signature,
            )
            .expect_err("corrupting a message invalidates it"),
            Error::InvalidSignatureForPublicKey
        );
        assert_eq!(
            cert.check_signature(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                forged_message,
                signature,
            )
            .expect_err("forgery undetected?"),
            Error::InvalidSignatureForPublicKey
        );
        #[cfg(feature = "rsa")]
        ca_cert.check_self_issued().unwrap();
        #[cfg(feature = "rsa")]
        cert.check_issued_by(&ca_cert).unwrap();
    }
}
