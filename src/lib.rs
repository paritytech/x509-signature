// Copyright 2020 Parity Technologies (UK) Ltd.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

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

#![no_std]
#![deny(
    exceeding_bitshifts,
    invalid_type_param_default,
    missing_fragment_specifier,
    mutable_transmutes,
    no_mangle_const_items,
    overflowing_literals,
    patterns_in_fns_without_body,
    pub_use_of_private_extern_crate,
    unknown_crate_types,
    const_err,
    order_dependent_trait_objects,
    illegal_floating_point_literal_pattern,
    improper_ctypes,
    late_bound_lifetime_arguments,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_snake_case,
    non_upper_case_globals,
    no_mangle_generic_items,
    path_statements,
    private_in_public,
    stable_features,
    type_alias_bounds,
    tyvar_behind_raw_pointer,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_mut,
    unreachable_pub,
    anonymous_parameters,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    clippy::all
)]
#![forbid(
    unsafe_code,
    intra_doc_link_resolution_failure,
    safe_packed_borrows,
    while_true,
    elided_lifetimes_in_paths,
    bare_trait_objects
)]

mod calendar;
mod das;
mod der;
mod sequence;
pub use das::DataAlgorithmSignature;
use ring::{error::Unspecified, signature};
pub use sequence::ExtensionIterator;

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
}

#[cfg(feature = "webpki")]
pub use w::Error;

/// A parsed (but not validated) X.509 version 3 certificate.
#[derive(Debug)]
pub struct X509Certificate<'a> {
    /// The tbsCertificate, signatureAlgorithm, and signature
    pub das: DataAlgorithmSignature<'a>,
    /// The serial number.  Big-endian and non-empty.
    pub serial: &'a [u8],
    /// Iterator over the elements of the issuer
    pub issuer: untrusted::Input<'a>,
    /// The earliest time, in seconds since the Unix epoch, that the certificate
    /// is valid
    pub not_before: u64,
    /// The latest time, in seconds since the Unix epoch, that the certificate
    /// is valid
    pub not_after: u64,
    /// Iterator over the elements of the subject
    pub subject: untrusted::Input<'a>,
    /// The subjectPublicKeyInfo, in the format used by OpenSSL
    pub subject_public_key_info: untrusted::Input<'a>,
    /// The public key’s algorithm identifier, with the wrapping DER SEQUENCE
    /// stripped off
    pub public_key_algorithm_id: untrusted::Input<'a>,
    /// The raw public key, in bytes
    pub public_key_bytes: untrusted::Input<'a>,
    /// An iterator over the certificate’s extensions
    pub extensions: ExtensionIterator<'a>,
}

impl X509Certificate<'_> {
    /// Verify a signature made by the certificate
    pub fn verify_signature_against_scheme(
        &self, time: u64, scheme: SignatureScheme, message: &[u8], signature: &[u8],
    ) -> Result<(), Error> {
        if time < self.not_before {
            return Err(Error::CertNotValidYet);
        } else if time > self.not_after {
            return Err(Error::CertExpired);
        }
        get_public_key_tls(
            self.public_key_algorithm_id.as_slice_less_safe(),
            self.public_key_bytes.as_slice_less_safe(),
            scheme,
        )?
        .verify(message, signature)
        .map_err(|_| Error::InvalidSignatureForPublicKey)
    }

    /// Verify a signature made by the certificate
    pub fn verify_data_algorithm_signature(
        &self, time: u64, das: &DataAlgorithmSignature<'_>,
    ) -> Result<(), Error> {
        if time < self.not_before {
            return Err(Error::CertNotValidYet);
        } else if time > self.not_after {
            return Err(Error::CertExpired);
        }
        get_public_key_x509(
            self.public_key_algorithm_id.as_slice_less_safe(),
            self.public_key_bytes.as_slice_less_safe(),
            das.algorithm.as_slice_less_safe(),
        )?
        .verify(
            das.data.as_slice_less_safe(),
            das.signature.as_slice_less_safe(),
        )
        .map_err(|_| Error::InvalidSignatureForPublicKey)
    }
}

#[inline(always)]
fn read_bit_string<'a>(
    input: &mut untrusted::Reader<'a>, e: Error,
) -> Result<untrusted::Input<'a>, Error> {
    der::bit_string_with_no_unused_bits(input).map_err(|_| e)
}

/// Extracts the algorithm id and public key from a certificate
pub fn parse_certificate<'a>(certificate: &'a [u8]) -> Result<X509Certificate<'a>, Error> {
    use core::convert::TryFrom as _;
    let das = DataAlgorithmSignature::try_from(certificate).map_err(|Unspecified| Error::BadDER)?;
    das.inner.clone().read_all(Error::BadDER, |input| {
        // We require extensions, which means we require version 3
        der::expect_bytes(input, &[160, 3, 2, 1, 2], Error::UnsupportedCertVersion)?;
        // serialNumber
        let serial = der::positive_integer(input)?.big_endian_without_leading_zero();
        // signature
        if der::expect_tag_and_get_value(input, der::Tag::Sequence)? != das.algorithm {
            // signature algorithms don’t match
            return Err(Error::SignatureAlgorithmMismatch);
        }
        // issuer
        let issuer = der::expect_tag_and_get_value(input, der::Tag::Sequence)?;
        // validity
        let (not_before, not_after) = der::expect_tag_and_get_value(input, der::Tag::Sequence)?
            .read_all(Error::BadDER, |input| {
                Ok((der::time_choice(input)?, der::time_choice(input)?))
            })?;
        if not_before > not_after {
            return Err(Error::InvalidCertValidity);
        }
        // subject
        let subject = der::expect_tag_and_get_value(input, der::Tag::Sequence)?;
        // subjectPublicKeyInfo
        let subject_public_key_info = der::expect_tag_and_get_value(input, der::Tag::Sequence)?;
        let (public_key_algorithm_id, public_key_bytes) =
            subject_public_key_info.read_all(Error::BadDER, |input| {
                let algorithm = der::expect_tag_and_get_value(input, der::Tag::Sequence)?;
                let public_key = read_bit_string(input, Error::BadDER)?;
                Ok((algorithm, public_key))
            })?;
        // subjectUniqueId and issuerUniqueId are unsupported
        // parse the extensions
        let extensions = ExtensionIterator::read(input)?;

        Ok(X509Certificate {
            das,
            serial,
            subject,
            not_before,
            not_after,
            issuer,
            subject_public_key_info,
            public_key_algorithm_id,
            public_key_bytes,
            extensions,
        })
    })
}

fn get_public_key_tls<'a>(
    public_key_algorithm: &[u8], x509_pkey_bytes: &'a [u8], signature_scheme: SignatureScheme,
) -> Result<ring::signature::UnparsedPublicKey<&'a [u8]>, Error> {
    #[cfg(feature = "rsa")]
    use signature::{
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    };
    let algorithm: &'static dyn signature::VerificationAlgorithm = match signature_scheme {
        #[cfg(feature = "rsa")]
        SignatureScheme::RSA_PKCS1_SHA256 => match public_key_algorithm {
            include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA256,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        #[cfg(feature = "rsa")]
        SignatureScheme::RSA_PKCS1_SHA384 => match public_key_algorithm {
            include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA384,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        #[cfg(feature = "rsa")]
        SignatureScheme::RSA_PKCS1_SHA512 => match public_key_algorithm {
            include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA512,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        SignatureScheme::ECDSA_NISTP256_SHA256 => match public_key_algorithm {
            include_bytes!("data/alg-ecdsa-p256.der") => &signature::ECDSA_P256_SHA256_ASN1,
            // include_bytes!("data/alg-ecdsa-p384.der") => &signature::ECDSA_P384_SHA256_ASN1,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        SignatureScheme::ECDSA_NISTP384_SHA384 => match public_key_algorithm {
            include_bytes!("data/alg-ecdsa-p384.der") => &signature::ECDSA_P384_SHA384_ASN1,
            // include_bytes!("data/alg-ecdsa-p256.der") => &signature::ECDSA_P256_SHA384_ASN1,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        SignatureScheme::ED25519 => match public_key_algorithm {
            include_bytes!("data/alg-ed25519.der") => &signature::ED25519,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        #[cfg(feature = "rsa")]
        SignatureScheme::RSA_PSS_SHA256 => match public_key_algorithm {
            include_bytes!("data/alg-rsa-encryption.der") => &signature::RSA_PSS_2048_8192_SHA256,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        #[cfg(feature = "rsa")]
        SignatureScheme::RSA_PSS_SHA384 => match public_key_algorithm {
            include_bytes!("data/alg-rsa-encryption.der") => &signature::RSA_PSS_2048_8192_SHA384,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        #[cfg(feature = "rsa")]
        SignatureScheme::RSA_PSS_SHA512 => match public_key_algorithm {
            include_bytes!("data/alg-rsa-encryption.der") => &signature::RSA_PSS_2048_8192_SHA512,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        _ => return Err(Error::UnsupportedSignatureAlgorithm),
    };
    Ok(signature::UnparsedPublicKey::new(
        algorithm,
        x509_pkey_bytes,
    ))
}

fn get_public_key_x509<'a>(
    public_key_algorithm: &[u8], public_key_bytes: &'a [u8], signature_algorithm: &[u8],
) -> Result<ring::signature::UnparsedPublicKey<&'a [u8]>, Error> {
    #[cfg(feature = "rsa")]
    const RSASSA_PSS_PREFIX: &[u8; 11] = include_bytes!("data/alg-rsa-pss.der");
    #[cfg(feature = "rsa")]
    use signature::{
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    };
    let algorithm: &'static dyn signature::VerificationAlgorithm = match signature_algorithm {
        #[cfg(feature = "rsa")]
        include_bytes!("data/alg-rsa-pkcs1-sha256.der") => match public_key_algorithm {
            include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA256,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        #[cfg(feature = "rsa")]
        include_bytes!("data/alg-rsa-pkcs1-sha384.der") => match public_key_algorithm {
            include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA384,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        #[cfg(feature = "rsa")]
        include_bytes!("data/alg-rsa-pkcs1-sha512.der") => match public_key_algorithm {
            include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA512,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        include_bytes!("data/alg-ecdsa-sha256.der") => match public_key_algorithm {
            include_bytes!("data/alg-ecdsa-p256.der") => &signature::ECDSA_P256_SHA256_ASN1,
            include_bytes!("data/alg-ecdsa-p384.der") => &signature::ECDSA_P384_SHA256_ASN1,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        include_bytes!("data/alg-ecdsa-sha384.der") => match public_key_algorithm {
            include_bytes!("data/alg-ecdsa-p256.der") => &signature::ECDSA_P256_SHA384_ASN1,
            include_bytes!("data/alg-ecdsa-p384.der") => &signature::ECDSA_P384_SHA384_ASN1,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        include_bytes!("data/alg-ed25519.der") => match public_key_algorithm {
            include_bytes!("data/alg-ed25519.der") => &signature::ED25519,
            _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
        },
        #[cfg(feature = "rsa")]
        e if e.starts_with(&RSASSA_PSS_PREFIX[..]) => {
            let alg = parse_rsa_pss(&e[RSASSA_PSS_PREFIX.len()..])?;
            match public_key_algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => alg,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            }
        }
        _ => return Err(Error::UnsupportedSignatureAlgorithm),
    };
    Ok(signature::UnparsedPublicKey::new(
        algorithm,
        public_key_bytes,
    ))
}

// While the RSA-PSS parameters are a ASN.1 SEQUENCE, it is simpler to match
// against the 12 different possibilities. The binary files are *generated* by a
// Go program.
#[cfg(feature = "rsa")]
fn parse_rsa_pss(data: &[u8]) -> Result<&'static signature::RsaParameters, Error> {
    match data {
        include_bytes!("data/alg-rsa-pss-sha256-v0.der")
        | include_bytes!("data/alg-rsa-pss-sha256-v1.der")
        | include_bytes!("data/alg-rsa-pss-sha256-v2.der")
        | include_bytes!("data/alg-rsa-pss-sha256-v3.der") => {
            Ok(&signature::RSA_PSS_2048_8192_SHA256)
        }
        include_bytes!("data/alg-rsa-pss-sha384-v0.der")
        | include_bytes!("data/alg-rsa-pss-sha384-v1.der")
        | include_bytes!("data/alg-rsa-pss-sha384-v2.der")
        | include_bytes!("data/alg-rsa-pss-sha384-v3.der") => {
            Ok(&signature::RSA_PSS_2048_8192_SHA384)
        }
        include_bytes!("data/alg-rsa-pss-sha512-v0.der")
        | include_bytes!("data/alg-rsa-pss-sha512-v1.der")
        | include_bytes!("data/alg-rsa-pss-sha512-v2.der")
        | include_bytes!("data/alg-rsa-pss-sha512-v3.der") => {
            Ok(&signature::RSA_PSS_2048_8192_SHA512)
        }
        _ => Err(Error::UnsupportedSignatureAlgorithm),
    }
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

        let cert = parse_certificate(certificate).unwrap();
        assert_eq!(
            cert.public_key_algorithm_id.as_slice_less_safe(),
            include_bytes!("data/alg-ecdsa-p256.der")
        );
        assert_eq!(cert.public_key_bytes.len(), 65);
        cert.verify_signature_against_scheme(
            1586128701,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            message,
            signature,
        )
        .expect("OpenSSL generates syntactically valid certificates");
        assert_eq!(
            cert.verify_signature_against_scheme(
                1586128701,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                message,
                invalid_signature,
            )
            .expect_err("corrupting a signature invalidates it"),
            Error::InvalidSignatureForPublicKey
        );
        assert_eq!(
            cert.verify_signature_against_scheme(
                1586128701,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                message,
                invalid_signature,
            )
            .expect_err("corrupting a signature invalidates it"),
            Error::InvalidSignatureForPublicKey
        );
        assert_eq!(
            cert.verify_signature_against_scheme(
                1586128701,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                forged_message,
                signature,
            )
            .expect_err("forgery undetected?"),
            Error::InvalidSignatureForPublicKey
        );
    }
}
