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

//! PKIX SubjectPublicKeyInfo parsing

use super::{
    der::{self, Tag},
    Error, SignatureScheme,
};

use ring::signature;

/// A PKIX SubjectPublicKeyInfo struct
#[derive(Debug, Copy, Clone)]
pub struct SubjectPublicKeyInfo<'a> {
    spki: &'a [u8],
    algorithm: &'a [u8],
    key: &'a [u8],
}

impl<'a> SubjectPublicKeyInfo<'a> {
    /// The data over which the signature is computed.  An X.509 SEQUENCE.
    pub fn spki(&self) -> &'a [u8] { self.spki }
    /// The algorithm identifier, with the outer SEQUENCE stripped.
    pub fn algorithm(&self) -> &'a [u8] { self.algorithm }
    /// The raw bytes of the signature.
    pub fn key(&self) -> &'a [u8] { self.key }
    /// Read a SubjectPublicKeyInfo from an [`untrusted::Reader`]
    pub fn read(input: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let (spki, (algorithm, key)) = input.read_partial(|input| {
            der::nested(input, Tag::Sequence, Error::BadDER, |input| {
                let algorithm = der::expect_tag_and_get_value(input, Tag::Sequence)
                    .map_err(|_| Error::BadDER)?;
                let key = der::bit_string_with_no_unused_bits(input).map_err(|_| Error::BadDER)?;
                Ok((algorithm.as_slice_less_safe(), key.as_slice_less_safe()))
            })
        })?;
        Ok(Self {
            spki: spki.as_slice_less_safe(),
            algorithm,
            key,
        })
    }

    /// Get a [`signature::UnparsedPublicKey`] for this SubjectPublicKeyInfo
    pub fn get_public_key_tls(
        &self, signature_scheme: SignatureScheme,
    ) -> Result<signature::UnparsedPublicKey<&'a [u8]>, Error> {
        #[cfg(feature = "rsa")]
        use signature::{
            RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        };
        let algorithm: &'static dyn signature::VerificationAlgorithm = match signature_scheme {
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PKCS1_SHA256 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA256,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PKCS1_SHA384 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA384,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PKCS1_SHA512 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA512,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            SignatureScheme::ECDSA_NISTP256_SHA256 => match self.algorithm {
                include_bytes!("data/alg-ecdsa-p256.der") => &signature::ECDSA_P256_SHA256_ASN1,
                include_bytes!("data/alg-ecdsa-p384.der") => &signature::ECDSA_P384_SHA256_ASN1,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            SignatureScheme::ECDSA_NISTP384_SHA384 => match self.algorithm {
                include_bytes!("data/alg-ecdsa-p384.der") => &signature::ECDSA_P384_SHA384_ASN1,
                include_bytes!("data/alg-ecdsa-p256.der") => &signature::ECDSA_P256_SHA384_ASN1,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            SignatureScheme::ED25519 => match self.algorithm {
                include_bytes!("data/alg-ed25519.der") => &signature::ED25519,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PSS_SHA256 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") =>
                    &signature::RSA_PSS_2048_8192_SHA256,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PSS_SHA384 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") =>
                    &signature::RSA_PSS_2048_8192_SHA384,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PSS_SHA512 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") =>
                    &signature::RSA_PSS_2048_8192_SHA512,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            _ => return Err(Error::UnsupportedSignatureAlgorithm),
        };
        Ok(signature::UnparsedPublicKey::new(algorithm, self.key))
    }

    /// Get a [`signature::UnparsedPublicKey`] for this SubjectPublicKeyInfo
    pub fn get_public_key_x509(
        &self, algorithm_id: &[u8],
    ) -> Result<ring::signature::UnparsedPublicKey<&'a [u8]>, Error> {
        #[cfg(feature = "rsa")]
        const RSASSA_PSS_PREFIX: &[u8; 11] = include_bytes!("data/alg-rsa-pss.der");
        #[cfg(feature = "rsa")]
        use signature::{
            RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        };
        let algorithm: &'static dyn signature::VerificationAlgorithm = match algorithm_id {
            #[cfg(feature = "rsa")]
            include_bytes!("data/alg-rsa-pkcs1-sha256.der") => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA256,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            include_bytes!("data/alg-rsa-pkcs1-sha384.der") => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA384,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            include_bytes!("data/alg-rsa-pkcs1-sha512.der") => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &RSA_PKCS1_2048_8192_SHA512,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            include_bytes!("data/alg-ecdsa-sha256.der") => match self.algorithm {
                include_bytes!("data/alg-ecdsa-p256.der") => &signature::ECDSA_P256_SHA256_ASN1,
                include_bytes!("data/alg-ecdsa-p384.der") => &signature::ECDSA_P384_SHA256_ASN1,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            include_bytes!("data/alg-ecdsa-sha384.der") => match self.algorithm {
                include_bytes!("data/alg-ecdsa-p256.der") => &signature::ECDSA_P256_SHA384_ASN1,
                include_bytes!("data/alg-ecdsa-p384.der") => &signature::ECDSA_P384_SHA384_ASN1,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            include_bytes!("data/alg-ed25519.der") => match self.algorithm {
                include_bytes!("data/alg-ed25519.der") => &signature::ED25519,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            e if e.starts_with(&RSASSA_PSS_PREFIX[..]) => {
                let alg = parse_rsa_pss(&e[RSASSA_PSS_PREFIX.len()..])?;
                match self.algorithm {
                    include_bytes!("data/alg-rsa-encryption.der") => alg,
                    _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
                }
            },
            _ => return Err(Error::UnsupportedSignatureAlgorithm),
        };
        Ok(signature::UnparsedPublicKey::new(algorithm, self.key))
    }
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
        | include_bytes!("data/alg-rsa-pss-sha256-v3.der") =>
            Ok(&signature::RSA_PSS_2048_8192_SHA256),
        include_bytes!("data/alg-rsa-pss-sha384-v0.der")
        | include_bytes!("data/alg-rsa-pss-sha384-v1.der")
        | include_bytes!("data/alg-rsa-pss-sha384-v2.der")
        | include_bytes!("data/alg-rsa-pss-sha384-v3.der") =>
            Ok(&signature::RSA_PSS_2048_8192_SHA384),
        include_bytes!("data/alg-rsa-pss-sha512-v0.der")
        | include_bytes!("data/alg-rsa-pss-sha512-v1.der")
        | include_bytes!("data/alg-rsa-pss-sha512-v2.der")
        | include_bytes!("data/alg-rsa-pss-sha512-v3.der") =>
            Ok(&signature::RSA_PSS_2048_8192_SHA512),
        _ => Err(Error::UnsupportedSignatureAlgorithm),
    }
}
