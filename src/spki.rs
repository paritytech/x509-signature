//! PKIX SubjectPublicKeyInfo parsing

use super::{
    der::{self, Tag},
    Error, SignatureScheme,
};

use ring::signature;

/// Restrictions on allowed signature algorithms
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Restrictions {
    /// Allow all supported signature algorithms. This is the default.
    None,
    /// Only support signature algorithms allowed by TLS1.2. This should not be
    /// used in other contexts.
    TLSv12,
    /// Only support signature algorithms allowed by TLS1.3. This is a good
    /// choice for new protocols as well.
    TLSv13,
}

impl Default for Restrictions {
    fn default() -> Self { Self::None }
}

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
            der::nested(input, Tag::Sequence, Error::BadDer, |input| {
                let algorithm = der::expect_tag_and_get_value(input, Tag::Sequence)
                    .map_err(|_| Error::BadDer)?;
                let key = der::bit_string_with_no_unused_bits(input).map_err(|_| Error::BadDer)?;
                Ok((algorithm.as_slice_less_safe(), key.as_slice_less_safe()))
            })
        })?;
        Ok(Self {
            spki: spki.as_slice_less_safe(),
            algorithm,
            key,
        })
    }

    /// Verify a signature by the private key corresponding to this
    /// SubjectPublicKeyInfo. `restrictions` indicates the restrictions on
    /// allowed algorithms.
    pub fn check_signature(
        &self, algorithm: SignatureScheme, message: &[u8], signature: &[u8],
        restrictions: Restrictions,
    ) -> Result<(), Error> {
        self.public_key(algorithm, restrictions)?
            .verify(message, signature)
            .map_err(|_| Error::InvalidSignatureForPublicKey)
    }

    /// Get a [`signature::UnparsedPublicKey`] for this SubjectPublicKeyInfo.
    ///
    /// `restrictions` indicates the restrictions on allowed algorithms.
    pub fn public_key(
        &self, algorithm: SignatureScheme, restrictions: Restrictions,
    ) -> Result<signature::UnparsedPublicKey<&'a [u8]>, Error> {
        use signature as s;
        #[cfg(feature = "rsa")]
        use Restrictions::TLSv12;
        use Restrictions::TLSv13;
        let algorithm: &'static dyn s::VerificationAlgorithm = match algorithm {
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PKCS1_SHA256 if restrictions != TLSv13 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => (&s::RSA_PKCS1_2048_8192_SHA256),
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PKCS1_SHA384 if restrictions != TLSv13 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => (&s::RSA_PKCS1_2048_8192_SHA384),
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PKCS1_SHA512 if restrictions != TLSv13 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &s::RSA_PKCS1_2048_8192_SHA512,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            SignatureScheme::ECDSA_NISTP256_SHA256 => match self.algorithm {
                include_bytes!("data/alg-ecdsa-p256.der") => &s::ECDSA_P256_SHA256_ASN1,
                include_bytes!("data/alg-ecdsa-p384.der") if restrictions != TLSv13 =>
                    &s::ECDSA_P384_SHA256_ASN1,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            SignatureScheme::ECDSA_NISTP384_SHA384 => match self.algorithm {
                include_bytes!("data/alg-ecdsa-p384.der") => &s::ECDSA_P384_SHA384_ASN1,
                include_bytes!("data/alg-ecdsa-p256.der") if restrictions != TLSv13 =>
                    &s::ECDSA_P256_SHA384_ASN1,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            SignatureScheme::ED25519 => match self.algorithm {
                include_bytes!("data/alg-ed25519.der") => &s::ED25519,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PSS_SHA256 if restrictions != TLSv12 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &s::RSA_PSS_2048_8192_SHA256,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PSS_SHA384 if restrictions != TLSv12 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &s::RSA_PSS_2048_8192_SHA384,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            #[cfg(feature = "rsa")]
            SignatureScheme::RSA_PSS_SHA512 if restrictions != TLSv12 => match self.algorithm {
                include_bytes!("data/alg-rsa-encryption.der") => &s::RSA_PSS_2048_8192_SHA512,
                _ => return Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            },
            _ => return Err(Error::UnsupportedSignatureAlgorithm),
        };
        Ok(s::UnparsedPublicKey::new(algorithm, self.key))
    }

    /// Get a [`signature::UnparsedPublicKey`] for this SubjectPublicKeyInfo
    pub fn get_public_key_x509(
        &self, algorithm_id: &[u8],
    ) -> Result<ring::signature::UnparsedPublicKey<&'a [u8]>, Error> {
        self.public_key(parse_algorithmid(algorithm_id)?, Restrictions::None)
    }
}

const RSASSA_PSS_PREFIX: &[u8; 11] = include_bytes!("data/alg-rsa-pss.der");

/// Parse the ASN.1 DER-encoded algorithm identifier in `asn1` into a
/// `SignatureScheme`. This will fail if `asn1` is not a known signature scheme.
pub fn parse_algorithmid(asn1: &[u8]) -> Result<SignatureScheme, Error> {
    match asn1 {
        include_bytes!("data/alg-rsa-pkcs1-sha256.der") => Ok(SignatureScheme::RSA_PKCS1_SHA256),
        include_bytes!("data/alg-rsa-pkcs1-sha384.der") => Ok(SignatureScheme::RSA_PKCS1_SHA384),
        include_bytes!("data/alg-rsa-pkcs1-sha512.der") => Ok(SignatureScheme::RSA_PKCS1_SHA512),
        include_bytes!("data/alg-ecdsa-sha256.der") => Ok(SignatureScheme::ECDSA_NISTP256_SHA256),
        include_bytes!("data/alg-ecdsa-sha384.der") => Ok(SignatureScheme::ECDSA_NISTP384_SHA384),
        include_bytes!("data/alg-ed25519.der") => Ok(SignatureScheme::ED25519),
        e if e.starts_with(&RSASSA_PSS_PREFIX[..]) => match &e[RSASSA_PSS_PREFIX.len()..] {
            include_bytes!("data/alg-rsa-pss-sha256-v0.der")
            | include_bytes!("data/alg-rsa-pss-sha256-v1.der")
            | include_bytes!("data/alg-rsa-pss-sha256-v2.der")
            | include_bytes!("data/alg-rsa-pss-sha256-v3.der") =>
                Ok(SignatureScheme::RSA_PSS_SHA256),

            include_bytes!("data/alg-rsa-pss-sha384-v0.der")
            | include_bytes!("data/alg-rsa-pss-sha384-v1.der")
            | include_bytes!("data/alg-rsa-pss-sha384-v2.der")
            | include_bytes!("data/alg-rsa-pss-sha384-v3.der") =>
                Ok(SignatureScheme::RSA_PSS_SHA384),

            include_bytes!("data/alg-rsa-pss-sha512-v0.der")
            | include_bytes!("data/alg-rsa-pss-sha512-v1.der")
            | include_bytes!("data/alg-rsa-pss-sha512-v2.der")
            | include_bytes!("data/alg-rsa-pss-sha512-v3.der") =>
                Ok(SignatureScheme::RSA_PSS_SHA512),
            _ => Err(Error::UnsupportedSignatureAlgorithm),
        },
        _ => Err(Error::UnsupportedSignatureAlgorithm),
    }
}
