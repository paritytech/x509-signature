//! Data-algorithm-signature ASN.1 structures

use super::Error;
use ring::io::der;

/// A data-algorithm-signature structure
#[derive(Debug, Copy, Clone)]
pub struct DataAlgorithmSignature<'a> {
    data: &'a [u8],
    inner: &'a [u8],
    algorithm: &'a [u8],
    signature: &'a [u8],
}

impl<'a> DataAlgorithmSignature<'a> {
    /// The data over which the signature is computed.  An X.509 SEQUENCE.
    pub fn data(&self) -> &'a [u8] { self.data }
    /// The data with the outer SEQUENCE stripped.
    pub fn inner(&self) -> &'a [u8] { self.inner }
    /// The algorithm identifier, with the outer SEQUENCE stripped.
    pub fn algorithm(&self) -> &'a [u8] { self.algorithm }
    /// The raw bytes of the signature.
    pub fn signature(&self) -> &'a [u8] { self.signature }
}

pub(crate) fn read_sequence<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<untrusted::Input<'a>, Error> {
    der::expect_tag_and_get_value(input, der::Tag::Sequence).map_err(|_| Error::BadDer)
}

impl<'a> core::convert::TryFrom<&'a [u8]> for DataAlgorithmSignature<'a> {
    type Error = Error;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        untrusted::Input::from(value).read_all(Error::BadDer, |input| {
            der::nested(input, der::Tag::Sequence, Error::BadDer, |input| {
                // tbsCertificate
                let (data, inner) = input.read_partial(read_sequence)?;
                // signatureAlgorithm
                let algorithm = read_sequence(input)?.as_slice_less_safe();
                // signatureValue
                let signature = der::bit_string_with_no_unused_bits(input)
                    .map_err(|_| Error::BadDer)?
                    .as_slice_less_safe();
                Ok(Self {
                    data: data.as_slice_less_safe(),
                    inner: inner.as_slice_less_safe(),
                    algorithm,
                    signature,
                })
            })
        })
    }
}
