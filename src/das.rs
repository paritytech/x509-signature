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

//! Data-algorithm-signature ASN.1 structures

use ring::{error::Unspecified, io::der};

/// A data-algorithm-signature structure
#[derive(Debug)]
pub struct DataAlgorithmSignature<'a> {
    /// The data over which the signature is computed.  An X.509 SEQUENCE.
    pub data: untrusted::Input<'a>,
    /// The data with the outer SEQUENCE stripped.
    pub inner: untrusted::Input<'a>,
    /// The algorithm identifier, with the outer SEQUENCE stripped.
    pub algorithm: untrusted::Input<'a>,
    /// The raw bytes of the signature.
    pub signature: untrusted::Input<'a>,
}

#[inline(always)]
pub(crate) fn read_sequence<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<untrusted::Input<'a>, Unspecified> {
    der::expect_tag_and_get_value(input, der::Tag::Sequence)
}

impl<'a> core::convert::TryFrom<&'a [u8]> for DataAlgorithmSignature<'a> {
    type Error = Unspecified;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        untrusted::Input::from(value).read_all(Unspecified, |input| {
            der::nested(input, der::Tag::Sequence, Unspecified, |input| {
                // tbsCertificate
                let (data, inner) = input.read_partial(read_sequence)?;
                // signatureAlgorithm
                let algorithm = read_sequence(input)?;
                // signatureValue
                let signature = der::bit_string_with_no_unused_bits(input)?;
                Ok(Self {
                    data,
                    inner,
                    algorithm,
                    signature,
                })
            })
        })
    }
}
