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

//! An iterator over ASN.1 SEQUENCE structures

use super::{der, Error};

/// An iterator over X.509 extensions.
///
/// Errors are detected lazily.
#[derive(Debug)]
pub struct ExtensionIterator<'a> {
    inner: untrusted::Input<'a>,
}

impl<'a> ExtensionIterator<'a> {
    /// Read X.509 extensions from an [`untrusted::Reader`].
    pub fn read(input: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let tag = der::Tag::ContextSpecificConstructed3;
        der::expect_tag_and_get_value(input, tag)?.read_all(Error::BadDER, |input| {
            Ok(Self {
                inner: der::expect_tag_and_get_value(input, der::Tag::Sequence)?,
            })
        })
    }

    /// Iterate over the X.509 extensions.
    pub fn iterate<T: FnMut(&'a [u8], bool, untrusted::Input<'a>) -> Result<(), Error>>(
        &self, cb: &mut T,
    ) -> Result<(), Error> {
        self.inner.read_all(Error::BadDER, |input| {
            while !input.at_end() {
                der::nested(input, der::Tag::Sequence, Error::BadDER, |input| {
                    let oid = der::expect_tag_and_get_value(input, der::Tag::OID)?;
                    let mut critical = false;
                    if input.peek(der::Tag::Boolean as _) {
                        critical = match input
                            .read_bytes(3)
                            .map_err(|_| Error::BadDER)?
                            .as_slice_less_safe()
                        {
                            b"\x01\x01\xFF" => true,
                            b"\x01\x01\0" => false,
                            _ => return Err(Error::BadDER),
                        }
                    }
                    let value = der::expect_tag_and_get_value(input, der::Tag::OctetString)?;
                    cb(oid.as_slice_less_safe(), critical, value)
                })?
            }
            Ok(())
        })
    }
}
