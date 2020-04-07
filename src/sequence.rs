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
#[derive(Debug, Copy, Clone)]
pub struct ExtensionIterator<'a>(pub(crate) SequenceIterator<'a>);

/// An iterator over X.509 sequences.
///
/// Errors are detected lazily.
#[derive(Debug, Copy, Clone)]
pub struct SequenceIterator<'a> {
    inner: untrusted::Input<'a>,
    tag: u8,
}

impl<'a> SequenceIterator<'a> {
    /// Read a sequence of X.509 items with tag `tag` from an
    /// [`untrusted::Reader`].
    pub fn read(input: &mut untrusted::Reader<'a>, tag: u8) -> Self {
        Self {
            inner: input.read_bytes_to_end(),
            tag,
        }
    }

    /// Iterate over the X.509 items.  The callback is expected to read the
    /// provided [`untrusted::Reader`] to the end; if it does not, or if the
    /// items in the sequence do not have tag `tag`, `Err(error)` will be
    /// returned.
    pub fn iterate<
        E: Copy + core::fmt::Debug,
        T: FnMut(&mut untrusted::Reader<'a>) -> Result<(), E>,
    >(
        &self, error: E, cb: &mut T,
    ) -> Result<(), E> {
        self.inner.read_all(error, |input| {
            while !input.at_end() {
                let (tag, value) =
                    ring::io::der::read_tag_and_get_value(input).map_err(|_| error)?;
                if tag != self.tag {
                    return Err(error);
                }
                value.read_all(error, &mut *cb)?
            }
            Ok(())
        })
    }
}

impl<'a> ExtensionIterator<'a> {
    /// Iterate over the X.509 extensions.
    pub fn iterate<T: FnMut(&'a [u8], bool, &mut untrusted::Reader<'a>) -> Result<(), Error>>(
        &self, cb: &mut T,
    ) -> Result<(), Error> {
        self.0.iterate(Error::BadDER, &mut |input| {
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
            der::nested(input, der::Tag::OctetString, Error::BadDER, |value| {
                cb(oid.as_slice_less_safe(), critical, value)
            })
        })
    }
}
