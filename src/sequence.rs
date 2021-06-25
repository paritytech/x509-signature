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
}

impl<'a> SequenceIterator<'a> {
    /// Read X.509 extensions from an [`untrusted::Reader`].
    pub fn read(input: &mut untrusted::Reader<'a>) -> Self {
        Self {
            inner: input.read_bytes_to_end(),
        }
    }

    /// Iterate over the X.509 sequences. The callback is expected to read the
    /// provided [`untrusted::Reader`] to the end; if it does not, or if the
    /// DER isn’t a sequence of sequences, `Err(error)` will be returned.
    pub fn iterate<
        E: Copy + core::fmt::Debug,
        T: FnMut(&mut untrusted::Reader<'a>) -> Result<(), E>,
    >(
        &self, error: E, cb: &mut T,
    ) -> Result<(), E> {
        self.inner.read_all(error, |input| {
            while !input.at_end() {
                der::nested(input, der::Tag::Sequence, error, &mut *cb)?
            }
            Ok(())
        })
    }
}

impl<'a> ExtensionIterator<'a> {
    /// Iterate over the X.509 extensions.
    pub fn iterate<T: FnMut(&'a [u8], bool, untrusted::Input<'a>) -> Result<(), Error>>(
        &self, cb: &mut T,
    ) -> Result<(), Error> {
        self.0.iterate(Error::BadDer, &mut |input| {
            let oid =
                der::expect_tag_and_get_value(input, der::Tag::OID).map_err(|_| Error::BadDer)?;
            let mut critical = false;
            if input.peek(der::Tag::Boolean as _) {
                critical = match input
                    .read_bytes(3)
                    .map_err(|_| Error::BadDer)?
                    .as_slice_less_safe()
                {
                    b"\x01\x01\xFF" => true,
                    b"\x01\x01\0" => false,
                    _ => return Err(Error::BadDer),
                }
            }
            let value = der::expect_tag_and_get_value(input, der::Tag::OctetString)
                .map_err(|_| Error::BadDer)?;
            cb(oid.as_slice_less_safe(), critical, value)
        })
    }
}
