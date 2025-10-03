use std::io::{self};

/// A wrapper around Iterator that keeps track of the current index.
pub struct EnumerateIter<I: Iterator<Item = io::Result<u8>>> {
    iter: I,
    pub index: usize,
}

impl<I: Iterator<Item = io::Result<u8>>> EnumerateIter<I> {
    pub fn new(iter: I) -> Self {
        Self { iter, index: 0 }
    }
}

impl<I: Iterator<Item = io::Result<u8>>> Iterator for EnumerateIter<I> {
    type Item = io::Result<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(Ok(value)) => {
                self.index += 1;
                Some(Ok(value))
            }
            Some(Err(e)) => Some(Err(e)),
            None => None,
        }
    }
}

impl<I: Iterator<Item = io::Result<u8>>> io::Read for EnumerateIter<I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        for i in 0..buf.len() {
            buf[i] = match self.next().transpose()? {
                Some(value) => value,
                None => return Ok(i),
            }
        }
        Ok(buf.len())
    }
}
