use std::io;

pub struct BufIter<I: Iterator<Item = io::Result<u8>>> {
    buf: Vec<u8>,
    iter: I,
}

impl<I: Iterator<Item = io::Result<u8>>> BufIter<I> {
    pub fn new(iter: I) -> Self {
        Self {
            buf: Vec::new(),
            iter,
        }
    }

    pub fn into_buf(self) -> Vec<u8> {
        self.buf
    }

    pub fn with_capacity(iter: I, capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            iter,
        }
    }
}

impl<I: Iterator<Item = io::Result<u8>>> Iterator for BufIter<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(Ok(value)) => {
                self.buf.push(value);
                Some(Ok(value))
            }
            Some(Err(e)) => Some(Err(e)),
            None => None,
        }
    }
}
