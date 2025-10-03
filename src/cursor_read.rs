use std::io::{self};

pub struct CursorRead<I: Iterator<Item = io::Result<u8>>> {
    iter: I,
    pub byte_offset: usize,
}

impl<I: Iterator<Item = io::Result<u8>>> CursorRead<I> {
    pub fn new(iter: I) -> Self {
        Self {
            iter,
            byte_offset: 0,
        }
    }
}

impl<I: Iterator<Item = io::Result<u8>>> Iterator for CursorRead<I> {
    type Item = io::Result<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(Ok(value)) => {
                self.byte_offset += 1;
                Some(Ok(value))
            }
            Some(Err(e)) => Some(Err(e)),
            None => None,
        }
    }
}

impl<I: Iterator<Item = io::Result<u8>>> io::Read for CursorRead<I> {
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
