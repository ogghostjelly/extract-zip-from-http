use std::{collections::VecDeque, io};

pub struct RewindBuffer<I: Iterator<Item = io::Result<u8>>> {
    buf: VecDeque<u8>,
    buf_ptr: usize,
    iter: I,
    byte_offset: usize,
}

impl<I: Iterator<Item = io::Result<u8>>> RewindBuffer<I> {
    pub fn flush(&mut self) {
        for _ in self.buf.drain(..self.buf_ptr) {
            self.byte_offset += 1;
        }
        self.buf_ptr = 0;
    }

    #[inline]
    pub fn rewind(&mut self) {
        self.buf_ptr = 0;
    }

    pub fn next(&mut self) -> io::Result<Option<u8>> {
        match self.peek()? {
            Some(value) => {
                self.buf_ptr += 1;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub fn peek(&mut self) -> io::Result<Option<u8>> {
        if let Some(value) = self.buf.get(self.buf_ptr) {
            return Ok(Some(*value));
        }

        let Some(value) = self.iter.next() else {
            return Ok(None);
        };

        let value = value?;

        self.buf.push_back(value);
        Ok(Some(value))
    }
}

impl<I: Iterator<Item = io::Result<u8>>> io::Read for RewindBuffer<I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        for i in 0..buf.len() {
            buf[i] = match self.next()? {
                Some(value) => value,
                None => return Ok(i),
            }
        }
        Ok(buf.len())
    }
}
