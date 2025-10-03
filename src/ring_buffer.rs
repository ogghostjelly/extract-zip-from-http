use std::mem;

pub struct RingBuffer<T, const N: usize> {
    buf: [T; N],
    buf_ptr: usize,
}

impl<T, const N: usize> RingBuffer<T, N> {
    pub fn new(buf: [T; N]) -> Self {
        Self { buf, buf_ptr: 0 }
    }

    pub fn from_iter<I: Iterator<Item = T>>(mut iter: I) -> Option<Self> {
        let mut buf = Vec::with_capacity(N);
        for _ in 0..N {
            buf.push(iter.next()?);
        }
        Some(Self::new(buf.try_into().ok()?))
    }

    pub fn from_parts(buf: [T; N], buf_ptr: usize) -> Self {
        assert!(buf_ptr < buf.len());
        Self { buf, buf_ptr }
    }
}

impl<T, const N: usize> RingBuffer<T, N> {
    pub const fn len(&self) -> usize {
        N
    }

    pub fn push(&mut self, value: T) -> T {
        let value = mem::replace(&mut self.buf[self.buf_ptr], value);
        self.buf_ptr += 1;
        if self.buf_ptr >= self.buf.len() {
            self.buf_ptr = 0;
        }
        value
    }
}
