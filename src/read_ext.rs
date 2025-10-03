use std::{io, mem::MaybeUninit};

pub trait ReadExt {
    fn read_bytes(&mut self, length: usize) -> io::Result<Vec<u8>>;
    fn next_exact<const N: usize>(&mut self) -> io::Result<[u8; N]>;
    fn next_u16(&mut self) -> io::Result<u16>;
    fn next_u32(&mut self) -> io::Result<u32>;
    fn next_u64(&mut self) -> io::Result<u64>;
}

impl<R: io::Read> ReadExt for R {
    fn read_bytes(&mut self, length: usize) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0; length];
        self.read_exact(bytes.as_mut_slice())?;
        Ok(bytes)
    }

    fn next_exact<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut buf: MaybeUninit<[u8; N]> = MaybeUninit::uninit();
        self.read_exact(unsafe { buf.assume_init_mut() })?;
        Ok(unsafe { buf.assume_init() })
    }

    fn next_u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.next_exact()?))
    }

    fn next_u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.next_exact()?))
    }

    fn next_u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.next_exact()?))
    }
}
