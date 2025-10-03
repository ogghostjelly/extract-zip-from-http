use std::io;

/// A reader that stores all the bytes it collects in a buffer.
pub struct TrackReader<R: io::Read> {
    buf: Vec<u8>,
    reader: R,
}

impl<R: io::Read> TrackReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            buf: vec![],
            reader,
        }
    }

    pub fn into_reader(self) -> R {
        self.reader
    }

    pub fn into_buf(self) -> Vec<u8> {
        self.buf
    }
}

impl<R: io::Read> io::Read for TrackReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reader.read(buf)?;
        self.buf.extend_from_slice(&buf[..bytes]);
        Ok(bytes)
    }
}
