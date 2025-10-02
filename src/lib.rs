use std::{io::Read, num::ParseIntError};

use ureq::{
    Agent,
    http::{Uri, header::ToStrError},
};

pub fn extract_file(agent: &Agent, uri: Uri, filesize: Option<usize>, name: &[u8]) -> Result<()> {
    let filesize = match filesize {
        Some(filesize) => filesize,
        None => request_content_length(agent, &uri)?,
    };

    find_in_central_directory(agent, &uri, filesize, name)?;

    todo!()
}

/// Find the central directory entry of a file.
///
/// # Errors
/// If HTTP range requests are not supported.
fn find_in_central_directory(agent: &Agent, uri: &Uri, filesize: usize, name: &[u8]) -> Result<()> {
    const CHUNK_SIZE: usize = 1_048_576; // 1 MB

    let chunks = filesize.div_ceil(CHUNK_SIZE);

    let mut bytes_from_last_read = vec![];

    for chunk_idx in 0..chunks {
        let from = filesize
            .checked_sub((chunk_idx + 1) * CHUNK_SIZE)
            .unwrap_or(0);
        let to = filesize - (chunk_idx * CHUNK_SIZE) - 1;

        println!("GET Range: bytes={from}-{to}");

        let req = agent
            .get(uri)
            .header("Range", format!("bytes={from}-{to}"))
            .call()?;

        let mut reader = req.into_body().into_reader();
        let mut buf = Vec::with_capacity(to - from);
        let start = std::time::Instant::now();
        reader.read_to_end(&mut buf).unwrap();
        buf.append(&mut bytes_from_last_read);
        println!("Read to buffer in {:?}", std::time::Instant::now() - start);

        let mut is_last_chunk = false;
        let mut stray_bytes = true;

        for i in 0..buf.len() {
            if buf[i..].starts_with(b"PK\x03\x04") {
                stray_bytes = false;
                is_last_chunk = true;
            } else if buf[i..].starts_with(b"PK\x01\x02") {
                stray_bytes = false;
                println!("Found CDFH at chunk relative offset {i}");
                let filename_len =
                    u16::from_le_bytes(buf[i + 28..i + 30].try_into().unwrap()) as usize;
                let filename = str::from_utf8(&buf[i + 46..i + 46 + filename_len]).unwrap();
                println!("{filename}")
            } else if stray_bytes {
                bytes_from_last_read.push(buf[i]);
            }
        }

        if is_last_chunk {
            break;
        }
    }

    todo!()
}

struct RingBuffer<T, const N: usize> {
    buf: [T; N],
    ptr: usize,
}

impl<T, const N: usize> RingBuffer<T, N> {
    pub fn push(&mut self, value: T) {
        self.buf[self.ptr] = value;
        self.ptr += 1;
        if self.ptr >= self.buf.len() {
            self.ptr = 0;
        }
    }
}

/// Make a HEAD request and retrive the Content-Length header.
///
/// # Errors
/// If the Content-Length is not present or malformed.
fn request_content_length(agent: &Agent, uri: &Uri) -> Result<usize> {
    let head = agent.head(uri).call()?;

    let Some(filesize) = head.headers().get("content-length") else {
        return Err(Error::MissingContentLength);
    };

    let filesize = match filesize.to_str() {
        Ok(filesize) => filesize,
        Err(e) => return Err(Error::MalformedContentLengthToStr(e)),
    };

    match filesize.parse() {
        Ok(filesize) => Ok(filesize),
        Err(e) => return Err(Error::MalformedContentLengthParseInt(e)),
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Ureq(#[from] ureq::Error),
    #[error("missing content length")]
    MissingContentLength,
    #[error("malformed content-length: {0}")]
    MalformedContentLengthToStr(ToStrError),
    #[error("malformed content-length: {0}")]
    MalformedContentLengthParseInt(ParseIntError),
}
