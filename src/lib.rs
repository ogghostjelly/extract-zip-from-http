use std::{
    fmt,
    io::{self, BufReader, Read},
    mem,
    num::ParseIntError,
};

use buf_iter::BufIter;
use enumerate_iter::EnumerateIter;
use ureq::{
    Agent,
    http::{Uri, header::ToStrError},
};

mod buf_iter;
mod enumerate_iter;

pub fn extract_file(agent: &Agent, uri: Uri, filesize: Option<usize>, name: &str) -> Result<()> {
    let filesize = match filesize {
        Some(filesize) => filesize,
        None => request_content_length(agent, &uri)?,
    };

    let start = std::time::Instant::now();
    let Some(cfdh) = find_in_central_directory(agent, &uri, filesize, name)? else {
        return Err(Error::FileNotFound);
    };
    println!("Finished in {:?}", std::time::Instant::now() - start);

    todo!()
}

/// Find the central directory entry of a file.
///
/// # Errors
/// If HTTP range requests are not supported.
fn find_in_central_directory(
    agent: &Agent,
    uri: &Uri,
    filesize: usize,
    name: &str,
) -> Result<Option<CDFH>> {
    const CHUNK_SIZE: usize = 1_048_576 / 4; // 1 MB

    let chunks = filesize.div_ceil(CHUNK_SIZE);

    let mut stray_bytes: Vec<u8> = vec![];
    let mut maximum_allowed_offset = filesize;

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

        let reader = BufReader::new(req.into_body().into_reader());
        let stray_bytes_vec = mem::take(&mut stray_bytes);
        let reader = reader.chain(stray_bytes_vec.as_slice());
        let mut reader = EnumerateIter::new(reader.bytes());

        let mut buf = match RingBuffer::try_from_iter(&mut reader)? {
            Ok(buf) => buf,
            Err(mut buf) => {
                stray_bytes.append(&mut buf);
                continue;
            }
        };

        let mut is_last_chunk = false;
        let mut is_stray_bytes = true;

        while let Some(value) = reader.next() {
            let value = value?;
            let stray = buf.push(value);

            if is_stray_bytes {
                stray_bytes.push(stray);
            }

            if buf.buf == *b"PK\x03\x04" {
                // Check the version_made_by field of the file header.
                // If the last 8 bits are bigger than 63 than it's likely a false positive.
                let version = read_u16(&mut reader)?;
                if (version & 0xff) > 63 {
                    // Found a file header.
                    // which means this data must be outside of the central directory record,
                    // and this is the last chunk we need to process.

                    println!("Found FH");

                    is_stray_bytes = false;
                    is_last_chunk = true;
                } else if is_stray_bytes {
                    // TODO: Push header bytes here.
                    for stray in version.to_le_bytes() {
                        stray_bytes.push(stray);
                    }
                }
            } else if buf.buf == *b"PK\x01\x02" {
                let mut reader = BufIter::new(&mut reader);

                if let Some(cdfh) = read_cdfh(&mut reader, maximum_allowed_offset)? {
                    // Found a central directory file header.
                    is_stray_bytes = false;

                    if cdfh.filename == name {
                        return Ok(Some(cdfh));
                    }
                } else if is_stray_bytes {
                    // TODO: Push header bytes here.
                    stray_bytes.append(&mut reader.into_buf());
                }
            } else if buf.buf == *b"PK\x05\x06" {
                // Reached the end of the central directory record (EOCD).
                // no offset should be after the EOCD, so set the maximum allowed offset.
                maximum_allowed_offset = from + reader.index - 4;
                println!("Found EOCD");
                break;
            }
        }

        if is_last_chunk {
            break;
        }
    }

    Ok(None)
}

/// Read a central directory file header or None if it is a false positive.
/// The iterator should return bytes right after the magic number.
fn read_cdfh<I: Iterator<Item = io::Result<u8>>>(
    reader: &mut I,
    maximum_allowed_offset: usize,
) -> Result<Option<CDFH>> {
    let version_made_by = read_u16(reader)?;
    let minimum_required_version = read_u16(reader)?;
    // The version is stored in the last 8 bits of the field,
    // if the version is larger than 63 it's likely a false positive.
    if (version_made_by & 0xff) > 63 || (minimum_required_version & 0xff) > 63 {
        return Ok(None);
    }
    let general_purpose_flags = read_u16(reader)?;
    let Some(compression_method) = CompressionMethod::from_id(read_u16(reader)?) else {
        return Ok(None);
    };
    let last_modification_time = read_u16(reader)?;
    let last_modification_date = read_u16(reader)?;
    let crc32 = read_u32(reader)?;
    let compressed_size = read_u32(reader)?;
    let uncompressed_size = read_u32(reader)?;
    let filename_length = read_u16(reader)?;
    let extra_field_length = read_u16(reader)?;
    let file_comment_length = read_u16(reader)?;
    let disk_number = read_u16(reader)?;
    let internal_attrs = read_u16(reader)?;
    let external_attrs = read_u32(reader)?;
    let file_header_offset = read_u32(reader)?;
    if file_header_offset as usize > maximum_allowed_offset {
        return Ok(None);
    }

    let Ok(filename) = String::from_utf8(read_bytes(reader, filename_length as usize)?) else {
        return Ok(None);
    };
    let _extra_field = skip_bytes(reader, extra_field_length as usize)?;
    let _file_comment = skip_bytes(reader, file_comment_length as usize)?;

    Ok(Some(CDFH {
        version_made_by,
        minimum_required_version,
        general_purpose_flags,
        compression_method,
        last_modification_time,
        last_modification_date,
        crc32,
        compressed_size,
        uncompressed_size,
        filename_length,
        extra_field_length,
        file_comment_length,
        disk_number,
        internal_attrs,
        external_attrs,
        file_header_offset,
        filename,
    }))
}

struct CDFH {
    version_made_by: u16,
    minimum_required_version: u16,
    general_purpose_flags: u16,
    compression_method: CompressionMethod,
    last_modification_time: u16,
    last_modification_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    filename_length: u16,
    extra_field_length: u16,
    file_comment_length: u16,
    disk_number: u16,
    internal_attrs: u16,
    external_attrs: u32,
    file_header_offset: u32,
    filename: String,
}

#[derive(Debug)]
enum CompressionMethod {
    Stored,
    Deflated,
    Deflate64,
    Bzip2,
    LZMA,
    Zstd,
    XZ,
    AES,
}

impl CompressionMethod {
    pub fn from_id(value: u16) -> Option<CompressionMethod> {
        Some(match value {
            0 => Self::Stored,
            8 => Self::Deflated,
            9 => Self::Deflate64,
            12 => Self::Bzip2,
            14 => Self::LZMA,
            93 => Self::Zstd,
            95 => Self::XZ,
            99 => Self::AES,
            _ => return None,
        })
    }
}

fn skip_bytes<I: Iterator<Item = io::Result<u8>>>(iter: &mut I, len: usize) -> Result<()> {
    for _ in 0..len {
        _ = opt2eof(iter.next())?;
    }
    Ok(())
}

fn read_bytes<I: Iterator<Item = io::Result<u8>>>(iter: &mut I, len: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        buf.push(opt2eof(iter.next())?);
    }
    Ok(buf)
}

fn read_u32<I: Iterator<Item = io::Result<u8>>>(iter: &mut I) -> Result<u32> {
    Ok(u32::from_le_bytes([
        opt2eof(iter.next())?,
        opt2eof(iter.next())?,
        opt2eof(iter.next())?,
        opt2eof(iter.next())?,
    ]))
}

fn read_u16<I: Iterator<Item = io::Result<u8>>>(iter: &mut I) -> Result<u16> {
    Ok(u16::from_le_bytes([
        opt2eof(iter.next())?,
        opt2eof(iter.next())?,
    ]))
}

#[inline]
fn opt2eof<T>(value: Option<io::Result<T>>) -> Result<T> {
    match value {
        Some(value) => Ok(value?),
        None => Err(Error::UnexpectedEof),
    }
}

struct RingBuffer<T, const N: usize> {
    buf: [T; N],
    ptr: usize,
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for RingBuffer<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut indicies = (0..N).map(|i| (i + self.ptr) % self.buf.len());

        write!(f, "[")?;

        if let Some(i) = indicies.next() {
            self.buf[i].fmt(f)?;
        }

        for i in indicies {
            write!(f, ", ")?;
            self.buf[i].fmt(f)?;
        }

        write!(f, "]")
    }
}

impl<T, const N: usize> RingBuffer<T, N> {
    pub fn try_from_iter<I: Iterator<Item = io::Result<T>>>(
        iter: I,
    ) -> io::Result<std::result::Result<Self, Vec<T>>> {
        let mut vals: Vec<T> = Vec::with_capacity(N);

        for value in iter.take(N) {
            vals.push(value?);
        }

        match vals.try_into() {
            Ok(buf) => Ok(Ok(Self::new(buf))),
            Err(e) => Ok(Err(e)),
        }
    }
}

impl<T, const N: usize> RingBuffer<T, N> {
    pub fn new(buf: [T; N]) -> Self {
        Self { buf, ptr: 0 }
    }
}

impl<T, const N: usize> RingBuffer<T, N> {
    pub fn push(&mut self, value: T) -> T {
        let value = mem::replace(&mut self.buf[self.ptr], value);
        self.ptr += 1;
        if self.ptr >= self.buf.len() {
            self.ptr = 0;
        }
        value
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
    #[error("extract file: {0}")]
    Io(#[from] io::Error),
    #[error("unexpected eof")]
    UnexpectedEof,
    #[error("file not found")]
    FileNotFound,
}
