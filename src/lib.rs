use std::{
    io::{self, BufReader, Read},
    mem,
    num::ParseIntError,
};

use ureq::{
    Agent,
    http::{Uri, header::ToStrError},
};

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
    println!("FIND filesize: {}, chunks: {}", filesize, chunks);

    let mut bytes_from_last_read = vec![];
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
        println!(
            "len, expect: {:?}: {}",
            b"PK\x03\x04",
            bytes_from_last_read.len()
        );
        let append = mem::take(&mut bytes_from_last_read).into_iter().map(Ok);
        let mut reader = reader.bytes().chain(append);

        let mut buf = match RingBuffer::try_from_iter(&mut reader)? {
            Ok(buf) => buf,
            Err(mut buf) => {
                println!("shouldn't really be here tbh");
                bytes_from_last_read.append(&mut buf);
                continue;
            }
        };

        let mut is_last_chunk = false;
        let mut stray_bytes = true;

        while let Some(value) = reader.next() {
            let value = value?;
            let stray = buf.push(value);

            if stray_bytes {
                bytes_from_last_read.push(stray);
            }

            if buf.buf == *b"PK\x03\x04" {
                println!("FOUND FH");
                // Found a file header.
                // which means this data must be outside of the central directory record,
                // and this is the last chunk we need to process.
                let version = read_u16(&mut reader, &mut vec![], "fh_version")?;
                if (version & 0xff) <= 63 {
                    stray_bytes = false;
                    is_last_chunk = true;
                }
            } else if buf.buf == *b"PK\x01\x02" {
                stray_bytes = false;

                match read_cdfh(&mut reader, maximum_allowed_offset)? {
                    Ok(cdfh) => {
                        if cdfh.filename == name {
                            return Ok(Some(cdfh));
                        }
                    }
                    Err(e) => todo!("excess cdfh {e:?}"),
                }
            } else if buf.buf == *b"PK\x05\x06" {
                // Reached the end of the central directory record (EOCD).
                // no offset should be after the EOCD, so set the maximum allowed offset.
                //maximum_allowed_offset = byte_offset;
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
    iter: &mut I,
    maximum_allowed_offset: usize,
) -> Result<std::result::Result<CDFH, Vec<u8>>> {
    let mut recov_buf = vec![];
    let recov = &mut recov_buf;

    let version_made_by = read_u16(iter, recov, "version_made_by")?;
    let minimum_required_version = read_u16(iter, recov, "minimum_required_version")?;
    // The version is stored in the last 8 bits of the field,
    // if the version is larger than 63 it's likely a false positive.
    if (version_made_by & 0xff) > 63 || (minimum_required_version & 0xff) > 63 {
        eprintln!("Not CDFH: Version");
        return Ok(Err(recov_buf));
    }
    let general_purpose_flags = read_u16(iter, recov, "general_purpose_flags")?;
    let compression_method_id = read_u16(iter, recov, "compression_method")?;
    let Some(compression_method) = CompressionMethod::from_id(compression_method_id) else {
        eprintln!("Not CDFH: Bad compression");
        return Ok(Err(recov_buf));
    };
    let last_modification_time = read_u16(iter, recov, "last_modification_time")?;
    let last_modification_date = read_u16(iter, recov, "last_modification_date")?;
    let crc32 = read_u32(iter, recov, "crc32")?;
    let compressed_size = read_u32(iter, recov, "compressed_size")?;
    let uncompressed_size = read_u32(iter, recov, "uncompressed_size")?;
    let filename_length = read_u16(iter, recov, "filename_length")?;
    let extra_field_length = read_u16(iter, recov, "extra_field_length")?;
    let file_comment_length = read_u16(iter, recov, "file_comment_length")?;
    let disk_number = read_u16(iter, recov, "disk_number")?;
    let internal_attrs = read_u16(iter, recov, "internal_attrs")?;
    let external_attrs = read_u32(iter, recov, "external_attrs")?;
    let file_header_offset = read_u32(iter, recov, "file_header_offset")?;
    if file_header_offset as usize > maximum_allowed_offset {
        eprintln!("Not CDFH: Offset too big");
        return Ok(Err(recov_buf));
    }

    // Filename should be valid UTF-8
    let Ok(filename) = String::from_utf8(read_bytes(
        iter,
        recov,
        "filename",
        filename_length as usize,
    )?) else {
        eprintln!("Not CDFH: Filename invalid");
        return Ok(Err(recov_buf));
    };
    let _extra_field = skip_bytes(iter, recov, "extra_field", extra_field_length as usize)?;
    let _file_comment = skip_bytes(iter, recov, "file_comment", file_comment_length as usize)?;

    Ok(Ok(CDFH {
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

fn skip_bytes<I: Iterator<Item = io::Result<u8>>>(
    iter: &mut I,
    recov: &mut Vec<u8>,
    field: &'static str,
    len: usize,
) -> Result<()> {
    for _ in 0..len {
        _ = next_recov(iter, recov, field, len)?;
    }
    Ok(())
}

fn read_bytes<I: Iterator<Item = io::Result<u8>>>(
    iter: &mut I,
    recov: &mut Vec<u8>,
    field: &'static str,
    len: usize,
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        buf.push(next_recov(iter, recov, field, len)?);
    }
    Ok(buf)
}

fn read_u32<I: Iterator<Item = io::Result<u8>>>(
    iter: &mut I,
    recov: &mut Vec<u8>,
    field: &'static str,
) -> Result<u32> {
    Ok(u32::from_le_bytes([
        next_recov(iter, recov, field, 4)?,
        next_recov(iter, recov, field, 4)?,
        next_recov(iter, recov, field, 4)?,
        next_recov(iter, recov, field, 4)?,
    ]))
}

fn read_u16<I: Iterator<Item = io::Result<u8>>>(
    iter: &mut I,
    recov: &mut Vec<u8>,
    field: &'static str,
) -> Result<u16> {
    Ok(u16::from_le_bytes([
        next_recov(iter, recov, field, 2)?,
        next_recov(iter, recov, field, 2)?,
    ]))
}

fn next_recov<I: Iterator<Item = io::Result<u8>>>(
    iter: &mut I,
    recov: &mut Vec<u8>,
    field: &'static str,
    bytes: usize,
) -> Result<u8> {
    match iter.next() {
        Some(value) => {
            let value = value?;
            recov.push(value);
            Ok(value)
        }
        None => return Err(Error::UnexpectedEof(field, bytes)),
    }
}

struct RingBuffer<T, const N: usize> {
    buf: [T; N],
    ptr: usize,
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
    #[error("unexpected eof in {0}: expected {1} bytes")]
    UnexpectedEof(&'static str, usize),
    #[error("file not found")]
    FileNotFound,
}
