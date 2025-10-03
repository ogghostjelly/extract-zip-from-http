use std::{io, num::ParseIntError};

use ureq::{
    Agent,
    http::{Uri, header::ToStrError},
};

mod read_ext;
mod rewind_buf;
mod ring_buffer;

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
    }

    todo!()
}

fn parse_cdfh_chunk<R: io::Read>(reader: R) -> Result<(Vec<u8>,)> {
    todo!()
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
    #[error("malformed content-length: {0}")]
    MalformedContentLengthToStr(ToStrError),
    #[error("malformed content-length: {0}")]
    MalformedContentLengthParseInt(ParseIntError),
    #[error("missing content length")]
    MissingContentLength,
    #[error("file not found")]
    FileNotFound,
}
