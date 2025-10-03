use std::{
    io::{self, BufReader},
    num::ParseIntError,
};

use read_ext::ReadExt;
use structs::{CDFH, CompressionMethod};
use ureq::{
    Agent,
    http::{Uri, header::ToStrError},
};

mod read_ext;
mod rewind_buf;
mod ring_buffer;
mod structs;

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

    for (from, to) in range_chunks(filesize, CHUNK_SIZE) {
        println!("GET Range: bytes={from}-{to}");

        let resp = agent
            .get(uri)
            .header("Range", format!("bytes={from}-{to}"))
            .call()?;

        let reader = resp.into_body().into_reader();
    }

    todo!()
}

/// Read a central directory file header or None if it is a false positive.
/// The iterator should return bytes right after the magic number.
fn read_cdfh<R: ReadExt>(r: &mut R, maximum_allowed_offset: usize) -> Result<Option<CDFH>> {
    let version_made_by = r.read_u16()?;
    let minimum_required_version = r.read_u16()?;
    // The version is stored in the last 8 bits of the field,
    // if the version is larger than 63 it's likely a false positive.
    if (version_made_by & 0xff) > 63 || (minimum_required_version & 0xff) > 63 {
        eprintln!("Not CDFH: Version");
        return Ok(None);
    }
    let general_purpose_flags = r.read_u16()?;
    let compression_method_id = r.read_u16()?;
    let Some(compression_method) = CompressionMethod::from_id(compression_method_id) else {
        eprintln!("Not CDFH: Bad compression");
        return Ok(None);
    };
    let last_modification_time = r.read_u16()?;
    let last_modification_date = r.read_u16()?;
    let crc32 = r.read_u32()?;
    let compressed_size = r.read_u32()?;
    let uncompressed_size = r.read_u32()?;
    let filename_length = r.read_u16()?;
    let extra_field_length = r.read_u16()?;
    let file_comment_length = r.read_u16()?;
    let disk_number = r.read_u16()?;
    let internal_attrs = r.read_u16()?;
    let external_attrs = r.read_u32()?;
    let file_header_offset = r.read_u32()?;
    if file_header_offset as usize > maximum_allowed_offset {
        eprintln!("Not CDFH: Offset too big");
        return Ok(None);
    }

    // Filename should be valid UTF-8
    let Ok(filename) = String::from_utf8(r.read_bytes(filename_length as usize)?) else {
        eprintln!("Not CDFH: Filename invalid");
        return Ok(None);
    };
    let _extra_field = r.skip_bytes(extra_field_length as usize)?;
    let _file_comment = r.skip_bytes(file_comment_length as usize)?;

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

/// Split a file into multiple chunks. The last chunk may not be chunk_size long.
/// Used to pass to a HTTP range request to get bytes out of a zip file.
fn range_chunks(filesize: usize, chunk_size: usize) -> impl Iterator<Item = (usize, usize)> {
    let chunks = filesize.div_ceil(chunk_size);

    (0..chunks).map(move |chunk_idx| {
        let from = filesize
            .checked_sub((chunk_idx + 1) * chunk_size)
            .unwrap_or(0);
        let to = filesize - (chunk_idx * chunk_size) - 1;
        (from, to)
    })
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
    #[error("{0}")]
    Io(#[from] io::Error),
}
