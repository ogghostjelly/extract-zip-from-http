use std::{
    io::{self, BufReader, Read},
    num::ParseIntError,
};

use read_ext::ReadExt;
use structs::{CDFH, CompressionMethod, Eocd, Eocd32, Eocd64};
use ureq::{
    Agent,
    http::{Uri, header::ToStrError},
};

mod read_ext;
mod structs;

pub fn extract_file(
    agent: &Agent,
    uri: Uri,
    filesize: Option<usize>,
    name: &str,
) -> Result<impl io::Read> {
    let start = std::time::Instant::now();
    let filesize = match filesize {
        Some(filesize) => filesize,
        None => request_content_length(agent, &uri)?,
    };
    println!(
        "Got Content-Length in {:?}",
        std::time::Instant::now() - start
    );

    let Some(cfdh) = find_in_central_directory(agent, &uri, filesize, name)? else {
        return Err(Error::FileNotFound);
    };

    let start = std::time::Instant::now();
    let resp = agent
        .get(uri)
        .header("Range", format!("bytes={}-", cfdh.file_header_offset))
        .call()?;

    let mut reader = BufReader::new(resp.into_body().into_reader());

    let mut signature = [0; 4];
    reader.read_exact(&mut signature)?;
    if signature != *b"PK\x03\x04" {
        return Err(Error::MalformedFileHeader);
    }

    let Some(()) = read_fh(&mut reader)? else {
        return Err(Error::MalformedFileHeader);
    };

    let reader = reader.take(cfdh.compressed_size as u64);
    let reader = inflate::DeflateDecoder::new(reader);

    println!("Got FH in {:?}", std::time::Instant::now() - start);

    Ok(reader)
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
    let start = std::time::Instant::now();
    let Some(eocd) = request_eocd(agent, uri, filesize)? else {
        return Err(Error::MissingEocd);
    };
    println!("Got EOCD in {:?}", std::time::Instant::now() - start);

    let from = eocd.cd_offset;
    let to = filesize as u64 + eocd.cd_size;

    let start = std::time::Instant::now();

    let resp = agent
        .get(uri)
        .header("Range", format!("bytes={from}-{to}"))
        .call()?;

    let mut reader = BufReader::new(resp.into_body().into_reader());
    let mut buf: [u8; 4] = [0u8; 4];

    while let Some(value) = (&mut reader).bytes().next() {
        let value = value?;

        buf[0] = value;
        buf.rotate_left(1);

        if buf == *b"PK\x01\x02" {
            if let Some(cfdh) = read_cdfh(&mut reader, eocd.offset)? {
                if cfdh.filename == name {
                    println!("Got CDFH in {:?}", std::time::Instant::now() - start);
                    return Ok(Some(cfdh));
                }
            }
        }
    }

    Ok(None)
}

fn request_eocd(agent: &Agent, uri: &Uri, filesize: usize) -> Result<Option<Eocd>> {
    const CHUNK_SIZE: usize = 256;

    let from = filesize - CHUNK_SIZE;
    let to = filesize - 1;

    let resp = agent
        .get(uri)
        .header("Range", format!("bytes={from}-{to}"))
        .call()?;

    let mut reader = BufReader::with_capacity(CHUNK_SIZE, resp.into_body().into_reader());
    let mut buf = [0u8; 4];
    let mut byte_offset = 0;

    while let Some(value) = (&mut reader).bytes().next() {
        let value = value?;

        buf[0] = value;
        buf.rotate_left(1);

        if buf == *b"PK\x05\x06" {
            if let Some(value) = read_eocd32(&mut reader, from + byte_offset, filesize)? {
                return Ok(Some(value.into()));
            }
        } else if buf == *b"PK\x06\x06" {
            if let Some(value) = read_eocd64(&mut reader, from + byte_offset)? {
                return Ok(Some(value.into()));
            }
        }

        byte_offset += 1;
    }

    Ok(None)
}

/// Read a EOCD32 or None if Zip64 is used instead.
/// The given reader should return bytes right after the magic number `PK\x05\x06`.
fn read_eocd32<R: ReadExt>(r: &mut R, offset: usize, filesize: usize) -> Result<Option<Eocd32>> {
    let this_disk_number = r.read_u16()?;
    if this_disk_number > 256 && this_disk_number != 0xff {
        return Ok(None);
    }
    let cd_disk = r.read_u16()?;
    if cd_disk > 256 && cd_disk != 0xff {
        return Ok(None);
    }
    let cd_records_on_disk = r.read_u16()?;
    let cd_records_total = r.read_u16()?;
    let cd_size = r.read_u32()?;
    if cd_size as usize > filesize {
        return Ok(None);
    }
    let cd_offset = r.read_u32()?;
    if cd_offset as usize > filesize {
        return Ok(None);
    }

    if this_disk_number == 0xff
        && cd_disk == 0xff
        && cd_records_on_disk == 0xff
        && cd_records_total == 0xff
        && cd_size == 0xffff
        && cd_offset == 0xffff
    {
        return Ok(None);
    }

    let comment_len = r.read_u16()?;
    let _comment = r.skip_bytes(comment_len as usize)?;

    Ok(Some(Eocd32 {
        this_disk_number,
        cd_disk,
        cd_records_on_disk,
        cd_records_total,
        cd_size,
        cd_offset,
        offset,
    }))
}

/// Read a EOCD32 or None if it is a false positive.
/// The given reader should return bytes right after the magic number `PK\x06\x06`.
fn read_eocd64<R: ReadExt>(r: &mut R, offset: usize) -> Result<Option<Eocd64>> {
    let _size = r.read_u64()?;
    let version_made_by = r.read_u16()?;
    let version_to_extract = r.read_u16()?;
    // The version is stored in the last 8 bits of the field,
    // if the version is larger than 63 it's likely a false positive.
    if (version_made_by & 0xff) > 63 || (version_to_extract & 0xff) > 63 {
        return Ok(None);
    }
    let this_disk_number = r.read_u32()?;
    let cd_disk = r.read_u32()?;
    let cd_records_on_disk = r.read_u64()?;
    let cd_records_total = r.read_u64()?;
    let cd_size = r.read_u64()?;
    let cd_offset = r.read_u64()?;
    //let _comment = r.read_bytes

    Ok(Some(Eocd64 {
        this_disk_number,
        cd_disk,
        cd_records_on_disk,
        cd_records_total,
        cd_size,
        cd_offset,
        offset,
    }))
}

/// Read a file header or None if it is a false positive.
/// The given reader should return bytes right after the magic number `PK\x03\x04`.
fn read_fh<R: ReadExt>(r: &mut R) -> Result<Option<()>> {
    let version_to_extract = r.read_u16()?;
    // The version is stored in the last 8 bits of the field,
    // if the version is larger than 63 it's likely a false positive.
    if (version_to_extract & 0xff) > 63 {
        return Ok(None);
    }

    let _general_purpose_flags = r.read_u16()?;
    let compression_method_id = r.read_u16()?;
    let Some(compression_method) = CompressionMethod::from_id(compression_method_id) else {
        return Ok(None);
    };
    assert_eq!(
        compression_method,
        CompressionMethod::Deflated,
        "only DEFLATE compression is supported"
    );

    let _last_modification_time = r.read_u16()?;
    let _last_modification_date = r.read_u16()?;

    let _crc32 = r.read_u32()?;
    let _compressed_size = r.read_u32()?;
    let _uncompressed_size = r.read_u32()?;

    let filename_length = r.read_u16()?;
    let extra_field_length = r.read_u16()?;

    let _filename = r.skip_bytes(filename_length as usize)?;
    let _extra_field = r.skip_bytes(extra_field_length as usize)?;

    Ok(Some(()))
}

/// Read a central directory file header or None if it is a false positive.
/// The given reader should return bytes right after the magic number `PK\x01\x02`.
fn read_cdfh<R: ReadExt>(r: &mut R, maximum_allowed_offset: usize) -> Result<Option<CDFH>> {
    let version_made_by = r.read_u16()?;
    let version_to_extract = r.read_u16()?;
    // The version is stored in the last 8 bits of the field,
    // if the version is larger than 63 it's likely a false positive.
    if (version_made_by & 0xff) > 63 || (version_to_extract & 0xff) > 63 {
        return Ok(None);
    }
    let general_purpose_flags = r.read_u16()?;
    let compression_method_id = r.read_u16()?;
    let Some(compression_method) = CompressionMethod::from_id(compression_method_id) else {
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
        return Ok(None);
    }

    // Filename should be valid UTF-8
    let Ok(filename) = String::from_utf8(r.read_bytes(filename_length as usize)?) else {
        return Ok(None);
    };
    let _extra_field = r.skip_bytes(extra_field_length as usize)?;
    let _file_comment = r.skip_bytes(file_comment_length as usize)?;

    Ok(Some(CDFH {
        version_made_by,
        version_to_extract,
        general_purpose_flags,
        compression_method,
        last_modification_time,
        last_modification_date,
        crc32,
        compressed_size,
        uncompressed_size,
        extra_field_length,
        file_comment_length,
        disk_number,
        internal_attrs,
        external_attrs,
        file_header_offset,
        filename,
    }))
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
    #[error("missing eocd")]
    MissingEocd,
    #[error("malformed file header")]
    MalformedFileHeader,
}
