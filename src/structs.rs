pub struct CDFH {
    pub version_made_by: u16,
    pub minimum_required_version: u16,
    pub general_purpose_flags: u16,
    pub compression_method: CompressionMethod,
    pub last_modification_time: u16,
    pub last_modification_date: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub filename_length: u16,
    pub extra_field_length: u16,
    pub file_comment_length: u16,
    pub disk_number: u16,
    pub internal_attrs: u16,
    pub external_attrs: u32,
    pub file_header_offset: u32,
    pub filename: String,
}

#[derive(Debug)]
pub enum CompressionMethod {
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
    pub fn from_id(id: u16) -> Option<CompressionMethod> {
        Some(match id {
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
