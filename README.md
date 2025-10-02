# Extract PKZIP from HTTP

> [!WARNING]
> Don't depend on this repository, it is not a library!
> It is simply meant to demonstrate extracting a file from a zip over HTTP.
> I'll probably rewrite this with `reqwest` and use it in `ferium` for dependency resolution.

A specialized zip decompresser that extracts a single file from a zip using HTTP range requests. Only supports files using DEFLATE compression. Blocking and uses `ureq` for HTTP requests.

Might work for Zip64 formats?? I haven't tested it... doesn't matter anyway since most jar files don't seem to use it.