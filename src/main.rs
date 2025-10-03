use extract_zip_from_http::extract_file;
use ureq::{Agent, http::Uri};

fn main() {
    let agent = Agent::new_with_defaults();
    let uri = Uri::try_from("https://cdn.modrinth.com/data/Xbc0uyRg/versions/XMiAOQvM/create-fabric-0.5.1-i-build.1630%2Bmc1.19.2.jar").unwrap();
    extract_file(&agent, uri, None, "fabric.mod.json").unwrap();
}
