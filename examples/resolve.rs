use onepassword_sdk_unofficial::{Client, DesktopAuth};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account = std::env::var("OP_ACCOUNT")?;
    let reference = std::env::var("OP_REFERENCE")?;

    let auth = DesktopAuth::new(account)?;
    let mut client = Client::builder(auth)
        .integration_name("onepassword-sdk-unofficial-example")
        .integration_version(env!("CARGO_PKG_VERSION"))
        .build()?;

    let value = client.secrets().resolve(&reference)?;
    println!("resolved {} bytes", value.len());
    Ok(())
}
