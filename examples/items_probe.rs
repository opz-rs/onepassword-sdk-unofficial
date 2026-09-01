use onepassword_sdk_unofficial::{Client, DesktopAuth};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account = std::env::var("OP_ACCOUNT")?;
    let started = Instant::now();
    let mut client = Client::builder(DesktopAuth::new(account)?)
        .integration_name("onepassword-sdk-unofficial")
        .build()?;
    eprintln!("init_ms={}", started.elapsed().as_millis());
    let vaults = client.vaults().list()?;
    let vault = vaults
        .first()
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .ok_or("no vault")?
        .to_owned();
    eprintln!("vaults={}", vaults.len());
    let started = Instant::now();
    let items = client.items().list(&vault)?;
    eprintln!(
        "items={} list_ms={}",
        items.len(),
        started.elapsed().as_millis()
    );
    if let Some(id) = items
        .first()
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
    {
        let started = Instant::now();
        let item = client.items().get(&vault, id)?;
        eprintln!(
            "get_ok={} get_ms={}",
            item.get("id").is_some(),
            started.elapsed().as_millis()
        );
    }
    Ok(())
}
