use std::time::Instant;

use onepassword_sdk_unofficial::{Client, DesktopAuth};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account = std::env::var("OP_ACCOUNT")?;
    let auth = DesktopAuth::new(account)?;

    let started = Instant::now();
    let mut client = Client::builder(auth)
        .integration_name("onepassword-sdk-unofficial-probe")
        .integration_version(env!("CARGO_PKG_VERSION"))
        .build()?;
    eprintln!("client_init_ms={}", started.elapsed().as_millis());

    for attempt in 1..=2 {
        let started = Instant::now();
        let result = client
            .secrets()
            .resolve("op://__onepassword_sdk_unofficial_probe__/missing/value");
        eprintln!(
            "resolve_{attempt}_ms={} outcome={}",
            started.elapsed().as_millis(),
            if result.is_ok() {
                "unexpected_success"
            } else {
                "expected_error"
            }
        );
    }
    Ok(())
}
