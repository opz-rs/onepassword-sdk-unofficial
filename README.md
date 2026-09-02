# onepassword-sdk-unofficial

> **Unofficial.** This project is not affiliated with, sponsored by, or endorsed by 1Password.

An experimental Rust SDK for 1Password, developed under the `opz-rs` organization and dogfooded by [`opz`](https://github.com/opz-rs/opz).

The first milestone proves that a Rust application can use 1Password desktop-app authorization with a persistent client and resolve secret references in batches, without storing a 1Password account password or exporting a service-account token.

## Status

Experimental / pre-1.0.

Implemented:

- `DesktopAuth`
- persistent `Client`
- `secrets().resolve()`
- `secrets().resolve_all()` (up to 100 references per invocation)
- `vaults().list()`
- `items().list()`, `get()`, and `get_all()`
- `items().create()`, `create_all()`, `put()`, `delete()`, `delete_all()`, and `archive()` using official-SDK JSON shapes
- retry after a desktop-session-expired response
- explicit release of the SDK client on drop
- bounded inputs and sanitized upstream errors
- macOS and Linux desktop transports using the SDK IPC library shipped with 1Password

Planned:

- Windows desktop transport
- service-account authentication
- typed Rust item/vault models over the current raw-JSON compatibility surface
- conformance tests against the official Go / JavaScript / Python SDKs
- adoption by `opz`, then replacement of the experimental 1Password sidecar in `temote-mcp`

## Platform support

- macOS: implemented and locally exercised against the 1Password desktop app.
- Linux: implemented against the same shared-library ABI and library locations used by the official Go SDK; compile/unit tested, with live desktop acceptance still pending.
- Windows: planned.

## Example

Enable **Settings → Developer → Integrate with the 1Password SDKs → Integrate with other apps** in the 1Password desktop app, then:

```rust,no_run
use onepassword_sdk_unofficial::{Client, DesktopAuth};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = DesktopAuth::new("my.1password.com")?;
    let mut client = Client::builder(auth)
        .integration_name("my-rust-app")
        .integration_version("0.1.0")
        .build()?;

    let password = client
        .secrets()
        .resolve("op://Personal/example/password")?;

    println!("resolved {} bytes", password.len());
    Ok(())
}
```

Batch resolution keeps one authenticated client alive. Prefer one long-lived `Client` and `resolve_all` calls over repeatedly creating clients; a single call accepts up to 100 references. Desktop authorization happens when the client is initialized, while subsequent secret resolutions and item operations reuse the authenticated client. If the desktop session expires, the SDK reinitializes the client once and retries.

Item management currently accepts and returns `serde_json::Value` objects matching the official SDK schemas. This keeps the compatibility layer small while `opz` dogfoods create/update/delete behavior; typed Rust models can be added later without coupling transport correctness to a large generated type surface. Write calls are bounded to 1 MiB per item and 100 items / 8 MiB per batch.


```rust,no_run
# use onepassword_sdk_unofficial::{Client, DesktopAuth};
# fn run() -> Result<(), Box<dyn std::error::Error>> {
# let auth = DesktopAuth::new("my.1password.com")?;
# let mut client = Client::builder(auth).build()?;
let values = client.secrets().resolve_all(&[
    "op://Personal/example/password",
    "op://Personal/example/token",
])?;
# Ok(()) }
```

## Why this repository exists

1Password publishes official SDKs for JavaScript, Go, and Python, including desktop-app authorization. There is currently no equivalent official Rust SDK.

`opz-rs/onepassword-sdk-unofficial` is intended to make that gap measurable rather than speculative: implement a small compatible Rust surface, compare behavior with official SDKs, benchmark it in `opz`, and use a second independent consumer (`temote-mcp`) to test whether the API is actually reusable.

## Compatibility and protocol policy

1Password also publishes the Rust `onepassword-ipc-client` transport crate. Its documentation warns that undocumented desktop IPC endpoints can change and should not be treated as supported integration points.

Accordingly this repository keeps transport details private and treats the current macOS/Linux implementation as a proof, not a stable public protocol contract. The current SDK core compatibility build is pinned to `0040102`, matching the official Go SDK v0.4.1 used for live conformance checks; that compatibility value is intentionally separate from this crate's own version. The public Rust API is intentionally small so the transport can be replaced as 1Password documents or publishes more of the SDK integration surface.

## Security

- Secret values are returned only to the caller; the SDK does not log them.
- Upstream error payloads are sanitized before becoming public errors.
- Desktop authentication does not require this crate to persist the account password.
- Secret references are bounded to 100 entries, 4 KiB each, and 128 KiB total per batch.
- Raw item writes are bounded to 1 MiB per item and 100 items / 8 MiB per batch; validation errors never include item contents.
- This crate does not read or write the local 1Password SQLite database.

## Testing

The normal test suite runs on stable Rust and includes property-based tests powered by [`sile/noprop`](https://github.com/sile/noprop). The properties cover secret-reference size boundaries, response ordering with duplicate references, payload-shape equivalence, and upstream-error sanitization. Failure seeds can be replayed with the `OPSDK_*_NOPROP_SEED` variables printed by noprop.

`noprop` currently requires Rust 1.88 or newer, but it is a dev-dependency only. The published library keeps its Rust 1.85 MSRV; CI checks `cargo check --lib --locked` separately with Rust 1.85.

## License

MIT. Use of 1Password APIs, SDKs, desktop integrations, and developer tools remains subject to 1Password's applicable terms.
