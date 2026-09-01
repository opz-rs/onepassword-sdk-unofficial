//! Unofficial Rust SDK experiment for 1Password desktop app integrations.
//!
//! This crate is not affiliated with or endorsed by 1Password.
//! The initial proof of concept implements desktop-app authentication and
//! secret resolution on macOS and Linux using the same SDK IPC library shipped with the
//! 1Password desktop app.

mod transport;

use serde_json::{Value, json};

const SDK_CORE_BUILD: &str = "0040102"; // Compatible with official Go SDK v0.4.1.

const MAX_SECRET_REFERENCES: usize = 100;
const MAX_REFERENCE_BYTES: usize = 4 * 1024;
const MAX_REFERENCE_INPUT_BYTES: usize = 128 * 1024;
const MAX_ACCOUNT_BYTES: usize = 4 * 1024;
const MAX_ITEM_BATCH: usize = 100;
const MAX_ITEM_JSON_BYTES: usize = 1024 * 1024;
const MAX_ITEM_BATCH_JSON_BYTES: usize = 8 * 1024 * 1024;

/// SDK result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the unofficial SDK.
#[derive(Debug)]
pub enum Error {
    UnsupportedPlatform(&'static str),
    InvalidArgument(String),
    Unavailable(String),
    AuthorizationDenied,
    DesktopSessionExpired,
    SecretResolutionFailed,
    Protocol(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform(message) => {
                write!(formatter, "unsupported platform: {message}")
            }
            Self::InvalidArgument(message) => write!(formatter, "invalid argument: {message}"),
            Self::Unavailable(message) => {
                write!(formatter, "1Password desktop SDK is unavailable: {message}")
            }
            Self::AuthorizationDenied => {
                formatter.write_str("1Password desktop authorization was denied")
            }
            Self::DesktopSessionExpired => formatter.write_str("1Password desktop session expired"),
            Self::SecretResolutionFailed => {
                formatter.write_str("1Password could not resolve one or more secret references")
            }
            Self::Protocol(message) => write!(formatter, "1Password SDK protocol error: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// Desktop-app authentication configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopAuth {
    account: String,
}

impl DesktopAuth {
    /// Authenticate through a signed-in 1Password desktop app account.
    pub fn new(account: impl Into<String>) -> Result<Self> {
        let account = account.into();
        validate_account(&account)?;
        Ok(Self { account })
    }

    /// Account name or UUID passed to the desktop SDK.
    pub fn account(&self) -> &str {
        &self.account
    }
}

/// Builder for a persistent SDK client.
pub struct ClientBuilder {
    auth: DesktopAuth,
    integration_name: String,
    integration_version: String,
}

impl ClientBuilder {
    /// Set the integration name shown to 1Password.
    pub fn integration_name(mut self, name: impl Into<String>) -> Self {
        self.integration_name = name.into();
        self
    }

    /// Set the integration version shown to 1Password.
    pub fn integration_version(mut self, version: impl Into<String>) -> Self {
        self.integration_version = version.into();
        self
    }

    /// Create and authenticate a persistent client.
    pub fn build(self) -> Result<Client> {
        validate_metadata("integration name", &self.integration_name)?;
        validate_metadata("integration version", &self.integration_version)?;
        Client::connect(self.auth, self.integration_name, self.integration_version)
    }
}

/// Persistent 1Password SDK client.
pub struct Client {
    auth: DesktopAuth,
    integration_name: String,
    integration_version: String,
    client_id: u64,
    transport: transport::DesktopTransport,
}

impl Client {
    /// Start building a client authenticated by the 1Password desktop app.
    pub fn builder(auth: DesktopAuth) -> ClientBuilder {
        ClientBuilder {
            auth,
            integration_name: env!("CARGO_PKG_NAME").to_owned(),
            integration_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn connect(
        auth: DesktopAuth,
        integration_name: String,
        integration_version: String,
    ) -> Result<Self> {
        let transport = transport::DesktopTransport::load()?;
        let client_id = init_client(&transport, &auth, &integration_name, &integration_version)?;
        Ok(Self {
            auth,
            integration_name,
            integration_version,
            client_id,
            transport,
        })
    }

    /// Access the secrets API.
    pub fn secrets(&mut self) -> Secrets<'_> {
        Secrets { client: self }
    }

    /// Access the item-management API.
    pub fn items(&mut self) -> Items<'_> {
        Items { client: self }
    }

    /// Access the read-only vaults API.
    pub fn vaults(&mut self) -> Vaults<'_> {
        Vaults { client: self }
    }

    fn invoke(&mut self, name: &str, parameters: Value) -> Result<Value> {
        let request = json!({
            "invocation": {
                "clientId": self.client_id,
                "parameters": {
                    "name": name,
                    "parameters": parameters,
                }
            }
        });
        match self.transport.call(
            self.auth.account(),
            "invoke",
            &serde_json::to_vec(&request).map_err(protocol_error)?,
        ) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(protocol_error),
            Err(Error::DesktopSessionExpired) => {
                self.client_id = init_client(
                    &self.transport,
                    &self.auth,
                    &self.integration_name,
                    &self.integration_version,
                )?;
                let retry = json!({
                    "invocation": {
                        "clientId": self.client_id,
                        "parameters": {
                            "name": name,
                            "parameters": parameters,
                        }
                    }
                });
                let bytes = self.transport.call(
                    self.auth.account(),
                    "invoke",
                    &serde_json::to_vec(&retry).map_err(protocol_error)?,
                )?;
                serde_json::from_slice(&bytes).map_err(protocol_error)
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Ok(payload) = serde_json::to_vec(&self.client_id) {
            let _ = self
                .transport
                .call(self.auth.account(), "release_client", &payload);
        }
    }
}

/// Read-only vault operations.
pub struct Vaults<'a> {
    client: &'a mut Client,
}

impl Vaults<'_> {
    /// List vault overviews visible to the authenticated desktop account.
    pub fn list(&mut self) -> Result<Vec<Value>> {
        let result = self
            .client
            .invoke("VaultsList", json!({ "params": null }))?;
        result
            .as_array()
            .cloned()
            .ok_or_else(|| Error::Protocol("vaults list response was not an array".to_owned()))
    }
}

/// Item-management operations.
///
/// Item values intentionally use raw JSON while this crate validates the
/// transport against the official SDK before committing to generated model types.
pub struct Items<'a> {
    client: &'a mut Client,
}

impl Items<'_> {
    /// Create one item from an official-SDK `ItemCreateParams` JSON object.
    pub fn create(&mut self, params: Value) -> Result<Value> {
        validate_item_json("item create params", &params)?;
        self.client
            .invoke("ItemsCreate", json!({ "params": params }))
    }

    /// Create up to 100 items in one vault using official-SDK `ItemCreateParams` JSON objects.
    pub fn create_all(&mut self, vault_id: &str, params: Vec<Value>) -> Result<Value> {
        validate_identifier("vault ID", vault_id)?;
        validate_item_batch("item create batch", &params)?;
        self.client.invoke(
            "ItemsCreateAll",
            json!({ "vault_id": vault_id, "params": params }),
        )
    }

    /// Get one decrypted item by vault and item ID.
    ///
    /// The returned JSON follows the 1Password SDK item schema. Keeping this
    /// surface as JSON lets the crate prove the Desktop SDK transport before
    /// committing to a large generated model API.
    pub fn get(&mut self, vault_id: &str, item_id: &str) -> Result<Value> {
        validate_identifier("vault ID", vault_id)?;
        validate_identifier("item ID", item_id)?;
        self.client.invoke(
            "ItemsGet",
            json!({ "vault_id": vault_id, "item_id": item_id }),
        )
    }

    /// Get multiple decrypted items from one vault in one SDK invocation.
    pub fn get_all<S: AsRef<str>>(&mut self, vault_id: &str, item_ids: &[S]) -> Result<Value> {
        validate_identifier("vault ID", vault_id)?;
        let item_ids = validate_item_ids(item_ids)?;
        self.client.invoke(
            "ItemsGetAll",
            json!({ "vault_id": vault_id, "item_ids": item_ids }),
        )
    }

    /// Replace an existing item using an official-SDK `Item` JSON object.
    pub fn put(&mut self, item: Value) -> Result<Value> {
        validate_item_json("item", &item)?;
        self.client.invoke("ItemsPut", json!({ "item": item }))
    }

    /// Permanently delete one item.
    pub fn delete(&mut self, vault_id: &str, item_id: &str) -> Result<()> {
        validate_identifier("vault ID", vault_id)?;
        validate_identifier("item ID", item_id)?;
        self.client.invoke(
            "ItemsDelete",
            json!({ "vault_id": vault_id, "item_id": item_id }),
        )?;
        Ok(())
    }

    /// Permanently delete up to 100 items from one vault.
    pub fn delete_all<S: AsRef<str>>(&mut self, vault_id: &str, item_ids: &[S]) -> Result<Value> {
        validate_identifier("vault ID", vault_id)?;
        let item_ids = validate_item_ids(item_ids)?;
        self.client.invoke(
            "ItemsDeleteAll",
            json!({ "vault_id": vault_id, "item_ids": item_ids }),
        )
    }

    /// Archive one item.
    pub fn archive(&mut self, vault_id: &str, item_id: &str) -> Result<()> {
        validate_identifier("vault ID", vault_id)?;
        validate_identifier("item ID", item_id)?;
        self.client.invoke(
            "ItemsArchive",
            json!({ "vault_id": vault_id, "item_id": item_id }),
        )?;
        Ok(())
    }

    /// List active items in a vault.
    pub fn list(&mut self, vault_id: &str) -> Result<Vec<Value>> {
        validate_identifier("vault ID", vault_id)?;
        let result = self
            .client
            .invoke("ItemsList", json!({ "vault_id": vault_id, "filters": [] }))?;
        result
            .as_array()
            .cloned()
            .ok_or_else(|| Error::Protocol("items list response was not an array".to_owned()))
    }
}

fn validate_item_json(kind: &str, value: &Value) -> Result<()> {
    if !value.is_object() {
        return Err(Error::InvalidArgument(format!(
            "{kind} must be a JSON object"
        )));
    }
    let size = serde_json::to_vec(value).map_err(protocol_error)?.len();
    if size > MAX_ITEM_JSON_BYTES {
        return Err(Error::InvalidArgument(format!(
            "{kind} exceeds {MAX_ITEM_JSON_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_item_batch(kind: &str, values: &[Value]) -> Result<()> {
    if values.is_empty() || values.len() > MAX_ITEM_BATCH {
        return Err(Error::InvalidArgument(format!(
            "{kind} must contain between 1 and {MAX_ITEM_BATCH} items"
        )));
    }
    let mut total = 0usize;
    for value in values {
        validate_item_json("item", value)?;
        total = total.saturating_add(serde_json::to_vec(value).map_err(protocol_error)?.len());
        if total > MAX_ITEM_BATCH_JSON_BYTES {
            return Err(Error::InvalidArgument(format!(
                "{kind} exceeds {MAX_ITEM_BATCH_JSON_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn validate_item_ids<S: AsRef<str>>(item_ids: &[S]) -> Result<Vec<String>> {
    if item_ids.is_empty() || item_ids.len() > MAX_ITEM_BATCH {
        return Err(Error::InvalidArgument(format!(
            "item batch must contain between 1 and {MAX_ITEM_BATCH} IDs"
        )));
    }
    item_ids
        .iter()
        .map(|id| id.as_ref())
        .map(|id| {
            validate_identifier("item ID", id)?;
            Ok(id.to_owned())
        })
        .collect()
}

fn validate_identifier(kind: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4 * 1024 {
        return Err(Error::InvalidArgument(format!(
            "{kind} is empty or too large"
        )));
    }
    Ok(())
}

/// Secret-reference operations.
pub struct Secrets<'a> {
    client: &'a mut Client,
}

impl Secrets<'_> {
    /// Resolve a single `op://` secret reference.
    pub fn resolve(&mut self, reference: &str) -> Result<String> {
        self.resolve_all(&[reference])?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Protocol("secret response was empty".to_owned()))
    }

    /// Resolve up to 100 `op://` secret references in one SDK invocation.
    pub fn resolve_all<S: AsRef<str>>(&mut self, references: &[S]) -> Result<Vec<String>> {
        let references = references
            .iter()
            .map(|reference| reference.as_ref().to_owned())
            .collect::<Vec<_>>();
        validate_references(&references)?;
        let result = self.client.invoke(
            "SecretsResolveAll",
            json!({ "secret_references": references }),
        )?;
        extract_secrets(&result, &references)
    }
}

fn init_client(
    transport: &transport::DesktopTransport,
    auth: &DesktopAuth,
    integration_name: &str,
    integration_version: &str,
) -> Result<u64> {
    let config = json!({
        "serviceAccountToken": "",
        "programmingLanguage": "Rust",
        "sdkVersion": SDK_CORE_BUILD,
        "integrationName": integration_name,
        "integrationVersion": integration_version,
        "requestLibraryName": env!("CARGO_PKG_NAME"),
        "requestLibraryVersion": env!("CARGO_PKG_VERSION"),
        "os": sdk_os_name(),
        "osVersion": "0.0.0",
        "architecture": std::env::consts::ARCH,
        "account_name": auth.account(),
    });
    let bytes = transport.call(
        auth.account(),
        "init_client",
        &serde_json::to_vec(&config).map_err(protocol_error)?,
    )?;
    serde_json::from_slice(&bytes).map_err(protocol_error)
}

fn extract_secrets(result: &Value, references: &[String]) -> Result<Vec<String>> {
    let responses = result
        .get("individualResponses")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            Error::Protocol("resolve response is missing individualResponses".to_owned())
        })?;

    references
        .iter()
        .map(|reference| {
            let response = responses.get(reference).ok_or_else(|| {
                Error::Protocol("resolve response is missing a requested reference".to_owned())
            })?;
            if response.get("error").is_some_and(|error| !error.is_null()) {
                return Err(Error::SecretResolutionFailed);
            }
            response
                .pointer("/content/secret")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::Protocol("resolve response is missing secret content".to_owned())
                })
        })
        .collect()
}

fn validate_account(account: &str) -> Result<()> {
    if account.is_empty() {
        return Err(Error::InvalidArgument(
            "account must not be empty".to_owned(),
        ));
    }
    if account.len() > MAX_ACCOUNT_BYTES {
        return Err(Error::InvalidArgument(format!(
            "account exceeds {MAX_ACCOUNT_BYTES} bytes"
        )));
    }
    if account.chars().any(char::is_control) {
        return Err(Error::InvalidArgument(
            "account must not contain control characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_metadata(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) || value.len() > 1024 {
        return Err(Error::InvalidArgument(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_references(references: &[String]) -> Result<()> {
    if references.is_empty() {
        return Err(Error::InvalidArgument(
            "references must not be empty".to_owned(),
        ));
    }
    if references.len() > MAX_SECRET_REFERENCES {
        return Err(Error::InvalidArgument(format!(
            "references must contain at most {MAX_SECRET_REFERENCES} entries"
        )));
    }
    let mut total = 0usize;
    for reference in references {
        if !reference.starts_with("op://") {
            return Err(Error::InvalidArgument(
                "secret references must start with op://".to_owned(),
            ));
        }
        if reference.len() > MAX_REFERENCE_BYTES {
            return Err(Error::InvalidArgument(format!(
                "secret reference exceeds {MAX_REFERENCE_BYTES} bytes"
            )));
        }
        if reference.chars().any(char::is_control) {
            return Err(Error::InvalidArgument(
                "secret references must not contain control characters".to_owned(),
            ));
        }
        total = total
            .checked_add(reference.len())
            .ok_or_else(|| Error::InvalidArgument("secret reference size overflow".to_owned()))?;
        if total > MAX_REFERENCE_INPUT_BYTES {
            return Err(Error::InvalidArgument(format!(
                "secret references exceed {MAX_REFERENCE_INPUT_BYTES} bytes in total"
            )));
        }
    }
    Ok(())
}

fn sdk_os_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "darwin"
    }
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        std::env::consts::OS
    }
}

fn protocol_error(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_os_name_matches_official_desktop_sdk_values() {
        #[cfg(target_os = "macos")]
        assert_eq!(sdk_os_name(), "darwin");
        #[cfg(target_os = "linux")]
        assert_eq!(sdk_os_name(), "linux");
        #[cfg(target_os = "windows")]
        assert_eq!(sdk_os_name(), "windows");
    }

    #[test]
    fn desktop_auth_rejects_invalid_accounts() {
        assert!(DesktopAuth::new("").is_err());
        assert!(DesktopAuth::new("account\nname").is_err());
        assert_eq!(
            DesktopAuth::new("my.1password.com").unwrap().account(),
            "my.1password.com"
        );
    }

    #[test]
    fn reference_validation_is_bounded() {
        assert!(validate_references(&[]).is_err());
        assert!(validate_references(&["not-a-reference".to_owned()]).is_err());
        assert!(validate_references(&vec!["op://v/i/f".to_owned(); 101]).is_err());
        assert!(validate_references(&["op://v/i/f".to_owned()]).is_ok());
    }

    #[test]
    fn extracts_secrets_in_request_order_and_supports_duplicates() {
        let result = json!({
            "individualResponses": {
                "op://v/i/a": {"content": {"secret": "alpha"}},
                "op://v/i/b": {"content": {"secret": "beta"}}
            }
        });
        let refs = vec![
            "op://v/i/b".to_owned(),
            "op://v/i/a".to_owned(),
            "op://v/i/b".to_owned(),
        ];
        assert_eq!(
            extract_secrets(&result, &refs).unwrap(),
            vec!["beta", "alpha", "beta"]
        );
    }

    #[test]
    fn item_write_inputs_are_bounded_and_errors_do_not_echo_values() {
        let invalid = json!("sensitive-canary");
        let error = validate_item_json("item", &invalid).unwrap_err();
        assert!(!error.to_string().contains("sensitive-canary"));

        assert!(validate_item_json("item", &json!({"title": "ok"})).is_ok());
        assert!(validate_item_batch("items", &[]).is_err());
        assert!(validate_item_batch("items", &vec![json!({}); 101]).is_err());
        assert!(validate_item_ids::<&str>(&[]).is_err());
        assert!(validate_item_ids(&["item-1", "item-2"]).is_ok());
        assert!(validate_item_ids(&vec!["item"; 101]).is_err());
    }

    #[test]
    fn reference_errors_do_not_expose_secret_payloads() {
        let result = json!({
            "individualResponses": {
                "op://v/i/a": {"error": {"message": "sensitive upstream detail"}}
            }
        });
        let error = extract_secrets(&result, &["op://v/i/a".to_owned()]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "1Password could not resolve one or more secret references"
        );
        assert!(!error.to_string().contains("sensitive upstream detail"));
    }
}
