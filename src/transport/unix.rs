use std::ffi::CString;
use std::path::PathBuf;

use base64::Engine as _;
use serde_json::{Value, json};

use crate::{Error, Result};

type SendMessage =
    unsafe extern "C" fn(*const u8, usize, *mut *mut u8, *mut usize, *mut usize) -> i32;
type FreeResponse = unsafe extern "C" fn(*mut u8, usize, usize);

pub(crate) struct DesktopTransport {
    handle: *mut libc::c_void,
    send_message: SendMessage,
    free_response: FreeResponse,
}

impl DesktopTransport {
    pub(crate) fn load() -> Result<Self> {
        let path = candidate_library_paths()
            .into_iter()
            .find(|path| path.is_file())
            .ok_or_else(|| {
                Error::Unavailable(
                    "SDK IPC library was not found; install the 1Password desktop app".to_owned(),
                )
            })?;
        let c_path = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|error| Error::Unavailable(error.to_string()))?;
        // SAFETY: c_path is a valid NUL-terminated string and RTLD_NOW requests eager resolution.
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW) };
        if handle.is_null() {
            return Err(Error::Unavailable(
                "failed to open the 1Password SDK IPC library".to_owned(),
            ));
        }

        let send_name = c"op_sdk_ipc_send_message";
        let free_name = c"op_sdk_ipc_free_response";
        // SAFETY: handle belongs to the 1Password SDK IPC library loaded above.
        let send = unsafe { libc::dlsym(handle, send_name.as_ptr()) };
        // SAFETY: handle belongs to the 1Password SDK IPC library loaded above.
        let free = unsafe { libc::dlsym(handle, free_name.as_ptr()) };
        if send.is_null() || free.is_null() {
            // SAFETY: handle was returned by dlopen above and has not been closed.
            unsafe { libc::dlclose(handle) };
            return Err(Error::Unavailable(
                "1Password SDK IPC library is missing required symbols".to_owned(),
            ));
        }
        // SAFETY: these signatures match the ABI consumed by the official 1Password SDK bindings.
        let send_message: SendMessage = unsafe { std::mem::transmute(send) };
        // SAFETY: same ABI contract as above.
        let free_response: FreeResponse = unsafe { std::mem::transmute(free) };
        Ok(Self {
            handle,
            send_message,
            free_response,
        })
    }

    pub(crate) fn call(&self, account: &str, kind: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let request = json!({
            "kind": kind,
            "account_name": account,
            "payload": base64::engine::general_purpose::STANDARD.encode(payload),
        });
        let input =
            serde_json::to_vec(&request).map_err(|error| Error::Protocol(error.to_string()))?;
        let mut output_ptr: *mut u8 = std::ptr::null_mut();
        let mut output_len = 0usize;
        let mut output_cap = 0usize;
        // SAFETY: input stays alive for the call and output arguments are valid writable pointers.
        let code = unsafe {
            (self.send_message)(
                input.as_ptr(),
                input.len(),
                &mut output_ptr,
                &mut output_len,
                &mut output_cap,
            )
        };
        if code != 0 {
            return Err(classify_return_code(code));
        }
        if output_ptr.is_null() {
            return Err(Error::Unavailable(
                "SDK IPC returned a null response".to_owned(),
            ));
        }
        // SAFETY: the SDK returned output_len initialized bytes valid until free_response.
        let raw = unsafe { std::slice::from_raw_parts(output_ptr, output_len).to_vec() };
        // SAFETY: pointer/length/capacity are exactly the allocation tuple returned by send_message.
        unsafe { (self.free_response)(output_ptr, output_len, output_cap) };

        let response: Value =
            serde_json::from_slice(&raw).map_err(|error| Error::Protocol(error.to_string()))?;
        let success = response
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let payload = decode_response_payload(response.get("payload"))?;
        if success {
            return Ok(payload);
        }
        Err(classify_sdk_error(&String::from_utf8_lossy(&payload)))
    }
}

impl Drop for DesktopTransport {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle is owned by this transport and came from dlopen.
            unsafe { libc::dlclose(self.handle) };
        }
    }
}

fn candidate_library_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut candidates = vec![PathBuf::from(
            "/Applications/1Password.app/Contents/Frameworks/libop_sdk_ipc_client.dylib",
        )];
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(
                PathBuf::from(home).join(
                    "Applications/1Password.app/Contents/Frameworks/libop_sdk_ipc_client.dylib",
                ),
            );
        }
        candidates
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/usr/bin/1password/libop_sdk_ipc_client.so"),
            PathBuf::from("/opt/1Password/libop_sdk_ipc_client.so"),
            PathBuf::from("/snap/bin/1password/libop_sdk_ipc_client.so"),
        ]
    }
}

fn classify_return_code(code: i32) -> Error {
    #[cfg(target_os = "macos")]
    let message = match code {
        -3 => "desktop app connection channel is closed",
        -7 => "connection was unexpectedly dropped by the desktop app",
        _ => "desktop SDK IPC call failed",
    };
    #[cfg(target_os = "linux")]
    let message = match code {
        -2 => "desktop app connection channel is closed",
        -5 => "connection was unexpectedly dropped by the desktop app",
        _ => "desktop SDK IPC call failed",
    };
    Error::Unavailable(message.to_owned())
}

fn classify_sdk_error(error: &str) -> Error {
    if error.contains("Denied authorization") {
        Error::AuthorizationDenied
    } else if error.contains("DesktopSessionExpired") || error.contains("desktop session expired") {
        Error::DesktopSessionExpired
    } else {
        Error::Unavailable("desktop SDK request failed".to_owned())
    }
}

fn decode_response_payload(value: Option<&Value>) -> Result<Vec<u8>> {
    let value =
        value.ok_or_else(|| Error::Protocol("SDK response is missing payload".to_owned()))?;
    if let Some(encoded) = value.as_str() {
        return base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| Error::Protocol(error.to_string()));
    }
    let array = value.as_array().ok_or_else(|| {
        Error::Protocol("SDK response payload has an unsupported shape".to_owned())
    })?;
    array
        .iter()
        .map(|byte| {
            byte.as_u64()
                .filter(|byte| *byte <= u8::MAX as u64)
                .map(|byte| byte as u8)
                .ok_or_else(|| {
                    Error::Protocol("SDK response payload contains a non-byte value".to_owned())
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_decoder_accepts_byte_array_and_base64_shapes() {
        let bytes = json!([123, 34, 111, 107, 34, 58, 116, 114, 117, 101, 125]);
        assert_eq!(
            decode_response_payload(Some(&bytes)).unwrap(),
            br#"{"ok":true}"#
        );

        let encoded = json!(base64::engine::general_purpose::STANDARD.encode(br#"{"ok":true}"#));
        assert_eq!(
            decode_response_payload(Some(&encoded)).unwrap(),
            br#"{"ok":true}"#
        );
        assert!(decode_response_payload(Some(&json!([256]))).is_err());
        assert!(decode_response_payload(Some(&json!({"unexpected": true}))).is_err());
    }

    #[test]
    fn pbt_payload_decoder_round_trips_supported_shapes() -> noprop::TestResult {
        let seed = noprop::seed_from_env_or_time("OPSDK_PAYLOAD_NOPROP_SEED")?;
        let mut runner = noprop::Runner::new(seed);

        runner.run(512, |ctx| {
            let len = noprop::sample_with_boundaries(
                ctx,
                &[0usize, 1, 255, 1024],
                noprop::Ratio::one_nth(2),
                |ctx| noprop::sample_usize_in(ctx, 0..=1024),
            );
            let payload = noprop::sample_bytes_vec(ctx, len);
            let byte_array = Value::Array(payload.iter().copied().map(Value::from).collect());
            let base64_payload = json!(base64::engine::general_purpose::STANDARD.encode(&payload));

            assert_eq!(decode_response_payload(Some(&byte_array))?, payload);
            assert_eq!(decode_response_payload(Some(&base64_payload))?, payload);
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn pbt_upstream_error_classification_never_echoes_input() -> noprop::TestResult {
        let seed = noprop::seed_from_env_or_time("OPSDK_ERROR_NOPROP_SEED")?;
        let mut runner = noprop::Runner::new(seed);

        runner.run(512, |ctx| {
            let len = noprop::sample_usize_in(ctx, 0..=128);
            let generated = noprop::sample_ascii_printable_string(ctx, len);
            let upstream = format!("sensitive-canary::{generated}");
            let rendered = classify_sdk_error(&upstream).to_string();
            assert!(!rendered.contains(&upstream));
            assert!(!rendered.contains("sensitive-canary::"));
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn upstream_errors_are_sanitized() {
        assert!(matches!(
            classify_sdk_error("Denied authorization for SDK client private detail"),
            Error::AuthorizationDenied
        ));
        let error = classify_sdk_error("secret upstream detail");
        assert!(!error.to_string().contains("secret upstream detail"));
    }

    #[test]
    fn library_paths_match_official_sdk_layouts() {
        let paths = candidate_library_paths();
        #[cfg(target_os = "macos")]
        assert!(paths.iter().any(|path| {
            path == std::path::Path::new(
                "/Applications/1Password.app/Contents/Frameworks/libop_sdk_ipc_client.dylib",
            )
        }));
        #[cfg(target_os = "linux")]
        {
            assert_eq!(paths.len(), 3);
            assert_eq!(
                paths[0],
                std::path::Path::new("/usr/bin/1password/libop_sdk_ipc_client.so")
            );
            assert_eq!(
                paths[1],
                std::path::Path::new("/opt/1Password/libop_sdk_ipc_client.so")
            );
            assert_eq!(
                paths[2],
                std::path::Path::new("/snap/bin/1password/libop_sdk_ipc_client.so")
            );
        }
    }

    #[test]
    fn return_codes_do_not_expose_internal_details() {
        #[cfg(target_os = "macos")]
        assert!(
            classify_return_code(-3)
                .to_string()
                .contains("channel is closed")
        );
        #[cfg(target_os = "linux")]
        assert!(
            classify_return_code(-2)
                .to_string()
                .contains("channel is closed")
        );
        assert!(!classify_return_code(-999).to_string().contains("-999"));
    }
}
