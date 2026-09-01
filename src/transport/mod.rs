#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) use unix::DesktopTransport;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) struct DesktopTransport;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl DesktopTransport {
    pub(crate) fn load() -> crate::Result<Self> {
        Err(crate::Error::UnsupportedPlatform(
            "desktop transport proof is currently implemented for macOS and Linux",
        ))
    }

    pub(crate) fn call(
        &self,
        _account: &str,
        _kind: &str,
        _payload: &[u8],
    ) -> crate::Result<Vec<u8>> {
        Err(crate::Error::UnsupportedPlatform(
            "desktop transport proof is currently implemented for macOS and Linux",
        ))
    }
}
