use core::fmt::{self, Debug, Formatter};
use core::{ffi::c_void, marker::PhantomData};
use winapi::{
    shared::{minwindef::DWORD, ntdef::LPWSTR},
    um::winbase::{
        FormatMessageW, LocalFree, FORMAT_MESSAGE_ALLOCATE_BUFFER,
        FORMAT_MESSAGE_FROM_SYSTEM,
    },
};

/// Some Windows API error occurred during the call to [`OpenProcess`]. To get the error code, use [`Error::code`].
///
/// [`OpenProcess`]: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
/// [`Error::code`]: struct.Error.html#method.code
pub struct Error(
    // there's a private field to prevent construction of this struct outside of the crate.
    pub(super) PhantomData<()>,
);

/// Error code that can be returned by [`GetLastError`] after unsuccessful [`open_process`](super::open_process).
///
/// The constants of this type present a sensible subset of the full list of error codes.
///
/// The full list of error codes can be found [here](https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes).
///
/// [`GetLastError`]: https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
pub struct ErrorCode(
    // TODO: wrap "the" ErrorCode that would correspond to an arbitrary error code returned by GetLastError.
    DWORD,
);

impl Error {
    /// Returns the error code of the last failed Windows API call
    /// via an internal call to [`GetLastError`].
    ///
    /// [`GetLastError`]: https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
    pub fn code(&self) -> ErrorCode {
        let error_code: DWORD =
            unsafe { winapi::um::errhandlingapi::GetLastError() };
        ErrorCode(error_code)
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let error_code = self.code();
        let error_msg = error_code.format_message();
        write!(f, "Error {}: {}", error_code.as_dword(), error_msg)
    }
}

impl ErrorCode {
    /// The calling process does not have the required permissions to open the target process.
    pub const ERROR_ACCESS_DENIED: Self = Self(5);
    /// An invalid handle or process identifier was used.
    pub const ERROR_INVALID_HANDLE: Self = Self(6);
    /// Not enough memory to complete the operation.
    pub const ERROR_NOT_ENOUGH_MEMORY: Self = Self(8);
    /// One or more of the function's parameters are invalid.
    pub const ERROR_INVALID_PARAMETER: Self = Self(87);
    /// The calling process does not have the necessary privileges to open the target process.
    pub const ERROR_PRIVILEGE_NOT_HELD: Self = Self(1314);

    /// Returns the error code as a [`DWORD`].
    pub fn as_dword(&self) -> DWORD {
        self.0
    }

    /// Returns a human-readable error message via an internal call to [`FormatMessageW`] on the error code.
    ///
    /// [`FormatMessageW`]: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagew
    pub fn format_message(&self) -> String {
        let error_code: DWORD = self.as_dword();
        let mut error_msg: LPWSTR = core::ptr::null_mut();
        let len: DWORD = unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                core::ptr::null_mut(), // No message source (NULL means use system source)
                error_code,
                0, // Default language
                &mut error_msg as *mut LPWSTR as LPWSTR,
                0, //
                core::ptr::null_mut(),
            )
        };
        if len == 0 {
            let format_message_w_err: DWORD =
                unsafe { winapi::um::errhandlingapi::GetLastError() };
            return format!(
                "Error {}: (failed to call FormatMessageW on GetLastError result. FormatMessageW failed with error code {})",
                error_code,
                format_message_w_err
            );
        }
        let error_msg_slice: &[u16] =
            unsafe { core::slice::from_raw_parts(error_msg, len as usize) };
        let formated_msg = String::from_utf16_lossy(error_msg_slice);
        // Q(JohnScience): Is there any benefit in using HeapFree instead of LocalFree in this case?
        // in case of failure,, LocalFree returns the handle but we can't do anything with it.
        let freed = unsafe { LocalFree(error_msg as *mut c_void) }
            == core::ptr::null_mut();
        if !freed {
            let local_free_err: DWORD =
                unsafe { winapi::um::errhandlingapi::GetLastError() };
            return format!(
                "Error {}: {}. Warning: failed to free the buffer allocated by FormatMessageW (err {}).",
                error_code,
                formated_msg,
                local_free_err,
            );
        }
        formated_msg
    }
}
