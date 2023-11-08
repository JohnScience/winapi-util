use core::marker::PhantomData;
use core::ptr::NonNull;
use winapi::shared::minwindef::BOOL;
use winapi::um::winnt::HANDLE;
use winapi::{shared::minwindef::DWORD, um::processthreadsapi::OpenProcess};

mod sealed {
    use core::ffi::c_void;
    use core::marker::PhantomData;
    use core::ptr::NonNull;
    use winapi::shared::minwindef::DWORD;

    pub trait HandleMetadata {
        type StoredType;
    }

    pub trait IntoAccessRights {
        const KNOWN: bool;
        const VALUE: DWORD;
        type RuntimeArgumentType: Clone + Copy;
        type AccessRightsType: HandleMetadata;
        fn rt_arg_to_dword(arg: Self::RuntimeArgumentType) -> DWORD;
        fn rt_arg_to_metadata(
            arg: Self::RuntimeArgumentType,
        ) -> <<Self as IntoAccessRights>::AccessRightsType as HandleMetadata>::StoredType;
    }

    pub trait IntoProcessId {
        fn into_process_id(self) -> DWORD;
    }

    pub struct ProcessHandleKind {}

    pub struct Handle<T: HandleType, M: HandleMetadata> {
        // PhantomData<*const T> is an idiom for removing the bearing of T on the borrow checker.
        // See https://doc.rust-lang.org/std/marker/struct.PhantomData.html#ownership-and-the-drop-check
        // for more information.
        pub(super) phantom_kind: PhantomData<*const T>,
        #[allow(dead_code)]
        pub(super) metadata: M::StoredType,
        pub inner: NonNull<c_void>,
    }

    pub trait HandleType {}

    // At the moment of writing, Option<T> cannot be used as a const generic parameter.
    pub struct AccessRights<const KNOWN: bool, const N: DWORD>;
}

use sealed::{
    AccessRights, Handle, HandleMetadata, HandleType, IntoAccessRights,
    IntoProcessId, ProcessHandleKind,
};

/// A non-null handle to a process, obtained e.g. via [`open_process`].
///
/// When the handle goes out of scope, the handle gets automatically closed by calling [`CloseHandle`].
///
/// [`CloseHandle`]: https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
pub type ProcessHandle<M> = Handle<ProcessHandleKind, M>;

/// Process Security and Access Rights that are meant to be known only at runtime.
/// If you know the access rights at compile time, use [`ComptimeAccessRights`] instead.
///
/// This type is meant to be used as a generic type parameter for [`open_process`] function.
///
/// When supplied as a generic type parameter for [`open_process`] function, its first argument
/// will be a [`DWORD`] value that will be passed to [`OpenProcess`] function.
pub type RuntimeAccessRights = AccessRights</*KNOWN=*/ false, 0>;
/// Process Security and Access Rights that are known at compile time.
/// If you don't know the access rights at compile time, fall back to [`RuntimeAccessRights`].
///
/// Parametrizations of this type are meant to be used as generic type parameters for
/// [`open_process`] function.
pub type ComptimeAccessRights<const N: DWORD> =
    AccessRights</*KNOWN=*/ true, N>;

impl<const N: DWORD> IntoAccessRights for ComptimeAccessRights<N> {
    const KNOWN: bool = true;
    const VALUE: DWORD = N;
    type RuntimeArgumentType =
        <ComptimeAccessRights<N> as HandleMetadata>::StoredType;
    type AccessRightsType = ComptimeAccessRights<N>;
    fn rt_arg_to_dword(_arg: Self::RuntimeArgumentType) -> DWORD {
        N
    }
    fn rt_arg_to_metadata(
                _arg: Self::RuntimeArgumentType,
    ) -> <<Self as IntoAccessRights>::AccessRightsType as HandleMetadata>::StoredType{
        PhantomData
    }
}

impl IntoAccessRights for RuntimeAccessRights {
    const KNOWN: bool = false;
    const VALUE: DWORD = 0;
    type RuntimeArgumentType =
        <RuntimeAccessRights as HandleMetadata>::StoredType;
    type AccessRightsType = RuntimeAccessRights;
    fn rt_arg_to_dword(arg: Self::RuntimeArgumentType) -> DWORD {
        arg
    }
    fn rt_arg_to_metadata(
                arg: Self::RuntimeArgumentType,
    ) -> <<Self as IntoAccessRights>::AccessRightsType as HandleMetadata>::StoredType{
        arg
    }
}

/// Rustic wrapper around [`OpenProcess`] function.
///
/// The returned handle gets automatically closed by calling [`CloseHandle`] when the handle goes out of scope.
///
/// [`OpenProcess`]: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
/// [`CloseHandle`]: https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
pub fn open_process<R: IntoAccessRights>(
    desired_access: R::RuntimeArgumentType,
    inherit_handle: bool,
    process_id: DWORD,
) -> Option<ProcessHandle<R::AccessRightsType>> {
    let dw_desired_access: DWORD = R::rt_arg_to_dword(desired_access);
    let inherit_handle: BOOL = if inherit_handle { 1 } else { 0 };

    let metadata = R::rt_arg_to_metadata(desired_access);

    let handle: HANDLE =
        unsafe { OpenProcess(dw_desired_access, inherit_handle, process_id) };
    let inner = NonNull::new(handle)?;

    let handle = Handle { phantom_kind: PhantomData, metadata, inner };
    Some(handle)
}

impl<const N: DWORD> HandleMetadata for ComptimeAccessRights<N> {
    type StoredType = PhantomData<()>;
}

impl HandleMetadata for RuntimeAccessRights {
    type StoredType = DWORD;
}

impl HandleType for ProcessHandleKind {}

impl IntoProcessId for u64 {
    fn into_process_id(self) -> DWORD {
        self as DWORD
    }
}

impl IntoProcessId for u32 {
    fn into_process_id(self) -> DWORD {
        self as DWORD
    }
}

// At the time of writing, fallible drop is not a thing
impl<T: HandleType, M: HandleMetadata> Drop for Handle<T, M> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        let is_ok: BOOL =
            unsafe { winapi::um::handleapi::CloseHandle(self.inner.as_mut()) };
        #[cfg(not(debug_assertions))]
        unsafe {
            winapi::um::handleapi::CloseHandle(self.inner.as_mut())
        };
        debug_assert!(is_ok != 0)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use winapi::um::winnt::PROCESS_QUERY_INFORMATION;

    #[test]
    fn open_process_using_runtime_desired_access() {
        // We pretend that the access rights are not known at compile time.
        let handle = open_process::<RuntimeAccessRights>(
            PROCESS_QUERY_INFORMATION,
            false,
            std::process::id(),
        );
        assert!(handle.is_some());
    }

    #[test]
    fn open_process_using_comptime_desired_access() {
        let handle = open_process::<
            ComptimeAccessRights<PROCESS_QUERY_INFORMATION>,
        >(PhantomData, false, std::process::id());
        assert!(handle.is_some());
    }
}
