#![allow(non_snake_case)]

extern crate winapi;
extern crate rustup;

use std::ffi::CString;
use std::path::PathBuf;
use ::winapi::{HRESULT, PCSTR, UINT, LPCWSTR, LPWSTR, LPVOID, ERROR_INSTALL_FAILURE, ERROR_SUCCESS};

pub type MSIHANDLE = u32;

pub const LOGMSG_TRACEONLY: i32 = 0;
pub const LOGMSG_VERBOSE: i32 = 1;
pub const LOGMSG_STANDARD: i32 = 2;

type Result<T> = ::std::result::Result<T, ()>;

// TODO: share this with self_update.rs
static TOOLS: &'static [&'static str]
    = &["rustc", "rustdoc", "cargo", "rust-lldb", "rust-gdb", "rls"];

#[no_mangle]
/// This is run as an `immediate` action early in the install sequence.
/// It should only collect information and not modify the system in any way.
pub unsafe extern "system" fn RustupPrepare(hInstall: MSIHANDLE) -> UINT {
    do_custom_action(hInstall, "RustupPrepare", rustup_prepare)
}

#[no_mangle]
/// This is be run as a `deferred` action after `InstallFiles` on install and upgrade
pub unsafe extern "system" fn RustupInstall(hInstall: MSIHANDLE) -> UINT {
    do_custom_action(hInstall, "RustupInstall", rustup_install)
}

#[no_mangle]
/// This is be run as a `deferred` action after `RemoveFiles` on uninstall (not on upgrade!)
pub unsafe extern "system" fn RustupUninstall(hInstall: MSIHANDLE) -> UINT {
    do_custom_action(hInstall, "RustupUninstall", rustup_uninstall)
}

fn rustup_prepare() -> Result<()> {
    //let path = ::rustup::utils::cargo_home()
    let path = try!(::std::env::var_os("USERPROFILE").map(|v| PathBuf::from(v).join(".rustup-test")).ok_or(()));
    let path_str = try!(path.to_str().ok_or(()));
    set_property("RustupInstallLocation", path_str)
}

fn rustup_install() -> Result<()> {
    // For deferred custom actions, all data must be passed through the `CustomActionData` property
    let custom_action_data = try!(get_property("CustomActionData"));
    // TODO: use rustup_utils::cargo_home() or pass through CustomActionData
    let path = try!(::std::env::var_os("USERPROFILE").map(|v| PathBuf::from(v).join(".rustup-test")).ok_or(()));
    let bin_path = path.join("bin");
    let rustup_path = bin_path.join("rustup.exe");
    let exe_installed = rustup_path.exists();
    log(&format!("Hello World from RustupInstall, confirming that rustup.exe has been installed: {}! CustomActionData: {}", exe_installed, custom_action_data));
    for tool in TOOLS {
        let ref tool_path = bin_path.join(&format!("{}.exe", tool));
        try!(::rustup::utils::hardlink_file(&rustup_path, tool_path).map_err(|_| ()))
    }
    // TODO: Install default toolchain and report progress to UI, but do not return Err
    //       when toolchain installation fails, otherwise MSI will try to rollback the
    //       whole installation which will leave hard links in place.
    //       Maybe show a warning instead.
    Err(())
}

fn rustup_uninstall() -> Result<()> {
    // For deferred custom actions, all data must be passed through the `CustomActionData` property
    let custom_action_data = try!(get_property("CustomActionData"));
    // TODO: use rustup_utils::cargo_home() or pass through CustomActionData
    let path = try!(::std::env::var_os("USERPROFILE").map(|v| PathBuf::from(v).join(".rustup-test")).ok_or(()));
    let exe_deleted = !path.join("bin").join("rustup.exe").exists();
    log(&format!("Hello World from RustupUninstall, confirming that rustup.exe has been deleted: {}! CustomActionData: {}", exe_deleted, custom_action_data));
    // TODO: Remove .cargo and .rustup
    ::rustup::utils::remove_dir("rustup-test", &path, &|_| {}).map_err(|_| ())
}

unsafe fn do_custom_action(hInstall: MSIHANDLE, name: &str, action: fn() -> Result<()>) -> UINT {
    let cname = CString::new(name).unwrap();
    let init_success = succeeded(WcaInitialize(hInstall, cname.as_ptr()));
     
    // See https://msdn.microsoft.com/en-us/library/windows/desktop/aa368072(v=vs.85).aspx for error codes
    if let Ok(_) = init_success.and_then(|_| action()) {
        WcaFinalize(ERROR_SUCCESS as i32)
    } else {
        WcaFinalize(ERROR_INSTALL_FAILURE as i32)
    }
}

fn succeeded(hr: HRESULT) -> Result<()> {
    if hr >= 0 {
        Ok(())
    } else {
        Err(())
    }
}

// wrapper for WcaGetProperty
fn get_property(name: &str) -> Result<String> {
    let encoded_name = to_wide_chars(name);
    let mut result_ptr = std::ptr::null_mut();
    try!(succeeded(unsafe { WcaGetProperty(encoded_name.as_ptr(), &mut result_ptr) }));
    let result = from_wide_ptr(result_ptr);
    unsafe { StrFree(result_ptr as LPVOID) };
    Ok(result)
}

// wrapper for WcaSetProperty
fn set_property(name: &str, value: &str) -> Result<()> {
    let encoded_name = to_wide_chars(name);
    let encoded_value = to_wide_chars(value);
    succeeded(unsafe { WcaSetProperty(encoded_name.as_ptr(), encoded_value.as_ptr()) })
}

fn log(message: &str) {
    let msg = CString::new(message).unwrap();
    unsafe { WcaLog(LOGMSG_STANDARD, msg.as_ptr()) }
}
fn from_wide_ptr(ptr: *const u16) -> String {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    unsafe {
        assert!(!ptr.is_null());
        let len = (0..std::isize::MAX).position(|i| *ptr.offset(i) == 0).unwrap();
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

fn to_wide_chars(s: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(s).encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>()
}

extern "system" {
    fn WcaInitialize(hInstall: MSIHANDLE, szCustomActionLogName: PCSTR) -> HRESULT;
    fn WcaFinalize(iReturnValue: HRESULT) -> UINT;
    fn WcaGetProperty(wzProperty: LPCWSTR, ppwzData: *mut LPWSTR) -> HRESULT; // see documentation for MsiGetProperty
    fn WcaSetProperty(wzPropertyName: LPCWSTR, wzPropertyValue: LPCWSTR) -> HRESULT;
    fn StrFree(p: LPVOID) -> HRESULT;
}

extern "cdecl" {
    fn WcaLog(llv: i32, fmt: PCSTR);
}