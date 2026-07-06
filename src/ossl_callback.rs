use super::OurError;
use crate::bindings::{c_int, c_void, OSSL_CALLBACK};
use crate::osslparams::{AsOsslParamPtr, OSSL_PARAM};
use anyhow::{anyhow, Ok};

type InnerCB = unsafe extern "C" fn(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int;

pub struct OSSLCallback {
    cb_fn: InnerCB,
    args: *mut c_void,
}

impl OSSLCallback {
    pub fn try_new(cb: OSSL_CALLBACK, args: *mut c_void) -> Result<Self, OurError> {
        let cb_fn: InnerCB = if let Some(cb_fn) = cb {
            cb_fn
        } else {
            return Err(anyhow!("Passed NULL callback"));
        };

        Ok(Self { cb_fn, args })
    }

    /// Low-level entry point mirroring the C ABI.
    ///
    /// # Safety
    /// - `params` must satisfy the target OpenSSL callback's contract (may be NULL
    ///   if the specific callback allows it).
    /// - `args` is forwarded as provided by OpenSSL; the callback may read/write
    ///   through it according to its own rules.
    /// - All aliasing/lifetime/initialization requirements of the callback must hold.
    pub unsafe fn call_raw(&self, params: *const OSSL_PARAM) -> c_int {
        let cb_fn = self.cb_fn;
        unsafe { cb_fn(params, self.args) }
    }

    /// Safe convenience: pass a slice of params (non-null, well-formed).
    pub fn call<P: ?Sized + AsOsslParamPtr>(&self, params: &P) -> c_int {
        // Safe for callers because &[T] guarantees non-null pointer + valid len.
        unsafe { self.call_raw(params.as_ossl_param_ptr()) }
    }
}
