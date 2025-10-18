//! This submodule provides functionality for handling UTF-8 encoded strings using raw pointers.
//!
//! The `utf8_ptr` submodule focuses on dealing with UTF-8 strings stored in memory that are accessed through raw pointers.
//! This is particularly useful when working with OpenSSL or other libraries that require efficient manipulation
//! of strings via pointers.
//!

use std::ffi::{c_char, CStr};

use crate::bindings::{OSSL_PARAM, OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING};
use crate::osslparams::{
    new_null_param, setter_type_err_string, KeyType, OSSLParam, OSSLParamData, OSSLParamError,
    OSSLParamGetter, OSSLParamSetter, TypedOSSLParamData, Utf8PtrData, Utf8StringData,
};

impl OSSLParamData for Utf8PtrData<'_> {
    fn new_null(key: &KeyType) -> Self
    where
        Self: Sized,
    {
        new_null_param!(Utf8PtrData, OSSL_PARAM_UTF8_PTR, key)
    }
}

// TODO: don't leak the buffer
// TODO, maybe: let the user specify how big the buffer should be
impl OSSLParamData for Utf8StringData<'_> {
    fn new_null(key: &KeyType) -> Self
    where
        Self: Sized,
    {
        let param_data = new_null_param!(Utf8StringData, OSSL_PARAM_UTF8_STRING, key);
        let bufsize = 1024;
        let buf = Box::into_raw(vec![0u8; bufsize].into_boxed_slice());
        param_data.param.data = buf.cast::<std::ffi::c_void>();
        param_data.param.data_size = bufsize;
        param_data
    }
}

// For these, we can't use impl_setter!, because that macro only lets you specify one enum variant
// per Rust type.
impl OSSLParamSetter<*const CStr> for OSSLParam<'_> {
    fn set_inner(&mut self, value: *const CStr) -> Result<(), OSSLParamError> {
        if let OSSLParam::Utf8Ptr(d) = self {
            d.set(value)
        } else if let OSSLParam::Utf8String(d) = self {
            d.set(value)
        } else {
            Err(setter_type_err_string!(self, value))
        }
    }
}

impl OSSLParamSetter<&'static CStr> for OSSLParam<'_> {
    fn set_inner(&mut self, value: &'static CStr) -> Result<(), OSSLParamError> {
        if let OSSLParam::Utf8Ptr(d) = self {
            d.set(value)
        } else if let OSSLParam::Utf8String(d) = self {
            d.set(value)
        } else {
            Err(setter_type_err_string!(self, value))
        }
    }
}

impl<'a> OSSLParamGetter<&'a CStr> for OSSLParam<'_> {
    fn get_inner(&self) -> Option<&'a CStr> {
        if let OSSLParam::Utf8Ptr(d) = self {
            let ptr = d.param.data as *const *mut c_char;
            if ptr.is_null() {
                return None;
            }
            let v = unsafe { CStr::from_ptr(*ptr) };
            Some(v)
        } else if let OSSLParam::Utf8String(d) = self {
            let ptr = d.param.data as *const c_char;
            if ptr.is_null() {
                return None;
            }
            let v = unsafe { CStr::from_ptr(ptr) };
            Some(v)
        } else {
            None
        }
    }
}

impl TypedOSSLParamData<*const CStr> for Utf8PtrData<'_> {
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // we cannot mark the method unsafe because of the trait definition
    fn set(&mut self, value: *const CStr) -> Result<(), OSSLParamError> {
        let p = &mut *self.param;
        if p.data.is_null() {
            p.return_size = 0;
        } else {
            match unsafe { value.as_ref() } {
                Some(cstr) => {
                    p.return_size = cstr.to_bytes().len();
                    unsafe { *p.data.cast::<*const c_char>() = cstr.as_ptr() };
                }
                None => return Err("couldn't get &CStr from *const CStr".to_string()),
            }
        }
        Ok(())
    }
}

impl TypedOSSLParamData<*const CStr> for Utf8StringData<'_> {
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // we cannot mark the method unsafe because of the trait definition
    fn set(&mut self, value: *const CStr) -> Result<(), OSSLParamError> {
        let p = &mut *self.param;
        p.return_size = 0;
        if value.is_null() {
            return Err("value was null".to_string());
        }
        // Set the inner contents of the param
        match unsafe { value.as_ref() } {
            Some(cstr) => {
                let len = cstr.to_bytes().len();
                p.return_size = len;
                if !p.data.is_null() {
                    if p.data_size < len {
                        return Err(
                            "p.data_size in param is too small to fit the string".to_string()
                        );
                    }
                    // copy the string, with the terminating null byte if there's room for it
                    let total_len = if p.data_size > len { len + 1 } else { len };
                    unsafe { std::ptr::copy(cstr.as_ptr(), p.data.cast::<c_char>(), total_len) };
                }
                Ok(())
            }
            None => Err("couldn't get &CStr from *const CStr".to_string()),
        }
    }
}

/* We don't need to `impl TypedOSSLParamData<&'static CStr> for Utf8PtrData` separately,
 * because Rust can implicitly convert a &'static CStr reference to a raw *const CStr pointer.
 * However, if we want to add an explicit non-static lifetime to an impl of it over CStr, I
 * think things would get more complicated.
*/

/// Converts a raw pointer (`*mut ossl_param_st`) into an `OSSLParam` enum.
impl TryFrom<*mut OSSL_PARAM> for Utf8PtrData<'_> {
    type Error = OSSLParamError;

    /// The `try_from` function converts a raw pointer to an OpenSSL parameter (`ossl_param_st`)
    /// into an appropriate variant of the `OSSLParam` enum. It performs safety checks to ensure
    /// that the pointer is not null and that the `data_type` of the parameter matches one of the
    /// expected OpenSSL parameter types.
    ///
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // we cannot mark the method unsafe because of the TryFrom trait
    fn try_from(param: *mut OSSL_PARAM) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) => {
                if param.data_type == OSSL_PARAM_UTF8_PTR {
                    Ok(Utf8PtrData { param })
                } else {
                    Err("tried to make Utf8PtrData from OSSL_PARAM with data_type != OSSL_PARAM_UTF8_PTR".to_string())
                }
            }
            None => Err("tried to make Utf8PtrData from null pointer".to_string()),
        }
    }
}

impl TryFrom<*mut OSSL_PARAM> for Utf8StringData<'_> {
    type Error = OSSLParamError;

    /// Converts a raw OpenSSL parameter (`OSSL_PARAM`) to an `OSSLParam` enum variant (`Utf8StringData`).
    /// Ensures the pointer is not null and that the `data_type` matches an expected OpenSSL parameter type.
    /// # Examples
    ///
    /// ```rust
    /// use openssl_provider_forge::osslparams::OSSLParam;
    /// use openssl_provider_forge::bindings::OSSL_PARAM;
    ///
    /// // Assume we have a raw pointer `param_ptr` of type `*mut OSSL_PARAM`.
    /// // For demonstration, we are using a null pointer here:
    /// let param_ptr: *mut OSSL_PARAM = std::ptr::null_mut();
    ///
    /// // Attempt to convert the pointer into an `OSSLParam`.
    /// match OSSLParam::try_from(param_ptr) {
    ///     Ok(param) => println!("Successfully converted to OSSLParam."),
    ///     Err(e) => println!("Failed to convert: {:?}", e),
    /// }
    /// ```
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // we cannot mark the method unsafe because of the TryFrom trait
    fn try_from(param: *mut OSSL_PARAM) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) => {
                if param.data_type == OSSL_PARAM_UTF8_STRING {
                    Ok(Utf8StringData { param })
                } else {
                    Err("tried to make Utf8StringData from OSSL_PARAM with data_type != OSSL_PARAM_UTF8_STRING".to_string())
                }
            }
            None => Err("tried to make Utf8StringData from null pointer".to_string()),
        }
    }
}
