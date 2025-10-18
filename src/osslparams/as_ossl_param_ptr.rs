use super::{CONST_OSSL_PARAM, OSSL_PARAM};

/// Treats both `&[OSSL_PARAM]` and `&[CONST_OSSL_PARAM]` as a slice of
/// `OSSL_PARAM` at the FFI boundary.
///
/// # Motivation
///
/// Sometime we have two distinct Rust structs for the same C struct:
/// `OSSL_PARAM` and `CONST_OSSL_PARAM`.
/// They are layout-identical but **different Rust types**, so a function that takes
/// `&[OSSL_PARAM]` cannot be called with `&[CONST_OSSL_PARAM]`, and vice versa.
///
/// This trait provides a tiny, zero-cost abstraction to accept **either**
/// slice type and yield a `*const OSSL_PARAM` suitable for calling C
/// callbacks/functions.
///
/// # Safety
///
/// Implementations must only convert between slice types that are
/// **layout-identical C representations** (`#[repr(C)]`) with the same size
/// and alignment. This crate implements the trait **only** for:
///
/// - `[CONST_OSSL_PARAM]`
/// - `[OSSL_PARAM]`
///
/// If you fork/extend this, do not implement it for unrelated types.
///
/// # Guarantees
///
/// - **Zero cost:** calling `as_ossl_param_ptr()` is just a pointer cast.
/// - **Non-owning:** the trait never takes ownership; it only provides a
///   view into an existing slice.
///
pub trait AsOsslParamPtr {
    /// Returns a `*const OSSL_PARAM` suitable for passing to C/FFI.
    ///
    /// The pointer is valid for the lifetime of `&self` and has the same
    /// provenance as the original slice.
    /// It cannot be `NULL`, and should always be terminated by the
    /// `OSSL_PARAM::END` item.
    fn as_ossl_param_ptr(&self) -> *const OSSL_PARAM;
}

impl AsOsslParamPtr for [CONST_OSSL_PARAM] {
    fn as_ossl_param_ptr(&self) -> *const OSSL_PARAM {
        self.as_ptr() as *const OSSL_PARAM
    }
}
impl AsOsslParamPtr for [OSSL_PARAM] {
    fn as_ossl_param_ptr(&self) -> *const OSSL_PARAM {
        self.as_ptr() as *const OSSL_PARAM
    }
}
impl<const N: usize> AsOsslParamPtr for [CONST_OSSL_PARAM; N] {
    fn as_ossl_param_ptr(&self) -> *const OSSL_PARAM {
        self.as_ptr() as *const OSSL_PARAM
    }
}
impl<const N: usize> AsOsslParamPtr for [OSSL_PARAM; N] {
    fn as_ossl_param_ptr(&self) -> *const OSSL_PARAM {
        self.as_ptr()
    }
}

/// Build-time sanity checks that both structs are layout-identical.
#[allow(dead_code)]
const _: () = {
    use core::mem::{align_of, size_of};
    {
        let _ = [(); size_of::<OSSL_PARAM>()];
        let _ = [(); size_of::<CONST_OSSL_PARAM>()];
        assert!(size_of::<OSSL_PARAM>() == size_of::<CONST_OSSL_PARAM>());
        assert!(align_of::<OSSL_PARAM>() == align_of::<CONST_OSSL_PARAM>());
    }
};
