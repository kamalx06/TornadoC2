//! Agent feature modules.
//!
//! Currently only `shaping` — the C2 profile response template
//! system. Future features that are pure data transforms and do
//! not touch the wire transport belong here.

pub mod shaping;

pub use shaping::{
    decode_payload, encode_payload, shape_unwrap, shape_wrap,
    validate_shaping_spec, Placement, ShapeSpec, ShapingError,
    ShapingSpec,
};