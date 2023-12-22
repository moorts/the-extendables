use pyo3::prelude::*;
use crate::attack::*;
use crate::hash::md5::*;

#[pyfunction]
fn length_extend_md5(base_digest: String, base_len: usize, extension: String, base: Option<String>) -> (String, String) {
    let base_bytes = base.map(|s| {
        hex::decode(s).expect("Invalid hex data for base")
    }).unwrap_or(b"\x00".repeat(base_len));

    let extension_bytes = hex::decode(extension).expect("Invalid hex data for extension");

    MD5::extend_bytes(base_bytes, &base_digest, extension_bytes)
}

#[pymodule]
fn extendables(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(length_extend_md5, m)?)?;

    Ok(())
}
