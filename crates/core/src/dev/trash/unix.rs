//! Recycle bin on macOS / Linux is not implemented in this build.
//!
//! Returning `not_implemented` keeps the permanent-deletion choice explicit.

use std::path::Path;

use crate::{Error, Result};

pub(super) fn trash_path(_path: &Path) -> Result<()> {
    Err(Error::not_implemented("dev-trash"))
}
