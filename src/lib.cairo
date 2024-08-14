pub mod sha1;
mod utils;
mod tests;

pub use sha1::SHA1Context as SHA1Context;
pub use sha1::sha1_hash as sha1_hash;
pub use sha1::sha1_context_as_u256 as sha1_context_as_u256;
pub use sha1::sha1_context_as_bytes as sha1_context_as_bytes;
pub use sha1::sha1_context_as_array as sha1_context_as_array;
