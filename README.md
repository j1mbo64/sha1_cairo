# sha1_cairo

## About

Cairo 1.0 library for hashing with SHA-1.

## Usage

In your Scarb.toml :
```toml
[dependencies]
sha1 = { git = "https://github.com/j1mbo64/sha1_cairo.git" }
```

In a .cairo file :
```rust
    // Import the module
    use sha1::{SHA1Context, sha1_hash, sha1_context_as_array};

    fn hash_something() {

        // Message to hash
        let message: ByteArray = "My string to hash";

        // Hash and return the hashed message in a struct
        let context: SHA1Context = sha1_hash(@message);

        // Get your hash in a ByteArray
        let hash_bytes: ByteArray = context.into();

        // Get your hash in an u256
        let hash_u256: u256 = sha1_hash(@message).into();

        // Get your hash via function (_as_bytes and _as_u256 also working)
        let hash_array: Array<u32> = sha1_context_as_array(@context);
```

## Contributing

Tips for gas optimization are welcome.

### Rules for submitting a PR :
  - Follow [Conventionnal Commits](https://www.conventionalcommits.org)
  - Ensure all tests pass with `scarb test`
  - Format the code with `scarb fmt`
