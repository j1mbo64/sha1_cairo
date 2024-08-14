// All test hashes were calculated using the SHA-1 function from the linux Openssl binary.
#[cfg(test)]
mod tests {
    use sha1::sha1::{SHA1Context, sha1_hash, sha1_context_as_u256};

    #[test]
    fn sha1_test_empty() {
        let message: ByteArray = "";
        let mut ctx: SHA1Context = sha1_hash(@message);
        let hash = sha1_context_as_u256(@ctx);
        let expected_hash: u256 = 0xda39a3ee5e6b4b0d3255bfef95601890afd80709;
        assert_eq!(hash, expected_hash, "Bad SHA-1 Hash");
    }

    #[test]
    fn sha1_test_1() {
        let message: ByteArray = "toto";
        let mut ctx: SHA1Context = sha1_hash(@message);
        let hash = sha1_context_as_u256(@ctx);
        let expected_hash: u256 = 0x0b9c2625dc21ef05f6ad4ddf47c5f203837aa32c;
        assert_eq!(hash, expected_hash, "Bad SHA-1 Hash");
    }

    #[test]
    fn sha1_test_2() {
        let message: ByteArray = "Hello World !\n";
        let mut ctx: SHA1Context = sha1_hash(@message);
        let hash = sha1_context_as_u256(@ctx);
        let expected_hash: u256 = 0x033d83c0c723806f486e047448bbbadb35786208;
        assert_eq!(hash, expected_hash, "Bad SHA-1 Hash");
    }

    #[test]
    fn sha1_test_3() {
        let message: ByteArray = "1234567890123456789012345678901234567890123456789012345678901234";
        let mut ctx: SHA1Context = sha1_hash(@message);
        let hash = sha1_context_as_u256(@ctx);
        let expected_hash: u256 = 0xc71490fc24aa3d19e11282da77032dd9cdb33103;
        assert_eq!(hash, expected_hash, "Bad SHA-1 Hash");
    }
    #[test]
    fn sha1_test_4() {
        let message: ByteArray =
            "utvyHvg5DaRCS09uTHeRb5LG9N2I2AJ1mC7g9Lt6U1iX050ZY4381GBpv76wIzHrae4k85HOX8bQkih15dnhI0qZ64";
        let mut ctx: SHA1Context = sha1_hash(@message);
        let hash = sha1_context_as_u256(@ctx);
        let expected_hash: u256 = 0xfd63715a4338241bffa0d13d7975e36bd23df0b5;
        assert_eq!(hash, expected_hash, "Bad SHA-1 Hash");
    }

    #[test]
    fn sha1_test_5() {
        let message: ByteArray =
            "6884QYmtkLS4IwK5F0xDYZB0wALHxWL8ycaIcQPdJtITlqdm8Lod6737DDx53wBh10u0vLs1uvMO97njQd6w4OIBvykD8A80R7U1Lcy2Dvvpc7Iev1hom4isr0yth43aL8V8V4i2JB9DuOmHpmG4W5O7CJzBAUJmn2FmlB7Wvdl454FH98t0CaAn5DUQ8w8UVuKkN2FX21c2JN4H0vz77d26I3L01kndyEP1hrXU7TkQpG8NY60765N38jf70VokvUz6q3eYT2FlU8ez2WvoL1P8059n3885wUfxkS2J67skXnS5OKO7LZSS43i1uRoB6T0pAoRs2C6tO30A4lst7iCrED9k0Q097YhlBMis7U33xda5kGzMV30HM2XZ7dOpR1Ze02hGygEAph4Kl34SD1gFCGUO4vxShy34Ktdz08vY8w5BPe46qE0kY5Wwdipv36uuGn75kq66TSR63s51c6n1135UNNlbH5v70n9h9S6D4D7E1h50";
        let mut ctx: SHA1Context = sha1_hash(@message);
        let hash = sha1_context_as_u256(@ctx);
        let expected_hash: u256 = 0x5a920b08ad97092e9336698b52a372ac8760c199;
        assert_eq!(hash, expected_hash, "Bad SHA-1 Hash");
    }
}
