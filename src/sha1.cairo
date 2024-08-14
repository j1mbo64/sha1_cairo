use core::dict::Felt252Dict;
use sha1::utils::{
    POW_2_32, POW_2_8, get_pow_2, bytes_to_u32, u32_leftrotate, u32_mod_add, u32_mod_add_5,
};

const BLOCK_SIZE: u32 = 64;
const BLOCK_SIZE_WO_LEN: u32 = 56;

#[derive(Drop, Clone, Copy)]
pub struct SHA1Context {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

pub impl SHA1ContextIntoU256 of Into<SHA1Context, u256> {
    fn into(self: SHA1Context) -> u256 {
        sha1_context_as_u256(@self)
    }
}

pub impl SHA1ContextIntoBytes of Into<SHA1Context, ByteArray> {
    fn into(self: SHA1Context) -> ByteArray {
        sha1_context_as_bytes(@self)
    }
}

pub impl SHA1ContextIntoArray of Into<SHA1Context, Array<u32>> {
    fn into(self: SHA1Context) -> Array<u32> {
        sha1_context_as_array(@self)
    }
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (z & (x | y))
}

fn w(x: u8, ref block: Felt252Dict<u32>) -> u32 {
    let a: felt252 = (x - 3 & 0x0F).into();
    let b: felt252 = (x - 8 & 0x0F).into();
    let c: felt252 = (x - 14 & 0x0F).into();
    let d: felt252 = (x & 0x0F).into();
    let temp = block[a] ^ block[b] ^ block[c] ^ block[d];
    block.insert(d, u32_leftrotate(temp, 1));
    block[d]
}

fn r0(h0: u32, ref h1: u32, h2: u32, h3: u32, ref h4: u32, x: u32) {
    h4 = u32_mod_add_5(h4, u32_leftrotate(h0, 5), f(h1, h2, h3), 0x5A827999, x);
    h1 = u32_leftrotate(h1, 30);
}

fn r1(h0: u32, ref h1: u32, h2: u32, h3: u32, ref h4: u32, x: u32) {
    h4 = u32_mod_add_5(h4, u32_leftrotate(h0, 5), g(h1, h2, h3), 0x6ED9EBA1, x);
    h1 = u32_leftrotate(h1, 30);
}

fn r2(h0: u32, ref h1: u32, h2: u32, h3: u32, ref h4: u32, x: u32) {
    h4 = u32_mod_add_5(h4, u32_leftrotate(h0, 5), h(h1, h2, h3), 0x8F1BBCDC, x);
    h1 = u32_leftrotate(h1, 30);
}

fn r3(h0: u32, ref h1: u32, h2: u32, h3: u32, ref h4: u32, x: u32) {
    h4 = u32_mod_add_5(h4, u32_leftrotate(h0, 5), g(h1, h2, h3), 0xCA62C1D6, x);
    h1 = u32_leftrotate(h1, 30);
}

// SHA-1 compression function
fn sha1_process_block(ref ctx: SHA1Context, ref block: Felt252Dict<u32>) {
    let mut h0: u32 = ctx.h0;
    let mut h1: u32 = ctx.h1;
    let mut h2: u32 = ctx.h2;
    let mut h3: u32 = ctx.h3;
    let mut h4: u32 = ctx.h4;

    // Round 0
    r0(h0, ref h1, h2, h3, ref h4, block[0]);
    r0(h4, ref h0, h1, h2, ref h3, block[1]);
    r0(h3, ref h4, h0, h1, ref h2, block[2]);
    r0(h2, ref h3, h4, h0, ref h1, block[3]);
    r0(h1, ref h2, h3, h4, ref h0, block[4]);
    r0(h0, ref h1, h2, h3, ref h4, block[5]);
    r0(h4, ref h0, h1, h2, ref h3, block[6]);
    r0(h3, ref h4, h0, h1, ref h2, block[7]);
    r0(h2, ref h3, h4, h0, ref h1, block[8]);
    r0(h1, ref h2, h3, h4, ref h0, block[9]);
    r0(h0, ref h1, h2, h3, ref h4, block[10]);
    r0(h4, ref h0, h1, h2, ref h3, block[11]);
    r0(h3, ref h4, h0, h1, ref h2, block[12]);
    r0(h2, ref h3, h4, h0, ref h1, block[13]);
    r0(h1, ref h2, h3, h4, ref h0, block[14]);
    r0(h0, ref h1, h2, h3, ref h4, block[15]);
    r0(h4, ref h0, h1, h2, ref h3, w(16, ref block));
    r0(h3, ref h4, h0, h1, ref h2, w(17, ref block));
    r0(h2, ref h3, h4, h0, ref h1, w(18, ref block));
    r0(h1, ref h2, h3, h4, ref h0, w(19, ref block));

    // Round 1
    r1(h0, ref h1, h2, h3, ref h4, w(20, ref block));
    r1(h4, ref h0, h1, h2, ref h3, w(21, ref block));
    r1(h3, ref h4, h0, h1, ref h2, w(22, ref block));
    r1(h2, ref h3, h4, h0, ref h1, w(23, ref block));
    r1(h1, ref h2, h3, h4, ref h0, w(24, ref block));
    r1(h0, ref h1, h2, h3, ref h4, w(25, ref block));
    r1(h4, ref h0, h1, h2, ref h3, w(26, ref block));
    r1(h3, ref h4, h0, h1, ref h2, w(27, ref block));
    r1(h2, ref h3, h4, h0, ref h1, w(28, ref block));
    r1(h1, ref h2, h3, h4, ref h0, w(29, ref block));
    r1(h0, ref h1, h2, h3, ref h4, w(30, ref block));
    r1(h4, ref h0, h1, h2, ref h3, w(31, ref block));
    r1(h3, ref h4, h0, h1, ref h2, w(32, ref block));
    r1(h2, ref h3, h4, h0, ref h1, w(33, ref block));
    r1(h1, ref h2, h3, h4, ref h0, w(34, ref block));
    r1(h0, ref h1, h2, h3, ref h4, w(35, ref block));
    r1(h4, ref h0, h1, h2, ref h3, w(36, ref block));
    r1(h3, ref h4, h0, h1, ref h2, w(37, ref block));
    r1(h2, ref h3, h4, h0, ref h1, w(38, ref block));
    r1(h1, ref h2, h3, h4, ref h0, w(39, ref block));

    // Round 2
    r2(h0, ref h1, h2, h3, ref h4, w(40, ref block));
    r2(h4, ref h0, h1, h2, ref h3, w(41, ref block));
    r2(h3, ref h4, h0, h1, ref h2, w(42, ref block));
    r2(h2, ref h3, h4, h0, ref h1, w(43, ref block));
    r2(h1, ref h2, h3, h4, ref h0, w(44, ref block));
    r2(h0, ref h1, h2, h3, ref h4, w(45, ref block));
    r2(h4, ref h0, h1, h2, ref h3, w(46, ref block));
    r2(h3, ref h4, h0, h1, ref h2, w(47, ref block));
    r2(h2, ref h3, h4, h0, ref h1, w(48, ref block));
    r2(h1, ref h2, h3, h4, ref h0, w(49, ref block));
    r2(h0, ref h1, h2, h3, ref h4, w(50, ref block));
    r2(h4, ref h0, h1, h2, ref h3, w(51, ref block));
    r2(h3, ref h4, h0, h1, ref h2, w(52, ref block));
    r2(h2, ref h3, h4, h0, ref h1, w(53, ref block));
    r2(h1, ref h2, h3, h4, ref h0, w(54, ref block));
    r2(h0, ref h1, h2, h3, ref h4, w(55, ref block));
    r2(h4, ref h0, h1, h2, ref h3, w(56, ref block));
    r2(h3, ref h4, h0, h1, ref h2, w(57, ref block));
    r2(h2, ref h3, h4, h0, ref h1, w(58, ref block));
    r2(h1, ref h2, h3, h4, ref h0, w(59, ref block));

    // Round 3
    r3(h0, ref h1, h2, h3, ref h4, w(60, ref block));
    r3(h4, ref h0, h1, h2, ref h3, w(61, ref block));
    r3(h3, ref h4, h0, h1, ref h2, w(62, ref block));
    r3(h2, ref h3, h4, h0, ref h1, w(63, ref block));
    r3(h1, ref h2, h3, h4, ref h0, w(64, ref block));
    r3(h0, ref h1, h2, h3, ref h4, w(65, ref block));
    r3(h4, ref h0, h1, h2, ref h3, w(66, ref block));
    r3(h3, ref h4, h0, h1, ref h2, w(67, ref block));
    r3(h2, ref h3, h4, h0, ref h1, w(68, ref block));
    r3(h1, ref h2, h3, h4, ref h0, w(69, ref block));
    r3(h0, ref h1, h2, h3, ref h4, w(70, ref block));
    r3(h4, ref h0, h1, h2, ref h3, w(71, ref block));
    r3(h3, ref h4, h0, h1, ref h2, w(72, ref block));
    r3(h2, ref h3, h4, h0, ref h1, w(73, ref block));
    r3(h1, ref h2, h3, h4, ref h0, w(74, ref block));
    r3(h0, ref h1, h2, h3, ref h4, w(75, ref block));
    r3(h4, ref h0, h1, h2, ref h3, w(76, ref block));
    r3(h3, ref h4, h0, h1, ref h2, w(77, ref block));
    r3(h2, ref h3, h4, h0, ref h1, w(78, ref block));
    r3(h1, ref h2, h3, h4, ref h0, w(79, ref block));

    // Combine results
    ctx.h0 = u32_mod_add(ctx.h0, h0);
    ctx.h1 = u32_mod_add(ctx.h1, h1);
    ctx.h2 = u32_mod_add(ctx.h2, h2);
    ctx.h3 = u32_mod_add(ctx.h3, h3);
    ctx.h4 = u32_mod_add(ctx.h4, h4);
}

// Add SHA-1 padding to the input.
fn sha1_padding(ref data: ByteArray) {
    // Get message len in bits
    let mut data_bits_len: felt252 = data.len().into() * 8;

    // Append padding bit
    data.append_byte(0x80);

    // Add padding zeroes
    let mut len = data.len();
    while (len % BLOCK_SIZE != BLOCK_SIZE_WO_LEN) {
        data.append_byte(0);
        len += 1;
    };

    // Add message len in big-endian
    data.append_word(data_bits_len, 8);
}

// Update the context by processing the whole data.
fn sha1_update(ref ctx: SHA1Context, data: ByteArray) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let len = data.len();
    let mut block: Felt252Dict<u32> = Default::default();
    while (i != len) {
        j = 0;
        let mut k: usize = 0;
        while (j < BLOCK_SIZE) {
            block.insert(k.into(), bytes_to_u32(@data, i));
            j += 4;
            i += 4;
            k += 1;
        };
        sha1_process_block(ref ctx, ref block);
    };
}

// Init context with SHA-1 constant.
fn sha1_init() -> SHA1Context {
    SHA1Context { h0: 0x67452301, h1: 0xefcdab89, h2: 0x98badcfe, h3: 0x10325476, h4: 0xc3d2e1f0, }
}

// Return hash as bytes.
pub fn sha1_context_as_bytes(ctx: @SHA1Context) -> ByteArray {
    let mut result: ByteArray = Default::default();
    result.append_word((*ctx.h0).into(), 4);
    result.append_word((*ctx.h1).into(), 4);
    result.append_word((*ctx.h2).into(), 4);
    result.append_word((*ctx.h3).into(), 4);
    result.append_word((*ctx.h4).into(), 4);
    result
}

// Return hash as u32 array.
pub fn sha1_context_as_array(ctx: @SHA1Context) -> Array<u32> {
    let mut result: Array<u32> = ArrayTrait::new();
    result.append(*ctx.h0);
    result.append(*ctx.h1);
    result.append(*ctx.h2);
    result.append(*ctx.h3);
    result.append(*ctx.h4);
    result
}

// Return hash as u256.
pub fn sha1_context_as_u256(ctx: @SHA1Context) -> u256 {
    let mut result: u256 = 0;
    result += (*ctx.h0).into();
    result *= POW_2_32.into();
    result += (*ctx.h1).into();
    result *= POW_2_32.into();
    result += (*ctx.h2).into();
    result *= POW_2_32.into();
    result += (*ctx.h3).into();
    result *= POW_2_32.into();
    result += (*ctx.h4).into();
    result
}

// SHA-1 hash function entrypoint.
pub fn sha1_hash(data: @ByteArray) -> SHA1Context {
    let mut data = data.clone();
    let mut ctx = sha1_init();
    sha1_padding(ref data);
    sha1_update(ref ctx, data);
    ctx
}
