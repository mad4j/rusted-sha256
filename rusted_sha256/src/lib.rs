#![no_std]

use arrayref::array_ref;

const STATE_SIZE: usize = 8;
const BLOCK_SIZE: usize = 64;

// Initialize hash values:
// (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// h0 := 0x6a09e667
// h1 := 0xbb67ae85
// h2 := 0x3c6ef372
// h3 := 0xa54ff53a
// h4 := 0x510e527f
// h5 := 0x9b05688c
// h6 := 0x1f83d9ab
// h7 := 0x5be0cd19
const H: [u32; STATE_SIZE] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// Initialize array of round constants:
// (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
// k[0..63] :=
//    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
//    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
//    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
//    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
//    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
//    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
//    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
//    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
const K: [u32; BLOCK_SIZE] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256 {
    state: [u32; STATE_SIZE],
    computed_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: H,
            computed_bytes: 0,
        }
    }

    pub fn with_state(state: [u32; STATE_SIZE]) -> Self {
        Self {
            state,
            computed_bytes: 0,
        }
    }

    pub fn update(&mut self, data: &[u8; BLOCK_SIZE]) {

        // create a 64-entry message schedule array w[0..63] of 32-bit words
        let mut w = [0; BLOCK_SIZE];

        // copy chunk into first 16 words w[0..15] of the message schedule array
        for i in 0..16 {
            let k = i * 4;
            w[i] = u32::from_be_bytes([data[k], data[k + 1], data[k + 2], data[k + 3]]);
        }

        // Extend the first 16 words into the remaining 48 words w[16..63] of the message
        // schedule array:
        // for i from 16 to 63
        //     s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
        //     s1 := (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
        //     w[i] := w[i-16] + s0 + w[i-7] + s1
        for i in 16..BLOCK_SIZE {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables to current hash value:
        // a := h0
        // b := h1
        // c := h2
        // d := h3
        // e := h4
        // f := h5
        // g := h6
        // h := h7
        let mut h = self.state;
        //let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);

        // Compression function main loop:
        // for i from 0 to 63
        //     S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        //     ch := (e and f) xor ((not e) and g)
        //     temp1 := h + S1 + ch + k[i] + w[i]
        //     S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        //     maj := (a and b) xor (a and c) xor (b and c)
        //     temp2 := S0 + maj
        // h := g
        // g := f
        // f := e
        // e := d + temp1
        // d := c
        // c := b
        // b := a
        // a := temp1 + temp2
        for i in 0..BLOCK_SIZE {
            let ch = (h[4] & h[5]) ^ (!h[4] & h[6]);
            let ma = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
            let t0 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t1 = s0.wrapping_add(ma);

            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(t0);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = t0.wrapping_add(t1);
        }

        // Add the compressed chunk to the current hash value:
        // h0 := h0 + a
        // h1 := h1 + b
        // h2 := h2 + c
        // h3 := h3 + d
        // h4 := h4 + e
        // h5 := h5 + f
        // h6 := h6 + g
        // h7 := h7 + h
        for i in 0..STATE_SIZE {
            self.state[i] = self.state[i].wrapping_add(h[i]);
        }

        self.computed_bytes += BLOCK_SIZE as u64;
    }

    pub fn finalize(&mut self, data: &[u8]) -> [u8; 32] {

        let mut offset = 0;
        for _ in 0 .. data.len() / BLOCK_SIZE {
            self.update(array_ref!(data, offset, BLOCK_SIZE));
            offset += BLOCK_SIZE;
        }

        let residual_length = data.len() - offset;
        let message_length = 8 * (self.computed_bytes + residual_length as u64);

        // Pre-processing (Padding):
        // begin with the original message of length L bits
        // append a single '1' bit
        // append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
        // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
        // such that the bits in the message are L 1 00..<K 0's>..00 <L as 64 bit integer> = k*512 total bits

        let mut last_block = [0u8; BLOCK_SIZE];
        last_block[..residual_length].copy_from_slice(&data[offset..]);
        last_block[residual_length] = 0x80;

        if residual_length > (BLOCK_SIZE - 8 - 1) {
            self.update(&last_block);
            last_block = [0u8; BLOCK_SIZE];    
        } 

        last_block[BLOCK_SIZE-8..].copy_from_slice(&message_length.to_be_bytes());

        self.update(&last_block);

        for h in self.state.iter_mut() {
            *h = h.to_be();
        }

        // Produce the final hash value (big-endian):
        // digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
        unsafe { *(self.state.as_ptr() as *const [u8; 32]) }
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        Self::new().finalize(&data)
    }
}
