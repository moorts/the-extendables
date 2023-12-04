use hex::FromHex;

pub struct MD5 {
    state: [u32; 4],
}

impl MD5 {
    const S: [u32; 64] = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ];

    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        }
    }

    pub fn from(state: [u32; 4]) -> Self {
        Self {
            state
        }
    }

    pub fn from_str(state: &str) -> Self {
        Self {
            state: Self::digest_to_state(state)
        }
    }
    
    pub fn pad(mut msg: Vec<u8>) -> Vec<u8> {
        let n = msg.len() * 8;


        if n > 0 && n % 512 == 0 {
            return msg;
        }

        let mut len_padding = 512 - (n % 512);

        if len_padding < 65 {
            // Add new block
            len_padding += 512;
            msg.reserve_exact(len_padding);
        } else {
            msg.reserve_exact(len_padding);
        }

        msg.push(0b10000000);

        let num_zeros = len_padding - 64 - 8;
        let num_zeros = num_zeros / 8;

        for _ in 0..num_zeros {
            msg.push(0);
        }

        msg.extend((n as u64).to_le_bytes());
        msg
    }

    pub fn hash_chunk(&mut self, chunk: &[u32]) -> [u32; 4] {
        assert_eq!(chunk.len(), 16);

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        for i in 0..64 {
            let (f, g) = if i <= 15 {
                ((b & c) | ((!b) & d), i)
            } else if i <= 31 {
                ((d & b) | ((!d) & c), (5 * i + 1) % 16)
            } else if i <= 47 {
                (b ^ c ^ d, (3*i + 5) % 16)
            } else {
                (c ^ (b | (!d)), (7*i) % 16)
            };
            let f = f.wrapping_add(a.wrapping_add(Self::K[i].wrapping_add(chunk[g])));
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(Self::S[i]));
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);

        self.state
    }

    pub fn as_u32_slice(v: &[u8]) -> &[u32] {
        assert!(v.len() % std::mem::size_of::<u32>() == 0);
        // SAFETY: This is safe since any slice is contiguous and we assert above that the length is a multiple
        //         of the size of u32.
        unsafe {
            std::slice::from_raw_parts(
                v.as_ptr() as *const u32,
                v.len() / std::mem::size_of::<u32>(),
            )
        }
    }

    pub fn update(&mut self, msg: &str) {
        let mut msg_bytes = msg.as_bytes().to_vec();
        msg_bytes = Self::pad(msg_bytes);

        for chunk in msg_bytes.array_chunks::<64>() {
            let _ = self.hash_chunk(Self::as_u32_slice(chunk));
        }
    }

    pub fn hash_bytes(&mut self, msg: &Vec<u8>) -> String {
        let msg_bytes = Self::pad(msg.clone());

        for chunk in msg_bytes.array_chunks::<64>() {
            let _ = self.hash_chunk(Self::as_u32_slice(chunk));
        }

        self.digest()
    }

    pub fn hash(&mut self, msg: &str) -> String {
        let mut msg_bytes = msg.as_bytes().to_vec();
        msg_bytes = Self::pad(msg_bytes);

        for chunk in msg_bytes.array_chunks::<64>() {
            let _ = self.hash_chunk(Self::as_u32_slice(chunk));
        }

        self.digest()
    }

    pub fn digest_to_state(digest: &str) -> [u32; 4] {
        if digest.len() != 32 {
            panic!("Invalid Digest. Size must be 32.");
        }

        [
            u32::from_str_radix(&digest[..8], 16).expect("Invalid Digest.").swap_bytes(),
            u32::from_str_radix(&digest[8..16], 16).expect("Invalid Digest.").swap_bytes(),
            u32::from_str_radix(&digest[16..24], 16).expect("Invalid Digest.").swap_bytes(),
            u32::from_str_radix(&digest[24..], 16).expect("Invalid Digest.").swap_bytes(),
        ]
    }

    pub fn digest(&self) -> String {
        format!("{:08x}{:08x}{:08x}{:08x}",
                self.state[0].swap_bytes(),
                self.state[1].swap_bytes(),
                self.state[2].swap_bytes(),
                self.state[3].swap_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding() {
        let msg = vec![1,2,3,4,5,6,7,8];

        let expected_padded_msg = vec![1,2,3,4,5,6,7,8,0b10000000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0];
        assert_eq!(expected_padded_msg.len(), 64);

        assert_eq!(MD5::pad(msg), expected_padded_msg);
    }

    #[test]
    fn md5_test_vectors() {
        let test_vectors = [
            ("The quick brown fox jumps over the lazy dog"  , "9e107d9d372bb6826bd81d3542a419d6"),
            ("The quick brown fox jumps over the lazy dog." , "e4d909c290d0fb1ca068ffaddf22cbd0"),
            (""                                             , "d41d8cd98f00b204e9800998ecf8427e"),
        ];

        for (input, expected) in test_vectors {
            let mut md5 = MD5::new();
            let actual = md5.hash(input);

            assert_eq!(actual, expected, "Test Vector \"{}\" failed", input);
        }
    }

    #[test]
    fn conversions() {
        let test_vectors = [
            ("The quick brown fox jumps over the lazy dog"  , "9e107d9d372bb6826bd81d3542a419d6"),
            ("The quick brown fox jumps over the lazy dog." , "e4d909c290d0fb1ca068ffaddf22cbd0"),
            (""                                             , "d41d8cd98f00b204e9800998ecf8427e"),
        ];

        for (input, expected) in test_vectors {
            let mut md5 = MD5::new();
            let actual = md5.hash(input);

            assert_eq!(MD5::digest_to_state(&actual), md5.state);
        }
    }
}
