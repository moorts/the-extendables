use crate::hash::md5::*;
use hex::*;

pub trait LengthExtend {
    /// Perform Length Extension Attack.
    ///
    /// Calculates h(base || extension) based on the length of `base` and the digest of `base`.
    /// 
    /// Arguments:
    /// * `base` - Bytes of Pre-Image of `base_digest` (Only length matters)
    /// * `base_digest` - Digest of original msg
    /// * `extension` - Bytes to extend the hash with
    ///
    /// TODO: Change signature (probably should only require `base_len`, not `base`
    fn extend_bytes(base: Vec<u8>, base_digest: &str, extension: Vec<u8>) -> (String, String);

    fn extend_str(base: &str, base_digest: &str, extension: &str) -> (String, String) {
        Self::extend_bytes(base.as_bytes().to_vec(), base_digest, extension.as_bytes().to_vec())
    }

    /// Pad msg as if its size was n
    fn forge_padding(msg: Vec<u8>, n: usize) -> Vec<u8>;
}

impl LengthExtend for MD5 {
    fn forge_padding(mut msg: Vec<u8>, n: usize) -> Vec<u8> {
        if n > 0 && n % 512 == 0 {
            return msg;
        }

        let mut len_padding = 512 - (n % 512);

        if len_padding <= 64 {
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

    fn extend_bytes(base: Vec<u8>, base_digest: &str, extension: Vec<u8>) -> (String, String) {
        let mut hash = MD5::from_str(base_digest);
        let mut payload = Self::pad(base);
        payload.extend(extension.clone());

        let msg_bytes = Self::forge_padding(extension, payload.len() * 8);

        for chunk in msg_bytes.array_chunks::<64>() {
            let _ = hash.hash_chunk(Self::as_u32_slice(chunk));
        }

        (hex::encode(payload.clone()), hash.digest())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_extension() {
        let mut hash = MD5::new();

        let base = "secretdata";
        let base_digest = hash.hash(base);

        assert_eq!("6036708eba0d11f6ef52ad44e8b74d5b", base_digest);

        let extension = "append";

        let (forged_message, forged_signature) = MD5::extend_str(base, &base_digest, extension);

        let expected_message = "73656372657464617461800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000617070656e64";
        let expected_signature = "6ee582a1669ce442f3719c47430dadee";

        assert_eq!(expected_message, forged_message);
        assert_eq!(expected_signature, forged_signature);
   }
}
