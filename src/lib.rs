/* A straight-line implementation of Skipjack, the block cipher developed
 * by the NSA and best known for being used in the Clipper chip.
 *
 * Skipjack is a 64-bit block cipher, utilizing an unbalanced Feistel network
 * with 32 rounds. It uses an 80-bit secret key.
 *
 * This implementation has three design goals:
 *   1. To represent idiomatic Rust in a cryptographic context
 *   2. To be easy to read and understand with a minimal understanding of Rust,
 *      even without a background in cryptography
 *   3. To directly reflect the NIST specification for Skipjack (i.e., no
 *      optimizations or shortcuts)
 *
 * The NIST specification for Skipjack can be found here:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/skipjack/skipjack.pdf
 *
 * Skipjack is not recommended for modern cryptographic use. To prevent use, this library
 * intentionally does not include any modes of operation other than codebook (ECB).
 */
pub mod skipjack {
    // Given a 64-bit block, return it as an array of four 16-bit words.
    // The high word is returned first, i.e. in index 0.
    fn block_to_words(block: u64) -> [u16; 4] {
        // In other languages (like C), we would need to mask off the high bits
        // in order to get just the 16 bits we intend. Rust does this safely
        // for us as part of `as u16`, which truncates to just the lower
        // 16 bits.
        let w1: u16 = (block >> 48) as u16;
        let w2: u16 = (block >> 32) as u16;
        let w3: u16 = (block >> 16) as u16;
        let w4: u16 = block as u16;

        [w1, w2, w3, w4]
    }

    // Given four 16-bit words, merge them into a single 64-bit block.
    fn words_to_block(words: [u16; 4]) -> u64 {
        let mut block = (words[0] as u64) << 48;
        block |= (words[1] as u64) << 32;
        block |= (words[2] as u64) << 16;
        block |= words[3] as u64;

        block
    }

    // Given a 16-bit word, return it as an array of two bytes.
    // The high byte is returned first, i.e. in index 0.
    fn word_to_bytes(word: u16) -> [u8; 2] {
        [(word >> 8) as u8, word as u8]
    }

    // Given two bytes, merge them into a single 16-bit word.
    fn bytes_to_word(bytes: [u8; 2]) -> u16 {
        (bytes[0] as u16) << 8 | bytes[1] as u16
    }

    // Skipjack's F table is an S-Box providing a bijective map on u8.
    #[rustfmt::skip]
    static F: [u8; 256] = [
        0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
        0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
        0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
        0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
        0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
        0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
        0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
        0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
        0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
        0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
        0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
        0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
        0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
        0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
        0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
        0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46,
    ];

    fn rule_g(word: u16, step: u16, key: &[u8; 10]) -> u16 {
        // Rule G is a 4 round Feistel cipher on a single word, divided
        // into two bytes (g1 and g2).
        //
        // Each round of G integrates a single byte of the secret key, based on the
        // current step. Each round also integrates a lookup to the F table.
        let bytes = word_to_bytes(word);
        let (g1, g2) = (bytes[0], bytes[1]);

        // Round 1: Transform g2 and a byte of the secret key into an index into F,
        // then XOR with g1.
        let g3 = F[(g2 ^ key[((4 * step) % 10) as usize]) as usize] ^ g1;

        // Round 2: Transform g3 and a byte of the secret key into an index into F,
        // then XOR with g2.
        let g4 = F[(g3 ^ key[(((4 * step) + 1) % 10) as usize]) as usize] ^ g2;

        // Round 3: Transform g4 and a byte of the secret key into an index into F,
        // then XOR with g3.
        let g5 = F[(g4 ^ key[(((4 * step) + 2) % 10) as usize]) as usize] ^ g3;

        // Round 4: Transform g5 and a byte of the secret key into an index into F,
        // then XOR with g4.
        let g6 = F[(g5 ^ key[(((4 * step) + 3) % 10) as usize]) as usize] ^ g4;

        // The result of rule G is the combination of the bytes from
        // the final two rounds into a single word.
        bytes_to_word([g5, g6])
    }

    fn rule_g_inv(word: u16, step: u16, key: &[u8; 10]) -> u16 {
        // Rule G' performs the inverse of rule G. Like G, it is a 4
        // round Feistel cipher divided across the two bytes of the input word.
        //
        // Observe that, unlike G, we begin with g5 and g6 instead of g1 and g2,
        // and work down through the rounds to the latter. This naming is arbitrary,
        // but consistent with the NIST documentation (and makes it clear that we're
        // performing an inverse operation).
        let bytes = word_to_bytes(word);
        let (g5, g6) = (bytes[0], bytes[1]);

        // Round 1: Transform g5 and a byte of the secret key into an index into F,
        // then XOR with g6.
        let g4 = F[(g5 ^ key[(((4 * step) + 3) % 10) as usize]) as usize] ^ g6;

        // Round 2: Transform g4 and a byte of the secret key into an index into F,
        // then XOR with g5.
        let g3 = F[(g4 ^ key[(((4 * step) + 2) % 10) as usize]) as usize] ^ g5;

        // Round 3: Transform g3 and a byte of the secret key into an index into F,
        // then XOR with g4.
        let g2 = F[(g3 ^ key[(((4 * step) + 1) % 10) as usize]) as usize] ^ g4;

        // Round 4: Transform g2 and a byte of the secret key into an index into F,
        // then XOR with g3.
        let g1 = F[(g2 ^ key[((4 * step) % 10) as usize]) as usize] ^ g3;

        // The result of rule G' is the combination of the bytes from
        // the final two rounds into a single word.
        bytes_to_word([g1, g2])
    }

    fn rule_a(words: &mut [u16; 4], counter: &mut u16, key: &[u8; 10]) {
        // Make a copy of our input block (as words) so that we don't accidentally
        // use the words that we're modifying while performing the rule.
        let original_words = words.to_owned();

        // Word 1 becomes an application of the G rule on itself,
        // XOR'ed with Word 4 and the current counter.
        // Observe that we pass `counter - 1` to rule G; G takes the
        // current step number, which is always the counter minus 1.
        words[0] = rule_g(original_words[0], *counter - 1, key) ^ original_words[3] ^ *counter;

        // Word 2 becomes an application of the G rule on Word 1.
        words[1] = rule_g(original_words[0], *counter - 1, key);

        // Word 3 becomes Word 2.
        words[2] = original_words[1];

        // Word 4 becomes Word 3.
        words[3] = original_words[2];

        // We're done with this round, so increment the counter.
        *counter += 1;
    }

    fn rule_b(words: &mut [u16; 4], counter: &mut u16, key: &[u8; 10]) {
        // Like rule A, we make a copy of our input block (as words) to avoid
        // accidentally clobbering it during updates.
        let original_words = words.to_owned();

        // Word 1 becomes Word 4.
        words[0] = original_words[3];

        // Word 2 becomes an application of the G rule on Word 1.
        words[1] = rule_g(original_words[0], *counter - 1, key);

        // Word 3 becomes an XOR of Word 1, Word 2, and the counter.
        words[2] = original_words[0] ^ original_words[1] ^ *counter;

        // Word 4 becomes Word 3.
        words[3] = original_words[2];

        // We're done with this round, so increment the counter.
        *counter += 1;
    }

    fn rule_a_inv(words: &mut [u16; 4], counter: &mut u16, key: &[u8; 10]) {
        // Rule A' performs the inverse of rule A.
        let original_words = words.to_owned();

        // Word 1 becomes an application of the G rule on Word 2.
        words[0] = rule_g_inv(original_words[1], *counter - 1, key);

        // Word 2 becomes Word 3.
        words[1] = original_words[2];

        // Word 3 becomes Word 4.
        words[2] = original_words[3];

        // Word 4 becomes an XOR of Word1, Word 2, and the counter.
        words[3] = original_words[0] ^ original_words[1] ^ *counter;

        // We're done with this round, so decrement the counter.
        *counter -= 1;
    }

    fn rule_b_inv(words: &mut [u16; 4], counter: &mut u16, key: &[u8; 10]) {
        // Rule B' performs the inverse of rule B.
        let original_words = words.to_owned();

        // Word 1 becomes an application of the G rule on Word 2.
        words[0] = rule_g_inv(original_words[1], *counter - 1, key);

        // Word 2 becomes an application of the G rule on itself,
        // XOR'ed with Word 3 and the counter.
        words[1] = rule_g_inv(original_words[1], *counter - 1, key) ^ original_words[2] ^ *counter;

        // Word 3 becomes Word 4.
        words[2] = original_words[3];

        // Word 4 becomes Word 1.
        words[3] = original_words[0];

        // We're done with this round, so decrement the counter.
        *counter -= 1;
    }

    /// Encrypts the given 64-bit block with the given 80-bit secret key.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to encrypt
    /// * `key` - The secret key to encrypt with
    pub fn encrypt_block(block: u64, key: [u8; 10]) -> u64 {
        // First, split our 64-bit input block into 4 16-bit words.
        let mut words = block_to_words(block);

        // Initialize our counter. The counter tracks which round we're in,
        // and is used to calculate the "step number" (which is just the
        // counter minus 1).
        let mut counter = 1;

        // Skipjack consists of 32 rounds each consisting of a single stepping rule.
        // In our implementation, each round modifies the block passed to it in-place.
        // First, 8 rounds of rule A.
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);

        // Then, 8 rounds of rule B.
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);

        // Then, 8 more rounds of rule A.
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);
        rule_a(&mut words, &mut counter, &key);

        // Finally, 8 more rounds of rule B.
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);
        rule_b(&mut words, &mut counter, &key);

        // After all 32 rounds, `words` now contains the fully encrypted block.
        // We convert it back into a single 64-bit block.
        words_to_block(words)
    }

    /// Decrypts the given 64-bit block with the given 80-bit secret key.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to decrypt
    /// * `key` - The secret key to decrypt with
    pub fn decrypt_block(block: u64, key: [u8; 10]) -> u64 {
        // Skipjack decryption closely mirrors encryption: we run 32 rounds,
        // but in reverse (B'A'B'A' instead of ABAB).
        let mut words = block_to_words(block);

        // Because decryption runs the rounds in reverse, we begin with
        // our counter at 32 instead of 1. Like encryption, we'll calculate
        // our "step number" from our counter.
        let mut counter = 32;

        // First, 8 rounds of rule B'.
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);

        // Then, 8 rounds of rule A'.
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);

        // Then, 8 rounds of rule B'.
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);
        rule_b_inv(&mut words, &mut counter, &key);

        // Finally, 8 more rounds of A'.
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);
        rule_a_inv(&mut words, &mut counter, &key);

        // Just an for encryption: our words now contain the decrypted block,
        // so we convert is back to a single block.
        words_to_block(words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_block() {
        let plaintext: u64 = 0x33221100ddccbbaa;
        let key: [u8; 10] = [0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

        let ciphertext = skipjack::encrypt_block(plaintext, key);

        // For a known plaintext and key, we get the expected ciphertext.
        assert_eq!(ciphertext, 0x2587cae27a12d300);
    }

    #[test]
    fn test_decrypt_block() {
        let plaintext: u64 = 0x33221100ddccbbaa;
        let key: [u8; 10] = [0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

        let ciphertext = skipjack::encrypt_block(plaintext, key);

        // For a known ciphertext and key, we get the expected plaintext.
        assert_eq!(skipjack::decrypt_block(ciphertext, key), plaintext);
    }
}
