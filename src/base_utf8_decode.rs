use std::collections::HashMap;

// Define the total number of padding options (1 to 14)
const MAX_PADDING: usize = 14;
lazy_static! {
    // Initialize the padding characters (using the first 14 Chinese characters)
    static ref PADDING_CHARS: Vec<char> = {
        let start = 0x4E00; // Unicode code point for the first Chinese character
    (0..MAX_PADDING)
        .map(|i| std::char::from_u32(start + i as u32).unwrap())
        .collect()
    };
    // Initialize the extended alphabet using Chinese characters
    static ref ALPHABET: Vec<char> = {
        // Starting from Unicode code point U+4E00 (CJK Unified Ideographs)
        let start = 0x4E00;
        let alphabet_size = 1 << 14; // 16384
        let mut vec = Vec::with_capacity(alphabet_size);
        for i in 0..alphabet_size {
            let code_point = start + i as u32;
            if let Some(ch) = std::char::from_u32(code_point) {
                vec.push(ch);
            } else {
                // If the code point is invalid, you may handle it accordingly.
                // For simplicity, we can skip invalid code points.
                continue;
            }
        }
        vec
    };
    // Create a reverse mapping from characters to indices for decoding
    static ref CHAR_TO_INDEX: HashMap<char, u32> = {
        let mut map = HashMap::with_capacity(1024);
        for (i, &ch) in ALPHABET.iter().enumerate() {
            map.insert(ch, i as u32);
        }
        map
    };
}

// Function to decode a string back into binary data using the Chinese character alphabet
pub fn decode(s: &str) -> Vec<u8> {
    let mut output = Vec::new();
    let mut bit_buffer: u128 = 0;
    let mut bit_buffer_len = 0;

    let chars = s.chars().collect::<Vec<char>>();

    // Check if the last character is a padding character
    let mut padding_bits = 0;
    let mut has_padding = false;
    let mut data_len = chars.len();

    if !chars.is_empty() {
        let last_char = chars[chars.len() - 1];
        if let Some(padding_index) = PADDING_CHARS.iter().position(|&c| c == last_char) {
            padding_bits = padding_index + 1; // padding_bits ranges from 1 to 14
            has_padding = true;
            data_len -= 1; // Exclude the padding character from data length
        }
    }

    for (i, &ch) in chars.iter().enumerate().take(data_len) {
        let index = match CHAR_TO_INDEX.get(&ch) {
            Some(&idx) => idx as u128,
            None => {
                // Handle invalid characters
                continue;
            }
        };

        if has_padding && i == data_len - 1 {
            // Last character with padding
            let valid_bits = 14 - padding_bits;
            let data_bits = index >> padding_bits;
            bit_buffer = (bit_buffer << valid_bits) | data_bits;
            bit_buffer_len += valid_bits as u128;
        } else {
            bit_buffer = (bit_buffer << 14) | index;
            bit_buffer_len += 14;
        }

        // Extract bytes from the bit buffer
        while bit_buffer_len >= 8 {
            bit_buffer_len -= 8;
            let byte = ((bit_buffer >> bit_buffer_len) & 0xFF) as u8;
            output.push(byte);
            bit_buffer &= (1 << bit_buffer_len) - 1;
        }
    }

    output
}
