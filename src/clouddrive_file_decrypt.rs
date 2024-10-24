use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
/* 
Encrypted file structure:
+----------------------+----------------------------------------+---------+-----------------------------------+
|     salt (16 bytes)  | nonce (24 bytes)| block size (4 bytes) | block 0 | block 1 | block 2 | ... | block n |
+----------------------+----------------------------------------+---------+-----------------------------------+
 */
const NONCE_SIZE: usize = 24;
const SALT_SIZE: usize = 16;
const BLOCK_SIZE_BYTES: usize = 4;
const START_OFFSET: u64 = SALT_SIZE as u64 + NONCE_SIZE as u64 + BLOCK_SIZE_BYTES as u64;
const KEY_SIZE: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;
const POLY1305_TAG_SIZE: usize = 16;
pub struct EncryptedFile {
    file: std::fs::File,
    key: Key,
    nonce: [u8; NONCE_SIZE],
    block_size: usize,
    plain_file_size: usize,
}
impl EncryptedFile {
    pub fn open(path: &str, password: &str) -> io::Result<Self> {
        let mut file = File::open(path)?;

        // Read the salt from the file
        let mut salt = [0u8; SALT_SIZE];
        file.read_exact(&mut salt)?;

        // Derive the key from the password and the salt
        let key = derive_key_from_password(password, &salt);

        // Read the nonce from the file
        let mut nonce = [0u8; NONCE_SIZE];
        file.read_exact(&mut nonce)?;

        // Read the block size from the file
        let mut block_size_bytes = [0u8; BLOCK_SIZE_BYTES];
        file.read_exact(&mut block_size_bytes)?;
        let block_size = u32::from_le_bytes(block_size_bytes) as usize;

        // Calculate the plain file size based on the encrypted file size
        let encrypted_file_size = file.metadata()?.len();
        let data_length = plain_file_size(encrypted_file_size, block_size as u64) as usize;
        // Determin the current length of the file (minus salt and nonce)
        Ok(Self {
            file,
            key,
            nonce,
            block_size,
            plain_file_size: data_length,
        })
    }
    pub fn plain_file_size(&self) -> usize {
        self.plain_file_size
    }
    pub fn fread(&mut self, position: usize, length: usize) -> io::Result<Vec<u8>> {
        if position >= self.plain_file_size {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        let mut remaining_length = length;
        let mut current_position = position;
        let encrypted_block_size = self.encrypted_block_size();
        while remaining_length > 0 {
            let block_position = current_position / self.block_size;
            let block_offset = current_position % self.block_size;

            // Create a nonce for the specific block
            let mut nonce = self.nonce.clone();
            nonce[..8].copy_from_slice(&(block_position as u64).to_le_bytes());

            // Read the encrypted block from the file
            let ciphertext = read_exact(
                &mut self.file,
                (block_position * encrypted_block_size) as u64 + START_OFFSET,
                encrypted_block_size,
            )?;

            //Deecrypt the block
            let plaintext_block = XChaCha20Poly1305::new(&self.key)
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &[],
                    },
                )
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Decryption failed"))?;

            // Calculate how much data we can read from this block
            let available_data = plaintext_block.len() - block_offset;
            let to_read = remaining_length
                .min(available_data)
                .min(self.block_size - block_offset);

            // If the current read position plus to_read exceeds self.data_lenght, truncate to_read
            let effective_data_lengthh = self.plain_file_size - current_position;
            let adjusted_to_read = to_read.min(effective_data_lengthh);

            // Copy the data from the decrypted block to the result
            result
                .extend_from_slice(&plaintext_block[block_offset..block_offset + adjusted_to_read]);

            // Update remaining length and current position
            remaining_length -= adjusted_to_read;
            current_position += adjusted_to_read;

            if to_read < available_data || current_position == self.plain_file_size {
                break;
            }
        }
        Ok(result)
    }
    fn encrypted_block_size(&self) -> usize {
        self.block_size + POLY1305_TAG_SIZE
    }
}
pub fn plain_file_size(encrypted_file_size: u64, block_size: u64) -> u64 {
    if encrypted_file_size < START_OFFSET + POLY1305_TAG_SIZE as u64 {
        return 0;
    }
    let encrypted_file_size = encrypted_file_size - START_OFFSET;
    let last_block_offset = encrypted_file_size % (block_size + POLY1305_TAG_SIZE as u64);
    let num_of_blocks = encrypted_file_size / (block_size + POLY1305_TAG_SIZE as u64);
    if last_block_offset == 0 {
        num_of_blocks * block_size
    } else {
        num_of_blocks * block_size + last_block_offset - POLY1305_TAG_SIZE as u64
    }
}

fn derive_key_from_password(password: &str, salt: &[u8]) -> Key {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    Key::from_slice(&key).clone()
}

fn read_exact(file: &mut File, offset: u64, read_len: usize) -> io::Result<Vec<u8>> {
    let mut read = 0;
    let mut buffer = vec![0u8; read_len];
    file.seek(SeekFrom::Start(offset))?;
    while read < buffer.len() {
        let count = file.read(&mut buffer[read..])?;
        if count == 0 {
            break;
        }
        read += count;
    }
    if read != buffer.len() {
        buffer.resize(read, 0);
    }
    Ok(buffer)
}
