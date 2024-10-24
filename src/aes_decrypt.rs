use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::mac::Mac;
use crypto::{aes, blockmodes, buffer, symmetriccipher};
const HASH_LEN: usize = 20;

pub fn aes_decrypt_data(data: &[u8], key: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut derived_bytes = Rfc2898DeriveBytes::new(key, salt, 1000);
    let key = derived_bytes.get_bytes(32);
    let iv = derived_bytes.get_bytes(16);
    aes256_cbc_decrypt(data, &key, &iv).map_err(|_| format!("invalid data"))
}
fn aes256_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}
struct Rfc2898DeriveBytes<'a> {
    key: &'a [u8],
    salt: &'a [u8],
    count: u32,
    _block_result: [u8; HASH_LEN],
    _block_temp: [u8; HASH_LEN],
    block_sault: Vec<u8>,
    startindex: usize,
    endindex: usize,
    blocksize: usize,
    block: u32,
    buffer: [u8; HASH_LEN],
}
impl<'a> Rfc2898DeriveBytes<'a> {
    fn new(key: &'a [u8], salt: &'a [u8], count: u32) -> Self {
        Self {
            key,
            salt,
            count,
            startindex: 0,
            endindex: 0,
            block: 0,
            blocksize: HASH_LEN,
            buffer: [0u8; HASH_LEN],
            _block_result: [0; HASH_LEN],
            _block_temp: [0; HASH_LEN],
            block_sault: Vec::new(),
        }
    }
    fn get_bytes(&mut self, cb: usize) -> Vec<u8> {
        let mut offset = 0;
        let mut result = vec![0u8; cb as usize];
        let size = self.endindex - self.startindex;
        if size > 0 {
            if cb >= size {
                result[..size]
                    .clone_from_slice(&self.buffer[self.startindex..self.startindex + size]);
                self.startindex = 0;
                self.endindex = 0;
                offset += size;
            } else {
                result[..cb].clone_from_slice(&self.buffer[self.startindex..self.startindex + cb]);
                return result;
            }
        }

        while offset < cb {
            self.func();
            let remainder = cb - offset;
            if remainder >= self.blocksize {
                result[offset..self.blocksize + offset]
                    .clone_from_slice(&self.buffer[0..self.blocksize]);
                offset += self.blocksize;
            } else {
                result[offset..remainder + offset].clone_from_slice(&self.buffer[0..remainder]);
                self.startindex = remainder;
                self.endindex = self.blocksize;
                return result;
            }
        }
        result
    }
    fn func(&mut self) {
        let mut result: Vec<u8> = Vec::new();
        self.block += 1;
        if self.block != 1 {
            for _ in 0..4 {
                self.block_sault.pop();
            }
        } else {
            let tsault = self.salt;
            for i0 in 0..tsault.len() {
                self.block_sault.push(tsault[i0]);
            }
        }
        for i2 in 0..4 {
            unsafe {
                let pb: *const u8 = &self.block as *const u32 as *const u8;
                self.block_sault.push(*pb.offset(3 - i2));
            }
        }
        self._block_temp = hmac_sha1(&self.key, &self.block_sault);
        self._block_result = self._block_temp;
        for _ in 0..self.count - 1 {
            self._block_temp = hmac_sha1(&self.key, &self._block_temp);
            for i3 in 0..self._block_temp.len() {
                self._block_result[i3] ^= self._block_temp[i3];
            }
        }
        for i4 in 0..self._block_temp.len() {
            result.push(self._block_result[i4]);
        }
        self.buffer[..].clone_from_slice(&result[..]);
    }
}
fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let sha1 = crypto::sha1::Sha1::new();
    let mut hmac = crypto::hmac::Hmac::new(sha1, key);
    hmac.input(data);
    let hresult = hmac.result();
    let mut result = [0; 20];
    result.copy_from_slice(&hresult.code()[0..20]);
    result
}
