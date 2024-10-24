use aes_decrypt::aes_decrypt_data;
use clouddrive_file_decrypt::EncryptedFile;
use std::io::Write;
use std::{fs::OpenOptions, io, path::PathBuf};

#[macro_use]
extern crate lazy_static;

const CLOUDFS_CRYPT_DOT_SURFIX: &str = ".cdcrypto";
const FILE_NAME_SALT_SIZE: usize = 8;

pub mod aes_decrypt;
pub mod base_utf8_decode;
pub mod clouddrive_file_decrypt;

fn decrypt_file_name(name: &str, password: &str) -> Result<String, String> {
    if !name.ends_with(CLOUDFS_CRYPT_DOT_SURFIX) {
        Err(format!("invalid file extension"))
    } else {
        let encoded_name = name.trim_end_matches(CLOUDFS_CRYPT_DOT_SURFIX);
        let encoded_bytes = crate::base_utf8_decode::decode(encoded_name);
        if encoded_bytes.len() <= FILE_NAME_SALT_SIZE {
            return Err(format!("invalid file name"));
        }
        let decrpted_bytes = aes_decrypt_data(
            &encoded_bytes[FILE_NAME_SALT_SIZE..],
            password.as_bytes(),
            &encoded_bytes[0..FILE_NAME_SALT_SIZE],
        )
        .map_err(|_| format!("invalid file name or password"))?;
        Ok(String::from_utf8_lossy(&decrpted_bytes).to_string())
    }
}
fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <input_file> <password>", args[0]);
        std::process::exit(0);
    }
    let input_file_path = &args[1];
    let password = &args[2];
    let encrypted_file_name = PathBuf::from(input_file_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let filename = decrypt_file_name(&encrypted_file_name, password).expect("invalid file name");
    println!("Decrypted file name: {}", filename);
    let mut encrypted_file = EncryptedFile::open(input_file_path, password)?;
    let read_size = 64 << 10; //64KB
    let mut position = 0;
    let mut decrypted_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&filename)?;
    loop {
        let read_bytes = encrypted_file.fread(position, read_size)?;
        if read_bytes.is_empty() {
            break;
        }
        decrypted_file.write_all(&read_bytes)?;
        position += read_bytes.len();
        print!(".");
    }
    println!("\nDecrypted file: {}", filename);
    Ok(())
}
