use std::{io::{self, Cursor, Read as _, Seek as _}};

use byteorder::{ReadBytesExt as _, LE};

use crate::ext::ReadExt as _;

#[derive(Debug, Clone)]
pub struct PakFooter {
  pub encryption_uuid: Option<u128>,
  pub encrypted: bool,
  pub magic: u32,
  pub magic_hex: String,
  pub version_major: u32,
  pub index_offset: u64,
  pub index_offset_hex: String,
  pub index_size: u64,
  pub hash: String,
  pub frozen: bool,
  pub compression: Vec<String>,
}

pub fn read_footer(buf: &[u8]) -> Result<PakFooter, Box<dyn std::error::Error>> {
  let mut reader = Cursor::new(buf);

  // (magic + version): u32 + (offset + size): u64 + hash: [u8; 20]
  let size = 4 + 4 + 8 + 8 + 20
    + 16 // encryption uuid: u128
    + 1 // encrypted: bool
    // + 1 // frozen index: bool
    + (32 * 4) // compression names: [[u8; 32]; 4]
    + 32; // additional compression name

  // seek to footer
  reader.seek(io::SeekFrom::End(-size))?;

  // start reading
  let encryption_uuid = {
    let uuid = reader.read_u128::<LE>().unwrap();
    if uuid == 0 { None } else { Some(uuid) }
  };
  let encrypted = reader.read_bool().unwrap();
  let magic = reader.read_u32::<LE>().unwrap();
  let magic_hex = format!("0x{:X}", magic);
  let version_major = reader.read_u32::<LE>().unwrap();
  let index_offset = reader.read_u64::<LE>().unwrap();
  let index_offset_hex = format!("0x{:X}", index_offset);
  let index_size = reader.read_u64::<LE>().unwrap();

  let mut _hash = [0; 20];
  reader.read_exact(&mut _hash)?;
  let hash = hex::encode(_hash).to_uppercase();

  let frozen = false; // reader.read_u8().unwrap() != 0;

  let mut compression = Vec::new();
  for _ in 0..5 {
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf)?;

    if let Some(pos) = buf.iter().position(|&b| b == 0) {
      let s = String::from_utf8_lossy(&buf[..pos]).to_string();
      if !s.is_empty() {
        compression.push(s);
      }
    }
  }

  Ok(PakFooter {
    encryption_uuid,
    encrypted,
    magic,
    magic_hex,
    version_major,
    index_offset,
    index_offset_hex,
    index_size,
    hash,
    frozen,
    compression,
  })
}