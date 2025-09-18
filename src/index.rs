use std::{collections::BTreeMap, io::{self, Cursor, Read as _, Seek as _}};

use aes::Aes256;
use byteorder::{ReadBytesExt as _, LE};
use cipher::{generic_array::GenericArray, BlockDecrypt as _};

use crate::{entry, ext::ReadExt as _, footer::PakFooter};

#[derive(Debug)]
pub struct Index {
  pub path_hash_seed: Option<u64>,
  pub mount_point: String,
  pub entries: BTreeMap<String, super::entry::Entry>,
}

// pub fn get_index(reader: &mut BufReader<File>, key: &Aes256, footer: &PakFooter) -> Result<Index, Box<dyn std::error::Error>> {
pub fn get_index(buf: &[u8], key: &Aes256, footer: &PakFooter) -> Result<Index, Box<dyn std::error::Error>> {
  let mut reader = Cursor::new(buf);
  
  let len = footer.index_size as usize;  
  let mut _index = vec![0; len];

  // read index
  // reader.seek(io::SeekFrom::Start(footer.index_offset))?;
  reader.seek(io::SeekFrom::Start(0))?;
  reader.read_exact(&mut _index)?;
  
  // is encrypted?
  if footer.encrypted {
    for chunk in _index.chunks_mut(16) {
      let mut block = GenericArray::clone_from_slice(chunk);
      key.decrypt_block(&mut block);
      chunk.copy_from_slice(&block);
    }
  }

  let mut index = io::Cursor::new(_index);
  let mount_point = index.read_string()?;
  let len = index.read_u32::<LE>()? as usize;

  // println!("{:#?}", mount_point);
  // println!("{:#?}", len);

  let path_hash_seed = index.read_u64::<LE>()?;

  // Left in for potential desire to verify path index hashes.
  let _path_hash_index = if index.read_u32::<LE>()? != 0 {
    let path_hash_index_offset = index.read_u64::<LE>()?;
    let path_hash_index_size = index.read_u64::<LE>()?;
    let _path_hash_index_hash = index.read_len(20)?;

    let new_path_hash_index_offset = path_hash_index_offset - footer.index_offset;
    reader.seek(io::SeekFrom::Start(new_path_hash_index_offset))?;

    let mut path_hash_index_buf = reader.read_len(path_hash_index_size as usize)?;
    // TODO verify hash

    if footer.encrypted {
      for chunk in path_hash_index_buf.chunks_mut(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        key.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
      }
    }

    let mut path_hash_index = vec![];
    let mut phi_reader = io::Cursor::new(&mut path_hash_index_buf);
    
    for _ in 0..phi_reader.read_u32::<LE>()? {
      let hash = phi_reader.read_u64::<LE>()?;
      let encoded_entry_offset = phi_reader.read_u32::<LE>()?;
      path_hash_index.push((hash, encoded_entry_offset));
    }

    Some(path_hash_index)
  } else {
    None
  };

  // println!("Path hash index: {:?}", _path_hash_index);

  // Left in for potential desire to verify full directory index hashes.
  let full_directory_index = if index.read_u32::<LE>()? != 0 {
    let full_directory_index_offset = index.read_u64::<LE>()?;
    let full_directory_index_size = index.read_u64::<LE>()?;
    let _full_directory_index_hash = index.read_len(20)?;

    let new_full_directory_index_offset = full_directory_index_offset - footer.index_offset;
    reader.seek(io::SeekFrom::Start(new_full_directory_index_offset))?;

    let mut full_directory_index = reader.read_len(full_directory_index_size as usize)?;
    // TODO verify hash

    if footer.encrypted {
      for chunk in full_directory_index.chunks_mut(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        key.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
      }
    }

    let mut fdi = io::Cursor::new(full_directory_index);
    let dir_count = fdi.read_u32::<LE>()? as usize;
    let mut directories = BTreeMap::new();

    for _ in 0..dir_count {
      let dir_name = fdi.read_string()?;
      let file_count = fdi.read_u32::<LE>()? as usize;
      let mut files = BTreeMap::new();

      for _ in 0..file_count {
        let file_name = fdi.read_string()?;
        files.insert(file_name, fdi.read_u32::<LE>()?);
      }

      directories.insert(dir_name, files);
    }

    Some(directories)
  } else {
    None
  };

  let size = index.read_u32::<LE>()? as usize;
  let encoded_entries = index.read_len(size)?;

  // start reading file path
  let mut entries_by_path = BTreeMap::new();
  if let Some(fdi) = &full_directory_index {
    let mut encoded_entries = io::Cursor::new(&encoded_entries);

    for (dir_name, dir) in fdi {
      for (file_name, encoded_offset) in dir {
        if *encoded_offset == 0x80000000 {
          println!("{file_name:?} has invalid offset: 0x{encoded_offset:08x}");
          continue;
        }

        encoded_entries.seek(io::SeekFrom::Start(*encoded_offset as u64))?;

        let entry = entry::read_encoded(&mut encoded_entries)?;
        let path = format!("{}{}", dir_name.strip_prefix('/').unwrap_or(dir_name), file_name);

        entries_by_path.insert(path, entry);
      }
    }
  }

  assert_eq!(index.read_u32::<LE>()?, 0, "remaining index bytes are 0"); // TODO possibly remaining unencoded entries?

  Ok(Index {
    path_hash_seed: Some(path_hash_seed),
    mount_point,
    entries: entries_by_path,
  })
}