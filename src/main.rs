#![allow(dead_code, unused_variables)]

mod ext;
mod footer;
mod index;
mod entry;
mod fetch;

use aes::Aes256;
use cipher::generic_array::GenericArray;
use cipher::KeyInit as _;

fn parse_key(hex_str: &str) -> [u8; 32] {
  let clean = hex_str.trim_start_matches("0x");
  let bytes = hex::decode(clean).expect("Invalid hex key");

  assert_eq!(bytes.len(), 32, "Key must be 32 bytes (256-bit)");

  let mut arr = [0u8; 32];
  arr.copy_from_slice(&bytes);
  arr
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let _key = parse_key("0x6F80948821CA338739A24D4D9F778BCAC0996B2EF2A73897A789C68AFF05174E");
  let key = Aes256::new(GenericArray::from_slice(&_key));

  let url = "https://hw-pcdownload-aws.aki-game.net/launcher/game/G153/50004/2.6.2/TmryWWDzYshLRahsXoGizseCUnInEDtj/zip/Client/Content/Paks/pakchunk0-WindowsNoEditor.pak";
  let total_size = fetch::get_size(&url).await?;
  println!("Total size: {}", total_size);

  // footer
  let footer_size = 221;
  let footer_buffer = fetch::fetch_range(url, total_size - footer_size, total_size).await?;
  let _footer = crate::footer::read_footer(&footer_buffer);
  let Ok(footer) = _footer else {
    return Err("Unable to read pak metadata!".into());
  };

  println!("{:?}", footer);

  // header
  let index_offset = footer.index_offset as usize;
  let index_size = (footer.index_size + 512000) as usize; // 500KB for (main index, path hash index & full directory index)
  let index_buffer = fetch::fetch_range(&url, index_offset, (index_offset) + (index_size - 1)).await?;

  // println!("{:?}", index_buffer);

  let _index = crate::index::get_index(&index_buffer, &key, &footer);
  let Ok(index) = _index else {
    return Err("Unable to read pak index!".into());
  };

  // println!("{:?}", index);

  let file_contains = vec![
    "Client/Config/Package/ParamsConfig.ini",
    "Client/Config/Kuro/KuroPublicConfig.ini"
  ];
  
  for (f, e) in index.entries
    .iter()
    .filter(|(f, _)| file_contains.iter().any(|s| f.contains(s)))
  {
    let file_offset = e.offset as usize;
    let mut file_len: usize = if footer.encrypted {
      ((e.uncompressed + 15) & !15) as usize
    } else {
      e.uncompressed as usize
    };

    let entry_size = 53 + 4; // entry + array size = FIXED!
    let block_size = if e.compression_slot.is_none() {
      0
    } else {
      if let Some(blocks) = &e.blocks {
        blocks.len() * 20
      } else {
        0
      }
    };

    file_len += entry_size + block_size;

    let file_buffer = fetch::fetch_range(&url, file_offset, file_offset + (file_len - 1)).await?;
    let _ = entry::read_file(&file_buffer, &key, &footer, f, e);
  }

  Ok(())
}