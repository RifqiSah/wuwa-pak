mod ext;
mod footer;
mod index;
mod entry;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let file = File::open(r"X:\Wuthering Waves Basic\Client\Content\Paks\pakchunk0-WindowsNoEditor.pak")?;
  let mut buffer = BufReader::new(file);

  let _key = parse_key("0x6F80948821CA338739A24D4D9F778BCAC0996B2EF2A73897A789C68AFF05174E");
  let key = Aes256::new(GenericArray::from_slice(&_key));

  let _footer = crate::footer::read_footer(&mut buffer);
  let Ok(footer) = _footer else {
    return Err("Unable to read pak metadata!".into());
  };
  
  println!("{:?}", footer);

  let _index = crate::index::get_index(&mut buffer, &key, &footer);
  let Ok(index) = _index else {
    return Err("Unable to read pak index!".into());
  };
  
  let file_contains = vec![
    "Client/Config/Package/ParamsConfig.ini",
    "Client/Config/Kuro/KuroPublicConfig.ini"
  ];

  index.entries
    .iter()
    .filter(|(f, _)| file_contains.iter().any(|s| f.contains(s)))
    .for_each(|(f, e)| {
      entry::read_file(&mut buffer, &key, &footer, f, e);
    });

  Ok(())
}