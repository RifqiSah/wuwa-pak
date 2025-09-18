use std::io::{self, Cursor, Read as _, Seek, Write};
use aes::Aes256;
use byteorder::{ReadBytesExt, LE};
use cipher::BlockDecrypt as _;

use crate::ext::ReadExt as _;
use crate::footer::PakFooter;

#[derive(Debug, Clone, Copy)]
enum Compression {
  Zlib,
  Gzip,
  Oodle,
  Zstd,
  LZ4,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Block {
  pub start: u64,
  pub end: u64,
}

impl Block {
  pub fn read<R: io::Read>(reader: &mut R) -> Result<Self, std::io::Error> {
    Ok(Self {
      start: reader.read_u64::<LE>()?,
      end: reader.read_u64::<LE>()?,
    })
  }
}

#[derive(Debug)]
pub(crate) struct Entry {
  pub offset: u64,
  pub compressed: u64,
  pub uncompressed: u64,
  pub compression_slot: Option<u32>,
  pub timestamp: Option<u64>,
  // pub hash: Option<String>,
  pub blocks: Option<Vec<Block>>,
  pub flags: u8,
  pub compression_block_size: u32,
}

#[inline(always)]
fn read_safe<R: io::Read>(reader: &mut R, bits: u32, bit: u32) -> Result<u64, std::io::Error> {
  Ok(if (bits & (1 << bit)) != 0 {
    reader.read_u32::<LE>()? as u64
  } else {
    reader.read_u64::<LE>()?
  })
}

fn flag_reader<R: io::Read>(reader: &mut R) -> Result<u32, std::io::Error> {
  let bits = reader.read_u32::<LE>()?;

  reader.read_u8()?;
  Ok(
    (bits >> 16) & 0x3f |
      (bits & 0xFFFF) << 6 |
      (bits & (1 << 28)) >> 6 |
      (bits & 0x0FC00000) << 1 |
      bits & 0xE0000000
  )
}

fn offset_reader<R: io::Read>(reader: &mut R, bits: u32) -> Result<(u64, u64), std::io::Error> {
  let offset = read_safe(reader, bits, 31)?;
  let uncompressed = read_safe(reader, bits, 30)?;

  Ok((uncompressed, offset))
}

pub fn get_serialized_size(compression: Option<u32>, block_count: u32) -> u64 {
  let mut size = 0;

  size += 8; // offset
  size += 8; // compressed
  size += 8; // uncompressed
  size += 4; // 32 bit compression
  size += 0; // timestamp
  size += 20; // hash
  size += match compression {
    Some(_) => 4 + (8 + 8) * block_count as u64, // blocks
    None => 0,
  };
  size += 1; // encrypted
  size += 4; // blocks uncompressed

  size
}

fn align(offset: u64) -> u64 {
  // add alignment (aes block size: 16) then zero out alignment bits
  (offset + 15) & !15
}

pub fn read_encoded<R: io::Read>(reader: &mut R) -> Result<Entry, std::io::Error> {
  let bits = flag_reader(reader)?;

  let compression = match (bits >> 23) & 0x3f {
    0 => None,
    n => Some(n - 1),
  };

  let encrypted = (bits & (1 << 22)) != 0;
  let compression_block_count: u32 = (bits >> 6) & 0xffff;
  let mut compression_block_size = bits & 0x3f;

  if compression_block_size == 0x3f {
    compression_block_size = reader.read_u32::<LE>()?;
  } else {
    compression_block_size <<= 11;
  }

  let (offset, uncompressed) = offset_reader(reader, bits)?;

  let compressed = match compression {
    None => uncompressed,
    _ => read_safe(reader, bits, 29)?,
  };

  let offset_base = get_serialized_size(compression, compression_block_count);

  let blocks = if compression_block_count == 1 && !encrypted {
    Some(vec![Block {
      start: offset_base,
      end: offset_base + compressed,
    }])
  } else if compression_block_count > 0 {
    let mut index = offset_base;
    Some(
      (0..compression_block_count)
        .map(|_| {
          let mut block_size = reader.read_u32::<LE>()? as u64;
          let block = Block {
            start: index,
            end: index + block_size,
          };
          if encrypted {
            block_size = align(block_size);
          }
          index += block_size;
          Ok(block)
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?,
    )
  } else {
    None
  };

  Ok(Entry {
    offset,
    compressed,
    uncompressed,
    timestamp: None,
    compression_slot: compression,
    // hash: None,
    blocks,
    flags: encrypted as u8,
    compression_block_size,
  })
}

fn entry_read(reader: &mut Cursor<&[u8]>) -> Result<Entry, Box<dyn std::error::Error>> {
  let offset = reader.read_u64::<LE>()?;
  let compressed = reader.read_u64::<LE>()?;
  let uncompressed = reader.read_u64::<LE>()?;
  let compression = match reader.read_u32::<LE>()? {
    0 => None,        // 0 = tidak dikompresi
    n => Some(n - 1), // slot disimpan 1-based, dikurangi 1 untuk index 0-based
  };
  // let timestamp = (ver == VersionMajor::Initial).then_try(|| reader.read_u64::<LE>())?;
  // let hash = Some(Hash(reader.read_guid()?));
  let mut _hash = [0; 20];
  reader.read_exact(&mut _hash)?;
  let hash = hex::encode(_hash).to_uppercase();

  let blocks = compression.and_then(|_| reader.read_array(Block::read).ok());
  let flags = reader.read_u8()?;
  let compression_block_size = reader.read_u32::<LE>()?;

  Ok(Entry {
    offset,
    compressed,
    uncompressed,
    compression_slot: compression,
    timestamp: None,
    // hash,
    blocks,
    flags,
    compression_block_size,
  })
}

fn parse_compression_array(strings: &[String]) -> Vec<Option<Compression>> {
  strings.iter().map(|s| {
    match s.as_str() {
      "Oodle" => Some(Compression::Oodle),
      "Zlib"  => Some(Compression::Zlib),
      "Gzip"  => Some(Compression::Gzip),
      "LZ4"   => Some(Compression::LZ4),
      "Zstd"  => Some(Compression::Zstd),
      _       => None,
    }
  }).collect()
}

pub fn read_file(buf: &[u8], key: &Aes256, footer: &PakFooter, path: &String, entry: &Entry) -> Result<(), Box<dyn std::error::Error>> {
  let mut reader = Cursor::new(buf);

  let mut decompressed = Vec::new();

  println!("\nReading {}", path);
  println!("File entry: {:?}", entry);

  // seek to target offset
  // reader.seek(io::SeekFrom::Start(entry.offset))?;
  reader.seek(io::SeekFrom::Start(0))?;
  let entry_read = entry_read(&mut reader)?;
  // println!("Entry read {:?}", entry_read);

  let data_offset = reader.stream_position()?;
  // println!("Data offset {}", data_offset);

  let is_encrypted = true; // TODO
  let mut data = reader.read_len(match is_encrypted {
    true => align(entry.compressed),
    false => entry.compressed,
  } as usize)?;

  // println!("Plain: {} bytes", data.len());
  // for b in &data {
  //   print!("{:02X} ", b);
  // }
  // println!("");
  
  // encryption
  if is_encrypted {
    let data_len = data.len();
    
    for block in data[..data_len].chunks_mut(16) {
      key.decrypt_block(aes::Block::from_mut_slice(block))
    }

    data.truncate(entry.compressed as usize);
  }

  // println!("After decrypt: {} bytes", data.len());
  // for b in &data {
  //   print!("{:02X} ", b);
  // }
  // println!("");

  // compression
  // let buffer_start = if let Some(blocks) = &entry.blocks {
  //   blocks[0].start
  // } else {
  //   entry.offset
  // };

  // let ranges = match &entry.blocks {
  //   Some(blocks) => blocks
  //     .iter()
  //     .map(|block| {
  //       let start = (block.start - buffer_start) as usize;
  //       let end   = (block.end   - buffer_start) as usize;
  //       start..end
  //     })
  //     .collect::<Vec<_>>(),
  //   None => vec![0..data.len()],
  // };

  let ranges = {
    let offset = |index: u64| -> usize {
      // (index - (data_offset - entry.offset)) as usize
      (index - (data_offset)) as usize
    };

    match &entry.blocks {
      Some(blocks) => blocks
        .iter()
        .map(|block| offset(block.start)..offset(block.end))
        .collect::<Vec<_>>(),
      None => vec![0..data.len()],
    }
  };

  // println!("Ranges: {:?}", ranges);

  macro_rules! decompress {
    ($decompressor: ty) => {
      for range in ranges {
        io::copy(&mut <$decompressor>::new(&data[range]), &mut decompressed)?;
      }
    };
  }
  
  let compression_slot: Option<u32> = entry.compression_slot;
  let compression_slots = parse_compression_array(&footer.compression);
  println!("Available compression: {:?}", compression_slots);

  let selected: Option<Compression> = compression_slot.and_then(|c| compression_slots.get(c as usize).copied().flatten());
  println!("Selected compression: {:?}", selected);

  match selected {
    None => decompressed.write_all(&data)?,
    Some(comp) => {
      let chunk_size = if ranges.len() == 1 {
          entry.uncompressed as usize
        } else {
          entry.compression_block_size as usize
        };

      match comp {
        Compression::Zlib => decompress!(flate2::read::ZlibDecoder<&[u8]>),
        Compression::Gzip => decompress!(flate2::read::GzDecoder<&[u8]>),
        Compression::Zstd => {
          for range in ranges {
            io::copy(&mut zstd::stream::read::Decoder::new(&data[range])?, &mut decompressed)?;
          }
        }
        Compression::LZ4 => {
          let mut loc_dec = vec![0; entry.uncompressed as usize];
          for (decomp_chunk, comp_range) in loc_dec.chunks_mut(chunk_size).zip(ranges) {
            lz4_flex::block::decompress_into(&data[comp_range], decomp_chunk)?;
          }

          decompressed.write_all(&loc_dec)?;
        }
        Compression::Oodle => {
          let mut loc_dec = vec![0; entry.uncompressed as usize];
          for (decomp_chunk, comp_range) in loc_dec.chunks_mut(chunk_size).zip(ranges) {
            let out = oodle_loader::oodle()?.decompress(&data[comp_range], decomp_chunk);
            if out == 0 {
              return Ok(());
            }
          }

          decompressed.write_all(&loc_dec)?;
        }
      }
    },
  }

  let str = String::from_utf8_lossy(&decompressed);
  println!("\nData:\n{}", str);

  Ok(())
}