use byteorder::{ReadBytesExt, LE};

pub trait ReadExt {
  fn read_bool(&mut self) -> Result<bool, std::io::Error>;
  fn read_guid(&mut self) -> Result<[u8; 20], std::io::Error>;
  fn read_array<T>(
    &mut self,
    func: impl FnMut(&mut Self) -> Result<T, std::io::Error>,
  ) -> Result<Vec<T>, std::io::Error>;
  fn read_array_len<T>(
    &mut self,
    len: usize,
    func: impl FnMut(&mut Self) -> Result<T, std::io::Error>,
  ) -> Result<Vec<T>, std::io::Error>;
  fn read_string(&mut self) -> Result<String, std::io::Error>;
  fn read_len(&mut self, len: usize) -> Result<Vec<u8>, std::io::Error>;
}

#[cfg(feature = "online")]
pub trait ReadSeek: std::io::Read + std::io::Seek {}
#[cfg(feature = "online")]
impl<T: std::io::Read + std::io::Seek> ReadSeek for T {}

#[cfg(feature = "file")]
pub trait ReadSeek: std::io::Read {}
#[cfg(feature = "file")]
impl<T: std::io::Read> ReadSeek for T {}

impl<R: ReadSeek> ReadExt for R {
  fn read_bool(&mut self) -> Result<bool, std::io::Error> {
    match self.read_u8()? {
      1 => Ok(true),
      0 => Ok(false),
      _ => Ok(false), // TODO
    }
  }

  fn read_guid(&mut self) -> Result<[u8; 20], std::io::Error> {
    let mut guid = [0; 20];
    self.read_exact(&mut guid)?;
    Ok(guid)
  }

  fn read_array<T>(
    &mut self,
    func: impl FnMut(&mut Self) -> Result<T, std::io::Error>,
  ) -> Result<Vec<T>, std::io::Error> {
    let len = self.read_u32::<LE>()? as usize;
    self.read_array_len(len, func)
  }

  fn read_array_len<T>(
    &mut self,
    len: usize,
    mut func: impl FnMut(&mut Self) -> Result<T, std::io::Error>,
  ) -> Result<Vec<T>, std::io::Error> {
    let mut buf = Vec::with_capacity(len);
    for _ in 0..buf.capacity() {
      buf.push(func(self)?);
    }
    Ok(buf)
  }

  fn read_string(&mut self) -> Result<String, std::io::Error> {
    let len = self.read_i32::<LE>()?;
    if len < 0 {
      let chars = self.read_array_len((-len) as usize, |r| Ok(r.read_u16::<LE>()?))?;
      let length = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
      Ok(String::from_utf16(&chars[..length]).unwrap())
    } else {
      let mut chars = vec![0; len as usize];
      self.read_exact(&mut chars)?;
      let length = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
      Ok(String::from_utf8_lossy(&chars[..length]).into_owned())
    }
  }

  fn read_len(&mut self, len: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = vec![0; len];
    self.read_exact(&mut buf)?;
    Ok(buf)
  }
}