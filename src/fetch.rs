use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;

const MAX_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

pub async fn get_size(url: &str) -> Result<usize, Box<dyn std::error::Error>> {
  let mut headers = HeaderMap::new();
  headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_static(USER_AGENT));
  headers.insert(reqwest::header::CONNECTION, HeaderValue::from_static("keep-alive"));

  let client = Client::builder()
    .timeout(MAX_TIMEOUT)
    .default_headers(headers)
    .build()?;

  let resp = client.head(url).send().await?;
  let size = resp
    .headers()
    .get(reqwest::header::CONTENT_LENGTH)
    .ok_or("Tidak ada Content-Length")?
    .to_str()?
    .parse::<usize>()?;

  Ok(size)
}

pub async fn fetch_range(url: &str, from: usize, to: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
  let mut headers = HeaderMap::new();
  headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_static(USER_AGENT));
  headers.insert(reqwest::header::CONNECTION, HeaderValue::from_static("keep-alive"));

  let range_header = format!("bytes={}-{}", from, to);
  headers.insert(reqwest::header::RANGE, HeaderValue::from_str(&range_header)?);

  let client = Client::builder()
    .timeout(MAX_TIMEOUT)
    .default_headers(headers)
    .build()?;
  
  let resp = client.get(url).send().await?;
  if !resp.status().is_success() {
    return Err(format!("HTTP error: {}", resp.status()).into());
  }
  
  let bytes = resp.bytes().await?.to_vec();
  // println!(
  //   "Fetched {} bytes (range {}-{})",
  //   bytes.len(),
  //   from,
  //   to
  // );

  Ok(bytes)
}