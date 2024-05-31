use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::time::Duration;

use hashlib::md5::{Md5, Md5Option};
use hashlib::prelude::HashAlgoKernel;
use rodio::{OutputStream, Source};
use walkdir::WalkDir;
use serde::{Deserialize, Serialize};
use toml::Value;

pub struct Utils;
#[derive(Serialize,Deserialize,Default)]
pub struct Config {
	pub apikey: String,
	pub audio: bool
}
impl Config {
	pub fn new() -> Result<Self, toml::de::Error> {
		let contents =std::fs::read_to_string("Config.toml").expect("Couldn't read Config.toml");

		let value = contents.parse::<Value>().expect("Couldn't parse Config.toml");
		println!("ok");
		let config = Config {
			apikey: value["virustotal"]["apikey"].as_str().unwrap().to_string(),
			audio: value["notifications"]["audio"].as_bool().unwrap(),
		};

		Ok(config)
	}
}

impl Utils {
	pub fn md5_files(path: &str) -> HashMap<String, String> {
		let mut hashes = HashMap::new();
		for entry in WalkDir::new(path)
			.into_iter()
			.filter_entry(|e| !e.path().to_str().unwrap().contains("System Volume Information"))
			.filter_map(|e| e.ok())
		{
			let path = entry.path();
			if path.is_file() {
				let mut file = match File::open(path) {
					Ok(file) => file,
					Err(e) => {
						eprintln!("Failed to open file {}: {}", path.display(), e);
						continue;
					}
				};
				let mut hasher = Md5::new(Md5Option::default());
				let mut buffer = [0; 1024];
				loop {
					let count = match file.read(&mut buffer) {
						Ok(count) => count,
						Err(e) => {
							eprintln!("Failed to read file {}: {}", path.display(), e);
							break;
						}
					};
					if count == 0 {
						break;
					}
					if let Err(_) = hasher.update(&buffer[0..count]) {
						eprintln!("Failed to update hash for file {}", path.display());
						break;
					}
				}
				let hash = match hasher.finalize() {
					Ok(hash) => format!("{:x}", hash),
					Err(_) => {
						eprintln!("Failed to finalize hash for file {}", path.display());
						continue;
					}
				};
				hashes.insert(path.to_str().unwrap().to_string(), hash);
			}
		}
		dbg!(&hashes);
		hashes
	}
	pub fn play_audio(path : &str) {
		let (_stream, stream_handle) = OutputStream::try_default().unwrap();
		let file = BufReader::new(File::open(path).unwrap());
		let source = rodio::Decoder::new(file).unwrap();
		stream_handle.play_raw(source.convert_samples()).unwrap();
		std::thread::sleep(Duration::from_secs(5));
	}
}


