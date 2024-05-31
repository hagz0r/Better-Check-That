use std::collections::HashMap;
use std::fs::File;
use std::time::Duration;

use chrono::Local;
use csv::Writer;
use reqwest::Client;
use serde_json::Value;
use crate::utils::{Config, Utils};

pub struct VirusTotal {
	config:Config
}

impl VirusTotal {
	pub fn new() -> Self {
		Self {
			config:Config::new().unwrap()
		}
	}

	pub async fn retrieve_vt_report(&self, md5: Vec<String>, hashes: HashMap<String, String>) {
		
						 Utils::play_audio("audio/detection.mp3");	

		println!("OK");
		let url = "https://www.virustotal.com/vtapi/v2/file/report";
		let mut count = 1;
		let mut to_scan = vec![];
		let file_to_open = format!("{}_malware_scan.csv", Local::now().format("%d-%m-%Y_%H-%M"));
		let headers = ["filename", "md5", "positives", "permalink"];
		let client = Client::new();

		let file = File::create(&file_to_open).unwrap();
		let mut wtr = Writer::from_writer(file);
		wtr.write_record(&headers).unwrap();

		for file_hash in md5 {
			let params = [("apikey", &self.config.apikey), ("resource", &file_hash)];
			let res = client.post(url).form(&params).send().await.unwrap();

			if res.status().is_success() {
				let report: Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
				println!("{:?}", report);
				println!("{}", report["response_code"]);

				if report["response_code"] == 0 {
					to_scan.push(file_hash.clone());
				} else {
					let positives = report["positives"].as_i64().unwrap();
					if positives != 0 {
						println!("OK");
						// if self.config.audio{
						// }
						let permalink = report["permalink"].as_str().unwrap();
						if let Some(filename) = hashes.iter().find(|(_, v)| *v == &file_hash).map(|(k, _)| k) {
							let row = [filename, &file_hash, &positives.to_string(), permalink];
							wtr.write_record(&row).unwrap();
						}
					}
				}
			}

			// Due to public api limitations
			if count % 4 == 0 {
				async_std::task::sleep(Duration::from_secs(60)).await;
				count += 1;
			}
		}
	}
}
