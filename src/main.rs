#[cfg(target_os="windows")]

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::ptr;
use std::time::Duration;

use chrono::Local;
use csv::Writer;
use hashlib::md5::Md5Option;
use hashlib::prelude::HashAlgoKernel;
use reqwest::Client;
use serde_json::Value;
use walkdir::WalkDir;
use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM};
use winapi::shared::windef::HWND;
use winapi::um::dbt::{DBT_DEVICEARRIVAL, DBT_DEVTYP_VOLUME, DEV_BROADCAST_HDR, DEV_BROADCAST_VOLUME};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::winuser::{self, COLOR_WINDOW, CS_VREDRAW, CW_USEDEFAULT, DefWindowProcW, IDC_ARROW, LoadCursorW, MSG, RegisterClassW, WM_DEVICECHANGE, WNDCLASSW, WS_OVERLAPPED, WS_SYSMENU};

#[derive(Eq, PartialEq)]
enum State {
	WaitingForDevice,
	HashingFiles,
	Reporting,
}

struct Notification {
	state: State,
	md5: Vec<String>,
	hashes: HashMap<String, String>,
}

impl Notification {
	fn new() -> Self {
		let class_name = "DeviceChangeDemo\0".encode_utf16().collect::<Vec<u16>>();
		let hinst = unsafe { GetModuleHandleW(ptr::null_mut()) };

		let wc = WNDCLASSW {
			style: CS_VREDRAW,
			lpfnWndProc: Some(Self::on_device_change),
			hInstance: hinst,
			lpszClassName: class_name.as_ptr(),
			hCursor: unsafe { LoadCursorW(ptr::null_mut(), IDC_ARROW) },
			hbrBackground: unsafe { winapi::um::wingdi::GetStockObject(COLOR_WINDOW) as _ },
			cbClsExtra: 0,
			cbWndExtra: 0,
			hIcon: ptr::null_mut(),
			lpszMenuName: ptr::null_mut(),
		};

		let class_atom = unsafe { RegisterClassW(&wc) };
		unsafe {
			winuser::CreateWindowExW(
				0,
				class_atom as *const u16,
				"Device Change Demo\0".encode_utf16().collect::<Vec<u16>>().as_ptr(),
				WS_OVERLAPPED | WS_SYSMENU,
				0,
				0,
				CW_USEDEFAULT,
				CW_USEDEFAULT,
				ptr::null_mut(),
				ptr::null_mut(),
				hinst,
				ptr::null_mut(),
			);
		}

		Self {
			state: State::WaitingForDevice,
			md5: vec![],
			hashes: Default::default(),
		}
	}

	unsafe extern "system" fn on_device_change(
		hwnd: HWND,
		msg: u32,
		wparam: WPARAM,
		lparam: LPARAM,
	) -> LRESULT {
		if msg == WM_DEVICECHANGE {
			let dev_broadcast_hdr = lparam as *const DEV_BROADCAST_HDR;

			if wparam == DBT_DEVICEARRIVAL {
				if (*dev_broadcast_hdr).dbch_devicetype == DBT_DEVTYP_VOLUME {
					println!("Device connected");
					let drive_letter = get_drive_letter(lparam);
					println!("Device {}", drive_letter);
					let path = format!("{}:\\", drive_letter);
					let hashes = md5_files(&path);
					// You might want to store the hashes and md5 values in the Notification struct here
					// Store hashes and md5 in Notification struct
				}
			}
		}

		DefWindowProcW(hwnd, msg, wparam, lparam)
	}

	pub async fn retrieve_vt_report(&self) {
		let url = "https://www.virustotal.com/vtapi/v2/file/report";
		let api = "";
		let mut count = 1;
		let mut to_scan = vec![];
		let file_to_open = format!("{}_malware_scan.csv", Local::now().format("%d-%m-%Y_%H-%M"));
		let headers = ["filename", "md5", "positives", "permalink"];
		let client = Client::new();

		let file = File::create(&file_to_open).unwrap();
		let mut wtr = Writer::from_writer(file);
		wtr.write_record(&headers).unwrap();

		for file_hash in &self.md5 {
			let params = [("apikey", api), ("resource", file_hash)];
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
						// if &self.audio {
						// Play audio
						// ...
						// }
						let permalink = report["permalink"].as_str().unwrap();
						if let Some(filename) = self.hashes.iter().find(|(_, v)| v == &file_hash).map(|(k, _)| k) {
							let row = [filename, file_hash, &positives.to_string(), permalink];
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

fn md5_files(path: &str) -> HashMap<String, String> {
	let mut hashes = HashMap::new();
	for entry in WalkDir::new(path) {
		let entry = entry.unwrap();
		let path = entry.path();
		if path.is_file() {
			let mut file = File::open(path).unwrap();
			let mut hasher = hashlib::md5::Md5::new(Md5Option::default());
			let mut buffer = [0; 1024];
			loop {
				let count = file.read(&mut buffer).unwrap();
				if count == 0 {
					break;
				}
				hasher.update(&buffer[0..count]).unwrap();
			}
			let hash = format!("{:x}", hasher.finalize().unwrap());
			hashes.insert(path.to_str().unwrap().to_string(), hash);
		}
	}
	hashes
}

unsafe fn get_drive_letter(lparam: LPARAM) -> char {
	let volume = lparam as *const DEV_BROADCAST_VOLUME;
	let mask = (*volume).dbcv_unitmask;
	let mut n_drive = 0;
	loop {
		if mask & (1 << n_drive) != 0 {
			break;
		}
		n_drive += 1;
	}
	(b'A' + n_drive) as char
}

#[tokio::main]
async fn main() {
	let w = Notification::new();

	// Pump messages
	let mut msg = MSG {
		hwnd: ptr::null_mut(),
		message: 0,
		wParam: 0 as WPARAM,
		lParam: 0 as LPARAM,
		time: 0,
		pt: winapi::shared::windef::POINT { x: 0, y: 0 },
	};

	unsafe {
		while winuser::GetMessageW(&mut msg, ptr::null_mut(), 0, 0) != 0 {
			if w.state == State::HashingFiles {
				w.retrieve_vt_report().await;
			}
			winuser::TranslateMessage(&msg);
			winuser::DispatchMessageW(&msg);
		}
	}
}