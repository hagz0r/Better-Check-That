use std::ptr;

use winapi::shared::minwindef::{LPARAM, WPARAM};
use winapi::um::dbt::DEV_BROADCAST_VOLUME;
use winapi::um::winuser::{self, MSG};

use crate::notification::{HASHES, Notification};
use crate::virustotal::VirusTotal;

mod notification;
mod virustotal;
mod utils;

#[derive(Eq, PartialEq)]
enum State {
	WaitingForDevice,
	HashingFiles,
	Reporting,
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
	let mut w = Notification::new();
	let vt = virustotal::VirusTotal::new();


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
				println!("OK");
				let hashes = HASHES.lock().unwrap().take().unwrap();
				let md5 = hashes.values().cloned().collect();
				w.state = State::Reporting;
				vt.retrieve_vt_report(md5, hashes).await;
				println!("OK");

			}
			winuser::TranslateMessage(&msg);
			winuser::DispatchMessageW(&msg);
		}
	}
}

