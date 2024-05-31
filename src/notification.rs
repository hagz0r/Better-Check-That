use std::collections::HashMap;
use std::ptr;
use std::sync::Mutex;

use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM};
use winapi::shared::windef::HWND;
use winapi::um::dbt::{DBT_DEVICEARRIVAL, DBT_DEVTYP_VOLUME, DEV_BROADCAST_HDR};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::winuser;
use winapi::um::winuser::{COLOR_WINDOW, CS_VREDRAW, CW_USEDEFAULT, DefWindowProcW, IDC_ARROW, LoadCursorW, RegisterClassW, WM_DEVICECHANGE, WNDCLASSW, WS_OVERLAPPED, WS_SYSMENU};

use crate::{get_drive_letter, State};
use crate::utils::Utils;

pub static HASHES: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

pub static PATH: Mutex<Option<String>> = Mutex::new(None);
pub struct Notification {
	pub state: State,
}

impl Notification {
	pub fn new() -> Self {
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
					let hashes = Utils::md5_files(&path);

					*HASHES.lock().unwrap() = Some(hashes);
					*PATH.lock().unwrap() = Some(path);
				}
			}
		}

		DefWindowProcW(hwnd, msg, wparam, lparam)
	}
}
