// import logging function from host

use alloc::string::String;

#[cfg(not(test))]
extern "C" {
  fn host_log_string(ptr: *const u8, byte_count: usize);
}

#[cfg(test)]
fn host_log_string(ptr: *const u8, byte_count: usize) {
  let message_str = unsafe {
    std::str::from_utf8(core::slice::from_raw_parts(ptr, byte_count)).unwrap()
  };
  println!("{}", message_str);
}

pub fn log<T: Into<String>>(val: T) {
  let string: String = val.into();
  let len = string.len();
  let ptr = string.as_ptr();
  unsafe {
    host_log_string(ptr, len);
  }
}
