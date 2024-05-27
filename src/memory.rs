use alloc::vec::Vec;
use core::mem;

pub fn forget_buf_ptr(buf: Vec<u8>) -> *const u8 {
  let ptr = buf.as_ptr();
  mem::forget(buf);

  ptr
}

pub fn forget_buf_ptr_len(buf: Vec<u8>) -> u64 {
  let len = buf.len() as u64;
  let output_ptr = buf.as_ptr() as u64;
  mem::forget(buf);

  // The higher 32 bits are a buffer length, the lower 32 bits are a pointer to the buffer.
  (len << 32) | output_ptr
}

#[no_mangle]
pub extern "C" fn alloc(capacity: usize) -> *const u8 {
  let buffer = Vec::with_capacity(capacity);
  forget_buf_ptr(buffer)
}

#[no_mangle]
pub extern "C" fn dealloc(pointer: *const u8, capacity: usize) {
  unsafe {
    let _ = Vec::from_raw_parts(pointer.cast_mut(), 0, capacity);
  }
}
