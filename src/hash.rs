use core::{str, slice};
use alloc::string::ToString;

use snarkvm_console::{
  program::{Value, Network, CastLossy, U128},
  network::Testnet3,
  prelude::*,
};

use crate::{
  log::log,
  memory::forget_buf_ptr_len,
};

#[no_mangle]
pub extern "C" fn hash_message(message: *const u8, message_len: usize) -> u64 {
  // Convert a pointer to a string into a string
  let message_str = unsafe {
    match str::from_utf8(slice::from_raw_parts(message, message_len)) {
      Ok(val) => val,
      Err(e) => {
        log(e.to_string());
        return 0;
      },
    }
  };

  let value = match Value::from_str(message_str) {
    Ok(val) => val,
    Err(e) => {
      log(e.to_string());
      return 0;
    }
  };

  // convert the string value into an array of fields
  let fields = match value.to_fields() {
    Ok(val) => val,
    Err(e) => {
      log(e.to_string());
      return 0;
    }
  };

  // hash the fields
  let hash = match Testnet3::hash_psd8(fields.as_slice()) {
    Ok(val) => val,
    Err(e) => {
      log(e.to_string());
      return 0;
    }
  };

  let hash_number: U128<Testnet3> = hash.cast_lossy();
  let hash_bytes = hash_number.to_string().into_bytes();

  forget_buf_ptr_len(hash_bytes)
}

#[no_mangle]
pub extern "C" fn hash_message_bytes(message: *const u8, message_len: usize) -> u64 {
  // Convert a pointer to a string into a string
  let message_str = unsafe {
    match str::from_utf8(slice::from_raw_parts(message, message_len)) {
      Ok(val) => val,
      Err(e) => {
        log(e.to_string());
        return 0;
      },
    }
  };

  let value = match Value::from_str(message_str) {
    Ok(val) => val,
    Err(e) => {
      log(e.to_string());
      return 0;
    }
  };

  // convert the string value into an array of fields
  let fields = match value.to_fields() {
    Ok(val) => val,
    Err(e) => {
      log(e.to_string());
      return 0;
    }
  };

  // hash the fields
  let hash = match Testnet3::hash_psd8(fields.as_slice()) {
    Ok(val) => val,
    Err(e) => {
      log(e.to_string());
      return 0;
    }
  };

  let hash_number: U128<Testnet3> = hash.cast_lossy();

  let hash_bytes = match hash_number.to_bytes_le() {
    Ok(val) => val,
    Err(e) => {
      log(e.to_string());
      return 0;
    }
  };

  forget_buf_ptr_len(hash_bytes)
}
