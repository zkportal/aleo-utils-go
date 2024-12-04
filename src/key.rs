use core::{str, slice, ptr};
use alloc::string::ToString;

use snarkvm_console::{
  account::{PrivateKey, Address},
  prelude::FromStr,
};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
  log::log,
  memory::forget_buf_ptr,
  network::CurrentNetwork,
};

#[no_mangle]
pub extern "C" fn new_private_key() -> *const u8 {
  let pk = match PrivateKey::<CurrentNetwork>::new(&mut StdRng::from_entropy()) {
    Ok(val) => val.to_string(),
    Err(e) => {
      let mut err_str = String::from("failed to generate new private key: ");
      err_str.push_str(e.to_string().as_str());

      log(err_str);

      return ptr::null();
    }
  };

  let output_bytes = pk.into_bytes();
  forget_buf_ptr(output_bytes)
}

#[no_mangle]
pub extern "C" fn get_address(private_key: *const u8, private_key_len: usize) -> *const u8 {
  // Convert the input string to a Rust string
  let private_key_str = unsafe {
    match str::from_utf8(slice::from_raw_parts(private_key, private_key_len)) {
      Ok(val) => val,
      Err(e) => {
        let mut err_str = String::from("failed to rebuild private key string from pointer: ");
        err_str.push_str(e.to_string().as_str());

        log(err_str);

        return ptr::null();
      }
    }
  };

  // Convert the private key string into a PrivateKey
  let priv_key: PrivateKey<CurrentNetwork> = match PrivateKey::from_str(private_key_str) {
    Ok(pk) => pk,
    Err(e) => {
      let mut err_str = String::from("failed to parse private key from string: ");
      err_str.push_str(e.to_string().as_str());

      log(err_str);

      return ptr::null();
    }
  };

  // Get address from the private key or return null ptr
  let address = match Address::<CurrentNetwork>::try_from(priv_key) {
    Ok(addr) => addr.to_string(),
    Err(e) => {
      let mut err_str = String::from("failed to convert a private key to address: ");
      err_str.push_str(e.to_string().as_str());

      log(err_str);

      return ptr::null();
    }
  };

  let output_bytes = address.into_bytes();
  forget_buf_ptr(output_bytes)
}
