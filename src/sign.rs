use core::{str, slice, ptr};
use alloc::string::ToString;

use snarkvm_console::{
  account::{PrivateKey, Address},
  program::{Plaintext, Literal, U128},
  prelude::{FromStr, ToFields, Result, FromBytes},
};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
  log::log,
  memory::forget_buf_ptr,
  network::CurrentNetwork,
};

#[no_mangle]
pub extern "C" fn sign(private_key_str: *const u8, private_key_len: usize, hash_field_str: *const u8, hash_field_len: usize) -> *const u8 {
  // Convert a pointer to private key into a string
  let private_key = unsafe {
    match str::from_utf8(slice::from_raw_parts(private_key_str, private_key_len)) {
      Ok(val) => val,
      Err(_) => return ptr::null(),
    }
  };

  // Convert a pointer to message into a string
  let hash_field_string = unsafe {
    match str::from_utf8(slice::from_raw_parts(hash_field_str, hash_field_len)) {
      Ok(val) => val,
      Err(_) => "", // return empty if it's not a string
    }
  };

  let value: Result<Plaintext<CurrentNetwork>>;

  // check if we're dealing with byte value instead of a string value
  if hash_field_string == "" {
    let hash_field_bytes = unsafe {
      slice::from_raw_parts(hash_field_str, hash_field_len)
    };

    // when we're dealing with bytes, we only accept U128 number as LE bytes (should come from the hash)
    value = U128::<CurrentNetwork>::from_bytes_le(hash_field_bytes)
      .and_then(|num_value| Ok(Plaintext::Literal(Literal::U128(num_value), Default::default())));
  } else {
    value = Plaintext::<CurrentNetwork>::from_str(hash_field_string);
  }

  // convert hash field string into fields
  let fields = match value.and_then(|value| value.to_fields()) {
    Ok(val) => val,
    Err(e) => {
      log(e.to_string());
      return ptr::null();
    }
  };

  // Convert private key string into a PrivateKey or return nullptr
  let priv_key: PrivateKey<CurrentNetwork> = match PrivateKey::from_str(private_key) {
    Ok(pk) => pk,
    Err(e) => {
      log(e.to_string());
      return ptr::null();
    }
  };
  let addr = Address::try_from(priv_key).expect("converting a valid private key to address shouldn't fail");

  // Sign, convert the signature into a string, or return nullptr
  let signature = match priv_key.sign(&fields, &mut StdRng::from_entropy()) {
    Ok(sig) => sig,
    Err(e) => {
      log(e.to_string());
      return ptr::null();
    }
  };

  // self verify
  if !signature.verify(&addr, &fields) {
    log("signature self check failed");
    return ptr::null();
  }

  let output_bytes = signature.to_string().into_bytes();
  forget_buf_ptr(output_bytes)
}
