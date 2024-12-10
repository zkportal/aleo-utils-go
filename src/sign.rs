use core::{str, slice, ptr};
use alloc::string::ToString;

use snarkvm_console::{
  account::{Address, PrivateKey}, prelude::{FromBytes, FromStr, ToFields},
  program::{Literal, Plaintext, U128},
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
      Err(e) => {
        let mut err_str = String::from("failed to rebuild private key string from pointer: ");
        err_str.push_str(e.to_string().as_str());

        log(err_str);

        return ptr::null()
      }
    }
  };

  // Convert private key string into a PrivateKey or return nullptr
  let priv_key: PrivateKey<CurrentNetwork> = match PrivateKey::from_str(private_key) {
    Ok(pk) => pk,
    Err(e) => {
      let mut err_str = String::from("failed to parse private key from string: ");
      err_str.push_str(e.to_string().as_str());

      log(err_str);

      return ptr::null();
    }
  };

  // get the public key of the private key
  let addr = match Address::try_from(priv_key) {
    Ok(val) => val,
    Err(e) => {
      let mut err_str = String::from("failed to convert a private key to address: ");
      err_str.push_str(e.to_string().as_str());

      log(err_str);

      return ptr::null();
    }
  };

  // restore the data for signing slice from the pointer
  let hash_field_bytes = unsafe {
    slice::from_raw_parts(hash_field_str, hash_field_len)
  };

  // when we're dealing with bytes, we only accept U128 number as LE bytes (should come from the hash)
  // first we create a u128 value, then turn it into a plaintext literal, then get fields of that literal
  let fields_for_signing = match U128::<CurrentNetwork>::from_bytes_le(hash_field_bytes)
    .and_then(|integer| Ok(Plaintext::Literal(Literal::U128(integer), Default::default())))
    .and_then(|plaintext| plaintext.to_fields()) {
      Ok(val) => val,
      Err(e) => {
        let mut err_str = String::from("failed to parse u128 plaintext value from bytes: ");
        err_str.push_str(e.to_string().as_str());

        log(err_str);

        return ptr::null();
    },
  };

  // Sign, convert the signature into a string, or return nullptr
  let signature = match priv_key.sign(&fields_for_signing, &mut StdRng::from_entropy()) {
    Ok(sig) => sig,
    Err(e) => {
      let mut err_str = String::from("failed to sign fields with private key: ");
      err_str.push_str(e.to_string().as_str());

      log(err_str);

      return ptr::null();
    }
  };

  // self verify
  if !signature.verify(&addr, &fields_for_signing) {
    log("signature self check failed");
    return ptr::null();
  }

  let output_bytes = signature.to_string().into_bytes();
  forget_buf_ptr(output_bytes)
}
