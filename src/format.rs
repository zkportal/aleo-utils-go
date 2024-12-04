use core::{slice, iter, str};
use alloc::{vec::Vec, string::{ToString, String}};

use indexmap::IndexMap;
use snarkvm_console::{
  program::{Plaintext, Literal, Identifier, Value, U128},
  prelude::{FromStr, FromBytes, Result, ToBytes},
};

use crate::{
  log::log,
  memory::forget_buf_ptr_len,
  network::CurrentNetwork,
};

const CHUNK_SIZE: usize = 16*32;
const MAX_CHUNKS: usize = 32;

fn create_struct_key(prefix: &str, idx: usize) -> String {
  let mut key = String::from(prefix);
  key.push_str(idx.to_string().as_str());

  key
}

#[no_mangle]
pub extern "C" fn format_message(message: *const u8, message_len: usize, target_chunks: usize) -> u64 {
  if target_chunks < 1 || target_chunks > MAX_CHUNKS {
    log("number of chunks must be between 1 and 32");
    return 0;
  }

  if message_len > CHUNK_SIZE * target_chunks {
    log("message is too big to fit into specified number of chunks");
    return 0;
  }

  // Convert a pointer to a string into a string
  let message_bytes = unsafe {
    slice::from_raw_parts(message, message_len)
  };

  let mut buf = Vec::<u8>::with_capacity(target_chunks * CHUNK_SIZE);
  buf.extend_from_slice(message_bytes);

  // Calculate the remaining capacity and pad with zeroes if needed
  let remaining_capacity = buf.capacity() - buf.len();
  if remaining_capacity > 0 {
    buf.extend(iter::repeat(0).take(remaining_capacity));
  }

  // transform a byte array into an array of u128 by grouping bytes in chunks of 16
  let numbers: Result<Vec<U128<CurrentNetwork>>> = buf
    .array_chunks::<16>() // group bytes in chunks of 16 to transform into U128
    .map(|chunk| U128::from_bytes_le(chunk))
    .collect();

  if !numbers.is_ok() {
    return 0;
  }

  let numeric_message = numbers.unwrap().iter()
    .map(|number| { // transform an array of 16 u8s into an array of snarkVM u128 plaintext literals
      Plaintext::Literal(
        Literal::U128(*number),
        Default::default()
      )
    })
    .collect::<Vec<_>>();

  // build DataChunk
  let number_chunks = numeric_message.array_chunks::<32>().collect::<Vec<_>>();

  let mut i = 0;
  let mut data_map = IndexMap::with_capacity(target_chunks);
  while i < target_chunks {
    let mut chunk_map = IndexMap::with_capacity(32);

    // inner loop builds ReportDataChunk consisting of 32 u128s
    for (index, plaintext) in number_chunks[i].iter().enumerate() {
      let key = create_struct_key("f", index);
      chunk_map.insert(Identifier::<CurrentNetwork>::from_str(&key).unwrap(), plaintext.clone());
    }

    // outer loop builds a struct consisting of 1-32 DataChunks
    let key = create_struct_key("c", i);
    data_map.insert(Identifier::<CurrentNetwork>::from_str(&key).unwrap(), Plaintext::Struct(chunk_map, Default::default()));
    i += 1;
  }

  // build final value
  let value = Value::Plaintext(Plaintext::Struct(data_map, Default::default()));
  let output_str = value.to_string();
  let output_bytes = output_str.into_bytes();

  forget_buf_ptr_len(output_bytes)
}

#[no_mangle]
pub extern "C" fn formatted_message_to_bytes(formatted_message_ptr: *const u8, formatted_message_len: usize) -> u64 {
  if formatted_message_ptr == std::ptr::null() {
    log("empty argument");
    return 0;
  }

  // Convert a pointer to a string into a string
  let formatted_message = unsafe {
    match str::from_utf8(slice::from_raw_parts(formatted_message_ptr, formatted_message_len)) {
      Ok(val) => val,
      Err(e) => {
        let mut err_str = String::from("failed to rebuild formatted message string from pointer: ");
        err_str.push_str(e.to_string().as_str());

        log(err_str);

        return 0;
      },
    }
  };

  let value: Value<CurrentNetwork> = match Value::<CurrentNetwork>::from_str(formatted_message) {
    Ok(val) => val,
    Err(e) => {
      let mut err_str = String::from("cannot convert string to Leo Value: ");
      err_str.push_str(e.to_string().as_str());

      log(err_str);

      return 0;
    }
  };

  // formatted message is expected to be a plaintext struct
  let index_map = match value {
    Value::Plaintext(Plaintext::Struct(struct_, _)) => struct_,
    _ => {
      log("expected Leo struct, got unexpected type");
      return 0;
    }
  };

  let mut buf = Vec::<u8>::new();

  // iterate over all struct keys, check that they're following the expected format
  for (idx, key) in index_map.keys().enumerate() {
    let key_str = key.to_string();
    if key_str != create_struct_key("c", idx) || idx >= 32 {
      log("expected keys as c0..c31");
      return 0;
    }

    // extract the chunk value
    let chunk = index_map.get(key).unwrap();

    // check that the chunk struct is a struct
    let chunk_struct = match chunk {
      Plaintext::Struct(struct_, _) => struct_,
      _ => {
        log("expected struct value to be Leo struct, got unexpected type");
        return 0;
      }
    };

    // iteratre over all chunk keys, check that they're following the expected format, then extract the number values,
    // transform them into bytes
    for (chunk_key_idx, chunk_key) in chunk_struct.keys().enumerate() {
      let chunk_key_str = chunk_key.to_string();
      if chunk_key_str != create_struct_key("f", chunk_key_idx) || chunk_key_idx >= 32 {
        log("expected inner keys as f0..f31");
        return 0;
      }

      // extract a number value stored in the chunk
      let chunk_value = chunk_struct.get(chunk_key).unwrap();

      // check that it's a U128
      let chunk_number =  match chunk_value {
        Plaintext::Literal(Literal::U128(number), _) => number,
        _ => {
          log("expected chunk struct value to be Leo U128 type, got unexpected type");
          return 0;
        }
      };

      // collect LE bytes of U128
      let mut number_bytes = match chunk_number.to_bytes_le() {
        Ok(b) => b,
        Err(e) => {
          let mut err_str = String::from("failed to convert U128 value to bytes: ");
          err_str.push_str(e.to_string().as_str());

          log(err_str);

          return 0;
        }
      };

      buf.append(&mut number_bytes);
    }
  }

  forget_buf_ptr_len(buf)
}
