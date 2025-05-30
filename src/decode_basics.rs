use crate::types::{EthernetHeader, IECData};

/// Decodes a boolean value from a buffer at the specified position.
///
/// # Parameters
/// - `value`: A mutable reference where the decoded boolean will be stored.
/// - `buffer`: The input byte slice containing the encoded data.
/// - `buffer_index`: The position in the buffer to read the boolean value from.
///
/// # Returns
/// The next position in the buffer after reading the boolean value.
///
/// # Panics
/// Panics if `buffer_index` is out of bounds for the buffer.
pub fn decode_boolean(buffer: &[u8], buffer_index: usize) -> (bool, usize) {
    if buffer_index >= buffer.len() {
        panic!(
            "Position {} is out of bounds for buffer of length {}",
            buffer_index,
            buffer.len()
        );
    }

    let value = buffer[buffer_index] != 0;
    (value, buffer_index + 1)
}

/// Decodes a UTF-8 string from the buffer at the specified position and length.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded data.
/// - `buffer_index`: The starting position in the buffer to read the string from.
/// - `length`: The number of bytes to read for the string.
///
/// # Returns
/// A tuple containing the decoded string and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
pub fn decode_string(buffer: &[u8], buffer_index: usize, length: usize) -> (String, usize) {
    if buffer_index + length > buffer.len() {
        panic!(
            "Attempt to read {} bytes from position {} exceeds buffer length {}",
            length,
            buffer_index,
            buffer.len()
        );
    }
    let value = String::from_utf8_lossy(&buffer[buffer_index..buffer_index + length]).to_string();
    (value, buffer_index + length)
}

/// Decodes an octet string (raw bytes) from the buffer at the specified position and length.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded data.
/// - `buffer_index`: The starting position in the buffer to read the octet string from.
/// - `length`: The number of bytes to read for the octet string.
///
/// # Returns
/// A tuple containing a `Vec<u8>` with the decoded bytes and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
pub fn decode_octet_string(buffer: &[u8], buffer_index: usize, length: usize) -> (Vec<u8>, usize) {
    if buffer_index + length > buffer.len() {
        panic!(
            "Attempt to read {} bytes from position {} exceeds buffer length {}",
            length,
            buffer_index,
            buffer.len()
        );
    }
    let value = buffer[buffer_index..buffer_index + length].to_vec();
    (value, buffer_index + length)
}

/// Decompresses an ASN.1 BER encoded integer from the buffer into the provided value slice,
/// restoring it to its full width (e.g., i32, i64) with correct sign extension.
///
/// # Parameters
/// - `value`: The output buffer (e.g., 4 or 8 bytes) to store the decompressed integer (big-endian).
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length,
/// or if `length` is greater than `value.len()`.
pub fn decompress_integer(value: &mut [u8], buffer: &[u8], buffer_index: usize, length: usize) {
    if buffer_index + length > buffer.len() {
        panic!(
            "Attempt to read {} bytes from position {} exceeds buffer length {}",
            length,
            buffer_index,
            buffer.len()
        );
    }
    if length > value.len() {
        panic!(
            "Encoded integer length {} exceeds output buffer size {}",
            length,
            value.len()
        );
    }

    // Determine fill byte for sign extension (0xFF for negative, 0x00 for positive)
    let fill = if buffer[buffer_index] & 0x80 == 0x80 {
        0xFF
    } else {
        0x00
    };

    // Fill the leading bytes with the sign extension
    let fill_length = value.len() - length;
    for i in 0..fill_length {
        value[i] = fill;
    }

    // Copy the encoded integer bytes into the lower part of the output buffer
    value[fill_length..].copy_from_slice(&buffer[buffer_index..buffer_index + length]);
}

/// Decodes an ASN.1 BER encoded 8-bit integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// A tuple containing the decoded `i8` value and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
pub fn decode_integer_8(buffer: &[u8], buffer_index: usize, length: usize) -> (i8, usize) {
    let mut value_bytes = [0u8; 1];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length);
    let value = i8::from_be_bytes(value_bytes);
    (value, buffer_index + length)
}

/// Decodes an ASN.1 BER encoded 16-bit integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// A tuple containing the decoded `i16` value and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
pub fn decode_integer_16(buffer: &[u8], buffer_index: usize, length: usize) -> (i16, usize) {
    let mut value_bytes = [0u8; 2];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length);
    let value = i16::from_be_bytes(value_bytes);
    (value, buffer_index + length)
}

/// Decodes an ASN.1 BER encoded 32-bit integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// A tuple containing the decoded `i32` value and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
pub fn decode_integer_32(buffer: &[u8], buffer_index: usize, length: usize) -> (i32, usize) {
    let mut value_bytes = [0u8; 4];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length);
    let value = i32::from_be_bytes(value_bytes);
    (value, buffer_index + length)
}

/// Decodes an ASN.1 BER encoded 64-bit integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// A tuple containing the decoded `i64` value and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
pub fn decode_integer_64(buffer: &[u8], buffer_index: usize, length: usize) -> (i64, usize) {
    let mut value_bytes = [0u8; 8];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length);
    let value = i64::from_be_bytes(value_bytes);
    (value, buffer_index + length)
}

/// Decodes an ASN.1 BER encoded 16-bit unsigned integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// A tuple containing the decoded `u16` value and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
pub fn decode_unsigned_16(buffer: &[u8], buffer_index: usize, length: usize) -> (u16, usize) {
    let mut value_bytes = [0u8; 2];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length);
    let value = u16::from_be_bytes(value_bytes);
    (value, buffer_index + length)
}

/// Decodes an ASN.1 BER encoded 32-bit unsigned integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// A tuple containing the decoded `u32` value and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
pub fn decode_unsigned_32(buffer: &[u8], buffer_index: usize, length: usize) -> (u32, usize) {
    let mut value_bytes = [0u8; 4];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length);
    let value = u32::from_be_bytes(value_bytes);
    (value, buffer_index + length)
}

/// Decodes an IEC 61850-7-2 encoded 32-bit IEEE 754 float from the buffer at the specified position.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded float.
/// - `buffer_index`: The starting position in the buffer to read the float from.
/// - `length`: The number of bytes used for the encoded float in the buffer (should be 5: 1 descriptor + 4 value bytes).
///
/// # Returns
/// A tuple containing the decoded `f32` value and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index+1..buffer_index+5) exceeds the buffer length.
pub fn decode_float_32(buffer: &[u8], buffer_index: usize, length: usize) -> (f32, usize) {
    if buffer_index + 5 > buffer.len() {
        panic!(
            "Attempt to read 4 bytes for f32 from position {} exceeds buffer length {}",
            buffer_index + 1,
            buffer.len()
        );
    }
    // Skip the descriptor byte (at buffer_index), read the next 4 bytes as IEEE 754 float
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buffer[buffer_index + 1..buffer_index + 5]);
    let value = f32::from_be_bytes(bytes);
    (value, buffer_index + length)
}

/// Decodes an IEC 61850-7-2 encoded 64-bit IEEE 754 float from the buffer at the specified position.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded float.
/// - `buffer_index`: The starting position in the buffer to read the float from.
/// - `length`: The number of bytes used for the encoded float in the buffer (should be 9: 1 descriptor + 8 value bytes).
///
/// # Returns
/// A tuple containing the decoded `f64` value and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index+1..buffer_index+9) exceeds the buffer length.
pub fn decode_float_64(buffer: &[u8], buffer_index: usize, length: usize) -> (f64, usize) {
    if buffer_index + 9 > buffer.len() {
        panic!(
            "Attempt to read 8 bytes for f64 from position {} exceeds buffer length {}",
            buffer_index + 1,
            buffer.len()
        );
    }
    // Skip the descriptor byte (at buffer_index), read the next 8 bytes as IEEE 754 float
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buffer[buffer_index + 1..buffer_index + 9]);
    let value = f64::from_be_bytes(bytes);
    (value, buffer_index + length)
}

/// Decodes an IEC 61850-8-1 coded enum (BIT STRING) from the buffer at the specified position and length.
///
/// This function reads the padding byte and then decodes the value bytes in reverse order and with bits reversed,
/// as required by IEC 61850-8-1 for coded enums.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded BIT STRING.
/// - `buffer_index`: The starting position in the buffer to read the BIT STRING from.
/// - `length`: The number of bytes used for the encoded BIT STRING (including the padding byte).
///
/// # Returns
/// A tuple containing a tuple of the decoded value bytes (`Vec<u8>`) and the padding (`u8`),
/// and the next position in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
pub fn decode_bit_string(
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> ((Vec<u8>, u8), usize) {
    if buffer_index + length > buffer.len() {
        panic!(
            "Attempt to read {} bytes from position {} exceeds buffer length {}",
            length,
            buffer_index,
            buffer.len()
        );
    }

    let padding = buffer[buffer_index];
    let value_len = length - 1;
    let mut value = vec![0u8; value_len];

    // Fill value in reverse order and with bits reversed (IEC 61850-8-1 coded enum)
    for i in 0..value_len {
        value[value_len - i - 1] = buffer[buffer_index + 1 + i].reverse_bits();
    }

    ((value, padding), buffer_index + length)
}

/// Decodes an ASN.1 BER tag and length field from the buffer at the specified position.
///
/// This function supports definite-length encoding with up to 3 length bytes (sufficient for most practical uses).
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded tag and length.
/// - `buffer_index`: The starting position in the buffer to read the tag and length from.
///
/// # Returns
/// A tuple containing the decoded tag (`u8`), the decoded length (`usize`), and the next position in the buffer.
///
/// # Panics
/// Panics if the buffer does not contain enough bytes to decode the tag and length.
pub fn decode_tag_length(buffer: &[u8], buffer_index: usize) -> (u8, usize, usize) {
    if buffer_index >= buffer.len() {
        panic!(
            "decode_tag_length: buffer_index {} out of bounds for buffer length {}",
            buffer_index,
            buffer.len()
        );
    }

    let tag = buffer[buffer_index];
    let mut pos = buffer_index + 1;

    if pos >= buffer.len() {
        panic!(
            "decode_tag_length: missing length byte after tag at position {}",
            buffer_index
        );
    }

    let first_len_byte = buffer[pos];
    pos += 1;

    let length: usize = if first_len_byte & 0x80 == 0 {
        // Short form: single byte length (0..127)
        first_len_byte as usize
    } else {
        // Long form: lower 7 bits indicate number of length bytes
        let num_len_bytes = (first_len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 3 {
            panic!(
                "decode_tag_length: unsupported or invalid number of length bytes: {}",
                num_len_bytes
            );
        }
        if pos + num_len_bytes > buffer.len() {
            panic!(
                "decode_tag_length: not enough bytes for {}-byte length at position {}",
                num_len_bytes, pos
            );
        }
        let mut len = 0usize;
        for _ in 0..num_len_bytes {
            len = (len << 8) | buffer[pos] as usize;
            pos += 1;
        }
        len
    };

    (tag, length, pos)
}

/// Decodes a single IECData element from the buffer at the specified position.
///
/// This function reads the tag and length, then decodes the value according to the tag,
/// supporting various IEC 61850 and ASN.1 BER types (booleans, integers, floats, strings, arrays, structures, etc.).
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded IECData element.
/// - `buffer_index`: The starting position in the buffer to read from.
///
/// # Returns
/// A tuple with the new buffer position and the decoded IECData element.
fn decode_iec_data_element(buffer: &[u8], buffer_index: usize) -> (usize, IECData) {
    let (tag, length, new_buffer_index) = decode_tag_length(buffer, buffer_index);

    match tag {
        // Boolean
        0x83 => {
            let (val, next_buffer_index) = decode_boolean(buffer, new_buffer_index);
            (next_buffer_index, IECData::Boolean(val))
        }
        // Signed integers (various sizes)
        0x85 => match length {
            1 => {
                let (val, next_buffer_index) = decode_integer_8(buffer, new_buffer_index, length);
                (next_buffer_index, IECData::Int8(val))
            }
            2 => {
                let (val, next_buffer_index) = decode_integer_16(buffer, new_buffer_index, length);
                (next_buffer_index, IECData::Int16(val))
            }
            3..=4 => {
                let (val, next_buffer_index) = decode_integer_32(buffer, new_buffer_index, length);
                (next_buffer_index, IECData::Int32(val))
            }
            5..=8 => {
                let (val, next_buffer_index) = decode_integer_64(buffer, new_buffer_index, length);
                (next_buffer_index, IECData::Int64(val))
            }
            _ => panic!("oversize signed integer at {}", new_buffer_index),
        },
        // Unsigned integers (various sizes)
        0x86 => match length {
            1 => {
                let (val, next_buffer_index) = decode_unsigned_16(buffer, new_buffer_index, length);
                (next_buffer_index, IECData::Int8u(val as u8))
            }
            2 => {
                let (val, next_buffer_index) = decode_unsigned_16(buffer, new_buffer_index, length);
                (next_buffer_index, IECData::Int16u(val))
            }
            3..=4 => {
                let (val, next_buffer_index) = decode_unsigned_32(buffer, new_buffer_index, length);
                (next_buffer_index, IECData::Int32u(val))
            }
            5..=8 => panic!("oversize unsigned integer at {}", new_buffer_index),
            _ => panic!("oversize unsigned integer at {}", new_buffer_index),
        },
        // Floating point numbers
        0x87 => match length {
            5 => {
                let (val, next_buffer_index) = decode_float_32(buffer, new_buffer_index, length);
                (next_buffer_index, IECData::Float32(val))
            }
            9 => {
                let (val, next_buffer_index) = decode_float_64(buffer, new_buffer_index, length);
                (next_buffer_index, IECData::Float64(val))
            }
            _ => panic!("unexpected size float at {}", new_buffer_index),
        },
        // Visible string
        0x8a => {
            let (val, next_buffer_index) = decode_string(buffer, new_buffer_index, length);
            (next_buffer_index, IECData::VisibleString(val))
        }
        // MMS string
        0x90 => {
            let (val, next_buffer_index) = decode_string(buffer, new_buffer_index, length);
            (next_buffer_index, IECData::MmsString(val))
        }
        // Bit string (coded enum)
        0x84 => {
            let ((val, padding), next_buffer_index) =
                decode_bit_string(buffer, new_buffer_index, length);
            (next_buffer_index, IECData::BitString { val, padding })
        }
        // Array
        0xa1 => {
            let (val, next_buffer_index) =
                decode_iec_data(buffer, new_buffer_index, new_buffer_index + length);
            (next_buffer_index, IECData::Array(val))
        }
        // Structure
        0xa2 => {
            let (val, next_buffer_index) =
                decode_iec_data(buffer, new_buffer_index, new_buffer_index + length);
            (next_buffer_index, IECData::Structure(val))
        }
        // Octet string
        0x89 => {
            let (val, next_buffer_index) = decode_octet_string(buffer, new_buffer_index, length);
            (next_buffer_index, IECData::OctetString(val))
        }
        // UTC time
        0x91 => {
            let (val, next_buffer_index) = decode_octet_string(buffer, new_buffer_index, length);
            if val.len() == 8 {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&val);
                (next_buffer_index, IECData::UtcTime(arr))
            } else {
                panic!("invalid utc_time length at {}", new_buffer_index)
            }
        }
        // Unknown or unsupported tag
        _ => panic!("unknown data type at {}", new_buffer_index),
    }
}

/// Decodes a sequence of IECData elements from the buffer, returning a vector of decoded elements.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded IECData elements.
/// - `start_pos`: The starting position in the buffer to read from.
/// - `end_pos`: The position in the buffer where decoding should stop.
///
/// # Returns
/// A tuple with the vector of decoded IECData elements and the next position in the buffer.
pub fn decode_iec_data(buffer: &[u8], start_pos: usize, end_pos: usize) -> (Vec<IECData>, usize) {
    let mut new_pos = start_pos;
    let mut data = Vec::new();

    while new_pos < end_pos {
        let (next_pos, new_data) = decode_iec_data_element(buffer, new_pos);
        data.push(new_data);
        new_pos = next_pos;
    }

    (data, new_pos)
}

pub fn decode_ethernet_header(buffer: &[u8]) -> (EthernetHeader, usize) {
    let mut new_pos = 0;
    let mut header = EthernetHeader::default();

    header
        .dst_addr
        .copy_from_slice(&buffer[new_pos..new_pos + 6]);
    new_pos += 6;

    header
        .src_addr
        .copy_from_slice(&buffer[new_pos..new_pos + 6]);
    new_pos += 6;

    header.tpid.copy_from_slice(&buffer[new_pos..new_pos + 2]);

    // VLAN tag present
    if header.tpid == [0x81, 0x00] {
        new_pos += 2;

        header.tci.copy_from_slice(&buffer[new_pos..new_pos + 2]);
        new_pos += 2;
    }

    header
        .ether_type
        .copy_from_slice(&buffer[new_pos..new_pos + 2]);
    new_pos += 2;

    header.appid.copy_from_slice(&buffer[new_pos..new_pos + 2]);
    new_pos += 2;

    header.length.copy_from_slice(&buffer[new_pos..new_pos + 2]);
    new_pos += 2;

    new_pos += 2; // reserved 1
    new_pos += 2; // reserved 2

    (header, new_pos)
}
