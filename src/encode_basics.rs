use crate::types::{EncodeError, IECData};

/// Returns the minimal two's complement representation of a signed integer as a byte slice.
/// This is used for ASN.1 BER INTEGER encoding.
pub fn minimal_twos_complement_bytes(value: &[u8]) -> &[u8] {
    let mut significant_start = 0;
    while significant_start < value.len() - 1 {
        let curr = value[significant_start];
        let next = value[significant_start + 1];
        if (curr == 0x00 && (next & 0x80) == 0) || (curr == 0xFF && (next & 0x80) == 0x80) {
            significant_start += 1;
        } else {
            break;
        }
    }
    &value[significant_start..]
}

/// Returns the number of bytes required to encode the length field in ASN.1 BER format.
///
/// This function determines how many bytes are needed to represent the given length value
/// according to BER rules:
/// - 1 byte for values < 128 (short form)
/// - 2 bytes for values < 256 (0x81 + 1 byte)
/// - 3 bytes for values < 65536 (0x82 + 2 bytes)
/// - 4 bytes for larger values (0x83 + 3 bytes)
pub fn size_length(value: usize) -> usize {
    if value < 128 {
        return 1;
    } else if value < 256 {
        return 2;
    } else if value < 65535 {
        return 3;
    } else {
        return 4;
    }
}

/// Encodes an ASN.1 tag and its length field using BER rules.
///
/// This function writes the tag and the length field into the provided buffer at `buffer_index`.
/// The length is encoded in short or long form depending on its value:
/// - For values < 128, the length is encoded in a single byte.
/// - For values < 256, the length is encoded as 0x81 followed by one byte.
/// - For values < 65536, the length is encoded as 0x82 followed by two bytes (big-endian).
/// - For larger values, the length is encoded as 0x83 followed by three bytes (big-endian).
///
/// # Parameters
/// - `tag`: The ASN.1 tag to write.
/// - `value`: The length value to encode.
/// - `buffer`: The output buffer.
/// - `buffer_index`: The position in the buffer to start writing.
///
/// # Returns
/// Result with the new position in the buffer after writing the tag and length, or EncodeError.
pub fn encode_tag_length(
    tag: u8,
    value: usize,
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    let required = 1 + size_length(value); // 1 for tag, rest for length field

    if buffer.len() < buffer_index + required {
        return Err(EncodeError::new(
            "Buffer too small to write tag and length.",
            buffer_index,
        ));
    }

    let mut new_pos = buffer_index;
    buffer[new_pos] = tag;
    new_pos += 1;

    // Now encode the length field as before
    if value < 128 {
        buffer[new_pos] = value as u8;
        new_pos += 1;
    } else if value < 256 {
        buffer[new_pos] = 0x81;
        new_pos += 1;
        buffer[new_pos] = value as u8;
        new_pos += 1;
    } else if value < 65535 {
        buffer[new_pos] = 0x82;
        new_pos += 1;
        buffer[new_pos] = (value >> 8) as u8;
        new_pos += 1;
        buffer[new_pos] = (value & 0xff) as u8;
        new_pos += 1;
    } else {
        if value >= 1 << 24 {
            return Err(EncodeError::new(
                "Value exceeds the maximum range for three-byte encoding (2^24 - 1).",
                buffer_index,
            ));
        }
        buffer[new_pos] = 0x83;
        new_pos += 1;
        buffer[new_pos] = (value >> 16) as u8;
        new_pos += 1;
        buffer[new_pos] = ((value >> 8) & 0xff) as u8;
        new_pos += 1;
        buffer[new_pos] = (value & 0xff) as u8;
        new_pos += 1;
    }

    Ok(new_pos)
}

/// Encodes an ASN.1 BER element (tag, length, value) into the buffer at the given position.
///
/// # Parameters
/// - `tag`: The ASN.1 tag to write.
/// - `value`: The value bytes to encode.
/// - `buffer`: The output buffer.
/// - `buffer_index`: The position in the buffer to start writing.
///
/// # Returns
/// Result with the new position in the buffer after writing, or EncodeError.
pub fn encode_ber(
    tag: u8,
    value: &[u8],
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    // Calculate required space: tag + length + value
    let length_field_size = size_length(value.len());
    let total_size = 1 + length_field_size + value.len();

    if buffer.len() < buffer_index + total_size {
        return Err(EncodeError::new(
            "Buffer does not have enough capacity to encode the BER element.",
            buffer_index,
        ));
    }

    // Write tag and length
    let mut pos = encode_tag_length(tag, value.len(), buffer, buffer_index)?;
    // Write value
    buffer[pos..pos + value.len()].copy_from_slice(value);
    pos += value.len();

    Ok(pos)
}

/// # Parameters
/// - `tag`: A `u8` representing the tag to be written to the buffer.
/// - `value`: A `bool` indicating the value to encode (true as 0xff, false as 0x00).
/// - `buffer`: A mutable slice of `u8` where the encoded data will be written.
/// - `buffer_index`: The starting position in the buffer to write the encoded data.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded data, or EncodeError.
pub fn encode_boolean(
    tag: u8,
    value: bool,
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    if buffer.len() < buffer_index + 3 {
        return Err(EncodeError::new(
            "Buffer does not have enough capacity to encode the boolean value.",
            buffer_index,
        ));
    }

    let mut new_pos = buffer_index;
    buffer[new_pos] = tag;

    new_pos += 1;
    buffer[new_pos] = 1;

    new_pos += 1;
    buffer[new_pos] = if value { 0xff } else { 0x00 };

    new_pos += 1;
    Ok(new_pos)
}

/// # Parameters
/// - `tag`: A `u8` representing the tag to be written to the buffer.
/// - `value`: A `String` reference containing the string to encode.
/// - `buffer`: A mutable slice of `u8` where the encoded data will be written.
/// - `buffer_index`: The starting position in the buffer to write the encoded data.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded string, or EncodeError.
pub fn encode_string(
    tag: u8,
    value: &str,
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    let bytes = value.as_bytes();
    encode_ber(tag, bytes, buffer, buffer_index)
}

/// Encodes an ASN.1 octet string using BER rules.
///
/// # Parameters
/// - `tag`: The ASN.1 tag to write.
/// - `value`: A slice of `u8` containing the octet string to encode.
/// - `buffer`: A mutable slice of `u8` where the encoded data will be written.
/// - `buffer_index`: The starting position in the buffer to write the encoded data.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded octet string, or EncodeError.
pub fn encode_octet_string(
    tag: u8,
    value: &[u8],
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    encode_ber(tag, value, buffer, buffer_index)
}

/// Encodes an integer in minimal two's complement form according to ASN.1 BER.
///
/// # Parameters
/// - `tag`: The ASN.1 tag for the integer type.
/// - `value`: The integer as a big-endian byte slice (with possible leading sign extension bytes).
/// - `buffer`: The output buffer.
/// - `buffer_index`: Where to start writing in the buffer.
///
/// # Returns
/// The new position in the buffer after writing the encoded integer.
pub fn encode_integer(
    tag: u8,
    value: &[u8],
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    encode_ber(
        tag,
        minimal_twos_complement_bytes(value),
        buffer,
        buffer_index,
    )
}

/// Encodes an unsigned integer in ASN.1 BER format with a leading zero byte to ensure positive interpretation.
///
/// # Parameters
/// - `tag`: A `u8` representing the ASN.1 tag for the unsigned integer type.
/// - `value`: A slice of `u8` containing the unsigned integer in big-endian format.
/// - `buffer`: A mutable slice of `u8` where the encoded data will be written.
/// - `buffer_index`: The starting position in the buffer to write the encoded data.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded unsigned integer, or EncodeError.
pub fn encode_unsigned_integer(
    tag: u8,
    value: &[u8],
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    let minimal = minimal_twos_complement_bytes(value);
    // If MSB is set, prepend a zero byte
    if !minimal.is_empty() && (minimal[0] & 0x80) != 0 {
        let mut prepend = [0u8; 1 + 8];
        prepend[0] = 0x00;
        prepend[1..1 + minimal.len()].copy_from_slice(minimal);
        encode_ber(tag, &prepend[..1 + minimal.len()], buffer, buffer_index)
    } else {
        encode_ber(tag, minimal, buffer, buffer_index)
    }
}

/// Encodes a single-precision IEEE 754 float as ASN.1 BER REAL for IEC 61850-7-2.
///
/// This function encodes a 4-byte IEEE 754 float using the binary encoding form
/// specified by ASN.1 BER, with a descriptor byte of 0x08. This matches the
/// requirements of IEC 61850-7-2 for FLOAT32 values.
///
/// # Parameters
/// - `tag`: The ASN.1 tag for REAL (usually 0x09).
/// - `bytes`: A 4-byte slice representing the IEEE 754 float (big-endian).
/// - `buffer`: The output buffer.
/// - `buffer_index`: The starting position in the buffer to write the encoded data.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded float, or EncodeError.
pub fn encode_float(
    tag: u8,
    bytes: &[u8],
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    // Ensure the input is exactly 4 bytes (IEEE 754 single-precision)
    if bytes.len() != 4 {
        return Err(EncodeError::new(
            "encode_float expects a 4-byte IEEE 754 single-precision float.",
            buffer_index,
        ));
    }

    // Check buffer capacity
    if buffer.len() < buffer_index + 6 {
        return Err(EncodeError::new(
            "Buffer does not have enough capacity to encode the float value.",
            buffer_index,
        ));
    }

    let mut new_pos = buffer_index;
    buffer[new_pos] = tag;
    new_pos += 1;
    buffer[new_pos] = 5; // Length: 1 descriptor + 4 float bytes
    new_pos += 1;
    buffer[new_pos] = 0x08; // Descriptor: binary encoding, base 2, exponent length 1
    new_pos += 1;
    buffer[new_pos..new_pos + 4].copy_from_slice(bytes); // IEEE 754 float bytes
    new_pos += 4;
    Ok(new_pos)
}

/// Encodes a coded enum as an ASN.1 BER BIT STRING, with bit and byte order reversed.
///
/// This function writes the tag, length, padding, and the value bytes (in reverse order and with bits reversed)
/// into the provided buffer. The reverse order and bit reversal may be required by specific protocol
/// implementations or legacy interoperability requirements.
///
/// # Parameters
/// - `tag`: The ASN.1 tag for BIT STRING (usually 0x03).
/// - `value`: The value bytes representing the coded enum (big-endian, unsigned integer encoding).
/// - `padding`: Number of unused bits in the last byte.
/// - `buffer`: The output buffer.
/// - `buffer_index`: The starting position in the buffer to write the encoded data.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded coded enum, or EncodeError.
///
/// # Note
/// The value bytes are written in reverse order and with bits reversed in each byte.
/// This is not standard ASN.1 BER encoding, but may be required for compatibility with some IEC 61850-8-1 implementations.
pub fn encode_coded_enum(
    tag: u8,
    value: &[u8],
    padding: u8,
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    let total_len = value.len() + 1; // +1 for the padding byte
    let required = 1 + size_length(total_len) + total_len; // tag + length + padding + value

    if buffer.len() < buffer_index + required {
        return Err(EncodeError::new(
            "Buffer too small to encode coded enum BIT STRING.",
            buffer_index,
        ));
    }

    // Write tag and length
    let mut pos = encode_tag_length(tag, total_len, buffer, buffer_index)?;

    // Write the padding (number of unused bits in the last byte)
    buffer[pos] = padding;
    pos += 1;

    // Write the value bytes in reverse order and with bits reversed in each byte
    for i in 0..value.len() {
        buffer[pos + i] = value[value.len() - i - 1].reverse_bits();
    }
    pos += value.len();

    Ok(pos)
}

/// Encodes an ASN.1 array of IECData elements into the buffer at the specified position.
///
/// This function first calculates the total size of all encoded elements. If `fill` is false,
/// it returns the size without writing anything to the buffer. If `fill` is true, it encodes
/// the tag and length, then encodes each IECData element in sequence.
///
/// # Parameters
/// - `tag`: The ASN.1 tag for the array.
/// - `value`: Slice of IECData elements to encode.
/// - `buffer`: The output buffer where the encoded array will be written.
/// - `pos`: The position in the buffer to start writing.
/// - `fill`: If true, actually writes to the buffer; if false, only computes the size.
///
/// # Returns
/// The new position in the buffer after writing the array, or the size if `fill` is false.
pub fn encode_structure(
    tag: u8,
    value: &[IECData],
    buffer: &mut [u8],
    pos: usize,
) -> Result<usize, EncodeError> {
    // Calculate total size of all elements
    let mut element_size = 0;
    for data in value {
        element_size += size_iec_data_element(data);
    }

    // Encode tag and length for the array
    let mut new_pos = pos;
    new_pos = encode_tag_length(tag, element_size, buffer, new_pos)?;

    // Encode each IECData element in sequence
    for data in value {
        new_pos = encode_iec_data_element(data, buffer, new_pos).unwrap_or(new_pos);
    }

    Ok(new_pos)
}

/// Encodes a single IECData element into ASN.1 BER format and writes it to the buffer.
///
/// This function matches the IECData variant and calls the appropriate encoding function
/// for each supported type. Each encoding function writes the encoded value to the buffer
/// at the specified buffer_index and returns the new buffer position or an error.
///
/// # Parameters
/// - `data`: Reference to the IECData enum variant to encode.
/// - `buffer`: The output buffer where the encoded data will be written.
/// - `buffer_index`: The position in the buffer to start writing.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded element, or EncodeError
/// if the buffer is too small or the data type is unknown.
pub fn encode_iec_data_element(
    data: &IECData,
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    match data {
        IECData::Boolean(val) => encode_boolean(0x83, *val, buffer, buffer_index),
        IECData::Int8(val) => encode_integer(0x85, &val.to_be_bytes(), buffer, buffer_index),
        IECData::Int16(val) => encode_integer(0x85, &val.to_be_bytes(), buffer, buffer_index),
        IECData::Int32(val) => encode_integer(0x85, &val.to_be_bytes(), buffer, buffer_index),
        IECData::Int64(val) => encode_integer(0x85, &val.to_be_bytes(), buffer, buffer_index),
        IECData::Int8u(val) => {
            encode_unsigned_integer(0x86, &val.to_be_bytes(), buffer, buffer_index)
        }
        IECData::Int16u(val) => {
            encode_unsigned_integer(0x86, &val.to_be_bytes(), buffer, buffer_index)
        }
        IECData::Int32u(val) => {
            encode_unsigned_integer(0x86, &val.to_be_bytes(), buffer, buffer_index)
        }
        IECData::Float32(val) => encode_float(0x87, &val.to_be_bytes(), buffer, buffer_index),
        IECData::VisibleString(val) => encode_string(0x8a, val, buffer, buffer_index),
        IECData::MmsString(val) => encode_string(0x90, val, buffer, buffer_index),
        IECData::BitString { padding, val } => {
            encode_coded_enum(0x84, val, *padding, buffer, buffer_index)
        }
        IECData::Array(val) => encode_structure(0xa1, val, buffer, buffer_index),
        IECData::Structure(val) => encode_structure(0xa2, val, buffer, buffer_index),
        IECData::OctetString(val) => encode_octet_string(0x89, val, buffer, buffer_index),
        IECData::UtcTime(val) => encode_octet_string(0x91, val, buffer, buffer_index),
        _ => Err(EncodeError::new("Unknown IECData type.", buffer_index)),
    }
}

/// Encodes all IECData elements in a PDU into the buffer using ASN.1 BER rules.
///
/// This function iterates over all elements in the `allData` field of the provided `IECGoosePdu`.
/// For each element, it calls `encode_iec_data_element` to encode the value into the buffer,
/// updating the buffer position after each successful encoding. If any encoding fails,
/// the function returns the encountered `EncodeError`.
///
/// # Parameters
/// - `pdu`: Reference to the IECGoosePdu containing allData.
/// - `buffer`: The output buffer.
/// - `buffer_index`: The position in the buffer to start writing.
///
/// # Returns
/// Result with the new position in the buffer after writing all elements, or EncodeError.
pub fn encode_iec_data(
    all_data: &Vec<IECData>,
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    let mut new_pos = buffer_index;

    for data in all_data {
        new_pos = encode_iec_data_element(data, buffer, new_pos)?;
    }

    Ok(new_pos)
}

pub fn minimal_integer_size(value: &[u8]) -> usize {
    // Strip leading sign-extension bytes
    let mut start = 0;
    while start < value.len() - 1 {
        let curr = value[start];
        let next = value[start + 1];
        if (curr == 0x00 && (next & 0x80) == 0) || (curr == 0xFF && (next & 0x80) == 0x80) {
            start += 1;
        } else {
            break;
        }
    }
    value.len() - start
}

pub fn minimal_unsigned_size(bytes: &[u8]) -> usize {
    // Strip leading zeros
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0x00 {
        start += 1;
    }
    let minimal = &bytes[start..];
    // If MSB is set, need a leading zero
    if !minimal.is_empty() && (minimal[0] & 0x80) != 0 {
        minimal.len() + 1
    } else {
        minimal.len()
    }
}

/// Returns the number of bytes required to encode a single IECData element (minimal ASN.1 BER encoding).
pub fn size_iec_data_element(data: &IECData) -> usize {
    match data {
        IECData::Boolean(_) => 3, // tag + length + value (always 1 byte for bool)
        IECData::Int8(val) => {
            let bytes = val.to_be_bytes();
            let value_size = minimal_integer_size(&bytes);
            1 + size_length(value_size) + value_size
        }
        IECData::Int16(val) => {
            let bytes = val.to_be_bytes();
            let value_size = minimal_integer_size(&bytes);
            1 + size_length(value_size) + value_size
        }
        IECData::Int32(val) => {
            let bytes = val.to_be_bytes();
            let value_size = minimal_integer_size(&bytes);
            1 + size_length(value_size) + value_size
        }
        IECData::Int64(val) => {
            let bytes = val.to_be_bytes();
            let value_size = minimal_integer_size(&bytes);
            1 + size_length(value_size) + value_size
        }
        IECData::Int8u(val) => {
            let bytes = val.to_be_bytes();
            let value_size = minimal_unsigned_size(&bytes);
            1 + size_length(value_size) + value_size
        }
        IECData::Int16u(val) => {
            let bytes = val.to_be_bytes();
            let value_size = minimal_unsigned_size(&bytes);
            1 + size_length(value_size) + value_size
        }
        IECData::Int32u(val) => {
            let bytes = val.to_be_bytes();
            let value_size = minimal_unsigned_size(&bytes);
            1 + size_length(value_size) + value_size
        }
        IECData::Float32(_) => 1 + size_length(5) + 5, // tag + length + descriptor + 4 bytes
        IECData::VisibleString(val) => 1 + size_length(val.len()) + val.len(),
        IECData::MmsString(val) => 1 + size_length(val.len()) + val.len(),
        IECData::BitString { padding: _, val } => 1 + size_length(val.len() + 1) + 1 + val.len(),
        IECData::Array(val) => {
            let content_size: usize = val.iter().map(size_iec_data_element).sum();
            1 + size_length(content_size) + content_size
        }
        IECData::Structure(val) => {
            let content_size: usize = val.iter().map(size_iec_data_element).sum();
            1 + size_length(content_size) + content_size
        }
        IECData::OctetString(val) => 1 + size_length(val.len()) + val.len(),
        IECData::UtcTime(val) => 1 + size_length(val.len()) + val.len(),
        _ => 0, // Or handle error/unsupported
    }
}

/// Returns the number of bytes required to encode all IECData elements in a PDU.
pub fn size_iec_data(all_data: &Vec<IECData>) -> usize {
    all_data.iter().map(size_iec_data_element).sum()
}
