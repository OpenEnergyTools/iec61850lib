use crate::types::{DecodeError, SavAsdu, SavPdu};

/// Decodes an octet string (raw bytes) from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded bytes will be stored.
/// - `buffer`: The input byte slice containing the encoded data.
/// - `buffer_index`: The starting position in the buffer to read the octet string from.
/// - `length`: The number of bytes to read for the octet string.
///
/// # Returns
/// The next position in the buffer after reading the octet string.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_octet_string(
    val: &mut [u8],
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    if buffer_index + length > buffer.len() {
        return Err(DecodeError::new(
            &format!(
                "Attempt to read {} bytes exceeds buffer length {}",
                length,
                buffer.len()
            ),
            buffer_index,
        ));
    }
    val[0..length].copy_from_slice(&buffer[buffer_index..buffer_index + length]);
    Ok(buffer_index + length)
}

/// Decodes an ASN.1 BER encoded 8-bit unsigned integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded u16 will be stored.
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// The next position in the buffer after reading the integer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_unsigned_8(
    val: &mut u8,
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    let mut value_bytes = [0u8; 1];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length)?;
    *val = u8::from_be_bytes(value_bytes);
    Ok(buffer_index + length)
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
fn decompress_integer(
    value: &mut [u8],
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<(), DecodeError> {
    if buffer_index + length > buffer.len() {
        return Err(DecodeError::new(
            &format!(
                "Attempt to read {} bytes exceeds buffer length {}",
                length,
                buffer.len()
            ),
            buffer_index,
        ));
    }
    if length > value.len() {
        return Err(DecodeError::new(
            &format!(
                "Mismatch value length {} vs buffer length {}",
                value.len(),
                length
            ),
            buffer_index,
        ));
    }

    // Determine fill byte for sign extension (0xFF for negative, 0x00 for positive)
    let fill = if buffer[buffer_index] & 0x80 == 0x80 {
        0xFF
    } else {
        0x00
    };

    // Fill the leading bytes with the sign extension
    let fill_length = value.len() - length;
    for item in value.iter_mut().take(fill_length) {
        *item = fill;
    }

    // Copy the encoded integer bytes into the lower part of the output buffer
    value[fill_length..].copy_from_slice(&buffer[buffer_index..buffer_index + length]);
    Ok(())
}

/// Decodes an ASN.1 BER encoded 32-bit unsigned integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded u32 will be stored.
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// The next position in the buffer after reading the integer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_unsigned_32(
    val: &mut u32,
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    let mut value_bytes = [0u8; 4];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length)?;
    *val = u32::from_be_bytes(value_bytes);
    Ok(buffer_index + length)
}

/// Decodes an ASN.1 BER encoded 16-bit unsigned integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded u16 will be stored.
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// The next position in the buffer after reading the integer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_unsigned_16(
    val: &mut u16,
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    let mut value_bytes = [0u8; 2];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length)?;
    *val = u16::from_be_bytes(value_bytes);
    Ok(buffer_index + length)
}

/// Decodes a UTF-8 string from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded string will be stored.
/// - `buffer`: The input byte slice containing the encoded data.
/// - `buffer_index`: The starting position in the buffer to read the string from.
/// - `length`: The number of bytes to read for the string.
///
/// # Returns
/// The next position in the buffer after reading the string.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_string(
    val: &mut String,
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    if buffer_index + length > buffer.len() {
        return Err(DecodeError::new(
            &format!(
                "Attempt to read {} bytes exceeds buffer length {}",
                length,
                buffer.len()
            ),
            buffer_index,
        ));
    }
    *val = String::from_utf8_lossy(&buffer[buffer_index..buffer_index + length]).to_string();
    Ok(buffer_index + length)
}

/// Decodes an ASN.1 BER tag and length field from the buffer at the specified position,
/// writing the results into the provided mutable references.
///
/// This function supports definite-length encoding with up to 3 length bytes (sufficient for most practical uses).
///
/// # Parameters
/// - `tag`: Mutable reference to store the decoded tag (`u8`).
/// - `length`: Mutable reference to store the decoded length (`usize`).
/// - `buffer`: The input byte slice containing the encoded tag and length.
/// - `buffer_index`: The starting position in the buffer to read the tag and length from.
///
/// # Returns
/// The next position in the buffer after reading the tag and length.
///
/// # Panics
/// Panics if the buffer does not contain enough bytes to decode the tag and length.
fn decode_tag_length(
    tag: &mut u8,
    length: &mut usize,
    buffer: &[u8],
    buffer_index: usize,
) -> Result<usize, DecodeError> {
    if buffer_index >= buffer.len() {
        return Err(DecodeError::new(
            &format!("Out of bounds for buffer length {}", buffer.len()),
            buffer_index,
        ));
    }

    *tag = buffer[buffer_index];
    let mut pos = buffer_index + 1;

    if pos >= buffer.len() {
        return Err(DecodeError::new(
            "Decode tag length: missing length byte ",
            buffer_index,
        ));
    }

    let first_len_byte = buffer[pos];
    pos += 1;

    *length = if first_len_byte & 0x80 == 0 {
        // Short form: single byte length (0..127)
        first_len_byte as usize
    } else {
        // Long form: lower 7 bits indicate number of length bytes
        let num_len_bytes = (first_len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 3 {
            return Err(DecodeError::new(
                &format!(
                    "Decode tag length: unsupported or invalid number of length bytes: {}",
                    num_len_bytes
                ),
                buffer_index,
            ));
        }
        if pos + num_len_bytes > buffer.len() {
            return Err(DecodeError::new(
                &format!(
                    "Decode tag length: not enough bytes for {}-byte length at position {}",
                    num_len_bytes, pos
                ),
                buffer_index,
            ));
        }
        let mut len = 0usize;
        for _ in 0..num_len_bytes {
            len = (len << 8) | buffer[pos] as usize;
            pos += 1;
        }
        len
    };

    Ok(pos)
}

/// Decodes a GOOSE PDU from the buffer at the specified position,
/// writing the result into the provided mutable reference.
///
/// # Parameters
/// - `pdu`: A mutable reference where the decoded IECGoosePdu will be stored.
/// - `buffer`: The input byte slice containing the encoded GOOSE PDU.
/// - `pos`: The starting position in the buffer to read from.
///
/// # Returns
/// The new buffer position after decoding the PDU.
pub fn decode_smv(buffer: &[u8], pos: usize) -> Result<usize, DecodeError> {
    let mut pdu = SavPdu::default();
    let mut new_pos = pos;

    // decode simulation bit that is encoded into the first bit of reserved 1 field (see decode ethernet)
    pdu.sim = decode_sim_bit(buffer).unwrap_or(false);

    // Jump over the length tag of the SAV PDU
    let mut _tag = 0u8;
    let mut _length = 0usize;
    new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos)?;

    // Number of ASDUs in the packet
    new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos)?;
    new_pos = decode_unsigned_16(&mut pdu.no_asdu, buffer, new_pos, _length)?;

    // Optional field security
    let tag = buffer[new_pos];
    if tag == 0x81 {
        pdu.security = true;
        new_pos += 12; // Skip the security tag and length field
    } else {
        pdu.security = false;
    }

    // sequence of ASDU
    let mut length = 0usize;
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;

    pdu.sav_asdu.clear();
    new_pos = decode_smv_asdus(&mut pdu.sav_asdu, buffer, new_pos, pdu.no_asdu)?;

    Ok(new_pos)
}

/// Determines if the provided Ethernet frame buffer contains a Sampled Values (SMV) frame
/// by checking the EtherType field, accounting for possible VLAN tagging.
///
/// Returns `true` if the EtherType matches the SMV type (0x88ba), regardless of VLAN presence.
/// If a VLAN tag (0x81, 0x00) is detected, the EtherType is checked at bytes 16-17; otherwise, at bytes 12-13.
pub fn is_smv_frame(buffer: &[u8]) -> bool {
    if buffer.len() < 14 {
        return false;
    }
    // If VLAN tag (0x81, 0x00) is present, EtherType is at offset 16; otherwise, at 12.
    let ether_type_offset = if buffer[12..14] == [0x81, 0x00] {
        16
    } else {
        12
    };
    if buffer.len() < ether_type_offset + 2 {
        return false;
    }
    let ether_type = &buffer[ether_type_offset..ether_type_offset + 2];
    ether_type == [0x88, 0xba]
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
fn decode_smv_asdus(
    val: &mut Vec<SavAsdu>,
    buffer: &[u8],
    start_pos: usize,
    no_asdu: u16,
) -> Result<usize, DecodeError> {
    let mut new_pos = start_pos;

    let mut _tag = 0u8;
    let mut _length = 0usize;

    for _ in 0..no_asdu {
        // length field of the next ASDU
        new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos)?;

        let (next_pos, new_asdu) = decode_smv_asdu(buffer, new_pos)?;
        val.push(new_asdu);
        new_pos = next_pos;
    }

    Ok(new_pos)
}

/// writing the result into the provided mutable reference.
///
/// # Parameters
/// - `pdu`: A mutable reference where the decoded IECGoosePdu will be stored.
/// - `buffer`: The input byte slice containing the encoded GOOSE PDU.
/// - `pos`: The starting position in the buffer to read from.
///
/// # Returns
/// The new buffer position after decoding the PDU.
fn decode_smv_asdu(buffer: &[u8], start_pos: usize) -> Result<(usize, SavAsdu), DecodeError> {
    let mut asdu = SavAsdu::default();

    let mut new_pos = start_pos;

    // SMV ASDU length
    let mut _tag = 0u8;
    let mut _length = 0usize;

    // sampled value ID
    let mut length = 0usize;
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    new_pos = decode_string(&mut asdu.msv_id, buffer, new_pos, length)?;

    // Optional data set reference description
    let tag = buffer[new_pos];
    if tag == 0x81 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut dat_set_str = String::new();
        new_pos = decode_string(&mut dat_set_str, buffer, new_pos, length)?;
        asdu.dat_set = Some(dat_set_str);
    } else {
        asdu.dat_set = None;
    }

    // sample count
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    new_pos = decode_unsigned_16(&mut asdu.smp_cnt, buffer, new_pos, length)?;

    // conf_rev
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    new_pos = decode_unsigned_32(&mut asdu.conf_rev, buffer, new_pos, length)?;

    // Optional refresh time (timestamp)
    let tag = buffer[new_pos];
    if tag == 0x84 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut refr_tm_arr = [0u8; 8];
        refr_tm_arr.copy_from_slice(&buffer[new_pos..new_pos + 8]);
        asdu.refr_tm = Some(refr_tm_arr);
        new_pos += 8;
    } else {
        asdu.refr_tm = None;
    }

    // samples synched
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    new_pos = decode_unsigned_8(&mut asdu.smp_synch, buffer, new_pos, length)?;

    // Optional sample rate
    let tag = buffer[new_pos];
    if tag == 0x86 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut smp_rate_num = 0u16;
        new_pos = decode_unsigned_16(&mut smp_rate_num, buffer, new_pos, length)?;
        asdu.smp_rate = Some(smp_rate_num);
    } else {
        asdu.smp_rate = None;
    }

    // Data Content
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    asdu.all_data.clear();
    let (next_pos, result) = decode_savs(buffer, new_pos, length)?;
    new_pos = next_pos;
    asdu.all_data = result;

    // Optional Sampling Mod
    if new_pos < buffer.len() && buffer[new_pos] == 0x88 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut smp_mod_num = 0u16;
        new_pos = decode_unsigned_16(&mut smp_mod_num, buffer, new_pos, length)?;
        asdu.smp_mod = Some(smp_mod_num);
    } else {
        asdu.smp_mod = None;
    }

    // Optional grandmaster clock identity
    if new_pos < buffer.len() && buffer[new_pos] == 0x89 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut gm_identity_oct = [0u8; 8];
        new_pos = decode_octet_string(&mut gm_identity_oct, buffer, new_pos, length)?;
        asdu.gm_identity = Some(gm_identity_oct);
    } else {
        asdu.gm_identity = None;
    }

    Ok((new_pos, asdu))
}

/// Extracts the SIM bit from the "reserved 1" field in the SV/SMV header.
/// The SIM bit is the most significant bit (bit 7) of the first byte of reserved 1.
/// Returns Some(true) if the SIM bit is set, Some(false) if not, or None if the buffer is too short.
///
/// # Arguments
/// * `buffer` - The Ethernet frame buffer (must be long enough to contain reserved 1).
fn decode_sim_bit(buffer: &[u8]) -> Option<bool> {
    // Ethernet: 6 (dst) + 6 (src)
    let mut offset = 12;

    // Check for VLAN tag (0x81, 0x00)
    if buffer.len() >= offset + 2 && buffer[offset..offset + 2] == [0x81, 0x00] {
        offset += 4; // VLAN tag is 4 bytes
    }

    // EtherType (2) + appid (2) + length (2)
    offset += 2 + 2 + 2;

    // Now offset points to the first byte of reserved 1
    if buffer.len() <= offset {
        return None;
    }

    let reserved1_byte = buffer[offset];
    Some((reserved1_byte & 0x80) != 0)
}

fn decode_savs(
    buffer: &[u8],
    buffer_index: usize,
    data_length: usize,
) -> Result<(usize, Vec<crate::types::Sample>), DecodeError> {
    let mut pos = buffer_index;
    let end_pos = buffer_index + data_length;
    let mut result = Vec::new();

    let mut tag = 0u8;
    let mut length = 0usize;

    while pos < end_pos {
        // Decode the i32 value (ASN.1 BER encoded integer)
        pos = decode_tag_length(&mut tag, &mut length, buffer, pos)?;

        if tag != 0x83 {
            return Err(DecodeError::new(
                &format!("Expected integer tag 0x83, got 0x{:02x}", tag),
                pos,
            ));
        }

        // Decode the integer value using BER decompression
        let mut value_bytes = [0u8; 4];
        decompress_integer(&mut value_bytes, buffer, pos, length)?;
        let int_val = i32::from_be_bytes(value_bytes);
        pos += length;

        // Decode the quality bitstring (ASN.1 BER encoded bitstring)
        pos = decode_tag_length(&mut tag, &mut length, buffer, pos)?;

        if tag != 0x84 {
            return Err(DecodeError::new(
                &format!("Expected bitstring tag 0x84, got 0x{:02x}", tag),
                pos,
            ));
        }

        // First byte of bitstring is the number of unused bits
        // For 13-bit quality, there should be 3 unused bits in the 2-byte encoding
        if pos >= buffer.len() {
            return Err(DecodeError::new(
                "Buffer too short for bitstring unused bits",
                pos,
            ));
        }
        let _unused_bits = buffer[pos];
        pos += 1;
        let quality_length = length - 1; // Subtract the unused bits byte

        // Read quality bytes (should be 2 bytes for 13-bit quality)
        if pos + quality_length > buffer.len() {
            return Err(DecodeError::new(
                &format!("Buffer too short for quality bytes at pos {}", pos),
                pos,
            ));
        }

        // Quality is encoded as big-endian, read it as u16
        // The unused bits are at the LSB end and already accounted for in the encoding
        let mut quality_bits = 0u16;
        for i in 0..quality_length {
            quality_bits = (quality_bits << 8) | buffer[pos + i] as u16;
        }
        pos += quality_length;

        result.push(crate::types::Sample::new(int_val, quality_bits));
    }

    Ok((pos, result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn create_test_data_buffer() -> Vec<u8> {
        let mut buffer = Vec::new();

        // 8 samples: each is ASN.1 BER encoded INT32 (tag 0x83) + BER encoded BITSTRING (tag 0x84)
        for i in 0..8 {
            let value = (10000 + i * 1000) as i32;
            let value_bytes = value.to_be_bytes();

            // Find the minimum number of bytes needed (BER compression)
            let mut start_idx = 0;
            for j in 0..3 {
                if value >= 0 && value_bytes[j] == 0 && (value_bytes[j + 1] & 0x80) == 0 {
                    start_idx = j + 1;
                } else if value < 0 && value_bytes[j] == 0xFF && (value_bytes[j + 1] & 0x80) != 0 {
                    start_idx = j + 1;
                } else {
                    break;
                }
            }
            let compressed_bytes = &value_bytes[start_idx..];

            // INT32 with tag 0x83
            buffer.push(0x83);
            buffer.push(compressed_bytes.len() as u8);
            buffer.extend_from_slice(compressed_bytes);

            // BITSTRING with tag 0x84 (13-bit quality in 2 bytes + 1 byte for unused bits)
            // 13 bits requires 2 bytes, with 3 unused bits
            let quality_13bit: u16 = 0x0000; // good quality (all zeros)
            let quality_with_padding = quality_13bit << 3; // Shift left by 3 to add padding

            buffer.push(0x84);
            buffer.push(3); // length: 1 (unused bits) + 2 (quality bytes)
            buffer.push(3); // 3 unused bits
            buffer.extend_from_slice(&quality_with_padding.to_be_bytes());
        }

        buffer
    }
    #[test]
    fn test_decode_92_le_data_correctness() {
        let buffer = create_test_data_buffer();
        let result = decode_savs(&buffer, 0, buffer.len());

        assert!(result.is_ok());
        let (pos, data) = result.unwrap();

        assert_eq!(pos, buffer.len());
        assert_eq!(data.len(), 8);

        // Check first value (10000)
        assert_eq!(data[0].value, 10000);
        assert_eq!(data[0].quality.to_u16(), 0);
        assert!(data[0].quality.is_good());

        // Check last value (17000)
        assert_eq!(data[7].value, 17000);
        assert_eq!(data[7].quality.to_u16(), 0);
        assert!(data[7].quality.is_good());
    }

    #[test]
    fn test_decode_92_le_data_performance() {
        let buffer = create_test_data_buffer();
        let iterations = 100_000;

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = decode_savs(&buffer, 0, buffer.len());
        }
        let duration = start.elapsed();

        let avg_ns = duration.as_nanos() / iterations;
        let avg_us = avg_ns as f64 / 1000.0;

        println!("\n=== SMV Data Decode Performance ===");
        println!("Iterations: {}", iterations);
        println!("Total time: {:?}", duration);
        println!("Average per decode: {} ns ({:.3} μs)", avg_ns, avg_us);
        println!(
            "Theoretical max rate: {:.0} Hz ({:.1} kHz)",
            1_000_000.0 / avg_us,
            (1_000_000.0 / avg_us) / 1000.0
        );

        // Performance assertion: should decode in less than 10 microseconds
        // (allowing headroom for 100 kHz = 10 μs between packets)
        assert!(
            avg_us < 10.0,
            "Decode too slow: {:.3} μs (should be < 10 μs for 100 kHz rate)",
            avg_us
        );
    }

    #[test]
    fn test_decode_variable_sample_count() {
        // Test with 4 samples - using ASN.1 BER encoding
        let mut buffer = Vec::new();
        for i in 0..4 {
            let value = (1000 + i * 100) as i32;
            let value_bytes = value.to_be_bytes();

            // Compress the integer (remove leading zeros for positive numbers)
            let mut start_idx = 0;
            for j in 0..3 {
                if value_bytes[j] == 0 && (value_bytes[j + 1] & 0x80) == 0 {
                    start_idx = j + 1;
                } else {
                    break;
                }
            }
            let compressed = &value_bytes[start_idx..];

            // INT32 with tag 0x83
            buffer.push(0x83);
            buffer.push(compressed.len() as u8);
            buffer.extend_from_slice(compressed);

            // BITSTRING with tag 0x84 (13-bit quality)
            let quality_13bit: u16 = 0x0000;
            let quality_with_padding = quality_13bit << 3;
            buffer.push(0x84);
            buffer.push(3); // 1 + 2 bytes
            buffer.push(3); // 3 unused bits
            buffer.extend_from_slice(&quality_with_padding.to_be_bytes());
        }

        let result = decode_savs(&buffer, 0, buffer.len());
        assert!(result.is_ok());
        let (pos, data) = result.unwrap();
        assert_eq!(data.len(), 4);
        assert_eq!(pos, buffer.len());
        assert_eq!(data[0].value, 1000);
        assert_eq!(data[3].value, 1300);

        // Test with 12 samples with quality flags (validity = invalid = 01)
        let mut buffer = Vec::new();
        for i in 0..12 {
            let value = (2000 + i * 50) as i32;
            let value_bytes = value.to_be_bytes();

            // Compress
            let mut start_idx = 0;
            for j in 0..3 {
                if value_bytes[j] == 0 && (value_bytes[j + 1] & 0x80) == 0 {
                    start_idx = j + 1;
                } else {
                    break;
                }
            }
            let compressed = &value_bytes[start_idx..];

            // INT32
            buffer.push(0x83);
            buffer.push(compressed.len() as u8);
            buffer.extend_from_slice(compressed);

            // BITSTRING with quality = invalid (validity bits = 01 in the 13-bit value)
            // The 13-bit quality occupies bits 15-3 of a 16-bit container (MSB aligned)
            // Validity is bits 0-1 of the 13-bit value, which are bits 15-14 of the container
            // 01 (invalid) = 0x4000 in the 16-bit container
            let quality_16bit_container: u16 = 0x4000; // bit 14 set = validity invalid
            buffer.push(0x84);
            buffer.push(3);
            buffer.push(3); // 3 unused bits at LSB end
            buffer.extend_from_slice(&quality_16bit_container.to_be_bytes());
        }

        let result = decode_savs(&buffer, 0, buffer.len());
        assert!(result.is_ok());
        let (pos, data) = result.unwrap();
        assert_eq!(data.len(), 12);
        assert_eq!(pos, buffer.len());
        assert_eq!(data[0].value, 2000);
        assert_eq!(data[11].value, 2550);
        // Check quality flag was decoded
        assert_eq!(data[0].quality.validity, crate::types::Validity::Invalid);
    }

    #[test]
    fn test_is_smv_frame_no_vlan() {
        let frame = vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, // dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
            0x88, 0xba, // EtherType = SMV
        ];

        assert!(is_smv_frame(&frame));
    }

    #[test]
    fn test_is_smv_frame_with_vlan() {
        let frame = vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, // dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
            0x81, 0x00, // VLAN TPID
            0x00, 0x64, // VLAN TCI
            0x88, 0xba, // EtherType = SMV
        ];

        assert!(is_smv_frame(&frame));
    }

    #[test]
    fn test_is_smv_frame_not_smv() {
        let frame = vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08,
            0x00, // EtherType = IPv4
        ];

        assert!(!is_smv_frame(&frame));
    }

    #[test]
    fn test_decode_sim_bit() {
        // Without VLAN, SIM bit not set
        let mut frame = vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x88, 0xba, // EtherType
            0x40, 0x00, // APPID
            0x00, 0x64, // Length
            0x00, 0x00, // Reserved 1 (SIM bit = 0)
        ];

        assert_eq!(decode_sim_bit(&frame), Some(false));

        // Set SIM bit (MSB of reserved 1)
        frame[18] = 0x80;
        assert_eq!(decode_sim_bit(&frame), Some(true));
    }
}
