use crate::decode_basics::*;
use crate::types::{DecodeError, SavAsdu, SavPdu};

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
pub fn decode_goose_smv(pdu: &mut SavPdu, buffer: &[u8], pos: usize) -> Result<usize, DecodeError> {
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
    new_pos = decode_sav_asdu(&mut pdu.sav_asdu, buffer, new_pos, pdu.no_asdu)?;

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
pub fn decode_sav_asdu(
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

        let (next_pos, new_asdu) = decode_goose_sav_asdu(buffer, new_pos)?;
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
pub fn decode_goose_sav_asdu(
    buffer: &[u8],
    start_pos: usize,
) -> Result<(usize, SavAsdu), DecodeError> {
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
    let (next_pos, result) = decode_92_le_data(buffer, new_pos)?;
    new_pos = next_pos;
    asdu.all_data = result;

    // Optional Sampling Mod
    if new_pos < buffer.len() && buffer[new_pos] == 0x88 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut smp_mod_num = 0u16;
        new_pos = decode_unsigned_16(&mut smp_mod_num, buffer, new_pos, length)?;
        asdu.smp_mod = Some(smp_mod_num as u16);
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
pub fn decode_sim_bit(buffer: &[u8]) -> Option<bool> {
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

pub fn decode_92_le_data(
    buffer: &[u8],
    buffer_index: usize,
) -> Result<(usize, Vec<(f32, u32)>), DecodeError> {
    let mut pos = buffer_index;
    let mut result = Vec::with_capacity(8);

    // Scaling factors for each float
    let scaling_factors = [
        0.001, 0.001, 0.001, 0.001, // first 4
        0.01, 0.01, 0.01, 0.01, // last 4
    ];

    for &scale in &scaling_factors {
        // Decode i32 (little endian)
        if pos + 4 > buffer.len() {
            return Err(DecodeError::new(
                &format!("Buffer too short for i32 at pos {}", pos),
                pos,
            ));
        }
        let int_bytes = &buffer[pos..pos + 4];
        let int_val = i32::from_be_bytes(int_bytes.try_into().unwrap());
        let float_val = int_val as f32 * scale;
        pos += 4;

        // Decode bitstring (4 bytes, as u32 little endian)
        if pos + 4 > buffer.len() {
            return Err(DecodeError::new(
                &format!("Buffer too short for bitstring at pos {}", pos),
                pos,
            ));
        }
        let bit_bytes = &buffer[pos..pos + 4];
        let bit_val = u32::from_be_bytes(bit_bytes.try_into().unwrap());
        pos += 4;

        result.push((float_val, bit_val));
    }

    Ok((pos, result))
}
