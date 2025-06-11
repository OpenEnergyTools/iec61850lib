use crate::decode_basics::*;
use crate::types::IECGoosePdu;

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
pub fn decode_goose_pdu(pdu: &mut IECGoosePdu, buffer: &[u8], pos: usize) -> usize {
    let mut new_pos = pos;

    // goose_pdu_length
    let mut _tag = 0u8;
    let mut _length = 0usize;
    new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos);

    // go_cb_ref
    let mut length = 0usize;
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    new_pos = decode_string(&mut pdu.go_cb_ref, buffer, new_pos, length);

    // time_allowed_to_live
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    new_pos = decode_unsigned_32(&mut pdu.time_allowed_to_live, buffer, new_pos, length);

    // data_set
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    new_pos = decode_string(&mut pdu.dat_set, buffer, new_pos, length);

    // go_id
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    new_pos = decode_string(&mut pdu.go_id, buffer, new_pos, length);

    // t (timestamp)
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    if length != 8 {
        panic!("Timestamp must be 8 bytes, got {}", length);
    }
    pdu.t.copy_from_slice(&buffer[new_pos..new_pos + 8]);
    new_pos += 8;

    // st_num
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    new_pos = decode_unsigned_32(&mut pdu.st_num, buffer, new_pos, length);

    // sq_num
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    new_pos = decode_unsigned_32(&mut pdu.sq_num, buffer, new_pos, length);

    // simulation
    new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos);
    new_pos = decode_boolean(&mut pdu.simulation, buffer, new_pos);

    // conf_rev
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    new_pos = decode_unsigned_32(&mut pdu.conf_rev, buffer, new_pos, length);

    // nds_com
    new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos);
    new_pos = decode_boolean(&mut pdu.nds_com, buffer, new_pos);

    // num_data_set_entries
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    new_pos = decode_unsigned_32(&mut pdu.num_dat_set_entries, buffer, new_pos, length);

    // all_data
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos);
    pdu.all_data.clear();
    new_pos = decode_iec_data(&mut pdu.all_data, buffer, new_pos, new_pos + length);

    new_pos
}

/// Checks if the given buffer contains a GOOSE frame by inspecting the EtherType field,
/// correctly handling the presence of a VLAN tag (0x81, 0x00).
///
/// This function returns `true` if the EtherType field in the buffer matches
/// the known GOOSE EtherTypes (0x88b8 or 0x88b9), whether or not a VLAN tag is present.
/// If a VLAN tag is present, the EtherType is checked at bytes 16-17; otherwise, at bytes 12-13.
pub fn is_goose_frame(buffer: &[u8]) -> bool {
    if buffer.len() < 14 {
        return false;
    }
    // Check for VLAN tag (0x81, 0x00)
    let ether_type_offset = if buffer[12..14] == [0x81, 0x00] {
        16 // EtherType is at 16 if VLAN tag is present
    } else {
        12 // Otherwise at 12
    };
    if buffer.len() < ether_type_offset + 2 {
        return false;
    }
    let ether_type = &buffer[ether_type_offset..ether_type_offset + 2];
    ether_type == [0x88, 0xb8] || ether_type == [0x88, 0xb9]
}
