use crate::decode_basics::*;
use crate::types::{EthernetHeader, IECGoosePdu};

pub fn decode_goose_pdu(buffer: &[u8], pos: usize) -> (IECGoosePdu, usize) {
    let new_pos = pos;

    // goose_pdu_length
    let (_tag, _length, new_pos) = decode_tag_length(buffer, new_pos);

    // go_cb_ref
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (go_cb_ref, next_pos) = decode_string(buffer, new_pos, length);
    new_pos = next_pos;

    // time_allowed_to_live
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (time_allowed_to_live, next_pos) = decode_unsigned_32(buffer, new_pos, length);
    new_pos = next_pos;

    // data_set
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (data_set, next_pos) = decode_string(buffer, new_pos, length);
    new_pos = next_pos;

    // go_id
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (go_id, next_pos) = decode_string(buffer, new_pos, length);
    new_pos = next_pos;

    // t (timestamp)
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    if length != 8 {
        panic!("Timestamp must be 8 bytes, got {}", length);
    }
    let t = {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&buffer[new_pos..new_pos + 8]);
        arr
    };
    new_pos += 8;

    // st_num
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (st_num, next_pos) = decode_unsigned_32(buffer, new_pos, length);
    new_pos = next_pos;

    // sq_num
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (sq_num, next_pos) = decode_unsigned_32(buffer, new_pos, length);
    new_pos = next_pos;

    // simulation
    let (_tag, _length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (simulation, next_pos) = decode_boolean(buffer, new_pos);
    new_pos = next_pos;

    // conf_rev
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (conf_rev, next_pos) = decode_unsigned_32(buffer, new_pos, length);
    new_pos = next_pos;

    // nds_com
    let (_tag, _length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (nds_com, next_pos) = decode_boolean(buffer, new_pos);
    new_pos = next_pos;

    // num_data_set_entries
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (num_data_set_entries, next_pos) = decode_unsigned_32(buffer, new_pos, length);
    new_pos = next_pos;

    // all_data
    let (_tag, length, mut new_pos) = decode_tag_length(buffer, new_pos);
    let (all_data, next_pos) = decode_iec_data(buffer, new_pos, new_pos + length);
    new_pos = next_pos;

    (
        IECGoosePdu {
            go_cb_ref,
            time_allowed_to_live,
            data_set,
            go_id,
            t,
            st_num,
            sq_num,
            simulation,
            conf_rev,
            nds_com,
            num_data_set_entries,
            all_data,
        },
        new_pos,
    )
}

/// Decodes a complete GOOSE Ethernet frame from the buffer.
///
/// This function first decodes the Ethernet header and then decodes the GOOSE PDU (Protocol Data Unit).
/// It returns the decoded [`EthernetHeader`], the [`IECGoosePdu`], and the next position in the buffer
/// after the entire frame has been processed. If the EtherType is not the expected GOOSE value (`0x88b8`),
/// it returns an error with the found EtherType.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the Ethernet frame and GOOSE PDU.
///
/// # Returns
/// `Ok((EthernetHeader, IECGoosePdu, usize))` on success, or
/// `Err([u8; 2])` with the unexpected EtherType on error.
pub fn decode_goose_frame(buffer: &[u8]) -> Result<(EthernetHeader, IECGoosePdu, usize), [u8; 2]> {
    let (header, next_pos) = decode_ethernet_header(buffer);

    // Check if the EtherType is for GOOSE (0x88b8)
    if header.ether_type != [0x88, 0xb8] {
        return Err(header.ether_type);
    }

    let (pdu, final_pos) = decode_goose_pdu(buffer, next_pos);
    Ok((header, pdu, final_pos))
}

/// Checks if the given Ethernet header corresponds to a GOOSE frame.
///
/// This function returns `true` if the EtherType field in the header matches
/// the known GOOSE EtherTypes (0x88b8 or 0x88b9), otherwise returns `false`.
pub fn is_goose_frame(header: &EthernetHeader) -> bool {
    return header.ether_type == [0x88, 0xb8] || header.ether_type == [0x88, 0xb9];
}
