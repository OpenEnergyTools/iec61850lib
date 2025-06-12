use crate::encode_basics::*;
use crate::types::*;

/// Returns the number of bytes required to encode an IECGoosePdu (minimal ASN.1 BER encoding).
///
/// This includes all fields and the encoded all_data array.
/// The size of all_data is determined using the size_iec_data function.
pub fn size_goose_pdu(config: &GooseConfig, runtime: &GooseRuntime, all_data_size: usize) -> usize {
    let mut pdu_size: usize = 0;

    // [80] goCbRef (VisibleString)
    pdu_size += 1 + size_length(config.go_cb_ref.len()) + config.go_cb_ref.len();

    // Helper for minimal unsigned integer encoding size (stack only)
    fn minimal_unsigned_len(value: u64) -> usize {
        let buf = value.to_be_bytes();
        let mut start = 0;
        while start < buf.len() - 1 && buf[start] == 0 {
            start += 1;
        }
        let minimal = &buf[start..];
        if !minimal.is_empty() && (minimal[0] & 0x80) != 0 {
            minimal.len() + 1 // leading zero for positive
        } else {
            minimal.len()
        }
    }

    // [81] timeAllowedToLive (Unsigned, minimal BER)
    let time_allowed_to_live = config.max_repetition * 2; // Following recommendation
    let time_allowed_to_live_len = minimal_unsigned_len(time_allowed_to_live as u64);
    pdu_size += 1 + size_length(time_allowed_to_live_len) + time_allowed_to_live_len;

    // [82] datSet (VisibleString)
    pdu_size += 1 + size_length(config.dat_set.len()) + config.dat_set.len();

    // [83] goID (VisibleString)
    pdu_size += 1 + size_length(config.go_id.len()) + config.go_id.len();

    // [84] t (UtcTime, 8 bytes)
    pdu_size += 1 + size_length(8) + 8;

    // [85] stNum (Unsigned, minimal BER)
    let st_num_len = minimal_unsigned_len(runtime.st_num as u64);
    pdu_size += 1 + size_length(st_num_len) + st_num_len;

    // [86] sqNum (Unsigned, minimal BER)
    let sq_num_len = minimal_unsigned_len(runtime.sq_num as u64);
    pdu_size += 1 + size_length(sq_num_len) + sq_num_len;

    // [87] simulation (Boolean)
    pdu_size += 3; // tag + length + value

    // [88] confRev (Unsigned, minimal BER)
    let conf_rev_len = minimal_unsigned_len(config.conf_rev as u64);
    pdu_size += 1 + size_length(conf_rev_len) + conf_rev_len;

    // [89] ndsCom (Boolean)
    pdu_size += 3; // tag + length + value

    // [8a] numDataSetEntries (Unsigned, minimal BER)
    let num_entries = config.all_data.len() as u64;
    let num_entries_len = minimal_unsigned_len(num_entries);
    pdu_size += 1 + size_length(num_entries_len) + num_entries_len;

    // [ab] allData tag and length
    pdu_size += 1 + size_length(all_data_size);
    pdu_size += all_data_size;

    pdu_size
}

/// Returns the number of bytes required to encode a complete GooseFrame (Ethernet header + GOOSE PDU).
pub fn goose_size(config: &GooseConfig, runtime: &GooseRuntime) -> (u16, usize, usize) {
    let dat_set_size = size_iec_data(&config.all_data);
    let pdu_size = size_goose_pdu(config, runtime, dat_set_size);

    let length: u16 = (pdu_size + 8 + 3) as u16; // APPID + length + reserved fields length of PDU
    (length, pdu_size, dat_set_size)
}

pub fn encode_goose(
    config: &GooseConfig,
    runtime: &GooseRuntime,
    buffer: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut new_pos = 0;

    let (length, pdu_length, data_set_size) = goose_size(&config, runtime);

    // Destination MAC address (6 bytes)
    buffer[new_pos..new_pos + 6].copy_from_slice(&config.dst_addr);
    new_pos += 6;

    // Source MAC address (6 bytes)
    buffer[new_pos..new_pos + 6].copy_from_slice(&runtime.src_addr);
    new_pos += 6;

    // VLAN tag (TPID and TCI) is optional
    if let (Some(tpid), Some(tci)) = (&config.tpid, &config.tci) {
        // Write TPID (2 bytes)
        buffer[new_pos..new_pos + 2].copy_from_slice(tpid);
        new_pos += 2;
        // Write TCI (2 bytes)
        buffer[new_pos..new_pos + 2].copy_from_slice(tci);
        new_pos += 2;
    }

    // EtherType is fixed to 0x88B8 for GOOSE
    buffer[new_pos..new_pos + 2].copy_from_slice(&[0x88, 0xB8]);
    new_pos += 2;

    // APPID (2 bytes)
    buffer[new_pos..new_pos + 2].copy_from_slice(&config.appid);
    new_pos += 2;

    // Length (2 bytes)
    buffer[new_pos..new_pos + 2].copy_from_slice(&(length as u16).to_be_bytes());
    new_pos += 2;

    // Reserved 1 (2 bytes, set to 0)
    buffer[new_pos..new_pos + 2].copy_from_slice(&[0; 2]);
    new_pos += 2;

    // Reserved 2 (2 bytes, set to 0)
    buffer[new_pos..new_pos + 2].copy_from_slice(&[0; 2]);
    new_pos += 2;

    // [61] GOOSE PDU tag and length
    new_pos = encode_tag_length(0x61, pdu_length, buffer, new_pos)?;

    // [80] goCbRef (VisibleString)
    new_pos = encode_string(0x80, &config.go_cb_ref, buffer, new_pos)?;

    // [81] timeAllowedToLive (Unsigned)
    let time_allowed_to_live = config.max_repetition * 2; // Following recommendation
    new_pos = encode_unsigned_integer(0x81, &time_allowed_to_live.to_be_bytes(), buffer, new_pos)?;

    // [82] datSet (VisibleString)
    new_pos = encode_string(0x82, &config.dat_set, buffer, new_pos)?;

    // [83] goID (VisibleString)
    new_pos = encode_string(0x83, &config.go_id, buffer, new_pos)?;

    // [84] t (UtcTime, 8 bytes)
    new_pos = encode_octet_string(0x84, &runtime.timestamp, buffer, new_pos)?;

    // [85] stNum (Unsigned)
    new_pos = encode_unsigned_integer(0x85, &runtime.st_num.to_be_bytes(), buffer, new_pos)?;

    // [86] sqNum (Unsigned)
    new_pos = encode_unsigned_integer(0x86, &runtime.sq_num.to_be_bytes(), buffer, new_pos)?;

    // [87] simulation (Boolean)
    new_pos = encode_boolean(0x87, config.simulation, buffer, new_pos)?;

    // [88] confRev (Unsigned)
    new_pos = encode_unsigned_integer(0x88, &config.conf_rev.to_be_bytes(), buffer, new_pos)?;

    // [89] ndsCom (Boolean)
    new_pos = encode_boolean(0x89, config.nds_com, buffer, new_pos)?;

    // [8a] numDataSetEntries (Unsigned)
    new_pos = encode_unsigned_integer(
        0x8a,
        &(config.all_data.len() as u16).to_be_bytes(),
        buffer,
        new_pos,
    )?;

    // [ab] allData tag and length
    new_pos = encode_tag_length(0xab, data_set_size, buffer, new_pos)?;

    // allData (Array of IECData)
    new_pos = encode_iec_data(&config.all_data, buffer, new_pos)?;

    Ok(new_pos)
}
