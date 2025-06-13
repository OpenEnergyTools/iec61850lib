use iec_61850_lib::{
    decode_basics::decode_ethernet_header,
    decode_goose::{decode_goose_pdu, is_goose_frame},
    types::{EthernetHeader, IECData, IECGoosePdu},
};

#[test]
fn test_decode_goose_pdu_all_fields() {
    let buf: &[u8] = &[
        1, 12, 205, 1, 0, 1, 0, 26, 182, 3, 47, 28, 129, 0, 0, 1, 136, 184, 16, 1, 0, 140, 0, 0, 0,
        0, 97, 129, 129, 128, 17, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 71, 79, 36, 103, 99, 98,
        49, 129, 2, 7, 208, 130, 18, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 68, 65, 84, 65, 83,
        69, 84, 49, 131, 6, 71, 79, 79, 83, 69, 49, 132, 8, 32, 33, 6, 18, 10, 48, 0, 0, 133, 1, 1,
        134, 1, 42, 135, 1, 0, 136, 2, 0, 128, 137, 1, 0, 138, 1, 11, 171, 47, 134, 1, 1, 134, 2,
        0, 128, 134, 2, 0, 255, 134, 1, 127, 134, 1, 1, 134, 2, 0, 128, 134, 2, 0, 255, 131, 1,
        255, 133, 4, 127, 255, 255, 255, 133, 5, 0, 128, 0, 0, 0, 138, 4, 116, 101, 115, 116,
    ];

    let mut goose_pdu = IECGoosePdu::default();
    let mut header = EthernetHeader::default();
    let pos = decode_ethernet_header(&mut header, &buf);
    let pos = decode_goose_pdu(&mut goose_pdu, &buf, pos);

    assert_eq!(pos, buf.len());
    assert_eq!(goose_pdu.go_cb_ref, "IED1/LLN0$GO$gcb1");
    assert_eq!(goose_pdu.time_allowed_to_live, 2000);
    assert_eq!(goose_pdu.dat_set, "IED1/LLN0$DATASET1");
    assert_eq!(goose_pdu.go_id, "GOOSE1");
    assert_eq!(
        goose_pdu.t,
        [0x20, 0x21, 0x06, 0x12, 0x0A, 0x30, 0x00, 0x00]
    );
    assert_eq!(goose_pdu.st_num, 1);
    assert_eq!(goose_pdu.sq_num, 42);
    assert_eq!(goose_pdu.simulation, false);
    assert_eq!(goose_pdu.conf_rev, 128);
    assert_eq!(goose_pdu.nds_com, false);
    assert_eq!(goose_pdu.num_dat_set_entries, 11);
    assert_eq!(goose_pdu.all_data[0], IECData::Int8u(1));
    assert_eq!(goose_pdu.all_data[1], IECData::Int16u(0x80));
    assert_eq!(goose_pdu.all_data[2], IECData::Int16u(0x000000FF));
    assert_eq!(goose_pdu.all_data[3], IECData::Int8u(0x0000007F));
    assert_eq!(goose_pdu.all_data[4], IECData::Int8u(0x00000001));
    assert_eq!(goose_pdu.all_data[5], IECData::Int16u(0x00000080));
    assert_eq!(goose_pdu.all_data[6], IECData::Int16u(0x000000FF));
    assert_eq!(goose_pdu.all_data[7], IECData::Boolean(true));
    assert_eq!(goose_pdu.all_data[8], IECData::Int32(2147483647));
    assert_eq!(goose_pdu.all_data[9], IECData::Int64(2147483648));
    assert_eq!(
        goose_pdu.all_data[10],
        IECData::VisibleString("test".to_string())
    );
}

#[test]
fn test_is_goose_frame() {
    // GOOSE EtherType without VLAN tag (0x88b8 at bytes 12-13)
    let mut buf = [0u8; 60];
    buf[12] = 0x88;
    buf[13] = 0xb8;
    assert!(is_goose_frame(&buf));

    // GOOSE EtherType with VLAN tag (0x81, 0x00 at 12-13, 0x88b8 at 16-17)
    let mut buf_vlan = [0u8; 60];
    buf_vlan[12] = 0x81;
    buf_vlan[13] = 0x00;
    buf_vlan[16] = 0x88;
    buf_vlan[17] = 0xb8;
    assert!(is_goose_frame(&buf_vlan));

    // Not a GOOSE frame (wrong EtherType)
    let mut buf_wrong = [0u8; 60];
    buf_wrong[12] = 0x08;
    buf_wrong[13] = 0x00;
    assert!(!is_goose_frame(&buf_wrong));

    // Not a GOOSE frame (VLAN tag present, wrong EtherType)
    let mut buf_vlan_wrong = [0u8; 60];
    buf_vlan_wrong[12] = 0x81;
    buf_vlan_wrong[13] = 0x00;
    buf_vlan_wrong[16] = 0x08;
    buf_vlan_wrong[17] = 0x00;
    assert!(!is_goose_frame(&buf_vlan_wrong));

    // Buffer just too short for EtherType without VLAN
    let short_buf = [0u8; 13];
    assert!(!is_goose_frame(&short_buf));

    // Buffer just too short for EtherType with VLAN
    let mut short_vlan_buf = [0u8; 17];
    short_vlan_buf[12] = 0x81;
    short_vlan_buf[13] = 0x00;
    assert!(!is_goose_frame(&short_vlan_buf));
}
