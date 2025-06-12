use iec_61850_lib::encode_goose::*;
use iec_61850_lib::types::*;

#[test]
fn test_encode_goose_pdu() {
    // Create a minimal IECGoosePdu or your equivalent struct
    let goose_config = GooseConfig {
        dst_addr: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
        tpid: Some([0x81, 0x00]),
        tci: Some([0x00, 0x01]),
        appid: [0x10, 0x01],
        go_cb_ref: "IED1/LLN0$GO$gcb1".to_string(),
        dat_set: "IED1/LLN0$DATASET1".to_string(),
        go_id: "GOOSE1".to_string(),
        simulation: false,
        conf_rev: 0x80, // 128
        nds_com: false,
        num_dat_set_entries: 2,
        all_data: vec![
            IECData::Int8u(1),           // minimal = [0x01], no leading zero needed
            IECData::Int16u(0x80),       // minimal = [0x80], triggers leading zero branch
            IECData::Int32u(0x000000FF), // minimal = [0xFF], triggers leading zero branch
            IECData::Int32u(0x0000007F), // minimal = [0x7F], no leading zero needed
            IECData::Int32u(0x00000001), // minimal = [0x01], no leading zero needed
            IECData::Int32u(0x00000080), // minimal = [0x80], triggers leading zero branch
            IECData::Int32u(0x000000FF), // minimal = [0xFF], triggers leading zero branch
            IECData::Boolean(true),
            IECData::Int16(1234),
            IECData::VisibleString("test".to_string()),
        ],
        max_repetition: 1000,
        min_repetition: 500,
    };
    let runtime = GooseRuntime {
        st_num: 1,
        sq_num: 42,
        timestamp: [0x20, 0x21, 0x06, 0x12, 0x0A, 0x30, 0x00, 0x00],
        src_addr: [0x00, 0x1A, 0xB6, 0x03, 0x2F, 0x1C],
    };
    let mut buf = [0u8; 1518];
    let result = encode_goose(&goose_config, &runtime, &mut buf);
    assert!(result.is_ok());

    let len = result.unwrap();

    // Replace this with your actual expected encoding:
    let expected: &[u8] = &[
        1, 12, 205, 1, 0, 1, 0, 26, 182, 3, 47, 28, 129, 0, 0, 1, 136, 184, 16, 1, 0, 130, 0, 0, 0,
        0, 97, 120, 128, 17, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 71, 79, 36, 103, 99, 98, 49,
        129, 2, 7, 208, 130, 18, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 68, 65, 84, 65, 83, 69,
        84, 49, 131, 6, 71, 79, 79, 83, 69, 49, 132, 8, 32, 33, 6, 18, 10, 48, 0, 0, 133, 1, 1,
        134, 1, 42, 135, 1, 0, 136, 2, 0, 128, 137, 1, 0, 138, 1, 10, 171, 38, 134, 1, 1, 134, 2,
        0, 128, 134, 2, 0, 255, 134, 1, 127, 134, 1, 1, 134, 2, 0, 128, 134, 2, 0, 255, 131, 1,
        255, 133, 2, 4, 210, 138, 4, 116, 101, 115, 116,
    ];

    assert_eq!(len, 148, "Encoded length does not match expected length");

    assert_eq!(
        &buf[..len],
        expected,
        "Encoded buffer does not match expected output"
    );
}
