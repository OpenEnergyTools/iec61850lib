use iec_61850_lib::encode_basics::*;

#[test]
fn test_minimal_twos_complement_bytes() {
    // 0x00 0x7F should become 0x7F
    assert_eq!(minimal_twos_complement_bytes(&[0x00, 0x7F]), &[0x7F]);
    // 0xFF 0x80 should become 0x80
    assert_eq!(minimal_twos_complement_bytes(&[0xFF, 0x80]), &[0x80]);
    // 0x00 0x00 0x01 should become 0x01
    assert_eq!(minimal_twos_complement_bytes(&[0x00, 0x00, 0x01]), &[0x01]);
    // 0x00 0x80: 0x00 is NOT redundant, so should not be stripped
    assert_eq!(minimal_twos_complement_bytes(&[0x00, 0x80]), &[0x00, 0x80]);
    // 0xFF 0x7F: 0xFF is NOT redundant, so should not be stripped
    assert_eq!(minimal_twos_complement_bytes(&[0xFF, 0x7F]), &[0xFF, 0x7F]);
}

#[test]
fn test_size_length() {
    assert_eq!(size_length(127), 1);
    assert_eq!(size_length(128), 2);
    assert_eq!(size_length(255), 2);
    assert_eq!(size_length(256), 3);
    assert_eq!(size_length(65535), 4);
}

#[test]
fn test_encode_tag_length() {
    let mut buf = [0u8; 4];
    let pos = encode_tag_length(0x80, 10, &mut buf, 0).unwrap();
    assert_eq!(pos, 2);
    assert_eq!(&buf[..2], &[0x80, 0x0A]);

    let mut buf = [0u8; 6];
    let pos = encode_tag_length(0x80, 200, &mut buf, 0).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(&buf[..3], &[0x80, 0x81, 0xC8]);

    let mut buf = [0u8; 6];
    let pos = encode_tag_length(0x80, 1300, &mut buf, 0).unwrap();
    assert_eq!(pos, 4);
    assert_eq!(&buf[..4], &[0x80, 0x82, 0x05, 0x14]);

    let mut buf = [0u8; 6];
    let pos = encode_tag_length(0x80, 70000, &mut buf, 0).unwrap();
    assert_eq!(pos, 5);
    assert_eq!(&buf[..5], &[0x80, 0x83, 0x01, 0x11, 0x70]);
}

#[test]
fn test_encode_tag_length_short_buffer() {
    // This will require 4 bytes (tag + 3-byte length), but buffer is only 3 bytes
    let mut buf = [0u8; 3];
    let result = encode_tag_length(0x80, 300, &mut buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_encode_tag_length_exceeds_max_length() {
    // Value exceeds 3-byte BER encoding (should trigger error in encode_tag_length)
    let mut buf = [0u8; 10];
    // 1 << 24 == 16777216, which is just above the supported range
    let result = encode_tag_length(0x80, 16_777_216, &mut buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_encode_ber_buffer_too_small() {
    // Assuming encode_ber encodes some IECData into the buffer.
    // We'll use a buffer that's too small to trigger the error.

    let mut buf = [0u8; 1]; // Intentionally too small
    let result = encode_ber(0x80, &[0xFF, 0x10], &mut buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_encode_ber_short_buffer() {
    let mut buf = [0u8; 3];
    let pos = encode_boolean(0x81, true, &mut buf, 0).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(&buf, &[0x81, 0x01, 0xFF]);
    let mut buf = [0u8; 3];
    let pos = encode_boolean(0x81, false, &mut buf, 0).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(&buf, &[0x81, 0x01, 0x00]);
}

#[test]
fn test_encode_ber() {
    let mut buf = [0u8; 10];
    let value = [0xDE, 0xAD, 0xBE, 0xEF];
    let start_pos = 2;
    let result = encode_ber(0x80, &value, &mut buf, start_pos);
    assert!(result.is_ok());
    let end_pos = result.unwrap();
    assert_eq!(&buf[start_pos..start_pos + 2], &[0x80, 0x04]); // tag and length
    assert_eq!(&buf[start_pos + 2..end_pos], &value); // value
    assert_eq!(end_pos, start_pos + 2 + value.len());
}

#[test]
fn test_encode_boolean() {
    let mut buf = [0u8; 3];
    let pos = encode_boolean(0x81, true, &mut buf, 0).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(&buf, &[0x81, 0x01, 0xFF]);

    let mut buf = [0u8; 3];
    let pos = encode_boolean(0x81, false, &mut buf, 0).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(&buf, &[0x81, 0x01, 0x00]);
}

#[test]
fn test_encode_boolean_buffer_too_small() {
    // encode_boolean writes 3 bytes (tag, length, value), so a buffer of 2 is too small
    let mut buf = [0u8; 2];
    let result = encode_boolean(0x81, true, &mut buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_encode_string() {
    let mut buf = [0u8; 10];
    let pos = encode_string(0x82, "A", &mut buf, 0).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(&buf[..3], &[0x82, 0x01, 0x41]);
}

#[test]
fn test_encode_octet_string() {
    let mut buf = [0u8; 10];
    let pos = encode_octet_string(0x83, &[0x01, 0x02], &mut buf, 0).unwrap();
    assert_eq!(pos, 4);
    assert_eq!(&buf[..4], &[0x83, 0x02, 0x01, 0x02]);
}

#[test]
fn test_encode_integer() {
    let mut buf = [0u8; 10];
    let pos = encode_integer(0x84, &[0x00, 0x7F], &mut buf, 0).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(&buf[..3], &[0x84, 0x01, 0x7F]);
}

#[test]
fn test_encode_unsigned_integer() {
    let mut buf = [0u8; 10];
    let pos = encode_unsigned_integer(0x85, &[0x7F], &mut buf, 0).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(&buf[..3], &[0x85, 0x01, 0x7F]);
    // Test with MSB set (should prepend 0x00)
    let mut buf = [0u8; 10];
    let pos = encode_unsigned_integer(0x85, &[0xFF], &mut buf, 0).unwrap();
    assert_eq!(pos, 4);
    assert_eq!(&buf[..4], &[0x85, 0x02, 0x00, 0xFF]);

    // 0xFF: MSB is set, should return 2
    let bytes = [0xFF];
    assert_eq!(minimal_unsigned_size(&bytes), 2);
}

#[test]
fn test_encode_float() {
    let mut buf = [0u8; 10];
    let float_bytes = 1.0f32.to_be_bytes();
    let pos = encode_float(0x09, &float_bytes, &mut buf, 0).unwrap();
    assert_eq!(pos, 7);
    assert_eq!(
        &buf[..7],
        &[
            0x09,
            0x05,
            0x08,
            float_bytes[0],
            float_bytes[1],
            float_bytes[2],
            float_bytes[3]
        ]
    );
}

#[test]
fn test_encode_float_wrong_length() {
    let mut buf = [0u8; 10];
    // Too short
    let bytes = [0x00, 0x01, 0x02];
    let result = encode_float(0x09, &bytes, &mut buf, 0);
    assert!(result.is_err());
    // Too long
    let bytes = [0x00, 0x01, 0x02, 0x03, 0x04];
    let result = encode_float(0x09, &bytes, &mut buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_encode_float_buffer_too_small() {
    let mut buf = [0u8; 5]; // Needs at least 6 bytes
    let bytes = 1.0f32.to_be_bytes();
    let result = encode_float(0x09, &bytes, &mut buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_encode_coded_enum() {
    let mut buf = [0u8; 10];
    encode_coded_enum(0x03, &[0b10100000], 3, &mut buf, 0).unwrap();
    // The value byte should be reversed bits: 0b10100000 -> 0b00000101
    assert_eq!(&buf[..4], &[0x03, 0x02, 0x03, 0x05]);
}

#[test]
fn test_encode_coded_enum_buffer_too_small() {
    let mut buf = [0u8; 2]; // Intentionally too small
    let value = [0b10100000];
    let padding = 3;
    let result = encode_coded_enum(0x03, &value, padding, &mut buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_encode_ied_data_all_types() {
    use iec_61850_lib::types::IECData;

    let all_types: Vec<IECData> = vec![
        IECData::Boolean(true),
        IECData::Int16(0x7F01), // 0x7F is not a redundant sign-extension byte for 0x7F01
        IECData::Int16(-32767), // 0x80 0x01, not a redundant sign-extension
        IECData::Int8(0x01),    // Single byte, else branch is hit
        IECData::Int8(-1),      // Single byte, else branch is hit
        IECData::Int8(-8),
        IECData::Int16(-16),
        IECData::Int32(-32),
        IECData::Int64(-64),
        IECData::Int8u(8),
        IECData::Int16u(16),
        IECData::Int32u(32),
        IECData::Float32(1.23),
        IECData::OctetString(vec![0x01, 0x02, 0x03]),
        IECData::VisibleString("abc".to_string()),
        IECData::MmsString("üöäß".to_string()),
        IECData::BitString {
            padding: 3,
            val: vec![0b10101000],
        },
        IECData::Array(vec![IECData::Int8u(1), IECData::Int8u(2)]),
        IECData::Structure(vec![
            IECData::MmsString("field2".to_string()),
            IECData::Int16(42),
        ]),
        IECData::UtcTime([1, 2, 3, 4, 5, 6, 7, 8]),
    ];

    let mut buf = [0u8; 1518]; // Maximum Ethernet frame size
    let result = encode_iec_data(&all_types, &mut buf, 0);
    assert!(result.is_ok());
    let len = result.unwrap();

    // Replace this with your actual expected encoding:
    let expected: &[u8] = &[
        131, 1, 255, 133, 2, 127, 1, 133, 2, 128, 1, 133, 1, 1, 133, 1, 255, 133, 1, 248, 133, 1,
        240, 133, 1, 224, 133, 1, 192, 134, 1, 8, 134, 1, 16, 134, 1, 32, 135, 5, 8, 63, 157, 112,
        164, 137, 3, 1, 2, 3, 138, 3, 97, 98, 99, 144, 8, 195, 188, 195, 182, 195, 164, 195, 159,
        132, 2, 3, 21, 161, 6, 134, 1, 1, 134, 1, 2, 162, 11, 144, 6, 102, 105, 101, 108, 100, 50,
        133, 1, 42, 145, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];

    assert_eq!(len, 100, "Encoded length does not match expected length");

    assert_eq!(
        &buf[..len],
        expected,
        "Encoded buffer does not match expected output"
    );
}

#[test]
fn test_encode_ied_data_unknown_data() {
    use iec_61850_lib::types::IECData;

    let all_types: Vec<IECData> = vec![IECData::Float64(1.23)];

    let mut buf = [0u8; 1518]; // Maximum Ethernet frame size
    let result = encode_iec_data(&all_types, &mut buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_size_iec_data_all_types() {
    use iec_61850_lib::types::IECData;

    let all_types: Vec<IECData> = vec![
        IECData::Boolean(true),
        IECData::Int16(0x7F01), // 0x7F is not a redundant sign-extension byte for 0x7F01
        IECData::Int16(-32767), // 0x80 0x01, not a redundant sign-extension
        IECData::Int8(0x01),    // Single byte, else branch is hit
        IECData::Int8(-1),      // Single byte, else branch is hit
        IECData::Int8(-8),
        IECData::Int16(-16),
        IECData::Int32(-32),
        IECData::Int64(-64),
        IECData::Int8u(8),
        IECData::Int16u(16),
        IECData::Int32u(32),
        IECData::Float32(1.23),
        IECData::OctetString(vec![0x01, 0x02, 0x03]),
        IECData::VisibleString("abc".to_string()),
        IECData::MmsString("üöäß".to_string()),
        IECData::BitString {
            padding: 3,
            val: vec![0b10101000],
        },
        IECData::Array(vec![IECData::Int8u(1), IECData::Int8u(2)]),
        IECData::Structure(vec![
            IECData::MmsString("field2".to_string()),
            IECData::Int16(42),
        ]),
        IECData::UtcTime([1, 2, 3, 4, 5, 6, 7, 8]),
    ];

    let result = size_iec_data(&all_types);

    assert_eq!(result, 100, "Encoded length does not match expected length");
}

#[test]
fn test_size_ied_data_unknown_data() {
    use iec_61850_lib::types::IECData;

    let all_types: Vec<IECData> = vec![IECData::Float64(1.23)];

    let result = size_iec_data(&all_types);
    assert_eq!(result, 0);
}
