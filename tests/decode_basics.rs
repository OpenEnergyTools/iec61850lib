use iec_61850_lib::decode_basics::*;
use iec_61850_lib::types::*;

#[test]
fn test_decode_boolean() {
    let buf = [0x81, 0x01, 0xFF];
    let mut value = false;
    let result = decode_boolean(&mut value, &buf, 0).unwrap();
    assert_eq!(result, 1);

    assert!(value, "Expected value to be true after decoding boolean");

    // Error branch: buffer_index out of bounds
    let err = decode_boolean(&mut value, &buf, 10);
    assert!(err.is_err());
}

#[test]
fn test_decode_integer() {
    // 0x84 as i8 is -124
    let buf = [0x84, 0x01, 0x84];
    let mut value: i8 = 0;
    let result = decode_integer_8(&mut value, &buf, 2, 1).unwrap();
    assert_eq!(result, 3);

    assert_eq!(
        value, -124,
        "Expected value to be -124 after decoding integer"
    );

    // Error branch: decompress_integer out of bounds
    let err = decode_integer_8(&mut value, &buf, 10, 1);
    assert!(err.is_err());

    // Error branch: decompress_integer length > value.len()
    let err = decompress_integer(&mut [0u8; 1], &buf, 2, 2);
    assert!(err.is_err());

    // Pass length that does not match value.len()
    let buf = [0x01, 0x02, 0x03, 0x04];
    let mut value = [0u8; 2];
    let err = decompress_integer(&mut value, &buf, 0, 3);
    assert!(err.is_err());
    let msg: String = err.unwrap_err().message.iter().collect();
    assert!(msg.contains("Mismatch value length"));

    // Decoding a 1-byte negative integer (0x84, which is -124 as i8) into a 2-byte i16.
    // This tests sign extension: the high byte should be filled with 0xFF, resulting in 0xFF84 (-124 as i16).
    let buf = [0x84, 0x01, 0x84];
    let mut value: i16 = 0;
    let result = decode_integer_16(&mut value, &buf, 2, 1).unwrap();
    assert_eq!(result, 3);

    assert_eq!(
        value, -124,
        "Expected value to be -124 after decoding integer"
    );

    // 0x7FFF as i16 is 32767
    let buf = [0x84, 0x02, 0x7F, 0xFF];
    let mut value: i16 = 0;
    let result = decode_integer_16(&mut value, &buf, 2, 2).unwrap();
    assert_eq!(result, 4);

    assert_eq!(
        value, 32767,
        "Expected value to be 32767 after decoding integer"
    );

    // 0x000001 as i32 is 1
    let buf = [0x84, 0x03, 0x00, 0x00, 0x00, 0x01];
    let mut value: i32 = 0;
    let result = decode_integer_32(&mut value, &buf, 2, 4).unwrap();
    assert_eq!(result, 6);

    assert_eq!(value, 1, "Expected value to be 1 after decoding integer");

    // 0x8000000000000000 as i64 is 1
    let buf = [0x84, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut value: i64 = 0;
    let result = decode_integer_64(&mut value, &buf, 2, 8).unwrap();
    assert_eq!(result, 10);

    assert_eq!(
        value, -9223372036854775808,
        "Expected value to be -9223372036854775808 after decoding integer"
    );
}

#[test]
fn test_decode_unsigned_integer() {
    let buf = [0x85, 0x01, 0x7F];
    let mut value: u8 = 0;
    let result = decode_unsigned_8(&mut value, &buf, 2, 1).unwrap();
    assert_eq!(result, 3);

    assert_eq!(
        value, 127,
        "Expected value to be 127 after decoding integer"
    );

    // Error branch: decompress_integer out of bounds
    let err = decode_unsigned_8(&mut value, &buf, 10, 1);
    assert!(err.is_err());

    // 0xFFFF as u16 is 65535
    let buf = [0x85, 0x02, 0xFF, 0xFF];
    let mut value: u16 = 0;
    let result = decode_unsigned_16(&mut value, &buf, 2, 2).unwrap();
    assert_eq!(result, 4);

    assert_eq!(
        value, 65535,
        "Expected value to be 65535 after decoding unsigned 16-bit integer"
    );

    // 0xFFFFFFFF as u32 is 4294967295
    let buf = [0x85, 0x04, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut value: u32 = 0;
    let result = decode_unsigned_32(&mut value, &buf, 2, 4).unwrap();
    assert_eq!(result, 6);

    assert_eq!(
        value, 4294967295,
        "Expected value to be 4294967295 after decoding unsigned 32-bit integer"
    );
}

#[test]
fn test_decode_float() {
    let mut value: f32 = 0.0;
    let test_value: f32 = 345234.2345234;
    let test_bytes = test_value.to_be_bytes();
    let buf = [
        0x09,
        0x05,
        0x08,
        test_bytes[0],
        test_bytes[1],
        test_bytes[2],
        test_bytes[3],
    ];
    let result = decode_float_32(&mut value, &buf, 2, 5).unwrap();
    assert_eq!(result, 7);
    assert_eq!(
        value, test_value,
        "Expected value to be {} after decoding float",
        test_value
    );

    // Maximum positive f32
    let max_f32 = std::f32::MAX;
    let max_bytes = max_f32.to_be_bytes();
    let buf_max = [
        0x09, // tag
        0x05, // length
        0x08, // descriptor
        max_bytes[0],
        max_bytes[1],
        max_bytes[2],
        max_bytes[3],
    ];
    let mut decoded_max: f32 = 0.0;
    let result = decode_float_32(&mut decoded_max, &buf_max, 2, 5).unwrap();
    assert_eq!(result, 7);
    assert_eq!(
        decoded_max, max_f32,
        "Expected value to be {} after decoding max float",
        max_f32
    );

    // Minimum (most negative) f32
    let min_f32 = -std::f32::MAX;
    let min_bytes = min_f32.to_be_bytes();
    let buf_min = [
        0x09, // tag
        0x05, // length
        0x08, // descriptor
        min_bytes[0],
        min_bytes[1],
        min_bytes[2],
        min_bytes[3],
    ];
    let mut decoded_min: f32 = 0.0;
    let result = decode_float_32(&mut decoded_min, &buf_min, 2, 5).unwrap();
    assert_eq!(result, 7);
    assert_eq!(
        decoded_min, min_f32,
        "Expected value to be {} after decoding min float",
        min_f32
    );

    let mut value: f32 = 0.0;
    // Buffer is too short to read 5 bytes for f32 (needs at least buffer_index+5 bytes)
    let buf = [0x09, 0x05, 0x08, 0x01];
    // Try to decode starting at index 2, length 5 (will go out of bounds)
    let err = decode_float_32(&mut value, &buf, 2, 5);
    assert!(err.is_err());
    let msg: String = err.unwrap_err().message.iter().collect();
    assert!(msg.contains("exceeds buffer length"));
}

#[test]
fn test_decode_string() {
    let mut value = String::new();
    // "AΩßÄ" in UTF-8: 0x41 0xCE 0xA9 0xC3 0x9F 0xC3 0x84
    let buf = [0x82, 0x07, 0x41, 0xCE, 0xA9, 0xC3, 0x9F, 0xC3, 0x84];
    let result = decode_string(&mut value, &buf, 2, 7).unwrap();
    assert_eq!(result, 9);
    assert_eq!(
        value, "AΩßÄ",
        "Expected value to be 'AΩßÄ' after decoding string"
    );

    // Error branch: buffer too short for string
    let err = decode_string(&mut value, &buf, 5, 10);
    assert!(err.is_err());
}

#[test]
fn test_decode_octet_string() {
    // Example octet string: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]
    let buf = [0x89, 0x06, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
    let mut value = [0u8; 6];
    // buffer_index = 2 (skip tag and length), length = 6
    let result = decode_octet_string(&mut value, &buf, 2, 6).unwrap();
    assert_eq!(result, 8);
    assert_eq!(value, [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]);

    // Error branch: buffer too short for octet string
    let err = decode_octet_string(&mut value, &buf, 5, 6);
    assert!(err.is_err());
}

#[test]
fn test_decode_bit_string() {
    // Let's encode the bit string 0b10101010100010 (14 bits)
    // In bytes: [0b10101010, 0b10001000]
    // ASN.1 BER BIT STRING encoding: [tag][length][padding][value bytes...]
    // Let's use tag 0x84, length 3 (1 padding byte + 2 value bytes), padding 2 (2 unused bits in last byte)
    let buf = [0x84, 0x03, 0x02, 0b10101010, 0b10001000];

    let mut val = Vec::new();
    let mut padding = 0u8;
    // buffer_index = 2 (where padding starts), length = 3 (padding + 2 value bytes)
    let result = decode_bit_string(&mut val, &mut padding, &buf, 2, 3).unwrap();

    // The function reverses the order and bits of each byte
    // 0b10101010.reverse_bits() = 0b01010101 = 0x55
    // 0b10001000.reverse_bits() = 0b00010001 = 0x11
    // The order is reversed, so val = [0x11, 0x55]
    assert_eq!(result, 5);
    assert_eq!(padding, 2);
    assert_eq!(val, vec![0x11, 0x55]);

    // Error branch: buffer too short for bit string
    let err = decode_bit_string(&mut val, &mut padding, &buf, 4, 3);
    assert!(err.is_err());
}

#[test]
fn test_decode_tag_length() {
    // Short form: tag = 0xA1, length = 5
    let buf_short = [0xA1, 0x05];
    let mut tag: u8 = 0;
    let mut length: usize = 0;
    let pos = decode_tag_length(&mut tag, &mut length, &buf_short, 0).unwrap();
    assert_eq!(tag, 0xA1);
    assert_eq!(length, 5);
    assert_eq!(pos, 2);

    // Long form: tag = 0xA2, length = 0x0123 (2 length bytes)
    let buf_long = [0xA2, 0x82, 0x01, 0x23];
    let mut tag: u8 = 0;
    let mut length: usize = 0;
    let pos = decode_tag_length(&mut tag, &mut length, &buf_long, 0).unwrap();
    assert_eq!(tag, 0xA2);
    assert_eq!(length, 0x0123);
    assert_eq!(pos, 4);

    // Long form: tag = 0xA3, length = 0x000102 (3 length bytes)
    let buf_long3 = [0xA3, 0x83, 0x00, 0x01, 0x02];
    let mut tag: u8 = 0;
    let mut length: usize = 0;
    let pos = decode_tag_length(&mut tag, &mut length, &buf_long3, 0).unwrap();
    assert_eq!(tag, 0xA3);
    assert_eq!(length, 0x000102);
    assert_eq!(pos, 5);

    // Error branch: missing length byte
    let buf_missing = [0xA1];
    let mut tag: u8 = 0;
    let mut length: usize = 0;
    let err = decode_tag_length(&mut tag, &mut length, &buf_missing, 0);
    assert!(err.is_err());

    // Error branch: invalid number of length bytes (0)
    let buf_invalid = [0xA1, 0x80];
    let mut tag: u8 = 0;
    let mut length: usize = 0;
    let err = decode_tag_length(&mut tag, &mut length, &buf_invalid, 0);
    assert!(err.is_err());

    // Error branch: not enough bytes for multi-byte length
    let buf_short_len = [0xA1, 0x82, 0x01];
    let mut tag: u8 = 0;
    let mut length: usize = 0;
    let err = decode_tag_length(&mut tag, &mut length, &buf_short_len, 0);
    assert!(err.is_err());

    let mut tag: u8 = 0;
    let mut length: usize = 0;
    // Empty buffer triggers out of bounds
    let buf: [u8; 0] = [];
    let err = decode_tag_length(&mut tag, &mut length, &buf, 0);
    assert!(err.is_err());
    let msg: String = err.unwrap_err().message.iter().collect();
    assert!(msg.contains("Out of bounds for buffer length"));
}

#[test]
fn test_decode_iec_data_element_errors() {
    // Oversize signed integer
    let buf = [0x85, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let err = decode_iec_data_element(&buf, 0);
    assert!(err.is_err());
    let err = decode_iec_data_element(&buf, 0).unwrap_err();
    let msg: String = err.message.iter().collect();
    assert!(msg.contains("oversize signed integer"));

    // Oversize unsigned integer
    let buf = [0x86, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let err = decode_iec_data_element(&buf, 0);
    assert!(err.is_err());
    let msg: String = err.unwrap_err().message.iter().collect();
    assert!(msg.contains("Unsigned integer exceeds supported size"));

    // 5-byte unsigned integer, but first byte is not 0x00
    let buf = [0x86, 0x05, 0x01, 0, 0, 0, 0];
    let err = decode_iec_data_element(&buf, 0);
    assert!(err.is_err());
    let msg: String = err.unwrap_err().message.iter().collect();
    assert!(msg.contains("Unsigned integer exceeds supported size"));

    // Unexpected float size
    let buf = [0x87, 0x04, 0, 0, 0, 0];
    let err = decode_iec_data_element(&buf, 0);
    assert!(err.is_err());
    let msg: String = err.unwrap_err().message.iter().collect();
    assert!(msg.contains("Unexpected float size"));

    // Tag 0xFF is not supported, should trigger the unknown data type error
    let buf = [0xFF, 0x01, 0x00];
    let err = decode_iec_data_element(&buf, 0);
    assert!(err.is_err());
    let msg: String = err.unwrap_err().message.iter().collect();
    assert!(msg.contains("Unknown data type"));
}

#[test]
fn test_decode_iec_data_multiple_elements() {
    let float_val: f32 = 42.5;
    let float_bytes = float_val.to_be_bytes();
    let int16_val: i16 = -12345;
    let int16_bytes = int16_val.to_be_bytes();
    let int32_val: i32 = 0x12345678;
    let int32_bytes = int32_val.to_be_bytes();
    let int64_val: i64 = -0x1234567890ABCDEF;
    let int64_bytes = int64_val.to_be_bytes();
    let uint8_val: u8 = 200;
    let uint16_val: u16 = 40000;
    let uint16_bytes = uint16_val.to_be_bytes();
    let uint32_val: u32 = 0xDEADBEEF;
    let uint32_bytes = uint32_val.to_be_bytes();

    let bitstring_bytes = [0b10101010, 0b10001000];
    let mms_string_bytes = [0xCE, 0xA9, 0xC3, 0x9F];
    let utc_time_bytes = [1, 2, 3, 4, 5, 6, 7, 8];
    let buf = [
        // Boolean (0x83, 1, 0xFF)
        0x83,
        0x01,
        0xFF,
        // Int8 (0x85, 1, 0xFE)
        0x85,
        0x01,
        0xFE,
        // Int16 (0x85, 2, int16_bytes)
        0x85,
        0x02,
        int16_bytes[0],
        int16_bytes[1],
        // Int32 (0x85, 4, int32_bytes)
        0x85,
        0x04,
        int32_bytes[0],
        int32_bytes[1],
        int32_bytes[2],
        int32_bytes[3],
        // Int64 (0x85, 8, int64_bytes)
        0x85,
        0x08,
        int64_bytes[0],
        int64_bytes[1],
        int64_bytes[2],
        int64_bytes[3],
        int64_bytes[4],
        int64_bytes[5],
        int64_bytes[6],
        int64_bytes[7],
        // UInt8 (0x86, 1, uint8_val)
        0x86,
        0x01,
        uint8_val,
        // UInt16 (0x86, 2, uint16_bytes)
        0x86,
        0x02,
        uint16_bytes[0],
        uint16_bytes[1],
        // UInt32 (0x86, 4, uint32_bytes)
        0x86,
        0x04,
        uint32_bytes[0],
        uint32_bytes[1],
        uint32_bytes[2],
        uint32_bytes[3],
        // 5-byte UInt32 (0x86, 0x05, 0x00, uint32_bytes)
        0x86,
        0x05,
        0x00,
        uint32_bytes[0],
        uint32_bytes[1],
        uint32_bytes[2],
        uint32_bytes[3],
        // Float32 (0x87, 5, 0x08, float_bytes...)
        0x87,
        0x05,
        0x08,
        float_bytes[0],
        float_bytes[1],
        float_bytes[2],
        float_bytes[3],
        // VisibleString (0x8a, 3, 0x41, 0xC3, 0x9F) "Aß"
        0x8a,
        0x03,
        0x41,
        0xC3,
        0x9F,
        // OctetString (0x89, 2, 0xDE, 0xAD)
        0x89,
        0x02,
        0xDE,
        0xAD,
        // BitString (0x84, 0x03, 0x02, 0b10101010, 0b10001000)
        0x84,
        0x03,
        0x02,
        bitstring_bytes[0],
        bitstring_bytes[1],
        // MmsString (0x90, 0x04, mms_string_bytes)
        0x90,
        0x04,
        mms_string_bytes[0],
        mms_string_bytes[1],
        mms_string_bytes[2],
        mms_string_bytes[3],
        // UtcTime (0x91, 0x08, utc_time_bytes)
        0x91,
        0x08,
        utc_time_bytes[0],
        utc_time_bytes[1],
        utc_time_bytes[2],
        utc_time_bytes[3],
        utc_time_bytes[4],
        utc_time_bytes[5],
        utc_time_bytes[6],
        utc_time_bytes[7],
        // Array (0xA1, 0x03, 0x85, 0x01, 0x01)
        0xA1,
        0x03,
        0x85,
        0x01,
        0x01,
        // Structure (0xA2, 0x03, 0x83, 0x01, 0x00)
        0xA2,
        0x03,
        0x83,
        0x01,
        0x00,
    ];

    let mut data: Vec<IECData> = Vec::new();
    let pos = decode_iec_data(&mut data, &buf, 0, buf.len()).unwrap();

    assert_eq!(pos, buf.len());
    assert_eq!(data[0], IECData::Boolean(true));
    assert_eq!(data[1], IECData::Int8(-2));
    assert_eq!(data[2], IECData::Int16(int16_val));
    assert_eq!(data[3], IECData::Int32(int32_val));
    assert_eq!(data[4], IECData::Int64(int64_val));
    assert_eq!(data[5], IECData::Int8u(uint8_val));
    assert_eq!(data[6], IECData::Int16u(uint16_val));
    assert_eq!(data[7], IECData::Int32u(uint32_val));
    assert_eq!(data[8], IECData::Int32u(uint32_val)); // 5-byte UInt32
    if let IECData::Float32(v) = data[9] {
        assert!((v - 42.5).abs() < 1e-6);
    }
    assert_eq!(data[10], IECData::VisibleString("Aß".to_string()));
    assert_eq!(data[11], IECData::OctetString(vec![0xDE, 0xAD]));
    assert_eq!(
        data[12],
        IECData::BitString {
            padding: 2,
            val: vec![0x11, 0x55]
        }
    );
    assert_eq!(data[13], IECData::MmsString("Ωß".to_string()));
    assert_eq!(data[14], IECData::UtcTime([1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(data[15], IECData::Array(vec![IECData::Int8(1)]));
    assert_eq!(data[16], IECData::Structure(vec![IECData::Boolean(false)]));
}

#[test]
fn test_decode_ethernet_header() {
    // Example Ethernet header values
    let src_addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_addr = [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
    let tpid = [0x81, 0x00];
    let tci = [0x00, 0x64];
    let ether_type = [0x88, 0xB8];
    let appid = [0x12, 0x34];
    let length = [0x00, 0x2A];

    // Compose buffer in the order expected by decode_ethernet_header
    let buf = [
        dst_addr[0],
        dst_addr[1],
        dst_addr[2],
        dst_addr[3],
        dst_addr[4],
        dst_addr[5],
        src_addr[0],
        src_addr[1],
        src_addr[2],
        src_addr[3],
        src_addr[4],
        src_addr[5],
        tpid[0],
        tpid[1],
        tci[0],
        tci[1],
        ether_type[0],
        ether_type[1],
        appid[0],
        appid[1],
        length[0],
        length[1],
        0x00,
        0x00, // reserved 1
        0x00,
        0x00, // reserved 2
    ];

    let mut header = EthernetHeader {
        src_addr: [0; 6],
        dst_addr: [0; 6],
        tpid: None,
        tci: None,
        ether_type: [0; 2],
        appid: [0; 2],
        length: [0; 2],
    };

    let result = decode_ethernet_header(&mut header, &buf);

    assert_eq!(header.src_addr, src_addr);
    assert_eq!(header.dst_addr, dst_addr);
    assert_eq!(header.tpid, Some(tpid));
    assert_eq!(header.tci, Some(tci));
    assert_eq!(header.ether_type, ether_type);
    assert_eq!(header.appid, appid);
    assert_eq!(header.length, length);
    // Optionally check the returned buffer index
    assert_eq!(result, buf.len());
}

#[test]
fn test_decode_ethernet_header_wo_tpid() {
    // Example Ethernet header values
    let src_addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_addr = [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
    let ether_type = [0x88, 0xB8];
    let appid = [0x12, 0x34];
    let length = [0x00, 0x2A];

    // Compose buffer in the order expected by decode_ethernet_header
    let buf = [
        dst_addr[0],
        dst_addr[1],
        dst_addr[2],
        dst_addr[3],
        dst_addr[4],
        dst_addr[5],
        src_addr[0],
        src_addr[1],
        src_addr[2],
        src_addr[3],
        src_addr[4],
        src_addr[5],
        ether_type[0],
        ether_type[1],
        appid[0],
        appid[1],
        length[0],
        length[1],
        0x00,
        0x00, // reserved 1
        0x00,
        0x00, // reserved 2
    ];

    let mut header = EthernetHeader {
        src_addr: [0; 6],
        dst_addr: [0; 6],
        tpid: None,
        tci: None,
        ether_type: [0; 2],
        appid: [0; 2],
        length: [0; 2],
    };

    let result = decode_ethernet_header(&mut header, &buf);

    assert_eq!(header.src_addr, src_addr);
    assert_eq!(header.dst_addr, dst_addr);
    assert_eq!(header.tpid, None);
    assert_eq!(header.tci, None);
    assert_eq!(header.ether_type, ether_type);
    assert_eq!(header.appid, appid);
    assert_eq!(header.length, length);
    // Optionally check the returned buffer index
    assert_eq!(result, buf.len());
}
