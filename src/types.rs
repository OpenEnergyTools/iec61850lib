use core::str;

use serde::{Deserialize, Serialize};

/** Data types allowed with a GOOSE */
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum IECData {
    Array(Vec<IECData>),
    Structure(Vec<IECData>),

    Boolean(bool),

    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),

    Int8u(u8),
    Int16u(u16),
    Int32u(u32),

    Float32(f32),
    Float64(f64),

    VisibleString(String),
    MmsString(String),
    BitString { padding: u8, val: Vec<u8> },
    OctetString(Vec<u8>),
    UtcTime([u8; 8]),
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EthernetHeader {
    /** Source MAC-Address */
    pub dst_addr: [u8; 6],
    /** Destination MAC-Address */
    pub src_addr: [u8; 6],
    /** Tag Protocol Identifier (0x8100) */
    pub tpid: Option<[u8; 2]>,
    /** Tag Control Information - VLAN-ID and VLAN-Priority */
    pub tci: Option<[u8; 2]>,
    /** Ethertype for the GOOSE (88-B8 or 88-B9) */
    pub ether_type: [u8; 2],
    /** APPID */
    pub appid: [u8; 2],
    /** Length of the GOOSE PDU */
    pub length: [u8; 2],
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IECGoosePdu {
    /** Reference to GOOSE control block in the data model of the sending IED */
    pub go_cb_ref: String,
    /** Time allowed to live until the next GOOSE packet */
    pub time_allowed_to_live: u32,
    /** Reference to the data set the GOOSE is shipping */
    pub dat_set: String,
    /** GOOSE ID as defined in GSEControl.appID */
    pub go_id: String,
    /** Time stamp of the GOOSE creation */
    pub t: [u8; 8],
    /** Status number - counter for repeating GOOSE packets */
    pub st_num: u32,
    /** Sequence number - counter for changes in GOOSE data  */
    pub sq_num: u32,
    /** Whether the GOOSE is a simulated */
    pub simulation: bool,
    /** Configuration revision of the GOOSE control block */
    pub conf_rev: u32,
    /** Whether the GOOSE needs commissioning */
    pub nds_com: bool,
    /** Number of data set entries in the GOOSE */
    pub num_dat_set_entries: u32,
    /** All data send with the GOOSE */
    pub all_data: Vec<IECData>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct SavPdu {
    /** Whether the sampled value stream is simulated */
    pub sim: bool,
    /** Number of ASDU in the packet*/
    pub no_asdu: u16,
    /** Time allowed to live until the next GOOSE packet */
    pub security: bool,
    /** All data send with the GOOSE */
    pub sav_asdu: Vec<SavAsdu>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct SavAsdu {
    /** Multicast Sampled Values ID as defined in tSampledValueControl.svId*/
    pub msv_id: String,
    /** Reference to the data set the GOOSE is shipping */
    pub dat_set: Option<String>,
    /** Increments with each sampled value taken */
    pub smp_cnt: u16,
    /** Configuration revision of the GOOSE control block */
    pub conf_rev: u32,
    /** Transmission time of the ASDU */
    pub refr_tm: Option<[u8; 8]>,
    /** How the sample value stream is time synchronized 0 = not, 1 = locally and 2 globally */
    pub smp_synch: u8,
    pub smp_rate: Option<u16>,
    /** All data send with the GOOSE */
    pub all_data: Vec<(f32, u32)>,
    pub smp_mod: Option<u16>,
    pub gm_identity: Option<[u8; 8]>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GooseConfig {
    /** Source MAC-Address */
    pub dst_addr: [u8; 6],
    /** Tag Protocol Identifier (0x8100) */
    pub tpid: Option<[u8; 2]>,
    /** Tag Control Information - VLAN-ID and VLAN-Priority */
    pub tci: Option<[u8; 2]>,
    /** APPID */
    pub appid: [u8; 2],
    /** Reference to GOOSE control block in the data model of the sending IED */
    pub go_cb_ref: String,
    /** Reference to the data set the GOOSE is shipping */
    pub dat_set: String,
    /** GOOSE ID as defined in GSEControl.appID */
    pub go_id: String,
    /** Whether the GOOSE is a simulated */
    pub simulation: bool,
    /** Configuration revision of the GOOSE control block */
    pub conf_rev: u32,
    /** Whether the GOOSE needs commissioning */
    pub nds_com: bool,
    /** Number of data set entries in the GOOSE */
    pub num_dat_set_entries: u32,
    /** All data send with the GOOSE */
    pub all_data: Vec<IECData>,
    /** The maximum repetition interval of the GOOSE */
    pub max_repetition: u32,
    /** The minimum repetition interval of the GOOSE */
    pub min_repetition: u32,
}
pub struct GooseSize {
    pub length: usize,
    pub pdu: usize,
    pub data_set: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct GooseRuntime {
    pub st_num: u32,
    pub sq_num: u32,
    pub timestamp: [u8; 8],
    pub src_addr: [u8; 6],
}

#[derive(Debug)]
pub struct EncodeError {
    pub message: [char; 128],
    pub buffer_index: usize,
}

impl EncodeError {
    pub fn new(msg: &str, buffer_index: usize) -> Self {
        let mut message = ['\0'; 128];
        for (i, c) in msg.chars().take(128).enumerate() {
            message[i] = c;
        }
        EncodeError {
            message,
            buffer_index,
        }
    }
}

#[derive(Debug)]
pub struct DecodeError {
    pub message: [char; 128],
    pub buffer_index: usize,
}

impl DecodeError {
    pub fn new(msg: &str, buffer_index: usize) -> Self {
        let mut message = ['\0'; 128];
        for (i, c) in msg.chars().take(128).enumerate() {
            message[i] = c;
        }
        DecodeError {
            message,
            buffer_index,
        }
    }
}
