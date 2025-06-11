use serde::{Deserialize, Serialize};

/** Data types allowed with a GOOSE */
#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Default)]
pub struct EthernetHeader {
    /** Destination MAC-Address */
    pub src_addr: [u8; 6],
    /** Source MAC-Address */
    pub dst_addr: [u8; 6],
    /** Tag Protocol Identifier (0x8100) */
    pub tpid: [u8; 2],
    /** Tag Control Information - VLAN-ID and VLAN-Priority */
    pub tci: [u8; 2],
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
    pub num_data_set_entries: u32,
    /** All data send with the GOOSE */
    pub all_data: Vec<IECData>,
}
