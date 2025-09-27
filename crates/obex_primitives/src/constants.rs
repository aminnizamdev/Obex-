#![forbid(unsafe_code)]

pub const GENESIS_PARENT_ID: [u8; 32] = [0u8; 32];
pub const TXROOT_GENESIS: [u8; 32] = [0u8; 32];
pub const GENESIS_SLOT: u64 = 0;

pub const TAG_MERKLE_LEAF: &str = "obex.merkle.leaf";
pub const TAG_MERKLE_NODE: &str = "obex.merkle.node";
pub const TAG_MERKLE_EMPTY: &str = "obex.merkle.empty";

pub const TAG_ALPHA: &str = "obex.alpha";
pub const TAG_SEED: &str = "obex.seed";
pub const TAG_L0: &str = "obex.l0";
pub const TAG_LBL: &str = "obex.lbl";
pub const TAG_IDX: &str = "obex.idx";
pub const TAG_CHAL: &str = "obex.chal";
pub const TAG_PART_LEAF: &str = "obex.part.leaf";
pub const TAG_PARTREC: &str = "obex.partrec";
pub const TAG_VRFY: &str = "obex.vrfy";

pub const TAG_HEADER_ID: &str = "obex.header.id";
pub const TAG_SLOT_SEED: &str = "obex.slot.seed";
pub const TAG_VDF_YCORE: &str = "obex.vdf.ycore";
pub const TAG_VDF_EDGE: &str = "obex.vdf.edge";

pub const TAG_TX_ACCESS: &str = "obex.tx.access";
pub const TAG_TX_BODY_V1: &str = "obex.tx.body.v1";
pub const TAG_TX_ID: &str = "obex.tx.id";
pub const TAG_TX_COMMIT: &str = "obex.tx.commit";
pub const TAG_TX_SIG: &str = "obex.tx.sig";
pub const TAG_TXID_LEAF: &str = "obex.txid.leaf";
pub const TAG_TICKET_ID: &str = "obex.ticket.id";
pub const TAG_TICKET_LEAF: &str = "obex.ticket.leaf";

pub const TAG_SYS_TX: &str = "obex.sys.tx";
pub const TAG_REWARD_DRAW: &str = "obex.reward.draw";
pub const TAG_REWARD_RANK: &str = "obex.reward.rank";
