//! IPv8 wire protocol support for TrustChain peer communication.
//!
//! Implements the py-ipv8 binary packet format so TrustChain nodes can
//! communicate with py-ipv8/Tribler peers over UDP.

pub mod community;
pub mod packet;
pub mod payload;
pub mod udp;

pub use community::TrustChainCommunity;
pub use packet::{Ipv8Header, Ipv8Packet};
pub use payload::{CrawlRequest, HalfBlockPairPayload, HalfBlockPayload, MessageType};
pub use udp::Ipv8UdpTransport;
