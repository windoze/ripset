//! Pure Rust implementation of ipset/nftset operations via netlink.
//!
//! This crate provides functions to add, check, and remove IP addresses
//! from Linux ipset and nftables sets using the netlink protocol.
//!
//! On non-Linux platforms, all operations return `Err(IpSetError::UnsupportedPlatform)`.

#[cfg(target_os = "linux")]
mod netlink;

#[cfg(target_os = "linux")]
pub mod ipset;
#[cfg(target_os = "linux")]
pub mod nftset;

#[cfg(target_os = "linux")]
pub use ipset::{
    IpSetCreateOptions, IpSetFamily, IpSetType, ipset_add, ipset_create, ipset_del, ipset_destroy,
    ipset_flush, ipset_list, ipset_test,
};
#[cfg(target_os = "linux")]
pub use nftset::{
    NftSetCreateOptions, NftSetType, nftset_add, nftset_create_set, nftset_create_table,
    nftset_del, nftset_delete_set, nftset_delete_table, nftset_list, nftset_list_tables,
    nftset_test,
};

// Stub implementations for non-Linux platforms
#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(not(target_os = "linux"))]
pub use stub::*;

use std::net::IpAddr;
use thiserror::Error;

/// Error type for ipset/nftset operations.
#[derive(Error, Debug)]
pub enum IpSetError {
    #[error("Invalid set name: {0}")]
    InvalidSetName(String),

    #[error("Invalid address family")]
    InvalidAddressFamily,

    #[error("Socket error: {0}")]
    SocketError(#[from] std::io::Error),

    #[error("Netlink error: {0}")]
    NetlinkError(i32),

    #[error("Set not found: {0}")]
    SetNotFound(String),

    #[error("Element not found")]
    ElementNotFound,

    #[error("Element already exists")]
    ElementExists,

    #[error("Invalid table name: {0}")]
    InvalidTableName(String),

    #[error("Send/receive error")]
    SendRecvError,

    #[error("Protocol error")]
    ProtocolError,

    #[error("Unsupported platform: ipset/nftset operations are only available on Linux")]
    UnsupportedPlatform,
}

pub type Result<T> = std::result::Result<T, IpSetError>;

/// IP address with optional timeout for set operations.
pub struct IpEntry {
    pub addr: IpAddr,
    pub timeout: Option<u32>,
}

impl IpEntry {
    pub fn new(addr: IpAddr) -> Self {
        Self {
            addr,
            timeout: None,
        }
    }

    pub fn with_timeout(addr: IpAddr, timeout: u32) -> Self {
        Self {
            addr,
            timeout: Some(timeout),
        }
    }
}

impl From<IpAddr> for IpEntry {
    fn from(addr: IpAddr) -> Self {
        Self::new(addr)
    }
}
