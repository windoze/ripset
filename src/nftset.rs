//! nftables set operations via netlink.
//!
//! This module provides functions to add, test, and delete IP addresses
//! from nftables sets using the netlink protocol.

use std::net::IpAddr;

use crate::netlink::{
    MsgBuffer, NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END, NFNL_SUBSYS_NFTABLES, NLA_F_NESTED,
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REQUEST, NetlinkSocket, NfGenMsg, NlAttr, NlMsgHdr,
    get_nlmsg_type, is_nlmsg_done, nla_align, parse_nlmsg_error,
};
use crate::{IpEntry, IpSetError, Result};

// nftables message types
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWSET: u16 = 9;
const NFT_MSG_DELSET: u16 = 11;
const NFT_MSG_GETSET: u16 = 10;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_GETSETELEM: u16 = 13;
const NFT_MSG_DELSETELEM: u16 = 14;

// nftables table attributes
const NFTA_TABLE_NAME: u16 = 1;

// nftables set attributes
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_TYPE: u16 = 4;
const NFTA_SET_KEY_LEN: u16 = 5;
const NFTA_SET_ID: u16 = 10;
const NFTA_SET_TIMEOUT: u16 = 11;

// nftables set element list attributes
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;

// nftables set element attributes
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
const NFTA_SET_ELEM_KEY_END: u16 = 10;

// nftables data attributes
const NFTA_DATA_VALUE: u16 = 1;

// nftables set flags
const NFT_SET_INTERVAL: u32 = 0x4;
const NFT_SET_TIMEOUT: u32 = 0x10;

// Address family constants
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;

const BUFF_SZ: usize = 2048;
const NFT_SET_MAXNAMELEN: usize = 256;

use std::sync::atomic::{AtomicU32, Ordering};

/// Atomic counter for generating unique set IDs within transactions.
static SET_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Get next set ID for transaction tracking.
fn next_set_id() -> u32 {
    SET_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Build the netlink message type for nftables commands.
fn nft_msg_type(cmd: u16) -> u16 {
    ((NFNL_SUBSYS_NFTABLES as u16) << 8) | cmd
}

/// Parse nftables family string to protocol number.
fn parse_nf_family(family: &str) -> Result<u8> {
    match family.to_lowercase().as_str() {
        "inet" => Ok(NFPROTO_INET),
        "ip" | "ipv4" => Ok(NFPROTO_IPV4),
        "ip6" | "ipv6" => Ok(NFPROTO_IPV6),
        _ => Err(IpSetError::InvalidAddressFamily),
    }
}

/// Calculate the interval end address for a single IP.
/// For interval sets, each IP needs a corresponding end address (IP + 1).
fn calculate_interval_end(addr: &IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let num = u32::from_be_bytes(v4.octets());
            let next = num.wrapping_add(1);
            IpAddr::V4(std::net::Ipv4Addr::from(next.to_be_bytes()))
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut result = [0u8; 16];
            let mut carry = 1u16;

            for i in (0..16).rev() {
                let sum = octets[i] as u16 + carry;
                result[i] = sum as u8;
                carry = sum >> 8;
            }

            IpAddr::V6(std::net::Ipv6Addr::from(result))
        }
    }
}

/// Address type for nftables sets
#[derive(Clone, Copy, Debug)]
pub enum NftSetType {
    /// IPv4 addresses
    Ipv4Addr,
    /// IPv6 addresses
    Ipv6Addr,
}

impl NftSetType {
    fn key_type(&self) -> u32 {
        match self {
            NftSetType::Ipv4Addr => 7, // TYPE_IPADDR
            NftSetType::Ipv6Addr => 8, // TYPE_IP6ADDR
        }
    }

    fn key_len(&self) -> u32 {
        match self {
            NftSetType::Ipv4Addr => 4,
            NftSetType::Ipv6Addr => 16,
        }
    }
}

/// Options for creating an nftables set
#[derive(Clone, Debug)]
pub struct NftSetCreateOptions {
    pub set_type: NftSetType,
    pub timeout: Option<u32>,
    pub flags: Option<u32>,
}

impl Default for NftSetCreateOptions {
    fn default() -> Self {
        Self {
            set_type: NftSetType::Ipv4Addr,
            timeout: None,
            flags: None,
        }
    }
}

/// Create an nftables table.
///
/// # Arguments
///
/// * `family` - The address family ("inet", "ip", "ip6")
/// * `table` - The table name to create
///
/// # Example
///
/// ```no_run
/// use ruhop_ipset::nftset::nftset_create_table;
///
/// nftset_create_table("inet", "mytable").unwrap();
/// ```
pub fn nftset_create_table(family: &str, table: &str) -> Result<()> {
    if table.is_empty() || table.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidTableName(table.to_string()));
    }

    let nf_family = parse_nf_family(family)?;

    let mut buf = MsgBuffer::new(BUFF_SZ);

    // Batch begin
    buf.put_nlmsghdr(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg();

    let msg_start = buf.len();

    // Create table message
    buf.put_nlmsghdr(
        nft_msg_type(NFT_MSG_NEWTABLE),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        1,
    );
    buf.put_nfgenmsg(nf_family, 0, 0);

    buf.put_attr_str(NFTA_TABLE_NAME, table);

    buf.finalize_nlmsg_at(msg_start);

    // Batch end
    let end_start = buf.len();
    buf.put_nlmsghdr(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 2);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg_at(end_start);

    let socket = NetlinkSocket::new()?;
    socket.send(buf.as_slice())?;

    let mut recv_buf = [0u8; BUFF_SZ];
    loop {
        let recv_len = socket.recv(&mut recv_buf)?;

        if recv_len < NlMsgHdr::SIZE {
            return Err(IpSetError::ProtocolError);
        }

        if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
            if error == 0 {
                // Continue
            } else if -error == libc::EEXIST {
                return Err(IpSetError::ElementExists);
            } else {
                return Err(IpSetError::NetlinkError(-error));
            }
        }

        if is_nlmsg_done(&recv_buf[..recv_len]) {
            break;
        }

        if get_nlmsg_type(&recv_buf[..recv_len]) == Some(crate::netlink::NLMSG_ERROR) {
            break;
        }
    }

    Ok(())
}

/// Delete an nftables table.
///
/// # Arguments
///
/// * `family` - The address family ("inet", "ip", "ip6")
/// * `table` - The table name to delete
///
/// # Example
///
/// ```no_run
/// use ruhop_ipset::nftset::nftset_delete_table;
///
/// nftset_delete_table("inet", "mytable").unwrap();
/// ```
pub fn nftset_delete_table(family: &str, table: &str) -> Result<()> {
    if table.is_empty() || table.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidTableName(table.to_string()));
    }

    let nf_family = parse_nf_family(family)?;

    let mut buf = MsgBuffer::new(BUFF_SZ);

    // Batch begin
    buf.put_nlmsghdr(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg();

    let msg_start = buf.len();

    // Delete table message
    buf.put_nlmsghdr(nft_msg_type(NFT_MSG_DELTABLE), NLM_F_REQUEST | NLM_F_ACK, 1);
    buf.put_nfgenmsg(nf_family, 0, 0);

    buf.put_attr_str(NFTA_TABLE_NAME, table);

    buf.finalize_nlmsg_at(msg_start);

    // Batch end
    let end_start = buf.len();
    buf.put_nlmsghdr(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 2);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg_at(end_start);

    let socket = NetlinkSocket::new()?;
    socket.send(buf.as_slice())?;

    let mut recv_buf = [0u8; BUFF_SZ];
    loop {
        let recv_len = socket.recv(&mut recv_buf)?;

        if recv_len < NlMsgHdr::SIZE {
            return Err(IpSetError::ProtocolError);
        }

        if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
            if error == 0 {
                // Continue
            } else if -error == libc::ENOENT {
                return Err(IpSetError::SetNotFound(table.to_string()));
            } else {
                return Err(IpSetError::NetlinkError(-error));
            }
        }

        if is_nlmsg_done(&recv_buf[..recv_len]) {
            break;
        }

        if get_nlmsg_type(&recv_buf[..recv_len]) == Some(crate::netlink::NLMSG_ERROR) {
            break;
        }
    }

    Ok(())
}

/// Create an nftables set.
///
/// # Arguments
///
/// * `family` - The address family ("inet", "ip", "ip6")
/// * `table` - The table name
/// * `setname` - The set name to create
/// * `options` - Creation options (type, timeout, etc.)
///
/// # Example
///
/// ```no_run
/// use ruhop_ipset::nftset::{nftset_create_set, NftSetCreateOptions, NftSetType};
///
/// let opts = NftSetCreateOptions {
///     set_type: NftSetType::Ipv4Addr,
///     timeout: Some(300),
///     ..Default::default()
/// };
/// nftset_create_set("inet", "filter", "myset", &opts).unwrap();
/// ```
pub fn nftset_create_set(
    family: &str,
    table: &str,
    setname: &str,
    options: &NftSetCreateOptions,
) -> Result<()> {
    if table.is_empty() || table.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidTableName(table.to_string()));
    }
    if setname.is_empty() || setname.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidSetName(setname.to_string()));
    }

    let nf_family = parse_nf_family(family)?;

    let mut buf = MsgBuffer::new(BUFF_SZ);

    // Batch begin
    buf.put_nlmsghdr(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg();

    let msg_start = buf.len();

    // Create set message
    buf.put_nlmsghdr(
        nft_msg_type(NFT_MSG_NEWSET),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        1,
    );
    buf.put_nfgenmsg(nf_family, 0, 0);

    buf.put_attr_str(NFTA_SET_TABLE, table);
    buf.put_attr_str(NFTA_SET_NAME, setname);

    // Set flags - nftables uses big-endian u32 without NLA_F_NET_BYTEORDER flag
    let mut flags = options.flags.unwrap_or(0);
    if options.timeout.is_some() {
        flags |= NFT_SET_TIMEOUT;
    }
    buf.put_attr_u32_nft(NFTA_SET_FLAGS, flags);

    // Key type and length - also big-endian without NLA_F_NET_BYTEORDER
    buf.put_attr_u32_nft(NFTA_SET_KEY_TYPE, options.set_type.key_type());
    buf.put_attr_u32_nft(NFTA_SET_KEY_LEN, options.set_type.key_len());

    // Set ID for transaction tracking (required by kernel)
    buf.put_attr_u32_nft(NFTA_SET_ID, next_set_id());

    // Timeout (if specified, in milliseconds)
    if let Some(timeout) = options.timeout {
        buf.put_attr_u64_nft(NFTA_SET_TIMEOUT, (timeout as u64) * 1000);
    }

    buf.finalize_nlmsg_at(msg_start);

    // Batch end
    let end_start = buf.len();
    buf.put_nlmsghdr(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 2);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg_at(end_start);

    let socket = NetlinkSocket::new()?;
    socket.send(buf.as_slice())?;

    let mut recv_buf = [0u8; BUFF_SZ];
    loop {
        let recv_len = socket.recv(&mut recv_buf)?;

        if recv_len < NlMsgHdr::SIZE {
            return Err(IpSetError::ProtocolError);
        }

        if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
            if error == 0 {
                // Continue
            } else if -error == libc::EEXIST {
                return Err(IpSetError::ElementExists);
            } else if -error == libc::ENOENT {
                return Err(IpSetError::SetNotFound(table.to_string()));
            } else {
                return Err(IpSetError::NetlinkError(-error));
            }
        }

        if is_nlmsg_done(&recv_buf[..recv_len]) {
            break;
        }

        if get_nlmsg_type(&recv_buf[..recv_len]) == Some(crate::netlink::NLMSG_ERROR) {
            break;
        }
    }

    Ok(())
}

/// Delete an nftables set.
///
/// # Arguments
///
/// * `family` - The address family ("inet", "ip", "ip6")
/// * `table` - The table name
/// * `setname` - The set name to delete
///
/// # Example
///
/// ```no_run
/// use ruhop_ipset::nftset::nftset_delete_set;
///
/// nftset_delete_set("inet", "filter", "myset").unwrap();
/// ```
pub fn nftset_delete_set(family: &str, table: &str, setname: &str) -> Result<()> {
    if table.is_empty() || table.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidTableName(table.to_string()));
    }
    if setname.is_empty() || setname.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidSetName(setname.to_string()));
    }

    let nf_family = parse_nf_family(family)?;

    let mut buf = MsgBuffer::new(BUFF_SZ);

    // Batch begin
    buf.put_nlmsghdr(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg();

    let msg_start = buf.len();

    // Delete set message
    buf.put_nlmsghdr(nft_msg_type(NFT_MSG_DELSET), NLM_F_REQUEST | NLM_F_ACK, 1);
    buf.put_nfgenmsg(nf_family, 0, 0);

    buf.put_attr_str(NFTA_SET_TABLE, table);
    buf.put_attr_str(NFTA_SET_NAME, setname);

    buf.finalize_nlmsg_at(msg_start);

    // Batch end
    let end_start = buf.len();
    buf.put_nlmsghdr(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 2);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg_at(end_start);

    let socket = NetlinkSocket::new()?;
    socket.send(buf.as_slice())?;

    let mut recv_buf = [0u8; BUFF_SZ];
    loop {
        let recv_len = socket.recv(&mut recv_buf)?;

        if recv_len < NlMsgHdr::SIZE {
            return Err(IpSetError::ProtocolError);
        }

        if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
            if error == 0 {
                // Continue
            } else if -error == libc::ENOENT {
                return Err(IpSetError::SetNotFound(setname.to_string()));
            } else {
                return Err(IpSetError::NetlinkError(-error));
            }
        }

        if is_nlmsg_done(&recv_buf[..recv_len]) {
            break;
        }

        if get_nlmsg_type(&recv_buf[..recv_len]) == Some(crate::netlink::NLMSG_ERROR) {
            break;
        }
    }

    Ok(())
}

/// Get the flags of an nftables set.
fn nftset_get_flags(family: &str, table: &str, setname: &str) -> Result<u32> {
    let nf_family = parse_nf_family(family)?;

    // Build the GETSET message
    let mut buf = MsgBuffer::new(BUFF_SZ);

    buf.put_nlmsghdr(nft_msg_type(NFT_MSG_GETSET), NLM_F_REQUEST | NLM_F_ACK, 0);
    buf.put_nfgenmsg(nf_family, 0, 0);

    buf.put_attr_str(NFTA_SET_TABLE, table);
    buf.put_attr_str(NFTA_SET_NAME, setname);

    buf.finalize_nlmsg();

    let socket = NetlinkSocket::new()?;
    let mut recv_buf = [0u8; BUFF_SZ];
    let recv_len = socket.send_recv(buf.as_slice(), &mut recv_buf)?;

    if recv_len < NlMsgHdr::SIZE + NfGenMsg::SIZE {
        return Err(IpSetError::ProtocolError);
    }

    // Check for error response
    if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len])
        && error != 0
    {
        return Err(IpSetError::NetlinkError(-error));
    }

    // Parse response to find flags
    let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(recv_buf.as_ptr() as *const NlMsgHdr) };

    if hdr.nlmsg_type == crate::netlink::NLMSG_ERROR {
        // This is an error response, not set data
        return Err(IpSetError::SetNotFound(setname.to_string()));
    }

    // Parse attributes to find NFTA_SET_FLAGS
    let attr_start = NlMsgHdr::SIZE + NfGenMsg::SIZE;
    let mut offset = attr_start;

    while offset + 4 <= recv_len {
        let attr_len = u16::from_ne_bytes([recv_buf[offset], recv_buf[offset + 1]]) as usize;
        let attr_type =
            u16::from_ne_bytes([recv_buf[offset + 2], recv_buf[offset + 3]]) & !NLA_F_NESTED;

        if attr_len < 4 {
            break;
        }

        if attr_type == NFTA_SET_FLAGS && attr_len >= 8 {
            let flags = u32::from_ne_bytes([
                recv_buf[offset + 4],
                recv_buf[offset + 5],
                recv_buf[offset + 6],
                recv_buf[offset + 7],
            ]);
            return Ok(flags);
        }

        offset += crate::netlink::nla_align(attr_len);
    }

    // Flags not found, assume 0
    Ok(0)
}

/// Test if an IP exists in an nftables set.
fn nftset_test_ip_exists(family: &str, table: &str, setname: &str, addr: &IpAddr) -> Result<bool> {
    let nf_family = parse_nf_family(family)?;

    let addr_bytes: Vec<u8> = match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    // Build GETSETELEM message
    let mut buf = MsgBuffer::new(BUFF_SZ);

    buf.put_nlmsghdr(
        nft_msg_type(NFT_MSG_GETSETELEM),
        NLM_F_REQUEST | NLM_F_ACK,
        0,
    );
    buf.put_nfgenmsg(nf_family, 0, 0);

    buf.put_attr_str(NFTA_SET_ELEM_LIST_TABLE, table);
    buf.put_attr_str(NFTA_SET_ELEM_LIST_SET, setname);

    // Elements list (nested)
    let elems_offset = buf.start_nested(NFTA_SET_ELEM_LIST_ELEMENTS);

    // Single element (nested)
    let elem_offset = buf.start_nested(0); // Type 0 for list item

    // Key (nested)
    let key_offset = buf.start_nested(NFTA_SET_ELEM_KEY);

    // Data value
    buf.put_attr_bytes(NFTA_DATA_VALUE, &addr_bytes);

    buf.end_nested(key_offset);
    buf.end_nested(elem_offset);
    buf.end_nested(elems_offset);

    buf.finalize_nlmsg();

    let socket = NetlinkSocket::new()?;
    let mut recv_buf = [0u8; BUFF_SZ];
    let recv_len = socket.send_recv(buf.as_slice(), &mut recv_buf)?;

    if recv_len < NlMsgHdr::SIZE {
        return Err(IpSetError::ProtocolError);
    }

    // Check for error
    if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
        if error == 0 {
            return Ok(true);
        }
        if -error == libc::ENOENT {
            return Ok(false);
        }
        return Err(IpSetError::NetlinkError(-error));
    }

    // If we got data back without error, the element exists
    let msg_type = get_nlmsg_type(&recv_buf[..recv_len]);
    if msg_type == Some(nft_msg_type(NFT_MSG_NEWSETELEM)) {
        return Ok(true);
    }

    Ok(false)
}

/// Internal function to perform nftset element operations.
fn nftset_operate(
    family: &str,
    table: &str,
    setname: &str,
    entry: &IpEntry,
    cmd: u16,
) -> Result<()> {
    // Validate names
    if table.is_empty() || table.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidTableName(table.to_string()));
    }
    if setname.is_empty() || setname.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidSetName(setname.to_string()));
    }

    let nf_family = parse_nf_family(family)?;

    // For ADD operations, check if element already exists
    if cmd == NFT_MSG_NEWSETELEM {
        match nftset_test_ip_exists(family, table, setname, &entry.addr) {
            Ok(true) => return Err(IpSetError::ElementExists),
            Ok(false) => {}
            Err(IpSetError::SetNotFound(_)) => {
                return Err(IpSetError::SetNotFound(setname.to_string()));
            }
            Err(_) => {} // Continue with add
        }
    }

    // Get set flags to determine if it's an interval set
    let set_flags = nftset_get_flags(family, table, setname).unwrap_or(0);
    let is_interval = (set_flags & NFT_SET_INTERVAL) != 0;

    let addr_bytes: Vec<u8> = match entry.addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    // Build the batched netlink message
    let mut buf = MsgBuffer::new(BUFF_SZ);

    // Batch begin message
    buf.put_nlmsghdr(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg();

    let msg_start = buf.len();

    // Main message
    let flags = if cmd == NFT_MSG_NEWSETELEM {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE
    } else {
        NLM_F_REQUEST | NLM_F_ACK
    };

    buf.put_nlmsghdr(nft_msg_type(cmd), flags, 1);
    buf.put_nfgenmsg(nf_family, 0, 0);

    buf.put_attr_str(NFTA_SET_ELEM_LIST_TABLE, table);
    buf.put_attr_str(NFTA_SET_ELEM_LIST_SET, setname);

    // Elements list (nested)
    let elems_offset = buf.start_nested(NFTA_SET_ELEM_LIST_ELEMENTS);

    // Single element (nested)
    let elem_offset = buf.start_nested(0); // Type 0 for list item

    // Key (nested)
    let key_offset = buf.start_nested(NFTA_SET_ELEM_KEY);
    buf.put_attr_bytes(NFTA_DATA_VALUE, &addr_bytes);
    buf.end_nested(key_offset);

    // For interval sets, add the end key
    if is_interval {
        let end_addr = calculate_interval_end(&entry.addr);
        let end_bytes: Vec<u8> = match end_addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        let key_end_offset = buf.start_nested(NFTA_SET_ELEM_KEY_END);
        buf.put_attr_bytes(NFTA_DATA_VALUE, &end_bytes);
        buf.end_nested(key_end_offset);
    }

    // Timeout (optional, in milliseconds for nftables)
    if let Some(timeout) = entry.timeout {
        // nftables uses milliseconds for timeout in netlink
        buf.put_attr_u64_be(NFTA_SET_ELEM_TIMEOUT, (timeout as u64) * 1000);
    }

    buf.end_nested(elem_offset);
    buf.end_nested(elems_offset);

    buf.finalize_nlmsg_at(msg_start);

    // Batch end message
    let end_start = buf.len();
    buf.put_nlmsghdr(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 2);
    buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
    buf.finalize_nlmsg_at(end_start);

    // Send and receive
    let socket = NetlinkSocket::new()?;
    socket.send(buf.as_slice())?;

    // Receive all responses
    let mut recv_buf = [0u8; BUFF_SZ];
    loop {
        let recv_len = socket.recv(&mut recv_buf)?;

        if recv_len < NlMsgHdr::SIZE {
            return Err(IpSetError::ProtocolError);
        }

        // Check for error
        if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
            if error == 0 {
                // Continue reading
            } else {
                match -error {
                    libc::ENOENT => {
                        if cmd == NFT_MSG_DELSETELEM {
                            return Err(IpSetError::ElementNotFound);
                        }
                        return Err(IpSetError::SetNotFound(setname.to_string()));
                    }
                    libc::EEXIST => return Err(IpSetError::ElementExists),
                    _ => return Err(IpSetError::NetlinkError(-error)),
                }
            }
        }

        // Check for NLMSG_DONE
        if is_nlmsg_done(&recv_buf[..recv_len]) {
            break;
        }

        // Check message type to determine if we should continue
        let msg_type = get_nlmsg_type(&recv_buf[..recv_len]);
        if msg_type == Some(crate::netlink::NLMSG_ERROR) {
            // Already handled above
            break;
        }
    }

    Ok(())
}

/// Add an IP address to an nftables set.
///
/// # Arguments
///
/// * `family` - The address family ("inet", "ip", "ip6")
/// * `table` - The table name
/// * `setname` - The set name
/// * `entry` - The IP entry to add (can be created from IpAddr)
///
/// # Example
///
/// ```no_run
/// use std::net::IpAddr;
/// use ruhop_ipset::nftset_add;
///
/// let addr: IpAddr = "192.168.1.1".parse().unwrap();
/// nftset_add("inet", "filter", "myset", addr).unwrap();
/// ```
pub fn nftset_add<E: Into<IpEntry>>(
    family: &str,
    table: &str,
    setname: &str,
    entry: E,
) -> Result<()> {
    nftset_operate(family, table, setname, &entry.into(), NFT_MSG_NEWSETELEM)
}

/// Delete an IP address from an nftables set.
///
/// # Arguments
///
/// * `family` - The address family ("inet", "ip", "ip6")
/// * `table` - The table name
/// * `setname` - The set name
/// * `entry` - The IP entry to delete (can be created from IpAddr)
///
/// # Example
///
/// ```no_run
/// use std::net::IpAddr;
/// use ruhop_ipset::nftset_del;
///
/// let addr: IpAddr = "192.168.1.1".parse().unwrap();
/// nftset_del("inet", "filter", "myset", addr).unwrap();
/// ```
pub fn nftset_del<E: Into<IpEntry>>(
    family: &str,
    table: &str,
    setname: &str,
    entry: E,
) -> Result<()> {
    nftset_operate(family, table, setname, &entry.into(), NFT_MSG_DELSETELEM)
}

/// Test if an IP address exists in an nftables set.
///
/// # Arguments
///
/// * `family` - The address family ("inet", "ip", "ip6")
/// * `table` - The table name
/// * `setname` - The set name
/// * `entry` - The IP entry to test (can be created from IpAddr)
///
/// # Returns
///
/// * `Ok(true)` - The IP address exists in the set
/// * `Ok(false)` - The IP address does not exist in the set
/// * `Err(_)` - An error occurred
///
/// # Example
///
/// ```no_run
/// use std::net::IpAddr;
/// use ruhop_ipset::nftset_test;
///
/// let addr: IpAddr = "192.168.1.1".parse().unwrap();
/// let exists = nftset_test("inet", "filter", "myset", addr).unwrap();
/// ```
pub fn nftset_test<E: Into<IpEntry>>(
    family: &str,
    table: &str,
    setname: &str,
    entry: E,
) -> Result<bool> {
    let entry = entry.into();
    nftset_test_ip_exists(family, table, setname, &entry.addr)
}

/// List all IP addresses in an nftables set.
///
/// # Arguments
///
/// * `family` - The address family ("inet", "ip", "ip6")
/// * `table` - The table name
/// * `setname` - The set name
///
/// # Returns
///
/// A vector of IP addresses currently in the set.
///
/// # Example
///
/// ```no_run
/// use linux_ipsets::nftset_list;
///
/// let ips = nftset_list("inet", "filter", "myset").unwrap();
/// for ip in ips {
///     println!("{}", ip);
/// }
/// ```
pub fn nftset_list(family: &str, table: &str, setname: &str) -> Result<Vec<IpAddr>> {
    if table.is_empty() || table.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidTableName(table.to_string()));
    }
    if setname.is_empty() || setname.len() >= NFT_SET_MAXNAMELEN {
        return Err(IpSetError::InvalidSetName(setname.to_string()));
    }

    let nf_family = parse_nf_family(family)?;

    // Build GETSETELEM message with DUMP flag
    let mut buf = MsgBuffer::new(BUFF_SZ);

    buf.put_nlmsghdr(
        nft_msg_type(NFT_MSG_GETSETELEM),
        NLM_F_REQUEST | NLM_F_DUMP,
        0,
    );
    buf.put_nfgenmsg(nf_family, 0, 0);

    buf.put_attr_str(NFTA_SET_ELEM_LIST_TABLE, table);
    buf.put_attr_str(NFTA_SET_ELEM_LIST_SET, setname);

    buf.finalize_nlmsg();

    let socket = NetlinkSocket::new()?;
    socket.send(buf.as_slice())?;

    let mut result = Vec::new();
    let mut recv_buf = [0u8; 16384]; // Larger buffer for dump responses

    loop {
        let recv_len = socket.recv(&mut recv_buf)?;
        if recv_len < NlMsgHdr::SIZE {
            break;
        }

        // Process all messages in the buffer
        let mut offset = 0;
        while offset + NlMsgHdr::SIZE <= recv_len {
            let hdr: NlMsgHdr =
                unsafe { std::ptr::read_unaligned(recv_buf[offset..].as_ptr() as *const NlMsgHdr) };

            if hdr.nlmsg_len as usize > recv_len - offset {
                break;
            }

            // Check for NLMSG_DONE
            if is_nlmsg_done(&recv_buf[offset..]) {
                return Ok(result);
            }

            // Check for error
            if let Some(error) =
                parse_nlmsg_error(&recv_buf[offset..offset + hdr.nlmsg_len as usize])
            {
                if error != 0 {
                    match -error {
                        libc::ENOENT => return Err(IpSetError::SetNotFound(setname.to_string())),
                        _ => return Err(IpSetError::NetlinkError(-error)),
                    }
                }
            } else {
                // Check if this is a NEWSETELEM message (response to GETSETELEM dump)
                let expected_type = nft_msg_type(NFT_MSG_NEWSETELEM);
                if hdr.nlmsg_type == expected_type {
                    // Parse the message for IP addresses
                    let msg_end = offset + hdr.nlmsg_len as usize;
                    let attr_start = offset + NlMsgHdr::SIZE + NfGenMsg::SIZE;
                    if attr_start < msg_end {
                        parse_nftset_elem_message(&recv_buf[attr_start..msg_end], &mut result);
                    }
                }
            }

            offset += nla_align(hdr.nlmsg_len as usize);
        }
    }

    Ok(result)
}

/// Parse a NEWSETELEM message to extract IP addresses.
fn parse_nftset_elem_message(data: &[u8], result: &mut Vec<IpAddr>) {
    let mut offset = 0;

    while offset + NlAttr::SIZE <= data.len() {
        let attr_len = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[offset + 2], data[offset + 3]]);

        if attr_len < NlAttr::SIZE || offset + attr_len > data.len() {
            break;
        }

        let attr_type_masked = attr_type & !NLA_F_NESTED;

        // NFTA_SET_ELEM_LIST_ELEMENTS contains the element list
        // Note: The nested flag may or may not be set in the response
        if attr_type_masked == NFTA_SET_ELEM_LIST_ELEMENTS {
            parse_nftset_elements_list(&data[offset + NlAttr::SIZE..offset + attr_len], result);
        }

        offset += nla_align(attr_len);
    }
}

/// Parse element list to extract individual elements.
fn parse_nftset_elements_list(data: &[u8], result: &mut Vec<IpAddr>) {
    let mut offset = 0;

    while offset + NlAttr::SIZE <= data.len() {
        let attr_len = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;

        if attr_len < NlAttr::SIZE || offset + attr_len > data.len() {
            break;
        }

        // Each element in the list - try to parse it as an element containing a key
        if let Some(addr) =
            parse_nftset_single_element(&data[offset + NlAttr::SIZE..offset + attr_len])
        {
            result.push(addr);
        }

        offset += nla_align(attr_len);
    }
}

/// Parse a single element to extract the IP address from its KEY attribute.
fn parse_nftset_single_element(data: &[u8]) -> Option<IpAddr> {
    let mut offset = 0;

    while offset + NlAttr::SIZE <= data.len() {
        let attr_len = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[offset + 2], data[offset + 3]]);

        if attr_len < NlAttr::SIZE || offset + attr_len > data.len() {
            break;
        }

        let attr_type_masked = attr_type & !NLA_F_NESTED;

        // NFTA_SET_ELEM_KEY contains the key (IP address)
        if attr_type_masked == NFTA_SET_ELEM_KEY {
            return parse_nftset_data_value(&data[offset + NlAttr::SIZE..offset + attr_len]);
        }

        offset += nla_align(attr_len);
    }

    None
}

/// Parse NFTA_DATA_VALUE to get the actual IP address bytes.
fn parse_nftset_data_value(data: &[u8]) -> Option<IpAddr> {
    let mut offset = 0;

    while offset + NlAttr::SIZE <= data.len() {
        let attr_len = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[offset + 2], data[offset + 3]]) & !NLA_F_NESTED;

        if attr_len < NlAttr::SIZE || offset + attr_len > data.len() {
            break;
        }

        // NFTA_DATA_VALUE contains the actual value
        if attr_type == NFTA_DATA_VALUE {
            let payload = &data[offset + NlAttr::SIZE..offset + attr_len];
            return match payload.len() {
                4 => {
                    let octets: [u8; 4] = payload.try_into().ok()?;
                    Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
                }
                16 => {
                    let octets: [u8; 16] = payload.try_into().ok()?;
                    Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                }
                _ => None,
            };
        }

        offset += nla_align(attr_len);
    }

    None
}

/// List all table names in an nftables family.
///
/// # Arguments
///
/// * `family` - The address family ("inet", "ip", "ip6")
///
/// # Returns
///
/// A vector of table names in the specified family.
///
/// # Example
///
/// ```no_run
/// use linux_ipsets::nftset_list_tables;
///
/// let tables = nftset_list_tables("inet").unwrap();
/// for table in tables {
///     println!("{}", table);
/// }
/// ```
pub fn nftset_list_tables(family: &str) -> Result<Vec<String>> {
    let nf_family = parse_nf_family(family)?;

    // Build GETTABLE message with DUMP flag
    let mut buf = MsgBuffer::new(BUFF_SZ);

    buf.put_nlmsghdr(
        nft_msg_type(NFT_MSG_GETTABLE),
        NLM_F_REQUEST | NLM_F_DUMP,
        0,
    );
    buf.put_nfgenmsg(nf_family, 0, 0);

    buf.finalize_nlmsg();

    let socket = NetlinkSocket::new()?;
    socket.send(buf.as_slice())?;

    let mut result = Vec::new();
    let mut recv_buf = [0u8; 8192];

    loop {
        let recv_len = socket.recv(&mut recv_buf)?;
        if recv_len < NlMsgHdr::SIZE {
            break;
        }

        // Process all messages in the buffer
        let mut offset = 0;
        while offset + NlMsgHdr::SIZE <= recv_len {
            let hdr: NlMsgHdr =
                unsafe { std::ptr::read_unaligned(recv_buf[offset..].as_ptr() as *const NlMsgHdr) };

            if hdr.nlmsg_len as usize > recv_len - offset {
                break;
            }

            // Check for NLMSG_DONE
            if is_nlmsg_done(&recv_buf[offset..]) {
                return Ok(result);
            }

            // Check for error
            if let Some(error) =
                parse_nlmsg_error(&recv_buf[offset..offset + hdr.nlmsg_len as usize])
            {
                if error != 0 {
                    return Err(IpSetError::NetlinkError(-error));
                }
            } else {
                // Check if this is a NEWTABLE message (response to GETTABLE dump)
                let expected_type = nft_msg_type(NFT_MSG_NEWTABLE);
                if hdr.nlmsg_type == expected_type {
                    // Parse the message for table name
                    let msg_end = offset + hdr.nlmsg_len as usize;
                    let attr_start = offset + NlMsgHdr::SIZE + NfGenMsg::SIZE;
                    if attr_start < msg_end
                        && let Some(name) = parse_nftset_table_name(&recv_buf[attr_start..msg_end])
                    {
                        result.push(name);
                    }
                }
            }

            offset += nla_align(hdr.nlmsg_len as usize);
        }
    }

    Ok(result)
}

/// Parse a NEWTABLE message to extract the table name.
fn parse_nftset_table_name(data: &[u8]) -> Option<String> {
    let mut offset = 0;

    while offset + NlAttr::SIZE <= data.len() {
        let attr_len = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[offset + 2], data[offset + 3]]) & !NLA_F_NESTED;

        if attr_len < NlAttr::SIZE || offset + attr_len > data.len() {
            break;
        }

        // NFTA_TABLE_NAME contains the table name
        if attr_type == NFTA_TABLE_NAME {
            let payload = &data[offset + NlAttr::SIZE..offset + attr_len];
            // Remove null terminator if present
            let name_end = payload
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(payload.len());
            return String::from_utf8(payload[..name_end].to_vec()).ok();
        }

        offset += nla_align(attr_len);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nft_msg_type() {
        // NFT_MSG_NEWSETELEM = 12, NFT_MSG_DELSETELEM = 14
        assert_eq!(nft_msg_type(NFT_MSG_NEWSETELEM), (10 << 8) | 12);
        assert_eq!(nft_msg_type(NFT_MSG_DELSETELEM), (10 << 8) | 14);
    }

    #[test]
    fn test_parse_nf_family() {
        assert_eq!(parse_nf_family("inet").unwrap(), NFPROTO_INET);
        assert_eq!(parse_nf_family("ip").unwrap(), NFPROTO_IPV4);
        assert_eq!(parse_nf_family("ipv4").unwrap(), NFPROTO_IPV4);
        assert_eq!(parse_nf_family("ip6").unwrap(), NFPROTO_IPV6);
        assert_eq!(parse_nf_family("ipv6").unwrap(), NFPROTO_IPV6);
        assert!(parse_nf_family("invalid").is_err());
    }

    #[test]
    fn test_calculate_interval_end() {
        let v4: IpAddr = "192.168.1.1".parse().unwrap();
        let v4_end = calculate_interval_end(&v4);
        assert_eq!(v4_end.to_string(), "192.168.1.2");

        let v4_edge: IpAddr = "192.168.1.255".parse().unwrap();
        let v4_edge_end = calculate_interval_end(&v4_edge);
        assert_eq!(v4_edge_end.to_string(), "192.168.2.0");

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let v6_end = calculate_interval_end(&v6);
        assert_eq!(v6_end.to_string(), "2001:db8::2");
    }

    #[test]
    fn test_invalid_names() {
        let addr: IpAddr = "192.168.1.1".parse().unwrap();

        // Empty table
        assert!(matches!(
            nftset_add("inet", "", "myset", addr),
            Err(IpSetError::InvalidTableName(_))
        ));

        // Empty set name
        assert!(matches!(
            nftset_add("inet", "filter", "", addr),
            Err(IpSetError::InvalidSetName(_))
        ));
    }

    // Integration tests require root privileges and nftables setup
    // Run with: sudo cargo test --package ruhop-ipset -- --ignored

    #[test]
    #[ignore]
    fn test_nftset_add_ipv4() {
        // Requires: sudo nft add table inet filter
        //           sudo nft add set inet filter test_set { type ipv4_addr\; }
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        nftset_add("inet", "filter", "test_set", addr).expect("Failed to add IP to nftset");
    }

    #[test]
    #[ignore]
    fn test_nftset_test_ipv4() {
        // Requires nftables set setup
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let exists =
            nftset_test("inet", "filter", "test_set", addr).expect("Failed to test IP in nftset");
        println!("IP exists in set: {}", exists);
    }

    #[test]
    #[ignore]
    fn test_nftset_del_ipv4() {
        // Requires nftables set setup
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        nftset_del("inet", "filter", "test_set", addr).expect("Failed to delete IP from nftset");
    }

    #[test]
    #[ignore]
    fn test_nftset_add_ipv6() {
        // Requires: sudo nft add set inet filter test_set6 { type ipv6_addr\; }
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        nftset_add("inet", "filter", "test_set6", addr).expect("Failed to add IPv6 to nftset");
    }

    #[test]
    #[ignore]
    fn test_nftset_with_timeout() {
        // Requires: sudo nft add set inet filter test_set_timeout { type ipv4_addr\; timeout 5m\; }
        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        let entry = IpEntry::with_timeout(addr, 60);
        nftset_add("inet", "filter", "test_set_timeout", entry)
            .expect("Failed to add IP with timeout");
    }
}
