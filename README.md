# ripset

Pure Rust library for managing Linux ipset and nftables sets via the netlink protocol.

## Features

- **Zero external dependencies** - No shelling out to `ipset` or `nft` commands
- **ipset support** - Create, destroy, flush, list sets; add, delete, test IP addresses
- **nftables support** - Create/delete tables and sets; add, delete, test, list IP addresses
- **IPv4 and IPv6** - Full support for both address families
- **Timeout support** - Add entries with optional expiration times
- **Cross-platform stubs** - Compiles on non-Linux platforms (returns `UnsupportedPlatform` error)
- **CLI tool** - Optional `ripset` binary for command-line management

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ripset = "0.1"
```

### CLI Installation

To build the `ripset` CLI tool, enable the `cli` feature:

```bash
cargo build --features cli
```

## Library Usage

### ipset Operations

```rust
use std::net::IpAddr;
use ripset::{
    ipset_create, ipset_destroy, ipset_flush, ipset_list,
    ipset_add, ipset_del, ipset_test,
    IpSetCreateOptions, IpSetFamily, IpSetType, IpEntry,
};

// Create an ipset
let opts = IpSetCreateOptions {
    set_type: IpSetType::HashIp,
    family: IpSetFamily::Inet,
    timeout: Some(300), // optional default timeout in seconds
    ..Default::default()
};
ipset_create("myset", &opts)?;

// Add an IP address
let addr: IpAddr = "192.168.1.1".parse()?;
ipset_add("myset", addr)?;

// Add with custom timeout
let entry = IpEntry::with_timeout(addr, 60);
ipset_add("myset", entry)?;

// Test if IP exists
let exists = ipset_test("myset", addr)?;

// List all entries
let entries = ipset_list("myset")?;

// Delete an IP
ipset_del("myset", addr)?;

// Flush all entries
ipset_flush("myset")?;

// Destroy the set
ipset_destroy("myset")?;
```

### nftables Operations

```rust
use std::net::IpAddr;
use ripset::{
    nftset_create_table, nftset_delete_table, nftset_list_tables,
    nftset_create_set, nftset_delete_set,
    nftset_add, nftset_del, nftset_test, nftset_list,
    NftSetCreateOptions, NftSetType,
};

// Create a table
nftset_create_table("inet", "mytable")?;

// List tables
let tables = nftset_list_tables("inet")?;

// Create a set
let opts = NftSetCreateOptions {
    set_type: NftSetType::Ipv4Addr,
    timeout: Some(300),
    ..Default::default()
};
nftset_create_set("inet", "mytable", "myset", &opts)?;

// Add an IP address
let addr: IpAddr = "10.0.0.1".parse()?;
nftset_add("inet", "mytable", "myset", addr)?;

// Test if IP exists
let exists = nftset_test("inet", "mytable", "myset", addr)?;

// List all entries
let entries = nftset_list("inet", "mytable", "myset")?;

// Delete an IP
nftset_del("inet", "mytable", "myset", addr)?;

// Delete the set and table
nftset_delete_set("inet", "mytable", "myset")?;
nftset_delete_table("inet", "mytable")?;
```

## CLI Usage

The `ripset` CLI tool supports both ipset and nftables backends.

### Global Options

- `-b, --backend <ipset|nftables>` - Backend to use (default: nftables)

### Entry Operations

```bash
# Add an entry to a set
ripset add <set-name> <ip-address> -t <table> [-f <family>]

# Delete an entry from a set
ripset del <set-name> <ip-address> -t <table> [-f <family>]

# List all entries in a set
ripset list <set-name> -t <table> [-f <family>]

# Flush all entries from a set
ripset flush <set-name> -t <table> [-f <family>]
```

### Table.Set Syntax

For the nftables backend, you can use `<table>.<set>` syntax instead of the `-t/--table` flag:

```bash
# These are equivalent:
ripset add myset 192.168.1.1 -t mytable
ripset add mytable.myset 192.168.1.1

# Works with all commands
ripset list mytable.myset
ripset del mytable.myset 192.168.1.1
ripset flush mytable.myset
ripset set new mytable.myset
ripset set del mytable.myset
```

The explicit `-t/--table` flag takes precedence over the parsed table name. For the ipset backend, the table part is ignored (ipset doesn't use tables).

### Set Management

```bash
# Create a new set
ripset set new <set-name> -t <table> [--type <type>] [-f <family>]

# Delete a set
ripset set del <set-name> -t <table> [-f <family>]
```

### Table Management (nftables only)

```bash
# Create a new table
ripset table new <table-name> [-f <family>]

# Delete a table
ripset table del <table-name> [-f <family>]
```

### Examples

```bash
# nftables backend (default) - using table.set syntax
sudo ripset table new mytable -f inet
sudo ripset set new mytable.myset --type ipv4
sudo ripset add mytable.myset 192.168.1.1
sudo ripset list mytable.myset
sudo ripset del mytable.myset 192.168.1.1
sudo ripset flush mytable.myset
sudo ripset set del mytable.myset
sudo ripset table del mytable

# nftables backend - using -t flag (equivalent)
sudo ripset set new myset -t mytable --type ipv4
sudo ripset add myset 192.168.1.1 -t mytable
sudo ripset list myset -t mytable

# ipset backend (table part ignored if using table.set syntax)
sudo ripset -b ipset set new myset --type hash-ip -f inet
sudo ripset -b ipset add myset 192.168.1.1
sudo ripset -b ipset list myset
sudo ripset -b ipset flush myset
sudo ripset -b ipset set del myset
```

## Requirements

- Linux kernel with netfilter support
- Root privileges (CAP_NET_ADMIN) for all operations
- For ipset: `ip_set` kernel module loaded
- For nftables: `nf_tables` kernel module loaded

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
