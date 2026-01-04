//! ripset - CLI for managing Linux ipset and nftables sets
//!
//! A command-line tool for managing IP sets using either the ipset or nftables backend.

use clap::{Parser, Subcommand, ValueEnum};
use ripset::{
    IpSetCreateOptions, IpSetFamily, IpSetType, NftSetCreateOptions, NftSetType, ipset_add,
    ipset_create, ipset_del, ipset_destroy, ipset_flush, ipset_rename, ipset_swap, ipset_list, nftset_add, nftset_create_set,
    nftset_create_table, nftset_del, nftset_delete_set, nftset_delete_table, nftset_list,
};
use std::net::IpAddr;
use std::process::ExitCode;

/// Parse a set name that may contain a table prefix in the format `<table>.<set>`.
/// Returns (table_name, set_name) where table_name is Some if a dot separator was found.
fn parse_table_set_name(name: &str) -> (Option<&str>, &str) {
    if let Some(dot_pos) = name.find('.') {
        let table = &name[..dot_pos];
        let set = &name[dot_pos + 1..];
        if !table.is_empty() && !set.is_empty() {
            return (Some(table), set);
        }
    }
    (None, name)
}

/// Resolve the table name from either the `<table>.<set>` syntax or the explicit --table flag.
/// The explicit --table flag takes precedence over the parsed table name.
fn resolve_table<'a>(
    parsed_table: Option<&'a str>,
    explicit_table: Option<&'a str>,
) -> Option<&'a str> {
    explicit_table.or(parsed_table)
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum Backend {
    /// Use ipset backend (legacy)
    Ipset,
    /// Use nftables backend (modern)
    #[default]
    #[value(alias("nft"))]
    Nftables,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Family {
    /// IPv4 addresses
    Inet,
    /// IPv6 addresses
    Inet6,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SetType {
    /// hash:ip - stores IP addresses
    HashIp,
    /// hash:net - stores network addresses (CIDR)
    HashNet,
}

#[derive(Parser)]
#[command(name = "ripset")]
#[command(about = "CLI for managing Linux ipset and nftables sets", long_about = None)]
struct Cli {
    /// Backend to use for set operations
    #[arg(short, long, value_enum, default_value_t = Backend::Nftables)]
    backend: Backend,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add an entry to a set
    Add {
        /// Name of the set (use <table>.<set> syntax for nftables)
        set_name: String,
        /// IP address entry to add
        entry: IpAddr,
        /// Table name (required for nftables backend)
        #[arg(short, long)]
        table: Option<String>,
        /// Address family for nftables (inet, ip, ip6)
        #[arg(short, long, default_value = "inet")]
        family: String,
    },
    /// Delete an entry from a set
    Del {
        /// Name of the set (use <table>.<set> syntax for nftables)
        set_name: String,
        /// IP address entry to delete
        entry: IpAddr,
        /// Table name (required for nftables backend)
        #[arg(short, long)]
        table: Option<String>,
        /// Address family for nftables (inet, ip, ip6)
        #[arg(short, long, default_value = "inet")]
        family: String,
    },
    /// List all entries in a set
    List {
        /// Name of the set (use <table>.<set> syntax for nftables)
        set_name: String,
        /// Table name (required for nftables backend)
        #[arg(short, long)]
        table: Option<String>,
        /// Address family for nftables (inet, ip, ip6)
        #[arg(short, long, default_value = "inet")]
        family: String,
    },
    /// Flush all entries from a set
    Flush {
        /// Name of the set (use <table>.<set> syntax for nftables)
        set_name: String,
        /// Table name (required for nftables backend)
        #[arg(short, long)]
        table: Option<String>,
        /// Address family for nftables (inet, ip, ip6)
        #[arg(short, long, default_value = "inet")]
        family: String,
    },
    /// Manage sets (create, delete, rename, swap)
    Set {
        #[command(subcommand)]
        command: SetCommands,
    },
    /// Manage nftables tables (create, delete)
    Table {
        #[command(subcommand)]
        command: TableCommands,
    },
}

#[derive(Subcommand)]
enum SetCommands {
    /// Create a new set
    New {
        /// Name of the set to create (use <table>.<set> syntax for nftables)
        set_name: String,
        /// Table name (required for nftables backend)
        #[arg(short, long)]
        table: Option<String>,
        /// Address family (inet, inet6 for ipset; inet, ip, ip6 for nftables)
        #[arg(short, long, default_value = "inet")]
        family: String,
        /// Set type (hash-ip, hash-net for ipset; ipv4, ipv6 for nftables)
        #[arg(long, default_value = "hash-ip")]
        r#type: String,
    },
    /// Delete a set
    Del {
        /// Name of the set to delete (use <table>.<set> syntax for nftables)
        set_name: String,
        /// Table name (required for nftables backend)
        #[arg(short, long)]
        table: Option<String>,
        /// Address family for nftables (inet, ip, ip6)
        #[arg(short, long, default_value = "inet")]
        family: String,
    },
    /// Rename a set
    Rename {
        /// Old name of the set to rename
        set_name_from: String,
        /// New name of the set to rename
        set_name_to: String,
    },
    /// Swap sets
    Swap {
        /// Name of one set to swap
        set_name_from: String,
        /// Name of other set to swap
        set_name_to: String,
    },
}

#[derive(Subcommand)]
enum TableCommands {
    /// Create a new nftables table
    New {
        /// Name of the table to create
        table_name: String,
        /// Address family (inet, ip, ip6)
        #[arg(short, long, default_value = "inet")]
        family: String,
    },
    /// Delete an nftables table
    Del {
        /// Name of the table to delete
        table_name: String,
        /// Address family (inet, ip, ip6)
        #[arg(short, long, default_value = "inet")]
        family: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Add {
            set_name,
            entry,
            table,
            family,
        } => handle_add(cli.backend, &set_name, entry, table.as_deref(), &family),
        Commands::Del {
            set_name,
            entry,
            table,
            family,
        } => handle_del(cli.backend, &set_name, entry, table.as_deref(), &family),
        Commands::List {
            set_name,
            table,
            family,
        } => handle_list(cli.backend, &set_name, table.as_deref(), &family),
        Commands::Flush {
            set_name,
            table,
            family,
        } => handle_flush(cli.backend, &set_name, table.as_deref(), &family),
        Commands::Set { command } => handle_set_command(cli.backend, command),
        Commands::Table { command } => handle_table_command(cli.backend, command),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn handle_add(
    backend: Backend,
    set_name: &str,
    entry: IpAddr,
    table: Option<&str>,
    family: &str,
) -> Result<(), String> {
    let (parsed_table, actual_set_name) = parse_table_set_name(set_name);
    let resolved_table = resolve_table(parsed_table, table);

    match backend {
        Backend::Ipset => ipset_add(actual_set_name, entry).map_err(|e| e.to_string()),
        Backend::Nftables => {
            let table = resolved_table
                .ok_or("Table name is required for nftables backend (use -t/--table or <table>.<set> syntax)")?;
            nftset_add(family, table, actual_set_name, entry).map_err(|e| e.to_string())
        }
    }
}

fn handle_del(
    backend: Backend,
    set_name: &str,
    entry: IpAddr,
    table: Option<&str>,
    family: &str,
) -> Result<(), String> {
    let (parsed_table, actual_set_name) = parse_table_set_name(set_name);
    let resolved_table = resolve_table(parsed_table, table);

    match backend {
        Backend::Ipset => ipset_del(actual_set_name, entry).map_err(|e| e.to_string()),
        Backend::Nftables => {
            let table = resolved_table
                .ok_or("Table name is required for nftables backend (use -t/--table or <table>.<set> syntax)")?;
            nftset_del(family, table, actual_set_name, entry).map_err(|e| e.to_string())
        }
    }
}

fn handle_list(
    backend: Backend,
    set_name: &str,
    table: Option<&str>,
    family: &str,
) -> Result<(), String> {
    let (parsed_table, actual_set_name) = parse_table_set_name(set_name);
    let resolved_table = resolve_table(parsed_table, table);

    let entries = match backend {
        Backend::Ipset => ipset_list(actual_set_name).map_err(|e| e.to_string())?,
        Backend::Nftables => {
            let table = resolved_table
                .ok_or("Table name is required for nftables backend (use -t/--table or <table>.<set> syntax)")?;
            nftset_list(family, table, actual_set_name).map_err(|e| e.to_string())?
        }
    };

    for entry in entries {
        println!("{entry}");
    }

    Ok(())
}

fn handle_flush(
    backend: Backend,
    set_name: &str,
    table: Option<&str>,
    family: &str,
) -> Result<(), String> {
    let (parsed_table, actual_set_name) = parse_table_set_name(set_name);
    let resolved_table = resolve_table(parsed_table, table);

    match backend {
        Backend::Ipset => ipset_flush(actual_set_name).map_err(|e| e.to_string()),
        Backend::Nftables => {
            let table = resolved_table
                .ok_or("Table name is required for nftables backend (use -t/--table or <table>.<set> syntax)")?;
            // nftables doesn't have a direct flush command, so we list and delete all
            let entries =
                nftset_list(family, table, actual_set_name).map_err(|e| e.to_string())?;
            for entry in entries {
                nftset_del(family, table, actual_set_name, entry).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
    }
}

fn handle_rename(
    backend: Backend,
    set_name_from: &str,
    set_name_to: &str,
) -> Result<(), String> {
    let (_parsed_table, actual_set_name_from) = parse_table_set_name(set_name_from);
    let (_parsed_table, actual_set_name_to) = parse_table_set_name(set_name_to);

    match backend {
        Backend::Ipset => ipset_rename(actual_set_name_from, actual_set_name_to).map_err(|e| e.to_string()),
        Backend::Nftables => {
            Err("Unsupported operation in this backend".into())
        }
    }
}

fn handle_swap(
    backend: Backend,
    set_name_from: &str,
    set_name_to: &str,
) -> Result<(), String> {
    let (_parsed_table, actual_set_name_from) = parse_table_set_name(set_name_from);
    let (_parsed_table, actual_set_name_to) = parse_table_set_name(set_name_to);

    match backend {
        Backend::Ipset => ipset_swap(actual_set_name_from, actual_set_name_to).map_err(|e| e.to_string()),
        Backend::Nftables => {
            Err("Unsupported operation in this backend".into())
        }
    }
}

fn handle_set_command(backend: Backend, command: SetCommands) -> Result<(), String> {
    match command {
        SetCommands::New {
            set_name,
            table,
            family,
            r#type,
        } => {
            let (parsed_table, actual_set_name) = parse_table_set_name(&set_name);
            let resolved_table = resolve_table(parsed_table, table.as_deref());

            match backend {
                Backend::Ipset => {
                    let set_type = parse_ipset_type(&r#type)?;
                    let ip_family = parse_ipset_family(&family)?;
                    let options = IpSetCreateOptions {
                        set_type,
                        family: ip_family,
                        ..Default::default()
                    };
                    ipset_create(actual_set_name, &options).map_err(|e| e.to_string())
                }
                Backend::Nftables => {
                    let table = resolved_table.ok_or(
                        "Table name is required for nftables backend (use -t/--table or <table>.<set> syntax)",
                    )?;
                    let nft_type = parse_nftset_type(&r#type, &family)?;
                    let options = NftSetCreateOptions {
                        set_type: nft_type,
                        ..Default::default()
                    };
                    nftset_create_set(&family, table, actual_set_name, &options)
                        .map_err(|e| e.to_string())
                }
            }
        }
        SetCommands::Del {
            set_name,
            table,
            family,
        } => {
            let (parsed_table, actual_set_name) = parse_table_set_name(&set_name);
            let resolved_table = resolve_table(parsed_table, table.as_deref());

            match backend {
                Backend::Ipset => ipset_destroy(actual_set_name).map_err(|e| e.to_string()),
                Backend::Nftables => {
                    let table = resolved_table.ok_or(
                        "Table name is required for nftables backend (use -t/--table or <table>.<set> syntax)",
                    )?;
                    nftset_delete_set(&family, table, actual_set_name).map_err(|e| e.to_string())
                }
            }
        }
        SetCommands::Rename {
            set_name_from,
            set_name_to,
        } => handle_rename(backend, &set_name_from, &set_name_to),
        SetCommands::Swap {
            set_name_from,
            set_name_to,
        } => handle_swap(backend, &set_name_from, &set_name_to),

    }
}

fn handle_table_command(backend: Backend, command: TableCommands) -> Result<(), String> {
    match backend {
        Backend::Ipset => Err("Table commands are only available for nftables backend".to_string()),
        Backend::Nftables => match command {
            TableCommands::New { table_name, family } => {
                nftset_create_table(&family, &table_name).map_err(|e| e.to_string())
            }
            TableCommands::Del { table_name, family } => {
                nftset_delete_table(&family, &table_name).map_err(|e| e.to_string())
            }
        },
    }
}

fn parse_ipset_type(type_str: &str) -> Result<IpSetType, String> {
    match type_str.to_lowercase().as_str() {
        "hash-ip" | "hash:ip" | "haship" => Ok(IpSetType::HashIp),
        "hash-net" | "hash:net" | "hashnet" => Ok(IpSetType::HashNet),
        _ => Err(format!(
            "Unknown ipset type: {type_str}. Valid types: hash-ip, hash-net"
        )),
    }
}

fn parse_ipset_family(family_str: &str) -> Result<IpSetFamily, String> {
    match family_str.to_lowercase().as_str() {
        "inet" | "ip" | "ipv4" => Ok(IpSetFamily::Inet),
        "inet6" | "ip6" | "ipv6" => Ok(IpSetFamily::Inet6),
        _ => Err(format!(
            "Unknown family: {family_str}. Valid families: inet, inet6"
        )),
    }
}

fn parse_nftset_type(type_str: &str, family: &str) -> Result<NftSetType, String> {
    // For nftables, we can infer from type string or family
    match type_str.to_lowercase().as_str() {
        "ipv4" | "ipv4_addr" | "hash-ip" | "hash:ip" => Ok(NftSetType::Ipv4Addr),
        "ipv6" | "ipv6_addr" => Ok(NftSetType::Ipv6Addr),
        _ => {
            // Try to infer from family
            match family.to_lowercase().as_str() {
                "ip6" | "ipv6" => Ok(NftSetType::Ipv6Addr),
                _ => Ok(NftSetType::Ipv4Addr),
            }
        }
    }
}
