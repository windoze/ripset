//! Integration tests for ipset/nftset operations.
//!
//! These tests require root privileges.
//! Build with: cargo test --no-run
//! Run with: sudo ./target/debug/deps/integration_tests-*

use std::net::IpAddr;

use ripset::{
    IpEntry, IpSetCreateOptions, IpSetFamily, NftSetCreateOptions, NftSetType, ipset_add,
    ipset_create, ipset_del, ipset_destroy, ipset_list, ipset_test, nftset_add, nftset_create_set,
    nftset_create_table, nftset_del, nftset_delete_table, nftset_list, nftset_list_tables,
    nftset_test,
};

// =====================
// ipset tests
// =====================

mod ipset_tests {
    use super::*;

    // Each test uses unique set names to avoid race conditions when running in parallel

    #[test]
    fn test_ipset_add_test_del_ipv4() {
        const SET_NAME: &str = "lipsets_test_v4";

        // Setup
        let _ = ipset_destroy(SET_NAME);
        let opts = IpSetCreateOptions::default();
        ipset_create(SET_NAME, &opts).expect("Failed to create ipset");

        let addr: IpAddr = "10.0.0.1".parse().unwrap();

        // Test that IP is not in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IP");
        assert!(!exists, "IP should not exist initially");

        // Add IP to set
        ipset_add(SET_NAME, addr).expect("Failed to add IP");

        // Test that IP is now in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IP after add");
        assert!(exists, "IP should exist after add");

        // Delete IP from set
        ipset_del(SET_NAME, addr).expect("Failed to delete IP");

        // Test that IP is no longer in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IP after del");
        assert!(!exists, "IP should not exist after delete");

        // Cleanup
        let _ = ipset_destroy(SET_NAME);
    }

    #[test]
    fn test_ipset_add_test_del_ipv6() {
        const SET_NAME: &str = "lipsets_test_v6";

        // Setup
        let _ = ipset_destroy(SET_NAME);
        let opts = IpSetCreateOptions {
            family: IpSetFamily::Inet6,
            ..Default::default()
        };
        ipset_create(SET_NAME, &opts).expect("Failed to create ipset6");

        let addr: IpAddr = "2001:db8::1".parse().unwrap();

        // Test that IP is not in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IPv6");
        assert!(!exists, "IPv6 should not exist initially");

        // Add IP to set
        ipset_add(SET_NAME, addr).expect("Failed to add IPv6");

        // Test that IP is now in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IPv6 after add");
        assert!(exists, "IPv6 should exist after add");

        // Delete IP from set
        ipset_del(SET_NAME, addr).expect("Failed to delete IPv6");

        // Test that IP is no longer in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IPv6 after del");
        assert!(!exists, "IPv6 should not exist after delete");

        // Cleanup
        let _ = ipset_destroy(SET_NAME);
    }

    #[test]
    fn test_ipset_with_timeout() {
        const SET_NAME: &str = "lipsets_test_timeout";

        // Setup
        let _ = ipset_destroy(SET_NAME);
        let opts = IpSetCreateOptions {
            timeout: Some(300),
            ..Default::default()
        };
        ipset_create(SET_NAME, &opts).expect("Failed to create ipset with timeout");

        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        let entry = IpEntry::with_timeout(addr, 60);

        // Add IP with timeout
        ipset_add(SET_NAME, entry).expect("Failed to add IP with timeout");

        // Test that IP is in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IP");
        assert!(exists, "IP should exist after add with timeout");

        // Cleanup
        let _ = ipset_destroy(SET_NAME);
    }

    #[test]
    fn test_ipset_multiple_ips() {
        const SET_NAME: &str = "lipsets_test_multi";

        // Setup
        let _ = ipset_destroy(SET_NAME);
        let opts = IpSetCreateOptions::default();
        ipset_create(SET_NAME, &opts).expect("Failed to create ipset");

        let addrs: Vec<IpAddr> = vec![
            "10.0.0.10".parse().unwrap(),
            "10.0.0.11".parse().unwrap(),
            "10.0.0.12".parse().unwrap(),
        ];

        // Add all IPs
        for addr in &addrs {
            ipset_add(SET_NAME, *addr).expect("Failed to add IP");
        }

        // Test all IPs exist
        for addr in &addrs {
            let exists = ipset_test(SET_NAME, *addr).expect("Failed to test IP");
            assert!(exists, "IP {} should exist", addr);
        }

        // Delete all IPs
        for addr in &addrs {
            ipset_del(SET_NAME, *addr).expect("Failed to delete IP");
        }

        // Test all IPs are gone
        for addr in &addrs {
            let exists = ipset_test(SET_NAME, *addr).expect("Failed to test IP");
            assert!(!exists, "IP {} should not exist after delete", addr);
        }

        // Cleanup
        let _ = ipset_destroy(SET_NAME);
    }

    #[test]
    fn test_ipset_nonexistent_set() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();

        let result = ipset_add("nonexistent_set_12345", addr);
        assert!(result.is_err(), "Should fail for nonexistent set");
    }

    #[test]
    fn test_ipset_list() {
        const SET_NAME: &str = "lipsets_test_list";

        // Setup
        let _ = ipset_destroy(SET_NAME);
        let opts = IpSetCreateOptions::default();
        ipset_create(SET_NAME, &opts).expect("Failed to create ipset");

        // Initially empty
        let ips = ipset_list(SET_NAME).expect("Failed to list ipset");
        assert!(ips.is_empty(), "Set should be empty initially");

        // Add some IPs
        let addr1: IpAddr = "10.0.0.1".parse().unwrap();
        let addr2: IpAddr = "10.0.0.2".parse().unwrap();
        let addr3: IpAddr = "10.0.0.3".parse().unwrap();

        ipset_add(SET_NAME, addr1).expect("Failed to add IP");
        ipset_add(SET_NAME, addr2).expect("Failed to add IP");
        ipset_add(SET_NAME, addr3).expect("Failed to add IP");

        // List should now contain all three
        let ips = ipset_list(SET_NAME).expect("Failed to list ipset");
        assert_eq!(ips.len(), 3, "Set should contain 3 IPs");
        assert!(ips.contains(&addr1), "Set should contain addr1");
        assert!(ips.contains(&addr2), "Set should contain addr2");
        assert!(ips.contains(&addr3), "Set should contain addr3");

        // Delete one and verify
        ipset_del(SET_NAME, addr2).expect("Failed to delete IP");
        let ips = ipset_list(SET_NAME).expect("Failed to list ipset");
        assert_eq!(ips.len(), 2, "Set should contain 2 IPs after delete");
        assert!(!ips.contains(&addr2), "Set should not contain addr2");

        // Cleanup
        let _ = ipset_destroy(SET_NAME);
    }
}

// =====================
// nftset tests
// =====================

mod nftset_tests {
    use super::*;

    // Each test uses unique table/set names to avoid race conditions when running in parallel

    #[test]
    fn test_nftset_add_test_del_ipv4() {
        const TABLE_NAME: &str = "lnftsets_test_v4";
        const SET_NAME: &str = "test_set";

        // Setup
        let _ = nftset_delete_table("inet", TABLE_NAME);
        nftset_create_table("inet", TABLE_NAME).expect("Failed to create table");
        let opts = NftSetCreateOptions::default();
        nftset_create_set("inet", TABLE_NAME, SET_NAME, &opts).expect("Failed to create set");

        let addr: IpAddr = "10.0.0.1".parse().unwrap();

        // Test that IP is not in set
        let exists = nftset_test("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to test IP");
        assert!(!exists, "IP should not exist initially");

        // Add IP to set
        nftset_add("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to add IP");

        // Test that IP is now in set
        let exists =
            nftset_test("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to test IP after add");
        assert!(exists, "IP should exist after add");

        // Delete IP from set
        nftset_del("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to delete IP");

        // Test that IP is no longer in set
        let exists =
            nftset_test("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to test IP after del");
        assert!(!exists, "IP should not exist after delete");

        // Cleanup
        let _ = nftset_delete_table("inet", TABLE_NAME);
    }

    #[test]
    fn test_nftset_add_test_del_ipv6() {
        const TABLE_NAME: &str = "lnftsets_test_v6";
        const SET_NAME: &str = "test_set";

        // Setup
        let _ = nftset_delete_table("inet", TABLE_NAME);
        nftset_create_table("inet", TABLE_NAME).expect("Failed to create table");
        let opts = NftSetCreateOptions {
            set_type: NftSetType::Ipv6Addr,
            ..Default::default()
        };
        nftset_create_set("inet", TABLE_NAME, SET_NAME, &opts).expect("Failed to create set6");

        let addr: IpAddr = "2001:db8::1".parse().unwrap();

        // Test that IP is not in set
        let exists = nftset_test("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to test IPv6");
        assert!(!exists, "IPv6 should not exist initially");

        // Add IP to set
        nftset_add("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to add IPv6");

        // Test that IP is now in set
        let exists =
            nftset_test("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to test IPv6 after add");
        assert!(exists, "IPv6 should exist after add");

        // Delete IP from set
        nftset_del("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to delete IPv6");

        // Test that IP is no longer in set
        let exists =
            nftset_test("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to test IPv6 after del");
        assert!(!exists, "IPv6 should not exist after delete");

        // Cleanup
        let _ = nftset_delete_table("inet", TABLE_NAME);
    }

    #[test]
    fn test_nftset_with_timeout() {
        const TABLE_NAME: &str = "lnftsets_test_timeout";
        const SET_NAME: &str = "test_set";

        // Setup
        let _ = nftset_delete_table("inet", TABLE_NAME);
        nftset_create_table("inet", TABLE_NAME).expect("Failed to create table");
        let opts = NftSetCreateOptions {
            timeout: Some(300),
            ..Default::default()
        };
        nftset_create_set("inet", TABLE_NAME, SET_NAME, &opts)
            .expect("Failed to create set with timeout");

        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        let entry = IpEntry::with_timeout(addr, 60);

        // Add IP with timeout
        nftset_add("inet", TABLE_NAME, SET_NAME, entry).expect("Failed to add IP with timeout");

        // Test that IP is in set
        let exists = nftset_test("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to test IP");
        assert!(exists, "IP should exist after add with timeout");

        // Cleanup
        let _ = nftset_delete_table("inet", TABLE_NAME);
    }

    #[test]
    fn test_nftset_multiple_ips() {
        const TABLE_NAME: &str = "lnftsets_test_multi";
        const SET_NAME: &str = "test_set";

        // Setup
        let _ = nftset_delete_table("inet", TABLE_NAME);
        nftset_create_table("inet", TABLE_NAME).expect("Failed to create table");
        let opts = NftSetCreateOptions::default();
        nftset_create_set("inet", TABLE_NAME, SET_NAME, &opts).expect("Failed to create set");

        let addrs: Vec<IpAddr> = vec![
            "10.0.0.10".parse().unwrap(),
            "10.0.0.11".parse().unwrap(),
            "10.0.0.12".parse().unwrap(),
        ];

        // Add all IPs
        for addr in &addrs {
            nftset_add("inet", TABLE_NAME, SET_NAME, *addr).expect("Failed to add IP");
        }

        // Test all IPs exist
        for addr in &addrs {
            let exists =
                nftset_test("inet", TABLE_NAME, SET_NAME, *addr).expect("Failed to test IP");
            assert!(exists, "IP {} should exist", addr);
        }

        // Delete all IPs
        for addr in &addrs {
            nftset_del("inet", TABLE_NAME, SET_NAME, *addr).expect("Failed to delete IP");
        }

        // Test all IPs are gone
        for addr in &addrs {
            let exists =
                nftset_test("inet", TABLE_NAME, SET_NAME, *addr).expect("Failed to test IP");
            assert!(!exists, "IP {} should not exist after delete", addr);
        }

        // Cleanup
        let _ = nftset_delete_table("inet", TABLE_NAME);
    }

    #[test]
    fn test_nftset_nonexistent_set() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();

        let result = nftset_add("inet", "nonexistent_table", "nonexistent_set", addr);
        assert!(result.is_err(), "Should fail for nonexistent set");
    }

    #[test]
    fn test_nftset_list() {
        const TABLE_NAME: &str = "lnftsets_test_list";
        const SET_NAME: &str = "test_set";

        // Setup
        let _ = nftset_delete_table("inet", TABLE_NAME);
        nftset_create_table("inet", TABLE_NAME).expect("Failed to create table");
        let opts = NftSetCreateOptions::default();
        nftset_create_set("inet", TABLE_NAME, SET_NAME, &opts).expect("Failed to create set");

        // Initially empty
        let ips = nftset_list("inet", TABLE_NAME, SET_NAME).expect("Failed to list nftset");
        assert!(ips.is_empty(), "Set should be empty initially");

        // Add some IPs
        let addr1: IpAddr = "10.0.0.1".parse().unwrap();
        let addr2: IpAddr = "10.0.0.2".parse().unwrap();
        let addr3: IpAddr = "10.0.0.3".parse().unwrap();

        nftset_add("inet", TABLE_NAME, SET_NAME, addr1).expect("Failed to add IP");
        nftset_add("inet", TABLE_NAME, SET_NAME, addr2).expect("Failed to add IP");
        nftset_add("inet", TABLE_NAME, SET_NAME, addr3).expect("Failed to add IP");

        // Verify with nftset_test
        assert!(
            nftset_test("inet", TABLE_NAME, SET_NAME, addr1).unwrap(),
            "addr1 should exist via test"
        );
        assert!(
            nftset_test("inet", TABLE_NAME, SET_NAME, addr2).unwrap(),
            "addr2 should exist via test"
        );
        assert!(
            nftset_test("inet", TABLE_NAME, SET_NAME, addr3).unwrap(),
            "addr3 should exist via test"
        );

        // List should now contain all three
        let ips = nftset_list("inet", TABLE_NAME, SET_NAME).expect("Failed to list nftset");
        assert_eq!(ips.len(), 3, "Set should contain 3 IPs");
        assert!(ips.contains(&addr1), "Set should contain addr1");
        assert!(ips.contains(&addr2), "Set should contain addr2");
        assert!(ips.contains(&addr3), "Set should contain addr3");

        // Delete one and verify
        nftset_del("inet", TABLE_NAME, SET_NAME, addr2).expect("Failed to delete IP");
        let ips = nftset_list("inet", TABLE_NAME, SET_NAME).expect("Failed to list nftset");
        assert_eq!(ips.len(), 2, "Set should contain 2 IPs after delete");
        assert!(!ips.contains(&addr2), "Set should not contain addr2");

        // Cleanup
        let _ = nftset_delete_table("inet", TABLE_NAME);
    }

    #[test]
    fn test_nftset_list_tables() {
        const TABLE_NAME1: &str = "lnftsets_test_tables_1";
        const TABLE_NAME2: &str = "lnftsets_test_tables_2";

        // Setup - ensure clean state
        let _ = nftset_delete_table("inet", TABLE_NAME1);
        let _ = nftset_delete_table("inet", TABLE_NAME2);

        // Create two tables
        nftset_create_table("inet", TABLE_NAME1).expect("Failed to create table1");
        nftset_create_table("inet", TABLE_NAME2).expect("Failed to create table2");

        // List tables
        let tables = nftset_list_tables("inet").expect("Failed to list tables");

        // Should contain both tables we created
        assert!(
            tables.contains(&TABLE_NAME1.to_string()),
            "Should contain table1"
        );
        assert!(
            tables.contains(&TABLE_NAME2.to_string()),
            "Should contain table2"
        );

        // Delete one and verify
        nftset_delete_table("inet", TABLE_NAME1).expect("Failed to delete table1");
        let tables = nftset_list_tables("inet").expect("Failed to list tables after delete");
        assert!(
            !tables.contains(&TABLE_NAME1.to_string()),
            "Should not contain deleted table1"
        );
        assert!(
            tables.contains(&TABLE_NAME2.to_string()),
            "Should still contain table2"
        );

        // Cleanup
        let _ = nftset_delete_table("inet", TABLE_NAME2);
    }
}
