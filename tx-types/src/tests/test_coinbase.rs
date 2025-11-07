#[cfg(test)]
pub mod tests {
    use crate::block_types::Page;
    use crate::collections::{ZMap, ZSet};
    use crate::transaction_types::*;

    // Helper to create test lock
    fn test_lock() -> Lock {
        let pubkey = SchnorrPubkey {
            x: F6LT {
                values: [1, 2, 3, 4, 5, 6],
            },
            y: F6LT {
                values: [7, 8, 9, 10, 11, 12],
            },
            inf: false,
        };
        let mut pubkeys = ZSet::new();
        pubkeys.put(pubkey);
        Lock { m: 1, pubkeys }
    }

    #[test]
    fn test_coinbase_timelock_first_month() {
        // Test that blocks in the first month are locked until block 4383
        let height = PageNumber { value: 100 };
        let timelock = Page::coinbase_timelock(height);

        assert!(timelock.intent.is_some());
        if let Some((_, page_range)) = &timelock.intent {
            assert_eq!(page_range.min, Some(PageNumber { value: 4383 }));
            assert_eq!(page_range.max, None);
        } else {
            panic!("Expected timelock to have intent");
        }
    }

    #[test]
    fn test_coinbase_timelock_after_first_month() {
        // Test that blocks after 4383 are locked until block 100
        let height = PageNumber { value: 5000 };
        let timelock = Page::coinbase_timelock(height);

        assert!(timelock.intent.is_some());
        if let Some((_, page_range)) = &timelock.intent {
            assert_eq!(page_range.min, Some(PageNumber { value: 100 }));
            assert_eq!(page_range.max, None);
        } else {
            panic!("Expected timelock to have intent");
        }
    }

    #[test]
    fn test_coinbase_timelock_boundary() {
        // Test the boundary case at exactly 4383
        let height = PageNumber { value: 4383 };
        let timelock = Page::coinbase_timelock(height);

        assert!(timelock.intent.is_some());
        if let Some((_, page_range)) = &timelock.intent {
            assert_eq!(page_range.min, Some(PageNumber { value: 100 }));
            assert_eq!(page_range.max, None);
        } else {
            panic!("Expected timelock to have intent");
        }
    }

    #[test]
    fn test_coinbase_notes_creation() {
        // Create a mock page with coinbase data
        let lock = test_lock();
        let coins = Coins { value: 1000 };

        let mut coinbase_map = ZMap::new();
        coinbase_map.put(lock.clone(), coins.clone());
        let coinbase = crate::block_types::Coinbase { map: coinbase_map };

        let parent_hash = Hash {
            values: [1, 2, 3, 4, 5],
        };

        let page = Page {
            digest: Hash {
                values: [0, 0, 0, 0, 0],
            },
            pow: crate::block_types::Pow {
                p: bytes::Bytes::new(),
            },
            parent: parent_hash.clone(),
            tx_ids: crate::block_types::TransactionIds::new(),
            coinbase,
            timestamp: crate::block_types::Timestamp {
                value: chrono::Utc::now(),
            },
            epoch_counter: crate::block_types::EpochCounter::new(0),
            target: crate::block_types::BigNum {
                header: "".to_string(),
                body: vec![],
            },
            accumulated_work: crate::block_types::BigNum {
                header: "".to_string(),
                body: vec![],
            },
            height: PageNumber { value: 100 },
            msg: crate::block_types::PageMsg::new(),
        };

        let notes = page.coinbase_notes();

        // Should have one note for our one coinbase recipient
        assert_eq!(notes.len(), 1);

        // Check the note properties
        let note = &notes[0];
        assert_eq!(note.lock, lock);
        assert_eq!(note.assets, coins);
        assert_eq!(note.meta.origin_page, PageNumber { value: 100 });
        assert!(note.source.is_coinbase);
        assert_eq!(note.source.p, parent_hash);
    }

    #[test]
    fn test_coinbase_notes_multiple_recipients() {
        // Create a mock page with multiple coinbase recipients
        let lock1 = test_lock();

        let pubkey2 = SchnorrPubkey {
            x: F6LT {
                values: [2, 2, 2, 2, 2, 2],
            },
            y: F6LT {
                values: [3, 3, 3, 3, 3, 3],
            },
            inf: false,
        };
        let mut pubkeys2 = ZSet::new();
        pubkeys2.put(pubkey2);
        let lock2 = Lock {
            m: 1,
            pubkeys: pubkeys2,
        };

        let coins1 = Coins { value: 1000 };
        let coins2 = Coins { value: 2000 };

        let mut coinbase_map = ZMap::new();
        coinbase_map.put(lock1.clone(), coins1.clone());
        coinbase_map.put(lock2.clone(), coins2.clone());
        let coinbase = crate::block_types::Coinbase { map: coinbase_map };

        let parent_hash = Hash {
            values: [5, 4, 3, 2, 1],
        };

        let page = Page {
            digest: Hash {
                values: [0, 0, 0, 0, 0],
            },
            pow: crate::block_types::Pow {
                p: bytes::Bytes::new(),
            },
            parent: parent_hash.clone(),
            tx_ids: crate::block_types::TransactionIds::new(),
            coinbase,
            timestamp: crate::block_types::Timestamp {
                value: chrono::Utc::now(),
            },
            epoch_counter: crate::block_types::EpochCounter::new(0),
            target: crate::block_types::BigNum {
                header: "".to_string(),
                body: vec![],
            },
            accumulated_work: crate::block_types::BigNum {
                header: "".to_string(),
                body: vec![],
            },
            height: PageNumber { value: 5000 },
            msg: crate::block_types::PageMsg::new(),
        };

        let notes = page.coinbase_notes();

        // Should have two notes
        assert_eq!(notes.len(), 2);

        // All notes should be coinbase and have correct timelock
        for note in &notes {
            assert!(note.source.is_coinbase);
            assert_eq!(note.source.p, parent_hash);
            assert_eq!(note.meta.origin_page, PageNumber { value: 5000 });

            // Check timelock is set to 100
            if let Some((_, page_range)) = &note.meta.timelock.intent {
                assert_eq!(page_range.min, Some(PageNumber { value: 100 }));
            } else {
                panic!("Expected timelock to have intent");
            }
        }
    }
}
