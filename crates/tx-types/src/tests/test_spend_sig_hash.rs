#[cfg(test)]
mod tests {
    use crate::transaction_types::{Spend, Seeds, Seed, Source, Lock, SchnorrPubkey, F6LT, Coins, Hash};
    use crate::collections::zset::ZSet;

    #[test]
    fn test_spend_sig_hash_matches_hoon() {
        println!("\n=== Test Spend sig_hash Against Hoon Output ===\n");
        
        // Create the public key used in both seeds
        // From Hoon:
        // x: [a0=13446826628350491310, a1=12945147827865106547, a2=3626991723173904249, ...]
        // y: [a0=9361184495546837822, a1=6958686679437226886, a2=10915892877206693303, ...]
        let pubkey = SchnorrPubkey {
            x: F6LT { 
                values: [
                    13_446_826_628_350_491_310_u64,  // a0
                    12_945_147_827_865_106_547_u64,  // a1
                    3_626_991_723_173_904_249_u64,   // a2
                    1_493_872_536_236_660_972_u64,   // a3
                    4_772_515_469_002_623_845_u64,   // a4
                    3_171_959_084_009_703_037_u64,   // a5
                ]
            },
            y: F6LT {
                values: [
                    9_361_184_495_546_837_822_u64,   // a0
                    6_958_686_679_437_226_886_u64,   // a1
                    10_915_892_877_206_693_303_u64,  // a2
                    5_854_210_250_480_214_826_u64,   // a3
                    13_496_788_948_640_845_657_u64,  // a4
                    15_139_034_619_859_969_291_u64,  // a5
                ]
            },
            inf: false,  // %.n in Hoon means false
        };
        
        // Create Seed 1
        // output-source=~, gift=1.000, parent-hash=[0x1111.1111 0x2222.2222 0x3333.3333 0x4444.4444 0x5555.5555]
        let seed1 = Seed {
            output_source: None,  // ~ means None
            recipient: Lock {
                m: 1,
                pubkeys: {
                    let mut pks = ZSet::new();
                    pks.put(pubkey.clone());
                    pks
                },
            },
            timelock_intent: None,  // ~ means None
            gift: Coins { value: 1000 },
            parent_hash: Hash { 
                values: [
                    0x11111111_u64,
                    0x22222222_u64,
                    0x33333333_u64,
                    0x44444444_u64,
                    0x55555555_u64,
                ]
            },
        };
        
        // Create Seed 2
        // output-source=~, gift=2.000, parent-hash=[0xaaaa.aaaa 0xbbbb.bbbb 0xcccc.cccc 0xdddd.dddd 0xeeee.eeee]
        let seed2 = Seed {
            output_source: None,  // ~ means None
            recipient: Lock {
                m: 1,
                pubkeys: {
                    let mut pks = ZSet::new();
                    pks.put(pubkey.clone());
                    pks
                },
            },
            timelock_intent: None,  // ~ means None
            gift: Coins { value: 2000 },
            parent_hash: Hash {
                values: [
                    0xaaaaaaaa_u64,
                    0xbbbbbbbb_u64,
                    0xcccccccc_u64,
                    0xdddddddd_u64,
                    0xeeeeeeee_u64,
                ]
            },
        };
        
        // Create the Seeds z-set
        // From the Hoon structure, seed1 appears to be in position 'n' (root)
        // and seed2 is in the 'l' (left) branch
        // The ZSet will maintain its own ordering based on the DorTip trait
        let mut seeds_set = ZSet::new();
        seeds_set.put(seed1.clone());
        seeds_set.put(seed2.clone());
        
        // Create the Spend
        let spend = Spend {
            signature: None,  // signature=~
            seeds: Seeds { set: seeds_set },
            fee: Coins { value: 150 },
        };
        
        // Calculate the sig_hash
        let sig_hash = spend.sig_hash();
        
        // Expected sig-hash from Hoon (with dots removed from hex notation):
        // [0x1952.5fdc.149a.ef7a, 0x970.ca46.bf1d.0ef2, 0x8701.1103.6c42.ae2a, 
        //  0x2408.7c50.9a0b.c9e3, 0xd120.c440.4307.1d72]
        let expected_hash = Hash {
            values: [
                0x19525fdc149aef7a_u64,
                0x0970ca46bf1d0ef2_u64,  // Note: leading zero preserved
                0x870111036c42ae2a_u64,
                0x24087c509a0bc9e3_u64,
                0xd120c44043071d72_u64,
            ]
        };
        
        // Print for debugging
        println!("Pubkey x: {:016x?}", pubkey.x.values);
        println!("Pubkey y: {:016x?}", pubkey.y.values);
        println!("\nSeed 1:");
        println!("  Gift: {}", seed1.gift.value);
        println!("  Parent hash: {:08x?}", seed1.parent_hash.values);
        println!("\nSeed 2:");
        println!("  Gift: {}", seed2.gift.value);
        println!("  Parent hash: {:08x?}", seed2.parent_hash.values);
        println!("\nSpend fee: {}", spend.fee.value);
        
        println!("\nGenerated sig_hash: {:016x?}", sig_hash.values);
        println!("Expected sig_hash:  {:016x?}", expected_hash.values);
        
        // Verify the hash matches
        assert_eq!(
            sig_hash, expected_hash,
            "sig_hash should match the Hoon output"
        );
        
        println!("\n✓ Spend sig_hash matches Hoon implementation!");
    }
}