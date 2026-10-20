use crate::note_data::{DecodedNoteData, DecodedNoteDataPayload};
use crate::word_count::{note_data_words, transaction_words};
use crate::*;
use alloc::{string::String, vec::Vec};
use pokenoun::codec::{Decode, Encode};

struct NoteDataFixture {
    case: String,
    data: NoteData,
    hash: Hash,
    words: u64,
}
struct WithdrawalTransaction {
    version: u64,
    name: String,
    spends: SpendsV1,
    metadata: UntypedNoun,
    witness_data: UntypedNoun,
}
struct WithdrawalFixture {
    case: String,
    transaction: WithdrawalTransaction,
    height: u64,
    min_fee: u64,
    seed_words: u64,
    witness_words: u64,
}
crate::noun_codec::noun_struct!(
    NoteDataFixture {
        case,
        data,
        hash,
        words
    },
    WithdrawalTransaction {
        version,
        name,
        spends,
        metadata,
        witness_data
    },
    WithdrawalFixture {
        case,
        transaction,
        height,
        min_fee,
        seed_words,
        witness_words
    }
);

#[test]
fn note_data_matches_official_hashes_words_and_typed_encodings() {
    let bytes = include_bytes!("../../tests/reference/note-data-oracle.jam");
    let fixtures = Vec::<NoteDataFixture>::from_jam(bytes).unwrap();
    assert!(fixtures.len() >= 14);
    for fixture in fixtures {
        assert_eq!(
            fixture.data.to_hash().unwrap(),
            fixture.hash,
            "{}",
            fixture.case
        );
        assert_eq!(
            note_data_words(&fixture.data).unwrap(),
            fixture.words,
            "{}",
            fixture.case
        );
        let decoded = DecodedNoteData::from_note_data(&fixture.data).unwrap();
        let entries = decoded
            .0
            .iter()
            .map(|entry| (entry.key.clone(), entry.raw_value().unwrap()));
        let normalized = NoteData::normalize(entries).unwrap();
        assert_eq!(
            normalized.to_jam().unwrap(),
            fixture.data.to_jam().unwrap(),
            "{}",
            fixture.case
        );
        let payload = &decoded.0[0].payload;
        if fixture.case.contains("unsupported") || fixture.case == "wildcard" {
            assert!(
                matches!(payload, DecodedNoteDataPayload::Raw(_)),
                "{}",
                fixture.case
            );
        } else {
            assert!(
                !matches!(payload, DecodedNoteDataPayload::Raw(_)),
                "{}",
                fixture.case
            );
        }
    }
}

#[test]
fn raw_transactions_match_official_ids_signature_hashes_and_word_counts() {
    let bytes = include_bytes!("../../tests/reference/raw-tx-v1.jam");
    let raw = RawTransactionV1::from_jam(bytes).unwrap();
    assert_eq!(compute_tx_id_v1(&raw.spends).unwrap(), raw.id);
    let oracle =
        Vec::<(NName, Hash)>::from_jam(include_bytes!("../../tests/reference/spend1-sig-hash.jam"))
            .unwrap();
    assert!(!oracle.is_empty());
    for (name, hash) in oracle {
        let spend = raw.spends.map.get(&name).unwrap();
        assert_eq!(spend.body.sig_hash().unwrap(), hash);
    }
    let words = transaction_words(&raw.spends.map, true).unwrap();
    // Seed fees count the flattened key/value reduction, including one terminator.
    assert_eq!((words.seed_words, words.witness_words), (5, 133));
    assert_eq!(calculate_min_fee(&raw.spends.map).value, 626_688);
    let raw =
        RawTransactionV0::from_jam(include_bytes!("../../tests/reference/raw-tx-v0.jam")).unwrap();
    assert_eq!(
        compute_tx_id(&Inputs::V0(raw.inputs), &raw.timelock_range, raw.total_fees),
        raw.id
    );
}

#[test]
fn withdrawal_fixtures_match_hoon_fee_configuration() {
    let fixtures = Vec::<WithdrawalFixture>::from_jam(include_bytes!(
        "../../tests/reference/withdrawal-transactions.jam"
    ))
    .unwrap();
    assert!(fixtures.len() >= 4);
    for fixture in fixtures {
        let active = fixture.height >= 10;
        let mut words = transaction_words(&fixture.transaction.spends.map, active).unwrap();
        // Wallet fixtures carry unsigned spends; their fee oracle includes the required signatures.
        for (_, spend) in fixture.transaction.spends.map.tap() {
            let SpendBody::V1(spend) = spend.body else {
                panic!("withdrawal witness spend")
            };
            let signatures = spend
                .witness
                .lmp
                .spend_condition()
                .required_pkh_policy()
                .unwrap()
                .threshold as u64;
            words.witness_words +=
                crate::word_count::signature_map_words(signatures, 18).unwrap() - 1;
        }
        assert_eq!(words.seed_words, fixture.seed_words, "{}", fixture.case);
        assert_eq!(
            words.witness_words, fixture.witness_words,
            "{}",
            fixture.case
        );
        let chain = planner::ChainContext {
            base_fee: 256,
            min_fee: 0,
            bythos_phase: 10,
            ..planner::ChainContext::at_height(fixture.height)
        };
        assert_eq!(
            chain.minimum_fee(words),
            fixture.min_fee,
            "{}",
            fixture.case
        );
    }
}

#[test]
fn bridge_addresses_and_note_data_reject_invalid_encodings() {
    use crate::note_data::BridgeDepositDataPayload;
    for address in [[0; 20], [255; 20], [42; 20]] {
        let payload = BridgeDepositDataPayload::from_evm_address(address);
        assert_eq!(payload.to_evm_address().unwrap(), address);
        let decoded = BridgeDepositDataPayload::from_jam(&payload.to_jam().unwrap()).unwrap();
        assert_eq!(decoded, payload);
    }
    assert!(BridgeDepositDataPayload {
        evm_address_based: [0, 0, u64::MAX]
    }
    .to_jam()
    .is_err());
    let one = UntypedNoun::from_value(&1u64).unwrap();
    let two = UntypedNoun::from_value(&2u64).unwrap();
    assert!(NoteData::normalize([("k".into(), one.clone()), (" k ".into(), two)]).is_err());
    assert_eq!(
        NoteData::normalize([("k".into(), one.clone()), (" k ".into(), one)])
            .unwrap()
            .map
            .wyt(),
        1
    );
    assert!(NoteData::normalize([("".into(), UntypedNoun::from_value(&0u64).unwrap())]).is_err());
}

#[test]
fn invalid_collection_insertions_preserve_existing_entries() {
    let mut map = ZMap::<u64, u64>::new();
    assert!(map.try_put(u64::MAX, 0).is_err());
    map.put(1, 2);
    let before = map.to_jam().unwrap();
    assert!(map.try_put(u64::MAX, 3).is_err());
    assert_eq!(map.to_jam().unwrap(), before);
    let mut set = ZSet::<u64>::new();
    assert!(set.try_put(u64::MAX).is_err());
    set.put(1);
    let before = set.to_jam().unwrap();
    assert!(set.try_put(u64::MAX).is_err());
    assert_eq!(set.to_jam().unwrap(), before);
}

struct FeeFixture {
    case: String,
    spends: SpendsV1,
    height: u64,
    base: u64,
    divisor: u64,
    minimum: u64,
    seed_words: u64,
    witness_words: u64,
    fee: u64,
}
crate::noun_codec::noun_struct!(FeeFixture {
    case,
    spends,
    height,
    base,
    divisor,
    minimum,
    seed_words,
    witness_words,
    fee
});

#[test]
fn fees_match_hoon_for_multiple_inputs_and_migration_on_both_sides_of_bythos() {
    let fixtures =
        Vec::<FeeFixture>::from_jam(include_bytes!("../../tests/reference/fee-oracle.jam"))
            .unwrap();
    assert_eq!(fixtures.len(), 12);
    for row in fixtures {
        let words = transaction_words(&row.spends.map, row.height >= 10).unwrap();
        assert_eq!(
            (words.seed_words, words.witness_words),
            (row.seed_words, row.witness_words),
            "{} at {}",
            row.case,
            row.height
        );
        let chain = planner::ChainContext {
            base_fee: row.base,
            min_fee: row.minimum,
            input_fee_divisor: row.divisor,
            bythos_phase: 10,
            ..planner::ChainContext::at_height(row.height)
        };
        assert_eq!(
            chain.minimum_fee(words),
            row.fee,
            "{} at {}",
            row.case,
            row.height
        );
    }
}

#[test]
fn portable_jam_matches_official_bytes_with_canonical_backreferences() {
    let fixtures: &[&[u8]] = &[
        include_bytes!("../../tests/reference/lock-proofs.jam"),
        include_bytes!("../../tests/reference/note-data-oracle.jam"),
        include_bytes!("../../tests/reference/fee-oracle.jam"),
        include_bytes!("../../tests/reference/raw-tx-v0.jam"),
        include_bytes!("../../tests/reference/raw-tx-v1.jam"),
        include_bytes!("../../tests/reference/spend1-sig-hash.jam"),
        include_bytes!("../../tests/reference/withdrawal-transactions.jam"),
    ];
    for bytes in fixtures {
        let mut arena = pokenoun::Arena::new();
        let noun = pokenoun::cue(bytes, &mut arena).unwrap();
        // Official generator files pad the JAM atom to an eight-byte word.
        let end = bytes.iter().rposition(|byte| *byte != 0).unwrap() + 1;
        assert_eq!(pokenoun::jam(noun, &arena), bytes[..end]);
    }
    let bytes = include_bytes!("../../tests/reference/raw-tx-v1.jam");
    let raw = RawTransactionV1::from_jam(bytes).unwrap();
    let end = bytes.iter().rposition(|byte| *byte != 0).unwrap() + 1;
    assert_eq!(raw.to_jam().unwrap(), bytes[..end]);
}
