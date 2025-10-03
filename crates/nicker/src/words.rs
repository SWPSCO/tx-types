// Simple deterministic word selection without external RNG

const ADJECTIVES: &[&str] = &[
    "sleepy", "hungry", "brave", "fuzzy", "clever", "rusty",
    "happy", "sad", "angry", "curious", "gentle", "bold",
    "shy", "loud", "quiet", "bright", "dark", "swift",
    "slow", "strong", "weak", "wise", "foolish", "graceful",
];
const NOUNS: &[&str] = &[
    "tiger", "otter", "eagle", "panda", "narwhal", "beetle",
    "lion", "dolphin", "falcon", "koala", "whale", "ant",
    "elephant", "wolf", "sparrow", "dragon", "shark", "butterfly",
    "giraffe", "bear", "penguin", "zebra", "fox", "rabbit",
];
const VERBS: &[&str] = &[
    "sleeping", "eating", "running", "jumping", "flying", "swimming",
    "reading", "writing", "singing", "dancing", "drawing", "painting",
    "cooking", "baking", "gardening", "cycling", "crouching", "climbing",
    "fishing", "skating", "skiing", "surfing", "kayaking", "rowing",
];

const NOUNS2: &[&str] = &[
    "cheetah", "platypus", "hawk", "lemur", "manatee", "cricket",
    "panther", "orca", "vulture", "sloth", "seal", "termite",
    "rhinoceros", "coyote", "finch", "griffin", "barracuda", "moth",
    "kangaroo", "bison", "flamingo", "gazelle", "badger", "hedgehog",
];

pub fn generate_tx_name(input: String) -> String {
    // 1. Convert the input data to u64
    let input_data: u64 = input.as_bytes().iter().fold(0u64, |h, b| h.wrapping_mul(131) ^ *b as u64) | 1;

    // 2. Pull current time in millis:
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs() as u64;

    // 3. Use a simple hash-based deterministic selection
    let seed = input_data.wrapping_mul(now);

    // 4. Select words deterministically using the seed
    let adj_idx = (seed.wrapping_mul(2654435761) >> 32) as usize % ADJECTIVES.len();
    let noun_idx = (seed.wrapping_mul(2654435789) >> 32) as usize % NOUNS.len();
    let verb_idx = (seed.wrapping_mul(2654435813) >> 32) as usize % VERBS.len();
    let noun2_idx = (seed.wrapping_mul(2654435831) >> 32) as usize % NOUNS2.len();

    let adj = ADJECTIVES[adj_idx];
    let noun = NOUNS[noun_idx];
    let verb = VERBS[verb_idx];
    let noun2 = NOUNS2[noun2_idx];

    // 5. Combine with timestamp and words:
    format!("{}-{}-{}-{}-{}", now, adj, noun, verb, noun2)
}