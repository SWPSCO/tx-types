/// Constants for the Cheetah elliptic curve
use super::field::F6Element;
use zkvm_jetpack::form::math::belt::Belt;

/// Group order for the Cheetah curve (hex string)
pub const GROUP_ORDER_HEX: &str =
    "7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf";

/// Generator point X coordinate
pub const GENERATOR_X: F6Element = F6Element([
    Belt(2_754_611_494_552_410_273),
    Belt(8_599_518_745_794_843_693),
    Belt(10_526_511_002_404_673_680),
    Belt(4_830_863_958_577_994_148),
    Belt(375_185_138_577_093_320),
    Belt(12_938_930_721_685_970_739),
]);

/// Generator point Y coordinate
pub const GENERATOR_Y: F6Element = F6Element([
    Belt(15_384_029_202_802_550_068),
    Belt(2_774_812_795_997_841_935),
    Belt(14_375_303_400_746_062_753),
    Belt(10_708_493_419_890_101_954),
    Belt(13_187_678_623_570_541_764),
    Belt(9_990_732_138_772_505_951),
]);

/// Zero element in F^6
pub const F6_ZERO: F6Element = F6Element([Belt(0); 6]);

/// One element in F^6
pub const F6_ONE: F6Element = F6Element([Belt(1), Belt(0), Belt(0), Belt(0), Belt(0), Belt(0)]);

use ibig::UBig;

/// Get the group order as a UBig
pub fn group_order() -> UBig {
    UBig::from_str_radix(GROUP_ORDER_HEX, 16).expect("Valid group order")
}
