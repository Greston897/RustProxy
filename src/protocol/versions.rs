//! Поддерживаемые протоколы Minecraft Java Edition: 1.16.5 (754) → 26.3 (777, 2026).
//!
//! Источник: wiki.vg / mcreference.com / minecraft.wiki (Protocol History).

pub const MIN_PROTOCOL: i32 = 754;
pub const MAX_PROTOCOL: i32 = 777;

pub const PROTOCOL_1_16_5: i32 = 754;
pub const PROTOCOL_1_17: i32 = 755;
pub const PROTOCOL_1_17_1: i32 = 756;
pub const PROTOCOL_1_18: i32 = 757;
pub const PROTOCOL_1_18_2: i32 = 758;
pub const PROTOCOL_1_19: i32 = 759;
pub const PROTOCOL_1_19_2: i32 = 760;
pub const PROTOCOL_1_19_3: i32 = 761;
pub const PROTOCOL_1_19_4: i32 = 762;
pub const PROTOCOL_1_20: i32 = 763;
pub const PROTOCOL_1_20_2: i32 = 764;
pub const PROTOCOL_1_20_4: i32 = 765;
pub const PROTOCOL_1_20_5: i32 = 766;
pub const PROTOCOL_1_21: i32 = 767;
pub const PROTOCOL_1_21_2: i32 = 768;
pub const PROTOCOL_1_21_4: i32 = 769;
pub const PROTOCOL_1_21_5: i32 = 770;
pub const PROTOCOL_1_21_6: i32 = 771;
pub const PROTOCOL_1_21_7: i32 = 772;
pub const PROTOCOL_1_21_9: i32 = 773;
pub const PROTOCOL_1_21_11: i32 = 774;
pub const PROTOCOL_26_1: i32 = 775;
pub const PROTOCOL_26_2: i32 = 776;
pub const PROTOCOL_26_3: i32 = 777; // planned release 26.3 (2026)

pub fn is_supported(protocol: i32) -> bool {
    protocol >= MIN_PROTOCOL && protocol <= MAX_PROTOCOL
}

pub fn version_name(protocol: i32) -> &'static str {
    match protocol {
        754 => "1.16.5",
        755 => "1.17",
        756 => "1.17.1",
        757 => "1.18",
        758 => "1.18.2",
        759 => "1.19",
        760 => "1.19.2",
        761 => "1.19.3",
        762 => "1.19.4",
        763 => "1.20",
        764 => "1.20.2",
        765 => "1.20.4",
        766 => "1.20.5",
        767 => "1.21",
        768 => "1.21.2",
        769 => "1.21.4",
        770 => "1.21.5",
        771 => "1.21.6",
        772 => "1.21.7",
        773 => "1.21.9",
        774 => "1.21.11",
        775 => "26.1",
        776 => "26.2",
        777 => "26.3",
        _ => "unknown",
    }
}

pub fn all_supported() -> &'static [i32] {
    &[
        754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772,
        773, 774, 775, 776, 777,
    ]
}
