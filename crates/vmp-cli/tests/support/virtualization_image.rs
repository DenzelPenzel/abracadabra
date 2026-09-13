use vmp_pe::PeFile;

pub fn image(target: u32) -> Vec<u8> {
    let mut bytes = vec![0; 0x400];
    for (at, value) in [
        (0, 0x5a4d_u16),
        (0x44, 0x8664),
        (0x46, 1),
        (0x54, 240),
        (0x58, 0x20b),
        (0x9c, 3),
    ] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [
        (0x3c, 0x40_u32),
        (0x40, 0x4550),
        (0x68, 0x1010),
        (0x78, 0x1000),
        (0x7c, 0x200),
        (0x90, 0x2000),
        (0x94, 0x200),
        (0xc4, 16),
        (0x150, 0x200),
        (0x154, 0x1000),
        (0x158, 0x200),
        (0x15c, 0x200),
        (0x16c, 0x6000_0020),
    ] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x70..0x78].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    bytes[0x148..0x14d].copy_from_slice(b".text");
    bytes[0x200..0x207].copy_from_slice(&[0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0xc3]);
    bytes[0x210] = 0xe8;
    bytes[0x211..0x215].copy_from_slice(&(i64::from(target) - 0x1015).to_le_bytes()[..4]);
    bytes[0x215] = 0xc3;
    bytes[0xf0..0xf4].copy_from_slice(&0x1040_u32.to_le_bytes());
    bytes[0xf4..0xf8].copy_from_slice(&12_u32.to_le_bytes());
    bytes[0x240..0x244].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[0x244..0x248].copy_from_slice(&12_u32.to_le_bytes());
    bytes[0x248..0x24a].copy_from_slice(&0xa060_u16.to_le_bytes());
    bytes[0x260..0x268].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    PeFile::parse(&bytes).expect("synthetic PE");
    bytes
}
