#[derive(Debug, Clone, Copy)]
enum Step {
    Ror(u8),
    Not,
    Xor(u8),
    Sub(u8),
    Add(u8),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ByteCryptor([Step; 4]);

impl ByteCryptor {
    pub(super) fn encode(self, plain: u8, key: &mut u64) -> u8 {
        let mut value = plain;
        for step in self.0.into_iter().rev() {
            value = match step {
                Step::Ror(n) => value.rotate_left(u32::from(n)),
                Step::Not => !value,
                Step::Xor(n) => value ^ n,
                Step::Sub(n) => value.wrapping_add(n),
                Step::Add(n) => value.wrapping_sub(n),
            };
        }
        value ^= *key as u8;
        *key ^= u64::from(plain);
        value
    }

    pub(super) fn emit(self, image: &mut Vec<u8>) {
        image.extend_from_slice(&[0x40, 0x30, 0xfa]); // xor dl, dil
        for step in self.0 {
            match step {
                Step::Ror(n) => image.extend_from_slice(&[0xc0, 0xca, n]),
                Step::Not => image.extend_from_slice(&[0xf6, 0xd2]),
                Step::Xor(n) => image.extend_from_slice(&[0x80, 0xf2, n]),
                Step::Sub(n) => image.extend_from_slice(&[0x80, 0xea, n]),
                Step::Add(n) => image.extend_from_slice(&[0x80, 0xc2, n]),
            }
        }
        image.extend_from_slice(&[0x40, 0x30, 0xd7]); // xor dil, dl
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Cryptors {
    pub opcode: ByteCryptor,
    pub operand: ByteCryptor,
}

impl Cryptors {
    pub(super) fn captured_classic() -> Self {
        Self {
            opcode: ByteCryptor([Step::Ror(4), Step::Not, Step::Ror(7), Step::Xor(0x1b)]),
            operand: ByteCryptor([Step::Sub(1), Step::Not, Step::Ror(1), Step::Add(1)]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cryptors;

    #[test]
    fn captured_cpp_fields_pin_ciphertext_and_full_key() {
        // Classic cryptors trace fields at 0x14000307f through 0x140003082
        let c = Cryptors::captured_classic();
        let mut key = 0x14000307f;
        for (cryptor, plain, cipher, after) in [
            (c.opcode, 0x32, 0xc9, 0x14000304d),
            (c.operand, 0x28, 0xff, 0x140003065),
            (c.opcode, 0x4c, 0x20, 0x140003029),
            (c.operand, 0x58, 0x7b, 0x140003071),
        ] {
            assert_eq!(cryptor.encode(plain, &mut key), cipher);
            assert_eq!(key, after);
        }
    }
}
