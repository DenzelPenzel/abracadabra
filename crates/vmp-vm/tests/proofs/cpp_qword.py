"""Capture a qword cryptor recipe and KATs by compiling original C++ methods.

The deterministic RNG selects DEC, NOT, ROR(17), INC through ValueCryptor::Init.
Container/intrinsic adapters are bounded proof scaffolding, not a full compiler.
"""
import argparse
import hashlib
from pathlib import Path
import subprocess
from cpp_sub import ROOT, between


def capture(core, out):
    source = (core / 'processors.cc').read_text()
    header = (core / 'processors.h').read_text()
    enum = between(header, 'enum CryptCommandType : uint8_t {', '\n\nclass ValueCryptor;')
    value = between(source, 'CryptCommandType ValueCommand::type(', '\n/**\n * ValueCryptor')
    cryptor = between(source, 'uint64_t ValueCryptor::Encrypt(', '\nvoid ValueCryptor::Add(')
    opcode = between(source, 'void OpcodeCryptor::Init(', '\n/**\n * CommandLink')
    prelude = r'''
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>
enum OperandSize { osByte, osWord, osDWord, osQWord };
static unsigned OperandSizeToValue(OperandSize size) { return 1u << size; }
#define BYTES_TO_BITS(n) ((n) * 8)
static uint64_t DWordToInt64(uint32_t n) { return static_cast<int64_t>(static_cast<int32_t>(n)); }
static uint32_t rand32() { assert(false); return 0; }
template<class T> T rotl(T v, int n) { const int bits = sizeof(T)*8; n %= bits; return n ? static_cast<T>((uint64_t(v) << n) | (uint64_t(v) >> (bits-n))) : v; }
template<class T> T rotr(T v, int n) { const int bits = sizeof(T)*8; n %= bits; return n ? static_cast<T>((uint64_t(v) >> n) | (uint64_t(v) << (bits-n))) : v; }
#define _rotl8 rotl<uint8_t>
#define _rotl16 rotl<uint16_t>
#define _rotl32 rotl<uint32_t>
#define _rotl64 rotl<uint64_t>
#define _rotr8 rotr<uint8_t>
#define _rotr16 rotr<uint16_t>
#define _rotr32 rotr<uint32_t>
#define _rotr64 rotr<uint64_t>
'''
    adapters = r'''
static int proof_rand() {
    static const int choices[] = {ccDec, ccNot, ccRor, 17, ccInc, 1};
    static size_t index = 0;
    assert(index < sizeof(choices)/sizeof(*choices));
    return choices[index++];
}
#define rand proof_rand
struct ValueCommand {
    CryptCommandType type_; OperandSize size_; uint64_t value_;
    CryptCommandType type(bool is_decrypt = false) const;
    uint64_t Encrypt(uint64_t); uint64_t Decrypt(uint64_t); uint64_t Calc(uint64_t, bool);
};
struct ValueCryptor {
    OperandSize size_; std::vector<ValueCommand> rows;
    void clear() { rows.clear(); }
    size_t count() const { return rows.size(); }
    ValueCommand* item(size_t i) { return &rows.at(i); }
    void Add(CryptCommandType command, uint64_t value) { rows.push_back({command, size_, value}); }
    void Init(OperandSize);
    uint64_t Encrypt(uint64_t); uint64_t Decrypt(uint64_t);
};
struct OpcodeCryptor : ValueCryptor {
    CryptCommandType type_;
    void Init(OperandSize);
    uint64_t EncryptOpcode(uint64_t, uint64_t); uint64_t DecryptOpcode(uint64_t, uint64_t);
    uint64_t Calc(uint64_t, uint64_t, bool);
};
'''
    main = r'''
int main() {
    OpcodeCryptor cryptor;
    cryptor.Init(osQWord);
    assert(cryptor.size_ == osQWord && cryptor.type_ == ccXor && cryptor.count() == 4);
    std::cout << "#";
    for (const auto& step : cryptor.rows) std::cout << ' ' << unsigned(step.type_) << ':' << step.value_;
    std::cout << '\n' << std::hex;
    for (uint64_t initial : {UINT64_C(0x14000307f), UINT64_C(0xfedcba9876543210)}) {
        uint64_t key = initial;
        for (uint64_t plain : {UINT64_C(0), UINT64_C(0x815), ~UINT64_C(0x815), UINT64_MAX, UINT64_C(0x8000000000000000)}) {
            uint64_t before = key;
            uint64_t cipher = cryptor.DecryptOpcode(cryptor.Decrypt(plain), key);
            key = cryptor.EncryptOpcode(key, plain);
            uint64_t decoded = cryptor.Encrypt(cryptor.DecryptOpcode(cipher, before));
            assert(decoded == plain);
            std::cout << plain << ' ' << cipher << ' ' << before << ' ' << key << '\n';
        }
    }
}
'''
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'qword.cc'
    cpp.write_text(prelude + enum + adapters + value + cryptor + opcode + main)
    executable = out / 'qword'
    # The unchanged C++ intentionally uses non-exhaustive switches for inverse operations
    subprocess.run(['clang++', '-std=c++11', '-Wall', '-Wextra', '-Werror', '-Wno-switch', str(cpp), '-o', str(executable)], check=True)
    trace = subprocess.check_output([str(executable)], text=True)
    (out / 'trace.txt').write_text(trace)
    (out / 'provenance.txt').write_text(''.join(
        f'{name} sha256={hashlib.sha256((core / name).read_bytes()).hexdigest()}\n'
        for name in ('processors.cc', 'processors.h')))
    return trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, default=ROOT.parent / 'core')
    parser.add_argument('--out', type=Path, default=ROOT / 'target/cpp-qword-proof')
    parser.add_argument('--check', type=Path)
    args = parser.parse_args()
    trace = capture(args.core, args.out)
    if args.check:
        assert args.check.read_text() == trace, 'C++ qword cryptor fixture differs'
    print(trace, end='')


if __name__ == '__main__':
    main()
