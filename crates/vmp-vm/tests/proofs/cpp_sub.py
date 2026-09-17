"""Capture a bounded SUB lowering trace from verbatim C++ source fragments.

This is not the full legacy compiler or a PE execution proof. The operand adapter
accepts qword GPRs only, the row sink records AddVMCommand arguments, and rand()
selects the existing all-NOR branches. No source under core/ is modified.
"""
import argparse
import hashlib
from pathlib import Path
import subprocess

if not __debug__:
    raise RuntimeError('proof requires assertions')

ROOT = Path(__file__).resolve().parents[4]


def between(text, start, end):
    assert text.count(start) == 1, start
    suffix = text.split(start, 1)[1]
    return start + suffix.split(end, 1)[0]


def capture(source, out):
    raw = source.read_bytes()
    text = raw.decode().replace('\r\n', '\n')
    sub = between(text, '\tcase cmSub: case cmCmp:\n\t\tCompileOperand', '\n\tcase cmInc:')
    register = between(text, '\tcase otRegistr:\n\t\tif (options & coSaveResult)', '\n\tcase otValue:')
    inverse = between(text, '\tif (options & coInverse) {', '\n}\n\nvoid IntelCommand::CompileToVM')
    mask = between(text, 'void IntelCommand::AddRegistrAndValueSection(', '\nvoid IntelCommand::AddRegistrOrValueSection(')
    combine = between(text, 'void IntelCommand::AddCombineFlagsSection(', '\nvoid IntelCommand::AddCorrectFlagSection(')
    discard = between(text, '\tbool need_popf = false;\n', '\n\tIntelVMCommand *vm_command = NULL;')
    fragments = '\n'.join((sub, register, inverse, mask, combine, discard))
    header = r'''
#include <cassert>
#include <cstdint>
#include <iostream>
#define rand() 1
struct CompileContext {};
enum Type { cmPush, cmPop, cmAdd, cmNor, cmNand, cmShr, cmShl, cmSub, cmCmp };
enum OperandType { otNone, otRegistr, otMemory, otValue, otHiPartRegistr };
enum OperandSize { osByte, osWord, osDWord, osQWord };
enum { regEAX, regECX, regEDX, regESP = 4, regEFX = 16, regEIX = 17, regEmpty = 255, segSS = 2 };
enum { coSaveResult = 1, coInverse = 2 };
constexpr uint16_t fl_P = 4, fl_O = 0x800, fl_A = 16, fl_C = 1;
struct IntelOperand { OperandType type; OperandSize size; uint8_t registr; };
using IntelCommandType = Type;
struct IntelCommand {
    OperandSize size_ = osQWord;
    Type type_ = cmSub;
    IntelOperand operands[2] = {{otRegistr, osQWord, regEAX}, {otRegistr, osQWord, regEDX}};
    void AddVMCommand(const CompileContext&, Type, OperandType, OperandSize, uint64_t);
    void CompileOperand(const CompileContext&, size_t, uint32_t = 0);
    void AddRegistrAndValueSection(const CompileContext&, uint8_t, OperandSize, uint64_t, bool = false);
    void AddCombineFlagsSection(const CompileContext&, uint16_t);
    void AddCorrectOperandSizeSection(const CompileContext&, OperandSize, OperandSize) { assert(false); }
    void AddStoreExtRegistrSection(const CompileContext&, uint8_t r) { assert(r == regEAX); }
    void AddCorrectESPSection(const CompileContext&, OperandSize, int) { assert(false); }
    void CompileToVM(const CompileContext&);
};
'''
    sink = r'''
    static const char* names[] = {"push", "pop", "add", "nor", "nand", "shr", "shl", "sub", "cmp"};
    static const char* operands[] = {"none", "reg", "mem", "imm", "hi"};
    std::cout << names[command_type] << ' ' << operands[operand_type] << ' '
              << (1u << operand_size) << ' ' << value << '\n';
    if (need_popf) AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty);
'''
    generated = header + '''
void IntelCommand::AddVMCommand(const CompileContext &ctx, Type command_type,
    OperandType operand_type, OperandSize operand_size, uint64_t value) {
''' + discard + sink + '''
}
void IntelCommand::CompileOperand(const CompileContext &ctx, size_t operand_index, uint32_t options) {
    IntelOperand *operand = &operands[operand_index];
    OperandSize operand_size = operand->size;
    switch (operand->type) {
''' + register + '''
    default: assert(false);
    }
''' + inverse + '''
}
''' + mask + combine + '''
void IntelCommand::CompileToVM(const CompileContext &ctx) {
    bool save_flags = true;
    OperandSize os;
    IntelOperand *operand_ = operands;
    switch (type_) {
''' + sub + '''
    default: assert(false);
    }
}
int main() { IntelCommand command; command.CompileToVM(CompileContext{}); }
'''
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'capture.cc'
    cpp.write_text(generated)
    executable = out / 'capture'
    subprocess.run(['clang++', '-std=c++11', '-Wall', '-Wextra', '-Werror', str(cpp), '-o', str(executable)], check=True)
    trace = subprocess.check_output([str(executable)], text=True)
    (out / 'trace.txt').write_text(trace)
    (out / 'provenance.txt').write_text(
        f'source={source.resolve()}\nsource_sha256={hashlib.sha256(raw).hexdigest()}\n'
        f'fragments_sha256={hashlib.sha256(fragments.encode()).hexdigest()}\n'
        'boundary=qword GPR SUB RAX,RDX; save_flags; all-NOR branch choices\n'
        'adapters=bounded GPR operand adapter; AddVMCommand argument sink; no PE compiler\n')
    return trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT.parent / 'core/intel.cc')
    parser.add_argument('--out', type=Path, default=ROOT / 'target/cpp-sub-proof')
    parser.add_argument('--check', type=Path)
    args = parser.parse_args()
    trace = capture(args.source, args.out)
    if args.check:
        assert trace == args.check.read_text(), 'C++ lowering fixture differs'
    print(trace, end='')
    print(f'PASS: {len(trace.splitlines())} C++ lowering commands')


if __name__ == '__main__':
    main()
