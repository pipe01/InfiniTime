import argparse
import struct
import lief

MEM_BASE = 0x20000000

argparser = argparse.ArgumentParser()
argparser.add_argument("input", help="Input file")
argparser.add_argument("output", help="Output file")

args = argparser.parse_args()

binary = lief.parse(args.input)
with open(args.output, "r+b") as f:
    for rel in binary.relocations:
        if rel.symbol.value == 0:
            print(f"ERROR: Symbol {rel.symbol.name} is undefined")
            continue

        if rel.address >= MEM_BASE:
            print(f"ERROR: Relocation {rel.symbol.name} at 0x{rel.address:x} is out of range")
            continue

        sym_offset = rel.symbol.value
        got_offset = rel.address

        print(f"Relocate {rel.symbol.name} at: 0x{got_offset:x}, offset: 0x{sym_offset:x}")

        f.seek(got_offset)
        f.write(struct.pack("<I", sym_offset))
