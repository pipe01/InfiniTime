import argparse
import struct
import lief

MEM_BASE = 0x20000000

argparser = argparse.ArgumentParser()
argparser.add_argument("input", help="Input file")
argparser.add_argument("output", help="Output file")

args = argparser.parse_args()

binary = lief.parse(args.input)

got_section = [s for s in binary.sections if s.name == ".got"][0]
got_entry_count = got_section.size // 4

print(f"Found .got section with {got_entry_count} entries")
print(f"Binary has {len(binary.relocations)} relocation entries")

if got_entry_count <= len(binary.relocations):
    print("ERROR: Not enough .got entries for all relocations")
    exit(1)

remaining_rels = [a * 4 for a in range(got_entry_count)]

with open(args.output, "rb") as f:
    original_got = f.read(got_section.size)

with open(args.output, "r+b") as f:
    for rel in binary.relocations:
        if rel.symbol.value == 0:
            print(f"WARN: Symbol {rel.symbol.name} is undefined")

        rel_location = rel.address
        rel_target = rel.symbol.value

        is_mem = rel_location >= MEM_BASE

        if not is_mem:
            if rel_location not in remaining_rels:
                print(f"Skipping {rel.symbol.name} because it's already relocated")
                continue

            remaining_rels.remove(rel_location)

        print(f"Relocate {rel.symbol.name}: 0x{rel_location:x} => 0x{rel_target:x}")

        f.write(struct.pack("<II", rel_location, rel_target))

    for rel_location in remaining_rels:
        rel_target = struct.unpack("<I", original_got[rel_location:rel_location + 4])[0]
        print(f"Relocate at 0x{rel_location:x}: 0x{rel_location:x} => 0x{rel_target}")

        f.write(struct.pack("<II", rel_location, rel_target))
