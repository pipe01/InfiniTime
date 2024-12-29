#!/bin/bash
set -e

BIN=/opt/gcc-arm-none-eabi-10.3-2021.10/bin/arm-none-eabi

ARGS="$ARGS plugin.cpp ../build/src/map.ld"
ARGS="$ARGS -shared"
ARGS="$ARGS -o plugin.so"

ARGS="$ARGS -mthumb"
ARGS="$ARGS -mabi=aapcs"
ARGS="$ARGS -mcpu=cortex-m4"
ARGS="$ARGS -mfloat-abi=hard"
ARGS="$ARGS -mfpu=fpv4-sp-d16"
ARGS="$ARGS -fstack-usage"
ARGS="$ARGS -fno-exceptions"
ARGS="$ARGS -fno-non-call-exceptions"

ARGS="$ARGS -fno-rtti"
ARGS="$ARGS -nostdlib"

ARGS="$ARGS -fpic"
ARGS="$ARGS -msingle-pic-base"
ARGS="$ARGS -mpic-register=r9"

ARGS="$ARGS -Wl,-Tplugin.ld"
ARGS="$ARGS -Wl,--no-undefined"
ARGS="$ARGS $@"

$BIN-gcc $ARGS
$BIN-readelf -a plugin.so > plugin.readelf
nm plugin.so > plugin.so.nm

$BIN-objcopy -O binary plugin.so plugin.bin
python plugin.py plugin.so plugin.bin

$BIN-objdump -CD --visualize-jumps plugin.so > plugin.so.dis
$BIN-objdump -CDb binary -marm plugin.bin -Mforce-thumb > plugin.bin.dis

stat -t plugin.so plugin.bin
