// $BIN-gcc -shared -fPIC plugin.cpp ../build/src/map.ld -o plugin.so -mthumb -mabi=aapcs -ftree-vrp -fno-strict-aliasing -fno-builtin
// -fshort-enums -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16 -fstack-usage -fno-exceptions -fno-non-call-exceptions -nostdlib
// -Wl,--verbose $BIN-objcopy -O binary plugin.so plugin.bin $BIN-objdump -d plugin.so > plugin.so.dis $BIN-objdump -D -b binary -marm
// plugin.bin -Mforce-thumb > plugin.bin.dis cp pinetime-app-1.15.0.bin flash.bin && truncate flash.bin --size 131072 && cat flash.bin
// ../../src/plugin.bin > flash_plugged.bin $BIN-gcc -shared -fpic plugin.cpp ../build/src/map.ld -o plugin.so -mthumb -mabi=aapcs
// -ftree-vrp -fno-strict-aliasing -fno-builtin -fshort-enums -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16 -fstack-usage
// -fno-exceptions -fno-non-call-exceptions -nostdlib -Wl,-Tplugin.ld && $BIN-objcopy -O binary plugin.so plugin.bin && $BIN-objdump -CD
// --visualize-jumps plugin.so > plugin.so.dis && $BIN-objdump -DCb binary -marm plugin.bin -Mforce-thumb > plugin.bin.dis && $BIN-readelf
// -a plugin.so > plugin.readelf && stat plugin.so plugin.bin && nm plugin.so > plugin.so.nm

#include "main_plugin.h"
#include <stdlib.h>
#include <stdint.h>
#include <typeinfo>

// uint8_t data[0x100];

class MyPlugin : public Plugin {
public:
  int Run() override {
    int n = 1;
    n += constant;
    n += constant;
    n += constant;
    n += constant;
    n += constant;
    n += constant;
    n += constant;
    n += constant;
    n += constant;
    return n;
    // Do something
  }
};

// ====================
extern uint8_t bss_start[];
extern uint8_t bss_end[];
extern uint8_t data_start[];
extern uint8_t data_end[];
extern uint8_t rom_data_start[];

#define ENTRYPOINT __attribute__((always_inline)) inline Plugin* Create()
ENTRYPOINT;

uint8_t myvar;
uint8_t myvar2;

extern "C" void __cxa_pure_virtual() {
  while (1)
    ;
}

// This function will be stored at 0x00 on the plugin binary
__attribute__((section(".init"))) void* _start() {
  // myvar = 0xAABB;
  // myvar2 = 0xCCDD;
  // constant = 0xAA;
  // bss_start[0] = 0xAA;
  // bss_end[0] = 0xBB;

  // // memset(bss_start, 0, bss_end - bss_start);
  // for (uint32_t i = (uint32_t) bss_start; i < (uint32_t) bss_end; i++) {
  //   *(uint8_t*) i = 0;
  // }

  // // memcpy(data_start, rom_data_start, data_end - data_start);
  // for (uint8_t *i = data_start, *j = rom_data_start; i < data_end; i++, j++) {
  //   *(uint8_t*) i = *(uint8_t*) j;
  // }

  // return new int;
  // return Create();
  return (void *)(two() * three() * myvar);
}

// ====================

ENTRYPOINT {
  // return static_cast<Plugin*>(malloc(0x123));
  return new MyPlugin();
}
