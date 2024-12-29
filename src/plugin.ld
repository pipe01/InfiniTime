ENTRY(run)

MEMORY {
  rom (rx)   : ORIGIN = 0, LENGTH = 0x1000
  ram (rw!x) : ORIGIN = 0x20000000, LENGTH = 0x1000
}

SECTIONS {
  .got : {
    got_start = .;
    *(.got);
    got_plt_start = .;
    *(.got.plt);
    got_end = .;
  } > rom

  .got.pad : {
    FILL(0xAA);

    /* Each GOT entry originally takes 1 word but our loader format needs 2 words per entry, so we reserve enough space */
    . += got_end - got_start;
  } > rom

  .init : {
    LONG(0xFFFFFFFF);
    *(.init);
  } > rom

  .text : {
    *(.text);
    *(.text.*);
  } > rom

  .plt : {
    *(.plt);
  } > rom

  .rodata : {
    *(.rodata);
    *(.rodata.*);
  } > rom

  .bss : {
    *(.bss);
    *(.bss.*);
  } > ram

  .data : {
    *(.data);
    *(.data.*);
  } > ram AT> rom
}

bss_start = ADDR(.bss);
bss_end = bss_start + SIZEOF(.bss);

data_start = ADDR(.data);
data_end = data_start + SIZEOF(.data);

rom_data_start = LOADADDR(.data);

ram_size = SIZEOF(.bss) + SIZEOF(.data);
