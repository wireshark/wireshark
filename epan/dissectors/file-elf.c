/* file-elf.c
 * Routines for Executable and Linkable Format
 * Based on: SYSTEM V APPLICATION BINARY INTERFACE Edition 4.1
 * http://www.sco.com/developers/devspecs/
 * http://www.sco.com/developers/gabi/latest/contents.html
 * http://refspecs.linuxfoundation.org/
 * http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
 * http://dwarfstd.org/doc/DWARF4.pdf
 * http://www.sco.com/developers/devspecs/
 *
 * Copyright 2013, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "dwarf.h"

static dissector_handle_t elf_handle;

static int proto_elf = -1;

static int hf_elf_magic_bytes = -1;
static int hf_elf_file_size = -1;
static int hf_elf_header_segment_size = -1;
static int hf_elf_blackholes_size = -1;
static int hf_elf_blackhole_size = -1;
static int hf_elf_overlapping_size = -1;
static int hf_elf_segment = -1;
static int hf_elf_entry_bytes = -1;
static int hf_elf_file_class = -1;
static int hf_elf_data_encoding = -1;
static int hf_elf_file_version = -1;
static int hf_elf_os_abi = -1;
static int hf_elf_abi_version = -1;
static int hf_elf_file_padding = -1;
static int hf_elf_type = -1;
static int hf_elf_machine = -1;
static int hf_elf_version = -1;
static int hf_elf_entry = -1;
static int hf_elf_phoff = -1;
static int hf_elf_shoff = -1;
static int hf_elf64_entry = -1;
static int hf_elf64_phoff = -1;
static int hf_elf64_shoff = -1;
static int hf_elf_flags = -1;
static int hf_elf_ehsize = -1;
static int hf_elf_phentsize = -1;
static int hf_elf_phnum = -1;
static int hf_elf_shentsize = -1;
static int hf_elf_shnum = -1;
static int hf_elf_shstrndx = -1;
static int hf_elf_p_type = -1;
static int hf_elf_p_type_operating_system_specific = -1;
static int hf_elf_p_type_processor_specific = -1;
static int hf_elf_p_flags_execute = -1;
static int hf_elf_p_flags_write = -1;
static int hf_elf_p_flags_read = -1;
static int hf_elf_p_flags_reserved = -1;
static int hf_elf_p_flags_operating_system_specific = -1;
static int hf_elf_p_flags_processor_specific = -1;
static int hf_elf_p_offset = -1;
static int hf_elf64_p_offset = -1;
static int hf_elf_p_vaddr = -1;
static int hf_elf64_p_vaddr = -1;
static int hf_elf_p_paddr = -1;
static int hf_elf64_p_paddr = -1;
static int hf_elf_p_filesz = -1;
static int hf_elf64_p_filesz = -1;
static int hf_elf_p_memsz = -1;
static int hf_elf64_p_memsz = -1;
static int hf_elf_p_align = -1;
static int hf_elf64_p_align = -1;

static int hf_elf_sh_name = -1;
static int hf_elf_sh_type_user_specific = -1;
static int hf_elf_sh_type_operating_system_specific = -1;
static int hf_elf_sh_type_processor_specific = -1;
static int hf_elf_sh_type = -1;

static int hf_elf_sh_flags_processor_specific = -1;
static int hf_elf_sh_flags_operating_system_specific = -1;
static int hf_elf_sh_flags_reserved = -1;
static int hf_elf_sh_flags_tls = -1;
static int hf_elf_sh_flags_group = -1;
static int hf_elf_sh_flags_os_nonconforming = -1;
static int hf_elf_sh_flags_link_order = -1;
static int hf_elf_sh_flags_info_link = -1;
static int hf_elf_sh_flags_strings = -1;
static int hf_elf_sh_flags_merge = -1;
static int hf_elf_sh_flags_reserved_8 = -1;
static int hf_elf_sh_flags_exec_instr = -1;
static int hf_elf_sh_flags_alloc = -1;
static int hf_elf_sh_flags_write = -1;
static int hf_elf_sh_addr = -1;
static int hf_elf64_sh_addr = -1;

static int hf_elf_sh_offset = -1;
static int hf_elf64_sh_offset = -1;
static int hf_elf_sh_size = -1;
static int hf_elf64_sh_size = -1;
static int hf_elf_sh_link = -1;
static int hf_elf_sh_info = -1;
static int hf_elf_sh_addralign = -1;
static int hf_elf64_sh_addralign = -1;
static int hf_elf_sh_entsize = -1;
static int hf_elf64_sh_entsize = -1;

static int hf_elf_eh_frame_length = -1;
static int hf_elf_eh_frame_extended_length = -1;
static int hf_elf_eh_frame_cie_id = -1;
static int hf_elf_eh_frame_version = -1;
static int hf_elf_eh_frame_augmentation_string = -1;
static int hf_elf_eh_frame_code_alignment_factor = -1;
static int hf_elf_eh_frame_data_alignment_factor = -1;
static int hf_elf_eh_frame_return_address_register = -1;
static int hf_elf_eh_frame_augmentation_length = -1;
static int hf_elf_eh_frame_augmentation_data = -1;
static int hf_elf_eh_frame_initial_instructions = -1;

static int hf_elf_eh_frame_fde_length = -1;
static int hf_elf_eh_frame_fde_extended_length = -1;
static int hf_elf_eh_frame_fde_cie_pointer = -1;
static int hf_elf_eh_frame_fde_pc_begin = -1;
static int hf_elf_eh_frame_fde_pc_range = -1;
static int hf_elf_eh_frame_fde_augmentation_length = -1;
static int hf_elf_eh_frame_fde_augmentation_data = -1;
static int hf_elf_eh_frame_fde_call_frame_instructions = -1;

static int hf_elf_eh_frame_hdr_version = -1;
static int hf_elf_eh_frame_hdr_exception_frame_pointer_encoding = -1;
static int hf_elf_eh_frame_hdr_fde_count_encoding = -1;
static int hf_elf_eh_frame_hdr_binary_search_table_encoding = -1;
static int hf_elf_eh_frame_hdr_eh_frame_ptr = -1;
static int hf_elf_eh_frame_hdr_fde_count = -1;
static int hf_elf_eh_frame_hdr_binary_search_table_entry_initial_location = -1;
static int hf_elf_eh_frame_hdr_binary_search_table_entry_address = -1;

static int hf_elf_symbol_table_name_index = -1;
static int hf_elf_symbol_table_value = -1;
static int hf_elf64_symbol_table_value = -1;
static int hf_elf_symbol_table_size = -1;
static int hf_elf64_symbol_table_size = -1;
static int hf_elf_symbol_table_info = -1;
static int hf_elf_symbol_table_info_bind = -1;
static int hf_elf_symbol_table_info_type = -1;
static int hf_elf_symbol_table_other = -1;
static int hf_elf_symbol_table_shndx = -1;

static int hf_elf_dynamic_tag = -1;
static int hf_elf_dynamic_value = -1;
static int hf_elf_dynamic_pointer = -1;
static int hf_elf_dynamic_ignored = -1;
static int hf_elf_dynamic_unspecified = -1;
static int hf_elf64_dynamic_tag = -1;
static int hf_elf64_dynamic_value = -1;
static int hf_elf64_dynamic_pointer = -1;
static int hf_elf64_dynamic_ignored = -1;
static int hf_elf64_dynamic_unspecified = -1;

static int hf_elf_string = -1;

static int hf_dwarf_omit = -1;
static int hf_dwarf_upper = -1;
static int hf_dwarf_format = -1;

static expert_field ei_invalid_segment_size                           = EI_INIT;
static expert_field ei_invalid_entry_size                             = EI_INIT;
static expert_field ei_cfi_extraneous_data                            = EI_INIT;
static expert_field ei_invalid_cie_length                             = EI_INIT;

static gint ett_elf = -1;
static gint ett_elf_header = -1;
static gint ett_elf_program_header = -1;
static gint ett_elf_program_header_entry = -1;
static gint ett_elf_section_header = -1;
static gint ett_elf_section_header_entry = -1;
static gint ett_elf_segment = -1;
static gint ett_elf_cfi_record = -1;
static gint ett_elf_cie_entry = -1;
static gint ett_elf_fde_entry = -1;
static gint ett_elf_cie_terminator = -1;
static gint ett_elf_info = -1;
static gint ett_elf_black_holes = -1;
static gint ett_elf_overlapping = -1;
static gint ett_dwarf_encoding = -1;
static gint ett_binary_table = -1;
static gint ett_binary_table_entry = -1;
static gint ett_symbol_table_entry = -1;
static gint ett_symbol_table_info = -1;

#define REGISTER_32_SIZE  4
#define REGISTER_64_SIZE  8

static const value_string class_vals[] = {
    { 0x00,  "Invalid class" },
    { 0x01,  "32-bit object" },
    { 0x02,  "64-bit object" },
    { 0, NULL }
};

static const value_string data_encoding_vals[] = {
    { 0x00,  "None" },
    { 0x01,  "Least Significant Bit" },
    { 0x02,  "Most Significant Bit " },
    { 0, NULL }
};

static const value_string version_vals[] = {
    { 0x00,  "None" },
    { 0x01,  "Current" },
    { 0, NULL }
};

static const value_string type_vals[] = {
    { 0x0000,  "No file type" },
    { 0x0001,  "Relocatable file" },
    { 0x0002,  "Executable file" },
    { 0x0003,  "Shared object file" },
    { 0x0004,  "Core file" },
    { 0xFE00,  "Operating system-specific Lo" }, /* From Draft */
    { 0xFEFF,  "Operating system-specific Hi" }, /* From Draft */
    { 0xFF00,  "Processor Specific Lo" },
    { 0xFFFF,  "Processor Specific Hi" },
    { 0, NULL }
};

static const value_string machine_vals[] = {
    {   0,  "No machine" },
    {   1,  "AT&T WE 32100" },
    {   2,  "SPARC" },
    {   3,  "Intel 80386" },
    {   4,  "Motorola 68000" },
    {   5,  "Motorola 88000" },
    {   7,  "Intel 80860" },
    /* From Draft */
    {   8,  "MIPS I Architecture" },
    {   9,  "IBM System/370 Processor" },
    {  10,  "MIPS RS3000 Little-endian" },
    {  15,  "Hewlett-Packard PA-RISC" },
    {  17,  "Fujitsu VPP500" },
    {  18,  "Enhanced instruction set SPARC" },
    {  19,  "Intel 80960" },
    {  20,  "PowerPC" },
    {  21,  "64-bit PowerPC" },
    {  22,  "IBM System/390 Processor" },
    {  23,  "IBM SPU/SPC" },
    {  36,  "NEC V800" },
    {  37,  "Fujitsu FR20" },
    {  38,  "TRW RH-32" },
    {  39,  "Motorola RCE" },
    {  40,  "ARM 32-bit architecture (AARCH32)" },
    {  41,  "Digital Alpha" },
    {  42,  "Hitachi SH" },
    {  43,  "SPARC Version 9" },
    {  44,  "Siemens TriCore embedded processor" },
    {  45,  "Argonaut RISC Core, Argonaut Technologies Inc." },
    {  46,  "Hitachi H8/300" },
    {  47,  "Hitachi H8/300H" },
    {  48,  "Hitachi H8S" },
    {  49,  "Hitachi H8/500" },
    {  50,  "Intel IA-64 processor architecture" },
    {  51,  "Stanford MIPS-X" },
    {  52,  "Motorola ColdFire" },
    {  53,  "Motorola M68HC12" },
    {  54,  "Fujitsu MMA Multimedia Accelerator" },
    {  55,  "Siemens PCP" },
    {  56,  "Sony nCPU embedded RISC processor" },
    {  57,  "Denso NDR1 microprocessor" },
    {  58,  "Motorola Star*Core processor" },
    {  59,  "Toyota ME16 processor" },
    {  60,  "STMicroelectronics ST100 processor" },
    {  61,  "Advanced Logic Corp. TinyJ embedded processor family" },
    {  62,  "AMD x86-64 architecture" },
    {  63,  "Sony DSP Processor" },
    {  64,  "Digital Equipment Corp. PDP-10" },
    {  65,  "Digital Equipment Corp. PDP-11" },
    {  66,  "Siemens FX66 microcontroller" },
    {  67,  "STMicroelectronics ST9+ 8/16 bit microcontroller" },
    {  68,  "STMicroelectronics ST7 8-bit microcontroller" },
    {  69,  "Motorola MC68HC16 Microcontroller" },
    {  70,  "Motorola MC68HC11 Microcontroller" },
    {  71,  "Motorola MC68HC08 Microcontroller" },
    {  72,  "Motorola MC68HC05 Microcontroller" },
    {  73,  "Silicon Graphics SVx" },
    {  74,  "STMicroelectronics ST19 8-bit microcontroller" },
    {  75,  "Digital VAX" },
    {  76,  "Axis Communications 32-bit embedded processor" },
    {  77,  "Infineon Technologies 32-bit embedded processor" },
    {  78,  "Element 14 64-bit DSP Processor" },
    {  79,  "LSI Logic 16-bit DSP Processor" },
    {  80,  "Donald Knuth's educational 64-bit processor" },
    {  81,  "Harvard University machine-independent object files" },
    {  82,  "SiTera Prism" },
    {  83,  "Atmel AVR 8-bit microcontroller" },
    {  84,  "Fujitsu FR30" },
    {  85,  "Mitsubishi D10V" },
    {  86,  "Mitsubishi D30V" },
    {  87,  "NEC v850" },
    {  88,  "Mitsubishi M32R" },
    {  89,  "Matsushita MN10300" },
    {  90,  "Matsushita MN10200" },
    {  91,  "picoJava" },
    {  92,  "OpenRISC 32-bit embedded processor" },
    {  93,  "ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)" },
    {  94,  "Tensilica Xtensa Architecture" },
    {  95,  "Alphamosaic VideoCore processor" },
    {  96,  "Thompson Multimedia General Purpose Processor" },
    {  97,  "National Semiconductor 32000 series" },
    {  98,  "Tenor Network TPC processor" },
    {  99,  "Trebia SNP 1000 processor" },
    { 100,  "STMicroelectronics (www.st.com) ST200 microcontroller" },
    { 101,  "Ubicom IP2xxx microcontroller family" },
    { 102,  "MAX Processor" },
    { 103,  "National Semiconductor CompactRISC microprocessor" },
    { 104,  "Fujitsu F2MC16" },
    { 105,  "Texas Instruments embedded microcontroller msp430" },
    { 106,  "Analog Devices Blackfin (DSP) processor" },
    { 107,  "S1C33 Family of Seiko Epson processors" },
    { 108,  "Sharp embedded microprocessor" },
    { 109,  "Arca RISC Microprocessor" },
    { 110,  "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University" },
    { 111,  "eXcess: 16/32/64-bit configurable embedded CPU" },
    { 112,  "Icera Semiconductor Inc. Deep Execution Processor" },
    { 113,  "Altera Nios II soft-core processor" },
    { 114,  "National Semiconductor CompactRISC CRX microprocessor" },
    { 115,  "Motorola XGATE embedded processor" },
    { 116,  "Infineon C16x/XC16x processor" },
    { 117,  "Renesas M16C series microprocessors" },
    { 118,  "Microchip Technology dsPIC30F Digital Signal Controller" },
    { 119,  "Freescale Communication Engine RISC core" },
    { 120,  "Renesas M32C series microprocessors" },
    { 131,  "Altium TSK3000 core" },
    { 132,  "Freescale RS08 embedded processor" },
    { 133,  "Analog Devices SHARC family of 32-bit DSP processors" },
    { 134,  "Cyan Technology eCOG2 microprocessor" },
    { 135,  "Sunplus S+core7 RISC processor" },
    { 136,  "New Japan Radio (NJR) 24-bit DSP Processor" },
    { 137,  "Broadcom VideoCore III processor" },
    { 138,  "RISC processor for Lattice FPGA architecture" },
    { 139,  "Seiko Epson C17 family" },
    { 140,  "The Texas Instruments TMS320C6000 DSP family" },
    { 141,  "The Texas Instruments TMS320C2000 DSP family" },
    { 142,  "The Texas Instruments TMS320C55x DSP family" },
    { 160,  "STMicroelectronics 64bit VLIW Data Signal Processor" },
    { 161,  "Cypress M8C microprocessor" },
    { 162,  "Renesas R32C series microprocessors" },
    { 163,  "NXP Semiconductors TriMedia architecture family" },
    { 164,  "QUALCOMM DSP6 Processor" },
    { 165,  "Intel 8051 and variants" },
    { 166,  "STMicroelectronics STxP7x family of configurable and extensible RISC processors" },
    { 167,  "Andes Technology compact code size embedded RISC processor family" },
    { 168,  "Cyan Technology eCOG1X family" },
    { 168,  "Cyan Technology eCOG1X family" },
    { 169,  "Dallas Semiconductor MAXQ30 Core Micro-controllers" },
    { 170,  "New Japan Radio (NJR) 16-bit DSP Processor" },
    { 171,  "M2000 Reconfigurable RISC Microprocessor" },
    { 172,  "Cray Inc. NV2 vector architecture" },
    { 173,  "Renesas RX family" },
    { 174,  "Imagination Technologies META processor architecture" },
    { 175,  "MCST Elbrus general purpose hardware architecture" },
    { 176,  "Cyan Technology eCOG16 family" },
    { 177,  "National Semiconductor CompactRISC CR16 16-bit microprocessor" },
    { 178,  "Freescale Extended Time Processing Unit" },
    { 179,  "Infineon Technologies SLE9X core" },
    { 180,  "Intel L10M" },
    { 181,  "Intel K10M" },
    { 182,  "Reserved for future Intel use" },
    { 183,  "ARM 64-bit architecture (AARCH64)" },
    { 184,  "Reserved for future ARM use" },
    { 185,  "Atmel Corporation 32-bit microprocessor family" },
    { 186,  "STMicroeletronics STM8 8-bit microcontroller" },
    { 187,  "Tilera TILE64 multicore architecture family" },
    { 188,  "Tilera TILEPro multicore architecture family" },
    { 189,  "Xilinx MicroBlaze 32-bit RISC soft processor core" },
    { 190,  "NVIDIA CUDA architecture" },
    { 191,  "Tilera TILE-Gx multicore architecture family" },
    { 192,  "CloudShield architecture family" },
    { 193,  "KIPO-KAIST Core-A 1st generation processor family" },
    { 194,  "KIPO-KAIST Core-A 2nd generation processor family" },
    { 195,  "Synopsys ARCompact V2" },
    { 196,  "Open8 8-bit RISC soft processor core" },
    { 197,  "Renesas RL78 family" },
    { 198,  "Broadcom VideoCore V processor" },
    { 199,  "Renesas 78KOR family" },
    { 200,  "Freescale 56800EX Digital Signal Controller (DSC)" },
    { 201,  "Beyond BA1 CPU architecture" },
    { 202,  "Beyond BA2 CPU architecture" },
    { 203,  "XMOS xCORE processor family" },
    { 204,  "Microchip 8-bit PIC(r) family" },
    { 0, NULL }
};
static value_string_ext machine_vals_ext = VALUE_STRING_EXT_INIT(machine_vals);

/* From Draft */
static const value_string os_abi_vals[] = {
    { 0x00,  "No extensions or unspecified" },
    { 0x01,  "Hewlett-Packard HP-UX" },
    { 0x02,  "NetBSD" },
    { 0x03,  "GNU (historial alias: Linux)" },
    { 0x06,  "Sun Solaris" },
    { 0x07,  "AIX" },
    { 0x08,  "IRIX" },
    { 0x09,  "FreeBSD" },
    { 0x0A,  "Compaq TRU64 UNIX" },
    { 0x0B,  "Novell Modesto" },
    { 0x0C,  "Open BSD" },
    { 0x0D,  "Open VMS" },
    { 0x0E,  "Hewlett-Packard Non-Stop Kernel" },
    { 0x0F,  "Amiga Research OS" },
    { 0x10,  "The FenixOS highly scalable multi-core OS" },
    { 0, NULL }
};
static value_string_ext os_abi_vals_ext = VALUE_STRING_EXT_INIT(os_abi_vals);

static const value_string p_type_vals[] = {
    { 0,  "PT_NULL" },
    { 1,  "PT_LOAD" },
    { 2,  "PT_DYNAMIC" },
    { 3,  "PT_INTERP" },
    { 4,  "PT_NOTE" },
    { 5,  "PT_SHLIB" },
    { 6,  "PT_PHDR" },
    { 7,  "PT_TLS" },
    { 0, NULL }
};

static const value_string sh_type_vals[] = {
    {  0,  "SHT_NULL" },
    {  1,  "SHT_PROGBITS" },
    {  2,  "SHT_SYMTAB" },
    {  3,  "SHT_STRTAB" },
    {  4,  "SHT_RELA" },
    {  5,  "SHT_HASH" },
    {  6,  "SHT_DYNAMIC" },
    {  7,  "SHT_NOTE" },
    {  8,  "SHT_NOBITS" },
    {  9,  "SHT_REL" },
    { 10,  "SHT_SHLIB" },
    { 11,  "SHT_DYNSYM" },
    { 14,  "SHT_INIT_ARRAY" },
    { 15,  "SHT_FINI_ARRAY" },
    { 16,  "SHT_PREINIT_ARRAY" },
    { 17,  "SHT_GROUP" },
    { 18,  "SHT_SYMTAB_SHNDX" },
    /* TODO: http://www.sco.com/developers/gabi/latest/ch4.sheader.html range_string? */
    { 0, NULL }
};
static value_string_ext sh_type_vals_ext = VALUE_STRING_EXT_INIT(sh_type_vals);

static const value_string eh_dwarf_upper[] = {
    { 0x0,  "Normal Value"  },
    { 0x1,  "Value is relative to the current program counter. (DW_EH_PE_pcrel)" },
    { 0x2,  "Value is relative to the beginning of the .text section. (DW_EH_PE_textrel)" },
    { 0x3,  "Value is relative to the beginning of the .got or .eh_frame_hdr section. (DW_EH_PE_datarel)" },
    { 0x4,  "Value is relative to the beginning of the function. (DW_EH_PE_funcrel)" },
    { 0x5,  "Value is aligned to an address unit sized boundary. (DW_EH_PE_aligned)" },
    { 0, NULL }
};

static const value_string eh_dwarf_format[] = {
    { 0x0,  "The Value is a literal pointer whose size is determined by the architecture. (DW_EH_PE_absptr)" },
    { 0x1,  "Unsigned value is encoded using the Little Endian Base 128 (LEB128). (DW_EH_PE_uleb128)" },
    { 0x2,  "A 2 bytes unsigned value. (DW_EH_PE_udata2)" },
    { 0x3,  "A 4 bytes unsigned value. (DW_EH_PE_udata4)" },
    { 0x4,  "An 8 bytes unsigned value. (DW_EH_PE_udata8)" },
    { 0x9,  "Signed value is encoded using the Little Endian Base 128 (LEB128). (DW_EH_PE_sleb128)" },
    { 0xA,  "A 2 bytes signed value. (DW_EH_PE_sdata2)" },
    { 0xB,  "A 4 bytes signed value. (DW_EH_PE_sdata4)" },
    { 0xC,  "An 8 bytes signed value. (DW_EH_PE_sdata8)" },
    { 0, NULL }
};

static const value_string symbol_table_other_vals[] = {
    { 0,   "Default" },
    { 1,   "Internal" },
    { 2,   "Hidden" },
    { 3,   "Protected" },
    { 0, NULL }
};


static const value_string symbol_table_info_bind_vals[] = {
    {  0,   "Local" },
    {  1,   "Global" },
    {  2,   "Weak" },
    { 10,   "Operating System Specific" },
    { 11,   "Operating System Specific" },
    { 12,   "Operating System Specific" },
    { 13,   "Processor Specific" },
    { 14,   "Processor Specific" },
    { 15,   "Processor Specific" },
    { 0, NULL }
};

static const value_string symbol_table_info_type_vals[] = {
    {  0,   "No Type" },
    {  1,   "Object" },
    {  2,   "Function" },
    {  3,   "Section" },
    {  4,   "File" },
    {  5,   "Common" },
    {  6,   "Thread-Local Storage" },
    { 10,   "Operating System Specific" },
    { 11,   "Operating System Specific" },
    { 12,   "Operating System Specific" },
    { 13,   "Processor Specific" },
    { 14,   "Processor Specific" },
    { 15,   "Processor Specific" },
    { 0, NULL }
};
static value_string_ext symbol_table_info_type_vals_ext = VALUE_STRING_EXT_INIT(symbol_table_info_type_vals);

static const range_string symbol_table_shndx_rvals[] = {
    { 0x0000, 0x0000,  "Undefined" },
    { 0x0001, 0xfeff,  "Normal Section" },
    { 0xff00, 0xff1f,  "Processor Specific" },
    { 0xff20, 0xff3f,  "Operating System Specific" },
    { 0xff40, 0xfff0,  "Reserved" },
    { 0xfff1, 0xfff1,  "Absolute Value" },
    { 0xfff2, 0xfff2,  "Common" },
    { 0xfff3, 0xfffe,  "Reserved" },
    { 0xffff, 0xffff,  "Xindex" },
    { 0, 0, NULL }
};

static const range_string dynamic_tag_rvals[] = {
    {  0,  0,   "NULL" },
    {  1,  1,   "Needed" },
    {  2,  2,   "Procedure Linkage Table Size" },
    {  3,  3,   "Procedure Linkage Table and/or the Global Offset Table Address" },
    {  4,  4,   "Hash" },

    {  5,  5,   "String Table Address" },
    {  6,  6,   "Symbol Table Address" },
    {  7,  7,   "Relocation Table Address" },
    {  8,  8,   "Relocation Table Size" },
    {  9,  9,   "Relocation Table Entry Size" },
    { 10, 10,   "String Table Size" },
    { 11, 11,   "Symbol Table Entry Size" },
    { 12, 12,   "Initialization Function Address" },
    { 13, 13,   "Termination Function Address" },
    { 14, 14,   "Shared Object Name Offset" },
    { 15, 15,   "Search Library Path (Rpath)" },
    { 16, 16,   "Symbolic" },
    { 17, 17,   "Relocation Table with Implicit Addends" },
    { 18, 18,   "Relocation Table with Implicit Addends Size" },
    { 19, 19,   "Relocation Table with Implicit Addends Entry Size" },
    { 20, 20,   "Procedure Linkage Table Relocation Entry Type" },
    { 21, 21,   "Debug" },
    { 22, 22,   "TEXT Relocation" },
    { 23, 23,   "Procedure Linkage Table Relocation Entries Address" },
    { 24, 24,   "Bind Now" },
    { 25, 25,   "Initialization Functions Array Address" },
    { 26, 26,   "Termination Functions Array Address" },
    { 27, 27,   "Initialization Functions Array Size" },
    { 28, 28,   "Termination Functions Array Size" },
    { 29, 29,   "Run Path" },
    { 30, 30,   "Flags" },
    { 31, 31,   "Preinitialization Functions Array Address" },
    { 32, 32,   "Preinitialization Functions Array Size" },
    { 33, 33,   "Encoding" },

    { 0x6000000D, 0x6ffff000,   "Operating System Specific" },
    { 0x70000000, 0x7fffffff,   "Processor Specific" },
    { 0, 0, NULL }
};


typedef struct _segment_info_t {
    guint64        offset;
    guint64        size;
    const guint8  *name;
} segment_info_t;

void proto_register_elf(void);
void proto_reg_handoff_elf(void);


/* Wireshark support "offset" as gint, but ELF needed guint64 size, so check if there is no overflow */
static gint
value_guard(guint64 value)
{
    DISSECTOR_ASSERT_HINT(value <= G_MAXINT, "Too big file - not supported");

    return (gint) value;
}

static guint8
dissect_dwarf_encoding(tvbuff_t *tvb, gint offset, proto_item *item)
{
    guint8      value;
    proto_tree *tree;

    tree = proto_item_add_subtree(item, ett_dwarf_encoding);

    value = tvb_get_guint8(tvb, offset);

    if (value == 0xFF) {
        proto_tree_add_item(tree, hf_dwarf_omit,   tvb, offset, 1, ENC_NA);
    } else {
        proto_tree_add_item(tree, hf_dwarf_upper,  tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_dwarf_format, tvb, offset, 1, ENC_NA);
    }

    return value;
}

#define LENGTH_LEB128   -1
#define LENGTH_ULEB128  -2

static gint8
get_dwarf_extension_length(guint8 format, guint register_size)
{
    switch (format & 0x0F) {
    case 0x0:
        return register_size;
    case 0x1:
        return LENGTH_ULEB128;
    case 0x2:
        return 2;
    case 0x3:
        return 4;
    case 0x4:
        return 8;
    case 0x9:
        return LENGTH_LEB128;
    case 0xA:
        return 2;
    case 0xB:
        return 4;
    case 0xC:
        return 8;
    }

    return 0;
}

static const guint8 *
get_section_name_offset(tvbuff_t *tvb, guint64 shoff, guint16 shnum, guint16 shentsize, guint16 shndx, guint64 shstrtab_offset, guint machine_encoding)
{
    gint     offset;
    guint32  sh_name;

    if (shndx > shnum)
        return NULL;

    offset = value_guard(shoff + shndx * shentsize);
    sh_name = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
    return tvb_get_const_stringz(tvb, value_guard(shstrtab_offset + sh_name), NULL);
}

#define MAX_TAG_TO_TYPE 34
static gint
dissect_dynamic(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *entry_tree, proto_item *entry_item,
        gint offset, gint register_size, guint machine_encoding)
{
    enum enum_tag_type {
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_IGNORED,
        DYNAMIC_TYPE_UNSPECIFIED
    };

    guint64                          tag;
    static const enum enum_tag_type  tag_to_type[MAX_TAG_TO_TYPE] = {
        DYNAMIC_TYPE_IGNORED,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_IGNORED,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_IGNORED,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_IGNORED,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_VALUE,
        DYNAMIC_TYPE_UNSPECIFIED,
        DYNAMIC_TYPE_POINTER,
        DYNAMIC_TYPE_VALUE
     };

    if (register_size == REGISTER_32_SIZE) {
        proto_tree_add_item(entry_tree, hf_elf_dynamic_tag, tvb, offset, 4, machine_encoding);
        tag = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        offset += 4;

        if (tag < MAX_TAG_TO_TYPE && tag_to_type[tag] == DYNAMIC_TYPE_VALUE)
            proto_tree_add_item(entry_tree, hf_elf_dynamic_value, tvb, offset, 4, machine_encoding);
        else if (tag < MAX_TAG_TO_TYPE && tag_to_type[tag] == DYNAMIC_TYPE_POINTER)
            proto_tree_add_item(entry_tree, hf_elf_dynamic_pointer, tvb, offset, 4, machine_encoding);
        else if (tag < MAX_TAG_TO_TYPE && tag_to_type[tag] == DYNAMIC_TYPE_IGNORED)
            proto_tree_add_item(entry_tree, hf_elf_dynamic_ignored, tvb, offset, 4, machine_encoding);
        else
            proto_tree_add_item(entry_tree, hf_elf_dynamic_unspecified, tvb, offset, 4, machine_encoding);
        offset += 4;
    } else {
        proto_item  *pitem;

        pitem = proto_tree_add_item(entry_tree, hf_elf64_dynamic_tag, tvb, offset, 8, machine_encoding);
        tag = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
        proto_item_append_text(pitem, " (%s)", rval_to_str(value_guard(tag), dynamic_tag_rvals, "Unknown"));
        offset += 8;

        if (tag < MAX_TAG_TO_TYPE && tag_to_type[tag] == DYNAMIC_TYPE_VALUE)
            proto_tree_add_item(entry_tree, hf_elf64_dynamic_value, tvb, offset, 8, machine_encoding);
        else if (tag < MAX_TAG_TO_TYPE && tag_to_type[tag] == DYNAMIC_TYPE_POINTER)
            proto_tree_add_item(entry_tree, hf_elf64_dynamic_pointer, tvb, offset, 8, machine_encoding);
        else if (tag < MAX_TAG_TO_TYPE && tag_to_type[tag] == DYNAMIC_TYPE_IGNORED)
            proto_tree_add_item(entry_tree, hf_elf64_dynamic_ignored, tvb, offset, 8, machine_encoding);
        else
            proto_tree_add_item(entry_tree, hf_elf64_dynamic_unspecified, tvb, offset, 8, machine_encoding);
        offset += 8;
    }

    proto_item_append_text(entry_item, ": %s", rval_to_str(value_guard(tag), dynamic_tag_rvals, "Unknown"));

    return offset;
}

static gint
dissect_symbol_table(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *entry_tree, proto_item *entry_item,
        gint offset, gint register_size, guint machine_encoding, guint64 strtab_offset,
        guint64 shoff, guint16 shnum, guint16 shentsize, guint64 shstrtab_offset)
{
    proto_item   *pitem;
    proto_item   *info_item;
    proto_tree   *info_tree;
    guint16       shndx;
    guint32       name_index;
    const guint8 *section_name;
    const guint8 *name;
    guint8        info_bind;
    guint8        info_type;

    pitem = proto_tree_add_item(entry_tree, hf_elf_symbol_table_name_index, tvb, offset, 4, machine_encoding);
    if (strtab_offset) {
        name_index = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        name = tvb_get_const_stringz(tvb, value_guard(strtab_offset + name_index), NULL);
        if (name) {
            proto_item_append_text(pitem, ": %s", name);
            proto_item_append_text(entry_item, ": %s", name);
        }
    }
    offset += 4;

    if (register_size == REGISTER_32_SIZE) {
        proto_tree_add_item(entry_tree, hf_elf_symbol_table_value, tvb, offset, 4, machine_encoding);
        offset += 4;

        proto_tree_add_item(entry_tree, hf_elf_symbol_table_size, tvb, offset, 4, machine_encoding);
        offset += 4;

        info_item = proto_tree_add_item(entry_tree, hf_elf_symbol_table_info, tvb, offset, 1, machine_encoding);
        info_tree = proto_item_add_subtree(info_item, ett_symbol_table_info);
        proto_tree_add_item(info_tree, hf_elf_symbol_table_info_bind, tvb, offset, 1, machine_encoding);
        proto_tree_add_item(info_tree, hf_elf_symbol_table_info_type, tvb, offset, 1, machine_encoding);
        info_bind = tvb_get_guint8(tvb, offset) >> 4;
        info_type = tvb_get_guint8(tvb, offset) & 0x0F;
        offset += 1;

        proto_tree_add_item(entry_tree, hf_elf_symbol_table_other, tvb, offset, 1, machine_encoding);
        offset += 1;

        pitem = proto_tree_add_item(entry_tree, hf_elf_symbol_table_shndx, tvb, offset, 2, machine_encoding);
        shndx = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohs(tvb, offset) : tvb_get_letohs(tvb, offset);
        if (shndx <= shnum) {
            section_name = get_section_name_offset(tvb, shoff, shnum, shentsize, shndx, shstrtab_offset, machine_encoding);
            if (section_name && section_name[0] != '\0')
                proto_item_append_text(pitem, " (%u: %s)", shndx, section_name);
        } else {
            proto_item_append_text(pitem, " (%u)", shndx);
        }
        offset += 2;
    } else {
        info_item = proto_tree_add_item(entry_tree, hf_elf_symbol_table_info, tvb, offset, 1, machine_encoding);
        info_tree = proto_item_add_subtree(info_item, ett_symbol_table_info);
        proto_tree_add_item(info_tree, hf_elf_symbol_table_info_bind, tvb, offset, 1, machine_encoding);
        proto_tree_add_item(info_tree, hf_elf_symbol_table_info_type, tvb, offset, 1, machine_encoding);
        info_bind = tvb_get_guint8(tvb, offset) >> 4;
        info_type = tvb_get_guint8(tvb, offset) & 0x0F;
        offset += 1;

        proto_tree_add_item(entry_tree, hf_elf_symbol_table_other, tvb, offset, 1, machine_encoding);
        offset += 1;

        pitem = proto_tree_add_item(entry_tree, hf_elf_symbol_table_shndx, tvb, offset, 2, machine_encoding);
        shndx = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohs(tvb, offset) : tvb_get_letohs(tvb, offset);
        if (shndx <= shnum) {
            section_name = get_section_name_offset(tvb, shoff, shnum, shentsize, shndx, shstrtab_offset, machine_encoding);
            if (section_name && section_name[0] != '\0')
                proto_item_append_text(pitem, " (%u: %s)", shndx, section_name);
        } else {
            proto_item_append_text(pitem, " (%u)", shndx);
        }
        offset += 2;

        proto_tree_add_item(entry_tree, hf_elf64_symbol_table_value, tvb, offset, 8, machine_encoding);
        offset += 8;

        proto_tree_add_item(entry_tree, hf_elf64_symbol_table_size, tvb, offset, 8, machine_encoding);
        offset += 8;
    }

    proto_item_append_text(info_item, " (Bind: %s, Type: %s)",
            val_to_str_const(info_bind, symbol_table_info_bind_vals, "Unknown"),
            val_to_str_ext_const(info_type, &symbol_table_info_type_vals_ext, "Unknown"));

    proto_item_append_text(entry_item, " (Bind: %s, Type: %s)",
            val_to_str_const(info_bind, symbol_table_info_bind_vals, "Unknown"),
            val_to_str_ext_const(info_type, &symbol_table_info_type_vals_ext, "Unknown"));

    return offset;
}

static gint
dissect_eh_frame_hdr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *segment_tree,
        gint offset, gint segment_size _U_, gint register_size, guint machine_encoding)
{
    proto_item  *item;
    proto_tree  *table_tree;
    guint8       format;
    gint         efp_length;
    gint         fde_count_length;
    gint         table_entry_length;
    guint64      fde_count;
    guint        i_entry;

    proto_tree_add_item(segment_tree, hf_elf_eh_frame_hdr_version, tvb, offset, 1, machine_encoding);
    offset += 1;

    item = proto_tree_add_item(segment_tree, hf_elf_eh_frame_hdr_exception_frame_pointer_encoding, tvb, offset, 1, machine_encoding);
    format = dissect_dwarf_encoding(tvb, offset, item);
    efp_length = get_dwarf_extension_length(format, register_size);
    offset += 1;

    item = proto_tree_add_item(segment_tree, hf_elf_eh_frame_hdr_fde_count_encoding, tvb, offset, 1, machine_encoding);
    format = dissect_dwarf_encoding(tvb, offset, item);
    fde_count_length = get_dwarf_extension_length(format, register_size);
    offset += 1;

    item = proto_tree_add_item(segment_tree, hf_elf_eh_frame_hdr_binary_search_table_encoding, tvb, offset, 1, machine_encoding);
    format = dissect_dwarf_encoding(tvb, offset, item);
    table_entry_length = get_dwarf_extension_length(format, register_size);
    offset += 1;

    if (efp_length == LENGTH_ULEB128) {
        guint64 value;

        efp_length = dissect_uleb128(tvb, offset, &value);
    } else if (efp_length == LENGTH_LEB128) {
        gint64 value;

        efp_length = dissect_leb128(tvb, offset, &value);
    }

    proto_tree_add_item(segment_tree, hf_elf_eh_frame_hdr_eh_frame_ptr, tvb, offset, efp_length, machine_encoding);
    offset += efp_length;


    if (fde_count_length == LENGTH_ULEB128) {
        fde_count_length = dissect_uleb128(tvb, offset, &fde_count);
    } else if (fde_count_length == LENGTH_LEB128) {
        gint64 value;

        fde_count_length = dissect_leb128(tvb, offset, &value);
        fde_count = (guint64) value;
    } else {
        if (fde_count_length == 0) fde_count_length = register_size;

        switch(fde_count_length) {
        case 2:
            fde_count = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohs(tvb, offset) : tvb_get_letohs(tvb, offset);
            break;
        case 4:
            fde_count = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
            break;
        case 8:
            fde_count = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
            break;
        case 0:
        default:
            fde_count = 0;
            break;
        }
    }

    proto_tree_add_item(segment_tree, hf_elf_eh_frame_hdr_fde_count, tvb, offset,
                        fde_count_length, machine_encoding);
    offset += fde_count_length;

    if (table_entry_length == LENGTH_ULEB128) {
        guint64 value;

        table_entry_length = dissect_uleb128(tvb, offset, &value);
    } else if (table_entry_length == LENGTH_LEB128) {
        gint64 value;

        table_entry_length = dissect_leb128(tvb, offset, &value);
    }

    i_entry = 0;

    table_tree = proto_tree_add_subtree(segment_tree, tvb, offset, value_guard(fde_count * table_entry_length * 2),
                    ett_binary_table, NULL, "Binary Search Table");

    while (++i_entry <= fde_count) {
        proto_tree *entry_tree;

        entry_tree = proto_tree_add_subtree_format(table_tree, tvb, offset, table_entry_length * 2, ett_binary_table_entry,
                NULL, "Binary Table Entry #%u", i_entry);

        proto_tree_add_item(entry_tree, hf_elf_eh_frame_hdr_binary_search_table_entry_initial_location, tvb, offset, table_entry_length, machine_encoding);
        offset += table_entry_length;

        proto_tree_add_item(entry_tree, hf_elf_eh_frame_hdr_binary_search_table_entry_address, tvb, offset, table_entry_length, machine_encoding);
        offset += table_entry_length;
    }

    return offset;
}


static gint
dissect_eh_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *segment_tree,
        gint offset, gint segment_size, gint register_size _U_, guint machine_encoding)
{
    proto_tree    *cfi_tree = NULL;
    proto_item    *cfi_tree_item = NULL;
    proto_tree    *entry_tree;
    proto_item    *pi = NULL;
    guint64        length;
    guint          lengths_size;
    gboolean       is_cie;
    guint          entry_size, entry_end = 0;
    guint          cfi_size = 0;
    guint64        unsigned_value;
    gint64         signed_value;
    gint           size;
    const gchar   *augmentation_string = "";
    gboolean       is_extended_length;
    gint           start_offset = offset;
    guint          cfi_number = 0;
    gint           entry_number = 0;

    while (offset - start_offset < segment_size) {
        length = (machine_encoding == ENC_BIG_ENDIAN) ?
                tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        is_extended_length = length == 0xFFFFFFFF;
        if (is_extended_length) {
            length = (machine_encoding == ENC_BIG_ENDIAN) ?
                        tvb_get_ntoh64(tvb, offset + 4) :
                        tvb_get_letoh64(tvb, offset + 4);
        }
        /* CIE ID/pointer is located after Length (4 bytes), or Length (4 bytes)
         * + Extended Length (8 bytes). Entry is CIE when field is 0. */
        lengths_size = is_extended_length ? 12 : 4;
        is_cie = length == 0 || tvb_get_ntohl(tvb, offset + lengths_size) == 0;
        entry_size = value_guard(length + lengths_size);
        entry_end = offset + entry_size;

        if (length == 0) {
            /* CIE Terminator, add it directly under the Segment tree as we stop
             * processing after this item. */
            entry_tree = proto_tree_add_subtree(segment_tree,
                    tvb, offset, entry_size,
                    ett_elf_cie_terminator, NULL, "CIE Terminator");
        } else if (cfi_number == 0 || is_cie) {
            /* New CIE, so create a new CFI subtree and reset FDE Entry. */
            ++cfi_number;
            cfi_tree = proto_tree_add_subtree_format(segment_tree,
                    tvb, offset, entry_size, ett_elf_cfi_record, &cfi_tree_item,
                    "Call Frame Information Entry %i", cfi_number);
            entry_tree = proto_tree_add_subtree(cfi_tree, tvb, offset,
                    entry_size, ett_elf_cie_entry, NULL, "Common Information Entry");
            cfi_size = entry_size;
            entry_number = 0;
        } else {
            /* FDE, add it in the CFI subtree. */
            ++entry_number;
            cfi_size += entry_size;
            proto_item_set_len(cfi_tree_item, cfi_size);
            entry_tree = proto_tree_add_subtree_format(cfi_tree,
                    tvb, offset, entry_size, ett_elf_fde_entry, NULL,
                    "Frame Description Entry %i", entry_number);
        }

        pi = proto_tree_add_item(entry_tree, is_cie ?
                                    hf_elf_eh_frame_length :
                                    hf_elf_eh_frame_fde_length,
                                 tvb, offset, 4, machine_encoding);
        offset += 4;

        if (is_extended_length) {
            pi = proto_tree_add_item(entry_tree, is_cie ?
                                        hf_elf_eh_frame_extended_length :
                                        hf_elf_eh_frame_fde_extended_length,
                                     tvb, offset, 8, machine_encoding);
            offset += 8;
        }

        /* CIE terminator */
        if (length == 0)
            break;

        /* CIE ID (8) + Augment. Str (1) + CAF+DAF+Aug.Len (3) = 12 (min. length) */
        if (length < 12 || entry_end - start_offset > (guint64)segment_size) {
            expert_add_info(pinfo, pi, &ei_invalid_cie_length);
            return offset;
        }

        proto_tree_add_item(entry_tree, is_cie ?
                            hf_elf_eh_frame_cie_id :
                            hf_elf_eh_frame_fde_cie_pointer,
                            tvb, offset, 4, machine_encoding);
        offset += 4;
        if (is_cie) {
            proto_tree_add_item(entry_tree, hf_elf_eh_frame_version,
                                tvb, offset, 1, machine_encoding);
            offset += 1;

            augmentation_string = tvb_get_const_stringz(tvb, offset, &size);
            proto_tree_add_item(entry_tree, hf_elf_eh_frame_augmentation_string,
                                tvb, offset, size, machine_encoding);
            offset += size;

            size = dissect_uleb128(tvb, offset, &unsigned_value);
            proto_tree_add_uint64(entry_tree, hf_elf_eh_frame_code_alignment_factor,
                                  tvb, offset, size, unsigned_value);
            offset += size;

            size = dissect_leb128(tvb, offset, &signed_value);
            proto_tree_add_int64(entry_tree, hf_elf_eh_frame_data_alignment_factor,
                                 tvb, offset, size, signed_value);
            offset += size;

            /* according to DWARF v4 this is uLEB128 */
            size = dissect_uleb128(tvb, offset, &unsigned_value);
            proto_tree_add_uint64(entry_tree, hf_elf_eh_frame_return_address_register,
                                  tvb, offset, size, unsigned_value);
            offset += size;
        } else {
            proto_tree_add_item(entry_tree, hf_elf_eh_frame_fde_pc_begin, tvb,
                                offset, 4, machine_encoding);
            offset += 4;

            proto_tree_add_item(entry_tree, hf_elf_eh_frame_fde_pc_range, tvb,
                                offset, 4, machine_encoding);
            offset += 4;
        }

        /* "A 'z' may be present as the first character of the string. If
         * present, the Augmentation Data field shall be present." (LSB 4.1) */
        if (augmentation_string[0] == 'z') {
            size = dissect_uleb128(tvb, offset, &unsigned_value);
            proto_tree_add_uint64(entry_tree, is_cie ?
                                    hf_elf_eh_frame_augmentation_length :
                                    hf_elf_eh_frame_fde_augmentation_length,
                                  tvb, offset, size, unsigned_value);
            offset += size;

            proto_tree_add_item(entry_tree, is_cie ?
                                    hf_elf_eh_frame_augmentation_data :
                                    hf_elf_eh_frame_fde_augmentation_data,
                                tvb, offset, value_guard(unsigned_value),
                                machine_encoding);
            offset += value_guard(unsigned_value);
        }

        proto_tree_add_item(entry_tree, is_cie ?
                                hf_elf_eh_frame_initial_instructions :
                                hf_elf_eh_frame_fde_call_frame_instructions,
                            tvb, offset, value_guard(entry_end - offset),
                            machine_encoding);
        offset = value_guard(entry_end);
    }

    if (entry_end - start_offset != (guint64)segment_size)
        expert_add_info(pinfo, pi, &ei_cfi_extraneous_data);

    return offset;
}

static int
dissect_elf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static const guint8 magic[] = { 0x7F, 'E', 'L', 'F'};
    gint             offset = 0;
    proto_tree      *main_tree;
    proto_item      *main_item, *ti;
    proto_tree      *header_tree;
    proto_item      *header_item;
    proto_tree      *program_header_tree;
    proto_tree      *section_header_tree;
    proto_tree      *ph_entry_tree;
    proto_item      *sh_entry_item;
    proto_tree      *sh_entry_tree;
    proto_item      *segment_item;
    proto_tree      *segment_tree;
    proto_item      *generated_item;
    proto_tree      *generated_tree;
    proto_tree      *overlapping_tree;
    proto_tree      *blackhole_tree;
    proto_item      *entry_item;
    proto_tree      *entry_tree;
    guint            machine_encoding = ENC_NA;
    gint             register_size = 4;
    guint16          phentsize;
    guint16          phnum;
    guint16          shentsize;
    guint16          shnum;
    guint64          phoff;
    guint64          shoff;
    guint16          i_16;
    guint32          p_type;
    guint32          sh_type;
    guint16          shstrndx;
    guint64          shstrtab_offset;
    guint32          sh_name;
    const guint8    *section_name;
    guint64          length;
    guint64          segment_offset;
    guint64          segment_size;
    guint64          file_size;
    guint64          p_offset;
    gint             ehsize;
    guint            area_counter = 0;
    segment_info_t  *segment_info;
    guint            i;
    guint            i_next;
    gint             next_offset;
    gint             len;
    guint64          sh_entsize;
    guint64          strtab_offset = 0;
    guint64          dynstr_offset = 0;

    if (tvb_captured_length(tvb) < 52)
        return 0;

    if (tvb_memeql(tvb, 0, magic, sizeof(magic)) != 0)
        return 0;

    main_item = proto_tree_add_item(tree, proto_elf, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_elf);

    header_tree = proto_tree_add_subtree(main_tree, tvb, offset, 1, ett_elf_header, &header_item, "Header");

    /* e_ident */
    proto_tree_add_item(header_tree, hf_elf_magic_bytes, tvb, offset, sizeof(magic), ENC_NA);
    offset += (int)sizeof(magic);

    proto_tree_add_item(header_tree, hf_elf_file_class, tvb, offset, 1, ENC_NA);
    register_size *= tvb_get_guint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(header_tree, hf_elf_data_encoding, tvb, offset, 1, ENC_NA);
    if (tvb_get_guint8(tvb, offset) == 1)
        machine_encoding = ENC_LITTLE_ENDIAN;
    else
        machine_encoding = ENC_BIG_ENDIAN;
    offset += 1;

    proto_tree_add_item(header_tree, hf_elf_file_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* From Draft */
    proto_tree_add_item(header_tree, hf_elf_os_abi, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(header_tree, hf_elf_abi_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(header_tree, hf_elf_file_padding, tvb, offset, 7, ENC_NA);
    offset += 7;

    /* other */

    proto_tree_add_item(header_tree, hf_elf_type, tvb, offset, 2, machine_encoding);
    offset += 2;

    proto_tree_add_item(header_tree, hf_elf_machine, tvb, offset, 2, machine_encoding);
    offset += 2;

    proto_tree_add_item(header_tree, hf_elf_version, tvb, offset, 4, machine_encoding);
    offset += 4;

    proto_tree_add_item(header_tree,
            (register_size == REGISTER_32_SIZE) ? hf_elf_entry : hf_elf64_entry,
            tvb, offset, register_size, machine_encoding);
    offset += register_size;

    if (register_size == REGISTER_32_SIZE) {
        proto_tree_add_item(header_tree, hf_elf_phoff, tvb, offset,
                register_size, machine_encoding);
        phoff = (machine_encoding == ENC_BIG_ENDIAN) ?
                tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
    } else {
        proto_tree_add_item(header_tree, hf_elf64_phoff, tvb, offset,
                register_size, machine_encoding);
        phoff = (machine_encoding == ENC_BIG_ENDIAN) ?
                tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
    }
    offset += register_size;


    if (register_size == REGISTER_32_SIZE) {
        proto_tree_add_item(header_tree, hf_elf_shoff, tvb, offset,
                register_size, machine_encoding);
        shoff = (machine_encoding == ENC_BIG_ENDIAN) ?
                tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
    } else {
        proto_tree_add_item(header_tree, hf_elf64_shoff, tvb, offset,
                register_size, machine_encoding);
        shoff = (machine_encoding == ENC_BIG_ENDIAN) ?
                tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
    }
    offset += register_size;

    proto_tree_add_item(header_tree, hf_elf_flags, tvb, offset, 4, machine_encoding);
    offset += 4;

    proto_tree_add_item(header_tree, hf_elf_ehsize, tvb, offset, 2, machine_encoding);
    ehsize =  (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohs(tvb, offset) : tvb_get_letohs(tvb, offset);
    proto_item_set_len(header_item, ehsize);
    offset += 2;

    proto_tree_add_item(header_tree, hf_elf_phentsize, tvb, offset, 2, machine_encoding);
    phentsize = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohs(tvb, offset) : tvb_get_letohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(header_tree, hf_elf_phnum, tvb, offset, 2, machine_encoding);
    phnum = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohs(tvb, offset) : tvb_get_letohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(header_tree, hf_elf_shentsize, tvb, offset, 2, machine_encoding);
    shentsize = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohs(tvb, offset) : tvb_get_letohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(header_tree, hf_elf_shnum, tvb, offset, 2, machine_encoding);
    shnum = (machine_encoding == ENC_BIG_ENDIAN) ? tvb_get_ntohs(tvb, offset) : tvb_get_letohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(header_tree, hf_elf_shstrndx, tvb, offset, 2, machine_encoding);
    shstrndx = (machine_encoding == ENC_BIG_ENDIAN) ?
            tvb_get_ntohs(tvb, offset) : tvb_get_letohs(tvb, offset);
    /*offset += 2;*/

    program_header_tree = proto_tree_add_subtree_format(main_tree, tvb, value_guard(phoff),
            phnum * phentsize, ett_elf_program_header, NULL, "Program Header Table [%d entries]", phnum);

    section_header_tree = proto_tree_add_subtree_format(main_tree, tvb, value_guard(shoff),
            shnum * shentsize, ett_elf_section_header, NULL, "Section Header Table [%d entries]", shnum);

    file_size = ehsize + phnum * phentsize + shnum * shentsize;

    /* Collect infos for blackholes */
    segment_info = (segment_info_t *) wmem_alloc(wmem_packet_scope(), sizeof(segment_info_t) * (shnum + phnum + 3));

    segment_info[area_counter].offset = 0;
    segment_info[area_counter].size = ehsize;
    segment_info[area_counter].name = "Header";
    area_counter += 1;

    if (phoff) {
        segment_info[area_counter].offset = phoff;
        segment_info[area_counter].size = phnum * phentsize;
        segment_info[area_counter].name = "ProgramHeader";
        area_counter += 1;
    }

    if (shoff) {
        segment_info[area_counter].offset = shoff;
        segment_info[area_counter].size = shnum * shentsize;
        segment_info[area_counter].name = "SectionHeader";
        area_counter += 1;
    }

    offset = value_guard(phoff);

    i_16 = phnum;
    while (i_16-- > 0) {
        p_type = (machine_encoding == ENC_BIG_ENDIAN) ?
                tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        if (p_type >= 0x60000000 && p_type <= 0x6FFFFFFF) {
            ph_entry_tree = proto_tree_add_subtree_format(program_header_tree,
                     tvb, offset, phentsize, ett_elf_program_header_entry, NULL,
                    "Entry #%d: Operating System Specific (0x%08x)", phnum - i_16 - 1, p_type);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_type_operating_system_specific, tvb, offset, 4, machine_encoding);
        } else if (p_type >= 0x70000000 && p_type <= 0x7FFFFFFF) {
            ph_entry_tree = proto_tree_add_subtree_format(program_header_tree,
                     tvb, offset, phentsize, ett_elf_program_header_entry, NULL,
                    "Entry #%d: Processor Specific (0x%08x)", phnum - i_16 - 1, p_type);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_type_processor_specific, tvb, offset, 4, machine_encoding);
        } else {
            ph_entry_tree = proto_tree_add_subtree_format(program_header_tree,
                     tvb, offset, phentsize, ett_elf_program_header_entry, NULL,
                    "Entry #%d: %s", phnum - i_16 - 1,
                    val_to_str_const(p_type, p_type_vals, "Unknown"));
            proto_tree_add_item(ph_entry_tree, hf_elf_p_type, tvb, offset, 4, machine_encoding);
        }
        offset += 4;

        if (register_size == REGISTER_64_SIZE) {
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_processor_specific, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_operating_system_specific, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_reserved, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_read, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_write, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_execute, tvb, offset, 4, machine_encoding);
            offset += 4;
        }

        proto_tree_add_item(ph_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_p_offset : hf_elf64_p_offset,
                tvb, offset, register_size, machine_encoding);
        if (register_size == REGISTER_32_SIZE) {
            p_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        } else {
            p_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
        }

        offset += register_size;

        proto_tree_add_item(ph_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_p_vaddr : hf_elf64_p_vaddr,
                tvb, offset, register_size, machine_encoding);
        offset += register_size;

        proto_tree_add_item(ph_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_p_paddr : hf_elf64_p_paddr,
                tvb, offset, register_size, machine_encoding);
        offset += register_size;

        proto_tree_add_item(ph_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_p_filesz : hf_elf64_p_filesz,
                tvb, offset, register_size, machine_encoding);
        if (register_size == REGISTER_32_SIZE) {
            segment_size = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        } else {
            segment_size = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
        }
        offset += register_size;

        proto_tree_add_item(ph_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_p_memsz : hf_elf64_p_memsz,
                tvb, offset, register_size, machine_encoding);
        offset += register_size;

        if (register_size == REGISTER_32_SIZE) {
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_processor_specific, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_operating_system_specific, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_reserved, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_read, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_write, tvb, offset, 4, machine_encoding);
            proto_tree_add_item(ph_entry_tree, hf_elf_p_flags_execute, tvb, offset, 4, machine_encoding);
            offset += 4;
        }

        proto_tree_add_item(ph_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_p_align : hf_elf64_p_align,
                tvb, offset, register_size, machine_encoding);
        offset += register_size;

        if (segment_size) {
            gchar  *name;

            name = wmem_strdup_printf(wmem_packet_scope(), "ProgramHeaderEntry #%u", phnum - i_16 - 1);

            proto_tree_add_bytes_format(ph_entry_tree, hf_elf_segment, tvb, value_guard(p_offset), value_guard(segment_size), NULL, "Segment");

            file_size += segment_size;

            segment_info[area_counter].offset = p_offset;
            segment_info[area_counter].size = segment_size;
            segment_info[area_counter].name = name;

            area_counter += 1;
        }
    }

/* Find and save some information for later */
    offset = value_guard(shoff);

    i_16 = shnum;
    while (i_16-- > 0) {
        sh_name = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);

        offset += 4;

        offset += 4;

        length = shoff + shstrndx * shentsize + 2 * 4 + 2 * register_size;
        if (register_size == REGISTER_32_SIZE) {
            shstrtab_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, value_guard(length)) : tvb_get_letohl(tvb, value_guard(length));
        } else {
            shstrtab_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntoh64(tvb, value_guard(length)) : tvb_get_letoh64(tvb, value_guard(length));
        }

        section_name = tvb_get_const_stringz(tvb, value_guard(shstrtab_offset + sh_name), NULL);

        if (register_size == REGISTER_64_SIZE && machine_encoding == ENC_BIG_ENDIAN) {
            offset += 4;
        }

        offset += 4;

        if (register_size == REGISTER_64_SIZE && machine_encoding == ENC_LITTLE_ENDIAN) {
            offset += 4;
        }

        offset += register_size;

        if (register_size == REGISTER_32_SIZE) {
            segment_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        } else {
            segment_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
        }

        if (g_strcmp0(section_name, ".strtab") == 0) {
            strtab_offset = segment_offset;
        } else if (g_strcmp0(section_name, ".dynstr") == 0) {
            dynstr_offset = segment_offset;
        }
        offset += register_size;
        offset += register_size;
        offset += 4;
        offset += 4;
        offset += register_size;
        offset += register_size;
    }

/* Sections */
    offset = value_guard(shoff);

    i_16 = shnum;
    while (i_16-- > 0) {
        sh_entry_tree = proto_tree_add_subtree_format(section_header_tree, tvb, offset, shentsize,
                ett_elf_section_header_entry, &sh_entry_item,
                "Entry #%d: ", shnum - i_16 - 1);

        proto_tree_add_item(sh_entry_tree, hf_elf_sh_name, tvb, offset, 4, machine_encoding);
        sh_name = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        offset += 4;

        sh_type = (machine_encoding == ENC_BIG_ENDIAN) ?
                tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        if (sh_type >= 0x60000000 && sh_type <= 0x6FFFFFFF) {
            proto_item_append_text(sh_entry_item, "Operating System Specific (0x%08x)", sh_type);
            proto_tree_add_item(sh_entry_tree, hf_elf_sh_type_operating_system_specific, tvb, offset, 4, machine_encoding);
        } else if (sh_type >= 0x70000000 && sh_type <= 0x7FFFFFFF) {
            proto_item_append_text(sh_entry_item, "Processor Specific (0x%08x)", sh_type);
            proto_tree_add_item(sh_entry_tree, hf_elf_sh_type_processor_specific, tvb, offset, 4, machine_encoding);
        } else if (sh_type >= 0x80000000 && sh_type <= 0xFFFFFFFF) {
            proto_item_append_text(sh_entry_item, "User Specific (0x%08x)", sh_type);
            proto_tree_add_item(sh_entry_tree, hf_elf_sh_type_user_specific, tvb, offset, 4, machine_encoding);
        }else {
            proto_item_append_text(sh_entry_item, "%s", val_to_str_ext_const(sh_type, &sh_type_vals_ext, "Unknown"));
            proto_tree_add_item(sh_entry_tree, hf_elf_sh_type, tvb, offset, 4, machine_encoding);
        }
        offset += 4;

        length = shoff + shstrndx * shentsize + 2 * 4 + 2 * register_size;
        if (register_size == REGISTER_32_SIZE) {
            shstrtab_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, value_guard(length)) : tvb_get_letohl(tvb, value_guard(length));
        } else {
            shstrtab_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntoh64(tvb, value_guard(length)) : tvb_get_letoh64(tvb, value_guard(length));
        }

        section_name = tvb_get_const_stringz(tvb, value_guard(shstrtab_offset + sh_name), NULL);
        if (section_name)
            proto_item_append_text(sh_entry_item, ": %s", section_name);

        if (register_size == REGISTER_64_SIZE && machine_encoding == ENC_BIG_ENDIAN) {
            offset += 4;
        }

        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_processor_specific, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_operating_system_specific, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_reserved, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_tls, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_group, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_os_nonconforming, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_link_order, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_info_link, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_strings, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_merge, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_reserved_8, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_exec_instr, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_alloc, tvb, offset, 4, machine_encoding);
        proto_tree_add_item(sh_entry_tree, hf_elf_sh_flags_write, tvb, offset, 4, machine_encoding);
        offset += 4;

        if (register_size == REGISTER_64_SIZE && machine_encoding == ENC_LITTLE_ENDIAN) {
            offset += 4;
        }

        proto_tree_add_item(sh_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_sh_addr : hf_elf64_sh_addr,
                tvb, offset, register_size, machine_encoding);
        offset += register_size;

        proto_tree_add_item(sh_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_sh_offset : hf_elf64_sh_offset,
                tvb, offset, register_size, machine_encoding);
        if (register_size == REGISTER_32_SIZE) {
            segment_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        } else {
            segment_offset = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
        }
        offset += register_size;

        proto_tree_add_item(sh_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_sh_size : hf_elf64_sh_size,
                tvb, offset, register_size, machine_encoding);
        if (register_size == REGISTER_32_SIZE) {
            segment_size = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        } else {
            segment_size = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
        }
        offset += register_size;

        proto_tree_add_item(sh_entry_tree, hf_elf_sh_link, tvb, offset, 4, machine_encoding);
        offset += 4;

        proto_tree_add_item(sh_entry_tree, hf_elf_sh_info, tvb, offset, 4, machine_encoding);
        offset += 4;

        proto_tree_add_item(sh_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_sh_addralign : hf_elf64_sh_addralign,
                tvb, offset, register_size, machine_encoding);
        offset += register_size;

        proto_tree_add_item(sh_entry_tree,
                (register_size == REGISTER_32_SIZE) ? hf_elf_sh_entsize : hf_elf64_sh_entsize,
                tvb, offset, register_size, machine_encoding);
        if (register_size == REGISTER_32_SIZE) {
            sh_entsize = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntohl(tvb, offset) : tvb_get_letohl(tvb, offset);
        } else {
            sh_entsize = (machine_encoding == ENC_BIG_ENDIAN) ?
                    tvb_get_ntoh64(tvb, offset) : tvb_get_letoh64(tvb, offset);
        }
        offset += register_size;

        if (segment_size > 0 && sh_type != 8) {
            file_size += segment_size;

            segment_info[area_counter].offset = segment_offset;
            segment_info[area_counter].size = segment_size;
            segment_info[area_counter].name = section_name;
            area_counter += 1;

            segment_tree = proto_tree_add_subtree(sh_entry_tree, tvb, value_guard(segment_offset),
                    value_guard(segment_size), ett_elf_segment, &segment_item, "Segment");

            if (g_strcmp0(section_name, ".eh_frame") == 0) {
                next_offset = dissect_eh_frame(tvb, pinfo, segment_tree,
                        value_guard(segment_offset), value_guard(segment_size), register_size,
                        machine_encoding);
                if (next_offset != (gint) (segment_offset + segment_size))
                    expert_add_info(pinfo, segment_item, &ei_invalid_segment_size);
            } else if (g_strcmp0(section_name, ".eh_frame_hdr") == 0) {
                next_offset = dissect_eh_frame_hdr(tvb, pinfo, segment_tree,
                        value_guard(segment_offset), value_guard(segment_size), register_size,
                        machine_encoding);
                if (next_offset != (gint) (segment_offset + segment_size))
                    expert_add_info(pinfo, segment_item, &ei_invalid_segment_size);
            } else if (sh_type == 0x06) { /* SHT_DYNAMIC */
                if (sh_entsize > 0) {
                    next_offset = value_guard(segment_offset);
                    for  (i = 1; i < (segment_size / sh_entsize) + 1; i += 1) {
                        entry_tree = proto_tree_add_subtree_format(segment_tree, tvb, next_offset,
                               value_guard(sh_entsize), ett_symbol_table_entry, &entry_item, "Entry #%d", i);

                        next_offset = dissect_dynamic(tvb, pinfo, entry_tree, entry_item,
                                next_offset, register_size, machine_encoding);
                        if (next_offset != (gint) (segment_offset + i * sh_entsize))
                            expert_add_info(pinfo, segment_item, &ei_invalid_entry_size);
                    }
                }
            } else if (sh_type == 0x02 || sh_type == 0x0b) { /* SHT_SYMTAB || SHT_DYNSYM */
                if (sh_entsize > 0) {
                    next_offset = value_guard(segment_offset);
                    for  (i = 1; i < (segment_size / sh_entsize) + 1; i += 1) {
                        entry_tree = proto_tree_add_subtree_format(segment_tree, tvb, next_offset,
                               value_guard(sh_entsize), ett_symbol_table_entry, &entry_item, "Entry #%d", i);

                        next_offset = dissect_symbol_table(tvb, pinfo, entry_tree, entry_item,
                                next_offset, register_size, machine_encoding, (sh_type == 0x02) ? strtab_offset : dynstr_offset,
                                shoff, shnum, shentsize, shstrtab_offset);
                        if (next_offset != (gint) (segment_offset + i * sh_entsize))
                            expert_add_info(pinfo, segment_item, &ei_invalid_entry_size);
                    }
                }
            } else if (sh_type == 0x03) { /* SHT_STRTAB */
                    next_offset = value_guard(segment_offset);
                    i = 1;
                    while (next_offset < (gint) (segment_offset + segment_size)) {
                        tvb_get_const_stringz(tvb, next_offset, &len);
                        entry_item = proto_tree_add_item(segment_tree, hf_elf_string, tvb, next_offset, len, ENC_ASCII | ENC_NA);
                        proto_item_append_text(entry_item, " (Number: %u, Index: %u, Length: %u)", (guint) i, (guint) (next_offset - segment_offset), len - 1);
                        next_offset += len;
                        i += 1;
                    }
            } else {
                if (sh_entsize > 0) {
                    next_offset = value_guard(segment_offset);
                    for  (i = 1; i < (segment_size / sh_entsize) + 1; i += 1) {
                        proto_tree_add_bytes_format(segment_tree, hf_elf_entry_bytes, tvb, next_offset,
                               value_guard(sh_entsize), NULL, "Entry #%d ", i);
                        next_offset += value_guard(sh_entsize);
                    }
                }
            }
        }
    }

    /* Try to detect blackholes and overlapping segments */
    generated_tree = proto_tree_add_subtree(main_tree, tvb, 0, 0, ett_elf_info, &generated_item, "Infos");
    PROTO_ITEM_SET_GENERATED(generated_item);

    blackhole_tree = proto_tree_add_subtree(generated_tree, tvb, 0, 0, ett_elf_black_holes, NULL, "Backholes");
    overlapping_tree = proto_tree_add_subtree(generated_tree, tvb, 0, 0, ett_elf_overlapping, NULL, "Overlapping");

    /* sorting... */
    for (i = 0; i < area_counter; i += 1) {
        segment_info_t   tmp_segment;
        segment_info_t  *min_offset_segment;

        min_offset_segment = &segment_info[i];

        for (i_next = i + 1; i_next <  area_counter; i_next += 1) {
            if (min_offset_segment->offset <= segment_info[i_next].offset) continue;

            tmp_segment = *min_offset_segment;
            *min_offset_segment = segment_info[i_next];
            segment_info[i_next] = tmp_segment;
        }
    }

    for (i = 1; i < area_counter; i += 1) {
        if (segment_info[i - 1].offset + segment_info[i - 1].size < segment_info[i].offset) {
            /* blackhole */
            len = (guint) (segment_info[i].offset - segment_info[i - 1].offset - segment_info[i - 1].size);

            ti = proto_tree_add_uint_format(blackhole_tree, hf_elf_blackhole_size, tvb, value_guard(segment_info[i].offset - len), 1, len,
                    "Blackhole between: %s and %s, size: %u", segment_info[i - 1].name, segment_info[i].name, len);
            proto_item_set_len(ti, len);

        } else if (segment_info[i - 1].offset + segment_info[i - 1].size > segment_info[i].offset) {
            /* overlapping */
            len = (guint) (segment_info[i - 1].offset + segment_info[i - 1].size - segment_info[i].offset);

            ti = proto_tree_add_uint_format(overlapping_tree, hf_elf_overlapping_size, tvb, value_guard(segment_info[i - 1].offset + segment_info[i - 1].size - len), 1, len,
                    "Overlapping between: %s and %s, size: %u", segment_info[i - 1].name, segment_info[i].name, len);
            proto_item_set_len(ti, len);

            file_size -= len;
        }
    }

    if (segment_info[area_counter - 1].offset + segment_info[area_counter - 1].size < tvb_captured_length(tvb)) {
            len = tvb_captured_length(tvb) - (guint) (segment_info[area_counter - 1].offset - segment_info[area_counter - 1].size);

            ti = proto_tree_add_uint_format(blackhole_tree, hf_elf_blackhole_size, tvb,
                    value_guard(segment_info[area_counter - 1].offset +
                    segment_info[area_counter - 1].size), 1,
                    len, "Blackhole between: %s and <EOF>, size: %u",
                    segment_info[area_counter - 1].name, len);
            proto_item_set_len(ti, len);
    }

    proto_tree_add_uint(generated_tree, hf_elf_file_size, tvb, 0, 0, tvb_captured_length(tvb));
    proto_tree_add_uint(generated_tree, hf_elf_header_segment_size, tvb, 0, 0, (guint)file_size);
    proto_tree_add_uint(generated_tree, hf_elf_blackholes_size, tvb, 0, 0, tvb_captured_length(tvb) - (guint)file_size);

    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, "(ELF)");

    /* We jumping around offsets, so treat as bytes as read */
    return tvb_captured_length(tvb);
}

static gboolean
dissect_elf_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_elf(tvb, pinfo, tree, NULL) > 0;
}

void
proto_register_elf(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        /* Header */
        { &hf_elf_magic_bytes,
            { "Magic Bytes",                               "elf.magic_bytes",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_file_size,
            { "File size",                                 "elf.file_size",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_header_segment_size,
            { "Header size + all segment size",            "elf.header_segment_size",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_blackholes_size,
            { "Total blackholes size",                     "elf.blackholes_size",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_blackhole_size,
            { "Blackhole size",                            "elf.blackhole_size",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "Blackhole size between sections or program headers", HFILL }
        },
        { &hf_elf_overlapping_size,
            { "Overlapping size",                          "elf.overlapping_size",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "Overlapping size between sections or program headers", HFILL }
        },
        { &hf_elf_segment,
            { "Segment",                                   "elf.segment",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_entry_bytes,
            { "Entry",                                   "elf.entry_bytes",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_file_class,
            { "File Class",                                "elf.file_class",
            FT_UINT8, BASE_HEX, VALS(class_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_elf_data_encoding,
            { "Data Encoding",                             "elf.data_encoding",
            FT_UINT8, BASE_HEX, VALS(data_encoding_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_elf_file_version,
            { "File Version",                              "elf.file_version",
            FT_UINT8, BASE_HEX, VALS(version_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_elf_os_abi,
            { "OS ABI",                                    "elf.os_abi",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &os_abi_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_abi_version,
            { "ABI Version",                               "elf.abi_version",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_file_padding,
            { "File Padding",                              "elf.file_padding",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_type,
            { "Type",                                      "elf.type",
            FT_UINT16, BASE_HEX, VALS(type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_elf_machine,
            { "Machine",                                   "elf.machine",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &machine_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_version,
            { "Version",                                   "elf.version",
            FT_UINT32, BASE_HEX, VALS(version_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_elf_entry,
            { "Entry",                                     "elf.entry",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            "This member gives the virtual address to which the system first transfers control, thus starting the process. If the file has no associated entry point, this member holds zero. ", HFILL }
        },
        { &hf_elf64_entry,
            { "Entry",                                     "elf.entry64",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            "This member gives the virtual address to which the system first transfers control, thus starting the process. If the file has no associated entry point, this member holds zero. ", HFILL }
        },
        { &hf_elf_phoff,
            { "Program Header Table File Offset",          "elf.phoff",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member holds the program header table's file offset in bytes. If the file has no program header table, this member holds zero.", HFILL }
        },
        { &hf_elf64_phoff,
            { "Program Header Table File Offset",          "elf.phoff64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "This member holds the program header table's file offset in bytes. If the file has no program header table, this member holds zero.", HFILL }
        },
        { &hf_elf_shoff,
            { "Section Header Table File Offset",          "elf.shoff",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member holds the section header table's file offset in bytes. If the file has no section header table, this member holds zero.", HFILL }
        },
        { &hf_elf64_shoff,
            { "Section Header Table File Offset",          "elf.shoff64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "This member holds the section header table's file offset in bytes. If the file has no section header table, this member holds zero.", HFILL }
        },
        { &hf_elf_flags, /* TODO: dissect flags */
            { "Flags",                                     "elf.flags",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            "This member holds processor-specific flags associated with the file. Flag names take the form EF_machine_flag.", HFILL }
        },
        { &hf_elf_ehsize,
            { "ELF Header Size",                           "elf.ehsize",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            "This member holds the ELF header's size in bytes.", HFILL }
        },
        { &hf_elf_phentsize,
            { "Entry Size in Program Header Table",        "elf.phentsize",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            "This member holds the size in bytes of one entry in the file's program header table; all entries are the same size.", HFILL }
        },
        { &hf_elf_phnum,
            { "Number of Entries in the Program Header Table",  "elf.phnum",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            "This member holds the number of entries in the program header table. Thus the product of e_phentsize and e_phnum gives the table's size in bytes. If a file has no program header table, e_phnum holds the value zero.", HFILL }
        },
        { &hf_elf_shentsize,
            { "Entry Size in Section Header Table",        "elf.shentsize",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            "This member holds a section header's size in bytes. A section header is one entry in the section header table; all entries are the same size.", HFILL }
        },
        { &hf_elf_shnum,
            { "Number of Entries in the Section Header Table",  "elf.shnum",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            "This member holds the number of entries in the section header table. Thus the product of e_shentsize and e_shnum gives the section header table's size in bytes. If a file has no section header table, e_shnum holds the value zero.", HFILL }
        },
        { &hf_elf_shstrndx,
            { "Section Header Table String Index",         "elf.shstrndx",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            "This member holds the section header table index of the entry associated with the section name string table. If the file has no section name string table, this member holds the value SHN_UNDEF.", HFILL }
        },
        /* Program Header */
        { &hf_elf_p_type,
            { "Element Type",                              "elf.p_type",
            FT_UINT32, BASE_HEX_DEC, VALS(p_type_vals), 0x00,
            "This member tells what kind of segment this array element describes or how to interpret the array element's information.", HFILL }
        },
        { &hf_elf_p_type_operating_system_specific,
            { "Element Type: Operating System Specific",   "elf.p_type",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            "This member tells what kind of segment this array element describes or how to interpret the array element's information.", HFILL }
        },
        { &hf_elf_p_type_processor_specific,
            { "Element Type: Processor Specific",          "elf.p_type",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            "This member tells what kind of segment this array element describes or how to interpret the array element's information.", HFILL }
        },
        { &hf_elf_p_offset,
            { "File Offset",                               "elf.p_offset",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the offset from the beginning of the file at which the first byte of the segment resides.", HFILL }
        },
        { &hf_elf64_p_offset,
            { "File Offset",                               "elf.p_offset64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the offset from the beginning of the file at which the first byte of the segment resides.", HFILL }
        },
        { &hf_elf_p_vaddr,
            { "Virtual Address",                           "elf.p_vaddr",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            "This member gives the virtual address at which the first byte of the segment resides in memory.", HFILL }
        },
        { &hf_elf64_p_vaddr,
            { "Virtual Address",                           "elf.p_vaddr64",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            "This member gives the virtual address at which the first byte of the segment resides in memory.", HFILL }
        },
        { &hf_elf_p_paddr,
            { "Physical Address",                          "elf.p_paddr",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            "On systems for which physical addressing is relevant, this member is reserved for the segment's physical address. Because System V ignores physical addressing for application programs, this member has unspecified contents for executable files and shared objects.", HFILL }
        },
        { &hf_elf64_p_paddr,
            { "Physical Address",                          "elf.p_paddr64",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            "On systems for which physical addressing is relevant, this member is reserved for the segment's physical address. Because System V ignores physical addressing for application programs, this member has unspecified contents for executable files and shared objects.", HFILL }
        },
        { &hf_elf_p_filesz,
            { "File Image Size",                           "elf.p_filesz",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the number of bytes in the file image of the segment; it may be zero.", HFILL }
        },
        { &hf_elf64_p_filesz,
            { "File Image Size",                           "elf.p_filesz64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the number of bytes in the file image of the segment; it may be zero.", HFILL }
        },
        { &hf_elf_p_memsz,
            { "Memory Image Size",                         "elf.p_memsz",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the number of bytes in the memory image of the segment; it may be zero.", HFILL }
        },
        { &hf_elf64_p_memsz,
            { "Memory Image Size",                         "elf.p_memsz64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the number of bytes in the memory image of the segment; it may be zero.", HFILL }
        },
        { &hf_elf_p_flags_processor_specific,
            { "Processor Specific Flags",                  "elf.p_flags.maskproc",
            FT_BOOLEAN, 32, NULL, 0xF0000000,
            NULL, HFILL }
        },
        { &hf_elf_p_flags_operating_system_specific,
            { "Operating System Specific Flags",           "elf.p_flags.maskos",
            FT_BOOLEAN, 32, NULL, 0x0FF00000,
            NULL, HFILL }
        },
        { &hf_elf_p_flags_reserved,
            { "Reserrved Flags",                           "elf.p_flags.reserved",
            FT_BOOLEAN, 32, NULL, 0x000FFFF8,
            NULL, HFILL }
        },
        { &hf_elf_p_flags_read,
            { "Read Flag",                                 "elf.p_flags.read",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_elf_p_flags_write,
            { "Write Flag",                                "elf.p_flags.write",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_elf_p_flags_execute,
            { "Execute Flag",                              "elf.p_flags.execute",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_elf_p_align,
            { "Align",                                     "elf.p_align",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the value to which the segments are aligned in memory and in the file. Values 0 and 1 mean no alignment is required. Otherwise, p_align should be a positive, integral power of 2, and p_vaddr should equal p_offset, modulo p_align.", HFILL }
        },
        { &hf_elf64_p_align,
            { "Align",                                     "elf.p_align64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the value to which the segments are aligned in memory and in the file. Values 0 and 1 mean no alignment is required. Otherwise, p_align should be a positive, integral power of 2, and p_vaddr should equal p_offset, modulo p_align.", HFILL }
        },
        /* Section Header */
        { &hf_elf_sh_name,
            { "Name Index",                                "elf.sh_name",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "Section Name. Its value is an index into the section header string table section, giving the location of a null-terminated string.", HFILL }
        },
        { &hf_elf_sh_type,
            { "Type",                                      "elf.sh_type",
            FT_UINT32, BASE_HEX_DEC | BASE_EXT_STRING, &sh_type_vals_ext, 0x00,
            "This member categorizes the section's contents and semantics.", HFILL }
        },
        { &hf_elf_sh_type_operating_system_specific,
            { "Type: Operating System Specific",           "elf.sh_type",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            "This member categorizes the section's contents and semantics.", HFILL }
        },
        { &hf_elf_sh_type_processor_specific,
            { "Type: Procesor Specific",                   "elf.sh_type",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            "This member categorizes the section's contents and semantics.", HFILL }
        },
        { &hf_elf_sh_type_user_specific,
            { "Type: User Specific",                       "elf.sh_type",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            "This member categorizes the section's contents and semantics.", HFILL }
        },
        { &hf_elf_sh_flags_processor_specific,
            { "Processor Specific Flags",                  "elf.sh_flags.maskproc",
            FT_BOOLEAN, 32, NULL, 0xF0000000,
            NULL, HFILL }
        },
        { &hf_elf_sh_flags_operating_system_specific,
            { "Operating System Specific Flags",           "elf.sh_flags.maskos",
            FT_BOOLEAN, 32, NULL, 0x0FF00000,
            NULL, HFILL }
        },
        { &hf_elf_sh_flags_reserved,
            { "Reserved",                                  "elf.sh_flags.reserved",
            FT_BOOLEAN, 32, NULL, 0x000FF800,
            NULL, HFILL }
        },
        { &hf_elf_sh_flags_tls,
            { "TLS Flag",                                  "elf.sh_flags.tls",
            FT_BOOLEAN, 32, NULL, 0x00000400,
            "This section holds Thread-Local Storage, meaning that each separate execution flow has its own distinct instance of this data. Implementations need not support this flag.", HFILL }
        },
        { &hf_elf_sh_flags_group,
            { "Group Flag",                                "elf.sh_flags.group",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            "This section is a member (perhaps the only one) of a section group.", HFILL }
        },
        { &hf_elf_sh_flags_os_nonconforming,
            { "OS NonConforming Flag",                     "elf.sh_flags.os_nonconforming",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            "This section requires special OS-specific processing to avoid incorrect behavior.", HFILL }
        },
        { &hf_elf_sh_flags_link_order,
            { "Link Order Flag",                           "elf.sh_flags.link_order",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            "This flag adds special ordering requirements for link editors.", HFILL }
        },
        { &hf_elf_sh_flags_info_link,
            { "Info Link Flag",                            "elf.sh_flags.info_link",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            "The sh_info field of this section header holds a section header table index.", HFILL }
        },
        { &hf_elf_sh_flags_strings,
            { "Strings Flag",                              "elf.sh_flags.strings",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            "The data elements in the section consist of null-terminated character strings. The size of each character is specified in the section header's sh_entsize field.", HFILL }
        },
        { &hf_elf_sh_flags_merge,
            { "Merge Flag",                                "elf.sh_flags.merge",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            "The data in the section may be merged to eliminate duplication.", HFILL }
        },
        { &hf_elf_sh_flags_reserved_8,
            { "Reserved",                                  "elf.sh_flags.reserved.8",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_elf_sh_flags_exec_instr,
            { "Exec Instr Flag",                           "elf.sh_flags.exec_instr",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            "The section contains executable machine instructions.", HFILL }
        },
        { &hf_elf_sh_flags_alloc,
            { "Alloc Flag",                                "elf.sh_flags.alloc",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            "The section occupies memory during process execution. Some control sections do not reside in the memory image of an object file; this attribute is off for those sections.", HFILL }
        },
        { &hf_elf_sh_flags_write,
            { "Write Flag",                                "elf.sh_flags.write",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            "The section contains data that should be writable during process execution.", HFILL }
        },
        { &hf_elf_sh_addr,
            { "Address",                                   "elf.sh_addr",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            "If the section will appear in the memory image of a process, this member gives the address at which the section's first byte should reside. Otherwise, the member contains 0.", HFILL }
        },
        { &hf_elf64_sh_addr,
            { "Address",                                   "elf.sh_addr64",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            "If the section will appear in the memory image of a process, this member gives the address at which the section's first byte should reside. Otherwise, the member contains 0.", HFILL }
        },
        { &hf_elf_sh_offset,
            { "File Offset",                               "elf.sh_offset",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member's value gives the byte offset from the beginning of the file to the first byte in the section. One section type, SHT_NOBITS, occupies no space in the file, and its sh_offset member locates the conceptual placement in the file.", HFILL }
        },
        { &hf_elf64_sh_offset,
            { "File Offset",                               "elf.sh_offset64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "This member's value gives the byte offset from the beginning of the file to the first byte in the section. One section type, SHT_NOBITS, occupies no space in the file, and its sh_offset member locates the conceptual placement in the file.", HFILL }
        },
        { &hf_elf_sh_size,
            { "Size",                                      "elf.sh_size",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the section's size in bytes.", HFILL }
        },
        { &hf_elf64_sh_size,
            { "Size",                                      "elf.sh_size64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "This member gives the section's size in bytes.", HFILL }
        },

        { &hf_elf_sh_link,
            { "Link Index",                                "elf.sh_link",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member holds a section header table index link, whose interpretation depends on the section type.", HFILL }
        },
        { &hf_elf_sh_info,
            { "Info",                                      "elf.sh_info",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "This member holds extra information, whose interpretation depends on the section type.", HFILL }
        },
        { &hf_elf_sh_addralign,
            { "Address Alignment",                         "elf.sh_addralign",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            "Some sections have address alignment constraints. Currently, only 0 and positive integral powers of two are allowed. Values 0 and 1 mean the section has no alignment constraints.", HFILL }
        },
        { &hf_elf64_sh_addralign,
            { "Address Alignment",                         "elf.sh_addralign64",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            "Some sections have address alignment constraints. Currently, only 0 and positive integral powers of two are allowed. Values 0 and 1 mean the section has no alignment constraints.", HFILL }
        },
        { &hf_elf_sh_entsize,
            { "Entry Size",                                "elf.sh_entsize",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "Some sections hold a table of fixed-size entries, such as a symbol table. For such a section, this member gives the size in bytes of each entry. The member contains 0 if the section does not hold a table of fixed-size entries.", HFILL }
        },
        { &hf_elf64_sh_entsize,
            { "Entry Size",                                "elf.sh_entsize64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "Some sections hold a table of fixed-size entries, such as a symbol table. For such a section, this member gives the size in bytes of each entry. The member contains 0 if the section does not hold a table of fixed-size entries.", HFILL }
        },
        /* .eh_frame */
        { &hf_elf_eh_frame_length,
            { "Length",                                    "elf.eh_frame.length",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "Length of CIE. Zero indicates a terminator, 0xffffffff means that "
            "the Extended Length field contains the actual length.", HFILL }
        },
        { &hf_elf_eh_frame_extended_length,
            { "Extended Length",                           "elf.eh_frame.extended_length",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "Extended Length of CIE.", HFILL }
        },
        { &hf_elf_eh_frame_cie_id,
            { "CIE ID",                                    "elf.eh_frame.cie_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "A 4 byte unsigned value that is used to distinguish CIE records from FDE records. This value shall always be 0, which indicates this record is a CIE.", HFILL }
        },
        { &hf_elf_eh_frame_version,
            { "Version",                                   "elf.eh_frame.version",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "A 1 byte value that identifies the version number of the frame information structure. This value shall be 1.", HFILL }
        },
        { &hf_elf_eh_frame_augmentation_string,
            { "Augmentation String",                       "elf.eh_frame.augmentation_string",
            FT_STRINGZ, BASE_NONE, NULL, 0x00,
            "This value is a NUL terminated string that identifies the augmentation to the CIE or to the FDEs associated with this CIE. A zero length string indicates that no augmentation data is present. The augmentation string is case sensitive.", HFILL }
        },
        { &hf_elf_eh_frame_code_alignment_factor,
            { "Code Alignment Factor",                     "elf.eh_frame.code_alignment_factor",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            "An unsigned LEB128 encoded value that is factored out of all advance location instructions that are associated with this CIE or its FDEs. This value shall be multiplied by the delta argument of an adavance location instruction to obtain the new location value.", HFILL }
        },
        { &hf_elf_eh_frame_data_alignment_factor,
            { "Data Alignment Factor",                     "elf.eh_frame.data_alignment_factor",
            FT_INT64, BASE_DEC, NULL, 0x00,
            "A signed LEB128 encoded value that is factored out of all offset instructions that are associated with this CIE or its FDEs. This value shall be multiplied by the register offset argument of an offset instruction to obtain the new offset value.", HFILL }
        },
        { &hf_elf_eh_frame_return_address_register,
            { "Return Address Register",                   "elf.eh_frame.return_address_register",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            "An unsigned LEB128 constant that indicates which column in the rule table represents the return address of the function. Note that this column might not correspond to an actual machine register.", HFILL }
        },
        { &hf_elf_eh_frame_augmentation_length,
            { "Augmentation Length",                       "elf.eh_frame.augmentation_length",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            "An unsigned LEB128 encoded value indicating the length in bytes of the Augmentation Data. This field is only present if the Augmentation String contains the character 'z'.", HFILL }
        },
        { &hf_elf_eh_frame_augmentation_data,
            { "Augmentation Data",                         "elf.eh_frame.augmentation_data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "A block of data whose contents are defined by the contents of the Augmentation String as described below. This field is only present if the Augmentation String contains the character 'z'.", HFILL }
        },
        { &hf_elf_eh_frame_initial_instructions,
            { "Initial Instructions",                      "elf.eh_frame.initial_instructions",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "Initial set of Call Frame Instructions.", HFILL }
        },
        /* .eh_frame fde */
        { &hf_elf_eh_frame_fde_length,
            { "Length",                                    "elf.eh_frame.fde.length",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "Length of FDE. Zero indicates a terminator, 0xffffffff means that "
            "the Extended Length field contains the actual length.", HFILL }
        },
        { &hf_elf_eh_frame_fde_extended_length,
            { "Extended Length",                           "elf.eh_frame.fde.extended_length",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            "Extended Length of FDE.", HFILL }
        },
        { &hf_elf_eh_frame_fde_cie_pointer,
            { "CIE Pointer",                               "elf.eh_frame.fde.cie_pointer",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "A 4 byte unsigned value that when subtracted from the offset of the the CIE Pointer in the current FDE yields the offset of the start of the associated CIE. This value shall never be 0.", HFILL }
        },
        { &hf_elf_eh_frame_fde_pc_begin,
            { "PC Begin",                                  "elf.eh_frame.fde.pc_begin",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            "An encoded value that indicates the address of the initial location associated with this FDE. The encoding format is specified in the Augmentation Data.", HFILL }
        },
        { &hf_elf_eh_frame_fde_pc_range,
            { "PC Range",                                  "elf.eh_frame.fde.pc_range",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "An absolute value that indicates the number of bytes of instructions associated with this FDE.", HFILL }
        },
        { &hf_elf_eh_frame_fde_augmentation_length,
            { "Augmentation Length",                       "elf.eh_frame.fde.augmentation_length",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            "An unsigned LEB128 encoded value indicating the length in bytes of the Augmentation Data.", HFILL }
        },
        { &hf_elf_eh_frame_fde_augmentation_data,
            { "Augmentation Data",                         "elf.eh_frame.fde.augmentation_data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "Data as described by the Augmentation String in the CIE.", HFILL }
        },
        { &hf_elf_eh_frame_fde_call_frame_instructions,
            { "Call Frame Instructions",                   "elf.eh_frame.fde.call_frame_instructions",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "A set of Call Frame Instructions.", HFILL }
        },
        /* .eh_frame_hdr */
        { &hf_elf_eh_frame_hdr_version,
            { "Version",                                   "elf.eh_frame_hdr.version",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "Version of the .eh_frame_hdr format. This value shall be 1.", HFILL }
        },
        { &hf_elf_eh_frame_hdr_exception_frame_pointer_encoding,
            { "Exception Frame Pointer Encoding",           "elf.eh_frame_hdr.eh_frame_ptr_enc",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "The encoding format of the eh_frame_ptr field.", HFILL }
        },
        { &hf_elf_eh_frame_hdr_fde_count_encoding,
            { "FDE Count Encoding",                        "elf.eh_frame_hdr.fde_count_enc",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "The encoding format of the fde_count field. A value of DW_EH_PE_omit indicates the binary search table is not present.", HFILL }
        },
        { &hf_elf_eh_frame_hdr_binary_search_table_encoding,
            { "Binary Search Table Encoding",              "elf.eh_frame_hdr.binary_search_table_encoding",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "The encoding format of the entries in the binary search table. A value of DW_EH_PE_omit indicates the binary search table is not present.", HFILL }
        },


        { &hf_elf_eh_frame_hdr_eh_frame_ptr,
            { "Exception Frame Pointer",                    "elf.eh_frame_hdr.eh_frame_ptr",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "Start of .eh_frame pointer", HFILL }
        },
        { &hf_elf_eh_frame_hdr_fde_count,
            { "Number of FDE entries",                     "elf.eh_frame_hdr.fde_count",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_eh_frame_hdr_binary_search_table_entry_initial_location,
            { "Initial location",                          "elf.eh_frame_hdr.binary_search_table_entry.initial_location",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_eh_frame_hdr_binary_search_table_entry_address,
            { "Address",                                   "elf.eh_frame_hdr.binary_search_table_entry.address",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },

        /* symbol_table */
        { &hf_elf_symbol_table_name_index,
            { "Name Index",                               "elf.symbol_table.name_index",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_symbol_table_info,
            { "Info",                                      "elf.symbol_table.info",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_symbol_table_info_bind,
            { "Bind",                                      "elf.symbol_table.info.bind",
            FT_UINT8, BASE_HEX, VALS(symbol_table_info_bind_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_elf_symbol_table_info_type,
            { "Type",                                      "elf.symbol_table.info.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &symbol_table_info_type_vals_ext, 0x0F,
            NULL, HFILL }
        },
        { &hf_elf_symbol_table_other,
            { "Other",                                     "elf.symbol_table.other",
            FT_UINT8, BASE_HEX, VALS(symbol_table_other_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_elf_symbol_table_shndx,
            { "Releated Section Header Index",             "elf.symbol_table.shndx",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(symbol_table_shndx_rvals), 0x00,
            NULL, HFILL }
        },
        { &hf_elf_symbol_table_value,
            { "Value",                                     "elf.symbol_table.value",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf64_symbol_table_value,
            { "Value",                                     "elf.symbol_table.value64",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_symbol_table_size,
            { "Size",                                      "elf.symbol_table.size",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf64_symbol_table_size,
            { "Size",                                      "elf.symbol_table.size64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },

        /* dynamic */
        { &hf_elf_dynamic_tag,
            { "Tag",                                       "elf.dynamic.tag",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(dynamic_tag_rvals), 0x00,
            NULL, HFILL }
        },
        { &hf_elf_dynamic_value,
            { "Value",                                     "elf.dynamic.value",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_dynamic_pointer,
            { "Pointer",                                   "elf.dynamic.pointer",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_dynamic_ignored,
            { "Ignored",                                   "elf.dynamic.ignored",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf_dynamic_unspecified,
            { "Unspecified",                               "elf.dynamic.unspecified",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf64_dynamic_tag,
            { "Tag",                                       "elf.dynamic.tag64",
            FT_UINT64, BASE_HEX /*| BASE_RANGE_STRING*/, NULL /*RVALS(dynamic_tag_rvals)*/, 0x00,
            NULL, HFILL }
        },
        { &hf_elf64_dynamic_value,
            { "Value",                                     "elf.dynamic.value64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf64_dynamic_pointer,
            { "Pointer",                                   "elf.dynamic.pointer64",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf64_dynamic_ignored,
            { "Ignored",                                   "elf.dynamic.ignored64",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_elf64_dynamic_unspecified,
            { "Unspecified",                               "elf.dynamic.unspecified64",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },

        /* dwarf */
        { &hf_dwarf_omit,
            { "DW_EH_PE_omit",                             "elf.dwarf.omit",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            "Used to indicate that no value is present.", HFILL }
        },
        { &hf_dwarf_upper,
            { "DWARF Exception Header application",        "elf.dwarf.upper",
            FT_UINT8, BASE_HEX, VALS(eh_dwarf_upper), 0xF0,
            "The upper 4 bits indicate how the value is to be applied.", HFILL }
        },
        { &hf_dwarf_format,
            { "DWARF Exception Header value format",       "elf.dwarf.format",
            FT_UINT8, BASE_HEX, VALS(eh_dwarf_format), 0x0F,
            "The lower 4 bits indicate the format of the data.", HFILL }
        },
        { &hf_elf_string,
            { "String",                                    "elf.string",
            FT_STRINGZ, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_invalid_segment_size, { "elf.invalid_segment_size", PI_PROTOCOL, PI_WARN, "Segment size is different then currently parsed bytes", EXPFILL }},
        { &ei_invalid_entry_size,   { "elf.invalid_entry_size", PI_PROTOCOL, PI_WARN, "Entry size is different then currently parsed bytes", EXPFILL }},
        { &ei_cfi_extraneous_data,  { "elf.cfi_extraneous_data", PI_PROTOCOL, PI_WARN, "Segment size is larger than CFI records combined", EXPFILL }},
        { &ei_invalid_cie_length,   { "elf.invalid_cie_length", PI_PROTOCOL, PI_ERROR, "CIE length is too small or larger than segment size", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_elf,
        &ett_elf_header,
        &ett_elf_program_header,
        &ett_elf_program_header_entry,
        &ett_elf_section_header,
        &ett_elf_section_header_entry,
        &ett_elf_segment,
        &ett_elf_cfi_record,
        &ett_elf_cie_entry,
        &ett_elf_fde_entry,
        &ett_elf_cie_terminator,
        &ett_elf_info,
        &ett_elf_black_holes,
        &ett_elf_overlapping,
        &ett_dwarf_encoding,
        &ett_binary_table,
        &ett_binary_table_entry,
        &ett_symbol_table_entry,
        &ett_symbol_table_info
    };

    proto_elf = proto_register_protocol("Executable and Linkable Format", "ELF", "elf");
    proto_register_field_array(proto_elf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    elf_handle = register_dissector("elf", dissect_elf, proto_elf);

    module = prefs_register_protocol(proto_elf, NULL);
    prefs_register_static_text_preference(module, "version",
            "ELF version: 4.1 DRAFT",
            "Version of file-format supported by this dissector.");

    expert_module = expert_register_protocol(proto_elf);
    expert_register_field_array(expert_module, ei, array_length(ei));
}

void
proto_reg_handoff_elf(void)
{
    dissector_add_string("media_type", "application/x-executable", elf_handle);
    dissector_add_string("media_type", "application/x-coredump", elf_handle);
    dissector_add_string("media_type", "application/x-object", elf_handle);
    dissector_add_string("media_type", "application/x-sharedlib", elf_handle);

    /* XXX - TEMPORARY HACK */
    dissector_add_uint("ftap_encap", 1234, elf_handle);

    heur_dissector_add("wtap_file", dissect_elf_heur, "ELF file", "elf_wtap", proto_elf, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
