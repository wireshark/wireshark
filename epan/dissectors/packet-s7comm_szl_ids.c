/* packet-s7comm_szl_ids.c
 *
 * Author:      Thomas Wiens, 2014 (th.wiens@gmx.de)
 * Description: Wireshark dissector for S7-Communication
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-s7comm.h"
#include "packet-s7comm_szl_ids.h"

static gint ett_s7comm_szl = -1;
static gint hf_s7comm_userdata_szl_partial_list = -1;           /* Partial list in szl response */
static gint hf_s7comm_userdata_szl_id = -1;                     /* SZL id */

static const value_string szl_module_type_names[] = {
    { 0x0000,                               "CPU" },            /* Binary: 0000 */
    { 0x0100,                               "IM" },             /* Binary: 0100 */
    { 0xC000,                               "CP" },             /* Binary: 1100 */
    { 0x8000,                               "FM" },             /* Binary: 1000 */
    { 0,                                    NULL }
};
static gint hf_s7comm_userdata_szl_id_type = -1;
static gint hf_s7comm_userdata_szl_id_partlist_ex = -1;
static gint hf_s7comm_userdata_szl_id_partlist_num = -1;
static gint hf_s7comm_userdata_szl_id_partlist_len = -1;
static gint hf_s7comm_userdata_szl_id_partlist_cnt = -1;
static gint ett_s7comm_userdata_szl_id = -1;
static int * const s7comm_userdata_szl_id_fields[] = {
    &hf_s7comm_userdata_szl_id_type,
    &hf_s7comm_userdata_szl_id_partlist_ex,
    &hf_s7comm_userdata_szl_id_partlist_num,
    NULL
};
/* Partial list extract names */
static const value_string szl_id_partlist_ex_names[] = {
    { 0x0000,                               "All SZL partial lists of the module" },
    { 0x0011,                               "All identification data records of a module" },
    { 0x0012,                               "All characteristics" },
    { 0x0013,                               "Data records of all memory areas" },
    { 0x0014,                               "All system areas of a module" },
    { 0x0015,                               "Data records of all block types of a module" },
    { 0x0016,                               "Data records of all priority classes" },
    { 0x0017,                               "All SDBs of a module" },
    { 0x0018,                               "All data records" },
    { 0x0019,                               "Status of all LEDs" },
    { 0x001c,                               "Identification of all components" },
    { 0x0021,                               "Data records of all possible interrupts on a module" },
    { 0x0022,                               "Data records of all possible interrupts on a module" },
    { 0x0023,                               "Data records of all priority classes of a module" },
    { 0x0024,                               "All modules that can occur on the module" },
    { 0x0031,                               "Not defined" },
    { 0x0033,                               "All stations logged on for messages and diagnostic events" },
    { 0x0037,                               "Details of all Ethernet interfaces" },
    { 0x0071,                               "Information about the current status of the H system" },
    { 0x0074,                               "Status of all LEDs" },
    { 0x0081,                               "Startup information of all OBs" },
    { 0x0082,                               "All startup events" },
    { 0x0090,                               "Information of all DP master systems known to the CPU" },
    { 0x0091,                               "Module status information of all plugged in modules and submodules" },
    { 0x0092,                               "Expected status of the central racks/stations of a DP master system connected via an integrated DP interface" },
    { 0x0094,                               "Expected status of the rack in the central configuration/the stations of a DP master system/IO controller system that is connected via an integrated DP/PN interface module" },
    { 0x0095,                               "Extended information on a DP master system/PROFINET IO system" },
    { 0x00a0,                               "All entries possible in the current mode" },
    { 0x00b1,                               "Obtain the first 4 diagnostic bytes of a module with diagnostic capability" },
    { 0x00b2,                               "Obtain diagnostic data record 1 of a module in a central rack, rack/slot specified by index" },
    { 0x00b3,                               "Obtain diagnostic data of a module, logical base address specified by index" },
    { 0x00b4,                               "Obtain diagnostic data of a DP slave, diagnostic address of the module specified by index" },
    { 0x0100,                               "A partial list with all partial list extracts" },
    { 0x0111,                               "A single identification data record" },
    { 0x0112,                               "Characteristics of a group, specified by index" },
    { 0x0113,                               "Data record for one memory area, specified by index" },
    { 0x0114,                               "One system area, specified by index" },
    { 0x0115,                               "Data record of a block type, specified by index" },
    { 0x0116,                               "Data record of the specified priority class, specified by index" },
    { 0x0117,                               "One single SDB, specified by index" },
    { 0x0118,                               "One data record, specified by index" },
    { 0x0119,                               "Status of one LED, specified by index" },
    { 0x011c,                               "Identification of one component" },
    { 0x0121,                               "Data records of all possible interrupts of one class, class specified by index" },
    { 0x0122,                               "Data records of all possible interrupts of one class, class specified by index" },
    { 0x0123,                               "Data record of one priority class, specified by index" },
    { 0x0124,                               "Information about the last mode transition" },
    { 0x0131,                               "Information about a communication unit, specified by index" },
    { 0x0132,                               "Status data for one communication section of the CPU, section specified by index" },
    { 0x0137,                               "Details of one Ethernet interface" },
    { 0x0174,                               "Status of an LED, specified by index" },
    { 0x0181,                               "Startup information of all synchronous error OBs" },
    { 0x0182,                               "Startup events of all synchronous error OBs" },
    { 0x0190,                               "Information of one DP master system" },
    { 0x0191,                               "Status information of all modules/racks with wrong type identifier" },
    { 0x01a0,                               "The most recent entries, the number of most recent entries specified by index" },
    { 0x0200,                               "A partial list extract" },
    { 0x021c,                               "Identification of all components of a CPU in an H system" },
    { 0x0221,                               "Data records for the specified interrupt, interrupt (OB no.) specified by index" },
    { 0x0222,                               "Data records for the specified interrupt, interrupt (OB no.) specified by index" },
    { 0x0223,                               "Data records of the priority classes being processed" },
    { 0x0224,                               "Processed mode transition" },
    { 0x0281,                               "Startup information of all synchronous error OBs of one priority class" },
    { 0x0282,                               "Startup events of all synchronous error OBs of one priority class" },
    { 0x0291,                               "Status information of all faulty modules" },
    { 0x0292,                               "Actual status of the central racks/stations of a DP master system connected via an integrated DP interface" },
    { 0x0294,                               "Actual status of the rack in the central configuration/the stations of a DP master system/IO controller system that is connected via an integrated DP/PN interface module" },
    { 0x0300,                               "Possible indexes of a partial list extract" },
    { 0x031c,                               "Identification of one component of all redundant CPUs in an H system" },
    { 0x0381,                               "Startup information of all OBs of one priority class" },
    { 0x0382,                               "Startup events of all OBs of a priority class" },
    { 0x0391,                               "Status information of all modules that are not available" },
    { 0x0392,                               "State of the battery backup of the racks in a central configuration" },
    { 0x0424,                               "Current mode transition" },
    { 0x0492,                               "State of the total backup of the racks in a central configuration" },
    { 0x04a0,                               "Start information of all standard OBs" },
    { 0x0524,                               "Specified mode transition, specified by index" },
    { 0x0581,                               "Startup information of all synchronous error OBs before processing" },
    { 0x0582,                               "Startup events of all synchronous error OBs before processing" },
    { 0x0591,                               "Status information of all submodules of the host module" },
    { 0x0592,                               "State of the 24 V power supply of the modules in a central configuration" },
    { 0x05a0,                               "All entries from communications units" },
    { 0x0681,                               "Startup information of all synchronous error OBs of a priority class before processing" },
    { 0x0682,                               "Startup events of all synchronous error OBs of a priority class before processing" },
    { 0x0692,                               "OK state of the expansion racks in the central configuration / of the stations of a DP master system connected via an integrated DP interface" },
    { 0x0694,                               "Status of the expansion racks in the central configuration/the stations of a DP master system/IO controller system that is connected via an integrated DP/PN interface module" },
    { 0x0696,                               "Module status information on all interface modules in a specified module (with PROFIBUS DP and central modules, the interface module level is not present)" },
    { 0x06a0,                               "All entries of the object management system" },
    { 0x0781,                               "Startup information of all OBs of one priority class before processing" },
    { 0x0782,                               "Startup events of all OBs of one priority class before processing" },
    { 0x07a0,                               "All entries of the test and installation function" },
    { 0x0822,                               "Data records of all interrupts of one class and for which the corresponding interrupt OB is loaded, class specified by index" },
    { 0x0881,                               "Startup information of all OBs before processing" },
    { 0x0882,                               "Startup events of all OBs before processing" },
    { 0x08a0,                               "All entries due to operating statuses" },
    { 0x0921,                               "Data records of all interrupts of one class and for which the corresponding interrupt OB is loaded, class specified by index" },
    { 0x0922,                               "Data records of all interrupts for which the corresponding interrupt OB is loaded" },
    { 0x0981,                               "Startup information of all synchronous error OBs being processed" },
    { 0x0982,                               "Startup events of all synchronous error OBs being processed" },
    { 0x0991,                               "Module status information of a DP master system" },
    { 0x09a0,                               "All entries caused by asynchronous errors" },
    { 0x0a21,                               "Data records of all interrupts for which the corresponding interrupt OB is loaded" },
    { 0x0a81,                               "Startup information of all synchronous error OBs of a priority class being processed" },
    { 0x0a82,                               "Startup events of all synchronous error OBs of a priority class being processed" },
    { 0x0a91,                               "Module status information of all DP master systems" },
    { 0x0aa0,                               "All entries caused by synchronous errors" },
    { 0x0b81,                               "Startup information of all OBs of one priority class being processed" },
    { 0x0b82,                               "Startup events of all OBs of one priority class being processed" },
    { 0x0ba0,                               "All entries caused by STOP, abort, mode transition" },
    { 0x0c75,                               "Communication status between the H system and a switched DP slave, slave specified by index" },
    { 0x0c81,                               "Startup information of all OBs being processed" },
    { 0x0c82,                               "Startup events of all OBs being processed" },
    { 0x0c91,                               "Status information of a module in the central rack or connected to an integrated DP communications processor via the logical base address" },
    { 0x0c96,                               "Module status information on a module/interface module centrally or at a PROFIBUS DP/PROFINET interface module via the start address" },
    { 0x0ca0,                               "All entries caused by fault-tolerant/fail-safe events" },
    { 0x0d91,                               "Module status information of all modules in the specified rack/in the specified station (DP or PROFINET)" },
    { 0x0da0,                               "All diagnostic entries" },
    { 0x0e91,                               "Module status information of all configured modules" },
    { 0x0ea0,                               "All user entries" },
    { 0x0f00,                               "List of all the SZL-IDs of a module, only partial list header information" },
    { 0x0f11,                               "Module identification, only partial list header information" },
    { 0x0f12,                               "CPU characteristics, only partial list header information" },
    { 0x0f13,                               "User memory areas, only partial list header information" },
    { 0x0f14,                               "System areas, only partial list header information" },
    { 0x0f15,                               "Block types, only partial list header information" },
    { 0x0f16,                               "Priority classes, only partial list header information" },
    { 0x0f17,                               "List of the permitted SDBs, only partial list header information" },
    { 0x0f18,                               "Maximum S7-300 I/O configuration, only partial list header information" },
    { 0x0f19,                               "Status of the module LEDs, only partial list header information" },
    { 0x0f1c,                               "Component Identification, only partial list header information" },
    { 0x0f21,                               "Interrupt / error assignment, only partial list header information" },
    { 0x0f22,                               "Interrupt status, only partial list header information" },
    { 0x0f23,                               "Priority classes, only partial list header information" },
    { 0x0f24,                               "Modes, only partial list header information" },
    { 0x0f31,                               "Communication capability parameters, only partial list header information" },
    { 0x0f32,                               "Communication status data, only partial list header information" },
    { 0x0f33,                               "Diagnostics: device logon list, only partial list header information" },
    { 0x0f37,                               "Ethernet - Details of a Module, only partial list header information" },
    { 0x0f71,                               "H CPU group information, only partial list header information" },
    { 0x0f81,                               "Start information list, only partial list header information" },
    { 0x0f82,                               "Start event list, only partial list header information" },
    { 0x0f90,                               "DP Master System Information, only partial list header information" },
    { 0x0f91,                               "Module status information, only partial list header information" },
    { 0x0f92,                               "Rack / station status information, only partial list header information" },
    { 0x0f94,                               "Rack / station status information, only partial list header information" },
    { 0x0f95,                               "Extended DP master system information, only partial list header information" },
    { 0x0fa0,                               "Diagnostic buffer of the CPU, only partial list header information" },
    { 0x4092,                               "Expected status of the stations of a DP master system connected via an external DP interface" },
    { 0x4292,                               "Actual status of the stations of a DP master system connected via an external DP interface" },
    { 0x4692,                               "OK state of the stations of a DP master system connected via an external DP interface" },
    { 0x4c91,                               "Status information of a module connected to an external DP communications processor via the logical base address" },
    { 0x4f92,                               "Only partial list header information of the '4x92' list" },
    { 0,                                    NULL }
};
static value_string_ext szl_id_partlist_ex_names_ext = VALUE_STRING_EXT_INIT(szl_id_partlist_ex_names);

static const value_string szl_partial_list_names[] = {
    { 0x0000,                               "List of all the SZL-IDs of a module" },
    { 0x0011,                               "Module identification" },
    { 0x0012,                               "CPU characteristics" },
    { 0x0013,                               "User memory areas" },
    { 0x0014,                               "System areas" },
    { 0x0015,                               "Block types" },
    { 0x0016,                               "Priority classes" },
    { 0x0017,                               "List of the permitted SDBs with a number < 1000" },
    { 0x0018,                               "Maximum S7-300 I/O configuration" },
    { 0x0019,                               "Status of the module LEDs" },
    { 0x001c,                               "Component Identification" },
    { 0x0021,                               "Interrupt / error assignment" },
    { 0x0022,                               "Interrupt status" },
    { 0x0023,                               "Priority classes" },
    { 0x0024,                               "Modes" },
    { 0x0025,                               "Assignment between process image partitions and OBs" },
    { 0x0031,                               "Communication capability parameters" },
    { 0x0032,                               "Communication status data" },
    { 0x0033,                               "Diagnostics: device logon list" },
    { 0x0037,                               "Ethernet - Details of a Module" },
    { 0x0071,                               "H CPU group information" },
    { 0x0074,                               "Status of the module LEDs" },
    { 0x0075,                               "Switched DP slaves in the H-system" },
    { 0x0081,                               "Start information list" },
    { 0x0082,                               "Start event list" },
    { 0x0090,                               "DP Master System Information" },
    { 0x0091,                               "Module status information" },
    { 0x0092,                               "Rack / station status information" },
    { 0x0094,                               "Rack / station status information" },
    { 0x0095,                               "Extended DP master system information" },
    { 0x0096,                               "Module status information, PROFINET IO and PROFIBUS DP" },
    { 0x00a0,                               "Diagnostic buffer of the CPU" },
    { 0x00b1,                               "Module diagnostic information (data record 0)" },
    { 0x00b2,                               "Module diagnostic information (data record 1), geographical address" },
    { 0x00b3,                               "Module diagnostic information (data record 1), logical address" },
    { 0x00b4,                               "Diagnostic data of a DP slave" },
    { 0,    NULL }
};
static value_string_ext szl_partial_list_names_ext = VALUE_STRING_EXT_INIT(szl_partial_list_names);

static gint hf_s7comm_userdata_szl_index = -1;                  /* SZL index */
static gint hf_s7comm_userdata_szl_tree = -1;                   /* SZL item tree */

/* Index description for SZL Requests */
static const value_string szl_0111_index_names[] = {
    { 0x0001,                               "Identification of the module" },
    { 0x0006,                               "Identification of the basic hardware" },
    { 0x0007,                               "Identification of the basic firmware" },
    { 0x0081,                               "Identification of the firmware-extension" },
    { 0,                                    NULL }
};

static const value_string szl_0112_index_names[] = {
    { 0x0000,                               "MC7 processing unit" },
    { 0x0100,                               "Time system" },
    { 0x0200,                               "System response" },
    { 0x0300,                               "Language description of the CPU" },
    { 0x0400,                               "Availability of SFC 87 and SFC 88" },
    { 0,                                    NULL }
};

static const value_string szl_0113_index_names[] = {
    { 0x0001,                               "Work memory" },
    { 0x0002,                               "Load memory integrated" },
    { 0x0003,                               "Load memory plugged in" },
    { 0x0004,                               "Maximum plug-in load memory" },
    { 0x0005,                               "Size of the backup memory" },
    { 0x0006,                               "Size of the memory reserved by the system for CFBs" },
    { 0,                                    NULL }
};

static const value_string szl_0114_index_names[] = {
    { 0x0001,                               "PII (number in bytes)" },
    { 0x0002,                               "PIQ (number in bytes)" },
    { 0x0003,                               "Memory (number)" },
    { 0x0004,                               "Timers (number)" },
    { 0x0005,                               "Counters (number)" },
    { 0x0006,                               "Number of bytes in the logical address area" },
    { 0x0007,                               "Size of the entire local data area of the CPU in bytes" },
    { 0x0008,                               "Memory (number in bytes)" },
    { 0x0009,                               "Local data (entire local data area of the CPU in Kbytes)" },
    { 0,                                    NULL }
};

static const value_string szl_0115_index_names[] = {
    { 0x0800,                               "OB" },
    { 0x0a00,                               "DB" },
    { 0x0b00,                               "SDB" },
    { 0x0c00,                               "FC" },
    { 0x0e00,                               "FB" },
    { 0,                                    NULL }
};

static const value_string szl_0116_index_names[] = {
    { 0x0000,                               "Free cycle" },
    { 0x000a,                               "Time-of-day interrupt" },
    { 0x0014,                               "Time-delay interrupt" },
    { 0x001e,                               "Cyclic interrupt" },
    { 0x0028,                               "Hardware interrupt" },
    { 0x0050,                               "Asynchronous error interrupt" },
    { 0x005a,                               "Background" },
    { 0x0064,                               "Startup" },
    { 0x0078,                               "Synchronous error interrupt" },
    { 0,                                    NULL }
};

static const value_string szl_0118_index_names[] = {
    { 0x0001,                               "Number of the rack: 1" },
    { 0x0002,                               "Number of the rack: 2" },
    { 0x0003,                               "Number of the rack: 3" },
    { 0x00ff,                               "Maximum number of racks (racknr) and total number of possible slots (anzst)" },
    { 0,                                    NULL }
};

static const value_string szl_0121_index_names[] = {
    { 0x0000,                               "Free cycle" },
    { 0x0a0a,                               "Time-of-day interrupt" },
    { 0x1414,                               "Time-delay interrupt" },
    { 0x1e23,                               "Cyclic interrupt" },
    { 0x2828,                               "Hardware interrupt" },
    { 0x5050,                               "Asynchronous error interrupt" },
    { 0x005a,                               "Background" },
    { 0x0064,                               "Startup" },
    { 0x7878,                               "Synchronous error interrupt" },
    { 0,                                    NULL }
};

static const value_string szl_0222_index_names[] = {
    { 0x0000,                               "Free cycle" },
    { 0x000a,                               "Time-of-day interrupt" },
    { 0x0014,                               "Time-delay interrupt" },
    { 0x001e,                               "Cyclic interrupt" },
    { 0x0028,                               "Hardware interrupt" },
    { 0x0032,                               "DP interrupt" },
    { 0x003c,                               "Multicomputing or synchronous cycle (isochrone) interrupt" },
    { 0x0048,                               "Redundancy interrupt (on with S7-400H systems)" },
    { 0x0050,                               "Asynchronous error interrupt" },
    { 0x005a,                               "Background" },
    { 0x0064,                               "Startup" },
    { 0x0078,                               "Synchronous error interrupt" },
    { 0,                                    NULL }
};

static const value_string szl_0524_index_names[] = {
    { 0x5000,                               "Mode STOP" },
    { 0x5010,                               "Mode STARTUP" },
    { 0x5020,                               "Mode RUN" },
    { 0x5030,                               "Mode HOLD" },
    { 0x4520,                               "Mode DEFECT" },
    { 0,                                    NULL }
};

static const value_string szl_0131_index_names[] = {
    { 0x0001,                               "General data for communication" },
    { 0x0002,                               "Test and installation function constants" },
    { 0x0003,                               "Operator interface (O/I)" },
    { 0x0004,                               "Object management system (OMS)" },
    { 0x0005,                               "Diagnostics" },
    { 0x0006,                               "Communication function block (CFB)" },
    { 0x0007,                               "Global data" },
    { 0x0008,                               "Test and installation function time information" },
    { 0x0009,                               "Time-of-day capability parameters" },
    { 0x0010,                               "Message parameters" },
    { 0x0011,                               "SCAN capability parameters" },
    { 0,                                    NULL }
};

static const value_string szl_0132_index_names[] = {
    { 0x0001,                               "General data for communication" },
    { 0x0002,                               "Test and installation status" },
    { 0x0003,                               "Operator interface status" },
    { 0x0004,                               "Object management system status" },
    { 0x0005,                               "Diagnostics" },
    { 0x0006,                               "Data exchange with CFBs" },
    { 0x0007,                               "Global data" },
    { 0x0008,                               "Time system" },
    { 0x0009,                               "MPI status" },
    { 0x000a,                               "Communication bus status" },
    { 0x000b,                               "32-bit runtime meters 0-7" },
    { 0x000c,                               "32-bit runtime meters 8-15" },
    { 0x0010,                               "S7-SCAN part 1" },
    { 0x0011,                               "S7-SCAN part 2" },
    { 0,                                    NULL }
};

static const value_string szl_0119_0174_ledid_index_names[] = {
    { 0x0001,                               "SF (group error)" },
    { 0x0002,                               "INTF (internal error)" },
    { 0x0003,                               "EXTF (external error)" },
    { 0x0004,                               "RUN" },
    { 0x0005,                               "STOP" },
    { 0x0006,                               "FRCE (force)" },
    { 0x0007,                               "CRST (cold restart)" },
    { 0x0008,                               "BAF (battery fault/overload, short circuit of battery voltage on bus)" },
    { 0x0009,                               "USR (user-defined)" },
    { 0x000a,                               "USR1 (user-defined)" },
    { 0x000b,                               "BUS1F (bus error interface 1)" },
    { 0x000c,                               "BUS2F (bus error interface 2)" },
    { 0x000d,                               "REDF (redundancy error)" },
    { 0x000e,                               "MSTR (master)" },
    { 0x000f,                               "RACK0 (rack number 0)" },
    { 0x0010,                               "RACK1 (rack number 1)" },
    { 0x0011,                               "RACK2 (rack number 2)" },
    { 0x0012,                               "IFM1F (interface error interface module 1)" },
    { 0x0013,                               "IFM2F (interface error interface module 2)" },
    { 0x0014,                               "BUS3F (bus fault interface 3)" },
    { 0x0015,                               "MAINT (meintenance demand)" },
    { 0x0016,                               "DC24V" },
    { 0x0080,                               "IF (init failure)" },
    { 0x0081,                               "UF (user failure)" },
    { 0x0082,                               "MF (monitoring failure)" },
    { 0x0083,                               "CF (communication failure)" },
    { 0x0084,                               "TF (task failure)" },
    { 0x00ec,                               "APPL_STATE_RED" },
    { 0x00ed,                               "APPL_STATE_GREEN" },
    { 0,                                    NULL }
};

static const value_string szl_xy1c_index_names[] = {
    { 0x0001,                               "Name of the automation system" },
    { 0x0002,                               "Name of the module" },
    { 0x0003,                               "Plant designation of the module" },
    { 0x0004,                               "Copyright entry" },
    { 0x0005,                               "Serial number of the module" },
    { 0x0007,                               "Module type name" },
    { 0x0008,                               "Serial number of the memory card" },
    { 0x0009,                               "Manufacturer and profile of a CPU module" },
    { 0x000a,                               "OEM ID of a module" },
    { 0x000b,                               "Location ID of a module" },
    { 0,                                    NULL }
};

/* Header fields of the SZL */
static gint hf_s7comm_szl_0000_0000_szl_id = -1;
static gint hf_s7comm_szl_0000_0000_module_type_class = -1;
static gint hf_s7comm_szl_0000_0000_partlist_extr_nr = -1;
static gint hf_s7comm_szl_0000_0000_partlist_nr = -1;

static gint hf_s7comm_szl_xy12_0x00_charac = -1;
static const value_string szl_xy12_cpu_characteristic_names[] = {
    { 0x0000,                               "MC7 processing unit group" },
    { 0x0001,                               "MC7 processing generating code" },
    { 0x0002,                               "MC7 interpreter" },
    { 0x0100,                               "Time system group" },
    { 0x0101,                               "1 ms resolution" },
    { 0x0102,                               "10 ms resolution" },
    { 0x0103,                               "No real time clock" },
    { 0x0104,                               "BCD time-of-day format" },
    { 0x0105,                               "All time-of-day functions (set time-of-day, set and read time-of-day, time-of-day synchronization: time-of-day slave and time-of-day master)" },
    { 0x0106,                               "SFC 78 OB_RT is available" },
    { 0x0200,                               "System response group" },
    { 0x0201,                               "Capable of multiprocessor mode" },
    { 0x0202,                               "Cold restart, warm restart and hot restart possible" },
    { 0x0203,                               "Cold restart and hot restart possible" },
    { 0x0204,                               "Warm restart and hot restart possible" },
    { 0x0205,                               "Only warm restart possible" },
    { 0x0206,                               "New distributed I/O configuration is possible during RUN by using predefined resources" },
    { 0x0207,                               "H-CPU in stand-alone mode: New distributed I/O configuration is possible during RUN by using predefined resources" },
    { 0x0208,                               "For taking motion control functionality into account" },
    { 0x0300,                               "Language description of the CPU group" },
    { 0x0301,                               "Reserved" },
    { 0x0302,                               "All 32 bit fixed-point instructions" },
    { 0x0303,                               "All floating-point instructions" },
    { 0x0304,                               "sin, asin, cos, acos, tan, atan, sqr, sqrt, ln, exp" },
    { 0x0305,                               "Accumulator 3/accumulator 4 with corresponding instructions (ENT,PUSH,POP,LEAVE)" },
    { 0x0306,                               "Master Control Relay instructions" },
    { 0x0307,                               "Address register 1 exists with corresponding instructions" },
    { 0x0308,                               "Address register 2 exists with corresponding instructions" },
    { 0x0309,                               "Operations for area-crossing addressing" },
    { 0x030A,                               "Operations for area-internal addressing" },
    { 0x030B,                               "All memory-indirect addressing instructions for bit memory (M)" },
    { 0x030C,                               "All memory-indirect addressing instructions for data blocks (DB)" },
    { 0x030D,                               "All memory-indirect addressing instructions for data blocks (DI)" },
    { 0x030E,                               "All memory-indirect addressing instructions for local data (L)" },
    { 0x030F,                               "All instructions for parameter transfer in FCs" },
    { 0x0310,                               "Memory bit edge instructions for process image input (I)" },
    { 0x0311,                               "Memory bit edge instructions for process image output (Q)" },
    { 0x0312,                               "Memory bit edge instructions for bit memory (M)" },
    { 0x0313,                               "Memory bit edge instructions for data blocks (DB)" },
    { 0x0314,                               "Memory bit edge instructions for data blocks (DI)" },
    { 0x0315,                               "Memory bit edge instructions for local data (L)" },
    { 0x0316,                               "Dynamic evaluation of the FC bit" },
    { 0x0317,                               "Dynamic local data area with the corresponding instructions" },
    { 0x0318,                               "Reserved" },
    { 0x0319,                               "Reserved" },
    { 0x0401,                               "SFC 87 C_DIAG is available" },
    { 0x0402,                               "SFC 88 C_CNTRL is available" },
    { 0,                                    NULL }
};

static gint hf_s7comm_szl_0013_0000_index = -1;

static gint hf_s7comm_szl_0013_0000_code = -1;
static const value_string szl_memory_type_names[] = {
    { 0x0001,                               "volatile memory (RAM)" },
    { 0x0002,                               "non-volatile memory (FEPROM)" },
    { 0x0003,                               "mixed memory (RAM + FEPROM)" },
    { 0,                                    NULL }
};
static gint hf_s7comm_szl_0013_0000_size = -1;
static gint hf_s7comm_szl_0013_0000_mode = -1;
static gint hf_s7comm_szl_0013_0000_mode_0 = -1;
static gint hf_s7comm_szl_0013_0000_mode_1 = -1;
static gint hf_s7comm_szl_0013_0000_mode_2 = -1;
static gint hf_s7comm_szl_0013_0000_mode_3 = -1;
static gint hf_s7comm_szl_0013_0000_mode_4 = -1;
static gint hf_s7comm_szl_0013_0000_granu = -1;
static gint hf_s7comm_szl_0013_0000_ber1 = -1;
static gint hf_s7comm_szl_0013_0000_belegt1 = -1;
static gint hf_s7comm_szl_0013_0000_block1 = -1;
static gint hf_s7comm_szl_0013_0000_ber2 = -1;
static gint hf_s7comm_szl_0013_0000_belegt2 = -1;
static gint hf_s7comm_szl_0013_0000_block2 = -1;

static gint hf_s7comm_szl_xy11_0001_index = -1;
static gint hf_s7comm_szl_xy11_0001_mlfb = -1;
static gint hf_s7comm_szl_xy11_0001_bgtyp = -1;
static gint hf_s7comm_szl_xy11_0001_ausbg = -1;
static gint hf_s7comm_szl_xy11_0001_ausbe = -1;

static gint hf_s7comm_szl_xy14_000x_index = -1;
static gint hf_s7comm_szl_xy14_000x_code = -1;
static gint hf_s7comm_szl_xy14_000x_quantity = -1;
static gint hf_s7comm_szl_xy14_000x_reman = -1;

static gint hf_s7comm_szl_xy15_000x_index = -1;
static gint hf_s7comm_szl_xy15_000x_maxanz = -1;
static gint hf_s7comm_szl_xy15_000x_maxlng = -1;
static gint hf_s7comm_szl_xy15_000x_maxabl = -1;

static gint hf_s7comm_szl_xy22_00xx_info = -1;
static gint hf_s7comm_szl_xy22_00xx_al1 = -1;
static gint hf_s7comm_szl_xy22_00xx_al1_0 = -1;
static gint hf_s7comm_szl_xy22_00xx_al1_1 = -1;
static gint hf_s7comm_szl_xy22_00xx_al1_2 = -1;
static gint hf_s7comm_szl_xy22_00xx_al1_4 = -1;
static gint hf_s7comm_szl_xy22_00xx_al1_5 = -1;
static gint hf_s7comm_szl_xy22_00xx_al1_6 = -1;
static gint hf_s7comm_szl_xy22_00xx_al2 = -1;
static gint hf_s7comm_szl_xy22_00xx_al2_0 = -1;
static gint hf_s7comm_szl_xy22_00xx_al2_1 = -1;
static gint hf_s7comm_szl_xy22_00xx_al2_2 = -1;
static gint hf_s7comm_szl_xy22_00xx_al2_3 = -1;
static gint hf_s7comm_szl_xy22_00xx_al3 = -1;

static gint ett_s7comm_szl_xy22_00xx_al1 = -1;
static int * const s7comm_szl_xy22_00xx_al1_fields[] = {
    &hf_s7comm_szl_xy22_00xx_al1_0,
    &hf_s7comm_szl_xy22_00xx_al1_1,
    &hf_s7comm_szl_xy22_00xx_al1_2,
    &hf_s7comm_szl_xy22_00xx_al1_4,
    &hf_s7comm_szl_xy22_00xx_al1_5,
    &hf_s7comm_szl_xy22_00xx_al1_6,
    NULL
};
static gint ett_s7comm_szl_xy22_00xx_al2 = -1;
static int * const s7comm_szl_xy22_00xx_al2_fields[] = {
    &hf_s7comm_szl_xy22_00xx_al2_0,
    &hf_s7comm_szl_xy22_00xx_al2_1,
    &hf_s7comm_szl_xy22_00xx_al2_2,
    &hf_s7comm_szl_xy22_00xx_al2_3,
    NULL
};

static gint hf_s7comm_szl_0131_0001_index = -1;
static gint hf_s7comm_szl_0131_0001_pdu = -1;
static gint hf_s7comm_szl_0131_0001_anz= -1;
static gint hf_s7comm_szl_0131_0001_mpi_bps = -1;
static gint hf_s7comm_szl_0131_0001_kbus_bps = -1;
static gint hf_s7comm_szl_0131_0001_res = -1;

static gint hf_s7comm_szl_0131_0002_index = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_0 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_1 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_2 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_3 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_4 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_5 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_6 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_7 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_0 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_1 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_2 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_3 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_4 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_5 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_6 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_7 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_0 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_1 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_2 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_3 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_4 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_5 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_6 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_7 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_3 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_4 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_5 = -1;
static gint hf_s7comm_szl_0131_0002_aseg = -1;
static gint hf_s7comm_szl_0131_0002_eseg = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_0 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_1 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_2 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_3 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_4 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_5 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_6 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_7 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_0 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_1 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_2 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_3 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_4 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_5 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_6 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_7 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_2 = -1;
static gint hf_s7comm_szl_0131_0002_trgbed = -1;
static gint hf_s7comm_szl_0131_0002_pfad = -1;
static gint hf_s7comm_szl_0131_0002_tiefe = -1;
static gint hf_s7comm_szl_0131_0002_systrig = -1;
static gint hf_s7comm_szl_0131_0002_erg_par = -1;
static gint hf_s7comm_szl_0131_0002_erg_pat_1 = -1;
static gint hf_s7comm_szl_0131_0002_erg_pat_2 = -1;
static gint hf_s7comm_szl_0131_0002_force = -1;
static gint hf_s7comm_szl_0131_0002_time = -1;
static gint hf_s7comm_szl_0131_0002_res = -1;

static gint ett_s7comm_szl_0131_0002_funkt_0 = -1;
static int * const s7comm_szl_0131_0002_funkt_0_fields[] = {
    &hf_s7comm_szl_0131_0002_funkt_0_0,
    &hf_s7comm_szl_0131_0002_funkt_0_1,
    &hf_s7comm_szl_0131_0002_funkt_0_2,
    &hf_s7comm_szl_0131_0002_funkt_0_3,
    &hf_s7comm_szl_0131_0002_funkt_0_4,
    &hf_s7comm_szl_0131_0002_funkt_0_5,
    &hf_s7comm_szl_0131_0002_funkt_0_6,
    &hf_s7comm_szl_0131_0002_funkt_0_7,
    NULL
};
static gint ett_s7comm_szl_0131_0002_funkt_1 = -1;
static int * const s7comm_szl_0131_0002_funkt_1_fields[] = {
    &hf_s7comm_szl_0131_0002_funkt_1_0,
    &hf_s7comm_szl_0131_0002_funkt_1_1,
    &hf_s7comm_szl_0131_0002_funkt_1_2,
    &hf_s7comm_szl_0131_0002_funkt_1_3,
    &hf_s7comm_szl_0131_0002_funkt_1_4,
    &hf_s7comm_szl_0131_0002_funkt_1_5,
    &hf_s7comm_szl_0131_0002_funkt_1_6,
    &hf_s7comm_szl_0131_0002_funkt_1_7,
    NULL
};
static gint ett_s7comm_szl_0131_0002_funkt_2 = -1;
static int * const s7comm_szl_0131_0002_funkt_2_fields[] = {
    &hf_s7comm_szl_0131_0002_funkt_2_0,
    &hf_s7comm_szl_0131_0002_funkt_2_1,
    &hf_s7comm_szl_0131_0002_funkt_2_2,
    &hf_s7comm_szl_0131_0002_funkt_2_3,
    &hf_s7comm_szl_0131_0002_funkt_2_4,
    &hf_s7comm_szl_0131_0002_funkt_2_5,
    &hf_s7comm_szl_0131_0002_funkt_2_6,
    &hf_s7comm_szl_0131_0002_funkt_2_7,
    NULL
};
static gint ett_s7comm_szl_0131_0002_trgereig_0 = -1;
static int * const s7comm_szl_0131_0002_trgereig_0_fields[] = {
    &hf_s7comm_szl_0131_0002_trgereig_0_0,
    &hf_s7comm_szl_0131_0002_trgereig_0_1,
    &hf_s7comm_szl_0131_0002_trgereig_0_2,
    &hf_s7comm_szl_0131_0002_trgereig_0_3,
    &hf_s7comm_szl_0131_0002_trgereig_0_4,
    &hf_s7comm_szl_0131_0002_trgereig_0_5,
    &hf_s7comm_szl_0131_0002_trgereig_0_6,
    &hf_s7comm_szl_0131_0002_trgereig_0_7,
    NULL
};
static gint ett_s7comm_szl_0131_0002_trgereig_1 = -1;
static int * const s7comm_szl_0131_0002_trgereig_1_fields[] = {
    &hf_s7comm_szl_0131_0002_trgereig_1_0,
    &hf_s7comm_szl_0131_0002_trgereig_1_1,
    &hf_s7comm_szl_0131_0002_trgereig_1_2,
    &hf_s7comm_szl_0131_0002_trgereig_1_3,
    &hf_s7comm_szl_0131_0002_trgereig_1_4,
    &hf_s7comm_szl_0131_0002_trgereig_1_5,
    &hf_s7comm_szl_0131_0002_trgereig_1_6,
    &hf_s7comm_szl_0131_0002_trgereig_1_7,
    NULL
};

static gint hf_s7comm_szl_0131_0003_index = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_4 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_5 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_6 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_7 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_4 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_5 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_6 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_7 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_4 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_5 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_6 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_7 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_4 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_5 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_6 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_7 = -1;
static gint hf_s7comm_szl_0131_0003_data = -1;
static gint hf_s7comm_szl_0131_0003_anz = -1;
static gint hf_s7comm_szl_0131_0003_per_min = -1;
static gint hf_s7comm_szl_0131_0003_per_max = -1;
static gint hf_s7comm_szl_0131_0003_res = -1;

static gint ett_s7comm_szl_0131_0003_funkt_0 = -1;
static int * const s7comm_szl_0131_0003_funkt_0_fields[] = {
    &hf_s7comm_szl_0131_0003_funkt_0_0,
    &hf_s7comm_szl_0131_0003_funkt_0_1,
    &hf_s7comm_szl_0131_0003_funkt_0_2,
    &hf_s7comm_szl_0131_0003_funkt_0_3,
    &hf_s7comm_szl_0131_0003_funkt_0_4,
    &hf_s7comm_szl_0131_0003_funkt_0_5,
    &hf_s7comm_szl_0131_0003_funkt_0_6,
    &hf_s7comm_szl_0131_0003_funkt_0_7,
    NULL
};
static gint ett_s7comm_szl_0131_0003_funkt_1 = -1;
static int * const s7comm_szl_0131_0003_funkt_1_fields[] = {
    &hf_s7comm_szl_0131_0003_funkt_1_0,
    &hf_s7comm_szl_0131_0003_funkt_1_1,
    &hf_s7comm_szl_0131_0003_funkt_1_2,
    &hf_s7comm_szl_0131_0003_funkt_1_3,
    &hf_s7comm_szl_0131_0003_funkt_1_4,
    &hf_s7comm_szl_0131_0003_funkt_1_5,
    &hf_s7comm_szl_0131_0003_funkt_1_6,
    &hf_s7comm_szl_0131_0003_funkt_1_7,
    NULL
};
static gint ett_s7comm_szl_0131_0003_funkt_2 = -1;
static int * const s7comm_szl_0131_0003_funkt_2_fields[] = {
    &hf_s7comm_szl_0131_0003_funkt_2_0,
    &hf_s7comm_szl_0131_0003_funkt_2_1,
    &hf_s7comm_szl_0131_0003_funkt_2_2,
    &hf_s7comm_szl_0131_0003_funkt_2_3,
    &hf_s7comm_szl_0131_0003_funkt_2_4,
    &hf_s7comm_szl_0131_0003_funkt_2_5,
    &hf_s7comm_szl_0131_0003_funkt_2_6,
    &hf_s7comm_szl_0131_0003_funkt_2_7,
    NULL
};
static gint ett_s7comm_szl_0131_0003_funkt_3 = -1;
static int * const s7comm_szl_0131_0003_funkt_3_fields[] = {
    &hf_s7comm_szl_0131_0003_funkt_3_0,
    &hf_s7comm_szl_0131_0003_funkt_3_1,
    &hf_s7comm_szl_0131_0003_funkt_3_2,
    &hf_s7comm_szl_0131_0003_funkt_3_3,
    &hf_s7comm_szl_0131_0003_funkt_3_4,
    &hf_s7comm_szl_0131_0003_funkt_3_5,
    &hf_s7comm_szl_0131_0003_funkt_3_6,
    &hf_s7comm_szl_0131_0003_funkt_3_7,
    NULL
};

static gint hf_s7comm_szl_0131_0004_index = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_7 = -1;
static gint hf_s7comm_szl_0131_0004_kop = -1;
static gint hf_s7comm_szl_0131_0004_del = -1;
static gint hf_s7comm_szl_0131_0004_kett = -1;
static gint hf_s7comm_szl_0131_0004_hoch = -1;
static gint hf_s7comm_szl_0131_0004_ver = -1;
static gint hf_s7comm_szl_0131_0004_res = -1;

static gint ett_s7comm_szl_0131_0004_funkt_0 = -1;
static int * const s7comm_szl_0131_0004_funkt_0_fields[] = {
    &hf_s7comm_szl_0131_0004_funkt_0_0,
    &hf_s7comm_szl_0131_0004_funkt_0_1,
    &hf_s7comm_szl_0131_0004_funkt_0_2,
    &hf_s7comm_szl_0131_0004_funkt_0_3,
    &hf_s7comm_szl_0131_0004_funkt_0_4,
    &hf_s7comm_szl_0131_0004_funkt_0_5,
    &hf_s7comm_szl_0131_0004_funkt_0_6,
    &hf_s7comm_szl_0131_0004_funkt_0_7,
    NULL
};
static gint ett_s7comm_szl_0131_0004_funkt_1 = -1;
static int * const s7comm_szl_0131_0004_funkt_1_fields[] = {
    &hf_s7comm_szl_0131_0004_funkt_1_0,
    &hf_s7comm_szl_0131_0004_funkt_1_1,
    &hf_s7comm_szl_0131_0004_funkt_1_2,
    &hf_s7comm_szl_0131_0004_funkt_1_3,
    &hf_s7comm_szl_0131_0004_funkt_1_4,
    &hf_s7comm_szl_0131_0004_funkt_1_5,
    &hf_s7comm_szl_0131_0004_funkt_1_6,
    &hf_s7comm_szl_0131_0004_funkt_1_7,
    NULL
};
static gint ett_s7comm_szl_0131_0004_funkt_2 = -1;
static int * const s7comm_szl_0131_0004_funkt_2_fields[] = {
    &hf_s7comm_szl_0131_0004_funkt_2_0,
    &hf_s7comm_szl_0131_0004_funkt_2_1,
    &hf_s7comm_szl_0131_0004_funkt_2_2,
    &hf_s7comm_szl_0131_0004_funkt_2_3,
    &hf_s7comm_szl_0131_0004_funkt_2_4,
    &hf_s7comm_szl_0131_0004_funkt_2_5,
    &hf_s7comm_szl_0131_0004_funkt_2_6,
    &hf_s7comm_szl_0131_0004_funkt_2_7,
    NULL
};
static gint ett_s7comm_szl_0131_0004_funkt_3 = -1;
static int * const s7comm_szl_0131_0004_funkt_3_fields[] = {
    &hf_s7comm_szl_0131_0004_funkt_3_0,
    &hf_s7comm_szl_0131_0004_funkt_3_1,
    &hf_s7comm_szl_0131_0004_funkt_3_2,
    &hf_s7comm_szl_0131_0004_funkt_3_3,
    &hf_s7comm_szl_0131_0004_funkt_3_4,
    &hf_s7comm_szl_0131_0004_funkt_3_5,
    &hf_s7comm_szl_0131_0004_funkt_3_6,
    &hf_s7comm_szl_0131_0004_funkt_3_7,
    NULL
};
static gint ett_s7comm_szl_0131_0004_funkt_4 = -1;
static int * const s7comm_szl_0131_0004_funkt_4_fields[] = {
    &hf_s7comm_szl_0131_0004_funkt_4_0,
    &hf_s7comm_szl_0131_0004_funkt_4_1,
    &hf_s7comm_szl_0131_0004_funkt_4_2,
    &hf_s7comm_szl_0131_0004_funkt_4_3,
    &hf_s7comm_szl_0131_0004_funkt_4_4,
    &hf_s7comm_szl_0131_0004_funkt_4_5,
    &hf_s7comm_szl_0131_0004_funkt_4_6,
    &hf_s7comm_szl_0131_0004_funkt_4_7,
    NULL
};

static gint hf_s7comm_szl_0131_0005_index = -1;
static gint hf_s7comm_szl_0131_0005_funkt_0 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_0_0 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_0_1 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_0_2 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_0_3 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_0_4 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_0_5 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_0_6 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_0_7 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_1 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_2 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_3 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_4 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_5 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_6 = -1;
static gint hf_s7comm_szl_0131_0005_funkt_7 = -1;
static gint hf_s7comm_szl_0131_0005_anz_sen = -1;
static gint hf_s7comm_szl_0131_0005_anz_ein = -1;
static gint hf_s7comm_szl_0131_0005_anz_mel = -1;
static gint hf_s7comm_szl_0131_0005_res = -1;

static gint ett_s7comm_szl_0131_0005_funkt_0 = -1;
static int * const s7comm_szl_0131_0005_funkt_0_fields[] = {
    &hf_s7comm_szl_0131_0005_funkt_0_0,
    &hf_s7comm_szl_0131_0005_funkt_0_1,
    &hf_s7comm_szl_0131_0005_funkt_0_2,
    &hf_s7comm_szl_0131_0005_funkt_0_3,
    &hf_s7comm_szl_0131_0005_funkt_0_4,
    &hf_s7comm_szl_0131_0005_funkt_0_5,
    &hf_s7comm_szl_0131_0005_funkt_0_6,
    &hf_s7comm_szl_0131_0005_funkt_0_7,
    NULL
};

static gint hf_s7comm_szl_0131_0006_index = -1;
static gint hf_s7comm_szl_0131_0006_funkt_0 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_0_0 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_0_1 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_0_2 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_0_3 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_0_4 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_0_5 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_0_6 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_0_7 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_1 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_1_0 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_1_1 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_1_2 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_1_3 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_1_4 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_1_5 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_1_6 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_1_7 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_2 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_2_0 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_2_1 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_2_2 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_2_3 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_2_4 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_2_5 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_2_6 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_2_7 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_3 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_3_0 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_3_1 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_3_2 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_3_3 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_3_4 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_3_5 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_3_6 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_3_7 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_4 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_5 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_6 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_6_0 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_6_1 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_6_2 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_6_3 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_6_4 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_6_5 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_6_6 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_6_7 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_7 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_7_0 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_7_1 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_7_2 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_7_3 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_7_4 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_7_5 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_7_6 = -1;
static gint hf_s7comm_szl_0131_0006_funkt_7_7 = -1;
static gint hf_s7comm_szl_0131_0006_schnell = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_0 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_0_0 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_0_1 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_0_2 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_0_3 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_0_4 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_0_5 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_0_6 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_0_7 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_1 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_1_0 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_1_1 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_1_2 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_1_3 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_1_4 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_1_5 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_1_6 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_1_7 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_2 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_2_0 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_2_1 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_2_2 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_2_3 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_2_4 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_2_5 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_2_6 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_2_7 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_3 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_3_0 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_3_1 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_3_2 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_3_3 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_3_4 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_3_5 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_3_6 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_3_7 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_4 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_5 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_6 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_6_0 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_6_1 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_6_2 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_6_3 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_6_4 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_6_5 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_6_6 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_6_7 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_7 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_7_0 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_7_1 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_7_2 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_7_3 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_7_4 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_7_5 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_7_6 = -1;
static gint hf_s7comm_szl_0131_0006_zugtyp_7_7 = -1;
static gint hf_s7comm_szl_0131_0006_res1 = -1;
static gint hf_s7comm_szl_0131_0006_max_sd_empf = -1;
static gint hf_s7comm_szl_0131_0006_max_sd_al8p = -1;
static gint hf_s7comm_szl_0131_0006_max_inst = -1;
static gint hf_s7comm_szl_0131_0006_res2 = -1;
static gint hf_s7comm_szl_0131_0006_verb_proj = -1;
static gint hf_s7comm_szl_0131_0006_verb_prog = -1;
static gint hf_s7comm_szl_0131_0006_res3 = -1;

static gint ett_s7comm_szl_0131_0006_funkt_0 = -1;
static int * const s7comm_szl_0131_0006_funkt_0_fields[] = {
    &hf_s7comm_szl_0131_0006_funkt_0_0,
    &hf_s7comm_szl_0131_0006_funkt_0_1,
    &hf_s7comm_szl_0131_0006_funkt_0_2,
    &hf_s7comm_szl_0131_0006_funkt_0_3,
    &hf_s7comm_szl_0131_0006_funkt_0_4,
    &hf_s7comm_szl_0131_0006_funkt_0_5,
    &hf_s7comm_szl_0131_0006_funkt_0_6,
    &hf_s7comm_szl_0131_0006_funkt_0_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_funkt_1 = -1;
static int * const s7comm_szl_0131_0006_funkt_1_fields[] = {
    &hf_s7comm_szl_0131_0006_funkt_1_0,
    &hf_s7comm_szl_0131_0006_funkt_1_1,
    &hf_s7comm_szl_0131_0006_funkt_1_2,
    &hf_s7comm_szl_0131_0006_funkt_1_3,
    &hf_s7comm_szl_0131_0006_funkt_1_4,
    &hf_s7comm_szl_0131_0006_funkt_1_5,
    &hf_s7comm_szl_0131_0006_funkt_1_6,
    &hf_s7comm_szl_0131_0006_funkt_1_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_funkt_2 = -1;
static int * const s7comm_szl_0131_0006_funkt_2_fields[] = {
    &hf_s7comm_szl_0131_0006_funkt_2_0,
    &hf_s7comm_szl_0131_0006_funkt_2_1,
    &hf_s7comm_szl_0131_0006_funkt_2_2,
    &hf_s7comm_szl_0131_0006_funkt_2_3,
    &hf_s7comm_szl_0131_0006_funkt_2_4,
    &hf_s7comm_szl_0131_0006_funkt_2_5,
    &hf_s7comm_szl_0131_0006_funkt_2_6,
    &hf_s7comm_szl_0131_0006_funkt_2_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_funkt_3 = -1;
static int * const s7comm_szl_0131_0006_funkt_3_fields[] = {
    &hf_s7comm_szl_0131_0006_funkt_3_0,
    &hf_s7comm_szl_0131_0006_funkt_3_1,
    &hf_s7comm_szl_0131_0006_funkt_3_2,
    &hf_s7comm_szl_0131_0006_funkt_3_3,
    &hf_s7comm_szl_0131_0006_funkt_3_4,
    &hf_s7comm_szl_0131_0006_funkt_3_5,
    &hf_s7comm_szl_0131_0006_funkt_3_6,
    &hf_s7comm_szl_0131_0006_funkt_3_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_funkt_6 = -1;
static int * const s7comm_szl_0131_0006_funkt_6_fields[] = {
    &hf_s7comm_szl_0131_0006_funkt_6_0,
    &hf_s7comm_szl_0131_0006_funkt_6_1,
    &hf_s7comm_szl_0131_0006_funkt_6_2,
    &hf_s7comm_szl_0131_0006_funkt_6_3,
    &hf_s7comm_szl_0131_0006_funkt_6_4,
    &hf_s7comm_szl_0131_0006_funkt_6_5,
    &hf_s7comm_szl_0131_0006_funkt_6_6,
    &hf_s7comm_szl_0131_0006_funkt_6_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_funkt_7 = -1;
static int * const s7comm_szl_0131_0006_funkt_7_fields[] = {
    &hf_s7comm_szl_0131_0006_funkt_7_0,
    &hf_s7comm_szl_0131_0006_funkt_7_1,
    &hf_s7comm_szl_0131_0006_funkt_7_2,
    &hf_s7comm_szl_0131_0006_funkt_7_3,
    &hf_s7comm_szl_0131_0006_funkt_7_4,
    &hf_s7comm_szl_0131_0006_funkt_7_5,
    &hf_s7comm_szl_0131_0006_funkt_7_6,
    &hf_s7comm_szl_0131_0006_funkt_7_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_zugtyp_0 = -1;
static int * const s7comm_szl_0131_0006_zugtyp_0_fields[] = {
    &hf_s7comm_szl_0131_0006_zugtyp_0_0,
    &hf_s7comm_szl_0131_0006_zugtyp_0_1,
    &hf_s7comm_szl_0131_0006_zugtyp_0_2,
    &hf_s7comm_szl_0131_0006_zugtyp_0_3,
    &hf_s7comm_szl_0131_0006_zugtyp_0_4,
    &hf_s7comm_szl_0131_0006_zugtyp_0_5,
    &hf_s7comm_szl_0131_0006_zugtyp_0_6,
    &hf_s7comm_szl_0131_0006_zugtyp_0_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_zugtyp_1 = -1;
static int * const s7comm_szl_0131_0006_zugtyp_1_fields[] = {
    &hf_s7comm_szl_0131_0006_zugtyp_1_0,
    &hf_s7comm_szl_0131_0006_zugtyp_1_1,
    &hf_s7comm_szl_0131_0006_zugtyp_1_2,
    &hf_s7comm_szl_0131_0006_zugtyp_1_3,
    &hf_s7comm_szl_0131_0006_zugtyp_1_4,
    &hf_s7comm_szl_0131_0006_zugtyp_1_5,
    &hf_s7comm_szl_0131_0006_zugtyp_1_6,
    &hf_s7comm_szl_0131_0006_zugtyp_1_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_zugtyp_2 = -1;
static int * const s7comm_szl_0131_0006_zugtyp_2_fields[] = {
    &hf_s7comm_szl_0131_0006_zugtyp_2_0,
    &hf_s7comm_szl_0131_0006_zugtyp_2_1,
    &hf_s7comm_szl_0131_0006_zugtyp_2_2,
    &hf_s7comm_szl_0131_0006_zugtyp_2_3,
    &hf_s7comm_szl_0131_0006_zugtyp_2_4,
    &hf_s7comm_szl_0131_0006_zugtyp_2_5,
    &hf_s7comm_szl_0131_0006_zugtyp_2_6,
    &hf_s7comm_szl_0131_0006_zugtyp_2_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_zugtyp_3 = -1;
static int * const s7comm_szl_0131_0006_zugtyp_3_fields[] = {
    &hf_s7comm_szl_0131_0006_zugtyp_3_0,
    &hf_s7comm_szl_0131_0006_zugtyp_3_1,
    &hf_s7comm_szl_0131_0006_zugtyp_3_2,
    &hf_s7comm_szl_0131_0006_zugtyp_3_3,
    &hf_s7comm_szl_0131_0006_zugtyp_3_4,
    &hf_s7comm_szl_0131_0006_zugtyp_3_5,
    &hf_s7comm_szl_0131_0006_zugtyp_3_6,
    &hf_s7comm_szl_0131_0006_zugtyp_3_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_zugtyp_6 = -1;
static int * const s7comm_szl_0131_0006_zugtyp_6_fields[] = {
    &hf_s7comm_szl_0131_0006_zugtyp_6_0,
    &hf_s7comm_szl_0131_0006_zugtyp_6_1,
    &hf_s7comm_szl_0131_0006_zugtyp_6_2,
    &hf_s7comm_szl_0131_0006_zugtyp_6_3,
    &hf_s7comm_szl_0131_0006_zugtyp_6_4,
    &hf_s7comm_szl_0131_0006_zugtyp_6_5,
    &hf_s7comm_szl_0131_0006_zugtyp_6_6,
    &hf_s7comm_szl_0131_0006_zugtyp_6_7,
    NULL
};
static gint ett_s7comm_szl_0131_0006_zugtyp_7 = -1;
static int * const s7comm_szl_0131_0006_zugtyp_7_fields[] = {
    &hf_s7comm_szl_0131_0006_zugtyp_7_0,
    &hf_s7comm_szl_0131_0006_zugtyp_7_1,
    &hf_s7comm_szl_0131_0006_zugtyp_7_2,
    &hf_s7comm_szl_0131_0006_zugtyp_7_3,
    &hf_s7comm_szl_0131_0006_zugtyp_7_4,
    &hf_s7comm_szl_0131_0006_zugtyp_7_5,
    &hf_s7comm_szl_0131_0006_zugtyp_7_6,
    &hf_s7comm_szl_0131_0006_zugtyp_7_7,
    NULL
};

static gint hf_s7comm_szl_0131_0007_index = -1;
static gint hf_s7comm_szl_0131_0007_funkt_0 = -1;
static gint hf_s7comm_szl_0131_0007_funkt_0_0 = -1;
static gint hf_s7comm_szl_0131_0007_funkt_0_1 = -1;
static gint hf_s7comm_szl_0131_0007_funkt_0_2 = -1;
static gint hf_s7comm_szl_0131_0007_funkt_0_3 = -1;
static gint hf_s7comm_szl_0131_0007_funkt_0_4 = -1;
static gint hf_s7comm_szl_0131_0007_funkt_0_5 = -1;
static gint hf_s7comm_szl_0131_0007_funkt_0_6 = -1;
static gint hf_s7comm_szl_0131_0007_funkt_0_7 = -1;
static gint hf_s7comm_szl_0131_0007_funkt_1 = -1;
static gint hf_s7comm_szl_0131_0007_obj_0 = -1;
static gint hf_s7comm_szl_0131_0007_obj_0_0 = -1;
static gint hf_s7comm_szl_0131_0007_obj_0_1 = -1;
static gint hf_s7comm_szl_0131_0007_obj_0_2 = -1;
static gint hf_s7comm_szl_0131_0007_obj_0_3 = -1;
static gint hf_s7comm_szl_0131_0007_obj_0_4 = -1;
static gint hf_s7comm_szl_0131_0007_obj_0_5 = -1;
static gint hf_s7comm_szl_0131_0007_obj_0_6 = -1;
static gint hf_s7comm_szl_0131_0007_obj_0_7 = -1;
static gint hf_s7comm_szl_0131_0007_obj_1 = -1;
static gint hf_s7comm_szl_0131_0007_kons = -1;
static gint hf_s7comm_szl_0131_0007_sen = -1;
static gint hf_s7comm_szl_0131_0007_rec = -1;
static gint hf_s7comm_szl_0131_0007_time = -1;
static gint hf_s7comm_szl_0131_0007_proj = -1;
static gint hf_s7comm_szl_0131_0007_alarm = -1;
static gint hf_s7comm_szl_0131_0007_mode = -1;
static gint hf_s7comm_szl_0131_0007_mode_0 = -1;
static gint hf_s7comm_szl_0131_0007_mode_1 = -1;
static gint hf_s7comm_szl_0131_0007_kreis = -1;
static gint hf_s7comm_szl_0131_0007_sk_1 = -1;
static gint hf_s7comm_szl_0131_0007_sk_2 = -1;
static gint hf_s7comm_szl_0131_0007_ek_1 = -1;
static gint hf_s7comm_szl_0131_0007_ek_2 = -1;
static gint hf_s7comm_szl_0131_0007_len_1 = -1;
static gint hf_s7comm_szl_0131_0007_len_2 = -1;
static gint hf_s7comm_szl_0131_0007_len_3 = -1;
static gint hf_s7comm_szl_0131_0007_res = -1;

static gint ett_s7comm_szl_0131_0007_funkt_0 = -1;
static int * const s7comm_szl_0131_0007_funkt_0_fields[] = {
    &hf_s7comm_szl_0131_0007_funkt_0_0,
    &hf_s7comm_szl_0131_0007_funkt_0_1,
    &hf_s7comm_szl_0131_0007_funkt_0_2,
    &hf_s7comm_szl_0131_0007_funkt_0_3,
    &hf_s7comm_szl_0131_0007_funkt_0_4,
    &hf_s7comm_szl_0131_0007_funkt_0_5,
    &hf_s7comm_szl_0131_0007_funkt_0_6,
    &hf_s7comm_szl_0131_0007_funkt_0_7,
    NULL
};

static gint ett_s7comm_szl_0131_0007_obj_0 = -1;
static int * const s7comm_szl_0131_0007_obj_0_fields[] = {
    &hf_s7comm_szl_0131_0007_obj_0_0,
    &hf_s7comm_szl_0131_0007_obj_0_1,
    &hf_s7comm_szl_0131_0007_obj_0_2,
    &hf_s7comm_szl_0131_0007_obj_0_3,
    &hf_s7comm_szl_0131_0007_obj_0_4,
    &hf_s7comm_szl_0131_0007_obj_0_5,
    &hf_s7comm_szl_0131_0007_obj_0_6,
    &hf_s7comm_szl_0131_0007_obj_0_7,
    NULL
};

static gint ett_s7comm_szl_0131_0007_mode = -1;
static int * const s7comm_szl_0131_0007_mode_fields[] = {
    &hf_s7comm_szl_0131_0007_mode_0,
    &hf_s7comm_szl_0131_0007_mode_1,
    NULL
};

static gint hf_s7comm_szl_0131_0008_index = -1;
static gint hf_s7comm_szl_0131_0008_last_1 = -1;
static gint hf_s7comm_szl_0131_0008_last_1_tb = -1;
static gint hf_s7comm_szl_0131_0008_last_2 = -1;
static gint hf_s7comm_szl_0131_0008_last_2_tb = -1;
static gint hf_s7comm_szl_0131_0008_last_3 = -1;
static gint hf_s7comm_szl_0131_0008_last_3_tb = -1;
static gint hf_s7comm_szl_0131_0008_merker = -1;
static gint hf_s7comm_szl_0131_0008_merker_tb = -1;
static gint hf_s7comm_szl_0131_0008_ea = -1;
static gint hf_s7comm_szl_0131_0008_ea_tb = -1;
static gint hf_s7comm_szl_0131_0008_tz = -1;
static gint hf_s7comm_szl_0131_0008_tz_tb = -1;
static gint hf_s7comm_szl_0131_0008_db = -1;
static gint hf_s7comm_szl_0131_0008_db_tb = -1;
static gint hf_s7comm_szl_0131_0008_ld = -1;
static gint hf_s7comm_szl_0131_0008_ld_tb = -1;
static gint hf_s7comm_szl_0131_0008_reg = -1;
static gint hf_s7comm_szl_0131_0008_reg_tb = -1;
static gint hf_s7comm_szl_0131_0008_ba_stali1 = -1;
static gint hf_s7comm_szl_0131_0008_ba_stali1_tb = -1;
static gint hf_s7comm_szl_0131_0008_ba_stali2 = -1;
static gint hf_s7comm_szl_0131_0008_ba_stali2_tb = -1;
static gint hf_s7comm_szl_0131_0008_ba_stali3 = -1;
static gint hf_s7comm_szl_0131_0008_ba_stali3_tb = -1;
static gint hf_s7comm_szl_0131_0008_akku = -1;
static gint hf_s7comm_szl_0131_0008_akku_tb = -1;
static gint hf_s7comm_szl_0131_0008_address = -1;
static gint hf_s7comm_szl_0131_0008_address_tb = -1;
static gint hf_s7comm_szl_0131_0008_dbreg = -1;
static gint hf_s7comm_szl_0131_0008_dbreg_tb = -1;
static gint hf_s7comm_szl_0131_0008_res = -1;
static const value_string s7comm_szl_0131_0008_timebase_names[] = {
    { 0,                                    "100 ps" },
    { 1,                                    "1 ns" },
    { 2,                                    "10 ns" },
    { 3,                                    "100 ns" },
    { 4,                                    "1 us" },
    { 5,                                    "10 us" },
    { 6,                                    "100 us" },
    { 7,                                    "1 ms" },
    { 8,                                    "10 ms" },
    { 9,                                    "100 ms" },
    { 10,                                   "1 s" },
    { 11,                                   "10 s" },
    { 12,                                   "100 s" },
    { 13,                                   "1000 s" },
    { 14,                                   "10000 s" },
    { 15,                                   "1000000 s" },
    { 0,                                    NULL }
};

static gint hf_s7comm_szl_0131_0009_index = -1;
static gint hf_s7comm_szl_0131_0009_sync_k = -1;
static gint hf_s7comm_szl_0131_0009_sync_k_0 = -1;
static gint hf_s7comm_szl_0131_0009_sync_k_1 = -1;
static gint hf_s7comm_szl_0131_0009_sync_k_2 = -1;
static gint hf_s7comm_szl_0131_0009_sync_mpi = -1;
static gint hf_s7comm_szl_0131_0009_sync_mpi_0 = -1;
static gint hf_s7comm_szl_0131_0009_sync_mpi_1 = -1;
static gint hf_s7comm_szl_0131_0009_sync_mpi_2 = -1;
static gint hf_s7comm_szl_0131_0009_sync_mfi = -1;
static gint hf_s7comm_szl_0131_0009_sync_mfi_0 = -1;
static gint hf_s7comm_szl_0131_0009_sync_mfi_1 = -1;
static gint hf_s7comm_szl_0131_0009_sync_mfi_2 = -1;
static gint hf_s7comm_szl_0131_0009_res1 = -1;
static gint hf_s7comm_szl_0131_0009_abw_puf = -1;
static gint hf_s7comm_szl_0131_0009_abw_5v = -1;
static gint hf_s7comm_szl_0131_0009_anz_bsz = -1;
static gint hf_s7comm_szl_0131_0009_res2 = -1;

static gint ett_s7comm_szl_0131_0009_sync_k = -1;
static int * const s7comm_szl_0131_0009_sync_k_fields[] = {
    &hf_s7comm_szl_0131_0009_sync_k_0,
    &hf_s7comm_szl_0131_0009_sync_k_1,
    &hf_s7comm_szl_0131_0009_sync_k_2,
    NULL
};

static gint ett_s7comm_szl_0131_0009_sync_mpi = -1;
static int * const s7comm_szl_0131_0009_sync_mpi_fields[] = {
    &hf_s7comm_szl_0131_0009_sync_mpi_0,
    &hf_s7comm_szl_0131_0009_sync_mpi_1,
    &hf_s7comm_szl_0131_0009_sync_mpi_2,
    NULL
};

static gint ett_s7comm_szl_0131_0009_sync_mfi = -1;
static int * const s7comm_szl_0131_0009_sync_mfi_fields[] = {
    &hf_s7comm_szl_0131_0009_sync_mfi_0,
    &hf_s7comm_szl_0131_0009_sync_mfi_1,
    &hf_s7comm_szl_0131_0009_sync_mfi_2,
    NULL
};

static gint hf_s7comm_szl_0131_0010_index = -1;
static gint hf_s7comm_szl_0131_0010_funk_1 = -1;
static gint hf_s7comm_szl_0131_0010_funk_1_0 = -1;
static gint hf_s7comm_szl_0131_0010_funk_1_1 = -1;
static gint hf_s7comm_szl_0131_0010_funk_1_2 = -1;
static gint hf_s7comm_szl_0131_0010_funk_1_3 = -1;
static gint hf_s7comm_szl_0131_0010_funk_1_4 = -1;
static gint hf_s7comm_szl_0131_0010_funk_1_5 = -1;
static gint hf_s7comm_szl_0131_0010_funk_1_6 = -1;
static gint hf_s7comm_szl_0131_0010_funk_1_7 = -1;
static gint hf_s7comm_szl_0131_0010_funk_2 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_1 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_1_0 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_1_1 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_1_2 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_1_3 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_1_4 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_1_5 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_1_6 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_1_7 = -1;
static gint hf_s7comm_szl_0131_0010_ber_meld_2 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_1 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_1_0 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_1_1 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_1_2 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_1_3 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_1_4 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_1_5 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_1_6 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_1_7 = -1;
static gint hf_s7comm_szl_0131_0010_ber_zus_2 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_1 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_1_0 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_1_1 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_1_2 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_1_3 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_1_4 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_1_5 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_1_6 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_1_7 = -1;
static gint hf_s7comm_szl_0131_0010_typ_zus_2 = -1;
static gint hf_s7comm_szl_0131_0010_maxanz_arch = -1;
static gint hf_s7comm_szl_0131_0010_res = -1;

static gint ett_s7comm_szl_0131_0010_funk_1 = -1;
static int * const s7comm_szl_0131_0010_funk_1_fields[] = {
    &hf_s7comm_szl_0131_0010_funk_1_0,
    &hf_s7comm_szl_0131_0010_funk_1_1,
    &hf_s7comm_szl_0131_0010_funk_1_2,
    &hf_s7comm_szl_0131_0010_funk_1_3,
    &hf_s7comm_szl_0131_0010_funk_1_4,
    &hf_s7comm_szl_0131_0010_funk_1_5,
    &hf_s7comm_szl_0131_0010_funk_1_6,
    &hf_s7comm_szl_0131_0010_funk_1_7,
    NULL
};
static gint ett_s7comm_szl_0131_0010_ber_meld_1 = -1;
static int * const s7comm_szl_0131_0010_ber_meld_1_fields[] = {
    &hf_s7comm_szl_0131_0010_ber_meld_1_0,
    &hf_s7comm_szl_0131_0010_ber_meld_1_1,
    &hf_s7comm_szl_0131_0010_ber_meld_1_2,
    &hf_s7comm_szl_0131_0010_ber_meld_1_3,
    &hf_s7comm_szl_0131_0010_ber_meld_1_4,
    &hf_s7comm_szl_0131_0010_ber_meld_1_5,
    &hf_s7comm_szl_0131_0010_ber_meld_1_6,
    &hf_s7comm_szl_0131_0010_ber_meld_1_7,
    NULL
};
static gint ett_s7comm_szl_0131_0010_ber_zus_1 = -1;
static int * const s7comm_szl_0131_0010_ber_zus_1_fields[] = {
    &hf_s7comm_szl_0131_0010_ber_zus_1_0,
    &hf_s7comm_szl_0131_0010_ber_zus_1_1,
    &hf_s7comm_szl_0131_0010_ber_zus_1_2,
    &hf_s7comm_szl_0131_0010_ber_zus_1_3,
    &hf_s7comm_szl_0131_0010_ber_zus_1_4,
    &hf_s7comm_szl_0131_0010_ber_zus_1_5,
    &hf_s7comm_szl_0131_0010_ber_zus_1_6,
    &hf_s7comm_szl_0131_0010_ber_zus_1_7,
    NULL
};
static gint ett_s7comm_szl_0131_0010_typ_zus_1 = -1;
static int * const s7comm_szl_0131_0010_typ_zus_1_fields[] = {
    &hf_s7comm_szl_0131_0010_typ_zus_1_0,
    &hf_s7comm_szl_0131_0010_typ_zus_1_1,
    &hf_s7comm_szl_0131_0010_typ_zus_1_2,
    &hf_s7comm_szl_0131_0010_typ_zus_1_3,
    &hf_s7comm_szl_0131_0010_typ_zus_1_4,
    &hf_s7comm_szl_0131_0010_typ_zus_1_5,
    &hf_s7comm_szl_0131_0010_typ_zus_1_6,
    &hf_s7comm_szl_0131_0010_typ_zus_1_7,
    NULL
};

static gint hf_s7comm_szl_0132_0001_index = -1;
static gint hf_s7comm_szl_0132_0001_res_pg = -1;
static gint hf_s7comm_szl_0132_0001_res_os = -1;
static gint hf_s7comm_szl_0132_0001_u_pg = -1;
static gint hf_s7comm_szl_0132_0001_u_os = -1;
static gint hf_s7comm_szl_0132_0001_proj = -1;
static gint hf_s7comm_szl_0132_0001_auf = -1;
static gint hf_s7comm_szl_0132_0001_free = -1;
static gint hf_s7comm_szl_0132_0001_used = -1;
static gint hf_s7comm_szl_0132_0001_last = -1;
static gint hf_s7comm_szl_0132_0001_res = -1;

static gint hf_s7comm_szl_0132_0002_index = -1;
static gint hf_s7comm_szl_0132_0002_anz = -1;
static gint hf_s7comm_szl_0132_0002_res = -1;

static gint hf_s7comm_szl_0132_0004_index = -1;
static gint hf_s7comm_szl_0132_0004_key = -1;
static gint hf_s7comm_szl_0132_0004_param = -1;
static gint hf_s7comm_szl_0132_0004_real = -1;
static gint hf_s7comm_szl_0132_0004_bart_sch = -1;

static const value_string szl_bart_sch_names[] = {
    { 0,                                    "undefined or cannot be ascertained" },
    { 1,                                    "RUN" },
    { 2,                                    "RUN_P" },
    { 3,                                    "STOP" },
    { 4,                                    "MRES" },
    { 0,                                    NULL }
};
static gint hf_s7comm_szl_0132_0004_crst_wrst = -1;
static const value_string szl_crst_wrst_names[] = {
    { 0,                                    "undefined, does not exist or cannot be be ascertained" },
    { 1,                                    "CRST" },
    { 2,                                    "WRST" },
    { 0,                                    NULL }
};
static gint hf_s7comm_szl_0132_0004_ken_f = -1;
static gint hf_s7comm_szl_0132_0004_ken_rel = -1;
static gint hf_s7comm_szl_0132_0004_ken_ver1_hw = -1;
static gint hf_s7comm_szl_0132_0004_ken_ver2_hw = -1;
static gint hf_s7comm_szl_0132_0004_ken_ver1_awp = -1;
static gint hf_s7comm_szl_0132_0004_ken_ver2_awp = -1;
static gint hf_s7comm_szl_0132_0004_res = -1;

static gint hf_s7comm_szl_0132_0005_index = -1;
static gint hf_s7comm_szl_0132_0005_erw = -1;
static gint hf_s7comm_szl_0132_0005_send = -1;
static gint hf_s7comm_szl_0132_0005_moeg = -1;
static gint hf_s7comm_szl_0132_0005_ltmerz = -1;
static gint hf_s7comm_szl_0132_0005_res = -1;

static const value_string szl_0132_0005_func_exist_names[] = {
    { 0x0,                                  "No" },
    { 0x1,                                  "Yes" },
    { 0,                                    NULL }
};

static gint hf_s7comm_szl_0132_0006_index = -1;
static gint hf_s7comm_szl_0132_0006_used_0 = -1;
static gint hf_s7comm_szl_0132_0006_used_1 = -1;
static gint hf_s7comm_szl_0132_0006_used_2 = -1;
static gint hf_s7comm_szl_0132_0006_used_3 = -1;
static gint hf_s7comm_szl_0132_0006_used_4 = -1;
static gint hf_s7comm_szl_0132_0006_used_5 = -1;
static gint hf_s7comm_szl_0132_0006_used_6 = -1;
static gint hf_s7comm_szl_0132_0006_used_7 = -1;
static gint hf_s7comm_szl_0132_0006_anz_schnell = -1;
static gint hf_s7comm_szl_0132_0006_anz_inst = -1;
static gint hf_s7comm_szl_0132_0006_anz_multicast = -1;
static gint hf_s7comm_szl_0132_0006_res = -1;

static gint hf_s7comm_szl_0132_0008_index = -1;
static gint hf_s7comm_szl_0132_0008_zykl = -1;
static gint hf_s7comm_szl_0132_0008_korr = -1;
static gint hf_s7comm_szl_0132_0008_clock0 = -1;
static gint hf_s7comm_szl_0132_0008_clock1 = -1;
static gint hf_s7comm_szl_0132_0008_clock2 = -1;
static gint hf_s7comm_szl_0132_0008_clock3 = -1;
static gint hf_s7comm_szl_0132_0008_clock4 = -1;
static gint hf_s7comm_szl_0132_0008_clock5 = -1;
static gint hf_s7comm_szl_0132_0008_clock6 = -1;
static gint hf_s7comm_szl_0132_0008_clock7 = -1;
static gint hf_s7comm_szl_0132_0008_time = -1;
static gint hf_s7comm_szl_0132_0008_res = -1;

static gint hf_s7comm_szl_0132_000b_index = -1;
static gint hf_s7comm_szl_0132_000b_bszl_0 = -1;
static gint hf_s7comm_szl_0132_000b_bszl_1 = -1;
static gint hf_s7comm_szl_0132_000b_bszu_0 = -1;
static gint hf_s7comm_szl_0132_000b_bszu_1 = -1;
static gint hf_s7comm_szl_0132_000b_clock0 = -1;
static gint hf_s7comm_szl_0132_000b_clock1 = -1;
static gint hf_s7comm_szl_0132_000b_clock2 = -1;
static gint hf_s7comm_szl_0132_000b_clock3 = -1;
static gint hf_s7comm_szl_0132_000b_clock4 = -1;
static gint hf_s7comm_szl_0132_000b_clock5 = -1;
static gint hf_s7comm_szl_0132_000b_clock6 = -1;
static gint hf_s7comm_szl_0132_000b_clock7 = -1;
static gint hf_s7comm_szl_0132_000b_res = -1;

static gint hf_s7comm_szl_0132_000c_index = -1;
static gint hf_s7comm_szl_0132_000c_bszl_0 = -1;
static gint hf_s7comm_szl_0132_000c_bszl_1 = -1;
static gint hf_s7comm_szl_0132_000c_bszu_0 = -1;
static gint hf_s7comm_szl_0132_000c_bszu_1 = -1;
static gint hf_s7comm_szl_0132_000c_clock8 = -1;
static gint hf_s7comm_szl_0132_000c_clock9 = -1;
static gint hf_s7comm_szl_0132_000c_clock10 = -1;
static gint hf_s7comm_szl_0132_000c_clock11 = -1;
static gint hf_s7comm_szl_0132_000c_clock12 = -1;
static gint hf_s7comm_szl_0132_000c_clock13 = -1;
static gint hf_s7comm_szl_0132_000c_clock14 = -1;
static gint hf_s7comm_szl_0132_000c_clock15 = -1;
static gint hf_s7comm_szl_0132_000c_res = -1;

static gint hf_s7comm_szl_001c_000x_index = -1;
static gint hf_s7comm_szl_001c_0001_name = -1;
static gint hf_s7comm_szl_001c_0002_name = -1;
static gint hf_s7comm_szl_001c_0003_tag = -1;
static gint hf_s7comm_szl_001c_0004_copyright = -1;
static gint hf_s7comm_szl_001c_0005_serialn = -1;
static gint hf_s7comm_szl_001c_0007_cputypname = -1;
static gint hf_s7comm_szl_001c_0008_snmcmmc = -1;
static gint hf_s7comm_szl_001c_0009_manufacturer_id = -1;
static gint hf_s7comm_szl_001c_0009_profile_id = -1;
static gint hf_s7comm_szl_001c_0009_profile_spec_typ = -1;
static gint hf_s7comm_szl_001c_000a_oem_copyright_string = -1;
static gint hf_s7comm_szl_001c_000a_oem_id = -1;
static gint hf_s7comm_szl_001c_000a_oem_add_id = -1;
static gint hf_s7comm_szl_001c_000b_loc_id = -1;
static gint hf_s7comm_szl_001c_000x_res = -1;

static gint hf_s7comm_szl_0091_0000_adr1 = -1;
static gint hf_s7comm_szl_0091_0000_adr2 = -1;
static gint hf_s7comm_szl_0091_0000_logadr = -1;
static gint hf_s7comm_szl_0091_0000_solltyp = -1;
static gint hf_s7comm_szl_0091_0000_isttyp = -1;
static gint hf_s7comm_szl_0091_0000_res1 = -1;
static gint hf_s7comm_szl_0091_0000_res1_0c_4c_4d = -1;
static gint hf_s7comm_szl_0091_0000_res1_0d = -1;
static gint hf_s7comm_szl_0091_0000_eastat = -1;
static gint hf_s7comm_szl_0091_0000_eastat_0 = -1;
static gint hf_s7comm_szl_0091_0000_eastat_1 = -1;
static gint hf_s7comm_szl_0091_0000_eastat_2 = -1;
static gint hf_s7comm_szl_0091_0000_eastat_3 = -1;
static gint hf_s7comm_szl_0091_0000_eastat_4 = -1;
static gint hf_s7comm_szl_0091_0000_eastat_5 = -1;
static gint hf_s7comm_szl_0091_0000_eastat_6 = -1;
static gint hf_s7comm_szl_0091_0000_eastat_7 = -1;
static gint hf_s7comm_szl_0091_0000_eastat_dataid = -1;
static gint hf_s7comm_szl_0091_0000_berbgbr = -1;
static gint hf_s7comm_szl_0091_0000_berbgbr_0_2 = -1;
static gint hf_s7comm_szl_0091_0000_berbgbr_3 = -1;
static gint hf_s7comm_szl_0091_0000_berbgbr_areaid = -1;
static gint hf_s7comm_szl_0091_0000_berbgbr_7 = -1;

static const value_string szl_0091_0000_eastat_dataid_names[] = {
    { 0xb4,                                 "Input" },
    { 0xb5,                                 "Output" },
    { 0xff,                                 "External DP interface" },
    { 0,                                    NULL }
};
static const value_string szl_0091_0000_berbgbr_areaid_names[] = {
    { 0,                                    "S7-400" },
    { 1,                                    "S7-300" },
    { 2,                                    "ET area" },
    { 3,                                    "P area" },
    { 4,                                    "Q area" },
    { 5,                                    "IM3 area" },
    { 6,                                    "IM4 area" },
    { 0,                                    NULL }
};
static gint ett_s7comm_szl_0091_0000_eastat = -1;
static int * const s7comm_szl_0091_0000_eastat_fields[] = {
    &hf_s7comm_szl_0091_0000_eastat_0,
    &hf_s7comm_szl_0091_0000_eastat_1,
    &hf_s7comm_szl_0091_0000_eastat_2,
    &hf_s7comm_szl_0091_0000_eastat_3,
    &hf_s7comm_szl_0091_0000_eastat_4,
    &hf_s7comm_szl_0091_0000_eastat_5,
    &hf_s7comm_szl_0091_0000_eastat_6,
    &hf_s7comm_szl_0091_0000_eastat_7,
    &hf_s7comm_szl_0091_0000_eastat_dataid,
    NULL
};
static gint ett_s7comm_szl_0091_0000_berbgbr = -1;
static int * const s7comm_szl_0091_0000_berbgbr_fields[] = {
    &hf_s7comm_szl_0091_0000_berbgbr_0_2,
    &hf_s7comm_szl_0091_0000_berbgbr_3,
    &hf_s7comm_szl_0091_0000_berbgbr_areaid,
    &hf_s7comm_szl_0091_0000_berbgbr_7,
    NULL
};

static gint ett_s7comm_szl_xx9x_station_info = -1;
static gint hf_s7comm_szl_xx9x_station_info = -1;

static gint hf_s7comm_szl_0092_0xxx_status_0 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_1 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_2 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_3 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_4 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_5 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_6 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_7 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_8 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_9 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_10 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_11 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_12 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_13 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_14 = -1;
static gint hf_s7comm_szl_0092_0xxx_status_15 = -1;

static gint hf_s7comm_szl_0094_xxxx_index = -1;
static gint hf_s7comm_szl_0094_xxxx_status_0 = -1;
static gint hf_s7comm_szl_0094_xxxx_status_1_2047 = -1;

static gint hf_s7comm_szl_0096_xxxx_logadr_adr = -1;
static gint hf_s7comm_szl_0096_xxxx_logadr_area = -1;
static const true_false_string tfs_szl_0096_xxx_logadr_area = {
    "Input",
    "Output"
};

static gint hf_s7comm_szl_0096_xxxx_system = -1;
static gint hf_s7comm_szl_0096_xxxx_api = -1;
static gint hf_s7comm_szl_0096_xxxx_station = -1;
static gint hf_s7comm_szl_0096_xxxx_slot = -1;
static gint hf_s7comm_szl_0096_xxxx_subslot = -1;
static gint hf_s7comm_szl_0096_xxxx_offset = -1;
static gint hf_s7comm_szl_0096_xxxx_solltyp1 = -1;
static gint hf_s7comm_szl_0096_xxxx_solltyp2 = -1;
static gint hf_s7comm_szl_0096_xxxx_solltyp3 = -1;
static gint hf_s7comm_szl_0096_xxxx_solltyp4_5 = -1;
static gint hf_s7comm_szl_0096_xxxx_solltyp6_7 = -1;
static gint hf_s7comm_szl_0096_xxxx_expactid = -1;
static gint hf_s7comm_szl_0096_xxxx_reserve1 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_0 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_1 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_2 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_3 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_4 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_5 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_6 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_7 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_8 = -1;
static gint hf_s7comm_szl_0096_xxxx_eastat_9 = -1;
static gint ett_s7comm_szl_0096_xxxx_eastat = -1;
static int * const s7comm_szl_0096_xxxx_eastat_fields[] = {
    &hf_s7comm_szl_0096_xxxx_eastat_0,
    &hf_s7comm_szl_0096_xxxx_eastat_1,
    &hf_s7comm_szl_0096_xxxx_eastat_2,
    &hf_s7comm_szl_0096_xxxx_eastat_3,
    &hf_s7comm_szl_0096_xxxx_eastat_4,
    &hf_s7comm_szl_0096_xxxx_eastat_5,
    &hf_s7comm_szl_0096_xxxx_eastat_6,
    &hf_s7comm_szl_0096_xxxx_eastat_7,
    &hf_s7comm_szl_0096_xxxx_eastat_8,
    &hf_s7comm_szl_0096_xxxx_eastat_9,
    NULL
};
static gint hf_s7comm_szl_0096_xxxx_berbgbr = -1;
static gint hf_s7comm_szl_0096_xxxx_berbgbr_0_2 = -1;
static gint hf_s7comm_szl_0096_xxxx_berbgbr_3 = -1;
static gint hf_s7comm_szl_0096_xxxx_berbgbr_areaid = -1;
static gint hf_s7comm_szl_0096_xxxx_berbgbr_7 = -1;
static gint ett_s7comm_szl_0096_xxxx_berbgbr = -1;
static int * const s7comm_szl_0096_xxxx_berbgbr_fields[] = {
    &hf_s7comm_szl_0096_xxxx_berbgbr_0_2,
    &hf_s7comm_szl_0096_xxxx_berbgbr_3,
    &hf_s7comm_szl_0096_xxxx_berbgbr_areaid,
    &hf_s7comm_szl_0096_xxxx_berbgbr_7,
    NULL
};
static gint hf_s7comm_szl_0096_xxxx_reserve2 = -1;

static gint hf_s7comm_szl_0424_0000_ereig = -1;
static gint hf_s7comm_szl_0424_0000_ae = -1;
static gint hf_s7comm_szl_0424_0000_bzu_id = -1;
static gint hf_s7comm_szl_0424_0000_bzu_id_req = -1;
static gint hf_s7comm_szl_0424_0000_bzu_id_pre = -1;
static const value_string szl_0424_0000_bzu_id_names[] = {
    { 0x1,                                  "STOP (update)" },
    { 0x2,                                  "STOP (memory reset)" },
    { 0x3,                                  "STOP (self initialization)" },
    { 0x4,                                  "STOP (internal)" },
    { 0x5,                                  "Startup (complete restart)" },
    { 0x7,                                  "Restart" },
    { 0x8,                                  "RUN" },
    { 0xa,                                  "HOLD" },
    { 0xd,                                  "DEFECT" },
    { 0,                                    NULL }
};
static gint ett_s7comm_szl_0424_0000_bzu_id = -1;
static int * const s7comm_szl_0424_0000_bzu_id_fields[] = {
    &hf_s7comm_szl_0424_0000_bzu_id_req,
    &hf_s7comm_szl_0424_0000_bzu_id_pre,
    NULL
};
static gint hf_s7comm_szl_0424_0000_res = -1;
static gint hf_s7comm_szl_0424_0000_anlinfo1 = -1;
static gint hf_s7comm_szl_0424_0000_anlinfo2 = -1;
static const value_string szl_0424_0000_anlinfo2_names[] = {
    { 0x01,                                 "Complete restart in multicomputing" },
    { 0x03,                                 "Complete restart set at mode selector" },
    { 0x04,                                 "Complete restart command via MPI" },
    { 0x0a,                                 "Restart in multicomputing" },
    { 0x0b,                                 "Restart set at mode selector" },
    { 0x0c,                                 "Restart command via MPI" },
    { 0x10,                                 "Automatic complete restart after battery-backed power on" },
    { 0x13,                                 "Complete restart set at mode selector; last power on battery backed" },
    { 0x14,                                 "Complete restart command via MPI; last power on battery backed" },
    { 0x20,                                 "Automatic complete restart after non battery backed power on (with memory reset by system)" },
    { 0x23,                                 "Complete restart set at mode selector; last power on unbattery backed" },
    { 0x24,                                 "Complete restart command via MPI; last power on unbattery backed" },
    { 0xa0,                                 "Automatic restart after battery backed power on according to parameter assignment" },
    { 0,                                    NULL }
};
static gint hf_s7comm_szl_0424_0000_anlinfo3 = -1;
static gint hf_s7comm_szl_0424_0000_anlinfo4 = -1;
static const value_string szl_0424_0000_anlinfo4_names[] = {
    { 0x00,                                 "No startup type" },
    { 0x01,                                 "Complete restart in multicomputing" },
    { 0x03,                                 "Complete restart due to switch setting" },
    { 0x04,                                 "Complete restart command via MPI" },
    { 0x0a,                                 "Restart in multicomputing" },
    { 0x0b,                                 "Restart set at mode selector" },
    { 0x0c,                                 "Restart command via MPI" },
    { 0x10,                                 "Automatic complete restart after battery-backed power on" },
    { 0x13,                                 "Complete restart set at mode selector; last power on battery backed" },
    { 0x14,                                 "Complete restart command via MPI; last power on battery backed" },
    { 0x20,                                 "Automatic complete restart after non battery backed power on (with memory reset by system)" },
    { 0x23,                                 "Complete restart set at mode selector; last power on unbattery backed" },
    { 0x24,                                 "Complete restart command via MPI; last power on unbattery backed" },
    { 0xa0,                                 "Automatic restart after battery backed power on according to parameter assignment" },
    { 0,                                    NULL }
};
static gint hf_s7comm_szl_0424_0000_time = -1;

static gint hf_s7comm_szl_xy74_0000_cpu_led_id = -1;
static gint hf_s7comm_szl_xy74_0000_cpu_led_id_rackno = -1;
static gint hf_s7comm_szl_xy74_0000_cpu_led_id_cputype = -1;
static gint hf_s7comm_szl_xy74_0000_cpu_led_id_id = -1;
static gint hf_s7comm_szl_xy74_0000_led_on = -1;
static const value_string szl_xy74_0000_led_on_names[] = {
    { 0x0,                                  "Off" },
    { 0x1,                                  "On" },
    { 0,                                    NULL }
};

static gint hf_s7comm_szl_xy74_0000_led_blink = -1;
static const value_string szl_xy74_0000_led_blink_names[] = {
    { 0x0,                                  "Not flashing" },
    { 0x1,                                  "Flashing normally (2 Hz)" },
    { 0x2,                                  "Flashing slowly (0.5 Hz)" },
    { 0,                                    NULL }
};

/*******************************************************************************************************
 *
 * Get the textual description of the szl index. Returns NULL if not description available
 *
 *******************************************************************************************************/
static const gchar*
s7comm_get_szl_id_index_description_text(guint16 id, guint16 idx)
{
    const gchar* str = NULL;
    switch (id) {
        case 0x0111:
            str = val_to_str(idx, szl_0111_index_names, "No description available");
            break;
        case 0x0112:
            str = val_to_str(idx, szl_0112_index_names, "No description available");
            break;
        case 0x0113:
            str = val_to_str(idx, szl_0113_index_names, "No description available");
            break;
        case 0x0114:
            str = val_to_str(idx, szl_0114_index_names, "No description available");
            break;
        case 0x0115:
            str = val_to_str(idx, szl_0115_index_names, "No description available");
            break;
        case 0x0116:
            str = val_to_str(idx, szl_0116_index_names, "No description available");
            break;
        case 0x0118:
            str = val_to_str(idx, szl_0118_index_names, "No description available");
            break;
        case 0x0119:
            str = val_to_str(idx, szl_0119_0174_ledid_index_names, "No description available");
            break;
        case 0x0121:
            str = val_to_str(idx, szl_0121_index_names, "No description available");
            break;
        case 0x0222:
            str = val_to_str(idx, szl_0222_index_names, "No description available");
            break;
        case 0x0524:
            str = val_to_str(idx, szl_0524_index_names, "No description available");
            break;
        case 0x0131:
            str = val_to_str(idx, szl_0131_index_names, "No description available");
            break;
        case 0x0132:
            str = val_to_str(idx, szl_0132_index_names, "No description available");
            break;
        case 0x0174:
            str = val_to_str(idx, szl_0119_0174_ledid_index_names, "No description available");
            break;
        case 0x011c:
        case 0x031c:
            str = val_to_str(idx, szl_xy1c_index_names, "No description available");
            break;
    }
    return str;
}

/*******************************************************************************************************
 *******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 4 -> SZL functions -> All known SZD-ID and Indices
 *
 *******************************************************************************************************
 *******************************************************************************************************/

/*******************************************************************************************************
 *
 * SZL-ID:      0xxy00
 * Content:
 *   If you read the partial lists with SZL-ID W#16#xy00, you obtain the
 *   SZL-IDs supported by the module.
 *
 *  The SZL-ID of the partial list extract
 * W#16#0000H: all SZL partial lists of the module
 * W#16#0100H: a partial list with all partial list extracts
 * W#16#0200H: a partial list extract
 * W#16#0300H: possible indexes of a partial list extract
 * W#16#0F00H: only partial list header information
 *
 *******************************************************************************************************/
static void
s7comm_szl_0000_0000_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0000_0000_szl_id,
        { "SZL ID that exists", "s7comm.szl.0000.0000.szl_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &szl_id_partlist_ex_names_ext, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0000_0000_module_type_class,
        { "Module type class", "s7comm.szl.0000.0000.module_type_class", FT_UINT16, BASE_HEX, NULL, 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0000_0000_partlist_extr_nr,
        { "Number of the SZL partial list extract", "s7comm.szl.0000.0000.partlist_extr_nr", FT_UINT16, BASE_HEX, NULL, 0x0f00,
          NULL, HFILL }},
        { &hf_s7comm_szl_0000_0000_partlist_nr,
        { "Number of the SZL partial list", "s7comm.szl.0000.0000.partlist_nr", FT_UINT16, BASE_HEX, NULL, 0x00ff,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_xy00(tvbuff_t *tvb,
                          proto_tree *tree,
                          guint16 id,
                          guint16 idx,
                          guint32 offset)
{
    if (id == 0 && idx == 0) {
        proto_tree_add_item(tree, hf_s7comm_szl_0000_0000_szl_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else if (id == 0x0100) {
        proto_tree_add_item(tree, hf_s7comm_szl_0000_0000_module_type_class, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_s7comm_szl_0000_0000_partlist_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else if (id == 0x0200 || id == 0x0300) {
        proto_tree_add_item(tree, hf_s7comm_szl_0000_0000_module_type_class, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_s7comm_szl_0000_0000_partlist_extr_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_s7comm_szl_0000_0000_partlist_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else {
        /* 0x0f00 / 0x000: Partial list header information (number of all SZL-IDs of the module */
        proto_tree_add_item(tree, hf_s7comm_szl_0000_0000_szl_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0013
 * Index:   0x0000
 * Content:
 *  If you read the partial list with SZL-ID W#16#xy13, you obtain information
 *  about the memory areas of the module.
 *
 *  The SZL-ID of the partial list extract
 *      W#16#0013: data records of all memory areas
 *      W#16#0113: data record for one memory area, You specify the memory area with the INDEX parameter.
 *      W#16#0F13: only partial list header information
 *
 *******************************************************************************************************/
static void
s7comm_szl_0013_0000_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0013_0000_index,
        { "Index", "s7comm.szl.0013.0000.index", FT_UINT16, BASE_HEX, VALS(szl_0113_index_names), 0x0,
          "Index of an identification data record", HFILL }},
        { &hf_s7comm_szl_0013_0000_code,
        { "Code (Memory type)", "s7comm.szl.0013.0000.code", FT_UINT16, BASE_HEX, VALS(szl_memory_type_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0013_0000_size,
        { "Size (Total size of the selected memory, total of area 1 and area 2)", "s7comm.szl.0013.0000.size", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0013_0000_mode,
        { "Mode (Logical mode of the memory)", "s7comm.szl.0013.0000.mode", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0013_0000_mode_0,
        { "Volatile memory area", "s7comm.szl.0013.0000.mode.vol_mem", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Volatile memory area", HFILL }},
        { &hf_s7comm_szl_0013_0000_mode_1,
        { "Non-volatile memory area", "s7comm.szl.0013.0000.mode.nvol_mem", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Non-volatile memory area", HFILL }},
        { &hf_s7comm_szl_0013_0000_mode_2,
        { "Mixed memory area", "s7comm.szl.0013.0000.mode.mixed_mem", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Mixed memory area", HFILL }},
        { &hf_s7comm_szl_0013_0000_mode_3,
        { "Code and data separate (for work memory)", "s7comm.szl.0013.0000.mode.cd_sep", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Code and data separate (for work memory)", HFILL }},
        { &hf_s7comm_szl_0013_0000_mode_4,
        { "Code and data together (for work memory)", "s7comm.szl.0013.0000.mode.cd_tog", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Code and data together (for work memory)", HFILL }},
        { &hf_s7comm_szl_0013_0000_granu,
        { "Granu", "s7comm.szl.0013.0000.granu", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Granu (Always has the value 0)", HFILL }},
        { &hf_s7comm_szl_0013_0000_ber1,
        { "ber1 (Size of the volatile memory area in bytes)", "s7comm.szl.0013.0000.ber1", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0013_0000_belegt1,
        { "belegt1 (Size of the volatile memory area being used)", "s7comm.szl.0013.0000.belegt1", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0013_0000_block1,
        { "block1 (Largest free block in the volatile memory area)", "s7comm.szl.0013.0000.block1", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0013_0000_ber2,
        { "ber2 (Size of the non-volatile memory area in bytes)", "s7comm.szl.0013.0000.ber2", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0013_0000_belegt2,
        { "belegt2 (Size of the non-volatile memory area being used)", "s7comm.szl.0013.0000.belegt2", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0013_0000_block2,
        { "block2 (Largest free block in the non-volatile memory area)", "s7comm.szl.0013.0000.block2", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0013_idx_0000(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_mode_0, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_mode_1, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_mode_2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_mode_3, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_mode_4, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_granu, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_ber1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_belegt1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_block1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_ber2, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_belegt2, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_block2, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy14
 * Index:   0x000x
 * Content:
 *  If you read the system status list with SZL-ID W#16#xy14, you obtain
 *  information about the system areas of the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy14_000x_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_xy14_000x_index,
        { "Index", "s7comm.szl.xy14.000x.index", FT_UINT16, BASE_HEX, VALS(szl_0114_index_names), 0x0,
          "Index of the system area", HFILL }},
        { &hf_s7comm_szl_xy14_000x_code,
        { "Code (Memory type)", "s7comm.szl.xy14.000x.code", FT_UINT16, BASE_HEX, VALS(szl_memory_type_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy14_000x_quantity,
        { "Quantity (Number of elements of the system area)", "s7comm.szl.xy14.000x.quantity", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy14_000x_reman,
        { "Reman (Number of retentive elements)", "s7comm.szl.xy14.000x.reman", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_xy14_idx_000x(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_xy14_000x_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy14_000x_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy14_000x_quantity, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy14_000x_reman, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy15
 * Index:   0x000x
 * Content:
 *  If you read the system status list with SZL-ID W#16#xy14, you obtain
 *  the block types that exist on the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy15_000x_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_xy15_000x_index,
        { "Index", "s7comm.szl.xy15.000x.index", FT_UINT16, BASE_HEX, VALS(szl_0115_index_names), 0x0,
          "Block type number", HFILL }},
        { &hf_s7comm_szl_xy15_000x_maxanz,
        { "MaxAnz (Maximum number of blocks of the type)", "s7comm.szl.xy15.000x.maxanz", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy15_000x_maxlng,
        { "MaxLng (Maximum total size of the object to be loaded in Kbytes)", "s7comm.szl.xy15.000x.maxlng", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy15_000x_maxabl,
        { "MaxAbl (Maximum length of the work memory part of a block in bytes)", "s7comm.szl.xy15.000x.maxabl", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_xy15_idx_000x(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_xy15_000x_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy15_000x_maxanz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy15_000x_maxlng, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy15_000x_maxabl, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy11
 * Index:   0x0001
 * Content:
 *  If you read the system status list with SZL-ID W#16#xy11, you obtain the
 *  module identification of the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy11_0001_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_xy11_0001_index,
        { "Index", "s7comm.szl.xy11.0001.index", FT_UINT16, BASE_HEX, VALS(szl_0111_index_names), 0x0,
          "Index of an identification data record", HFILL }},
        { &hf_s7comm_szl_xy11_0001_mlfb,
        { "MlfB (Order number of the module)", "s7comm.szl.xy11.0001.anz", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy11_0001_bgtyp,
        { "BGTyp (Module type ID)", "s7comm.szl.xy11.0001.bgtyp", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy11_0001_ausbg,
        { "Ausbg (Version of the module or release of the operating system)", "s7comm.szl.xy11.0001.ausbg", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy11_0001_ausbe,
        { "Ausbe (Release of the PG description file)", "s7comm.szl.xy11.0001.ausbe", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0111_idx_0001(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_xy11_0001_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy11_0001_mlfb, tvb, offset, 20, ENC_ASCII|ENC_NA);
    offset += 20;
    proto_tree_add_item(tree, hf_s7comm_szl_xy11_0001_bgtyp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy11_0001_ausbg, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy11_0001_ausbe, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy22
 * Index:   0x00xx
 * Content:
 *  Contains information about the current status of interrupt
 *  processing and interrupt generation in the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy22_00xx_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_xy22_00xx_info,
        { "Start info for the given OB", "s7comm.szl.xy22.00xx.info", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1,
        { "al1 (Processing identifiers)", "s7comm.szl.xy22.00xx.al1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_0,
        { "Interrupt event is caused by parameters disabled", "s7comm.szl.xy22.00xx.al1.evpd", FT_BOOLEAN, 16, NULL, 0x01,
          "Bit 0: Interrupt event is caused by parameters, 0=Enabled, 1=Disabled", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_1,
        { "Interrupt event as per SFC 39 locked", "s7comm.szl.xy22.00xx.al1.iel", FT_BOOLEAN, 16, NULL, 0x02,
          "Bit 1: Interrupt event as per SFC 39, 0=Not locked, 1=Locked", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_2,
        { "Interrupt source is active", "s7comm.szl.xy22.00xx.al1.isia", FT_BOOLEAN, 16, NULL, 0x04,
          "Bit 2: Interrupt source is active", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_4,
        { "Interrupt OB is loaded", "s7comm.szl.xy22.00xx.al1.ioil", FT_BOOLEAN, 16, NULL, 0x10,
          "Bit 4: Interrupt OB, 0=Is not loaded, 1=Is loaded", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_5,
        { "Interrupt OB is locked by TIS", "s7comm.szl.xy22.00xx.al1.ioilbt", FT_BOOLEAN, 16, NULL, 0x20,
          "Bit 5: Interrupt OB is by TIS, 1=Locked", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_6,
        { "Entry in diagnostic buffer locked", "s7comm.szl.xy22.00xx.al1.eidbl", FT_BOOLEAN, 16, NULL, 0x40,
          "Bit 6: Entry in diagnostic buffer, 1=Locked", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2,
        { "al2 (Reaction with not loaded/locked OB)", "s7comm.szl.xy22.00xx.al2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2_0,
        { "Lock interrupt source", "s7comm.szl.xy22.00xx.al2.lis", FT_BOOLEAN, 16, NULL, 0x01,
          "Bit 0: Lock interrupt source", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2_1,
        { "Generate interrupt event error", "s7comm.szl.xy22.00xx.al2.giee", FT_BOOLEAN, 16, NULL, 0x02,
          "Bit 1: Generate interrupt event error", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2_2,
        { "CPU goes into STOP mode", "s7comm.szl.xy22.00xx.al2.gism", FT_BOOLEAN, 16, NULL, 0x04,
          "Bit 2: CPU goes into STOP mode", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2_3,
        { "Interrupt only discarded", "s7comm.szl.xy22.00xx.al2.iod", FT_BOOLEAN, 16, NULL, 0x08,
          "Bit 3: Interrupt only discarded", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al3,
        { "al3 (Discarded by TIS functions)", "s7comm.szl.xy22.00xx.al3", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_xy22_idx_00xx(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_xy22_00xx_info, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_xy22_00xx_al1,
        ett_s7comm_szl_xy22_00xx_al1, s7comm_szl_xy22_00xx_al1_fields, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_xy22_00xx_al2,
        ett_s7comm_szl_xy22_00xx_al2, s7comm_szl_xy22_00xx_al2_fields, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy22_00xx_al3, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0001
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and the index W#16#0001
 *  contains general data about the communication of a communication unit.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0001_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0001_index,
        { "Index", "s7comm.szl.0131.0001.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0001: Index for general communication data", HFILL }},
        { &hf_s7comm_szl_0131_0001_pdu,
        { "pdu (Maximum PDU size in bytes)", "s7comm.szl.0131.0001.pdu", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Maximum PDU size in bytes", HFILL }},
        { &hf_s7comm_szl_0131_0001_anz,
        { "anz (Maximum number of communication connections)", "s7comm.szl.0131.0001.anz", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Maximum number of communication connections", HFILL }},
        { &hf_s7comm_szl_0131_0001_mpi_bps,
        { "mpi_bps (Maximum data rate of the MPI in hexadecimal format)", "s7comm.szl.0131.0001.mpi_bps", FT_UINT32, BASE_HEX, NULL, 0x0,
          "Maximum data rate of the MPI in hexadecimal format, Example: 0x2DC6C corresponds to 187500 bps", HFILL }},
        { &hf_s7comm_szl_0131_0001_kbus_bps,
        { "mkbus_bps (Maximum data rate of the communication bus)", "s7comm.szl.0131.0001.kbus_bps", FT_UINT32, BASE_HEX, NULL, 0x0,
          "Maximum data rate of the communication bus", HFILL }},
        { &hf_s7comm_szl_0131_0001_res,
        { "res (Reserved)", "s7comm.szl.0131.0001.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          "Reserved", HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0001(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_pdu, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_anz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_mpi_bps, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_kbus_bps, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_res, tvb, offset, 26, ENC_NA);
    offset += 26;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0002
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and the index W#16#0002
 *  contains information about the test and installation constants of the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0002_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0002_index,
        { "Index", "s7comm.szl.0131.0002.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0002: test and installation", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_0,
        { "funkt_0", "s7comm.szl.0131.0002.funkt_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_0_0,
        { "Reserved", "s7comm.szl.0131.0002.funkt_0.bit0_res", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_0_1,
        { "Block status", "s7comm.szl.0131.0002.funkt_0.block_stat", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Block status", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_0_2,
        { "Variable status", "s7comm.szl.0131.0002.funkt_0.var_stat", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Variable status", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_0_3,
        { "Output ISTACK", "s7comm.szl.0131.0002.funkt_0.outp_istack", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Output ISTACK", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_0_4,
        { "Output BSTACK", "s7comm.szl.0131.0002.funkt_0.outp_bstack", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Output BSTACK", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_0_5,
        { "Output LSTACK", "s7comm.szl.0131.0002.funkt_0.outp_lstack", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Output LSTACK", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_0_6,
        { "Time measurement from ... to ...", "s7comm.szl.0131.0002.funkt_0.time_meas", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Time measurement from ... to ...", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_0_7,
        { "Force selection", "s7comm.szl.0131.0002.funkt_0.force_sel", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Force selection", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_1,
        { "funkt_1", "s7comm.szl.0131.0002.funkt_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_1_0,
        { "Modify variable", "s7comm.szl.0131.0002.funkt_1.mod_var", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Modify variable", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_1_1,
        { "Force", "s7comm.szl.0131.0002.funkt_1.force", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Force", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_1_2,
        { "Breakpoint", "s7comm.szl.0131.0002.funkt_1.breakp", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Breakpoint", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_1_3,
        { "Exit HOLD", "s7comm.szl.0131.0002.funkt_1.exit_hold", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Exit HOLD", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_1_4,
        { "Memory reset", "s7comm.szl.0131.0002.funkt_1.mem_res", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Memory reset", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_1_5,
        { "Disable job", "s7comm.szl.0131.0002.funkt_1.dis_job", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Disable job", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_1_6,
        { "Enable job", "s7comm.szl.0131.0002.funkt_1.en_job", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Enable job", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_1_7,
        { "Delete job", "s7comm.szl.0131.0002.funkt_1.del_job", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Delete job", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_2,
        { "funkt_2", "s7comm.szl.0131.0002.funkt_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_2_0,
        { "Read job list", "s7comm.szl.0131.0002.funkt_2.rd_job_list", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Read job list", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_2_1,
        { "Read job", "s7comm.szl.0131.0002.funkt_2.rd_job", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Read job", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_2_2,
        { "Replace job", "s7comm.szl.0131.0002.funkt_2.repl_job", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Replace job", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_2_3,
        { "Block status v2", "s7comm.szl.0131.0002.funkt_2.block_stat_v2", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Block status v2", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_2_4,
        { "Reserved", "s7comm.szl.0131.0002.funkt_2.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_2_5,
        { "Reserved", "s7comm.szl.0131.0002.funkt_2.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_2_6,
        { "Flash LED", "s7comm.szl.0131.0002.funkt_2.flash_led", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Flash LED", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_2_7,
        { "Reserved", "s7comm.szl.0131.0002.funkt_2.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_3,
        { "funkt_3 (Reserved)", "s7comm.szl.0131.0002.funkt_3", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_4,
        { "funkt_4 (Reserved)", "s7comm.szl.0131.0002.funkt_4", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0002_funkt_5,
        { "funkt_5 (Reserved)", "s7comm.szl.0131.0002.funkt_5", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0002_aseg,
        { "aseg", "s7comm.szl.0131.0002.aseg", FT_BYTES, BASE_NONE, NULL, 0x0,
          "aseg (Non-relevant system data)", HFILL }},
        { &hf_s7comm_szl_0131_0002_eseg,
        { "eseg", "s7comm.szl.0131.0002.eseg", FT_BYTES, BASE_NONE, NULL, 0x0,
          "eseg (Non-relevant system data)", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_0,
        { "trgereig_0 (Permitted trigger events)", "s7comm.szl.0131.0002.trgereig_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_0_0,
        { "Immediately", "s7comm.szl.0131.0002.trgereig_0.immed", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: immediately", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_0_1,
        { "System trigger", "s7comm.szl.0131.0002.trgereig_0.sys_trig", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: System trigger", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_0_2,
        { "System checkpoint main cycle start", "s7comm.szl.0131.0002.trgereig_0.sys_cp_mcs", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: System checkpoint main cycle start", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_0_3,
        { "System checkpoint main cycle end", "s7comm.szl.0131.0002.trgereig_0.sys_cp_mce", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: System checkpoint main cycle end", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_0_4,
        { "Mode transition RUN-STOP", "s7comm.szl.0131.0002.trgereig_0.mtrans_rs", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Mode transition RUN-STOP", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_0_5,
        { "After code address", "s7comm.szl.0131.0002.trgereig_0.acode_adr", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: After code address", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_0_6,
        { "Code address area", "s7comm.szl.0131.0002.trgereig_0.code_adr_a", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Code address area", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_0_7,
        { "Data address", "s7comm.szl.0131.0002.trgereig_0.data_adr", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Data Address", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_1,
        { "trgereig_1 (Permitted trigger events)", "s7comm.szl.0131.0002.trgereig_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_1_0,
        { "Data address area", "s7comm.szl.0131.0002.trgereig_1.data_adr_a", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Data address area", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_1_1,
        { "Local data address", "s7comm.szl.0131.0002.trgereig_1.loc_adr", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Local data address", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_1_2,
        { "Local data address area", "s7comm.szl.0131.0002.trgereig_1.loc_adr_a", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Local data address area", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_1_3,
        { "Range trigger", "s7comm.szl.0131.0002.trgereig_1.range_trig", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Range trigger", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_1_4,
        { "Before code address", "s7comm.szl.0131.0002.trgereig_1.bcode_adr", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Before code address", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_1_5,
        { "Reserved", "s7comm.szl.0131.0002.trgereig_1.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_1_6,
        { "Reserved", "s7comm.szl.0131.0002.trgereig_1.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_1_7,
        { "Reserved", "s7comm.szl.0131.0002.trgereig_1.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0002_trgereig_2,
        { "trgereig_2 (Permitted trigger events, reserved)", "s7comm.szl.0131.0002.trgereig_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_trgbed,
        { "trgbed (System data with no relevance)", "s7comm.szl.0131.0002.trgbed", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_pfad,
        { "pfad (System data with no relevance)", "s7comm.szl.0131.0002.pfad", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_tiefe,
        { "tiefe (System data with no relevance)", "s7comm.szl.0131.0002.tiefe", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_systrig,
        { "systrig (System data with no relevance)", "s7comm.szl.0131.0002.systrig", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_erg_par,
        { "erg par (System data with no relevance)", "s7comm.szl.0131.0002.erg_par", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_erg_pat_1,
        { "erg pat 1 (System data with no relevance)", "s7comm.szl.0131.0002.erg_pat_1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_erg_pat_2,
        { "erg pat 2 (System data with no relevance)", "s7comm.szl.0131.0002.erg_pat_2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_force,
        { "force (Number of modifiable Variables)", "s7comm.szl.0131.0002.force", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0002_time,
        { "time", "s7comm.szl.0131.0002.time", FT_UINT16, BASE_HEX, NULL, 0x0,
          "time (Upper time limit run-time meas, Format: bits 0 to 11 contain the time value (0 to 4K-1); bits 12 to 15 contain the time base: 0H= 10^-10s, 1H = 10^-9s,...,AH = 100s, ... FH = 105s)", HFILL }},
        { &hf_s7comm_szl_0131_0002_res,
        { "res (Reserved)", "s7comm.szl.0131.0002.res", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0002(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0002_funkt_0,
        ett_s7comm_szl_0131_0002_funkt_0, s7comm_szl_0131_0002_funkt_0_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0002_funkt_1,
        ett_s7comm_szl_0131_0002_funkt_1, s7comm_szl_0131_0002_funkt_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0002_funkt_2,
        ett_s7comm_szl_0131_0002_funkt_2, s7comm_szl_0131_0002_funkt_2_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_aseg, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_eseg, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0002_trgereig_0,
        ett_s7comm_szl_0131_0002_trgereig_0, s7comm_szl_0131_0002_trgereig_0_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0002_trgereig_1,
        ett_s7comm_szl_0131_0002_trgereig_1, s7comm_szl_0131_0002_trgereig_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgbed, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_pfad, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_tiefe, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_systrig, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_erg_par, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_erg_pat_1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_erg_pat_2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_force, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_res, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0003
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and the index W#16#0003
 *  contains information about the communication parameters of the module for
 *  connection to a unit for operator interface functions.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0003_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0003_index,
        { "Index", "s7comm.szl.0131.0003.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0003: Index for operator interface functions", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_0,
        { "funkt_0", "s7comm.szl.0131.0003.funkt_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Bits indicating the available functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_0_0,
        { "Read once", "s7comm.szl.0131.0003.funkt_0.read_once", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Read once", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_0_1,
        { "Write once", "s7comm.szl.0131.0003.funkt_0.write_once", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Write once", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_0_2,
        { "Initialize cyclic reading (start implicitly)", "s7comm.szl.0131.0003.funkt_0.init_cycl_read_impl", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Initialize cyclic reading (start implicitly)", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_0_3,
        { "Initialize cyclic reading (start explicitly)", "s7comm.szl.0131.0003.funkt_0.init_cycl_read_expl", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Initialize cyclic reading (start explicitly)", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_0_4,
        { "Start cyclic reading", "s7comm.szl.0131.0003.funkt_0.start_cycl_read", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Start cyclic reading", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_0_5,
        { "Stop cyclic reading", "s7comm.szl.0131.0003.funkt_0.stop_cycl_read", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Stop cyclic reading", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_0_6,
        { "Clear cyclic reading", "s7comm.szl.0131.0002.funkt_0.clr_cycl_read", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Clear cyclic reading", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_0_7,
        { "Reserved", "s7comm.szl.0131.0002.funkt_0.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_1,
        { "funkt_1", "s7comm.szl.0131.0003.funkt_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Bits indicating the available functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_1_0,
        { "Reserved", "s7comm.szl.0131.0003.funkt_1.bit0_res", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_1_1,
        { "Reserved", "s7comm.szl.0131.0003.funkt_1.bit1_res", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_1_2,
        { "Reserved", "s7comm.szl.0131.0003.funkt_1.bit2_res", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_1_3,
        { "Reserved", "s7comm.szl.0131.0003.funkt_1.bit3_res", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_1_4,
        { "Peripheral I/Os", "s7comm.szl.0131.0003.funkt_1.periph_io", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Peripheral I/Os", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_1_5,
        { "Inputs", "s7comm.szl.0131.0003.funkt_1.inputs", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Inputs", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_1_6,
        { "Outputs", "s7comm.szl.0131.0002.funkt_1.outputs", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Outputs", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_1_7,
        { "Bit memory", "s7comm.szl.0131.0002.funkt_1.bit_mem", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Bit memory", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_2,
        { "funkt_2", "s7comm.szl.0131.0003.funkt_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Bits indicating the available functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_2_0,
        { "User DB", "s7comm.szl.0131.0003.funkt_2.user_db", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: User DB", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_2_1,
        { "Data record", "s7comm.szl.0131.0003.funkt_2.data_rec", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Data record", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_2_2,
        { "Reserved", "s7comm.szl.0131.0003.funkt_2.bit2_res", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_2_3,
        { "Reserved", "s7comm.szl.0131.0003.funkt_2.bit3_res", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_2_4,
        { "Reserved", "s7comm.szl.0131.0003.funkt_2.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_2_5,
        { "Reserved", "s7comm.szl.0131.0003.funkt_2.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_2_6,
        { "Reserved", "s7comm.szl.0131.0002.funkt_2.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_2_7,
        { "S7 counter", "s7comm.szl.0131.0002.funkt_2.s7_counter", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: S7 counter", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_3,
        { "funkt_3", "s7comm.szl.0131.0003.funkt_3", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Bits indicating the available functions (bit = 1: function exists)", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_3_0,
        { "S7 timer", "s7comm.szl.0131.0003.funkt_3.s7_timer", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: S7 timer", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_3_1,
        { "IEC counter", "s7comm.szl.0131.0003.funkt_3.iec_counter", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: IEC counter", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_3_2,
        { "IEC timer", "s7comm.szl.0131.0003.funkt_3.iec_timer", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: IEC timer", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_3_3,
        { "High speed counter", "s7comm.szl.0131.0003.funkt_3.hs_counter", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: High speed counter", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_3_4,
        { "Reserved", "s7comm.szl.0131.0003.funkt_3.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_3_5,
        { "Reserved", "s7comm.szl.0131.0003.funkt_3.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_3_6,
        { "Reserved", "s7comm.szl.0131.0002.funkt_3.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_funkt_3_7,
        { "Reserved", "s7comm.szl.0131.0002.funkt_3.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0003_data,
        { "data (Maximum size of consistently readable data)", "s7comm.szl.0131.0003.data", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0003_anz,
        { "anz (Maximum number of cyclic read jobs)", "s7comm.szl.0131.0003.anz", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0003_per_min,
        { "per min (Minimum period for cyclic read jobs (n x 100 ms)", "s7comm.szl.0131.0003.per_min", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0003_per_max,
        { "per max (Maximum period for cyclic read jobs (n x 100 ms)", "s7comm.szl.0131.0003.per_max", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0003_res,
        { "res (Reserved)", "s7comm.szl.0131.0003.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0003(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0003_funkt_0,
        ett_s7comm_szl_0131_0003_funkt_0, s7comm_szl_0131_0003_funkt_0_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0003_funkt_1,
        ett_s7comm_szl_0131_0003_funkt_1, s7comm_szl_0131_0003_funkt_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0003_funkt_2,
        ett_s7comm_szl_0131_0003_funkt_2, s7comm_szl_0131_0003_funkt_2_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0003_funkt_3,
        ett_s7comm_szl_0131_0003_funkt_3, s7comm_szl_0131_0003_funkt_3_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_data, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_anz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_per_min, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_per_max, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_res, tvb, offset, 26, ENC_NA);
    offset += 26;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0004
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and the index W#16#0004
 *  contains information about the object management system (OMS) of the
 *  module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0004_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0004_index,
        { "Index", "s7comm.szl.0131.0004.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0004 Index for OMS", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_0,
        { "funkt_0", "s7comm.szl.0131.0004.funkt_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_0_0,
        { "Reserved", "s7comm.szl.0131.0004.funkt_0.bit0_res", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_0_1,
        { "Directory (hierarchy 1)", "s7comm.szl.0131.0004.funkt_0.dir_h1", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Directory (hierarchy 1)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_0_2,
        { "Directory (hierarchy 2)", "s7comm.szl.0131.0004.funkt_0.dir_h2", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Directory (hierarchy 2)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_0_3,
        { "Directory (hierarchy 3)", "s7comm.szl.0131.0004.funkt_0.dir_h3", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Directory (hierarchy 3)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_0_4,
        { "Copy", "s7comm.szl.0131.0004.funkt_0.copy", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Copy", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_0_5,
        { "Chain (list)", "s7comm.szl.0131.0004.funkt_0.chain_list", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Chain (list)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_0_6,
        { "Chain (all copied)", "s7comm.szl.0131.0004.funkt_0.chain_copied", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Chain (all copied)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_0_7,
        { "Delete (list)", "s7comm.szl.0131.0004.funkt_0.delete_list", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Delete (list)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_1,
        { "funkt_1", "s7comm.szl.0131.0004.funkt_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_1_0,
        { "Upload on PG", "s7comm.szl.0131.0004.funkt_1.upl_on_pg", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Upload on PG", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_1_1,
        { "Assign parameters when chaining", "s7comm.szl.0131.0004.funkt_1.asgn_w_chain", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Assign parameters when chaining", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_1_2,
        { "LOAD function when exchanging data with CFBs", "s7comm.szl.0131.0004.funkt_1.load_w_chg", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: LOAD function when exchanging data with CFBs", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_1_3,
        { "Reserved", "s7comm.szl.0131.0004.funkt_1.bit3_res", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_1_4,
        { "Reserved", "s7comm.szl.0131.0004.funkt_1.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_1_5,
        { "Reserved", "s7comm.szl.0131.0004.funkt_1.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_1_6,
        { "Reserved", "s7comm.szl.0131.0004.funkt_1.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_1_7,
        { "Delete *.*", "s7comm.szl.0131.0004.funkt_1.delete_all", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Delete *.*", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_2,
        { "funkt_2", "s7comm.szl.0131.0004.funkt_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_2_0,
        { "Load user program (RAM)", "s7comm.szl.0131.0004.funkt_2.load_ram", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Load user program (RAM)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_2_1,
        { "Load user program (EPROM)", "s7comm.szl.0131.0004.funkt_2.load_eprom", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Load user program (EPROM)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_2_2,
        { "Save user program (RAM)", "s7comm.szl.0131.0004.funkt_2.save_ram", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Save user program (RAM)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_2_3,
        { "Save user program (EPROM)", "s7comm.szl.0131.0004.funkt_2.save_eprom", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Save user program (EPROM)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_2_4,
        { "Save user program (all)", "s7comm.szl.0131.0004.funkt_2.save_all", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Save user program (all)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_2_5,
        { "Compress (external)", "s7comm.szl.0131.0004.funkt_2.compress", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Compress (external)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_2_6,
        { "Firmware update (using communication)", "s7comm.szl.0131.0004.funkt_2.fw_update", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Firmware update (using communication)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_2_7,
        { "Set RAM memory mode", "s7comm.szl.0131.0004.funkt_2.set_ram_mode", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Set RAM memory mode", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_3,
        { "funkt_3", "s7comm.szl.0131.0004.funkt_3", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_3_0,
        { "Set EPROM memory mode", "s7comm.szl.0131.0004.funkt_3.set_eprom_mode", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Set EPROM memory mode", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_3_1,
        { "Reserved", "s7comm.szl.0131.0004.funkt_3.bit1_res", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_3_2,
        { "Reserved", "s7comm.szl.0131.0004.funkt_3.bit2_res", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_3_3,
        { "Reserved", "s7comm.szl.0131.0004.funkt_3.bit3_res", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_3_4,
        { "Reserved", "s7comm.szl.0131.0004.funkt_3.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_3_5,
        { "Reserved", "s7comm.szl.0131.0004.funkt_3.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_3_6,
        { "Assign parameters to newly plugged in modules", "s7comm.szl.0131.0004.funkt_3.asgn_par_mod", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Assign parameters to newly plugged in modules", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_3_7,
        { "Assign parameters when evaluating memory card", "s7comm.szl.0131.0004.funkt_3.asgn_par_mc", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Assign parameters when evaluating memory card", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_4,
        { "funkt_4", "s7comm.szl.0131.0004.funkt_4", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_4_0,
        { "Assign parameters when loading user program", "s7comm.szl.0131.0004.funkt_4.asgn_par_lprog", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Assign parameters when loading user program", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_4_1,
        { "Assign parameters in complete restart", "s7comm.szl.0131.0004.funkt_4.asgn_par_cres", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Assign parameters in complete restart", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_4_2,
        { "Assign parameters in restart", "s7comm.szl.0131.0004.funkt_4.asgn_par_res", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Assign parameters in restart", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_4_3,
        { "Compress (SFC25 COMPRESS)", "s7comm.szl.0131.0004.funkt_4.compress", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Compress (SFC25 COMPRESS)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_4_4,
        { "Evaluate memory card after switch setting", "s7comm.szl.0131.0004.funkt_4.ev_mc", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Evaluate memory card after switch setting", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_4_5,
        { "Firmware update using memory card", "s7comm.szl.0131.0004.funkt_4.fw_update_mc", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Firmware update using memory card", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_4_6,
        { "Reserved", "s7comm.szl.0131.0004.funkt_4.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_4_7,
        { "Reserved", "s7comm.szl.0131.0004.funkt_4.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_5,
        { "funkt_5 (Reserved)", "s7comm.szl.0131.0004.funkt_5", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_6,
        { "funkt_6 (Reserved)", "s7comm.szl.0131.0004.funkt_6", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
        { &hf_s7comm_szl_0131_0004_funkt_7,
        { "funkt_7 (Reserved)", "s7comm.szl.0131.0004.funkt_7", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
        { &hf_s7comm_szl_0131_0004_kop,
        { "kop (Maximum number of copied blocks)", "s7comm.szl.0131.0004.kop", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0004_del,
        { "del (Maximum number of uninterruptable, deletable blocks)", "s7comm.szl.0131.0004.del", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0004_kett,
        { "kett (Maximum number of blocks chained in one job)", "s7comm.szl.0131.0004.kett", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0004_hoch,
        { "hoch (Maximum number of simultaneous upload procedures)", "s7comm.szl.0131.0004.hoch", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0004_ver,
        { "ver (Maximum size (in bytes) of shiftable blocks in RUN)", "s7comm.szl.0131.0004.hoch", FT_UINT8, BASE_DEC, NULL, 0x0,
          "ver (Maximum size (in bytes) of shiftable blocks in RUN) With an S7-300, this size refers to the entire block,with the S7-400, it refers to the part of the block relevant to running the program.", HFILL }},
        { &hf_s7comm_szl_0131_0004_res,
        { "res (Reserved)", "s7comm.szl.0131.0004.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0004(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0004_funkt_0,
        ett_s7comm_szl_0131_0004_funkt_0, s7comm_szl_0131_0004_funkt_0_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0004_funkt_1,
        ett_s7comm_szl_0131_0004_funkt_1, s7comm_szl_0131_0004_funkt_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0004_funkt_2,
        ett_s7comm_szl_0131_0004_funkt_2, s7comm_szl_0131_0004_funkt_2_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0004_funkt_3,
        ett_s7comm_szl_0131_0004_funkt_3, s7comm_szl_0131_0004_funkt_3_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0004_funkt_4,
        ett_s7comm_szl_0131_0004_funkt_4, s7comm_szl_0131_0004_funkt_4_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_kop, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_del, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_kett, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_hoch, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_res, tvb, offset, 25, ENC_NA);
    offset += 25;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0005
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and the index W#16#0005
 *  contains information about the diagnostic capabilities of the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0005_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0005_index,
        { "Index", "s7comm.szl.0131.0005.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0005 Index for Diagnostics", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_0,
        { "funkt_0 (Available diagnostic functions)", "s7comm.szl.0131.0005.funkt_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Available diagnostic functions: (Bit = 1: functions exists)", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_0_0,
        { "Reserved", "s7comm.szl.0131.0005.funkt_0.bit0_res", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_0_1,
        { "Diagnostic buffer exists", "s7comm.szl.0131.0005.funkt_0.diag_buf", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Diagnostic buffer exists", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_0_2,
        { "Sending system diagnostic data possible", "s7comm.szl.0131.0005.funkt_0.sysdiag", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Sending system diagnostic data possible", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_0_3,
        { "Sending user-defined diagnostic messages possible", "s7comm.szl.0131.0005.funkt_0.userdiag", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Sending user-defined diagnostic messages possible", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_0_4,
        { "Sending VMD status possible", "s7comm.szl.0131.0005.funkt_0.vmdstat", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Sending VMD status possible", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_0_5,
        { "Evaluating diagnostic interrupts", "s7comm.szl.0131.0005.funkt_0.evaldiagint", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Evaluating diagnostic interrupts", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_0_6,
        { "Diagnostic interrupt exists on module", "s7comm.szl.0131.0005.funkt_0.diagint", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Diagnostic interrupt exists on module", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_0_7,
        { "Reserved", "s7comm.szl.0131.0005.funkt_0.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_1,
        { "funkt_1 (Reserved)", "s7comm.szl.0131.0005.funkt_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_2,
        { "funkt_2 (Reserved)", "s7comm.szl.0131.0005.funkt_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_3,
        { "funkt_3 (Reserved)", "s7comm.szl.0131.0005.funkt_3", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_4,
        { "funkt_4 (Reserved)", "s7comm.szl.0131.0005.funkt_4", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_5,
        { "funkt_5 (Reserved)", "s7comm.szl.0131.0005.funkt_5", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_6,
        { "funkt_6 (Reserved)", "s7comm.szl.0131.0005.funkt_6", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_funkt_7,
        { "funkt_7 (Reserved)", "s7comm.szl.0131.0005.funkt_7", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_anz_sen,
        { "anz_sen (Maximum number of diagnostic data sinks)", "s7comm.szl.0131.0005.anz_sen", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_anz_ein,
        { "anz_ein (Maximum number of entries in the diagnostic buffer)", "s7comm.szl.0131.0005.anz_ein", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_anz_mel,
        { "anz_mel (Maximum number of process control group messages)", "s7comm.szl.0131.0005.anz_mel", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0005_res,
        { "res (Reserved)", "s7comm.szl.0131.0005.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0005(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0005_funkt_0,
        ett_s7comm_szl_0131_0005_funkt_0, s7comm_szl_0131_0005_funkt_0_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_funkt_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_funkt_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_funkt_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_funkt_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_funkt_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_funkt_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_funkt_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_anz_sen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_anz_ein, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_anz_mel, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0005_res, tvb, offset, 24, ENC_NA);
    offset += 24;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0006
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and the index W#16#0006
 *  contains information about the functions available for data exchange with
 *  communication SFBs for configured connections on the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0006_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0006_index,
        { "Index", "s7comm.szl.0131.0006.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0006 Data exchange with communication SFBs for configured connections", HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_0,
        { "funkt_0", "s7comm.szl.0131.0006.funkt_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Block types available for data exchange with communication SFBs for configured connections", HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_0_0,
        { "Bit 0: USEND", "s7comm.szl.0131.0006.funkt_0.usend", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_0_1,
        { "Bit 1: URCV", "s7comm.szl.0131.0006.funkt_0.urcv", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_0_2,
        { "Bit 2: SEND", "s7comm.szl.0131.0006.funkt_0.send", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_0_3,
        { "Bit 3: RCV", "s7comm.szl.0131.0006.funkt_0.rcv", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_0_4,
        { "Bit 4: BSEND", "s7comm.szl.0131.0006.funkt_0.bsend", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_0_5,
        { "Bit 5: BRCV", "s7comm.szl.0131.0006.funkt_0.brcv", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_0_6,
        { "Bit 6: GET", "s7comm.szl.0131.0006.funkt_0.get", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_0_7,
        { "Bit 7: PUT", "s7comm.szl.0131.0006.funkt_0.put", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_1,
        { "funkt_1", "s7comm.szl.0131.0006.funkt_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Block types available for data exchange with communication SFBs for configured connections", HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_1_0,
        { "Bit 0: PRINT", "s7comm.szl.0131.0006.funkt_1.print", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_1_1,
        { "Bit 1: ABORT", "s7comm.szl.0131.0006.funkt_1.abort", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_1_2,
        { "Bit 2: INITIATE", "s7comm.szl.0131.0006.funkt_1.initiate", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_1_3,
        { "Bit 3: START", "s7comm.szl.0131.0006.funkt_1.start", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_1_4,
        { "Bit 4: STOP", "s7comm.szl.0131.0006.funkt_1.stop", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_1_5,
        { "Bit 5: RESUME", "s7comm.szl.0131.0006.funkt_1.resume", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_1_6,
        { "Bit 6: STATUS", "s7comm.szl.0131.0006.funkt_1.status", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_1_7,
        { "Bit 7: USTATUS", "s7comm.szl.0131.0006.funkt_1.ustatus", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_2,
        { "funkt_2", "s7comm.szl.0131.0006.funkt_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Block types available for data exchange with communication SFBs for configured connections", HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_2_0,
        { "Bit 0: PI", "s7comm.szl.0131.0006.funkt_2.pi", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_2_1,
        { "Bit 1: READ", "s7comm.szl.0131.0006.funkt_2.read", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_2_2,
        { "Bit 2: WRITE", "s7comm.szl.0131.0006.funkt_2.write", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_2_3,
        { "Bit 3: LOAD", "s7comm.szl.0131.0006.funkt_2.load", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_2_4,
        { "Bit 4: LOAD_ME", "s7comm.szl.0131.0006.funkt_2.load_me", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_2_5,
        { "Bit 5: ALARM", "s7comm.szl.0131.0006.funkt_2.alarm", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_2_6,
        { "Bit 6: ALARM_8", "s7comm.szl.0131.0006.funkt_2.alarm_8", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_2_7,
        { "Bit 7: ALARM_8P", "s7comm.szl.0131.0006.funkt_2.alarm_8p", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_3,
        { "funkt_3", "s7comm.szl.0131.0006.funkt_3", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Block types available for data exchange with communication SFBs for configured connections", HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_3_0,
        { "Bit 0: NOTIFY", "s7comm.szl.0131.0006.funkt_3.notify", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_3_1,
        { "Bit 1: AR_SEND", "s7comm.szl.0131.0006.funkt_3.ar_send", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_3_2,
        { "Bit 2: Reserved", "s7comm.szl.0131.0006.funkt_3.bit2_res", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_3_3,
        { "Bit 3: Reserved", "s7comm.szl.0131.0006.funkt_3.bit3_res", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_3_4,
        { "Bit 4: Reserved", "s7comm.szl.0131.0006.funkt_3.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_3_5,
        { "Bit 5: Reserved", "s7comm.szl.0131.0006.funkt_3.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_3_6,
        { "Bit 6: Reserved", "s7comm.szl.0131.0006.funkt_3.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_3_7,
        { "Bit 7: Reserved", "s7comm.szl.0131.0006.funkt_3.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_4,
        { "funkt_4", "s7comm.szl.0131.0006.funkt_4", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_5,
        { "funkt_5", "s7comm.szl.0131.0006.funkt_5", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_6,
        { "funkt_6", "s7comm.szl.0131.0006.funkt_6", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Block types available for data exchange with communication SFBs for configured connections", HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_6_0,
        { "Bit 0: X_SEND", "s7comm.szl.0131.0006.funkt_6.x_send", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_6_1,
        { "Bit 1: X_RCV", "s7comm.szl.0131.0006.funkt_6.x_rcv", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_6_2,
        { "Bit 2: X_GET", "s7comm.szl.0131.0006.funkt_6.x_get", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_6_3,
        { "Bit 3: X_PUT", "s7comm.szl.0131.0006.funkt_6.x_put", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_6_4,
        { "Bit 4: X_ABORT", "s7comm.szl.0131.0006.funkt_6.x_abort", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_6_5,
        { "Bit 5: I_GET", "s7comm.szl.0131.0006.funkt_6.i_get", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_6_6,
        { "Bit 6: I_PUT", "s7comm.szl.0131.0006.funkt_6.i_put", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_6_7,
        { "Bit 7: I_ABORT", "s7comm.szl.0131.0006.funkt_6.i_abort", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_7,
        { "funkt_7", "s7comm.szl.0131.0006.funkt_7", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Block types available for data exchange with communication SFBs for configured connections", HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_7_0,
        { "Bit 0: SCAN_SND", "s7comm.szl.0131.0006.funkt_7.scan_snd", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_7_1,
        { "Bit 1: ALARM_SQ", "s7comm.szl.0131.0006.funkt_7.alarm_sq", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_7_2,
        { "Bit 2: ALARM_S", "s7comm.szl.0131.0006.funkt_7.alarm_s", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_7_3,
        { "Bit 3: ALARM_SC", "s7comm.szl.0131.0006.funkt_7.alarm_sc", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_7_4,
        { "Bit 4: EN_MSG", "s7comm.szl.0131.0006.funkt_7.en_msg", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_7_5,
        { "Bit 5: DIS_MSG", "s7comm.szl.0131.0006.funkt_7.dis_msg", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_7_6,
        { "Bit 6: CONTROL", "s7comm.szl.0131.0006.funkt_7.control", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_funkt_7_7,
        { "Bit 7: Reserved", "s7comm.szl.0131.0006.funkt_7.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_schnell,
        { "schnell (Fast reaction yes/no)", "s7comm.szl.0131.0006.schnell", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_0,
        { "zugtyp_0", "s7comm.szl.0131.0006.zugtyp_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "zugtyp_0 (Permitted module types for fast reaction)", HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_0_0,
        { "Bit 0: USEND", "s7comm.szl.0131.0006.zugtyp_0.usend", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_0_1,
        { "Bit 1: URCV", "s7comm.szl.0131.0006.zugtyp_0.urcv", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_0_2,
        { "Bit 2: SEND", "s7comm.szl.0131.0006.zugtyp_0.send", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_0_3,
        { "Bit 3: RCV", "s7comm.szl.0131.0006.zugtyp_0.rcv", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_0_4,
        { "Bit 4: BSEND", "s7comm.szl.0131.0006.zugtyp_0.bsend", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_0_5,
        { "Bit 5: BRCV", "s7comm.szl.0131.0006.zugtyp_0.brcv", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_0_6,
        { "Bit 6: GET", "s7comm.szl.0131.0006.zugtyp_0.get", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_0_7,
        { "Bit 7: PUT", "s7comm.szl.0131.0006.zugtyp_0.put", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_1,
        { "zugtyp_1", "s7comm.szl.0131.0006.zugtyp_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "zugtyp_1 (Permitted module types for fast reaction)", HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_1_0,
        { "Bit 0: PRINT", "s7comm.szl.0131.0006.zugtyp_1.print", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_1_1,
        { "Bit 1: ABORT", "s7comm.szl.0131.0006.zugtyp_1abort", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_1_2,
        { "Bit 2: INITIATE", "s7comm.szl.0131.0006.zugtyp_1.initiate", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_1_3,
        { "Bit 3: START", "s7comm.szl.0131.0006.zugtyp_1.start", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_1_4,
        { "Bit 4: STOP", "s7comm.szl.0131.0006.zugtyp_1.stop", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_1_5,
        { "Bit 5: RESUME", "s7comm.szl.0131.0006.zugtyp_1.resume", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_1_6,
        { "Bit 6: STATUS", "s7comm.szl.0131.0006.zugtyp_1.status", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_1_7,
        { "Bit 7: USTATUS", "s7comm.szl.0131.0006.zugtyp_1.ustatus", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_2,
        { "zugtyp_2", "s7comm.szl.0131.0006.zugtyp_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "zugtyp_2 (Permitted module types for fast reaction)", HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_2_0,
        { "Bit 0: PI", "s7comm.szl.0131.0006.zugtyp_2.pi", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_2_1,
        { "Bit 1: READ", "s7comm.szl.0131.0006.zugtyp_2.read", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_2_2,
        { "Bit 2: WRITE", "s7comm.szl.0131.0006.zugtyp_2.write", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_2_3,
        { "Bit 3: LOAD", "s7comm.szl.0131.0006.zugtyp_2.load", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_2_4,
        { "Bit 4: LOAD_ME", "s7comm.szl.0131.0006.zugtyp_2.load_me", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_2_5,
        { "Bit 5: ALARM", "s7comm.szl.0131.0006.zugtyp_2.alarm", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_2_6,
        { "Bit 6: ALARM_8", "s7comm.szl.0131.0006.zugtyp_2.alarm_8", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_2_7,
        { "Bit 7: ALARM_8P", "s7comm.szl.0131.0006.zugtyp_2.alarm_8p", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_3,
        { "zugtyp_3", "s7comm.szl.0131.0006.zugtyp_3", FT_UINT8, BASE_HEX, NULL, 0x0,
          "zugtyp_3 (Permitted module types for fast reaction)", HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_3_0,
        { "Bit 0: NOTIFY", "s7comm.szl.0131.0006.zugtyp_3.notify", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_3_1,
        { "Bit 1: AR_SEND", "s7comm.szl.0131.0006.zugtyp_3.ar_send", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_3_2,
        { "Bit 2: Reserved", "s7comm.szl.0131.0006.zugtyp_3.bit2_res", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_3_3,
        { "Bit 3: Reserved", "s7comm.szl.0131.0006.zugtyp_3.bit3_res", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_3_4,
        { "Bit 4: Reserved", "s7comm.szl.0131.0006.zugtyp_3.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_3_5,
        { "Bit 5: Reserved", "s7comm.szl.0131.0006.zugtyp_3.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_3_6,
        { "Bit 6: Reserved", "s7comm.szl.0131.0006.zugtyp_3.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_3_7,
        { "Bit 7: Reserved", "s7comm.szl.0131.0006.zugtyp_3.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_4,
        { "zugtyp_4", "s7comm.szl.0131.0006.zugtyp_4", FT_UINT8, BASE_HEX, NULL, 0x0,
          "zugtyp_4 (Permitted module types for fast reaction)", HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_5,
        { "zugtyp_5", "s7comm.szl.0131.0006.zugtyp_5", FT_UINT8, BASE_HEX, NULL, 0x0,
          "zugtyp_5 (Permitted module types for fast reaction)", HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_6,
        { "zugtyp_6", "s7comm.szl.0131.0006.zugtyp_6", FT_UINT8, BASE_HEX, NULL, 0x0,
          "zugtyp_6 (Permitted module types for fast reaction)", HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_6_0,
        { "Bit 0: X_SEND", "s7comm.szl.0131.0006.zugtyp_6.x_send", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_6_1,
        { "Bit 1: X_RCV", "s7comm.szl.0131.0006.zugtyp_6.x_rcv", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_6_2,
        { "Bit 2: X_GET", "s7comm.szl.0131.0006.zugtyp_6.x_get", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_6_3,
        { "Bit 3: X_PUT", "s7comm.szl.0131.0006.zugtyp_6.x_put", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_6_4,
        { "Bit 4: X_ABORT", "s7comm.szl.0131.0006.zugtyp_6.x_abort", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_6_5,
        { "Bit 5: I_GET", "s7comm.szl.0131.0006.zugtyp_6.i_get", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_6_6,
        { "Bit 6: I_PUT", "s7comm.szl.0131.0006.zugtyp_6.i_put", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_6_7,
        { "Bit 7: I_ABORT", "s7comm.szl.0131.0006.zugtyp_6.i_abort", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_7,
        { "zugtyp_7", "s7comm.szl.0131.0006.zugtyp_7", FT_UINT8, BASE_HEX, NULL, 0x0,
          "zugtyp_7 (Permitted module types for fast reaction)", HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_7_0,
        { "Bit 0: SCAN_SND", "s7comm.szl.0131.0006.zugtyp_7.scan_snd", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_7_1,
        { "Bit 1: ALARM_SQ", "s7comm.szl.0131.0006.zugtyp_7.alarm_sq", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_7_2,
        { "Bit 2: ALARM_S", "s7comm.szl.0131.0006.zugtyp_7.alarm_s", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_7_3,
        { "Bit 3: ALARM_SC", "s7comm.szl.0131.0006.zugtyp_7.alarm_sc", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_7_4,
        { "Bit 4: EN_MSG", "s7comm.szl.0131.0006.zugtyp_7.en_msg", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_7_5,
        { "Bit 5: DIS_MSG", "s7comm.szl.0131.0006.zugtyp_7.dis_msg", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_7_6,
        { "Bit 6: CONTROL", "s7comm.szl.0131.0006.zugtyp_7.control", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_zugtyp_7_7,
        { "Bit 7: Reserved", "s7comm.szl.0131.0006.zugtyp_7.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_res1,
        { "res1 (Reserved)", "s7comm.szl.0131.0006.res1", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_max_sd_empf,
        { "max_sd_empf (Maximum number of send and receive parameters per block)", "s7comm.szl.0131.0006.max_sd_empf", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_max_sd_al8p,
        { "max_sd_al8p (Maximum number of send parameters for ALARM_8P)", "s7comm.szl.0131.0006.max_sd_al8p", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_max_inst,
        { "max_inst (Maximum number of instances for communication SFBs for configured connections)", "s7comm.szl.0131.0006.max_inst", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_res2,
        { "res2 (Reserved)", "s7comm.szl.0131.0006.res2", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_verb_proj,
        { "verb_proj (Connection configured (yes=1) possible)", "s7comm.szl.0131.0006.verb_proj", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_verb_prog,
        { "verb_prog (Connection programmed (yes=1) possible)", "s7comm.szl.0131.0006.verb_prog", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0006_res3,
        { "res3 (Reserved)", "s7comm.szl.0131.0006.res3", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0006(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_funkt_0,
        ett_s7comm_szl_0131_0006_funkt_0, s7comm_szl_0131_0006_funkt_0_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_funkt_1,
        ett_s7comm_szl_0131_0006_funkt_1, s7comm_szl_0131_0006_funkt_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_funkt_2,
        ett_s7comm_szl_0131_0006_funkt_2, s7comm_szl_0131_0006_funkt_2_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_funkt_3,
        ett_s7comm_szl_0131_0006_funkt_3, s7comm_szl_0131_0006_funkt_3_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_funkt_6,
        ett_s7comm_szl_0131_0006_funkt_6, s7comm_szl_0131_0006_funkt_6_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_funkt_7,
        ett_s7comm_szl_0131_0006_funkt_7, s7comm_szl_0131_0006_funkt_7_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_schnell, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_zugtyp_0,
        ett_s7comm_szl_0131_0006_zugtyp_0, s7comm_szl_0131_0006_zugtyp_0_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_zugtyp_1,
        ett_s7comm_szl_0131_0006_zugtyp_1, s7comm_szl_0131_0006_zugtyp_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_zugtyp_2,
        ett_s7comm_szl_0131_0006_zugtyp_2, s7comm_szl_0131_0006_zugtyp_2_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_zugtyp_3,
        ett_s7comm_szl_0131_0006_zugtyp_3, s7comm_szl_0131_0006_zugtyp_3_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_zugtyp_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_zugtyp_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_zugtyp_6,
        ett_s7comm_szl_0131_0006_zugtyp_6, s7comm_szl_0131_0006_zugtyp_6_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0006_zugtyp_7,
        ett_s7comm_szl_0131_0006_zugtyp_7, s7comm_szl_0131_0006_zugtyp_7_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_res1, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_max_sd_empf, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_max_sd_al8p, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_max_inst, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_res2, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_verb_proj, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_verb_prog, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_res3, tvb, offset, 10, ENC_NA);
    offset += 10;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0007
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and the index W#16#0007
 *  contains information about the functions available available for global data
 *  communication on the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0007_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0007_index,
        { "Index", "s7comm.szl.0131.0007.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0007 Global data communication", HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_0,
        { "funkt_0 (Available GD functions)", "s7comm.szl.0131.0007.funkt_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_0_0,
        { "Cyclic", "s7comm.szl.0131.0007.funkt_0.cyclic", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Cyclic", HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_0_1,
        { "GD_SND", "s7comm.szl.0131.0007.funkt_0.gd_snd", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: GD_SND", HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_0_2,
        { "GD_RCV", "s7comm.szl.0131.0007.funkt_0.gd_rcv", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: GD_RCV", HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_0_3,
        { "Reserved", "s7comm.szl.0131.0007.funkt_0.bit3_res", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_0_4,
        { "Reserved", "s7comm.szl.0131.0007.funkt_0.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_0_5,
        { "Reserved", "s7comm.szl.0131.0007.funkt_0.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_0_6,
        { "Reserved", "s7comm.szl.0131.0007.funkt_0.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_0_7,
        { "Reserved", "s7comm.szl.0131.0007.funkt_0.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0007_funkt_1,
        { "funkt_1 (Reserved)", "s7comm.szl.0131.0007.funkt_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_0,
        { "obj_0 (Addressable objects)", "s7comm.szl.0131.0007.obj_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_0_0,
        { "M", "s7comm.szl.0131.0007.obj_0.m", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: M", HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_0_1,
        { "PII", "s7comm.szl.0131.0007.obj_0.pii", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: PII", HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_0_2,
        { "PIQ", "s7comm.szl.0131.0007.obj_0.piq", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: PIQ", HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_0_3,
        { "T", "s7comm.szl.0131.0007.obj_0.t", FT_BOOLEAN, 8, NULL, 0x08,
          "Bit 3: T", HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_0_4,
        { "C", "s7comm.szl.0131.0007.obj_0.c", FT_BOOLEAN, 8, NULL, 0x10,
          "Bit 4: C", HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_0_5,
        { "DB", "s7comm.szl.0131.0007.obj_0.db", FT_BOOLEAN, 8, NULL, 0x20,
          "Bit 5: DB", HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_0_6,
        { "Reserved", "s7comm.szl.0131.0007.obj_0.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          "Bit 6: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_0_7,
        { "Reserved", "s7comm.szl.0131.0007.obj_0.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          "Bit 7: Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0007_obj_1,
        { "obj_1 (Reserved)", "s7comm.szl.0131.0007.obj_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_kons,
        { "kons (Consistent length in bytes)", "s7comm.szl.0131.0007.kons", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_sen,
        { "sen (Minimum scan rate for sending)", "s7comm.szl.0131.0007.sen", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_rec,
        { "rec (Minimum scan rate for receiving)", "s7comm.szl.0131.0007.rec", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_time,
        { "time (Time monitoring when receiving yes/no)", "s7comm.szl.0131.0007.time", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_proj,
        { "proj (Re-configuration possible in RUN yes/no)", "s7comm.szl.0131.0007.proj", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_alarm,
        { "alarm (Communication interrupt yes/no)", "s7comm.szl.0131.0007.alarm", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_mode,
        { "mode", "s7comm.szl.0131.0007.mode", FT_UINT8, BASE_HEX, NULL, 0x0,
          "mode: Party line/MPI, communication bus", HFILL }},
        { &hf_s7comm_szl_0131_0007_mode_0,
        { "Party line/MPI", "s7comm.szl.0131.0007.mode.pl_mpi", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Party line/MPI", HFILL }},
        { &hf_s7comm_szl_0131_0007_mode_1,
        { "Communication bus", "s7comm.szl.0131.0007.mode.comm_bus", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Communication bus", HFILL }},
        { &hf_s7comm_szl_0131_0007_kreis,
        { "kreis (Maximum number of GD groups of the CPU)", "s7comm.szl.0131.0007.kreis", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_sk_1,
        { "sk_1 (Maximum number of GD packets to be sent per GD circle of the CPU)", "s7comm.szl.0131.0007.sk_1", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_sk_2,
        { "sk_2 (Maximum number of GD packets to be sent for all GD circles of the CPU)", "s7comm.szl.0131.0007.sk_2", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_ek_1,
        { "ek_1 (Maximum number of GD packets to be received per GD circle of the CPU)", "s7comm.szl.0131.0007.ek_1", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_ek_2,
        { "ek_2 (Maximum number of GD packets to be received for all GD circles of the CPU)", "s7comm.szl.0131.0007.ek_2", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_len_1,
        { "len_1 (Maximum length of a GD packet)", "s7comm.szl.0131.0007.len_1", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_len_2,
        { "len_2 (Maximum length of a GD packet header)", "s7comm.szl.0131.0007.len_2", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_len_3,
        { "len_3 (Length of the object description header)", "s7comm.szl.0131.0007.len_3", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0007_res,
        { "res (Reserved)", "s7comm.szl.0131.0007.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0007(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0007_funkt_0,
        ett_s7comm_szl_0131_0007_funkt_0, s7comm_szl_0131_0007_funkt_0_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_funkt_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0007_obj_0,
        ett_s7comm_szl_0131_0007_obj_0, s7comm_szl_0131_0007_obj_0_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_obj_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_kons, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_sen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_rec, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_time, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_proj, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_alarm, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0007_mode,
        ett_s7comm_szl_0131_0007_mode, s7comm_szl_0131_0007_mode_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_kreis, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_sk_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_sk_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_ek_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_ek_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_len_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_len_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_len_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0007_res, tvb, offset, 19, ENC_NA);
    offset += 19;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0008
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and the index W#16#0008
 *  contains information about the time required for test and installation
 *  functions.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0008_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0008_index,
        { "Index", "s7comm.szl.0131.0008.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0008 Test and installation function time information", HFILL }},
        /* Time format:
         * - Bit 0 to bit 11 contains the time value
         * - Bit 12 to bit 15 contains the time base: 0=10e-10 sec, 1=10e-9 sec, 0xa = 10e0 sec, 0xf=10e5 sec
         */
        { &hf_s7comm_szl_0131_0008_last_1,
        { "last_1 (Basic overhead for status block) time value", "s7comm.szl.0131.0008.last_1", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_last_1_tb,
        { "last_1 (Basic overhead for status block) time base", "s7comm.szl.0131.0008.last_1_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_last_2,
        { "last_2 (Basic overhead for monitor variables) time value", "s7comm.szl.0131.0008.last_2", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_last_2_tb,
        { "last_2 (Basic overhead for monitor variables) time base", "s7comm.szl.0131.0008.last_2_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_last_3,
        { "last_3 (Basic overhead for modify variables) time value", "s7comm.szl.0131.0008.last_3", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_last_3_tb,
        { "last_3 (Basic overhead for modify variables) time base", "s7comm.szl.0131.0008.last_3_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_merker,
        { "merker (Time for one variable address 'memory bit') time value", "s7comm.szl.0131.0008.merker", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_merker_tb,
        { "merker (Time for one variable address 'memory bit') time base", "s7comm.szl.0131.0008.merker_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ea,
        { "ea (Time for one variable address 'input' or 'output') time value", "s7comm.szl.0131.0008.ea", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ea_tb,
        { "ea (Time for one variable address 'input' or 'output') time base", "s7comm.szl.0131.0008.ea_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_tz,
        { "tz (Time for one variable address 'timer' or 'counter') time value", "s7comm.szl.0131.0008.tz", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_tz_tb,
        { "tz (Time for one variable address 'timer' or 'counter') time base", "s7comm.szl.0131.0008.tz_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_db,
        { "db (Time for one variable address 'data block DB') time value", "s7comm.szl.0131.0008.db", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_db_tb,
        { "db (Time for one variable address 'data block DB') time base", "s7comm.szl.0131.0008.db_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ld,
        { "ld (Time for one variable address 'ADB' or 'local data') time value", "s7comm.szl.0131.0008.ld", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ld_tb,
        { "ld (Time for one variable address 'ADB' or 'local data') time base", "s7comm.szl.0131.0008.ld_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_reg,
        { "reg (Time for one variable address 'register') time value", "s7comm.szl.0131.0008.reg", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_reg_tb,
        { "reg (Time for one variable address 'register') time base", "s7comm.szl.0131.0008.reg_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ba_stali1,
        { "ba_stali1 (Basic time for a status list ID of group 1) time value", "s7comm.szl.0131.0008.ba_stali1", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ba_stali1_tb,
        { "ba_stali1 (Basic time for a status list ID of group 1) time base", "s7comm.szl.0131.0008.ba_stali1_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ba_stali2,
        { "ba_stali2 (Basic time for a status list ID of group 2) time value", "s7comm.szl.0131.0008.ba_stali2", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ba_stali2_tb,
        { "ba_stali2 (Basic time for a status list ID of group 2) time base", "s7comm.szl.0131.0008.ba_stali2_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ba_stali3,
        { "ba_stali3 (Basic time for a status list ID of group 3) time value", "s7comm.szl.0131.0008.ba_stali3", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_ba_stali3_tb,
        { "ba_stali3 (Basic time for a status list ID of group 3) time base", "s7comm.szl.0131.0008.ba_stali3_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_akku,
        { "akku (Accumulators added to basic time when ACCU 1, 2 addressed) time value", "s7comm.szl.0131.0008.akku", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_akku_tb,
        { "akku (Accumulators added to basic time when ACCU 1, 2 addressed) time base", "s7comm.szl.0131.0008.akku_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_address,
        { "address (Address register added to basic time when AR 1 or AR 2 addressed) time value", "s7comm.szl.0131.0008.address", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_address_tb,
        { "address (Address register added to basic time when AR 1 or AR 2 addressed) time base", "s7comm.szl.0131.0008.address_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_dbreg,
        { "dbreg (DB register added to basic time when DB register addressed) time value", "s7comm.szl.0131.0008.dbreg", FT_UINT16, BASE_DEC, NULL, 0x0fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_dbreg_tb,
        { "dbreg (DB register added to basic time when DB register addressed) time base", "s7comm.szl.0131.0008.dbreg_tb", FT_UINT16, BASE_HEX, VALS(s7comm_szl_0131_0008_timebase_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0008_res,
        { "res (Reserved)", "s7comm.szl.0131.0008.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0008(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_last_1, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_last_1_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_last_2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_last_2_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_last_3, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_last_3_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_merker, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_merker_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ea, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ea_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_tz, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_tz_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_db, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_db_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ld, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ld_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_reg, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_reg_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ba_stali1, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ba_stali1_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ba_stali2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ba_stali2_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ba_stali3, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_ba_stali3_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_akku, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_akku_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_address, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_address_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_dbreg, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_dbreg_tb, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0008_res, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0009
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and the index W#16#0009
 *  contains time-of-day capability parameters.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0009_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0009_index,
        { "Index", "s7comm.szl.0131.0009.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0009 Time-of-day capability", HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_k,
        { "sync_k (Time synchronization C bus)", "s7comm.szl.0131.0009.sync_k", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_k_0,
        { "Time-of-day synchronization neutral", "s7comm.szl.0131.0009.sync_k.neutral", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Time-of-day synchronization neutral", HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_k_1,
        { "Capable of being slave for time-of-day synchronization", "s7comm.szl.0131.0009.sync_k.slave", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Capable of being slave for time-of-day synchronization", HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_k_2,
        { "Capable of being master for time-of-day synchronization", "s7comm.szl.0131.0009.sync_k.master", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Capable of being master for time-of-day synchronization", HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_mpi,
        { "sync_mpi (Time synchronization via MPI)", "s7comm.szl.0131.0009.sync_mpi", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_mpi_0,
        { "Time-of-day synchronization neutral", "s7comm.szl.0131.0009.sync_mpi.neutral", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Time-of-day synchronization neutral", HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_mpi_1,
        { "Capable of being slave for time-of-day synchronization", "s7comm.szl.0131.0009.sync_mpi.slave", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Capable of being slave for time-of-day synchronization", HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_mpi_2,
        { "Capable of being master for time-of-day synchronization", "s7comm.szl.0131.0009.sync_mpi.master", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Capable of being master for time-of-day synchronization", HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_mfi,
        { "sync_k (Time synchronization via MFI)", "s7comm.szl.0131.0009.sync_mfi", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_mfi_0,
        { "Time-of-day synchronization neutral", "s7comm.szl.0131.0009.sync_mfi.neutral", FT_BOOLEAN, 8, NULL, 0x01,
          "Bit 0: Time-of-day synchronization neutral", HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_mfi_1,
        { "Capable of being slave for time-of-day synchronization", "s7comm.szl.0131.0009.sync_mfi.slave", FT_BOOLEAN, 8, NULL, 0x02,
          "Bit 1: Capable of being slave for time-of-day synchronization", HFILL }},
        { &hf_s7comm_szl_0131_0009_sync_mfi_2,
        { "Capable of being master for time-of-day synchronization", "s7comm.szl.0131.0009.sync_mfi.master", FT_BOOLEAN, 8, NULL, 0x04,
          "Bit 2: Capable of being master for time-of-day synchronization", HFILL }},
        { &hf_s7comm_szl_0131_0009_res1,
        { "res1 (Reserved)", "s7comm.szl.0131.0009.res1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0009_abw_puf,
        { "abw_puf (Clock deviation in ms/day when backed up)", "s7comm.szl.0131.0009.abw_puf", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0009_abw_5v,
        { "abw_5v (Clock deviation in ms/day in 5V operation)", "s7comm.szl.0131.0009.abw_5v", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0009_anz_bsz,
        { "anz_bsz (Number of run-time meters)", "s7comm.szl.0131.0009.anz_bsz", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0009_res2,
        { "res2 (Reserved)", "s7comm.szl.0131.0009.res2", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0009(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0009_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0009_sync_k,
        ett_s7comm_szl_0131_0009_sync_k, s7comm_szl_0131_0009_sync_k_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0009_sync_mpi,
        ett_s7comm_szl_0131_0009_sync_mpi, s7comm_szl_0131_0009_sync_mpi_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0009_sync_mfi,
        ett_s7comm_szl_0131_0009_sync_mfi, s7comm_szl_0131_0009_sync_mfi_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0009_res1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0009_abw_puf, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0009_abw_5v, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0009_anz_bsz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0009_res2, tvb, offset, 28, ENC_NA);
    offset += 28;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0131
 * Index:   0x0010
 * Content:
 *  The partial list extract with SZL-ID W#16#0131 and index W#16#0010
 *  contains message parameters.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0131_0010_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0131_0010_index,
        { "Index", "s7comm.szl.0131.0010.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0010 Message parameter", HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_1,
        { "funk_1", "s7comm.szl.0131.0010.funk_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Block types available for data exchange with communication SFBs for configured connections", HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_1_0,
        { "Bit 0: Group status messages exist", "s7comm.szl.0131.0010.funk_1.grp_status_msg", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_1_1,
        { "Bit 1: Scan possible", "s7comm.szl.0131.0010.funk_1.scan_possible", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_1_2,
        { "Bit 2: NOTIFY, ALARM, ALARM_8P, ALARM_8, (multicast) possible", "s7comm.szl.0131.0010.funk_1.notify_alarm", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_1_3,
        { "Bit 3: Sending archive data possible", "s7comm.szl.0131.0010.funk_1.send_arc", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_1_4,
        { "Bit 4: Reserved", "s7comm.szl.0131.0010.funk_1.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_1_5,
        { "Bit 5: Reserved", "s7comm.szl.0131.0010.funk_1.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_1_6,
        { "Bit 6: Reserved", "s7comm.szl.0131.0010.funk_1.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_1_7,
        { "Bit 7: Reserved", "s7comm.szl.0131.0010.funk_1.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_funk_2,
        { "funk_2", "s7comm.szl.0131.0010.funk_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_1,
        { "ber_meld_1", "s7comm.szl.0131.0010.ber_meld_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permitted address areas for messages (SCAN)", HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_1_0,
        { "Bit 0: PII", "s7comm.szl.0131.0010.ber_meld_1.pii", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_1_1,
        { "Bit 1: PIQ", "s7comm.szl.0131.0010.ber_meld_1.piq", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_1_2,
        { "Bit 2: M", "s7comm.szl.0131.0010.ber_meld_1.m", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_1_3,
        { "Bit 3: DB", "s7comm.szl.0131.0010.ber_meld_1.db", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_1_4,
        { "Bit 4: Reserved", "s7comm.szl.0131.0010.ber_meld_1.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_1_5,
        { "Bit 5: Reserved", "s7comm.szl.0131.0010.ber_meld_1.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_1_6,
        { "Bit 6: Reserved", "s7comm.szl.0131.0010.ber_meld_1.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_1_7,
        { "Bit 7: Reserved", "s7comm.szl.0131.0010.ber_meld_1.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_meld_2,
        { "ber_meld_2", "s7comm.szl.0131.0010.ber_meld_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_1,
        { "ber_zus_1", "s7comm.szl.0131.0010.ber_zus_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permitted address areas for messages (SCAN)", HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_1_0,
        { "Bit 0: PII", "s7comm.szl.0131.0010.ber_zus_1.pii", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_1_1,
        { "Bit 1: PIQ", "s7comm.szl.0131.0010.ber_zus_1.piq", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_1_2,
        { "Bit 2: M", "s7comm.szl.0131.0010.ber_zus_1.m", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_1_3,
        { "Bit 3: DB", "s7comm.szl.0131.0010.ber_zus_1.db", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_1_4,
        { "Bit 4: Reserved", "s7comm.szl.0131.0010.ber_zus_1.bit4_res", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_1_5,
        { "Bit 5: Reserved", "s7comm.szl.0131.0010.ber_zus_1.bit5_res", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_1_6,
        { "Bit 6: Reserved", "s7comm.szl.0131.0010.ber_zus_1.bit6_res", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_1_7,
        { "Bit 7: Reserved", "s7comm.szl.0131.0010.ber_zus_1.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_ber_zus_2,
        { "ber_zus_2", "s7comm.szl.0131.0010.ber_zus_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_1,
        { "typ_zus_1", "s7comm.szl.0131.0010.typ_zus_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permitted data types for additional values (SCAN)", HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_1_0,
        { "Bit 0: Bit", "s7comm.szl.0131.0010.typ_zus_1.bit", FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_1_1,
        { "Bit 1: Byte", "s7comm.szl.0131.0010.typ_zus_1.byte", FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_1_2,
        { "Bit 2: Word", "s7comm.szl.0131.0010.typ_zus_1.word", FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_1_3,
        { "Bit 3: DWord", "s7comm.szl.0131.0010.typ_zus_1.dword", FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_1_4,
        { "Bit 4: Timer", "s7comm.szl.0131.0010.typ_zus_1.timer", FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_1_5,
        { "Bit 5: Counter", "s7comm.szl.0131.0010.typ_zus_1.counter", FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_1_6,
        { "Bit 6: Array of char[16]", "s7comm.szl.0131.0010.typ_zus_1.array_char", FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_1_7,
        { "Bit 7: Reserved", "s7comm.szl.0131.0010.typ_zus_1.bit7_res", FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_typ_zus_2,
        { "typ_zus_2", "s7comm.szl.0131.0010.typ_zus_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Reserved", HFILL }},
        { &hf_s7comm_szl_0131_0010_maxanz_arch,
        { "maxanz_arch (Maximum number of archives for 'Send Archive')", "s7comm.szl.0132.0010.maxanz_arch", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0010_res,
        { "res (Reserved)", "s7comm.szl.0131.0010.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0131_idx_0010(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0010_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0010_funk_1,
        ett_s7comm_szl_0131_0010_funk_1, s7comm_szl_0131_0010_funk_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0010_funk_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0010_ber_meld_1,
        ett_s7comm_szl_0131_0010_ber_meld_1, s7comm_szl_0131_0010_ber_meld_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0010_ber_meld_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0010_ber_zus_1,
        ett_s7comm_szl_0131_0010_ber_zus_1, s7comm_szl_0131_0010_ber_zus_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0010_ber_zus_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0131_0010_typ_zus_1,
        ett_s7comm_szl_0131_0010_typ_zus_1, s7comm_szl_0131_0010_typ_zus_1_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0010_typ_zus_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0010_maxanz_arch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0010_res, tvb, offset, 28, ENC_NA);
    offset += 28;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0132
 * Index:   0x0001
 * Content:
 *  The partial list extract with SZL-ID W#16#0132 and index W#16#0001
 *  contains general communication status data.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0132_0001_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0132_0001_index,
        { "Index", "s7comm.szl.0132.0001.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0001: General status data for communication", HFILL }},
        { &hf_s7comm_szl_0132_0001_res_pg,
        { "res pg (Guaranteed number of PG connections)", "s7comm.szl.0132.0001.res_pg", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0001_res_os,
        { "res os (Guaranteed number of OS connections)", "s7comm.szl.0132.0001.res_os", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0001_u_pg,
        { "u pg (Current number of PG connections)", "s7comm.szl.0132.0001.u_pg", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0001_u_os,
        { "u os (Current number of OS connections)", "s7comm.szl.0132.0001.u_os", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0001_proj,
        { "proj (Current number of configured connections)", "s7comm.szl.0132.0001.proj", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0001_auf,
        { "auf (Current number of connections established by proj)", "s7comm.szl.0132.0001.auf", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0001_free,
        { "free (Number of free connections)", "s7comm.szl.0132.0001.free", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0001_used,
        { "used (Number of free connections used)", "s7comm.szl.0132.0001.used", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0001_last,
        { "last (Maximum selected communication load of the CPU in %)", "s7comm.szl.0132.0001.last", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0001_res,
        { "res (Reserved)", "s7comm.szl.0132.0001.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0132_idx_0001(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_res_pg, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_res_os, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_u_pg, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_u_os, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_proj, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_auf, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_free, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_used, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_last, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_res, tvb, offset, 20, ENC_NA);
    offset += 20;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0132
 * Index:   0x0002
 * Content:
 *  The partial list extract with SZL-ID W#16#0132 and the index W#16#0002
 *  contains information about the test and installation function status of the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0132_0002_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0132_0002_index,
        { "Index", "s7comm.szl.0132.0002.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0002: Test and installation status", HFILL }},
        { &hf_s7comm_szl_0132_0002_anz,
        { "anz (Number of initialized test and installation jobs)", "s7comm.szl.0132.0002.anz", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0002_res,
        { "res (Reserved)", "s7comm.szl.0132.0002.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0132_idx_0002(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0002_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0002_anz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0002_res, tvb, offset, 36, ENC_NA);
    offset += 36;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0132
 * Index:   0x0004
 * Content:
 *  The partial list extract with SZL-ID W#16#0132 and the index W#16#0004
 *  contains information about the protection level of the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0132_0004_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0132_0004_index,
        { "Index", "s7comm.szl.0132.0004.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0004 Protection status data", HFILL }},
        { &hf_s7comm_szl_0132_0004_key,
        { "key (Protection level for the key switch, possible values: 1,2 or 3)", "s7comm.szl.0132.0004.key", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0004_param,
        { "param (Assigned protection level (possible values: 0, 1, 2 or 3)", "s7comm.szl.0132.0004.param", FT_UINT16, BASE_DEC, NULL, 0x0,
          "param (Assigned protection level (possible values: 0, 1, 2 or 3;0 means: no password assigned, assigned protection level is not valid)", HFILL }},
        { &hf_s7comm_szl_0132_0004_real,
        { "real (Valid protection level of the CPU, possible values: 1, 2 or 3)", "s7comm.szl.0132.0004.real", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0004_bart_sch,
        { "bart_sch (Position of the mode switch)", "s7comm.szl.0132.0004.bart_sch", FT_UINT16, BASE_DEC, VALS(szl_bart_sch_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0004_crst_wrst,
        { "crst_wrst (Setting of the CRST/WRST switch)", "s7comm.szl.0132.0004.crst_wrst", FT_UINT16, BASE_DEC, VALS(szl_crst_wrst_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0004_ken_f,
        { "ken_f (Reserved)", "s7comm.szl.0132.0004.ken_f", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0004_ken_rel,
        { "ken_rel (ID for valid version identifications/checksums)", "s7comm.szl.0132.0004.ken_rel", FT_UINT16, BASE_HEX, NULL, 0x0,
          "ken_rel (ID for valid version identifications/checksums) 0=invalid", HFILL }},
        { &hf_s7comm_szl_0132_0004_ken_ver1_hw,
        { "ken_ver1_hw (Version ID/checksum 1 of the hardware configuration)", "s7comm.szl.0132.0004.ken_ver1_hw", FT_UINT16, BASE_HEX, NULL, 0x0,
          "ken_ver1_hw: Version ID/checksum 1 of the hardware configuration: XOR over the length of all SDBs", HFILL }},
        { &hf_s7comm_szl_0132_0004_ken_ver2_hw,
        { "ken_ver2_hw (Version ID/checksum 2 of the hardware configuration)", "s7comm.szl.0132.0004.ken_ver2_hw", FT_UINT16, BASE_HEX, NULL, 0x0,
          "ken_ver2_hw: Version ID/checksum 2 of the hardware configuration: XOR over the checksums of all SDBs", HFILL }},
        { &hf_s7comm_szl_0132_0004_ken_ver1_awp,
        { "ken_ver1_awp (Version ID/checksum 1 of the user program)", "s7comm.szl.0132.0004.ken_ver1_awp", FT_UINT16, BASE_HEX, NULL, 0x0,
          "ken_ver1_awp: Version ID/checksum 1 of the user program): XOR over the length of all OBs, DBs, FBs, FCs", HFILL }},
        { &hf_s7comm_szl_0132_0004_ken_ver2_awp,
        { "ken_ver2_awp (Version ID/checksum 2 of the user program)", "s7comm.szl.0132.0004.ken_ver2_awp", FT_UINT16, BASE_HEX, NULL, 0x0,
          "ken_ver2_awp: Version ID/checksum 2 of the user program): XOR over the checksums of all OBs, DBs, FBs, FCs", HFILL }},
        { &hf_s7comm_szl_0132_0004_res,
        { "res (Reserved)", "s7comm.szl.0132.0004.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0132_idx_0004(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_key, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_param, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_real, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_bart_sch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_crst_wrst, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_ken_f, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_ken_rel, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_ken_ver1_hw, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_ken_ver2_hw, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_ken_ver1_awp, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_ken_ver2_awp, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_res, tvb, offset, 16, ENC_NA);
    offset += 16;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0132
 * Index:   0x0005
 * Content:
 *  The partial list extract with SZL-ID W#16#0132 and index W#16#0005
 *  contains information about the status of the diagnostics on the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0132_0005_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0132_0005_index,
        { "Index", "s7comm.szl.0132.0005.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0005: Diagnostics", HFILL }},
        { &hf_s7comm_szl_0132_0005_erw,
        { "erw (Extended functions)", "s7comm.szl.0132.0005.erw", FT_UINT16, BASE_DEC, VALS(szl_0132_0005_func_exist_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0005_send,
        { "send (Automatic sending)", "s7comm.szl.0132.0005.send", FT_UINT16, BASE_DEC, VALS(szl_0132_0005_func_exist_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0005_moeg,
        { "moeg (Sending user-defined diagnostic messages currently possible)", "s7comm.szl.0132.0005.moeg", FT_UINT16, BASE_DEC, VALS(szl_0132_0005_func_exist_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0005_ltmerz,
        { "ltmerz (Generation of status message active)", "s7comm.szl.0132.0005.ltmerz", FT_UINT16, BASE_DEC, VALS(szl_0132_0005_func_exist_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0005_res,
        { "res (Reserved)", "s7comm.szl.0132.0005.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0132_idx_0005(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0005_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0005_erw, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0005_send, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0005_moeg, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0005_ltmerz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0005_res, tvb, offset, 30, ENC_NA);
    offset += 30;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0132
 * Index:   0x0006
 * Content:
 *  The partial list extract with SZL-ID W#16#0132 and index W#16#0006
 *  contains status data about data exchange with communication SFBs for
 *  configured connections.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0132_0006_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0132_0006_index,
        { "Index", "s7comm.szl.0132.0006.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0006: Data exchange with communication SFBs for configured connections", HFILL }},
        { &hf_s7comm_szl_0132_0006_used_0,
        { "used_0 (Blocks used)", "s7comm.szl.0132.0006.used_0", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_used_1,
        { "used_1 (Blocks used)", "s7comm.szl.0132.0006.used_1", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_used_2,
        { "used_2 (Blocks used)", "s7comm.szl.0132.0006.used_2", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_used_3,
        { "used_3 (Blocks used)", "s7comm.szl.0132.0006.used_3", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_used_4,
        { "used_4 (Blocks used)", "s7comm.szl.0132.0006.used_4", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_used_5,
        { "used_5 (Blocks used)", "s7comm.szl.0132.0006.used_5", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_used_6,
        { "used_6 (Blocks used)", "s7comm.szl.0132.0006.used_6", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_used_7,
        { "used_7 (Blocks used)", "s7comm.szl.0132.0006.used_7", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_anz_schnell,
        { "anz_schnell (Reserved)", "s7comm.szl.0132.0006.anz_schnell", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_anz_inst,
        { "anz_inst (Number of loaded SFB instances)", "s7comm.szl.0132.0006.anz_inst", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_anz_multicast,
        { "anz_multicast (Number of blocks used for multicast)", "s7comm.szl.0132.0006.anz_multicast", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0006_res,
        { "res (Reserved)", "s7comm.szl.0132.0006.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0132_idx_0006(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_used_0, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_0_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_0_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_0_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_0_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_0_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_0_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_0_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_0_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_used_1, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_1_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_1_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_1_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_1_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_1_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_1_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_1_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_1_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_used_2, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_2_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_2_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_2_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_2_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_2_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_2_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_2_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_2_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_used_3, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_3_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_3_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_3_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_3_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_3_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_3_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_3_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_3_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_used_4, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_used_5, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_used_6, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_6_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_6_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_6_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_6_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_6_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_6_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_6_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_6_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_used_7, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_7_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_7_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_7_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_7_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_7_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_7_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_7_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0131_0006_funkt_7_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_anz_schnell, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_anz_inst, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_anz_multicast, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0006_res, tvb, offset, 25, ENC_NA);
    offset += 25;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0132
 * Index:   0x0008
 * Content:
 *  The partial list extract with SZL-ID W#16#0132 and index W#16#0008
 *  contains information on the status of the modules time system.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0132_0008_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0132_0008_index,
        { "Index", "s7comm.szl.0132.0008.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#0008: Time system status", HFILL }},
        { &hf_s7comm_szl_0132_0008_zykl,
        { "zykl (Cycle time of the synchronization frames)", "s7comm.szl.0132.0008.zykl", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_korr,
        { "korr (Correction factor for time-of-day)", "s7comm.szl.0132.0008.korr", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_clock0,
        { "clock 0 (Run-time meter 0: Time in hours)", "s7comm.szl.0132.0008.clock0", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_clock1,
        { "clock 1 (Run-time meter 1: Time in hours)", "s7comm.szl.0132.0008.clock1", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_clock2,
        { "clock 2 (Run-time meter 2: Time in hours)", "s7comm.szl.0132.0008.clock2", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_clock3,
        { "clock 3 (Run-time meter 3: Time in hours)", "s7comm.szl.0132.0008.clock3", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_clock4,
        { "clock 4 (Run-time meter 4: Time in hours)", "s7comm.szl.0132.0008.clock4", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_clock5,
        { "clock 5 (Run-time meter 5: Time in hours)", "s7comm.szl.0132.0008.clock5", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_clock6,
        { "clock 6 (Run-time meter 6: Time in hours)", "s7comm.szl.0132.0008.clock6", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_clock7,
        { "clock 7 (Run-time meter 7: Time in hours)", "s7comm.szl.0132.0008.clock7", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_0008_time,
        { "time (Current date and time)", "s7comm.szl.0132.0008.time", FT_BYTES, BASE_NONE, NULL, 0x0,
          "time (Current date and time) format: date_and_time", HFILL }},
        { &hf_s7comm_szl_0132_0008_res,
        { "res (Reserved)", "s7comm.szl.0132.0008.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0132_idx_0008(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_zykl, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_korr, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_clock0, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_clock1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_clock2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_clock3, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_clock4, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_clock5, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_clock6, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_clock7, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_time, tvb, offset, 8, ENC_NA);
    offset += 8;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_0008_res, tvb, offset, 10, ENC_NA);
    offset += 10;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0132
 * Index:   0x000b
 * Content:
 *  The partial list extract with SZL-ID W#16#0132 and index W#16#000B
 *  contains information about the status of the 32-bit run-time meters 0..7 of the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0132_000b_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0132_000b_index,
        { "Index", "s7comm.szl.0132.000b.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#000B: Time system status", HFILL }},
        { &hf_s7comm_szl_0132_000b_bszl_0,
        { "bszl_0 (Status of run-time meter)", "s7comm.szl.0132.000b.bszl_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "bszl_0 (Status of run-time meter): Bit = 1: run-time meter is busy" , HFILL }},
        { &hf_s7comm_szl_0132_000b_bszl_1,
        { "bszl_1 (Reserved)", "s7comm.szl.0132.000b.bszl_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_bszu_0,
        { "bszu_0 (Overflow of run-time meter)", "s7comm.szl.0132.000b.bszu_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "bszu_0 (Overflow of run-time meter): Bit = 1: overflow", HFILL }},
        { &hf_s7comm_szl_0132_000b_bszu_1,
        { "bszu_1 (Reserved)", "s7comm.szl.0132.000b.bszu_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_clock0,
        { "clock 0 (Run-time meter 0: Time in hours)", "s7comm.szl.0132.000b.clock0", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_clock1,
        { "clock 1 (Run-time meter 1: Time in hours)", "s7comm.szl.0132.000b.clock1", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_clock2,
        { "clock 2 (Run-time meter 2: Time in hours)", "s7comm.szl.0132.000b.clock2", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_clock3,
        { "clock 3 (Run-time meter 3: Time in hours)", "s7comm.szl.0132.000b.clock3", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_clock4,
        { "clock 4 (Run-time meter 4: Time in hours)", "s7comm.szl.0132.000b.clock4", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_clock5,
        { "clock 5 (Run-time meter 5: Time in hours)", "s7comm.szl.0132.000b.clock5", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_clock6,
        { "clock 6 (Run-time meter 6: Time in hours)", "s7comm.szl.0132.000b.clock6", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_clock7,
        { "clock 7 (Run-time meter 7: Time in hours)", "s7comm.szl.0132.000b.clock7", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000b_res,
        { "res (Reserved)", "s7comm.szl.0132.000b.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}
/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0132_idx_000b(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_bszl_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_bszl_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_bszu_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_bszu_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_clock0, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_clock1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_clock2, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_clock3, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_clock4, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_clock5, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_clock6, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_clock7, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000b_res, tvb, offset, 2, ENC_NA);
    offset += 2;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0132
 * Index:   0x000c
 * Content:
 *  The partial list extract with SZL-ID W#16#0132 and index W#16#000C
 *  contains information about the status of the 32-bit run-time meters 8..15 of the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0132_000c_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0132_000c_index,
        { "Index", "s7comm.szl.0132.000c.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "W#16#000C: Time system status", HFILL }},
        { &hf_s7comm_szl_0132_000c_bszl_0,
        { "bszl_0 (Status of run-time meter)", "s7comm.szl.0132.000c.bszl_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "bszl_0 (Status of run-time meter): Bit = 1: run-time meter is busy" , HFILL }},
        { &hf_s7comm_szl_0132_000c_bszl_1,
        { "bszl_1 (Reserved)", "s7comm.szl.0132.000c.bszl_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_bszu_0,
        { "bszu_0 (Overflow of run-time meter)", "s7comm.szl.0132.000c.bszu_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "bszu_0 (Overflow of run-time meter): Bit = 1: overflow", HFILL }},
        { &hf_s7comm_szl_0132_000c_bszu_1,
        { "bszu_1 (Reserved)", "s7comm.szl.0132.000c.bszu_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_clock8,
        { "clock 8 (Run-time meter 8: Time in hours)", "s7comm.szl.0132.000c.clock8", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_clock9,
        { "clock 9 (Run-time meter 9: Time in hours)", "s7comm.szl.0132.000c.clock9", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_clock10,
        { "clock 10 (Run-time meter 10: Time in hours)", "s7comm.szl.0132.000c.clock10", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_clock11,
        { "clock 11 (Run-time meter 11: Time in hours)", "s7comm.szl.0132.000c.clock11", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_clock12,
        { "clock 12 (Run-time meter 12: Time in hours)", "s7comm.szl.0132.000c.clock12", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_clock13,
        { "clock 13 (Run-time meter 13: Time in hours)", "s7comm.szl.0132.000c.clock13", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_clock14,
        { "clock 14 (Run-time meter 14: Time in hours)", "s7comm.szl.0132.000c.clock14", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_clock15,
        { "clock 15 (Run-time meter 15: Time in hours)", "s7comm.szl.0132.000c.clock15", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0132_000c_res,
        { "res (Reserved)", "s7comm.szl.0132.000c.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0132_idx_000c(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_bszl_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_bszl_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_bszu_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_bszu_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_clock8, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_clock9, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_clock10, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_clock11, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_clock12, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_clock13, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_clock14, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_clock15, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0132_000c_res, tvb, offset, 2, ENC_NA);
    offset += 2;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy74
 * Index:   0x0000
 * Content:
 *  If you read the partial list SSL-ID W#16#xy74, with standard CPUs (if present) and
 *  with the H CPUs, you obtain the status of the module LEDs.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy74_0000_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_xy74_0000_cpu_led_id,
        { "cpu_led_id", "s7comm.szl.xy74.0000.cpu_led_id", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy74_0000_cpu_led_id_rackno,
        { "Bits 0, 1, 2: Rack number", "s7comm.szl.xy74.0000.cpu_led_id.rackno", FT_UINT16, BASE_DEC, NULL, 0x0700,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy74_0000_cpu_led_id_cputype,
        { "Bit 3: CPU Type (0=Standby, 1=Master)", "s7comm.szl.xy74.0000.cpu_led_id.cputype", FT_UINT16, BASE_DEC, NULL, 0x0800,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy74_0000_cpu_led_id_id,
        { "Byte 1: LED ID", "s7comm.szl.xy74.0000.cpu_led_id.id", FT_UINT16, BASE_DEC, VALS(szl_0119_0174_ledid_index_names), 0x00ff,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy74_0000_led_on,
        { "Status of the LED", "s7comm.szl.xy74.0000.led_on", FT_UINT8, BASE_DEC, VALS(szl_xy74_0000_led_on_names), 0x00,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy74_0000_led_blink,
        { "Flashing status of the LED", "s7comm.szl.xy74.0000.led_blink", FT_UINT8, BASE_DEC, VALS(szl_xy74_0000_led_blink_names), 0x00,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_xy74_idx_0000(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_xy74_0000_cpu_led_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_xy74_0000_cpu_led_id_rackno, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_xy74_0000_cpu_led_id_cputype, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_xy74_0000_cpu_led_id_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy74_0000_led_on, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_xy74_0000_led_blink, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy1c
 * Index:   0x000x
 * Content:
 *  If you read the partial list SSL-ID W#16#xy1c, you obtain the CPU or PLC identification.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy1c_000x_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_001c_000x_index,
        { "Index", "s7comm.szl.001c.000x.index", FT_UINT16, BASE_HEX, VALS(szl_xy1c_index_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_000x_res,
        { "Reserved", "s7comm.szl.001c.000x.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_0001_name,
        { "Name (Name of the PLC)", "s7comm.szl.001c.0001.name", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_0002_name,
        { "Name (Name of the module)", "s7comm.szl.001c.0002.name", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_0003_tag,
        { "Tag (Plant identification of the module)", "s7comm.szl.001c.0003.tag", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_0004_copyright,
        { "Copyright", "s7comm.szl.001c.0004.copyright", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_0005_serialn,
        { "Serialn (Serialnumber of the module)", "s7comm.szl.001c.0005.serialn", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_0007_cputypname,
        { "Cputypname (Module type namee)", "s7comm.szl.001c.0007.cputypname", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_0008_snmcmmc,
        { "Sn_mc/mmc (Serial number of the Memory Card/Micro Memory Card)", "s7comm.szl.001c.0008.snmcmmc", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_0009_manufacturer_id,
        { "Manufacturer_id", "s7comm.szl.001c.0009.manufacturer_id", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Manufacturer_id (PROFIBUS / PROFINET Identification & Maintenance)", HFILL }},
        { &hf_s7comm_szl_001c_0009_profile_id,
        { "Profile_id", "s7comm.szl.001c.0009.profile_id", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Profile_id (PROFIBUS / PROFINET Identification & Maintenance)", HFILL }},
        { &hf_s7comm_szl_001c_0009_profile_spec_typ,
        { "Profile_spec_typ", "s7comm.szl.001c.0009.profile_spec_typ", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Profile_spec_typ (PROFIBUS / PROFINET Identification & Maintenance)", HFILL }},
        { &hf_s7comm_szl_001c_000a_oem_copyright_string,
        { "Oem_copyright_string (OEM Copyright ID)", "s7comm.szl.001c.000a.oem_copyright_string", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_000a_oem_id,
        { "Oem_id (OEM ID)", "s7comm.szl.001c.000a.oem_id", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_000a_oem_add_id,
        { "Oem_add_id (OEM additional ID)", "s7comm.szl.001c.000a.oem_add_id", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_001c_000b_loc_id,
        { "Loc_id (Location designation)", "s7comm.szl.001c.000b.loc_id", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_xy1c_idx_000x(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    guint32 idx;
    proto_tree_add_item_ret_uint(tree, hf_s7comm_szl_001c_000x_index, tvb, offset, 2, ENC_BIG_ENDIAN, &idx);
    offset += 2;
    /* For redundant H-CPUs there may be some upper bits set to identify the CPU */
    switch (idx & 0x000f) {
        case 0x0001:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0001_name, tvb, offset, 24, ENC_ASCII|ENC_NA);
            offset += 24;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 8, ENC_NA);
            offset += 8;
            break;
        case 0x0002:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0002_name, tvb, offset, 24, ENC_ASCII|ENC_NA);
            offset += 24;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 8, ENC_NA);
            offset += 8;
            break;
        case 0x0003:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0003_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
            offset += 32;
            break;
        case 0x0004:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0004_copyright, tvb, offset, 26, ENC_ASCII|ENC_NA);
            offset += 26;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 6, ENC_NA);
            offset += 6;
            break;
        case 0x0005:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0005_serialn, tvb, offset, 24, ENC_ASCII|ENC_NA);
            offset += 24;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 8, ENC_NA);
            offset += 8;
            break;
        case 0x0007:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0007_cputypname, tvb, offset, 32, ENC_ASCII|ENC_NA);
            offset += 32;
            break;
        case 0x0008:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0008_snmcmmc, tvb, offset, 32, ENC_ASCII|ENC_NA);
            offset += 32;
            break;
        case 0x0009:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0009_manufacturer_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0009_profile_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0009_profile_spec_typ, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 26, ENC_NA);
            offset += 26;
            break;
        case 0x000a:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000a_oem_copyright_string, tvb, offset, 26, ENC_ASCII|ENC_NA);
            offset += 26;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000a_oem_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000a_oem_add_id, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case 0x000b:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000b_loc_id, tvb, offset, 32, ENC_ASCII|ENC_NA);
            offset += 32;
            break;
        default:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 32, ENC_NA);
            offset += 32;
            break;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy91
 * Index:   0x0000
 * Content:
 *  If you read the partial list SSL-ID W#16#xy91, you obtain the status information of modules assigned
 *  to the CPU.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy91_0000_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0091_0000_adr1,
        { "Adr1", "s7comm.szl.0091.0000.adr1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0091_0000_adr2,
        { "Adr2", "s7comm.szl.0091.0000.adr2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0091_0000_logadr,
        { "Logadr", "s7comm.szl.0091.0000.logadr", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Logadr (First assigned logical I/O address (base address)", HFILL }},
        { &hf_s7comm_szl_0091_0000_solltyp,
        { "Expected type", "s7comm.szl.0091.0000.exptype", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Solltyp (PROFINET IO: expected (configured) type, otherwise reserved", HFILL }},
        { &hf_s7comm_szl_0091_0000_isttyp,
        { "Actual type", "s7comm.szl.0091.0000.acttype", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Isttyp (PROFINET IO: actual type, otherwise reserved", HFILL }},
        /* Field depends on the first byte of the SZL-ID */
        { &hf_s7comm_szl_0091_0000_res1,
        { "Reserved", "s7comm.szl.0091.0000.res1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0091_0000_res1_0c_4c_4d,
        { "Reserved (number of actually existing interface modules)", "s7comm.szl.0091.0000.res1_0c_4c_4d", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0091_0000_res1_0d,
        { "Reserved (number of interface modules)", "s7comm.szl.0091.0000.res1_0d", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat,
        { "I/O status", "s7comm.szl.0091.0000.eastat", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat_0,
        { "Module error", "s7comm.szl.0091.0000.eastat.moderror", FT_BOOLEAN, 16, NULL, 0x0001,
          "Bit 0: Module error", HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat_1,
        { "Module exists", "s7comm.szl.0091.0000.eastat.modexists", FT_BOOLEAN, 16, NULL, 0x0002,
          "Bit 1: Module exists", HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat_2,
        { "Module not available", "s7comm.szl.0091.0000.eastat.modnotav", FT_BOOLEAN, 16, NULL, 0x0004,
          "Bit 2: Module not available", HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat_3,
        { "Module disabled", "s7comm.szl.0091.0000.eastat.moddisabl", FT_BOOLEAN, 16, NULL, 0x0008,
          "Bit 3: Module disabled", HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat_4,
        { "Station error", "s7comm.szl.0091.0000.eastat.staterr", FT_BOOLEAN, 16, NULL, 0x0010,
          "Bit 4: Station error", HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat_5,
        { "CiR event busy", "s7comm.szl.0091.0000.eastat.cirbusy", FT_BOOLEAN, 16, NULL, 0x0020,
          "Bit 5: A CiR event at this module/station is busy or not yet completed", HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat_6,
        { "Reserved", "s7comm.szl.0091.0000.eastat.res", FT_BOOLEAN, 16, NULL, 0x0040,
          "Bit 6: Reserved for S7-400", HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat_7,
        { "Module in local bus segment", "s7comm.szl.0091.0000.eastat.modlocseg", FT_BOOLEAN, 16, NULL, 0x0080,
          "Bit 7: Module in local bus segment", HFILL }},
        { &hf_s7comm_szl_0091_0000_eastat_dataid,
        { "Data ID for logical address", "s7comm.szl.0091.0000.eastat.dataid", FT_UINT16, BASE_HEX, VALS(szl_0091_0000_eastat_dataid_names), 0xff00,
          "Bit 8 to 15: Data ID for logical address", HFILL }},
        { &hf_s7comm_szl_0091_0000_berbgbr,
        { "Ber_bgbr (Area ID/module width)", "s7comm.szl.0091.0000.berbgbr", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0091_0000_berbgbr_0_2,
        { "Module width", "s7comm.szl.0091.0000.berbgbr.width", FT_UINT16, BASE_DEC, NULL, 0x0007,
          "Bit 0 to 2: Module width", HFILL }},
        { &hf_s7comm_szl_0091_0000_berbgbr_3,
        { "Reserved", "s7comm.szl.0091.0000.berbgbr.bit3_res", FT_BOOLEAN, 16, NULL, 0x0008,
          "Bit 3: Reserved", HFILL }},
        { &hf_s7comm_szl_0091_0000_berbgbr_areaid,
        { "Area ID", "s7comm.szl.0091.0000.berbgbr.areaid", FT_UINT16, BASE_DEC, VALS(szl_0091_0000_berbgbr_areaid_names), 0x0070,
          "Bit 4 to 6: Area ID", HFILL }},
        { &hf_s7comm_szl_0091_0000_berbgbr_7,
        { "Reserved", "s7comm.szl.0091.0000.berbgbr.bit7_res", FT_BOOLEAN, 16, NULL, 0x0080,
          "Bit 7: Reserved", HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_xy91_idx_0000(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint16 id,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0091_0000_adr1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0091_0000_adr2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0091_0000_logadr, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0091_0000_solltyp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0091_0000_isttyp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    switch (id) {
        case 0x0c91:
        case 0x4c91:
        case 0x4d91:
            proto_tree_add_item(tree, hf_s7comm_szl_0091_0000_res1_0c_4c_4d, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        case 0x0d91:
            proto_tree_add_item(tree, hf_s7comm_szl_0091_0000_res1_0d, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        default:
            proto_tree_add_item(tree, hf_s7comm_szl_0091_0000_res1, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
    }
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0091_0000_eastat,
        ett_s7comm_szl_0091_0000_eastat, s7comm_szl_0091_0000_eastat_fields, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0091_0000_berbgbr,
        ett_s7comm_szl_0091_0000_berbgbr, s7comm_szl_0091_0000_berbgbr_fields, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy92
 * Index:   0x0000
 * Content:
 *  If you read the partial list SSL-ID W#16#xy92, you obtain information about the expected and the
 *  current hardware configuration of centrally installed racks and stations of a DP master system.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy92_xxxx_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0092_0xxx_status_0,
        { "status_0", "s7comm.szl.0092.xxxx.status_0", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_0: Status of station 1..8", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_1,
        { "status_1", "s7comm.szl.0092.xxxx.status_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_1: Status of station 9..16", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_2,
        { "status_2", "s7comm.szl.0092.xxxx.status_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_2: Status of station 17..24", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_3,
        { "status_3", "s7comm.szl.0092.xxxx.status_3", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_3: Status of station 25..32", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_4,
        { "status_4", "s7comm.szl.0092.xxxx.status_4", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_4: Status of station 33..40", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_5,
        { "status_5", "s7comm.szl.0092.xxxx.status_5", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_5: Status of station 41..48", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_6,
        { "status_6", "s7comm.szl.0092.xxxx.status_6", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_6: Status of station 49..56", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_7,
        { "status_7", "s7comm.szl.0092.xxxx.status_7", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_7: Status of station 57..64", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_8,
        { "status_8", "s7comm.szl.0092.xxxx.status_8", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_8: Status of station 65..72", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_9,
        { "status_9", "s7comm.szl.0092.xxxx.status_9", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_9: Status of station 73..80", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_10,
        { "status_10", "s7comm.szl.0092.xxxx.status_10", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_0: Status of station 81..88", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_11,
        { "status_11", "s7comm.szl.0092.xxxx.status_11", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_11: Status of station 89..96", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_12,
        { "status_12", "s7comm.szl.0092.xxxx.status_12", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_12: Status of station 97..104", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_13,
        { "status_13", "s7comm.szl.0092.xxxx.status_13", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_13: Status of station 105..112", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_14,
        { "status_14", "s7comm.szl.0092.xxxx.status_14", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_14: Status of station 113..120", HFILL }},
        { &hf_s7comm_szl_0092_0xxx_status_15,
        { "status_15", "s7comm.szl.0092.xxxx.status_15", FT_UINT8, BASE_HEX, NULL, 0x0,
          "status_15: Status of station 121..128", HFILL }},
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
add_station_byte_with_bitinfo(tvbuff_t *tvb,
                              proto_tree *tree,
                              gint hf,
                              const gchar *info_text,
                              guint32 start,
                              guint32 offset)
{
    proto_item *pi = NULL;
    proto_item *pti = NULL;
    proto_tree *pt = NULL;
    guint32 val;
    guint32 i;
    pi = proto_tree_add_item_ret_uint(tree, hf, tvb, offset, 1, ENC_BIG_ENDIAN, &val);
    /* Add the rack/station number when information bit is set */
    if (val) {
        pt = proto_item_add_subtree(pi, ett_s7comm_szl_xx9x_station_info);
        for (i = 0; i < 8; i++) {
            if (val & 1) {
                pti = proto_tree_add_item(pt, hf_s7comm_szl_xx9x_station_info, tvb, offset, 1, ENC_NA);
                proto_item_set_text(pti, "%s: %d", info_text, start + i);
            }
            val >>= 1;
        }
    }
    return offset + 1;
}

static guint32
s7comm_decode_szl_id_xy92_idx_xxxx(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint16 id,
                                   guint32 offset)
{
    gchar *txt;
    switch (id) {
        case 0x0092:
            txt = "Rack/Station configured";
            break;
        case 0x4092:
            txt = "Station configured";
            break;
        case 0x0192:
            txt = "Station configured and activated";
            break;
        case 0x0292:
            txt = "Rack/Station exists, activated and not failed";
            break;
        case 0x0492:
            txt = "Station exists, activated and not failed";
            break;
        case 0x0692:
            txt = "Modules of a station in a expansion rack not OK or station deactivated";
            break;
        case 0x4692:
            txt = "Modules of a station not OK or station deactivated";
            break;
        default:
            txt = "Station info bit set";
            break;
    }
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_0, txt, 1, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_1, txt, 9, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_2, txt, 17, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_3, txt, 25, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_4, txt, 33, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_5, txt, 41, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_6, txt, 49, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_7, txt, 57, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_8, txt, 65, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_9, txt, 73, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_10, txt, 81, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_11, txt, 89, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_12, txt, 97, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_13, txt, 105, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_14, txt, 113, offset);
    offset = add_station_byte_with_bitinfo(tvb, tree, hf_s7comm_szl_0092_0xxx_status_15, txt, 121, offset);

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0x94
 * Index:   0x0000
 * Content:
 *  Partial list SSL-ID W#16#0x94 contains information about the expected and actual
 *  configuration of module racks in central configurations and stations of a
 *  PROFIBUS DP mastersystem/PROFINET IO controller system.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0x94_xxxx_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0094_xxxx_index,
        { "Index", "s7comm.szl.0094.xxxx.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Index: 0=central module, 1-32=distributed module on PROFIBUS DP, 100-115=distributed module on PROFINET IO", HFILL }},
        { &hf_s7comm_szl_0094_xxxx_status_0,
        { "status_0 (Group information)", "s7comm.szl.0094.xxxx.status_0", FT_BOOLEAN, 8, NULL, 0x01,
          "status_0 (Group information): 1=at least one of the following status bis has the value 1", HFILL }},
        { &hf_s7comm_szl_0094_xxxx_status_1_2047,
        { "Status", "s7comm.szl.0094.xxxx.status_1_2047", FT_BYTES, BASE_NONE, NULL, 0x0,
          "Status of Station 1 to 2047", HFILL }},
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0x94_idx_xxxx(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint16 id,
                                   guint32 offset)
{
    proto_item *pi = NULL;
    proto_item *pti = NULL;
    proto_tree *pt = NULL;
    guint8 val;
    guint32 i, j;
    guint32 offset_tmp;
    guint32 n;
    gchar *txt;

    proto_tree_add_item(tree, hf_s7comm_szl_0094_xxxx_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0094_xxxx_status_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    pi = proto_tree_add_item(tree, hf_s7comm_szl_0094_xxxx_status_1_2047, tvb, offset, 256, ENC_NA);
    offset_tmp = offset;
    val = tvb_get_guint8(tvb, offset_tmp);
    /* If first bit is set, there is at least one station with active information */
    if (val & 1) {
        switch (id) {
            case 0x0094:
                txt = "Rack/Station configured";
                break;
            case 0x0194:
                txt = "Station configured and deactivated";
                break;
            case 0x0294:
                txt = "Rack/Station exists, activated and not failed";
                break;
            case 0x0694:
                txt = "Rack/Station with at least one module disrupted or deactivated";
                break;
            case 0x0794:
                txt = "Rack/Station with problem and/or maintenance requirement/request";
                break;
            default:
                txt = "Station info bit set";
                break;
        }
        pt = proto_item_add_subtree(pi, ett_s7comm_szl_xx9x_station_info);
        n = 0;
        /* Add the rack/station number when information bit is set */
        for (i = 0; i < 256; i++) {
            val = tvb_get_guint8(tvb, offset_tmp);
            if (val) {
                for (j = 0; j < 8; j++) {
                    if ((val & 1) && !(n == 0 && j == 0)) {  /* skip group information bit */
                        pti = proto_tree_add_item(pt, hf_s7comm_szl_xx9x_station_info, tvb, offset_tmp, 1, ENC_NA);
                        proto_item_set_text(pti, "%s: %d", txt, n + j);
                    }
                    val >>= 1;
                }
            }
            n += 8;
            offset_tmp += 1;
        }
    }
    return offset + 256;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy96
 * Index:   0xxxxx
 * Content:
 *  The partial list SSL-ID W#16#xy96 contains status information on all the modules assigned to the CPU.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy96_xxxx_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0096_xxxx_logadr_adr,
        { "logadr (Address of the module)", "s7comm.szl.xx96.xxxx.logadr.adr", FT_UINT16, BASE_HEX, NULL, 0x7fff,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_logadr_area,
        { "logadr (Area)", "s7comm.szl.xx96.xxxx.logadr.area", FT_BOOLEAN, 16, TFS(&tfs_szl_0096_xxx_logadr_area), 0x8000,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_system,
        { "System (Identifier for the central module/DP master system ID /PROFINET IO system ID)", "s7comm.szl.xx96.xxxx.system", FT_UINT16, BASE_DEC, NULL, 0x0,
          "System: 0=central module, 1-32=distributed module on PROFIBUS DP, 100-115=distributed module on PROFINET IO", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_api,
        { "API (Configured Application Profile)", "s7comm.szl.xx96.xxxx.api", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_station,
        { "Station (Rack no./station number/device number)", "s7comm.szl.xx96.xxxx.station", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_slot,
        { "Slot (Slot number)", "s7comm.szl.xx96.xxxx.slot", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_subslot,
        { "Subslot (Interface module slot)", "s7comm.szl.xx96.xxxx.subslot", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_offset,
        { "Offset (Offset in the user data address range of the associated module)", "s7comm.szl.xx96.xxxx.offset", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_solltyp1,
        { "Solltyp1 (Expected Type: Manufacturer no. or profile identificcation)", "s7comm.szl.xx96.xxxx.solltyp1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_solltyp2,
        { "Solltyp2 (Device)", "s7comm.szl.xx96.xxxx.solltyp2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_solltyp3,
        { "Solltyp3 (Sequential number or profile index)", "s7comm.szl.xx96.xxxx.solltyp3", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_solltyp4_5,
        { "Solltyp4_5 (Submodule identification)", "s7comm.szl.xx96.xxxx.solltyp4_5", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_solltyp6_7,
        { "Solltyp6_7 (Interface module identification)", "s7comm.szl.xx96.xxxx.solltyp6_7", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_expactid,
        { "Expected/actual identifier", "s7comm.szl.xx96.xxxx.expactid", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Expected/actual identifier: Bit0=0 -> Expected the same as actual, Bit0=1 -> Expected not same as actual", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_reserve1,
        { "Reserve 1", "s7comm.szl.xx96.xxxx.reserve1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        /* From here almost identical with ID 0x0091, but there are some differences and it's also convenient to have separate filter fields */
        { &hf_s7comm_szl_0096_xxxx_eastat,
        { "I/O status", "s7comm.szl.xx96.xxxx.eastat", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_0,
        { "Module disrupted", "s7comm.szl.xx96.xxxx.eastat.moddisrupt", FT_BOOLEAN, 16, NULL, 0x0001,
          "Bit 0: Module disrupted (detected over diagnostic interrupt)", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_1,
        { "Module exists", "s7comm.szl.xx96.xxxx.eastat.modexists", FT_BOOLEAN, 16, NULL, 0x0002,
          "Bit 1: Module exists", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_2,
        { "Module not available", "s7comm.szl.xx96.xxxx.eastat.modnotav", FT_BOOLEAN, 16, NULL, 0x0004,
          "Bit 2: Module not available", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_3,
        { "Module disabled", "s7comm.szl.xx96.xxxx.eastat.moddisabl", FT_BOOLEAN, 16, NULL, 0x0008,
          "Bit 3: Module disabled", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_4,
        { "Problem on station", "s7comm.szl.xx96.xxxx.eastat.statproblem", FT_BOOLEAN, 16, NULL, 0x0010,
          "Bit 4: Problem on station (representative slot only)", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_5,
        { "CiR event active", "s7comm.szl.xx96.xxxx.eastat.ciractive", FT_BOOLEAN, 16, NULL, 0x0020,
          "Bit 5: A CiR event at this module/station is active or not yet completed", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_6,
        { "Reserved", "s7comm.szl.xx96.xxxx.eastat.res", FT_BOOLEAN, 16, NULL, 0x0040,
          "Bit 6: Reserved for S7-400", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_7,
        { "Module in local bus segment", "s7comm.szl.xx96.xxxx.eastat.modlocseg", FT_BOOLEAN, 16, NULL, 0x0080,
          "Bit 7: Module in local bus segment", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_8,
        { "Module maintenance required", "s7comm.szl.xx96.xxxx.eastat.modmaintreq", FT_BOOLEAN, 16, NULL, 0x0100,
          "Bit 8: Module maintenance required (green)", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_eastat_9,
        { "Module maintenance demand", "s7comm.szl.xx96.xxxx.eastat.modmaintdem", FT_BOOLEAN, 16, NULL, 0x0200,
          "Bit 9: Module maintenance demand (yellow)", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_berbgbr,
        { "Ber_bgbr (Area ID/module width)", "s7comm.szl.xx96.xxxx.berbgbr", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0096_xxxx_berbgbr_0_2,
        { "Module width", "s7comm.szl.xx96.xxxx.berbgbr.width", FT_UINT16, BASE_DEC, NULL, 0x0007,
          "Bit 0 to 2: Module width", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_berbgbr_3,
        { "Reserved", "s7comm.szl.xx96.xxxx.berbgbr.bit3_res", FT_BOOLEAN, 16, NULL, 0x0008,
          "Bit 3: Reserved", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_berbgbr_areaid,
        { "Area ID", "s7comm.szl.xx96.xxxx.berbgbr.areaid", FT_UINT16, BASE_DEC, VALS(szl_0091_0000_berbgbr_areaid_names), 0x0070,
          "Bit 4 to 6: Area ID", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_berbgbr_7,
        { "Reserved", "s7comm.szl.xx96.xxxx.berbgbr.bit7_res", FT_BOOLEAN, 16, NULL, 0x0080,
          "Bit 7: Reserved", HFILL }},
        { &hf_s7comm_szl_0096_xxxx_reserve2,
        { "res (Reserved)", "s7comm.szl.xx96.xxxx.reserve2", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_xy96_idx_xxxx(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_logadr_adr, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_logadr_area, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_system, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_api, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_station, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_slot, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_subslot, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_solltyp1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_solltyp2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_solltyp3, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_solltyp4_5, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_solltyp6_7, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_expactid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_reserve1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0096_xxxx_eastat,
        ett_s7comm_szl_0096_xxxx_eastat, s7comm_szl_0096_xxxx_eastat_fields, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0096_xxxx_berbgbr,
        ett_s7comm_szl_0096_xxxx_berbgbr, s7comm_szl_0096_xxxx_berbgbr_fields, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0096_xxxx_reserve2, tvb, offset, 10, ENC_NA);
    offset += 10;

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0x0424
 * Index:   0x0000
 * Content:
 *  If you read the system status list with SZL-ID W#16#xy24, you obtain
 *  information about the modes of the module.
 *
 *******************************************************************************************************/
static void
s7comm_szl_0424_0000_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_0424_0000_ereig,
        { "ereig", "s7comm.szl.0424.0000.ereig", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Event ID", HFILL }},
        { &hf_s7comm_szl_0424_0000_ae,
        { "ae", "s7comm.szl.0424.0000.ereig", FT_UINT8, BASE_HEX, NULL, 0x0,
          "ae (B#16#FF)", HFILL }},
        { &hf_s7comm_szl_0424_0000_bzu_id,
        { "bzu-id", "s7comm.szl.0424.0000.bzu_id", FT_UINT8, BASE_HEX, NULL, 0x0,
          "bzu-id (ID of the mode change divided into 4 bits, Bit 0 to 3: Requested mode, Bit 4 to 7: Previous mode", HFILL }},
        { &hf_s7comm_szl_0424_0000_bzu_id_req,
        { "Requested mode", "s7comm.szl.0424.0000.bzu_id.req", FT_UINT8, BASE_HEX, VALS(szl_0424_0000_bzu_id_names), 0x0f,
          "bzu-id Requested mode", HFILL }},
        { &hf_s7comm_szl_0424_0000_bzu_id_pre,
        { "Previous mode", "s7comm.szl.0424.0000.bzu_id.pre", FT_UINT8, BASE_HEX, VALS(szl_0424_0000_bzu_id_names), 0xf0,
          "bzu-id Previous mode", HFILL }},
        { &hf_s7comm_szl_0424_0000_res,
        { "res (Reserved)", "s7comm.szl.0424.0000.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0424_0000_anlinfo1,
        { "anlinfo1", "s7comm.szl.0424.0000.anlinfo1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0424_0000_anlinfo2,
        { "anlinfo2", "s7comm.szl.0424.0000.anlinfo2", FT_UINT8, BASE_HEX, VALS(szl_0424_0000_anlinfo2_names), 0x0,
          "Type of startup just exceeded", HFILL }},
        { &hf_s7comm_szl_0424_0000_anlinfo3,
        { "anlinfo3", "s7comm.szl.0424.0000.anlinfo3", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Permissibility of startup types", HFILL }},
        { &hf_s7comm_szl_0424_0000_anlinfo4,
        { "anlinfo4", "s7comm.szl.0424.0000.anlinfo4", FT_UINT8, BASE_HEX, VALS(szl_0424_0000_anlinfo4_names), 0x0,
          "Last valid operation or setting of the automatic startup type at power on", HFILL }},
        { &hf_s7comm_szl_0424_0000_time,
        { "time", "s7comm.szl.0424.0000.time", FT_BYTES, BASE_NONE, NULL, 0x0,
          "time (Time stamp)", HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static guint32
s7comm_decode_szl_id_0424_idx_0000(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_ereig, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_ae, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_s7comm_szl_0424_0000_bzu_id,
        ett_s7comm_szl_0424_0000_bzu_id, s7comm_szl_0424_0000_bzu_id_fields, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_res, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_anlinfo1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_anlinfo2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_anlinfo3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_anlinfo4, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_time, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

/*******************************************************************************************************
 *
 * Register SZL header fields
 *
 *******************************************************************************************************/
void
s7comm_register_szl_types(int proto)
{
    static hf_register_info hf[] = {
        /*** SZL functions ***/
        { &hf_s7comm_userdata_szl_partial_list,
        { "SZL partial list data", "s7comm.param.userdata.szl_part_list", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
          /* SZL ID */
        { &hf_s7comm_userdata_szl_id,
        { "SZL-ID", "s7comm.data.userdata.szl_id", FT_UINT16, BASE_HEX, NULL, 0x0,
          "SZL-ID (System Status List) Bits 15-12: Diagnostic type, Bits 11-8: Number of the partial list extract, Bits 7-0: Number of the partial list", HFILL }},

        { &hf_s7comm_userdata_szl_id_type,
        { "Diagnostic type", "s7comm.data.userdata.szl_id.diag_type", FT_UINT16, BASE_HEX, VALS(szl_module_type_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_userdata_szl_id_partlist_ex,
        { "Number of the partial list extract", "s7comm.data.userdata.szl_id.partlist_ex", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &szl_id_partlist_ex_names_ext, 0xffff,
          NULL, HFILL }},
        { &hf_s7comm_userdata_szl_id_partlist_num,
        { "Number of the partial list", "s7comm.data.userdata.szl_id.partlist_num", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &szl_partial_list_names_ext, 0x00ff,
          NULL, HFILL }},

          /* SZL index */
        { &hf_s7comm_userdata_szl_index,
        { "SZL-Index", "s7comm.data.userdata.szl_index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "SZL-Index (System Status List)", HFILL }},
        { &hf_s7comm_userdata_szl_tree,
        { "SZL data tree", "s7comm.data.userdata.szl_data_tree", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_szl_id_partlist_len,
        { "SZL partial list length in bytes", "s7comm.data.userdata.szl_id.partlist_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_szl_id_partlist_cnt,
        { "SZL partial list count", "s7comm.data.userdata.szl_id.partlist_cnt", FT_UINT16, BASE_DEC, NULL, 0x0,
          "SZL partial list count: the number of datasets in the results", HFILL }},

        { &hf_s7comm_szl_xy12_0x00_charac,
        { "Characteristic", "s7comm.szl.xy12.0x00.charac", FT_UINT16, BASE_HEX, VALS(szl_xy12_cpu_characteristic_names), 0x0,
          NULL, HFILL }},
        /* For general usage as a station information */
        { &hf_s7comm_szl_xx9x_station_info,
        { "Station", "s7comm.szl.xy12.xx9x.station_info", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };

    /* Register Subtrees */
    static gint *ett[] = {
        &ett_s7comm_szl,
        &ett_s7comm_userdata_szl_id,
        &ett_s7comm_szl_xy22_00xx_al1,
        &ett_s7comm_szl_xy22_00xx_al2,
        &ett_s7comm_szl_0131_0002_funkt_0,
        &ett_s7comm_szl_0131_0002_funkt_1,
        &ett_s7comm_szl_0131_0002_funkt_2,
        &ett_s7comm_szl_0131_0002_trgereig_0,
        &ett_s7comm_szl_0131_0002_trgereig_1,
        &ett_s7comm_szl_0131_0003_funkt_0,
        &ett_s7comm_szl_0131_0003_funkt_1,
        &ett_s7comm_szl_0131_0003_funkt_2,
        &ett_s7comm_szl_0131_0003_funkt_3,
        &ett_s7comm_szl_0131_0004_funkt_0,
        &ett_s7comm_szl_0131_0004_funkt_1,
        &ett_s7comm_szl_0131_0004_funkt_2,
        &ett_s7comm_szl_0131_0004_funkt_3,
        &ett_s7comm_szl_0131_0004_funkt_4,
        &ett_s7comm_szl_0131_0005_funkt_0,
        &ett_s7comm_szl_0131_0006_funkt_0,
        &ett_s7comm_szl_0131_0006_funkt_1,
        &ett_s7comm_szl_0131_0006_funkt_2,
        &ett_s7comm_szl_0131_0006_funkt_3,
        &ett_s7comm_szl_0131_0006_funkt_6,
        &ett_s7comm_szl_0131_0006_funkt_7,
        &ett_s7comm_szl_0131_0006_zugtyp_0,
        &ett_s7comm_szl_0131_0006_zugtyp_1,
        &ett_s7comm_szl_0131_0006_zugtyp_2,
        &ett_s7comm_szl_0131_0006_zugtyp_3,
        &ett_s7comm_szl_0131_0006_zugtyp_6,
        &ett_s7comm_szl_0131_0006_zugtyp_7,
        &ett_s7comm_szl_0131_0007_funkt_0,
        &ett_s7comm_szl_0131_0007_obj_0,
        &ett_s7comm_szl_0131_0007_mode,
        &ett_s7comm_szl_0131_0009_sync_k,
        &ett_s7comm_szl_0131_0009_sync_mpi,
        &ett_s7comm_szl_0131_0009_sync_mfi,
        &ett_s7comm_szl_0131_0010_funk_1,
        &ett_s7comm_szl_0131_0010_ber_meld_1,
        &ett_s7comm_szl_0131_0010_ber_zus_1,
        &ett_s7comm_szl_0131_0010_typ_zus_1,
        &ett_s7comm_szl_0091_0000_eastat,
        &ett_s7comm_szl_0091_0000_berbgbr,
        &ett_s7comm_szl_0096_xxxx_eastat,
        &ett_s7comm_szl_0096_xxxx_berbgbr,
        &ett_s7comm_szl_xx9x_station_info,
        &ett_s7comm_szl_0424_0000_bzu_id,
    };
    proto_register_subtree_array(ett, array_length (ett));
    proto_register_field_array(proto, hf, array_length(hf));

    /* Register the SZL fields */
    s7comm_szl_0000_0000_register(proto);
    s7comm_szl_0013_0000_register(proto);
    s7comm_szl_xy14_000x_register(proto);
    s7comm_szl_xy15_000x_register(proto);
    s7comm_szl_xy11_0001_register(proto);
    s7comm_szl_xy22_00xx_register(proto);
    s7comm_szl_0131_0001_register(proto);
    s7comm_szl_0131_0002_register(proto);
    s7comm_szl_0131_0003_register(proto);
    s7comm_szl_0131_0004_register(proto);
    s7comm_szl_0131_0005_register(proto);
    s7comm_szl_0131_0006_register(proto);
    s7comm_szl_0131_0007_register(proto);
    s7comm_szl_0131_0008_register(proto);
    s7comm_szl_0131_0009_register(proto);
    s7comm_szl_0131_0010_register(proto);
    s7comm_szl_0132_0001_register(proto);
    s7comm_szl_0132_0002_register(proto);
    s7comm_szl_0132_0004_register(proto);
    s7comm_szl_0132_0005_register(proto);
    s7comm_szl_0132_0006_register(proto);
    s7comm_szl_0132_0008_register(proto);
    s7comm_szl_0132_000b_register(proto);
    s7comm_szl_0132_000c_register(proto);
    s7comm_szl_xy1c_000x_register(proto);
    s7comm_szl_xy91_0000_register(proto);
    s7comm_szl_xy92_xxxx_register(proto);
    s7comm_szl_0x94_xxxx_register(proto);
    s7comm_szl_xy96_xxxx_register(proto);
    s7comm_szl_xy74_0000_register(proto);
    s7comm_szl_0424_0000_register(proto);
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 4 -> SZL functions
 *
 *******************************************************************************************************/
guint32
s7comm_decode_ud_cpu_szl_subfunc(tvbuff_t *tvb,
                                 packet_info *pinfo,
                                 proto_tree *data_tree,
                                 guint8 type,                /* Type of data (request/response) */
                                 guint8 ret_val,             /* Return value in data part */
                                 guint32 dlength,
                                 guint32 offset)
{
    guint16 id;
    guint16 idx;
    guint16 list_len;
    guint16 list_count;
    guint16 i;
    guint32 start_offset;
    proto_item *szl_item = NULL;
    proto_tree *szl_item_tree = NULL;
    proto_item *szl_item_entry = NULL;
    const gchar* szl_index_description;
    gboolean szl_decoded = FALSE;

    start_offset = offset;
    if (type == S7COMM_UD_TYPE_REQ) {
        id = tvb_get_ntohs(tvb, offset);
        proto_tree_add_bitmask(data_tree, tvb, offset, hf_s7comm_userdata_szl_id,
            ett_s7comm_userdata_szl_id, s7comm_userdata_szl_id_fields, ENC_BIG_ENDIAN);
        offset += 2;
        idx = tvb_get_ntohs(tvb, offset);
        szl_item_entry = proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_index, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        szl_index_description = s7comm_get_szl_id_index_description_text(id, idx);
        if (szl_index_description != NULL) {
            proto_item_append_text(szl_item_entry, " [%s]", szl_index_description);
        }
        proto_item_append_text(data_tree, " (SZL-ID: 0x%04x, Index: 0x%04x)", id, idx);
        col_append_fstr(pinfo->cinfo, COL_INFO, " ID=0x%04x Index=0x%04x" , id, idx);
    } else if (type == S7COMM_UD_TYPE_RES) {
        if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
            id = tvb_get_ntohs(tvb, offset);
            proto_tree_add_bitmask(data_tree, tvb, offset, hf_s7comm_userdata_szl_id,
                ett_s7comm_userdata_szl_id, s7comm_userdata_szl_id_fields, ENC_BIG_ENDIAN);
            offset += 2;
            idx = tvb_get_ntohs(tvb, offset);
            szl_item_entry = proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_index, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            szl_index_description = s7comm_get_szl_id_index_description_text(id, idx);
            if (szl_index_description != NULL) {
                proto_item_append_text(szl_item_entry, " [%s]", szl_index_description);
            }
            proto_item_append_text(data_tree, " (SZL-ID: 0x%04x, Index: 0x%04x)", id, idx);
            col_append_fstr(pinfo->cinfo, COL_INFO, " ID=0x%04x Index=0x%04x" , id, idx);

            /* SZL-Data, 4 Bytes header, 4 bytes id/index = 8 bytes */
            list_len = tvb_get_ntohs(tvb, offset); /* Length of an list set in bytes */
            proto_tree_add_uint(data_tree, hf_s7comm_userdata_szl_id_partlist_len, tvb, offset, 2, list_len);
            offset += 2;
            list_count = tvb_get_ntohs(tvb, offset); /* count of partlists */
            proto_tree_add_uint(data_tree, hf_s7comm_userdata_szl_id_partlist_cnt, tvb, offset, 2, list_count);
            offset += 2;
            /* Check the listcount, as in fragmented packets some CPUs (firmware bug?) send 0xffff as list count */
            if (((guint32)list_count * (guint32)list_len) > (dlength - (offset - start_offset))) {
                /* TODO: Make entry in expert field */
                list_count = (dlength - (offset - start_offset)) / list_len;
            }
            /* Add a Data element for each partlist */
            if (dlength > 8) {      /* minimum length of a correct szl data part is 8 bytes */
                for (i = 1; i <= list_count && (list_count * list_len != 0); i++) {
                    /* Add a separate tree for the SZL data */
                    szl_item = proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_tree, tvb, offset, list_len, ENC_NA);
                    szl_item_tree = proto_item_add_subtree(szl_item, ett_s7comm_szl);
                    proto_item_append_text(szl_item, " (list count no. %d)", i);
                    szl_decoded = FALSE;
                    /* lets try to decode some known szl-id and indexes */
                    switch (id) {
                        case 0x0000:
                            offset = s7comm_decode_szl_id_xy00(tvb, szl_item_tree, id, idx, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x0012:
                        case 0x0112:
                            proto_tree_add_item(szl_item_tree, hf_s7comm_szl_xy12_0x00_charac, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            szl_decoded = TRUE;
                            break;
                        case 0x0013:
                        case 0x0113:
                            if (idx == 0x0000) {
                                offset = s7comm_decode_szl_id_0013_idx_0000(tvb, szl_item_tree, offset);
                                szl_decoded = TRUE;
                            }
                            break;
                        case 0x0014:
                        case 0x0114:
                            offset = s7comm_decode_szl_id_xy14_idx_000x(tvb, szl_item_tree, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x0015:
                        case 0x0115:
                            offset = s7comm_decode_szl_id_xy15_idx_000x(tvb, szl_item_tree, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x0011:
                        case 0x0111:
                            /* It's (almost) the same structure for all possible indexes */
                            offset = s7comm_decode_szl_id_0111_idx_0001(tvb, szl_item_tree, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x0222:
                            offset = s7comm_decode_szl_id_xy22_idx_00xx(tvb, szl_item_tree, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x00a0:
                        case 0x01a0:
                        case 0x04a0:
                        case 0x05a0:
                        case 0x06a0:
                        case 0x07a0:
                        case 0x08a0:
                        case 0x09a0:
                        case 0x0aa0:
                        case 0x0ba0:
                        case 0x0ca0:
                        case 0x0da0:
                        case 0x0ea0:
                            /* the data structure is the same as used when CPU is sending online such messages */
                            offset = s7comm_decode_ud_cpu_diagnostic_message(tvb, pinfo, FALSE, szl_item_tree, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x001c:
                        case 0x011c:
                        case 0x021c:
                        case 0x031c:
                            offset = s7comm_decode_szl_id_xy1c_idx_000x(tvb, szl_item_tree, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x0131:
                            switch (idx) {
                                case 0x0001:
                                    offset = s7comm_decode_szl_id_0131_idx_0001(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0002:
                                    offset = s7comm_decode_szl_id_0131_idx_0002(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0003:
                                    offset = s7comm_decode_szl_id_0131_idx_0003(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0004:
                                    offset = s7comm_decode_szl_id_0131_idx_0004(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0005:
                                    offset = s7comm_decode_szl_id_0131_idx_0005(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0006:
                                    offset = s7comm_decode_szl_id_0131_idx_0006(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0007:
                                    offset = s7comm_decode_szl_id_0131_idx_0007(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0008:
                                    offset = s7comm_decode_szl_id_0131_idx_0008(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0009:
                                    offset = s7comm_decode_szl_id_0131_idx_0009(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0010:
                                    offset = s7comm_decode_szl_id_0131_idx_0010(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                            }
                            break;
                        case 0x0132:
                            switch (idx) {
                                case 0x0001:
                                    offset = s7comm_decode_szl_id_0132_idx_0001(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0002:
                                    offset = s7comm_decode_szl_id_0132_idx_0002(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0004:
                                    offset = s7comm_decode_szl_id_0132_idx_0004(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0005:
                                    offset = s7comm_decode_szl_id_0132_idx_0005(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0006:
                                    offset = s7comm_decode_szl_id_0132_idx_0006(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x0008:
                                    offset = s7comm_decode_szl_id_0132_idx_0008(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x000b:
                                    offset = s7comm_decode_szl_id_0132_idx_000b(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                                case 0x000c:
                                    offset = s7comm_decode_szl_id_0132_idx_000c(tvb, szl_item_tree, offset);
                                    szl_decoded = TRUE;
                                    break;
                            }
                            break;
                        case 0x0019:
                        case 0x0119:
                        case 0x0074:
                        case 0x0174:
                                offset = s7comm_decode_szl_id_xy74_idx_0000(tvb, szl_item_tree, offset);
                                szl_decoded = TRUE;
                            break;
                        case 0x0091:
                        case 0x0191:
                        case 0x0291:
                        case 0x0391:
                        case 0x0491:
                        case 0x0591:
                        case 0x0991:
                        case 0x0a91:
                        case 0x0c91:
                        case 0x4c91:
                        case 0x0d91:
                        case 0x0e91:
                            offset = s7comm_decode_szl_id_xy91_idx_0000(tvb, szl_item_tree, id, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x0092:
                        case 0x0192:
                        case 0x0292:
                        case 0x0392:
                        case 0x0492:
                        case 0x0592:
                        case 0x0692:
                        case 0x4092:
                        case 0x4292:
                        case 0x4692:
                            offset = s7comm_decode_szl_id_xy92_idx_xxxx(tvb, szl_item_tree, id, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x0094:
                        case 0x0194:
                        case 0x0294:
                        case 0x0694:
                        case 0x0794:
                            offset = s7comm_decode_szl_id_0x94_idx_xxxx(tvb, szl_item_tree, id, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x0696:
                        case 0x0c96:
                            offset = s7comm_decode_szl_id_xy96_idx_xxxx(tvb, szl_item_tree, offset);
                            szl_decoded = TRUE;
                            break;
                        case 0x0124:
                        case 0x0424:
                            if (idx == 0x0000) {
                                offset = s7comm_decode_szl_id_0424_idx_0000(tvb, szl_item_tree, offset);
                                szl_decoded = TRUE;
                            }
                            break;
                        default:
                            szl_decoded = FALSE;
                            break;
                    }
                    if (szl_decoded == FALSE) {
                        proto_tree_add_item(szl_item_tree, hf_s7comm_userdata_szl_partial_list, tvb, offset, list_len, ENC_NA);
                        offset += list_len;
                    }
                } /* ...for */
            }
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Return value:[%s]", val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown return value:0x%02x"));
        }
    }
    return offset;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
