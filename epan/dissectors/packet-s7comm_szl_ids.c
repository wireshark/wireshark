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
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-s7comm.h"
#include "packet-s7comm_szl_ids.h"

static int ett_s7comm_szl;
static int hf_s7comm_userdata_szl_partial_list;           /* Partial list in szl response */
static int hf_s7comm_userdata_szl_id;                     /* SZL id */

static const value_string szl_module_type_names[] = {
    { 0x0,                                  "CPU" },            /* Binary: 0000 */
    { 0x4,                                  "IM" },             /* Binary: 0100 */
    { 0xc,                                  "CP" },             /* Binary: 1100 */
    { 0x8,                                  "FM" },             /* Binary: 1000 */
    { 0,                                    NULL }
};
static int hf_s7comm_userdata_szl_id_type;
static int hf_s7comm_userdata_szl_id_partlist_ex;
static int hf_s7comm_userdata_szl_id_partlist_num;
static int hf_s7comm_userdata_szl_id_partlist_len;
static int hf_s7comm_userdata_szl_id_partlist_cnt;
static int ett_s7comm_userdata_szl_id;
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
    { 0x0076,                               "DNN tree’s root node" },
    { 0x0077,                               "DNN node - all linked objects" },
    { 0x0078,                               "DNN node data" },
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

static int hf_s7comm_userdata_szl_index;                  /* SZL index */
static int hf_s7comm_userdata_szl_tree;                   /* SZL item tree */

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
    { 0x0015,                               "MAINT (maintenance demand)" },
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
static int hf_s7comm_szl_0000_0000_szl_id;
static int hf_s7comm_szl_0000_0000_module_type_class;
static int hf_s7comm_szl_0000_0000_partlist_extr_nr;
static int hf_s7comm_szl_0000_0000_partlist_nr;

static int hf_s7comm_szl_xy12_0x00_charac;
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

static int hf_s7comm_szl_0013_0000_index;

static int hf_s7comm_szl_0013_0000_code;
static const value_string szl_memory_type_names[] = {
    { 0x0001,                               "volatile memory (RAM)" },
    { 0x0002,                               "non-volatile memory (FEPROM)" },
    { 0x0003,                               "mixed memory (RAM + FEPROM)" },
    { 0,                                    NULL }
};
static int hf_s7comm_szl_0013_0000_size;
static int hf_s7comm_szl_0013_0000_mode;
static int hf_s7comm_szl_0013_0000_mode_0;
static int hf_s7comm_szl_0013_0000_mode_1;
static int hf_s7comm_szl_0013_0000_mode_2;
static int hf_s7comm_szl_0013_0000_mode_3;
static int hf_s7comm_szl_0013_0000_mode_4;
static int hf_s7comm_szl_0013_0000_granu;
static int hf_s7comm_szl_0013_0000_ber1;
static int hf_s7comm_szl_0013_0000_belegt1;
static int hf_s7comm_szl_0013_0000_block1;
static int hf_s7comm_szl_0013_0000_ber2;
static int hf_s7comm_szl_0013_0000_belegt2;
static int hf_s7comm_szl_0013_0000_block2;

static int hf_s7comm_szl_xy11_0001_index;
static int hf_s7comm_szl_xy11_0001_mlfb;
static int hf_s7comm_szl_xy11_0001_bgtyp;
static int hf_s7comm_szl_xy11_0001_ausbg;
static int hf_s7comm_szl_xy11_0001_ausbe;

static int hf_s7comm_szl_xy14_000x_index;
static int hf_s7comm_szl_xy14_000x_code;
static int hf_s7comm_szl_xy14_000x_quantity;
static int hf_s7comm_szl_xy14_000x_reman;

static int hf_s7comm_szl_xy15_000x_index;
static int hf_s7comm_szl_xy15_000x_maxanz;
static int hf_s7comm_szl_xy15_000x_maxlng;
static int hf_s7comm_szl_xy15_000x_maxabl;

static int hf_s7comm_szl_xy22_00xx_info;
static int hf_s7comm_szl_xy22_00xx_al1;
static int hf_s7comm_szl_xy22_00xx_al1_0;
static int hf_s7comm_szl_xy22_00xx_al1_1;
static int hf_s7comm_szl_xy22_00xx_al1_2;
static int hf_s7comm_szl_xy22_00xx_al1_4;
static int hf_s7comm_szl_xy22_00xx_al1_5;
static int hf_s7comm_szl_xy22_00xx_al1_6;
static int hf_s7comm_szl_xy22_00xx_al2;
static int hf_s7comm_szl_xy22_00xx_al2_0;
static int hf_s7comm_szl_xy22_00xx_al2_1;
static int hf_s7comm_szl_xy22_00xx_al2_2;
static int hf_s7comm_szl_xy22_00xx_al2_3;
static int hf_s7comm_szl_xy22_00xx_al3;

static int ett_s7comm_szl_xy22_00xx_al1;
static int * const s7comm_szl_xy22_00xx_al1_fields[] = {
    &hf_s7comm_szl_xy22_00xx_al1_0,
    &hf_s7comm_szl_xy22_00xx_al1_1,
    &hf_s7comm_szl_xy22_00xx_al1_2,
    &hf_s7comm_szl_xy22_00xx_al1_4,
    &hf_s7comm_szl_xy22_00xx_al1_5,
    &hf_s7comm_szl_xy22_00xx_al1_6,
    NULL
};
static int ett_s7comm_szl_xy22_00xx_al2;
static int * const s7comm_szl_xy22_00xx_al2_fields[] = {
    &hf_s7comm_szl_xy22_00xx_al2_0,
    &hf_s7comm_szl_xy22_00xx_al2_1,
    &hf_s7comm_szl_xy22_00xx_al2_2,
    &hf_s7comm_szl_xy22_00xx_al2_3,
    NULL
};

static int hf_s7comm_szl_0131_0001_index;
static int hf_s7comm_szl_0131_0001_pdu;
static int hf_s7comm_szl_0131_0001_anz;
static int hf_s7comm_szl_0131_0001_mpi_bps;
static int hf_s7comm_szl_0131_0001_kbus_bps;
static int hf_s7comm_szl_0131_0001_res;

static int hf_s7comm_szl_0131_0002_index;
static int hf_s7comm_szl_0131_0002_funkt_0;
static int hf_s7comm_szl_0131_0002_funkt_0_0;
static int hf_s7comm_szl_0131_0002_funkt_0_1;
static int hf_s7comm_szl_0131_0002_funkt_0_2;
static int hf_s7comm_szl_0131_0002_funkt_0_3;
static int hf_s7comm_szl_0131_0002_funkt_0_4;
static int hf_s7comm_szl_0131_0002_funkt_0_5;
static int hf_s7comm_szl_0131_0002_funkt_0_6;
static int hf_s7comm_szl_0131_0002_funkt_0_7;
static int hf_s7comm_szl_0131_0002_funkt_1;
static int hf_s7comm_szl_0131_0002_funkt_1_0;
static int hf_s7comm_szl_0131_0002_funkt_1_1;
static int hf_s7comm_szl_0131_0002_funkt_1_2;
static int hf_s7comm_szl_0131_0002_funkt_1_3;
static int hf_s7comm_szl_0131_0002_funkt_1_4;
static int hf_s7comm_szl_0131_0002_funkt_1_5;
static int hf_s7comm_szl_0131_0002_funkt_1_6;
static int hf_s7comm_szl_0131_0002_funkt_1_7;
static int hf_s7comm_szl_0131_0002_funkt_2;
static int hf_s7comm_szl_0131_0002_funkt_2_0;
static int hf_s7comm_szl_0131_0002_funkt_2_1;
static int hf_s7comm_szl_0131_0002_funkt_2_2;
static int hf_s7comm_szl_0131_0002_funkt_2_3;
static int hf_s7comm_szl_0131_0002_funkt_2_4;
static int hf_s7comm_szl_0131_0002_funkt_2_5;
static int hf_s7comm_szl_0131_0002_funkt_2_6;
static int hf_s7comm_szl_0131_0002_funkt_2_7;
static int hf_s7comm_szl_0131_0002_funkt_3;
static int hf_s7comm_szl_0131_0002_funkt_4;
static int hf_s7comm_szl_0131_0002_funkt_5;
static int hf_s7comm_szl_0131_0002_aseg;
static int hf_s7comm_szl_0131_0002_eseg;
static int hf_s7comm_szl_0131_0002_trgereig_0;
static int hf_s7comm_szl_0131_0002_trgereig_0_0;
static int hf_s7comm_szl_0131_0002_trgereig_0_1;
static int hf_s7comm_szl_0131_0002_trgereig_0_2;
static int hf_s7comm_szl_0131_0002_trgereig_0_3;
static int hf_s7comm_szl_0131_0002_trgereig_0_4;
static int hf_s7comm_szl_0131_0002_trgereig_0_5;
static int hf_s7comm_szl_0131_0002_trgereig_0_6;
static int hf_s7comm_szl_0131_0002_trgereig_0_7;
static int hf_s7comm_szl_0131_0002_trgereig_1;
static int hf_s7comm_szl_0131_0002_trgereig_1_0;
static int hf_s7comm_szl_0131_0002_trgereig_1_1;
static int hf_s7comm_szl_0131_0002_trgereig_1_2;
static int hf_s7comm_szl_0131_0002_trgereig_1_3;
static int hf_s7comm_szl_0131_0002_trgereig_1_4;
static int hf_s7comm_szl_0131_0002_trgereig_1_5;
static int hf_s7comm_szl_0131_0002_trgereig_1_6;
static int hf_s7comm_szl_0131_0002_trgereig_1_7;
static int hf_s7comm_szl_0131_0002_trgereig_2;
static int hf_s7comm_szl_0131_0002_trgbed;
static int hf_s7comm_szl_0131_0002_pfad;
static int hf_s7comm_szl_0131_0002_tiefe;
static int hf_s7comm_szl_0131_0002_systrig;
static int hf_s7comm_szl_0131_0002_erg_par;
static int hf_s7comm_szl_0131_0002_erg_pat_1;
static int hf_s7comm_szl_0131_0002_erg_pat_2;
static int hf_s7comm_szl_0131_0002_force;
static int hf_s7comm_szl_0131_0002_time;
static int hf_s7comm_szl_0131_0002_res;

static int ett_s7comm_szl_0131_0002_funkt_0;
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
static int ett_s7comm_szl_0131_0002_funkt_1;
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
static int ett_s7comm_szl_0131_0002_funkt_2;
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
static int ett_s7comm_szl_0131_0002_trgereig_0;
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
static int ett_s7comm_szl_0131_0002_trgereig_1;
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

static int hf_s7comm_szl_0131_0003_index;
static int hf_s7comm_szl_0131_0003_funkt_0;
static int hf_s7comm_szl_0131_0003_funkt_0_0;
static int hf_s7comm_szl_0131_0003_funkt_0_1;
static int hf_s7comm_szl_0131_0003_funkt_0_2;
static int hf_s7comm_szl_0131_0003_funkt_0_3;
static int hf_s7comm_szl_0131_0003_funkt_0_4;
static int hf_s7comm_szl_0131_0003_funkt_0_5;
static int hf_s7comm_szl_0131_0003_funkt_0_6;
static int hf_s7comm_szl_0131_0003_funkt_0_7;
static int hf_s7comm_szl_0131_0003_funkt_1;
static int hf_s7comm_szl_0131_0003_funkt_1_0;
static int hf_s7comm_szl_0131_0003_funkt_1_1;
static int hf_s7comm_szl_0131_0003_funkt_1_2;
static int hf_s7comm_szl_0131_0003_funkt_1_3;
static int hf_s7comm_szl_0131_0003_funkt_1_4;
static int hf_s7comm_szl_0131_0003_funkt_1_5;
static int hf_s7comm_szl_0131_0003_funkt_1_6;
static int hf_s7comm_szl_0131_0003_funkt_1_7;
static int hf_s7comm_szl_0131_0003_funkt_2;
static int hf_s7comm_szl_0131_0003_funkt_2_0;
static int hf_s7comm_szl_0131_0003_funkt_2_1;
static int hf_s7comm_szl_0131_0003_funkt_2_2;
static int hf_s7comm_szl_0131_0003_funkt_2_3;
static int hf_s7comm_szl_0131_0003_funkt_2_4;
static int hf_s7comm_szl_0131_0003_funkt_2_5;
static int hf_s7comm_szl_0131_0003_funkt_2_6;
static int hf_s7comm_szl_0131_0003_funkt_2_7;
static int hf_s7comm_szl_0131_0003_funkt_3;
static int hf_s7comm_szl_0131_0003_funkt_3_0;
static int hf_s7comm_szl_0131_0003_funkt_3_1;
static int hf_s7comm_szl_0131_0003_funkt_3_2;
static int hf_s7comm_szl_0131_0003_funkt_3_3;
static int hf_s7comm_szl_0131_0003_funkt_3_4;
static int hf_s7comm_szl_0131_0003_funkt_3_5;
static int hf_s7comm_szl_0131_0003_funkt_3_6;
static int hf_s7comm_szl_0131_0003_funkt_3_7;
static int hf_s7comm_szl_0131_0003_data;
static int hf_s7comm_szl_0131_0003_anz;
static int hf_s7comm_szl_0131_0003_per_min;
static int hf_s7comm_szl_0131_0003_per_max;
static int hf_s7comm_szl_0131_0003_res;

static int ett_s7comm_szl_0131_0003_funkt_0;
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
static int ett_s7comm_szl_0131_0003_funkt_1;
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
static int ett_s7comm_szl_0131_0003_funkt_2;
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
static int ett_s7comm_szl_0131_0003_funkt_3;
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

static int hf_s7comm_szl_0131_0004_index;
static int hf_s7comm_szl_0131_0004_funkt_0;
static int hf_s7comm_szl_0131_0004_funkt_0_0;
static int hf_s7comm_szl_0131_0004_funkt_0_1;
static int hf_s7comm_szl_0131_0004_funkt_0_2;
static int hf_s7comm_szl_0131_0004_funkt_0_3;
static int hf_s7comm_szl_0131_0004_funkt_0_4;
static int hf_s7comm_szl_0131_0004_funkt_0_5;
static int hf_s7comm_szl_0131_0004_funkt_0_6;
static int hf_s7comm_szl_0131_0004_funkt_0_7;
static int hf_s7comm_szl_0131_0004_funkt_1;
static int hf_s7comm_szl_0131_0004_funkt_1_0;
static int hf_s7comm_szl_0131_0004_funkt_1_1;
static int hf_s7comm_szl_0131_0004_funkt_1_2;
static int hf_s7comm_szl_0131_0004_funkt_1_3;
static int hf_s7comm_szl_0131_0004_funkt_1_4;
static int hf_s7comm_szl_0131_0004_funkt_1_5;
static int hf_s7comm_szl_0131_0004_funkt_1_6;
static int hf_s7comm_szl_0131_0004_funkt_1_7;
static int hf_s7comm_szl_0131_0004_funkt_2;
static int hf_s7comm_szl_0131_0004_funkt_2_0;
static int hf_s7comm_szl_0131_0004_funkt_2_1;
static int hf_s7comm_szl_0131_0004_funkt_2_2;
static int hf_s7comm_szl_0131_0004_funkt_2_3;
static int hf_s7comm_szl_0131_0004_funkt_2_4;
static int hf_s7comm_szl_0131_0004_funkt_2_5;
static int hf_s7comm_szl_0131_0004_funkt_2_6;
static int hf_s7comm_szl_0131_0004_funkt_2_7;
static int hf_s7comm_szl_0131_0004_funkt_3;
static int hf_s7comm_szl_0131_0004_funkt_3_0;
static int hf_s7comm_szl_0131_0004_funkt_3_1;
static int hf_s7comm_szl_0131_0004_funkt_3_2;
static int hf_s7comm_szl_0131_0004_funkt_3_3;
static int hf_s7comm_szl_0131_0004_funkt_3_4;
static int hf_s7comm_szl_0131_0004_funkt_3_5;
static int hf_s7comm_szl_0131_0004_funkt_3_6;
static int hf_s7comm_szl_0131_0004_funkt_3_7;
static int hf_s7comm_szl_0131_0004_funkt_4;
static int hf_s7comm_szl_0131_0004_funkt_4_0;
static int hf_s7comm_szl_0131_0004_funkt_4_1;
static int hf_s7comm_szl_0131_0004_funkt_4_2;
static int hf_s7comm_szl_0131_0004_funkt_4_3;
static int hf_s7comm_szl_0131_0004_funkt_4_4;
static int hf_s7comm_szl_0131_0004_funkt_4_5;
static int hf_s7comm_szl_0131_0004_funkt_4_6;
static int hf_s7comm_szl_0131_0004_funkt_4_7;
static int hf_s7comm_szl_0131_0004_funkt_5;
static int hf_s7comm_szl_0131_0004_funkt_6;
static int hf_s7comm_szl_0131_0004_funkt_7;
static int hf_s7comm_szl_0131_0004_kop;
static int hf_s7comm_szl_0131_0004_del;
static int hf_s7comm_szl_0131_0004_kett;
static int hf_s7comm_szl_0131_0004_hoch;
static int hf_s7comm_szl_0131_0004_ver;
static int hf_s7comm_szl_0131_0004_res;

static int ett_s7comm_szl_0131_0004_funkt_0;
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
static int ett_s7comm_szl_0131_0004_funkt_1;
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
static int ett_s7comm_szl_0131_0004_funkt_2;
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
static int ett_s7comm_szl_0131_0004_funkt_3;
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
static int ett_s7comm_szl_0131_0004_funkt_4;
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

static int hf_s7comm_szl_0131_0005_index;
static int hf_s7comm_szl_0131_0005_funkt_0;
static int hf_s7comm_szl_0131_0005_funkt_0_0;
static int hf_s7comm_szl_0131_0005_funkt_0_1;
static int hf_s7comm_szl_0131_0005_funkt_0_2;
static int hf_s7comm_szl_0131_0005_funkt_0_3;
static int hf_s7comm_szl_0131_0005_funkt_0_4;
static int hf_s7comm_szl_0131_0005_funkt_0_5;
static int hf_s7comm_szl_0131_0005_funkt_0_6;
static int hf_s7comm_szl_0131_0005_funkt_0_7;
static int hf_s7comm_szl_0131_0005_funkt_1;
static int hf_s7comm_szl_0131_0005_funkt_2;
static int hf_s7comm_szl_0131_0005_funkt_3;
static int hf_s7comm_szl_0131_0005_funkt_4;
static int hf_s7comm_szl_0131_0005_funkt_5;
static int hf_s7comm_szl_0131_0005_funkt_6;
static int hf_s7comm_szl_0131_0005_funkt_7;
static int hf_s7comm_szl_0131_0005_anz_sen;
static int hf_s7comm_szl_0131_0005_anz_ein;
static int hf_s7comm_szl_0131_0005_anz_mel;
static int hf_s7comm_szl_0131_0005_res;

static int ett_s7comm_szl_0131_0005_funkt_0;
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

static int hf_s7comm_szl_0131_0006_index;
static int hf_s7comm_szl_0131_0006_funkt_0;
static int hf_s7comm_szl_0131_0006_funkt_0_0;
static int hf_s7comm_szl_0131_0006_funkt_0_1;
static int hf_s7comm_szl_0131_0006_funkt_0_2;
static int hf_s7comm_szl_0131_0006_funkt_0_3;
static int hf_s7comm_szl_0131_0006_funkt_0_4;
static int hf_s7comm_szl_0131_0006_funkt_0_5;
static int hf_s7comm_szl_0131_0006_funkt_0_6;
static int hf_s7comm_szl_0131_0006_funkt_0_7;
static int hf_s7comm_szl_0131_0006_funkt_1;
static int hf_s7comm_szl_0131_0006_funkt_1_0;
static int hf_s7comm_szl_0131_0006_funkt_1_1;
static int hf_s7comm_szl_0131_0006_funkt_1_2;
static int hf_s7comm_szl_0131_0006_funkt_1_3;
static int hf_s7comm_szl_0131_0006_funkt_1_4;
static int hf_s7comm_szl_0131_0006_funkt_1_5;
static int hf_s7comm_szl_0131_0006_funkt_1_6;
static int hf_s7comm_szl_0131_0006_funkt_1_7;
static int hf_s7comm_szl_0131_0006_funkt_2;
static int hf_s7comm_szl_0131_0006_funkt_2_0;
static int hf_s7comm_szl_0131_0006_funkt_2_1;
static int hf_s7comm_szl_0131_0006_funkt_2_2;
static int hf_s7comm_szl_0131_0006_funkt_2_3;
static int hf_s7comm_szl_0131_0006_funkt_2_4;
static int hf_s7comm_szl_0131_0006_funkt_2_5;
static int hf_s7comm_szl_0131_0006_funkt_2_6;
static int hf_s7comm_szl_0131_0006_funkt_2_7;
static int hf_s7comm_szl_0131_0006_funkt_3;
static int hf_s7comm_szl_0131_0006_funkt_3_0;
static int hf_s7comm_szl_0131_0006_funkt_3_1;
static int hf_s7comm_szl_0131_0006_funkt_3_2;
static int hf_s7comm_szl_0131_0006_funkt_3_3;
static int hf_s7comm_szl_0131_0006_funkt_3_4;
static int hf_s7comm_szl_0131_0006_funkt_3_5;
static int hf_s7comm_szl_0131_0006_funkt_3_6;
static int hf_s7comm_szl_0131_0006_funkt_3_7;
static int hf_s7comm_szl_0131_0006_funkt_4;
static int hf_s7comm_szl_0131_0006_funkt_5;
static int hf_s7comm_szl_0131_0006_funkt_6;
static int hf_s7comm_szl_0131_0006_funkt_6_0;
static int hf_s7comm_szl_0131_0006_funkt_6_1;
static int hf_s7comm_szl_0131_0006_funkt_6_2;
static int hf_s7comm_szl_0131_0006_funkt_6_3;
static int hf_s7comm_szl_0131_0006_funkt_6_4;
static int hf_s7comm_szl_0131_0006_funkt_6_5;
static int hf_s7comm_szl_0131_0006_funkt_6_6;
static int hf_s7comm_szl_0131_0006_funkt_6_7;
static int hf_s7comm_szl_0131_0006_funkt_7;
static int hf_s7comm_szl_0131_0006_funkt_7_0;
static int hf_s7comm_szl_0131_0006_funkt_7_1;
static int hf_s7comm_szl_0131_0006_funkt_7_2;
static int hf_s7comm_szl_0131_0006_funkt_7_3;
static int hf_s7comm_szl_0131_0006_funkt_7_4;
static int hf_s7comm_szl_0131_0006_funkt_7_5;
static int hf_s7comm_szl_0131_0006_funkt_7_6;
static int hf_s7comm_szl_0131_0006_funkt_7_7;
static int hf_s7comm_szl_0131_0006_schnell;
static int hf_s7comm_szl_0131_0006_zugtyp_0;
static int hf_s7comm_szl_0131_0006_zugtyp_0_0;
static int hf_s7comm_szl_0131_0006_zugtyp_0_1;
static int hf_s7comm_szl_0131_0006_zugtyp_0_2;
static int hf_s7comm_szl_0131_0006_zugtyp_0_3;
static int hf_s7comm_szl_0131_0006_zugtyp_0_4;
static int hf_s7comm_szl_0131_0006_zugtyp_0_5;
static int hf_s7comm_szl_0131_0006_zugtyp_0_6;
static int hf_s7comm_szl_0131_0006_zugtyp_0_7;
static int hf_s7comm_szl_0131_0006_zugtyp_1;
static int hf_s7comm_szl_0131_0006_zugtyp_1_0;
static int hf_s7comm_szl_0131_0006_zugtyp_1_1;
static int hf_s7comm_szl_0131_0006_zugtyp_1_2;
static int hf_s7comm_szl_0131_0006_zugtyp_1_3;
static int hf_s7comm_szl_0131_0006_zugtyp_1_4;
static int hf_s7comm_szl_0131_0006_zugtyp_1_5;
static int hf_s7comm_szl_0131_0006_zugtyp_1_6;
static int hf_s7comm_szl_0131_0006_zugtyp_1_7;
static int hf_s7comm_szl_0131_0006_zugtyp_2;
static int hf_s7comm_szl_0131_0006_zugtyp_2_0;
static int hf_s7comm_szl_0131_0006_zugtyp_2_1;
static int hf_s7comm_szl_0131_0006_zugtyp_2_2;
static int hf_s7comm_szl_0131_0006_zugtyp_2_3;
static int hf_s7comm_szl_0131_0006_zugtyp_2_4;
static int hf_s7comm_szl_0131_0006_zugtyp_2_5;
static int hf_s7comm_szl_0131_0006_zugtyp_2_6;
static int hf_s7comm_szl_0131_0006_zugtyp_2_7;
static int hf_s7comm_szl_0131_0006_zugtyp_3;
static int hf_s7comm_szl_0131_0006_zugtyp_3_0;
static int hf_s7comm_szl_0131_0006_zugtyp_3_1;
static int hf_s7comm_szl_0131_0006_zugtyp_3_2;
static int hf_s7comm_szl_0131_0006_zugtyp_3_3;
static int hf_s7comm_szl_0131_0006_zugtyp_3_4;
static int hf_s7comm_szl_0131_0006_zugtyp_3_5;
static int hf_s7comm_szl_0131_0006_zugtyp_3_6;
static int hf_s7comm_szl_0131_0006_zugtyp_3_7;
static int hf_s7comm_szl_0131_0006_zugtyp_4;
static int hf_s7comm_szl_0131_0006_zugtyp_5;
static int hf_s7comm_szl_0131_0006_zugtyp_6;
static int hf_s7comm_szl_0131_0006_zugtyp_6_0;
static int hf_s7comm_szl_0131_0006_zugtyp_6_1;
static int hf_s7comm_szl_0131_0006_zugtyp_6_2;
static int hf_s7comm_szl_0131_0006_zugtyp_6_3;
static int hf_s7comm_szl_0131_0006_zugtyp_6_4;
static int hf_s7comm_szl_0131_0006_zugtyp_6_5;
static int hf_s7comm_szl_0131_0006_zugtyp_6_6;
static int hf_s7comm_szl_0131_0006_zugtyp_6_7;
static int hf_s7comm_szl_0131_0006_zugtyp_7;
static int hf_s7comm_szl_0131_0006_zugtyp_7_0;
static int hf_s7comm_szl_0131_0006_zugtyp_7_1;
static int hf_s7comm_szl_0131_0006_zugtyp_7_2;
static int hf_s7comm_szl_0131_0006_zugtyp_7_3;
static int hf_s7comm_szl_0131_0006_zugtyp_7_4;
static int hf_s7comm_szl_0131_0006_zugtyp_7_5;
static int hf_s7comm_szl_0131_0006_zugtyp_7_6;
static int hf_s7comm_szl_0131_0006_zugtyp_7_7;
static int hf_s7comm_szl_0131_0006_res1;
static int hf_s7comm_szl_0131_0006_max_sd_empf;
static int hf_s7comm_szl_0131_0006_max_sd_al8p;
static int hf_s7comm_szl_0131_0006_max_inst;
static int hf_s7comm_szl_0131_0006_res2;
static int hf_s7comm_szl_0131_0006_verb_proj;
static int hf_s7comm_szl_0131_0006_verb_prog;
static int hf_s7comm_szl_0131_0006_res3;

static int ett_s7comm_szl_0131_0006_funkt_0;
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
static int ett_s7comm_szl_0131_0006_funkt_1;
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
static int ett_s7comm_szl_0131_0006_funkt_2;
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
static int ett_s7comm_szl_0131_0006_funkt_3;
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
static int ett_s7comm_szl_0131_0006_funkt_6;
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
static int ett_s7comm_szl_0131_0006_funkt_7;
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
static int ett_s7comm_szl_0131_0006_zugtyp_0;
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
static int ett_s7comm_szl_0131_0006_zugtyp_1;
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
static int ett_s7comm_szl_0131_0006_zugtyp_2;
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
static int ett_s7comm_szl_0131_0006_zugtyp_3;
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
static int ett_s7comm_szl_0131_0006_zugtyp_6;
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
static int ett_s7comm_szl_0131_0006_zugtyp_7;
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

static int hf_s7comm_szl_0131_0007_index;
static int hf_s7comm_szl_0131_0007_funkt_0;
static int hf_s7comm_szl_0131_0007_funkt_0_0;
static int hf_s7comm_szl_0131_0007_funkt_0_1;
static int hf_s7comm_szl_0131_0007_funkt_0_2;
static int hf_s7comm_szl_0131_0007_funkt_0_3;
static int hf_s7comm_szl_0131_0007_funkt_0_4;
static int hf_s7comm_szl_0131_0007_funkt_0_5;
static int hf_s7comm_szl_0131_0007_funkt_0_6;
static int hf_s7comm_szl_0131_0007_funkt_0_7;
static int hf_s7comm_szl_0131_0007_funkt_1;
static int hf_s7comm_szl_0131_0007_obj_0;
static int hf_s7comm_szl_0131_0007_obj_0_0;
static int hf_s7comm_szl_0131_0007_obj_0_1;
static int hf_s7comm_szl_0131_0007_obj_0_2;
static int hf_s7comm_szl_0131_0007_obj_0_3;
static int hf_s7comm_szl_0131_0007_obj_0_4;
static int hf_s7comm_szl_0131_0007_obj_0_5;
static int hf_s7comm_szl_0131_0007_obj_0_6;
static int hf_s7comm_szl_0131_0007_obj_0_7;
static int hf_s7comm_szl_0131_0007_obj_1;
static int hf_s7comm_szl_0131_0007_kons;
static int hf_s7comm_szl_0131_0007_sen;
static int hf_s7comm_szl_0131_0007_rec;
static int hf_s7comm_szl_0131_0007_time;
static int hf_s7comm_szl_0131_0007_proj;
static int hf_s7comm_szl_0131_0007_alarm;
static int hf_s7comm_szl_0131_0007_mode;
static int hf_s7comm_szl_0131_0007_mode_0;
static int hf_s7comm_szl_0131_0007_mode_1;
static int hf_s7comm_szl_0131_0007_kreis;
static int hf_s7comm_szl_0131_0007_sk_1;
static int hf_s7comm_szl_0131_0007_sk_2;
static int hf_s7comm_szl_0131_0007_ek_1;
static int hf_s7comm_szl_0131_0007_ek_2;
static int hf_s7comm_szl_0131_0007_len_1;
static int hf_s7comm_szl_0131_0007_len_2;
static int hf_s7comm_szl_0131_0007_len_3;
static int hf_s7comm_szl_0131_0007_res;

static int ett_s7comm_szl_0131_0007_funkt_0;
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

static int ett_s7comm_szl_0131_0007_obj_0;
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

static int ett_s7comm_szl_0131_0007_mode;
static int * const s7comm_szl_0131_0007_mode_fields[] = {
    &hf_s7comm_szl_0131_0007_mode_0,
    &hf_s7comm_szl_0131_0007_mode_1,
    NULL
};

static int hf_s7comm_szl_0131_0008_index;
static int hf_s7comm_szl_0131_0008_last_1;
static int hf_s7comm_szl_0131_0008_last_1_tb;
static int hf_s7comm_szl_0131_0008_last_2;
static int hf_s7comm_szl_0131_0008_last_2_tb;
static int hf_s7comm_szl_0131_0008_last_3;
static int hf_s7comm_szl_0131_0008_last_3_tb;
static int hf_s7comm_szl_0131_0008_merker;
static int hf_s7comm_szl_0131_0008_merker_tb;
static int hf_s7comm_szl_0131_0008_ea;
static int hf_s7comm_szl_0131_0008_ea_tb;
static int hf_s7comm_szl_0131_0008_tz;
static int hf_s7comm_szl_0131_0008_tz_tb;
static int hf_s7comm_szl_0131_0008_db;
static int hf_s7comm_szl_0131_0008_db_tb;
static int hf_s7comm_szl_0131_0008_ld;
static int hf_s7comm_szl_0131_0008_ld_tb;
static int hf_s7comm_szl_0131_0008_reg;
static int hf_s7comm_szl_0131_0008_reg_tb;
static int hf_s7comm_szl_0131_0008_ba_stali1;
static int hf_s7comm_szl_0131_0008_ba_stali1_tb;
static int hf_s7comm_szl_0131_0008_ba_stali2;
static int hf_s7comm_szl_0131_0008_ba_stali2_tb;
static int hf_s7comm_szl_0131_0008_ba_stali3;
static int hf_s7comm_szl_0131_0008_ba_stali3_tb;
static int hf_s7comm_szl_0131_0008_akku;
static int hf_s7comm_szl_0131_0008_akku_tb;
static int hf_s7comm_szl_0131_0008_address;
static int hf_s7comm_szl_0131_0008_address_tb;
static int hf_s7comm_szl_0131_0008_dbreg;
static int hf_s7comm_szl_0131_0008_dbreg_tb;
static int hf_s7comm_szl_0131_0008_res;
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

static int hf_s7comm_szl_0131_0009_index;
static int hf_s7comm_szl_0131_0009_sync_k;
static int hf_s7comm_szl_0131_0009_sync_k_0;
static int hf_s7comm_szl_0131_0009_sync_k_1;
static int hf_s7comm_szl_0131_0009_sync_k_2;
static int hf_s7comm_szl_0131_0009_sync_mpi;
static int hf_s7comm_szl_0131_0009_sync_mpi_0;
static int hf_s7comm_szl_0131_0009_sync_mpi_1;
static int hf_s7comm_szl_0131_0009_sync_mpi_2;
static int hf_s7comm_szl_0131_0009_sync_mfi;
static int hf_s7comm_szl_0131_0009_sync_mfi_0;
static int hf_s7comm_szl_0131_0009_sync_mfi_1;
static int hf_s7comm_szl_0131_0009_sync_mfi_2;
static int hf_s7comm_szl_0131_0009_res1;
static int hf_s7comm_szl_0131_0009_abw_puf;
static int hf_s7comm_szl_0131_0009_abw_5v;
static int hf_s7comm_szl_0131_0009_anz_bsz;
static int hf_s7comm_szl_0131_0009_res2;

static int ett_s7comm_szl_0131_0009_sync_k;
static int * const s7comm_szl_0131_0009_sync_k_fields[] = {
    &hf_s7comm_szl_0131_0009_sync_k_0,
    &hf_s7comm_szl_0131_0009_sync_k_1,
    &hf_s7comm_szl_0131_0009_sync_k_2,
    NULL
};

static int ett_s7comm_szl_0131_0009_sync_mpi;
static int * const s7comm_szl_0131_0009_sync_mpi_fields[] = {
    &hf_s7comm_szl_0131_0009_sync_mpi_0,
    &hf_s7comm_szl_0131_0009_sync_mpi_1,
    &hf_s7comm_szl_0131_0009_sync_mpi_2,
    NULL
};

static int ett_s7comm_szl_0131_0009_sync_mfi;
static int * const s7comm_szl_0131_0009_sync_mfi_fields[] = {
    &hf_s7comm_szl_0131_0009_sync_mfi_0,
    &hf_s7comm_szl_0131_0009_sync_mfi_1,
    &hf_s7comm_szl_0131_0009_sync_mfi_2,
    NULL
};

static int hf_s7comm_szl_0131_0010_index;
static int hf_s7comm_szl_0131_0010_funk_1;
static int hf_s7comm_szl_0131_0010_funk_1_0;
static int hf_s7comm_szl_0131_0010_funk_1_1;
static int hf_s7comm_szl_0131_0010_funk_1_2;
static int hf_s7comm_szl_0131_0010_funk_1_3;
static int hf_s7comm_szl_0131_0010_funk_1_4;
static int hf_s7comm_szl_0131_0010_funk_1_5;
static int hf_s7comm_szl_0131_0010_funk_1_6;
static int hf_s7comm_szl_0131_0010_funk_1_7;
static int hf_s7comm_szl_0131_0010_funk_2;
static int hf_s7comm_szl_0131_0010_ber_meld_1;
static int hf_s7comm_szl_0131_0010_ber_meld_1_0;
static int hf_s7comm_szl_0131_0010_ber_meld_1_1;
static int hf_s7comm_szl_0131_0010_ber_meld_1_2;
static int hf_s7comm_szl_0131_0010_ber_meld_1_3;
static int hf_s7comm_szl_0131_0010_ber_meld_1_4;
static int hf_s7comm_szl_0131_0010_ber_meld_1_5;
static int hf_s7comm_szl_0131_0010_ber_meld_1_6;
static int hf_s7comm_szl_0131_0010_ber_meld_1_7;
static int hf_s7comm_szl_0131_0010_ber_meld_2;
static int hf_s7comm_szl_0131_0010_ber_zus_1;
static int hf_s7comm_szl_0131_0010_ber_zus_1_0;
static int hf_s7comm_szl_0131_0010_ber_zus_1_1;
static int hf_s7comm_szl_0131_0010_ber_zus_1_2;
static int hf_s7comm_szl_0131_0010_ber_zus_1_3;
static int hf_s7comm_szl_0131_0010_ber_zus_1_4;
static int hf_s7comm_szl_0131_0010_ber_zus_1_5;
static int hf_s7comm_szl_0131_0010_ber_zus_1_6;
static int hf_s7comm_szl_0131_0010_ber_zus_1_7;
static int hf_s7comm_szl_0131_0010_ber_zus_2;
static int hf_s7comm_szl_0131_0010_typ_zus_1;
static int hf_s7comm_szl_0131_0010_typ_zus_1_0;
static int hf_s7comm_szl_0131_0010_typ_zus_1_1;
static int hf_s7comm_szl_0131_0010_typ_zus_1_2;
static int hf_s7comm_szl_0131_0010_typ_zus_1_3;
static int hf_s7comm_szl_0131_0010_typ_zus_1_4;
static int hf_s7comm_szl_0131_0010_typ_zus_1_5;
static int hf_s7comm_szl_0131_0010_typ_zus_1_6;
static int hf_s7comm_szl_0131_0010_typ_zus_1_7;
static int hf_s7comm_szl_0131_0010_typ_zus_2;
static int hf_s7comm_szl_0131_0010_maxanz_arch;
static int hf_s7comm_szl_0131_0010_res;

static int ett_s7comm_szl_0131_0010_funk_1;
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
static int ett_s7comm_szl_0131_0010_ber_meld_1;
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
static int ett_s7comm_szl_0131_0010_ber_zus_1;
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
static int ett_s7comm_szl_0131_0010_typ_zus_1;
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

static int hf_s7comm_szl_0132_0001_index;
static int hf_s7comm_szl_0132_0001_res_pg;
static int hf_s7comm_szl_0132_0001_res_os;
static int hf_s7comm_szl_0132_0001_u_pg;
static int hf_s7comm_szl_0132_0001_u_os;
static int hf_s7comm_szl_0132_0001_proj;
static int hf_s7comm_szl_0132_0001_auf;
static int hf_s7comm_szl_0132_0001_free;
static int hf_s7comm_szl_0132_0001_used;
static int hf_s7comm_szl_0132_0001_last;
static int hf_s7comm_szl_0132_0001_res;

static int hf_s7comm_szl_0132_0002_index;
static int hf_s7comm_szl_0132_0002_anz;
static int hf_s7comm_szl_0132_0002_res;

static int hf_s7comm_szl_0132_0004_index;
static int hf_s7comm_szl_0132_0004_key;
static int hf_s7comm_szl_0132_0004_param;
static int hf_s7comm_szl_0132_0004_real;
static int hf_s7comm_szl_0132_0004_bart_sch;

static const value_string szl_bart_sch_names[] = {
    { 0,                                    "undefined or cannot be ascertained" },
    { 1,                                    "RUN" },
    { 2,                                    "RUN_P" },
    { 3,                                    "STOP" },
    { 4,                                    "MRES" },
    { 0,                                    NULL }
};
static int hf_s7comm_szl_0132_0004_crst_wrst;
static const value_string szl_crst_wrst_names[] = {
    { 0,                                    "undefined, does not exist or cannot be ascertained" },
    { 1,                                    "CRST" },
    { 2,                                    "WRST" },
    { 0,                                    NULL }
};
static int hf_s7comm_szl_0132_0004_ken_f;
static int hf_s7comm_szl_0132_0004_ken_rel;
static int hf_s7comm_szl_0132_0004_ken_ver1_hw;
static int hf_s7comm_szl_0132_0004_ken_ver2_hw;
static int hf_s7comm_szl_0132_0004_ken_ver1_awp;
static int hf_s7comm_szl_0132_0004_ken_ver2_awp;
static int hf_s7comm_szl_0132_0004_res;

static int hf_s7comm_szl_0132_0005_index;
static int hf_s7comm_szl_0132_0005_erw;
static int hf_s7comm_szl_0132_0005_send;
static int hf_s7comm_szl_0132_0005_moeg;
static int hf_s7comm_szl_0132_0005_ltmerz;
static int hf_s7comm_szl_0132_0005_res;

static const value_string szl_0132_0005_func_exist_names[] = {
    { 0x0,                                  "No" },
    { 0x1,                                  "Yes" },
    { 0,                                    NULL }
};

static int hf_s7comm_szl_0132_0006_index;
static int hf_s7comm_szl_0132_0006_used_0;
static int hf_s7comm_szl_0132_0006_used_1;
static int hf_s7comm_szl_0132_0006_used_2;
static int hf_s7comm_szl_0132_0006_used_3;
static int hf_s7comm_szl_0132_0006_used_4;
static int hf_s7comm_szl_0132_0006_used_5;
static int hf_s7comm_szl_0132_0006_used_6;
static int hf_s7comm_szl_0132_0006_used_7;
static int hf_s7comm_szl_0132_0006_anz_schnell;
static int hf_s7comm_szl_0132_0006_anz_inst;
static int hf_s7comm_szl_0132_0006_anz_multicast;
static int hf_s7comm_szl_0132_0006_res;

static int hf_s7comm_szl_0132_0008_index;
static int hf_s7comm_szl_0132_0008_zykl;
static int hf_s7comm_szl_0132_0008_korr;
static int hf_s7comm_szl_0132_0008_clock0;
static int hf_s7comm_szl_0132_0008_clock1;
static int hf_s7comm_szl_0132_0008_clock2;
static int hf_s7comm_szl_0132_0008_clock3;
static int hf_s7comm_szl_0132_0008_clock4;
static int hf_s7comm_szl_0132_0008_clock5;
static int hf_s7comm_szl_0132_0008_clock6;
static int hf_s7comm_szl_0132_0008_clock7;
static int hf_s7comm_szl_0132_0008_time;
static int hf_s7comm_szl_0132_0008_res;

static int hf_s7comm_szl_0132_000b_index;
static int hf_s7comm_szl_0132_000b_bszl_0;
static int hf_s7comm_szl_0132_000b_bszl_1;
static int hf_s7comm_szl_0132_000b_bszu_0;
static int hf_s7comm_szl_0132_000b_bszu_1;
static int hf_s7comm_szl_0132_000b_clock0;
static int hf_s7comm_szl_0132_000b_clock1;
static int hf_s7comm_szl_0132_000b_clock2;
static int hf_s7comm_szl_0132_000b_clock3;
static int hf_s7comm_szl_0132_000b_clock4;
static int hf_s7comm_szl_0132_000b_clock5;
static int hf_s7comm_szl_0132_000b_clock6;
static int hf_s7comm_szl_0132_000b_clock7;
static int hf_s7comm_szl_0132_000b_res;

static int hf_s7comm_szl_0132_000c_index;
static int hf_s7comm_szl_0132_000c_bszl_0;
static int hf_s7comm_szl_0132_000c_bszl_1;
static int hf_s7comm_szl_0132_000c_bszu_0;
static int hf_s7comm_szl_0132_000c_bszu_1;
static int hf_s7comm_szl_0132_000c_clock8;
static int hf_s7comm_szl_0132_000c_clock9;
static int hf_s7comm_szl_0132_000c_clock10;
static int hf_s7comm_szl_0132_000c_clock11;
static int hf_s7comm_szl_0132_000c_clock12;
static int hf_s7comm_szl_0132_000c_clock13;
static int hf_s7comm_szl_0132_000c_clock14;
static int hf_s7comm_szl_0132_000c_clock15;
static int hf_s7comm_szl_0132_000c_res;

static int hf_s7comm_szl_001c_000x_index;
static int hf_s7comm_szl_001c_0001_name;
static int hf_s7comm_szl_001c_0002_name;
static int hf_s7comm_szl_001c_0003_tag;
static int hf_s7comm_szl_001c_0004_copyright;
static int hf_s7comm_szl_001c_0005_serialn;
static int hf_s7comm_szl_001c_0007_cputypname;
static int hf_s7comm_szl_001c_0008_snmcmmc;
static int hf_s7comm_szl_001c_0009_manufacturer_id;
static int hf_s7comm_szl_001c_0009_profile_id;
static int hf_s7comm_szl_001c_0009_profile_spec_typ;
static int hf_s7comm_szl_001c_000a_oem_copyright_string;
static int hf_s7comm_szl_001c_000a_oem_id;
static int hf_s7comm_szl_001c_000a_oem_add_id;
static int hf_s7comm_szl_001c_000b_loc_id;
static int hf_s7comm_szl_001c_000x_res;

static int hf_s7comm_szl_0091_0000_adr1;
static int hf_s7comm_szl_0091_0000_adr2;
static int hf_s7comm_szl_0091_0000_logadr;
static int hf_s7comm_szl_0091_0000_solltyp;
static int hf_s7comm_szl_0091_0000_isttyp;
static int hf_s7comm_szl_0091_0000_res1;
static int hf_s7comm_szl_0091_0000_res1_0c_4c_4d;
static int hf_s7comm_szl_0091_0000_res1_0d;
static int hf_s7comm_szl_0091_0000_eastat;
static int hf_s7comm_szl_0091_0000_eastat_0;
static int hf_s7comm_szl_0091_0000_eastat_1;
static int hf_s7comm_szl_0091_0000_eastat_2;
static int hf_s7comm_szl_0091_0000_eastat_3;
static int hf_s7comm_szl_0091_0000_eastat_4;
static int hf_s7comm_szl_0091_0000_eastat_5;
static int hf_s7comm_szl_0091_0000_eastat_6;
static int hf_s7comm_szl_0091_0000_eastat_7;
static int hf_s7comm_szl_0091_0000_eastat_dataid;
static int hf_s7comm_szl_0091_0000_berbgbr;
static int hf_s7comm_szl_0091_0000_berbgbr_0_2;
static int hf_s7comm_szl_0091_0000_berbgbr_3;
static int hf_s7comm_szl_0091_0000_berbgbr_areaid;
static int hf_s7comm_szl_0091_0000_berbgbr_7;

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
static int ett_s7comm_szl_0091_0000_eastat;
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
static int ett_s7comm_szl_0091_0000_berbgbr;
static int * const s7comm_szl_0091_0000_berbgbr_fields[] = {
    &hf_s7comm_szl_0091_0000_berbgbr_0_2,
    &hf_s7comm_szl_0091_0000_berbgbr_3,
    &hf_s7comm_szl_0091_0000_berbgbr_areaid,
    &hf_s7comm_szl_0091_0000_berbgbr_7,
    NULL
};

static int ett_s7comm_szl_xx9x_station_info;
static int hf_s7comm_szl_xx9x_station_info;

static int hf_s7comm_szl_0092_0xxx_status_0;
static int hf_s7comm_szl_0092_0xxx_status_1;
static int hf_s7comm_szl_0092_0xxx_status_2;
static int hf_s7comm_szl_0092_0xxx_status_3;
static int hf_s7comm_szl_0092_0xxx_status_4;
static int hf_s7comm_szl_0092_0xxx_status_5;
static int hf_s7comm_szl_0092_0xxx_status_6;
static int hf_s7comm_szl_0092_0xxx_status_7;
static int hf_s7comm_szl_0092_0xxx_status_8;
static int hf_s7comm_szl_0092_0xxx_status_9;
static int hf_s7comm_szl_0092_0xxx_status_10;
static int hf_s7comm_szl_0092_0xxx_status_11;
static int hf_s7comm_szl_0092_0xxx_status_12;
static int hf_s7comm_szl_0092_0xxx_status_13;
static int hf_s7comm_szl_0092_0xxx_status_14;
static int hf_s7comm_szl_0092_0xxx_status_15;

static int hf_s7comm_szl_0094_xxxx_index;
static int hf_s7comm_szl_0094_xxxx_status_0;
static int hf_s7comm_szl_0094_xxxx_status_1_2047;

static int hf_s7comm_szl_0096_xxxx_logadr_adr;
static int hf_s7comm_szl_0096_xxxx_logadr_area;
static const true_false_string tfs_szl_0096_xxx_logadr_area = {
    "Input",
    "Output"
};

static int hf_s7comm_szl_0096_xxxx_system;
static int hf_s7comm_szl_0096_xxxx_api;
static int hf_s7comm_szl_0096_xxxx_station;
static int hf_s7comm_szl_0096_xxxx_slot;
static int hf_s7comm_szl_0096_xxxx_subslot;
static int hf_s7comm_szl_0096_xxxx_offset;
static int hf_s7comm_szl_0096_xxxx_solltyp1;
static int hf_s7comm_szl_0096_xxxx_solltyp2;
static int hf_s7comm_szl_0096_xxxx_solltyp3;
static int hf_s7comm_szl_0096_xxxx_solltyp4_5;
static int hf_s7comm_szl_0096_xxxx_solltyp6_7;
static int hf_s7comm_szl_0096_xxxx_expactid;
static int hf_s7comm_szl_0096_xxxx_reserve1;
static int hf_s7comm_szl_0096_xxxx_eastat;
static int hf_s7comm_szl_0096_xxxx_eastat_0;
static int hf_s7comm_szl_0096_xxxx_eastat_1;
static int hf_s7comm_szl_0096_xxxx_eastat_2;
static int hf_s7comm_szl_0096_xxxx_eastat_3;
static int hf_s7comm_szl_0096_xxxx_eastat_4;
static int hf_s7comm_szl_0096_xxxx_eastat_5;
static int hf_s7comm_szl_0096_xxxx_eastat_6;
static int hf_s7comm_szl_0096_xxxx_eastat_7;
static int hf_s7comm_szl_0096_xxxx_eastat_8;
static int hf_s7comm_szl_0096_xxxx_eastat_9;
static int ett_s7comm_szl_0096_xxxx_eastat;
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
static int hf_s7comm_szl_0096_xxxx_berbgbr;
static int hf_s7comm_szl_0096_xxxx_berbgbr_0_2;
static int hf_s7comm_szl_0096_xxxx_berbgbr_3;
static int hf_s7comm_szl_0096_xxxx_berbgbr_areaid;
static int hf_s7comm_szl_0096_xxxx_berbgbr_7;
static int ett_s7comm_szl_0096_xxxx_berbgbr;
static int * const s7comm_szl_0096_xxxx_berbgbr_fields[] = {
    &hf_s7comm_szl_0096_xxxx_berbgbr_0_2,
    &hf_s7comm_szl_0096_xxxx_berbgbr_3,
    &hf_s7comm_szl_0096_xxxx_berbgbr_areaid,
    &hf_s7comm_szl_0096_xxxx_berbgbr_7,
    NULL
};
static int hf_s7comm_szl_0096_xxxx_reserve2;

static int hf_s7comm_szl_0424_0000_ereig;
static int hf_s7comm_szl_0424_0000_ae;
static int hf_s7comm_szl_0424_0000_bzu_id;
static int hf_s7comm_szl_0424_0000_bzu_id_req;
static int hf_s7comm_szl_0424_0000_bzu_id_pre;
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
static int ett_s7comm_szl_0424_0000_bzu_id;
static int * const s7comm_szl_0424_0000_bzu_id_fields[] = {
    &hf_s7comm_szl_0424_0000_bzu_id_req,
    &hf_s7comm_szl_0424_0000_bzu_id_pre,
    NULL
};
static int hf_s7comm_szl_0424_0000_res;
static int hf_s7comm_szl_0424_0000_anlinfo1;
static int hf_s7comm_szl_0424_0000_anlinfo2;
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
static int hf_s7comm_szl_0424_0000_anlinfo3;
static int hf_s7comm_szl_0424_0000_anlinfo4;
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
static int hf_s7comm_szl_0424_0000_time;

static int hf_s7comm_szl_xy74_0000_cpu_led_id;
static int hf_s7comm_szl_xy74_0000_cpu_led_id_rackno;
static int hf_s7comm_szl_xy74_0000_cpu_led_id_cputype;
static int hf_s7comm_szl_xy74_0000_cpu_led_id_id;
static int hf_s7comm_szl_xy74_0000_led_on;
static const value_string szl_xy74_0000_led_on_names[] = {
    { 0x0,                                  "Off" },
    { 0x1,                                  "On" },
    { 0,                                    NULL }
};

static int hf_s7comm_szl_xy74_0000_led_blink;
static const value_string szl_xy74_0000_led_blink_names[] = {
    { 0x0,                                  "Not flashing" },
    { 0x1,                                  "Flashing normally (2 Hz)" },
    { 0x2,                                  "Flashing slowly (0.5 Hz)" },
    { 0,                                    NULL }
};

static int hf_s7comm_szl_xy76_0000_version;
static int hf_s7comm_szl_xy76_0000_top_dnn_id;

static int hf_s7comm_szl_xy77_xxxx_version;
static int hf_s7comm_szl_xy77_xxxx_num_parent;
static int hf_s7comm_szl_xy77_xxxx_obj_parent;
static int hf_s7comm_szl_xy77_xxxx_num_child;
static int hf_s7comm_szl_xy77_xxxx_obj_child;
static int hf_s7comm_szl_xy77_xxxx_num_redundancy_links;
static int hf_s7comm_szl_xy77_xxxx_obj_redundancy;
static int hf_s7comm_szl_xy77_xxxx_num_iodevice_agent_links;
static int hf_s7comm_szl_xy77_xxxx_obj_iodevice_agent;

static int hf_s7comm_szl_xy78_xxxx_version;
static int hf_s7comm_szl_xy78_xxxx_unknown_version_data;
static int hf_s7comm_szl_xy78_xxxx_geo_addr;
static int hf_s7comm_szl_xy78_xxxx_geo_addr_subsys;
static int hf_s7comm_szl_xy78_xxxx_geo_addr_station;
static int hf_s7comm_szl_xy78_xxxx_geo_addr_rack;
static int hf_s7comm_szl_xy78_xxxx_geo_addr_slot;
static int hf_s7comm_szl_xy78_xxxx_geo_addr_subslot;
static int hf_s7comm_szl_xy78_xxxx_name;
static int hf_s7comm_szl_xy78_xxxx_short_name;
static int hf_s7comm_szl_xy78_xxxx_dnn_mode;
static int hf_s7comm_szl_xy78_xxxx_dis;
static int hf_s7comm_szl_xy78_xxxx_dis_num_cdiag;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiags;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_ch_nr;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_ch_prop;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_alcat;
static const value_string s7comm_szl_xy78_xxxx_dis_cdiag_entry_alcat_names[] = {
    {0x0001, "ALCAT_CH_MSG"},
    {0x0002, "ALCAT_SUBMODUL_MSG"},
    {0x0003, "ALCAT_MODUL_MSG"},
    {0x0004, "ALCAT_RACK_MSG"},
    {0x0005, "ALCAT_DEVICE_MSG"},
    {0x0006, "ALCAT_IOSYSTEM_MSG"},
    {0x0007, "ALCAT_DREPEAT_A_MSG"},
    {0x0008, "ALCAT_DREPEAT_B_MSG"},
    {0x0009, "ALCAT_DREPEAT_C_MSG"},
    {0x000A, "ALCAT_DREPEAT_D_MSG"},
    {0x000B, "ALCAT_DREPEAT_E_MSG"},
    {0x000C, "ALCAT_CPU_MSG"},
    {0x000D, "ALCAT_CPU_OST_MSG"},
    {0x000F, "ALCAT_CPU_INFO_MSG"},
    {0x0010, "ALCAT_CPU_ERR_MSG"},
    {0x0011, "ALCAT_CPU_MD_MSG"},
    {0x0012, "ALCAT_CPU_MR_MSG"},
    {0x0013, "ALCAT_CPU_TMPERR_MSG"},
    {0x0014, "ALCAT_CPU_INTERN_MSG"},
    {0x0015, "ALCAT_CH_ERR_MSG"},
    {0x0016, "ALCAT_ECH_ERR_MSG"},
    {0x0017, "ALCAT_QCH_ERR_MSG"},
    {0x0018, "ALCAT_CH_MD_MSG"},
    {0x0019, "ALCAT_ECH_MD_MSG"},
    {0x001A, "ALCAT_QCH_MDMSG"},
    {0x001B, "ALCAT_CH_MR_MSG"},
    {0x001C, "ALCAT_ECH_MR_MSG"},
    {0x001D, "ALCAT_QCH_MR_MSG"},
    {0x001E, "ALCAT_SUB_ERR_MSG"},
    {0x001F, "ALCAT_ESUB_ERR_MSG"},
    {0x0020, "ALCAT_QSUB_ERR_MSG"},
    {0x0021, "ALCAT_SUB_MD_MSG"},
    {0x0022, "ALCAT_ESUB_MD_MSG"},
    {0x0023, "ALCAT_QSUB_MDMSG"},
    {0x0024, "ALCAT_SUB_MR_MSG"},
    {0x0025, "ALCAT_ESUB_MR_MSG"},
    {0x0026, "ALCAT_QSUB_MR_MSG"},
    {0x0028, "ALCAT_CONFIG_INFO"},
    {0, NULL}
};

static value_string_ext s7comm_szl_xy78_xxxx_dis_cdiag_entry_alcat_names_ext =
    VALUE_STRING_EXT_INIT(s7comm_szl_xy78_xxxx_dis_cdiag_entry_alcat_names);

static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_res;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_qualifier;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_chet;
static const value_string s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_names[] = {
    {0x0001, "ErrTextLib"},
    {0x0002, "CPUTextlib"},
    {0x0003, "ErrTextLibEx"},
    {0x0004, "DS1TextLib"},
    {0x0005, "OSTTextLib (S7classic)"},
    {0x0006, "IOTextLib"},
    {0x0007, "DR"},
    {0x0008, "IOTextLibFlat"},
    {0x000D, "FS_TextLib"},
    {0x000F, "CPTextlib"},
    {0x0020, "AddHCPUTextLib"},
    {0x0040, "PCStationTextlib"},
    {0x0042, "PCCPTextlib"},
    {0x0043, "PCDiagBase"},
    {0x0064, "Domain0TextLib"},
    {0x00F0, "MotionControlTextLib"},
    {0x00F1, "SINAUT"},
    {0x00F2, "SINUMERIK"},
    {0x00FC, "AlarmCatEvid"},
    {0x00FD, "AlarmCatShort"},
    {0x00FE, "AlarmCatLong"},
    {0x00FF, "AlarmCat"},
    {0x0100, "CmpPlcName"},
    {0x0101, "CmpRackName"},
    {0x0102, "CmpModuleName"},
    {0x0103, "CmpSubModuleName"},
    {0x0104, "CmpTypeName"},
    {0x0105, "CmpComment"},
    {0x0106, "CmpTagFunction"},
    {0x0107, "CmpTagLocation"},
    {0x0108, "CmpLogAddress"},
    {0x0109, "CmpOrderNo"},
    {0x010A, "CmpSubsystemNo"},
    {0x010B, "CmpRackNo"},
    {0x010C, "CmpSlotNo"},
    {0x010D, "CmpSubslotNo"},
    {0x010E, "CmpHtmlPath"},
    {0x010F, "CmpVendorName"},
    {0x0110, "CmpFirmwareVersion"},
    {0x0111, "CmpAdditionalInfo"},
    {0x0112, "CmpInstallDate"},
    {0x0113, "CmpName"},
    {0x0114, "CmpIOSystemName"},
    {0x0118, "CmpSymbolRedirection"},
    {0x0119, "CmpSymbolInput"},
    {0x011A, "CmpSymbolOutput"},
    {0x011B, "CmpSymbolChannel_IN00"},
    {0x015A, "CmpSymbolChannel_IN63"},
    {0x015B, "CmpSymbolChannel_OUT00"},
    {0x019A, "CmpSymbolChannel_OUT63"},
    {0x01F0, "CmpMotionControl"},
    {0x01FE, "PnoVendorName"},
    {0x8001, "ErrTextLibHelp"},
    {0x8002, "CPUTextlibHelp"},
    {0x8003, "ErrTextLibExHelp"},
    {0x8004, "DS1TextListHelp"},
    {0x8005, "OSTTextLibHelp  (S7classic)"},
    {0x8006, "IOTextlibHelp"},
    {0x8007, "DRHelp"},
    {0x8008, "IOTextLibFlatHelp"},
    {0x800D, "FS_TextLibHelp"},
    {0x800F, "CPTextlibHelp"},
    {0x8040, "PCStationHelp"},
    {0x8042, "PCCPHelp"},
    {0x8043, "PCDiagBaseHelp"},
    {0x80F0, "MotionControlHelp"},
    {0x80F2,  "SinumerikHelp"},
    {0, NULL}
};

static value_string_ext s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_names_ext =
    VALUE_STRING_EXT_INIT(s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_names);

static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet_text_list_8;
static const value_string s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet_text_list_8_names[] = {
    {1, "Short-circuit"},
    {2, "Undervoltage"},
    {3, "Overvoltage"},
    {4, "Overload"},
    {5, "Overtemperature"},
    {6, "Wire break"},
    {7, "High limit exceeded"},
    {8, "Low limit violated"},
    {9, "Error"},
    {10, "Simulation active"},
    {11, "Error (000B)"},
    {12, "Error (000C)"},
    {13, "Error (000D)"},
    {14, "Error (000E)"},
    {15, "Parameter not adequate"},
    {16, "Parameter error"},
    {17, "Supply voltage missing"},
    {18, "Fuse fault"},
    {19, "Communication fault"},
    {20, "Ground fault"},
    {21, "Reference channel fault"},
    {22, "Hardware interrupt lost"},
    {23, "Limit value warning"},
    {24, "Actuator shutoff"},
    {25, "Safety-related shutoff"},
    {26, "External error"},
    {27, "General error"},
    {28, "PROFIsafe communications error"},
    {29, "Error1 in actuator/sensor"},
    {30, "Error2 in actuator/sensor"},
    {31, "Channel/component temporarily not available "},
    {33, "Further diagnostics information available not stored individually"},
    {34, "Diagnostics available and is being processed"},
    {35, "Module monitoring time exceeded"},
    {64, "Mismatch of safety destination address (F_Dest_Add)"},
    {65, "Safety destination address not valid (F_Dest_Add)"},
    {66, "Safety source address not valid (F_Source_Add)"},
    {67, "Safety watchdog time value is 0 ms (F_WD_Time) "},
    {68, "Parameter F_SIL exceeds SIL from specific device application "},
    {69, "Parameter F_CRC_Length does not match the generated values "},
    {70, "Version of F parameter set incorrect "},
    {71, "CRC1 fault "},
    {72, "Device-specific diagnostics information, see manual "},
    {73, "Save iParameter watchdog time exceeded "},
    {74, "Restore iParameter watchdog time exceeded "},
    {75, "Inconsistent iParameters (iParCRC error) "},
    {76, "F_Block_ID not supported "},
    {77, "Transmission error: Inconsistent data (CRC error) "},
    {78, "Transmission error: Timeout (watchdog time 1 or 2 expired) "},
    {79, "Acknowledge required to enable channel(s) - as channel error(s) are remedied."},
    {256, "Module is defective"},
    {257, "Front connector not plugged"},
    {258, "Error (0102)"},
    {259, "Watchdog tripped"},
    {260, "Internal supply voltage fault"},
    {261, "Short-circuit to L+"},
    {262, "Short-circuit to ground"},
    {263, "Overcurrent"},
    {264, "Illegal input voltage"},
    {265, "Line break"},
    {266, "Supply voltage missing"},
    {267, "Overvoltage backplane bus"},
    {268, "Switch off"},
    {269, "Error (010D)"},
    {270, "Short circuit / overload of the sensor supply voltage"},
    {271, "Error at digital outputs"},
    {272, "Supply voltage fault"},
    {273, "Error (0111)"},
    {274, "Error (0112)"},
    {275, "Error (0113)"},
    {276, "Error (0114)"},
    {277, "Error (0115)"},
    {278, "Error (0116)"},
    {279, "Error (0117)"},
    {280, "Common mode error"},
    {281, "Undervoltage/Overload in power segment "},
    {282, "Error in the power segment"},
    {283, "Invalid/inconsistent firmware present"},
    {284, "At least one battery empty"},
    {285, "Safety shutdown"},
    {286, "Read Back Error"},
    {287, "Error (011F)"},
    {288, "Redundancy partner has different hardware/firmware version"},
    {289, "IO redundancy warning"},
    {290, "Shut-off via push-button handling"},
    {291, "Inconsistent parameter assignment"},
    {292, "Short circuit/wire break of sensor cable"},
    {293, "Changeover switch error"},
    {294, "Error partner channel"},
    {295, "Output deviation"},
    {296, "Wire break sensor supply"},
    {297, "Internal AI power supply issue"},
    {298, "Application Software Execution Fault TM-RTC"},
    {299, "Module firmware download:"},
    {300, "Firmware successfully downloaded and activated for use after reset (New firmware version @5Y%s@@6Y%u@.@7Y%u@.@8Y%u@)"},
    {318, "Diagnostic queue overflow"},
    {319, "Slot @3W%u@"},
    {320, "HART parameter error"},
    {321, "HART communication error"},
    {322, "HART primary variable out of range"},
    {323, "HART analog output current saturated"},
    {324, "HART output current of the field device fixed"},
    {325, "HART - more status available"},
    {326, "HART configuration changed"},
    {327, "HART field device malfunction"},
    {328, "HART safety related HART shutoff defective "},
    {329, "HART - non primary variable out of limits"},
    {330, "HART error (014A)"},
    {331, "HART error (014B)"},
    {332, "HART error (014C)"},
    {333, "HART error (014D)"},
    {334, "HART error (014E)"},
    {335, "HART error (014F)"},
    {337, "Invalid BaseUnit"},
    {338, "Invalid terminal block"},
    {339, "Remanent memory in base unit is defective "},
    {340, "Carrier module or memory in carrier module is defective"},
    {341, "Terminal block (TB) or memory in terminal block is defective "},
    {342, "Bus adapter is defective"},
    {343, "Output channels inactive"},
    {344, "Failure"},
    {345, "Function check"},
    {346, "Out of specification"},
    {347, "Maintenance required"},
    {384, "Short-circuit to ground on AS-interface line"},
    {740, "Positioning error"},
    {741, "Driver error"},
    {742, "Internal error"},
    {743, "DIS input active"},
    {752, "Pilot valve: switching cycle counter limit reached"},
    {753, "Actuator: switching cycle counter limit reached"},
    {754, "No valve voltage"},
    {755, "Pilot valve: wire break"},
    {756, "Pilot valve: short circuit"},
    {757, "Internal module fault"},
    {758, "Pressure limit value exceeded"},
    {759, "Pressure limit value not reached"},
    {760, "Error (02F8)"},
    {761, "Error (02F9)"},
    {762, "Error (02FA)"},
    {763, "Error (02FB)"},
    {764, "Error (02FC)"},
    {765, "Error (02FD)"},
    {766, "Error (02FE)"},
    {767, "Error (02FF)"},
    {768, "Discrepancy failure, channel state 0/0"},
    {769, "Discrepancy failure, channel state 0/1"},
    {770, "Discrepancy failure, channel state 1/0"},
    {771, "Discrepancy failure, channel state 1/1"},
    {772, "Analog input signal not recorded unique"},
    {773, "Input signal not recorded unique"},
    {774, "Internal sensor supply short-circuit to P"},
    {775, "Overload or internal sensor supply short-circuit to ground"},
    {776, "Short-circuit of sensor supply defective"},
    {777, "Short-circuit of the sensor with the sensor supply"},
    {778, "No pulses detected"},
    {779, "Channel failure acknowledgement"},
    {780, "Device deactivation"},
    {781, "F-address memory not accessible"},
    {782, "No valid F-address available"},
    {783, "Error during failsafe address assignment"},
    {784, "Sensor signal flutters"},
    {785, "Frequency too high"},
    {786, "Undertemperature"},
    {787, "Failure in the input circuit"},
    {788, "Discrepancy failure"},
    {789, "Internal discrepancy failure"},
    {790, "Relay can not be turned on"},
    {791, "Relay can not be turned off (contacts welded) "},
    {792, "PROFIsafe communication failure (timeout)"},
    {793, "PROFIsafe communication error (CRC)"},
    {794, "PROFIsafe address assignment failure"},
    {795, "Input short-circuit to ground"},
    {796, "Input shorted to P"},
    {797, "Output defective"},
    {798, "Read back failure"},
    {799, "Overcurrent"},
    {800, "Overload"},
    {801, "Supply voltage too high"},
    {802, "Supply voltage too low"},
    {803, "Supply voltage too high"},
    {804, "Supply voltage too low"},
    {805, "Bus enumeration fault"},
    {806, "Bus enumeration fault / old FW version"},
    {807, "Module slot wrong or configuration faulty"},
    {808, "Module slot wrong or configuration faulty(not safety relevant)"},
    {809, "Inconsistent configuration data"},
    {810, "Safety related HART shutoff defective "},
    {811, "Channel passivated"},
    {812, "Safety related shut-off (relay continuous on time limit exceeded)"},
    {813, "Panic operation of enabling button incomplete"},
    {814, "F module error (0x032E)"},
    {815, "F module error (0x032F)"},
    {816, "Safety related shut-off"},
    {817, "ADC failure"},
    {818, "Failure in the test circuit"},
    {1024, "AS-i slave failed"},
    {1025, "AS-i slave on B-address failed"},
    {1026, "Peripheral fault in AS-i slave "},
    {1027, "Peripheral fault in AS-i slave on B-address"},
    {1028, "AS-i address used multiple times"},
    {1029, "AS-i B-address used multiple times"},
    {1030, "No voltage or too low voltage on AS-interface cable"},
    {1031, "AS-i configuration fault"},
    {1032, "Short-circuit to ground on AS-interface line"},
    {1033, "AS-i fault (0x0409)"},
    {1034, "Supernumerary AS-i slave "},
    {1035, "Supernumerary AS-i slave on B-address "},
    {1036, "Incorrect AS-i slave"},
    {1037, "Incorrect AS-i slave on B-address "},
    {1038, "AS-i voltage too high"},
    {1039, "AS-i voltage too low"},
    {1040, "Discrepancy failure, channel state 0/0"},
    {1041, "Discrepancy failure, channel state 0/1"},
    {1042, "Discrepancy failure, channel state 1/0"},
    {1043, "Discrepancy failure, channel state 1/1"},
    {1044, "Sequence error, channel state 0/0"},
    {1045, "Sequence error, channel state 0/1"},
    {1046, "Sequence error, channel state 1/0"},
    {1047, "Sequence error, channel state 1/1"},
    {1048, "Overtemperature"},
    {1049, "New AS-i safety slave code sequence detected"},
    {1050, "Safe AS-i input slave missing"},
    {1051, "Safe AS-i output slave failed"},
    {1052, "Peripheral fault in one or more AS-i slaves "},
    {1053, "One or more AS-i addresses used multiple times"},
    {1054, "AS-i safety signal error"},
    {1055, "AS-i safety slave code sequence ready to save"},
    {1056, "AS-i safety slave code sequence missing"},
    {1057, "AS-i safety slave code sequence multiple used"},
    {1058, "AS-i safety communication error"},
    {1059, "Device error"},
    {1060, "AS-i error (0x0424)"},
    {1061, "AS-i error (0x0425)"},
    {1062, "AS-i error (0x0426)"},
    {1232, "CAN in bus off mode"},
    {1233, "CAN in error passive mode"},
    {1234, "CAN receive buffer overflow"},
    {1235, "CAN transmit buffer overflow"},
    {1236, "Received PDO too short"},
    {1237, "Heartbeat error"},
    {1238, "Node guarding error"},
    {1239, "Heartbeat / node guarding error"},
    {1240, "Wrong NMT state"},
    {1241, "Bootup failed"},
    {1242, "Bootup - node not responding"},
    {1243, "Bootup"},
    {1244, "EMCY received"},
    {1245, "Received message wrong length"},
    {1246, "Extended parameterization error"},
    {1248, "Interface error"},
    {1249, "IP address (@5Y%u@.@6Y%u@.@7Y%u@.@8Y%u@) of an IE interface already exists "},
    {1250, "Name of an IE interface already exists "},
    {1251, "PROFIBUS interface error "},
    {1252, "DHCP Server offer not acceptable or not present"},
    {1253, "Retrieved DHCP parameter changed to invalid"},
    {1256, "Module firmware update aborted: "},
    {1257, "Firmware for hardware component unchanged"},
    {1280, "Illegal A/B signal ratio"},
    {1281, "Frequency outside specification"},
    {1282, "RS422/TTL error"},
    {1283, "Error on SSI sensor"},
    {1284, "Error on BiSS sensor"},
    {1285, "Wire break digital input (A, B or N) "},
    {1286, "Overtemperature"},
    {1536, "Error (0x0600)"},
    {1537, "Status error"},
    {1538, "Configuration error"},
    {1539, "Net configuration error"},
    {1552, "Load voltage error"},
    {1568, "ET-Connection error"},
    {1584, "Redundancy error"},
    {1600, "Hardware error"},
    {1664, "IO bus fault starting at slot @4W%u@"},
    {1665, "Transmitted IO data invalid (partially bad-flagged)  "},
    {1666, "Communication with slot @4W%u@ failed"},
    {1667, "Drag chain fault"},
    {1668, "Firmware activation pending"},
    {1678, "Incompatible MultiFieldbus project found on device remanence (ModuleID=@8W%X@)"},
    {1679, "No active backplane bus detected at an IM port"},
    {1680, "Wrong module on slot"},
    {1681, "Station stop - Module parameter 'potential group' incorrect or wrong BaseUnit/TerminalBlock on real configuration slot @4W%u@"},
    {1682, "Permitted number of I/O modules exceeded at slot @4W%u@"},
    {1683, "Station stop - missing or wrong server module"},
    {1684, "Station stop - too many missing modules (@4W%u@)"},
    {1685, "IO data packing fault for slot @4W%u@"},
    {1686, "No U connector detected at IM port"},
    {1687, "More than one bus master module (IM/CPU) detected"},
    {1688, "Permitted size of backplane exceeded"},
    {1689, "Invalid backplane configuration for slot @4W%u@"},
    {1690, "Interface module at wrong slot"},
    {1691, "Permitted number of power supply modules exceeded at slot @4W%u@"},
    {1692, "Invalid bus adapter at interface module"},
    {1693, "Missing record for configuration control"},
    {1694, "Missing or wrong server module"},
    {1695, "Module parameter 'potential group' incorrect or wrong BaseUnit / TerminalBlock on real configuration slot (slot number)"},
    {1696, "Error on other net"},
    {1697, "Difference between nets at slot @4W%u@"},
    {1698, "No input data for activated data validity display configured"},
    {1699, "Coupling of sync domains not possible/nsync master on X1, sync slave on X2 missing"},
    {1700, "Coupling of sync domains not possible/nsync master on X2, sync slave on X1 missing"},
    {1701, "Shared device conflict, invalid sub module combination in slot @4W%u@"},
    {1702, "Shared device conflict, valid IO range exceeded by @4W%u@ bytes."},
    {1703, "IO memory for interface X@4W%u@ is too fragmented. The device needs to be restarted."},
    {1712, "Missing voltage in load group at slot according channel number"},
    {1713, "Overloaded power segment at slot @4W%u@"},
    {1714, "IM power supply error"},
    {1715, "Power supply failure (PS number  @4W%u@)"},
    {1716, "Power supply undervoltage"},
    {1728, "Invalid number of modules in the extension rack @4W%u@"},
    {1729, "Invalid number of extension racks (number @4W%u@)"},
    {1730, "BA-Send module on incorrect slot  @4W%u@"},
    {1731, "Invalid component in the extension rack @4W%u@"},
    {1732, "Link error in the extension rack @4W%u@"},
    {1744, "Request for maintenance @4W%X@"},
    {1745, "Power supply malfunctioning"},
    {1746, "Failure in bus adapter of partner module"},
    {1747, "Redundancy partner with different hardware or software version"},
    {1760, "Failure on access of flash memory in base unit"},
    {1761, "Failure on access of flash memory in bus adapter"},
    {1762, "Module is operated in the limit range"},
    {1763, "Name of station existing in flash memory (e.g. bus adapter) but not used"},
    {1764, "Increased disturbances detected"},
    {4096, "Zero current after ON command"},
    {4097, "Current flow after OFF command"},
    {4098, "Current flow after ON command"},
    {4099, "Zero current after OFF command"},
    {4100, "Positioner blockage"},
    {4101, "Torque switch concurrence"},
    {4102, "End position switch concurrence"},
    {4103, "End position switch state change "},
    {4104, "End position / torque switch antivalence error"},
    {4105, "Test mode running"},
    {4106, "Test mode current flow"},
    {4107, "Main circuit power failure"},
    {4108, "Protection off mode"},
    {4109, "Wiring fault"},
    {4110, "Module dropped out"},
    {4111, "External memory module not accessible "},
    {4112, "Operating hours counter"},
    {4113, "Generator operation"},
    {4114, "Phase control failure"},
    {4115, "2-phase control active"},
    {4116, "Error after self-diagnosis"},
    {4128, "Prewarning overload (I>115%Ie)"},
    {4129, "Phase unbalance"},
    {4130, "Thermal motor model overload"},
    {4131, "Phase failure + thermal motor model overload"},
    {4132, "Temperature sensor overload"},
    {4133, "Temperature sensor short-circuit"},
    {4134, "Temperature sensor wire break"},
    {4135, "Ground fault"},
    {4136, "Ground fault module ground fault"},
    {4137, "Ground fault module wire break"},
    {4138, "Ground fault module short-circuit"},
    {4139, "Temperature module 1 above threshold T"},
    {4140, "Temperature module 1 sensor error"},
    {4141, "Temperature module 1 outside measuring range"},
    {4142, "Temperature module 2 above threshold T"},
    {4143, "Temperature module 2 sensor error"},
    {4144, "Temperature module 2 outside measuring range"},
    {4145, "Emergency thermal motor model deleted"},
    {4146, "Cooling down period active"},
    {4147, "Missing startup parameters"},
    {4148, "Ramp up time exceeded"},
    {4149, "Ramp up time underrun"},
    {4150, "Ex motor protection parameters received"},
    {4160, "Above threshold I"},
    {4161, "Below threshold I"},
    {4162, "Above threshold P"},
    {4163, "Below threshold P"},
    {4164, "Error (0x1044)"},
    {4165, "Below threshold Cos-Phi"},
    {4166, "Actuator shutoff"},
    {4167, "Below threshold U"},
    {4168, "Analog module 1 above threshold 0/4-20mA"},
    {4169, "Analog module 1 below threshold 0/4-20mA"},
    {4170, "Analog module 2 above threshold 0/4-20mA"},
    {4171, "Analog module 2 below threshold 0/4-20mA"},
    {4172, "Motor blockage"},
    {4173, "Dry-run pump"},
    {4174, "Dry-run-protection error"},
    {4181, "Test trip"},
    {4182, "Number of starting operations reached."},
    {4183, "Number of starting operations exceeded"},
    {4184, "One more starting operation allowed."},
    {4185, "Motor operating hours exceeded"},
    {4186, "Standstill time exceeded"},
    {4187, "Analog module 1 wire break"},
    {4188, "Analog module 2 wire break"},
    {4189, "Analog output wire break"},
    {4190, "F-component test requirement"},
    {4191, "F-component feedback circuit"},
    {4192, "F-component discrepancy error"},
    {4193, "F-component wiring error"},
    {4194, "F-component cross-circuit"},
    {4195, "Error (0x1063)"},
    {4196, "Error (0x1064)"},
    {4208, "External error 1"},
    {4209, "External error 2"},
    {4210, "External error 3"},
    {4211, "External error 4"},
    {4212, "External error 5"},
    {4213, "External error 6"},
    {4214, "Error (0x1076)"},
    {4215, "Error (0x1077)"},
    {4224, "Device error"},
    {4225, "Bypass defective"},
    {4226, "Power semiconductor device defective"},
    {4227, "Switching element overload"},
    {4228, "Supply voltage too low"},
    {4229, "Bypass overload"},
    {4230, "Supply voltage contact blocks too low"},
    {4231, "External bypass defect"},
    {4232, "Power supply to switching element missing"},
    {4233, "Time reserve before tripping underrun"},
    {4234, "Error (0x108A)"},
    {4241, "Zero current"},
    {4242, "Motor connection variant unknown or incorrect  "},
    {4243, "Sensor supply overload"},
    {4244, "Module slot wrong or configuration faulty"},
    {4245, "Parameter fault"},
    {4246, "Process image error"},
    {4247, "Phase failure"},
    {4248, "Connection break in manual mode"},
    {4249, "Error (0x1099)"},
    {4253, "Input action"},
    {4254, "Emergency end position clockwise"},
    {4255, "Emergency end position counter-clockwise"},
    {4261, "Zero current"},
    {4856, "Limit: @3W%d@ °C (@4W%d@ °F)"},
    {4857, "Limit: @2X%d@ %"},
    {4858, "Cooling period in progress ≤ @2X%u@ sec"},
    {4859, "Prohibited Ie / CLASS setting"},
    {4860, "Limit: @2X%d@ % relative to Ie"},
    {4861, "Slot number: @2X%u@"},
    {4862, "Parameter ID @2X%u@"},
    {4939, "Trip reset not possible"},
    {5393, "Tag does not answer"},
    {5394, "Tag access refused due to wrong password. "},
    {5395, "Tag data verification failed."},
    {5396, "Tag reports an unspecific error"},
    {5397, "Tag has insufficient power "},
    {5405, "Error (0x151D)"},
    {5406, "Error (0x151E)"},
    {5407, "Error (0x151F)"},
    {5409, "RF field without tag"},
    {5410, "RF field returns no data"},
    {5411, "RF field returns CRC error"},
    {5413, "RF field without active frequency"},
    {5414, "RF field without active base"},
    {5415, "RF field with more than one tag"},
    {5416, "RF field with unspecific error on air protocol"},
    {5478, "Command Inventory failed"},
    {5479, "Command Read Tag failed"},
    {5480, "Command Write Tag failed"},
    {5481, "Command Write Tag Id failed"},
    {5482, "Command Lock Tag failed"},
    {5483, "Command Kill Tag failed"},
    {5521, "Antenna 1 not connected"},
    {5522, "Antenna 2 not connected"},
    {5523, "Antenna 3 not connected"},
    {5524, "Antenna 4 not connected"},
    {5525, "Antenna 5 not connected"},
    {5526, "Antenna 6 not connected"},
    {5527, "Antenna 7 not connected"},
    {5528, "Antenna 8 not connected"},
    {5537, "Alarm overflow"},
    {20480, "Invalid sensor"},
    {20481, "Reader not found"},
    {20482, "Error (0x5002)"},
    {20483, "Error during DISA signal change"},
    {20484, "Sequence error"},
    {20485, "Internal file error - Program cannot be started"},
    {20486, "Transmit error"},
    {20487, "Transfer error"},
    {20488, "Error (0x5008)"},
    {20489, "Error (0x5009)"},
    {20490, "Program saving error"},
    {20491, "Match error"},
    {20492, "Error (0x500C)"},
    {20493, "TCP communication / archiving / MMI communication error"},
    {20494, "TCP communication / archiving / MMI communication error"},
    {20495, "Lamp overload error"},
    {20496, "Invalid program number error"},
    {20497, "Error (0x5011)"},
    {20498, "PROFINET IO connection error"},
    {20501, "PROFINET IO controller status STOP"},
    {20502, "PROFINET IO configuration error"},
    {20503, "PROFINET IO compatibility error"},
    {20737, "Communication error HCS bus"},
    {20738, "Line voltage error "},
    {20739, "Frequency error"},
    {20740, "Triac short-circuited"},
    {20741, "Incoming fuse tripped or triac is highly resistive"},
    {20742, "Outgoing fuse tripped"},
    {20743, "External error"},
    {20744, "Internal temperature warning "},
    {20745, "Internal temperature error"},
    {20746, "fan error"},
    {20747, "At least one phase is not connected"},
    {20748, "Internal error"},
    {20749, "CIM communication error"},
    {20750, "Error rotating field"},
    {20751, "Phase LX1 is not connected"},
    {20752, "Phase LX3 is not connected"},
    {20753, "Phase LX3 is not connected"},
    {20754, "Polarity error on measuring input "},
    {20755, "partial load missing"},
    {20756, "permitted channel current exceeded"},
    {20757, "permitted current phase LX1 exceeded"},
    {20758, "permitted current phase LX3 exceeded"},
    {20759, "power-setpoint cannot be reached"},
    {20760, "fault current exceeded"},
    {20761, "adaptive softstart cannot be finished"},
    {20762, "permitted current phase LX2 exceeded"},
    {21761, "No supply voltage"},
    {21762, "No server module"},
    {21763, "Too many modules removed "},
    {21764, "Incorrect Base Unit"},
    {21765, "Incorrect bus structure"},
    {24577, "Redundancy link 1 error"},
    {24578, "Redundancy link 2 error"},
    {24832, "Contactor cannot be turned on"},
    {24833, "Contactor cannot be turned off (contacts welded)"},
    {32464, "Error (Quality Code derived)"},
    {32465, "Maintenance demanded (Quality Code derived)"},
    {32466, "Maintenance required (Quality Code derived)"},
    {32467, "Out of service (Quality Code derived)"},
    {32468, "Passivated (Quality Code derived)"},
    {32469, "Simulated (Quality Code derived)"},
    {32470, "Local control override (Quality Code derived)"},
    {32768, "valid for group of @3W%5d@ channels starting with @8W%t#7W@ channel @4W%5d@ "},
    {36864, "Hardware/software error"},
    {36865, "Net error"},
    {36866, "Supply voltage fault"},
    {36867, "DC link fault"},
    {36868, "Power electronics fault"},
    {36869, "Overtemperature of electronic components"},
    {36870, "Ground fault/phase short-circuit detected"},
    {36871, "Motor overload"},
    {36872, "Communication error to the higher-level control system"},
    {36873, "Safety monitoring channel has identified an error"},
    {36874, "Position/velocity process value incorrect or not available"},
    {36875, "Internal connection error (e.g. DRIVE-CLiQ)"},
    {36876, "Infeed defective"},
    {36877, "Braking module faulty"},
    {36878, "Line filter faulty"},
    {36879, "External measured value/signal state outside permitted range"},
    {36880, "Application/technological function faulty"},
    {36881, "Error in parameter assignment/configuration/commissioning"},
    {36882, "General drive fault"},
    {36883, "Auxiliary unit faulty"},
    {36884, "Drive fault (class 20)"},
    {36885, "Drive fault (class 21)"},
    {36886, "Drive fault (class 22)"},
    {36887, "Drive fault (class 23)"},
    {39826, "Error packet size adoption (PIB)"},
    {39827, "Command repetition not supported (PIB)"},
    {39828, "Timeout during INIT (PIB)"},
    {39829, "Ident Unit does not respond to INIT (PIB)"},
    {39830, "Wrong index (PIB)"},
    {39831, "Only INIT as next command allowed (PIB)"},
    {39832, "RXBUF overflow (PIB)"},
    {39833, "Parameter 'Length' too long (PIB)"},
    {39834, "Command code not allowed (PIB)"},
    {39835, "Only INIT command allowed (PIB)"},
    {39931, "Command in which only Write-Config is permissible in this state"},
    {39932, "Command with wrong synchronization between application and tag"},
    {39933, "Command parameter invalid"},
    {39934, "Command index invalid."},
    {39935, "Command invalid"},
    {40024, "Communication error: synchronization error (PIB)"},
    {40025, "Communication error: wrong sequence of acknowledge telegrams (PIB)"},
    {40026, "Communication error: command code and acknowledgement do not correspond (PIB)"},
    {40027, "Communication error: Ident Unit executes a hardware reset (PIB)"},
    {40028, "Communication error: command from another user being processed"},
    {40029, "Communication error: invalid data block length (PIB)"},
    {40030, "Communication error: invalid data block length"},
    {40031, "Communication error: invalid data block number (PIB)"},
    {40032, "Communication error: invalid data block number"},
    {40034, "Communication error: wrong sequence number (PIB)"},
    {40035, "Communication error: wrong sequence number"},
    {40129, "Device error due to cyclic Status Word"},
    {40130, "Device command in this mode not supported"},
    {40131, "Device data buffer overflow"},
    {40132, "Device command buffer overflow"},
    {40133, "Device antenna error or not activated"},
    {40134, "Device hardware failure"},
    {40135, "Device power supply failure"},
    {40228, "File not accessible"},
    {40229, "File length overflow"},
    {40230, "File access right violation"},
    {40231, "File already exists"},
    {40232, "File entries exhausted."},
    {40233, "File system not available on tag type."},
    {40234, "File does not exist"},
    {40235, "File name incorrect."},
    {40334, "RF field with more tags than allowed"},
    {40335, "RF field communication disturbed"},
    {40426, "Tag access violation "},
    {40427, "Tag command not supported "},
    {40428, "Tag does not have the expected ID"},
    {40429, "Tag data structure inconsistent. "},
    {40430, "Tag unformatted"},
    {40431, "Tag memory overflow"},
    {40432, "Tag is defective"},
    {40433, "Tag address or command does not fit the tag characteristics"},
    {40434, "Tag presence error"},
    {40435, "Tag memory error "},
    {65521, "Input channel"},
    {65522, "Output channel"},
    {65523, "Input/Output channel"},
    {0, NULL}
};

static value_string_ext s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet_text_list_8_names_ext =
    VALUE_STRING_EXT_INIT(s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet_text_list_8_names);

static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_echet;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_echet;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_0;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_1;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_2;
static int hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_3;
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail;
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_0_2; /* mask: 0x00000007 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_3;
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_4;
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_5;
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_6;
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_7_10; /* mask: 0x00000780 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_11_14; /* mask: 0x00007800 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_15; /* mask: 0x00008000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_16; /* mask: 0x00010000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_17; /* mask: 0x00020000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_18; /* mask: 0x00040000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_19; /* mask: 0x00080000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_20; /* mask: 0x00100000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_21; /* mask: 0x00200000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_22; /* mask: 0x00400000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_23; /* mask: 0x00800000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_24; /* mask: 0x01000000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_25; /* mask: 0x02000000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_26; /* mask: 0x04000000 */
static int hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_27_31; /* mask: 0xF8000000 */


static int hf_s7comm_szl_xy78_xxxx_dis_io_state;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_0;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_1;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_2;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_3;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_4;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_5;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_6;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_7;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_8_14;
static int hf_s7comm_szl_xy78_xxxx_dis_io_state_15;
static int hf_s7comm_szl_xy78_xxxx_dis_res;
static int hf_s7comm_szl_xy78_xxxx_dis_maint_state;
static const value_string s7comm_szl_xy78_xxxx_dis_maint_state_names[] = {
    { 0x0,                                  "Good" },
    { 0x1,                                  "DevicePassivated" },
    { 0x2,                                  "OutOfService" },
    { 0x3,                                  "Simulated" },
    { 0x4,                                  "LocalOperation" },
    { 0x5,                                  "MaintenanceRequired" },
    { 0x6,                                  "MaintenanceDemanded" },    
    { 0x7,                                  "MaintenanceAlarm" },
    { 0x8,                                  "Unknown" },
    { 0x9,                                  "ConfigurationChanged" },
    { 0xA,                                  "IOnotAvailable" },
    { 0,                                    NULL }
};

static int hf_s7comm_szl_xy78_xxxx_dis_operating_state;
static int hf_s7comm_szl_xy78_xxxx_dis_own_state;
static const value_string s7comm_szl_xy78_xxxx_dis_own_state_names[] = {
    { 0x0,                                  "Good" },
    { 0x1,                                  "Deactivated" },
    { 0x2,                                  "Maintenance Required" },
    { 0x3,                                  "Maintenance Demanded" },
    { 0x4,                                  "Error" },
    { 0x5,                                  "Not Reachable" },
    { 0x6,                                  "Unknown" },
    { 0x7,                                  "IOnotAvailable" },
    { 0,                                    NULL }
};

static int hf_s7comm_szl_xy78_xxxx_sub_ord_io_state;
static int hf_s7comm_szl_xy78_xxxx_sub_ord_state;
static int hf_s7comm_szl_xy78_xxxx_disp_own_state;
static int hf_s7comm_szl_xy78_xxxx_disp_sub_ord_state;
static int hf_s7comm_szl_xy78_xxxx_disp_mode;
static int hf_s7comm_szl_xy78_xxxx_vendor;
static int hf_s7comm_szl_xy78_xxxx_order_id;
static int hf_s7comm_szl_xy78_xxxx_im1;
static int hf_s7comm_szl_xy78_xxxx_iam1_function;
static int hf_s7comm_szl_xy78_xxxx_iam1_location;
static int hf_s7comm_szl_xy78_xxxx_asset_id;
static int hf_s7comm_szl_xy78_xxxx_tlv;
static int hf_s7comm_szl_xy78_xxxx_tlv_num;
static int hf_s7comm_szl_xy78_xxxx_tlv_item;

static int hf_s7comm_szl_xy78_xxxx_tlv_item_type;
static const value_string szl_xy78_xxxx_tlv_item_type_names[] = {
    { 0x1,                                  "DTI-Type" },
    { 0x2,                                  "Alarm-SD" },
    { 0x3,                                  "Propagation behaviour" },
    { 0,                                    NULL }
};

static int hf_s7comm_szl_xy78_xxxx_tlv_item_len;
static int hf_s7comm_szl_xy78_xxxx_tlv_item_data;
static int hf_s7comm_szl_xy78_xxxx_tlv_item_dti_type;
static const value_string szl_xy78_xxxx_tlv_item_dti_type_name[] = {
    { 0x1,                                  "IO-System" },
    { 0x2,                                  "Device" },
    { 0x3,                                  "Rack" },
    { 0x4,                                  "Module" },
    { 0x5,                                  "Submodule" },
    { 0xB,                                  "IO-Device Agent" },
    { 0,                                    NULL }
};

static int ett_s7comm_szl_xy78_xxxx_geo_addr;
static int ett_s7comm_szl_xy78_xxxx_dis;
static int ett_s7comm_szl_xy78_xxxx_dis_cdiags;
static int ett_s7comm_szl_xy78_xxxx_dis_cdiag_entry;
static int ett_s7comm_szl_xy78_xxxx_dis_cdiag_add_val;
static int ett_s7comm_szl_xy78_xxxx_iam1;
static int ett_s7comm_szl_xy78_xxxx_tlv;
static int ett_s7comm_szl_xy78_xxxx_tlv_item;

static int ett_s7comm_szl_xy78_xxxx_dis_io_state;
static int* const s7comm_szl_xy78_xxxx_dis_io_state_fields[] = {
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_0,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_1,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_2,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_3,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_4,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_5,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_6,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_7,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_8_14,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_15,
    NULL
};

static int ett_s7comm_szl_xy78_xxxx_sub_ord_io_state;
static int* const s7comm_szl_xy78_xxxx_sub_ord_io_state_fields[] = {
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_0,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_1,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_2,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_3,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_4,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_5,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_6,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_7,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_8_14,
    &hf_s7comm_szl_xy78_xxxx_dis_io_state_15,
    NULL
};

static int ett_s7comm_szl_xy78_xxxx_dis_comp_state_detail;
static int* const s7comm_szl_xy78_xxxx_dis_comp_state_detail_fields[] = {
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_0_2,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_3,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_4,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_5,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_6,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_7_10,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_11_14,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_15,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_16,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_17,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_18,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_19,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_20,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_21,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_22,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_23,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_24,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_25,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_26,
    &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_27_31,
    NULL
};

/*******************************************************************************************************
 *
 * Get the textual description of the szl index. Returns NULL if not description available
 *
 *******************************************************************************************************/
static const char*
s7comm_get_szl_id_index_description_text(uint16_t id, uint16_t idx)
{
    const char* str = NULL;
    switch (id) {
        case 0x0077:
            str = "DNN-Id";
            break;
        case 0x0078:
            str = "DNN-Id";
            break;
        case 0x0111:
            str = val_to_str_const(idx, szl_0111_index_names, "No description available");
            break;
        case 0x0112:
            str = val_to_str_const(idx, szl_0112_index_names, "No description available");
            break;
        case 0x0113:
            str = val_to_str_const(idx, szl_0113_index_names, "No description available");
            break;
        case 0x0114:
            str = val_to_str_const(idx, szl_0114_index_names, "No description available");
            break;
        case 0x0115:
            str = val_to_str_const(idx, szl_0115_index_names, "No description available");
            break;
        case 0x0116:
            str = val_to_str_const(idx, szl_0116_index_names, "No description available");
            break;
        case 0x0118:
            str = val_to_str_const(idx, szl_0118_index_names, "No description available");
            break;
        case 0x0119:
            str = val_to_str_const(idx, szl_0119_0174_ledid_index_names, "No description available");
            break;
        case 0x0121:
            str = val_to_str_const(idx, szl_0121_index_names, "No description available");
            break;
        case 0x0222:
            str = val_to_str_const(idx, szl_0222_index_names, "No description available");
            break;
        case 0x0524:
            str = val_to_str_const(idx, szl_0524_index_names, "No description available");
            break;
        case 0x0131:
            str = val_to_str_const(idx, szl_0131_index_names, "No description available");
            break;
        case 0x0132:
            str = val_to_str_const(idx, szl_0132_index_names, "No description available");
            break;
        case 0x0174:
            str = val_to_str_const(idx, szl_0119_0174_ledid_index_names, "No description available");
            break;
        case 0x011c:
        case 0x031c:
            str = val_to_str_const(idx, szl_xy1c_index_names, "No description available");
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
static uint32_t
s7comm_decode_szl_id_xy00(tvbuff_t *tvb,
                          proto_tree *tree,
                          uint16_t id,
                          uint16_t idx,
                          uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0013_idx_0000(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_xy14_idx_000x(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_xy15_idx_000x(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0111_idx_0001(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_xy11_0001_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy11_0001_mlfb, tvb, offset, 20, ENC_ASCII);
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
        { "Interrupt event is caused by parameters disabled", "s7comm.szl.xy22.00xx.al1.evpd", FT_BOOLEAN, 16, NULL, 0x0001,
          "Bit 0: Interrupt event is caused by parameters, 0=Enabled, 1=Disabled", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_1,
        { "Interrupt event as per SFC 39 locked", "s7comm.szl.xy22.00xx.al1.iel", FT_BOOLEAN, 16, NULL, 0x0002,
          "Bit 1: Interrupt event as per SFC 39, 0=Not locked, 1=Locked", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_2,
        { "Interrupt source is active", "s7comm.szl.xy22.00xx.al1.isia", FT_BOOLEAN, 16, NULL, 0x0004,
          "Bit 2: Interrupt source is active", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_4,
        { "Interrupt OB is loaded", "s7comm.szl.xy22.00xx.al1.ioil", FT_BOOLEAN, 16, NULL, 0x0010,
          "Bit 4: Interrupt OB, 0=Is not loaded, 1=Is loaded", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_5,
        { "Interrupt OB is locked by TIS", "s7comm.szl.xy22.00xx.al1.ioilbt", FT_BOOLEAN, 16, NULL, 0x0020,
          "Bit 5: Interrupt OB is by TIS, 1=Locked", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al1_6,
        { "Entry in diagnostic buffer locked", "s7comm.szl.xy22.00xx.al1.eidbl", FT_BOOLEAN, 16, NULL, 0x0040,
          "Bit 6: Entry in diagnostic buffer, 1=Locked", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2,
        { "al2 (Reaction with not loaded/locked OB)", "s7comm.szl.xy22.00xx.al2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2_0,
        { "Lock interrupt source", "s7comm.szl.xy22.00xx.al2.lis", FT_BOOLEAN, 16, NULL, 0x0001,
          "Bit 0: Lock interrupt source", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2_1,
        { "Generate interrupt event error", "s7comm.szl.xy22.00xx.al2.giee", FT_BOOLEAN, 16, NULL, 0x0002,
          "Bit 1: Generate interrupt event error", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2_2,
        { "CPU goes into STOP mode", "s7comm.szl.xy22.00xx.al2.gism", FT_BOOLEAN, 16, NULL, 0x0004,
          "Bit 2: CPU goes into STOP mode", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al2_3,
        { "Interrupt only discarded", "s7comm.szl.xy22.00xx.al2.iod", FT_BOOLEAN, 16, NULL, 0x0008,
          "Bit 3: Interrupt only discarded", HFILL }},
        { &hf_s7comm_szl_xy22_00xx_al3,
        { "al3 (Discarded by TIS functions)", "s7comm.szl.xy22.00xx.al3", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static uint32_t
s7comm_decode_szl_id_xy22_idx_00xx(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0131_idx_0001(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0131_idx_0002(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
        { "per min (Minimum period for cyclic read jobs (n x 100 ms))", "s7comm.szl.0131.0003.per_min", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0003_per_max,
        { "per max (Maximum period for cyclic read jobs (n x 100 ms))", "s7comm.szl.0131.0003.per_max", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_0131_0003_res,
        { "res (Reserved)", "s7comm.szl.0131.0003.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static uint32_t
s7comm_decode_szl_id_0131_idx_0003(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
        { "ver (Maximum size (in bytes) of shiftable blocks in RUN)", "s7comm.szl.0131.0004.ver", FT_UINT8, BASE_DEC, NULL, 0x0,
          "ver (Maximum size (in bytes) of shiftable blocks in RUN) With an S7-300, this size refers to the entire block,with the S7-400, it refers to the part of the block relevant to running the program.", HFILL }},
        { &hf_s7comm_szl_0131_0004_res,
        { "res (Reserved)", "s7comm.szl.0131.0004.res", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
static uint32_t
s7comm_decode_szl_id_0131_idx_0004(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0131_idx_0005(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0131_idx_0006(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
 *  contains information about the functions available for global data
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
static uint32_t
s7comm_decode_szl_id_0131_idx_0007(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0131_idx_0008(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0131_idx_0009(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0131_idx_0010(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0132_idx_0001(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0132_idx_0002(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
        { "param (Assigned protection level, possible values: 0, 1, 2 or 3)", "s7comm.szl.0132.0004.param", FT_UINT16, BASE_DEC, NULL, 0x0,
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
static uint32_t
s7comm_decode_szl_id_0132_idx_0004(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0132_idx_0005(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0132_idx_0006(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0132_idx_0008(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0132_idx_000b(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_0132_idx_000c(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
static uint32_t
s7comm_decode_szl_id_xy74_idx_0000(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
 * SZL-ID:  0xxy76
 * Index:   0x0000
 * Content:
 *  If you read the partial list SSL-ID W#16#xy76, you obtain the DNN-Id of the top DNN node.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy76_0000_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_xy76_0000_version,
        { "Version", "s7comm.szl.xy76.0000.version", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy76_0000_top_dnn_id,
        { "Top DNN Id", "s7comm.szl.xy76.0000.top_dnn_id", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy77
 * Index:   0xxxxx
 * Content:
 *  If you read the partial list SSL-ID W#16#xy77, you obtain the relations of a DNN node.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy77_xxxx_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_xy77_xxxx_version,
        { "Version", "s7comm.szl.xy77.xxxx.version", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy77_xxxx_num_parent,
        { "Number of parent objects", "s7comm.szl.xy77.xxxx.num_parent", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy77_xxxx_obj_parent,
        { "Parent object", "s7comm.szl.xy77.xxxx.obj_parent", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy77_xxxx_num_child,
        { "Number of child objects", "s7comm.szl.xy77.xxxx.num_child", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy77_xxxx_obj_child,
        { "Child object", "s7comm.szl.xy77.xxxx.obj_child", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy77_xxxx_num_redundancy_links,
        { "Number of redundancy links", "s7comm.szl.xy77.xxxx.num_red_links", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy77_xxxx_obj_redundancy,
        { "Redundancy object", "s7comm.szl.xy77.xxxx.obj_red", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy77_xxxx_num_iodevice_agent_links,
        { "Number of redundancy links", "s7comm.szl.xy77.xxxx.num_red_links", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy77_xxxx_obj_iodevice_agent,
        { "IO-Device agent object", "s7comm.szl.xy77.xxxx.obj_agent", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy78
 * Index:   0xxxxx
 * Content:
 *  If you read the partial list SSL-ID W#16#xy78, you obtain the diagnostic data of a DNN node.
 *
 *******************************************************************************************************/
static void
s7comm_szl_xy78_xxxx_register(int proto)
{
    static hf_register_info hf[] = {
        { &hf_s7comm_szl_xy78_xxxx_version,
        { "Version", "s7comm.szl.xy78.xxxx.version", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_unknown_version_data,
        { "Unknown versioned data", "s7comm.szl.xy78.xxxx.unknown_version_data", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},          
        { &hf_s7comm_szl_xy78_xxxx_geo_addr,
        { "GEO. addr", "s7comm.szl.xy78.xxxx.geo", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_geo_addr_subsys,
        { "Subsystem", "s7comm.szl.xy78.xxxx.geo.subsys", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_geo_addr_station,
        { "Station", "s7comm.szl.xy78.xxxx.geo.station", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_geo_addr_rack,
        { "Rack", "s7comm.szl.xy78.xxxx.geo.rack", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_geo_addr_slot,
        { "Slot", "s7comm.szl.xy78.xxxx.geo.slot", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_geo_addr_subslot,
        { "Subslot", "s7comm.szl.xy78.xxxx.geo.subslot", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_name,
        { "Name", "s7comm.szl.xy78.xxxx.name", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_short_name,
        { "Short name", "s7comm.szl.xy78.xxxx.short_name", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dnn_mode,
        { "DNN mode", "s7comm.szl.xy78.xxxx.dnn_mode", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis,
        { "DIS", "s7comm.szl.xy78.xxxx.dis", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_num_cdiag,
        { "Number of component diags", "s7comm.szl.xy78.xxxx.dis.num_cdiag", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiags,
        { "Component diagnostics", "s7comm.szl.xy78.xxxx.dis.cdiag", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry,
        { "Diagnostic entry", "s7comm.szl.xy78.xxxx.dis.cdiag.entry", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_ch_nr,
        { "Channel number", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.ch_nr", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_ch_prop,
        { "Channel properties", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.ch_prop", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_alcat,
        { "Alarm category", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.alcat", FT_UINT16, BASE_DEC_HEX | BASE_EXT_STRING,
          VALS_EXT_PTR(&s7comm_szl_xy78_xxxx_dis_cdiag_entry_alcat_names_ext), 0x00,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_res,
        { "Reserved", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.res", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_qualifier,
        { "Qualifier", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.qual", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_chet,
        { "TextList - CHET", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.text_chet", FT_UINT16, BASE_DEC_HEX | BASE_EXT_STRING,
          VALS_EXT_PTR(&s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_names_ext), 0x00,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet,
        { "CHET", "s7comm.szl.xy78.xxxx.dis.cdiag.chet", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet_text_list_8,
        { "Text", "s7comm.szl.xy78.xxxx.dis.cdiag.text_chet.l8.chet", FT_UINT16, BASE_DEC_HEX | BASE_EXT_STRING,
          VALS_EXT_PTR(&s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet_text_list_8_names_ext), 0x00,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_echet,
        { "TextList - ECHET", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.text_echet", FT_UINT16, BASE_DEC_HEX | BASE_EXT_STRING,
          VALS_EXT_PTR(&s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_names_ext), 0x00,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_echet,
        { "ECHET", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.echet", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val,
        { "AddVal", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.adval", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_0,
        { "W0", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.adval.w0", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_1,
        { "W1", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.adval.w1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_2,
        { "W2", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.adval.w2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_3,
        { "W3", "s7comm.szl.xy78.xxxx.dis.cdiag.entry.adval.w3", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail,
        { "Component state details", "s7comm.szl.xy78.xxxx.dis.comp_state", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_0_2,
          { "Submodule State AddInfo", "s7comm.szl.xy78.xxxx.dis.comp_state.bit0_2", FT_BOOLEAN, 32, NULL, 0x00000007,
          "Bit 0-2: Submodule State AddInfo", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_3,
          { "Qualified Diagnosis", "s7comm.szl.xy78.xxxx.dis.comp_state.bit3", FT_BOOLEAN, 32, NULL, 0x00000008,
          "Bit 3: Qualified Diagnosis", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_4,
          { "Maintenance Required", "s7comm.szl.xy78.xxxx.dis.comp_state.bit4", FT_BOOLEAN, 32, NULL, 0x00000010,
          "Bit 4: Maintenance Required", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_5,
          { "Maintenance Demanded", "s7comm.szl.xy78.xxxx.dis.comp_state.bit5", FT_BOOLEAN, 32, NULL, 0x00000020,
          "Bit 5: Maintenance Demanded", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_6,
          { "Diagnostic Information", "s7comm.szl.xy78.xxxx.dis.comp_state.bit6", FT_BOOLEAN, 32, NULL, 0x00000040,
          "Bit 6: Diagnostic Information", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_7_10,
          { "AR Information", "s7comm.szl.xy78.xxxx.dis.comp_state.bit7_10", FT_BOOLEAN, 32, NULL, 0x00000780,
          "Bit 7-10: AR Information", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_11_14,
          { "Ident Information", "s7comm.szl.xy78.xxxx.dis.comp_state.bit11_14", FT_BOOLEAN, 32, NULL, 0x00007800,
          "Bit 11-14: Ident Information", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_15,
          { "Form Indicator", "s7comm.szl.xy78.xxxx.dis.comp_state.bit15", FT_BOOLEAN, 32, NULL, 0x00008000,
          "Bit 15: Form Indicator", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_16,
          { "Deactivated", "s7comm.szl.xy78.xxxx.dis.comp_state.bit16", FT_BOOLEAN, 32, NULL, 0x00010000,
          "Bit 16: Deactivated", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_17,
          { "CiR", "s7comm.szl.xy78.xxxx.dis.comp_state.bit17", FT_BOOLEAN, 32, NULL, 0x00020000,
          "Bit 17: CiR", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_18,
          { "Input not available", "s7comm.szl.xy78.xxxx.dis.comp_state.bit18", FT_BOOLEAN, 32, NULL, 0x00040000,
          "Bit 18: Input not available", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_19,
          { "Output not available", "s7comm.szl.xy78.xxxx.dis.comp_state.bit19", FT_BOOLEAN, 32, NULL, 0x00080000,
          "Bit 19: Output not available", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_20,
          { "AS-Log overflow", "s7comm.szl.xy78.xxxx.dis.comp_state.bit20", FT_BOOLEAN, 32, NULL, 0x00100000,
          "Bit 20: AS-Log overflow", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_21,
          { "Out of service", "s7comm.szl.xy78.xxxx.dis.comp_state.bit21", FT_BOOLEAN, 32, NULL, 0x00200000,
          "Bit 21: Out of service", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_22,
          { "Partial Failure", "s7comm.szl.xy78.xxxx.dis.comp_state.bit22", FT_BOOLEAN, 32, NULL, 0x00400000,
          "Bit 22: Partial Failure", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_23,
          { "H-Unknown", "s7comm.szl.xy78.xxxx.dis.comp_state.bit23", FT_BOOLEAN, 32, NULL, 0x00800000,
          "Bit 23: H-Unknown", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_24,
          { "Passivated", "s7comm.szl.xy78.xxxx.dis.comp_state.bit24", FT_BOOLEAN, 32, NULL, 0x01000000,
          "Bit 24: Passivated", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_25,
          { "Simulated", "s7comm.szl.xy78.xxxx.dis.comp_state.bit25", FT_BOOLEAN, 32, NULL, 0x02000000,
          "Bit 25: Simulated", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_26,
          { "Local Operation", "s7comm.szl.xy78.xxxx.dis.comp_state.bit26", FT_BOOLEAN, 32, NULL, 0x04000000,
          "Bit 26: Local Operation", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail_b_27_31,
          { "Reserved", "s7comm.szl.xy78.xxxx.dis.comp_state.bit27_31", FT_BOOLEAN, 32, NULL, 0xF8000000,
          "Bit 27-31: Reserved", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state,
        { "IO state", "s7comm.szl.xy78.xxxx.dis.io_state", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_0,
        { "Good", "s7comm.szl.xy78.xxxx.dis.io_state.bit0", FT_BOOLEAN, 16, NULL, 0x0001,
          "Bit 0: Good", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_1,
        { "Deactivated", "s7comm.szl.xy78.xxxx.dis.io_state.bit1", FT_BOOLEAN, 16, NULL, 0x0002,
          "Bit 1: Deactivated", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_2,
        { "Maint. Req.", "s7comm.szl.xy78.xxxx.dis.io_state.bit2", FT_BOOLEAN, 16, NULL, 0x0004,
          "Bit 2: Maint. Req.", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_3,
        { "Maint. Dem.", "s7comm.szl.xy78.xxxx.dis.io_state.bit3", FT_BOOLEAN, 16, NULL, 0x0008,
          "Bit 3: Maint. Dem.", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_4,
        { "Error", "s7comm.szl.xy78.xxxx.dis.io_state.bit4", FT_BOOLEAN, 16, NULL, 0x0010,
          "Bit 4: Error", HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_5,
        { "Not reachable", "s7comm.szl.xy78.xxxx.dis.io_state.bit5", FT_BOOLEAN, 16, NULL, 0x0020,
          "Bit 5: Not reachable", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_6,
        { "Qualified", "s7comm.szl.xy78.xxxx.dis.io_state.bit6", FT_BOOLEAN, 16, NULL, 0x0040,
          "Bit 6: Qualified", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_7,
        { "Not available", "s7comm.szl.xy78.xxxx.dis.io_state.bit7", FT_BOOLEAN, 16, NULL, 0x0080,
          "Bit 7: Not available", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_8_14,
        { "Reserved", "s7comm.szl.xy78.xxxx.dis.io_state.bit8_14", FT_BOOLEAN, 16, NULL, 0x7F00,
          "Bit 8-14: Reserved", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_io_state_15,
        { "Hardware fault", "s7comm.szl.xy78.xxxx.dis.io_state.bit15_res", FT_BOOLEAN, 16, NULL, 0x8000,
          "Bit 15: Hardware fault", HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_dis_res,
        { "Reserved", "s7comm.szl.xy78.xxxx.dis.reserved", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_maint_state,
        { "Maintenance state", "s7comm.szl.xy78.xxxx.dis.maint", FT_UINT32, BASE_HEX, VALS(s7comm_szl_xy78_xxxx_dis_maint_state_names), 0x00,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_operating_state,
        { "Operating state", "s7comm.szl.xy78.xxxx.dis.operating_state", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_dis_own_state,
        { "Own state", "s7comm.szl.xy78.xxxx.dis.own_state", FT_UINT16, BASE_HEX, VALS(s7comm_szl_xy78_xxxx_dis_own_state_names), 0x00,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_sub_ord_io_state,
        { "Subordinated io state", "s7comm.szl.xy78.xxxx.sub_io_state", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_szl_xy78_xxxx_sub_ord_state,
        { "Subordinated state", "s7comm.szl.xy78.xxxx.sub_state", FT_UINT16, BASE_HEX, VALS(s7comm_szl_xy78_xxxx_dis_own_state_names), 0x00,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_disp_own_state,
        { "Displayed own state", "s7comm.szl.xy78.xxxx.disp_own_state", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_disp_sub_ord_state,
        { "Displayed sub. state", "s7comm.szl.xy78.xxxx.disp_sub_state", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_disp_mode,
        { "Display mode", "s7comm.szl.xy78.xxxx.disp_mode", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_vendor,
        { "Vendor-Id", "s7comm.szl.xy78.xxxx.vendor_high", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_order_id,
        { "Order-Id", "s7comm.szl.xy78.xxxx.order_id", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_im1,
        { "I&M1", "s7comm.szl.xy78.xxxx.ium1", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_iam1_function,
        { "Function", "s7comm.szl.xy78.xxxx.ium1.func", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_iam1_location,
        { "Location", "s7comm.szl.xy78.xxxx.ium1.loc", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_asset_id,
        { "Asset-Id", "s7comm.szl.xy78.xxxx.asset", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_tlv,
        { "TLV", "s7comm.szl.xy78.xxxx.tlv", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_tlv_num,
        { "Count", "s7comm.szl.xy78.xxxx.tlv.num", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_tlv_item,
        { "Item", "s7comm.szl.xy78.xxxx.tlv.item", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_tlv_item_type,
        { "Type", "s7comm.szl.xy78.xxxx.tlv.item.type", FT_UINT8, BASE_DEC, VALS(szl_xy78_xxxx_tlv_item_type_names), 0x00,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_tlv_item_len,
        { "Length", "s7comm.szl.xy78.xxxx.tlv.item.len", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_tlv_item_data,
        { "Data", "s7comm.szl.xy78.xxxx.tlv.item.data", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL } },
        { &hf_s7comm_szl_xy78_xxxx_tlv_item_dti_type,
        { "DTI-Type", "s7comm.szl.xy78.xxxx.tlv.item.dti", FT_UINT16, BASE_DEC, VALS(szl_xy78_xxxx_tlv_item_dti_type_name), 0x00,
          NULL, HFILL } },
    };

    /* Register Subtrees */
    static int* ett[] = {
        &ett_s7comm_szl_xy78_xxxx_geo_addr,
        &ett_s7comm_szl_xy78_xxxx_dis,
        &ett_s7comm_szl_xy78_xxxx_dis_cdiags,
        &ett_s7comm_szl_xy78_xxxx_dis_cdiag_entry,
        &ett_s7comm_szl_xy78_xxxx_dis_cdiag_add_val,
        &ett_s7comm_szl_xy78_xxxx_iam1,
        &ett_s7comm_szl_xy78_xxxx_tlv,
        &ett_s7comm_szl_xy78_xxxx_tlv_item,
        &ett_s7comm_szl_xy78_xxxx_dis_io_state,
        &ett_s7comm_szl_xy78_xxxx_sub_ord_io_state,
        &ett_s7comm_szl_xy78_xxxx_dis_comp_state_detail
    };

    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto, hf, array_length(hf));
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy76
 * Index:   0x0000
 * Content:
 *  If you read the partial list SSL-ID W#16#xy76, you obtain the DNN-Id of the top DNN node.
 *
 *******************************************************************************************************/
static uint32_t
s7comm_decode_szl_id_xy76_idx_0000(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
{
    proto_tree_add_item(tree, hf_s7comm_szl_xy76_0000_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy76_0000_top_dnn_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;    

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy77
 * Index:   0xxxxx
 * Content:
 *  If you read the partial list SSL-ID W#16#xy77, you obtain the relations of the given DNN node.
 *
 *******************************************************************************************************/
static uint32_t
s7comm_decode_szl_id_xy77_idx_xxxx(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
{
    uint16_t num_parent;
    uint16_t num_child;
    uint16_t num_red;
    uint16_t num_agent;
    uint16_t i;

    proto_tree_add_item(tree, hf_s7comm_szl_xy77_xxxx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    num_parent = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_s7comm_szl_xy77_xxxx_num_parent, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    for (i = 0; i < num_parent; i++) {
        proto_tree_add_item(tree, hf_s7comm_szl_xy77_xxxx_obj_parent, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    num_child = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_s7comm_szl_xy77_xxxx_num_child, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    for (i = 0; i < num_child; i++) {
        proto_tree_add_item(tree, hf_s7comm_szl_xy77_xxxx_obj_child, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    num_red = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_s7comm_szl_xy77_xxxx_num_redundancy_links, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    for (i = 0; i < num_red; i++) {
        proto_tree_add_item(tree, hf_s7comm_szl_xy77_xxxx_obj_redundancy, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    num_agent = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_s7comm_szl_xy77_xxxx_num_iodevice_agent_links, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    for (i = 0; i < num_agent; i++) {
        proto_tree_add_item(tree, hf_s7comm_szl_xy77_xxxx_obj_iodevice_agent, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:  0xxy78
 * Index:   0xxxxx
 * Content:
 *  If you read the partial list SSL-ID W#16#xy78, you obtain the diagnostic data of a DNN node.
 *
 *******************************************************************************************************/
static uint32_t
s7comm_decode_szl_id_xy78_idx_xxxx(tvbuff_t *tvb,
                                   packet_info *pinfo,
                                   proto_tree *tree,
                                   uint32_t offset)
{
    proto_item *geo_addr_item = NULL;
    proto_tree *geo_addr_item_tree = NULL;
    proto_item *dis_item = NULL;
    proto_tree *dis_item_tree = NULL;
    proto_item *cdiags_item = NULL;
    proto_tree *cdiags_item_tree = NULL;
    proto_item *cdiag_entry_item = NULL;
    proto_tree *cdiag_entry_item_tree = NULL;
    proto_item *adval_item = NULL;
    proto_tree *adval_item_tree = NULL;
    proto_item *iam1_item = NULL;
    proto_tree *iam1_item_tree = NULL;
    proto_item *tlv_item = NULL;
    proto_tree *tlv_item_tree = NULL;
    proto_item *tlv_item_item = NULL;
    proto_tree *tlv_item_item_tree = NULL;
    proto_item* chet_item_gen = NULL;
    proto_item* echet_item_gen = NULL;

    uint16_t num_cdiag;
    int32_t dis_cdiag_total_len;
    int32_t dis_total_len;
    uint16_t i;
    int32_t remaining_bytes;
    uint8_t num_tlvs;
    uint8_t tlv_item_len;
    uint8_t tlv_type;
    uint16_t version;
    uint16_t text_list;
    uint16_t chet;
    uint16_t echet;
    int32_t chet_entry_count = 0;
    const uint16_t cdiag_entry_len = 28;
    const uint16_t supported_version = 0x0005;

    version = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /*unknown version data*/
    if (version != supported_version) {
        remaining_bytes = tvb_reported_length_remaining(tvb, offset);
        proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_unknown_version_data, tvb, offset, remaining_bytes, ENC_NA);
        offset += remaining_bytes;
        return offset;
    }

    /*GEO address*/
    geo_addr_item = proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_geo_addr, tvb, offset, 8, ENC_NA);
    geo_addr_item_tree = proto_item_add_subtree(geo_addr_item, ett_s7comm_szl_xy78_xxxx_geo_addr);
    proto_tree_add_item(geo_addr_item_tree, hf_s7comm_szl_xy78_xxxx_geo_addr_subsys, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(geo_addr_item_tree, hf_s7comm_szl_xy78_xxxx_geo_addr_station, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(geo_addr_item_tree, hf_s7comm_szl_xy78_xxxx_geo_addr_rack, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(geo_addr_item_tree, hf_s7comm_szl_xy78_xxxx_geo_addr_slot, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(geo_addr_item_tree, hf_s7comm_szl_xy78_xxxx_geo_addr_subslot, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /*Name data*/
    proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_name, tvb, offset, 32, ENC_ASCII);
    offset += 32;
    proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_short_name, tvb, offset, 32, ENC_ASCII);
    offset += 32;
    proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_dnn_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /*DIS section*/
    num_cdiag = tvb_get_letohs(tvb, offset);
    dis_cdiag_total_len = cdiag_entry_len * num_cdiag;
    dis_total_len = dis_cdiag_total_len + 18;
    dis_item = proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_dis, tvb, offset, dis_total_len, ENC_NA);
    dis_item_tree = proto_item_add_subtree(dis_item, ett_s7comm_szl_xy78_xxxx_dis);    
    proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_dis_num_cdiag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /*DIS component diagnostic entry section*/
    if (num_cdiag != 0) {
        cdiags_item = proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiags, tvb, offset, dis_cdiag_total_len, ENC_NA);
        cdiags_item_tree = proto_item_add_subtree(cdiags_item, ett_s7comm_szl_xy78_xxxx_dis_cdiags);

        for (i = 0; i < num_cdiag; i++) {
            cdiag_entry_item = proto_tree_add_item(cdiags_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry, tvb, offset, cdiag_entry_len, ENC_NA);
            cdiag_entry_item_tree = proto_item_add_subtree(cdiag_entry_item, ett_s7comm_szl_xy78_xxxx_dis_cdiag_entry);
            proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_ch_nr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_ch_prop, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_alcat, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_res, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_qualifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            /*evaluate channel error type (CHET)*/
            chet = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            text_list = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_chet, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            /*add corresponding text for TextList 8*/
            if (text_list == 8 && chet != 0 && chet != 0xFFFF) {
                chet_item_gen = proto_tree_add_uint(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet_text_list_8, tvb, offset-2, 2, chet);
                PROTO_ITEM_SET_GENERATED(chet_item_gen);
                proto_item_append_text(cdiag_entry_item, " / %s",
                    val_to_str_ext(chet, &s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet_text_list_8_names_ext, "unknown 0x%04x"));
            } else {
                proto_item_append_text(cdiag_entry_item, " / CHET: 0x%04x", chet);
            }

            if (chet != 0 && chet != 0xFFFF) {
                chet_entry_count++;
            }
            offset += 2;

            /*evaluate ext. channel error type (ECHET)*/
            echet = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_echet, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            text_list = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_text_list_echet, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            if (text_list == 8 && echet != 0) {
                echet_item_gen = proto_tree_add_uint(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_chet_text_list_8, tvb, offset - 2, 2, echet);
                PROTO_ITEM_SET_GENERATED(echet_item_gen);
            }
            offset += 2;

            /*Addvalue decoding*/
            adval_item = proto_tree_add_item(cdiag_entry_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val, tvb, offset, 8, ENC_NA);
            adval_item_tree = proto_item_add_subtree(adval_item, ett_s7comm_szl_xy78_xxxx_dis_cdiag_add_val);
            proto_tree_add_item(adval_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(adval_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(adval_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(adval_item_tree, hf_s7comm_szl_xy78_xxxx_dis_cdiag_entry_add_val_3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
    }

    if (chet_entry_count != 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%u CHET entry]", chet_entry_count);
    }

    proto_tree_add_bitmask(dis_item_tree, tvb, offset, hf_s7comm_szl_xy78_xxxx_dis_comp_state_detail,
        ett_s7comm_szl_xy78_xxxx_dis_comp_state_detail, s7comm_szl_xy78_xxxx_dis_comp_state_detail_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(dis_item_tree, tvb, offset, hf_s7comm_szl_xy78_xxxx_dis_io_state,
        ett_s7comm_szl_xy78_xxxx_dis_io_state, s7comm_szl_xy78_xxxx_dis_io_state_fields, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_dis_res, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_dis_maint_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_dis_operating_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_dis_own_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /*Further state information*/
    proto_tree_add_bitmask(dis_item_tree, tvb, offset, hf_s7comm_szl_xy78_xxxx_sub_ord_io_state,
        ett_s7comm_szl_xy78_xxxx_sub_ord_io_state, s7comm_szl_xy78_xxxx_sub_ord_io_state_fields, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_sub_ord_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_disp_own_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_disp_sub_ord_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(dis_item_tree, hf_s7comm_szl_xy78_xxxx_disp_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_vendor, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_order_id, tvb, offset, 20, ENC_ASCII);
    offset += 20;

    /*I&M1 data*/
    iam1_item = proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_im1, tvb, offset, 54, ENC_NA);
    iam1_item_tree = proto_item_add_subtree(iam1_item, ett_s7comm_szl_xy78_xxxx_iam1);
    proto_tree_add_item(iam1_item_tree, hf_s7comm_szl_xy78_xxxx_iam1_function, tvb, offset, 32, ENC_ASCII);
    offset += 32;
    proto_tree_add_item(iam1_item_tree, hf_s7comm_szl_xy78_xxxx_iam1_location, tvb, offset, 22, ENC_ASCII);
    offset += 22;
    proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_asset_id, tvb, offset, 32, ENC_ASCII);
    offset += 32;

    /*check for TLVs*/
    remaining_bytes = tvb_reported_length_remaining(tvb, offset);
    if (remaining_bytes == 0) {
        return offset;
    }

    tlv_item = proto_tree_add_item(tree, hf_s7comm_szl_xy78_xxxx_tlv, tvb, offset, remaining_bytes, ENC_NA);
    tlv_item_tree = proto_item_add_subtree(tlv_item, ett_s7comm_szl_xy78_xxxx_tlv);
    num_tlvs = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tlv_item_tree, hf_s7comm_szl_xy78_xxxx_tlv_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /*iterate over TLVs*/
    for (i = 0; i < num_tlvs; i++) {
        tlv_item_item = proto_tree_add_item(tlv_item_tree, hf_s7comm_szl_xy78_xxxx_tlv_item, tvb, offset, 2, ENC_NA);
        tlv_item_item_tree = proto_item_add_subtree(tlv_item_item, ett_s7comm_szl_xy78_xxxx_tlv_item);

        tlv_type = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tlv_item_item_tree, hf_s7comm_szl_xy78_xxxx_tlv_item_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        tlv_item_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tlv_item_item_tree, hf_s7comm_szl_xy78_xxxx_tlv_item_len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        switch (tlv_type) {
            case 1:
                proto_tree_add_item(tlv_item_item_tree, hf_s7comm_szl_xy78_xxxx_tlv_item_dti_type, tvb, offset, tlv_item_len, ENC_LITTLE_ENDIAN);
                offset += tlv_item_len;
                break;
            default:
                proto_tree_add_item(tlv_item_item_tree, hf_s7comm_szl_xy78_xxxx_tlv_item_data, tvb, offset, tlv_item_len, ENC_NA);
                offset += tlv_item_len;
                break;
        }
    }

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
static uint32_t
s7comm_decode_szl_id_xy1c_idx_000x(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
{
    uint32_t idx;
    proto_tree_add_item_ret_uint(tree, hf_s7comm_szl_001c_000x_index, tvb, offset, 2, ENC_BIG_ENDIAN, &idx);
    offset += 2;
    /* For redundant H-CPUs there may be some upper bits set to identify the CPU */
    switch (idx & 0x000f) {
        case 0x0001:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0001_name, tvb, offset, 24, ENC_ASCII);
            offset += 24;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 8, ENC_NA);
            offset += 8;
            break;
        case 0x0002:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0002_name, tvb, offset, 24, ENC_ASCII);
            offset += 24;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 8, ENC_NA);
            offset += 8;
            break;
        case 0x0003:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0003_tag, tvb, offset, 32, ENC_ASCII);
            offset += 32;
            break;
        case 0x0004:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0004_copyright, tvb, offset, 26, ENC_ASCII);
            offset += 26;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 6, ENC_NA);
            offset += 6;
            break;
        case 0x0005:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0005_serialn, tvb, offset, 24, ENC_ASCII);
            offset += 24;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000x_res, tvb, offset, 8, ENC_NA);
            offset += 8;
            break;
        case 0x0007:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0007_cputypname, tvb, offset, 32, ENC_ASCII);
            offset += 32;
            break;
        case 0x0008:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_0008_snmcmmc, tvb, offset, 32, ENC_ASCII);
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
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000a_oem_copyright_string, tvb, offset, 26, ENC_ASCII);
            offset += 26;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000a_oem_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000a_oem_add_id, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case 0x000b:
            proto_tree_add_item(tree, hf_s7comm_szl_001c_000b_loc_id, tvb, offset, 32, ENC_ASCII);
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
          "Logadr (First assigned logical I/O address (base address))", HFILL }},
        { &hf_s7comm_szl_0091_0000_solltyp,
        { "Expected type", "s7comm.szl.0091.0000.exptype", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Solltyp (PROFINET IO: expected (configured) type, otherwise reserved)", HFILL }},
        { &hf_s7comm_szl_0091_0000_isttyp,
        { "Actual type", "s7comm.szl.0091.0000.acttype", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Isttyp (PROFINET IO: actual type, otherwise reserved)", HFILL }},
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
static uint32_t
s7comm_decode_szl_id_xy91_idx_0000(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint16_t id,
                                   uint32_t offset)
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
static uint32_t
add_station_byte_with_bitinfo(tvbuff_t *tvb,
                              proto_tree *tree,
                              int hf,
                              const char *info_text,
                              uint32_t start,
                              uint32_t offset)
{
    proto_item *pi = NULL;
    proto_item *pti = NULL;
    proto_tree *pt = NULL;
    uint32_t val;
    uint32_t i;
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

static uint32_t
s7comm_decode_szl_id_xy92_idx_xxxx(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint16_t id,
                                   uint32_t offset)
{
    char *txt;
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
static uint32_t
s7comm_decode_szl_id_0x94_idx_xxxx(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint16_t id,
                                   uint32_t offset)
{
    proto_item *pi = NULL;
    proto_item *pti = NULL;
    proto_tree *pt = NULL;
    uint8_t val;
    uint32_t i, j;
    uint32_t offset_tmp;
    uint32_t n;
    char *txt;

    proto_tree_add_item(tree, hf_s7comm_szl_0094_xxxx_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_szl_0094_xxxx_status_0, tvb, offset, 1, ENC_BIG_ENDIAN);
    pi = proto_tree_add_item(tree, hf_s7comm_szl_0094_xxxx_status_1_2047, tvb, offset, 256, ENC_NA);
    offset_tmp = offset;
    val = tvb_get_uint8(tvb, offset_tmp);
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
            val = tvb_get_uint8(tvb, offset_tmp);
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
        { "Solltyp1 (Expected Type: Manufacturer no. or profile identification)", "s7comm.szl.xx96.xxxx.solltyp1", FT_UINT16, BASE_HEX, NULL, 0x0,
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
static uint32_t
s7comm_decode_szl_id_xy96_idx_xxxx(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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
        { "ae", "s7comm.szl.0424.0000.ae", FT_UINT8, BASE_HEX, NULL, 0x0,
          "ae (B#16#FF)", HFILL }},
        { &hf_s7comm_szl_0424_0000_bzu_id,
        { "bzu-id", "s7comm.szl.0424.0000.bzu_id", FT_UINT8, BASE_HEX, NULL, 0x0,
          "bzu-id (ID of the mode change divided into 4 bits, Bit 0 to 3: Requested mode, Bit 4 to 7: Previous mode)", HFILL }},
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
static uint32_t
s7comm_decode_szl_id_0424_idx_0000(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   uint32_t offset)
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

        /* N.B. 2nd member of the bitfield test covers all 16 bits.. */
        { &hf_s7comm_userdata_szl_id_type,
        { "Diagnostic type", "s7comm.data.userdata.szl_id.diag_type", FT_UINT16, BASE_HEX, VALS(szl_module_type_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_userdata_szl_id_partlist_ex,
        { "Number of the partial list extract", "s7comm.data.userdata.szl_id.partlist_ex", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &szl_id_partlist_ex_names_ext, 0x0f00,
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
    static int *ett[] = {
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
    s7comm_szl_xy76_0000_register(proto);
    s7comm_szl_xy77_xxxx_register(proto);
    s7comm_szl_xy78_xxxx_register(proto);
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 4 -> SZL functions
 *
 *******************************************************************************************************/
uint32_t
s7comm_decode_ud_cpu_szl_subfunc(tvbuff_t *tvb,
                                 packet_info *pinfo,
                                 proto_tree *data_tree,
                                 uint8_t type,                /* Type of data (request/response) */
                                 uint8_t ret_val,             /* Return value in data part */
                                 uint32_t dlength,
                                 uint32_t offset)
{
    uint16_t id;
    uint16_t idx;
    uint16_t list_len;
    uint16_t list_count;
    uint16_t i;
    uint32_t start_offset;
    proto_item *szl_item = NULL;
    proto_tree *szl_item_tree = NULL;
    proto_item *szl_item_entry = NULL;
    const char* szl_index_description;
    bool szl_decoded = false;

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
            if (((uint32_t)list_count * (uint32_t)list_len) > (dlength - (offset - start_offset))) {
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
                    szl_decoded = false;
                    /* lets try to decode some known szl-id and indexes */
                    switch (id) {
                        case 0x0000:
                            offset = s7comm_decode_szl_id_xy00(tvb, szl_item_tree, id, idx, offset);
                            szl_decoded = true;
                            break;
                        case 0x0012:
                        case 0x0112:
                            proto_tree_add_item(szl_item_tree, hf_s7comm_szl_xy12_0x00_charac, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            szl_decoded = true;
                            break;
                        case 0x0013:
                        case 0x0113:
                            if (idx == 0x0000) {
                                offset = s7comm_decode_szl_id_0013_idx_0000(tvb, szl_item_tree, offset);
                                szl_decoded = true;
                            }
                            break;
                        case 0x0014:
                        case 0x0114:
                            offset = s7comm_decode_szl_id_xy14_idx_000x(tvb, szl_item_tree, offset);
                            szl_decoded = true;
                            break;
                        case 0x0015:
                        case 0x0115:
                            offset = s7comm_decode_szl_id_xy15_idx_000x(tvb, szl_item_tree, offset);
                            szl_decoded = true;
                            break;
                        case 0x0011:
                        case 0x0111:
                            /* It's (almost) the same structure for all possible indexes */
                            offset = s7comm_decode_szl_id_0111_idx_0001(tvb, szl_item_tree, offset);
                            szl_decoded = true;
                            break;
                        case 0x0222:
                            offset = s7comm_decode_szl_id_xy22_idx_00xx(tvb, szl_item_tree, offset);
                            szl_decoded = true;
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
                            offset = s7comm_decode_ud_cpu_diagnostic_message(tvb, pinfo, false, szl_item_tree, offset);
                            szl_decoded = true;
                            break;
                        case 0x001c:
                        case 0x011c:
                        case 0x021c:
                        case 0x031c:
                            offset = s7comm_decode_szl_id_xy1c_idx_000x(tvb, szl_item_tree, offset);
                            szl_decoded = true;
                            break;
                        case 0x0131:
                            switch (idx) {
                                case 0x0001:
                                    offset = s7comm_decode_szl_id_0131_idx_0001(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0002:
                                    offset = s7comm_decode_szl_id_0131_idx_0002(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0003:
                                    offset = s7comm_decode_szl_id_0131_idx_0003(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0004:
                                    offset = s7comm_decode_szl_id_0131_idx_0004(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0005:
                                    offset = s7comm_decode_szl_id_0131_idx_0005(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0006:
                                    offset = s7comm_decode_szl_id_0131_idx_0006(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0007:
                                    offset = s7comm_decode_szl_id_0131_idx_0007(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0008:
                                    offset = s7comm_decode_szl_id_0131_idx_0008(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0009:
                                    offset = s7comm_decode_szl_id_0131_idx_0009(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0010:
                                    offset = s7comm_decode_szl_id_0131_idx_0010(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                            }
                            break;
                        case 0x0132:
                            switch (idx) {
                                case 0x0001:
                                    offset = s7comm_decode_szl_id_0132_idx_0001(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0002:
                                    offset = s7comm_decode_szl_id_0132_idx_0002(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0004:
                                    offset = s7comm_decode_szl_id_0132_idx_0004(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0005:
                                    offset = s7comm_decode_szl_id_0132_idx_0005(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0006:
                                    offset = s7comm_decode_szl_id_0132_idx_0006(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x0008:
                                    offset = s7comm_decode_szl_id_0132_idx_0008(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x000b:
                                    offset = s7comm_decode_szl_id_0132_idx_000b(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                                case 0x000c:
                                    offset = s7comm_decode_szl_id_0132_idx_000c(tvb, szl_item_tree, offset);
                                    szl_decoded = true;
                                    break;
                            }
                            break;
                        case 0x0019:
                        case 0x0119:
                        case 0x0074:
                        case 0x0174:
                                offset = s7comm_decode_szl_id_xy74_idx_0000(tvb, szl_item_tree, offset);
                                szl_decoded = true;
                            break;
                        case 0x0076:
                            offset = s7comm_decode_szl_id_xy76_idx_0000(tvb, szl_item_tree, offset);
                            szl_decoded = true;
                            break;
                        case 0x0077:
                            offset = s7comm_decode_szl_id_xy77_idx_xxxx(tvb, szl_item_tree, offset);
                            szl_decoded = true;
                            break;
                        case 0x0078:
                            offset = s7comm_decode_szl_id_xy78_idx_xxxx(tvb, pinfo, szl_item_tree, offset);
                            szl_decoded = true;
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
                            szl_decoded = true;
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
                            szl_decoded = true;
                            break;
                        case 0x0094:
                        case 0x0194:
                        case 0x0294:
                        case 0x0694:
                        case 0x0794:
                            offset = s7comm_decode_szl_id_0x94_idx_xxxx(tvb, szl_item_tree, id, offset);
                            szl_decoded = true;
                            break;
                        case 0x0696:
                        case 0x0c96:
                            offset = s7comm_decode_szl_id_xy96_idx_xxxx(tvb, szl_item_tree, offset);
                            szl_decoded = true;
                            break;
                        case 0x0124:
                        case 0x0424:
                            if (idx == 0x0000) {
                                offset = s7comm_decode_szl_id_0424_idx_0000(tvb, szl_item_tree, offset);
                                szl_decoded = true;
                            }
                            break;
                        default:
                            szl_decoded = false;
                            break;
                    }
                    if (szl_decoded == false) {
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
