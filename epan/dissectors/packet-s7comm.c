/* packet-s7comm.c
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
#include <epan/reassemble.h>
#include <stdlib.h>
#include <wsutil/strtoi.h>
#include <epan/expert.h>

#include "packet-s7comm.h"
#include "packet-s7comm_szl_ids.h"

#define PROTO_TAG_S7COMM                    "S7COMM"

/* Min. telegram length for heuristic check */
#define S7COMM_MIN_TELEGRAM_LENGTH          10

/* Protocol identifier */
#define S7COMM_PROT_ID                      0x32

/* Wireshark ID of the S7COMM protocol */
static int proto_s7comm = -1;

/* Forward declarations */
void proto_reg_handoff_s7comm(void);
void proto_register_s7comm (void);
static guint32 s7comm_decode_ud_tis_data(tvbuff_t *tvb, proto_tree *tree, guint8 type, guint8 subfunc, guint16 td_size, guint32 offset);

/**************************************************************************
 * PDU types
 */
#define S7COMM_ROSCTR_JOB                   0x01
#define S7COMM_ROSCTR_ACK                   0x02
#define S7COMM_ROSCTR_ACK_DATA              0x03
#define S7COMM_ROSCTR_USERDATA              0x07

static const value_string rosctr_names[] = {
    { S7COMM_ROSCTR_JOB,                    "Job" },        /* Request: job with acknowledgement */
    { S7COMM_ROSCTR_ACK,                    "Ack" },        /* acknowledgement without additional field */
    { S7COMM_ROSCTR_ACK_DATA,               "Ack_Data" },   /* Response: acknowledgement with additional field */
    { S7COMM_ROSCTR_USERDATA,               "Userdata" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Error classes in header
 */
#define S7COMM_ERRCLS_NONE                  0x00
#define S7COMM_ERRCLS_APPREL                0x81
#define S7COMM_ERRCLS_OBJDEF                0x82
#define S7COMM_ERRCLS_RESOURCE              0x83
#define S7COMM_ERRCLS_SERVICE               0x84
#define S7COMM_ERRCLS_SUPPLIES              0x85
#define S7COMM_ERRCLS_ACCESS                0x87

static const value_string errcls_names[] = {
    { S7COMM_ERRCLS_NONE,                   "No error" },
    { S7COMM_ERRCLS_APPREL,                 "Application relationship" },
    { S7COMM_ERRCLS_OBJDEF,                 "Object definition" },
    { S7COMM_ERRCLS_RESOURCE,               "No resources available" },
    { S7COMM_ERRCLS_SERVICE,                "Error on service processing" },
    { S7COMM_ERRCLS_SUPPLIES,               "Error on supplies" },
    { S7COMM_ERRCLS_ACCESS,                 "Access error" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Error code in parameter part
 */

static const value_string param_errcode_names[] = {
    { 0x0000,                               "No error" },
    { 0x0110,                               "Invalid block number" },
    { 0x0111,                               "Invalid request length" },
    { 0x0112,                               "Invalid parameter" },
    { 0x0113,                               "Invalid block type" },
    { 0x0114,                               "Block not found" },
    { 0x0115,                               "Block already exists" },
    { 0x0116,                               "Block is write-protected" },
    { 0x0117,                               "The block/operating system update is too large" },
    { 0x0118,                               "Invalid block number" },
    { 0x0119,                               "Incorrect password entered" },
    { 0x011A,                               "PG resource error" },
    { 0x011B,                               "PLC resource error" },
    { 0x011C,                               "Protocol error" },
    { 0x011D,                               "Too many blocks (module-related restriction)" },
    { 0x011E,                               "There is no longer a connection to the database, or S7DOS handle is invalid" },
    { 0x011F,                               "Result buffer too small" },
    { 0x0120,                               "End of block list" },
    { 0x0140,                               "Insufficient memory available" },
    { 0x0141,                               "Job cannot be processed because of a lack of resources" },
    { 0x8001,                               "The requested service cannot be performed while the block is in the current status" },
    { 0x8003,                               "S7 protocol error: Error occurred while transferring the block" },
    { 0x8100,                               "Application, general error: Service unknown to remote module" },
    { 0x8104,                               "This service is not implemented on the module or a frame error was reported" },
    { 0x8204,                               "The type specification for the object is inconsistent" },
    { 0x8205,                               "A copied block already exists and is not linked" },
    { 0x8301,                               "Insufficient memory space or work memory on the module, or specified storage medium not accessible" },
    { 0x8302,                               "Too few resources available or the processor resources are not available" },
    { 0x8304,                               "No further parallel upload possible. There is a resource bottleneck" },
    { 0x8305,                               "Function not available" },
    { 0x8306,                               "Insufficient work memory (for copying, linking, loading AWP)" },
    { 0x8307,                               "Not enough retentive work memory (for copying, linking, loading AWP)" },
    { 0x8401,                               "S7 protocol error: Invalid service sequence (for example, loading or uploading a block)" },
    { 0x8402,                               "Service cannot execute owing to status of the addressed object" },
    { 0x8404,                               "S7 protocol: The function cannot be performed" },
    { 0x8405,                               "Remote block is in DISABLE state (CFB). The function cannot be performed" },
    { 0x8500,                               "S7 protocol error: Wrong frames" },
    { 0x8503,                               "Alarm from the module: Service canceled prematurely" },
    { 0x8701,                               "Error addressing the object on the communications partner (for example, area length error)" },
    { 0x8702,                               "The requested service is not supported by the module" },
    { 0x8703,                               "Access to object refused" },
    { 0x8704,                               "Access error: Object damaged" },
    { 0xD001,                               "Protocol error: Illegal job number" },
    { 0xD002,                               "Parameter error: Illegal job variant" },
    { 0xD003,                               "Parameter error: Debugging function not supported by module" },
    { 0xD004,                               "Parameter error: Illegal job status" },
    { 0xD005,                               "Parameter error: Illegal job termination" },
    { 0xD006,                               "Parameter error: Illegal link disconnection ID" },
    { 0xD007,                               "Parameter error: Illegal number of buffer elements" },
    { 0xD008,                               "Parameter error: Illegal scan rate" },
    { 0xD009,                               "Parameter error: Illegal number of executions" },
    { 0xD00A,                               "Parameter error: Illegal trigger event" },
    { 0xD00B,                               "Parameter error: Illegal trigger condition" },
    { 0xD011,                               "Parameter error in path of the call environment: Block does not exist" },
    { 0xD012,                               "Parameter error: Wrong address in block" },
    { 0xD014,                               "Parameter error: Block being deleted/overwritten" },
    { 0xD015,                               "Parameter error: Illegal tag address" },
    { 0xD016,                               "Parameter error: Test jobs not possible, because of errors in user program" },
    { 0xD017,                               "Parameter error: Illegal trigger number" },
    { 0xD025,                               "Parameter error: Invalid path" },
    { 0xD026,                               "Parameter error: Illegal access type" },
    { 0xD027,                               "Parameter error: This number of data blocks is not permitted" },
    { 0xD031,                               "Internal protocol error" },
    { 0xD032,                               "Parameter error: Wrong result buffer length" },
    { 0xD033,                               "Protocol error: Wrong job length" },
    { 0xD03F,                               "Coding error: Error in parameter section (for example, reserve bytes not equal to 0)" },
    { 0xD041,                               "Data error: Illegal status list ID" },
    { 0xD042,                               "Data error: Illegal tag address" },
    { 0xD043,                               "Data error: Referenced job not found, check job data" },
    { 0xD044,                               "Data error: Illegal tag value, check job data" },
    { 0xD045,                               "Data error: Exiting the ODIS control is not allowed in HOLD" },
    { 0xD046,                               "Data error: Illegal measuring stage during run-time measurement" },
    { 0xD047,                               "Data error: Illegal hierarchy in 'Read job list'" },
    { 0xD048,                               "Data error: Illegal deletion ID in 'Delete job'" },
    { 0xD049,                               "Invalid substitute ID in 'Replace job'" },
    { 0xD04A,                               "Error executing 'program status'" },
    { 0xD05F,                               "Coding error: Error in data section (for example, reserve bytes not equal to 0, ...)" },
    { 0xD061,                               "Resource error: No memory space for job" },
    { 0xD062,                               "Resource error: Job list full" },
    { 0xD063,                               "Resource error: Trigger event occupied" },
    { 0xD064,                               "Resource error: Not enough memory space for one result buffer element" },
    { 0xD065,                               "Resource error: Not enough memory space for several  result buffer elements" },
    { 0xD066,                               "Resource error: The timer available for run-time measurement is occupied by another job" },
    { 0xD067,                               "Resource error: Too many 'modify tag' jobs active (in particular multi-processor operation)" },
    { 0xD081,                               "Function not permitted in current mode" },
    { 0xD082,                               "Mode error: Cannot exit HOLD mode" },
    { 0xD0A1,                               "Function not permitted in current protection level" },
    { 0xD0A2,                               "Function not possible at present, because a function is running that modifies memory" },
    { 0xD0A3,                               "Too many 'modify tag' jobs active on the I/O (in particular multi-processor operation)" },
    { 0xD0A4,                               "'Forcing' has already been established" },
    { 0xD0A5,                               "Referenced job not found" },
    { 0xD0A6,                               "Job cannot be disabled/enabled" },
    { 0xD0A7,                               "Job cannot be deleted, for example because it is currently being read" },
    { 0xD0A8,                               "Job cannot be replaced, for example because it is currently being read or deleted" },
    { 0xD0A9,                               "Job cannot be read, for example because it is currently being deleted" },
    { 0xD0AA,                               "Time limit exceeded in processing operation" },
    { 0xD0AB,                               "Invalid job parameters in process operation" },
    { 0xD0AC,                               "Invalid job data in process operation" },
    { 0xD0AD,                               "Operating mode already set" },
    { 0xD0AE,                               "The job was set up over a different connection and can only be handled over this connection" },
    { 0xD0C1,                               "At least one error has been detected while accessing the tag(s)" },
    { 0xD0C2,                               "Change to STOP/HOLD mode" },
    { 0xD0C3,                               "At least one error was detected while accessing the tag(s). Mode change to STOP/HOLD" },
    { 0xD0C4,                               "Timeout during run-time measurement" },
    { 0xD0C5,                               "Display of block stack inconsistent, because blocks were deleted/reloaded" },
    { 0xD0C6,                               "Job was automatically deleted as the jobs it referenced have been deleted" },
    { 0xD0C7,                               "The job was automatically deleted because STOP mode was exited" },
    { 0xD0C8,                               "'Block status' aborted because of inconsistencies between test job and running program" },
    { 0xD0C9,                               "Exit the status area by resetting OB90" },
    { 0xD0CA,                               "Exiting the status range by resetting OB90 and access error reading tags before exiting" },
    { 0xD0CB,                               "The output disable for the peripheral outputs has been activated again" },
    { 0xD0CC,                               "The amount of data for the debugging functions is restricted by the time limit" },
    { 0xD201,                               "Syntax error in block name" },
    { 0xD202,                               "Syntax error in function parameters" },
    { 0xD205,                               "Linked block already exists in RAM: Conditional copying is not possible" },
    { 0xD206,                               "Linked block already exists in EPROM: Conditional copying is not possible" },
    { 0xD208,                               "Maximum number of copied (not linked) blocks on module exceeded" },
    { 0xD209,                               "(At least) one of the given blocks not found on the module" },
    { 0xD20A,                               "The maximum number of blocks that can be linked with one job was exceeded" },
    { 0xD20B,                               "The maximum number of blocks that can be deleted with one job was exceeded" },
    { 0xD20C,                               "OB cannot be copied because the associated priority class does not exist" },
    { 0xD20D,                               "SDB cannot be interpreted (for example, unknown number)" },
    { 0xD20E,                               "No (further) block available" },
    { 0xD20F,                               "Module-specific maximum block size exceeded" },
    { 0xD210,                               "Invalid block number" },
    { 0xD212,                               "Incorrect header attribute (run-time relevant)" },
    { 0xD213,                               "Too many SDBs. Note the restrictions on the module being used" },
    { 0xD216,                               "Invalid user program - reset module" },
    { 0xD217,                               "Protection level specified in module properties not permitted" },
    { 0xD218,                               "Incorrect attribute (active/passive)" },
    { 0xD219,                               "Incorrect block lengths (for example, incorrect length of first section or of the whole block)" },
    { 0xD21A,                               "Incorrect local data length or write-protection code faulty" },
    { 0xD21B,                               "Module cannot compress or compression was interrupted early" },
    { 0xD21D,                               "The volume of dynamic project data transferred is illegal" },
    { 0xD21E,                               "Unable to assign parameters to a module (such as FM, CP). The system data could not be linked" },
    { 0xD220,                               "Invalid programming language. Note the restrictions on the module being used" },
    { 0xD221,                               "The system data for connections or routing are not valid" },
    { 0xD222,                               "The system data of the global data definition contain invalid parameters" },
    { 0xD223,                               "Error in instance data block for communication function block or maximum number of instance DBs exceeded" },
    { 0xD224,                               "The SCAN system data block contains invalid parameters" },
    { 0xD225,                               "The DP system data block contains invalid parameters" },
    { 0xD226,                               "A structural error occurred in a block" },
    { 0xD230,                               "A structural error occurred in a block" },
    { 0xD231,                               "At least one loaded OB cannot be copied because the associated priority class does not exist" },
    { 0xD232,                               "At least one block number of a loaded block is illegal" },
    { 0xD234,                               "Block exists twice in the specified memory medium or in the job" },
    { 0xD235,                               "The block contains an incorrect checksum" },
    { 0xD236,                               "The block does not contain a checksum" },
    { 0xD237,                               "You are about to load the block twice, i.e. a block with the same time stamp already exists on the CPU" },
    { 0xD238,                               "At least one of the blocks specified is not a DB" },
    { 0xD239,                               "At least one of the DBs specified is not available as a linked variant in the load memory" },
    { 0xD23A,                               "At least one of the specified DBs is considerably different from the copied and linked variant" },
    { 0xD240,                               "Coordination rules violated" },
    { 0xD241,                               "The function is not permitted in the current protection level" },
    { 0xD242,                               "Protection violation while processing F blocks" },
    { 0xD250,                               "Update and module ID or version do not match" },
    { 0xD251,                               "Incorrect sequence of operating system components" },
    { 0xD252,                               "Checksum error" },
    { 0xD253,                               "No executable loader available; update only possible using a memory card" },
    { 0xD254,                               "Storage error in operating system" },
    { 0xD280,                               "Error compiling block in S7-300 CPU" },
    { 0xD2A1,                               "Another block function or a trigger on a block is active" },
    { 0xD2A2,                               "A trigger is active on a block. Complete the debugging function first" },
    { 0xD2A3,                               "The block is not active (linked), the block is occupied or the block is currently marked for deletion" },
    { 0xD2A4,                               "The block is already being processed by another block function" },
    { 0xD2A6,                               "It is not possible to save and change the user program simultaneously" },
    { 0xD2A7,                               "The block has the attribute 'unlinked' or is not processed" },
    { 0xD2A8,                               "An active debugging function is preventing parameters from being assigned to the CPU" },
    { 0xD2A9,                               "New parameters are being assigned to the CPU" },
    { 0xD2AA,                               "New parameters are currently being assigned to the modules" },
    { 0xD2AB,                               "The dynamic configuration limits are currently being changed" },
    { 0xD2AC,                               "A running active or deactivate assignment (SFC 12) is temporarily preventing R-KiR process" },
    { 0xD2B0,                               "An error occurred while configuring in RUN (CiR)" },
    { 0xD2C0,                               "The maximum number of technological objects has been exceeded" },
    { 0xD2C1,                               "The same technology data block already exists on the module" },
    { 0xD2C2,                               "Downloading the user program or downloading the hardware configuration is not possible" },
    { 0xD401,                               "Information function unavailable" },
    { 0xD402,                               "Information function unavailable" },
    { 0xD403,                               "Service has already been logged on/off (Diagnostics/PMC)" },
    { 0xD404,                               "Maximum number of nodes reached. No more logons possible for diagnostics/PMC" },
    { 0xD405,                               "Service not supported or syntax error in function parameters" },
    { 0xD406,                               "Required information currently unavailable" },
    { 0xD407,                               "Diagnostics error occurred" },
    { 0xD408,                               "Update aborted" },
    { 0xD409,                               "Error on DP bus" },
    { 0xD601,                               "Syntax error in function parameter" },
    { 0xD602,                               "Incorrect password entered" },
    { 0xD603,                               "The connection has already been legitimized" },
    { 0xD604,                               "The connection has already been enabled" },
    { 0xD605,                               "Legitimization not possible because password does not exist" },
    { 0xD801,                               "At least one tag address is invalid" },
    { 0xD802,                               "Specified job does not exist" },
    { 0xD803,                               "Illegal job status" },
    { 0xD804,                               "Illegal cycle time (illegal time base or multiple)" },
    { 0xD805,                               "No more cyclic read jobs can be set up" },
    { 0xD806,                               "The referenced job is in a state in which the requested function cannot be performed" },
    { 0xD807,                               "Function aborted due to overload, meaning executing the read cycle takes longer than the set scan cycle time" },
    { 0xDC01,                               "Date and/or time invalid" },
    { 0xE201,                               "CPU is already the master" },
    { 0xE202,                               "Connect and update not possible due to different user program in flash module" },
    { 0xE203,                               "Connect and update not possible due to different firmware" },
    { 0xE204,                               "Connect and update not possible due to different memory configuration" },
    { 0xE205,                               "Connect/update aborted due to synchronization error" },
    { 0xE206,                               "Connect/update denied due to coordination violation" },
    { 0xEF01,                               "S7 protocol error: Error at ID2; only 00H permitted in job" },
    { 0xEF02,                               "S7 protocol error: Error at ID2; set of resources does not exist" },
    { 0,                                    NULL }
};
static value_string_ext param_errcode_names_ext = VALUE_STRING_EXT_INIT(param_errcode_names);

/**************************************************************************
 * Function codes in parameter part
 */
#define S7COMM_SERV_CPU                     0x00
#define S7COMM_SERV_SETUPCOMM               0xF0
#define S7COMM_SERV_READVAR                 0x04
#define S7COMM_SERV_WRITEVAR                0x05

#define S7COMM_FUNCREQUESTDOWNLOAD          0x1A
#define S7COMM_FUNCDOWNLOADBLOCK            0x1B
#define S7COMM_FUNCDOWNLOADENDED            0x1C
#define S7COMM_FUNCSTARTUPLOAD              0x1D
#define S7COMM_FUNCUPLOAD                   0x1E
#define S7COMM_FUNCENDUPLOAD                0x1F
#define S7COMM_FUNCPISERVICE                0x28
#define S7COMM_FUNC_PLC_STOP                0x29

static const value_string param_functionnames[] = {
    { S7COMM_SERV_CPU,                      "CPU services" },
    { S7COMM_SERV_SETUPCOMM,                "Setup communication" },
    { S7COMM_SERV_READVAR,                  "Read Var" },
    { S7COMM_SERV_WRITEVAR,                 "Write Var" },
    /* Block management services */
    { S7COMM_FUNCREQUESTDOWNLOAD,           "Request download" },
    { S7COMM_FUNCDOWNLOADBLOCK,             "Download block" },
    { S7COMM_FUNCDOWNLOADENDED,             "Download ended" },
    { S7COMM_FUNCSTARTUPLOAD,               "Start upload" },
    { S7COMM_FUNCUPLOAD,                    "Upload" },
    { S7COMM_FUNCENDUPLOAD,                 "End upload" },
    { S7COMM_FUNCPISERVICE,                 "PI-Service" },
    { S7COMM_FUNC_PLC_STOP,                 "PLC Stop" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Area names
 */
#define S7COMM_AREA_DATARECORD              0x01        /* Data record, used with RDREC or firmware updates on CP */
#define S7COMM_AREA_SYSINFO                 0x03        /* System info of 200 family */
#define S7COMM_AREA_SYSFLAGS                0x05        /* System flags of 200 family */
#define S7COMM_AREA_ANAIN                   0x06        /* analog inputs of 200 family */
#define S7COMM_AREA_ANAOUT                  0x07        /* analog outputs of 200 family */
#define S7COMM_AREA_P                       0x80        /* direct peripheral access */
#define S7COMM_AREA_INPUTS                  0x81
#define S7COMM_AREA_OUTPUTS                 0x82
#define S7COMM_AREA_FLAGS                   0x83
#define S7COMM_AREA_DB                      0x84        /* data blocks */
#define S7COMM_AREA_DI                      0x85        /* instance data blocks */
#define S7COMM_AREA_LOCAL                   0x86        /* local data (should not be accessible over network) */
#define S7COMM_AREA_V                       0x87        /* previous (Vorgaenger) local data (should not be accessible over network)  */
#define S7COMM_AREA_COUNTER                 28          /* S7 counters */
#define S7COMM_AREA_TIMER                   29          /* S7 timers */
#define S7COMM_AREA_COUNTER200              30          /* IEC counters (200 family) */
#define S7COMM_AREA_TIMER200                31          /* IEC timers (200 family) */

static const value_string item_areanames[] = {
    { S7COMM_AREA_DATARECORD,               "Data record" },
    { S7COMM_AREA_SYSINFO,                  "System info of 200 family" },
    { S7COMM_AREA_SYSFLAGS,                 "System flags of 200 family" },
    { S7COMM_AREA_ANAIN,                    "Analog inputs of 200 family" },
    { S7COMM_AREA_ANAOUT,                   "Analog outputs of 200 family" },
    { S7COMM_AREA_P,                        "Direct peripheral access (P)" },
    { S7COMM_AREA_INPUTS,                   "Inputs (I)" },
    { S7COMM_AREA_OUTPUTS,                  "Outputs (Q)" },
    { S7COMM_AREA_FLAGS,                    "Flags (M)" },
    { S7COMM_AREA_DB,                       "Data blocks (DB)" },
    { S7COMM_AREA_DI,                       "Instance data blocks (DI)" },
    { S7COMM_AREA_LOCAL,                    "Local data (L)" },
    { S7COMM_AREA_V,                        "Unknown yet (V)" },
    { S7COMM_AREA_COUNTER,                  "S7 counters (C)" },
    { S7COMM_AREA_TIMER,                    "S7 timers (T)" },
    { S7COMM_AREA_COUNTER200,               "IEC counters (200 family)" },
    { S7COMM_AREA_TIMER200,                 "IEC timers (200 family)" },
    { 0,                                    NULL }
};

static const value_string item_areanames_short[] = {
    { S7COMM_AREA_DATARECORD,               "RECORD" },
    { S7COMM_AREA_SYSINFO,                  "SI200" },
    { S7COMM_AREA_SYSFLAGS,                 "SF200" },
    { S7COMM_AREA_ANAIN,                    "AI200" },
    { S7COMM_AREA_ANAOUT,                   "AO" },
    { S7COMM_AREA_P,                        "P" },
    { S7COMM_AREA_INPUTS,                   "I" },
    { S7COMM_AREA_OUTPUTS,                  "Q" },
    { S7COMM_AREA_FLAGS,                    "M" },
    { S7COMM_AREA_DB,                       "DB" },
    { S7COMM_AREA_DI,                       "DI" },
    { S7COMM_AREA_LOCAL,                    "L" },
    { S7COMM_AREA_V,                        "V" },
    { S7COMM_AREA_COUNTER,                  "C" },
    { S7COMM_AREA_TIMER,                    "T" },
    { S7COMM_AREA_COUNTER200,               "C200" },
    { S7COMM_AREA_TIMER200,                 "T200" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Transport sizes in item data
 */
    /* types of 1 byte length */
#define S7COMM_TRANSPORT_SIZE_BIT           1
#define S7COMM_TRANSPORT_SIZE_BYTE          2
#define S7COMM_TRANSPORT_SIZE_CHAR          3
    /* types of 2 bytes length */
#define S7COMM_TRANSPORT_SIZE_WORD          4
#define S7COMM_TRANSPORT_SIZE_INT           5
    /* types of 4 bytes length */
#define S7COMM_TRANSPORT_SIZE_DWORD         6
#define S7COMM_TRANSPORT_SIZE_DINT          7
#define S7COMM_TRANSPORT_SIZE_REAL          8
    /* Special types */
#define S7COMM_TRANSPORT_SIZE_DATE          9
#define S7COMM_TRANSPORT_SIZE_TOD           10
#define S7COMM_TRANSPORT_SIZE_TIME          11
#define S7COMM_TRANSPORT_SIZE_S5TIME        12
#define S7COMM_TRANSPORT_SIZE_DT            15
    /* Timer or counter */
#define S7COMM_TRANSPORT_SIZE_COUNTER       28
#define S7COMM_TRANSPORT_SIZE_TIMER         29
#define S7COMM_TRANSPORT_SIZE_IEC_COUNTER   30
#define S7COMM_TRANSPORT_SIZE_IEC_TIMER     31
#define S7COMM_TRANSPORT_SIZE_HS_COUNTER    32
static const value_string item_transportsizenames[] = {
    { S7COMM_TRANSPORT_SIZE_BIT,            "BIT" },
    { S7COMM_TRANSPORT_SIZE_BYTE,           "BYTE" },
    { S7COMM_TRANSPORT_SIZE_CHAR,           "CHAR" },
    { S7COMM_TRANSPORT_SIZE_WORD,           "WORD" },
    { S7COMM_TRANSPORT_SIZE_INT,            "INT" },
    { S7COMM_TRANSPORT_SIZE_DWORD,          "DWORD" },
    { S7COMM_TRANSPORT_SIZE_DINT,           "DINT" },
    { S7COMM_TRANSPORT_SIZE_REAL,           "REAL" },
    { S7COMM_TRANSPORT_SIZE_TOD,            "TOD" },
    { S7COMM_TRANSPORT_SIZE_TIME,           "TIME" },
    { S7COMM_TRANSPORT_SIZE_S5TIME,         "S5TIME" },
    { S7COMM_TRANSPORT_SIZE_DT,             "DATE_AND_TIME" },
    { S7COMM_TRANSPORT_SIZE_COUNTER,        "COUNTER" },
    { S7COMM_TRANSPORT_SIZE_TIMER,          "TIMER" },
    { S7COMM_TRANSPORT_SIZE_IEC_COUNTER,    "IEC TIMER" },
    { S7COMM_TRANSPORT_SIZE_IEC_TIMER,      "IEC COUNTER" },
    { S7COMM_TRANSPORT_SIZE_HS_COUNTER,     "HS COUNTER" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Syntax Ids of variable specification
 */
#define S7COMM_SYNTAXID_S7ANY               0x10        /* Address data S7-Any pointer-like DB1.DBX10.2 */
#define S7COMM_SYNTAXID_PBC_ID              0x13        /* R_ID for PBC */
#define S7COMM_SYNTAXID_ALARM_LOCKFREESET   0x15        /* Alarm lock/free dataset */
#define S7COMM_SYNTAXID_ALARM_INDSET        0x16        /* Alarm indication dataset */
#define S7COMM_SYNTAXID_ALARM_ACKSET        0x19        /* Alarm acknowledge message dataset */
#define S7COMM_SYNTAXID_ALARM_QUERYREQSET   0x1a        /* Alarm query request dataset */
#define S7COMM_SYNTAXID_NOTIFY_INDSET       0x1c        /* Notify indication dataset */
#define S7COMM_SYNTAXID_NCK                 0x82        /* Sinumerik NCK HMI access (current units) */
#define S7COMM_SYNTAXID_NCK_METRIC          0x83        /* Sinumerik NCK HMI access metric units */
#define S7COMM_SYNTAXID_NCK_INCH            0x84        /* Sinumerik NCK HMI access inch */
#define S7COMM_SYNTAXID_DRIVEESANY          0xa2        /* seen on Drive ES Starter with routing over S7 */
#define S7COMM_SYNTAXID_1200SYM             0xb2        /* Symbolic address mode of S7-1200 */
#define S7COMM_SYNTAXID_DBREAD              0xb0        /* Kind of DB block read, seen only at an S7-400 */

static const value_string item_syntaxid_names[] = {
    { S7COMM_SYNTAXID_S7ANY,                "S7ANY" },
    { S7COMM_SYNTAXID_PBC_ID,               "PBC-R_ID" },
    { S7COMM_SYNTAXID_ALARM_LOCKFREESET,    "ALARM_LOCKFREE" },
    { S7COMM_SYNTAXID_ALARM_INDSET,         "ALARM_IND" },
    { S7COMM_SYNTAXID_ALARM_ACKSET,         "ALARM_ACK" },
    { S7COMM_SYNTAXID_ALARM_QUERYREQSET,    "ALARM_QUERYREQ" },
    { S7COMM_SYNTAXID_NOTIFY_INDSET,        "NOTIFY_IND" },
    { S7COMM_SYNTAXID_NCK,                  "NCK" },
    { S7COMM_SYNTAXID_NCK_METRIC,           "NCK_M" },
    { S7COMM_SYNTAXID_NCK_INCH,             "NCK_I" },
    { S7COMM_SYNTAXID_DRIVEESANY,           "DRIVEESANY" },
    { S7COMM_SYNTAXID_1200SYM,              "1200SYM" },
    { S7COMM_SYNTAXID_DBREAD,               "DBREAD" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Transport sizes in data
 */
#define S7COMM_DATA_TRANSPORT_SIZE_NULL     0
#define S7COMM_DATA_TRANSPORT_SIZE_BBIT     3           /* bit access, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BBYTE    4           /* byte/word/dword access, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BINT     5           /* integer access, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BDINT    6           /* integer access, len is in bytes */
#define S7COMM_DATA_TRANSPORT_SIZE_BREAL    7           /* real access, len is in bytes */
#define S7COMM_DATA_TRANSPORT_SIZE_BSTR     9           /* octet string, len is in bytes */
#define S7COMM_DATA_TRANSPORT_SIZE_NCKADDR1 17          /* NCK address description, fixed length */
#define S7COMM_DATA_TRANSPORT_SIZE_NCKADDR2 18          /* NCK address description, fixed length */

static const value_string data_transportsizenames[] = {
    { S7COMM_DATA_TRANSPORT_SIZE_NULL,      "NULL" },
    { S7COMM_DATA_TRANSPORT_SIZE_BBIT,      "BIT" },
    { S7COMM_DATA_TRANSPORT_SIZE_BBYTE,     "BYTE/WORD/DWORD" },
    { S7COMM_DATA_TRANSPORT_SIZE_BINT,      "INTEGER" },
    { S7COMM_DATA_TRANSPORT_SIZE_BDINT,     "DINTEGER" },
    { S7COMM_DATA_TRANSPORT_SIZE_BREAL,     "REAL" },
    { S7COMM_DATA_TRANSPORT_SIZE_BSTR,      "OCTET STRING" },
    { S7COMM_DATA_TRANSPORT_SIZE_NCKADDR1,  "NCK ADDRESS1" },
    { S7COMM_DATA_TRANSPORT_SIZE_NCKADDR2,  "NCK ADDRESS2" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Returnvalues of an item response
 */

const value_string s7comm_item_return_valuenames[] = {
    { S7COMM_ITEM_RETVAL_RESERVED,              "Reserved" },
    { S7COMM_ITEM_RETVAL_DATA_HW_FAULT,         "Hardware error" },
    { S7COMM_ITEM_RETVAL_DATA_ACCESS_FAULT,     "Accessing the object not allowed" },
    { S7COMM_ITEM_RETVAL_DATA_OUTOFRANGE,       "Invalid address" },
    { S7COMM_ITEM_RETVAL_DATA_NOT_SUP,          "Data type not supported" },
    { S7COMM_ITEM_RETVAL_DATA_SIZEMISMATCH,     "Data type inconsistent" },
    { S7COMM_ITEM_RETVAL_DATA_ERR,              "Object does not exist" },
    { S7COMM_ITEM_RETVAL_DATA_OK,               "Success" },
    { 0,                                        NULL }
};
/**************************************************************************
 * Block Types, used when blocktype is transfered as string
 */
#define S7COMM_BLOCKTYPE_OB                 0x3038      /* '08' */
#define S7COMM_BLOCKTYPE_CMOD               0x3039      /* '09' */
#define S7COMM_BLOCKTYPE_DB                 0x3041      /* '0A' */
#define S7COMM_BLOCKTYPE_SDB                0x3042      /* '0B' */
#define S7COMM_BLOCKTYPE_FC                 0x3043      /* '0C' */
#define S7COMM_BLOCKTYPE_SFC                0x3044      /* '0D' */
#define S7COMM_BLOCKTYPE_FB                 0x3045      /* '0E' */
#define S7COMM_BLOCKTYPE_SFB                0x3046      /* '0F' */

static const value_string blocktype_names[] = {
    { S7COMM_BLOCKTYPE_OB,                  "OB" },
    { S7COMM_BLOCKTYPE_CMOD,                "CMod" },
    { S7COMM_BLOCKTYPE_DB,                  "DB" },
    { S7COMM_BLOCKTYPE_SDB,                 "SDB" },
    { S7COMM_BLOCKTYPE_FC,                  "FC" },
    { S7COMM_BLOCKTYPE_SFC,                 "SFC" },
    { S7COMM_BLOCKTYPE_FB,                  "FB" },
    { S7COMM_BLOCKTYPE_SFB,                 "SFB" },
    { 0,                                    NULL }
};


static const value_string blocktype_attribute1_names[] = {
    { '_',                                  "Complete Module" },
    { '$',                                  "Module header for up-loading" },
    { 0,                                    NULL }
};

static const value_string blocktype_attribute2_names[] = {
    { 'P',                                  "Passive (copied, but not chained) module" },
    { 'A',                                  "Active embedded module" },
    { 'B',                                  "Active as well as passive module" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Subblk types
 */
#define S7COMM_SUBBLKTYPE_NONE              0x00
#define S7COMM_SUBBLKTYPE_OB                0x08
#define S7COMM_SUBBLKTYPE_DB                0x0a
#define S7COMM_SUBBLKTYPE_SDB               0x0b
#define S7COMM_SUBBLKTYPE_FC                0x0c
#define S7COMM_SUBBLKTYPE_SFC               0x0d
#define S7COMM_SUBBLKTYPE_FB                0x0e
#define S7COMM_SUBBLKTYPE_SFB               0x0f

static const value_string subblktype_names[] = {
    { S7COMM_SUBBLKTYPE_NONE,               "Not set" },
    { S7COMM_SUBBLKTYPE_OB,                 "OB" },
    { S7COMM_SUBBLKTYPE_DB,                 "DB" },
    { S7COMM_SUBBLKTYPE_SDB,                "SDB" },
    { S7COMM_SUBBLKTYPE_FC,                 "FC" },
    { S7COMM_SUBBLKTYPE_SFC,                "SFC" },
    { S7COMM_SUBBLKTYPE_FB,                 "FB" },
    { S7COMM_SUBBLKTYPE_SFB,                "SFB" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Block security
 */
#define S7COMM_BLOCKSECURITY_OFF            0
#define S7COMM_BLOCKSECURITY_KNOWHOWPROTECT 3

static const value_string blocksecurity_names[] = {
    { S7COMM_BLOCKSECURITY_OFF,             "None" },
    { S7COMM_BLOCKSECURITY_KNOWHOWPROTECT,  "Know How Protect" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Block Languages
 */
static const value_string blocklanguage_names[] = {
    { 0x00,                                 "Not defined" },
    { 0x01,                                 "AWL" },
    { 0x02,                                 "KOP" },
    { 0x03,                                 "FUP" },
    { 0x04,                                 "SCL" },
    { 0x05,                                 "DB" },
    { 0x06,                                 "GRAPH" },
    { 0x07,                                 "SDB" },
    { 0x08,                                 "CPU-DB" },                     /* DB was created from Plc programm (CREAT_DB) */
    { 0x11,                                 "SDB (after overall reset)" },  /* another SDB, don't know what it means, in SDB 1 and SDB 2, uncertain*/
    { 0x12,                                 "SDB (Routing)" },              /* another SDB, in SDB 999 and SDB 1000 (routing information), uncertain */
    { 0x29,                                 "ENCRYPT" },                    /* block is encrypted with S7-Block-Privacy */
    { 0,                                    NULL }
};

/**************************************************************************
 * Second request/response in userdata parameter part
 */
#define S7COMM_UD_REQRES2_UNDEF             0x00
#define S7COMM_UD_REQRES2_REQ               0x11
#define S7COMM_UD_REQRES2_RES               0x12

static const value_string userdata_reqres2_names[] = {
    { S7COMM_UD_REQRES2_UNDEF,              "Undef" },                      /* only seen in mode transition events */
    { S7COMM_UD_REQRES2_REQ,                "Req" },
    { S7COMM_UD_REQRES2_RES,                "Res" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of types in userdata parameter part
 */

#define S7COMM_UD_TYPE_NCPUSH               0x3
#define S7COMM_UD_TYPE_NCREQ                0x7
#define S7COMM_UD_TYPE_NCRES                0xb

static const value_string userdata_type_names[] = {
    { S7COMM_UD_TYPE_PUSH,                  "Push" },               /* this type occurs when 2 telegrams follow after another from the same partner, or initiated from PLC */
    { S7COMM_UD_TYPE_REQ,                   "Request" },
    { S7COMM_UD_TYPE_RES,                   "Response" },
    { S7COMM_UD_TYPE_NCPUSH,                "NC Push" },            /* used only by Sinumerik NC */
    { S7COMM_UD_TYPE_NCREQ,                 "NC Request" },         /* used only by Sinumerik NC */
    { S7COMM_UD_TYPE_NCRES,                 "NC Response" },        /* used only by Sinumerik NC */
    { 0,                                    NULL }
};

/**************************************************************************
 * Subfunctions only used in Sinumerik NC file download
 */
#define S7COMM_NCPRG_FUNCREQUESTDOWNLOAD    1
#define S7COMM_NCPRG_FUNCDOWNLOADBLOCK      2
#define S7COMM_NCPRG_FUNCCONTDOWNLOAD       3
#define S7COMM_NCPRG_FUNCDOWNLOADENDED      4
#define S7COMM_NCPRG_FUNCSTARTUPLOAD        6
#define S7COMM_NCPRG_FUNCUPLOAD             7
#define S7COMM_NCPRG_FUNCCONTUPLOAD         8

static const value_string userdata_ncprg_subfunc_names[] = {
    { S7COMM_NCPRG_FUNCREQUESTDOWNLOAD,     "Request download" },
    { S7COMM_NCPRG_FUNCDOWNLOADBLOCK,       "Download block" },
    { S7COMM_NCPRG_FUNCCONTDOWNLOAD,        "Continue download" },
    { S7COMM_NCPRG_FUNCDOWNLOADENDED,       "Download ended" },
    { S7COMM_NCPRG_FUNCSTARTUPLOAD,         "Start upload" },
    { S7COMM_NCPRG_FUNCUPLOAD,              "Upload" },
    { S7COMM_NCPRG_FUNCCONTUPLOAD,          "Continue upload" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Userdata Parameter, last data unit
 */
#define S7COMM_UD_LASTDATAUNIT_YES          0x00
#define S7COMM_UD_LASTDATAUNIT_NO           0x01

static const value_string userdata_lastdataunit_names[] = {
    { S7COMM_UD_LASTDATAUNIT_YES,           "Yes" },
    { S7COMM_UD_LASTDATAUNIT_NO,            "No" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of Function groups in userdata parameter part
 */
#define S7COMM_UD_FUNCGROUP_MODETRANS       0x0
#define S7COMM_UD_FUNCGROUP_PROG            0x1
#define S7COMM_UD_FUNCGROUP_CYCLIC          0x2
#define S7COMM_UD_FUNCGROUP_BLOCK           0x3
#define S7COMM_UD_FUNCGROUP_CPU             0x4
#define S7COMM_UD_FUNCGROUP_SEC             0x5                     /* Security functions e.g. plc password */
#define S7COMM_UD_FUNCGROUP_PBC             0x6                     /* PBC = Programmable Block Communication (PBK in german) */
#define S7COMM_UD_FUNCGROUP_TIME            0x7
#define S7COMM_UD_FUNCGROUP_NCPRG           0xf

static const value_string userdata_functiongroup_names[] = {
    { S7COMM_UD_FUNCGROUP_MODETRANS,        "Mode-transition" },
    { S7COMM_UD_FUNCGROUP_PROG,             "Programmer commands" },
    { S7COMM_UD_FUNCGROUP_CYCLIC,           "Cyclic services" },    /* to read data from plc without a request */
    { S7COMM_UD_FUNCGROUP_BLOCK,            "Block functions" },
    { S7COMM_UD_FUNCGROUP_CPU,              "CPU functions" },
    { S7COMM_UD_FUNCGROUP_SEC,              "Security" },
    { S7COMM_UD_FUNCGROUP_PBC,              "PBC BSEND/BRECV" },
    { S7COMM_UD_FUNCGROUP_TIME,             "Time functions" },
    { S7COMM_UD_FUNCGROUP_NCPRG,            "NC programming" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Variable status: Area of data request
 *
 * Low       Hi
 * 0=M       0=BOOL
 * 1=E       1=BYTE
 * 2=A       2=WORD
 * 3=PEx     3=DWORD
 * 7=DB
 * 54=TIMER
 * 64=COUNTER
 */
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MX     0x00
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MB     0x01
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MW     0x02
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MD     0x03
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_EX     0x10
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_EB     0x11
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_EW     0x12
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_ED     0x13
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AX     0x20
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AB     0x21
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AW     0x22
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AD     0x23
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_PEB    0x31
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_PEW    0x32
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_PED    0x33
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBX    0x70
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBB    0x71
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBW    0x72
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBD    0x73
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_T      0x54
#define S7COMM_UD_SUBF_PROG_VARSTAT_AREA_C      0x64

static const value_string userdata_prog_varstat_area_names[] = {
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MX,      "MX" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MB,      "MB" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MW,      "MW" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MD,      "MD" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_EB,      "IB" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_EX,      "IX" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_EW,      "IW" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_ED,      "ID" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AX,      "QX" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AB,      "QB" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AW,      "QW" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AD,      "QD" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_PEB,     "PIB" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_PEW,     "PIW" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_PED,     "PID" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBX,     "DBX" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBB,     "DBB" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBW,     "DBW" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBD,     "DBD" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_T,       "TIMER" },
    { S7COMM_UD_SUBF_PROG_VARSTAT_AREA_C,       "COUNTER" },
    { 0,                                        NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 1 (Programmer commands)
 * In szl dataset 0x0132/2 these are defined as "Test and installation functions TIS".
 * The methods supported by the CPU are listed in the funkt_n bits.
 */
#define S7COMM_UD_SUBF_PROG_BLOCKSTAT       0x01
#define S7COMM_UD_SUBF_PROG_VARSTAT         0x02
#define S7COMM_UD_SUBF_PROG_OUTISTACK       0x03
#define S7COMM_UD_SUBF_PROG_OUTBSTACK       0x04
#define S7COMM_UD_SUBF_PROG_OUTLSTACK       0x05
#define S7COMM_UD_SUBF_PROG_TIMEMEAS        0x06
#define S7COMM_UD_SUBF_PROG_FORCESEL        0x07
#define S7COMM_UD_SUBF_PROG_MODVAR          0x08
#define S7COMM_UD_SUBF_PROG_FORCE           0x09
#define S7COMM_UD_SUBF_PROG_BREAKPOINT      0x0a
#define S7COMM_UD_SUBF_PROG_EXITHOLD        0x0b
#define S7COMM_UD_SUBF_PROG_MEMORYRES       0x0c
#define S7COMM_UD_SUBF_PROG_DISABLEJOB      0x0d
#define S7COMM_UD_SUBF_PROG_ENABLEJOB       0x0e
#define S7COMM_UD_SUBF_PROG_DELETEJOB       0x0f
#define S7COMM_UD_SUBF_PROG_READJOBLIST     0x10
#define S7COMM_UD_SUBF_PROG_READJOB         0x11
#define S7COMM_UD_SUBF_PROG_REPLACEJOB      0x12
#define S7COMM_UD_SUBF_PROG_BLOCKSTAT2      0x13
#define S7COMM_UD_SUBF_PROG_FLASHLED        0x16

static const value_string userdata_prog_subfunc_names[] = {
    { S7COMM_UD_SUBF_PROG_BLOCKSTAT,        "Block status" },
    { S7COMM_UD_SUBF_PROG_VARSTAT,          "Variable status" },
    { S7COMM_UD_SUBF_PROG_OUTISTACK,        "Output ISTACK" },
    { S7COMM_UD_SUBF_PROG_OUTBSTACK,        "Output BSTACK" },
    { S7COMM_UD_SUBF_PROG_OUTLSTACK,        "Output LSTACK" },
    { S7COMM_UD_SUBF_PROG_TIMEMEAS,         "Time measurement from to" },       /* never seen yet */
    { S7COMM_UD_SUBF_PROG_FORCESEL,         "Force selection" },
    { S7COMM_UD_SUBF_PROG_MODVAR,           "Modify variable" },
    { S7COMM_UD_SUBF_PROG_FORCE,            "Force" },
    { S7COMM_UD_SUBF_PROG_BREAKPOINT,       "Breakpoint" },
    { S7COMM_UD_SUBF_PROG_EXITHOLD,         "Exit HOLD" },
    { S7COMM_UD_SUBF_PROG_MEMORYRES,        "Memory reset" },
    { S7COMM_UD_SUBF_PROG_DISABLEJOB,       "Disable job" },
    { S7COMM_UD_SUBF_PROG_ENABLEJOB,        "Enable job" },
    { S7COMM_UD_SUBF_PROG_DELETEJOB,        "Delete job" },
    { S7COMM_UD_SUBF_PROG_READJOBLIST,      "Read job list" },
    { S7COMM_UD_SUBF_PROG_READJOB,          "Read job" },
    { S7COMM_UD_SUBF_PROG_REPLACEJOB,       "Replace job" },
    { S7COMM_UD_SUBF_PROG_BLOCKSTAT2,       "Block status v2" },
    { S7COMM_UD_SUBF_PROG_FLASHLED,         "Flash LED" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Variable status: Trigger point
 */
static const value_string userdata_varstat_trgevent_names[] = {
    { 0x0000,                               "Immediately" },
    { 0x0100,                               "System Trigger" },
    { 0x0200,                               "System checkpoint main cycle start" },
    { 0x0300,                               "System checkpoint main cycle end" },
    { 0x0400,                               "Mode transition RUN-STOP" },
    { 0x0500,                               "After code address" },
    { 0x0600,                               "Code address area" },
    { 0x0601,                               "Code address area with call environment" },  /* Call conditions like opened DB/DI or called block */
    { 0x0700,                               "Data address" },
    { 0x0800,                               "Data address area" },
    { 0x0900,                               "Local data address" },
    { 0x0a00,                               "Local data address area" },
    { 0x0b00,                               "Range trigger" },
    { 0x0c00,                               "Before code address" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 2 (cyclic data)
 */
#define S7COMM_UD_SUBF_CYCLIC_TRANSF        0x01
#define S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE   0x04
#define S7COMM_UD_SUBF_CYCLIC_CHANGE        0x05
#define S7COMM_UD_SUBF_CYCLIC_CHANGE_MOD    0x07
#define S7COMM_UD_SUBF_CYCLIC_RDREC         0x08

static const value_string userdata_cyclic_subfunc_names[] = {
    { S7COMM_UD_SUBF_CYCLIC_TRANSF,         "Cyclic transfer" },
    { S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE,    "Unsubscribe" },
    { S7COMM_UD_SUBF_CYCLIC_CHANGE,         "Change driven transfer" },
    { S7COMM_UD_SUBF_CYCLIC_CHANGE_MOD,     "Change driven transfer modify" },
    { S7COMM_UD_SUBF_CYCLIC_RDREC,          "RDREC" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Timebase for cyclic services
 */
static const value_string cycl_interval_timebase_names[] = {
    { 0,                                    "100 milliseconds" },
    { 1,                                    "1 second" },
    { 2,                                    "10 seconds" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 3 (Block functions)
 */
#define S7COMM_UD_SUBF_BLOCK_LIST           0x01
#define S7COMM_UD_SUBF_BLOCK_LISTTYPE       0x02
#define S7COMM_UD_SUBF_BLOCK_BLOCKINFO      0x03

static const value_string userdata_block_subfunc_names[] = {
    { S7COMM_UD_SUBF_BLOCK_LIST,            "List blocks" },
    { S7COMM_UD_SUBF_BLOCK_LISTTYPE,        "List blocks of type" },
    { S7COMM_UD_SUBF_BLOCK_BLOCKINFO,       "Get block info" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 4 (CPU functions)
 */
#define S7COMM_UD_SUBF_CPU_SCAN_IND         0x09

static const value_string userdata_cpu_subfunc_names[] = {
    { S7COMM_UD_SUBF_CPU_READSZL,           "Read SZL" },
    { S7COMM_UD_SUBF_CPU_MSGS,              "Message service" },                /* Header constant is also different here */
    { S7COMM_UD_SUBF_CPU_DIAGMSG,           "Diagnostic message" },             /* Diagnostic message from PLC */
    { S7COMM_UD_SUBF_CPU_ALARM8_IND,        "ALARM_8 indication" },             /* PLC is indicating an ALARM message, using ALARM_8 SFBs */
    { S7COMM_UD_SUBF_CPU_NOTIFY_IND,        "NOTIFY indication" },              /* PLC is indicating a NOTIFY message, using NOTIFY SFBs */
    { S7COMM_UD_SUBF_CPU_ALARM8LOCK,        "ALARM_8 lock" },                   /* Lock an ALARM message from HMI/SCADA */
    { S7COMM_UD_SUBF_CPU_ALARM8UNLOCK,      "ALARM_8 unlock" },                 /* Unlock an ALARM message from HMI/SCADA */
    { S7COMM_UD_SUBF_CPU_SCAN_IND,          "SCAN indication" },                /* PLC is indicating a SCAN message */
    { S7COMM_UD_SUBF_CPU_ALARMS_IND,        "ALARM_S indication" },             /* PLC is indicating an ALARM message, using ALARM_S/ALARM_D SFCs */
    { S7COMM_UD_SUBF_CPU_ALARMSQ_IND,       "ALARM_SQ indication" },            /* PLC is indicating an ALARM message, using ALARM_SQ/ALARM_DQ SFCs */
    { S7COMM_UD_SUBF_CPU_ALARMQUERY,        "ALARM query" },                    /* HMI/SCADA query of ALARMs */
    { S7COMM_UD_SUBF_CPU_ALARMACK,          "ALARM ack" },                      /* Alarm was acknowledged in HMI/SCADA */
    { S7COMM_UD_SUBF_CPU_ALARMACK_IND,      "ALARM ack indication" },           /* Alarm acknowledge indication from CPU to HMI */
    { S7COMM_UD_SUBF_CPU_ALARM8LOCK_IND,    "ALARM lock indication" },          /* Alarm lock indication from CPU to HMI */
    { S7COMM_UD_SUBF_CPU_ALARM8UNLOCK_IND,  "ALARM unlock indication" },        /* Alarm unlock indication from CPU to HMI */
    { S7COMM_UD_SUBF_CPU_NOTIFY8_IND,       "NOTIFY_8 indication" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 5 (Security?)
 */
#define S7COMM_UD_SUBF_SEC_PASSWD           0x01

static const value_string userdata_sec_subfunc_names[] = {
    { S7COMM_UD_SUBF_SEC_PASSWD,            "PLC password" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 7 (Time functions)
 */
#define S7COMM_UD_SUBF_TIME_READ            0x01
#define S7COMM_UD_SUBF_TIME_SET             0x02
#define S7COMM_UD_SUBF_TIME_READF           0x03
#define S7COMM_UD_SUBF_TIME_SET2            0x04

static const value_string userdata_time_subfunc_names[] = {
    { S7COMM_UD_SUBF_TIME_READ,             "Read clock" },
    { S7COMM_UD_SUBF_TIME_SET,              "Set clock" },
    { S7COMM_UD_SUBF_TIME_READF,            "Read clock (following)" },
    { S7COMM_UD_SUBF_TIME_SET2,             "Set clock" },
    { 0,                                    NULL }
};

/*******************************************************************************************************
 * Weekday names in DATE_AND_TIME
 */
static const value_string weekdaynames[] = {
    { 0,                                    "Undefined" },
    { 1,                                    "Sunday" },
    { 2,                                    "Monday" },
    { 3,                                    "Tuesday" },
    { 4,                                    "Wednesday" },
    { 5,                                    "Thursday" },
    { 6,                                    "Friday" },
    { 7,                                    "Saturday" },
    { 0,                                    NULL }
};

/**************************************************************************
 **************************************************************************/

/**************************************************************************
 * Flags for LID access
 */
#define S7COMM_TIA1200_VAR_ENCAPS_LID       0x2
#define S7COMM_TIA1200_VAR_ENCAPS_IDX       0x3
#define S7COMM_TIA1200_VAR_OBTAIN_LID       0x4
#define S7COMM_TIA1200_VAR_OBTAIN_IDX       0x5
#define S7COMM_TIA1200_VAR_PART_START       0x6
#define S7COMM_TIA1200_VAR_PART_LEN         0x7

static const value_string tia1200_var_lid_flag_names[] = {
    { S7COMM_TIA1200_VAR_ENCAPS_LID,        "Encapsulated LID" },
    { S7COMM_TIA1200_VAR_ENCAPS_IDX,        "Encapsulated Index" },
    { S7COMM_TIA1200_VAR_OBTAIN_LID,        "Obtain by LID" },
    { S7COMM_TIA1200_VAR_OBTAIN_IDX,        "Obtain by Index" },
    { S7COMM_TIA1200_VAR_PART_START,        "Part Start Address" },
    { S7COMM_TIA1200_VAR_PART_LEN,          "Part Length" },
    { 0,                                    NULL }
};

/**************************************************************************
 * TIA 1200 Area Names for variable access
 */
#define S7COMM_TIA1200_VAR_ITEM_AREA1_DB    0x8a0e              /* Reading DB, 2 byte DB-Number following */
#define S7COMM_TIA1200_VAR_ITEM_AREA1_IQMCT 0x0000              /* Reading I/Q/M/C/T, 2 Byte detail area following */

static const value_string tia1200_var_item_area1_names[] = {
    { S7COMM_TIA1200_VAR_ITEM_AREA1_DB,     "DB" },
    { S7COMM_TIA1200_VAR_ITEM_AREA1_IQMCT,  "IQMCT" },
    { 0,                                    NULL }
};

#define S7COMM_TIA1200_VAR_ITEM_AREA2_I     0x50
#define S7COMM_TIA1200_VAR_ITEM_AREA2_Q     0x51
#define S7COMM_TIA1200_VAR_ITEM_AREA2_M     0x52
#define S7COMM_TIA1200_VAR_ITEM_AREA2_C     0x53
#define S7COMM_TIA1200_VAR_ITEM_AREA2_T     0x54

static const value_string tia1200_var_item_area2_names[] = {
    { S7COMM_TIA1200_VAR_ITEM_AREA2_I,      "Inputs (I)" },
    { S7COMM_TIA1200_VAR_ITEM_AREA2_Q,      "Outputs (Q)" },
    { S7COMM_TIA1200_VAR_ITEM_AREA2_M,      "Flags (M)" },
    { S7COMM_TIA1200_VAR_ITEM_AREA2_C,      "Counter (C)" },
    { S7COMM_TIA1200_VAR_ITEM_AREA2_T,      "Timer (T)" },
    { 0,                                    NULL }
};

/**************************************************************************
 * NCK areas
 */
#define S7COMM_NCK_AREA_N_NCK               0
#define S7COMM_NCK_AREA_B_MODEGROUP         1
#define S7COMM_NCK_AREA_C_CHANNEL           2
#define S7COMM_NCK_AREA_A_AXIS              3
#define S7COMM_NCK_AREA_T_TOOL              4
#define S7COMM_NCK_AREA_V_FEEDDRIVE         5
#define S7COMM_NCK_AREA_H_MAINDRIVE         6
#define S7COMM_NCK_AREA_M_MMC               7

static const value_string nck_area_names[] = {
    { S7COMM_NCK_AREA_N_NCK,                "N - NCK" },
    { S7COMM_NCK_AREA_B_MODEGROUP,          "B - Mode group" },
    { S7COMM_NCK_AREA_C_CHANNEL,            "C - Channel" },
    { S7COMM_NCK_AREA_A_AXIS,               "A - Axis" },
    { S7COMM_NCK_AREA_T_TOOL,               "T - Tool" },
    { S7COMM_NCK_AREA_V_FEEDDRIVE,          "V - Feed drive" },
    { S7COMM_NCK_AREA_H_MAINDRIVE,          "M - Main drive" },
    { S7COMM_NCK_AREA_M_MMC,                "M - MMC" },
    { 0,                                    NULL }
};

static const value_string nck_module_names[] = {
    { 0x10,                                 "Y - Global system data" },
    { 0x11,                                 "YNCFL - NCK instruction groups" },
    { 0x12,                                 "FU - NCU global settable frames" },
    { 0x13,                                 "FA - Active NCU global frames" },
    { 0x14,                                 "TO - Tool data" },
    { 0x15,                                 "RP - Arithmetic parameters" },
    { 0x16,                                 "SE - Setting data" },
    { 0x17,                                 "SGUD - SGUD-Block" },
    { 0x18,                                 "LUD - Local userdata" },
    { 0x19,                                 "TC - Toolholder parameters" },
    { 0x1a,                                 "M - Machine data" },
    { 0x1c,                                 "WAL - Working area limitation" },
    { 0x1e,                                 "DIAG - Internal diagnostic data" },
    { 0x1f,                                 "CC - Unknown" },
    { 0x20,                                 "FE - Channel-specific external frame" },
    { 0x21,                                 "TD - Tool data: General data" },
    { 0x22,                                 "TS - Tool edge data: Monitoring data" },
    { 0x23,                                 "TG - Tool data: Grinding-specific data" },
    { 0x24,                                 "TU - Tool data" },
    { 0x25,                                 "TUE - Tool edge data, userdefined data" },
    { 0x26,                                 "TV - Tool data, directory" },
    { 0x27,                                 "TM - Magazine data: General data" },
    { 0x28,                                 "TP - Magazine data: Location data" },
    { 0x29,                                 "TPM - Magazine data: Multiple assignment of location data" },
    { 0x2a,                                 "TT - Magazine data: Location typ" },
    { 0x2b,                                 "TMV - Magazine data: Directory" },
    { 0x2c,                                 "TMC - Magazine data: Configuration data" },
    { 0x2d,                                 "MGUD - MGUD-Block" },
    { 0x2e,                                 "UGUD - UGUD-Block" },
    { 0x2f,                                 "GUD4 - GUD4-Block" },
    { 0x30,                                 "GUD5 - GUD5-Block" },
    { 0x31,                                 "GUD6 - GUD6-Block" },
    { 0x32,                                 "GUD7 - GUD7-Block" },
    { 0x33,                                 "GUD8 - GUD8-Block" },
    { 0x34,                                 "GUD9 - GUD9-Block" },
    { 0x35,                                 "PA - Channel-specific protection zones" },
    { 0x36,                                 "GD1 - SGUD-Block GD1" },
    { 0x37,                                 "NIB - State data: Nibbling" },
    { 0x38,                                 "ETP - Types of events" },
    { 0x39,                                 "ETPD - Data lists for protocolling" },
    { 0x3a,                                 "SYNACT - Channel-specific synchronous actions" },
    { 0x3b,                                 "DIAGN - Diagnostic data" },
    { 0x3c,                                 "VSYN - Channel-specific user variables for synchronous actions" },
    { 0x3d,                                 "TUS - Tool data: user monitoring data" },
    { 0x3e,                                 "TUM - Tool data: user magazine data" },
    { 0x3f,                                 "TUP - Tool data: user magatine place data" },
    { 0x40,                                 "TF - Parametrizing, return parameters of _N_TMGETT, _N_TSEARC" },
    { 0x41,                                 "FB - Channel-specific base frames" },
    { 0x42,                                 "SSP2 - State data: Spindle" },
    { 0x43,                                 "PUD - programmglobale Benutzerdaten" },
    { 0x44,                                 "TOS - Edge-related location-dependent fine total offsets" },
    { 0x45,                                 "TOST - Edge-related location-dependent fine total offsets, transformed" },
    { 0x46,                                 "TOE - Edge-related coarse total offsets, setup offsets" },
    { 0x47,                                 "TOET - Edge-related coarse total offsets, transformed setup offsets" },
    { 0x48,                                 "AD - Adapter data" },
    { 0x49,                                 "TOT - Edge data: Transformed offset data" },
    { 0x4a,                                 "AEV - Working offsets: Directory" },
    { 0x4b,                                 "YFAFL - NCK instruction groups (Fanuc)" },
    { 0x4c,                                 "FS - System-Frame" },
    { 0x4d,                                 "SD - Servo data" },
    { 0x4e,                                 "TAD - Application-specific data" },
    { 0x4f,                                 "TAO - Aplication-specific cutting edge data" },
    { 0x50,                                 "TAS - Application-specific monitoring data" },
    { 0x51,                                 "TAM - Application-specific magazine data" },
    { 0x52,                                 "TAP - Application-specific magazine location data" },
    { 0x53,                                 "MEM - Unknown" },
    { 0x54,                                 "SALUC - Alarm actions: List in reverse chronological order" },
    { 0x55,                                 "AUXFU - Auxiliary functions" },
    { 0x56,                                 "TDC - Tool/Tools" },
    { 0x57,                                 "CP - Generic coupling" },
    { 0x6e,                                 "SDME - Unknown" },
    { 0x6f,                                 "SPARPI - Program pointer on interruption" },
    { 0x70,                                 "SEGA - State data: Geometry axes in tool offset memory (extended)" },
    { 0x71,                                 "SEMA - State data: Machine axes (extended)" },
    { 0x72,                                 "SSP - State data: Spindle" },
    { 0x73,                                 "SGA - State data: Geometry axes in tool offset memory" },
    { 0x74,                                 "SMA - State data: Machine axes" },
    { 0x75,                                 "SALAL - Alarms: List organized according to time" },
    { 0x76,                                 "SALAP - Alarms: List organized according to priority" },
    { 0x77,                                 "SALA - Alarms: List organized according to time" },
    { 0x78,                                 "SSYNAC - Synchronous actions" },
    { 0x79,                                 "SPARPF - Program pointers for block search and stop run" },
    { 0x7a,                                 "SPARPP - Program pointer in automatic operation" },
    { 0x7b,                                 "SNCF - Active G functions" },
    { 0x7d,                                 "SPARP - Part program information" },
    { 0x7e,                                 "SINF - Part-program-specific status data" },
    { 0x7f,                                 "S - State data" },
    { 0x80,                                 "0x80 - Unknown" },
    { 0x81,                                 "0x81 - Unknown" },
    { 0x82,                                 "0x82 - Unknown" },
    { 0x83,                                 "0x83 - Unknown" },
    { 0x84,                                 "0x84 - Unknown" },
    { 0x85,                                 "0x85 - Unknown" },
    { 0xfd,                                 "0 - Internal" },
    { 0,                                    NULL }
};
static value_string_ext nck_module_names_ext = VALUE_STRING_EXT_INIT(nck_module_names);

static gint hf_s7comm_tia1200_item_reserved1 = -1;          /* 1 Byte Reserved (always 0xff?) */
static gint hf_s7comm_tia1200_item_area1 = -1;              /* 2 Byte2 Root area (DB or IQMCT) */
static gint hf_s7comm_tia1200_item_area2 = -1;              /* 2 Bytes detail area (I/Q/M/C/T) */
static gint hf_s7comm_tia1200_item_area2unknown = -1;       /* 2 Bytes detail area for possible unknown or not seen areas */
static gint hf_s7comm_tia1200_item_dbnumber = -1;           /* 2 Bytes DB number */
static gint hf_s7comm_tia1200_item_crc = -1;                /* 4 Bytes CRC */

static gint hf_s7comm_tia1200_substructure_item = -1;       /* Substructure */
static gint hf_s7comm_tia1200_var_lid_flags = -1;           /* LID Flags */
static gint hf_s7comm_tia1200_item_value = -1;

/**************************************************************************
 **************************************************************************/

/* Header Block */
static gint hf_s7comm_header = -1;
static gint hf_s7comm_header_protid = -1;                   /* Header Byte  0 */
static gint hf_s7comm_header_rosctr = -1;                   /* Header Bytes 1 */
static gint hf_s7comm_header_redid = -1;                    /* Header Bytes 2, 3 */
static gint hf_s7comm_header_pduref = -1;                   /* Header Bytes 4, 5 */
static gint hf_s7comm_header_parlg = -1;                    /* Header Bytes 6, 7 */
static gint hf_s7comm_header_datlg = -1;                    /* Header Bytes 8, 9 */
static gint hf_s7comm_header_errcls = -1;                   /* Header Byte 10, only available at type 2 or 3 */
static gint hf_s7comm_header_errcod = -1;                   /* Header Byte 11, only available at type 2 or 3 */
/* Parameter Block */
static gint hf_s7comm_param = -1;
static gint hf_s7comm_param_errcod = -1;                    /* Parameter part: Error code */
static gint hf_s7comm_param_service = -1;                   /* Parameter part: service */
static gint hf_s7comm_param_itemcount = -1;                 /* Parameter part: item count */
static gint hf_s7comm_param_data = -1;                      /* Parameter part: data */
static gint hf_s7comm_param_neg_pdu_length = -1;            /* Parameter part: Negotiate PDU length */
static gint hf_s7comm_param_setup_reserved1 = -1;           /* Parameter part: Reserved byte in communication setup pdu*/

static gint hf_s7comm_param_maxamq_calling = -1;            /* Parameter part: Max AmQ calling */
static gint hf_s7comm_param_maxamq_called = -1;             /* Parameter part: Max AmQ called */

/* Item data */
static gint hf_s7comm_param_item = -1;
static gint hf_s7comm_param_subitem = -1;                   /* Substructure */
static gint hf_s7comm_item_varspec = -1;                    /* Variable specification */
static gint hf_s7comm_item_varspec_length = -1;             /* Length of following address specification */
static gint hf_s7comm_item_syntax_id = -1;                  /* Syntax Id */
static gint hf_s7comm_item_transport_size = -1;             /* Transport size, 1 Byte*/
static gint hf_s7comm_item_length = -1;                     /* length, 2 Bytes*/
static gint hf_s7comm_item_db = -1;                         /* DB/M/E/A, 2 Bytes */
static gint hf_s7comm_item_area = -1;                       /* Area code, 1 byte */
static gint hf_s7comm_item_address = -1;                    /* Bit address, 3 Bytes */
static gint hf_s7comm_item_address_byte = -1;               /* address: Byte address */
static gint hf_s7comm_item_address_bit = -1;                /* address: Bit address */
static gint hf_s7comm_item_address_nr = -1;                 /* address: Timer/Counter/block number */
/* Special variable read with Syntax-Id 0xb0 (DBREAD) */
static gint hf_s7comm_item_dbread_numareas = -1;            /* Number of areas following, 1 Byte*/
static gint hf_s7comm_item_dbread_length = -1;              /* length, 1 Byte*/
static gint hf_s7comm_item_dbread_db = -1;                  /* DB number, 2 Bytes*/
static gint hf_s7comm_item_dbread_startadr = -1;            /* Start address, 2 Bytes*/
/* Reading frequency inverter parameters via routing */
static gint hf_s7comm_item_driveesany_unknown1 = -1;        /* Unknown value 1, 1 Byte */
static gint hf_s7comm_item_driveesany_unknown2 = -1;        /* Unknown value 2, 2 Bytes */
static gint hf_s7comm_item_driveesany_unknown3 = -1;        /* Unknown value 3, 2 Bytes */
static gint hf_s7comm_item_driveesany_parameter_nr = -1;    /* Parameter number, 2 Bytes */
static gint hf_s7comm_item_driveesany_parameter_idx = -1;   /* Parameter index, 2 Bytes */
/* NCK access with Syntax-Id 0x82 */
static gint hf_s7comm_item_nck_areaunit = -1;               /* Bitmask: aaauuuuu: a=area, u=unit */
static gint hf_s7comm_item_nck_area = -1;
static gint hf_s7comm_item_nck_unit = -1;
static gint hf_s7comm_item_nck_column = -1;
static gint hf_s7comm_item_nck_line = -1;
static gint hf_s7comm_item_nck_module = -1;
static gint hf_s7comm_item_nck_linecount = -1;

static gint hf_s7comm_data = -1;
static gint hf_s7comm_data_returncode = -1;                 /* return code, 1 byte */
static gint hf_s7comm_data_transport_size = -1;             /* transport size 1 byte */
static gint hf_s7comm_data_length = -1;                     /* Length of data, 2 Bytes */

static gint hf_s7comm_data_item = -1;

static gint hf_s7comm_readresponse_data = -1;
static gint hf_s7comm_data_fillbyte = -1;

/* timefunction: s7 timestamp */
static gint hf_s7comm_data_ts = -1;
static gint hf_s7comm_data_ts_reserved = -1;
static gint hf_s7comm_data_ts_year1 = -1;                   /* first byte of BCD coded year, should be ignored */
static gint hf_s7comm_data_ts_year2 = -1;                   /* second byte of BCD coded year, if 00...89 then it's 2000...2089, else 1990...1999*/
static gint hf_s7comm_data_ts_month = -1;
static gint hf_s7comm_data_ts_day = -1;
static gint hf_s7comm_data_ts_hour = -1;
static gint hf_s7comm_data_ts_minute = -1;
static gint hf_s7comm_data_ts_second = -1;
static gint hf_s7comm_data_ts_millisecond = -1;
static gint hf_s7comm_data_ts_weekday = -1;

/* userdata, block services */
static gint hf_s7comm_userdata_data = -1;

static gint hf_s7comm_userdata_param_head = -1;
static gint hf_s7comm_userdata_param_len = -1;
static gint hf_s7comm_userdata_param_reqres2 = -1;
static gint hf_s7comm_userdata_param_type = -1;
static gint hf_s7comm_userdata_param_funcgroup = -1;
static gint hf_s7comm_userdata_param_subfunc_prog = -1;
static gint hf_s7comm_userdata_param_subfunc_cyclic = -1;
static gint hf_s7comm_userdata_param_subfunc_block = -1;
static gint hf_s7comm_userdata_param_subfunc_cpu = -1;
static gint hf_s7comm_userdata_param_subfunc_sec = -1;
static gint hf_s7comm_userdata_param_subfunc_time = -1;
static gint hf_s7comm_userdata_param_subfunc_ncprg = -1;
static gint hf_s7comm_userdata_param_subfunc = -1;          /* for all other subfunctions */
static gint hf_s7comm_userdata_param_seq_num = -1;
static gint hf_s7comm_userdata_param_dataunitref = -1;
static gint hf_s7comm_userdata_param_dataunit = -1;

/* block functions, list blocks of type */
static gint hf_s7comm_ud_blockinfo_block_type = -1;         /* Block type, 2 bytes */
static gint hf_s7comm_ud_blockinfo_block_num = -1;          /* Block number, 2 bytes as int */
static gint hf_s7comm_ud_blockinfo_block_cnt = -1;          /* Count, 2 bytes as int */
static gint hf_s7comm_ud_blockinfo_block_flags = -1;        /* Block flags (unknown), 1 byte */
static gint hf_s7comm_ud_blockinfo_block_lang = -1;         /* Block language, 1 byte, stringlist blocklanguage_names */
/* block functions, get block infos */
static gint hf_s7comm_ud_blockinfo_block_num_ascii = -1;    /* Block number, 5 bytes, ASCII*/
static gint hf_s7comm_ud_blockinfo_filesys = -1;            /* Filesystem, 1 byte, ASCII*/
static gint hf_s7comm_ud_blockinfo_res_infolength = -1;     /* Length of Info, 2 bytes as int */
static gint hf_s7comm_ud_blockinfo_res_unknown2 = -1;       /* Unknown blockinfo 2, 2 bytes, HEX*/
static gint hf_s7comm_ud_blockinfo_res_const3 = -1;         /* Constant 3, 2 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_res_unknown = -1;        /* Unknown byte(s) */
static gint hf_s7comm_ud_blockinfo_subblk_type = -1;        /* Subblk type, 1 byte, stringlist subblktype_names */
static gint hf_s7comm_ud_blockinfo_load_mem_len = -1;       /* Length load memory, 4 bytes, int */
static gint hf_s7comm_ud_blockinfo_blocksecurity = -1;      /* Block Security, 4 bytes, stringlist blocksecurity_names*/
static gint hf_s7comm_ud_blockinfo_interface_timestamp = -1;/* Interface Timestamp, string */
static gint hf_s7comm_ud_blockinfo_code_timestamp = -1;     /* Code Timestamp, string */
static gint hf_s7comm_ud_blockinfo_ssb_len = -1;            /* SSB length, 2 bytes, int */
static gint hf_s7comm_ud_blockinfo_add_len = -1;            /* ADD length, 2 bytes, int */
static gint hf_s7comm_ud_blockinfo_localdata_len = -1;      /* Length localdata, 2 bytes, int */
static gint hf_s7comm_ud_blockinfo_mc7_len = -1;            /* Length MC7 code, 2 bytes, int */
static gint hf_s7comm_ud_blockinfo_author = -1;             /* Author, 8 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_family = -1;             /* Family, 8 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_headername = -1;         /* Name (Header), 8 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_headerversion = -1;      /* Version (Header), 8 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_checksum = -1;           /* Block checksum, 2 bytes, HEX */
static gint hf_s7comm_ud_blockinfo_reserved1 = -1;          /* Reserved 1, 4 bytes, HEX */
static gint hf_s7comm_ud_blockinfo_reserved2 = -1;          /* Reserved 2, 4 bytes, HEX */

static gint hf_s7comm_userdata_blockinfo_flags = -1;        /* Some flags in Block info response */
static gint hf_s7comm_userdata_blockinfo_linked = -1;       /* Some flags in Block info response */
static gint hf_s7comm_userdata_blockinfo_standard_block = -1;
static gint hf_s7comm_userdata_blockinfo_nonretain = -1;    /* Some flags in Block info response */
static gint ett_s7comm_userdata_blockinfo_flags = -1;
static int * const s7comm_userdata_blockinfo_flags_fields[] = {
    &hf_s7comm_userdata_blockinfo_linked,
    &hf_s7comm_userdata_blockinfo_standard_block,
    &hf_s7comm_userdata_blockinfo_nonretain,
    NULL
};

/* Programmer commands / Test and installation (TIS) functions */
static gint hf_s7comm_tis_parameter = -1;
static gint hf_s7comm_tis_data = -1;
static gint hf_s7comm_tis_parametersize = -1;
static gint hf_s7comm_tis_datasize = -1;
static gint hf_s7comm_tis_param1 = -1;
static gint hf_s7comm_tis_param2 = -1;
static const value_string tis_param2_names[] = {    /* Values and their meaning are not always clearly defined in every function */
    { 0,                                    "Update Monitor Variables / Activate Modify Values"},
    { 1,                                    "Monitor Variable / Modify Variable" },
    { 2,                                    "Modify Variable permanent" },
    { 256,                                  "Force immediately" },
    { 0,                                    NULL }
};
static gint hf_s7comm_tis_param3 = -1;
static const value_string tis_param3_names[] = {
    { 0,                                    "Every cycle (permanent)" },
    { 1,                                    "Once" },
    { 2,                                    "Always (force)" },
    { 0,                                    NULL }
};
static gint hf_s7comm_tis_answersize = -1;
static gint hf_s7comm_tis_param5 = -1;
static gint hf_s7comm_tis_param6 = -1;
static gint hf_s7comm_tis_param7 = -1;
static gint hf_s7comm_tis_param8 = -1;
static gint hf_s7comm_tis_param9 = -1;
static gint hf_s7comm_tis_trgevent = -1;
static gint hf_s7comm_tis_res_param1 = -1;
static gint hf_s7comm_tis_res_param2 = -1;
static gint hf_s7comm_tis_job_function = -1;
static gint hf_s7comm_tis_job_seqnr = -1;
static gint hf_s7comm_tis_job_reserved = -1;



/* B/I/L Stack */
static gint hf_s7comm_tis_interrupted_blocktype = -1;
static gint hf_s7comm_tis_interrupted_blocknr = -1;
static gint hf_s7comm_tis_interrupted_address = -1;
static gint hf_s7comm_tis_interrupted_prioclass = -1;
static gint hf_s7comm_tis_continued_blocktype = -1;
static gint hf_s7comm_tis_continued_blocknr = -1;
static gint hf_s7comm_tis_continued_address = -1;
static gint hf_s7comm_tis_breakpoint_blocktype = -1;
static gint hf_s7comm_tis_breakpoint_blocknr = -1;
static gint hf_s7comm_tis_breakpoint_address = -1;
static gint hf_s7comm_tis_breakpoint_reserved = -1;

static gint hf_s7comm_tis_p_callenv = -1;
static const value_string tis_p_callenv_names[] = {
    { 0,                                   "Specified call environment"},
    { 2,                                   "Specified global and/or instance data block"},
    { 0,                                    NULL }
};
static gint hf_s7comm_tis_p_callcond = -1;
static const value_string tis_p_callcond_names[] = {
    { 0x0000,                               "Not set" },
    { 0x0001,                               "On block number" },
    { 0x0101,                               "On block number with code address" },
    { 0x0a00,                               "On DB1 (DB) content" },
    { 0x000a,                               "On DB2 (DI) content" },
    { 0x0a0a,                               "On DB1 (DB) and DB2 (DI) content" },
    { 0,                                    NULL }
};
static gint hf_s7comm_tis_p_callcond_blocktype = -1;
static gint hf_s7comm_tis_p_callcond_blocknr = -1;
static gint hf_s7comm_tis_p_callcond_address = -1;


static gint hf_s7comm_tis_register_db1_type = -1;
static gint hf_s7comm_tis_register_db2_type = -1;
static gint hf_s7comm_tis_register_db1_nr = -1;
static gint hf_s7comm_tis_register_db2_nr = -1;
static gint hf_s7comm_tis_register_accu1 = -1;
static gint hf_s7comm_tis_register_accu2 = -1;
static gint hf_s7comm_tis_register_accu3 = -1;
static gint hf_s7comm_tis_register_accu4 = -1;
static gint hf_s7comm_tis_register_ar1 = -1;
static gint hf_s7comm_tis_register_ar2 = -1;
static gint hf_s7comm_tis_register_stw = -1;
static gint hf_s7comm_tis_exithold_until = -1;
static const value_string tis_exithold_until_names[] = {
    { 0,                                    "Next breakpoint" },
    { 1,                                    "Next statement" },
    { 0,                                    NULL }
};
static gint hf_s7comm_tis_exithold_res1 = -1;
static gint hf_s7comm_tis_bstack_nest_depth = -1;
static gint hf_s7comm_tis_bstack_reserved = -1;
static gint hf_s7comm_tis_istack_reserved = -1;
static gint hf_s7comm_tis_lstack_reserved = -1;
static gint hf_s7comm_tis_lstack_size = -1;
static gint hf_s7comm_tis_lstack_data = -1;
static gint hf_s7comm_tis_blockstat_flagsunknown = -1;
static gint hf_s7comm_tis_blockstat_number_of_lines = -1;
static gint hf_s7comm_tis_blockstat_line_address = -1;
static gint hf_s7comm_tis_blockstat_data = -1;
static gint hf_s7comm_tis_blockstat_reserved = -1;

/* Organization block local data */
static gint hf_s7comm_ob_ev_class = -1;
static gint hf_s7comm_ob_scan_1 = -1;
static gint hf_s7comm_ob_strt_inf = -1;
static gint hf_s7comm_ob_flt_id = -1;
static gint hf_s7comm_ob_priority = -1;
static gint hf_s7comm_ob_number = -1;
static gint hf_s7comm_ob_reserved_1 = -1;
static gint hf_s7comm_ob_reserved_2 = -1;
static gint hf_s7comm_ob_reserved_3 = -1;
static gint hf_s7comm_ob_reserved_4 = -1;
static gint hf_s7comm_ob_reserved_4_dw = -1;
static gint hf_s7comm_ob_prev_cycle = -1;
static gint hf_s7comm_ob_min_cycle = -1;
static gint hf_s7comm_ob_max_cycle = -1;
static gint hf_s7comm_ob_period_exe = -1;
static gint hf_s7comm_ob_sign = -1;
static gint hf_s7comm_ob_dtime = -1;
static gint hf_s7comm_ob_phase_offset = -1;
static gint hf_s7comm_ob_exec_freq = -1;
static gint hf_s7comm_ob_io_flag = -1;
static gint hf_s7comm_ob_mdl_addr = -1;
static gint hf_s7comm_ob_point_addr = -1;
static gint hf_s7comm_ob_inf_len = -1;
static gint hf_s7comm_ob_alarm_type = -1;
static gint hf_s7comm_ob_alarm_slot = -1;
static gint hf_s7comm_ob_alarm_spec = -1;
static gint hf_s7comm_ob_error_info = -1;
static gint hf_s7comm_ob_err_ev_class = -1;
static gint hf_s7comm_ob_err_ev_num = -1;
static gint hf_s7comm_ob_err_ob_priority = -1;
static gint hf_s7comm_ob_err_ob_num = -1;
static gint hf_s7comm_ob_rack_cpu = -1;
static gint hf_s7comm_ob_8x_fault_flags = -1;
static gint hf_s7comm_ob_mdl_type_b = -1;
static gint hf_s7comm_ob_mdl_type_w = -1;
static gint hf_s7comm_ob_rack_num = -1;
static gint hf_s7comm_ob_racks_flt = -1;
static gint hf_s7comm_ob_strtup = -1;
static gint hf_s7comm_ob_stop = -1;
static gint hf_s7comm_ob_strt_info = -1;
static gint hf_s7comm_ob_sw_flt = -1;
static gint hf_s7comm_ob_blk_type = -1;
static gint hf_s7comm_ob_flt_reg = -1;
static gint hf_s7comm_ob_flt_blk_num = -1;
static gint hf_s7comm_ob_prg_addr = -1;
static gint hf_s7comm_ob_mem_area = -1;
static gint hf_s7comm_ob_mem_addr = -1;

static gint hf_s7comm_diagdata_req_block_type = -1;
static gint hf_s7comm_diagdata_req_block_num = -1;
static gint hf_s7comm_diagdata_req_startaddr_awl = -1;
static gint hf_s7comm_diagdata_req_saz = -1;

/* Flags for requested registers in diagnostic data telegrams */
static gint hf_s7comm_diagdata_registerflag = -1;           /* Registerflags */
static gint hf_s7comm_diagdata_registerflag_stw = -1;       /* STW = Status word */
static gint hf_s7comm_diagdata_registerflag_accu1 = -1;     /* Accumulator 1 */
static gint hf_s7comm_diagdata_registerflag_accu2 = -1;     /* Accumulator 2 */
static gint hf_s7comm_diagdata_registerflag_ar1 = -1;       /* Addressregister 1 */
static gint hf_s7comm_diagdata_registerflag_ar2 = -1;       /* Addressregister 2 */
static gint hf_s7comm_diagdata_registerflag_db1 = -1;       /* Datablock register 1 */
static gint hf_s7comm_diagdata_registerflag_db2 = -1;       /* Datablock register 2 */
static gint ett_s7comm_diagdata_registerflag = -1;
static int * const s7comm_diagdata_registerflag_fields[] = {
    &hf_s7comm_diagdata_registerflag_stw,
    &hf_s7comm_diagdata_registerflag_accu1,
    &hf_s7comm_diagdata_registerflag_accu2,
    &hf_s7comm_diagdata_registerflag_ar1,
    &hf_s7comm_diagdata_registerflag_ar2,
    &hf_s7comm_diagdata_registerflag_db1,
    &hf_s7comm_diagdata_registerflag_db2,
    NULL
};

static expert_field ei_s7comm_data_blockcontrol_block_num_invalid = EI_INIT;
static expert_field ei_s7comm_ud_blockinfo_block_num_ascii_invalid = EI_INIT;

/* PI service name IDs. Index represents the index in pi_service_names */
typedef enum
{
    S7COMM_PI_UNKNOWN = 0,
    S7COMM_PI_INSE,
    S7COMM_PI_INS2,
    S7COMM_PI_DELE,
    S7COMM_PIP_PROGRAM,
    S7COMM_PI_MODU,
    S7COMM_PI_GARB,
    S7COMM_PI_N_LOGIN_,
    S7COMM_PI_N_LOGOUT,
    S7COMM_PI_N_CANCEL,
    S7COMM_PI_N_DASAVE,
    S7COMM_PI_N_DIGIOF,
    S7COMM_PI_N_DIGION,
    S7COMM_PI_N_DZERO_,
    S7COMM_PI_N_ENDEXT,
    S7COMM_PI_N_F_OPER,
    S7COMM_PI_N_OST_OF,
    S7COMM_PI_N_OST_ON,
    S7COMM_PI_N_SCALE_,
    S7COMM_PI_N_SETUFR,
    S7COMM_PI_N_STRTLK,
    S7COMM_PI_N_STRTUL,
    S7COMM_PI_N_TMRASS,
    S7COMM_PI_N_F_DELE,
    S7COMM_PI_N_EXTERN,
    S7COMM_PI_N_EXTMOD,
    S7COMM_PI_N_F_DELR,
    S7COMM_PI_N_F_XFER,
    S7COMM_PI_N_LOCKE_,
    S7COMM_PI_N_SELECT,
    S7COMM_PI_N_SRTEXT,
    S7COMM_PI_N_F_CLOS,
    S7COMM_PI_N_F_OPEN,
    S7COMM_PI_N_F_SEEK,
    S7COMM_PI_N_ASUP__,
    S7COMM_PI_N_CHEKDM,
    S7COMM_PI_N_CHKDNO,
    S7COMM_PI_N_CONFIG,
    S7COMM_PI_N_CRCEDN,
    S7COMM_PI_N_DELECE,
    S7COMM_PI_N_CREACE,
    S7COMM_PI_N_CREATO,
    S7COMM_PI_N_DELETO,
    S7COMM_PI_N_CRTOCE,
    S7COMM_PI_N_DELVAR,
    S7COMM_PI_N_F_COPY,
    S7COMM_PI_N_F_DMDA,
    S7COMM_PI_N_F_PROR,
    S7COMM_PI_N_F_PROT,
    S7COMM_PI_N_F_RENA,
    S7COMM_PI_N_FINDBL,
    S7COMM_PI_N_IBN_SS,
    S7COMM_PI_N_MMCSEM,
    S7COMM_PI_N_NCKMOD,
    S7COMM_PI_N_NEWPWD,
    S7COMM_PI_N_SEL_BL,
    S7COMM_PI_N_SETTST,
    S7COMM_PI_N_TMAWCO,
    S7COMM_PI_N_TMCRTC,
    S7COMM_PI_N_TMCRTO,
    S7COMM_PI_N_TMFDPL,
    S7COMM_PI_N_TMFPBP,
    S7COMM_PI_N_TMGETT,
    S7COMM_PI_N_TMMVTL,
    S7COMM_PI_N_TMPCIT,
    S7COMM_PI_N_TMPOSM,
    S7COMM_PI_N_TRESMO,
    S7COMM_PI_N_TSEARC
} pi_service_e;

/* Description for PI service names */
static const string_string pi_service_names[] = {
    { "UNKNOWN",                            "PI-Service is currently unknown" },
    { "_INSE",                              "PI-Service _INSE (Activates a PLC module)" },
    { "_INS2",                              "PI-Service _INS2 (Activates a PLC module)" },
    { "_DELE",                              "PI-Service _DELE (Removes module from the PLC's passive file system)" },
    { "P_PROGRAM",                          "PI-Service P_PROGRAM (PLC Start / Stop)" },
    { "_MODU",                              "PI-Service _MODU (PLC Copy Ram to Rom)" },
    { "_GARB",                              "PI-Service _GARB (Compress PLC memory)" },
    { "_N_LOGIN_",                          "PI-Service _N_LOGIN_ (Login)" },
    { "_N_LOGOUT",                          "PI-Service _N_LOGOUT (Logout)" },
    { "_N_CANCEL",                          "PI-Service _N_CANCEL (Cancels NC alarm)" },
    { "_N_DASAVE",                          "PI-Service _N_DASAVE (PI-Service for copying data from SRAM to FLASH)" },
    { "_N_DIGIOF",                          "PI-Service _N_DIGIOF (Turns off digitizing)" },
    { "_N_DIGION",                          "PI-Service _N_DIGION (Turns on digitizing)" },
    { "_N_DZERO_",                          "PI-Service _N_DZERO_ (Set all D nos. invalid for function \"unique D no.\")" },
    { "_N_ENDEXT",                          "PI-Service _N_ENDEXT ()" },
    { "_N_F_OPER",                          "PI-Service _N_F_OPER (Opens a file read-only)" },
    { "_N_OST_OF",                          "PI-Service _N_OST_OF (Overstore OFF)" },
    { "_N_OST_ON",                          "PI-Service _N_OST_ON (Overstore ON)" },
    { "_N_SCALE_",                          "PI-Service _N_SCALE_ (Unit of measurement setting (metric<->INCH))" },
    { "_N_SETUFR",                          "PI-Service _N_SETUFR (Activates user frame)" },
    { "_N_STRTLK",                          "PI-Service _N_STRTLK (The global start disable is set)" },
    { "_N_STRTUL",                          "PI-Service _N_STRTUL (The global start disable is reset)" },
    { "_N_TMRASS",                          "PI-Service _N_TMRASS (Resets the Active status)" },
    { "_N_F_DELE",                          "PI-Service _N_F_DELE (Deletes file)" },
    { "_N_EXTERN",                          "PI-Service _N_EXTERN (Selects external program for execution)" },
    { "_N_EXTMOD",                          "PI-Service _N_EXTMOD (Selects external program for execution)" },
    { "_N_F_DELR",                          "PI-Service _N_F_DELR (Delete file even without access rights)" },
    { "_N_F_XFER",                          "PI-Service _N_F_XFER (Selects file for uploading)" },
    { "_N_LOCKE_",                          "PI-Service _N_LOCKE_ (Locks the active file for editing)" },
    { "_N_SELECT",                          "PI-Service _N_SELECT (Selects program for execution)" },
    { "_N_SRTEXT",                          "PI-Service _N_SRTEXT (A file is being marked in /_N_EXT_DIR)" },
    { "_N_F_CLOS",                          "PI-Service _N_F_CLOS (Closes file)" },
    { "_N_F_OPEN",                          "PI-Service _N_F_OPEN (Opens file)" },
    { "_N_F_SEEK",                          "PI-Service _N_F_SEEK (Position the file search pointer)" },
    { "_N_ASUP__",                          "PI-Service _N_ASUP__ (Assigns interrupt)" },
    { "_N_CHEKDM",                          "PI-Service _N_CHEKDM (Start uniqueness check on D numbers)" },
    { "_N_CHKDNO",                          "PI-Service _N_CHKDNO (Check whether the tools have unique D numbers)" },
    { "_N_CONFIG",                          "PI-Service _N_CONFIG (Reconfigures machine data)" },
    { "_N_CRCEDN",                          "PI-Service _N_CRCEDN (Creates a cutting edge by specifying an edge no.)" },
    { "_N_DELECE",                          "PI-Service _N_DELECE (Deletes a cutting edge)" },
    { "_N_CREACE",                          "PI-Service _N_CREACE (Creates a cutting edge)" },
    { "_N_CREATO",                          "PI-Service _N_CREATO (Creates a tool)" },
    { "_N_DELETO",                          "PI-Service _N_DELETO (Deletes tool)" },
    { "_N_CRTOCE",                          "PI-Service _N_CRTOCE (Generate tool with specified edge number)" },
    { "_N_DELVAR",                          "PI-Service _N_DELVAR (Delete data block)" },
    { "_N_F_COPY",                          "PI-Service _N_F_COPY (Copies file within the NCK)" },
    { "_N_F_DMDA",                          "PI-Service _N_F_DMDA (Deletes MDA memory)" },
    { "_N_F_PROR",                          "PI-Service _N_F_PROR" },
    { "_N_F_PROT",                          "PI-Service _N_F_PROT (Assigns a protection level to a file)" },
    { "_N_F_RENA",                          "PI-Service _N_F_RENA (Renames file)" },
    { "_N_FINDBL",                          "PI-Service _N_FINDBL (Activates search)" },
    { "_N_IBN_SS",                          "PI-Service _N_IBN_SS (Sets the set-up switch)" },
    { "_N_MMCSEM",                          "PI-Service _N_MMCSEM (MMC-Semaphore)" },
    { "_N_NCKMOD",                          "PI-Service _N_NCKMOD (The mode in which the NCK will work is being set)" },
    { "_N_NEWPWD",                          "PI-Service _N_NEWPWD (New password)" },
    { "_N_SEL_BL",                          "PI-Service _N_SEL_BL (Selects a new block)" },
    { "_N_SETTST",                          "PI-Service _N_SETTST (Activate tools for replacement tool group)" },
    { "_N_TMAWCO",                          "PI-Service _N_TMAWCO (Set the active wear group in one magazine)" },
    { "_N_TMCRTC",                          "PI-Service _N_TMCRTC (Create tool with specified edge number)" },
    { "_N_TMCRTO",                          "PI-Service _N_TMCRTO (Creates tool in the tool management)" },
    { "_N_TMFDPL",                          "PI-Service _N_TMFDPL (Searches an empty place for loading)" },
    { "_N_TMFPBP",                          "PI-Service _N_TMFPBP (Searches for empty location)" },
    { "_N_TMGETT",                          "PI-Service _N_TMGETT (Determines T-number for specific toolID with Duplono)" },
    { "_N_TMMVTL",                          "PI-Service _N_TMMVTL (Loads or unloads a tool)" },
    { "_N_TMPCIT",                          "PI-Service _N_TMPCIT (Sets increment value of the piece counter)" },
    { "_N_TMPOSM",                          "PI-Service _N_TMPOSM (Positions a magazine or tool)" },
    { "_N_TRESMO",                          "PI-Service _N_TRESMO (Reset monitoring values)" },
    { "_N_TSEARC",                          "PI-Service _N_TSEARC (Complex search via search screenforms)" },
    { NULL,                                 NULL }
};

/* Function 0x28 (PI Start) */
static gint hf_s7comm_piservice_unknown1 = -1;   /* Unknown bytes */
static gint hf_s7comm_piservice_parameterblock = -1;
static gint hf_s7comm_piservice_parameterblock_len = -1;
static gint hf_s7comm_piservice_servicename = -1;

static gint ett_s7comm_piservice_parameterblock = -1;

static gint hf_s7comm_piservice_string_len = -1;
static gint hf_s7comm_pi_n_x_addressident = -1;
static gint hf_s7comm_pi_n_x_password = -1;
static gint hf_s7comm_pi_n_x_filename = -1;
static gint hf_s7comm_pi_n_x_editwindowname = -1;
static gint hf_s7comm_pi_n_x_seekpointer = -1;
static gint hf_s7comm_pi_n_x_windowsize = -1;
static gint hf_s7comm_pi_n_x_comparestring = -1;
static gint hf_s7comm_pi_n_x_skipcount = -1;
static gint hf_s7comm_pi_n_x_interruptnr = -1;
static gint hf_s7comm_pi_n_x_priority = -1;
static gint hf_s7comm_pi_n_x_liftfast = -1;
static gint hf_s7comm_pi_n_x_blsync = -1;
static gint hf_s7comm_pi_n_x_magnr = -1;
static gint hf_s7comm_pi_n_x_dnr = -1;
static gint hf_s7comm_pi_n_x_spindlenumber = -1;
static gint hf_s7comm_pi_n_x_wznr = -1;
static gint hf_s7comm_pi_n_x_class = -1;
static gint hf_s7comm_pi_n_x_tnr = -1;
static gint hf_s7comm_pi_n_x_toolnumber = -1;
static gint hf_s7comm_pi_n_x_cenumber = -1;
static gint hf_s7comm_pi_n_x_datablocknumber = -1;
static gint hf_s7comm_pi_n_x_firstcolumnnumber = -1;
static gint hf_s7comm_pi_n_x_lastcolumnnumber = -1;
static gint hf_s7comm_pi_n_x_firstrownumber = -1;
static gint hf_s7comm_pi_n_x_lastrownumber = -1;
static gint hf_s7comm_pi_n_x_direction = -1;
static gint hf_s7comm_pi_n_x_sourcefilename = -1;
static gint hf_s7comm_pi_n_x_destinationfilename = -1;
static gint hf_s7comm_pi_n_x_channelnumber = -1;
static gint hf_s7comm_pi_n_x_protection = -1;
static gint hf_s7comm_pi_n_x_oldfilename = -1;
static gint hf_s7comm_pi_n_x_newfilename = -1;
static gint hf_s7comm_pi_n_x_findmode = -1;
static gint hf_s7comm_pi_n_x_switch = -1;
static gint hf_s7comm_pi_n_x_functionnumber = -1;
static gint hf_s7comm_pi_n_x_semaphorvalue = -1;
static gint hf_s7comm_pi_n_x_onoff = -1;
static gint hf_s7comm_pi_n_x_mode = -1;
static gint hf_s7comm_pi_n_x_factor = -1;
static gint hf_s7comm_pi_n_x_passwordlevel = -1;
static gint hf_s7comm_pi_n_x_linenumber = -1;
static gint hf_s7comm_pi_n_x_weargroup = -1;
static gint hf_s7comm_pi_n_x_toolstatus = -1;
static gint hf_s7comm_pi_n_x_wearsearchstrat = -1;
static gint hf_s7comm_pi_n_x_toolid = -1;
static gint hf_s7comm_pi_n_x_duplonumber = -1;
static gint hf_s7comm_pi_n_x_edgenumber = -1;
static gint hf_s7comm_pi_n_x_placenr = -1;
static gint hf_s7comm_pi_n_x_placerefnr = -1;
static gint hf_s7comm_pi_n_x_magrefnr = -1;
static gint hf_s7comm_pi_n_x_magnrfrom = -1;
static gint hf_s7comm_pi_n_x_placenrfrom = -1;
static gint hf_s7comm_pi_n_x_magnrto = -1;
static gint hf_s7comm_pi_n_x_placenrto = -1;
static gint hf_s7comm_pi_n_x_halfplacesleft = -1;
static gint hf_s7comm_pi_n_x_halfplacesright = -1;
static gint hf_s7comm_pi_n_x_halfplacesup = -1;
static gint hf_s7comm_pi_n_x_halfplacesdown = -1;
static gint hf_s7comm_pi_n_x_placetype = -1;
static gint hf_s7comm_pi_n_x_searchdirection = -1;
static gint hf_s7comm_pi_n_x_toolname = -1;
static gint hf_s7comm_pi_n_x_placenrsource = -1;
static gint hf_s7comm_pi_n_x_magnrsource = -1;
static gint hf_s7comm_pi_n_x_placenrdestination = -1;
static gint hf_s7comm_pi_n_x_magnrdestination = -1;
static gint hf_s7comm_pi_n_x_incrementnumber = -1;
static gint hf_s7comm_pi_n_x_monitoringmode = -1;
static gint hf_s7comm_pi_n_x_kindofsearch = -1;

static gint hf_s7comm_data_plccontrol_argument = -1;        /* Argument, 2 Bytes as char */
static gint hf_s7comm_data_plccontrol_block_cnt = -1;       /* Number of blocks, 1 Byte as int */
static gint hf_s7comm_data_pi_inse_unknown = -1;
static gint hf_s7comm_data_plccontrol_part2_len = -1;       /* Length part 2 in bytes, 1 Byte as Int */

/* block control functions */
static gint hf_s7comm_data_blockcontrol_unknown1 = -1;      /* for all unknown bytes in blockcontrol */
static gint hf_s7comm_data_blockcontrol_errorcode = -1;     /* Error code 2 bytes as int, 0 is no error */
static gint hf_s7comm_data_blockcontrol_uploadid = -1;
static gint hf_s7comm_data_blockcontrol_file_ident = -1;    /* File identifier, as ASCII */
static gint hf_s7comm_data_blockcontrol_block_type = -1;    /* Block type, 2 Byte */
static gint hf_s7comm_data_blockcontrol_block_num = -1;     /* Block number, 5 Bytes, ASCII */
static gint hf_s7comm_data_blockcontrol_dest_filesys = -1;  /* Destination filesystem, 1 Byte, ASCII */
static gint hf_s7comm_data_blockcontrol_part2_len = -1;     /* Length part 2 in bytes, 1 Byte Int */
static gint hf_s7comm_data_blockcontrol_part2_unknown = -1; /* Unknown char, ASCII */
static gint hf_s7comm_data_blockcontrol_loadmem_len = -1;   /* Length load memory in bytes, ASCII */
static gint hf_s7comm_data_blockcontrol_mc7code_len = -1;   /* Length of MC7 code in bytes, ASCII */
static gint hf_s7comm_data_blockcontrol_filename_len = -1;
static gint hf_s7comm_data_blockcontrol_filename = -1;
static gint hf_s7comm_data_blockcontrol_upl_lenstring_len = -1;
static gint hf_s7comm_data_blockcontrol_upl_lenstring = -1;

static gint hf_s7comm_data_blockcontrol_functionstatus = -1;
static gint hf_s7comm_data_blockcontrol_functionstatus_more = -1;
static gint hf_s7comm_data_blockcontrol_functionstatus_error = -1;
static gint ett_s7comm_data_blockcontrol_status = -1;
static int * const s7comm_data_blockcontrol_status_fields[] = {
    &hf_s7comm_data_blockcontrol_functionstatus_more,
    &hf_s7comm_data_blockcontrol_functionstatus_error,
    NULL
};

static gint ett_s7comm_plcfilename = -1;
static gint hf_s7comm_data_ncprg_unackcount = -1;
static gint hf_s7comm_data_ncprg_filelength = -1;
static gint hf_s7comm_data_ncprg_filetime = -1;
static gint hf_s7comm_data_ncprg_filepath = -1;
static gint hf_s7comm_data_ncprg_filedata = -1;

/* Variable status */
static gint hf_s7comm_varstat_unknown = -1;                  /* Unknown byte(s), hex */
static gint hf_s7comm_varstat_item_count = -1;               /* Item count, 2 bytes, int */
static gint hf_s7comm_varstat_req_memory_area = -1;          /* Memory area, 1 byte, stringlist userdata_prog_varstat_area_names  */
static gint hf_s7comm_varstat_req_repetition_factor = -1;    /* Repetition factor, 1 byte as int */
static gint hf_s7comm_varstat_req_db_number = -1;            /* DB number, 2 bytes as int */
static gint hf_s7comm_varstat_req_startaddress = -1;         /* Startaddress, 2 bytes as int */
static gint hf_s7comm_varstat_req_bitpos = -1;

/* cyclic services */
static gint hf_s7comm_cycl_interval_timebase = -1;          /* Interval timebase, 1 byte, int */
static gint hf_s7comm_cycl_interval_time = -1;              /* Interval time, 1 byte, int */
static gint hf_s7comm_cycl_function = -1;
static gint hf_s7comm_cycl_jobid = -1;

/* Read record */
static gint hf_s7comm_rdrec_mlen = -1;                      /* Max. length in bytes of the data record data to be read */
static gint hf_s7comm_rdrec_index = -1;                     /* Data record number */
static gint hf_s7comm_rdrec_id = -1;                        /* Diagnostic address */
static gint hf_s7comm_rdrec_statuslen = -1;                 /* Length of optional status data */
static gint hf_s7comm_rdrec_statusdata = -1;                /* Optional status data */
static gint hf_s7comm_rdrec_recordlen = -1;                 /* Length of data record data read */
static gint hf_s7comm_rdrec_data = -1;                      /* The read data record */
static gint hf_s7comm_rdrec_reserved1 = -1;

/* PBC, Programmable Block Functions */
static gint hf_s7comm_pbc_unknown = -1;                     /* unknown, 1 byte */
static gint hf_s7comm_pbc_r_id = -1;                        /* Request ID R_ID, 4 bytes as hex */
static gint hf_s7comm_pbc_len = -1;

/* Alarm messages */
static gint hf_s7comm_cpu_alarm_message_item = -1;
static gint hf_s7comm_cpu_alarm_message_obj_item = -1;
static gint hf_s7comm_cpu_alarm_message_function = -1;
static gint hf_s7comm_cpu_alarm_message_nr_objects = -1;
static gint hf_s7comm_cpu_alarm_message_nr_add_values = -1;
static gint hf_s7comm_cpu_alarm_message_eventid = -1;
static gint hf_s7comm_cpu_alarm_message_timestamp_coming = -1;
static gint hf_s7comm_cpu_alarm_message_timestamp_going = -1;
static gint hf_s7comm_cpu_alarm_message_associated_value = -1;
static gint hf_s7comm_cpu_alarm_message_eventstate = -1;
static gint hf_s7comm_cpu_alarm_message_state = -1;
static gint hf_s7comm_cpu_alarm_message_ackstate_coming = -1;
static gint hf_s7comm_cpu_alarm_message_ackstate_going = -1;
static gint hf_s7comm_cpu_alarm_message_event_coming = -1;
static gint hf_s7comm_cpu_alarm_message_event_going = -1;
static gint hf_s7comm_cpu_alarm_message_event_lastchanged = -1;
static gint hf_s7comm_cpu_alarm_message_event_reserved = -1;
static gint hf_s7comm_cpu_alarm_message_scan_unknown1 = -1;
static gint hf_s7comm_cpu_alarm_message_scan_unknown2 = -1;

static gint hf_s7comm_cpu_alarm_message_signal_sig1 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig2 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig3 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig4 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig5 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig6 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig7 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig8 = -1;
static gint ett_s7comm_cpu_alarm_message_signal = -1;
static int * const s7comm_cpu_alarm_message_signal_fields[] = {
    &hf_s7comm_cpu_alarm_message_signal_sig1,
    &hf_s7comm_cpu_alarm_message_signal_sig2,
    &hf_s7comm_cpu_alarm_message_signal_sig3,
    &hf_s7comm_cpu_alarm_message_signal_sig4,
    &hf_s7comm_cpu_alarm_message_signal_sig5,
    &hf_s7comm_cpu_alarm_message_signal_sig6,
    &hf_s7comm_cpu_alarm_message_signal_sig7,
    &hf_s7comm_cpu_alarm_message_signal_sig8,
    NULL
};

static gint hf_s7comm_cpu_alarm_query_unknown1 = -1;
static gint hf_s7comm_cpu_alarm_query_querytype = -1;
static gint hf_s7comm_cpu_alarm_query_unknown2 = -1;
static gint hf_s7comm_cpu_alarm_query_alarmtype = -1;
static gint hf_s7comm_cpu_alarm_query_completelen = -1;
static gint hf_s7comm_cpu_alarm_query_datasetlen = -1;
static gint hf_s7comm_cpu_alarm_query_resunknown1 = -1;

/* CPU diagnostic messages */
static gint hf_s7comm_cpu_diag_msg_item = -1;
static gint hf_s7comm_cpu_diag_msg_eventid = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_class = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_ident_entleave = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_ident_diagbuf = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_ident_interr = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_ident_exterr = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_nr = -1;
static gint hf_s7comm_cpu_diag_msg_prioclass = -1;
static gint hf_s7comm_cpu_diag_msg_obnumber = -1;
static gint hf_s7comm_cpu_diag_msg_datid = -1;
static gint hf_s7comm_cpu_diag_msg_info1 = -1;
static gint hf_s7comm_cpu_diag_msg_info2 = -1;

static gint ett_s7comm_cpu_diag_msg_eventid = -1;
static int * const s7comm_cpu_diag_msg_eventid_fields[] = {
    &hf_s7comm_cpu_diag_msg_eventid_class,
    &hf_s7comm_cpu_diag_msg_eventid_ident_entleave,
    &hf_s7comm_cpu_diag_msg_eventid_ident_diagbuf,
    &hf_s7comm_cpu_diag_msg_eventid_ident_interr,
    &hf_s7comm_cpu_diag_msg_eventid_ident_exterr,
    &hf_s7comm_cpu_diag_msg_eventid_nr,
    NULL
};

static const true_false_string tfs_s7comm_cpu_diag_msg_eventid_ident_entleave = {
    "Event entering",
    "Event leaving"
};

static const value_string cpu_diag_msg_eventid_class_names[] = {
    { 0x01,                                 "Standard OB events" },
    { 0x02,                                 "Synchronous errors" },
    { 0x03,                                 "Asynchronous errors" },
    { 0x04,                                 "Mode transitions" },
    { 0x05,                                 "Run-time events" },
    { 0x06,                                 "Communication events" },
    { 0x07,                                 "Events for fail-safe and fault-tolerant systems" },
    { 0x08,                                 "Standardized diagnostic data on modules" },
    { 0x09,                                 "Predefined user events" },
    { 0x0a,                                 "Freely definable events" },
    { 0x0b,                                 "Freely definable events" },
    { 0x0c,                                 "Reserved" },
    { 0x0d,                                 "Reserved" },
    { 0x0e,                                 "Reserved" },
    { 0x0f,                                 "Events for modules other than CPUs" },
    { 0,                                    NULL }
};

static const value_string cpu_diag_eventid_fix_names[] = {
    { 0x113A,                               "Start request for cyclic interrupt OB with special handling (S7-300 only)" },
    { 0x1155,                               "Status alarm for PROFIBUS DP" },
    { 0x1156,                               "Update interrupt for PROFIBUS DP" },
    { 0x1157,                               "Manufacturer interrupt for PROFIBUS DP" },
    { 0x1158,                               "Status interrupt for PROFINET IO" },
    { 0x1159,                               "Update interrupt for PROFINET IO" },
    { 0x115A,                               "Manufacturer interrupt for PROFINET IO" },
    { 0x115B,                               "IO: Profile-specific interrupt" },
    { 0x116A,                               "Technology synchronization interrupt" },
    { 0x1381,                               "Request for manual warm restart" },
    { 0x1382,                               "Request for automatic warm restart" },
    { 0x1383,                               "Request for manual hot restart" },
    { 0x1384,                               "Request for automatic hot restart" },
    { 0x1385,                               "Request for manual cold restart" },
    { 0x1386,                               "Request for automatic cold restart" },
    { 0x1387,                               "Master CPU: request for manual cold restart" },
    { 0x1388,                               "Master CPU: request for automatic cold restart" },
    { 0x138A,                               "Master CPU: request for manual warm restart" },
    { 0x138B,                               "Master CPU: request for automatic warm restart" },
    { 0x138C,                               "Standby CPU: request for manual hot restart" },
    { 0x138D,                               "Standby CPU: request for automatic hot restart" },
    { 0x2521,                               "BCD conversion error" },
    { 0x2522,                               "Area length error when reading" },
    { 0x2523,                               "Area length error when writing" },
    { 0x2524,                               "Area error when reading" },
    { 0x2525,                               "Area error when writing" },
    { 0x2526,                               "Timer number error" },
    { 0x2527,                               "Counter number error" },
    { 0x2528,                               "Alignment error when reading" },
    { 0x2529,                               "Alignment error when writing" },
    { 0x2530,                               "Write error when accessing the DB" },
    { 0x2531,                               "Write error when accessing the DI" },
    { 0x2532,                               "Block number error when opening a DB" },
    { 0x2533,                               "Block number error when opening a DI" },
    { 0x2534,                               "Block number error when calling an FC" },
    { 0x2535,                               "Block number error when calling an FB" },
    { 0x253A,                               "DB not loaded" },
    { 0x253C,                               "FC not loaded" },
    { 0x253D,                               "SFC not loaded" },
    { 0x253E,                               "FB not loaded" },
    { 0x253F,                               "SFB not loaded" },
    { 0x2942,                               "I/O access error, reading" },
    { 0x2943,                               "I/O access error, writing" },
    { 0x3267,                               "End of module reconfiguration" },
    { 0x3367,                               "Start of module reconfiguration" },
    { 0x34A4,                               "PROFInet Interface DB can be addressed again" },
    { 0x3501,                               "Cycle time exceeded" },
    { 0x3502,                               "User interface (OB or FRB) request error" },
    { 0x3503,                               "Delay too long processing a priority class" },
    { 0x3505,                               "Time-of-day interrupt(s) skipped due to new clock setting" },
    { 0x3506,                               "Time-of-day interrupt(s) skipped when changing to RUN after HOLD" },
    { 0x3507,                               "Multiple OB request errors caused internal buffer overflow" },
    { 0x3508,                               "Synchronous cycle interrupt-timing error" },
    { 0x3509,                               "Interrupt loss due to excess interrupt load" },
    { 0x350A,                               "Resume RUN mode after CiR" },
    { 0x350B,                               "Technology synchronization interrupt - timing error" },
    { 0x3571,                               "Nesting depth too high in nesting levels" },
    { 0x3572,                               "Nesting depth for Master Control Relays too high" },
    { 0x3573,                               "Nesting depth too high after synchronous errors" },
    { 0x3574,                               "Nesting depth for block calls (U stack) too high" },
    { 0x3575,                               "Nesting depth for block calls (B stack) too high" },
    { 0x3576,                               "Local data allocation error" },
    { 0x3578,                               "Unknown instruction" },
    { 0x357A,                               "Jump instruction to target outside of the block" },
    { 0x3582,                               "Memory error detected and corrected by operating system" },
    { 0x3583,                               "Accumulation of detected and corrected memo errors" },
    { 0x3585,                               "Error in the PC operating system (only for LC RTX)" },
    { 0x3587,                               "Multi-bit memory error detected and corrected" },
    { 0x35A1,                               "User interface (OB or FRB) not found" },
    { 0x35A2,                               "OB not loaded (started by SFC or operating system due to configuration)" },
    { 0x35A3,                               "Error when operating system accesses a block" },
    { 0x35A4,                               "PROFInet Interface DB cannot be addressed" },
    { 0x35D2,                               "Diagnostic entries cannot be sent at present" },
    { 0x35D3,                               "Synchronization frames cannot be sent" },
    { 0x35D4,                               "Illegal time jump resulting from synchronization" },
    { 0x35D5,                               "Error adopting the synchronization time" },
    { 0x35E1,                               "Incorrect frame ID in GD" },
    { 0x35E2,                               "GD packet status cannot be entered in DB" },
    { 0x35E3,                               "Frame length error in GD" },
    { 0x35E4,                               "Illegal GD packet number received" },
    { 0x35E5,                               "Error accessing DB in communication SFBs for configured S7 connections" },
    { 0x35E6,                               "GD total status cannot be entered in DB" },
    { 0x3821,                               "BATTF: failure on at least one backup battery of the central rack, problem eliminated" },
    { 0x3822,                               "BAF: failure of backup voltage on central rack, problem eliminated" },
    { 0x3823,                               "24 volt supply failure on central rack, problem eliminated" },
    { 0x3825,                               "BATTF: failure on at least one backup battery of the redundant central rack, problem eliminated" },
    { 0x3826,                               "BAF: failure of backup voltage on redundant central rack, problem eliminated" },
    { 0x3827,                               "24 volt supply failure on redundant central rack, problem eliminated" },
    { 0x3831,                               "BATTF: failure of at least one backup battery of the expansion rack, problem eliminated" },
    { 0x3832,                               "BAF: failure of backup voltage on expansion rack, problem eliminated" },
    { 0x3833,                               "24 volt supply failure on at least one expansion rack, problem eliminated" },
    { 0x3842,                               "Module OK" },
    { 0x3854,                               "PROFINET IO interface submodule/submodule and matches the configured interface submodule/submodule" },
    { 0x3855,                               "PROFINET IO interface submodule/submodule inserted, but does not match the configured interface submodule/submodule" },
    { 0x3856,                               "PROFINET IO interface submodule/submodule inserted, but error in module parameter assignment" },
    { 0x3858,                               "PROFINET IO interface submodule access error corrected" },
    { 0x3861,                               "Module/interface module inserted, module type OK" },
    { 0x3863,                               "Module/interface module plugged in, but wrong module type" },
    { 0x3864,                               "Module/interface module plugged in, but causing problem (type ID unreadable)" },
    { 0x3865,                               "Module plugged in, but error in module parameter assignment" },
    { 0x3866,                               "Module can be addressed again, load voltage error removed" },
    { 0x3881,                               "Interface error leaving state" },
    { 0x3884,                               "Interface module plugged in" },
    { 0x38B3,                               "I/O access error when updating the process image input table" },
    { 0x38B4,                               "I/O access error when transferring the process image to the output modules" },
    { 0x38C1,                               "Expansion rack operational again (1 to 21), leaving state" },
    { 0x38C2,                               "Expansion rack operational again but mismatch between setpoint and actual configuration" },
    { 0x38C4,                               "Distributed I/Os: station failure, leaving state" },
    { 0x38C5,                               "Distributed I/Os: station fault, leaving state" },
    { 0x38C6,                               "Expansion rack operational again, but error(s) in module parameter assignment" },
    { 0x38C7,                               "DP: station operational again, but error(s) in module parameter assignment" },
    { 0x38C8,                               "DP: station operational again, but mismatch between setpoint and actual configuration" },
    { 0x38CB,                               "PROFINET IO station operational again" },
    { 0x38CC,                               "PROFINET IO station error corrected" },
    { 0x3921,                               "BATTF: failure on at least one backup battery of the central rack" },
    { 0x3922,                               "BAF: failure of backup voltage on central rack" },
    { 0x3923,                               "24 volt supply failure on central rack" },
    { 0x3925,                               "BATTF: failure on at least one backup battery of the redundant central rack" },
    { 0x3926,                               "BAF: failure of backup voltage on redundant central rack" },
    { 0x3927,                               "24 volt supply failure on redundant central rack" },
    { 0x3931,                               "BATTF: failure of at least one backup battery of the expansion rack" },
    { 0x3932,                               "BAF: failure of backup voltage on expansion rack" },
    { 0x3933,                               "24 volt supply failure on at least one expansion rack" },
    { 0x3942,                               "Module error" },
    { 0x3951,                               "PROFINET IO submodule removed" },
    { 0x3954,                               "PROFINET IO interface submodule/submodule removed" },
    { 0x3961,                               "Module/interface module removed, cannot be addressed" },
    { 0x3966,                               "Module cannot be addressed, load voltage error" },
    { 0x3968,                               "Module reconfiguration has ended with error" },
    { 0x3981,                               "Interface error entering state" },
    { 0x3984,                               "Interface module removed" },
    { 0x3986,                               "Performance of an H-Sync link negatively affected" },
    { 0x39B1,                               "I/O access error when updating the process image input table" },
    { 0x39B2,                               "I/O access error when transferring the process image to the output modules" },
    { 0x39B3,                               "I/O access error when updating the process image input table" },
    { 0x39B4,                               "I/O access error when transferring the process image to the output modules" },
    { 0x39C1,                               "Expansion rack failure (1 to 21), entering state" },
    { 0x39C3,                               "Distributed I/Os: master system failure entering state" },
    { 0x39C4,                               "Distributed I/Os: station failure, entering state" },
    { 0x39C5,                               "Distributed I/Os: station fault, entering state" },
    { 0x39CA,                               "PROFINET IO system failure" },
    { 0x39CB,                               "PROFINET IO station failure" },
    { 0x39CC,                               "PROFINET IO station error" },
    { 0x39CD,                               "PROFINET IO station operational again, but expected configuration does not match actual configuration" },
    { 0x39CE,                               "PROFINET IO station operational again, but error(s) in module parameter assignment" },
    { 0x42F3,                               "Checksum error detected and corrected by the operating system" },
    { 0x42F4,                               "Standby CPU: connection/update via SFC90 is locked in the master CPU" },
    { 0x4300,                               "Backed-up power on" },
    { 0x4301,                               "Mode transition from STOP to STARTUP" },
    { 0x4302,                               "Mode transition from STARTUP to RUN" },
    { 0x4303,                               "STOP caused by stop switch being activated" },
    { 0x4304,                               "STOP caused by PG STOP operation or by SFB 20 STOP" },
    { 0x4305,                               "HOLD: breakpoint reached" },
    { 0x4306,                               "HOLD: breakpoint exited" },
    { 0x4307,                               "Memory reset started by PG operation" },
    { 0x4308,                               "Memory reset started by switch setting" },
    { 0x4309,                               "Memory reset started automatically (power on not backed up)" },
    { 0x430A,                               "HOLD exited, transition to STOP" },
    { 0x430D,                               "STOP caused by other CPU in multicomputing" },
    { 0x430E,                               "Memory reset executed" },
    { 0x430F,                               "STOP on the module due to STOP on a CPU" },
    { 0x4318,                               "Start of CiR" },
    { 0x4319,                               "CiR completed" },
    { 0x4357,                               "Module watchdog started" },
    { 0x4358,                               "All modules are ready for operation" },
    { 0x43B0,                               "Firmware update was successful" },
    { 0x43B4,                               "Error in firmware fuse" },
    { 0x43B6,                               "Firmware updates canceled by redundant modules" },
    { 0x43D3,                               "STOP on standby CPU" },
    { 0x43DC,                               "Abort during link-up with switchover" },
    { 0x43DE,                               "Updating aborted due to monitoring time being exceeded during the n-th attempt, new update attempt initiated" },
    { 0x43DF,                               "Updating aborted for final time due to monitoring time being exceeded after completing the maximum amount of attempts. User intervention required" },
    { 0x43E0,                               "Change from solo mode after link-up" },
    { 0x43E1,                               "Change from link-up after updating" },
    { 0x43E2,                               "Change from updating to redundant mode" },
    { 0x43E3,                               "Master CPU: change from redundant mode to solo mode" },
    { 0x43E4,                               "Standby CPU: change from redundant mode after error-search mode" },
    { 0x43E5,                               "Standby CPU: change from error-search mode after link-up or STOP" },
    { 0x43E6,                               "Link-up aborted on the standby CPU" },
    { 0x43E7,                               "Updating aborted on the standby CPU" },
    { 0x43E8,                               "Standby CPU: change from link-up after startup" },
    { 0x43E9,                               "Standby CPU: change from startup after updating" },
    { 0x43F1,                               "Reserve-master switchover" },
    { 0x43F2,                               "Coupling of incompatible H-CPUs blocked by system program" },
    { 0x4510,                               "STOP violation of the CPU's data range" },
    { 0x4520,                               "DEFECTIVE: STOP not possible" },
    { 0x4521,                               "DEFECTIVE: failure of instruction processing processor" },
    { 0x4522,                               "DEFECTIVE: failure of clock chip" },
    { 0x4523,                               "DEFECTIVE: failure of clock pulse generator" },
    { 0x4524,                               "DEFECTIVE: failure of timer update function" },
    { 0x4525,                               "DEFECTIVE: failure of multicomputing synchronization" },
    { 0x4527,                               "DEFECTIVE: failure of I/O access monitoring" },
    { 0x4528,                               "DEFECTIVE: failure of scan time monitoring" },
    { 0x4530,                               "DEFECTIVE: memory test error in internal memory" },
    { 0x4532,                               "DEFECTIVE: failure of core resources" },
    { 0x4536,                               "DEFECTIVE: switch defective" },
    { 0x4540,                               "STOP: Memory expansion of the internal work memory has gaps. First memory expansion too small or missing" },
    { 0x4541,                               "STOP caused by priority class system" },
    { 0x4542,                               "STOP caused by object management system" },
    { 0x4543,                               "STOP caused by test functions" },
    { 0x4544,                               "STOP caused by diagnostic system" },
    { 0x4545,                               "STOP caused by communication system" },
    { 0x4546,                               "STOP caused by CPU memory management" },
    { 0x4547,                               "STOP caused by process image management" },
    { 0x4548,                               "STOP caused by I/O management" },
    { 0x454A,                               "STOP caused by configuration: an OB deselected with STEP 7 was being loaded into the CPU during STARTUP" },
    { 0x4550,                               "DEFECTIVE: internal system error" },
    { 0x4555,                               "No restart possible, monitoring time elapsed" },
    { 0x4556,                               "STOP: memory reset request from communication system / due to data inconsistency" },
    { 0x4562,                               "STOP caused by programming error (OB not loaded or not possible)" },
    { 0x4563,                               "STOP caused by I/O access error (OB not loaded or not possible)" },
    { 0x4567,                               "STOP caused by H event" },
    { 0x4568,                               "STOP caused by time error (OB not loaded or not possible)" },
    { 0x456A,                               "STOP caused by diagnostic interrupt (OB not loaded or not possible)" },
    { 0x456B,                               "STOP caused by removing/inserting module (OB not loaded or not possible)" },
    { 0x456C,                               "STOP caused by CPU hardware error (OB not loaded or not possible, or no FRB)" },
    { 0x456D,                               "STOP caused by program sequence error (OB not loaded or not possible)" },
    { 0x456E,                               "STOP caused by communication error (OB not loaded or not possible)" },
    { 0x456F,                               "STOP caused by rack failure OB (OB not loaded or not possible)" },
    { 0x4570,                               "STOP caused by process interrupt (OB not loaded or not possible)" },
    { 0x4571,                               "STOP caused by nesting stack error" },
    { 0x4572,                               "STOP caused by master control relay stack error" },
    { 0x4573,                               "STOP caused by exceeding the nesting depth for synchronous errors" },
    { 0x4574,                               "STOP caused by exceeding interrupt stack nesting depth in the priority class stack" },
    { 0x4575,                               "STOP caused by exceeding block stack nesting depth in the priority class stack" },
    { 0x4576,                               "STOP caused by error when allocating the local data" },
    { 0x4578,                               "STOP caused by unknown opcode" },
    { 0x457A,                               "STOP caused by code length error" },
    { 0x457B,                               "STOP caused by DB not being loaded on on-board I/Os" },
    { 0x457D,                               "Reset/clear request because the version of the internal interface to the integrated technology was changed" },
    { 0x457F,                               "STOP caused by STOP command" },
    { 0x4580,                               "STOP: back-up buffer contents inconsistent (no transition to RUN)" },
    { 0x4590,                               "STOP caused by overloading the internal functions" },
    { 0x45D5,                               "LINK-UP rejected due to mismatched CPU memory configuration of the sub-PLC" },
    { 0x45D6,                               "LINK-UP rejected due to mismatched system program of the sub-PLC" },
    { 0x45D8,                               "DEFECTIVE: hardware fault detected due to other error" },
    { 0x45D9,                               "STOP due to SYNC module error" },
    { 0x45DA,                               "STOP due to synchronization error between H CPUs" },
    { 0x45DD,                               "LINK-UP rejected due to running test or other online functions" },
    { 0x4926,                               "DEFECTIVE: failure of the watchdog for I/O access" },
    { 0x4931,                               "STOP or DEFECTIVE: memory test error in memory submodule" },
    { 0x4933,                               "Checksum error" },
    { 0x4934,                               "DEFECTIVE: memory not available" },
    { 0x4935,                               "DEFECTIVE: cancelled by watchdog/processor exceptions" },
    { 0x4949,                               "STOP caused by continuous hardware interrupt" },
    { 0x494D,                               "STOP caused by I/O error" },
    { 0x494E,                               "STOP caused by power failure" },
    { 0x494F,                               "STOP caused by configuration error" },
    { 0x4959,                               "One or more modules not ready for operation" },
    { 0x497C,                               "STOP caused by integrated technology" },
    { 0x49A0,                               "STOP caused by parameter assignment error or non-permissible variation of setpoint and actual extension: Start-up blocked" },
    { 0x49A1,                               "STOP caused by parameter assignment error: memory reset request" },
    { 0x49A2,                               "STOP caused by error in parameter modification: startup disabled" },
    { 0x49A3,                               "STOP caused by error in parameter modification: memory reset request" },
    { 0x49A4,                               "STOP: inconsistency in configuration data" },
    { 0x49A5,                               "STOP: distributed I/Os: inconsistency in the loaded configuration information" },
    { 0x49A6,                               "STOP: distributed I/Os: invalid configuration information" },
    { 0x49A7,                               "STOP: distributed I/Os: no configuration information" },
    { 0x49A8,                               "STOP: error indicated by the interface module for the distributed I/Os" },
    { 0x49B1,                               "Firmware update data incorrect" },
    { 0x49B2,                               "Firmware update: hardware version does not match firmware" },
    { 0x49B3,                               "Firmware update: module type does not match firmware" },
    { 0x49D0,                               "LINK-UP aborted due to violation of coordination rules" },
    { 0x49D1,                               "LINK-UP/UPDATE sequence aborted" },
    { 0x49D2,                               "Standby CPU changed to STOP due to STOP on the master CPU during link-up" },
    { 0x49D4,                               "STOP on a master, since partner CPU is also a master (link-up error)" },
    { 0x49D7,                               "LINK-UP rejected due to change in user program or in configuration" },
    { 0x510F,                               "A problem as occurred with WinLC. This problem has caused the CPU to go into STOP mode or has caused a fault in the CPU" },
    { 0x530D,                               "New startup information in the STOP mode" },
    { 0x5311,                               "Startup despite Not Ready message from module(s)" },
    { 0x5371,                               "Distributed I/Os: end of the synchronization with a DP master" },
    { 0x5380,                               "Diagnostic buffer entries of interrupt and asynchronous errors disabled" },
    { 0x5395,                               "Distributed I/Os: reset of a DP master" },
    { 0x53A2,                               "Download of technology firmware successful" },
    { 0x53A4,                               "Download of technology DB not successful" },
    { 0x53FF,                               "Reset to factory setting" },
    { 0x5445,                               "Start of System reconfiguration in RUN mode" },
    { 0x5481,                               "All licenses for runtime software are complete again" },
    { 0x5498,                               "No more inconsistency with DP master systems due to CiR" },
    { 0x5545,                               "Start of System reconfiguration in RUN mode" },
    { 0x5581,                               "One or several licenses for runtime software are missing" },
    { 0x558A,                               "Difference between the MLFB of the configured and inserted CPU" },
    { 0x558B,                               "Difference in the firmware version of the configured and inserted CPU" },
    { 0x5598,                               "Start of possible inconsistency with DP master systems due to CiR" },
    { 0x55A5,                               "Version conflict: internal interface with integrated technology" },
    { 0x55A6,                               "The maximum number of technology objects has been exceeded" },
    { 0x55A7,                               "A technology DB of this type is already present" },
    { 0x5879,                               "Diagnostic message from DP interface: EXTF LED off" },
    { 0x5960,                               "Parameter assignment error when switching" },
    { 0x5961,                               "Parameter assignment error" },
    { 0x5962,                               "Parameter assignment error preventing startup" },
    { 0x5963,                               "Parameter assignment error with memory reset request" },
    { 0x5966,                               "Parameter assignment error when switching" },
    { 0x5969,                               "Parameter assignment error with startup blocked" },
    { 0x596A,                               "PROFINET IO: IP address of an IO device already present" },
    { 0x596B,                               "IP address of an Ethernet interface already exists" },
    { 0x596C,                               "Name of an Ethernet interface already exists" },
    { 0x596D,                               "The existing network configuration does not mach the system requirements or configuration" },
    { 0x5979,                               "Diagnostic message from DP interface: EXTF LED on" },
    { 0x597C,                               "DP Global Control command failed or moved" },
    { 0x59A0,                               "The interrupt can not be associated in the CPU" },
    { 0x59A1,                               "Configuration error in the integrated technology" },
    { 0x59A3,                               "Error when downloading the integrated technology" },
    { 0x6253,                               "Firmware update: End of firmware download over the network" },
    { 0x6316,                               "Interface error when starting programmable controller" },
    { 0x6353,                               "Firmware update: Start of firmware download over the network" },
    { 0x6390,                               "Formatting of Micro Memory Card complete" },
    { 0x6500,                               "Connection ID exists twice on module" },
    { 0x6501,                               "Connection resources inadequate" },
    { 0x6502,                               "Error in the connection description" },
    { 0x6510,                               "CFB structure error detected in instance DB when evaluating EPROM" },
    { 0x6514,                               "GD packet number exists twice on the module" },
    { 0x6515,                               "Inconsistent length specifications in GD configuration information" },
    { 0x6521,                               "No memory submodule and no internal memory available" },
    { 0x6522,                               "Illegal memory submodule: replace submodule and reset memory" },
    { 0x6523,                               "Memory reset request due to error accessing submodule" },
    { 0x6524,                               "Memory reset request due to error in block header" },
    { 0x6526,                               "Memory reset request due to memory replacement" },
    { 0x6527,                               "Memory replaced, therefore restart not possible" },
    { 0x6528,                               "Object handling function in the STOP/HOLD mode, no restart possible" },
    { 0x6529,                               "No startup possible during the \"load user program\" function" },
    { 0x652A,                               "No startup because block exists twice in user memory" },
    { 0x652B,                               "No startup because block is too long for submodule - replace submodule" },
    { 0x652C,                               "No startup due to illegal OB on submodule" },
    { 0x6532,                               "No startup because illegal configuration information on submodule" },
    { 0x6533,                               "Memory reset request because of invalid submodule content" },
    { 0x6534,                               "No startup: block exists more than once on submodule" },
    { 0x6535,                               "No startup: not enough memory to transfer block from submodule" },
    { 0x6536,                               "No startup: submodule contains an illegal block number" },
    { 0x6537,                               "No startup: submodule contains a block with an illegal length" },
    { 0x6538,                               "Local data or write-protection ID (for DB) of a block illegal for CPU" },
    { 0x6539,                               "Illegal command in block (detected by compiler)" },
    { 0x653A,                               "Memory reset request because local OB data on submodule too short" },
    { 0x6543,                               "No startup: illegal block type" },
    { 0x6544,                               "No startup: attribute \"relevant for processing\" illegal" },
    { 0x6545,                               "Source language illegal" },
    { 0x6546,                               "Maximum amount of configuration information reached" },
    { 0x6547,                               "Parameter assignment error assigning parameters to modules (not on P bus, cancel download)" },
    { 0x6548,                               "Plausibility error during block check" },
    { 0x6549,                               "Structure error in block" },
    { 0x6550,                               "A block has an error in the CRC" },
    { 0x6551,                               "A block has no CRC" },
    { 0x6560,                               "SCAN overflow" },
    { 0x6805,                               "Resource problem on configured connections, eliminated" },
    { 0x6881,                               "Interface error leaving state" },
    { 0x6905,                               "Resource problem on configured connections" },
    { 0x6981,                               "Interface error entering state" },
    { 0x72A2,                               "Failure of a DP master or a DP master system" },
    { 0x72A3,                               "Redundancy restored on the DP slave" },
    { 0x72DB,                               "Safety program: safety mode disabled" },
    { 0x72E0,                               "Loss of redundancy in communication, problem eliminated" },
    { 0x7301,                               "Loss of redundancy (1 of 2) due to failure of a CPU" },
    { 0x7302,                               "Loss of redundancy (1 of 2) due to STOP on the standby triggered by user" },
    { 0x7303,                               "H system (1 of 2) changed to redundant mode" },
    { 0x7323,                               "Discrepancy found in operating system data" },
    { 0x7331,                               "Standby-master switchover due to master failure" },
    { 0x7333,                               "Standby-master switchover due to system modification during runtime" },
    { 0x7334,                               "Standby-master switchover due to communication error at the synchronization module" },
    { 0x7340,                               "Synchronization error in user program due to elapsed wait time" },
    { 0x7341,                               "Synchronization error in user program due to waiting at different synchronization points" },
    { 0x7342,                               "Synchronization error in operating system due to waiting at different synchronization points" },
    { 0x7343,                               "Synchronization error in operating system due to elapsed wait time" },
    { 0x7344,                               "Synchronization error in operating system due to incorrect data" },
    { 0x734A,                               "The \"Re-enable\" job triggered by SFC 90 \"H_CTRL\" was executed" },
    { 0x73A3,                               "Loss of redundancy on the DP slave" },
    { 0x73C1,                               "Update process canceled" },
    { 0x73C2,                               "Updating aborted due to monitoring time being exceeded during the n-th attempt (1 = n = max. possible number of update attempts after abort due to excessive monitoring time)" },
    { 0x73D8,                               "Safety mode disabled" },
    { 0x73DB,                               "Safety program: safety mode enabled" },
    { 0x73E0,                               "Loss of redundancy in communication" },
    { 0x74DD,                               "Safety program: Shutdown of a fail-save runtime group disabled" },
    { 0x74DE,                               "Safety program: Shutdown of the F program disabled" },
    { 0x74DF,                               "Start of F program initialization" },
    { 0x7520,                               "Error in RAM comparison" },
    { 0x7521,                               "Error in comparison of process image output value" },
    { 0x7522,                               "Error in comparison of memory bits, timers, or counters" },
    { 0x75D1,                               "Safety program: Internal CPU error" },
    { 0x75D2,                               "Safety program error: Cycle time time-out" },
    { 0x75D6,                               "Data corrupted in safety program prior to the output to F I/O" },
    { 0x75D7,                               "Data corrupted in safety program prior to the output to partner F-CPU" },
    { 0x75D9,                               "Invalid REAL number in a DB" },
    { 0x75DA,                               "Safety program: Error in safety data format" },
    { 0x75DC,                               "Runtime group, internal protocol error" },
    { 0x75DD,                               "Safety program: Shutdown of a fail-save runtime group enabled" },
    { 0x75DE,                               "Safety program: Shutdown of the F program enabled" },
    { 0x75DF,                               "End of F program initialization" },
    { 0x75E1,                               "Safety program: Error in FB \"F_PLK\" or \"F_PLK_O\" or \"F_CYC_CO\" or \"F_TEST\" or \"F_TESTC\"" },
    { 0x75E2,                               "Safety program: Area length error" },
    { 0x7852,                               "SYNC module inserted" },
    { 0x7855,                               "SYNC module eliminated" },
    { 0x78D3,                               "Communication error between PROFIsafe and F I/O" },
    { 0x78D4,                               "Error in safety relevant communication between F CPUs" },
    { 0x78D5,                               "Error in safety relevant communication between F CPUs" },
    { 0x78E3,                               "F-I/O device input channel depassivated" },
    { 0x78E4,                               "F-I/O device output channel depassivated" },
    { 0x78E5,                               "F-I/O device depassivated" },
    { 0x7934,                               "Standby-master switchover due to connection problem at the SYNC module" },
    { 0x7950,                               "Synchronization module missing" },
    { 0x7951,                               "Change at the SYNC module without Power On" },
    { 0x7952,                               "SYNC module removed" },
    { 0x7953,                               "Change at the SYNC-module without reset" },
    { 0x7954,                               "SYNC module: rack number assigned twice" },
    { 0x7955,                               "SYNC module error" },
    { 0x7956,                               "Illegal rack number set on SYNC module" },
    { 0x7960,                               "Redundant I/O: Time-out of discrepancy time at digital input, error is not yet localized" },
    { 0x7961,                               "Redundant I/O, digital input error: Signal change after expiration of the discrepancy time" },
    { 0x7962,                               "Redundant I/O: Digital input error" },
    { 0x796F,                               "Redundant I/O: The I/O was globally disabled" },
    { 0x7970,                               "Redundant I/O: Digital output error" },
    { 0x7980,                               "Redundant I/O: Time-out of discrepancy time at analog input" },
    { 0x7981,                               "Redundant I/O: Analog input error" },
    { 0x7990,                               "Redundant I/O: Analog output error" },
    { 0x79D3,                               "Communication error between PROFIsafe and F I/O" },
    { 0x79D4,                               "Error in safety relevant communication between F CPUs" },
    { 0x79D5,                               "Error in safety relevant communication between F CPUs" },
    { 0x79E3,                               "F-I/O device input channel passivated" },
    { 0x79E4,                               "F-I/O device output channel passivated" },
    { 0x79E5,                               "F-I/O device passivated" },
    { 0x79E6,                               "Inconsistent safety program" },
    { 0x79E7,                               "Simulation block (F system block) loaded" },
    { 0,                                    NULL }
};
static value_string_ext cpu_diag_eventid_fix_names_ext = VALUE_STRING_EXT_INIT(cpu_diag_eventid_fix_names);

static const value_string cpu_diag_eventid_0x8_0x9_names[] = {
    { 0x8000,                               "Module fault/OK" },
    { 0x8001,                               "Internal error" },
    { 0x8002,                               "External error" },
    { 0x8003,                               "Channel error" },
    { 0x8004,                               "No external auxiliary voltage" },
    { 0x8005,                               "No front connector" },
    { 0x8006,                               "No parameter assignment" },
    { 0x8007,                               "Incorrect parameters in module" },
    { 0x8030,                               "User submodule incorrect/not found" },
    { 0x8031,                               "Communication problem" },
    { 0x8032,                               "Operating mode: RUN/STOP (STOP: entering state, RUN: leaving state)" },
    { 0x8033,                               "Time monitoring responded (watchdog)" },
    { 0x8034,                               "Internal module power failure" },
    { 0x8035,                               "BATTF: battery exhausted" },
    { 0x8036,                               "Total backup failed" },
    { 0x8040,                               "Expansion rack failed" },
    { 0x8041,                               "Processor failure" },
    { 0x8042,                               "EPROM error" },
    { 0x8043,                               "RAM error" },
    { 0x8044,                               "ADC/DAC error" },
    { 0x8045,                               "Fuse blown" },
    { 0x8046,                               "Hardware interrupt lost Any" },
    { 0x8050,                               "Configuration/parameter assignment error" },
    { 0x8051,                               "Common mode error" },
    { 0x8052,                               "Short circuit to phase" },
    { 0x8053,                               "Short circuit to ground" },
    { 0x8054,                               "Wire break" },
    { 0x8055,                               "Reference channel error" },
    { 0x8056,                               "Below measuring range" },
    { 0x8057,                               "Above measuring range Analog input" },
    { 0x8060,                               "Configuration/parameter assignment error" },
    { 0x8061,                               "Common mode error" },
    { 0x8062,                               "Short circuit to phase" },
    { 0x8063,                               "Short circuit to ground" },
    { 0x8064,                               "Wire break" },
    { 0x8066,                               "No load voltage" },
    { 0x8070,                               "Configuration/parameter assignment error" },
    { 0x8071,                               "Chassis ground fault" },
    { 0x8072,                               "Short circuit to phase (sensor)" },
    { 0x8073,                               "Short circuit to ground (sensor)" },
    { 0x8074,                               "Wire break" },
    { 0x8075,                               "No sensor power supply Digital input" },
    { 0x8080,                               "Configuration/parameter assignment error" },
    { 0x8081,                               "Chassis ground fault" },
    { 0x8082,                               "Short circuit to phase" },
    { 0x8083,                               "Short circuit to ground" },
    { 0x8084,                               "Wire break" },
    { 0x8085,                               "Fuse tripped" },
    { 0x8086,                               "No load voltage" },
    { 0x8087,                               "Excess temperature Digital output" },
    { 0x80B0,                               "Counter module, signal A faulty" },
    { 0x80B1,                               "Counter module, signal B faulty" },
    { 0x80B2,                               "Counter module, signal N faulty" },
    { 0x80B3,                               "Counter module, incorrect value passed between the channels" },
    { 0x80B4,                               "Counter module, 5.2 V sensor supply faulty" },
    { 0x80B5,                               "Counter module, 24 V sensor supply faulty" },
    { 0x9001,                               "Automatic/Manual mode (coming=man,going=auto)" },
    { 0x9002,                               "OPEN/CLOSED, ON/OFF" },
    { 0x9003,                               "Manual command enable" },
    { 0x9004,                               "Unit protective command (OPEN/CLOSED)" },
    { 0x9005,                               "Process enable" },
    { 0x9006,                               "System protection command" },
    { 0x9007,                               "Process value monitoring responded" },
    { 0x9008,                               "Manipulated variable monitoring responded" },
    { 0x9009,                               "System deviation greater than permitted" },
    { 0x900A,                               "Limit position error" },
    { 0x900B,                               "Runtime error" },
    { 0x900C,                               "Command execution error (sequencer)" },
    { 0x900D,                               "Operating status running > OPEN" },
    { 0x900E,                               "Operating status running > CLOSED" },
    { 0x900F,                               "Command blocking" },
    { 0x9011,                               "Process status OPEN/ON" },
    { 0x9012,                               "Process status CLOSED/OFF" },
    { 0x9013,                               "Process status intermediate position" },
    { 0x9014,                               "Process status ON via AUTO" },
    { 0x9015,                               "Process status ON via manual" },
    { 0x9016,                               "Process status ON via protective command" },
    { 0x9017,                               "Process status OFF via AUTO" },
    { 0x9018,                               "Process status OFF via manual" },
    { 0x9019,                               "Process status OFF via protective command" },
    { 0x9021,                               "Function error on approach" },
    { 0x9022,                               "Function error on leaving" },
    { 0x9031,                               "Actuator (DE/WE) limit position OPEN" },
    { 0x9032,                               "Actuator (DE/WE) limit position not OPEN" },
    { 0x9033,                               "Actuator (DE/WE) limit position CLOSED" },
    { 0x9034,                               "Actuator (DE/WE) limit position not CLOSED" },
    { 0x9041,                               "Illegal status, tolerance time elapsed" },
    { 0x9042,                               "Illegal status, tolerance time not elapsed" },
    { 0x9043,                               "Interlock error, tolerance time = 0" },
    { 0x9044,                               "Interlock error, tolerance time > 0" },
    { 0x9045,                               "No reaction" },
    { 0x9046,                               "Final status exited illegally, tolerance time = 0" },
    { 0x9047,                               "Final status exited illegally, tolerance time > 0" },
    { 0x9050,                               "Upper limit of signal range USR" },
    { 0x9051,                               "Upper limit of measuring range UMR" },
    { 0x9052,                               "Lower limit of signal range LSR" },
    { 0x9053,                               "Lower limit of measuring range LMR" },
    { 0x9054,                               "Upper alarm limit UAL" },
    { 0x9055,                               "Upper warning limit UWL" },
    { 0x9056,                               "Upper tolerance limit UTL" },
    { 0x9057,                               "Lower tolerance limit LTL" },
    { 0x9058,                               "Lower warning limit LWL" },
    { 0x9059,                               "Lower alarm limit LAL" },
    { 0x9060,                               "GRAPH7 step entering/leaving" },
    { 0x9061,                               "GRAPH7 interlock error" },
    { 0x9062,                               "GRAPH7 execution error" },
    { 0x9063,                               "GRAPH7 error noted" },
    { 0x9064,                               "GRAPH7 error acknowledged" },
    { 0x9070,                               "Trend exceeded in positive direction" },
    { 0x9071,                               "Trend exceeded in negative direction" },
    { 0x9072,                               "No reaction" },
    { 0x9073,                               "Final state exited illegally" },
    { 0x9080,                               "Limit value exceeded, tolerance time = 0" },
    { 0x9081,                               "Limit value exceeded, tolerance time > 0" },
    { 0x9082,                               "Below limit value, tolerance time = 0" },
    { 0x9083,                               "Below limit value, tolerance time > 0" },
    { 0x9084,                               "Gradient exceeded, tolerance time = 0" },
    { 0x9085,                               "Gradient exceeded, tolerance time > 0" },
    { 0x9086,                               "Below gradient, tolerance time = 0" },
    { 0x9087,                               "Below gradient, tolerance time > 0" },
    { 0x9090,                               "User parameter assignment error entering/leaving" },
    { 0x90F0,                               "Overflow" },
    { 0x90F1,                               "Underflow" },
    { 0x90F2,                               "Division by 0" },
    { 0x90F3,                               "Illegal calculation operation" },
    { 0,                                    NULL }
};
static value_string_ext cpu_diag_eventid_0x8_0x9_names_ext = VALUE_STRING_EXT_INIT(cpu_diag_eventid_0x8_0x9_names);

/**************************************************************************
 * Type of alarmquery in alarm query request
 */
#define S7COMM_ALARM_MESSAGE_QUERYTYPE_BYALARMTYPE      1
#define S7COMM_ALARM_MESSAGE_QUERYTYPE_BYEVENTID        3

static const value_string alarm_message_querytype_names[] = {
    { S7COMM_ALARM_MESSAGE_QUERYTYPE_BYALARMTYPE,      "ByAlarmtype" },
    { S7COMM_ALARM_MESSAGE_QUERYTYPE_BYEVENTID,        "ByEventID" },
    { 0,                                                NULL }
};

/**************************************************************************
 * Alarmtype in alarm query
 */
#define S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_SCAN       1
#define S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_ALARM_8    2
#define S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_ALARM_S    4

static const value_string alarm_message_query_alarmtype_names[] = {
    { S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_SCAN,        "SCAN" },
    { S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_ALARM_8,     "ALARM_8" },
    { S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_ALARM_S,     "ALARM_S" },
    { 0,                                                NULL }
};

/* CPU message service */
static gint hf_s7comm_cpu_msgservice_subscribe_events = -1;
static gint hf_s7comm_cpu_msgservice_subscribe_events_modetrans = -1;
static gint hf_s7comm_cpu_msgservice_subscribe_events_system = -1;
static gint hf_s7comm_cpu_msgservice_subscribe_events_userdefined = -1;
static gint hf_s7comm_cpu_msgservice_subscribe_events_alarms = -1;
static gint ett_s7comm_cpu_msgservice_subscribe_events = -1;
static int * const s7comm_cpu_msgservice_subscribe_events_fields[] = {
    &hf_s7comm_cpu_msgservice_subscribe_events_modetrans,
    &hf_s7comm_cpu_msgservice_subscribe_events_system,
    &hf_s7comm_cpu_msgservice_subscribe_events_userdefined,
    &hf_s7comm_cpu_msgservice_subscribe_events_alarms,
    NULL
};
static gint hf_s7comm_cpu_msgservice_req_reserved1 = -1;
static gint hf_s7comm_cpu_msgservice_username = -1;
static gint hf_s7comm_cpu_msgservice_almtype = -1;
static gint hf_s7comm_cpu_msgservice_req_reserved2 = -1;
static gint hf_s7comm_cpu_msgservice_res_result = -1;
static gint hf_s7comm_cpu_msgservice_res_reserved1 = -1;
static gint hf_s7comm_cpu_msgservice_res_reserved2 = -1;
static gint hf_s7comm_cpu_msgservice_res_reserved3 = -1;

static const value_string cpu_msgservice_almtype_names[] = {
    { 0,                                    "SCAN_ABORT" },
    { 1,                                    "SCAN_INITIATE" },
    { 4,                                    "ALARM_ABORT" },
    { 5,                                    "ALARM_INITIATE" },
    { 8,                                    "ALARM_S_ABORT" },
    { 9,                                    "ALARM_S_INITIATE" },
    { 0,                                    NULL }
};

static gint hf_s7comm_modetrans_param_subfunc = -1;
static const value_string modetrans_param_subfunc_names[] = {
    { 0,                                    "STOP" },
    { 1,                                    "Warm Restart" },
    { 2,                                    "RUN" },
    { 3,                                    "Hot Restart" },
    { 4,                                    "HOLD" },
    { 6,                                    "Cold Restart" },
    { 9,                                    "RUN_R (H-System redundant)" },
    { 11,                                   "LINK-UP" },
    { 12,                                   "UPDATE" },
    { 0,                                    NULL }
};

/* These fields used when reassembling S7COMM fragments */
static gint hf_s7comm_fragments = -1;
static gint hf_s7comm_fragment = -1;
static gint hf_s7comm_fragment_overlap = -1;
static gint hf_s7comm_fragment_overlap_conflict = -1;
static gint hf_s7comm_fragment_multiple_tails = -1;
static gint hf_s7comm_fragment_too_long_fragment = -1;
static gint hf_s7comm_fragment_error = -1;
static gint hf_s7comm_fragment_count = -1;
static gint hf_s7comm_reassembled_in = -1;
static gint hf_s7comm_reassembled_length = -1;
static gint ett_s7comm_fragment = -1;
static gint ett_s7comm_fragments = -1;

static const fragment_items s7comm_frag_items = {
    /* Fragment subtrees */
    &ett_s7comm_fragment,
    &ett_s7comm_fragments,
    /* Fragment fields */
    &hf_s7comm_fragments,
    &hf_s7comm_fragment,
    &hf_s7comm_fragment_overlap,
    &hf_s7comm_fragment_overlap_conflict,
    &hf_s7comm_fragment_multiple_tails,
    &hf_s7comm_fragment_too_long_fragment,
    &hf_s7comm_fragment_error,
    &hf_s7comm_fragment_count,
    /* Reassembled in field */
    &hf_s7comm_reassembled_in,
    /* Reassembled length field */
    &hf_s7comm_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "S7COMM fragments"
};

static reassembly_table s7comm_reassembly_table;

/* These are the ids of the subtrees that we are creating */
static gint ett_s7comm = -1;                                        /* S7 communication tree, parent of all other subtree */
static gint ett_s7comm_header = -1;                                 /* Subtree for header block */
static gint ett_s7comm_param = -1;                                  /* Subtree for parameter block */
static gint ett_s7comm_param_item = -1;                             /* Subtree for items in parameter block */
static gint ett_s7comm_param_subitem = -1;                          /* Subtree for subitems under items in parameter block */
static gint ett_s7comm_data = -1;                                   /* Subtree for data block */
static gint ett_s7comm_data_item = -1;                              /* Subtree for an item in data block */
static gint ett_s7comm_item_address = -1;                           /* Subtree for an address (byte/bit) */
static gint ett_s7comm_cpu_alarm_message = -1;                      /* Subtree for an alarm message */
static gint ett_s7comm_cpu_alarm_message_object = -1;               /* Subtree for an alarm message block*/
static gint ett_s7comm_cpu_alarm_message_timestamp = -1;            /* Subtree for an alarm message timestamp */
static gint ett_s7comm_cpu_alarm_message_associated_value = -1;     /* Subtree for an alarm message associated value */
static gint ett_s7comm_cpu_diag_msg = -1;                           /* Subtree for a CPU diagnostic message */
static gint ett_s7comm_prog_parameter = -1;
static gint ett_s7comm_prog_data = -1;

static const char mon_names[][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/*******************************************************************************************************
 *
 * Converts a siemens special timestamp to a string of 25+1 bytes length (e.g. "Apr 15, 2009 12:49:30.520").
 * The timestamp is 6 bytes long, one word is the number of days since 1.1.1984, and 4 bytes milliseconds of the day
 *
 *******************************************************************************************************/
static void
s7comm_get_timestring_from_s7time(tvbuff_t *tvb, guint offset, char *str, gint max)
{
    guint16 days;
    guint32 day_msec;
    struct tm *mt;
    time_t t;

    day_msec = tvb_get_ntohl(tvb, offset);
    days = tvb_get_ntohs(tvb, offset + 4);

    t = 441763200L;             /* 1.1.1984 00:00:00 */
    t += (guint32)days * (24*60*60);
    t += day_msec / 1000;
    mt = gmtime(&t);
    str[0] = '\0';
    if (mt != NULL) {
        g_snprintf(str, max, "%s %2d, %d %02d:%02d:%02d.%03d", mon_names[mt->tm_mon], mt->tm_mday,
            mt->tm_year + 1900, mt->tm_hour, mt->tm_min, mt->tm_sec, day_msec % 1000);
    }
}

/*******************************************************************************************************
 *
 * Helper for time functions
 * Get int from bcd
 *
 *******************************************************************************************************/
static guint8
s7comm_guint8_from_bcd(guint8 i)
{
    return 10 * (i /16) + (i % 16);
}

/*******************************************************************************************************
 *
 * Helper for time functions
 * Add a BCD coded timestamp (10/8 Bytes length) to tree
 *
 *******************************************************************************************************/
static guint32
s7comm_add_timestamp_to_tree(tvbuff_t *tvb,
                             proto_tree *tree,
                             guint32 offset,
                             gboolean append_text,
                             gboolean has_ten_bytes)          /* if this is false the [0] reserved and [1] year bytes are missing */
{
    guint8 timestamp[10];
    guint8 i;
    guint8 tmp;
    guint8 year_org;
    guint16 msec;
    nstime_t tv;
    proto_item *item = NULL;
    proto_item *time_tree = NULL;
    struct tm mt;
    int timestamp_size = 10;

    if (has_ten_bytes) {
        /* The low nibble of byte 10 is weekday, the high nibble the LSD of msec */
        for (i = 0; i < 9; i++) {
            timestamp[i] = s7comm_guint8_from_bcd(tvb_get_guint8(tvb, offset + i));
        }
        tmp = tvb_get_guint8(tvb, offset + 9) >> 4;
    } else {
        /* this is a 8 byte timestamp, where the reserved and the year byte is missing */
        timestamp_size = 8;
        timestamp[0] = 0;
        timestamp[1] = 19;  /* start with 19.., will be corrected later */
        for (i = 0; i < 7; i++) {
            timestamp[i + 2] = s7comm_guint8_from_bcd(tvb_get_guint8(tvb, offset + i));
        }
        tmp = tvb_get_guint8(tvb, offset + 7) >> 4;
    }
    timestamp[9] = s7comm_guint8_from_bcd(tmp);

    msec = (guint16)timestamp[8] * 10 + (guint16)timestamp[9];
    year_org = timestamp[1];
    /* year special: ignore the first byte, since some cpus give 1914 for 2014
     * if second byte is below 89, it's 2000..2089, if over 90 it's 1990..1999
     */
    if (timestamp[2] < 89) {
        timestamp[1] = 20;
    }
    /* convert time to nstime_t */
    mt.tm_year = (timestamp[1] * 100 + timestamp[2]) - 1900;
    mt.tm_mon = timestamp[3] - 1;
    mt.tm_mday = timestamp[4];
    mt.tm_hour = timestamp[5];
    mt.tm_min = timestamp[6];
    mt.tm_sec = timestamp[7];
    mt.tm_isdst = -1;
    tv.secs = mktime(&mt);
    tv.nsecs = msec * 1000000;
    item = proto_tree_add_time_format(tree, hf_s7comm_data_ts, tvb, offset, timestamp_size, &tv,
        "S7 Timestamp: %s %2d, %d %02d:%02d:%02d.%03d", mon_names[mt.tm_mon], mt.tm_mday,
        mt.tm_year + 1900, mt.tm_hour, mt.tm_min, mt.tm_sec,
        msec);
    time_tree = proto_item_add_subtree(item, ett_s7comm_data_item);

    /* timefunction: s7 timestamp */
    if (has_ten_bytes) {
        proto_tree_add_uint(time_tree, hf_s7comm_data_ts_reserved, tvb, offset, 1, timestamp[0]);
        offset += 1;
        proto_tree_add_uint(time_tree, hf_s7comm_data_ts_year1, tvb, offset, 1, year_org);
        offset += 1;
    }
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_year2, tvb, offset, 1, timestamp[2]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_month, tvb, offset, 1, timestamp[3]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_day, tvb, offset, 1, timestamp[4]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_hour, tvb, offset, 1, timestamp[5]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_minute, tvb, offset, 1, timestamp[6]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_second, tvb, offset, 1, timestamp[7]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_millisecond, tvb, offset, 2, msec);
    proto_tree_add_item(time_tree, hf_s7comm_data_ts_weekday, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (append_text == TRUE) {
        proto_item_append_text(tree, "(Timestamp: %s %2d, %d %02d:%02d:%02d.%03d)", mon_names[mt.tm_mon], mt.tm_mday,
            mt.tm_year + 1900, mt.tm_hour, mt.tm_min, mt.tm_sec,
            msec);
    }
    return offset;
}

/*******************************************************************************************************
 *
 * Generate a comma separated string for registerflags
 *
 *******************************************************************************************************/
static void
make_registerflag_string(gchar *str, guint8 flags, gint max)
{
    g_strlcpy(str, "", max);
    if (flags & 0x01) g_strlcat(str, "STW, ", max);
    if (flags & 0x02) g_strlcat(str, "ACCU1, ", max);
    if (flags & 0x04) g_strlcat(str, "ACCU2, ", max);
    if (flags & 0x08) g_strlcat(str, "AR1, ", max);
    if (flags & 0x10) g_strlcat(str, "AR2, ", max);
    if (flags & 0x20) g_strlcat(str, "DB1, ", max);
    if (flags & 0x40) g_strlcat(str, "DB2, ", max);
    if (strlen(str) > 2)
        str[strlen(str) - 2 ] = '\0';
}

/*******************************************************************************************************
 *
 * Addressdefinition for Syntax ID S7-ANY (Step 7 Classic 300/400 or 1200/1500 not optimized)
 * type == 0x12, length == 10, syntax-ID == 0x10
 *
 *******************************************************************************************************/
static guint32
s7comm_syntaxid_s7any(tvbuff_t *tvb,
                      guint32 offset,
                      proto_tree *tree)
{
    guint32 t_size = 0;
    guint32 len = 0;
    guint32 db = 0;
    guint32 area = 0;
    guint32 a_address = 0;
    guint32 bytepos = 0;
    guint32 bitpos = 0;
    proto_item *address_item = NULL;
    proto_tree *address_item_tree = NULL;

    /* Transport size, 1 byte */
    proto_tree_add_item_ret_uint(tree, hf_s7comm_item_transport_size, tvb, offset, 1, ENC_BIG_ENDIAN, &t_size);
    offset += 1;
    /* Special handling of data record */
    area = tvb_get_guint8(tvb, offset + 4);     /* peek area first */
    if (area == S7COMM_AREA_DATARECORD) {
        /* MLEN, 2 bytes */
        proto_tree_add_item_ret_uint(tree, hf_s7comm_rdrec_mlen, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;
        /* INDEX, 2 bytes */
        proto_tree_add_item_ret_uint(tree, hf_s7comm_rdrec_index, tvb, offset, 2, ENC_BIG_ENDIAN, &db);
        offset += 2;
        /* Area, 1 byte */
        proto_tree_add_uint(tree, hf_s7comm_item_area, tvb, offset, 1, area);
        offset += 1;
        /* ID, 3 bytes */
        proto_tree_add_item_ret_uint(tree, hf_s7comm_rdrec_id, tvb, offset, 3, ENC_BIG_ENDIAN, &a_address);
        offset += 3;
        proto_item_append_text(tree, " (RECORD MLEN=%d INDEX=0x%04x ID=%d)", len, db, a_address);
    } else {
        /* Length, 2 bytes */
        proto_tree_add_item_ret_uint(tree, hf_s7comm_item_length, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;
        /* DB number, 2 bytes */
        proto_tree_add_item_ret_uint(tree, hf_s7comm_item_db, tvb, offset, 2, ENC_BIG_ENDIAN, &db);
        offset += 2;
        /* Area, 1 byte */
        proto_tree_add_uint(tree, hf_s7comm_item_area, tvb, offset, 1, area);
        offset += 1;
        /* Address, 3 bytes */
        address_item = proto_tree_add_item_ret_uint(tree, hf_s7comm_item_address, tvb, offset, 3, ENC_BIG_ENDIAN, &a_address);
        address_item_tree = proto_item_add_subtree(address_item, ett_s7comm_item_address);
        bytepos = a_address / 8;
        bitpos = a_address % 8;
        /* build a full address to show item data directly beside the item */
        proto_item_append_text(tree, " (%s", val_to_str(area, item_areanames_short, "unknown area 0x%02x"));
        if (area == S7COMM_AREA_TIMER || area == S7COMM_AREA_COUNTER) {
            proto_item_append_text(tree, " %d)", a_address);
            proto_tree_add_uint(address_item_tree, hf_s7comm_item_address_nr, tvb, offset, 3, a_address);
        } else {
            proto_tree_add_uint(address_item_tree, hf_s7comm_item_address_byte, tvb, offset, 3, a_address);
            proto_tree_add_uint(address_item_tree, hf_s7comm_item_address_bit, tvb, offset, 3, a_address);
            if (area == S7COMM_AREA_DB) {
                proto_item_append_text(tree, " %d.DBX", db);
            } else if (area == S7COMM_AREA_DI) {
                proto_item_append_text(tree, " %d.DIX", db);
            }
            proto_item_append_text(tree, " %d.%d %s %d)",
                bytepos, bitpos, val_to_str(t_size, item_transportsizenames, "Unknown transport size: 0x%02x"), len);
        }
        offset += 3;
    }
    return offset;
}
/*******************************************************************************************************
 *
 * Addressdefinition to read a DB area (S7-400 special)
 * type == 0x12, length >= 7, syntax-ID == 0xb0
 *
 *******************************************************************************************************/
static guint32
s7comm_syntaxid_dbread(tvbuff_t *tvb,
                       guint32 offset,
                       proto_tree *tree)
{
    guint32 number_of_areas = 0;
    guint32 len = 0;
    guint32 db = 0;
    guint32 bytepos = 0;
    guint32 i;
    proto_item *sub_item = NULL;
    proto_tree *sub_item_tree = NULL;

    proto_tree_add_item_ret_uint(tree, hf_s7comm_item_dbread_numareas, tvb, offset, 1, ENC_BIG_ENDIAN, &number_of_areas);
    proto_item_append_text(tree, " (%d Data-Areas of Syntax-Id DBREAD)", number_of_areas);
    offset += 1;
    for (i = 0; i < number_of_areas; i++) {
        sub_item = proto_tree_add_item(tree, hf_s7comm_param_subitem, tvb, offset, 5, ENC_NA);
        sub_item_tree = proto_item_add_subtree(sub_item, ett_s7comm_param_subitem);
        proto_tree_add_item_ret_uint(sub_item_tree, hf_s7comm_item_dbread_length, tvb, offset, 1, ENC_BIG_ENDIAN, &len);
        offset += 1;
        proto_tree_add_item_ret_uint(sub_item_tree, hf_s7comm_item_dbread_db, tvb, offset, 2, ENC_BIG_ENDIAN, &db);
        offset += 2;
        proto_tree_add_item_ret_uint(sub_item_tree, hf_s7comm_item_dbread_startadr, tvb, offset, 2, ENC_BIG_ENDIAN, &bytepos);
        offset += 2;
        /* Display in pseudo S7-Any Format */
        proto_item_append_text(sub_item, " [%d]: (DB%d.DBB %d BYTE %d)", i+1, db, bytepos, len);
    }
    return offset;
}

/*******************************************************************************************************
 *
 * Addressdefinition for TIA S7 1200 symbolic address mode
 * type == 0x12, length >= 14, syntax-ID == 0xb2
 *
 *******************************************************************************************************/
static guint32
s7comm_syntaxid_1200sym(tvbuff_t *tvb,
                        guint32 offset,
                        proto_tree *tree,
                        guint8 var_spec_length)
{
    guint32 tia_var_area1 = 0;
    guint32 tia_var_area2 = 0;
    guint8 tia_lid_flags = 0;
    guint32 tia_value = 0;
    guint16 i;
    proto_item *sub_item = NULL;
    proto_tree *sub_item_tree = NULL;

    proto_item_append_text(tree, " 1200 symbolic address");
    /* first byte in address seems always to be 0xff */
    proto_tree_add_item(tree, hf_s7comm_tia1200_item_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* When Bytes 2/3 == 0, then Bytes 4/5 defines the area as known from classic 300/400 address mode.
     * When Bytes 2/3 == 0x8a0e then Bytes 4/5 are containing the DB number.
     */
    proto_tree_add_item_ret_uint(tree, hf_s7comm_tia1200_item_area1, tvb, offset, 2, ENC_BIG_ENDIAN, &tia_var_area1);
    offset += 2;
    tia_var_area2 = tvb_get_ntohs(tvb, offset);
    if (tia_var_area1 == S7COMM_TIA1200_VAR_ITEM_AREA1_IQMCT) {
        proto_tree_add_uint(tree, hf_s7comm_tia1200_item_area2, tvb, offset, 2, tia_var_area2);
        proto_item_append_text(tree, " - Accessing %s", val_to_str(tia_var_area2, tia1200_var_item_area2_names, "Unknown IQMCT Area: 0x%04x"));
        offset += 2;
    } else if (tia_var_area1 == S7COMM_TIA1200_VAR_ITEM_AREA1_DB) {
        proto_tree_add_uint(tree, hf_s7comm_tia1200_item_dbnumber, tvb, offset, 2, tia_var_area2);
        proto_item_append_text(tree, " - Accessing DB%d", tia_var_area2);
        offset += 2;
    } else {
        /* for current unknown areas */
        proto_tree_add_uint(tree, hf_s7comm_tia1200_item_area2unknown, tvb, offset, 2, tia_var_area2);
        proto_item_append_text(tree, " - Unknown area specification");
        offset += 2;
    }
    proto_tree_add_item(tree, hf_s7comm_tia1200_item_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    for (i = 0; i < (var_spec_length - 10) / 4; i++) {
        sub_item = proto_tree_add_item(tree, hf_s7comm_tia1200_substructure_item, tvb, offset, 4, ENC_NA);
        sub_item_tree = proto_item_add_subtree(sub_item, ett_s7comm_param_subitem);
        tia_lid_flags = tvb_get_guint8(tvb, offset) >> 4;
        proto_tree_add_item(sub_item_tree, hf_s7comm_tia1200_var_lid_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        tia_value = tvb_get_ntohl(tvb, offset) & 0x0fffffff;
        proto_item_append_text(sub_item, " [%d]: %s, Value: %u", i + 1,
            val_to_str(tia_lid_flags, tia1200_var_lid_flag_names, "Unknown flags: 0x%02x"),
            tia_value
        );
        proto_tree_add_item(sub_item_tree, hf_s7comm_tia1200_item_value, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * Addressdefinition for Sinumeric NCK access
 * type == 0x12, length == 8, syntax-ID == 0x82 or == 0x83 or == 0x84
 *
 *******************************************************************************************************/
static guint32
s7comm_syntaxid_nck(tvbuff_t *tvb,
                    guint32 offset,
                    proto_tree *tree)
{
    guint32 area = 0;
    guint32 nck_area = 0;
    guint32 nck_unit = 0;
    guint32 nck_column = 0;
    guint32 nck_line = 0;
    guint32 nck_module = 0;

    proto_tree_add_item_ret_uint(tree, hf_s7comm_item_nck_areaunit, tvb, offset, 1, ENC_BIG_ENDIAN, &area);
    nck_area = area >> 5;
    nck_unit = area & 0x1f;
    proto_tree_add_item(tree, hf_s7comm_item_nck_area, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_s7comm_item_nck_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_s7comm_item_nck_column, tvb, offset, 2, ENC_BIG_ENDIAN, &nck_column);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_s7comm_item_nck_line, tvb, offset, 2, ENC_BIG_ENDIAN, &nck_line);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_s7comm_item_nck_module, tvb, offset, 1, ENC_BIG_ENDIAN, &nck_module);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_item_nck_linecount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_item_append_text(tree, " (NCK Area:%d Unit:%d Column:%d Line:%d Module:0x%02x)",
        nck_area, nck_unit, nck_column, nck_line, nck_module);
    return offset;
}

/*******************************************************************************************************
 *
 * Addressdefinition for accessing Multimaster / Sinamics frequency convertes via routing from DriveES.
 * type == 0x12, length == 10, syntax-ID == 0x82
 *
 *******************************************************************************************************/
static guint32
s7comm_syntaxid_driveesany(tvbuff_t *tvb,
                           guint32 offset,
                           proto_tree *tree)
{
    guint32 nr = 0;
    guint32 idx = 0;

    proto_tree_add_item(tree, hf_s7comm_item_driveesany_unknown1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_item_driveesany_unknown2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_item_driveesany_unknown3, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_s7comm_item_driveesany_parameter_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &nr);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_s7comm_item_driveesany_parameter_idx, tvb, offset, 2, ENC_BIG_ENDIAN, &idx);
    offset += 2;
    proto_item_append_text(tree, " (DriveES Parameter: %d[%d])", nr, idx);
    return offset;
}

/*******************************************************************************************************
 *
 * Dissect the parameter details of a read/write request (Items)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_param_item(tvbuff_t *tvb,
                         guint32 offset,
                         proto_tree *sub_tree,
                         guint8 item_no)
{
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;
    guint8 var_spec_type = 0;
    guint8 var_spec_length = 0;
    guint8 var_spec_syntax_id = 0;

    var_spec_type = tvb_get_guint8(tvb, offset);
    var_spec_length = tvb_get_guint8(tvb, offset + 1);
    var_spec_syntax_id = tvb_get_guint8(tvb, offset + 2);

    /* Insert a new tree for every item */
    item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, var_spec_length + 2, ENC_NA);
    item_tree = proto_item_add_subtree(item, ett_s7comm_param_item);
    proto_item_append_text(item, " [%d]:", item_no + 1);

    /* Item head, constant 3 bytes */
    proto_tree_add_item(item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_S7ANY) {
        /* Step 7 Classic 300 400 */
        offset = s7comm_syntaxid_s7any(tvb, offset, item_tree);
    } else if (var_spec_type == 0x12 && var_spec_length >= 7 && var_spec_syntax_id == S7COMM_SYNTAXID_DBREAD) {
        /* S7-400 special address mode (kind of cyclic read) */
        offset = s7comm_syntaxid_dbread(tvb, offset, item_tree);
    } else if (var_spec_type == 0x12 && var_spec_length >= 14 && var_spec_syntax_id == S7COMM_SYNTAXID_1200SYM) {
        /* TIA S7 1200 symbolic address mode */
        offset = s7comm_syntaxid_1200sym(tvb, offset, item_tree, var_spec_length);
    } else if (var_spec_type == 0x12 && var_spec_length == 8
               && ((var_spec_syntax_id == S7COMM_SYNTAXID_NCK)
                   || (var_spec_syntax_id == S7COMM_SYNTAXID_NCK_METRIC)
                   || (var_spec_syntax_id == S7COMM_SYNTAXID_NCK_INCH))) {
        /* Sinumerik NCK access */
        offset = s7comm_syntaxid_nck(tvb, offset, item_tree);
    } else if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_DRIVEESANY) {
        /* Accessing frequency inverter parameters (via routing) */
        offset = s7comm_syntaxid_driveesany(tvb, offset, item_tree);
    }
    else {
        /* var spec, length and syntax id are still added to tree here */
        offset += var_spec_length - 1;
        proto_item_append_text(item_tree, " Unknown variable specification");
    }
    return offset;
}

/*******************************************************************************************************
 *
 * Decode parameter part of a PDU for setup communication
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_pdu_setup_communication(tvbuff_t *tvb,
                                      proto_tree *tree,
                                      guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_param_setup_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_param_maxamq_calling, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_param_maxamq_called, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_param_neg_pdu_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Response -> Function Write  -> Data part
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_response_write_data(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint8 item_count,
                                  guint32 offset)
{
    guint8 ret_val = 0;
    guint8 i = 0;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;

    for (i = 0; i < item_count; i++) {
        ret_val = tvb_get_guint8(tvb, offset);
        /* Insert a new tree for every item */
        item = proto_tree_add_item(tree, hf_s7comm_data_item, tvb, offset, 1, ENC_NA);
        item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
        proto_item_append_text(item, " [%d]: (%s)", i+1, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
        proto_tree_add_uint(item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
        offset += 1;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Response -> Function Read  -> Data part
 *           Request  -> Function Write -> Data part
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_response_read_data(tvbuff_t *tvb,
                                 proto_tree *tree,
                                 guint8 item_count,
                                 guint32 offset)
{
    guint8 ret_val = 0;
    guint8 tsize = 0;
    guint16 len = 0, len2 = 0;
    guint16 head_len = 4;           /* 1 byte res-code, 1 byte transp-size, 2 bytes len */
    guint8 i = 0;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;

    /* Maybe this is only valid for Sinumerik NCK: Pre-check transport-size
     * If transport size is 0x11 or 0x12, then an array with requested NCK areas will follow.
     */
    tsize = tvb_get_guint8(tvb, offset + 1);
    if (tsize == S7COMM_DATA_TRANSPORT_SIZE_NCKADDR1 || tsize == S7COMM_DATA_TRANSPORT_SIZE_NCKADDR2) {
        proto_tree_add_item(tree, hf_s7comm_data_returncode, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint(tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);
        offset += 2;
        for (i = 0; i < item_count; i++) {
            offset = s7comm_decode_param_item(tvb, offset, tree, i);
        }
    } else {
        /* Standard */
        for (i = 0; i < item_count; i++) {
            ret_val = tvb_get_guint8(tvb, offset);
            if (ret_val == S7COMM_ITEM_RETVAL_RESERVED ||
                ret_val == S7COMM_ITEM_RETVAL_DATA_OK ||
                ret_val == S7COMM_ITEM_RETVAL_DATA_ERR
                ) {
                tsize = tvb_get_guint8(tvb, offset + 1);
                len = tvb_get_ntohs(tvb, offset + 2);
                /* calculate length in bytes */
                if (tsize == S7COMM_DATA_TRANSPORT_SIZE_BBIT ||
                    tsize == S7COMM_DATA_TRANSPORT_SIZE_BBYTE ||
                    tsize == S7COMM_DATA_TRANSPORT_SIZE_BINT
                    ) {     /* given length is in number of bits */
                    if (len % 8) { /* len is not a multiple of 8, then round up to next number */
                        len /= 8;
                        len = len + 1;
                    } else {
                        len /= 8;
                    }
                }

                /* the PLC places extra bytes at the end of all but last result, if length is not a multiple of 2 */
                if ((len % 2) && (i < (item_count-1))) {
                    len2 = len + 1;
                } else {
                    len2 = len;
                }
            }
            /* Insert a new tree for every item */
            item = proto_tree_add_item(tree, hf_s7comm_data_item, tvb, offset, len + head_len, ENC_NA);
            item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
            proto_item_append_text(item, " [%d]: (%s)", i+1, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));

            proto_tree_add_uint(item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
            proto_tree_add_uint(item_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);
            proto_tree_add_uint(item_tree, hf_s7comm_data_length, tvb, offset + 2, 2, len);
            offset += head_len;

            if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK || ret_val == S7COMM_ITEM_RETVAL_RESERVED) {
                proto_tree_add_item(item_tree, hf_s7comm_readresponse_data, tvb, offset, len, ENC_NA);
                offset += len;
                if (len != len2) {
                    proto_tree_add_item(item_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                }
            }
        }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response -> Function 0x29 (PLC control functions -> STOP)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_plc_controls_param_hex29(tvbuff_t *tvb,
                                       proto_tree *tree,
                                       guint32 offset)
{
    guint8 len;

    /* The first byte 0x29 is checked and inserted to tree outside, so skip it here */
    offset += 1;
    /* Meaning of first 5 bytes (Part 1) is unknown */
    proto_tree_add_item(tree, hf_s7comm_piservice_unknown1, tvb, offset, 5, ENC_NA);
    offset += 5;
    /* Part 2 */
    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_s7comm_data_plccontrol_part2_len, tvb, offset, 1, len);
    offset += 1;
    /* Function as string */
    proto_tree_add_item(tree, hf_s7comm_piservice_servicename, tvb, offset, len, ENC_ASCII|ENC_NA);
    offset += len;

    return offset;
}

/*******************************************************************************************************
 * PI_START Parameters: Decodes a parameter array with string values.
 *******************************************************************************************************/
static guint32
s7comm_decode_pistart_parameters(tvbuff_t *tvb,
                                 packet_info *pinfo,
                                 proto_tree *tree,
                                 proto_tree *param_tree,
                                 const guint8 *servicename,
                                 guint8 nfields,      /* number of fields used */
                                 guint hf[12],        /* array with header fields */
                                 guint32 offset)
{
    guint8 i;
    guint8 len;
    wmem_strbuf_t *args_buf;
    args_buf = wmem_strbuf_new_label(wmem_packet_scope());

    for (i = 0; i < nfields; i++) {
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(param_tree, hf_s7comm_piservice_string_len, tvb, offset, 1, len);
        offset += 1;
        proto_tree_add_item(param_tree, hf[i], tvb, offset, len, ENC_ASCII|ENC_NA);
        wmem_strbuf_append(args_buf, "\"");
        wmem_strbuf_append(args_buf, tvb_format_text(tvb, offset, len));
        if (i < nfields-1) {
            wmem_strbuf_append(args_buf, "\", ");
        } else {
            wmem_strbuf_append(args_buf, "\"");
        }
        offset += len + (len % 2 == 0);
    }
    proto_item_append_text(param_tree, ": (%s)", wmem_strbuf_get_str(args_buf));
    proto_item_append_text(tree, " -> %s(%s)", servicename, wmem_strbuf_get_str(args_buf));
    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s(%s)", servicename, wmem_strbuf_get_str(args_buf));

    return offset;
}

/*******************************************************************************************************
 * PI-Service
 *******************************************************************************************************/
static guint32
s7comm_decode_pi_service(tvbuff_t *tvb,
                         packet_info *pinfo,
                         proto_tree *tree,
                         guint16 plength,
                         guint32 offset)
{
    guint16 len, paramlen;
    guint32 startoffset;
    guint32 paramoffset;
    guint8 count;
    guint8 i;
    const guint8 *servicename;
    const guint8 *str;
    const guint8 *str1;
    guint16 blocktype;
    guint hf[13];
    int pi_servicename_idx;
    const gchar *pi_servicename_descr;

    proto_item *item = NULL;
    proto_item *itemadd = NULL;
    proto_tree *param_tree = NULL;
    proto_tree *file_tree = NULL;

    gint32 num = -1;
    gboolean num_valid;

    startoffset = offset;

    /* The first byte is checked and inserted to tree outside, so skip it here */
    offset += 1;

    /* First part is unknown, 7 bytes */
    proto_tree_add_item(tree, hf_s7comm_piservice_unknown1, tvb, offset, 7, ENC_NA);
    offset += 7;

    if (offset - startoffset >= plength) {
        return offset;
    }
    /* Parameter block */
    paramlen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_s7comm_piservice_parameterblock_len, tvb, offset, 2, paramlen);
    offset += 2;

    paramoffset = offset;
    item = proto_tree_add_item(tree, hf_s7comm_piservice_parameterblock, tvb, offset, paramlen, ENC_NA);
    param_tree = proto_item_add_subtree(item, ett_s7comm_piservice_parameterblock);
    offset += paramlen;

    /* PI servicename */
    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_s7comm_piservice_string_len, tvb, offset, 1, len);
    offset += 1;
    item = proto_tree_add_item_ret_string(tree, hf_s7comm_piservice_servicename, tvb, offset, len, ENC_ASCII|ENC_NA, wmem_packet_scope(), &servicename);
    offset += len;

    /* get the index position in pi_service_names, and add infotext with description to the item */
    pi_servicename_descr = try_str_to_str_idx((const gchar*)servicename, pi_service_names, &pi_servicename_idx);
    if (pi_servicename_idx < 0) {
        pi_servicename_idx = S7COMM_PI_UNKNOWN;
        pi_servicename_descr = "Unknown PI Service";
    }
    proto_item_append_text(item, " [%s]", pi_servicename_descr);

    /* Work parameter data, depending on servicename */
    switch (pi_servicename_idx) {
        case S7COMM_PI_INSE:
        case S7COMM_PI_INS2:
        case S7COMM_PI_DELE:
            count = tvb_get_guint8(tvb, paramoffset);                   /* number of blocks following */
            proto_tree_add_uint(param_tree, hf_s7comm_data_plccontrol_block_cnt, tvb, paramoffset, 1, count);
            paramoffset += 1;
            /* Unknown, is always 0x00 */
            proto_tree_add_item(param_tree, hf_s7comm_data_pi_inse_unknown, tvb, paramoffset, 1, ENC_BIG_ENDIAN);
            paramoffset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s(", servicename);
            for (i = 0; i < count; i++) {
                item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, paramoffset, 8, ENC_ASCII|ENC_NA);
                file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
                blocktype = tvb_get_ntohs(tvb, paramoffset);
                itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, paramoffset, 2, ENC_ASCII|ENC_NA);
                proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
                paramoffset += 2;
                proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, paramoffset, 5, ENC_ASCII|ENC_NA, wmem_packet_scope(), &str);
                paramoffset += 5;
                num_valid = ws_strtoi32((const char*)str, NULL, &num);
                proto_item_append_text(file_tree, " [%s ",
                    val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
                col_append_str(pinfo->cinfo, COL_INFO,
                    val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
                if (num_valid) {
                    proto_item_append_text(file_tree, "%d]", num);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%d", num);
                } else {
                    expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
                    proto_item_append_text(file_tree, "NaN]");
                    col_append_str(pinfo->cinfo, COL_INFO, "NaN");
                }
                if (i+1 < count) {
                    col_append_str(pinfo->cinfo, COL_INFO, ", ");
                }
                itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, paramoffset, 1, ENC_ASCII|ENC_NA);
                proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, paramoffset), blocktype_attribute2_names, "Unknown filesys: %c"));
                paramoffset += 1;
            }
            col_append_str(pinfo->cinfo, COL_INFO, ")");
            break;
        case S7COMM_PIP_PROGRAM:
        case S7COMM_PI_MODU:
        case S7COMM_PI_GARB:
            if (paramlen == 0) {
                proto_item_append_text(param_tree, ": ()");
                proto_item_append_text(tree, " -> %s()", servicename);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s()", servicename);
            } else {
                proto_tree_add_item_ret_string(param_tree, hf_s7comm_data_plccontrol_argument, tvb, paramoffset, paramlen, ENC_ASCII|ENC_NA, wmem_packet_scope(), &str1);
                proto_item_append_text(param_tree, ": (\"%s\")", str1);
                proto_item_append_text(tree, " -> %s(\"%s\")", servicename, str1);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s(\"%s\")", servicename, str1);
            }
            break;
        case S7COMM_PI_N_LOGIN_:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_password;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
            break;
        case S7COMM_PI_N_LOGOUT:
        case S7COMM_PI_N_CANCEL:
        case S7COMM_PI_N_DASAVE:
        case S7COMM_PI_N_DIGIOF:
        case S7COMM_PI_N_DIGION:
        case S7COMM_PI_N_DZERO_:
        case S7COMM_PI_N_ENDEXT:
        case S7COMM_PI_N_OST_OF:
        case S7COMM_PI_N_OST_ON:
        case S7COMM_PI_N_SCALE_:
        case S7COMM_PI_N_SETUFR:
        case S7COMM_PI_N_STRTLK:
        case S7COMM_PI_N_STRTUL:
        case S7COMM_PI_N_TMRASS:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 1, hf, paramoffset);
            break;
        case S7COMM_PI_N_F_DELE:
        case S7COMM_PI_N_EXTERN:
        case S7COMM_PI_N_EXTMOD:
        case S7COMM_PI_N_F_DELR:
        case S7COMM_PI_N_F_XFER:
        case S7COMM_PI_N_LOCKE_:
        case S7COMM_PI_N_SELECT:
        case S7COMM_PI_N_SRTEXT:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_filename;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
            break;
        case S7COMM_PI_N_F_CLOS:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_editwindowname;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
            break;
        case S7COMM_PI_N_F_OPEN:
        case S7COMM_PI_N_F_OPER:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_filename;
            hf[2] = hf_s7comm_pi_n_x_editwindowname;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
            break;
        case S7COMM_PI_N_F_SEEK:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_editwindowname;
            hf[2] = hf_s7comm_pi_n_x_seekpointer;
            hf[3] = hf_s7comm_pi_n_x_windowsize;
            hf[4] = hf_s7comm_pi_n_x_comparestring;
            hf[5] = hf_s7comm_pi_n_x_skipcount;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
            break;
        case S7COMM_PI_N_ASUP__:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_interruptnr;
            hf[2] = hf_s7comm_pi_n_x_priority;
            hf[3] = hf_s7comm_pi_n_x_liftfast;
            hf[4] = hf_s7comm_pi_n_x_blsync;
            hf[5] = hf_s7comm_pi_n_x_filename;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
            break;
        case S7COMM_PI_N_CHEKDM:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_magnr;
            hf[2] = hf_s7comm_pi_n_x_dnr;
            hf[3] = hf_s7comm_pi_n_x_spindlenumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
            break;
        case S7COMM_PI_N_CHKDNO:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_wznr;
            hf[2] = hf_s7comm_pi_n_x_wznr;
            hf[3] = hf_s7comm_pi_n_x_dnr;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
            break;
        case S7COMM_PI_N_CONFIG:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_class;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
            break;
        case S7COMM_PI_N_CRCEDN:
        case S7COMM_PI_N_DELECE:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_tnr;
            hf[2] = hf_s7comm_pi_n_x_dnr;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
            break;
        case S7COMM_PI_N_CREACE:
        case S7COMM_PI_N_CREATO:
        case S7COMM_PI_N_DELETO:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_toolnumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
            break;
        case S7COMM_PI_N_CRTOCE:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_toolnumber;
            hf[2] = hf_s7comm_pi_n_x_cenumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
            break;
        case S7COMM_PI_N_DELVAR:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_datablocknumber;
            hf[2] = hf_s7comm_pi_n_x_firstcolumnnumber;
            hf[3] = hf_s7comm_pi_n_x_lastcolumnnumber;
            hf[4] = hf_s7comm_pi_n_x_firstrownumber;
            hf[5] = hf_s7comm_pi_n_x_lastrownumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
            break;
        case S7COMM_PI_N_F_COPY:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_direction;
            hf[2] = hf_s7comm_pi_n_x_sourcefilename;
            hf[3] = hf_s7comm_pi_n_x_destinationfilename;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
            break;
        case S7COMM_PI_N_F_DMDA:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_channelnumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
            break;
        case S7COMM_PI_N_F_PROR:
        case S7COMM_PI_N_F_PROT:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_filename;
            hf[2] = hf_s7comm_pi_n_x_protection;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
            break;
        case S7COMM_PI_N_F_RENA:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_oldfilename;
            hf[2] = hf_s7comm_pi_n_x_newfilename;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
            break;
        case S7COMM_PI_N_FINDBL:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_findmode;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
            break;
        case S7COMM_PI_N_IBN_SS:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_switch;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
            break;
        case S7COMM_PI_N_MMCSEM:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_functionnumber;
            hf[2] = hf_s7comm_pi_n_x_semaphorvalue;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
            break;
        case S7COMM_PI_N_NCKMOD:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_onoff;
            hf[2] = hf_s7comm_pi_n_x_mode;
            hf[3] = hf_s7comm_pi_n_x_factor;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
            break;
        case S7COMM_PI_N_NEWPWD:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_password;
            hf[2] = hf_s7comm_pi_n_x_passwordlevel;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
            break;
        case S7COMM_PI_N_SEL_BL:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_linenumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
            break;
        case S7COMM_PI_N_SETTST:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_magnr;
            hf[2] = hf_s7comm_pi_n_x_weargroup;
            hf[3] = hf_s7comm_pi_n_x_toolstatus;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
            break;
        case S7COMM_PI_N_TMAWCO:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_magnr;
            hf[2] = hf_s7comm_pi_n_x_weargroup;
            hf[3] = hf_s7comm_pi_n_x_wearsearchstrat;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
            break;
        case S7COMM_PI_N_TMCRTC:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_toolid;
            hf[2] = hf_s7comm_pi_n_x_toolnumber;
            hf[3] = hf_s7comm_pi_n_x_duplonumber;
            hf[4] = hf_s7comm_pi_n_x_edgenumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 5, hf, paramoffset);
            break;
        case S7COMM_PI_N_TMCRTO:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_toolid;
            hf[2] = hf_s7comm_pi_n_x_toolnumber;
            hf[3] = hf_s7comm_pi_n_x_duplonumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
            break;
        case S7COMM_PI_N_TMFDPL:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_toolnumber;
            hf[2] = hf_s7comm_pi_n_x_placenr;
            hf[3] = hf_s7comm_pi_n_x_magnr;
            hf[4] = hf_s7comm_pi_n_x_placerefnr;
            hf[5] = hf_s7comm_pi_n_x_magrefnr;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
            break;
        case S7COMM_PI_N_TMFPBP:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_magnrfrom;
            hf[2] = hf_s7comm_pi_n_x_placenrfrom;
            hf[3] = hf_s7comm_pi_n_x_magnrto;
            hf[4] = hf_s7comm_pi_n_x_placenrto;
            hf[5] = hf_s7comm_pi_n_x_magrefnr;
            hf[6] = hf_s7comm_pi_n_x_placerefnr;
            hf[7] = hf_s7comm_pi_n_x_halfplacesleft;
            hf[8] = hf_s7comm_pi_n_x_halfplacesright;
            hf[9] = hf_s7comm_pi_n_x_halfplacesup;
            hf[10] = hf_s7comm_pi_n_x_halfplacesdown;
            hf[11] = hf_s7comm_pi_n_x_placetype;
            hf[12] = hf_s7comm_pi_n_x_searchdirection;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 13, hf, paramoffset);
            break;
        case S7COMM_PI_N_TMGETT:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_toolname;
            hf[2] = hf_s7comm_pi_n_x_duplonumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
            break;
        case S7COMM_PI_N_TMMVTL:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_toolnumber;
            hf[2] = hf_s7comm_pi_n_x_placenrsource;
            hf[3] = hf_s7comm_pi_n_x_magnrsource;
            hf[4] = hf_s7comm_pi_n_x_placenrdestination;
            hf[5] = hf_s7comm_pi_n_x_magnrdestination;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
            break;
        case S7COMM_PI_N_TMPCIT:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_spindlenumber;
            hf[2] = hf_s7comm_pi_n_x_incrementnumber;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
            break;
        case S7COMM_PI_N_TMPOSM:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_toolnumber;
            hf[2] = hf_s7comm_pi_n_x_toolid;
            hf[3] = hf_s7comm_pi_n_x_duplonumber;
            hf[4] = hf_s7comm_pi_n_x_placenrsource;
            hf[5] = hf_s7comm_pi_n_x_magnrsource;
            hf[6] = hf_s7comm_pi_n_x_placenrdestination;
            hf[7] = hf_s7comm_pi_n_x_magnrdestination;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 8, hf, paramoffset);
            break;
        case S7COMM_PI_N_TRESMO:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_toolnumber;
            hf[2] = hf_s7comm_pi_n_x_dnr;
            hf[3] = hf_s7comm_pi_n_x_monitoringmode;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
            break;
        case S7COMM_PI_N_TSEARC:
            hf[0] = hf_s7comm_pi_n_x_addressident;
            hf[1] = hf_s7comm_pi_n_x_magnrfrom;
            hf[2] = hf_s7comm_pi_n_x_placenrfrom;
            hf[3] = hf_s7comm_pi_n_x_magnrto;
            hf[4] = hf_s7comm_pi_n_x_placenrto;
            hf[5] = hf_s7comm_pi_n_x_magrefnr;
            hf[6] = hf_s7comm_pi_n_x_placerefnr;
            hf[7] = hf_s7comm_pi_n_x_searchdirection;
            hf[8] = hf_s7comm_pi_n_x_kindofsearch;
            s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 9, hf, paramoffset);
            break;
        default:
            /* Don't know how to interpret the parameters, show only the PI servicename */
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]", servicename);
    }
    return offset;
}

/*******************************************************************************************************
 *
 * Decode a blockname/filename used in block/file upload/download
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_plc_controls_filename(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *param_tree,
                                    guint32 offset)
{
    guint8 len;
    const guint8 *str;
    guint16 blocktype;
    gboolean is_plcfilename;
    proto_item *item = NULL;
    proto_item *itemadd = NULL;
    proto_tree *file_tree = NULL;

    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_filename_len, tvb, offset, 1, len);
    offset += 1;
    item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, len, ENC_ASCII|ENC_NA);
    /* The filename when uploading from PLC has a well known structure, which can be further dissected.
     * An upload from a NC is a simple filename string with no deeper structure.
     * Check for PLC filename, by checking some fixed fields.
     */
    is_plcfilename = FALSE;
    if (len == 9) {
        blocktype = tvb_get_ntohs(tvb, offset + 1);
        if ((tvb_get_guint8(tvb, offset) == '_') && (blocktype >= S7COMM_BLOCKTYPE_OB) && (blocktype <= S7COMM_BLOCKTYPE_SFB)) {
            gint32 num = 1;
            gboolean num_valid;
            is_plcfilename = TRUE;
            file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
            itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII|ENC_NA);
            proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute1_names, "Unknown identifier: %c"));
            offset += 1;
            itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 2, ENC_ASCII|ENC_NA);
            proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
            offset += 2;
            proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA, wmem_packet_scope(), &str);
            offset += 5;
            num_valid = ws_strtoi32((const gchar*)str, NULL, &num);
            proto_item_append_text(file_tree, " [%s",
                val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s",
                val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
            if (num_valid) {
                proto_item_append_text(file_tree, "%d]", num);
                col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
            } else {
                expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
                proto_item_append_text(file_tree, "NaN]");
                col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
            }
            itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII|ENC_NA);
            proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys: %c"));
            offset += 1;
        }
    }
    if (is_plcfilename == FALSE) {
        str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len, ENC_ASCII);
        col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str);
        offset += len;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response -> Function 0x1d, 0x1e, 0x1f (block control functions) for upload
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_plc_controls_updownload(tvbuff_t *tvb,
                                      packet_info *pinfo,
                                      proto_tree *tree,
                                      proto_tree *param_tree,
                                      guint16 plength,
                                      guint16 dlength,
                                      guint32 offset,
                                      guint8 rosctr)
{
    guint8 len;
    guint8 function;
    guint32 errorcode;
    const gchar *errorcode_text;
    proto_item *item = NULL;
    proto_tree *data_tree = NULL;

    function = tvb_get_guint8(tvb, offset);
    offset += 1;
    errorcode = 0;

    switch (function) {
        /*---------------------------------------------------------------------*/
        case S7COMM_FUNCREQUESTDOWNLOAD:
            if (rosctr == S7COMM_ROSCTR_JOB) {
                proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,
                    ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
                offset += 2;
                /* on upload this is the upload-id, here it is anything else (or not used ) */
                proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
                offset += 4;
                offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
                if (plength > 18) {
                    len = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_part2_len, tvb, offset, 1, len);
                    offset += 1;
                    /* first byte unknown '1' */
                    proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_part2_unknown, tvb, offset, 1, ENC_ASCII|ENC_NA);
                    offset += 1;
                    proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_loadmem_len, tvb, offset, 6, ENC_ASCII|ENC_NA);
                    offset += 6;
                    proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_mc7code_len, tvb, offset, 6, ENC_ASCII|ENC_NA);
                    offset += 6;
                }
            } else if (rosctr == S7COMM_ROSCTR_ACK_DATA) {
                if (plength >= 2) {
                    proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,
                        ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
                    offset += 1;
                }
            }
            break;
        /*---------------------------------------------------------------------*/
        case S7COMM_FUNCSTARTUPLOAD:
            proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,
                ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_uploadid, tvb, offset, 4, ENC_NA);
            offset += 4;
            if (rosctr == S7COMM_ROSCTR_JOB) {
                offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
            } else if (rosctr == S7COMM_ROSCTR_ACK_DATA) {
                if (plength > 8) {
                    /* If uploading from a PLC, the response has a string with the length
                     * of the complete module in bytes, which maybe transferred/split into many PDUs.
                     * On a NC file upload, there are no such fields.
                     */
                    len = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_upl_lenstring_len, tvb, offset, 1, len);
                    offset += 1;
                    proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_upl_lenstring, tvb, offset, len, ENC_ASCII|ENC_NA);
                    offset += len;
                }
            }
            break;
        /*---------------------------------------------------------------------*/
        case S7COMM_FUNCUPLOAD:
        case S7COMM_FUNCDOWNLOADBLOCK:
            if (rosctr == S7COMM_ROSCTR_JOB) {
                proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,
                    ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
                offset += 2;
                if (function == S7COMM_FUNCUPLOAD) {
                    proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_uploadid, tvb, offset, 4, ENC_NA);
                    offset += 4;
                } else {
                    proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
                    offset += 4;
                    offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
                }
            } else if (rosctr == S7COMM_ROSCTR_ACK_DATA) {
                if (plength >= 2) {
                    proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,
                        ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
                    offset += 1;
                }
                if (dlength > 0) {
                    item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
                    data_tree = proto_item_add_subtree(item, ett_s7comm_data);
                    proto_tree_add_item(data_tree, hf_s7comm_data_length, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength - 4, ENC_NA);
                    offset += dlength - 4;
                }
            }
            break;
        /*---------------------------------------------------------------------*/
        case S7COMM_FUNCENDUPLOAD:
        case S7COMM_FUNCDOWNLOADENDED:
            if (rosctr == S7COMM_ROSCTR_JOB) {
                proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,
                    ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
                offset += 1;
                item = proto_tree_add_item_ret_uint(param_tree, hf_s7comm_data_blockcontrol_errorcode, tvb, offset, 2, ENC_BIG_ENDIAN, &errorcode);
                /* here it uses the same errorcode from parameter part */
                if ((errorcode_text = try_val_to_str_ext(errorcode, &param_errcode_names_ext))) {
                    proto_item_append_text(item, " (%s)", errorcode_text);
                }
                offset += 2;
                if (function == S7COMM_FUNCENDUPLOAD) {
                    proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_uploadid, tvb, offset, 4, ENC_NA);
                    offset += 4;
                } else {
                    proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
                    offset += 4;
                    offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
                }
            } else if (rosctr == S7COMM_ROSCTR_ACK_DATA) {
                if (plength >= 2) {
                    proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,
                        ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
                    offset += 1;
                }
            }
            break;
    }
    /* if an error occurred show in info column */
    if (errorcode > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " -> Errorcode:[0x%04x]", errorcode);
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Block status (0x13 or 0x01)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_blockstat(tvbuff_t *tvb,
                               proto_tree *td_tree,
                               guint16 td_size,
                               guint8 type,
                               guint8 subfunc,
                               guint32 offset)
{
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;
    guint16 line_nr;
    guint16 line_cnt;
    guint16 item_size = 4;
    guint8 registerflags;
    gchar str_flags[80];

    if (type == S7COMM_UD_TYPE_REQ) {
        if (subfunc == S7COMM_UD_SUBF_PROG_BLOCKSTAT2) {
            proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_flagsunknown, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            line_cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(td_tree, hf_s7comm_tis_blockstat_number_of_lines, tvb, offset, 1, line_cnt);
            offset += 1;
            proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
        } else {
            proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
            line_cnt = (td_size - 2) / 2;
        }
        proto_tree_add_bitmask(td_tree, tvb, offset, hf_s7comm_diagdata_registerflag,
            ett_s7comm_diagdata_registerflag, s7comm_diagdata_registerflag_fields, ENC_BIG_ENDIAN);
        offset += 1;

        if (subfunc == S7COMM_UD_SUBF_PROG_BLOCKSTAT2) {
            item_size = 4;
        } else {
            item_size = 2;
        }
        for (line_nr = 0; line_nr < line_cnt; line_nr++) {
            item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, item_size, ENC_NA);
            item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
            if (subfunc == S7COMM_UD_SUBF_PROG_BLOCKSTAT2) {
                proto_tree_add_item(item_tree, hf_s7comm_tis_blockstat_line_address, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            proto_tree_add_item(item_tree, hf_s7comm_tis_blockstat_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
            registerflags = tvb_get_guint8(tvb, offset);
            make_registerflag_string(str_flags, registerflags, sizeof(str_flags));
            proto_item_append_text(item, " [%d]: (%s)", line_nr+1, str_flags);
            proto_tree_add_bitmask(item_tree, tvb, offset, hf_s7comm_diagdata_registerflag,
                ett_s7comm_diagdata_registerflag, s7comm_diagdata_registerflag_fields, ENC_BIG_ENDIAN);
            offset += 1;
        }
    } else if (type == S7COMM_UD_TYPE_PUSH) {
        /* The response data can only be dissected when the requested registers for each line
         * from the job setup is known. As the STW is only 16 Bits and all other registers 32 Bits,
         * this has no fixed structure.
         * The only thing that can be shown is the start address. Next the requested registers,
         * the start address of next line with the requested registers and so on.
         */
        proto_tree_add_item(td_tree, hf_s7comm_diagdata_req_startaddr_awl, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_data, tvb, offset, td_size - 2, ENC_NA);
        offset += (td_size - 2);
    } else {
        /* TODO: Show unknown data as raw bytes */
        proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_reserved, tvb, offset, td_size, ENC_NA);
        offset += td_size;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Item address
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_item_address(tvbuff_t *tvb,
                                  guint32 offset,
                                  proto_tree *sub_tree,
                                  guint16 item_no,
                                  gchar *add_text)
{
    guint32 bytepos = 0;
    guint16 len = 0;
    guint16 bitpos = 0;
    guint16 db = 0;
    guint8 area = 0;
    proto_item *item = NULL;

    /* Insert a new tree with 6 bytes for every item */
    item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, 6, ENC_NA);

    sub_tree = proto_item_add_subtree(item, ett_s7comm_param_item);

    proto_item_append_text(item, " [%d]%s:", item_no + 1, add_text);

    /* Area, 1 byte */
    area = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(sub_tree, hf_s7comm_varstat_req_memory_area, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Length (repetition factor), 1 byte. If area is a bit address, then this is the bit number.
     * The area is a bit address when the low nibble is zero.
     */
    if (area & 0x0f) {
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_repetition_factor, tvb, offset, 1, len);
        offset += 1;
    } else {
        bitpos = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_bitpos, tvb, offset, 1, bitpos);
        offset += 1;
    }

    /* DB number, 2 bytes */
    db = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_db_number, tvb, offset, 2, db);
    offset += 2;

    /* byte offset, 2 bytes */
    bytepos = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_startaddress, tvb, offset, 2, bytepos);
    offset += 2;

    /* build a full address to show item data directly beside the item */
    switch (area) {
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MX:
            proto_item_append_text(sub_tree, " (M%d.%d)", bytepos, bitpos);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MB:
            proto_item_append_text(sub_tree, " (M%d.0 BYTE %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MW:
            proto_item_append_text(sub_tree, " (M%d.0 WORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_MD:
            proto_item_append_text(sub_tree, " (M%d.0 DWORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_EX:
            proto_item_append_text(sub_tree, " (I%d.%d)", bytepos, bitpos);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_EB:
            proto_item_append_text(sub_tree, " (I%d.0 BYTE %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_EW:
            proto_item_append_text(sub_tree, " (I%d.0 WORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_ED:
            proto_item_append_text(sub_tree, " (I%d.0 DWORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AX:
            proto_item_append_text(sub_tree, " (Q%d.%d)", bytepos, bitpos);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AB:
            proto_item_append_text(sub_tree, " (Q%d.0 BYTE %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AW:
            proto_item_append_text(sub_tree, " (Q%d.0 WORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_AD:
            proto_item_append_text(sub_tree, " (Q%d.0 DWORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_PEB:
            proto_item_append_text(sub_tree, " (PI%d.0 BYTE %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_PEW:
            proto_item_append_text(sub_tree, " (PI%d.0 WORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_PED:
            proto_item_append_text(sub_tree, " (PI%d.0 DWORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBX:
            proto_item_append_text(sub_tree, " (DB%d.DBX%d.%d)", db, bytepos, bitpos);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBB:
            proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 BYTE %d)", db, bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBW:
            proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 WORD %d)", db, bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_DBD:
            proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 DWORD %d)", db, bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_T:
            /* it's possible to read multiple timers */
            if (len >1)
                proto_item_append_text(sub_tree, " (T %d..%d)", bytepos, bytepos + len - 1);
            else
                proto_item_append_text(sub_tree, " (T %d)", bytepos);
            break;
        case S7COMM_UD_SUBF_PROG_VARSTAT_AREA_C:
            /* it's possible to read multiple counters */
            if (len >1)
                proto_item_append_text(sub_tree, " (C %d..%d)", bytepos, bytepos + len - 1);
            else
                proto_item_append_text(sub_tree, " (C %d)", bytepos);
            break;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Item value
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_item_value(tvbuff_t *tvb,
                                guint32 offset,
                                proto_tree *sub_tree,
                                guint16 item_no,
                                gchar *add_text)
{
    guint16 len = 0, len2 = 0;
    guint8 ret_val = 0;
    guint8 tsize = 0;
    guint8 head_len = 4;

    proto_item *item = NULL;

    ret_val = tvb_get_guint8(tvb, offset);
    if (ret_val == S7COMM_ITEM_RETVAL_RESERVED ||
        ret_val == S7COMM_ITEM_RETVAL_DATA_OK ||
        ret_val == S7COMM_ITEM_RETVAL_DATA_ERR
        ) {
        tsize = tvb_get_guint8(tvb, offset + 1);
        len = tvb_get_ntohs(tvb, offset + 2);

        if (tsize == S7COMM_DATA_TRANSPORT_SIZE_BBYTE || tsize == S7COMM_DATA_TRANSPORT_SIZE_BINT) {
            len /= 8;
        }
        /* the PLC places extra bytes at the end if length is not a multiple of 2 */
        if (len % 2) {
            len2 = len + 1;
        } else {
            len2 = len;
        }
    }
    /* Insert a new tree for every item */
    item = proto_tree_add_item(sub_tree, hf_s7comm_data_item, tvb, offset, len + head_len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_s7comm_data_item);

    proto_item_append_text(item, " [%d]%s: (%s)", item_no + 1, add_text, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));

    proto_tree_add_uint(sub_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
    proto_tree_add_uint(sub_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);
    proto_tree_add_uint(sub_tree, hf_s7comm_data_length, tvb, offset + 2, 2, len);

    offset += head_len;
    if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK || ret_val == S7COMM_ITEM_RETVAL_RESERVED) {
        proto_tree_add_item(sub_tree, hf_s7comm_readresponse_data, tvb, offset, len, ENC_NA);
        offset += len;
        if (len != len2) {
            proto_tree_add_item(sub_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Force (0x09)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_force(tvbuff_t *tvb,
                           proto_tree *td_tree,
                           guint8 type,
                           guint32 offset)
{
    guint16 item_count;
    guint16 i;
    guint8 ret_val = 0;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;

    switch (type) {
        case S7COMM_UD_TYPE_REQ:
            item_count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
            offset += 2;
            for (i = 0; i < item_count; i++) {
                offset = s7comm_decode_ud_tis_item_address(tvb, offset, td_tree, i, " Address to force");
            }
            for (i = 0; i < item_count; i++) {
                offset = s7comm_decode_ud_tis_item_value(tvb, offset, td_tree, i, " Value to force");
            }
            break;
        case S7COMM_UD_TYPE_PUSH:
            item_count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
            offset += 2;
            for (i = 0; i < item_count; i++) {
                item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, 1, ENC_NA);
                item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
                ret_val = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
                proto_item_append_text(item, " [%d]: (%s)", i + 1, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
                offset += 1;
            }
            if (item_count % 2) {
                proto_tree_add_item(item_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands / Test and installation functions
 *           Dissects the parameter part
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_param(tvbuff_t *tvb,
                           proto_tree *tree,
                           guint8 type,
                           guint16 tp_size,
                           guint32 offset)
{
    guint32 start_offset;
    guint32 callenv_setup = 0;
    proto_item *item = NULL;
    proto_tree *tp_tree = NULL;

    start_offset = offset;
    if (tp_size > 0) {
        item = proto_tree_add_item(tree, hf_s7comm_tis_parameter, tvb, offset, tp_size, ENC_NA);
        tp_tree = proto_item_add_subtree(item, ett_s7comm_prog_parameter);
        if (type == S7COMM_UD_TYPE_REQ) {
            if (tp_size >= 4) {
                proto_tree_add_item(tp_tree, hf_s7comm_tis_param1, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_tis_param2, tvb, offset, 2, ENC_NA);
                offset += 2;
            }
            if (tp_size >= 20) {
                proto_tree_add_item(tp_tree, hf_s7comm_tis_param3, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_tis_answersize, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_tis_param5, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_tis_param6, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_tis_param7, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_tis_param8, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_tis_param9, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_tis_trgevent, tvb, offset, 2, ENC_NA);
                offset += 2;
            }
            if (tp_size >= 26) {
                proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_block_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_startaddr_awl, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            if (tp_size >= 28) {
                proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_saz, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            if (tp_size >= 36) {
                proto_tree_add_item_ret_uint(tp_tree, hf_s7comm_tis_p_callenv, tvb, offset, 2, ENC_BIG_ENDIAN, &callenv_setup);
                offset += 2;
                proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                if (callenv_setup == 2) {
                    proto_tree_add_item(tp_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(tp_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    if (tp_size >= 38) {
                        proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_address, tvb, offset, 2, ENC_BIG_ENDIAN);
                    }
                }
            }
        } else {
            proto_tree_add_item(tp_tree, hf_s7comm_tis_res_param1, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(tp_tree, hf_s7comm_tis_res_param2, tvb, offset, 2, ENC_NA);
        }
    }
    /* May be we don't know all values when here, so set offset to the given length */
    return start_offset + tp_size;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Disable job (0x0d), Enable job (0x0e),
 *                                                                   Delete job (0x0f), Read job list (0x10),
 *                                                                   Read job (0x11)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_jobs(tvbuff_t *tvb,
                          proto_tree *td_tree,
                          guint16 td_size,
                          guint8 type,
                          guint8 subfunc,
                          guint32 offset)
{
    guint16 i;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;
    guint16 job_tp_size;
    guint16 job_td_size;
    proto_tree *job_td_tree = NULL;
    guint8 job_subfunc;

    if (type == S7COMM_UD_TYPE_REQ) {
        switch (subfunc) {
            case S7COMM_UD_SUBF_PROG_DELETEJOB:
                proto_tree_add_item(td_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;
                /* fallthrough */
            case S7COMM_UD_SUBF_PROG_ENABLEJOB:
            case S7COMM_UD_SUBF_PROG_DISABLEJOB:
            case S7COMM_UD_SUBF_PROG_READJOB:
                proto_tree_add_item(td_tree, hf_s7comm_tis_job_function, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(td_tree, hf_s7comm_tis_job_seqnr, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            case S7COMM_UD_SUBF_PROG_READJOBLIST:
                /* 4 bytes, possible as filter? */
                proto_tree_add_item(td_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(td_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;
            case S7COMM_UD_SUBF_PROG_REPLACEJOB:
                proto_tree_add_item(td_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;
                /* The job which has to be replaced */
                job_subfunc = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(td_tree, hf_s7comm_tis_job_function, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(td_tree, hf_s7comm_tis_job_seqnr, tvb, offset, 1, ENC_NA);
                offset += 1;
                job_tp_size = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(td_tree, hf_s7comm_tis_parametersize, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                job_td_size = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(td_tree, hf_s7comm_tis_datasize, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* New job parameter tree */
                if (job_tp_size > 0) {
                    offset = s7comm_decode_ud_tis_param(tvb, td_tree, S7COMM_UD_TYPE_REQ, job_tp_size, offset);
                }
                /* New job data tree */
                if (job_td_size > 0) {
                    offset = s7comm_decode_ud_tis_data(tvb, td_tree, S7COMM_UD_TYPE_REQ, job_subfunc, job_td_size, offset);
                }
                break;
        }
    } else {
        switch (subfunc) {
            case S7COMM_UD_SUBF_PROG_READJOBLIST:
                /* 4 bytes each job:
                 * - 2 bytes job id
                 * - 2 bytes status: 1=active, 0=idle/pending?
                 */
                for (i = 0; i < td_size / 4; i++) {
                    item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, 4, ENC_NA);
                    item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
                    proto_item_append_text(item, " [%d] Job", i + 1);

                    proto_tree_add_item(item_tree, hf_s7comm_tis_job_function, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(item_tree, hf_s7comm_tis_job_seqnr, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(item_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;
                }
                break;
            case S7COMM_UD_SUBF_PROG_READJOB:
                /* This includes the same data as in the job request. With the disadvantage that is does
                 * not contain information of the function, so the data can't be further dissected.
                 * We need to know the function from the request.
                 */
                job_tp_size = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(td_tree, hf_s7comm_tis_parametersize, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                job_td_size = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(td_tree, hf_s7comm_tis_datasize, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* Job parameter tree */
                if (job_tp_size > 0) {
                    offset = s7comm_decode_ud_tis_param(tvb, td_tree, S7COMM_UD_TYPE_REQ, job_tp_size, offset);
                }
                /* Job data tree */
                if (job_td_size > 0) {
                    item = proto_tree_add_item(td_tree, hf_s7comm_tis_data, tvb, offset, job_td_size, ENC_NA);
                    job_td_tree = proto_item_add_subtree(item, ett_s7comm_prog_data);
                    proto_tree_add_item(job_td_tree, hf_s7comm_tis_job_reserved, tvb, offset, job_td_size, ENC_NA);
                    offset += job_td_size;
                }
                break;
        }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Variable status (0x03)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_varstat(tvbuff_t *tvb,
                             proto_tree *td_tree,
                             guint8 type,
                             guint32 offset)
{
    guint16 item_count;
    guint16 i;

    switch (type) {
        case S7COMM_UD_TYPE_REQ:
            item_count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
            offset += 2;
            for (i = 0; i < item_count; i++) {
                offset = s7comm_decode_ud_tis_item_address(tvb, offset, td_tree, i, " Address to read");
            }
            break;
        case S7COMM_UD_TYPE_PUSH:
            item_count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
            offset += 2;
            for (i = 0; i < item_count; i++) {
                offset = s7comm_decode_ud_tis_item_value(tvb, offset, td_tree, i, " Read data");
            }
            break;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Modify variable (0x08)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_modvar(tvbuff_t *tvb,
                            proto_tree *td_tree,
                            guint8 type,
                            guint32 offset)
{
    guint16 item_count;
    guint16 i;
    guint8 ret_val = 0;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;

    switch (type) {
        case S7COMM_UD_TYPE_REQ:
            item_count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
            offset += 2;
            for (i = 0; i < item_count; i++) {
                offset = s7comm_decode_ud_tis_item_address(tvb, offset, td_tree, i, " Address to write");
            }
            for (i = 0; i < item_count; i++) {
                offset = s7comm_decode_ud_tis_item_value(tvb, offset, td_tree, i, " Data to write");
            }
            break;
        case S7COMM_UD_TYPE_PUSH:
            item_count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
            offset += 2;
            for (i = 0; i < item_count; i++) {
                item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, 1, ENC_NA);
                item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
                ret_val = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
                proto_item_append_text(item, " [%d]: (%s)", i + 1, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
                offset += 1;
            }
            if (item_count % 2) {
                proto_tree_add_item(item_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Output ISTACK (0x03)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_istack(tvbuff_t *tvb,
                            proto_tree *td_tree,
                            guint8 type,
                            guint32 offset)
{
    guint8 ob_number = 0;
    switch (type) {
        case S7COMM_UD_TYPE_REQ:
            proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            break;
        case S7COMM_UD_TYPE_RES:
        case S7COMM_UD_TYPE_PUSH:
            proto_tree_add_item(td_tree, hf_s7comm_tis_continued_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_continued_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_continued_address, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_db1_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_db2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu1, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu2, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu3, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu4, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_ar1, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_ar2, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_stw, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_address, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 4, ENC_NA);
            offset += 4;
            /* read the OB number first */
            ob_number = tvb_get_guint8(tvb, offset + 3);
            switch (ob_number) {
                case 1:     /* Cyclic execution */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_scan_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_prev_cycle, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_min_cycle, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_max_cycle, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                case 10:    /* Time of day interrupt 0..7 */
                case 11:
                case 12:
                case 13:
                case 14:
                case 15:
                case 16:
                case 17:
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_period_exe, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_4, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                case 20:    /* Time delay interrupt 0..3 */
                case 21:
                case 22:
                case 23:
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_scan_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_sign, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_dtime, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    break;
                case 30:    /* Cyclic interrupt 0..8 */
                case 31:
                case 32:
                case 33:
                case 34:
                case 35:
                case 36:
                case 37:
                case 38:
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_phase_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_exec_freq, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                case 40:    /* Hardware interrupt 0..8 */
                case 41:
                case 42:
                case 43:
                case 44:
                case 45:
                case 46:
                case 47:
                case 48:
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_io_flag, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_point_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    break;
                case 55:    /* DP Statusalarm */
                case 56:    /* DP Updatealarm */
                case 57:    /* DP Specific alarm */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_io_flag, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_inf_len, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_alarm_type, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_alarm_slot, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_alarm_spec, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    break;
                case 80:    /* Cycle time fault */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_error_info, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_err_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_err_ev_num, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_err_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_err_ob_num, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    break;
                case 81:    /* Power supply fault */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_rack_cpu, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_4, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                case 82:    /* I/O Point fault 1 */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_io_flag, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_8x_fault_flags, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_type_b, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_8x_fault_flags, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_8x_fault_flags, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    break;
                case 83:    /* I/O Point fault 2 */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_io_flag, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_rack_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_type_w, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                case 84:    /* CPU fault */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_4_dw, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    break;
                case 85:    /* OB not loaded fault */
                case 87:    /* Communication Fault */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_err_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_err_ev_num, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_err_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_err_ob_num, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    break;
                case 86:    /* Loss of rack fault */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_racks_flt, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    break;
                case 90:    /* Background cycle */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_4_dw, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    break;
                case 100:    /* Complete restart */
                case 101:    /* Restart */
                case 102:    /* Cold restart */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_strtup, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_stop, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_strt_info, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    break;
                case 121:    /* Programming Error */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_sw_flt, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_blk_type, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_reg, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_blk_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_prg_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                case 122:    /* Module Access Error */
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_sw_flt, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_blk_type, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_mem_area, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_mem_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_flt_blk_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_prg_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                default:
                    proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    break;
            }
            offset = s7comm_add_timestamp_to_tree(tvb, td_tree, offset, FALSE, FALSE);
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Output BSTACK (0x04)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_bstack(tvbuff_t *tvb,
                            proto_tree *td_tree,
                            guint16 td_size,
                            guint8 type,
                            guint32 offset)
{
    guint16 i;
    guint16 blocktype;
    guint16 blocknumber;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;
    int rem;
    guint32 replen;

    /* Possible firmware bug in IM151-8 CPU, where also the date size information
     * in the header is 4 bytes too short.
     */
    replen = tvb_reported_length_remaining(tvb, offset);
    if (replen < td_size) {
        /* TODO: Show this mismatch? We fix the length here. */
        td_size = replen;
    }
    switch (type) {
        case S7COMM_UD_TYPE_REQ:
            proto_tree_add_item(td_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            break;
        case S7COMM_UD_TYPE_RES:
        case S7COMM_UD_TYPE_PUSH:
            rem = td_size;
            i = 1;
            while (rem > 16) {
                item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, 16, ENC_NA);
                item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
                blocktype = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(item_tree, hf_s7comm_tis_interrupted_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                blocknumber = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(item_tree, hf_s7comm_tis_interrupted_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(item_tree, hf_s7comm_tis_interrupted_address, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(item_tree, hf_s7comm_tis_register_db1_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(item_tree, hf_s7comm_tis_register_db2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(item_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(item_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(item_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;
                proto_item_append_text(item, " [%d] BSTACK entry for: %s %d", i++,
                    val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"), blocknumber);
                rem -= 16;
                if (blocktype == S7COMM_SUBBLKTYPE_OB) {
                    proto_tree_add_item(item_tree, hf_s7comm_tis_interrupted_prioclass, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(item_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(item_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    rem -= 4;
                    if (rem >= 8) {
                        offset = s7comm_add_timestamp_to_tree(tvb, item_tree, offset, FALSE, FALSE);
                        rem -= 8;
                    } else {
                        proto_tree_add_item(item_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, rem, ENC_NA);
                        offset += rem;
                        break;
                    }
                }
            }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Output LSTACK (0x05)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_lstack(tvbuff_t *tvb,
                            proto_tree *td_tree,
                            guint8 type,
                            guint32 offset)
{
    guint16 len;

    if (type == S7COMM_UD_TYPE_REQ) {
        proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_prioclass, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(td_tree, hf_s7comm_tis_bstack_nest_depth, tvb, offset, 1, ENC_NA);
        offset += 1;
    } else {
        proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_address, tvb, offset, 2, ENC_NA);
        offset += 2;
        len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(td_tree, hf_s7comm_tis_lstack_size, tvb, offset, 2, ENC_NA);
        offset += 2;
        proto_tree_add_item(td_tree, hf_s7comm_tis_lstack_data, tvb, offset, len, ENC_NA);
        offset += len;
        proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_prioclass, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(td_tree, hf_s7comm_tis_lstack_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(td_tree, hf_s7comm_tis_lstack_reserved, tvb, offset, 2, ENC_NA);
        offset += 2;
        offset = s7comm_add_timestamp_to_tree(tvb, td_tree, offset, FALSE, FALSE);
    }
    return offset;
}
/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Exit Hold (0x0b)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_exithold(tvbuff_t *tvb,
                              proto_tree *td_tree,
                              guint8 type,
                              guint32 offset)
{
    /* Only request with data payload was seen */
    switch (type) {
        case S7COMM_UD_TYPE_REQ:
            proto_tree_add_item(td_tree, hf_s7comm_tis_exithold_until, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(td_tree, hf_s7comm_tis_exithold_res1, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Breakpoint (0x0a)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_breakpoint(tvbuff_t *tvb,
                                proto_tree *td_tree,
                                guint8 type,
                                guint32 offset)
{
    switch (type) {
        case S7COMM_UD_TYPE_REQ:
            proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            break;
        case S7COMM_UD_TYPE_RES:
        case S7COMM_UD_TYPE_PUSH:
            /* Info: Both blocknumbers and addresses are the same on online-blockview inside a block.
             * On return out of a block, the first address contains the current breakpoint, the second
             * address the address from where it was returned (previous block).
             */
            proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_address, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_address, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_stw, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu1, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu2, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_ar1, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_ar2, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_db1_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_db2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(td_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands / Test and installation functions
 *           Dissects the data part
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_data(tvbuff_t *tvb,
                          proto_tree *tree,
                          guint8 type,
                          guint8 subfunc,
                          guint16 td_size,
                          guint32 offset)
{
    proto_item *item = NULL;
    proto_tree *td_tree = NULL;

    if (td_size > 0) {
        item = proto_tree_add_item(tree, hf_s7comm_tis_data, tvb, offset, td_size, ENC_NA);
        td_tree = proto_item_add_subtree(item, ett_s7comm_prog_data);
        switch (subfunc) {
            case S7COMM_UD_SUBF_PROG_OUTISTACK:
                offset = s7comm_decode_ud_tis_istack(tvb, td_tree, type, offset);
                break;
            case S7COMM_UD_SUBF_PROG_OUTBSTACK:
                offset = s7comm_decode_ud_tis_bstack(tvb, td_tree, td_size, type, offset);
                break;
            case S7COMM_UD_SUBF_PROG_OUTLSTACK:
                offset = s7comm_decode_ud_tis_lstack(tvb, td_tree, type, offset);
                break;
            case S7COMM_UD_SUBF_PROG_BREAKPOINT:
                offset = s7comm_decode_ud_tis_breakpoint(tvb, td_tree, type, offset);
                break;
            case S7COMM_UD_SUBF_PROG_EXITHOLD:
                offset = s7comm_decode_ud_tis_exithold(tvb, td_tree, type, offset);
                break;
            case S7COMM_UD_SUBF_PROG_BLOCKSTAT:
            case S7COMM_UD_SUBF_PROG_BLOCKSTAT2:
                offset = s7comm_decode_ud_tis_blockstat(tvb, td_tree, td_size, type, subfunc, offset);
                break;
            case S7COMM_UD_SUBF_PROG_VARSTAT:
                offset = s7comm_decode_ud_tis_varstat(tvb, td_tree, type, offset);
                break;
            case S7COMM_UD_SUBF_PROG_DISABLEJOB:
            case S7COMM_UD_SUBF_PROG_ENABLEJOB:
            case S7COMM_UD_SUBF_PROG_DELETEJOB:
            case S7COMM_UD_SUBF_PROG_READJOBLIST:
            case S7COMM_UD_SUBF_PROG_READJOB:
            case S7COMM_UD_SUBF_PROG_REPLACEJOB:
                offset = s7comm_decode_ud_tis_jobs(tvb, td_tree, td_size, type, subfunc, offset);
                break;
            case S7COMM_UD_SUBF_PROG_MODVAR:
                offset = s7comm_decode_ud_tis_modvar(tvb, td_tree, type, offset);
                break;
            case S7COMM_UD_SUBF_PROG_FORCE:
                offset = s7comm_decode_ud_tis_force(tvb, td_tree, type, offset);
                break;
            default:
                proto_tree_add_item(td_tree, hf_s7comm_varstat_unknown, tvb, offset, td_size, ENC_NA);
                offset += td_size;
                break;
        }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands / Test and installation functions
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_tis_subfunc(tvbuff_t *tvb,
                             proto_tree *data_tree,
                             guint8 type,
                             guint8 subfunc,
                             guint32 offset)
{
    guint16 tp_size = 0;
    guint16 td_size = 0;

    tp_size = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(data_tree, hf_s7comm_tis_parametersize, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    td_size = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(data_tree, hf_s7comm_tis_datasize, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* Parameter tree */
    offset = s7comm_decode_ud_tis_param(tvb, data_tree, type, tp_size, offset);
    /* Data tree */
    offset = s7comm_decode_ud_tis_data(tvb, data_tree, type, subfunc, td_size, offset);
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 5 -> Security functions?
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_security_subfunc(tvbuff_t *tvb,
                                  proto_tree *data_tree,
                                  guint32 dlength,
                                  guint32 offset)
{
    /* Display dataset as raw bytes. Maybe this part can be extended with further knowledge. */
    proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
    offset += dlength;

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 6 -> PBC, Programmable Block Functions (e.g. BSEND/BRECV), before reassembly
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_pbc_pre_reass(tvbuff_t *tvb,
                               packet_info *pinfo,
                               proto_tree *data_tree,
                               guint8 type,                /* Type of data (request/response) */
                               guint16 *dlength,
                               guint32 *r_id,              /* R_ID of the PBC communication */
                               guint32 offset)
{
    if ((type == S7COMM_UD_TYPE_REQ || type == S7COMM_UD_TYPE_RES) && (*dlength >= 8)) {
        proto_tree_add_item(data_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(data_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(data_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* 0x00 when passive partners is sending, 0xcc when active partner is sending? */
        proto_tree_add_item(data_tree, hf_s7comm_pbc_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(data_tree, hf_s7comm_pbc_r_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        *r_id = tvb_get_ntohl(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " R_ID=0x%X", *r_id);
        offset += 4;
        *dlength -= 8;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 6 -> PBC, Programmable Block Functions (e.g. BSEND/BRECV)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_pbc_subfunc(tvbuff_t *tvb,
                             proto_tree *data_tree,
                             guint32 dlength,
                             guint32 offset)
{
    proto_tree_add_item(data_tree, hf_s7comm_pbc_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 2, ENC_NA);
    offset += (dlength - 2);

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> NC programming functions (file download/upload), before reassembly
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_ncprg_pre_reass(tvbuff_t *tvb,
                                 proto_tree *data_tree,
                                 guint8 type,                /* Type of data (request/response) */
                                 guint8 subfunc,             /* Subfunction */
                                 guint16 *dlength,
                                 guint32 offset)
{
    if ((type == S7COMM_UD_TYPE_NCRES || type == S7COMM_UD_TYPE_NCPUSH) &&
        (subfunc == S7COMM_NCPRG_FUNCDOWNLOADBLOCK ||
         subfunc == S7COMM_NCPRG_FUNCUPLOAD ||
         subfunc == S7COMM_NCPRG_FUNCSTARTUPLOAD)) {
        proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
        offset += 2;
        *dlength -= 2;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> NC programming functions (file download/upload)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_ncprg_subfunc(tvbuff_t *tvb,
                               packet_info *pinfo,
                               proto_tree *data_tree,
                               guint8 type,                /* Type of data (request/response) */
                               guint8 subfunc,             /* Subfunction */
                               guint32 dlength,
                               guint32 offset)
{
    const guint8 *str_filename;
    guint32 string_end_offset;
    guint32 string_len;
    guint32 filelength;
    guint32 start_offset;

    if (dlength >= 2) {
        if (type == S7COMM_UD_TYPE_NCREQ && subfunc == S7COMM_NCPRG_FUNCREQUESTDOWNLOAD) {
            proto_tree_add_item_ret_string(data_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, dlength,
                                           ENC_ASCII|ENC_NA, wmem_packet_scope(), &str_filename);
            col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str_filename);
            offset += dlength;
        } else if (type == S7COMM_UD_TYPE_NCREQ && subfunc == S7COMM_NCPRG_FUNCSTARTUPLOAD) {
            proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_unackcount, tvb, offset, 1, ENC_NA);
            offset += 1;
            dlength -= 1;
            proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 1, ENC_NA);
            offset += 1;
            dlength -= 1;
            proto_tree_add_item_ret_string(data_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, dlength,
                                           ENC_ASCII|ENC_NA, wmem_packet_scope(), &str_filename);
            col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str_filename);
            offset += dlength;
        } else if (type == S7COMM_UD_TYPE_NCRES && subfunc == S7COMM_NCPRG_FUNCREQUESTDOWNLOAD) {
                proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_unackcount, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 1, ENC_NA);
                offset += 1;
        } else if (type == S7COMM_UD_TYPE_NCPUSH && (subfunc == S7COMM_NCPRG_FUNCCONTUPLOAD || subfunc == S7COMM_NCPRG_FUNCCONTDOWNLOAD)) {
                proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_unackcount, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 1, ENC_NA);
                offset += 1;
        } else if ((type == S7COMM_UD_TYPE_NCRES || type == S7COMM_UD_TYPE_NCPUSH) &&
                (subfunc == S7COMM_NCPRG_FUNCDOWNLOADBLOCK ||
                 subfunc == S7COMM_NCPRG_FUNCUPLOAD ||
                 subfunc == S7COMM_NCPRG_FUNCSTARTUPLOAD)) {
            start_offset = offset;
            /* file length may be contain only spaces when downloading a directory */
            proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_filelength, tvb, offset, 8, ENC_ASCII|ENC_NA);
            offset += 8;
            proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_filetime, tvb, offset, 16, ENC_ASCII|ENC_NA);
            offset += 16;
            /* File path and file data aren't always there */
            if (dlength > 24) {
                if (subfunc == S7COMM_NCPRG_FUNCDOWNLOADBLOCK || subfunc == S7COMM_NCPRG_FUNCSTARTUPLOAD || subfunc == S7COMM_NCPRG_FUNCUPLOAD) {
                    string_end_offset = tvb_find_guint8(tvb, offset, dlength-8-16, 0x0a);
                    if (string_end_offset > 0) {
                        string_len = string_end_offset - offset + 1;    /* include 0x0a */
                        proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_filepath, tvb, offset, string_len, ENC_ASCII|ENC_NA);
                        offset += string_len;
                        filelength = dlength - (offset - start_offset);
                        proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_filedata, tvb, offset, filelength, ENC_NA);
                        offset += filelength;
                    }
                }
            }
        } else {
            proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
            offset += 2;
            dlength -= 2;
            if (dlength >= 4) {
                proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
                offset += dlength;
            }
        }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Message services
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_message_service(tvbuff_t *tvb,
                              packet_info *pinfo,
                              proto_tree *data_tree,
                              guint8 type,                /* Type of data (request/response) */
                              guint32 dlength,
                              guint32 offset)
{
    guint8 events;
    guint8 almtype;
    gchar events_string[42];

    switch (type) {
        case S7COMM_UD_TYPE_REQ:
            events = tvb_get_guint8(tvb, offset);
            proto_tree_add_bitmask(data_tree, tvb, offset, hf_s7comm_cpu_msgservice_subscribe_events,
                ett_s7comm_cpu_msgservice_subscribe_events, s7comm_cpu_msgservice_subscribe_events_fields, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_req_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            g_strlcpy(events_string, "", sizeof(events_string));
            if (events & 0x01) g_strlcat(events_string, "MODE,", sizeof(events_string));    /* Change in mode-transition: Stop, Run, by Push and Function-group=0, Subfunction: 0=Stop, 1=Warm Restart, 2=RUN */
            if (events & 0x02) g_strlcat(events_string, "SYS,", sizeof(events_string));     /* System diagnostics */
            if (events & 0x04) g_strlcat(events_string, "USR,", sizeof(events_string));     /* User-defined diagnostic messages */
            if (events & 0x08) g_strlcat(events_string, "-4-,", sizeof(events_string));     /* currently unknown flag */
            if (events & 0x10) g_strlcat(events_string, "-5-,", sizeof(events_string));     /* currently unknown flag */
            if (events & 0x20) g_strlcat(events_string, "-6-,", sizeof(events_string));     /* currently unknown flag */
            if (events & 0x40) g_strlcat(events_string, "-7-,", sizeof(events_string));     /* currently unknown flag */
            if (events & 0x80) g_strlcat(events_string, "ALM,", sizeof(events_string));     /* Program block message, type of message in additional field */
            if (strlen(events_string) > 2)
                events_string[strlen(events_string) - 1 ] = '\0';
            col_append_fstr(pinfo->cinfo, COL_INFO, " SubscribedEvents=(%s)", events_string);

            proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_username, tvb, offset, 8, ENC_ASCII|ENC_NA);
            offset += 8;
            if ((events & 0x80) && (dlength > 10)) {
                almtype = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_almtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " AlmType=%s", val_to_str(almtype, cpu_msgservice_almtype_names, "Unknown type: 0x%02x"));
                offset += 1;
                proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_req_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
        case S7COMM_UD_TYPE_RES:
            proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_res_result, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_res_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            if (dlength > 2) {
                almtype = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_almtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " AlmType=%s", val_to_str(almtype, cpu_msgservice_almtype_names, "Unknown type: 0x%02x"));
                offset += 1;
                proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_res_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_res_reserved3, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
    }

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 4 -> alarm, main tree for all except query response
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_cpu_alarm_main(tvbuff_t *tvb,
                                packet_info *pinfo,
                                proto_tree *data_tree,
                                guint8 type,                /* Type of data (request/response) */
                                guint8 subfunc,             /* Subfunction */
                                guint32 offset)
{
    guint32 start_offset;
    guint32 asc_start_offset;
    guint32 msg_obj_start_offset;
    guint32 ev_id;
    proto_item *msg_item = NULL;
    proto_tree *msg_item_tree = NULL;
    proto_item *msg_obj_item = NULL;
    proto_tree *msg_obj_item_tree = NULL;
    proto_item *msg_work_item = NULL;
    proto_tree *msg_work_item_tree = NULL;
    guint8 nr_objects;
    guint8 i;
    guint8 syntax_id;
    guint8 nr_of_additional_values;
    guint8 signalstate;
    guint8 sig_nr;
    guint8 ret_val;
    guint8 querytype;
    guint8 varspec_length;

    start_offset = offset;

    msg_item = proto_tree_add_item(data_tree, hf_s7comm_cpu_alarm_message_item, tvb, offset, 0, ENC_NA);
    msg_item_tree = proto_item_add_subtree(msg_item, ett_s7comm_cpu_alarm_message);

    switch (subfunc) {
        case S7COMM_UD_SUBF_CPU_SCAN_IND:
            proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_scan_unknown1, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            msg_work_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_timestamp_coming, tvb, offset, 8, ENC_NA);
            msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_timestamp);
            offset = s7comm_add_timestamp_to_tree(tvb, msg_work_item_tree, offset, TRUE, FALSE);
            proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_scan_unknown2, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case S7COMM_UD_SUBF_CPU_ALARM8_IND:
        case S7COMM_UD_SUBF_CPU_ALARMACK_IND:
        case S7COMM_UD_SUBF_CPU_ALARMSQ_IND:
        case S7COMM_UD_SUBF_CPU_ALARMS_IND:
        case S7COMM_UD_SUBF_CPU_NOTIFY_IND:
        case S7COMM_UD_SUBF_CPU_NOTIFY8_IND:
            msg_work_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_timestamp_coming, tvb, offset, 8, ENC_NA);
            msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_timestamp);
            offset = s7comm_add_timestamp_to_tree(tvb, msg_work_item_tree, offset, TRUE, FALSE);
            break;
    }
    proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_function, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    nr_objects = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(msg_item_tree, hf_s7comm_cpu_alarm_message_nr_objects, tvb, offset, 1, nr_objects);
    offset += 1;
    for (i = 0; i < nr_objects; i++) {
        msg_obj_start_offset = offset;
        msg_obj_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_obj_item, tvb, offset, 0, ENC_NA);
        msg_obj_item_tree = proto_item_add_subtree(msg_obj_item, ett_s7comm_cpu_alarm_message_object);
        proto_item_append_text(msg_obj_item_tree, " [%d]", i+1);
        if (type == S7COMM_UD_TYPE_REQ || type == S7COMM_UD_TYPE_PUSH) {
            proto_tree_add_item(msg_obj_item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            varspec_length = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, varspec_length);
            offset += 1;
            syntax_id = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, syntax_id);
            offset += 1;
            switch (syntax_id) {
                case S7COMM_SYNTAXID_ALARM_LOCKFREESET:
                case S7COMM_SYNTAXID_ALARM_INDSET:
                case S7COMM_SYNTAXID_NOTIFY_INDSET:
                case S7COMM_SYNTAXID_ALARM_ACKSET:
                    nr_of_additional_values = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_nr_add_values, tvb, offset, 1, nr_of_additional_values);
                    offset += 1;
                    ev_id = tvb_get_ntohl(tvb, offset);
                    proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_eventid, tvb, offset, 4, ev_id);
                    offset += 4;
                    proto_item_append_text(msg_obj_item_tree, ": EventID=0x%08x", ev_id);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " EventID=0x%08x", ev_id);
                    if (syntax_id == S7COMM_SYNTAXID_ALARM_INDSET || syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET) {
                        signalstate = tvb_get_guint8(tvb, offset);
                        proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_eventstate,
                            ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
                        offset += 1;
                        /* show SIG with True values for a quick overview in info-column */
                        if (signalstate > 0) {
                            col_append_str(pinfo->cinfo, COL_INFO, " On=[");
                            for (sig_nr = 0; sig_nr < 8; sig_nr++) {
                                if (signalstate & 0x01) {
                                    signalstate >>= 1;
                                    if (signalstate == 0) {
                                        col_append_fstr(pinfo->cinfo, COL_INFO, "SIG_%d", sig_nr + 1);
                                    } else {
                                        col_append_fstr(pinfo->cinfo, COL_INFO, "SIG_%d,", sig_nr + 1);
                                    }
                                } else {
                                    signalstate >>= 1;
                                }
                            }
                            col_append_str(pinfo->cinfo, COL_INFO, "]");
                        }
                        proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_state,
                            ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                    if (syntax_id == S7COMM_SYNTAXID_ALARM_INDSET || syntax_id == S7COMM_SYNTAXID_ALARM_ACKSET || syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET) {
                        proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_ackstate_going,
                            ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_ackstate_coming,
                            ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                    if (syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET) {
                        proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_event_going,
                            ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_event_coming,
                            ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_event_lastchanged,
                            ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_event_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                    if (syntax_id == S7COMM_SYNTAXID_ALARM_INDSET || syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET) {
                        if (nr_of_additional_values > 0) {
                            asc_start_offset = offset;
                            msg_work_item = proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_associated_value, tvb, offset, 0, ENC_NA);
                            msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_associated_value);
                            offset = s7comm_decode_response_read_data(tvb, msg_work_item_tree, nr_of_additional_values, offset);
                            proto_item_set_len(msg_work_item_tree, offset - asc_start_offset);
                        }
                    }
                    break;
                case S7COMM_SYNTAXID_ALARM_QUERYREQSET:
                    proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_unknown1, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    querytype = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_querytype, tvb, offset, 1, querytype);
                    offset += 1;
                    proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_unknown2, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    ev_id = tvb_get_ntohl(tvb, offset);
                    /* there is a querytype=8, which only occurs when a previous SZL request 0x131 index 0x10 has a missing flag in funk_1 */
                    switch (querytype) {
                        case S7COMM_ALARM_MESSAGE_QUERYTYPE_BYALARMTYPE:
                            proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_alarmtype, tvb, offset, 4, ENC_BIG_ENDIAN);
                            col_append_fstr(pinfo->cinfo, COL_INFO, " ByAlarmtype=%s",
                                val_to_str(ev_id, alarm_message_query_alarmtype_names, "Unknown Alarmtype: %u"));
                            break;
                        case S7COMM_ALARM_MESSAGE_QUERYTYPE_BYEVENTID:
                            proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_eventid, tvb, offset, 4, ENC_BIG_ENDIAN);
                            col_append_fstr(pinfo->cinfo, COL_INFO, " ByEventID=0x%08x", ev_id);
                            break;
                        default:
                            break;
                    }
                    offset += 4;
                    break;
                default:
                    /* for current unknown syntax id, set offset to end of dataset. The varspec_length includes
                     * the byte for the syntax_id, so minus one.
                     */
                    offset += (varspec_length - 1);
                    break;
            }
        } else if (type == S7COMM_UD_TYPE_RES) {
            ret_val = tvb_get_guint8(tvb, offset);
            proto_item_append_text(msg_obj_item_tree, ": (%s)", val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
            proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
            offset += 1;
        }
        proto_item_set_len(msg_obj_item_tree, offset - msg_obj_start_offset);
    }
    proto_item_set_len(msg_item_tree, offset - start_offset);
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 4 -> alarm query response
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_cpu_alarm_query_response(tvbuff_t *tvb,
                                          proto_tree *data_tree,
                                          guint32 offset)
{
    proto_item *msg_item = NULL;
    proto_tree *msg_item_tree = NULL;
    proto_item *msg_obj_item = NULL;
    proto_tree *msg_obj_item_tree = NULL;
    proto_item *msg_work_item = NULL;
    proto_tree *msg_work_item_tree = NULL;
    guint32 start_offset;
    guint32 msg_obj_start_offset;
    guint32 asc_start_offset;
    guint32 ev_id;
    guint8 returncode;
    guint8 alarmtype;
    guint16 complete_length;
    gint32 remaining_length;
    gboolean cont;

    start_offset = offset;
    msg_item = proto_tree_add_item(data_tree, hf_s7comm_cpu_alarm_message_item, tvb, offset, 0, ENC_NA);
    msg_item_tree = proto_item_add_subtree(msg_item, ett_s7comm_cpu_alarm_message);

    /* Maybe this value here is something different, always 0x00 or 0x01 */
    proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_function, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_nr_objects, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    returncode = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(msg_item_tree, hf_s7comm_data_returncode, tvb, offset, 1, returncode);
    offset += 1;
    proto_tree_add_item(msg_item_tree, hf_s7comm_data_transport_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    complete_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(msg_item_tree, hf_s7comm_cpu_alarm_query_completelen, tvb, offset, 2, complete_length);
    remaining_length = (gint32)complete_length;
    offset += 2;

    if (returncode == S7COMM_ITEM_RETVAL_DATA_OK) {
        do {
            msg_obj_start_offset = offset;
            msg_obj_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_obj_item, tvb, offset, 0, ENC_NA);
            msg_obj_item_tree = proto_item_add_subtree(msg_obj_item, ett_s7comm_cpu_alarm_message_object);

            proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_datasetlen, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_resunknown1, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* begin of count dataset length */
            alarmtype = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_alarmtype, tvb, offset, 1, alarmtype);
            proto_item_append_text(msg_obj_item_tree, " (Alarmtype=%s)", val_to_str(alarmtype, alarm_message_query_alarmtype_names, "Unknown Alarmtype: %u"));
            offset += 1;
            ev_id = tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_eventid, tvb, offset, 4, ev_id);
            proto_item_append_text(msg_obj_item_tree, ": EventID=0x%08x", ev_id);
            offset += 4;
            proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_resunknown1, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_eventstate,
                ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_ackstate_going,
                ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_ackstate_coming,
                ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
            offset += 1;
            if (alarmtype == S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_ALARM_S) {
                /* 8 bytes timestamp (coming)*/
                msg_work_item = proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_timestamp_coming, tvb, offset, 8, ENC_NA);
                msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_timestamp);
                offset = s7comm_add_timestamp_to_tree(tvb, msg_work_item_tree, offset, TRUE, FALSE);
                /* Associated value of coming alarm */
                asc_start_offset = offset;
                msg_work_item = proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_associated_value, tvb, offset, 0, ENC_NA);
                msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_associated_value);
                offset = s7comm_decode_response_read_data(tvb, msg_work_item_tree, 1, offset);
                proto_item_set_len(msg_work_item_tree, offset - asc_start_offset);
                /* 8 bytes timestamp (going)
                 * If all bytes in timestamp are zero, then the message is still active. */
                msg_work_item = proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_timestamp_going, tvb, offset, 8, ENC_NA);
                msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_timestamp);
                offset = s7comm_add_timestamp_to_tree(tvb, msg_work_item_tree, offset, TRUE, FALSE);
                /* Associated value of going alarm  */
                asc_start_offset = offset;
                msg_work_item = proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_associated_value, tvb, offset, 0, ENC_NA);
                msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_associated_value);
                offset = s7comm_decode_response_read_data(tvb, msg_work_item_tree, 1, offset);
                proto_item_set_len(msg_work_item_tree, offset - asc_start_offset);
            }
            remaining_length = remaining_length - (offset - msg_obj_start_offset);
            proto_item_set_len(msg_obj_item_tree, offset - msg_obj_start_offset);
            /* when complete_length is 0xffff, then loop until terminating null */
            if (complete_length == 0xffff) {
                cont = (tvb_get_guint8(tvb, offset) > 0);
            } else {
                cont = (remaining_length > 0);
            }
        } while (cont);
    }
    proto_item_set_len(msg_item_tree, offset - start_offset);

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 4 -> diagnostic message
 * Also used as a dataset in the diagnostic buffer, read with SZL-ID 0x00a0 index 0.
 *
 *******************************************************************************************************/
guint32
s7comm_decode_ud_cpu_diagnostic_message(tvbuff_t *tvb,
                                        packet_info *pinfo,
                                        gboolean add_info_to_col,
                                        proto_tree *data_tree,
                                        guint32 offset)
{
    proto_item *msg_item = NULL;
    proto_tree *msg_item_tree = NULL;
    guint16 eventid;
    guint16 eventid_masked;
    const gchar *event_text;
    gboolean has_text = FALSE;

    msg_item = proto_tree_add_item(data_tree, hf_s7comm_cpu_diag_msg_item, tvb, offset, 20, ENC_NA);
    msg_item_tree = proto_item_add_subtree(msg_item, ett_s7comm_cpu_diag_msg);

    eventid = tvb_get_ntohs(tvb, offset);
    if ((eventid >= 0x8000) && (eventid <= 0x9fff)) {
        eventid_masked = eventid & 0xf0ff;
        if ((event_text = try_val_to_str_ext(eventid_masked, &cpu_diag_eventid_0x8_0x9_names_ext))) {
            if (add_info_to_col) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " Event='%s'", event_text);
            }
            has_text = TRUE;
        } else {
            if (add_info_to_col) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " EventID=0x%04x", eventid);
            }
        }
    } else if ((eventid >= 0x1000) && (eventid < 0x8000)) {
        if ((event_text = try_val_to_str_ext(eventid, &cpu_diag_eventid_fix_names_ext))) {
            if (add_info_to_col) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " Event='%s'", event_text);
            }
            has_text = TRUE;
        } else {
            if (add_info_to_col) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " EventID=0x%04x", eventid);
            }
        }
    } else {
        if (add_info_to_col) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " EventID=0x%04x", eventid);
        }
    }
    proto_tree_add_bitmask(msg_item_tree, tvb, offset, hf_s7comm_cpu_diag_msg_eventid,
            ett_s7comm_cpu_diag_msg_eventid, s7comm_cpu_diag_msg_eventid_fields, ENC_BIG_ENDIAN);
    if (has_text) {
        proto_item_append_text(msg_item_tree, ": Event='%s'", event_text);
    } else {
        proto_item_append_text(msg_item_tree, ": EventID=0x%04x", eventid);
    }
    offset += 2;
    proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_prioclass, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_obnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_datid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_info1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_info2, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    offset = s7comm_add_timestamp_to_tree(tvb, msg_item_tree, offset, FALSE, FALSE);

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 7 -> time functions
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_time_subfunc(tvbuff_t *tvb,
                              proto_tree *data_tree,
                              guint8 type,                /* Type of data (request/response) */
                              guint8 subfunc,             /* Subfunction */
                              guint8 ret_val,             /* Return value in data part */
                              guint32 dlength,
                              guint32 offset)
{
    gboolean know_data = FALSE;

    switch (subfunc) {
        case S7COMM_UD_SUBF_TIME_READ:
        case S7COMM_UD_SUBF_TIME_READF:
            if (type == S7COMM_UD_TYPE_RES) {                   /*** Response ***/
                if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
                    proto_item_append_text(data_tree, ": ");
                    offset = s7comm_add_timestamp_to_tree(tvb, data_tree, offset, TRUE, TRUE);
                }
                know_data = TRUE;
            }
            break;
        case S7COMM_UD_SUBF_TIME_SET:
        case S7COMM_UD_SUBF_TIME_SET2:
            if (type == S7COMM_UD_TYPE_REQ) {                   /*** Request ***/
                if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
                    proto_item_append_text(data_tree, ": ");
                    offset = s7comm_add_timestamp_to_tree(tvb, data_tree, offset, TRUE, TRUE);
                }
                know_data = TRUE;
            }
            break;
        default:
            break;
    }

    if (know_data == FALSE && dlength > 0) {
        proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
        offset += dlength;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 3 -> block functions
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_block_subfunc(tvbuff_t *tvb,
                               packet_info *pinfo,
                               proto_tree *data_tree,
                               guint8 type,                /* Type of data (request/response) */
                               guint8 subfunc,             /* Subfunction */
                               guint8 ret_val,             /* Return value in data part */
                               guint8 tsize,               /* transport size in data part */
                               guint32 dlength,
                               guint32 offset)
{
    guint32 count;
    guint32 i;
    const guint8 *pBlocknumber;
    guint16 blocknumber;
    guint8 blocktype;
    guint16 blocktype16;
    gboolean know_data = FALSE;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;
    proto_item *itemadd = NULL;
    char str_timestamp[30];
    char str_version[10];

    switch (subfunc) {
        /*************************************************
         * List blocks
         */
        case S7COMM_UD_SUBF_BLOCK_LIST:
            if (type == S7COMM_UD_TYPE_REQ) {
                /* Is this a possible combination? Never seen it... */

            } else if (type == S7COMM_UD_TYPE_RES) {
                count = dlength / 4;
                for (i = 0; i < count; i++) {
                    /* Insert a new tree of 4 byte length for every item */
                    item = proto_tree_add_item(data_tree, hf_s7comm_data_item, tvb, offset, 4, ENC_NA);
                    item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
                    blocktype16 = tvb_get_ntohs(tvb, offset);
                    proto_item_append_text(item, " [%d]: (Block type %s)", i+1, val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
                    itemadd = proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 2, ENC_ASCII|ENC_NA);
                    proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
                    offset += 2;
                    proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                }
                know_data = TRUE;
            }
            break;
        /*************************************************
         * List blocks of type
         */
        case S7COMM_UD_SUBF_BLOCK_LISTTYPE:
            if (type == S7COMM_UD_TYPE_REQ) {
                if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
                    blocktype16 = tvb_get_ntohs(tvb, offset);
                    itemadd = proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 2, ENC_ASCII|ENC_NA);
                    proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Type:[%s]",
                        val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
                    proto_item_append_text(data_tree, ": (%s)",
                        val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
                    offset += 2;
                }
                know_data = TRUE;

            } else if (type == S7COMM_UD_TYPE_RES) {
                if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
                    count = dlength / 4;

                    for (i = 0; i < count; i++) {
                        /* Insert a new tree of 4 byte length for every item */
                        item = proto_tree_add_item(data_tree, hf_s7comm_data_item, tvb, offset, 4, ENC_NA);
                        item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);

                        proto_item_append_text(item, " [%d]: (Block number %d)", i+1, tvb_get_ntohs(tvb, offset));
                        proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        /* The first Byte is unknown, kind of flags? */
                        proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                }
                know_data = TRUE;
            }
            break;
        /*************************************************
         * Get block infos
         */
        case S7COMM_UD_SUBF_BLOCK_BLOCKINFO:
            if (type == S7COMM_UD_TYPE_REQ) {
                if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
                    gint32 num = -1;
                    gboolean num_valid;
                    /* 8 Bytes of Data follow, 1./ 2. type, 3-7 blocknumber as ascii number */
                    blocktype16 = tvb_get_ntohs(tvb, offset);
                    itemadd = proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 2, ENC_ASCII|ENC_NA);
                    proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
                    offset += 2;
                    proto_tree_add_item_ret_string(data_tree, hf_s7comm_ud_blockinfo_block_num_ascii, tvb, offset, 5, ENC_ASCII|ENC_NA, wmem_packet_scope(), &pBlocknumber);
                    num_valid = ws_strtoi32((const gchar*)pBlocknumber, NULL, &num);
                    proto_item_append_text(data_tree, " [%s ",
                        val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s ",
                        val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
                    if (num_valid) {
                        proto_item_append_text(data_tree, "%d]", num);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
                    } else {
                        expert_add_info(pinfo, data_tree, &ei_s7comm_ud_blockinfo_block_num_ascii_invalid);
                        proto_item_append_text(data_tree, "NaN]");
                        col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
                    }
                    offset += 5;
                    itemadd = proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_filesys, tvb, offset, 1, ENC_ASCII|ENC_NA);
                    proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys: %c"));
                    offset += 1;
                }
                know_data = TRUE;

            } else if (type == S7COMM_UD_TYPE_RES) {
                /* 78 Bytes */
                if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
                    itemadd = proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 2, ENC_ASCII|ENC_NA);
                    proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_ntohs(tvb, offset), blocktype_names, "Unknown Block type: 0x%04x"));
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_infolength, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_unknown2, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_const3, tvb, offset, 2, ENC_ASCII|ENC_NA);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_unknown, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_bitmask(data_tree, tvb, offset, hf_s7comm_userdata_blockinfo_flags,
                        ett_s7comm_userdata_blockinfo_flags, s7comm_userdata_blockinfo_flags_fields, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    blocktype = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_subblk_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    blocknumber = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_uint(data_tree, hf_s7comm_ud_blockinfo_block_num, tvb, offset, 2, blocknumber);
                    /* Add block type and number to info column */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s %d]",
                        val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"),
                        blocknumber);
                    proto_item_append_text(data_tree, ": (Block:[%s %d])",
                        val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"),
                        blocknumber);
                    offset += 2;
                    /* "Length Load mem" -> the length in Step7 Manager seems to be this length +6 bytes */
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_load_mem_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_blocksecurity, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    s7comm_get_timestring_from_s7time(tvb, offset, str_timestamp, sizeof(str_timestamp));
                    proto_tree_add_string(data_tree, hf_s7comm_ud_blockinfo_code_timestamp, tvb, offset, 6, str_timestamp);
                    offset += 6;
                    s7comm_get_timestring_from_s7time(tvb, offset, str_timestamp, sizeof(str_timestamp));
                    proto_tree_add_string(data_tree, hf_s7comm_ud_blockinfo_interface_timestamp, tvb, offset, 6, str_timestamp);
                    offset += 6;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_ssb_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_add_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_localdata_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_mc7_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_author, tvb, offset, 8, ENC_ASCII|ENC_NA);
                    offset += 8;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_family, tvb, offset, 8, ENC_ASCII|ENC_NA);
                    offset += 8;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_headername, tvb, offset, 8, ENC_ASCII|ENC_NA);
                    offset += 8;
                    g_snprintf(str_version, sizeof(str_version), "%d.%d", ((tvb_get_guint8(tvb, offset) & 0xf0) >> 4), tvb_get_guint8(tvb, offset) & 0x0f);
                    proto_tree_add_string(data_tree, hf_s7comm_ud_blockinfo_headerversion, tvb, offset, 1, str_version);
                    offset += 1;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_unknown, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_checksum(data_tree, tvb, offset, hf_s7comm_ud_blockinfo_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_reserved1, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_reserved2, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                }
                know_data = TRUE;
            }
            break;
        default:
            break;
    }
    if (know_data == FALSE && dlength > 0) {
        proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
        offset += dlength;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 2 -> Read record
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_readrec(tvbuff_t *tvb,
                         proto_tree *tree,
                         guint8 type,
                         guint32 offset)
{
    guint32 ret_val;
    guint32 statuslen;
    guint32 reclen;
    guint8 item_count;

    if (type == S7COMM_UD_TYPE_REQ) {
        proto_tree_add_item(tree, hf_s7comm_rdrec_reserved1, tvb, offset, 1, ENC_NA);
        offset += 1;
        /* Although here is an item_count field, values above 1 aren't allowed or at least never seen */
        item_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
        offset += 1;
        if (item_count > 0) {
            offset = s7comm_decode_param_item(tvb, offset, tree, 0);
        }
    } else if (type == S7COMM_UD_TYPE_RES) {
        /* The item with data is used for optional status code similar to the
         * STATUS output of SFB52 RDREC used in Plc code.
         */
        proto_tree_add_item(tree, hf_s7comm_rdrec_reserved1, tvb, offset, 1, ENC_NA);
        offset += 1;
        item_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
        offset += 1;
        /* As all testsubjects have shown that no more than one item is allowed,
         * we decode only the first item here.
         */
        if (item_count > 0) {
            proto_tree_add_item_ret_uint(tree, hf_s7comm_data_returncode, tvb, offset, 1, ENC_BIG_ENDIAN, &ret_val);
            offset += 1;
            if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
                proto_tree_add_item(tree, hf_s7comm_data_transport_size, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            proto_tree_add_item_ret_uint(tree, hf_s7comm_rdrec_statuslen, tvb, offset, 1, ENC_BIG_ENDIAN, &statuslen);
            offset += 1;
            if (statuslen > 0) {
                proto_tree_add_item(tree, hf_s7comm_rdrec_statusdata, tvb, offset, statuslen, ENC_NA);
                offset += statuslen;
            } else {
                offset += 1;    /* Fillbyte */
            }
            if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
                proto_tree_add_item_ret_uint(tree, hf_s7comm_rdrec_recordlen, tvb, offset, 2, ENC_BIG_ENDIAN, &reclen);
                offset += 2;
                if (reclen > 0) {
                    proto_tree_add_item(tree, hf_s7comm_rdrec_data, tvb, offset, reclen, ENC_NA);
                    offset += reclen;
                }
            }
        }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 2 -> cyclic services
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_cyclic_subfunc(tvbuff_t *tvb,
                                packet_info *pinfo,
                                guint8 seq_num,
                                proto_tree *data_tree,
                                guint8 type,                /* Type of data (request/response) */
                                guint8 subfunc,             /* Subfunction */
                                guint32 dlength,
                                guint32 offset)
{
    gboolean know_data = FALSE;
    guint32 offset_old;
    guint32 len_item;
    guint8 item_count;
    guint8 i;
    guint8 job_id;

    switch (subfunc)
    {
        case S7COMM_UD_SUBF_CYCLIC_CHANGE_MOD:
            if (type == S7COMM_UD_TYPE_REQ) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " JobID=%d", seq_num);
            }
            /* fall through */
        case S7COMM_UD_SUBF_CYCLIC_TRANSF:
        case S7COMM_UD_SUBF_CYCLIC_CHANGE:
            item_count = tvb_get_guint8(tvb, offset + 1);     /* first byte reserved??? */
            proto_tree_add_uint(data_tree, hf_s7comm_param_itemcount, tvb, offset, 2, item_count);
            offset += 2;
            if (type == S7COMM_UD_TYPE_REQ) {
                proto_tree_add_item(data_tree, hf_s7comm_cycl_interval_timebase, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(data_tree, hf_s7comm_cycl_interval_time, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                for (i = 0; i < item_count; i++) {
                    offset_old = offset;
                    offset = s7comm_decode_param_item(tvb, offset, data_tree, i);
                    /* if length is not a multiple of 2 and this is not the last item, then add a fill-byte */
                    len_item = offset - offset_old;
                    if ((len_item % 2) && (i < (item_count-1))) {
                        offset += 1;
                    }
                }
            } else if (type == S7COMM_UD_TYPE_RES || type == S7COMM_UD_TYPE_PUSH) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " JobID=%d", seq_num);
                offset = s7comm_decode_response_read_data(tvb, data_tree, item_count, offset);
            }
            know_data = TRUE;
            break;
        case S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE:
            if (type == S7COMM_UD_TYPE_REQ) {
                proto_tree_add_item(data_tree, hf_s7comm_cycl_function, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(data_tree, hf_s7comm_cycl_jobid, tvb, offset, 1, ENC_BIG_ENDIAN);
                job_id = tvb_get_guint8(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " JobID=%d", job_id);
                offset += 1;
                know_data = TRUE;
            } else if (type == S7COMM_UD_TYPE_RES) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " JobID=%d", seq_num);
            }
            break;
        case S7COMM_UD_SUBF_CYCLIC_RDREC:
            offset = s7comm_decode_ud_readrec(tvb, data_tree, type, offset);
            know_data = TRUE;
            break;
    }

    if (know_data == FALSE && dlength > 0) {
        proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
        offset += dlength;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data: Data part and reassembly
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_data(tvbuff_t *tvb,
                      packet_info *pinfo,
                      proto_tree *tree,
                      guint16 dlength,
                      guint8 type,
                      guint8 funcgroup,
                      guint8 subfunc,
                      guint8 seq_num,
                      guint8 data_unit_ref,
                      guint8 last_data_unit,
                      guint32 offset)
{
    proto_item *item = NULL;
    proto_tree *data_tree = NULL;
    guint8 tsize;
    guint16 len;
    guint8 ret_val;
    guint32 length_rem = 0;
    gboolean save_fragmented;
    guint32 frag_id = 0;
    gboolean more_frags = FALSE;
    gboolean is_fragmented = FALSE;
    tvbuff_t* new_tvb = NULL;
    tvbuff_t* next_tvb = NULL;
    fragment_head *fd_head;
    gchar str_fragadd[32];

    /* The first 4 bytes of the data part of a userdata telegram are the same for all types.
     * This is also the minumum length of the data part.
     */
    if (dlength >= 4) {
        item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
        data_tree = proto_item_add_subtree(item, ett_s7comm_data);

        ret_val = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(data_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
        offset += 1;
        /* Not definitely known part, kind of "transport size"? constant 0x09, 1 byte
         * The position is the same as in a data response/write telegram,
         */
        tsize = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(data_tree, hf_s7comm_data_transport_size, tvb, offset, 1, tsize);
        offset += 1;
        len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(data_tree, hf_s7comm_data_length, tvb, offset, 2, len);
        offset += 2;

        if (len >= 2) {
            more_frags = (last_data_unit == S7COMM_UD_LASTDATAUNIT_NO);
            /* Some packets have an additional header before the payload, which must be
             * extracted from the data before reassembly.
             */
            switch (funcgroup) {
                case S7COMM_UD_FUNCGROUP_NCPRG:
                    offset = s7comm_decode_ud_ncprg_pre_reass(tvb, data_tree, type, subfunc, &len, offset);
                    /* Unfortunately on NC programming the first PDU is always shown as reassembled also when not fragmented,
                     * because data_unit_ref may overflow and start again at 0 on big file transfers.
                     */
                    is_fragmented = TRUE;
                    frag_id = seq_num;
                    break;
                case S7COMM_UD_FUNCGROUP_PBC:
                    /* The R_ID is used for fragment identification */
                    offset = s7comm_decode_ud_pbc_pre_reass(tvb, pinfo, data_tree, type, &len, &frag_id, offset);
                    is_fragmented = data_unit_ref > 0 || seq_num > 0;
                    break;
                default:
                    is_fragmented = (data_unit_ref > 0);
                    frag_id = data_unit_ref;
                    break;
            }
            /* Reassembly of fragmented data part */
            save_fragmented = pinfo->fragmented;
            if (is_fragmented) {            /* fragmented */
                pinfo->fragmented = TRUE;
                /* NC programming uses a different method of fragment indication. The sequence number is used as reference-id,
                 * the data unit reference number is increased with every packet, as the sender does not need to wait for
                 * the acknowledge of the packet. Also different in NC programming is, that also when a packet is not
                 * fragmented, data_unit_ref is > 0 and "reassembled" would be displayed even when not fragmented (count number of fragments?)
                 * Using fragment number does not work here, as it's only one byte. And if there are more than 255 fragments this would fail.
                 */
                fd_head = fragment_add_seq_next(&s7comm_reassembly_table,
                                                tvb, offset, pinfo,
                                                frag_id,               /* ID for fragments belonging together */
                                                NULL,                  /* void *data */
                                                len,                   /* fragment length - to the end */
                                                more_frags);           /* More fragments? */
                g_snprintf(str_fragadd, sizeof(str_fragadd), " id=%d", frag_id);
                new_tvb = process_reassembled_data(tvb, offset, pinfo,
                    "Reassembled S7COMM", fd_head, &s7comm_frag_items,
                    NULL, tree);
                if (new_tvb) { /* take it all */
                    /* add reassembly info only when there's more than one fragment */
                    if (fd_head && fd_head->next) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (S7COMM reassembled%s)", str_fragadd);
                        proto_item_append_text(data_tree, " (S7COMM reassembled%s)", str_fragadd);
                    }
                    next_tvb = new_tvb;
                    offset = 0;
                } else { /* make a new subset */
                    next_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, -1);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " (S7COMM fragment%s)", str_fragadd);
                    proto_item_append_text(data_tree, " (S7COMM fragment%s)", str_fragadd);
                    offset = 0;
                }
            } else { /* Not fragmented */
                next_tvb = tvb;
            }
            pinfo->fragmented = save_fragmented;
            length_rem = tvb_reported_length_remaining(next_tvb, offset);
            /* TODO: PBC telegrams say "Last data unit = no" and data_unit_ref=0 and not fragmented */
            if (last_data_unit == S7COMM_UD_LASTDATAUNIT_YES && length_rem > 0) {
                switch (funcgroup) {
                    case S7COMM_UD_FUNCGROUP_PROG:
                        offset = s7comm_decode_ud_tis_subfunc(next_tvb, data_tree, type, subfunc, offset);
                        break;
                    case S7COMM_UD_FUNCGROUP_CYCLIC:
                        offset = s7comm_decode_ud_cyclic_subfunc(next_tvb, pinfo, seq_num, data_tree, type, subfunc, length_rem, offset);
                        break;
                    case S7COMM_UD_FUNCGROUP_BLOCK:
                        offset = s7comm_decode_ud_block_subfunc(next_tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, length_rem, offset);
                        break;
                    case S7COMM_UD_FUNCGROUP_CPU:
                        switch (subfunc) {
                            case S7COMM_UD_SUBF_CPU_READSZL:
                                offset = s7comm_decode_ud_cpu_szl_subfunc(next_tvb, pinfo, data_tree, type, ret_val, length_rem, offset);
                                break;
                            case S7COMM_UD_SUBF_CPU_NOTIFY_IND:
                            case S7COMM_UD_SUBF_CPU_NOTIFY8_IND:
                            case S7COMM_UD_SUBF_CPU_ALARMSQ_IND:
                            case S7COMM_UD_SUBF_CPU_ALARMS_IND:
                            case S7COMM_UD_SUBF_CPU_SCAN_IND:
                            case S7COMM_UD_SUBF_CPU_ALARMACK:
                            case S7COMM_UD_SUBF_CPU_ALARMACK_IND:
                            case S7COMM_UD_SUBF_CPU_ALARM8_IND:
                            case S7COMM_UD_SUBF_CPU_ALARM8LOCK:
                            case S7COMM_UD_SUBF_CPU_ALARM8LOCK_IND:
                            case S7COMM_UD_SUBF_CPU_ALARM8UNLOCK:
                            case S7COMM_UD_SUBF_CPU_ALARM8UNLOCK_IND:
                                offset = s7comm_decode_ud_cpu_alarm_main(next_tvb, pinfo, data_tree, type, subfunc, offset);
                                break;
                            case S7COMM_UD_SUBF_CPU_ALARMQUERY:
                                if (type == S7COMM_UD_TYPE_RES) {
                                    offset = s7comm_decode_ud_cpu_alarm_query_response(next_tvb, data_tree, offset);
                                } else {
                                    offset = s7comm_decode_ud_cpu_alarm_main(next_tvb, pinfo, data_tree, type, subfunc, offset);
                                }
                                break;
                            case S7COMM_UD_SUBF_CPU_DIAGMSG:
                                offset = s7comm_decode_ud_cpu_diagnostic_message(next_tvb, pinfo, TRUE, data_tree, offset);
                                break;
                            case S7COMM_UD_SUBF_CPU_MSGS:
                                offset = s7comm_decode_message_service(next_tvb, pinfo, data_tree, type, length_rem, offset);
                                break;
                            default:
                                /* print other currently unknown data as raw bytes */
                                proto_tree_add_item(data_tree, hf_s7comm_userdata_data, next_tvb, offset, length_rem, ENC_NA);
                                break;
                        }
                        break;
                    case S7COMM_UD_FUNCGROUP_SEC:
                        offset = s7comm_decode_ud_security_subfunc(next_tvb, data_tree, length_rem, offset);
                        break;
                    case S7COMM_UD_FUNCGROUP_PBC:
                        offset = s7comm_decode_ud_pbc_subfunc(next_tvb, data_tree, length_rem, offset);
                        break;
                    case S7COMM_UD_FUNCGROUP_TIME:
                        offset = s7comm_decode_ud_time_subfunc(next_tvb, data_tree, type, subfunc, ret_val, length_rem, offset);
                        break;
                    case S7COMM_UD_FUNCGROUP_NCPRG:
                        offset = s7comm_decode_ud_ncprg_subfunc(next_tvb, pinfo, data_tree, type, subfunc, length_rem, offset);
                        break;
                    default:
                        break;
                }
            }
        }
    }
    return offset;
}

/*******************************************************************************************************
 *******************************************************************************************************
 *
 * PDU Type: User Data
 *
 *******************************************************************************************************
 *******************************************************************************************************/
static guint32
s7comm_decode_ud(tvbuff_t *tvb,
                 packet_info *pinfo,
                 proto_tree *tree,
                 guint16 plength,
                 guint16 dlength,
                 guint32 offset)
{
    proto_item *item = NULL;
    proto_tree *param_tree = NULL;

    guint32 errorcode;
    guint32 offset_temp;
    guint32 reqres2;
    guint8 type;
    guint8 funcgroup;
    guint8 subfunc;
    guint8 data_unit_ref = 0;
    guint8 last_data_unit = 0;
    guint8 seq_num;

    /* Add parameter tree */
    item = proto_tree_add_item(tree, hf_s7comm_param, tvb, offset, plength, ENC_NA);
    param_tree = proto_item_add_subtree(item, ett_s7comm_param);

    offset_temp = offset;
    /* 3 bytes constant head */
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_head, tvb, offset_temp, 3, ENC_BIG_ENDIAN);
    offset_temp += 3;
    /* 1 byte length of following parameter (8 or 12 bytes) */
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_len, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
    offset_temp += 1;
    /* 1 byte indicating request/response again, but useful in Push telegrams*/
    proto_tree_add_item_ret_uint(param_tree, hf_s7comm_userdata_param_reqres2, tvb, offset_temp, 1, ENC_BIG_ENDIAN, &reqres2);
    offset_temp += 1;
    /* High nibble (following/request/response) */
    type = (tvb_get_guint8(tvb, offset_temp) & 0xf0) >> 4;
    funcgroup = (tvb_get_guint8(tvb, offset_temp) & 0x0f);
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_type, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
    if (type == S7COMM_UD_TYPE_PUSH || type == S7COMM_UD_TYPE_NCPUSH) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[%s-%s] -> [%s]",
            val_to_str(type, userdata_type_names, "Unknown type: 0x%02x"),
            val_to_str(reqres2, userdata_reqres2_names, "Unknown method: 0x%02x"),
            val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function: 0x%02x")
            );
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[%s] -> [%s]",
            val_to_str(type, userdata_type_names, "Unknown type: 0x%02x"),
            val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function: 0x%02x")
            );
    }
    proto_item_append_text(param_tree, ": (%s)", val_to_str(type, userdata_type_names, "Unknown type: 0x%02x"));
    proto_item_append_text(param_tree, " ->(%s)", val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function: 0x%02x"));

    /* Low nibble function group  */
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_funcgroup, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
    offset_temp += 1;
    /* 1 Byte subfunction  */
    subfunc = tvb_get_guint8(tvb, offset_temp);
    switch (funcgroup){
        case S7COMM_UD_FUNCGROUP_PROG:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_prog, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_prog_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_prog_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_CYCLIC:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_cyclic, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_cyclic_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_cyclic_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_BLOCK:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_block, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_block_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_block_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_CPU:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_cpu, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_cpu_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_cpu_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_SEC:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_sec, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_sec_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_sec_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_TIME:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_time, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_time_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_time_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_MODETRANS:
            proto_tree_add_uint(param_tree, hf_s7comm_modetrans_param_subfunc, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, modetrans_param_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, modetrans_param_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_NCPRG:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_ncprg, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_ncprg_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_ncprg_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        default:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc, tvb, offset_temp, 1, subfunc);
            break;
    }
    offset_temp += 1;
    /* 1 Byte sequence number  */
    seq_num = tvb_get_guint8(tvb, offset_temp);
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_seq_num, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
    offset_temp += 1;
    if (plength >= 12) {
        /* 1 Byte data unit reference. If packet is fragmented, all packets with this number belong together */
        data_unit_ref = tvb_get_guint8(tvb, offset_temp);
        proto_tree_add_item(param_tree, hf_s7comm_userdata_param_dataunitref, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
        offset_temp += 1;
        /* 1 Byte fragmented flag, if this is not the last data unit (telegram is fragmented) this is != 0 */
        last_data_unit = tvb_get_guint8(tvb, offset_temp);
        proto_tree_add_item(param_tree, hf_s7comm_userdata_param_dataunit, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
        offset_temp += 1;
        proto_tree_add_item_ret_uint(param_tree, hf_s7comm_param_errcod, tvb, offset_temp, 2, ENC_BIG_ENDIAN, &errorcode);
        if (errorcode > 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> Errorcode:[0x%04x]", errorcode);
        }
    }
    offset += plength;

    offset = s7comm_decode_ud_data(tvb, pinfo, tree, dlength, type, funcgroup, subfunc, seq_num, data_unit_ref, last_data_unit, offset);

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_req_resp(tvbuff_t *tvb,
                       packet_info *pinfo,
                       proto_tree *tree,
                       guint16 plength,
                       guint16 dlength,
                       guint32 offset,
                       guint8 rosctr)
{
    proto_item *item = NULL;
    proto_tree *param_tree = NULL;
    proto_tree *data_tree = NULL;
    guint8 function = 0;
    guint8 item_count = 0;
    guint8 i;
    guint32 offset_old;
    guint32 len;

    if (plength > 0) {
        /* Add parameter tree */
        item = proto_tree_add_item(tree, hf_s7comm_param, tvb, offset, plength, ENC_NA);
        param_tree = proto_item_add_subtree(item, ett_s7comm_param);
        /* Analyze function */
        function = tvb_get_guint8(tvb, offset);
        /* add param.function to info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[%s]", val_to_str(function, param_functionnames, "Unknown function: 0x%02x"));
        proto_tree_add_uint(param_tree, hf_s7comm_param_service, tvb, offset, 1, function);
        /* show param.function code at the tree */
        proto_item_append_text(param_tree, ": (%s)", val_to_str(function, param_functionnames, "Unknown function: 0x%02x"));
        offset += 1;

        if (rosctr == S7COMM_ROSCTR_JOB) {
            switch (function){
                case S7COMM_SERV_READVAR:
                case S7COMM_SERV_WRITEVAR:
                    item_count = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(param_tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
                    offset += 1;
                    /* parse item data */
                    for (i = 0; i < item_count; i++) {
                        offset_old = offset;
                        offset = s7comm_decode_param_item(tvb, offset, param_tree, i);
                        /* if length is not a multiple of 2 and this is not the last item, then add a fill-byte */
                        len = offset - offset_old;
                        if ((len % 2) && (i < (item_count-1))) {
                            offset += 1;
                        }
                    }
                    /* in write-function there is a data part */
                    if ((function == S7COMM_SERV_WRITEVAR) && (dlength > 0)) {
                        item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
                        data_tree = proto_item_add_subtree(item, ett_s7comm_data);
                        /* Add returned data to data-tree */
                        offset = s7comm_decode_response_read_data(tvb, data_tree, item_count, offset);
                    }
                    break;
                case S7COMM_SERV_SETUPCOMM:
                    offset = s7comm_decode_pdu_setup_communication(tvb, param_tree, offset);
                    break;
                /* Special functions */
                case S7COMM_FUNCREQUESTDOWNLOAD:
                case S7COMM_FUNCDOWNLOADBLOCK:
                case S7COMM_FUNCDOWNLOADENDED:
                case S7COMM_FUNCSTARTUPLOAD:
                case S7COMM_FUNCUPLOAD:
                case S7COMM_FUNCENDUPLOAD:
                    offset = s7comm_decode_plc_controls_updownload(tvb, pinfo, tree, param_tree, plength, dlength, offset -1, rosctr);
                    break;
                case S7COMM_FUNCPISERVICE:
                    offset = s7comm_decode_pi_service(tvb, pinfo, param_tree, plength, offset -1);
                    break;
                case S7COMM_FUNC_PLC_STOP:
                    offset = s7comm_decode_plc_controls_param_hex29(tvb, param_tree, offset -1);
                    break;

                default:
                    /* Print unknown part as raw bytes */
                    if (plength > 1) {
                        proto_tree_add_item(param_tree, hf_s7comm_param_data, tvb, offset, plength - 1, ENC_NA);
                    }
                    offset += plength - 1; /* 1 byte function code */
                    if (dlength > 0) {
                        /* Add data tree
                         * First 2 bytes in data seem to be a length indicator of (dlength -4 ), so next 2 bytes
                         * seem to indicate something else. But I'm not sure, so leave it as it is.....
                         */
                        item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
                        data_tree = proto_item_add_subtree(item, ett_s7comm_data);
                        proto_tree_add_item(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength, ENC_NA);
                        offset += dlength;
                    }
                    break;
            }
        } else if (rosctr == S7COMM_ROSCTR_ACK_DATA) {
            switch (function){
                case S7COMM_SERV_READVAR:
                case S7COMM_SERV_WRITEVAR:
                    /* This is a read-response, so the requested data may follow when address in request was ok */
                    item_count = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(param_tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
                    offset += 1;
                    /* Add data tree */
                    item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
                    data_tree = proto_item_add_subtree(item, ett_s7comm_data);
                    /* Add returned data to data-tree */
                    if ((function == S7COMM_SERV_READVAR) && (dlength > 0)) {
                        offset = s7comm_decode_response_read_data(tvb, data_tree, item_count, offset);
                    } else if ((function == S7COMM_SERV_WRITEVAR) && (dlength > 0)) {
                        offset = s7comm_decode_response_write_data(tvb, data_tree, item_count, offset);
                    }
                    break;
                case S7COMM_SERV_SETUPCOMM:
                    offset = s7comm_decode_pdu_setup_communication(tvb, param_tree, offset);
                    break;
                case S7COMM_FUNCREQUESTDOWNLOAD:
                case S7COMM_FUNCDOWNLOADBLOCK:
                case S7COMM_FUNCDOWNLOADENDED:
                case S7COMM_FUNCSTARTUPLOAD:
                case S7COMM_FUNCUPLOAD:
                case S7COMM_FUNCENDUPLOAD:
                    offset = s7comm_decode_plc_controls_updownload(tvb, pinfo, tree, param_tree, plength, dlength, offset -1, rosctr);
                    break;
                case S7COMM_FUNCPISERVICE:
                    if (plength >= 2) {
                        proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,
                            ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                    break;
                default:
                    /* Print unknown part as raw bytes */
                    if (plength > 1) {
                        proto_tree_add_item(param_tree, hf_s7comm_param_data, tvb, offset, plength - 1, ENC_NA);
                    }
                    offset += plength - 1; /* 1 byte function code */
                    if (dlength > 0) {
                        /* Add data tree
                         * First 2 bytes in data seem to be a length indicator of (dlength -4 ), so next 2 bytes
                         * seem to indicate something else. But I'm not sure, so leave it as it is.....
                         */
                        item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
                        data_tree = proto_item_add_subtree(item, ett_s7comm_data);
                        proto_tree_add_item(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength, ENC_NA);
                        offset += dlength;
                    }
                    break;
            }
        }
    }
    return offset;
}

/*******************************************************************************************************
 *******************************************************************************************************
 *
 * S7-Protocol (main tree)
 *
 *******************************************************************************************************
 *******************************************************************************************************/
static gboolean
dissect_s7comm(tvbuff_t *tvb,
               packet_info *pinfo,
               proto_tree *tree,
               void *data _U_)
{
    proto_item *s7comm_item = NULL;
    proto_item *s7comm_sub_item = NULL;
    proto_tree *s7comm_tree = NULL;
    proto_tree *s7comm_header_tree = NULL;

    guint32 offset = 0;

    guint8 rosctr = 0;
    guint8 hlength = 10;                /* Header 10 Bytes, when type 2 or 3 (Response) -> 12 Bytes */
    guint16 plength = 0;
    guint16 dlength = 0;
    guint16 errorcode = 0;

    /*----------------- Heuristic Checks - Begin */
    /* 1) check for minimum length */
    if(tvb_captured_length(tvb) < S7COMM_MIN_TELEGRAM_LENGTH)
        return FALSE;
    /* 2) first byte must be 0x32 */
    if (tvb_get_guint8(tvb, 0) != S7COMM_PROT_ID)
        return FALSE;
    /* 3) second byte is a type field and only can contain values between 0x01-0x07 (1/2/3/7) */
    if (tvb_get_guint8(tvb, 1) < 0x01 || tvb_get_guint8(tvb, 1) > 0x07)
        return FALSE;
    /*----------------- Heuristic Checks - End */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_S7COMM);
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", "");

    rosctr = tvb_get_guint8(tvb, 1);                            /* Get the type byte */
    if (rosctr == 2 || rosctr == 3) hlength = 12;               /* Header 10 Bytes, when type 2 or 3 (response) -> 12 Bytes */

    /* display some infos in info-column of wireshark */
    col_append_fstr(pinfo->cinfo, COL_INFO, "ROSCTR:[%-8s]", val_to_str(rosctr, rosctr_names, "Unknown: 0x%02x"));

    s7comm_item = proto_tree_add_item(tree, proto_s7comm, tvb, 0, -1, ENC_NA);
    s7comm_tree = proto_item_add_subtree(s7comm_item, ett_s7comm);

    /* insert header tree */
    s7comm_sub_item = proto_tree_add_item(s7comm_tree, hf_s7comm_header,
                      tvb, offset, hlength, ENC_NA);

    /* insert sub-items in header tree */
    s7comm_header_tree = proto_item_add_subtree(s7comm_sub_item, ett_s7comm_header);

    /* Protocol Identifier, constant 0x32 */
    proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_protid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* ROSCTR (Remote Operating Service Control) - PDU Type */
    proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_rosctr, tvb, offset, 1, rosctr);
    /* Show pdu type beside the header tree */
    proto_item_append_text(s7comm_header_tree, ": (%s)", val_to_str(rosctr, rosctr_names, "Unknown ROSCTR: 0x%02x"));
    offset += 1;
    /* Redundancy ID, reserved */
    proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_redid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* Protocol Data Unit Reference */
    proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_pduref, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* Parameter length */
    plength = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_parlg, tvb, offset, 2, plength);
    offset += 2;
    /* Data length */
    dlength = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_datlg, tvb, offset, 2, dlength);
    offset += 2;
    /* when type is 2 or 3 there are 2 bytes with errorclass and errorcode */
    if (hlength == 12) {
        errorcode = tvb_get_ntohs(tvb, offset);     /* this uses the same errorcodes (combined) from parameter part */
        proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_errcls, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_errcod, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* when there is an error, use the errorcode from parameterpart*/
        if (errorcode > 0) {
            s7comm_item = proto_tree_add_item(s7comm_header_tree, hf_s7comm_param_errcod, tvb, offset-2, 2, ENC_BIG_ENDIAN);
            proto_item_set_generated (s7comm_item);
        }
    }

    switch (rosctr) {
        case S7COMM_ROSCTR_JOB:
        case S7COMM_ROSCTR_ACK_DATA:
            s7comm_decode_req_resp(tvb, pinfo, s7comm_tree, plength, dlength, offset, rosctr);
            break;
        case S7COMM_ROSCTR_USERDATA:
            s7comm_decode_ud(tvb, pinfo, s7comm_tree, plength, dlength, offset);
            break;
    }
    /* Add the errorcode from header as last entry in info column */
    if (errorcode > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " -> Errorcode:[0x%04x]", errorcode);
    }
    /* set fence as there may be more than one S7comm PDU in one frame */
    col_set_fence(pinfo->cinfo, COL_INFO);
    return TRUE;
}

/*******************************************************************************************************
 * Reassembly of S7COMM
 *******************************************************************************************************/
static void
s7comm_defragment_init(void)
{
    reassembly_table_init(&s7comm_reassembly_table,
                          &addresses_ports_reassembly_table_functions);
}

/*******************************************************************************************************
 *******************************************************************************************************/
void
proto_register_s7comm (void)
{
    expert_module_t* expert_s7comm;

    /* format:
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
     */
    static hf_register_info hf[] = {
        { &hf_s7comm_header,
        { "Header", "s7comm.header", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is the header of S7 communication", HFILL }},
        { &hf_s7comm_header_protid,
        { "Protocol Id", "s7comm.header.protid", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Protocol Identification, 0x32 for S7", HFILL }},
        { &hf_s7comm_header_rosctr,
        { "ROSCTR", "s7comm.header.rosctr", FT_UINT8, BASE_DEC, VALS(rosctr_names), 0x0,
          "Remote Operating Service Control", HFILL }},
        { &hf_s7comm_header_redid,
        { "Redundancy Identification (Reserved)", "s7comm.header.redid", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Redundancy Identification (Reserved), should be always 0x0000", HFILL }},
        { &hf_s7comm_header_pduref,
        { "Protocol Data Unit Reference", "s7comm.header.pduref", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_header_parlg,
        { "Parameter length", "s7comm.header.parlg", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Specifies the entire length of the parameter block in bytes", HFILL }},
        { &hf_s7comm_header_datlg,
        { "Data length", "s7comm.header.datlg", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Specifies the entire length of the data block in bytes", HFILL }},
        { &hf_s7comm_header_errcls,
        { "Error class", "s7comm.header.errcls", FT_UINT8, BASE_HEX, VALS(errcls_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_header_errcod,
        { "Error code", "s7comm.header.errcod", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_param,
        { "Parameter", "s7comm.param", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is the parameter part of S7 communication", HFILL }},
        { &hf_s7comm_param_errcod,
        { "Error code", "s7comm.param.errcod", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &param_errcode_names_ext, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_service,
        { "Function", "s7comm.param.func", FT_UINT8, BASE_HEX, VALS(param_functionnames), 0x0,
          "Indicates the function of parameter/data", HFILL }},
        { &hf_s7comm_param_maxamq_calling,
        { "Max AmQ (parallel jobs with ack) calling", "s7comm.param.maxamq_calling", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_maxamq_called,
        { "Max AmQ (parallel jobs with ack) called", "s7comm.param.maxamq_called", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_setup_reserved1,
        { "Reserved", "s7comm.param.setup_reserved1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_neg_pdu_length,
        { "PDU length", "s7comm.param.pdu_length", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Negotiated PDU length", HFILL }},
        { &hf_s7comm_param_itemcount,
        { "Item count", "s7comm.param.itemcount", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Number of Items in parameter/data part", HFILL }},
        { &hf_s7comm_param_data,
        { "Parameter data", "s7comm.param.data", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_item,
        { "Item", "s7comm.param.item", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_subitem,
        { "Subitem", "s7comm.param.subitem", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_varspec,
        { "Variable specification", "s7comm.param.item.varspec", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_varspec_length,
        { "Length of following address specification", "s7comm.param.item.varspec_length", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_syntax_id,
        { "Syntax Id", "s7comm.param.item.syntaxid", FT_UINT8, BASE_HEX, VALS(item_syntaxid_names), 0x0,
          "Syntax Id, format type of following address specification", HFILL }},
        { &hf_s7comm_item_transport_size,
        { "Transport size", "s7comm.param.item.transp_size", FT_UINT8, BASE_DEC, VALS(item_transportsizenames), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_length,
        { "Length", "s7comm.param.item.length", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_db,
        { "DB number", "s7comm.param.item.db", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_area,
        { "Area", "s7comm.param.item.area", FT_UINT8, BASE_HEX, VALS(item_areanames), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_address,
        { "Address", "s7comm.param.item.address", FT_UINT24, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_address_byte,
        { "Byte Address", "s7comm.param.item.address.byte", FT_UINT24, BASE_DEC, NULL, 0x7fff8,
          NULL, HFILL }},
        { &hf_s7comm_item_address_bit,
        { "Bit Address", "s7comm.param.item.address.bit", FT_UINT24, BASE_DEC, NULL, 0x000007,
          NULL, HFILL }},
        { &hf_s7comm_item_address_nr,
        { "Number (T/C/BLOCK)", "s7comm.param.item.address.number", FT_UINT24, BASE_DEC, NULL, 0x00ffff,
          NULL, HFILL }},
        /* Special variable read with Syntax-Id 0xb0 (DBREAD) */
        { &hf_s7comm_item_dbread_numareas,
        { "Number of areas", "s7comm.param.item.dbread.numareas", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Number of area specifications following", HFILL }},
        { &hf_s7comm_item_dbread_length,
        { "Bytes to read", "s7comm.param.item.dbread.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Number of bytes to read", HFILL }},
        { &hf_s7comm_item_dbread_db,
        { "DB number", "s7comm.param.item.dbread.db", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_dbread_startadr,
        { "Start address", "s7comm.param.item.dbread.startaddress", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        /* Reading frequency inverter parameters via routing */
        { &hf_s7comm_item_driveesany_unknown1,
        { "DriveES Unknown 1", "s7comm.param.item.driveesany.unknown1", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_driveesany_unknown2,
        { "DriveES Unknown 2", "s7comm.param.item.driveesany.unknown2", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_driveesany_unknown3,
        { "DriveES Unknown 3", "s7comm.param.item.driveesany.unknown3", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_driveesany_parameter_nr,
        { "DriveES Parameter number", "s7comm.param.item.driveesany.parameternr", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_driveesany_parameter_idx,
        { "DriveES Parameter index", "s7comm.param.item.driveesany.parameteridx", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        /* NCK access with Syntax-Id 0x82 */
        { &hf_s7comm_item_nck_areaunit,
        { "NCK Area/Unit", "s7comm.param.item.nck.area_unit", FT_UINT8, BASE_HEX, NULL, 0x0,
          "NCK Area/Unit: Bitmask aaauuuuu: a=area, u=unit", HFILL }},
        { &hf_s7comm_item_nck_area,
        { "NCK Area", "s7comm.param.item.nck.area", FT_UINT8, BASE_DEC, VALS(nck_area_names), 0xe0,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_unit,
        { "NCK Unit", "s7comm.param.item.nck.unit", FT_UINT8, BASE_DEC, NULL, 0x1f,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_column,
        { "NCK Column number", "s7comm.param.item.nck.column", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_line,
        { "NCK Line number", "s7comm.param.item.nck.line", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_module,
        { "NCK Module", "s7comm.param.item.nck.module", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &nck_module_names_ext, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_linecount,
        { "NCK Linecount", "s7comm.param.item.nck.linecount", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_data,
        { "Data", "s7comm.data", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is the data part of S7 communication", HFILL }},
        { &hf_s7comm_data_returncode,
        { "Return code", "s7comm.data.returncode", FT_UINT8, BASE_HEX, VALS(s7comm_item_return_valuenames), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_transport_size,
        { "Transport size", "s7comm.data.transportsize", FT_UINT8, BASE_HEX, VALS(data_transportsizenames), 0x0,
          "Data type / Transport size. If 3, 4 or 5 the following length gives the number of bits, otherwise the number of bytes.", HFILL }},
        { &hf_s7comm_data_length,
        { "Length", "s7comm.data.length", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of data", HFILL }},

        { &hf_s7comm_data_item,
        { "Item", "s7comm.data.item", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_readresponse_data,
        { "Data", "s7comm.resp.data", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_fillbyte,
        { "Fill byte", "s7comm.data.fillbyte", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_userdata_data,
        { "Data", "s7comm.data.userdata", FT_BYTES, BASE_NONE, NULL, 0x0,
          "Userdata data", HFILL }},

        /* Userdata parameter 8/12 Bytes len*/
        { &hf_s7comm_userdata_param_head,
        { "Parameter head", "s7comm.param.userdata.head", FT_UINT24, BASE_HEX, NULL, 0x0,
          "Header before parameter (constant 0x000112)", HFILL }},
        { &hf_s7comm_userdata_param_len,
        { "Parameter length", "s7comm.param.userdata.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length of following parameter data (without head)", HFILL }},
        { &hf_s7comm_userdata_param_reqres2,
        { "Method (Request/Response)", "s7comm.param.userdata.reqres1", FT_UINT8, BASE_HEX, VALS(userdata_reqres2_names), 0x0,
          "Unknown part, second request/response (0x00, 0x11, 0x12)", HFILL }},

        { &hf_s7comm_userdata_param_type,
        { "Type", "s7comm.param.userdata.type", FT_UINT8, BASE_DEC, VALS(userdata_type_names), 0xf0,
          "Type of parameter", HFILL }},

        { &hf_s7comm_userdata_param_funcgroup,
        { "Function group", "s7comm.param.userdata.funcgroup", FT_UINT8, BASE_DEC, VALS(userdata_functiongroup_names), 0x0f,
          NULL, HFILL }},

        { &hf_s7comm_userdata_param_subfunc_prog,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_prog_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_cyclic,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_cyclic_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_block,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_block_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_cpu,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_cpu_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_sec,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_sec_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_time,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_time_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_ncprg,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_ncprg_subfunc_names), 0x0,
          NULL, HFILL }},

        { &hf_s7comm_userdata_param_seq_num,
        { "Sequence number", "s7comm.param.userdata.seq_num", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_userdata_param_dataunitref,
        { "Data unit reference number", "s7comm.param.userdata.dataunitref", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Data unit reference number if PDU is fragmented", HFILL }},

        { &hf_s7comm_userdata_param_dataunit,
        { "Last data unit", "s7comm.param.userdata.lastdataunit", FT_UINT8, BASE_HEX, VALS(userdata_lastdataunit_names), 0x0,
          NULL, HFILL }},

        /* block functions / info */
        { &hf_s7comm_ud_blockinfo_block_type,
        { "Block type", "s7comm.blockinfo.blocktype", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_cnt,
        { "Block count", "s7comm.blockinfo.block_count", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_num,
        { "Block number", "s7comm.blockinfo.block_num", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_flags,
        { "Block flags (unknown)", "s7comm.blockinfo.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_lang,
        { "Block language", "s7comm.blockinfo.block_lang", FT_UINT8, BASE_DEC, VALS(blocklanguage_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_num_ascii,
        { "Block number", "s7comm.data.blockinfo.block_number", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_filesys,
        { "Filesystem", "s7comm.data.blockinfo.filesys", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_res_infolength,
        { "Length of Info", "s7comm.blockinfo.res_infolength", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of Info in bytes", HFILL }},
        { &hf_s7comm_ud_blockinfo_res_unknown2,
        { "Unknown blockinfo 2", "s7comm.blockinfo.res_unknown2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_res_const3,
        { "Constant 3", "s7comm.blockinfo.res_const3", FT_STRING, BASE_NONE, NULL, 0x0,
          "Possible constant 3, seems to be always 'pp'", HFILL }},
        { &hf_s7comm_ud_blockinfo_res_unknown,
        { "Unknown byte(s) blockinfo", "s7comm.blockinfo.res_unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_subblk_type,
        { "Subblk type", "s7comm.blockinfo.subblk_type", FT_UINT8, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_load_mem_len,
        { "Length load memory", "s7comm.blockinfo.load_mem_len", FT_UINT32, BASE_DEC, NULL, 0x0,
          "Length of load memory in bytes", HFILL }},
        { &hf_s7comm_ud_blockinfo_blocksecurity,
        { "Block Security", "s7comm.blockinfo.blocksecurity", FT_UINT32, BASE_DEC, VALS(blocksecurity_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_interface_timestamp,
        { "Interface timestamp", "s7comm.blockinfo.interface_timestamp", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_code_timestamp,
        { "Code timestamp", "s7comm.blockinfo.code_timestamp", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_ssb_len,
        { "SSB length", "s7comm.blockinfo.ssb_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_add_len,
        { "ADD length", "s7comm.blockinfo.add_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_localdata_len,
        { "Localdata length", "s7comm.blockinfo.localdata_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of localdata in bytes", HFILL }},
        { &hf_s7comm_ud_blockinfo_mc7_len,
        { "MC7 code length", "s7comm.blockinfo.mc7_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of MC7 code in bytes", HFILL }},
        { &hf_s7comm_ud_blockinfo_author,
        { "Author", "s7comm.blockinfo.author", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_family,
        { "Family", "s7comm.blockinfo.family", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_headername,
        { "Name (Header)", "s7comm.blockinfo.headername", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_headerversion,
        { "Version (Header)", "s7comm.blockinfo.headerversion", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_checksum,
        { "Block checksum", "s7comm.blockinfo.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_reserved1,
        { "Reserved 1", "s7comm.blockinfo.reserved1", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_reserved2,
        { "Reserved 2", "s7comm.blockinfo.reserved2", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        /* Flags in blockinfo response */
        { &hf_s7comm_userdata_blockinfo_flags,
        { "Block flags", "s7comm.param.userdata.blockinfo.flags", FT_UINT8, BASE_HEX, NULL, 0xff,
          "Some block configuration flags", HFILL }},
         /* Bit : 0 -> DB Linked = true */
        { &hf_s7comm_userdata_blockinfo_linked,
        { "Linked", "s7comm.param.userdata.blockinfo.linked", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
          NULL, HFILL }},
        /* Bit : 1 -> Standard block = true */
        { &hf_s7comm_userdata_blockinfo_standard_block,
        { "Standard block", "s7comm.param.userdata.blockinfo.standard_block", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
          NULL, HFILL }},
        /* Bit : 5 -> DB Non Retain = true */
        { &hf_s7comm_userdata_blockinfo_nonretain,
        { "Non Retain", "s7comm.param.userdata.blockinfo.nonretain", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
          NULL, HFILL }},

        /* Programmer commands / Test and installation (TIS) functions */
        { &hf_s7comm_tis_parameter,
        { "TIS Parameter", "s7comm.tis.parameter", FT_NONE, BASE_NONE, NULL, 0x0,
          "TIS Test and Installation: Parameter", HFILL }},
        { &hf_s7comm_tis_data,
        { "TIS Data", "s7comm.cpu.tis.data", FT_NONE, BASE_NONE, NULL, 0x0,
          "TIS Test and Installation: Data", HFILL }},
        { &hf_s7comm_tis_parametersize,
        { "TIS Parameter size", "s7comm.tis.parametersize", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_datasize,
        { "TIS Data size", "s7comm.tis.datasize", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_param1,
        { "TIS Parameter 1", "s7comm.tis.param1", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_param2,
        { "TIS Parameter 2 - Trigger type", "s7comm.tis.param2", FT_UINT16, BASE_DEC, VALS(tis_param2_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_param3,
        { "TIS Parameter 3 - Trigger frequency", "s7comm.tis.param3", FT_UINT16, BASE_DEC, VALS(tis_param3_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_answersize,
        { "TIS Parameter 4 - Answer size", "s7comm.tis.answersize", FT_UINT16, BASE_DEC, NULL, 0x0,
          "TIS Answer size: Expected data size of PLC answer to this job", HFILL }},
        { &hf_s7comm_tis_param5,
        { "TIS Parameter 5", "s7comm.tis.param5", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_param6,
        { "TIS Parameter 6", "s7comm.tis.param6", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_param7,
        { "TIS Parameter 7", "s7comm.tis.param7", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_param8,
        { "TIS Parameter 8", "s7comm.tis.param8", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_param9,
        { "TIS Parameter 9", "s7comm.tis.param9", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_trgevent,
        { "TIS Parameter 10 - Trigger event", "s7comm.varstat.trgevent", FT_UINT16, BASE_HEX, VALS(userdata_varstat_trgevent_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_res_param1,
        { "TIS Response Parameter 1", "s7comm.tis.res.param1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_res_param2,
        { "TIS Response Parameter 2", "s7comm.tis.res.param2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_job_function,
        { "Job function", "s7comm.tis.job.function", FT_UINT8, BASE_DEC, VALS(userdata_prog_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_job_seqnr,
        { "Job reference sequence number", "s7comm.tis.job.response_seq_num", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Job reference sequence number (find function setup with s7comm.param.userdata.seq_num)", HFILL }},
        { &hf_s7comm_tis_job_reserved,
        { "Job Reserved / Unknown", "s7comm.tis.job.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_interrupted_blocktype,
        { "Interrupted block type", "s7comm.tis.interrupted.blocktype", FT_UINT16, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_interrupted_blocknr,
        { "Interrupted block number", "s7comm.tis.interrupted.blocknumber", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_interrupted_address,
        { "Interrupted code address", "s7comm.tis.interrupted.address", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_interrupted_prioclass,
        { "Interrupted priority class", "s7comm.tis.interrupted.priorityclass", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_continued_blocktype,
        { "Continued block type", "s7comm.tis.continued.blocktype", FT_UINT16, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_continued_blocknr,
        { "Continued block number", "s7comm.tis.continued.blocknumber", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_continued_address,
        { "Continued code address", "s7comm.tis.continued.address", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_breakpoint_blocktype,
        { "Breakpoint block type", "s7comm.tis.breakpoint.blocktype", FT_UINT16, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_breakpoint_blocknr,
        { "Breakpoint block number", "s7comm.tis.breakpoint.blocknumber", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_breakpoint_address,
        { "Breakpoint code address", "s7comm.tis.breakpoint.address", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_breakpoint_reserved,
        { "Breakpoint Reserved / Unknown", "s7comm.tis.breakpoint.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_tis_p_callenv,
        { "Call environment setup", "s7comm.tis.callenv_setup", FT_UINT16, BASE_DEC, VALS(tis_p_callenv_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_p_callcond,
        { "Call condition", "s7comm.tis.callenv_cond", FT_UINT16, BASE_DEC, VALS(tis_p_callcond_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_p_callcond_blocktype,
        { "Call condition block type", "s7comm.tis.callenv_cond_blocktype", FT_UINT16, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_p_callcond_blocknr,
        { "Call condition block number", "s7comm.tis.callenv_cond_blocknumber", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_p_callcond_address,
        { "Call condition code address", "s7comm.tis.callenv_cond_blockaddress", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_tis_register_db1_type,
        { "Register DB1 content type", "s7comm.tis.db1.type", FT_UINT8, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_db2_type,
        { "Register DB2 content type", "s7comm.tis.db2.type", FT_UINT8, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_db1_nr,
        { "Register DB1 block number", "s7comm.tis.db1.number", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_db2_nr,
        { "Register DB2 block number", "s7comm.tis.db2.number", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_accu1,
        { "Register ACCU1", "s7comm.tis.accu1", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_accu2,
        { "Register ACCU2", "s7comm.tis.accu2", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_accu3,
        { "Register ACCU3", "s7comm.tis.accu3", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_accu4,
        { "Register ACCU4", "s7comm.tis.accu4", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_ar1,
        { "Register AR1", "s7comm.tis.ar1", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_ar2,
        { "Register AR2", "s7comm.tis.ar2", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_register_stw,
        { "Register STW", "s7comm.tis.stw", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_exithold_until,
        { "Exit HOLD state until", "s7comm.tis.exithold_until", FT_UINT8, BASE_DEC, VALS(tis_exithold_until_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_exithold_res1 ,
        { "Exit HOLD Reserved / Unknown", "s7comm.tis.exithold_res1", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_bstack_nest_depth,
        { "BSTACK nesting depth", "s7comm.tis.bstack.neting_depth", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_bstack_reserved,
        { "BSTACK Reserved / Unknown", "s7comm.tis.bstack.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_istack_reserved,
        { "ISTACK Reserved / Unknown", "s7comm.tis.istack.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_lstack_reserved,
        { "LSTACK Reserved / Unknown", "s7comm.tis.lstack.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_lstack_size,
        { "Localdata stack size", "s7comm.tis.lstack.size", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_lstack_data,
        { "Localdata stack data", "s7comm.tis.lstack.data", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_blockstat_flagsunknown,
        { "Blockstat flags", "s7comm.tis.blockstat.flagsunknown", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_blockstat_number_of_lines,
        { "Number of lines", "s7comm.tis.blockstat.number_of_lines", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_blockstat_line_address,
        { "Address", "s7comm.tis.blockstat.line_address", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_blockstat_data,
        { "Blockstatus data", "s7comm.tis.blockstat.data", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tis_blockstat_reserved,
        { "Blockstatus Reserved / Unknown", "s7comm.tis.blockstat.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        /* Organization block local data */
        { &hf_s7comm_ob_ev_class,
        { "OB Event class", "s7comm.ob.ev_class", FT_UINT8, BASE_HEX, NULL, 0x0,
          "OB Event class (Bits 0-3 = 1 (Coming event), Bits 4-7 = 1 (Event class 1)", HFILL }},
        { &hf_s7comm_ob_scan_1,
        { "OB Scan 1", "s7comm.ob.scan_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "OB Scan 1 (1=Cold restart scan 1 of OB 1), 3=Scan 2-n of OB 1)", HFILL }},
        { &hf_s7comm_ob_strt_inf,
        { "OB Start info", "s7comm.ob.strt_info", FT_UINT8, BASE_HEX, NULL, 0x0,
          "OB Start info (OB n has started)", HFILL }},
        { &hf_s7comm_ob_flt_id,
        { "OB Fault identifcation code", "s7comm.ob.flt_id", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_priority,
        { "OB Priority", "s7comm.ob.priority", FT_UINT8, BASE_DEC, NULL, 0x0,
          "OB Priority (1 is lowest)", HFILL }},
        { &hf_s7comm_ob_number,
        { "OB Number", "s7comm.ob.number", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_reserved_1,
        { "OB Reserved 1", "s7comm.ob.reserved_1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "OB Reserved 1 (Reserved for System)", HFILL }},
        { &hf_s7comm_ob_reserved_2,
        { "OB Reserved 2", "s7comm.ob.reserved_2", FT_UINT8, BASE_HEX, NULL, 0x0,
          "OB Reserved 2 (Reserved for System)", HFILL }},
        { &hf_s7comm_ob_reserved_3,
        { "OB Reserved 3", "s7comm.ob.reserved_3", FT_UINT16, BASE_HEX, NULL, 0x0,
          "OB Reserved 3 (Reserved for System)", HFILL }},
        { &hf_s7comm_ob_reserved_4,
        { "OB Reserved 4", "s7comm.ob.reserved_4", FT_UINT16, BASE_HEX, NULL, 0x0,
          "OB Reserved 4 (Reserved for System)", HFILL }},
        { &hf_s7comm_ob_reserved_4_dw,
        { "OB Reserved 4", "s7comm.ob.reserved_4_dw", FT_UINT32, BASE_HEX, NULL, 0x0,
          "OB Reserved 4 (Reserved for System)", HFILL }},
        { &hf_s7comm_ob_prev_cycle,
        { "OB Cycle time of previous OB scan (ms)", "s7comm.ob.prev_cycle", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_min_cycle,
        { "OB Minimum cycle time of OB (ms)", "s7comm.ob.min_cycle", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_max_cycle,
        { "OB Maximum cycle time of OB (ms)", "s7comm.ob.max_cycle", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_period_exe,
        { "OB Period of execution", "s7comm.ob.period_exe", FT_UINT16, BASE_HEX, NULL, 0x0,
          "OB Period of execution (once, per minute/hour/day/week/month/year)", HFILL }},
        { &hf_s7comm_ob_sign,
        { "OB Identifier input (SIGN) attached to SRT_DINT", "s7comm.ob.sign", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_dtime,
        { "OB Delay time (DTIME) input to SRT_DINT instruction", "s7comm.ob.dtime", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_phase_offset,
        { "OB Phase offset (ms)", "s7comm.ob.phase_offset", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_exec_freq,
        { "OB Frequency of execution (ms)", "s7comm.ob.exec_freq", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_io_flag,
        { "OB IO flags", "s7comm.ob.io_flag", FT_UINT16, BASE_DEC, NULL, 0x0,
          "OB IO flags (0x54=input module, 0x55=output module)", HFILL }},
        { &hf_s7comm_ob_mdl_addr,
        { "OB Base address of module initiating interrupt", "s7comm.ob.mdl_addr", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_point_addr,
        { "OB Address of interrupt point on module", "s7comm.ob.point_addr", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_inf_len,
        { "OB Length of information", "s7comm.ob.inf_len", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_alarm_type,
        { "OB Type of alarm", "s7comm.ob.alarm_type", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_alarm_slot,
        { "OB Slot", "s7comm.ob.alarm_slot", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_alarm_spec,
        { "OB Specifier", "s7comm.ob.alarm_spec", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_error_info,
        { "OB Error information on event", "s7comm.ob.error_info", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_err_ev_class,
        { "OB Class of event causing error", "s7comm.ob.err_ev_class", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_err_ev_num,
        { "OB Number of event causing error", "s7comm.ob.err_ev_num", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_err_ob_priority,
        { "OB Priority of OB causing error", "s7comm.ob.err_ob_priority", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_err_ob_num,
        { "OB Number of OB causing error", "s7comm.ob.err_ob_num", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_rack_cpu,
        { "OB Rack / CPU number", "s7comm.ob.rack_cpu", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_8x_fault_flags,
        { "OB 8x Fault flags", "s7comm.ob.8x_fault_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_mdl_type_b,
        { "OB Type of module", "s7comm.ob.mdl_type_b", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_mdl_type_w,
        { "OB Module type with point fault", "s7comm.ob.mdl_type_w", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_rack_num,
        { "OB Number of rack that has module with point fault", "s7comm.ob.rack_num", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_racks_flt,
        { "OB Racks in fault", "s7comm.ob.racks_flt", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_strtup,
        { "OB Method of startup", "s7comm.ob.strtup", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_stop,
        { "OB Event that caused CPU to stop", "s7comm.ob.stop", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_strt_info,
        { "OB Information on how system started", "s7comm.ob.strt_info", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_sw_flt,
        { "OB Software programming fault", "s7comm.ob.sw_flt", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_blk_type,
        { "OB Type of block fault occured in", "s7comm.ob.blk_type", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_flt_reg,
        { "OB Specific register that caused fault", "s7comm.ob.flt_reg", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_flt_blk_num,
        { "OB Number of block that programming fault occured in", "s7comm.ob.flt_blk_num", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_prg_addr,
        { "OB Address in block where programming fault occured", "s7comm.ob.prg_addr", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_mem_area,
        { "OB Memory area where access error occured", "s7comm.ob.mem_area", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ob_mem_addr,
        { "OB Memory address where access error occured", "s7comm.ob.mem_addr", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_block_type,
        { "Block type", "s7comm.diagdata.req.blocktype", FT_UINT16, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_block_num,
        { "Block number", "s7comm.diagdata.req.blocknumber", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_startaddr_awl,
        { "Start address AWL", "s7comm.diagdata.req.startaddr_awl", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_saz,
        { "Step address counter (SAZ)", "s7comm.diagdata.req.saz", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

         /* Flags for requested registers in diagnostic data telegrams */
        { &hf_s7comm_diagdata_registerflag,
        { "Registers", "s7comm.diagdata.register", FT_UINT8, BASE_HEX, NULL, 0x00,
          "Requested registers", HFILL }},
        { &hf_s7comm_diagdata_registerflag_stw,
        { "STW", "s7comm.diagdata.register.stw", FT_BOOLEAN, 8, NULL, 0x01,
          "STW / Status word", HFILL }},
        { &hf_s7comm_diagdata_registerflag_accu1,
        { "ACCU1", "s7comm.diagdata.register.accu1", FT_BOOLEAN, 8, NULL, 0x02,
          "ACCU1 / Accumulator 1", HFILL }},
        { &hf_s7comm_diagdata_registerflag_accu2,
        { "ACCU2", "s7comm.diagdata.register.accu2", FT_BOOLEAN, 8, NULL, 0x04,
          "ACCU2 / Accumulator 2", HFILL }},
        { &hf_s7comm_diagdata_registerflag_ar1,
        { "AR1", "s7comm.diagdata.register.ar1", FT_BOOLEAN, 8, NULL, 0x08,
          "AR1 / Addressregister 1", HFILL }},
        { &hf_s7comm_diagdata_registerflag_ar2,
        { "AR2", "s7comm.diagdata.register.ar2", FT_BOOLEAN, 8, NULL, 0x10,
          "AR2 / Addressregister 2", HFILL }},
        { &hf_s7comm_diagdata_registerflag_db1,
        { "DB1", "s7comm.diagdata.register.db1", FT_BOOLEAN, 8, NULL, 0x20,
          "DB1 (global)/ Datablock register 1", HFILL }},
        { &hf_s7comm_diagdata_registerflag_db2,
        { "DB2", "s7comm.diagdata.register.db2", FT_BOOLEAN, 8, NULL, 0x40,
          "DB2 (instance) / Datablock register 2", HFILL }},

        /* timefunction: s7 timestamp */
        { &hf_s7comm_data_ts,
        { "S7 Timestamp", "s7comm.data.ts", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
          "S7 Timestamp, BCD coded", HFILL }},
        { &hf_s7comm_data_ts_reserved,
        { "S7 Timestamp - Reserved", "s7comm.data.ts_reserved", FT_UINT8, BASE_HEX, NULL, 0x00,
          "S7 Timestamp: Reserved byte", HFILL }},
        { &hf_s7comm_data_ts_year1,
        { "S7 Timestamp - Year 1", "s7comm.data.ts_year1", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded year thousands/hundreds, should be ignored (19 or 20)", HFILL }},
        { &hf_s7comm_data_ts_year2,
        { "S7 Timestamp - Year 2", "s7comm.data.ts_year2", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded year, if 00...89 then it's 2000...2089, else 1990...1999", HFILL }},
        { &hf_s7comm_data_ts_month,
        { "S7 Timestamp - Month", "s7comm.data.ts_month", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded month", HFILL }},
        { &hf_s7comm_data_ts_day,
        { "S7 Timestamp - Day", "s7comm.data.ts_day", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded day", HFILL }},
        { &hf_s7comm_data_ts_hour,
        { "S7 Timestamp - Hour", "s7comm.data.ts_hour", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded hour", HFILL }},
        { &hf_s7comm_data_ts_minute,
        { "S7 Timestamp - Minute", "s7comm.data.ts_minute", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded minute", HFILL }},
        { &hf_s7comm_data_ts_second,
        { "S7 Timestamp - Second", "s7comm.data.ts_second", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded second", HFILL }},
        { &hf_s7comm_data_ts_millisecond,
        { "S7 Timestamp - Milliseconds", "s7comm.data.ts_millisecond", FT_UINT16, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded milliseconds (left 3 nibbles)", HFILL }},
        { &hf_s7comm_data_ts_weekday,
        { "S7 Timestamp - Weekday", "s7comm.data.ts_weekday", FT_UINT16, BASE_DEC, VALS(weekdaynames), 0x000f,
          "S7 Timestamp: Weekday number (right nibble, 1=Su,2=Mo,..)", HFILL }},

        /* Function 0x28 (PI service) and 0x29 */
        { &hf_s7comm_piservice_unknown1,
        { "Unknown bytes", "s7comm.param.pistart.unknown1", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_piservice_parameterblock_len,
        { "Parameter block length", "s7comm.param.pistart.parameterblock_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of Parameter block in bytes", HFILL }},
        { &hf_s7comm_piservice_parameterblock,
        { "Parameter block", "s7comm.param.pistart.parameterblock", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_piservice_servicename,
        { "PI (program invocation) Service", "s7comm.param.pistart.servicename", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},

        /* PI Service parameters for NC services */
        { &hf_s7comm_piservice_string_len,
        { "String length", "s7comm.param.pi.n_x.string_len", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length of the following string. If LengthByte + Stringlen is uneven, a fillbyte is added", HFILL }},
        { &hf_s7comm_pi_n_x_addressident,
        { "Addressidentification", "s7comm.param.pi.n_x.addressident", FT_STRING, BASE_NONE, NULL, 0x0,
          "Addressidentification (RangeID / Index)", HFILL }},
        { &hf_s7comm_pi_n_x_filename,
        { "Filename", "s7comm.param.pi.n_x.filename", FT_STRING, BASE_NONE, NULL, 0x0,
          "Name of the file or directory", HFILL }},
        { &hf_s7comm_pi_n_x_editwindowname,
        { "Editor Window Name", "s7comm.param.pi.n_x.editwindowname", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_pi_n_x_password,
        { "Password", "s7comm.param.pi.n_x.password", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_pi_n_x_seekpointer,
        { "Seek pointer", "s7comm.param.pi.n_x.seekpointer", FT_STRING, BASE_NONE, NULL, 0x0,
          "SeekPointer string with exact 9 digit/character(s)", HFILL }},
        { &hf_s7comm_pi_n_x_windowsize,
        { "Window size", "s7comm.param.pi.n_x.windowsize", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_pi_n_x_comparestring,
        { "Compare String", "s7comm.param.pi.n_x.comparestring", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_pi_n_x_skipcount,
        { "Skip Count", "s7comm.param.pi.n_x.skipcount", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_pi_n_x_interruptnr,
        { "Interrupt Number", "s7comm.param.pi.n_x.interruptnr", FT_STRING, BASE_NONE, NULL, 0x0,
          "Interrupt Number: Interrupt number corresponds to the input number which caused the interrupt" , HFILL }},
        { &hf_s7comm_pi_n_x_priority,
        { "Priority", "s7comm.param.pi.n_x.priority", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_liftfast,
        { "Liftfast", "s7comm.param.pi.n_x.liftfast", FT_STRING, BASE_NONE, NULL, 0x0,
          "Liftfast: Indicates whether an interrupt routine should simultaneously cause a fast lift-off motion" , HFILL }},
        { &hf_s7comm_pi_n_x_blsync,
        { "Blsync", "s7comm.param.pi.n_x.blsync", FT_STRING, BASE_NONE, NULL, 0x0,
          "Blsync: Indicates whether the interrupt has to be synchronized to the next block end" , HFILL }},
        { &hf_s7comm_pi_n_x_magnr,
        { "Magnr", "s7comm.param.pi.n_x.magnr", FT_STRING, BASE_NONE, NULL, 0x0,
          "Magnr: Magazine number" , HFILL }},
        { &hf_s7comm_pi_n_x_dnr,
        { "DNr", "s7comm.param.pi.n_x.dnr", FT_STRING, BASE_NONE, NULL, 0x0,
          "DNr: D number" , HFILL }},
        { &hf_s7comm_pi_n_x_spindlenumber,
        { "Spindle Number", "s7comm.param.pi.n_x.spindlenumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_pi_n_x_wznr,
        { "WZ-Nr", "s7comm.param.pi.n_x.wznr", FT_STRING, BASE_NONE, NULL, 0x0,
          "WZ-Nr: Tool number" , HFILL }},
        { &hf_s7comm_pi_n_x_class,
        { "Class", "s7comm.param.pi.n_x.class", FT_STRING, BASE_NONE, NULL, 0x0,
          "Class: Classify machine data" , HFILL }},
        { &hf_s7comm_pi_n_x_tnr,
        { "TNr", "s7comm.param.pi.n_x.tnr", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_toolnumber,
        { "Tool Number", "s7comm.param.pi.n_x.toolnumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_cenumber,
        { "CE-Number", "s7comm.param.pi.n_x.cenumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_datablocknumber,
        { "Datablock Number", "s7comm.param.pi.n_x.datablocknumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_firstcolumnnumber,
        { "First Column Number", "s7comm.param.pi.n_x.firstcolumnnumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_lastcolumnnumber,
        { "Last Column Number", "s7comm.param.pi.n_x.lastcolumnnumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_firstrownumber,
        { "First Row Number", "s7comm.param.pi.n_x.firstrownnumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_lastrownumber,
        { "Last Row Number", "s7comm.param.pi.n_x.lastrownnumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_direction,
        { "Direction", "s7comm.param.pi.n_x.direction", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_sourcefilename,
        { "Source-Filename", "s7comm.param.pi.n_x.sourcefilename", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_destinationfilename,
        { "Destination-Filename", "s7comm.param.pi.n_x.destinationfilename", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_channelnumber,
        { "Channel Number", "s7comm.param.pi.n_x.channelnumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_protection,
        { "Protection", "s7comm.param.pi.n_x.protection", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_oldfilename,
        { "Old Filename", "s7comm.param.pi.n_x.oldfilename", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_newfilename,
        { "New Filename", "s7comm.param.pi.n_x.newfilename", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_findmode,
        { "Findmode", "s7comm.param.pi.n_x.findmode", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_switch,
        { "Switch", "s7comm.param.pi.n_x.switch", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_functionnumber,
        { "Function Number", "s7comm.param.pi.n_x.functionnumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_semaphorvalue,
        { "Semaphor Value", "s7comm.param.pi.n_x.semaphorvalue", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_onoff,
        { "OnOff", "s7comm.param.pi.n_x.onoff", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_mode,
        { "Mode", "s7comm.param.pi.n_x.mode", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_factor,
        { "Factor", "s7comm.param.pi.n_x.factor", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_passwordlevel,
        { "Password Level", "s7comm.param.pi.n_x.passwordlevel", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_linenumber,
        { "Line Number", "s7comm.param.pi.n_x.linenumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_weargroup,
        { "Wear Group", "s7comm.param.pi.n_x.weargroup", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_toolstatus,
        { "Tool Status", "s7comm.param.pi.n_x.toolstatus", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_wearsearchstrat,
        { "Search Strategie", "s7comm.param.pi.n_x.wearsearchstrat", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_toolid,
        { "Tool ID", "s7comm.param.pi.n_x.toolid", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_duplonumber,
        { "Duplo Number", "s7comm.param.pi.n_x.duplonumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_edgenumber,
        { "Edge Number", "s7comm.param.pi.n_x.edgenumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_placenr,
        { "Place Number", "s7comm.param.pi.n_x.placenr", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_placerefnr,
        { "Place Reference Number", "s7comm.param.pi.n_x.placerefnr", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_magrefnr,
        { "Magazine Reference Number", "s7comm.param.pi.n_x.magrefnr", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_placenrfrom,
        { "Place Number from", "s7comm.param.pi.n_x.placenrfrom", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_magnrfrom,
        { "Magazine Number from", "s7comm.param.pi.n_x.magnrfrom", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_placenrto,
        { "Place Number to", "s7comm.param.pi.n_x.placenrto", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_magnrto,
        { "Magazine Number to", "s7comm.param.pi.n_x.magnrto", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_halfplacesleft,
        { "Half places left", "s7comm.param.pi.n_x.halfplacesleft", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_halfplacesright,
        { "Half places right", "s7comm.param.pi.n_x.halfplacesright", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_halfplacesup,
        { "Half places up", "s7comm.param.pi.n_x.halfplacesup", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_halfplacesdown,
        { "Half places down", "s7comm.param.pi.n_x.halfplacesdown", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_placetype,
        { "Place type index", "s7comm.param.pi.n_x.placetype", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_searchdirection,
        { "Search direction", "s7comm.param.pi.n_x.searchdirection", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_toolname,
        { "Tool Name", "s7comm.param.pi.n_x.toolname", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_placenrsource,
        { "Place Number Source", "s7comm.param.pi.n_x.placenrsource", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_magnrsource,
        { "Magazine Number Source", "s7comm.param.pi.n_x.magnrsource", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_placenrdestination,
        { "Place Number Destination", "s7comm.param.pi.n_x.placenrdestination", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_magnrdestination,
        { "Magazine Number Destination", "s7comm.param.pi.n_x.magnrdestination", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_incrementnumber,
        { "Increment Number", "s7comm.param.pi.n_x.incrementnumber", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_monitoringmode,
        { "Monitoring mode", "s7comm.param.pi.n_x.monitoringmode", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},
        { &hf_s7comm_pi_n_x_kindofsearch,
        { "Kind of search", "s7comm.param.pi.n_x.kindofsearch", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL , HFILL }},

        { &hf_s7comm_data_pi_inse_unknown,
        { "Unknown byte", "s7comm.param.pi.inse.unknown", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_data_plccontrol_argument,
        { "Argument", "s7comm.param.pistart.argument", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_block_cnt,
        { "Number of blocks", "s7comm.data.plccontrol.block_cnt", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_part2_len,
        { "Length part 2", "s7comm.data.plccontrol.part2_len", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length of part 2 in bytes", HFILL }},

        /* block control functions */
        { &hf_s7comm_data_blockcontrol_unknown1,
        { "Unknown byte(s) in blockcontrol", "s7comm.data.blockcontrol.unknown1", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_errorcode,
        { "Errorcode", "s7comm.data.blockcontrol.errorcode", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Errorcode, 0 on success", HFILL }},
        { &hf_s7comm_data_blockcontrol_uploadid,
        { "UploadID", "s7comm.data.blockcontrol.uploadid", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_file_ident,
        { "File identifier", "s7comm.data.blockcontrol.file_identifier", FT_STRING, BASE_NONE, NULL, 0x0,
          "File identifier: '_'=complete module; '$'=Module header for up-loading", HFILL }},
        { &hf_s7comm_data_blockcontrol_block_type,
        { "Block type", "s7comm.data.blockcontrol.block_type", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_block_num,
        { "Block number", "s7comm.data.blockcontrol.block_number", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_dest_filesys,
        { "Destination filesystem", "s7comm.data.blockcontrol.dest_filesys", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_part2_len,
        { "Length part 2", "s7comm.data.blockcontrol.part2_len", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length of part 2 in bytes", HFILL }},
        { &hf_s7comm_data_blockcontrol_part2_unknown,
        { "Unknown char before load mem", "s7comm.data.blockcontrol.part2_unknown", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_loadmem_len,
        { "Length of load memory", "s7comm.data.blockcontrol.loadmem_len", FT_STRING, BASE_NONE, NULL, 0x0,
          "Length of load memory in bytes", HFILL }},
        { &hf_s7comm_data_blockcontrol_mc7code_len,
        { "Length of MC7 code", "s7comm.data.blockcontrol.mc7code_len", FT_STRING, BASE_NONE, NULL, 0x0,
          "Length of MC7 code in bytes", HFILL }},

        { &hf_s7comm_data_blockcontrol_filename_len,
        { "Filename Length", "s7comm.param.blockcontrol.filename_len", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length following filename in bytes", HFILL }},
        { &hf_s7comm_data_blockcontrol_filename,
        { "Filename", "s7comm.param.blockcontrol.filename", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_upl_lenstring_len,
        { "Blocklengthstring Length", "s7comm.param.blockcontrol.upl_lenstring_len", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length following blocklength string in bytes", HFILL }},
        { &hf_s7comm_data_blockcontrol_upl_lenstring,
        { "Blocklength", "s7comm.param.blockcontrol.upl_lenstring", FT_STRING, BASE_NONE, NULL, 0x0,
          "Length of the complete uploadblock in bytes, may be split into many PDUs", HFILL }},
        { &hf_s7comm_data_blockcontrol_functionstatus,
        { "Function Status", "s7comm.param.blockcontrol.functionstatus", FT_UINT8, BASE_HEX, NULL, 0x0,
          "0=no error, 1=more data, 2=error", HFILL }},
        { &hf_s7comm_data_blockcontrol_functionstatus_more,
        { "More data following", "s7comm.param.blockcontrol.functionstatus.more", FT_BOOLEAN, 8, NULL, 0x01,
          "More data of the block/file can be retrieved with another request", HFILL }},
        { &hf_s7comm_data_blockcontrol_functionstatus_error,
        { "Error", "s7comm.param.blockcontrol.functionstatus.error", FT_BOOLEAN, 8, NULL, 0x02,
          "An error occurred", HFILL }},

        /* NC programming functions */
        { &hf_s7comm_data_ncprg_unackcount,
        { "Number of telegrams sent without acknowledge", "s7comm.data.ncprg.unackcount", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_ncprg_filelength,
        { "NC file length", "s7comm.data.ncprg.filelength", FT_STRING, BASE_NONE, NULL, 0x0,
          "NC file length: length of file date + file path", HFILL }},
        { &hf_s7comm_data_ncprg_filetime,
        { "NC file timestamp", "s7comm.data.ncprg.filetime", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_ncprg_filepath,
        { "NC file path", "s7comm.data.ncprg.filepath", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_ncprg_filedata,
        { "NC file data", "s7comm.data.ncprg.filedata", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        /* Variable status */
        { &hf_s7comm_varstat_unknown,
        { "Unknown byte(s) varstat", "s7comm.varstat.unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_varstat_item_count,
        { "Item count", "s7comm.varstat.item_count", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_varstat_req_memory_area,
        { "Memory area", "s7comm.varstat.req.memory_area", FT_UINT8, BASE_DEC, VALS(userdata_prog_varstat_area_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_varstat_req_repetition_factor,
        { "Repetition factor", "s7comm.varstat.req.repetition_factor", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_varstat_req_db_number,
        { "DB number", "s7comm.varstat.req.db_number", FT_UINT16, BASE_DEC, NULL, 0x0,
          "DB number, when area is DB", HFILL }},
        { &hf_s7comm_varstat_req_startaddress,
        { "Startaddress", "s7comm.varstat.req.startaddress", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Startaddress / byteoffset", HFILL }},
        { &hf_s7comm_varstat_req_bitpos,
        { "Bitposition", "s7comm.varstat.req.bitpos", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        /* cyclic services */
        { &hf_s7comm_cycl_interval_timebase,
        { "Interval timebase", "s7comm.cyclic.interval_timebase", FT_UINT8, BASE_DEC, VALS(cycl_interval_timebase_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cycl_interval_time,
        { "Interval time factor", "s7comm.cyclic.interval_time", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cycl_function,
        { "Function", "s7comm.cyclic.function", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cycl_jobid,
        { "Job-ID", "s7comm.cyclic.job_id", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        /* Read record */
        { &hf_s7comm_rdrec_mlen,
        { "Rdrec Mlen", "s7comm.readrec.mlen", FT_UINT16, BASE_DEC, NULL, 0x0,
          "MLEN, Max. length in bytes of the data record data to be read", HFILL }},
        { &hf_s7comm_rdrec_index,
        { "Rdrec Index", "s7comm.readrec.index", FT_UINT16, BASE_HEX, NULL, 0x0,
          "INDEX, Data record number", HFILL }},
        { &hf_s7comm_rdrec_id,
        { "Rdrec ID", "s7comm.readrec.id", FT_UINT24, BASE_DEC, NULL, 0x0,
          "ID, Diagnostic address", HFILL }},
        { &hf_s7comm_rdrec_statuslen,
        { "Rdrec Status Len", "s7comm.readrec.statuslen", FT_UINT8, BASE_DEC, NULL, 0x0,
          "STATUS LEN, Length of status data", HFILL }},
        { &hf_s7comm_rdrec_statusdata,
        { "Rdrec Status", "s7comm.readrec.status", FT_BYTES, BASE_NONE, NULL, 0x0,
          "STATUS, Status data", HFILL }},
        { &hf_s7comm_rdrec_recordlen,
        { "Rdrec Len", "s7comm.readrec.len", FT_UINT16, BASE_DEC, NULL, 0x0,
          "LEN, Length of data record data read", HFILL }},
        { &hf_s7comm_rdrec_data,
        { "Rdrec Data", "s7comm.readrec.data", FT_BYTES, BASE_NONE, NULL, 0x0,
          "DATA, The read data record", HFILL }},
        { &hf_s7comm_rdrec_reserved1,
        { "Rdrec reserved", "s7comm.readrec.reserved1", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        /* PBC, Programmable Block Functions */
        { &hf_s7comm_pbc_unknown,
        { "PBC BSEND/BRECV unknown", "s7comm.pbc.bsend.unknown", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_pbc_r_id,
        { "PBC BSEND/BRECV R_ID", "s7comm.pbc.req.bsend.r_id", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_pbc_len,
        { "PBC BSEND/BRECV LEN", "s7comm.pbc.req.bsend.len", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        /* CPU alarms */
        { &hf_s7comm_cpu_alarm_message_item,
        { "Alarm message", "s7comm.alarm.message", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_obj_item,
        { "Message object", "s7comm.alarm.message_object", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_function,
        { "Function identifier", "s7comm.alarm.function", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_nr_objects,
        { "Number of message objects", "s7comm.alarm.nr_objects", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_nr_add_values,
        { "Number of associated values", "s7comm.alarm.nr_add_values", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_eventid,
        { "EventID", "s7comm.alarm.event_id", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_timestamp_coming,
        { "Timestamp message coming", "s7comm.alarm.timestamp_coming", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_timestamp_going,
        { "Timestamp message going", "s7comm.alarm.timestamp_going", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_associated_value,
        { "Associated value(s)", "s7comm.alarm.associated_value", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_eventstate,
        { "EventState", "s7comm.alarm.eventstate", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_signal_sig1,
        { "SIG_1", "s7comm.alarm.signal.sig1", FT_BOOLEAN, 8, NULL, 0x01,
          "Current state of Signal SIG_1", HFILL }},
        { &hf_s7comm_cpu_alarm_message_signal_sig2,
        { "SIG_2", "s7comm.alarm.signal.sig2", FT_BOOLEAN, 8, NULL, 0x02,
          "Current state of Signal SIG_2", HFILL }},
        { &hf_s7comm_cpu_alarm_message_signal_sig3,
        { "SIG_3", "s7comm.alarm.signal.sig3", FT_BOOLEAN, 8, NULL, 0x04,
          "Current state of Signal SIG_3", HFILL }},
        { &hf_s7comm_cpu_alarm_message_signal_sig4,
        { "SIG_4", "s7comm.alarm.signal.sig4", FT_BOOLEAN, 8, NULL, 0x08,
          "Current state of Signal SIG_4", HFILL }},
        { &hf_s7comm_cpu_alarm_message_signal_sig5,
        { "SIG_5", "s7comm.alarm.signal.sig5", FT_BOOLEAN, 8, NULL, 0x10,
          "Current state of Signal SIG_5", HFILL }},
        { &hf_s7comm_cpu_alarm_message_signal_sig6,
        { "SIG_6", "s7comm.alarm.signal.sig6", FT_BOOLEAN, 8, NULL, 0x20,
          "Current state of Signal SIG_6", HFILL }},
        { &hf_s7comm_cpu_alarm_message_signal_sig7,
        { "SIG_7", "s7comm.alarm.signal.sig7", FT_BOOLEAN, 8, NULL, 0x40,
          "Current state of Signal SIG_7", HFILL }},
        { &hf_s7comm_cpu_alarm_message_signal_sig8,
        { "SIG_8", "s7comm.alarm.signal.sig8", FT_BOOLEAN, 8, NULL, 0x80,
          "Current state of Signal SIG_8", HFILL }},
        { &hf_s7comm_cpu_alarm_message_state,
        { "State", "s7comm.alarm.state", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_ackstate_coming,
        { "AckState coming", "s7comm.alarm.ack_state.coming", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Acknowledge state coming (1=Event acknowledged, 0=Event not acknowledged)", HFILL }},
        { &hf_s7comm_cpu_alarm_message_ackstate_going,
        { "AckState going", "s7comm.alarm.ack_state.going", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Acknowledge state going (1=Event acknowledged, 0=Event not acknowledged)", HFILL }},
         { &hf_s7comm_cpu_alarm_message_event_coming,
        { "Event coming", "s7comm.alarm.event.coming", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_event_going,
        { "Event going", "s7comm.alarm.event.going", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_event_lastchanged,
        { "Event last changed", "s7comm.alarm.event.lastchanged", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_event_reserved,
        { "Reserved", "s7comm.alarm.event.reserved", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_scan_unknown1,
        { "SCAN unknown 1", "s7comm.alarm.scan.unknown1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_message_scan_unknown2,
        { "SCAN unknown 2", "s7comm.alarm.scan.unknown2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        /* Alarm message query */
        { &hf_s7comm_cpu_alarm_query_unknown1,
        { "Unknown/Reserved (1)", "s7comm.alarm.query.unknown1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_query_querytype,
        { "Querytype", "s7comm.alarm.query.querytype", FT_UINT8, BASE_DEC, VALS(alarm_message_querytype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_query_unknown2,
        { "Unknown/Reserved (2)", "s7comm.alarm.query.unknown2", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_query_alarmtype,
        { "Alarmtype", "s7comm.alarm.query.alarmtype", FT_UINT32, BASE_DEC, VALS(alarm_message_query_alarmtype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_query_completelen,
        { "Complete data length", "s7comm.alarm.query.complete_length", FT_UINT32, BASE_DEC, NULL, 0x0,
          "Complete data length (with ALARM_S this is 0xffff, as they might be split into many telegrams)", HFILL }},
        { &hf_s7comm_cpu_alarm_query_datasetlen,
        { "Length of dataset", "s7comm.alarm.query.dataset_length", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_alarm_query_resunknown1,
        { "Unknown", "s7comm.alarm.query.resunknown1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        /* CPU diagnostic messages */
        { &hf_s7comm_cpu_diag_msg_item,
        { "CPU diagnostic message", "s7comm.cpu.diag_msg", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_diag_msg_eventid,
        { "Event ID", "s7comm.cpu.diag_msg.eventid", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_diag_msg_eventid_class,
        { "Event class", "s7comm.cpu.diag_msg.eventid.class", FT_UINT16, BASE_HEX, VALS(cpu_diag_msg_eventid_class_names), 0xf000,
          NULL, HFILL }},
        { &hf_s7comm_cpu_diag_msg_eventid_ident_entleave,
        { "Event entering state", "s7comm.cpu.diag_msg.eventid.ident.entleave", FT_BOOLEAN, 16, TFS(&tfs_s7comm_cpu_diag_msg_eventid_ident_entleave), 0x0100,
          "Event identifier: 0=Event leaving state,1=Event entering state", HFILL }},
        { &hf_s7comm_cpu_diag_msg_eventid_ident_diagbuf,
        { "Entry in diagnostic buffer", "s7comm.cpu.diag_msg.eventid.ident.diagbuf", FT_BOOLEAN, 16, NULL, 0x0200,
          "Event identifier: Entry in diagnostic buffer", HFILL }},
        { &hf_s7comm_cpu_diag_msg_eventid_ident_interr,
        { "Internal error", "s7comm.cpu.diag_msg.eventid.ident.interr", FT_BOOLEAN, 16, NULL, 0x0400,
          "Event identifier: Internal error", HFILL }},
        { &hf_s7comm_cpu_diag_msg_eventid_ident_exterr,
        { "External error", "s7comm.cpu.diag_msg.eventid.ident.exterr", FT_BOOLEAN, 16, NULL, 0x0800,
          "Event identifier: External error", HFILL }},
        { &hf_s7comm_cpu_diag_msg_eventid_nr,
        { "Event number", "s7comm.cpu.diag_msg.eventid.nr", FT_UINT16, BASE_HEX, NULL, 0x00ff,
          NULL, HFILL }},
        { &hf_s7comm_cpu_diag_msg_prioclass,
        { "Priority class", "s7comm.cpu.diag_msg.prioclass", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_diag_msg_obnumber,
        { "OB number", "s7comm.cpu.diag_msg.obnumber", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_diag_msg_datid,
        { "DatID", "s7comm.cpu.diag_msg.datid", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_diag_msg_info1,
        { "INFO1 Additional information 1", "s7comm.cpu.diag_msg.info1", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_diag_msg_info2,
        { "INFO2 Additional information 2", "s7comm.cpu.diag_msg.info2", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        /* CPU message service */
        { &hf_s7comm_cpu_msgservice_subscribe_events,
        { "Subscribed events", "s7comm.cpu.msg.events", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_msgservice_subscribe_events_modetrans,
        { "Mode-transition", "s7comm.cpu.msg.events.modetrans", FT_BOOLEAN, 8, NULL, 0x01,
          "MODE: Register for mode-transition events via func-group=0 and subfunction=state", HFILL }},
        { &hf_s7comm_cpu_msgservice_subscribe_events_system,
        { "System-diagnostics", "s7comm.cpu.msg.events.system", FT_BOOLEAN, 8, NULL, 0x02,
          "SYS: Register for system diagnostic events", HFILL }},
        { &hf_s7comm_cpu_msgservice_subscribe_events_userdefined,
        { "Userdefined", "s7comm.cpu.msg.events.userdefined", FT_BOOLEAN, 8, NULL, 0x04,
          "USR: Register system user-defined diagnostic messages", HFILL }},
        { &hf_s7comm_cpu_msgservice_subscribe_events_alarms,
        { "Alarms", "s7comm.cpu.msg.events.alarms", FT_BOOLEAN, 8, NULL, 0x80,
          "ALM: Register alarm events (ALARM, SCAN, ALARM_S) type of event defined in additional field", HFILL }},
        { &hf_s7comm_cpu_msgservice_req_reserved1,
        { "Reserved/Unknown", "s7comm.cpu.msg.req_reserved1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_msgservice_username,
        { "Username", "s7comm.cpu.msg.username", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_msgservice_almtype,
        { "Alarm type", "s7comm.cpu.msg.almtype", FT_UINT8, BASE_DEC, VALS(cpu_msgservice_almtype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_msgservice_req_reserved2,
        { "Reserved/Unknown", "s7comm.cpu.msg.req_reserved2", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_msgservice_res_result,
        { "Result", "s7comm.cpu.msg.res_result", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_msgservice_res_reserved1,
        { "Reserved/Unknown", "s7comm.cpu.msg.res_reserved1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_msgservice_res_reserved2,
        { "Reserved/Unknown", "s7comm.cpu.msg.res_reserved2", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cpu_msgservice_res_reserved3,
        { "Reserved/Unknown", "s7comm.cpu.msg.res_reserved3", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_modetrans_param_subfunc,
        { "Current mode", "s7comm.param.modetrans.subfunc", FT_UINT8, BASE_DEC, VALS(modetrans_param_subfunc_names), 0x0,
          NULL, HFILL }},

        /* TIA Portal stuff */
        { &hf_s7comm_tia1200_item_reserved1,
        { "1200 sym Reserved", "s7comm.tiap.item.reserved1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tia1200_item_area1,
        { "1200 sym root area 1", "s7comm.tiap.item.area1", FT_UINT16, BASE_HEX, VALS(tia1200_var_item_area1_names), 0x0,
          "Area from where to read: DB or Inputs, Outputs, etc.", HFILL }},
        { &hf_s7comm_tia1200_item_area2,
        { "1200 sym root area 2", "s7comm.tiap.item.area2", FT_UINT16, BASE_HEX, VALS(tia1200_var_item_area2_names), 0x0,
          "Specifies the area from where to read", HFILL }},
        { &hf_s7comm_tia1200_item_area2unknown,
        { "1200 sym root area 2 unknown", "s7comm.tiap.item.area2unknown", FT_UINT16, BASE_HEX, NULL, 0x0,
          "For current unknown areas", HFILL }},
        { &hf_s7comm_tia1200_item_dbnumber,
        { "1200 sym root DB number", "s7comm.tiap.item.dbnumber", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tia1200_item_crc,
        { "1200 sym CRC", "s7comm.tiap.item.crc", FT_UINT32, BASE_HEX, NULL, 0x0,
          "CRC generated out of symbolic name with (x^32+x^31+x^30+x^29+x^28+x^26+x^23+x^21+x^19+x^18+x^15+x^14+x^13+x^12+x^9+x^8+x^4+x+1)", HFILL }},
        { &hf_s7comm_tia1200_var_lid_flags,
        { "LID flags", "s7comm.tiap.item.lid_flags", FT_UINT8, BASE_DEC, VALS(tia1200_var_lid_flag_names), 0xf0,
          NULL, HFILL }},
        { &hf_s7comm_tia1200_substructure_item,
        { "Substructure", "s7comm.tiap.item.substructure", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tia1200_item_value,
        { "Value", "s7comm.tiap.item.value", FT_UINT32, BASE_DEC, NULL, 0x0fffffff,
          NULL, HFILL }},

        /* Fragment fields */
        { &hf_s7comm_fragment_overlap,
        { "Fragment overlap", "s7comm.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Fragment overlaps with other fragments", HFILL }},
        { &hf_s7comm_fragment_overlap_conflict,
        { "Conflicting data in fragment overlap", "s7comm.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Overlapping fragments contained conflicting data", HFILL }},
        { &hf_s7comm_fragment_multiple_tails,
        { "Multiple tail fragments found", "s7comm.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Several tails were found when defragmenting the packet", HFILL }},
        { &hf_s7comm_fragment_too_long_fragment,
        { "Fragment too long", "s7comm.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Fragment contained data past end of packet", HFILL }},
        { &hf_s7comm_fragment_error,
        { "Defragmentation error", "s7comm.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          "Defragmentation error due to illegal fragments", HFILL }},
        { &hf_s7comm_fragment_count,
        { "Fragment count", "s7comm.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_reassembled_in,
        { "Reassembled in", "s7comm.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          "S7COMM fragments are reassembled in the given packet", HFILL }},
        { &hf_s7comm_reassembled_length,
        { "Reassembled S7COMM length", "s7comm.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
          "The total length of the reassembled payload", HFILL }},
        { &hf_s7comm_fragment,
        { "S7COMM Fragment", "s7comm.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_fragments,
        { "S7COMM Fragments", "s7comm.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    };

    static ei_register_info ei[] = {
        { &ei_s7comm_data_blockcontrol_block_num_invalid, { "s7comm.data.blockcontrol.block_number.invalid", PI_MALFORMED, PI_ERROR,
            "Block number must be a string containing an integer", EXPFILL }},
        { &ei_s7comm_ud_blockinfo_block_num_ascii_invalid, { "s7comm.data.blockinfo.block_number.invalid", PI_MALFORMED, PI_ERROR,
            "Block info must be a string containing an integer", EXPFILL }}
    };

    static gint *ett[] = {
        &ett_s7comm,
        &ett_s7comm_header,
        &ett_s7comm_param,
        &ett_s7comm_param_item,
        &ett_s7comm_param_subitem,
        &ett_s7comm_data,
        &ett_s7comm_data_item,
        &ett_s7comm_item_address,
        &ett_s7comm_diagdata_registerflag,
        &ett_s7comm_userdata_blockinfo_flags,
        &ett_s7comm_cpu_alarm_message,
        &ett_s7comm_cpu_alarm_message_object,
        &ett_s7comm_cpu_alarm_message_signal,
        &ett_s7comm_cpu_alarm_message_timestamp,
        &ett_s7comm_cpu_alarm_message_associated_value,
        &ett_s7comm_cpu_diag_msg,
        &ett_s7comm_cpu_diag_msg_eventid,
        &ett_s7comm_cpu_msgservice_subscribe_events,
        &ett_s7comm_piservice_parameterblock,
        &ett_s7comm_data_blockcontrol_status,
        &ett_s7comm_plcfilename,
        &ett_s7comm_prog_parameter,
        &ett_s7comm_prog_data,
        &ett_s7comm_fragments,
        &ett_s7comm_fragment,
    };

    proto_s7comm = proto_register_protocol (
            "S7 Communication",         /* name */
            "S7COMM",                   /* short name */
            "s7comm"                    /* abbrev */
            );

    proto_register_field_array(proto_s7comm, hf, array_length (hf));

    s7comm_register_szl_types(proto_s7comm);

    proto_register_subtree_array(ett, array_length (ett));

    expert_s7comm = expert_register_protocol(proto_s7comm);
    expert_register_field_array(expert_s7comm, ei, array_length(ei));

    register_init_routine(s7comm_defragment_init);
}

/* Register this protocol */
void
proto_reg_handoff_s7comm(void)
{
    /* register ourself as an heuristic cotp (ISO 8073) payload dissector */
    heur_dissector_add("cotp", dissect_s7comm, "S7 Communication over COTP", "s7comm_cotp", proto_s7comm, HEURISTIC_ENABLE);
    heur_dissector_add("cotp_is", dissect_s7comm, "S7 Communication over COTP", "s7comm_cotp_is", proto_s7comm, HEURISTIC_ENABLE);
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
