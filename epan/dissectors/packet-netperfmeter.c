/* packet-netperfmeter.c
 * Routines for the NetPerfMeter protocol used by the Open Source
 * network performance meter application NetPerfMeter:
 * https://www.uni-due.de/~be0001/netperfmeter/
 *
 * Copyright 2009-2021 by Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/stat_tap_ui.h>

void proto_register_npm(void);
void proto_reg_handoff_npm(void);

static int proto_npm              = -1;
static int tap_npm                = -1;
static int ett_npm                = -1;
static int ett_addflow_flags      = -1;
static int ett_identifyflow_flags = -1;
static int ett_start_flags        = -1;
static int ett_data_flags         = -1;
static int ett_results_flags      = -1;
static int ett_onoffarray         = -1;

static guint64 npm_total_msgs     = 0;
static guint64 npm_total_bytes    = 0;


#define PPID_NETPERFMETER_CONTROL_LEGACY   0x29097605
#define PPID_NETPERFMETER_DATA_LEGACY      0x29097606


/* Initialize the protocol and registered fields */

#define NETPERFMETER_ACKNOWLEDGE    0x01
#define NETPERFMETER_ADD_FLOW       0x02
#define NETPERFMETER_REMOVE_FLOW    0x03
#define NETPERFMETER_IDENTIFY_FLOW  0x04
#define NETPERFMETER_DATA           0x05
#define NETPERFMETER_START          0x06
#define NETPERFMETER_STOP           0x07
#define NETPERFMETER_RESULTS        0x08

static const value_string message_type_values[] = {
  { NETPERFMETER_ACKNOWLEDGE,   "NetPerfMeter Acknowledge" },
  { NETPERFMETER_ADD_FLOW,      "NetPerfMeter Add Flow" },
  { NETPERFMETER_REMOVE_FLOW,   "NetPerfMeter Remove Flow" },
  { NETPERFMETER_IDENTIFY_FLOW, "NetPerfMeter Identify Flow" },
  { NETPERFMETER_DATA,          "NetPerfMeter Data" },
  { NETPERFMETER_START,         "NetPerfMeter Start Measurement" },
  { NETPERFMETER_STOP,          "NetPerfMeter Stop Measurement" },
  { NETPERFMETER_RESULTS,       "NetPerfMeter Results" },
  { 0, NULL }
};

static int hf_message_type               = -1;
static int hf_message_flags              = -1;
static int hf_message_length             = -1;

static int hf_acknowledge_flowid         = -1;
static int hf_acknowledge_measurementid  = -1;
static int hf_acknowledge_streamid       = -1;
// static int hf_acknowledge_padding     = -1;
static int hf_acknowledge_status         = -1;

static int hf_addflow_flag_debug         = -1;
static int hf_addflow_flag_nodelay       = -1;
static int hf_addflow_flag_repeatonoff   = -1;
static int hf_addflow_flowid             = -1;
static int hf_addflow_measurementid      = -1;
static int hf_addflow_streamid           = -1;
static int hf_addflow_protocol           = -1;
static int hf_addflow_flags              = -1;
static int hf_addflow_description        = -1;
static int hf_addflow_ordered            = -1;
static int hf_addflow_reliable           = -1;
static int hf_addflow_retranstrials      = -1;
static int hf_addflow_framerate1         = -1;
static int hf_addflow_framerate2         = -1;
static int hf_addflow_framerate3         = -1;
static int hf_addflow_framerate4         = -1;
static int hf_addflow_framesize1         = -1;
static int hf_addflow_framesize2         = -1;
static int hf_addflow_framesize3         = -1;
static int hf_addflow_framesize4         = -1;
static int hf_addflow_frameraterng       = -1;
static int hf_addflow_framesizerng       = -1;
static int hf_addflow_rcvbuffersize      = -1;
static int hf_addflow_sndbuffersize      = -1;
static int hf_addflow_maxmsgsize         = -1;
static int hf_addflow_cmt                = -1;
static int hf_addflow_ccid               = -1;
static int hf_addflow_onoffevents        = -1;
static int hf_addflow_onoffeventarray    = -1;

static int hf_removeflow_flowid          = -1;
static int hf_removeflow_measurementid   = -1;
static int hf_removeflow_streamid        = -1;

static int hf_identifyflow_flag_compress_vectors = -1;
static int hf_identifyflow_flag_no_vectors       = -1;
static int hf_identifyflow_flowid        = -1;
static int hf_identifyflow_magicnumber   = -1;
static int hf_identifyflow_measurementid = -1;
static int hf_identifyflow_streamid      = -1;

#define NETPERFMETER_IDENTIFY_FLOW_MAGIC_NUMBER 0x4bcdf3aa303c6774ULL

static int hf_data_flag_frame_begin       = -1;
static int hf_data_flag_frame_end         = -1;
static int hf_data_flowid                 = -1;
static int hf_data_measurementid          = -1;
static int hf_data_streamid               = -1;
static int hf_data_padding                = -1;
static int hf_data_frameid                = -1;
static int hf_data_packetseqnumber        = -1;
static int hf_data_byteseqnumber          = -1;
static int hf_data_timestamp              = -1;
static int hf_data_payload                = -1;

static int hf_start_flag_compress_vectors = -1;
static int hf_start_flag_compress_scalars = -1;
static int hf_start_flag_no_vectors       = -1;
static int hf_start_flag_no_scalars       = -1;
// static int hf_start_padding            = -1;
static int hf_start_measurementid         = -1;

// static int hf_stop_padding             = -1;
static int hf_stop_measurementid          = -1;

static int hf_results_flag_eof            = -1;
static int hf_results_data                = -1;


/* Setup list of Transport Layer protocol types */
static const value_string proto_type_values[] = {
  { 6,   "TCP" },
  { 8,   "MPTCP" },
  { 17,  "UDP" },
  { 33,  "DCCP" },
  { 132, "SCTP" },
  { 0,   NULL }
};

/* Setup list of CMT values */
static const value_string cmt_values[] = {
  { 0, "Off" },
  { 1, "CMT" },
  { 2, "CMT/RPv1" },
  { 3, "CMT/RPv2" },
  { 4, "MPTCP-Like" },
  { 0, NULL }
};

/* Setup list of random number generator types */
static const value_string rng_type_values[] = {
  { 0, "Constant" },
  { 1, "Uniform" },
  { 2, "Neg. Exponential" },
  { 0, NULL }
};

/* Message flags */
#define NPMAFF_DEBUG           (1 << 0)
#define NPMAFF_NODELAY         (1 << 1)
#define NPMAFF_REPEATONOFF     (1 << 2)

#define NPMIF_COMPRESS_VECTORS (1 << 0)
#define NPMIF_NO_VECTORS       (1 << 1)

#define NPMSF_COMPRESS_VECTORS (1 << 0)
#define NPMSF_COMPRESS_SCALARS (1 << 1)
#define NPMSF_NO_VECTORS       (1 << 2)
#define NPMSF_NO_SCALARS       (1 << 3)

#define NPMDF_FRAME_BEGIN      (1 << 0)
#define NPMDF_FRAME_END        (1 << 1)

#define NPMRF_EOF              (1 << 0)


/* Setup list of header fields */
static hf_register_info hf[] = {
   { &hf_message_type,               { "Type",                  "netperfmeter.message_type",               FT_UINT8,   BASE_DEC,  VALS(message_type_values), 0x0, NULL, HFILL } },
   { &hf_message_flags,              { "Flags",                 "netperfmeter.message_flags",              FT_UINT8,   BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_message_length,             { "Length",                "netperfmeter.message_length",             FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_acknowledge_flowid,         { "Flow ID",               "netperfmeter.acknowledge_flowid",         FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_acknowledge_measurementid,  { "Measurement ID",        "netperfmeter.acknowledge_measurementid",  FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_acknowledge_streamid,       { "Stream ID",             "netperfmeter.acknowledge_streamid",       FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
#if 0
   { &hf_acknowledge_padding,        { "Padding",               "netperfmeter.acknowledge_padding",        FT_UINT16,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
#endif
   { &hf_acknowledge_status,         { "Status",                "netperfmeter.acknowledge_status",         FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_addflow_flowid,             { "Flow ID",               "netperfmeter.addflow_flowid",             FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_measurementid,      { "Measurement ID",        "netperfmeter.addflow_measurementid",      FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_streamid,           { "Stream ID",             "netperfmeter.addflow_streamid",           FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_protocol,           { "Protocol",              "netperfmeter.addflow_protocol",           FT_UINT8,   BASE_DEC,  VALS(proto_type_values),   0x0, NULL, HFILL } },
   { &hf_addflow_flags,              { "Flags",                 "netperfmeter.addflow_flags",              FT_UINT8,   BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_description,        { "Description",           "netperfmeter.addflow_description",        FT_STRING,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_ordered,            { "Ordered",               "netperfmeter.addflow_ordered",            FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_reliable,           { "Reliable",              "netperfmeter.addflow_reliable",           FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_retranstrials,      { "Retransmission Trials", "netperfmeter.addflow_retranstrials",      FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_frameraterng,       { "Frame Rate RNG",        "netperfmeter.addflow_frameraterng",       FT_UINT8,   BASE_DEC,  VALS(rng_type_values),     0x0, NULL, HFILL } },
   { &hf_addflow_framerate1,         { "Frame Rate 1",          "netperfmeter.addflow_framerate1",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framerate2,         { "Frame Rate 2",          "netperfmeter.addflow_framerate2",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framerate3,         { "Frame Rate 3",          "netperfmeter.addflow_framerate3",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framerate4,         { "Frame Rate 4",          "netperfmeter.addflow_framerate4",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framesizerng,       { "Frame Size RNG",        "netperfmeter.addflow_framesizerng",       FT_UINT8,   BASE_DEC,  VALS(rng_type_values),     0x0, NULL, HFILL } },
   { &hf_addflow_framesize1,         { "Frame Size 1",          "netperfmeter.addflow_framesize1",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framesize2,         { "Frame Size 2",          "netperfmeter.addflow_framesize2",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framesize3,         { "Frame Size 3",          "netperfmeter.addflow_framesize3",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framesize4,         { "Frame Size 4",          "netperfmeter.addflow_framesize4",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_rcvbuffersize,      { "Receive Buffer Size",   "netperfmeter.addflow_rcvbuffersize",      FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_sndbuffersize,      { "Send Buffer Size",      "netperfmeter.addflow_sndbuffersize",      FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_maxmsgsize,         { "Max. Message Size",     "netperfmeter.addflow_maxmsgsize",         FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_cmt,                { "CMT",                   "netperfmeter.addflow_cmt",                FT_UINT8,   BASE_HEX,  VALS(cmt_values),          0x0, NULL, HFILL } },
   { &hf_addflow_ccid,               { "CCID",                  "netperfmeter.addflow_ccid",               FT_UINT8,   BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_onoffevents,        { "On/Off Events",         "netperfmeter.addflow_onoffevents",        FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_onoffeventarray,    { "On/Off Event",          "netperfmeter.addflow_onoffeventarray",    FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_flag_debug,         { "Debug",                 "netperfmeter.addflow_flags.debug",        FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMAFF_DEBUG,       NULL, HFILL } },
   { &hf_addflow_flag_nodelay,       { "No Delay",              "netperfmeter.addflow_flags.nodelay",      FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMAFF_NODELAY,     NULL, HFILL } },
   { &hf_addflow_flag_repeatonoff,   { "Repeat On/Off",         "netperfmeter.addflow_flags.repeatonoff",  FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMAFF_REPEATONOFF, NULL, HFILL } },

   { &hf_removeflow_flowid,          { "Flow ID",               "netperfmeter.removeflow_flowid",          FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_removeflow_measurementid,   { "Measurement ID",        "netperfmeter.removeflow_measurementid",   FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_removeflow_streamid,        { "Stream ID",             "netperfmeter.removeflow_streamid",        FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_identifyflow_flowid,        { "Flow ID",               "netperfmeter.identifyflow_flowid",        FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_magicnumber,   { "Magic Number",          "netperfmeter.identifyflow_magicnumber",   FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_measurementid, { "Measurement ID",        "netperfmeter.identifyflow_measurementid", FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_streamid,      { "Stream ID",             "netperfmeter.identifyflow_streamid",      FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_flag_compress_vectors, { "Compress Vectors", "netperfmeter.dentifyflow_flags.compress_vectors", FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMIF_COMPRESS_VECTORS, NULL, HFILL } },
   { &hf_identifyflow_flag_no_vectors,       { "No Vectors", "netperfmeter.dentifyflow_flags.no_vectors",             FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMIF_NO_VECTORS,       NULL, HFILL } },

   { &hf_data_flowid,                { "Flow ID",               "netperfmeter.data_flowid",                FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_measurementid,         { "Measurement ID",        "netperfmeter.data_measurementid",         FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_streamid,              { "Stream ID",             "netperfmeter.data_streamid",              FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_padding,               { "Padding",               "netperfmeter.data_padding",               FT_UINT16,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_frameid,               { "Frame ID",              "netperfmeter.data_frameid",               FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_packetseqnumber,       { "Packet Seq Number",     "netperfmeter.data_packetseqnumber",       FT_UINT64,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_byteseqnumber,         { "Byte Seq Number",       "netperfmeter.data_byteseqnumber",         FT_UINT64,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_timestamp,             { "Time Stamp",            "netperfmeter.data_timestamp",             FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,        0x0, NULL, HFILL } },
   { &hf_data_payload,               { "Payload",               "netperfmeter.data_payload",               FT_BYTES,   BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_data_flag_frame_begin,      { "Begin of Frame",        "netperfmeter.data_flags.frame_begin",     FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMDF_FRAME_BEGIN, NULL, HFILL } },
   { &hf_data_flag_frame_end,        { "End of Frame",          "netperfmeter.data_flags.frame_end",       FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMDF_FRAME_END,   NULL, HFILL } },

#if 0
   { &hf_start_padding,              { "Padding",               "netperfmeter.start_padding",              FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
#endif
   { &hf_start_measurementid,        { "Measurement ID",        "netperfmeter.start_measurementid",        FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_start_flag_compress_vectors,{ "Compress Vectors",      "netperfmeter.start_flags.compress_vectors", FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMSF_COMPRESS_VECTORS, NULL, HFILL } },
   { &hf_start_flag_compress_scalars,{ "Compress Scalars",      "netperfmeter.start_flags.compress_scalars", FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMSF_COMPRESS_SCALARS, NULL, HFILL } },
   { &hf_start_flag_no_vectors,      { "No Vectors",            "netperfmeter.start_flags.no_vectors",       FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMSF_NO_VECTORS,       NULL, HFILL } },
   { &hf_start_flag_no_scalars,      { "No Scalars",            "netperfmeter.start_flags.no_scalars",       FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMSF_NO_SCALARS,       NULL, HFILL } },

#if 0
   { &hf_stop_padding,               { "Padding",               "netperfmeter.stop_padding",               FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
#endif
   { &hf_stop_measurementid,         { "Measurement ID",        "netperfmeter.stop_measurementid",         FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },

   { &hf_results_data,               { "Data",                  "netperfmeter.results_data",               FT_BYTES,   BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_results_flag_eof,           { "End of File",           "netperfmeter.results_flags.eof",          FT_BOOLEAN, 8, TFS(&tfs_set_notset), NPMRF_EOF, NULL, HFILL } }
};


typedef struct _tap_npm_rec_t {
  guint8      type;
  guint16     size;
  const char* type_string;
} tap_npm_rec_t;


static void
dissect_npm_acknowledge_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  proto_tree_add_item(message_tree, hf_acknowledge_flowid, message_tvb,         4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_acknowledge_measurementid, message_tvb,  8, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_acknowledge_streamid, message_tvb,      16, 2, ENC_BIG_ENDIAN);
  /* proto_tree_add_item(message_tree, acknowledge_padding, message_tvb,       18, 2, ENC_BIG_ENDIAN); */
  proto_tree_add_item(message_tree, hf_acknowledge_status, message_tvb,        20, 4, ENC_BIG_ENDIAN);
}


static void
dissect_npm_add_flow_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_item *flags_item)
{
  guint32      retranstrials;
  proto_item*  onoffitem;
  proto_tree*  onofftree;
  proto_tree*  flags_tree;
  guint16      onoffevents;
  guint32      onoffvalue;
  unsigned int i;

  flags_tree = proto_item_add_subtree(flags_item, ett_addflow_flags);
  proto_tree_add_item(flags_tree, hf_addflow_flag_debug,       message_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_addflow_flag_nodelay,     message_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_addflow_flag_repeatonoff, message_tvb, 1, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(message_tree, hf_addflow_flowid, message_tvb,         4,  4, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_measurementid, message_tvb,  8,  8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_streamid, message_tvb,      16,  2, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_protocol, message_tvb,      18,  1, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_flags, message_tvb,         19,  1, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_description, message_tvb,   20, 32, ENC_UTF_8);

  proto_tree_add_double_format_value(message_tree, hf_addflow_ordered, message_tvb, 52, 4,
                                     100.0 * tvb_get_ntohl(message_tvb, 52) / (double)0xffffffff, "%1.3f%%",
                                     100.0 * tvb_get_ntohl(message_tvb, 52) / (double)0xffffffff);
  proto_tree_add_double_format_value(message_tree, hf_addflow_reliable, message_tvb, 56, 4,
                                     100.0 * tvb_get_ntohl(message_tvb, 56) / (double)0xffffffff, "%1.3f%%",
                                     100.0 * tvb_get_ntohl(message_tvb, 56) / (double)0xffffffff);

  retranstrials = tvb_get_ntohl(message_tvb, 60);
  proto_tree_add_uint_format_value(message_tree, hf_addflow_retranstrials, message_tvb, 60, 4,
                                   retranstrials, (retranstrials & (1U << 31)) ? "%u ms" : "%u trials",
                                   retranstrials &~ (1U << 31));

  proto_tree_add_item(message_tree, hf_addflow_frameraterng,  message_tvb, 128, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_framerate1,    message_tvb,  64, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_framerate2,    message_tvb,  72, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_framerate3,    message_tvb,  80, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_framerate4,    message_tvb,  88, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_framesizerng,  message_tvb, 129, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_framesize1,    message_tvb,  96, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_framesize2,    message_tvb, 104, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_framesize3,    message_tvb, 112, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_framesize4,    message_tvb, 120, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_rcvbuffersize, message_tvb, 130, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_sndbuffersize, message_tvb, 134, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_maxmsgsize,    message_tvb, 138, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_cmt,           message_tvb, 140, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_addflow_ccid,          message_tvb, 141, 1, ENC_BIG_ENDIAN);

  onoffitem = proto_tree_add_item(message_tree, hf_addflow_onoffevents, message_tvb, 142, 2, ENC_BIG_ENDIAN);

  onoffevents = tvb_get_ntohs(message_tvb, 142);
  if (onoffevents > 0) {
     onofftree = proto_item_add_subtree(onoffitem, ett_onoffarray);
    for(i = 0;i < onoffevents;i++) {
      onoffvalue = tvb_get_ntohl(message_tvb, 144 + (int)(sizeof(guint32) * i));
      proto_tree_add_uint_format(onofftree, hf_addflow_onoffeventarray, message_tvb,
                                 144 + (int)(sizeof(guint32) * i), (int)sizeof(guint32),
                                 onoffvalue, "%1.3f s: set to %s", onoffvalue / 1000.0, (i & 1) ? "OFF" : "ON");
    }
  }
}


static void
dissect_npm_remove_flow_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  proto_tree_add_item(message_tree, hf_removeflow_flowid,        message_tvb,  4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_removeflow_measurementid, message_tvb,  8, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_removeflow_streamid,      message_tvb, 16, 2, ENC_BIG_ENDIAN);
}


static void
dissect_npm_identify_flow_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_item *flags_item)
{
  proto_tree* flags_tree;

  flags_tree = proto_item_add_subtree(flags_item, ett_identifyflow_flags);
  proto_tree_add_item(flags_tree, hf_identifyflow_flag_compress_vectors, message_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_identifyflow_flag_no_vectors,       message_tvb, 1, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(message_tree, hf_identifyflow_flowid,        message_tvb,  4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_identifyflow_magicnumber,   message_tvb,  8, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_identifyflow_measurementid, message_tvb, 16, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_identifyflow_streamid,      message_tvb, 24, 2, ENC_BIG_ENDIAN);
}


static void
dissect_npm_data_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_item *flags_item)
{
  proto_tree*   flags_tree;
  const guint16 message_length = tvb_get_ntohs(message_tvb, 2);
  guint64       timestamp;
  nstime_t      t;

  flags_tree = proto_item_add_subtree(flags_item, ett_data_flags);
  proto_tree_add_item(flags_tree, hf_data_flag_frame_begin, message_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_data_flag_frame_end,   message_tvb, 1, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(message_tree, hf_data_flowid,          message_tvb,  4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_data_measurementid,   message_tvb,  8, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_data_streamid,        message_tvb, 16, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_data_padding,         message_tvb, 18, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_data_frameid,         message_tvb, 20, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_data_packetseqnumber, message_tvb, 24, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_data_byteseqnumber,   message_tvb, 32, 8, ENC_BIG_ENDIAN);

  timestamp = tvb_get_ntoh64(message_tvb, 40);
  t.secs  = (time_t)(timestamp / 1000000);
  t.nsecs = (int)((timestamp - 1000000 * t.secs) * 1000);

  proto_tree_add_time(message_tree, hf_data_timestamp, message_tvb, 40, 8, &t);

  if (message_length > 4) {
    proto_tree_add_item(message_tree, hf_data_payload, message_tvb, 48, message_length - 48, ENC_NA);
  }
}


static void
dissect_npm_start_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_item *flags_item)
{
  proto_tree* flags_tree;

  flags_tree = proto_item_add_subtree(flags_item, ett_start_flags);
  proto_tree_add_item(flags_tree, hf_start_flag_compress_vectors, message_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_start_flag_compress_scalars, message_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_start_flag_no_vectors,       message_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_start_flag_no_scalars,       message_tvb, 1, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(message_tree, hf_start_measurementid, message_tvb, 8, 8, ENC_BIG_ENDIAN);
}


static void
dissect_npm_stop_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  proto_tree_add_item(message_tree, hf_stop_measurementid, message_tvb, 8, 8, ENC_BIG_ENDIAN);
}


static void
dissect_npm_results_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_item *flags_item)
{
  proto_tree* flags_tree;

  flags_tree = proto_item_add_subtree(flags_item, ett_data_flags);
  proto_tree_add_item(flags_tree, hf_results_flag_eof, message_tvb, 1, 1, ENC_BIG_ENDIAN);

  const guint16 message_length = tvb_get_ntohs(message_tvb, 2);
  if (message_length > 4) {
    proto_tree_add_item(message_tree, hf_results_data, message_tvb, 4, message_length - 4, ENC_NA);
  }
}


static void
dissect_npm_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *npm_tree)
{
  proto_tree* flags_tree;

  tap_npm_rec_t* tap_rec = wmem_new0(pinfo->pool, tap_npm_rec_t);
  tap_rec->type        = tvb_get_guint8(message_tvb, 0);
  tap_rec->size        = tvb_get_ntohs(message_tvb, 2);
  tap_rec->type_string = val_to_str_const(tap_rec->type, message_type_values, "Unknown NetPerfMeter message type");
  tap_queue_packet(tap_npm, pinfo, tap_rec);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", tap_rec->type_string);

  proto_tree_add_item(npm_tree, hf_message_type,   message_tvb, 0, 1, ENC_BIG_ENDIAN);
  flags_tree = proto_tree_add_item(npm_tree, hf_message_flags,  message_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(npm_tree, hf_message_length, message_tvb, 2, 2, ENC_BIG_ENDIAN);

  switch (tap_rec->type) {
    case NETPERFMETER_ACKNOWLEDGE:
      dissect_npm_acknowledge_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_ADD_FLOW:
      dissect_npm_add_flow_message(message_tvb, npm_tree, flags_tree);
     break;
    case NETPERFMETER_REMOVE_FLOW:
      dissect_npm_remove_flow_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_IDENTIFY_FLOW:
      dissect_npm_identify_flow_message(message_tvb, npm_tree, flags_tree);
     break;
    case NETPERFMETER_DATA:
      dissect_npm_data_message(message_tvb, npm_tree, flags_tree);
     break;
    case NETPERFMETER_START:
      dissect_npm_start_message(message_tvb, npm_tree, flags_tree);
     break;
    case NETPERFMETER_STOP:
      dissect_npm_stop_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_RESULTS:
      dissect_npm_results_message(message_tvb, npm_tree, flags_tree);
     break;
  }
}

static int
dissect_npm(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *npm_item;
  proto_tree *npm_tree;

  col_append_sep_fstr(pinfo->cinfo, COL_PROTOCOL, NULL, "NetPerfMeter");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the npm protocol tree */
    npm_item = proto_tree_add_item(tree, proto_npm, message_tvb, 0, -1, ENC_NA);
    npm_tree = proto_item_add_subtree(npm_item, ett_npm);
  } else {
    npm_tree = NULL;
  };
  /* dissect the message */
  dissect_npm_message(message_tvb, pinfo, npm_tree);
  return TRUE;
}


static int
heur_dissect_npm(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  const guint length = tvb_captured_length(message_tvb);
  if (length < 4)
    return FALSE;

  /* For TCP, UDP or DCCP:
      Type must either be NETPERFMETER_DATA or NETPERFMETER_IDENTIFY_FLOW */
  const guint8 type = tvb_get_guint8(message_tvb, 0);
  switch(type) {
    case NETPERFMETER_DATA:
      if (length < 48 + 8)
        return FALSE;
      /* Identify NetPerfMeter flow by payload pattern */
      for(int i = 0; i < 8; i++) {
        guint8 d = tvb_get_guint8(message_tvb, 48 + i);
        if( (d != 30 + i) && (d != 127 - i) )
          return FALSE;
      }
      break;
    case NETPERFMETER_IDENTIFY_FLOW:
      if (length < 24 + 2)
        return FALSE;
      if (tvb_get_ntoh64(message_tvb, 8) != NETPERFMETER_IDENTIFY_FLOW_MAGIC_NUMBER) {
        /* Identify NetPerfMeter flow by NETPERFMETER_IDENTIFY_FLOW_MAGIC_NUMBER */
        return FALSE;
      }
      break;
    default:
      /* Not a NetPerfMeter packet */
        return FALSE;
      break;
  }

  return dissect_npm(message_tvb, pinfo, tree, data);
}


/* TAP STAT INFO */
typedef enum
{
  MESSAGE_TYPE_COLUMN = 0,
  MESSAGES_COLUMN,
  MESSAGES_SHARE_COLUMN,
  BYTES_COLUMN,
  BYTES_SHARE_COLUMN,
  FIRST_SEEN_COLUMN,
  LAST_SEEN_COLUMN,
  INTERVAL_COLUMN,
  MESSAGE_RATE_COLUMN,
  BYTE_RATE_COLUMN
} npm_stat_columns;

static stat_tap_table_item npm_stat_fields[] = {
  { TABLE_ITEM_STRING, TAP_ALIGN_LEFT,  "NetPerfMeter Message Type", "%-25s" },
  { TABLE_ITEM_UINT,   TAP_ALIGN_RIGHT, "Messages ",            "%u"       },
  { TABLE_ITEM_UINT,   TAP_ALIGN_RIGHT, "Messages Share (%)"  , "%1.3f %%" },
  { TABLE_ITEM_UINT,   TAP_ALIGN_RIGHT, "Bytes (B)",            "%u"       },
  { TABLE_ITEM_UINT,   TAP_ALIGN_RIGHT, "Bytes Share (%) ",     "%1.3f %%" },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "First Seen (s)",       "%1.6f"    },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "Last Seen (s)",        "%1.6f"    },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "Interval (s)",         "%1.6f"    },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "Message Rate (Msg/s)", "%1.2f"    },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "Byte Rate (B/s)",      "%1.2f"    }
};

static void npm_stat_init(stat_tap_table_ui* new_stat)
{
  const char *table_name = "NetPerfMeter Statistics";
  int num_fields = sizeof(npm_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table *table;
  int i = 0;
  stat_tap_table_item_type items[sizeof(npm_stat_fields)/sizeof(stat_tap_table_item)];

  table = stat_tap_find_table(new_stat, table_name);
  if (table) {
    if (new_stat->stat_tap_reset_table_cb) {
      new_stat->stat_tap_reset_table_cb(table);
    }
    return;
  }

  table = stat_tap_init_table(table_name, num_fields, 0, NULL);
  stat_tap_add_table(new_stat, table);

  memset(items, 0x0, sizeof(items));
  /* Add a row for each value type */
  while (message_type_values[i].strptr) {
    items[MESSAGE_TYPE_COLUMN].type                = TABLE_ITEM_STRING;
    items[MESSAGE_TYPE_COLUMN].value.string_value  = message_type_values[i].strptr;
    items[MESSAGES_COLUMN].type                    = TABLE_ITEM_UINT;
    items[MESSAGES_COLUMN].value.uint_value        = 0;
    items[MESSAGES_SHARE_COLUMN].type              = TABLE_ITEM_NONE;
    items[MESSAGES_SHARE_COLUMN].value.float_value = -1.0;
    items[BYTES_COLUMN].type                       = TABLE_ITEM_UINT;
    items[BYTES_COLUMN].value.uint_value           = 0;
    items[BYTES_SHARE_COLUMN].type                 = TABLE_ITEM_NONE;
    items[BYTES_SHARE_COLUMN].value.float_value    = -1.0;
    items[FIRST_SEEN_COLUMN].type                  = TABLE_ITEM_NONE;
    items[FIRST_SEEN_COLUMN].value.float_value     = DBL_MAX;
    items[LAST_SEEN_COLUMN].type                   = TABLE_ITEM_NONE;
    items[LAST_SEEN_COLUMN].value.float_value      = DBL_MIN;
    items[INTERVAL_COLUMN].type                    = TABLE_ITEM_NONE;
    items[INTERVAL_COLUMN].value.float_value       = -1.0;
    items[MESSAGE_RATE_COLUMN].type                = TABLE_ITEM_NONE;
    items[MESSAGE_RATE_COLUMN].value.float_value   = -1.0;
    items[BYTE_RATE_COLUMN].type                   = TABLE_ITEM_NONE;
    items[BYTE_RATE_COLUMN].value.float_value      = -1.0;
    stat_tap_init_table_row(table, i, num_fields, items);
    i++;
  }
}

static tap_packet_status
npm_stat_packet(void* tapdata, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* data, tap_flags_t flags _U_)
{
  stat_data_t*              stat_data = (stat_data_t*)tapdata;
  const tap_npm_rec_t*      tap_rec   = (const tap_npm_rec_t*)data;
  stat_tap_table*           table;
  stat_tap_table_item_type* msg_data;
  gint                      idx;
  guint64                   messages;
  guint64                   bytes;
  int                       i         = 0;
  double                    firstSeen = -1.0;
  double                    lastSeen  = -1.0;

  idx = str_to_val_idx(tap_rec->type_string, message_type_values);
  if (idx < 0)
    return TAP_PACKET_DONT_REDRAW;

  table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);

  /* Update packets counter */
  npm_total_msgs++;
  msg_data = stat_tap_get_field_data(table, idx, MESSAGES_COLUMN);
  msg_data->value.uint_value++;
  messages = msg_data->value.uint_value;
  stat_tap_set_field_data(table, idx, MESSAGES_COLUMN, msg_data);

  /* Update bytes counter */
  npm_total_bytes += tap_rec->size;
  msg_data = stat_tap_get_field_data(table, idx, BYTES_COLUMN);
  msg_data->value.uint_value += tap_rec->size;
  bytes = msg_data->value.uint_value;
  stat_tap_set_field_data(table, idx, BYTES_COLUMN, msg_data);

  /* Update messages and bytes share */
  while (message_type_values[i].strptr) {
    msg_data = stat_tap_get_field_data(table, i, MESSAGES_COLUMN);
    const guint m = msg_data->value.uint_value;
    msg_data = stat_tap_get_field_data(table, i, BYTES_COLUMN);
    const guint b = msg_data->value.uint_value;

    msg_data = stat_tap_get_field_data(table, i, MESSAGES_SHARE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = 100.0 * m / (double)npm_total_msgs;
    stat_tap_set_field_data(table, i, MESSAGES_SHARE_COLUMN, msg_data);

    msg_data = stat_tap_get_field_data(table, i, BYTES_SHARE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = 100.0 * b / (double)npm_total_bytes;
    stat_tap_set_field_data(table, i, BYTES_SHARE_COLUMN, msg_data);
    i++;
  }

  /* Update first seen time */
  if (pinfo->presence_flags & PINFO_HAS_TS) {
    msg_data = stat_tap_get_field_data(table, idx, FIRST_SEEN_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = MIN(msg_data->value.float_value, nstime_to_sec(&pinfo->rel_ts));
    firstSeen = msg_data->value.float_value;
    stat_tap_set_field_data(table, idx, FIRST_SEEN_COLUMN, msg_data);
  }

  /* Update last seen time */
  if (pinfo->presence_flags & PINFO_HAS_TS) {
    msg_data = stat_tap_get_field_data(table, idx, LAST_SEEN_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = MAX(msg_data->value.float_value, nstime_to_sec(&pinfo->rel_ts));
    lastSeen = msg_data->value.float_value;
    stat_tap_set_field_data(table, idx, LAST_SEEN_COLUMN, msg_data);
  }

  if ((lastSeen - firstSeen) > 0.0) {
    /* Update interval */
    msg_data = stat_tap_get_field_data(table, idx, INTERVAL_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = lastSeen - firstSeen;
    stat_tap_set_field_data(table, idx, INTERVAL_COLUMN, msg_data);

    /* Update message rate */
    msg_data = stat_tap_get_field_data(table, idx, MESSAGE_RATE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = messages / (lastSeen - firstSeen);
    stat_tap_set_field_data(table, idx, MESSAGE_RATE_COLUMN, msg_data);

    /* Update byte rate */
    msg_data = stat_tap_get_field_data(table, idx, BYTE_RATE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = bytes / (lastSeen - firstSeen);
    stat_tap_set_field_data(table, idx, BYTE_RATE_COLUMN, msg_data);
  }

  return TAP_PACKET_REDRAW;
}

static void
npm_stat_reset(stat_tap_table* table)
{
  guint element;
  stat_tap_table_item_type* item_data;

  for (element = 0; element < table->num_elements; element++) {
    item_data = stat_tap_get_field_data(table, element, MESSAGES_COLUMN);
    item_data->value.uint_value = 0;
    stat_tap_set_field_data(table, element, MESSAGES_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, MESSAGES_SHARE_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, MESSAGES_SHARE_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, BYTES_COLUMN);
    item_data->value.uint_value = 0;
    stat_tap_set_field_data(table, element, BYTES_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, BYTES_SHARE_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, BYTES_SHARE_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, FIRST_SEEN_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = DBL_MAX;
    stat_tap_set_field_data(table, element, FIRST_SEEN_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, LAST_SEEN_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = DBL_MIN;
    stat_tap_set_field_data(table, element, LAST_SEEN_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, INTERVAL_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, INTERVAL_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, MESSAGE_RATE_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, MESSAGE_RATE_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, BYTE_RATE_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, BYTE_RATE_COLUMN, item_data);
  }
  npm_total_msgs  = 0;
  npm_total_bytes = 0;
}


/* Register the protocol with Wireshark */
void
proto_register_npm(void)
{
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_npm,
    &ett_addflow_flags,
    &ett_identifyflow_flags,
    &ett_start_flags,
    &ett_data_flags,
    &ett_results_flags,
    &ett_onoffarray
  };

  static tap_param npm_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui npm_stat_table = {
    REGISTER_PACKET_STAT_GROUP_UNSORTED,
    "NetPerfMeter Statistics",
    "npm",
    "npm,stat",
    npm_stat_init,
    npm_stat_packet,
    npm_stat_reset,
    NULL,
    NULL,
    sizeof(npm_stat_fields)/sizeof(stat_tap_table_item), npm_stat_fields,
    sizeof(npm_stat_params)/sizeof(tap_param), npm_stat_params,
    NULL,
    0
  };

  /* Register the protocol name and description */
  proto_npm = proto_register_protocol("NetPerfMeter Protocol", "NetPerfMeter", "netperfmeter");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_npm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  tap_npm = register_tap("npm");

  register_stat_tap_table_ui(&npm_stat_table);
}


void
proto_reg_handoff_npm(void)
{
  dissector_handle_t npm_handle;

  /* NetPerfMeter protocol over SCTP is detected by PPIDs */
  npm_handle = create_dissector_handle(dissect_npm, proto_npm);
  dissector_add_uint("sctp.ppi", PPID_NETPERFMETER_CONTROL_LEGACY, npm_handle);
  dissector_add_uint("sctp.ppi", PPID_NETPERFMETER_DATA_LEGACY,    npm_handle);
  dissector_add_uint("sctp.ppi", NPMP_CTRL_PAYLOAD_PROTOCOL_ID,    npm_handle);
  dissector_add_uint("sctp.ppi", NPMP_DATA_PAYLOAD_PROTOCOL_ID,    npm_handle);

  /* Heuristic dissector for TCP, UDP and DCCP */
  heur_dissector_add("tcp",  heur_dissect_npm, "NetPerfMeter over TCP",  "netperfmeter_tcp",  proto_npm, HEURISTIC_ENABLE);
  heur_dissector_add("udp",  heur_dissect_npm, "NetPerfMeter over UDP",  "netperfmeter_udp",  proto_npm, HEURISTIC_ENABLE);
  heur_dissector_add("dccp", heur_dissect_npm, "NetPerfMeter over DCCP", "netperfmeter_dccp", proto_npm, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
