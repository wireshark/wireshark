/* packet-netperfmeter.c
 * Routines for the NetPerfMeter protocol used by the Open Source
 * network performance meter application NetPerfMeter:
 * http://www.exp-math.uni-essen.de/~dreibh/netperfmeter/
 *
 * Copyright 2009 by Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
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

void proto_register_npm(void);
void proto_reg_handoff_npm(void);

static int  proto_npm       = -1;
static gint ett_npm         = -1;
static gint ett_onoffarray  = -1;


#define PPID_NETPERFMETER_CONTROL_LEGACY   0x29097605
#define PPID_NETPERFMETER_DATA_LEGACY      0x29097606


/* Initialize the protocol and registered fields */
#define INIT_FIELD(variable, offset, length) \
   static int hf_##variable           = -1;        \
   static const unsigned int offset_##variable = offset;    \
   static const int length_##variable = length;

#define INIT_FIELD_WITHOUT_LEN(variable, offset) \
   static int hf_##variable           = -1;        \
   static const unsigned int offset_##variable = offset;

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

INIT_FIELD(message_type,   0, 1)
INIT_FIELD(message_flags,  1, 1)
INIT_FIELD(message_length, 2, 2)

INIT_FIELD(acknowledge_flowid,          4,  4)
INIT_FIELD(acknowledge_measurementid,   8,  8)
INIT_FIELD(acknowledge_streamid,       16,  2)
/* INIT_FIELD(acknowledge_padding,        18,  2) */
INIT_FIELD(acknowledge_status,         20,  4)

INIT_FIELD(addflow_flowid,              4,  4)
INIT_FIELD(addflow_measurementid,       8,  8)
INIT_FIELD(addflow_streamid,           16,  2)
INIT_FIELD(addflow_protocol,           18,  1)
INIT_FIELD(addflow_flags,              19,  1)
INIT_FIELD(addflow_description,        20, 32)
INIT_FIELD(addflow_ordered,            52,  4)
INIT_FIELD(addflow_reliable,           56,  4)
INIT_FIELD(addflow_retranstrials,      60,  4)
INIT_FIELD(addflow_framerate1,         64,  8)
INIT_FIELD(addflow_framerate2,         72,  8)
INIT_FIELD(addflow_framerate3,         80,  8)
INIT_FIELD(addflow_framerate4,         88,  8)
INIT_FIELD(addflow_framesize1,         96,  8)
INIT_FIELD(addflow_framesize2,        104,  8)
INIT_FIELD(addflow_framesize3,        112,  8)
INIT_FIELD(addflow_framesize4,        120,  8)
INIT_FIELD(addflow_frameraterng,      128,  1)
INIT_FIELD(addflow_framesizerng,      129,  1)
INIT_FIELD(addflow_rcvbuffersize,     130,  4)
INIT_FIELD(addflow_sndbuffersize,     134,  4)
INIT_FIELD(addflow_maxmsgsize,        138,  2)
INIT_FIELD(addflow_cmt,               140,  1)
INIT_FIELD(addflow_ccid,              141,  1)
INIT_FIELD(addflow_onoffevents,       142,  2)
INIT_FIELD_WITHOUT_LEN(addflow_onoffeventarray,   144)

INIT_FIELD(removeflow_flowid,           4,  4)
INIT_FIELD(removeflow_measurementid,    8,  8)
INIT_FIELD(removeflow_streamid,        16,  2)

INIT_FIELD(identifyflow_flowid,         4,  4)
INIT_FIELD(identifyflow_magicnumber,    8,  8)
INIT_FIELD(identifyflow_measurementid, 16,  8)
INIT_FIELD(identifyflow_streamid,      24,  2)

#define NETPERFMETER_IDENTIFY_FLOW_MAGIC_NUMBER 0x4bcdf3aa303c6774ULL

INIT_FIELD(data_flowid,           4,  4)
INIT_FIELD(data_measurementid,    8,  8)
INIT_FIELD(data_streamid,        16,  2)
INIT_FIELD(data_padding,         18,  2)
INIT_FIELD(data_frameid,         20,  4)
INIT_FIELD(data_packetseqnumber, 24,  8)
INIT_FIELD(data_byteseqnumber,   32,  8)
INIT_FIELD(data_timestamp,       40,  8)
INIT_FIELD_WITHOUT_LEN(data_payload,         48)

/* INIT_FIELD(start_padding,         4,  4) */
INIT_FIELD(start_measurementid,   8,  8)

/* INIT_FIELD(stop_padding,          4,  4) */
INIT_FIELD(stop_measurementid,    8,  8)

INIT_FIELD_WITHOUT_LEN(results_data,          4)


/* Setup list of Transport Layer protocol types */
static const value_string proto_type_values[] = {
  { 6,              "TCP" },
  { 8,              "MPTCP" },
  { 17,             "UDP" },
  { 33,             "DCCP" },
  { 132,            "SCTP" },
  { 0,              NULL }
};

/* Setup list of CMT values */
static const value_string cmt_values[] = {
  { 0,              "Off" },
  { 1,              "CMT" },
  { 2,              "CMT/RPv1" },
  { 3,              "CMT/RPv2" },
  { 4,              "MPTCP-Like" },
  { 0,              NULL }
};

/* Setup list of random number generator types */
static const value_string rng_type_values[] = {
  { 0,              "Constant" },
  { 1,              "Uniform" },
  { 2,              "Neg. Exponential" },
  { 0,              NULL }
};

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

   { &hf_removeflow_flowid,          { "Flow ID",               "netperfmeter.removeflow_flowid",          FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_removeflow_measurementid,   { "Measurement ID",        "netperfmeter.removeflow_measurementid",   FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_removeflow_streamid,        { "Stream ID",             "netperfmeter.removeflow_streamid",        FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_identifyflow_flowid,        { "Flow ID",               "netperfmeter.identifyflow_flowid",        FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_magicnumber,   { "Magic Number",          "netperfmeter.identifyflow_magicnumber",   FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_measurementid, { "Measurement ID",        "netperfmeter.identifyflow_measurementid", FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_streamid,      { "Stream ID",             "netperfmeter.identifyflow_streamid",      FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_data_flowid,                { "Flow ID",               "netperfmeter.data_flowid",                FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_measurementid,         { "Measurement ID",        "netperfmeter.data_measurementid",         FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_streamid,              { "Stream ID",             "netperfmeter.data_streamid",              FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_padding,               { "Padding",               "netperfmeter.data_padding",               FT_UINT16,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_frameid,               { "Frame ID",              "netperfmeter.data_frameid",               FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_packetseqnumber,       { "Packet Seq Number",     "netperfmeter.data_packetseqnumber",       FT_UINT64,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_byteseqnumber,         { "Byte Seq Number",       "netperfmeter.data_byteseqnumber",         FT_UINT64,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_timestamp,             { "Time Stamp",            "netperfmeter.data_timestamp",             FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,        0x0, NULL, HFILL } },
   { &hf_data_payload,               { "Payload",               "netperfmeter.data_payload",               FT_BYTES,   BASE_NONE, NULL,                      0x0, NULL, HFILL } },

#if 0
   { &hf_start_padding,              { "Padding",               "netperfmeter.start_padding",              FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
#endif
   { &hf_start_measurementid,        { "Measurement ID",        "netperfmeter.start_measurementid",        FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },

#if 0
   { &hf_stop_padding,               { "Padding",               "netperfmeter.stop_padding",               FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
#endif
   { &hf_stop_measurementid,         { "Measurement ID",        "netperfmeter.stop_measurementid",         FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },

   { &hf_results_data,               { "Data",                  "netperfmeter.results_data",               FT_BYTES,   BASE_NONE, NULL,                      0x0, NULL, HFILL } },
};


#define ADD_FIELD_UINT(tree, field) proto_tree_add_item(tree, hf_##field, message_tvb, offset_##field, length_##field, ENC_BIG_ENDIAN)
#define ADD_FIELD_STRING(tree, field) proto_tree_add_item(tree, hf_##field, message_tvb, offset_##field, length_##field, ENC_ASCII|ENC_NA)


static void
dissect_npm_acknowledge_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD_UINT(message_tree, acknowledge_flowid);
  ADD_FIELD_UINT(message_tree, acknowledge_measurementid);
  ADD_FIELD_UINT(message_tree, acknowledge_streamid);
  ADD_FIELD_UINT(message_tree, acknowledge_status);
}


static void
dissect_npm_add_flow_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  guint32      retranstrials;
  proto_item*  onoffitem;
  proto_tree*  onofftree;
  guint16      onoffevents;
  guint32      onoffvalue;
  unsigned int i;

  ADD_FIELD_UINT(message_tree, addflow_flowid);
  ADD_FIELD_UINT(message_tree, addflow_measurementid);
  ADD_FIELD_UINT(message_tree, addflow_streamid);
  ADD_FIELD_UINT(message_tree, addflow_protocol);
  ADD_FIELD_UINT(message_tree, addflow_flags);
  ADD_FIELD_STRING(message_tree, addflow_description);

  proto_tree_add_double_format_value(message_tree, hf_addflow_ordered, message_tvb, offset_addflow_ordered, length_addflow_ordered,
                                     100.0 * tvb_get_ntohl(message_tvb, offset_addflow_ordered) / (double)0xffffffff, "%1.3f%%",
                                     100.0 * tvb_get_ntohl(message_tvb, offset_addflow_ordered) / (double)0xffffffff);
  proto_tree_add_double_format_value(message_tree, hf_addflow_reliable, message_tvb, offset_addflow_reliable, length_addflow_reliable,
                                     100.0 * tvb_get_ntohl(message_tvb, offset_addflow_reliable) / (double)0xffffffff, "%1.3f%%",
                                     100.0 * tvb_get_ntohl(message_tvb, offset_addflow_reliable) / (double)0xffffffff);

  retranstrials = tvb_get_ntohl(message_tvb, offset_addflow_retranstrials);
  proto_tree_add_uint_format_value(message_tree, hf_addflow_retranstrials, message_tvb, offset_addflow_retranstrials, length_addflow_retranstrials,
                                   retranstrials, (retranstrials & (1U << 31)) ? "%u ms" : "%u trials",
                                   retranstrials &~ (1U << 31));

  ADD_FIELD_UINT(message_tree, addflow_frameraterng);
  ADD_FIELD_UINT(message_tree, addflow_framerate1);
  ADD_FIELD_UINT(message_tree, addflow_framerate2);
  ADD_FIELD_UINT(message_tree, addflow_framerate3);
  ADD_FIELD_UINT(message_tree, addflow_framerate4);
  ADD_FIELD_UINT(message_tree, addflow_framesizerng);
  ADD_FIELD_UINT(message_tree, addflow_framesize1);
  ADD_FIELD_UINT(message_tree, addflow_framesize2);
  ADD_FIELD_UINT(message_tree, addflow_framesize3);
  ADD_FIELD_UINT(message_tree, addflow_framesize4);
  ADD_FIELD_UINT(message_tree, addflow_rcvbuffersize);
  ADD_FIELD_UINT(message_tree, addflow_sndbuffersize);
  ADD_FIELD_UINT(message_tree, addflow_maxmsgsize);
  ADD_FIELD_UINT(message_tree, addflow_cmt);
  ADD_FIELD_UINT(message_tree, addflow_ccid);

  onoffitem = ADD_FIELD_UINT(message_tree, addflow_onoffevents);

  onoffevents = tvb_get_ntohs(message_tvb, offset_addflow_onoffevents);
  if (onoffevents > 0) {
     onofftree = proto_item_add_subtree(onoffitem, ett_onoffarray);
    for(i = 0;i < onoffevents;i++) {
      onoffvalue = tvb_get_ntohl(message_tvb, offset_addflow_onoffeventarray + (int)(sizeof(guint32) * i));
      proto_tree_add_uint_format(onofftree, hf_addflow_onoffeventarray, message_tvb,
                                 offset_addflow_onoffeventarray + (int)(sizeof(guint32) * i), (int)sizeof(guint32),
                                 onoffvalue, "%1.3f s: set to %s", onoffvalue / 1000.0, (i & 1) ? "OFF" : "ON");
    }
  }
}


static void
dissect_npm_remove_flow_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD_UINT(message_tree, removeflow_flowid);
  ADD_FIELD_UINT(message_tree, removeflow_measurementid);
  ADD_FIELD_UINT(message_tree, removeflow_streamid);
}


static void
dissect_npm_identify_flow_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD_UINT(message_tree, identifyflow_magicnumber);
  ADD_FIELD_UINT(message_tree, identifyflow_flowid);
  ADD_FIELD_UINT(message_tree, identifyflow_measurementid);
  ADD_FIELD_UINT(message_tree, identifyflow_streamid);
}


static void
dissect_npm_data_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  const guint16 message_length = tvb_get_ntohs(message_tvb, offset_message_length);
  guint64       timestamp;
  nstime_t      t;

  ADD_FIELD_UINT(message_tree, data_flowid);
  ADD_FIELD_UINT(message_tree, data_measurementid);
  ADD_FIELD_UINT(message_tree, data_streamid);
  ADD_FIELD_UINT(message_tree, data_padding);
  ADD_FIELD_UINT(message_tree, data_frameid);
  ADD_FIELD_UINT(message_tree, data_packetseqnumber);
  ADD_FIELD_UINT(message_tree, data_byteseqnumber);

  timestamp = tvb_get_ntoh64(message_tvb, offset_data_timestamp);
  t.secs  = (time_t)(timestamp / 1000000);
  t.nsecs = (int)((timestamp - 1000000 * t.secs) * 1000);

  proto_tree_add_time(message_tree, hf_data_timestamp, message_tvb, offset_data_timestamp, length_data_timestamp, &t);

  if (message_length > offset_data_payload) {
    proto_tree_add_item(message_tree, hf_data_payload, message_tvb, offset_data_payload, message_length - offset_data_payload, ENC_NA);
  }
}


static void
dissect_npm_start_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD_UINT(message_tree, start_measurementid);
}


static void
dissect_npm_stop_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD_UINT(message_tree, stop_measurementid);
}


static void
dissect_npm_results_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  const guint16 message_length = tvb_get_ntohs(message_tvb, offset_message_length);
  if (message_length > offset_results_data) {
    proto_tree_add_item(message_tree, hf_results_data, message_tvb, offset_results_data, message_length - offset_results_data, ENC_NA);
  }
}


static void
dissect_npm_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *npm_tree)
{
  guint8 type;

  type = tvb_get_guint8(message_tvb, offset_message_type);
  col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_const(type, message_type_values, "Unknown NetPerfMeter message type"));

  ADD_FIELD_UINT(npm_tree, message_type);
  ADD_FIELD_UINT(npm_tree, message_flags);
  ADD_FIELD_UINT(npm_tree, message_length);

  switch (type) {
    case NETPERFMETER_ACKNOWLEDGE:
      dissect_npm_acknowledge_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_ADD_FLOW:
      dissect_npm_add_flow_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_REMOVE_FLOW:
      dissect_npm_remove_flow_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_IDENTIFY_FLOW:
      dissect_npm_identify_flow_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_DATA:
      dissect_npm_data_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_START:
      dissect_npm_start_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_STOP:
      dissect_npm_stop_message(message_tvb, npm_tree);
     break;
    case NETPERFMETER_RESULTS:
      dissect_npm_results_message(message_tvb, npm_tree);
     break;
  }
}


static int
dissect_npm(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *npm_item;
  proto_tree *npm_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetPerfMeter");

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
  const guint8 type = tvb_get_guint8(message_tvb, offset_message_type);
  switch(type) {
    case NETPERFMETER_DATA:
      if (length < offset_data_payload + 8)
        return FALSE;
      /* Identify NetPerfMeter flow by payload pattern */
      for(int i = 0; i < 8; i++) {
        guint8 d = tvb_get_guint8(message_tvb, offset_data_payload + i);
        if( (d != 30 + i) && (d != 127 - i) )
          return FALSE;
      }
      break;
    case NETPERFMETER_IDENTIFY_FLOW:
      if (length < offset_identifyflow_streamid + length_identifyflow_streamid)
        return FALSE;
      if (tvb_get_ntoh64(message_tvb, offset_identifyflow_magicnumber) != NETPERFMETER_IDENTIFY_FLOW_MAGIC_NUMBER) {
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


/* Register the protocol with Wireshark */
void
proto_register_npm(void)
{
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_npm,
    &ett_onoffarray
  };

  /* Register the protocol name and description */
  proto_npm = proto_register_protocol("NetPerfMeter Protocol", "NetPerfMeter", "netperfmeter");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_npm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
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
