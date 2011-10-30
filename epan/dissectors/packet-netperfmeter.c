/* packet-netperfmeter.c
 * Routines for the NetPerfMeter Protocol used by the Open Source
 * network performance meter application NetPerfMeter:
 * http://www.exp-math.uni-essen.de/~dreibh/netperfmeter/
 *
 * Copyright 2009 by Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/sctpppids.h>


static int  proto_npmp      = -1;
static gint ett_npmp        = -1;
static gint ett_onoffarray  = -1;


#define PPID_NETPERFMETER_CONTROL_LEGACY   0x29097605
#define PPID_NETPERFMETER_DATA_LEGACY      0x29097606


/* Initialize the protocol and registered fields */
#define INIT_FIELD(variable, offset, length) \
   static int hf_##variable           = -1;        \
   static const int offset_##variable = offset;    \
   static const int length_##variable = length;

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
INIT_FIELD(acknowledge_padding,        18,  2)
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
INIT_FIELD(addflow_onoffeventarray,   144,  4)

INIT_FIELD(removeflow_flowid,           4,  4)
INIT_FIELD(removeflow_measurementid,    8,  8)
INIT_FIELD(removeflow_streamid,        16,  2)

INIT_FIELD(identifyflow_flowid,         4,  4)
INIT_FIELD(identifyflow_magicnumber,    8,  8)
INIT_FIELD(identifyflow_measurementid, 16,  8)
INIT_FIELD(identifyflow_streamid,      24,  2)

INIT_FIELD(data_flowid,           4,  4)
INIT_FIELD(data_measurementid,    8,  8)
INIT_FIELD(data_streamid,        16,  2)
INIT_FIELD(data_padding,         18,  2)
INIT_FIELD(data_frameid,         20,  4)
INIT_FIELD(data_packetseqnumber, 24,  8)
INIT_FIELD(data_byteseqnumber,   32,  8)
INIT_FIELD(data_timestamp,       40,  8)
INIT_FIELD(data_payload,         48,  0)

INIT_FIELD(start_padding,         4,  4)
INIT_FIELD(start_measurementid,   8,  8)

INIT_FIELD(stop_padding,          4,  4)
INIT_FIELD(stop_measurementid,    8,  8)

INIT_FIELD(results_data,          4,  0)


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
   { &hf_message_type,               { "Type",                  "npmp.message_type",               FT_UINT8,   BASE_DEC,  VALS(message_type_values), 0x0, NULL, HFILL } },
   { &hf_message_flags,              { "Flags",                 "npmp.message_flags",              FT_UINT8,   BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_message_length,             { "Length",                "npmp.message_length",             FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_acknowledge_flowid,         { "Flow ID",               "npmp.acknowledge_flowid",         FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_acknowledge_measurementid,  { "Measurement ID",        "npmp.acknowledge_measurementid",  FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_acknowledge_streamid,       { "Stream ID",             "npmp.acknowledge_streamid",       FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_acknowledge_padding,        { "Padding",               "npmp.acknowledge_padding",        FT_UINT16,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_acknowledge_status,         { "Status",                "npmp.acknowledge_status",         FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_addflow_flowid,             { "Flow ID",               "npmp.addflow_flowid",             FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_measurementid,      { "Measurement ID",        "npmp.addflow_measurementid",      FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_streamid,           { "Stream ID",             "npmp.addflow_streamid",           FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_protocol,           { "Protocol",              "npmp.addflow_protocol",           FT_UINT8,   BASE_DEC,  VALS(proto_type_values),   0x0, NULL, HFILL } },
   { &hf_addflow_flags,              { "Flags",                 "npmp.addflow_flags",              FT_UINT8,   BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_description,        { "Description",           "npmp.addflow_description",        FT_STRING,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_ordered,            { "Ordered",               "npmp.addflow_ordered",            FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_reliable,           { "Reliable",              "npmp.addflow_reliable",           FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_retranstrials,      { "Retransmission Trials", "npmp.addflow_retranstrials",      FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_frameraterng,       { "Frame Rate RNG",        "npmp.addflow_frameraterng",       FT_UINT8,   BASE_DEC,  VALS(rng_type_values),     0x0, NULL, HFILL } },
   { &hf_addflow_framerate1,         { "Frame Rate 1",          "npmp.addflow_framerate1",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framerate2,         { "Frame Rate 2",          "npmp.addflow_framerate2",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framerate3,         { "Frame Rate 3",          "npmp.addflow_framerate3",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framerate4,         { "Frame Rate 4",          "npmp.addflow_framerate4",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framesizerng,       { "Frame Size RNG",        "npmp.addflow_framesizerng",       FT_UINT8,   BASE_DEC,  VALS(rng_type_values),     0x0, NULL, HFILL } },
   { &hf_addflow_framesize1,         { "Frame Size 1",          "npmp.addflow_framesize1",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framesize2,         { "Frame Size 2",          "npmp.addflow_framesize2",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framesize3,         { "Frame Size 3",          "npmp.addflow_framesize3",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_framesize4,         { "Frame Size 4",          "npmp.addflow_framesize4",         FT_DOUBLE,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_rcvbuffersize,      { "Receive Buffer Size",   "npmp.addflow_rcvbuffersize",      FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_sndbuffersize,      { "Send Buffer Size",      "npmp.addflow_sndbuffersize",      FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_maxmsgsize,         { "Max. Message Size",     "npmp.addflow_maxmsgsize",         FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_cmt,                { "CMT",                   "npmp.addflow_cmt",                FT_UINT8,   BASE_HEX,  VALS(cmt_values),          0x0, NULL, HFILL } },
   { &hf_addflow_ccid,               { "CCID",                  "npmp.addflow_ccid",               FT_UINT8,   BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_onoffevents,        { "On/Off Events",         "npmp.addflow_onoffevents",        FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_addflow_onoffeventarray,    { "On/Off Event",          "npmp.addflow_onoffeventarray",    FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_removeflow_flowid,          { "Flow ID",               "npmp.removeflow_flowid",          FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_removeflow_measurementid,   { "Measurement ID",        "npmp.removeflow_measurementid",   FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_removeflow_streamid,        { "Stream ID",             "npmp.removeflow_streamid",        FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_identifyflow_flowid,        { "Flow ID",               "npmp.identifyflow_flowid",        FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_magicnumber,   { "Magic Number",          "npmp.identifyflow_magicnumber",   FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_measurementid, { "Measurement ID",        "npmp.identifyflow_measurementid", FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_identifyflow_streamid,      { "Stream ID",             "npmp.identifyflow_streamid",      FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },

   { &hf_data_flowid,                { "Flow ID",               "npmp.data_flowid",                FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_measurementid,         { "Measurement ID",        "npmp.data_measurementid",         FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_streamid,              { "Stream ID",             "npmp.data_streamid",              FT_UINT16,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_padding,               { "Padding",               "npmp.data_padding",               FT_UINT16,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_frameid,               { "Frame ID",              "npmp.data_frameid",               FT_UINT32,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_packetseqnumber,       { "Packet Seq Number",     "npmp.data_packetseqnumber",       FT_UINT64,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_byteseqnumber,         { "Byte Seq Number",       "npmp.data_byteseqnumber",         FT_UINT64,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_timestamp,             { "Time Stamp",            "npmp.data_timestamp",             FT_UINT64,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
   { &hf_data_payload,               { "Payload",               "npmp.data_payload",               FT_BYTES,   BASE_NONE, NULL,                      0x0, NULL, HFILL } },

   { &hf_start_padding,              { "Padding",               "npmp.start_padding",              FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_start_measurementid,        { "Measurement ID",        "npmp.start_measurementid",        FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },

   { &hf_stop_padding,               { "Padding",               "npmp.stop_padding",               FT_UINT32,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },
   { &hf_stop_measurementid,         { "Measurement ID",        "npmp.stop_measurementid",         FT_UINT64,  BASE_HEX,  NULL,                      0x0, NULL, HFILL } },

   { &hf_results_data,               { "Data",                  "npmp.results_data",               FT_BYTES,   BASE_NONE, NULL,                      0x0, NULL, HFILL } },
};


#define ADD_FIELD(tree, field) proto_tree_add_item(tree, hf_##field, message_tvb, offset_##field, length_##field, FALSE)


static void
dissect_npmp_acknowledge_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD(message_tree, acknowledge_flowid);
  ADD_FIELD(message_tree, acknowledge_measurementid);
  ADD_FIELD(message_tree, acknowledge_streamid);
  ADD_FIELD(message_tree, acknowledge_status);
}


static void
dissect_npmp_add_flow_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  guint32      retranstrials;
  proto_item*  onoffitem;
  proto_tree*  onofftree;
  guint16      onoffevents;
  guint32      onoffvalue;
  unsigned int i;

  ADD_FIELD(message_tree, addflow_flowid);
  ADD_FIELD(message_tree, addflow_measurementid);
  ADD_FIELD(message_tree, addflow_streamid);
  ADD_FIELD(message_tree, addflow_protocol);
  ADD_FIELD(message_tree, addflow_flags);
  ADD_FIELD(message_tree, addflow_description);

  proto_tree_add_double_format_value(message_tree, hf_addflow_ordered, message_tvb, offset_addflow_ordered, length_addflow_ordered,
                                     100.0 * tvb_get_ntohl(message_tvb, offset_addflow_ordered) / (double)0xffffffff, "%1.3f%%",
                                     100.0 * tvb_get_ntohl(message_tvb, offset_addflow_ordered) / (double)0xffffffff);
  proto_tree_add_double_format_value(message_tree, hf_addflow_reliable, message_tvb, offset_addflow_reliable, length_addflow_reliable,
                                     100.0 * tvb_get_ntohl(message_tvb, offset_addflow_reliable) / (double)0xffffffff, "%1.3f%%",
                                     100.0 * tvb_get_ntohl(message_tvb, offset_addflow_reliable) / (double)0xffffffff);

  retranstrials = tvb_get_ntohl(message_tvb, offset_addflow_retranstrials);
  proto_tree_add_uint_format_value(message_tree, hf_addflow_retranstrials, message_tvb, offset_addflow_retranstrials, length_addflow_retranstrials,
                                   retranstrials, (retranstrials & (1 << 31)) ? "%u ms" : "%u trials",
                                   retranstrials &~ (1 << 31));

  ADD_FIELD(message_tree, addflow_frameraterng);
  ADD_FIELD(message_tree, addflow_framerate1);
  ADD_FIELD(message_tree, addflow_framerate2);
  ADD_FIELD(message_tree, addflow_framerate3);
  ADD_FIELD(message_tree, addflow_framerate4);
  ADD_FIELD(message_tree, addflow_framesizerng);
  ADD_FIELD(message_tree, addflow_framesize1);
  ADD_FIELD(message_tree, addflow_framesize2);
  ADD_FIELD(message_tree, addflow_framesize3);
  ADD_FIELD(message_tree, addflow_framesize4);
  ADD_FIELD(message_tree, addflow_rcvbuffersize);
  ADD_FIELD(message_tree, addflow_sndbuffersize);
  ADD_FIELD(message_tree, addflow_maxmsgsize);
  ADD_FIELD(message_tree, addflow_cmt);
  ADD_FIELD(message_tree, addflow_ccid);

  onoffitem = ADD_FIELD(message_tree, addflow_onoffevents);

  onoffevents = tvb_get_ntohs(message_tvb, offset_addflow_onoffevents);
  if (onoffevents > 0) {
     onofftree = proto_item_add_subtree(onoffitem, ett_onoffarray);
    for(i = 0;i < onoffevents;i++) {
      onoffvalue = tvb_get_ntohl(message_tvb, offset_addflow_onoffeventarray + (sizeof(guint32) * i));
      proto_tree_add_uint_format(onofftree, hf_addflow_onoffeventarray, message_tvb,
                                 offset_addflow_onoffeventarray + (sizeof(guint32) * i), sizeof(guint32),
                                 onoffvalue, "%1.3f s: set to %s", onoffvalue / 1000.0, (i & 1) ? "OFF" : "ON");
    }
  }
}


static void
dissect_npmp_remove_flow_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD(message_tree, removeflow_flowid);
  ADD_FIELD(message_tree, removeflow_measurementid);
  ADD_FIELD(message_tree, removeflow_streamid);
}


static void
dissect_npmp_identify_flow_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD(message_tree, identifyflow_magicnumber);
  ADD_FIELD(message_tree, identifyflow_flowid);
  ADD_FIELD(message_tree, identifyflow_measurementid);
  ADD_FIELD(message_tree, identifyflow_streamid);
}


static void
dissect_npmp_data_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  const guint16 message_length = tvb_get_ntohs(message_tvb, offset_message_length);

  ADD_FIELD(message_tree, data_flowid);
  ADD_FIELD(message_tree, data_measurementid);
  ADD_FIELD(message_tree, data_streamid);
  ADD_FIELD(message_tree, data_padding);
  ADD_FIELD(message_tree, data_frameid);
  ADD_FIELD(message_tree, data_packetseqnumber);
  ADD_FIELD(message_tree, data_byteseqnumber);
  ADD_FIELD(message_tree, data_timestamp);
  if (message_length > offset_data_payload) {
    proto_tree_add_item(message_tree, hf_data_payload, message_tvb, offset_data_payload, message_length - offset_data_payload, ENC_NA);
  }
}


static void
dissect_npmp_start_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD(message_tree, start_measurementid);
}


static void
dissect_npmp_stop_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  ADD_FIELD(message_tree, stop_measurementid);
}


static void
dissect_npmp_results_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  const guint16 message_length = tvb_get_guint8(message_tvb, offset_message_length);
  if (message_length > offset_results_data) {
    proto_tree_add_item(message_tree, hf_results_data, message_tvb, offset_results_data, message_length - offset_results_data, ENC_NA);
  }
}


static void
dissect_npmp_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *npmp_tree)
{
  guint8 type;

  type = tvb_get_guint8(message_tvb, offset_message_type);
  if (pinfo && (check_col(pinfo->cinfo, COL_INFO))) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, message_type_values, "Unknown NetPerfMeterProtocol type"));
  }

  ADD_FIELD(npmp_tree, message_type);
  ADD_FIELD(npmp_tree, message_flags);
  ADD_FIELD(npmp_tree, message_length);

  switch (type) {
    case NETPERFMETER_ACKNOWLEDGE:
      dissect_npmp_acknowledge_message(message_tvb, npmp_tree);
     break;
    case NETPERFMETER_ADD_FLOW:
      dissect_npmp_add_flow_message(message_tvb, npmp_tree);
     break;
    case NETPERFMETER_REMOVE_FLOW:
      dissect_npmp_remove_flow_message(message_tvb, npmp_tree);
     break;
    case NETPERFMETER_IDENTIFY_FLOW:
      dissect_npmp_identify_flow_message(message_tvb, npmp_tree);
     break;
    case NETPERFMETER_DATA:
      dissect_npmp_data_message(message_tvb, npmp_tree);
     break;
    case NETPERFMETER_START:
      dissect_npmp_start_message(message_tvb, npmp_tree);
     break;
    case NETPERFMETER_STOP:
      dissect_npmp_stop_message(message_tvb, npmp_tree);
     break;
    case NETPERFMETER_RESULTS:
      dissect_npmp_results_message(message_tvb, npmp_tree);
     break;
  }
}


static int
dissect_npmp(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *npmp_item;
  proto_tree *npmp_tree;

  /* pinfo is NULL only if dissect_npmp_message is called from dissect_error cause */
  if (pinfo)
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetPerfMeterProtocol");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the npmp protocol tree */
    npmp_item = proto_tree_add_item(tree, proto_npmp, message_tvb, 0, -1, ENC_NA);
    npmp_tree = proto_item_add_subtree(npmp_item, ett_npmp);
  } else {
    npmp_tree = NULL;
  };
  /* dissect the message */
  dissect_npmp_message(message_tvb, pinfo, npmp_tree);
  return(TRUE);
}


/* Register the protocol with Wireshark */
void
proto_register_npmp(void)
{
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_npmp,
    &ett_onoffarray
  };

  /* Register the protocol name and description */
  proto_npmp = proto_register_protocol("NetPerfMeter Protocol", "NetPerfMeterProtocol",  "npmp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_npmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_npmp(void)
{
  dissector_handle_t npmp_handle;

  npmp_handle = new_create_dissector_handle(dissect_npmp, proto_npmp);
  dissector_add_uint("sctp.ppi", PPID_NETPERFMETER_CONTROL_LEGACY, npmp_handle);
  dissector_add_uint("sctp.ppi", PPID_NETPERFMETER_DATA_LEGACY,    npmp_handle);
  dissector_add_uint("sctp.ppi", NPMP_CTRL_PAYLOAD_PROTOCOL_ID,    npmp_handle);
  dissector_add_uint("sctp.ppi", NPMP_DATA_PAYLOAD_PROTOCOL_ID,    npmp_handle);
}
