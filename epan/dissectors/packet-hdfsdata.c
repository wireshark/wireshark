/* packet-hdfsdata.c
 * HDFS data Protocol and dissectors
 *
 * Copyright (c) 2011 by Isilon Systems.
 *
 * Author: Allison Obourn <aobourn@isilon.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
#include "packet-tcp.h"

void proto_register_hdfsdata(void);
void proto_reg_handoff_hdfsdata(void);

#if 0
#define NAMENODE_PORT 8020
#define DATANODE_PORT 8021
#endif

#define FIRST_READ_FRAGMENT_LEN 15
#define SECOND_READ_FRAGMENT_LEN 29
#define LAST_READ_FRAGMENT_LEN 4
#define WRITE_OP 80
#define READ_OP 81
#define MIN_WRITE_REQ 35
#define MIN_READ_REQ 36

#define STATUS_SUCCESS 6
#define PIPELINE_LEN 1
#define STATUS_LEN 2
#define FINISH_REQ_LEN 4
#define END_PACKET_LEN 8
#define READ_RESP_HEAD_LEN 19
#define WRITE_RESP_HEAD_LEN 21
#define WRITE_REQ_HEAD_LEN 7

#define CRC 1
#define CRC_SIZE 8.0
#define CHUNKSIZE_START 3


#if 0
static const int RESPONSE_HEADER = 1;
static const int RESPONSE_METADATA = 2;
static const int RESPONSE_DATA = 3;
#endif

static guint tcp_port = 0;

static int proto_hdfsdata = -1;
static int hf_hdfsdata_version = -1;
static int hf_hdfsdata_cmd = -1;
static int hf_hdfsdata_blockid = -1;
static int hf_hdfsdata_timestamp = -1;
static int hf_hdfsdata_startoffset = -1;
static int hf_hdfsdata_blocklen = -1;
static int hf_hdfsdata_clientlen = -1;
static int hf_hdfsdata_clientid = -1;
static int hf_hdfsdata_tokenlen = -1;
static int hf_hdfsdata_tokenid = -1;
static int hf_hdfsdata_tokenpassword = -1;
static int hf_hdfsdata_tokentype = -1;
static int hf_hdfsdata_tokenservice = -1;
static int hf_hdfsdata_status = -1;
static int hf_hdfsdata_checksumtype = -1;
static int hf_hdfsdata_chunksize = -1;
static int hf_hdfsdata_chunkoffset = -1;
static int hf_hdfsdata_datalength = -1;
static int hf_hdfsdata_inblockoffset = -1;
static int hf_hdfsdata_seqnum = -1;
static int hf_hdfsdata_last = -1;
static int hf_hdfsdata_crc32 = -1;
static int hf_hdfsdata_datalen = -1;
static int hf_hdfsdata_rest = -1;
static int hf_hdfsdata_end = -1;
static int hf_hdfsdata_packetsize = -1;
static int hf_hdfsdata_chunklength = -1;
static int hf_hdfsdata_crc64 = -1;
static int hf_hdfsdata_pipelinestatus = -1;

static int hf_hdfsdata_pipelinenum = -1;
static int hf_hdfsdata_recovery = -1;
static int hf_hdfsdata_sourcenode = -1;
static int hf_hdfsdata_currentpipeline = -1;
static int hf_hdfsdata_node = -1;

static gint ett_hdfsdata = -1;

static dissector_handle_t hdfsdata_handle;

/* Taken from HDFS
   Parse the first byte of a vint/vlong to determine the number of bytes
   value is the first byte of the vint/vlong
   returns the total number of bytes (1 to 9) */
static int
decode_vint_size (gint8 value) {
  if (value >= -112) {
    return 1;
  } else if (value < -120) {
    return -119 - value;
  }
  return -111 - value;
}

/* Taken from HDFS
   converts a variable length number into a long and discovers how many bytes it is
   returns the decoded number */
static guint
dissect_variable_length_long (tvbuff_t *tvb, proto_tree *hdfsdata_tree, int* offset)
{
  int byte_count = 1;
  int idx = 0;
  guint i = 0;
  gint8 first_byte = tvb_get_guint8(tvb, *offset);
  guint size = 0;

  int len = decode_vint_size(first_byte);
  if (len == 1) {
    proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_clientlen, tvb, *offset, byte_count, ENC_BIG_ENDIAN);
    *offset = (*offset) + byte_count;
    return first_byte;
  }

  for  (idx = 0; idx < len-1; idx++) {
    char b = tvb_get_guint8(tvb, *offset + byte_count);
    byte_count++;
    i = i << 8;
    i = i | (b & 0xFF);
  }
  size = ((first_byte < -120 || (first_byte >= -112 && first_byte < 0)) ? (i ^ 0xFFFFFFFF) : i);
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_clientlen, tvb, *offset, byte_count, ENC_BIG_ENDIAN);
  *offset = (*offset) + byte_count;

  return size;
}

/* dissects a variable length int and then using its value dissects the following string */
static void
dissect_variable_int_string(tvbuff_t *tvb, proto_tree *hdfsdata_tree, int *offset)
{
  /* Get the variable length int that represents the length of the next feild */
  int len = dissect_variable_length_long (tvb, hdfsdata_tree, offset);

  /* client id = amount of bytes in previous */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_clientid, tvb, *offset, len, ENC_ASCII|ENC_NA);
  *offset += len;
}

/* dissects the access tokens that appear at the end of requests.
 tokens: id, password, kind, service */
static void
dissect_access_tokens(tvbuff_t *tvb, proto_tree *hdfsdata_tree, int *offset)
{
  int len = 0;

  len = tvb_get_guint8(tvb, *offset);
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_tokenlen, tvb, *offset, 1, ENC_BIG_ENDIAN);
  *offset += 1;

  /* token id = amount of bytes in previous */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_tokenid, tvb, *offset, len, ENC_ASCII|ENC_NA);
  *offset += len;

  len = tvb_get_guint8(tvb, *offset);
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_tokenlen, tvb, *offset, 1, ENC_BIG_ENDIAN);
  *offset += 1;

  /* token password = amount of bytes in previous */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_tokenpassword, tvb, *offset, len, ENC_ASCII|ENC_NA);
  *offset += len;

  len = tvb_get_guint8(tvb, *offset);
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_tokenlen, tvb, *offset, 1, ENC_BIG_ENDIAN);
  *offset += 1;

  /* token type = amount of bytes in previous */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_tokentype, tvb, *offset, len, ENC_ASCII|ENC_NA);
  *offset += len;

  len = tvb_get_guint8(tvb, *offset);
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_tokenlen, tvb, *offset, 1, ENC_BIG_ENDIAN);
  *offset += 1;

  /* token service = amount of bytes in previous; */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_tokenservice, tvb, *offset, len, ENC_ASCII|ENC_NA);
  *offset += len;
}

/* handles parsing read response packets */
static void
dissect_read_response(tvbuff_t *tvb, proto_tree *hdfsdata_tree, int offset)
{
  int len = 0;
  guint32 chunksize;

  /* 4 bytes = data length */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_datalength, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* 8 bytes = in block offset */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_inblockoffset, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  /* 8 bytes = sequence number */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_seqnum, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  /* 1 byte = last packet in block */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_last, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* 4 byte = length of data */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_datalen, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* if there is a crc checksum it is 8* the length of the data * checksum size / chunksize */
  chunksize = tvb_get_ntohl(tvb, CHUNKSIZE_START);
  if (chunksize == 0)   /* let's not divide by zero */
    return;
  if (tvb_get_guint8(tvb, 2) == CRC) {
    len = (int)(CRC_SIZE * tvb_get_ntohl(tvb, offset - 4) *
      tvb_get_ntohl(tvb, offset - 8) / chunksize);
  }

  /* the rest of bytes (usually 4) = crc32 code */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_crc32, tvb, offset, len, ENC_BIG_ENDIAN);
  /* offset += len; */
}

/* dissects the first packet of the read response */
static void
dissect_read_response_start(tvbuff_t *tvb, proto_tree *hdfsdata_tree, int offset) {
  /* 2 bytes = status code */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_status, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* checksum type = 1 byte. 1 = crc32, 0 = null */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_checksumtype, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* 4 bytes = chunksize */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_chunksize, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* 8 bytes = chunk offset */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_chunkoffset, tvb, offset, 8, ENC_BIG_ENDIAN);
  /* offset += 8; */
}

/* dissects the fields specific to a read request */
static void
dissect_read_request(tvbuff_t *tvb, proto_tree *hdfsdata_tree, int *offset)
{

  /* 8 bytes = start offset */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_startoffset, tvb, *offset, 8, ENC_BIG_ENDIAN);
  *offset += 8;

  /* 8 bytes = block length */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_blocklen, tvb, *offset, 8, ENC_BIG_ENDIAN);
  *offset += 8;

}

/* dissects the fields specific to a write request */
static void
dissect_write_request(tvbuff_t *tvb, proto_tree *hdfsdata_tree, int *offset)
{
  /* 4 bytes = number of nodes in pipeline */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_pipelinenum, tvb, *offset, 4, ENC_BIG_ENDIAN);
  *offset += 4;

  /* 1 bytes = recovery boolean */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_recovery, tvb, *offset, 1, ENC_BIG_ENDIAN);
  *offset += 1;
}

/* dissects the fields specific to a write request */
static void
dissect_write_request_end(tvbuff_t *tvb, proto_tree *hdfsdata_tree, int *offset)
{
  int i = 0;
  int len = 0;

  /* 1 bytes = source node */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_sourcenode, tvb, *offset, 1, ENC_BIG_ENDIAN);
  *offset += 1;

  /* 4 bytes = number of nodes currently in the pipeline (usually just -1 of before) */
  len = tvb_get_ntohl(tvb, *offset);
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_currentpipeline, tvb, *offset, 4, ENC_BIG_ENDIAN);
  *offset += 4;

  /* varible length sequence of node objects */
  for (i = 0; i < len; i++) {
    proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_node, tvb, *offset, 4, ENC_BIG_ENDIAN);
    *offset += 4;
  }
}

/* dissects the beginning of the read and write request messages */
static int
dissect_header(tvbuff_t *tvb, proto_tree *hdfsdata_tree, int* offset){

  int command = 0;

  /* 2 bytes = protocol version */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_version, tvb, *offset, 2, ENC_BIG_ENDIAN);
  *offset += 2;

  /* 1 byte = command */
  command = tvb_get_guint8(tvb, *offset);
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_cmd, tvb, *offset, 1, ENC_BIG_ENDIAN);
  *offset += 1;

  /* 8 bytes = block id */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_blockid, tvb, *offset, 8, ENC_BIG_ENDIAN);
  *offset += 8;

  /* 8 bytes = timestamp */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_timestamp, tvb, *offset, 8, ENC_BIG_ENDIAN);
  *offset += 8;

  return command;
}

/* decodes the write response messages */
static void
dissect_write_response(tvbuff_t *tvb, proto_tree *hdfsdata_tree, int offset)
{
  /* 4 bytes = packetsize */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_packetsize, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* 8 bytes = offset in block */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_startoffset, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  /* 8 bytes = sequence number */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_seqnum, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  /* 1 bytes = last packet */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_last, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* 4 bytes = chunk length */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_chunklength, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* 8 bytes = crc code */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_crc64, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  /* add the rest -> RESPONSE_DATA */
  proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_rest, tvb, offset, (tvb_reported_length(tvb)) - offset, ENC_ASCII|ENC_NA);
   /* offset += (tvb_reported_length(tvb)); */
}

/* determine PDU length of protocol  */
static guint
get_hdfsdata_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  /* get data packet len, add FIRST_READ_FRAGMENT_LEN for first fragment (before len),
     SECOND_READ_FRAGMENT_LEN for second fragment (incl len), subtract 4 for length itself. */

  if (tvb_reported_length(tvb) <= 4 || tvb_reported_length(tvb) == END_PACKET_LEN
    || tvb_get_ntohl(tvb, 0) == tvb_reported_length(tvb) - WRITE_RESP_HEAD_LEN
    || (tvb_reported_length(tvb) >= MIN_READ_REQ && tvb_get_guint8(tvb, 2) == READ_OP)
    || (tvb_reported_length(tvb) >= MIN_WRITE_REQ && tvb_get_guint8(tvb, 2) == WRITE_OP)) {

    return tvb_reported_length(tvb);
  }
  return tvb_get_ntohl(tvb, offset + FIRST_READ_FRAGMENT_LEN) +
    FIRST_READ_FRAGMENT_LEN + SECOND_READ_FRAGMENT_LEN - LAST_READ_FRAGMENT_LEN;
}

/* This method dissects fully reassembled messages */
static int
dissect_hdfsdata_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HDFSDATA");
  /* Clear out stuff in the info column */
  col_set_str(pinfo->cinfo, COL_INFO, "HDFS Data");


  if (tree) {
    proto_item *ti = NULL;
    proto_tree *hdfsdata_tree = NULL;

    ti = proto_tree_add_item(tree, proto_hdfsdata, tvb, offset, -1, ENC_NA);
    hdfsdata_tree = proto_item_add_subtree(ti, ett_hdfsdata);

    /* if only 1 bytes packet must just contain just the pipeline status */
    if ((tvb_reported_length(tvb)) == PIPELINE_LEN) {

      /* 1 bytes = pipeline status */
      proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_pipelinestatus, tvb, offset, PIPELINE_LEN, ENC_BIG_ENDIAN);

    /* if only 2 bytes packet must just contain just a status code */
    } else if ((tvb_reported_length(tvb)) == STATUS_LEN) {
      /* 2 bytes = status code */
      proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_status, tvb, offset, STATUS_LEN, ENC_BIG_ENDIAN);

    /* if it is 4 bytes long it must be a finish request packet */
    } else if ((tvb_reported_length(tvb)) == FINISH_REQ_LEN) {
      proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_end, tvb, offset, 4, ENC_BIG_ENDIAN);

    /* read response packet */
    } else if (tvb_reported_length(tvb) >= READ_RESP_HEAD_LEN && tvb_reported_length(tvb) ==
      tvb_get_ntohl(tvb, FIRST_READ_FRAGMENT_LEN) +
      FIRST_READ_FRAGMENT_LEN + SECOND_READ_FRAGMENT_LEN - LAST_READ_FRAGMENT_LEN){

      dissect_read_response_start(tvb, hdfsdata_tree, offset);
      offset += FIRST_READ_FRAGMENT_LEN;

      dissect_read_response(tvb, hdfsdata_tree, offset);
      offset+= SECOND_READ_FRAGMENT_LEN;

      /* This message just contains data so we can display it all as one block */

      proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_rest, tvb, offset, (tvb_reported_length(tvb)) - offset, ENC_ASCII|ENC_NA);

    } else {

      guint8 op = tvb_get_guint8(tvb, 2);

      /* READ  request */
      if ((tvb_reported_length(tvb)) >= MIN_READ_REQ && op == READ_OP) {
        dissect_header(tvb, hdfsdata_tree, &offset);
        dissect_read_request(tvb, hdfsdata_tree, &offset);
        dissect_variable_int_string(tvb, hdfsdata_tree, &offset);
        dissect_access_tokens(tvb, hdfsdata_tree, &offset);

      /* WRITE request */
      } else if ((tvb_reported_length(tvb)) >= MIN_WRITE_REQ && op == WRITE_OP) {
        dissect_header(tvb, hdfsdata_tree, &offset);
        dissect_write_request(tvb, hdfsdata_tree, &offset);
        dissect_variable_int_string(tvb, hdfsdata_tree, &offset);
        dissect_write_request_end(tvb, hdfsdata_tree, &offset);
        dissect_access_tokens(tvb, hdfsdata_tree, &offset);

        /* checksum type = 1 byte. 1 = crc32, 0 = null */
        proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_checksumtype, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* 4 bytes = chunksize */
        proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_chunksize, tvb, offset, 4, ENC_BIG_ENDIAN);

      /* write responses store the data length in the first 4 bytes. This length does not
         include 21 bits of header */
      } else if (tvb_reported_length(tvb) >= 4 && tvb_get_ntohl(tvb, 0) ==
        tvb_reported_length(tvb) - WRITE_RESP_HEAD_LEN) {

        dissect_write_response(tvb, hdfsdata_tree, offset);

      } else {
        /* This message contains some form of data that we have not successfully been able to
           pattern match and catagorize. Display all of it as data. */
        proto_tree_add_item(hdfsdata_tree, hf_hdfsdata_rest, tvb, offset, (tvb_reported_length(tvb)), ENC_ASCII|ENC_NA);
      }
    }
  }

  return tvb_captured_length(tvb);
}

static int
dissect_hdfsdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  int frame_header_len = 0;

  gboolean need_reassemble = FALSE;
  guint8 op = 0;
  gboolean only_packet = tvb_reported_length(tvb) == 1 || (tvb_reported_length(tvb) == 2 &&
    tvb_get_ntohs(tvb, 0) == STATUS_SUCCESS);

  if (tvb_reported_length(tvb) >= 3)
    op = tvb_get_guint8(tvb, 2);

  if (!only_packet && tvb_reported_length(tvb) != 4 && !(tvb_reported_length(tvb) >= MIN_READ_REQ && op == READ_OP) &&
    !(tvb_reported_length(tvb) >= MIN_WRITE_REQ && op == WRITE_OP) && !(tvb_reported_length(tvb) == END_PACKET_LEN &&
    !tvb_get_ntohl(tvb, 0) && !tvb_get_ntohl(tvb, 4))) {

    need_reassemble = TRUE;
  }

  /* setting the header size for the different types of packets */
  if (only_packet || tvb_reported_length(tvb) == END_PACKET_LEN) {
    frame_header_len = tvb_reported_length(tvb);

  } else if (tvb_reported_length(tvb) == FIRST_READ_FRAGMENT_LEN ||(tvb_reported_length(tvb) >= MIN_READ_REQ &&
    op == READ_OP && !((tvb_reported_length(tvb)) == 2 && !tvb_get_ntohs(tvb, 0)))) {

    frame_header_len = READ_RESP_HEAD_LEN;

  } else if (tvb_reported_length(tvb) >= MIN_WRITE_REQ && op == WRITE_OP) {
    frame_header_len = WRITE_REQ_HEAD_LEN;
  }

  tcp_dissect_pdus(tvb, pinfo, tree, need_reassemble, frame_header_len, get_hdfsdata_message_len, dissect_hdfsdata_message, data);
  return tvb_captured_length(tvb);
}

/* registers the protcol with the given names */
void
proto_register_hdfsdata(void)
{
    static hf_register_info hf[] = {

  /* list of all options for dissecting the protocol */

  /*************************************************
  Read request
  **************************************************/
  { &hf_hdfsdata_version,
    { "HDFSDATA protocol version", "hdfsdata.version",
      FT_UINT16, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_cmd,
    { "HDFSDATA command", "hdfsdata.cmd",
      FT_UINT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_blockid,
    { "HDFSDATA block id", "hdfsdata.blockid",
      FT_UINT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_timestamp,
    { "HDFSDATA timestamp", "hdfsdata.timestamp",
      FT_UINT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  /***
  Read specific
  ***/
  { &hf_hdfsdata_startoffset,
    { "HDFSDATA start offset" , "hdfsdata.startoffset",
      FT_UINT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_blocklen,
    { "HDFSDATA block length", "hdfsdata.blocklen",
      FT_UINT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  /***
  Write specific
  ***/
  { &hf_hdfsdata_pipelinenum,
    { "HDFSDATA number in pipeline", "hdfsdata.pipelinenum",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_recovery,
    { "HDFSDATA recovery boolean", "hdfsdata.recovery",
      FT_UINT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_sourcenode,
    { "HDFSDATA source node", "hdfsdata.sourcenode",
      FT_UINT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_currentpipeline,
    { "HDFSDATA current number of nodes in the pipeline", "hdfsdata.currentpipline",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_node,
    { "HDFSDATA node object", "hdfsdata.node",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  /***
  Var length
  **/
  { &hf_hdfsdata_clientlen,
    { "HDFSDATA client id length", "hdfsdata.clientlen",
      FT_UINT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_clientid,
    { "HDFSDATA client id", "hdfsdata.clientid",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_end,
    { "HDFSDATA end data request", "hdfsdata.end",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  /*************************************************
  Access tokens
  **************************************************/
  { &hf_hdfsdata_tokenlen,
    { "HDFSDATA access token length", "hdfsdata.tokenlen",
      FT_UINT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_tokenid,
    { "HDFSDATA access token ID", "hdfsdata.tokenid",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_tokenpassword,
    { "HDFSDATA access token password", "hdfsdata.tokenpassword",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_tokentype,
    { "HDFSDATA access token type", "hdfsdata.tokentype",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_tokenservice,
    { "HDFSDATA access token service", "hdfsdata.tokenservice",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  /***********************************************
  Responses 1
  ***********************************************/
  { &hf_hdfsdata_status,
    { "HDFSDATA status code", "hdfsdata.status",
      FT_UINT16, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_checksumtype,
    { "HDFSDATA checksum type", "hdfsdata.checksumtype",
      FT_UINT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_chunksize,
    { "HDFSDATA chunk size", "hdfsdata.chunksize",
      FT_UINT16, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_chunkoffset,
    { "HDFSDATA chunk offset", "hdfsdata.chunkoffset",
      FT_UINT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  /***********************************************
  Responses 2
  ***********************************************/
  { &hf_hdfsdata_datalength,
    { "HDFSDATA length of data", "hdfsdata.datalength",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_inblockoffset,
    { "HDFSDATA in block offset", "hdfsdata.inblockoffset",
      FT_UINT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_seqnum,
    { "HDFSDATA sequence number", "hdfsdata.seqnum",
      FT_UINT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_last,
    { "HDFSDATA last packet in block", "hdfsdata.last",
      FT_INT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_datalen,
    { "HDFSDATA length of data", "hdfsdata.datalen",
      FT_INT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_crc32,
    { "HDFSDATA crc32 checksum", "hdfsdata.crc32",
      FT_INT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  /***********************************************
  Responses 3
  ***********************************************/
  { &hf_hdfsdata_rest,
    { "HDFSDATA data", "hdfsdata.rest",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  /***********************************************
  Write Response 1
  ***********************************************/
  { &hf_hdfsdata_packetsize,
    { "HDFSDATA packet size", "hdfsdata.packetsize",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_chunklength,
    { "HDFSDATA chunk length", "hdfsdata.chunklength",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_crc64,
    { "HDFSDATA crc64 checksum", "hdfsdata.crc64",
      FT_INT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfsdata_pipelinestatus,
    { "HDFSDATA pipeline status", "hdfsdata.pipelinestatus",
      FT_INT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_hdfsdata
    };

    module_t *hdfsdata_module;

    proto_hdfsdata = proto_register_protocol (
      "HDFSDATA Protocol", /* name       */
      "HDFSDATA",      /* short name */
      "hdfsdata"       /* abbrev     */
      );

    proto_register_field_array(proto_hdfsdata, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    hdfsdata_module = prefs_register_protocol(proto_hdfsdata, proto_reg_handoff_hdfsdata);

    prefs_register_uint_preference(hdfsdata_module,
                                   "tcp.port",
                                   "TCP port for HDFSDATA",
                                   "Set the TCP port for HDFSDATA",
                                   10,
                                   &tcp_port);

    hdfsdata_handle = register_dissector("hdfsdata", dissect_hdfsdata, proto_hdfsdata);
}

/* registers handoff */
void
proto_reg_handoff_hdfsdata(void)
{
  static gboolean initialized = FALSE;
    static guint saved_tcp_port;

    if (!initialized) {
        dissector_add_for_decode_as("tcp.port", hdfsdata_handle);
        initialized = TRUE;
    } else if (saved_tcp_port != 0) {
        dissector_delete_uint("tcp.port", saved_tcp_port, hdfsdata_handle);
    }

    if (tcp_port != 0) {
        dissector_add_uint("tcp.port", tcp_port, hdfsdata_handle);
    }

    saved_tcp_port = tcp_port;
}
/*
 * Editor modelines
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
