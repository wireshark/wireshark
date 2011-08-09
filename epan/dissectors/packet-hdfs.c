/* packet-hdfs.c
 * HDFS Protocol and dissectors
 *
 * Copyright (c) 2011 by Isilon Systems.
 *
 * Author: Allison Obourn <aobourn@isilon.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#define NAMENODE_PORT 8020
#define REQUEST_STR "hrpc"

#define SEND_DEC 1936027236
#define SEND_OFFSET 13
#define HEAR_DEC 1214603634
#define HEAR_OFFSET 9
#define TBEA_DEC 1952605537
#define TBEA_OFFSET 5
#define T_DEC 116
#define T_OFFSET 1

#define FIRST_READ_FRAGMENT_LEN 15
#define SECOND_READ_FRAGMENT_LEN 29


static const int START = 0;
static const int AUTHENTICATION = 1;
static const int DATA = 2;

static guint tcp_port = 0;

static int proto_hdfs = -1;
static int hf_hdfs_pdu_type = -1;
static int hf_hdfs_flags = -1;
static int hf_hdfs_sequenceno = -1;
static int hf_hdfs_packetno = -1;
static int hf_hdfs_authlen = -1;
static int hf_hdfs_success = -1;
static int hf_hdfs_auth = -1;
static int hf_hdfs_len = -1;
static int hf_hdfs_strcall = -1;
static int hf_hdfs_methodnamelen = -1;
static int hf_hdfs_params = -1;
static int hf_hdfs_paramtype = -1;
static int hf_hdfs_paramval = -1;
static int hf_hdfs_paramtypelen = -1;
static int hf_hdfs_paramvallen = -1;
static int hf_hdfs_paramvalnum = -1;
static int hf_hdfs_rest = -1;

static gint ett_hdfs = -1;

void proto_reg_handoff_hdfs(void);

/* Parses the parameters of a function.
   Parses the type length which is always in 2 bytes.
   Next the type which is the previously found length.
   If this type is variable length it then reads the length of the data
   from 2 bytes and then the data.
   Otherwise reads just the data. */
static void
dissect_params(tvbuff_t *tvb, proto_tree *hdfs_tree, int offset, guint params) {

  guint i =  0;
  int length;
  const guint8* type_name;
  for (i = 0; i < params; i++) {

    /* get length that we just dissected */
    length = tvb_get_ntohs(tvb, offset);

    /* 2 bytes = parameter type length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_paramtypelen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* length bytes = parameter type */
    proto_tree_add_item(hdfs_tree, hf_hdfs_paramtype, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;

    if (offset >= length && (!tvb_memeql(tvb, offset - length, "long", length) || !tvb_memeql(tvb, offset - length, "int", length) ||
        !tvb_memeql(tvb, offset - length, "short", length) || !tvb_memeql(tvb, offset - length, "char", length) ||
        !tvb_memeql(tvb, offset - length, "byte", length) || !tvb_memeql(tvb, offset - length, "float", length)
      || !tvb_memeql(tvb, offset - length, "double", length) || !tvb_memeql(tvb, offset - length, "boolean", length))) {

      length = sizeof(type_name);

      proto_tree_add_item(hdfs_tree, hf_hdfs_paramvalnum, tvb, offset, length, ENC_BIG_ENDIAN);
      offset += length;

    } else {
      /* get length */
      length = tvb_get_ntohs(tvb, offset);

      /* 2 bytes = parameter value length */
      proto_tree_add_item(hdfs_tree, hf_hdfs_paramvallen, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      proto_tree_add_item(hdfs_tree, hf_hdfs_paramval, tvb, offset, length, ENC_BIG_ENDIAN);
      offset += length;
    }
  }
}


/* Dissects a data packet of the form:
   method name length   : 2B
   method name    : above value
   number of parameters   : 4B
    -- list of parameters the length of above --
   parameter type length  : 2B
   parameter type    : above value
   -- if the type is variable size --
   parameter value length  : 2B
   parameter value    : above value
   -- otherwise --
   parameter value   : length of the type  */
static void
dissect_data(tvbuff_t *tvb, proto_tree *hdfs_tree, int offset) {

  int params = 0;
  guint length = 0;

  /* get length */
  length = tvb_get_ntohs(tvb, offset);

  /* method name length = 2 B */
  proto_tree_add_item(hdfs_tree, hf_hdfs_methodnamelen, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* length bytes = method name */
  proto_tree_add_item(hdfs_tree, hf_hdfs_strcall, tvb, offset, length, ENC_BIG_ENDIAN);
  offset += length;

  /* we only want to parse the packet if it is not a heartbeat (random looking numbers are the decimal
     representation of sendHeartbeat */
  if (!(tvb_get_ntohl(tvb, offset - SEND_OFFSET) == SEND_DEC && tvb_get_ntohl(tvb, offset - HEAR_OFFSET) == HEAR_DEC &&
    tvb_get_ntohl(tvb, offset - TBEA_OFFSET) == TBEA_DEC && tvb_get_guint8(tvb, offset - T_OFFSET) == T_DEC)) {

    /* get number of params */
    params = tvb_get_ntohl(tvb, offset);

    /* 4 bytes = # of parameters */
    proto_tree_add_item(hdfs_tree, hf_hdfs_params, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* go through all params and dissect their type length, type, value length and value */
    dissect_params (tvb, hdfs_tree, offset, params);
  }
}

static void
dissect_hdfs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset = 0;
  int success = 0;
  guint length = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HDFS");
  col_set_str(pinfo->cinfo, COL_INFO, "HDFS");

  if (tree) {

    proto_item *ti = NULL;
    proto_tree *hdfs_tree = NULL;

    ti = proto_tree_add_item(tree, proto_hdfs, tvb, 0, -1, ENC_BIG_ENDIAN);
    hdfs_tree = proto_item_add_subtree(ti, ett_hdfs);

    /* Response */
    if (pinfo->srcport == NAMENODE_PORT) {
      /* 4 bytes = sequence number */ 
      proto_tree_add_item(hdfs_tree, hf_hdfs_packetno, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* 4 bytes = status -> 0000 = success, 0001 = error, ffff = fatal */
      success = tvb_get_ntohl(tvb, offset);
      proto_tree_add_item(hdfs_tree, hf_hdfs_success, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

        if (success == 0) {
        /* name length = 2 B */
        length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(hdfs_tree, hf_hdfs_methodnamelen, tvb, offset, 2, ENC_BIG_ENDIAN); 
        offset += 2;

        /* length bytes = method name */
        proto_tree_add_item(hdfs_tree, hf_hdfs_strcall, tvb, offset, length, ENC_BIG_ENDIAN);
        offset += length;

        proto_tree_add_item(hdfs_tree, hf_hdfs_rest, tvb, offset, ((tvb_reported_length(tvb)) - offset), ENC_BIG_ENDIAN);
      }

    /* Request to namenode */
    } else {

      /* check the packet length */
      guint auth = tvb_get_ntohl(tvb, offset);

      /* first setup packet starts with "hrpc" */
      if (!tvb_memeql(tvb, offset, REQUEST_STR, sizeof(REQUEST_STR) - 1)) {
        
        proto_tree_add_item(hdfs_tree, hf_hdfs_sequenceno, tvb, offset, sizeof(REQUEST_STR) - 1, ENC_BIG_ENDIAN);
        offset += sizeof(REQUEST_STR) - 1;

        proto_tree_add_item(hdfs_tree, hf_hdfs_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(hdfs_tree, hf_hdfs_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* offset += 1; */

      } else {
        /* second authentication packet */
        if (auth + 4 != tvb_reported_length(tvb)) {
          
          /* authentication length (read out of first 4 bytes) */
          length = tvb_get_ntohl(tvb, offset);
          proto_tree_add_item(hdfs_tree, hf_hdfs_authlen, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;

          /* authentication (length the number we just got) */
          proto_tree_add_item(hdfs_tree, hf_hdfs_auth, tvb, offset, length, ENC_BIG_ENDIAN);
          offset += length;
        }

        /* data packets */

        /* 4 bytes = length */
        proto_tree_add_item(hdfs_tree, hf_hdfs_len, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* 4 bytes = sequence number */
        proto_tree_add_item(hdfs_tree, hf_hdfs_packetno, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* dissect packet data */
        dissect_data(tvb, hdfs_tree, offset);
      }
    }
  }
}



/* registers the protcol with the given names */
void
proto_register_hdfs(void)
{

    static hf_register_info hf[] = {

  /* list of all options for dissecting the protocol */

  /*************************************************
  First packet
  **************************************************/
  { &hf_hdfs_sequenceno,
    { "HDFS protocol type", "hdfs.type",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_pdu_type,
    { "HDFS protocol version", "hdfs.version",
      FT_UINT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_flags,
    { "HDFS authentication type", "hdfs.auth",
      FT_UINT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  /***********************************************
  Authentication packet
  ***********************************************/
  { &hf_hdfs_authlen,
    { "HDFS authentication length", "hdfs.authlen",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_auth,
    { "HDFS authorization bits", "hdfs.auth",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  /**********************************************
  Response
  **********************************************/
  { &hf_hdfs_packetno,
    { "HDFS packet number", "hdfs.seqno",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_success,
    { "HDFS success", "hdfs.success",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_methodnamelen,
    { "HDFS method name length", "hdfs.methodnamelen",
      FT_UINT16, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_strcall,
    { "HDFS method name", "hdfs.strcall",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_rest,
    { "HDFS value", "hdfs.rest",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  /***********************************************
  Data request
  ***********************************************/
  { &hf_hdfs_len,
    { "HDFS length", "hdfs.len",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  /* packet number, same as in response
     method name length, same as in response
     string call, same as in response */
  { &hf_hdfs_params,
    { "HDFS number of parameters", "hdfs.params",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_paramtypelen,
    { "HDFS parameter type length", "hdfs.paramtypelen",
      FT_UINT16, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_paramtype,
    { "HDFS parameter type", "hdfs.paramtype",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_paramvallen,
    { "HDFS parameter value length", "hdfs.paramvallen",
      FT_UINT16, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },
  { &hf_hdfs_paramval,
    { "HDFS parameter value", "hdfs.paramval",
      FT_STRING, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
  },
  /* param value that is displayed as a number not a string */
  { &hf_hdfs_paramvalnum,
    { "HDFS parameter value", "hdfs.paramvalnum",
      FT_INT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
  },

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_hdfs
    };

    module_t *hdfs_module;

    proto_hdfs = proto_register_protocol (
        "HDFS Protocol", /* name       */
        "HDFS",      /* short name */
        "hdfs"       /* abbrev     */
        );

    proto_register_field_array(proto_hdfs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    hdfs_module = prefs_register_protocol(proto_hdfs, proto_reg_handoff_hdfs);

    prefs_register_uint_preference(hdfs_module,
                                  "tcp.port",
                                  "TCP port for HDFS",
                                  "Set the TCP port for HDFS",
                                  10,
                                  &tcp_port);

    register_dissector("hdfs", dissect_hdfs, proto_hdfs);
}

/* registers handoff */
void
proto_reg_handoff_hdfs(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t hdfs_handle;
    static guint saved_tcp_port;

    if (!initialized) {
        hdfs_handle = create_dissector_handle(dissect_hdfs, proto_hdfs);
        dissector_add_handle("tcp.port", hdfs_handle);  /* for "decode as" */
        initialized = TRUE;
    } else if (saved_tcp_port != 0) {
        dissector_delete_uint("tcp.port", saved_tcp_port, hdfs_handle);
    }

    if (tcp_port != 0) {
        dissector_add_uint("tcp.port", tcp_port, hdfs_handle);
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
 * ex: set shiftwidth=2 tabstop=8 expandtab
 * :indentSize=2:tabSize=8:noTabs=true:
 */
