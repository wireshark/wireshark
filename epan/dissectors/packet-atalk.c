/* packet-atalk.c
 * Routines for AppleTalk packet disassembly: LLAP, DDP, NBP, ATP, ASP,
 * RTMP, PAP.
 *
 * $Id$
 *
 * Simon Wilkinson <sxw@dcs.ed.ac.uk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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

#include <glib.h>
#include <epan/packet.h>
#include <string.h>

#include <epan/etypes.h>
#include <epan/ppptypes.h>
#include <epan/aftypes.h>
#include <epan/arcnet_pids.h>
#include <epan/atalk-utils.h>
#include <epan/conversation.h>

#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/emem.h>

#include "packet-atalk.h"
#include "packet-afp.h"

/* Tables for reassembly of fragments. */
static GHashTable *atp_fragment_table = NULL;
static GHashTable *atp_reassembled_table = NULL;

/* desegmentation of ATP */
static gboolean atp_defragment = TRUE;

static dissector_handle_t afp_handle;

static int proto_llap = -1;
static int hf_llap_dst = -1;
static int hf_llap_src = -1;
static int hf_llap_type = -1;

static int proto_ddp = -1;
static int hf_ddp_hopcount = -1;
static int hf_ddp_len = -1;
static int hf_ddp_checksum = -1;
static int hf_ddp_dst = -1;
static int hf_ddp_dst_net = -1;
static int hf_ddp_src = -1;
static int hf_ddp_src_net = -1;
static int hf_ddp_dst_node = -1;
static int hf_ddp_src_node = -1;
static int hf_ddp_dst_socket = -1;
static int hf_ddp_src_socket = -1;
static int hf_ddp_type = -1;

static dissector_handle_t ddp_handle;

/* --------------------------------------
 * ATP protocol parameters
 * from netatalk/include/atalk/atp.h
 */
#define ATP_MAXDATA     (578+4)         /* maximum ATP data size */
#define ATP_BUFSIZ      587             /* maximum packet size */
#define ATP_HDRSIZE     5               /* includes DDP type field */

#define ATP_TRELMASK    0x07            /* mask all but TREL */
#define ATP_RELTIME     30              /* base release timer (in secs) */

#define ATP_TREL30      0x0             /* release time codes */
#define ATP_TREL1M      0x1             /* these are passed in flags of */
#define ATP_TREL2M      0x2             /* atp_sreq call, and set in the */
#define ATP_TREL4M      0x3             /* packet control info. */
#define ATP_TREL8M      0x4

/* flags for ATP options (and control byte)
*/
#define ATP_XO          0x20 /* (1<<5)     eXactly Once mode  */
#define ATP_EOM         0x10 /* (1<<4)     End Of Message     */
#define ATP_STS         0x08 /* (1<<3)     Transaction Status */

/* function codes
*/
#define ATP_FUNCMASK    (3<<6)          /* mask all but function */

#define ATP_TREQ        1    /* (1<<6)     Trans. REQuest  */
#define ATP_TRESP       2    /* (2<<6)     Trans. RESPonse */
#define ATP_TREL        3    /* (3<<6)     Trans. RELease  */

/* ------------------------- */
static dissector_handle_t asp_handle;
static dissector_handle_t pap_handle;

static int proto_atp = -1;
static int hf_atp_ctrlinfo  = -1; /* guint8_t    control information */
static int hf_atp_function  = -1; /* bits 7,6    function */
static int hf_atp_xo        = -1; /* bit 5       exactly-once */
static int hf_atp_eom       = -1; /* bit 4       end-of-message */
static int hf_atp_sts       = -1; /* bit 3       send transaction status */
static int hf_atp_treltimer = -1; /* bits 2,1,0  TRel timeout indicator */

static int hf_atp_bitmap = -1;   /* guint8_t  bitmap or sequence number */
static int hf_atp_tid = -1;      /* guint16_t transaction id. */
static int hf_atp_user_bytes = -1;

static int hf_atp_segments = -1;
static int hf_atp_segment = -1;
static int hf_atp_segment_overlap = -1;
static int hf_atp_segment_overlap_conflict = -1;
static int hf_atp_segment_multiple_tails = -1;
static int hf_atp_segment_too_long_segment = -1;
static int hf_atp_segment_error = -1;
static int hf_atp_segment_count = -1;
static int hf_atp_reassembled_in = -1;
static int hf_atp_reassembled_length = -1;

/* ------------------------- */
static int proto_zip = -1;
static dissector_handle_t zip_atp_handle;

static int hf_zip_function = -1;
static int hf_zip_atp_function = -1;
static int hf_zip_start_index = -1;
static int hf_zip_count = -1;
static int hf_zip_zero_value = -1;

static int hf_zip_network_count = -1;
static int hf_zip_network = -1;
static int hf_zip_network_start = -1;
static int hf_zip_network_end = -1;

static int hf_zip_flags = -1;

static int hf_zip_flags_zone_invalid  = -1;
static int hf_zip_flags_use_broadcast = -1;
static int hf_zip_flags_only_one_zone = -1;

static int hf_zip_last_flag = -1;

static int hf_zip_zone_name    = -1;
static int hf_zip_default_zone = -1;

static int hf_zip_multicast_length  = -1;
static int hf_zip_multicast_address = -1;

static const value_string zip_function_vals[] = {
  {1, "Query"},
  {2, "Reply"},
  {5, "GetNetInfo request"},
  {6, "GetNetInfo reply"},
  {7, "notify"},
  {8, "Extended reply"},
  {0, NULL}
};
static value_string_ext zip_function_vals_ext = VALUE_STRING_EXT_INIT(zip_function_vals);

static const value_string zip_atp_function_vals[] = {
  {7, "GetMyZone"},
  {8, "GetZoneList"},
  {9, "GetLocalZones"},
  {0, NULL}
};

static gint ett_zip              = -1;
static gint ett_zip_flags        = -1;
static gint ett_zip_zones_list   = -1;
static gint ett_zip_network_list = -1;

/* --------------------------------
 * from netatalk/include/atalk/ats.h
 */

#define ASPFUNC_CLOSE   1
#define ASPFUNC_CMD     2
#define ASPFUNC_STAT    3
#define ASPFUNC_OPEN    4
#define ASPFUNC_TICKLE  5
#define ASPFUNC_WRITE   6
#define ASPFUNC_WRTCONT 7
#define ASPFUNC_ATTN    8

#define ASP_HDRSIZ      4
#define ASPERR_OK       0
#define ASPERR_BADVERS  (-1066)
#define ASPERR_BUFSMALL (-1067)
#define ASPERR_NOSESS   (-1068)
#define ASPERR_NOSERV   (-1069)
#define ASPERR_PARM     (-1070)
#define ASPERR_SERVBUSY (-1071)
#define ASPERR_SESSCLOS (-1072)
#define ASPERR_SIZERR   (-1073)
#define ASPERR_TOOMANY  (-1074)
#define ASPERR_NOACK    (-1075)

static int proto_asp            = -1;
static int hf_asp_func          = -1;
static int hf_asp_error         = -1;
static int hf_asp_socket        = -1;
static int hf_asp_version       = -1;
static int hf_asp_session_id    = -1;
static int hf_asp_zero_value    = -1;
static int hf_asp_init_error    = -1;
static int hf_asp_attn_code     = -1;
static int hf_asp_seq           = -1;
static int hf_asp_size          = -1;

/* status stuff same for asp and afp */
static int hf_asp_server_name = -1;
static int hf_asp_server_type = -1;
static int hf_asp_server_vers = -1;
static int hf_asp_server_uams = -1;
static int hf_asp_server_icon = -1;
static int hf_asp_server_directory = -1;

static int hf_asp_server_flag = -1;
static int hf_asp_server_flag_copyfile  = -1;
static int hf_asp_server_flag_passwd    = -1;
static int hf_asp_server_flag_no_save_passwd = -1;
static int hf_asp_server_flag_srv_msg   = -1;
static int hf_asp_server_flag_srv_sig   = -1;
static int hf_asp_server_flag_tcpip     = -1;
static int hf_asp_server_flag_notify    = -1;
static int hf_asp_server_flag_reconnect = -1;
static int hf_asp_server_flag_directory = -1;
static int hf_asp_server_flag_utf8_name = -1;
static int hf_asp_server_flag_fast_copy = -1;
static int hf_asp_server_signature      = -1;
static int hf_asp_server_utf8_name_len  = -1;
static int hf_asp_server_utf8_name      = -1;

static int hf_asp_server_addr_len       = -1;
static int hf_asp_server_addr_type      = -1;
static int hf_asp_server_addr_value     = -1;

static gint ett_asp_status = -1;
static gint ett_asp_uams   = -1;
static gint ett_asp_vers   = -1;
static gint ett_asp_addr   = -1;
static gint ett_asp_addr_line = -1;
static gint ett_asp_directory = -1;
static gint ett_asp_utf8_name = -1;
static gint ett_asp_status_server_flag = -1;

typedef struct {
  guint32 conversation;
  guint8  src[4];
  guint16 seq;
} asp_request_key;

typedef struct {
  guint8  value;        /* command for asp, bitmap for atp */
} asp_request_val;

static GHashTable *asp_request_hash = NULL;

/* Hash Functions */
static gint  asp_equal (gconstpointer v, gconstpointer v2)
{
  const asp_request_key *val1 = (const asp_request_key*)v;
  const asp_request_key *val2 = (const asp_request_key*)v2;

  if (val1->conversation == val2->conversation &&
      val1->seq == val2->seq &&
      !memcmp(val1->src, val2->src, 4)) {
    return 1;
  }
  return 0;
}

static guint asp_hash  (gconstpointer v)
{
  const asp_request_key *asp_key = (const asp_request_key*)v;
  return asp_key->seq;
}

/* ------------------------------------ */
static GHashTable *atp_request_hash = NULL;


/* ------------------------------------ */
static int proto_nbp = -1;
static int hf_nbp_op = -1;
static int hf_nbp_info = -1;
static int hf_nbp_count = -1;
static int hf_nbp_tid = -1;

static int hf_nbp_node_net = -1;
static int hf_nbp_node_port = -1;
static int hf_nbp_node_node = -1;
static int hf_nbp_node_enum = -1;
static int hf_nbp_node_object = -1;
static int hf_nbp_node_type = -1;
static int hf_nbp_node_zone = -1;

static int proto_rtmp = -1;
static int hf_rtmp_net = -1;
static int hf_rtmp_node_len = -1;
static int hf_rtmp_node = -1;
static int hf_rtmp_tuple_net = -1;
static int hf_rtmp_tuple_range_start = -1;
static int hf_rtmp_tuple_range_end = -1;
static int hf_rtmp_tuple_dist = -1;
static int hf_rtmp_function = -1;

static gint ett_atp = -1;

static gint ett_atp_segments = -1;
static gint ett_atp_segment = -1;
static gint ett_atp_info = -1;
static gint ett_asp = -1;
static gint ett_pap = -1;

static gint ett_nbp = -1;
static gint ett_nbp_info = -1;
static gint ett_nbp_node = -1;
static gint ett_rtmp = -1;
static gint ett_rtmp_tuple = -1;
static gint ett_ddp = -1;
static gint ett_llap = -1;
static gint ett_pstring = -1;

static const fragment_items atp_frag_items = {
  &ett_atp_segment,
  &ett_atp_segments,
  &hf_atp_segments,
  &hf_atp_segment,
  &hf_atp_segment_overlap,
  &hf_atp_segment_overlap_conflict,
  &hf_atp_segment_multiple_tails,
  &hf_atp_segment_too_long_segment,
  &hf_atp_segment_error,
  &hf_atp_segment_count,
  &hf_atp_reassembled_in,
  &hf_atp_reassembled_length,
  /* Reassembled data field */
  NULL,
  "segments"
};

/* -------------------------------- */

#define PAPOpenConn       1
#define PAPOpenConnReply  2
#define PAPSendData       3
#define PAPData           4
#define PAPTickle         5
#define PAPCloseConn      6
#define PAPCloseConnReply 7
#define PAPSendStatus     8
#define PAPStatus         9

static int proto_pap = -1;

static int hf_pap_connid   = -1;
static int hf_pap_function = -1;
static int hf_pap_socket   = -1;
static int hf_pap_quantum  = -1;
static int hf_pap_waittime = -1;
static int hf_pap_result   = -1;
static int hf_pap_status   = -1;
static int hf_pap_seq      = -1;
static int hf_pap_eof      = -1;

static int hf_pap_pad = -1;

static const value_string pap_function_vals[] = {
  {PAPOpenConn       , "Open Connection Query"},
  {PAPOpenConnReply  , "Open Connection Reply"},
  {PAPSendData       , "Send Data"},
  {PAPData           , "Data"},
  {PAPTickle         , "Tickle"},
  {PAPCloseConn      , "Close Connection Query"},
  {PAPCloseConnReply , "Close Connection reply"},
  {PAPSendStatus     , "Send Status"},
  {PAPStatus         , "Status"},

  {0, NULL}
};
static value_string_ext pap_function_vals_ext = VALUE_STRING_EXT_INIT(pap_function_vals);

/* -------------------------------- */

static dissector_table_t ddp_dissector_table;

static dissector_handle_t data_handle;

#define DDP_SHORT_HEADER_SIZE 5

/*
 * P = Padding, H = Hops, L = Len
 *
 * PPHHHHLL LLLLLLLL
 *
 * Assumes the argument is in host byte order.
 */
#define ddp_hops(x)     ( ( x >> 10) & 0x3C )
#define ddp_len(x)      ( x & 0x03ff )
typedef struct _e_ddp {
  guint16       hops_len; /* combines pad, hops, and len */
  guint16       sum,dnet,snet;
  guint8        dnode,snode;
  guint8        dport,sport;
  guint8        type;
} e_ddp;

#define DDP_HEADER_SIZE 13


static const value_string op_vals[] = {
  {DDP_RTMPDATA, "AppleTalk Routing Table response or data" },
  {DDP_NBP,      "AppleTalk Name Binding Protocol packet"},
  {DDP_ATP,      "AppleTalk Transaction Protocol packet"},
  {DDP_AEP,      "AppleTalk Echo Protocol packet"},
  {DDP_RTMPREQ,  "AppleTalk Routing Table request"},
  {DDP_ZIP,      "AppleTalk Zone Information Protocol packet"},
  {DDP_ADSP,     "AppleTalk Data Stream Protocol"},
  {DDP_EIGRP,    "Cisco EIGRP for AppleTalk"},
  {0, NULL}
};
static value_string_ext op_vals_ext = VALUE_STRING_EXT_INIT(op_vals);

static const value_string rtmp_function_vals[] = {
  {1, "Request"},
  {2, "Route Data Request (split horizon processed)"},
  {3, "Route Data Request (no split horizon processing)"},
  {0, NULL}
};

#define NBP_BROADCAST 1
#define NBP_LOOKUP 2
#define NBP_FORWARD 4
#define NBP_REPLY 3

static const value_string nbp_op_vals[] = {
  {NBP_BROADCAST, "broadcast request"},
  {NBP_LOOKUP, "lookup"},
  {NBP_FORWARD, "forward request"},
  {NBP_REPLY, "reply"},
  {0, NULL}
};

static const value_string atp_function_vals[] = {
  {ATP_TREQ        ,"REQuest"},
  {ATP_TRESP       ,"RESPonse"},
  {ATP_TREL        ,"RELease"},
  {0, NULL}
};

static const value_string atp_trel_timer_vals[] = {
  {0, "30 seconds"},
  {1, "1 minute"},
  {2, "2 minutes"},
  {3, "4 minutes"},
  {4, "8 minutes"},
  {0, NULL}
};

/*
*/
static const value_string asp_func_vals[] = {
  {ASPFUNC_CLOSE,       "CloseSession" },
  {ASPFUNC_CMD,         "Command" },
  {ASPFUNC_STAT,        "GetStatus" },
  {ASPFUNC_OPEN,        "OpenSession" },
  {ASPFUNC_TICKLE,      "Tickle" },
  {ASPFUNC_WRITE,       "Write" },
  {ASPFUNC_WRTCONT,     "Write Cont" },
  {ASPFUNC_ATTN,        "Attention" },
  {0,                   NULL } };
static value_string_ext asp_func_vals_ext = VALUE_STRING_EXT_INIT(asp_func_vals);

/* XXX: Array sorted in ascending order (unsigned) to allow value_string_ext binary search */
static const value_string asp_error_vals[] = {
  {AFP_OK               , "success"},
  {AFPERR_USRLOGIN      , "user already logged on" },
  {AFPERR_PWDPOLCY      , "password fails policy check" },
  {AFPERR_PWDCHNG       , "password needs to be changed" },
  {AFPERR_INTRASH       , "shared folder in trash." },
  {AFPERR_INSHRD        , "folder being shared is inside a shared folder." },
  {AFPERR_PWDEXPR       , "password expired" },
  {AFPERR_PWDSHORT      , "password too short" },
  {AFPERR_PWDSAME       , "same password/can't change password" },
  {AFPERR_BADID         , "non-existent file id" },
  {AFPERR_SAMEOBJ       , "source file == destination file" },
  {AFPERR_CATCHNG       , "catalog has changed" },
  {AFPERR_DIFFVOL       , "different volume" },
  {AFPERR_EXISTID       , "file already has an id" },
  {AFPERR_NOID          , "file thread not found" },
  {AFPERR_CTNSHRD       , "share point contains a share point" },
  {AFPERR_OLOCK         , "object locked" },
  {AFPERR_VLOCK         , "volume locked" },
  {AFPERR_ITYPE         , "wrong icon type" },
  {AFPERR_NODIR         , "couldn't find directory" },
  {AFPERR_NORENAME      , "can't rename" },
  {AFPERR_SHUTDOWN      , "server is going down" },
  {AFPERR_NFILE         , "too many files open" },
  {AFPERR_BADTYPE       , "object is the wrong type" },
  {AFPERR_NOOP          , "command not supported" },
  {AFPERR_NOTAUTH       , "user not authenticated" },
  {AFPERR_SESSCLOS      , "session closed" },
  {AFPERR_RANGEOVR      , "range overlap" },
  {AFPERR_NORANGE       , "no range lock" },
  {AFPERR_PARAM         , "parameter error" },
  {AFPERR_NOOBJ         , "object not found" },
  {AFPERR_EXIST         , "object already exists" },
  {AFPERR_NOSRVR        , "no response by server at that address" },
  {AFPERR_NLOCK         , "no more locks" },
  {AFPERR_MISC          , "misc. err" },
  {AFPERR_LOCK          , "LockErr" },
  {AFPERR_NOITEM        , "ItemNotFound" },
  {AFPERR_FLATVOL       , "volume doesn't support directories" },
  {AFPERR_BUSY          , "FileBusy" },
  {AFPERR_EOF           , "end of file" },
  {AFPERR_DFULL         , "disk full" },
  {AFPERR_DIRNEMPT      , "directory not empty" },
  {AFPERR_DENYCONF      , "file synchronization locks conflict" },
  {AFPERR_CANTMOVE      , "can't move file" },
  {AFPERR_BITMAP        , "invalid bitmap" },
  {AFPERR_BADVERS       , "bad afp version number" },
  {AFPERR_BADUAM        , "uam doesn't exist" },
  {AFPERR_AUTHCONT      , "logincont" },
  {AFPERR_ACCESS        , "permission denied" },
  {ASPERR_SESSCLOS      , "session closed (ASP)" },
  {ASPERR_NOSESS        , "no more sessions available"},
  {0,                   NULL } };
value_string_ext asp_error_vals_ext = VALUE_STRING_EXT_INIT(asp_error_vals);

/*
 * XXX - do this with an FT_UINT_STRING?
 * Unfortunately, you can't extract from an FT_UINT_STRING the string,
 * which we'd want to do in order to put it into the "Data:" portion.
 *
 * Are these always in the Mac extended character set?
 */
static int dissect_pascal_string(tvbuff_t *tvb, int offset, proto_tree *tree,
                                 int hf_index)
{
  int   len;
  char *tmp;

  len = tvb_get_guint8(tvb, offset);
  offset++;

  if ( tree )
  {
    proto_tree *item;
    proto_tree *subtree;

    /*
     * XXX - if we could do this inside the protocol tree
     * code, we could perhaps avoid allocating and freeing
     * this string buffer.
     */
    tmp  = (gchar*)tvb_get_ephemeral_string(tvb, offset, len);
    item = proto_tree_add_string(tree, hf_index, tvb, offset-1, len+1, tmp);

    subtree = proto_item_add_subtree(item, ett_pstring);
    proto_tree_add_text(subtree, tvb, offset-1, 1, "Length: %d", len);
    proto_tree_add_text(subtree, tvb, offset, len, "Data: %s", tmp);

  }
  offset += len;

  return offset;
}

static void
dissect_rtmp_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree *rtmp_tree;
  proto_item *ti;
  guint8      function;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTMP");
  col_clear(pinfo->cinfo, COL_INFO);

  function = tvb_get_guint8(tvb, 0);

  col_add_str(pinfo->cinfo, COL_INFO,
              val_to_str(function, rtmp_function_vals, "Unknown function (%02x)"));

  if (tree) {
    ti = proto_tree_add_item(tree, proto_rtmp, tvb, 0, 1, ENC_NA);
    rtmp_tree = proto_item_add_subtree(ti, ett_rtmp);

    proto_tree_add_uint(rtmp_tree, hf_rtmp_function, tvb, 0, 1, function);
  }
}

static void
dissect_rtmp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree *rtmp_tree;
  proto_item *ti;
  int         offset = 0;
  guint16     net;
  guint8      nodelen,nodelen_bits;
  guint16     node;             /* might be more than 8 bits */
  int         i;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTMP");
  col_clear(pinfo->cinfo, COL_INFO);

  net = tvb_get_ntohs(tvb, offset);
  nodelen_bits = tvb_get_guint8(tvb, offset+2);
  if ( nodelen_bits <= 8 ) {
    node = tvb_get_guint8(tvb, offset)+1;
    nodelen = 1;
  } else {
    node = tvb_get_ntohs(tvb, offset);
    nodelen = 2;
  }

  col_add_fstr(pinfo->cinfo, COL_INFO, "Net: %u  Node Len: %u  Node: %u",
               net, nodelen_bits, node);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_rtmp, tvb, offset, -1, ENC_NA);
    rtmp_tree = proto_item_add_subtree(ti, ett_rtmp);

    proto_tree_add_uint(rtmp_tree, hf_rtmp_net, tvb, offset, 2, net);
    proto_tree_add_uint(rtmp_tree, hf_rtmp_node_len, tvb, offset+2, 1,
                        nodelen_bits);
    proto_tree_add_uint(rtmp_tree, hf_rtmp_node, tvb, offset+3, nodelen,
                        node);
    offset += 3 + nodelen;

    i = 1;
    while (tvb_offset_exists(tvb, offset)) {
      proto_tree *tuple_item, *tuple_tree;
      guint16 tuple_net;
      guint8 tuple_dist;
      guint16 tuple_range_end;

      tuple_net = tvb_get_ntohs(tvb, offset);
      tuple_dist = tvb_get_guint8(tvb, offset+2);

      if (tuple_dist & 0x80) {
        tuple_range_end = tvb_get_ntohs(tvb, offset+3);
        tuple_item = proto_tree_add_text(rtmp_tree, tvb, offset, 6,
                                         "Tuple %d:  Range Start: %u  Dist: %u  Range End: %u",
                                         i, tuple_net, tuple_dist&0x7F, tuple_range_end);
      } else {
        tuple_item = proto_tree_add_text(rtmp_tree, tvb, offset, 3,
                                         "Tuple %d:  Net: %u  Dist: %u",
                                         i, tuple_net, tuple_dist);
      }
      tuple_tree = proto_item_add_subtree(tuple_item, ett_rtmp_tuple);

      if (tuple_dist & 0x80) {
        proto_tree_add_uint(tuple_tree, hf_rtmp_tuple_range_start, tvb, offset, 2,
                            tuple_net);
      } else {
        proto_tree_add_uint(tuple_tree, hf_rtmp_tuple_net, tvb, offset, 2,
                            tuple_net);
      }
      proto_tree_add_uint(tuple_tree, hf_rtmp_tuple_dist, tvb, offset+2, 1,
                          tuple_dist & 0x7F);

      if (tuple_dist & 0x80) {
        /*
         * Extended network tuple.
         */
        proto_tree_add_item(tuple_tree, hf_rtmp_tuple_range_end, tvb, offset+3, 2,
                            ENC_BIG_ENDIAN);
        offset += 6;
      } else
        offset += 3;

      i++;
    }
  }
}

static void
dissect_nbp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree *nbp_tree;
  proto_tree *nbp_info_tree;
  proto_item *ti, *info_item;
  int         offset = 0;
  guint8      info;
  guint       op, count;
  guint       i;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBP");
  col_clear(pinfo->cinfo, COL_INFO);

  info  = tvb_get_guint8(tvb, offset);
  op    = info >> 4;
  count = info & 0x0F;

  col_add_fstr(pinfo->cinfo, COL_INFO, "Op: %s  Count: %u",
    val_to_str(op, nbp_op_vals, "Unknown (0x%01x)"), count);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_nbp, tvb, offset, -1, ENC_NA);
    nbp_tree = proto_item_add_subtree(ti, ett_nbp);

    info_item = proto_tree_add_uint_format(nbp_tree, hf_nbp_info, tvb, offset, 1,
                info,
                "Info: 0x%01X  Operation: %s  Count: %u", info,
                val_to_str(op, nbp_op_vals, "Unknown (0x%01X)"),
                count);
    nbp_info_tree = proto_item_add_subtree(info_item, ett_nbp_info);
    proto_tree_add_uint(nbp_info_tree, hf_nbp_op, tvb, offset, 1, info);
    proto_tree_add_uint(nbp_info_tree, hf_nbp_count, tvb, offset, 1, info);
    proto_tree_add_item(nbp_tree, hf_nbp_tid, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    offset += 2;

    for (i = 0; i < count; i++) {
      proto_tree *node_item,*node_tree;
      int soffset = offset;

      node_item = proto_tree_add_text(nbp_tree, tvb, offset, -1,
                                      "Node %u", i+1);
      node_tree = proto_item_add_subtree(node_item, ett_nbp_node);

      proto_tree_add_item(node_tree, hf_nbp_node_net, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(node_tree, hf_nbp_node_node, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(node_tree, hf_nbp_node_port, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(node_tree, hf_nbp_node_enum, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;

      offset = dissect_pascal_string(tvb, offset, node_tree, hf_nbp_node_object);
      offset = dissect_pascal_string(tvb, offset, node_tree, hf_nbp_node_type);
      offset = dissect_pascal_string(tvb, offset, node_tree, hf_nbp_node_zone);

      proto_item_set_len(node_item, offset-soffset);
    }
  }

  return;
}

/* -----------------------------
   ATP protocol cf. inside appletalk chap. 9
   desegmentation from packet-ieee80211.c
*/
static void
dissect_atp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree      *atp_tree      = NULL;
  proto_item      *ti;
  proto_tree      *atp_info_tree;
  proto_item      *info_item;
  int              offset        = 0;
  guint8           ctrlinfo;
  guint8           frag_number   = 0;
  guint            op;
  guint16          tid;
  guint8           query;
  struct aspinfo   aspinfo;
  tvbuff_t        *new_tvb       = NULL;
  gboolean         save_fragmented;
  gboolean         more_fragment = FALSE;
  int              len;
  guint8           bitmap;
  guint8           nbe           = 0;
  guint8           t             = 0;
  conversation_t  *conversation;
  asp_request_val *request_val   = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATP");

  ctrlinfo = tvb_get_guint8(tvb, offset);
  bitmap   = tvb_get_guint8(tvb, offset +1);
  tid      = tvb_get_ntohs(tvb, offset +2);

  t = bitmap;
  while(t) {
    nbe++;
    t >>= 1;
  }

  op = ctrlinfo >> 6;

  aspinfo.reply   = (0x80 == (ctrlinfo & ATP_FUNCMASK))?1:0;
  aspinfo.release = (0xC0 == (ctrlinfo & ATP_FUNCMASK))?1:0;
  aspinfo.seq = tid;
  aspinfo.code = 0;
  query = (!aspinfo.reply && !aspinfo.release);

  conversation = find_or_create_conversation(pinfo);

  if (atp_defragment) {
    asp_request_key request_key;

    request_key.conversation = conversation->index;
    memcpy(request_key.src, (!aspinfo.reply)?pinfo->src.data:pinfo->dst.data, 4);
    request_key.seq = aspinfo.seq;

    request_val = (asp_request_val *) g_hash_table_lookup(atp_request_hash, &request_key);

    if (!request_val && query && nbe > 1)  {
      asp_request_key *new_request_key;

      /* only save nbe packets if more than 1 requested
         save some memory and help the defragmentation if tid wraparound, ie
         we have both a request for 1 packet and a request for n packets,
         hopefully most of the time ATP_EOM will be set in the last packet.
      */
      new_request_key = se_alloc(sizeof(asp_request_key));
      *new_request_key = request_key;

      request_val = se_alloc(sizeof(asp_request_val));
      request_val->value = nbe;

      g_hash_table_insert(atp_request_hash, new_request_key,request_val);
    }
  }

  /*
    ATP_EOM is not mandatory. Some implementations don't always set it
    if the query is only one packet.

    So it needs to keep the number of packets asked in request.
  */

  if (aspinfo.reply) {
    more_fragment = !(ATP_EOM & ctrlinfo) && request_val;
    frag_number = bitmap;
  }

  col_clear(pinfo->cinfo, COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "%s transaction %u",
               val_to_str(op, atp_function_vals, "Unknown (0x%01x)"),tid);
  if (more_fragment)
    col_append_str(pinfo->cinfo, COL_INFO, " [fragment]");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_atp, tvb, offset, -1, ENC_NA);
    atp_tree = proto_item_add_subtree(ti, ett_atp);
    proto_item_set_len(atp_tree, aspinfo.release?8:ATP_HDRSIZE -1);

    info_item = proto_tree_add_item(atp_tree, hf_atp_ctrlinfo, tvb, offset, 1, ENC_BIG_ENDIAN);
    atp_info_tree = proto_item_add_subtree(info_item, ett_atp_info);

    proto_tree_add_item(atp_info_tree, hf_atp_function, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(atp_info_tree, hf_atp_xo, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(atp_info_tree, hf_atp_eom, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(atp_info_tree, hf_atp_sts, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((ctrlinfo & (ATP_FUNCMASK|ATP_XO)) == (0x40|ATP_XO)) {
      /* TReq with XO set */
      proto_tree_add_item(atp_info_tree, hf_atp_treltimer, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    if (query) {
      proto_tree_add_text(atp_tree, tvb, offset +1, 1,
                          "Bitmap: 0x%02x  %u packet(s) max", bitmap, nbe);
    }
    else {
      proto_tree_add_item(atp_tree, hf_atp_bitmap, tvb, offset +1, 1, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(atp_tree, hf_atp_tid, tvb, offset +2, 2, ENC_BIG_ENDIAN);

    if (aspinfo.release)
      proto_tree_add_item(atp_tree, hf_atp_user_bytes, tvb, offset +4, 4, ENC_BIG_ENDIAN);

  }

  if (aspinfo.release)
    return;

  save_fragmented = pinfo->fragmented;

  /* FIXME
     asp doesn't fit very well here
     move asp back in atp?
  */
  if (atp_defragment && aspinfo.reply && (more_fragment || frag_number != 0)) {
    fragment_data *fd_head;
    int hdr;

    hdr = ATP_HDRSIZE -1;
    if (frag_number != 0)
      hdr += 4; /* asp header */
    len = tvb_reported_length_remaining(tvb, hdr);
    fd_head = fragment_add_seq_check(tvb, hdr, pinfo, tid,
                                     atp_fragment_table,
                                     atp_reassembled_table,
                                     frag_number,
                                     len,
                                     more_fragment);
    new_tvb = process_reassembled_data(tvb, ATP_HDRSIZE -1, pinfo,
                                       "Reassembled ATP", fd_head, &atp_frag_items,
                                       NULL, atp_tree);
  }
  else {
    /* full packet */
    new_tvb = tvb_new_subset_remaining(tvb, ATP_HDRSIZE -1 );
  }

  if (new_tvb) {
    void* pd_save;
    pd_save = pinfo->private_data;
    pinfo->private_data = &aspinfo;
    /* if port == 6 it's not an ASP packet but a ZIP packet */
    if (pinfo->srcport == 6 || pinfo->destport == 6 )
      call_dissector(zip_atp_handle, new_tvb, pinfo, tree);
    else {
      /* XXX need a conversation_get_dissector function ? */
      if (!aspinfo.reply && !conversation->dissector_handle) {
        dissector_handle_t sub;

        /* if it's a known ASP function call ASP dissector
           else assume it's a PAP connection ID.
           the test is wrong because PAP conn IDs overlapped with ASP fn
           but I don't want to keep track of NBP msgs and open connection
           port allocation.
        */
        guint8 fn = tvb_get_guint8(new_tvb, 0);

        if (!fn || fn > ASPFUNC_ATTN) {
          sub = pap_handle;
        }
        else {
          sub = asp_handle;
        }
        call_dissector(sub, new_tvb, pinfo, tree);
        conversation_set_dissector(conversation, sub);
      }
      else if (!try_conversation_dissector(&pinfo->src, &pinfo->dst, pinfo->ptype,
                                           pinfo->srcport, pinfo->destport, new_tvb,pinfo, tree)) {
        call_dissector(data_handle, new_tvb, pinfo, tree);

      }
    }
    pinfo->private_data = pd_save;
  }
  else {
    /* Just show this as a fragment. */
    new_tvb = tvb_new_subset_remaining (tvb, ATP_HDRSIZE -1);
    call_dissector(data_handle, new_tvb, pinfo, tree);
  }
  pinfo->fragmented = save_fragmented;
  return;
}

/*
  copy and paste from dsi
  XXX - is the format of this reply dependent on the type of server,
  with this format being the format for AFP servers?
*/
static gint
dissect_asp_reply_get_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
  proto_tree *sub_tree;
  proto_item *ti;

  guint16     ofs;
  guint16     flag;
  guint16     machine_ofs;
  guint16     sign_ofs = 0;
  guint16     adr_ofs  = 0;
  guint16     dir_ofs  = 0;
  guint16     utf_ofs  = 0;
  guint8      nbe;
  guint       len;
  guint       i;

  proto_tree *adr_tree;
  char       *tmp;
  guint16     net;
  guint8      node;
  guint16     port;

  guint16     ulen;

  if (!tree)
    return offset;

  ti = proto_tree_add_text(tree, tvb, offset, -1, "Get Status");
  tree = proto_item_add_subtree(ti, ett_asp_status);

  machine_ofs = tvb_get_ntohs(tvb, offset +AFPSTATUS_MACHOFF);
  proto_tree_add_text(tree, tvb, offset +AFPSTATUS_MACHOFF, 2, "Machine offset: %u", machine_ofs);
  if (machine_ofs)
    machine_ofs += offset;

  ofs = tvb_get_ntohs(tvb, offset +AFPSTATUS_VERSOFF);
  proto_tree_add_text(tree, tvb, offset +AFPSTATUS_VERSOFF, 2, "Version offset: %u", ofs);

  ofs = tvb_get_ntohs(tvb, offset +AFPSTATUS_UAMSOFF);
  proto_tree_add_text(tree, tvb, offset +AFPSTATUS_UAMSOFF, 2, "UAMS offset: %u", ofs);

  ofs = tvb_get_ntohs(tvb, offset +AFPSTATUS_ICONOFF);
  proto_tree_add_text(tree, tvb, offset +AFPSTATUS_ICONOFF, 2, "Icon offset: %u", ofs);

  ofs = offset +AFPSTATUS_FLAGOFF;
  ti = proto_tree_add_item(tree, hf_asp_server_flag, tvb, ofs, 2, ENC_BIG_ENDIAN);
  sub_tree = proto_item_add_subtree(ti, ett_asp_status_server_flag);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_copyfile      , tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_passwd        , tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_no_save_passwd, tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_srv_msg       , tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_srv_sig       , tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_tcpip         , tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_notify        , tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_reconnect     , tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_directory     , tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_utf8_name     , tvb, ofs, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(sub_tree, hf_asp_server_flag_fast_copy     , tvb, ofs, 2, ENC_BIG_ENDIAN);

  proto_tree_add_item(tree, hf_asp_server_name, tvb, offset +AFPSTATUS_PRELEN, 1, ENC_ASCII|ENC_NA);

  flag = tvb_get_ntohs(tvb, ofs);
  if ((flag & AFPSRVRINFO_SRVSIGNATURE)) {
    ofs = offset +AFPSTATUS_PRELEN +tvb_get_guint8(tvb, offset +AFPSTATUS_PRELEN) +1;
    if ((ofs & 1))
      ofs++;

    sign_ofs = tvb_get_ntohs(tvb, ofs);
    proto_tree_add_text(tree, tvb, ofs, 2, "Signature offset: %u", sign_ofs);
    sign_ofs += offset;
    ofs += 2;

    if ((flag & AFPSRVRINFO_TCPIP) && ofs < machine_ofs ) {
      adr_ofs =  tvb_get_ntohs(tvb, ofs);
      proto_tree_add_text(tree, tvb, ofs, 2, "Network address offset: %u", adr_ofs);
      adr_ofs += offset;
      ofs += 2;
    }

    if ((flag & AFPSRVRINFO_SRVDIRECTORY) && ofs < machine_ofs) {
      dir_ofs =  tvb_get_ntohs(tvb, ofs);
      proto_tree_add_text(tree, tvb, ofs, 2, "Directory services offset: %u", dir_ofs);
      dir_ofs += offset;
      ofs += 2;
    }

    if ((flag & AFPSRVRINFO_SRVUTF8) && ofs < machine_ofs) {
      utf_ofs =  tvb_get_ntohs(tvb, ofs);
      proto_tree_add_text(tree, tvb, ofs, 2, "UTF-8 Server name offset: %u", utf_ofs);
      utf_ofs += offset;
    }
  }

  if (machine_ofs)
    proto_tree_add_item(tree, hf_asp_server_type, tvb, machine_ofs, 1, ENC_ASCII|ENC_NA);

  ofs = offset +tvb_get_ntohs(tvb, offset +AFPSTATUS_VERSOFF);
  if (ofs) {
    nbe = tvb_get_guint8(tvb, ofs);
    ti = proto_tree_add_text(tree, tvb, ofs, 1, "Version list: %u", nbe);
    ofs++;
    sub_tree = proto_item_add_subtree(ti, ett_asp_vers);
    for (i = 0; i < nbe; i++) {
      len = tvb_get_guint8(tvb, ofs);
      proto_tree_add_item(sub_tree, hf_asp_server_vers, tvb, ofs, 1, ENC_ASCII|ENC_NA);
      ofs += len + 1;
    }
  }

  ofs = offset +tvb_get_ntohs(tvb, offset +AFPSTATUS_UAMSOFF);
  if (ofs) {
    nbe = tvb_get_guint8(tvb, ofs);
    ti = proto_tree_add_text(tree, tvb, ofs, 1, "UAMS list: %u", nbe);
    ofs++;
    sub_tree = proto_item_add_subtree(ti, ett_asp_uams);
    for (i = 0; i < nbe; i++) {
      len = tvb_get_guint8(tvb, ofs);
      proto_tree_add_item(sub_tree, hf_asp_server_uams, tvb, ofs, 1, ENC_ASCII|ENC_NA);
      ofs += len + 1;
    }
  }

  ofs = offset +tvb_get_ntohs(tvb, offset +AFPSTATUS_ICONOFF);
  if (ofs)
    proto_tree_add_item(tree, hf_asp_server_icon, tvb, ofs, 256, ENC_NA);

  if (sign_ofs) {
    proto_tree_add_item(tree, hf_asp_server_signature, tvb, sign_ofs, 16, ENC_NA);
  }

  if (adr_ofs) {

    ofs = adr_ofs;
    nbe = tvb_get_guint8(tvb, ofs);
    ti = proto_tree_add_text(tree, tvb, ofs, 1, "Address list: %u", nbe);
    ofs++;
    adr_tree = proto_item_add_subtree(ti, ett_asp_addr);
    for (i = 0; i < nbe; i++) {
      guint8 type;

      len = tvb_get_guint8(tvb, ofs);
      type =  tvb_get_guint8(tvb, ofs +1);
      switch (type) {
      case 1:   /* IP */
        ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "ip %s", tvb_ip_to_str(tvb, ofs+2));
        break;
      case 2: /* IP + port */
        port = tvb_get_ntohs(tvb, ofs+6);
        ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "ip %s:%u",
                                 tvb_ip_to_str(tvb, ofs+2), port);
        break;
      case 3: /* DDP, atalk_addr_to_str want host order not network */
        net  = tvb_get_ntohs(tvb, ofs+2);
        node = tvb_get_guint8(tvb, ofs +4);
        port = tvb_get_guint8(tvb, ofs +5);
        ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "ddp %u.%u:%u",
                                 net, node, port);
        break;
      case 5: /* IP + port ssh tunnel */
        port = tvb_get_ntohs(tvb, ofs+6);
        ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "ip (ssh tunnel) %s:%u",
                                 tvb_ip_to_str(tvb, ofs+2), port);
        break;
      case 4: /* DNS */
        if (len > 2) {
          tmp = (gchar*)tvb_get_ephemeral_string(tvb, ofs +2, len -2);
          ti = proto_tree_add_text(adr_tree, tvb, ofs, len, "dns %s", tmp);
          break;
        }
        /* else fall to default malformed record */
      default:
        ti = proto_tree_add_text(adr_tree, tvb, ofs, len,"Unknown type : %u", type);
        break;
      }
      len -= 2;
      sub_tree = proto_item_add_subtree(ti,ett_asp_addr_line);
      proto_tree_add_item(sub_tree, hf_asp_server_addr_len, tvb, ofs, 1, ENC_BIG_ENDIAN);
      ofs++;
      proto_tree_add_item(sub_tree, hf_asp_server_addr_type, tvb, ofs, 1, ENC_BIG_ENDIAN);
      ofs++;
      proto_tree_add_item(sub_tree, hf_asp_server_addr_value,tvb, ofs, len, ENC_NA);
      ofs += len;
    }
  }

  if (dir_ofs) {
    ofs = dir_ofs;
    nbe = tvb_get_guint8(tvb, ofs);
    ti = proto_tree_add_text(tree, tvb, ofs, 1, "Directory services list: %u", nbe);
    ofs++;
    sub_tree = proto_item_add_subtree(ti, ett_asp_directory);
    for (i = 0; i < nbe; i++) {
      len = tvb_get_guint8(tvb, ofs);
      proto_tree_add_item(sub_tree, hf_asp_server_directory, tvb, ofs, 1, ENC_ASCII|ENC_NA);
      ofs += len + 1;
    }
  }
  if (utf_ofs) {

    ofs = utf_ofs;
    ulen = tvb_get_ntohs(tvb, ofs);
    tmp = (gchar*)tvb_get_ephemeral_string(tvb, ofs + 2, ulen);
    ti = proto_tree_add_text(tree, tvb, ofs, ulen +2, "UTF8 server name: %s", tmp);
    sub_tree = proto_item_add_subtree(ti, ett_asp_utf8_name);
    proto_tree_add_uint(sub_tree, hf_asp_server_utf8_name_len, tvb, ofs, 2, ulen);
    ofs += 2;
    proto_tree_add_string(sub_tree, hf_asp_server_utf8_name, tvb, ofs, ulen, tmp);
    ofs += ulen;
  }
  return ofs;
}

/* -----------------------------
   PAP protocol cf. inside appletalk chap. 10
*/
#define PAD(x)      { proto_tree_add_item(pap_tree, hf_pap_pad, tvb, offset,  x, ENC_NA); offset += x; }

static int
dissect_pap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int         offset   = 0;
  guint8      fn;
  guint8      connID;
  proto_tree *pap_tree = NULL;
  proto_item *ti;
  int         len;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PAP");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_pap, tvb, offset, -1, ENC_NA);
    pap_tree = proto_item_add_subtree(ti, ett_pap);
  }

  connID = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(pap_tree, hf_pap_connid, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  fn = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(pap_tree, hf_pap_function, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s  ID: %d",
               val_to_str_ext(fn, &pap_function_vals_ext, "Unknown (0x%01x)"), connID);

  switch(fn) {
  case PAPOpenConn:
    PAD(2);
    proto_tree_add_item(pap_tree, hf_pap_socket, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(pap_tree, hf_pap_quantum, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(pap_tree, hf_pap_waittime, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;

  case PAPOpenConnReply:
    PAD(2);
    proto_tree_add_item(pap_tree, hf_pap_socket, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(pap_tree, hf_pap_quantum, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(pap_tree, hf_pap_result, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    offset = dissect_pascal_string(tvb, offset, pap_tree, hf_pap_status);
    break;

  case PAPSendData:
    proto_tree_add_item(pap_tree, hf_pap_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;

  case PAPData:
    proto_tree_add_item(pap_tree, hf_pap_eof, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    PAD(1);
    /* follow by data */
    len = tvb_reported_length_remaining(tvb,offset);
    call_dissector(data_handle,tvb_new_subset(tvb, offset,-1,len), pinfo, tree);
    break;

  case PAPTickle:
  case PAPCloseConn:
  case PAPCloseConnReply:
    PAD(2);
    break;

  case PAPSendStatus:
    PAD(2);
    break;

  case PAPStatus:
    PAD(2);
    PAD(4);
    offset = dissect_pascal_string(tvb, offset, pap_tree, hf_pap_status);
    break;

  default:  /* unknown */
    break;
  }
  return offset;
}

/* -----------------------------
   ASP protocol cf. inside appletalk chap. 11
*/
static struct aspinfo *
get_transaction(tvbuff_t *tvb, packet_info *pinfo)
{
  struct aspinfo  *aspinfo = pinfo->private_data;
  conversation_t  *conversation;
  asp_request_key  request_key, *new_request_key;
  asp_request_val *request_val;
  guint8           fn;

  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
                                   pinfo->srcport, pinfo->destport, 0);

  if (conversation == NULL)
  {
    conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                    pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
  }

  request_key.conversation = conversation->index;
  memcpy(request_key.src, (!aspinfo->reply)?pinfo->src.data:pinfo->dst.data, 4);
  request_key.seq = aspinfo->seq;

  request_val = (asp_request_val *) g_hash_table_lookup(asp_request_hash, &request_key);
  if (!request_val && !aspinfo->reply )  {
    fn = tvb_get_guint8(tvb, 0);
    new_request_key = se_alloc(sizeof(asp_request_key));
    *new_request_key = request_key;

    request_val = se_alloc(sizeof(asp_request_val));
    request_val->value = fn;

    g_hash_table_insert(asp_request_hash, new_request_key, request_val);
  }

  if (!request_val)
    return NULL;

  aspinfo->command = request_val->value;
  return aspinfo;
}


static int
dissect_asp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct aspinfo *aspinfo;
  int             offset   = 0;
  proto_tree     *asp_tree = NULL;
  proto_item     *ti;
  guint8          fn;
  int             len;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ASP");
  col_clear(pinfo->cinfo, COL_INFO);

  aspinfo = get_transaction(tvb, pinfo);
  if (!aspinfo)
     return 0;

  fn = (guint8) aspinfo->command;

  if (aspinfo->reply)
    col_add_fstr(pinfo->cinfo, COL_INFO, "Reply tid %u",aspinfo->seq);
  else
    col_add_fstr(pinfo->cinfo, COL_INFO, "Function: %s  tid %u",
                 val_to_str_ext(fn, &asp_func_vals_ext, "Unknown (0x%01x)"), aspinfo->seq);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_asp, tvb, offset, -1, ENC_NA);
    asp_tree = proto_item_add_subtree(ti, ett_asp);
  }
  if (!aspinfo->reply) {
    tvbuff_t   *new_tvb;
    /* let the called deal with asp_tree == NULL */

    proto_tree_add_item(asp_tree, hf_asp_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    switch(fn) {
    case ASPFUNC_OPEN:
      proto_tree_add_item(asp_tree, hf_asp_socket, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_version, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
    case ASPFUNC_TICKLE:
    case ASPFUNC_CLOSE:
      proto_tree_add_item(asp_tree, hf_asp_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_zero_value, tvb, offset, 2, ENC_NA);
      offset +=2;
      break;
    case ASPFUNC_STAT:
      proto_tree_add_item(asp_tree, hf_asp_zero_value, tvb, offset, 1, ENC_NA);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_zero_value, tvb, offset, 2, ENC_NA);
      offset += 2;
      break;
    case ASPFUNC_ATTN:
      proto_tree_add_item(asp_tree, hf_asp_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_attn_code, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset +=2;
      break;
    case ASPFUNC_CMD:
    case ASPFUNC_WRITE:
      proto_item_set_len(asp_tree, 4);
      proto_tree_add_item(asp_tree, hf_asp_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      len = tvb_reported_length_remaining(tvb,offset);
      new_tvb = tvb_new_subset(tvb, offset,-1,len);
      call_dissector(afp_handle, new_tvb, pinfo, tree);
      break;
    case ASPFUNC_WRTCONT:
      proto_tree_add_item(asp_tree, hf_asp_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(asp_tree, hf_asp_size, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
    default:
      proto_item_set_len(asp_tree, 4);
      offset += 3;
      len = tvb_reported_length_remaining(tvb,offset);
      call_dissector(data_handle,tvb_new_subset(tvb, offset,-1,len), pinfo, tree);
      break;
    }
  }
  else {
    tvbuff_t   *new_tvb;

    proto_tree_add_uint(asp_tree, hf_asp_func, tvb, 0, 0, fn);
    switch(fn) {
    case ASPFUNC_OPEN:
      proto_tree_add_item(asp_tree, hf_asp_socket, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_init_error, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
    case ASPFUNC_CLOSE:
      proto_tree_add_item(asp_tree, hf_asp_zero_value, tvb, offset, 1, ENC_NA);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_zero_value, tvb, offset, 1, ENC_NA);
      offset++;
      proto_tree_add_item(asp_tree, hf_asp_zero_value, tvb, offset, 2, ENC_NA);
      offset += 2;
      break;
    case ASPFUNC_STAT:
      proto_tree_add_item(asp_tree, hf_asp_zero_value, tvb, offset, 4, ENC_NA);
      offset += 4;
      dissect_asp_reply_get_status(tvb, pinfo, asp_tree, offset);
      break;
    case ASPFUNC_CMD:
    case ASPFUNC_WRITE:
      proto_item_set_len(asp_tree, 4);
      aspinfo->code = tvb_get_ntohl(tvb, offset);
      proto_tree_add_item(asp_tree, hf_asp_error, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      len = tvb_reported_length_remaining(tvb,offset);
      new_tvb = tvb_new_subset(tvb, offset,-1,len);
      call_dissector(afp_handle, new_tvb, pinfo, tree);
      break;
    case ASPFUNC_TICKLE:
    case ASPFUNC_WRTCONT:
      proto_tree_add_item(asp_tree, hf_asp_zero_value, tvb, offset, 4, ENC_NA);
      /* fall */
    case ASPFUNC_ATTN:  /* FIXME capture and spec disagree */
    default:
      proto_item_set_len(asp_tree, 4);
      offset += 4;
      len = tvb_reported_length_remaining(tvb,offset);
      call_dissector(data_handle,tvb_new_subset(tvb, offset,-1,len), pinfo, tree);
      break;
    }
  }
  return offset;
}

/* -----------------------------
   ZIP protocol cf. inside appletalk chap. 8
*/
static void
dissect_atp_zip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct aspinfo *aspinfo;
  int             offset = 0;
  proto_tree     *zip_tree;
  proto_tree     *sub_tree;
  proto_item     *ti;
  guint8          fn;
  guint16         count;
  guint8          len;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZIP");
  col_clear(pinfo->cinfo, COL_INFO);

  aspinfo = get_transaction(tvb, pinfo);
  if (!aspinfo)
     return;

  fn = (guint8) aspinfo->command;

  if (aspinfo->reply)
    col_add_fstr(pinfo->cinfo, COL_INFO, "Reply tid %u",aspinfo->seq);
  else
    col_add_fstr(pinfo->cinfo, COL_INFO, "Function: %s  tid %u",
                 val_to_str(fn, zip_atp_function_vals, "Unknown (0x%01x)"), aspinfo->seq);

  if (!tree)
    return;

  ti = proto_tree_add_item(tree, proto_zip, tvb, offset, -1, ENC_NA);
  zip_tree = proto_item_add_subtree(ti, ett_zip);

  if (!aspinfo->reply) {
    proto_tree_add_item(zip_tree, hf_zip_atp_function, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    switch(fn) {
    case 7:     /* start_index = 0 */
    case 8:
    case 9:
      proto_tree_add_item(zip_tree, hf_zip_zero_value, tvb, offset, 1, ENC_NA);
      offset++;
      proto_tree_add_item(zip_tree, hf_zip_start_index, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    }
  }
  else {
    guint i;

    proto_tree_add_uint(zip_tree, hf_zip_atp_function, tvb, 0, 0, fn);
    switch(fn) {
    case 7:
    case 8:
    case 9:
      proto_tree_add_item(zip_tree, hf_zip_last_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;

      proto_tree_add_item(zip_tree, hf_zip_zero_value, tvb, offset, 1, ENC_NA);
      offset++;
      count = tvb_get_ntohs(tvb, offset);
      ti = proto_tree_add_item(zip_tree, hf_zip_count, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      sub_tree = proto_item_add_subtree(ti, ett_zip_zones_list);
      for (i = 0; i < count; i++) {
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_tree, hf_zip_zone_name, tvb, offset, 1,ENC_ASCII|ENC_NA);
        offset += len +1;
      }
      break;
    }
  }
}

static void
dissect_ddp_zip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *zip_tree = NULL;
  proto_item *ti;
  guint8      fn;
  guint8      len;
  gint        offset   = 0;
  proto_tree *flag_tree;
  proto_tree *sub_tree;
  proto_tree *net_tree;
  guint8      flag;
  guint16     net;
  guint       i;
  guint       count;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZIP");
  col_clear(pinfo->cinfo, COL_INFO);

  fn = tvb_get_guint8(tvb, 0);
  col_add_str(pinfo->cinfo, COL_INFO,
              val_to_str_ext(fn, &zip_function_vals_ext, "Unknown ZIP function (%02x)"));

  if (!tree)
    return;

  ti = proto_tree_add_item(tree, proto_zip, tvb, 0, -1, ENC_NA);
  zip_tree = proto_item_add_subtree(ti, ett_zip);

  proto_tree_add_item(zip_tree, hf_zip_function, tvb, offset, 1,ENC_BIG_ENDIAN);
  offset++;
  /* fn 1,7,2,8 are not tested */
  switch (fn) {
  case 1: /* Query */
    count = tvb_get_guint8(tvb, offset);
    ti    = proto_tree_add_item(zip_tree, hf_zip_network_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    sub_tree = proto_item_add_subtree(ti, ett_zip_network_list);
    for (i = 0; i < count; i++) {
      proto_tree_add_item(sub_tree, hf_zip_network, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
    break;
  case 7: /* Notify */
    flag = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_text(zip_tree, tvb, offset , 1,"Flags : 0x%02x", flag);
    flag_tree = proto_item_add_subtree(ti, ett_zip_flags);
    proto_tree_add_item(flag_tree, hf_zip_flags_zone_invalid, tvb, offset, 1,ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_zip_flags_use_broadcast,tvb, offset, 1,ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_zip_flags_only_one_zone,tvb, offset, 1,ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(zip_tree, hf_zip_zero_value, tvb, offset, 4, ENC_NA);
    offset += 4;

    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(zip_tree, hf_zip_zone_name, tvb, offset, 1,ENC_ASCII|ENC_NA);
    offset += len +1;

    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(zip_tree, hf_zip_multicast_length,tvb, offset, 1,ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(zip_tree, hf_zip_multicast_address,tvb, offset, len,ENC_NA);
    offset += len;

    proto_tree_add_item(zip_tree, hf_zip_zone_name, tvb, offset, 1,ENC_ASCII|ENC_NA);
    break;

  case 2: /* Reply */
  case 8: /* Extended Reply */
    count = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_item(zip_tree, hf_zip_network_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    sub_tree = proto_item_add_subtree(ti, ett_zip_network_list);
    for (i = 0; i < count; i++) {
      net = tvb_get_ntohs(tvb, offset);
      ti = proto_tree_add_text(sub_tree, tvb, offset , 2, "Zone for network : %u", net);
      net_tree = proto_item_add_subtree(ti, ett_zip_network_list);
      proto_tree_add_item(net_tree, hf_zip_network, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      len = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(net_tree, hf_zip_zone_name, tvb, offset, 1,ENC_ASCII|ENC_NA);
      offset += len +1;
    }
    break;

  case 5 :  /* GetNetInfo request */
    proto_tree_add_item(zip_tree, hf_zip_zero_value, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(zip_tree, hf_zip_zero_value, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(zip_tree, hf_zip_zone_name, tvb, offset, 1,ENC_ASCII|ENC_NA);
    break;

  case 6 :  /* GetNetInfo reply */
    flag = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_text(zip_tree, tvb, offset , 1,"Flags : 0x%02x", flag);
    flag_tree = proto_item_add_subtree(ti, ett_zip_flags);
    proto_tree_add_item(flag_tree, hf_zip_flags_zone_invalid, tvb, offset, 1,ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_zip_flags_use_broadcast,tvb, offset, 1,ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_zip_flags_only_one_zone,tvb, offset, 1,ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(zip_tree, hf_zip_network_start, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(zip_tree, hf_zip_network_end, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(zip_tree, hf_zip_zone_name, tvb, offset, 1,ENC_ASCII|ENC_NA);
    offset += len +1;

    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(zip_tree, hf_zip_multicast_length,tvb, offset, 1,ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(zip_tree, hf_zip_multicast_address,tvb, offset, len,ENC_NA);
    offset += len;
    if ((flag & 0x80) != 0)
      proto_tree_add_item(zip_tree, hf_zip_default_zone, tvb, offset, 1,ENC_ASCII|ENC_NA);
    break;

  default:
    break;
  }
}

static void
dissect_ddp_short(tvbuff_t *tvb, packet_info *pinfo, guint8 dnode,
                  guint8 snode, proto_tree *tree)
{
  guint16                       len;
  guint8                        dport;
  guint8                        sport;
  guint8                        type;
  proto_tree                   *ddp_tree = NULL;
  proto_item                   *ti, *hidden_item;
  static struct atalk_ddp_addr  src, dst;
  tvbuff_t                     *new_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DDP");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_ddp, tvb, 0, DDP_SHORT_HEADER_SIZE,
                             ENC_NA);
    ddp_tree = proto_item_add_subtree(ti, ett_ddp);
  }
  len = tvb_get_ntohs(tvb, 0);
  if (tree)
    proto_tree_add_uint(ddp_tree, hf_ddp_len, tvb, 0, 2, len);
  dport = tvb_get_guint8(tvb, 2);
  if (tree)
    proto_tree_add_uint(ddp_tree, hf_ddp_dst_socket, tvb, 2, 1, dport);
  sport = tvb_get_guint8(tvb, 3);
  if (tree)
    proto_tree_add_uint(ddp_tree, hf_ddp_src_socket, tvb, 3, 1, sport);
  type = tvb_get_guint8(tvb, 4);

  src.net = 0;
  src.node = snode;
  dst.net = 0;
  dst.node = dnode;
  SET_ADDRESS(&pinfo->net_src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->net_dst, AT_ATALK, sizeof dst, (guint8 *)&dst);
  SET_ADDRESS(&pinfo->dst, AT_ATALK, sizeof dst, (guint8 *)&dst);

  pinfo->ptype = PT_DDP;
  pinfo->destport = dport;
  pinfo->srcport = sport;

  col_add_str(pinfo->cinfo, COL_INFO,
              val_to_str_ext(type, &op_vals_ext, "Unknown DDP protocol (%02x)"));

  if (tree) {
    hidden_item = proto_tree_add_string(ddp_tree, hf_ddp_src, tvb,
                                        4, 3, atalk_addr_to_str(&src));
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_string(ddp_tree, hf_ddp_dst, tvb,
                                        6, 3, atalk_addr_to_str(&dst));
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    proto_tree_add_uint(ddp_tree, hf_ddp_type, tvb, 4, 1, type);
  }
  new_tvb = tvb_new_subset_remaining(tvb, DDP_SHORT_HEADER_SIZE);

  if (!dissector_try_uint(ddp_dissector_table, type, new_tvb, pinfo, tree))
    call_dissector(data_handle,new_tvb, pinfo, tree);
}

static void
dissect_ddp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  e_ddp                         ddp;
  proto_tree                   *ddp_tree;
  proto_item                   *ti, *hidden_item;
  static struct atalk_ddp_addr  src, dst;
  tvbuff_t                     *new_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DDP");
  col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&ddp, 0, sizeof(e_ddp));
  ddp.dnet=g_ntohs(ddp.dnet);
  ddp.snet=g_ntohs(ddp.snet);
  ddp.sum=g_ntohs(ddp.sum);
  ddp.hops_len=g_ntohs(ddp.hops_len);

  src.net = ddp.snet;
  src.node = ddp.snode;
  dst.net = ddp.dnet;
  dst.node = ddp.dnode;
  SET_ADDRESS(&pinfo->net_src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->net_dst, AT_ATALK, sizeof dst, (guint8 *)&dst);
  SET_ADDRESS(&pinfo->dst, AT_ATALK, sizeof dst, (guint8 *)&dst);

  pinfo->ptype = PT_DDP;
  pinfo->destport = ddp.dport;
  pinfo->srcport = ddp.sport;

  col_add_str(pinfo->cinfo, COL_INFO,
    val_to_str_ext(ddp.type, &op_vals_ext, "Unknown DDP protocol (%02x)"));

  if (tree) {
    ti = proto_tree_add_item(tree, proto_ddp, tvb, 0, DDP_HEADER_SIZE,
                             ENC_NA);
    ddp_tree = proto_item_add_subtree(ti, ett_ddp);

    hidden_item = proto_tree_add_string(ddp_tree, hf_ddp_src, tvb,
                                        4, 3, atalk_addr_to_str(&src));
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    hidden_item = proto_tree_add_string(ddp_tree, hf_ddp_dst, tvb,
                                        6, 3, atalk_addr_to_str(&dst));
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    proto_tree_add_uint(ddp_tree, hf_ddp_hopcount,   tvb, 0, 1,
                        ddp_hops(ddp.hops_len));
    proto_tree_add_uint(ddp_tree, hf_ddp_len,        tvb, 0, 2,
                        ddp_len(ddp.hops_len));
    proto_tree_add_uint(ddp_tree, hf_ddp_checksum,   tvb, 2,  2,
                        ddp.sum);
    proto_tree_add_uint(ddp_tree, hf_ddp_dst_net,    tvb, 4,  2,
                        ddp.dnet);
    proto_tree_add_uint(ddp_tree, hf_ddp_src_net,    tvb, 6,  2,
                        ddp.snet);
    proto_tree_add_uint(ddp_tree, hf_ddp_dst_node,   tvb, 8,  1,
                        ddp.dnode);
    proto_tree_add_uint(ddp_tree, hf_ddp_src_node,   tvb, 9,  1,
                        ddp.snode);
    proto_tree_add_uint(ddp_tree, hf_ddp_dst_socket, tvb, 10, 1,
                        ddp.dport);
    proto_tree_add_uint(ddp_tree, hf_ddp_src_socket, tvb, 11, 1,
                        ddp.sport);
    proto_tree_add_uint(ddp_tree, hf_ddp_type,       tvb, 12, 1,
                        ddp.type);
  }

  new_tvb = tvb_new_subset_remaining(tvb, DDP_HEADER_SIZE);

  if (!dissector_try_uint(ddp_dissector_table, ddp.type, new_tvb, pinfo, tree))
    call_dissector(data_handle,new_tvb, pinfo, tree);
}

static const value_string llap_type_vals[] = {
  {0x01, "Short DDP"},
  {0x02, "DDP" },
  {0x81, "Enquiry"},
  {0x82, "Acknowledgement"},
  {0x84, "RTS"},
  {0x85, "CTS"},
  {0, NULL}
};
static value_string_ext llap_type_vals_ext = VALUE_STRING_EXT_INIT(llap_type_vals);

void
capture_llap(packet_counts *ld)
{
  ld->other++;
}

static void
dissect_llap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 dnode;
  guint8 snode;
  guint8 type;
  proto_tree *llap_tree = NULL;
  proto_item *ti;
  tvbuff_t   *new_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLAP");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_llap, tvb, 0, 3, ENC_NA);
    llap_tree = proto_item_add_subtree(ti, ett_llap);
  }

  dnode = tvb_get_guint8(tvb, 0);
  if (tree)
    proto_tree_add_uint(llap_tree, hf_llap_dst, tvb, 0, 1, dnode);
  snode = tvb_get_guint8(tvb, 1);
  if (tree)
    proto_tree_add_uint(llap_tree, hf_llap_src, tvb, 1, 1, snode);
  type = tvb_get_guint8(tvb, 2);
  col_add_str(pinfo->cinfo, COL_INFO,
    val_to_str_ext(type, &llap_type_vals_ext, "Unknown LLAP type (%02x)"));

  if (tree)
    proto_tree_add_uint(llap_tree, hf_llap_type, tvb, 2, 1, type);

  new_tvb = tvb_new_subset_remaining(tvb, 3);

  switch (type) {

  case 0x01:
    if (proto_is_protocol_enabled(find_protocol_by_id(proto_ddp))) {
      pinfo->current_proto = "DDP";
      dissect_ddp_short(new_tvb, pinfo, dnode, snode, tree);
      return;
    }

  case 0x02:
    if (call_dissector(ddp_handle, new_tvb, pinfo, tree))
      return;
  }
  call_dissector(data_handle,new_tvb, pinfo, tree);
}

static void
atp_init(void)
{
  /* fragment */
  fragment_table_init(&atp_fragment_table);
  reassembled_table_init(&atp_reassembled_table);
  /* bitmap */
  if (atp_request_hash)
    g_hash_table_destroy(atp_request_hash);

  atp_request_hash = g_hash_table_new(asp_hash, asp_equal);

}

static void
asp_reinit( void)
{

  if (asp_request_hash)
    g_hash_table_destroy(asp_request_hash);

  asp_request_hash = g_hash_table_new(asp_hash, asp_equal);

}

void
proto_register_atalk(void)
{
  static hf_register_info hf_llap[] = {
    { &hf_llap_dst,
      { "Destination Node",     "llap.dst",     FT_UINT8,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_llap_src,
      { "Source Node",          "llap.src",     FT_UINT8,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_llap_type,
      { "Type",                 "llap.type",    FT_UINT8,  BASE_HEX|BASE_EXT_STRING, &llap_type_vals_ext, 0x0,
        NULL, HFILL }},
  };

  static hf_register_info hf_ddp[] = {
    { &hf_ddp_hopcount,
      { "Hop count",            "ddp.hopcount", FT_UINT8,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_len,
      { "Datagram length",      "ddp.len",      FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_checksum,
      { "Checksum",             "ddp.checksum", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_dst,
      { "Destination address",  "ddp.dst",      FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_dst_net,
      { "Destination Net",      "ddp.dst.net",  FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_src,
      { "Source address",       "ddp.src",      FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_src_net,
      { "Source Net",           "ddp.src.net",  FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_dst_node,
      { "Destination Node",     "ddp.dst.node", FT_UINT8,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_src_node,
      { "Source Node",          "ddp.src.node", FT_UINT8,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_dst_socket,
      { "Destination Socket",   "ddp.dst_socket", FT_UINT8,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_src_socket,
      { "Source Socket",        "ddp.src_socket", FT_UINT8,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ddp_type,
      { "Protocol type",        "ddp.type",     FT_UINT8,  BASE_DEC|BASE_EXT_STRING, &op_vals_ext, 0x0,
        NULL, HFILL }},
  };

  static hf_register_info hf_nbp[] = {
    { &hf_nbp_op,
      { "Operation",            "nbp.op",       FT_UINT8,  BASE_DEC,
                VALS(nbp_op_vals), 0xF0, NULL, HFILL }},
    { &hf_nbp_info,
      { "Info",         "nbp.info",     FT_UINT8,  BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
    { &hf_nbp_count,
      { "Count",                "nbp.count",    FT_UINT8,  BASE_DEC,
                NULL, 0x0F, NULL, HFILL }},
    { &hf_nbp_node_net,
      { "Network",              "nbp.net",      FT_UINT16,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_nbp_node_node,
      { "Node",         "nbp.node",     FT_UINT8,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_nbp_node_port,
      { "Port",         "nbp.port",     FT_UINT8,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_nbp_node_enum,
      { "Enumerator",           "nbp.enum",     FT_UINT8,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_nbp_node_object,
      { "Object",               "nbp.object",   FT_STRING,  BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
    { &hf_nbp_node_type,
      { "Type",         "nbp.type",     FT_STRING,  BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
    { &hf_nbp_node_zone,
      { "Zone",         "nbp.zone",     FT_STRING,  BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
    { &hf_nbp_tid,
      { "Transaction ID",               "nbp.tid",      FT_UINT8,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }}
  };

  static hf_register_info hf_rtmp[] = {
    { &hf_rtmp_net,
      { "Net",          "rtmp.net",     FT_UINT16,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_rtmp_node,
      { "Node",         "nbp.nodeid",   FT_UINT8,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_rtmp_node_len,
      { "Node Length",          "nbp.nodeid.length",    FT_UINT8,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_rtmp_tuple_net,
      { "Net",          "rtmp.tuple.net",       FT_UINT16,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_rtmp_tuple_range_start,
      { "Range Start",          "rtmp.tuple.range_start",       FT_UINT16,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_rtmp_tuple_range_end,
      { "Range End",            "rtmp.tuple.range_end", FT_UINT16,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_rtmp_tuple_dist,
      { "Distance",             "rtmp.tuple.dist",      FT_UINT16,  BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    { &hf_rtmp_function,
      { "Function",             "rtmp.function",        FT_UINT8,  BASE_DEC,
                VALS(rtmp_function_vals), 0x0, "Request Function", HFILL }}
  };

  static hf_register_info hf_atp[] = {
    { &hf_atp_ctrlinfo,
      { "Control info",         "atp.ctrlinfo", FT_UINT8,  BASE_HEX,
                NULL, 0, NULL, HFILL }},

    { &hf_atp_function,
      { "Function",             "atp.function", FT_UINT8,  BASE_DEC,
                VALS(atp_function_vals), ATP_FUNCMASK, "function code", HFILL }},


    { &hf_atp_xo,
      { "XO",           "atp.xo",       FT_BOOLEAN,  8,
                NULL, ATP_XO, "Exactly-once flag", HFILL }},

    { &hf_atp_eom,
      { "EOM",          "atp.eom",      FT_BOOLEAN,  8,
                NULL, ATP_EOM, "End-of-message", HFILL }},

    { &hf_atp_sts,
      { "STS",          "atp.sts",      FT_BOOLEAN,  8,
                NULL, ATP_STS, "Send transaction status", HFILL }},

    { &hf_atp_treltimer,
      { "TRel timer",           "atp.treltimer",        FT_UINT8,  BASE_DEC,
                VALS(atp_trel_timer_vals), 0x07, NULL, HFILL }},

    { &hf_atp_bitmap,
      { "Bitmap",               "atp.bitmap",   FT_UINT8,  BASE_HEX,
                NULL, 0x0, "Bitmap or sequence number", HFILL }},

    { &hf_atp_tid,
      { "TID",                  "atp.tid",      FT_UINT16,  BASE_DEC,
                NULL, 0x0, "Transaction id", HFILL }},
    { &hf_atp_user_bytes,
      { "User bytes",                   "atp.user_bytes",       FT_UINT32,  BASE_HEX,
                NULL, 0x0, NULL, HFILL }},

    { &hf_atp_segment_overlap,
      { "Segment overlap",      "atp.segment.overlap", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, "Segment overlaps with other segments", HFILL }},

    { &hf_atp_segment_overlap_conflict,
      { "Conflicting data in segment overlap", "atp.segment.overlap.conflict",
        FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, "Overlapping segments contained conflicting data", HFILL }},

    { &hf_atp_segment_multiple_tails,
      { "Multiple tail segments found", "atp.segment.multipletails",
        FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, "Several tails were found when desegmenting the packet", HFILL }},

    { &hf_atp_segment_too_long_segment,
      { "Segment too long",     "atp.segment.toolongsegment", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, "Segment contained data past end of packet", HFILL }},

    { &hf_atp_segment_error,
      {"Desegmentation error",  "atp.segment.error", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, "Desegmentation error due to illegal segments", HFILL }},

    { &hf_atp_segment_count,
      { "Segment count", "atp.segment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_atp_segment,
      { "ATP Fragment",         "atp.fragment", FT_FRAMENUM, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},

    { &hf_atp_segments,
      { "ATP Fragments",        "atp.fragments", FT_NONE, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},

    { &hf_atp_reassembled_in,
      { "Reassembled ATP in frame", "atp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This ATP packet is reassembled in this frame", HFILL }},

    { &hf_atp_reassembled_length,
      { "Reassembled ATP length", "atp.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
        "The total length of the reassembled payload", HFILL }}
  };

  static hf_register_info hf_asp[] = {
    { &hf_asp_func,
      { "asp function",         "asp.function", FT_UINT8,  BASE_DEC|BASE_EXT_STRING,
                &asp_func_vals_ext, 0, NULL, HFILL }},

    { &hf_asp_error,
      { "asp error",            "asp.error",    FT_INT32,  BASE_DEC|BASE_EXT_STRING,
                &asp_error_vals_ext, 0, "return error code", HFILL }},

    { &hf_asp_version,
      { "Version",              "asp.version",  FT_UINT16,  BASE_HEX,
                NULL, 0, "asp version", HFILL }},

    { &hf_asp_attn_code,
      { "Attn code",            "asp.attn_code",        FT_UINT16,  BASE_HEX,
                NULL, 0, "asp attention code", HFILL }},

    { &hf_asp_init_error,
      { "Error",                "asp.init_error",       FT_UINT16,  BASE_DEC,
                NULL, 0, "asp init error", HFILL }},

    { &hf_asp_session_id,
      { "Session ID",           "asp.session_id", FT_UINT8,  BASE_DEC,
                NULL, 0, "asp session id", HFILL }},

    { &hf_asp_socket,
      { "Socket",               "asp.socket",   FT_UINT8,  BASE_DEC,
                NULL, 0, "asp socket", HFILL }},

    { &hf_asp_seq,
      { "Sequence",             "asp.seq",      FT_UINT16,  BASE_DEC,
                NULL, 0, "asp sequence number", HFILL }},

    { &hf_asp_size,
      { "size",         "asp.size",     FT_UINT16,  BASE_DEC,
                NULL, 0, "asp available size for reply", HFILL }},

    { &hf_asp_zero_value,
      { "Pad (0)",         "asp.zero_value",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Pad", HFILL }},

        /* asp ,dsi, afp */
    { &hf_asp_server_name,
      { "Server name",         "asp.server_name",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_asp_server_type,
      { "Server type",         "asp.server_type",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_asp_server_vers,
      { "AFP version",         "asp.server_vers",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_asp_server_uams,
      { "UAM",         "asp.server_uams",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_asp_server_icon,
      { "Icon bitmap",         "asp.server_icon",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Server icon bitmap", HFILL }},

    { &hf_asp_server_directory,
      { "Directory service",         "asp.server_directory",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        "Server directory service", HFILL }},

    { &hf_asp_server_signature,
      { "Server signature",         "asp.server_signature",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_asp_server_flag,
      { "Flag",         "asp.server_flag",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Server capabilities flag", HFILL }},
    { &hf_asp_server_flag_copyfile,
      { "Support copyfile",      "asp.server_flag.copyfile",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_COPY,
        "Server support copyfile", HFILL }},
    { &hf_asp_server_flag_passwd,
      { "Support change password",      "asp.server_flag.passwd",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_PASSWD,
        "Server support change password", HFILL }},
    { &hf_asp_server_flag_no_save_passwd,
      { "Don't allow save password",      "asp.server_flag.no_save_passwd",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_NOSAVEPASSWD,
        NULL, HFILL }},
    { &hf_asp_server_flag_srv_msg,
      { "Support server message",      "asp.server_flag.srv_msg",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVMSGS,
        NULL, HFILL }},
    { &hf_asp_server_flag_srv_sig,
      { "Support server signature",      "asp.server_flag.srv_sig",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVSIGNATURE,
        NULL, HFILL }},
    { &hf_asp_server_flag_tcpip,
      { "Support TCP/IP",      "asp.server_flag.tcpip",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_TCPIP,
        "Server support TCP/IP", HFILL }},
    { &hf_asp_server_flag_notify,
      { "Support server notifications",      "asp.server_flag.notify",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVNOTIFY,
        "Server support notifications", HFILL }},
    { &hf_asp_server_flag_reconnect,
      { "Support server reconnect",      "asp.server_flag.reconnect",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVRECONNECT,
        "Server support reconnect", HFILL }},
    { &hf_asp_server_flag_directory,
      { "Support directory services",      "asp.server_flag.directory",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVDIRECTORY,
        "Server support directory services", HFILL }},
    { &hf_asp_server_flag_utf8_name,
      { "Support UTF8 server name",      "asp.server_flag.utf8_name",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_SRVUTF8,
        "Server support UTF8 server name", HFILL }},
    { &hf_asp_server_flag_fast_copy,
      { "Support fast copy",      "asp.server_flag.fast_copy",
                FT_BOOLEAN, 16, NULL, AFPSRVRINFO_FASTBOZO,
        "Server support fast copy", HFILL }},

    { &hf_asp_server_addr_len,
      { "Length",          "asp.server_addr.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Address length.", HFILL }},

    { &hf_asp_server_addr_type,
      { "Type",          "asp.server_addr.type",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &afp_server_addr_type_vals_ext, 0x0,
        "Address type.", HFILL }},

    { &hf_asp_server_addr_value,
      { "Value",          "asp.server_addr.value",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Address value", HFILL }},

    { &hf_asp_server_utf8_name_len,
      { "Server name length",         "asp.server_utf8_name_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "UTF8 server name length", HFILL }},

    { &hf_asp_server_utf8_name,
      { "Server name (UTF8)",         "asp.server_utf8_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
  };

  static hf_register_info hf_zip[] = {
    { &hf_zip_function,
      { "Function",     "zip.function", FT_UINT8,  BASE_DEC|BASE_EXT_STRING, &zip_function_vals_ext, 0x0,
        "ZIP function", HFILL }},

    { &hf_zip_zero_value,
      { "Pad (0)",      "zip.zero_value",FT_BYTES, BASE_NONE, NULL, 0x0,
        "Pad", HFILL }},

    { &hf_zip_atp_function,
      { "Function",     "zip.atp_function", FT_UINT8,  BASE_DEC, VALS(zip_atp_function_vals), 0x0,
        NULL, HFILL }},

    { &hf_zip_start_index,
      { "Start index",  "zip.start_index", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_zip_count,
      { "Count",        "zip.count", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_zip_network_count,
      { "Count",        "zip.network_count", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_zip_network,
      { "Network","zip.network", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_zip_network_start,
      { "Network start","zip.network_start", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_zip_network_end,
      { "Network end",  "zip.network_end", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_zip_flags,
      { "Flags",        "zip.flags", FT_BOOLEAN, 8, NULL, 0xC0,
        NULL, HFILL }},

    { &hf_zip_last_flag,
      { "Last Flag",    "zip.last_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Non zero if contains last zone name in the zone list", HFILL }},

    { &hf_zip_flags_zone_invalid,
      { "Zone invalid", "zip.flags.zone_invalid", FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_zip_flags_use_broadcast,
      { "Use broadcast","zip.flags.use_broadcast", FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

    { &hf_zip_flags_only_one_zone,
      { "Only one zone","zip.flags.only_one_zone", FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},

    { &hf_zip_zone_name,
      { "Zone",         "zip.zone_name", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_zip_default_zone,
      { "Default zone", "zip.default_zone",FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_zip_multicast_length,
      { "Multicast length",     "zip.multicast_length", FT_UINT8,  BASE_DEC, NULL, 0x0,
        "Multicast address length", HFILL }},

    { &hf_zip_multicast_address,
      { "Multicast address", "zip.multicast_address",FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

  };

  static hf_register_info hf_pap[] = {
    { &hf_pap_connid,
      { "ConnID",       "prap.connid",   FT_UINT8,  BASE_DEC, NULL, 0x0,
        "PAP connection ID", HFILL }},

    { &hf_pap_function,
      { "Function",     "prap.function", FT_UINT8,  BASE_DEC|BASE_EXT_STRING, &pap_function_vals_ext, 0x0,
        "PAP function", HFILL }},

    { &hf_pap_socket,
      { "Socket",       "prap.socket",   FT_UINT8,  BASE_DEC, NULL, 0x0,
        "ATP responding socket number", HFILL }},

    { &hf_pap_quantum,
      { "Quantum",      "prap.quantum",  FT_UINT8,  BASE_DEC, NULL, 0x0,
        "Flow quantum", HFILL }},

    { &hf_pap_waittime,
      { "Wait time",    "prap.waittime",  FT_UINT16,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_pap_result,
      { "Result",       "prap.result",  FT_UINT16,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_pap_seq,
      { "Sequence",     "prap.seq",      FT_UINT16,  BASE_DEC, NULL, 0x0,
        "Sequence number", HFILL }},

    { &hf_pap_status,
      { "Status",       "prap.status",   FT_STRING,  BASE_NONE, NULL, 0x0,
                "Printer status", HFILL }},

    { &hf_pap_eof,
      { "EOF",  "prap.eof", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},

    { &hf_pap_pad,
      { "Pad",          "prap.pad",              FT_NONE,   BASE_NONE, NULL, 0,
                "Pad Byte",     HFILL }},

  };

  static gint *ett[] = {
    &ett_llap,
    &ett_ddp,
    &ett_atp,
    &ett_atp_info,
    &ett_atp_segments,
    &ett_atp_segment,
    &ett_asp,
    &ett_pap,

    /* asp dsi afp */
    &ett_asp_status,
    &ett_asp_status_server_flag,
    &ett_asp_vers,
    &ett_asp_uams,
    &ett_asp_addr,
    &ett_asp_addr_line,
    &ett_asp_directory,
    &ett_asp_utf8_name,

    &ett_nbp,
    &ett_nbp_info,
    &ett_nbp_node,
    &ett_pstring,
    &ett_rtmp,
    &ett_rtmp_tuple,

    &ett_zip,
    &ett_zip_flags,
    &ett_zip_zones_list,
    &ett_zip_network_list,
  };
  module_t *atp_module;

  proto_llap = proto_register_protocol("LocalTalk Link Access Protocol", "LLAP", "llap");
  proto_register_field_array(proto_llap, hf_llap, array_length(hf_llap));

  proto_ddp = proto_register_protocol("Datagram Delivery Protocol", "DDP", "ddp");
  proto_register_field_array(proto_ddp, hf_ddp, array_length(hf_ddp));

  proto_nbp = proto_register_protocol("Name Binding Protocol", "NBP", "nbp");
  proto_register_field_array(proto_nbp, hf_nbp, array_length(hf_nbp));

  proto_atp = proto_register_protocol("AppleTalk Transaction Protocol packet", "ATP", "atp");
  proto_register_field_array(proto_atp, hf_atp, array_length(hf_atp));

  proto_asp = proto_register_protocol("AppleTalk Session Protocol", "ASP", "asp");
  proto_register_field_array(proto_asp, hf_asp, array_length(hf_asp));

  proto_pap = proto_register_protocol("Printer Access Protocol", "PrAP", "prap");
  proto_register_field_array(proto_pap, hf_pap, array_length(hf_pap));

  proto_zip = proto_register_protocol("Zone Information Protocol", "ZIP", "zip");
  proto_register_field_array(proto_zip, hf_zip, array_length(hf_zip));

  atp_module = prefs_register_protocol(proto_atp, NULL);
  prefs_register_bool_preference(atp_module, "desegment",
    "Reassemble ATP messages spanning multiple DDP packets",
    "Whether the ATP dissector should reassemble messages spanning multiple DDP packets",
    &atp_defragment);

  proto_rtmp = proto_register_protocol("Routing Table Maintenance Protocol",
                                       "RTMP", "rtmp");
  proto_register_field_array(proto_rtmp, hf_rtmp, array_length(hf_rtmp));

  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  ddp_dissector_table = register_dissector_table("ddp.type", "DDP packet type",
                                                 FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_atalk(void)
{
  dissector_handle_t nbp_handle, rtmp_request_handle;
  dissector_handle_t atp_handle;
  dissector_handle_t zip_ddp_handle;
  dissector_handle_t rtmp_data_handle, llap_handle;

  ddp_handle = create_dissector_handle(dissect_ddp, proto_ddp);
  dissector_add_uint("ethertype", ETHERTYPE_ATALK, ddp_handle);
  dissector_add_uint("chdlctype", ETHERTYPE_ATALK, ddp_handle);
  dissector_add_uint("ppp.protocol", PPP_AT, ddp_handle);
  dissector_add_uint("null.type", BSD_AF_APPLETALK, ddp_handle);
  dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_APPLETALK, ddp_handle);

  nbp_handle = create_dissector_handle(dissect_nbp, proto_nbp);
  dissector_add_uint("ddp.type", DDP_NBP, nbp_handle);

  atp_handle = create_dissector_handle(dissect_atp, proto_atp);
  dissector_add_uint("ddp.type", DDP_ATP, atp_handle);

  asp_handle = new_create_dissector_handle(dissect_asp, proto_asp);
  pap_handle = new_create_dissector_handle(dissect_pap, proto_pap);

  rtmp_request_handle = create_dissector_handle(dissect_rtmp_request, proto_rtmp);
  rtmp_data_handle    = create_dissector_handle(dissect_rtmp_data, proto_rtmp);
  dissector_add_uint("ddp.type", DDP_RTMPREQ, rtmp_request_handle);
  dissector_add_uint("ddp.type", DDP_RTMPDATA, rtmp_data_handle);

  zip_ddp_handle = create_dissector_handle(dissect_ddp_zip, proto_zip);
  dissector_add_uint("ddp.type", DDP_ZIP, zip_ddp_handle);

  zip_atp_handle = create_dissector_handle(dissect_atp_zip, proto_zip);

  llap_handle = create_dissector_handle(dissect_llap, proto_llap);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_LOCALTALK, llap_handle);

  register_init_routine( atp_init);
  register_init_routine( &asp_reinit);

  afp_handle  = find_dissector("afp");
  data_handle = find_dissector("data");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
