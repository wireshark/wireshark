/* packet-atalk.c
 * Routines for Appletalk packet disassembly (DDP, currently).
 *
 * $Id: packet-atalk.c,v 1.69 2002/05/01 07:26:45 guy Exp $
 *
 * Simon Wilkinson <sxw@dcs.ed.ac.uk>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include <epan/packet.h>
#include "etypes.h"
#include "ppptypes.h"
#include "aftypes.h"
#include <epan/atalk-utils.h>
#include <epan/conversation.h>

#include "prefs.h"
#include "reassemble.h"

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
static int hf_ddp_dst_net = -1;
static int hf_ddp_src_net = -1;
static int hf_ddp_dst_node = -1;
static int hf_ddp_src_node = -1;
static int hf_ddp_dst_socket = -1;
static int hf_ddp_src_socket = -1;
static int hf_ddp_type = -1;


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
#define ATP_XO          0x20 /* (1<<5)          eXactly Once mode */
#define ATP_EOM         0x10 /* (1<<4)          End Of Message */
#define ATP_STS         0x08 /* (1<<3)          Transaction Status */
 
/* function codes
*/
#define ATP_FUNCMASK    (3<<6)          /* mask all but function */
  
#define ATP_TREQ        1 /* (1<<6)        Trans. REQuest */
#define ATP_TRESP       2 /* (2<<6)        Trans. RESPonse */
#define ATP_TREL        3 /* (3<<6)        Trans. RELease */

/* ------------------------- */    
static dissector_handle_t asp_handle;

static int proto_atp = -1;
static int hf_atp_ctrlinfo  = -1; /* u_int8_t    control information */
static int hf_atp_function  = -1; /* bits 7,6    function */
static int hf_atp_xo        = -1; /* bit 5       exactly-once */
static int hf_atp_eom       = -1; /* bit 4       end-of-message */
static int hf_atp_sts       = -1; /* bit 3       send transaction status */
static int hf_atp_treltimer = -1; /* bits 2,1,0  TRel timeout indicator */

static int hf_atp_bitmap = -1;   /* u_int8_t  bitmap or sequence number */
static int hf_atp_tid = -1;      /* u_int16_t transaction id. */

static int hf_atp_segments = -1;
static int hf_atp_segment = -1;
static int hf_atp_segment_overlap = -1;
static int hf_atp_segment_overlap_conflict = -1;
static int hf_atp_segment_multiple_tails = -1;
static int hf_atp_segment_too_long_segment = -1;
static int hf_atp_segment_error = -1;

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
#define ASPERR_OK       0x0000
#define ASPERR_BADVERS  0xfbd6
#define ASPERR_BUFSMALL 0xfbd5
#define ASPERR_NOSESS   0xfbd4
#define ASPERR_NOSERV   0xfbd3
#define ASPERR_PARM     0xfbd2
#define ASPERR_SERVBUSY 0xfbd1
#define ASPERR_SESSCLOS 0xfbd0
#define ASPERR_SIZERR   0xfbcf
#define ASPERR_TOOMANY  0xfbce
#define ASPERR_NOACK    0xfbcd

static int proto_asp = -1;
static int hf_asp_func = -1;
static int hf_asp_error = -1;

static guint asp_packet_init_count = 200;

typedef struct {
	guint32 conversation;
	guint16	seq;
} asp_request_key;
 
typedef struct {
	guint8	command;
} asp_request_val;
 
static GHashTable *asp_request_hash = NULL;
static GMemChunk *asp_request_keys = NULL;
static GMemChunk *asp_request_vals = NULL;

/* Hash Functions */
static gint  asp_equal (gconstpointer v, gconstpointer v2)
{
	asp_request_key *val1 = (asp_request_key*)v;
	asp_request_key *val2 = (asp_request_key*)v2;

	if (val1->conversation == val2->conversation &&
			val1->seq == val2->seq) {
		return 1;
	}
	return 0;
}

static guint asp_hash  (gconstpointer v)
{
        asp_request_key *asp_key = (asp_request_key*)v;
        return asp_key->seq;
}

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

static gint ett_nbp = -1;
static gint ett_nbp_info = -1;
static gint ett_nbp_node = -1;
static gint ett_rtmp = -1;
static gint ett_rtmp_tuple = -1;
static gint ett_ddp = -1;
static gint ett_llap = -1;
static gint ett_pstring = -1;

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
#define ddp_hops(x)	( ( x >> 10) & 0x3C )
#define ddp_len(x)		( x & 0x03ff )
typedef struct _e_ddp {
  guint16	hops_len; /* combines pad, hops, and len */
  guint16	sum,dnet,snet;
  guint8	dnode,snode;
  guint8	dport,sport;
  guint8	type;
} e_ddp;

#define DDP_HEADER_SIZE 13


static const value_string op_vals[] = {
  {DDP_RTMPDATA, "AppleTalk Routing Table response or data" },
  {DDP_NBP, "AppleTalk Name Binding Protocol packet"},
  {DDP_ATP, "AppleTalk Transaction Protocol packet"},
  {DDP_AEP, "AppleTalk Echo Protocol packet"},
  {DDP_RTMPREQ, "AppleTalk Routing Table request"},
  {DDP_ZIP, "AppleTalk Zone Information Protocol packet"},
  {DDP_ADSP, "AppleTalk Data Stream Protocol"},
  {DDP_EIGRP, "Cisco EIGRP for AppleTalk"},
  {0, NULL}
};

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
  {ASPFUNC_CLOSE,	"CloseSession" },
  {ASPFUNC_CMD,		"Command" },
  {ASPFUNC_STAT,	"GetStatus" },
  {ASPFUNC_OPEN,	"OpenSession" },
  {ASPFUNC_TICKLE,	"Tickle" },
  {ASPFUNC_WRITE,	"Write" },
  {ASPFUNC_WRTCONT,	"Write Cont" },
  {ASPFUNC_ATTN,	"Attention" },
  {0,			NULL } };

const value_string asp_error_vals[] = {
  {AFP_OK			, "success"},
  {AFPERR_ACCESS	, "permission denied" },
  {AFPERR_AUTHCONT	, "logincont" },
  {AFPERR_BADUAM	, "uam doesn't exist" },
  {AFPERR_BADVERS	, "bad afp version number" },
  {AFPERR_BITMAP	, "invalid bitmap" },
  {AFPERR_CANTMOVE 	, "can't move file" },
  {AFPERR_DENYCONF	, "file synchronization locks conflict" },
  {AFPERR_DIRNEMPT	, "directory not empty" },
  {AFPERR_DFULL		, "disk full" },
  {AFPERR_EOF		, "end of file" },
  {AFPERR_BUSY		, "FileBusy" },
  {AFPERR_FLATVOL  	, "volume doesn't support directories" },
  {AFPERR_NOITEM	, "ItemNotFound" },
  {AFPERR_LOCK     	, "LockErr" },
  {AFPERR_MISC     	, "misc. err" },
  {AFPERR_NLOCK    	, "no more locks" },
  {AFPERR_NOSRVR	, "no response by server at that address" },
  {AFPERR_EXIST		, "object already exists" },
  {AFPERR_NOOBJ		, "object not found" },
  {AFPERR_PARAM		, "parameter error" },
  {AFPERR_NORANGE  	, "no range lock" },
  {AFPERR_RANGEOVR 	, "range overlap" },
  {AFPERR_SESSCLOS 	, "session closed" },
  {AFPERR_NOTAUTH	, "user not authenticated" },
  {AFPERR_NOOP		, "command not supported" },
  {AFPERR_BADTYPE	, "object is the wrong type" },
  {AFPERR_NFILE		, "too many files open" },
  {AFPERR_SHUTDOWN	, "server is going down" },
  {AFPERR_NORENAME 	, "can't rename" },
  {AFPERR_NODIR		, "couldn't find directory" },
  {AFPERR_ITYPE		, "wrong icon type" },
  {AFPERR_VLOCK		, "volume locked" },
  {AFPERR_OLOCK    	, "object locked" },
  {AFPERR_CTNSHRD  	, "share point contains a share point" },
  {AFPERR_NOID     	, "file thread not found" },
  {AFPERR_EXISTID  	, "file already has an id" },
  {AFPERR_DIFFVOL  	, "different volume" },
  {AFPERR_CATCHNG  	, "catalog has changed" },
  {AFPERR_SAMEOBJ  	, "source file == destination file" },
  {AFPERR_BADID    	, "non-existent file id" },
  {AFPERR_PWDSAME  	, "same password/can't change password" },
  {AFPERR_PWDSHORT 	, "password too short" },
  {AFPERR_PWDEXPR  	, "password expired" },
  {AFPERR_INSHRD   	, "folder being shared is inside a shared folder." },
  {AFPERR_INTRASH   , "shared folder in trash." },
  {AFPERR_PWDCHNG   , "password needs to be changed" },
  {AFPERR_PWDPOLCY  , "password fails policy check" },
  {AFPERR_USRLOGIN  , "user already logged on" },
  {0,			NULL } };

/*
 * XXX - do this with an FT_UINT_STRING?
 * Unfortunately, you can't extract from an FT_UINT_STRING the string,
 * which we'd want to do in order to put it into the "Data:" portion.
 *
 * Are these always in the Mac extended character set?
 */
int dissect_pascal_string(tvbuff_t *tvb, int offset, proto_tree *tree,
	int hf_index)
{
	int len;
	
	len = tvb_get_guint8(tvb, offset);
	offset++;

	if ( tree )
	{
		char *tmp;
		proto_tree *item;
		proto_tree *subtree;
		
		/*
		 * XXX - if we could do this inside the protocol tree
		 * code, we could perhaps avoid allocating and freeing
		 * this string buffer.
		 */
		tmp = g_malloc( len+1 );
		tvb_memcpy(tvb, tmp, offset, len);
		tmp[len] = 0;
		item = proto_tree_add_string(tree, hf_index, tvb, offset-1, len+1, tmp);

		subtree = proto_item_add_subtree(item, ett_pstring);
		proto_tree_add_text(subtree, tvb, offset-1, 1, "Length: %d", len);
		proto_tree_add_text(subtree, tvb, offset, len, "Data: %s", tmp);
		
		g_free(tmp);
	}
	offset += len;
	
	return offset;	
}

static void
dissect_rtmp_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree *rtmp_tree;
  proto_item *ti;
  guint8 function;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTMP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  function = tvb_get_guint8(tvb, 0);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
	val_to_str(function, rtmp_function_vals, "Unknown function (%02)"));
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_rtmp, tvb, 0, 1, FALSE);
    rtmp_tree = proto_item_add_subtree(ti, ett_rtmp);

    proto_tree_add_uint(rtmp_tree, hf_rtmp_function, tvb, 0, 1, function);
  }
}

static void
dissect_rtmp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree *rtmp_tree;
  proto_item *ti;
  int offset = 0;
  guint16 net;
  guint8 nodelen,nodelen_bits;
  guint16 node; /* might be more than 8 bits */
  int i;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTMP");
  if (check_col(pinfo->cinfo, COL_INFO))
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
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "Net: %u  Node Len: %u  Node: %u",
		net, nodelen_bits, node);
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_rtmp, tvb, offset, -1, FALSE);
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
				FALSE);
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
  int offset = 0;
  guint8 info;
  guint op, count;
  unsigned int i;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  info = tvb_get_guint8(tvb, offset);
  op = info >> 4;
  count = info & 0x0F;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "Op: %s  Count: %u",
      val_to_str(op, nbp_op_vals, "Unknown (0x%01x)"), count);
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_nbp, tvb, offset, -1, FALSE);
    nbp_tree = proto_item_add_subtree(ti, ett_nbp);

    info_item = proto_tree_add_uint_format(nbp_tree, hf_nbp_info, tvb, offset, 1,
		info,
		"Info: 0x%01X  Operation: %s  Count: %u", info,
		val_to_str(op, nbp_op_vals, "Unknown (0x%01X)"),
		count);
    nbp_info_tree = proto_item_add_subtree(info_item, ett_nbp_info);
    proto_tree_add_uint(nbp_info_tree, hf_nbp_op, tvb, offset, 1, info);
    proto_tree_add_uint(nbp_info_tree, hf_nbp_count, tvb, offset, 1, info);
    proto_tree_add_item(nbp_tree, hf_nbp_tid, tvb, offset+1, 1, FALSE);
    offset += 2;

    for (i=0; i<count; i++) {
      proto_tree *node_item,*node_tree;
      int soffset = offset;

      node_item = proto_tree_add_text(nbp_tree, tvb, offset, -1, 
			"Node %d", i+1);
      node_tree = proto_item_add_subtree(node_item, ett_nbp_node);

      proto_tree_add_item(node_tree, hf_nbp_node_net, tvb, offset, 2, FALSE);
      offset += 2;
      proto_tree_add_item(node_tree, hf_nbp_node_node, tvb, offset, 1, FALSE);
      offset++;
      proto_tree_add_item(node_tree, hf_nbp_node_port, tvb, offset, 1, FALSE);
      offset++;
      proto_tree_add_item(node_tree, hf_nbp_node_enum, tvb, offset, 1, FALSE);
      offset++;

      offset = dissect_pascal_string(tvb, offset, node_tree, hf_nbp_node_object);
      offset = dissect_pascal_string(tvb, offset, node_tree, hf_nbp_node_type);
      offset = dissect_pascal_string(tvb, offset, node_tree, hf_nbp_node_zone);

      proto_item_set_len(node_item, offset-soffset);
    }
  }

  return;
}

static void
show_fragments(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	       fragment_data *fd_head)
{
  guint32 offset;
  fragment_data *fd;
  proto_tree *ft;
  proto_item *fi;

  fi = proto_tree_add_item(tree, hf_atp_segments, tvb, 0, -1, FALSE);
  ft = proto_item_add_subtree(fi, ett_atp_segments);
  offset = 0;
  for (fd = fd_head->next; fd != NULL; fd = fd->next){
    if (fd->flags & (FD_OVERLAP|FD_OVERLAPCONFLICT|FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
      /*
       * This segment has some flags set; create a subtree for it and
       * display the flags.
       */
      proto_tree *fet = NULL;
      proto_item *fei = NULL;
      int hf;

      if (fd->flags & (FD_OVERLAPCONFLICT|FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
	hf = hf_atp_segment_error;
      } else {
	hf = hf_atp_segment;
      }
      fei = proto_tree_add_none_format(ft, hf, tvb, offset, fd->len,
				       "Frame:%u payload:%u-%u",
				       fd->frame, offset, offset+fd->len-1);
      fet = proto_item_add_subtree(fei, ett_atp_segment);
      if (fd->flags&FD_OVERLAP)
	proto_tree_add_boolean(fet, hf_atp_segment_overlap, tvb, 0, 0, TRUE);
      if (fd->flags&FD_OVERLAPCONFLICT) {
	proto_tree_add_boolean(fet, hf_atp_segment_overlap_conflict, tvb, 0, 0,
			       TRUE);
      }
      if (fd->flags&FD_MULTIPLETAILS) {
	proto_tree_add_boolean(fet, hf_atp_segment_multiple_tails, tvb, 0, 0,
			       TRUE);
      }
      if (fd->flags&FD_TOOLONGFRAGMENT) {
	proto_tree_add_boolean(fet, hf_atp_segment_too_long_segment, tvb, 0, 0,
			       TRUE);
      }
    } else {
      /*
       * Nothing of interest for this segment.
       */
      proto_tree_add_text (ft, tvb, offset, fd->len,
			   "Frame:%u payload:%u-%u",
			   fd->frame, offset, offset+fd->len-1);
    }
    offset += fd->len;
  }
  if (fd_head->flags & (FD_OVERLAPCONFLICT|FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
    if (check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "[Illegal segments]");
  }
}

/* ----------------------------- 
   ATP protocol cf. inside appletalk chap. 9
   desegmentation from packet-ieee80211.c
*/
static void
dissect_atp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree *atp_tree = NULL;
  proto_item *ti;
  proto_tree *atp_info_tree;
  proto_item *info_item;
  int offset = 0;
  guint8 ctrlinfo;
  guint8 frag_number = 0;
  guint op;
  guint16 tid;
  struct aspinfo aspinfo;
  tvbuff_t   *new_tvb = NULL;
  gboolean save_fragmented;
  gboolean more_fragment = FALSE;
  int len;
  guint8 bitmap;
  
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATP");

  ctrlinfo = tvb_get_guint8(tvb, offset);
  bitmap   = tvb_get_guint8(tvb, offset +1);
  tid      = tvb_get_ntohs(tvb, offset +2);

  op = ctrlinfo >> 6;

  aspinfo.reply   = (0x80 == (ctrlinfo & ATP_FUNCMASK))?1:0;
  aspinfo.release = (0xC0 == (ctrlinfo & ATP_FUNCMASK))?1:0;
  aspinfo.seq = tid;
  aspinfo.code = 0;

  /* FIXME
     ATP_EOM is not mandatory. Some implementations don't always set it
     if the query is only one packet.
    	
     need to keep bitmap from request.
    */    	
  if (aspinfo.reply) {
     more_fragment = !(ATP_EOM & ctrlinfo); /* or only one segment in transaction request */
     frag_number = bitmap;
  }
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s transaction %d", 
    	val_to_str(op, atp_function_vals, "Unknown (0x%01x)"),tid);
    if (more_fragment) 
	col_append_fstr(pinfo->cinfo, COL_INFO, " [fragment]");
  }  

  if (tree) {
    ti = proto_tree_add_item(tree, proto_atp, tvb, offset, -1, FALSE);
    atp_tree = proto_item_add_subtree(ti, ett_atp);
    proto_item_set_len(atp_tree, ATP_HDRSIZE -1);

    info_item = proto_tree_add_item(atp_tree, hf_atp_ctrlinfo, tvb, offset, 1, FALSE);
    atp_info_tree = proto_item_add_subtree(info_item, ett_atp_info);

    proto_tree_add_item(atp_info_tree, hf_atp_function, tvb, offset, 1, FALSE);
    proto_tree_add_item(atp_info_tree, hf_atp_xo, tvb, offset, 1, FALSE);
    proto_tree_add_item(atp_info_tree, hf_atp_eom, tvb, offset, 1, FALSE);
    proto_tree_add_item(atp_info_tree, hf_atp_sts, tvb, offset, 1, FALSE);
    if ((ctrlinfo & (ATP_FUNCMASK|ATP_XO)) == (0x40|ATP_XO)) {
      /* TReq with XO set */
      proto_tree_add_item(atp_info_tree, hf_atp_treltimer, tvb, offset, 1, FALSE);
    }

    if (!aspinfo.reply) {
      guint8 nbe = 0;
      guint8 t = bitmap;
		
      while(t) {
	nbe++;
	t >>= 1;
      }
      proto_tree_add_text(atp_tree, tvb, offset +1, 1,
			  "Bitmap: 0x%02x  %d packet(s) max", bitmap, nbe);
    }
    else {
      proto_tree_add_item(atp_tree, hf_atp_bitmap, tvb, offset +1, 1, FALSE);
    }
    proto_tree_add_item(atp_tree, hf_atp_tid, tvb, offset +2, 2, FALSE);
  }
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
     	hdr += 4;	/* asp header */
     len = tvb_length_remaining(tvb, hdr);
     fd_head = fragment_add_seq_check(tvb, hdr, pinfo, tid,
				     atp_fragment_table,
				     atp_reassembled_table,
				     frag_number,
				     len,
				     more_fragment);
     if (fd_head != NULL) {
	if (fd_head->next != NULL) {
            new_tvb = tvb_new_real_data(fd_head->data, fd_head->len, fd_head->len);
            tvb_set_child_real_data_tvbuff(tvb, new_tvb);
            add_new_data_source(pinfo->fd, new_tvb, "Reassembled ATP");
	    /* Show all fragments. */
	    if (tree)
		    show_fragments(new_tvb, pinfo, atp_tree, fd_head);
        }
        else 
      	    new_tvb = tvb_new_subset(tvb, ATP_HDRSIZE -1, -1, -1);
     }
     else {
	new_tvb = NULL;
     }
  }
  else {
      /* full packet */
     new_tvb = tvb_new_subset(tvb, ATP_HDRSIZE -1, -1,- 1);
  }
  
  if (new_tvb) {
     pinfo->private_data = &aspinfo;
     call_dissector(asp_handle, new_tvb, pinfo, tree);
  }
  else {
    /* Just show this as a fragment. */
    new_tvb = tvb_new_subset (tvb, ATP_HDRSIZE -1, -1, -1);
    call_dissector(data_handle, new_tvb, pinfo, tree);
  }
  pinfo->fragmented = save_fragmented;
  return;
}


static void
dissect_asp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
  struct aspinfo *aspinfo = pinfo->private_data;
  int offset = 0;
  proto_tree *asp_tree = NULL;
  proto_item *ti;
  guint8 fn;
  gint32 error;
  int len;
  conversation_t	*conversation;
  asp_request_key request_key, *new_request_key;
  asp_request_val *request_val;
    
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ASP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  conversation = find_conversation(&pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

  if (conversation == NULL)
  {
	conversation = conversation_new(&pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
  }

  request_key.conversation = conversation->index;	
  request_key.seq = aspinfo->seq;

  request_val = (asp_request_val *) g_hash_table_lookup(
								asp_request_hash, &request_key);

  if (!request_val && !aspinfo->reply && !aspinfo->release)  {
	 fn = tvb_get_guint8(tvb, offset);
	 new_request_key = g_mem_chunk_alloc(asp_request_keys);
	 *new_request_key = request_key;

	 request_val = g_mem_chunk_alloc(asp_request_vals);
	 request_val->command = fn;

	 g_hash_table_insert(asp_request_hash, new_request_key,
								request_val);
  }

  if (!request_val) { 
	return;
  }

  fn = request_val->command;

  if (check_col(pinfo->cinfo, COL_INFO)) {
	if (aspinfo->reply)
		col_add_fstr(pinfo->cinfo, COL_INFO, "Reply tid %d",aspinfo->seq);
	else if (aspinfo->release)
		col_add_fstr(pinfo->cinfo, COL_INFO, "Release tid %d",aspinfo->seq);
	else
		col_add_fstr(pinfo->cinfo, COL_INFO, "Function: %s  tid %d",
      				val_to_str(fn, asp_func_vals, "Unknown (0x%01x)"), aspinfo->seq);
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_asp, tvb, offset, -1, FALSE);
    asp_tree = proto_item_add_subtree(ti, ett_asp);
    if (!aspinfo->reply && !aspinfo->release) {
      proto_tree_add_item(asp_tree, hf_asp_func, tvb, offset, 1, FALSE);
    }
    else { /* error code */
      error = tvb_get_ntohl(tvb, offset);
      if (error <= 0) 
	proto_tree_add_item(asp_tree, hf_asp_error, tvb, offset, 4, FALSE);
    }
  }
  aspinfo->command = fn;
  offset += 4;
  len = tvb_reported_length_remaining(tvb,offset);
  if (!aspinfo->release &&
  		   (fn == ASPFUNC_CMD || fn  == ASPFUNC_WRITE)) {
	tvbuff_t   *new_tvb;

	if (asp_tree)
		proto_item_set_len(asp_tree, 4);
	new_tvb = tvb_new_subset(tvb, offset,-1,len);
	call_dissector(afp_handle, new_tvb, pinfo, tree);  	
  }
  else {	
	call_dissector(data_handle,tvb_new_subset(tvb, offset,-1,len), pinfo, tree); 
  }
}


static void
dissect_ddp_short(tvbuff_t *tvb, packet_info *pinfo, guint8 dnode,
		  guint8 snode, proto_tree *tree)
{
  guint16 len;
  guint8  dport;
  guint8  sport;
  guint8  type;
  proto_tree *ddp_tree = NULL;
  proto_item *ti;
  static struct atalk_ddp_addr src, dst;
  tvbuff_t   *new_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DDP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_ddp, tvb, 0, DDP_SHORT_HEADER_SIZE,
			     FALSE);
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
  src.port = sport;
  dst.net = 0;
  dst.node = dnode;
  dst.port = dport;
  SET_ADDRESS(&pinfo->net_src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->net_dst, AT_ATALK, sizeof dst, (guint8 *)&dst);
  SET_ADDRESS(&pinfo->dst, AT_ATALK, sizeof dst, (guint8 *)&dst);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_str(pinfo->cinfo, COL_INFO,
      val_to_str(type, op_vals, "Unknown DDP protocol (%02x)"));
  }
  if (tree)
    proto_tree_add_uint(ddp_tree, hf_ddp_type, tvb, 4, 1, type);
  
  new_tvb = tvb_new_subset(tvb, DDP_SHORT_HEADER_SIZE, -1, -1);

  if (!dissector_try_port(ddp_dissector_table, type, new_tvb, pinfo, tree))
    call_dissector(data_handle,new_tvb, pinfo, tree);
}

static void
dissect_ddp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  e_ddp       ddp;
  proto_tree *ddp_tree;
  proto_item *ti;
  static struct atalk_ddp_addr src, dst;
  tvbuff_t   *new_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DDP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&ddp, 0, sizeof(e_ddp));
  ddp.dnet=ntohs(ddp.dnet);
  ddp.snet=ntohs(ddp.snet);
  ddp.sum=ntohs(ddp.sum);
  ddp.hops_len=ntohs(ddp.hops_len);
  
  src.net = ddp.snet;
  src.node = ddp.snode;
  src.port = ddp.sport;
  dst.net = ddp.dnet;
  dst.node = ddp.dnode;
  dst.port = ddp.dport;
  SET_ADDRESS(&pinfo->net_src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->net_dst, AT_ATALK, sizeof dst, (guint8 *)&dst);
  SET_ADDRESS(&pinfo->dst, AT_ATALK, sizeof dst, (guint8 *)&dst);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
      val_to_str(ddp.type, op_vals, "Unknown DDP protocol (%02x)"));
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_ddp, tvb, 0, DDP_HEADER_SIZE,
			     FALSE);
    ddp_tree = proto_item_add_subtree(ti, ett_ddp);
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

  new_tvb = tvb_new_subset(tvb, DDP_HEADER_SIZE, -1, -1);

  if (!dissector_try_port(ddp_dissector_table, ddp.type, new_tvb, pinfo, tree))
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

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLAP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_llap, tvb, 0, 3, FALSE);
    llap_tree = proto_item_add_subtree(ti, ett_llap);
  }

  dnode = tvb_get_guint8(tvb, 0);
  if (tree)  
    proto_tree_add_uint(llap_tree, hf_llap_dst, tvb, 0, 1, dnode);
  snode = tvb_get_guint8(tvb, 1);
  if (tree)
    proto_tree_add_uint(llap_tree, hf_llap_src, tvb, 1, 1, snode);
  type = tvb_get_guint8(tvb, 2);
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_str(pinfo->cinfo, COL_INFO,
      val_to_str(type, llap_type_vals, "Unknown LLAP type (%02x)"));
  }
  if (tree)
    proto_tree_add_uint(llap_tree, hf_llap_type, tvb, 2, 1, type);
  
  new_tvb = tvb_new_subset(tvb, 3, -1, -1);

  if (proto_is_protocol_enabled(proto_ddp)) {
    pinfo->current_proto = "DDP";
    switch (type) {

    case 0x01:
      dissect_ddp_short(new_tvb, pinfo, dnode, snode, tree);
      return;

    case 0x02:
      dissect_ddp(new_tvb, pinfo, tree);
      return;
    }
  }
  call_dissector(data_handle,new_tvb, pinfo, tree);
}

static void
atp_defragment_init(void)
{
  fragment_table_init(&atp_fragment_table);
  reassembled_table_init(&atp_reassembled_table);
}

static void 
asp_reinit( void)
{

	if (asp_request_hash)
		g_hash_table_destroy(asp_request_hash);
	if (asp_request_keys)
		g_mem_chunk_destroy(asp_request_keys);
	if (asp_request_vals)
		g_mem_chunk_destroy(asp_request_vals);

	asp_request_hash = g_hash_table_new(asp_hash, asp_equal);

	asp_request_keys = g_mem_chunk_new("asp_request_keys",
		sizeof(asp_request_key),
		asp_packet_init_count * sizeof(asp_request_key),
		G_ALLOC_AND_FREE);
	asp_request_vals = g_mem_chunk_new("asp_request_vals",
		sizeof(asp_request_val),
		asp_packet_init_count * sizeof(asp_request_val),
		G_ALLOC_AND_FREE);

}

void
proto_register_atalk(void)
{
  static hf_register_info hf_llap[] = {
    { &hf_llap_dst,
      { "Destination Node",	"llap.dst",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_llap_src,
      { "Source Node",		"llap.src",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_llap_type,
      { "Type",			"llap.type",	FT_UINT8,  BASE_HEX, VALS(llap_type_vals), 0x0,
      	"", HFILL }},
  };

  static hf_register_info hf_ddp[] = {
    { &hf_ddp_hopcount,
      { "Hop count",		"ddp.hopcount",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_len,
      { "Datagram length",	"ddp.len",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_checksum,
      { "Checksum",		"ddp.checksum",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_dst_net,
      { "Destination Net",	"ddp.dst.net",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_src_net,
      { "Source Net",		"ddp.src.net",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_dst_node,
      { "Destination Node",	"ddp.dst.node",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_src_node,
      { "Source Node",		"ddp.src.node",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_dst_socket,
      { "Destination Socket",	"ddp.dst.socket", FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_src_socket,
      { "Source Socket",       	"ddp.src.socket", FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_type,
      { "Protocol type",       	"ddp.type",	FT_UINT8,  BASE_DEC, VALS(op_vals), 0x0,
      	"", HFILL }},
  };

  static hf_register_info hf_nbp[] = {
    { &hf_nbp_op,
      { "Operation",		"nbp.op",	FT_UINT8,  BASE_DEC, 
		VALS(nbp_op_vals), 0xF0, "Operation", HFILL }},
    { &hf_nbp_info,
      { "Info",		"nbp.info",	FT_UINT8,  BASE_HEX, 
		NULL, 0x0, "Info", HFILL }},
    { &hf_nbp_count,
      { "Count",		"nbp.count",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0F, "Count", HFILL }},
    { &hf_nbp_node_net,
      { "Network",		"nbp.net",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Network", HFILL }},
    { &hf_nbp_node_node,
      { "Node",		"nbp.node",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Node", HFILL }},
    { &hf_nbp_node_port,
      { "Port",		"nbp.port",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Port", HFILL }},
    { &hf_nbp_node_enum,
      { "Enumerator",		"nbp.enum",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Enumerator", HFILL }},
    { &hf_nbp_node_object,
      { "Object",		"nbp.object",	FT_STRING,  BASE_DEC, 
		NULL, 0x0, "Object", HFILL }},
    { &hf_nbp_node_type,
      { "Type",		"nbp.type",	FT_STRING,  BASE_DEC, 
		NULL, 0x0, "Type", HFILL }},
    { &hf_nbp_node_zone,
      { "Zone",		"nbp.zone",	FT_STRING,  BASE_DEC, 
		NULL, 0x0, "Zone", HFILL }},
    { &hf_nbp_tid,
      { "Transaction ID",		"nbp.tid",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Transaction ID", HFILL }}
  };

  static hf_register_info hf_rtmp[] = {
    { &hf_rtmp_net,
      { "Net",		"rtmp.net",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Net", HFILL }},
    { &hf_rtmp_node,
      { "Node",		"nbp.nodeid",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Node", HFILL }},
    { &hf_rtmp_node_len,
      { "Node Length",		"nbp.nodeid.length",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Node Length", HFILL }},
    { &hf_rtmp_tuple_net,
      { "Net",		"rtmp.tuple.net",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Net", HFILL }},
    { &hf_rtmp_tuple_range_start,
      { "Range Start",		"rtmp.tuple.range_start",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Range Start", HFILL }},
    { &hf_rtmp_tuple_range_end,
      { "Range End",		"rtmp.tuple.range_end",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Range End", HFILL }},
    { &hf_rtmp_tuple_dist,
      { "Distance",		"rtmp.tuple.dist",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Distance", HFILL }},
    { &hf_rtmp_function,
      { "Function",		"rtmp.function",	FT_UINT8,  BASE_DEC, 
		VALS(rtmp_function_vals), 0x0, "Request Function", HFILL }}
  };

  static hf_register_info hf_atp[] = {
    { &hf_atp_ctrlinfo,
      { "Control info",		"atp.ctrlinfo",	FT_UINT8,  BASE_HEX, 
		NULL, 0, "control info", HFILL }},

    { &hf_atp_function,
      { "Function",		"atp.function",	FT_UINT8,  BASE_DEC, 
		VALS(atp_function_vals), ATP_FUNCMASK, "function code", HFILL }},


    { &hf_atp_xo,
      { "XO",		"atp.xo",	FT_BOOLEAN,  8,
		NULL, ATP_XO, "Exactly-once flag", HFILL }},

    { &hf_atp_eom,
      { "EOM",		"atp.eom",	FT_BOOLEAN,  8,
		NULL, ATP_EOM, "End-of-message", HFILL }},

    { &hf_atp_sts,
      { "STS",		"atp.sts",	FT_BOOLEAN,  8,
		NULL, ATP_STS, "Send transaction status", HFILL }},

    { &hf_atp_treltimer,
      { "TRel timer",		"atp.treltimer",	FT_UINT8,  BASE_DEC,
		VALS(atp_trel_timer_vals), 0x07, "TRel timer", HFILL }},

    { &hf_atp_bitmap,
      { "Bitmap",		"atp.bitmap",	FT_UINT8,  BASE_HEX, 
		NULL, 0x0, "Bitmap or sequence number", HFILL }},

    { &hf_atp_tid,
      { "TID",			"atp.tid",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Transaction id", HFILL }},

    { &hf_atp_segment_overlap,
      { "Segment overlap",	"atp.segment.overlap", FT_BOOLEAN, BASE_NONE,
		NULL, 0x0, "Segment overlaps with other segments", HFILL }},

    { &hf_atp_segment_overlap_conflict,
      { "Conflicting data in seagment overlap", "atp.segment.overlap.conflict",
	FT_BOOLEAN, BASE_NONE,
		NULL, 0x0, "Overlapping segments contained conflicting data", HFILL }},

    { &hf_atp_segment_multiple_tails,
      { "Multiple tail segments found", "atp.segment.multipletails",
	FT_BOOLEAN, BASE_NONE,
		NULL, 0x0, "Several tails were found when desegmenting the packet", HFILL }},

    { &hf_atp_segment_too_long_segment,
      { "Segment too long",	"atp.segment.toolongsegment", FT_BOOLEAN, BASE_NONE,
		NULL, 0x0, "Segment contained data past end of packet", HFILL }},

    { &hf_atp_segment_error,
      {" Desegmentation error",	"atp.segment.error", FT_NONE, BASE_NONE,
		NULL, 0x0, "Desegmentation error due to illegal segments", HFILL }},

    { &hf_atp_segment,
      { "ATP Fragment",		"atp.fragment", FT_NONE, BASE_NONE,
		NULL, 0x0, "ATP Fragment", HFILL }},

    { &hf_atp_segments,
      { "ATP Fragments",	"atp.fragments", FT_NONE, BASE_NONE,
		NULL, 0x0, "ATP Fragments", HFILL }},
  };

  static hf_register_info hf_asp[] = {
    { &hf_asp_func,
      { "asp function",		"asp.function",	FT_UINT8,  BASE_DEC, 
		VALS(asp_func_vals), 0, "asp function", HFILL }},

    { &hf_asp_error,
      { "asp error",		"asp.error",	FT_INT32,  BASE_DEC, 
		VALS(asp_error_vals), 0, "return error code", HFILL }},
  };
  
  static gint *ett[] = {
  	&ett_llap,
	&ett_ddp,
	&ett_atp,
	&ett_atp_info,
	&ett_atp_segments,
	&ett_atp_segment,
	&ett_asp,
	&ett_nbp,
	&ett_nbp_info,
	&ett_nbp_node,
	&ett_pstring,
	&ett_rtmp,
	&ett_rtmp_tuple,
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

  atp_module = prefs_register_protocol(proto_atp, NULL);
  prefs_register_bool_preference(atp_module, "desegment",
    "Desegment all ATP messages spanning multiple DDP packets",
    "Whether the ATP dissector should desegment all messages spanning multiple DDP packets",
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
  dissector_handle_t ddp_handle, nbp_handle, rtmp_request_handle;
  dissector_handle_t atp_handle;
  dissector_handle_t rtmp_data_handle, llap_handle;

  ddp_handle = create_dissector_handle(dissect_ddp, proto_ddp);
  dissector_add("ethertype", ETHERTYPE_ATALK, ddp_handle);
  dissector_add("chdlctype", ETHERTYPE_ATALK, ddp_handle);
  dissector_add("ppp.protocol", PPP_AT, ddp_handle);
  dissector_add("null.type", BSD_AF_APPLETALK, ddp_handle);

  nbp_handle = create_dissector_handle(dissect_nbp, proto_nbp);
  dissector_add("ddp.type", DDP_NBP, nbp_handle);

  atp_handle = create_dissector_handle(dissect_atp, proto_atp);
  dissector_add("ddp.type", DDP_ATP, atp_handle);

  asp_handle = create_dissector_handle(dissect_asp, proto_asp);

  rtmp_request_handle = create_dissector_handle(dissect_rtmp_request, proto_rtmp);
  rtmp_data_handle = create_dissector_handle(dissect_rtmp_data, proto_rtmp);
  dissector_add("ddp.type", DDP_RTMPREQ, rtmp_request_handle);
  dissector_add("ddp.type", DDP_RTMPDATA, rtmp_data_handle);

  llap_handle = create_dissector_handle(dissect_llap, proto_llap);
  dissector_add("wtap_encap", WTAP_ENCAP_LOCALTALK, llap_handle);

  register_init_routine( atp_defragment_init);
  register_init_routine( &asp_reinit);

  afp_handle = find_dissector("afp");
  data_handle = find_dissector("data");
}
