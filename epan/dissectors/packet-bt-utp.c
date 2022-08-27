/* packet-bt-utp.c
 * Routines for BT-UTP dissection
 * Copyright 2011, Xiao Xiangquan <xiaoxiangquan@gmail.com>
 * Copyright 2021, John Thacker <johnthacker@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>

#include "packet-udp.h"
#include "packet-bt-utp.h"

void proto_register_bt_utp(void);
void proto_reg_handoff_bt_utp(void);

enum {
  ST_DATA  = 0,
  ST_FIN   = 1,
  ST_STATE = 2,
  ST_RESET = 3,
  ST_SYN   = 4,
  ST_NUM_STATES
};

/* V0 hdr: "flags"; V1 hdr: "type" */
static const value_string bt_utp_type_vals[] = {
  { ST_DATA,  "Data"  },
  { ST_FIN,   "Fin"   },
  { ST_STATE, "State" },
  { ST_RESET, "Reset" },
  { ST_SYN,   "Syn"   },
  { 0, NULL }
};

enum {
  EXT_NO_EXTENSION    = 0,
  EXT_SELECTIVE_ACKS  = 1,
  EXT_EXTENSION_BITS  = 2,
  EXT_CLOSE_REASON    = 3,
  EXT_NUM_EXT
};

static const value_string bt_utp_extension_type_vals[] = {
  { EXT_NO_EXTENSION,   "No Extension" },
  { EXT_SELECTIVE_ACKS, "Selective ACKs" },
  { EXT_EXTENSION_BITS, "Extension bits" },
  { EXT_CLOSE_REASON,   "Close reason" },
  { 0, NULL }
};

/* https://github.com/arvidn/libtorrent/blob/master/include/libtorrent/close_reason.hpp */
static const value_string bt_utp_close_reason_vals[] = {
  {  0, "None" },
  {  1, "Duplicate peer ID" },
  {  2, "Torrent removed" },
  {  3, "Memory allocation failed" },
  {  4, "Port blocked" },
  {  5, "Address blocked" },
  {  6, "Upload to upload" },
  {  7, "Not interested upload only" },
  {  8, "Timeout" },
  {  9, "Timeout: interest" },
  { 10, "Timeout: activity" },
  { 11, "Timeout: handshake" },
  { 12, "Timeout: request" },
  { 13, "Protocol blocked" },
  { 14, "Peer churn" },
  { 15, "Too many connections" },
  { 16, "Too many files" },
  /* Reasons caused by the peer sending unexpected data are 256 and up */
  {256, "Encryption error" },
  {257, "Invalid info hash" },
  {258, "Self connection" },
  {259, "Invalid metadata" },
  {260, "Metadata too big" },
  {261, "Message too big" },
  {262, "Invalid message id" },
  {263, "Invalid message" },
  {264, "Invalid piece message" },
  {265, "Invalid have message" },
  {266, "Invalid bitfield message" },
  {267, "Invalid choke message" },
  {268, "Invalid unchoke message" },
  {269, "Invalid interested message" },
  {270, "Invalid not interested message" },
  {271, "Invalid request message" },
  {272, "Invalid reject message" },
  {273, "Invalid allow fast message" },
  {274, "Invalid extended message" },
  {275, "Invalid cancel message" },
  {276, "Invalid DHT port message" },
  {277, "Invalid suggest message" },
  {278, "Invalid have all message" },
  {279, "Invalid don't have message" },
  {280, "Invalid PEX message" },
  {281, "Invalid metadata request message" },
  {282, "Invalid metadata message" },
  {283, "Invalid metadata offset" },
  {284, "Request when choked" },
  {285, "Corrupt pieces" },
  {286, "PEX message too big" },
  {287, "PEX too frequent" },
  {  0, NULL }
};

static int proto_bt_utp = -1;

/* ---  "Original" uTP Header ("version 0" ?) --------------

See utp.cpp source code @ https://github.com/bittorrent/libutp

-- Fixed Header --
0       4       8               16              24              32
+-------+-------+---------------+---------------+---------------+
| connection_id                                                 |
+-------+-------+---------------+---------------+---------------+
| timestamp_seconds                                             |
+---------------+---------------+---------------+---------------+
| timestamp_microseconds                                        |
+---------------+---------------+---------------+---------------+
| timestamp_difference_microseconds                             |
+---------------+---------------+---------------+---------------+
| wnd_size      | ext           | flags         | seq_nr [ho]   |
+---------------+---------------+---------------+---------------+
| seq_nr [lo]   | ack_nr                        |
+---------------+---------------+---------------+

-- Extension Field(s) --
0               8               16
+---------------+---------------+---------------+---------------+
| extension     | len           | bitmask
+---------------+---------------+---------------+---------------+
                                |
+---------------+---------------+....

*/

/* --- Version 1 Header ----------------

Specifications: BEP-0029
http://www.bittorrent.org/beps/bep_0029.html

-- Fixed Header --
Fields Types
0       4       8               16              24              32
+-------+-------+---------------+---------------+---------------+
| type  | ver   | extension     | connection_id                 |
+-------+-------+---------------+---------------+---------------+
| timestamp_microseconds                                        |
+---------------+---------------+---------------+---------------+
| timestamp_difference_microseconds                             |
+---------------+---------------+---------------+---------------+
| wnd_size                                                      |
+---------------+---------------+---------------+---------------+
| seq_nr                        | ack_nr                        |
+---------------+---------------+---------------+---------------+

-- Extension Field(s) --
0               8               16
+---------------+---------------+---------------+---------------+
| extension     | len           | bitmask
+---------------+---------------+---------------+---------------+
                                |
+---------------+---------------+....
*/

#define V0_FIXED_HDR_SIZE 23
#define V1_FIXED_HDR_SIZE 20

/* Very early versions of libutp (still used by Transmission) set the max
 * recv window size to 0x00380000, versions from 2013 and later set it to
 * 0x00100000, and some other clients use 0x00040000. This is one of the
 * few possible sources of heuristics.
 */

#define V1_MAX_WINDOW_SIZE 0x380000U

static dissector_handle_t bt_utp_handle;
static dissector_handle_t bittorrent_handle;

static int hf_bt_utp_ver = -1;
static int hf_bt_utp_type = -1;
static int hf_bt_utp_flags = -1;
static int hf_bt_utp_extension = -1;
static int hf_bt_utp_next_extension_type = -1;
static int hf_bt_utp_extension_len = -1;
static int hf_bt_utp_extension_bitmask = -1;
static int hf_bt_utp_extension_close_reason = -1;
static int hf_bt_utp_extension_unknown = -1;
static int hf_bt_utp_connection_id_v0 = -1;
static int hf_bt_utp_connection_id_v1 = -1;
static int hf_bt_utp_stream = -1;
static int hf_bt_utp_timestamp_sec = -1;
static int hf_bt_utp_timestamp_us = -1;
static int hf_bt_utp_timestamp_diff_us = -1;
static int hf_bt_utp_wnd_size_v0 = -1;
static int hf_bt_utp_wnd_size_v1 = -1;
static int hf_bt_utp_seq_nr = -1;
static int hf_bt_utp_ack_nr = -1;
static int hf_bt_utp_len = -1;
static int hf_bt_utp_data = -1;
static int hf_bt_utp_pdu_size = -1;
static int hf_bt_utp_continuation_to = -1;

static expert_field ei_extension_len_invalid = EI_INIT;

static gint ett_bt_utp = -1;
static gint ett_bt_utp_extension = -1;

static gboolean enable_version0 = FALSE;
static guint max_window_size = V1_MAX_WINDOW_SIZE;
/* XXX: Desegementation and OOO-reassembly are not supported yet */
static gboolean utp_desegment = FALSE;
/*static gboolean utp_reassemble_out_of_order = FALSE;*/
static gboolean utp_analyze_seq = TRUE;

static guint32 bt_utp_stream_count = 0;

typedef struct _utp_multisegment_pdu {

  guint16 first_seq;
  guint16 last_seq;
  guint first_seq_start_offset;
  guint last_seq_end_offset;
  /*gint length;
  guint32 reassembly_id;*/
  guint32 first_frame;

} utp_multisegment_pdu;

typedef struct _utp_flow_t {
#if 0
  /* XXX: Some other things to add in later. */
  gboolean base_seq_set;
  guint16 base_seq;
  guint32 fin;
  guint32 window;
  guint32 maxnextseq;
#endif

  wmem_tree_t *multisegment_pdus;
} utp_flow_t;

typedef struct {
  guint32 stream;

  utp_flow_t flow[2];
  utp_flow_t *fwd;
  utp_flow_t *rev;
#if 0
  /* XXX: Some other things to add in later. */
  nstime_t ts_first;
  nstime_t ts_prev;
  guint8 conversation_completeness;
#endif
} utp_stream_info_t;

/* Per-packet header information. */
typedef struct {
  guint8  type;
  gboolean v0;
  guint32 connection; /* The prelease "V0" version is 32 bit */
  guint32 stream;
  guint16 seq;
  guint16 ack;
  guint32 seglen; /* reported length remaining */
  gboolean have_seglen;

  proto_tree *tree; /* For the bittorrent subdissector to access */
} utp_info_t;

static utp_stream_info_t*
get_utp_stream_info(packet_info *pinfo, utp_info_t *utp_info)
{
  conversation_t* conv;
  utp_stream_info_t *stream_info;
  guint32 id_up, id_down;
  int direction;

  /* Handle connection ID wrapping correctly. (Mainline libutp source
   * does not appear to do this, probably fails to connect if the random
   * connection ID is GMAX_UINT16 and tries again.)
   */
  if (utp_info->v0) {
    id_up = utp_info->connection+1;
    id_down = utp_info->connection-1;
  } else {
    id_up = (guint16)(utp_info->connection+1);
    id_down = (guint16)(utp_info->connection-1);
  }

  if (utp_info->type == ST_SYN) {
    /* SYN packets are special, they have the connection ID for the other
     * side, and allow us to know both.
     */
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_BT_UTP,
 id_up, utp_info->connection, 0);
    if (!conv) {
      /* XXX: A SYN for between the same pair of hosts with a duplicate
       * connection ID in the same direction is almost surely a retransmission
       * (unless there's a client that doesn't actually generate random IDs.)
       * We could check to see if we've gotten a FIN or RST on that same
       * connection, and also could do like TCP and see if the initial sequence
       * number matches. (The latter still doesn't help if the client also
       * doesn't start with random sequence numbers.)
       */
      conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_BT_UTP, id_up, utp_info->connection, 0);
    }
  } else {
    /* For non-SYN packets, we know our connection ID, but we don't know if
     * the other side has our ID+1 (src initiated the connection) or our ID-1
     * (dst initiated). We also don't want find_conversation() to accidentally
     * call conversation_set_port2() with the wrong ID. So first we see if
     * we have a wildcarded conversation around (if we've seen previous
     * non-SYN packets from our current direction but none in the other.)
     */
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_BT_UTP, utp_info->connection, 0, NO_PORT_B);
    if (!conv) {
      /* Do we have a complete conversation originated by our src, or
       * possibly a wildcarded conversation originated in this direction
       * (but we saw a non-SYN for the non-initiating side first)? */
      conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_BT_UTP, utp_info->connection, id_up, 0);
      if (!conv) {
        /* As above, but dst initiated? */
        conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_BT_UTP, utp_info->connection, id_down, 0);
        if (!conv) {
          /* Didn't find it, so create a new wildcarded conversation. When we
           * get a packet for the other direction, find_conversation() above
           * will set port2 with the other connection ID.
           */
          conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_BT_UTP, utp_info->connection, 0, NO_PORT2);
        }
      }
    }
  }

  stream_info = (utp_stream_info_t *)conversation_get_proto_data(conv, proto_bt_utp);
  if (!stream_info) {
    stream_info = wmem_new0(wmem_file_scope(), utp_stream_info_t);
    stream_info->stream = bt_utp_stream_count++;
    stream_info->flow[0].multisegment_pdus=wmem_tree_new(wmem_file_scope());
    stream_info->flow[1].multisegment_pdus=wmem_tree_new(wmem_file_scope());
    conversation_add_proto_data(conv, proto_bt_utp, stream_info);
  }

  /* check direction */
  direction=cmp_address(&pinfo->src, &pinfo->dst);
  /* if the addresses are equal, match the ports instead. Use
   * the UDP ports instead of the uTP connection IDs because
   * we don't know which ID is smaller if we don't have both. */
  if(direction==0) {
      direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
  }
  if(direction>=0) {
      stream_info->fwd=&(stream_info->flow[0]);
      stream_info->rev=&(stream_info->flow[1]);
  } else {
      stream_info->fwd=&(stream_info->flow[1]);
      stream_info->rev=&(stream_info->flow[0]);
  }

  return stream_info;
}

static void
print_pdu_tracking_data(packet_info *pinfo, tvbuff_t *tvb, proto_tree *utp_tree, utp_multisegment_pdu *msp)
{
    proto_item *item;

    col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Continuation to #%u] ", msp->first_frame);
    item=proto_tree_add_uint(utp_tree, hf_bt_utp_continuation_to,
        tvb, 0, 0, msp->first_frame);
    proto_item_set_generated(item);
}

static int
scan_for_next_pdu(tvbuff_t *tvb, proto_tree *utp_tree, packet_info *pinfo, wmem_tree_t *multisegment_pdus)
{
  utp_multisegment_pdu *msp;
  utp_info_t *p_utp_info;
  guint16 seq, prev_seq;

  p_utp_info = (utp_info_t *)p_get_proto_data(pinfo->pool, pinfo, proto_bt_utp, pinfo->curr_layer_num);

  /* XXX: Wraparound is possible, as is cycling through all 16 bit
   * sequence numbers in a connection. We only do this path if
   * "seq analysis" is on; that ought to do something (relative
   * sequence numbers definitely, maybe extend the width?) to help,
   * but doesn't yet.
   */
  seq = p_utp_info->seq;
  prev_seq = seq - 1;
  msp = (utp_multisegment_pdu *)wmem_tree_lookup32_le(multisegment_pdus, prev_seq);
  if (msp) {

    if(seq>msp->first_seq && seq<=msp->last_seq) {
      print_pdu_tracking_data(pinfo, tvb, utp_tree, msp);
    }

    /* If this segment is completely within a previous PDU
     * then we just skip this packet
     */
    if(seq>msp->first_seq && seq<msp->last_seq) {
      return -1;
    }

    if(seq>msp->first_seq && seq==msp->last_seq) {
      if (!PINFO_FD_VISITED(pinfo) && p_utp_info->have_seglen) {
        /* Unlike TCP, the sequence numbers don't measure bytes, so
         * we can only really update the end of the MSP when the packets
         * are in order, and if we have the real segment length (so not
         * an unreassembled IP fragment).
         */
        if (p_utp_info->seglen >= msp->last_seq_end_offset) {
          return msp->last_seq_end_offset;
        } else {
          msp->last_seq++;
          msp->last_seq_end_offset -= p_utp_info->seglen;
          return -1;
        }
      } else {
        /* We can still provide a hint to the offset start in some
         * cases even when we can't update the MSP.
         */
        if (msp->last_seq_end_offset < tvb_reported_length(tvb)) {
          return msp->last_seq_end_offset;
        } else {
          return -1;
        }
      }
    }
  }

  return 0;
}

static utp_multisegment_pdu *
pdu_store_sequencenumber_of_next_pdu(packet_info *pinfo, guint16 seq, int offset, guint32 bytes_until_next_pdu, wmem_tree_t *multisegment_pdus)
{
  utp_multisegment_pdu *msp;

  msp = wmem_new(wmem_file_scope(), utp_multisegment_pdu);
  msp->first_seq = seq;
  msp->first_seq_start_offset = offset;
  msp->last_seq = seq+1;
  msp->last_seq_end_offset = bytes_until_next_pdu;
  msp->first_frame = pinfo->num;
  wmem_tree_insert32(multisegment_pdus, seq, (void *)msp);

  return msp;
}

#if 0
static void
desegment_utp(tvbuff_t *tvb, packet_info *pinfo, int offset,
              guint32 seq, guint32 nxtseq,
              proto_tree *tree, proto_tree *utp_tree,
              utp_stream_info_t *stream_info)
{

}
#endif

void
utp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 gboolean proto_desegment, guint fixed_len,
                 guint (*get_pdu_len)(packet_info *, tvbuff_t *, int, void*),
                 dissector_t dissect_pdu, void* dissector_data)
{
  volatile int offset = 0;
  int offset_before;
  guint captured_length_remaining;
  volatile guint plen;
  guint length;
  tvbuff_t *next_tvb;
  proto_item *item=NULL;
  const char *saved_proto;
  guint8 curr_layer_num;
  wmem_list_frame_t *frame;

  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    /*
     * We use "tvb_ensure_captured_length_remaining()" to make
     * sure there actually *is* data remaining.  The protocol
     * we're handling could conceivably consists of a sequence of
     * fixed-length PDUs, and therefore the "get_pdu_len" routine
     * might not actually fetch anything from the tvbuff, and thus
     * might not cause an exception to be thrown if we've run past
     * the end of the tvbuff.
     *
     * This means we're guaranteed that "captured_length_remaining" is positive.
     */
    captured_length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

    /*
     * Can we do reassembly?
     */
    if (proto_desegment && pinfo->can_desegment) {
      /*
       * Yes - is the fixed-length part of the PDU split across segment
       * boundaries?
       */
      if (captured_length_remaining < fixed_len) {
        /*
         * Yes.  Tell the uTP dissector where the data for this message
         * starts in the data it handed us and that we need "some more
         * data."  Don't tell it exactly how many bytes we need because
         * if/when we ask for even more (after the header) that will
         * break reassembly.
         */
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        return;
      }
    }

    /*
     * Get the length of the PDU.
     */
    plen = (*get_pdu_len)(pinfo, tvb, offset, dissector_data);
    if (plen == 0) {
      /*
       * Support protocols which have a variable length which cannot
       * always be determined within the given fixed_len.
       */
      DISSECTOR_ASSERT(proto_desegment && pinfo->can_desegment);
      pinfo->desegment_offset = offset;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return;
    }
    if (plen < fixed_len) {
      /*
       * Either:
       *
       *  1) the length value extracted from the fixed-length portion
       *     doesn't include the fixed-length portion's length, and
       *     was so large that, when the fixed-length portion's
       *     length was added to it, the total length overflowed;
       *
       *  2) the length value extracted from the fixed-length portion
       *     includes the fixed-length portion's length, and the value
       *     was less than the fixed-length portion's length, i.e. it
       *     was bogus.
       *
       * Report this as a bounds error.
       */
      show_reported_bounds_error(tvb, pinfo, tree);
      return;
    }

    /* give a hint to uTP where the next PDU starts
     * so that it can attempt to find it in case it starts
     * somewhere in the middle of a segment.
     */
    if(!pinfo->fd->visited && utp_analyze_seq) {
      guint remaining_bytes;
      remaining_bytes = tvb_reported_length_remaining(tvb, offset);
      if(plen>remaining_bytes) {
        pinfo->want_pdu_tracking=2;
        pinfo->bytes_until_next_pdu=plen-remaining_bytes;
      }
    }

    /*
     * Can we do reassembly?
     */
    if (proto_desegment && pinfo->can_desegment) {
      /*
       * Yes - is the PDU split across segment boundaries?
       */
      if (captured_length_remaining < plen) {
        /*
         * Yes.  Tell the TCP dissector where the data for this message
         * starts in the data it handed us, and how many more bytes we
         * need, and return.
         */
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = plen - captured_length_remaining;
        return;
      }
    }

    curr_layer_num = pinfo->curr_layer_num-1;
    frame = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
    while (frame && (proto_bt_utp != (gint) GPOINTER_TO_UINT(wmem_list_frame_data(frame)))) {
      frame = wmem_list_frame_prev(frame);
      curr_layer_num--;
    }
#if 0
    if (captured_length_remaining >= plen || there are more packets)
    {
#endif
          /*
           * Display the PDU length as a field
           */
          item=proto_tree_add_uint(((utp_info_t *)p_get_proto_data(pinfo->pool, pinfo, proto_bt_utp, curr_layer_num))->tree,
                                   hf_bt_utp_pdu_size,
                                   tvb, offset, plen, plen);
          proto_item_set_generated(item);
#if 0
    } else {
          item = proto_tree_add_expert_format((proto_tree *)p_get_proto_data(pinfo->pool, pinfo, proto_bt_utp, curr_layer_num),
                                  tvb, offset, -1,
              "PDU Size: %u cut short at %u",plen,captured_length_remaining);
          proto_item_set_generated(item);
    }
#endif

    /*
     * Construct a tvbuff containing the amount of the payload we have
     * available.  Make its reported length the amount of data in the PDU.
     */
    length = captured_length_remaining;
    if (length > plen) {
      length = plen;
    }
    next_tvb = tvb_new_subset_length_caplen(tvb, offset, length, plen);
    if (!(proto_desegment && pinfo->can_desegment)) {
      /* If we can't do reassembly, give a hint that bounds errors
       * are probably fragment errors. */
      tvb_set_fragment(next_tvb);
    }

    /*
     * Dissect the PDU.
     *
     * If it gets an error that means there's no point in
     * dissecting any more PDUs, rethrow the exception in
     * question.
     *
     * If it gets any other error, report it and continue, as that
     * means that PDU got an error, but that doesn't mean we should
     * stop dissecting PDUs within this frame or chunk of reassembled
     * data.
     */
    saved_proto = pinfo->current_proto;
    TRY {
      (*dissect_pdu)(next_tvb, pinfo, tree, dissector_data);
    }
    CATCH_NONFATAL_ERRORS {
      show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
      /*
       * Restore the saved protocol as well; we do this after
       * show_exception(), so that the "Malformed packet" indication
       * shows the protocol for which dissection failed.
       */
      pinfo->current_proto = saved_proto;
    }
    ENDTRY;

    /*
     * Step to the next PDU.
     * Make sure we don't overflow.
     */
    offset_before = offset;
    offset += plen;
    if (offset <= offset_before)
        break;
  }
}

static gint
get_utp_version(tvbuff_t *tvb) {
  guint8  v0_flags;
  guint8  v1_ver_type, ext, ext_len;
  guint32 window;
  guint   len, offset = 0;
  gint    ver = -1;

  /* Simple heuristics inspired by code from utp.cpp */

  len = tvb_captured_length(tvb);

  /* Version 1? */
  if (len < V1_FIXED_HDR_SIZE) {
    return -1;
  }

  v1_ver_type = tvb_get_guint8(tvb, 0);
  ext = tvb_get_guint8(tvb, 1);
  if (((v1_ver_type & 0x0f) == 1) && ((v1_ver_type>>4) < ST_NUM_STATES) &&
      (ext < EXT_NUM_EXT)) {
    window = tvb_get_guint32(tvb, 12, ENC_BIG_ENDIAN);
    if (window > max_window_size) {
      return -1;
    }
    ver = 1;
    offset = V1_FIXED_HDR_SIZE;
  } else if (enable_version0) {
    /* Version 0? */
    if (len < V0_FIXED_HDR_SIZE) {
      return -1;
    }
    v0_flags = tvb_get_guint8(tvb, 18);
    ext = tvb_get_guint8(tvb, 17);
    if ((v0_flags < ST_NUM_STATES) && (ext < EXT_NUM_EXT)) {
      ver = 0;
      offset = V0_FIXED_HDR_SIZE;
    }
  }

  if (ver < 0) {
    return ver;
  }

  /* In V0 we could use the microseconds value as a heuristic, because
   * it was tv_usec, but in the modern V1 we cannot, because it is
   * computed by converting a time_t into a 64 bit quantity of microseconds
   * and then taking the lower 32 bits, so all possible values are likely.
   */
  /* If we have an extension, then check the next two bytes,
   * the first of which is another extension type (likely NO_EXTENSION)
   * and the second of which is a length, which must be at least 4.
   */
  if (ext != EXT_NO_EXTENSION) {
    if (len < offset + 2) {
      return -1;
    }
    ext = tvb_get_guint8(tvb, offset);
    ext_len = tvb_get_guint8(tvb, offset+1);
    if (ext >= EXT_NUM_EXT || ext_len < 4) {
      return -1;
    }
  }

  return ver;
}

static int
dissect_utp_header_v0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  /* "Original" (V0) */
  utp_info_t        *p_utp_info = NULL;
  utp_stream_info_t *stream_info = NULL;

  proto_item     *ti;
  guint32 type, connection, win, seq, ack;

  p_utp_info = wmem_new(pinfo->pool, utp_info_t);
  p_utp_info->v0 = TRUE;
  p_add_proto_data(pinfo->pool, pinfo, proto_bt_utp, pinfo->curr_layer_num, p_utp_info);

  proto_tree_add_item_ret_uint(tree, hf_bt_utp_connection_id_v0, tvb, offset, 4, ENC_BIG_ENDIAN, &connection);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_diff_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_wnd_size_v0, tvb, offset, 1, ENC_BIG_ENDIAN, &win);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  *extension_type = tvb_get_guint8(tvb, offset);
  offset += 1;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_flags, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
  offset += 1;

  col_append_fstr(pinfo->cinfo, COL_INFO, "Connection ID:%d [%s]", connection, val_to_str(type, bt_utp_type_vals, "Unknown %d"));
  p_utp_info->type = type;
  p_utp_info->connection = connection;

  proto_tree_add_item(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item_ret_uint(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &seq);
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Seq", seq, " ");
  p_utp_info->seq = seq;
  offset += 2;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &ack);
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Ack", ack, " ");
  p_utp_info->ack = ack;
  offset += 2;
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Win", win, " ");

  stream_info = get_utp_stream_info(pinfo, p_utp_info);
  ti = proto_tree_add_uint(tree, hf_bt_utp_stream, tvb, offset, 0, stream_info->stream);
  p_utp_info->stream = stream_info->stream;
  proto_item_set_generated(ti);

  return offset;
}

static int
dissect_utp_header_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  /* V1 */
  utp_info_t        *p_utp_info = NULL;
  utp_stream_info_t *stream_info = NULL;

  proto_item     *ti;

  guint32 type, connection, win, seq, ack;

  p_utp_info = wmem_new(pinfo->pool, utp_info_t);
  p_utp_info->v0 = FALSE;
  p_add_proto_data(pinfo->pool, pinfo, proto_bt_utp, pinfo->curr_layer_num, p_utp_info);

  proto_tree_add_item(tree, hf_bt_utp_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  *extension_type = tvb_get_guint8(tvb, offset);
  offset += 1;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_connection_id_v1, tvb, offset, 2, ENC_BIG_ENDIAN, &connection);
  offset += 2;

  col_append_fstr(pinfo->cinfo, COL_INFO, "Connection ID:%d [%s]", connection, val_to_str(type, bt_utp_type_vals, "Unknown %d"));
  p_utp_info->type = type;
  p_utp_info->connection = connection;

  proto_tree_add_item(tree, hf_bt_utp_timestamp_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_diff_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_wnd_size_v1, tvb, offset, 4, ENC_BIG_ENDIAN, &win);
  offset += 4;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &seq);
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Seq", seq, " ");
  p_utp_info->seq = seq;
  offset += 2;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &ack);
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Ack", ack, " ");
  p_utp_info->ack = ack;
  offset += 2;
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Win", win, " ");

  stream_info = get_utp_stream_info(pinfo, p_utp_info);
  ti = proto_tree_add_uint(tree, hf_bt_utp_stream, tvb, offset, 0, stream_info->stream);
  p_utp_info->stream = stream_info->stream;
  proto_item_set_generated(ti);

  /* XXX: Multisegment PDUs are the top priority to add, but a number of
   * other features in the TCP dissector would be useful- relative sequence
   * numbers, conversation completeness, maybe even tracking SACKs.
   */
  return offset;
}

static int
dissect_utp_extension(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  proto_item *ti;
  proto_tree *ext_tree;
  guint32 next_extension, extension_length;
  /* display the extension tree */

  while(*extension_type != EXT_NO_EXTENSION && offset < (int)tvb_reported_length(tvb))
  {
    ti = proto_tree_add_none_format(tree, hf_bt_utp_extension, tvb, offset, -1, "Extension: %s", val_to_str_const(*extension_type, bt_utp_extension_type_vals, "Unknown"));
    ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

    proto_tree_add_item_ret_uint(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN, &next_extension);
    offset += 1;

    proto_tree_add_item_ret_uint(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_length);
    proto_item_append_text(ti, ", Len=%d", extension_length);
    offset += 1;

    switch(*extension_type){
      case EXT_SELECTIVE_ACKS: /* 1 */
      {
        proto_tree_add_item(ext_tree, hf_bt_utp_extension_bitmask, tvb, offset, extension_length, ENC_NA);
        break;
      }
      case EXT_EXTENSION_BITS: /* 2 */
      {
        proto_tree_add_item(ext_tree, hf_bt_utp_extension_bitmask, tvb, offset, extension_length, ENC_NA);
        break;
      }
      case EXT_CLOSE_REASON: /* 3 */
      {
        if (extension_length != 4) {
          expert_add_info(pinfo, ti, &ei_extension_len_invalid);
        }
        proto_tree_add_item(ext_tree, hf_bt_utp_extension_close_reason, tvb, offset, 4, ENC_NA);
        break;
      }
      default:
        proto_tree_add_item(ext_tree, hf_bt_utp_extension_unknown, tvb, offset, extension_length, ENC_NA);
      break;
    }
    offset += extension_length;
    proto_item_set_len(ti, 1 + 1 + extension_length);
    *extension_type = next_extension;
  }

  return offset;
}

static gboolean
decode_utp(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree)
{
  proto_tree *parent_tree;
  tvbuff_t *next_tvb;
  int save_desegment_offset;
  guint32 save_desegment_len;

  /* XXX: Check for retransmission? */

  next_tvb = tvb_new_subset_remaining(tvb, offset);

  save_desegment_offset = pinfo->desegment_offset;
  save_desegment_len = pinfo->desegment_len;

  /* The only possible payload is bittorrent */

  parent_tree = proto_tree_get_parent_tree(tree);
  if (call_dissector_with_data(bittorrent_handle, next_tvb, pinfo, parent_tree, NULL)) {
    pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
    return TRUE;
  }

  DISSECTOR_ASSERT(save_desegment_offset == pinfo->desegment_offset &&
                   save_desegment_len == pinfo->desegment_len);

  call_data_dissector(tvb, pinfo, parent_tree);
  pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);

  return FALSE;
}

static void
process_utp_payload(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, guint16 seq, gboolean is_utp_segment,
    utp_stream_info_t *stream_info)
{
  volatile int offset = 0;
  pinfo->want_pdu_tracking = 0;

  TRY {
    if (is_utp_segment) {
      /* See if an unaligned PDU */
      if (stream_info && utp_analyze_seq && (!utp_desegment)) {
        offset = scan_for_next_pdu(tvb, tree, pinfo,
                stream_info->fwd->multisegment_pdus);
      }
    }

    if ((offset != -1) && decode_utp(tvb, offset, pinfo, tree)) {
      /*
       * We succeeded in handing off to bittorent.
       *
       * Is this a segment (so we're not desegmenting for whatever
       * reason)? Then at least do rudimentary PDU tracking.
       */
      if(is_utp_segment) {
        /* if !visited, check want_pdu_tracking and
           store it in table */
        if(stream_info && (!pinfo->fd->visited) &&
            utp_analyze_seq && pinfo->want_pdu_tracking) {
              pdu_store_sequencenumber_of_next_pdu(
                  pinfo,
                  seq,
                  offset,
                  pinfo->bytes_until_next_pdu,
                  stream_info->fwd->multisegment_pdus);
        }
      }
    }
  }
  CATCH_ALL {
    /* We got an exception. Before dissection is aborted and execution
     * is transferred back to (probably) the frame dissector, do PDU
     * tracking if we need to because this is a segment.
     */
    if (is_utp_segment) {
        if(stream_info && (!pinfo->fd->visited) &&
            utp_analyze_seq && pinfo->want_pdu_tracking) {
              pdu_store_sequencenumber_of_next_pdu(
                  pinfo,
                  seq,
                  offset,
                  pinfo->bytes_until_next_pdu,
                  stream_info->fwd->multisegment_pdus);
        }
    }
    RETHROW;
  }
  ENDTRY;
}

static guint
dissect_utp_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;

  utp_info_t *p_utp_info;
  guint len_tvb;
  gboolean save_fragmented;

  p_utp_info = (utp_info_t *)p_get_proto_data(pinfo->pool, pinfo, proto_bt_utp, pinfo->curr_layer_num);

  p_utp_info->tree = tree;

  utp_stream_info_t *stream_info;
  stream_info = get_utp_stream_info(pinfo, p_utp_info);

  len_tvb = tvb_reported_length(tvb);

  /* As with TCP, if we've been handed an IP fragment, we don't really
   * know how big the segment is, and we don't really want to do anything
   * if this is an error packet from ICMP or similar.
   *
   * XXX: We don't want to desegment if the UDP checksum is bad either.
   * Need to add that to the per-packet info that UDP stores and access
   * it.
   */
  pinfo->can_desegment = 0;
  if (!pinfo->fragmented && !pinfo->flags.in_error_pkt) {
    p_utp_info->seglen = len_tvb;
    p_utp_info->have_seglen = TRUE;

    ti = proto_tree_add_uint(tree, hf_bt_utp_len, tvb, 0, 0, len_tvb);
    proto_item_set_generated(ti);
    col_append_str_uint(pinfo->cinfo, COL_INFO, "Len", len_tvb, " ");

    if (utp_desegment && tvb_bytes_exist(tvb, 0, len_tvb)) {
      /* If we actually have the bytes too then we can desegment. */
      pinfo->can_desegment = 2;
    }
  } else {
    p_utp_info->have_seglen = FALSE;
  }

  if(tvb_captured_length(tvb)) {
    proto_tree_add_item(tree, hf_bt_utp_data, tvb, 0, len_tvb, ENC_NA);
    if (pinfo->can_desegment) {
      /* XXX: desegment_utp() is not implemented, but we can't get
       * into this code path yet because utp_desegment is FALSE. */
    } else {
      save_fragmented = pinfo->fragmented;
      pinfo->fragmented = TRUE;
      process_utp_payload(tvb, pinfo, tree, p_utp_info->seq, TRUE, stream_info);
      pinfo->fragmented = save_fragmented;
    }
  }

  return len_tvb;
}

static int
dissect_bt_utp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint version;
  version = get_utp_version(tvb);

  /* try dissecting */
  if (version >= 0)
  {
    proto_tree *sub_tree = NULL;
    proto_item *ti;
    gint offset = 0;
    guint8 extension_type;

    /* set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT-uTP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Determine header version */

    if (version == 0) {
      ti = proto_tree_add_protocol_format(tree, proto_bt_utp, tvb, 0, -1,
                                          "uTorrent Transport Protocol V0");
      sub_tree = proto_item_add_subtree(ti, ett_bt_utp);
      offset = dissect_utp_header_v0(tvb, pinfo, sub_tree, offset, &extension_type);
    } else {
      ti = proto_tree_add_item(tree, proto_bt_utp, tvb, 0, -1, ENC_NA);
      sub_tree = proto_item_add_subtree(ti, ett_bt_utp);
      offset = dissect_utp_header_v1(tvb, pinfo, sub_tree, offset, &extension_type);
    }

    offset = dissect_utp_extension(tvb, pinfo, sub_tree, offset, &extension_type);

    offset += dissect_utp_payload(tvb_new_subset_remaining(tvb, offset), pinfo, sub_tree);

    return offset;
  }
  return 0;
}

static gboolean
dissect_bt_utp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint version;
  version = get_utp_version(tvb);

  if (version >= 0)
  {
    conversation_t *conversation;

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector_from_frame_number(conversation, pinfo->num, bt_utp_handle);

    dissect_bt_utp(tvb, pinfo, tree, data);
    return TRUE;
  }

  return FALSE;
}

static void
utp_init(void)
{
  bt_utp_stream_count = 0;
}

void
proto_register_bt_utp(void)
{
  static hf_register_info hf[] = {
    { &hf_bt_utp_ver,
      { "Version", "bt-utp.ver",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL }
    },
    { &hf_bt_utp_flags,
      { "Flags", "bt-utp.flags",
      FT_UINT8, BASE_DEC,  VALS(bt_utp_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_type,
      { "Type", "bt-utp.type",
      FT_UINT8, BASE_DEC,  VALS(bt_utp_type_vals), 0xF0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension,
      { "Extension", "bt-utp.extension",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_next_extension_type,
      { "Next Extension Type", "bt-utp.next_extension_type",
      FT_UINT8, BASE_DEC, VALS(bt_utp_extension_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_len,
      { "Extension Length", "bt-utp.extension_len",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_bitmask,
      { "Extension Bitmask", "bt-utp.extension_bitmask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_close_reason,
      { "Close Reason", "bt-utp.extension_close_reason",
      FT_UINT32, BASE_DEC, VALS(bt_utp_close_reason_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_unknown,
      { "Extension Unknown", "bt-utp.extension_unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_connection_id_v0,
      { "Connection ID", "bt-utp.connection_id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_connection_id_v1,
      { "Connection ID", "bt-utp.connection_id",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_stream,
      { "Stream index", "bt-utp.stream",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_sec,
      { "Timestamp seconds", "bt-utp.timestamp_sec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_us,
      { "Timestamp Microseconds", "bt-utp.timestamp_us",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_diff_us,
      { "Timestamp Difference Microseconds", "bt-utp.timestamp_diff_us",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_wnd_size_v0,
      { "Window Size", "bt-utp.wnd_size",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "V0 receive window size, in multiples of 350 bytes", HFILL }
    },
    { &hf_bt_utp_wnd_size_v1,
      { "Window Size", "bt-utp.wnd_size",
      FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_seq_nr,
      { "Sequence number", "bt-utp.seq_nr",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_ack_nr,
      { "ACK number", "bt-utp.ack_nr",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_len,
      { "uTP Segment Len", "bt-utp.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_data,
      { "Data", "bt-utp.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_pdu_size,
      { "PDU Size", "bt-utp.pdu.size",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "The size of this PDU", HFILL }
    },
    { &hf_bt_utp_continuation_to,
      { "This is a continuation to the PDU in frame",
      "bt-utp.continuation_to", FT_FRAMENUM, BASE_NONE,
      NULL, 0x0, "This is a continuation to the PDU in frame #", HFILL }
    },
  };

  static ei_register_info ei[] = {
    { &ei_extension_len_invalid,
      { "bt-utp.extension_len.invalid", PI_PROTOCOL, PI_WARN,
        "The extension is an unexpected length", EXPFILL }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_bt_utp, &ett_bt_utp_extension };

  module_t *bt_utp_module;
  expert_module_t *expert_bt_utp;

  /* Register protocol */
  proto_bt_utp = proto_register_protocol ("uTorrent Transport Protocol", "BT-uTP", "bt-utp");

  bt_utp_module = prefs_register_protocol(proto_bt_utp, NULL);
  prefs_register_obsolete_preference(bt_utp_module, "enable");
  prefs_register_bool_preference(bt_utp_module,
      "analyze_sequence_numbers",
      "Analyze uTP sequence numbers",
      "Make the uTP dissector analyze uTP sequence numbers. Currently this "
      "just means that it tries to find the correct start offset of a PDU "
      "if it detected that previous in-order packets spanned multiple "
      "frames.",
      &utp_analyze_seq);
  prefs_register_bool_preference(bt_utp_module,
      "enable_version0",
      "Dissect prerelease (version 0) packets",
      "Whether the dissector should attempt to dissect packets with the "
      "obsolete format (version 0) that predates BEP 29 (22-Jun-2009)",
      &enable_version0);
  prefs_register_uint_preference(bt_utp_module,
      "max_window_size",
      "Maximum window size (in hex)",
      "Maximum receive window size allowed by the dissector. Early clients "
      "(and a few modern ones) set this value to 0x380000 (the default), "
      "later ones use smaller values like 0x100000 and 0x40000. A higher "
      "value can detect nonstandard packets, but at the cost of false "
      "positives.",
      16, &max_window_size);

  proto_register_field_array(proto_bt_utp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_bt_utp = expert_register_protocol(proto_bt_utp);
  expert_register_field_array(expert_bt_utp, ei, array_length(ei));

  register_init_routine(utp_init);
}

void
proto_reg_handoff_bt_utp(void)
{
  /* disabled by default since heuristic is weak */
  /* XXX: The heuristic is stronger now, but might still get false positives
   * on packets with lots of zero bytes. Needs more testing before enabling
   * by default.
   */
  heur_dissector_add("udp", dissect_bt_utp_heur, "BitTorrent UTP over UDP", "bt_utp_udp", proto_bt_utp, HEURISTIC_DISABLE);

  bt_utp_handle = create_dissector_handle(dissect_bt_utp, proto_bt_utp);
  dissector_add_for_decode_as_with_preference("udp.port", bt_utp_handle);

  bittorrent_handle = find_dissector_add_dependency("bittorrent.utp", proto_bt_utp);
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

