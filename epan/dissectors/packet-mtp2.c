/* packet-mtp2.c
 * Routines for MTP2 dissection
 * It is hopefully (needs testing) compliant to
 * ITU-T Q.703 and Q.703 Annex A.
 *
 * Copyright 2001, 2004 Michael Tuexen <tuexen [AT] fh-muenster.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-m2pa.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/crc16-tvb.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>

void proto_register_mtp2(void);
void proto_reg_handoff_mtp2(void);

static dissector_handle_t mtp2_handle;

/* possible packet states */
enum packet_direction_state_mtp2 {FORWARD, BACKWARD};

/* structure for telling the bitstream dissector if it shall use a mtp2_flag_search value from the prev. packet */
typedef struct mtp2_flag_search {
  gboolean      set;            /* shows if the mtp2_flag_search value is valid, needed to be set in the dissect function */
  guint8        mtp2_flag_search;    /* mtp2_flag_search value itself */
} mtp2_mtp2_flag_search_t;

/* Possible states of the state machine for decoding the MTP2 bitstream */
enum mtp2_bitstream_states {OUT_OF_SYNC, FLAGS, DATA};

/* data type for chained list of found MTP2 packets in RTP stream */
typedef struct mtp2_recognized_packet {
  tvbuff_t                *data;              /* data of the actual packet */
  guint8                  unalignment_offset; /* !=0 signals if this packet was not a multiple of 8 bits in the stream */
} mtp2_recognized_packet_t;

/* structure used in mtp2_dissect_tvb_res
   this contains the tvb's before the first and after last header */
typedef struct mtp2_remain_data {
  tvbuff_t        *before_first_flag;              /* data found before the first flag */
  tvbuff_t        *after_last_flag;                /* data found after the last flag */
  guint8          before_fh_unalignment_offset;    /* !=0 signals if the before_fh data was not a multiple of 8 bits in the stream */
  gboolean        before_fh_frame_reset;           /* signals if there was a frame reset in the data before the 1st flag */
} mtp2_remain_data_t;


/* structure to store the result of dissect_mtp2_tvb function */
typedef struct mtp2_dissect_tvb_res {
  mtp2_remain_data_t              mtp2_remain_data;       /* stores the tvbuffs found before 1st and after last flags in the packet */
  mtp2_mtp2_flag_search_t         mtp2_flag_search;       /* this contains the mtp2_flag_search's value at the end of the packet dissection */
  wmem_list_t                     *found_packets;         /* contains the packets found in tvbuff */
  guint8                          data_buff;              /* to store the data_buff value */
  guint8                          data_buff_offset;       /* to store the data_buff_offset value */
  guint8                          last_flag_beginning_offset_for_align_check;     /* the offset of the last flag's beginning have to be stored */
  gboolean                        flag_found;             /* boolean value to sign if there was a flag in the RTP packet or not */
  enum mtp2_bitstream_states      state;                  /* to store the value of the state of the dissection after finish */
} mtp2_dissect_tvb_res_t;

/* mtp2 per-packet data */
typedef struct mtp2_ppd {
  mtp2_mtp2_flag_search_t         mtp2_flag_search;                               /* flag search needed to pass to dissect_mtp2_tvb - it was derived from the prev. packet in the same direction */
  guint8                          data_buff;                                      /* data buff needed to pass to dissect_mtp2_tvb - it was derived from the prev. packet in the same direction */
  guint8                          data_buff_offset;                               /* data buff offset needed to pass to dissect_mtp2_tvb - it was derived from the prev. packet in the same direction */
  guint8                          last_flag_beginning_offset_for_align_check;     /* variable for align check, stores the last flag's beginning's offset */
  guint32                         reass_seq_num_for_reass_check_before_fh;        /* this is the id (reass_seq_num) which should be used for looking up reassembled data found before the first flag */
  guint32                         reass_seq_num_for_reass_check_after_lh;         /* this is the id (reass_seq_num) which should be used for looking up reassembled data found after the last flag */
  enum mtp2_bitstream_states      state;                                          /* state needed to pass to dissect_mtp2_tvb - it was derived from the prev. packet in the same direction */
} mtp2_ppd_t;

/* conversation data about the previous packet in the conversation (in one direction) */
typedef struct mtp2_convo_data_prev_packet {
  mtp2_mtp2_flag_search_t       mtp2_flag_search;       /* storing the prev. packet's flag search */
  guint8                        data_buff;              /* storing the prev. packet's data buffer */
  guint8                        data_buff_offset;       /* storing the prev. packet's data buffer offset */
  guint8                        last_flag_beginning_offset_for_align_check;     /* storing the prev. packet's last flag's offset */
  guint32                       reass_seq_num;          /* storing the prev. packet's reassemble seq. num */
  enum mtp2_bitstream_states    state;                  /* storing the prev. packet's state in the forward direction */
} mtp2_convo_data_prev_packet_t;

/* conversation data for MTP2 dissection from RTP payload */
typedef struct mtp2_convo_data {
  address         addr_a;                               /* storing the first packet's originating address */
  address         addr_b;                               /* storing the first packet's terminating address */
  guint32         port_a;                               /* storing the first packet's originating port */
  guint32         port_b;                               /* storing the first packet's terminating port */
  mtp2_convo_data_prev_packet_t   *forward;             /* storing needed info about the prev. packet's in forward direction */
  mtp2_convo_data_prev_packet_t   *backward;            /* storing needed info about the prev. packet's in backward direction */
} mtp2_convo_data_t;

/* Initialize the protocol and registered fields */
static int proto_mtp2        = -1;
static int hf_mtp2_bsn       = -1;
static int hf_mtp2_ext_bsn   = -1;
static int hf_mtp2_ext_res   = -1;
static int hf_mtp2_bib       = -1;
static int hf_mtp2_ext_bib   = -1;
static int hf_mtp2_fsn       = -1;
static int hf_mtp2_ext_fsn   = -1;
static int hf_mtp2_fib       = -1;
static int hf_mtp2_ext_fib   = -1;
static int hf_mtp2_li        = -1;
static int hf_mtp2_ext_li    = -1;
static int hf_mtp2_spare     = -1;
static int hf_mtp2_ext_spare = -1;
static int hf_mtp2_sf        = -1;
static int hf_mtp2_sf_extra  = -1;
static int hf_mtp2_fcs_16    = -1;
static int hf_mtp2_fcs_16_status = -1;
static int hf_mtp2_unexpect_end = -1;
static int hf_mtp2_frame_reset = -1;

/* reassemble variables */
static int hf_mtp2_fragments = -1;
static int hf_mtp2_fragment = -1;
static int hf_mtp2_fragment_overlap = -1;
static int hf_mtp2_fragment_overlap_conflicts = -1;
static int hf_mtp2_fragment_multiple_tails = -1;
static int hf_mtp2_fragment_too_long_fragment = -1;
static int hf_mtp2_fragment_error = -1;
static int hf_mtp2_fragment_count = -1;
static int hf_mtp2_reassembled_in = -1;
static int hf_mtp2_reassembled_length = -1;
static gint ett_mtp2_fragment = -1;
static gint ett_mtp2_fragments = -1;

/* local static const needed for reassembly */
static const fragment_items mtp2_frag_items = {
  &ett_mtp2_fragment,
  &ett_mtp2_fragments,
  &hf_mtp2_fragments,
  &hf_mtp2_fragment,
  &hf_mtp2_fragment_overlap,
  &hf_mtp2_fragment_overlap_conflicts,
  &hf_mtp2_fragment_multiple_tails,
  &hf_mtp2_fragment_too_long_fragment,
  &hf_mtp2_fragment_error,
  &hf_mtp2_fragment_count,
  &hf_mtp2_reassembled_in,
  &hf_mtp2_reassembled_length,
  NULL,
  "MTP2 Message fragments"
};

/* needed for packet reassembly */
static reassembly_table mtp2_reassembly_table;

/* variables needed for property registration to wireshark menu */
static gboolean reverse_bit_order_mtp2 = FALSE;

static expert_field ei_mtp2_checksum_error = EI_INIT;
static expert_field ei_mtp2_li_bad = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_mtp2       = -1;

static dissector_handle_t mtp3_handle;
static gboolean use_extended_sequence_numbers_default = FALSE;
static gboolean capture_contains_fcs_crc_default = FALSE;

/* sequence number of the actual packet to be reassembled
 * this is needed because the reassemble handler uses a key based on the
 * source and destination IP addresses
 * therefore if there are multiple streams between 2 IP end-points
 * the reassemble sequence numbers can conflict if they are based on conversations */
static guint32    mtp2_absolute_reass_seq_num = 0;

#define BSN_BIB_LENGTH          1
#define FSN_FIB_LENGTH          1
#define LI_LENGTH               1
#define HEADER_LENGTH           (BSN_BIB_LENGTH + FSN_FIB_LENGTH + LI_LENGTH)

#define EXTENDED_BSN_BIB_LENGTH 2
#define EXTENDED_FSN_FIB_LENGTH 2
#define EXTENDED_LI_LENGTH      2
#define EXTENDED_HEADER_LENGTH  (EXTENDED_BSN_BIB_LENGTH + EXTENDED_FSN_FIB_LENGTH + EXTENDED_LI_LENGTH)

#define BSN_BIB_OFFSET          0
#define FSN_FIB_OFFSET          (BSN_BIB_OFFSET + BSN_BIB_LENGTH)
#define LI_OFFSET               (FSN_FIB_OFFSET + FSN_FIB_LENGTH)
#define SIO_OFFSET              (LI_OFFSET + LI_LENGTH)

#define EXTENDED_BSN_BIB_OFFSET 0
#define EXTENDED_FSN_FIB_OFFSET (EXTENDED_BSN_BIB_OFFSET + EXTENDED_BSN_BIB_LENGTH)
#define EXTENDED_LI_OFFSET      (EXTENDED_FSN_FIB_OFFSET + EXTENDED_FSN_FIB_LENGTH)
#define EXTENDED_SIO_OFFSET     (EXTENDED_LI_OFFSET + EXTENDED_LI_LENGTH)

#define BSN_MASK                0x7f
#define BIB_MASK                0x80
#define FSN_MASK                0x7f
#define FIB_MASK                0x80
#define LI_MASK                 0x3f
#define SPARE_MASK              0xc0

#define EXTENDED_BSN_MASK       0x0fff
#define EXTENDED_RES_MASK       0x7000
#define EXTENDED_BIB_MASK       0x8000
#define EXTENDED_FSN_MASK       0x0fff
#define EXTENDED_FIB_MASK       0x8000
#define EXTENDED_LI_MASK        0x01ff
#define EXTENDED_SPARE_MASK     0xfe00

/* remove comment to enable debugging of bitstream dissector
 * if enabled this produces printout to stderr like this for every packet:

start_dissect_bitstream_packet: 2120
11010010        SKIPPED ZEROS: 3.
10000000
01100001
01101111
10011111        SKIPPED ZEROS: 2.
10011001        FLAG FOUND
11110100        SKIPPED ZEROS: 5.
10100000
00011000
 * under the development it can be very helpful to see RTP packet content like this
 * to identify and solve problems regarding bitstream parsing*/
/*#define MTP2_BITSTREAM_DEBUG    1*/

#ifdef MTP2_BITSTREAM_DEBUG
#include <glib/gprintf.h>
#endif

static void
dissect_mtp2_header(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_tree, gboolean use_extended_sequence_numbers, gboolean validate_crc, guint32 *li)
{
  guint reported_len;
  proto_item *li_item;

  if (use_extended_sequence_numbers) {
    reported_len = tvb_reported_length_remaining(su_tvb, EXTENDED_HEADER_LENGTH);
    if (validate_crc) {
      reported_len = reported_len < 2 ? 0 : (reported_len - 2);
    }
    proto_tree_add_item(mtp2_tree, hf_mtp2_ext_bsn,   su_tvb, EXTENDED_BSN_BIB_OFFSET, EXTENDED_BSN_BIB_LENGTH, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mtp2_tree, hf_mtp2_ext_res,   su_tvb, EXTENDED_BSN_BIB_OFFSET, EXTENDED_BSN_BIB_LENGTH, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mtp2_tree, hf_mtp2_ext_bib,   su_tvb, EXTENDED_BSN_BIB_OFFSET, EXTENDED_BSN_BIB_LENGTH, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mtp2_tree, hf_mtp2_ext_fsn,   su_tvb, EXTENDED_FSN_FIB_OFFSET, EXTENDED_FSN_FIB_LENGTH, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mtp2_tree, hf_mtp2_ext_res,   su_tvb, EXTENDED_BSN_BIB_OFFSET, EXTENDED_BSN_BIB_LENGTH, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mtp2_tree, hf_mtp2_ext_fib,   su_tvb, EXTENDED_FSN_FIB_OFFSET, EXTENDED_FSN_FIB_LENGTH, ENC_LITTLE_ENDIAN);
    li_item = proto_tree_add_item_ret_uint(mtp2_tree, hf_mtp2_ext_li, su_tvb, EXTENDED_LI_OFFSET, EXTENDED_LI_LENGTH, ENC_LITTLE_ENDIAN, li);
    if (*li != reported_len) {
      /* ITU-T Q.703 A.2.3.3 When the extended sequence numbers are used,
       * the field is large enough to contain all legal values. 0-273.
       * Thus the check in the other case doesn't apply. */
      proto_item_append_text(li_item, " [expected payload length %u]", reported_len);
      expert_add_info_format(pinfo, li_item, &ei_mtp2_li_bad, "Bad length value %u != payload length ", *li);
      col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD MTP2 LI %u != PAYLOAD LENGTH]", *li);
    }
    proto_tree_add_item(mtp2_tree, hf_mtp2_ext_spare, su_tvb, EXTENDED_LI_OFFSET,      EXTENDED_LI_LENGTH,      ENC_LITTLE_ENDIAN);
  } else {
    reported_len = tvb_reported_length_remaining(su_tvb, HEADER_LENGTH);
    if (validate_crc) {
      reported_len = reported_len < 2 ? 0 : (reported_len - 2);
    }
    proto_tree_add_item(mtp2_tree, hf_mtp2_bsn,   su_tvb, BSN_BIB_OFFSET, BSN_BIB_LENGTH, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mtp2_tree, hf_mtp2_bib,   su_tvb, BSN_BIB_OFFSET, BSN_BIB_LENGTH, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mtp2_tree, hf_mtp2_fsn,   su_tvb, FSN_FIB_OFFSET, FSN_FIB_LENGTH, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mtp2_tree, hf_mtp2_fib,   su_tvb, FSN_FIB_OFFSET, FSN_FIB_LENGTH, ENC_LITTLE_ENDIAN);
    li_item = proto_tree_add_item_ret_uint(mtp2_tree, hf_mtp2_li, su_tvb, LI_OFFSET, LI_LENGTH, ENC_LITTLE_ENDIAN, li);
    /* ITU-T Q.703 2.3.3: In the case that the payload is more than the
     * li field allows, should be set to the max, i.e. the mask 63 */
    if (reported_len > LI_MASK) {
      if (*li != LI_MASK) {
        proto_item_append_text(li_item, " [payload length %u, expected max value %u]", reported_len, LI_MASK);
        expert_add_info_format(pinfo, li_item, &ei_mtp2_li_bad, "Bad length value %u != max value ", *li);
        col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD MTP2 LI %u != MAX VALUE]", *li);
      }
    } else if (*li != reported_len ) {
      proto_item_append_text(li_item, " [expected payload length %u]", reported_len);
      expert_add_info_format(pinfo, li_item, &ei_mtp2_li_bad, "Bad length value %u != payload length ", *li);
      col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD MTP2 LI %u != PAYLOAD LENGTH]", *li);
    }
    proto_tree_add_item(mtp2_tree, hf_mtp2_spare, su_tvb, LI_OFFSET,      LI_LENGTH,      ENC_LITTLE_ENDIAN);
  }
}
/*
*******************************************************************************
* DETAILS : Calculate a new FCS-16 given the current FCS-16 and the new data.
*******************************************************************************
*/
static guint16
mtp2_fcs16(tvbuff_t * tvbuff)
{
  guint len = tvb_reported_length(tvbuff)-2;

  /* Check for Invalid Length */
  if (len == 0)
    return (0x0000);
  return crc16_ccitt_tvb(tvbuff, len);
}

/*
 * This function for CRC16 only is based on the decode_fcs of packet_ppp.c
 */
static tvbuff_t *
mtp2_decode_crc16(tvbuff_t *tvb, proto_tree *fh_tree, packet_info *pinfo)
{
  tvbuff_t   *next_tvb;
  gint       len, reported_len;
  int proto_offset=0;

  /*
   * Do we have the entire packet, and does it include a 2-byte FCS?
   */
  len = tvb_reported_length_remaining(tvb, proto_offset);
  reported_len = tvb_reported_length_remaining(tvb, proto_offset);
  if (reported_len < 2 || len < 0) {
    /*
     * The packet is claimed not to even have enough data for a 2-byte FCS,
     * or we're already past the end of the captured data.
     * Don't slice anything off.
     */
    next_tvb = tvb_new_subset_remaining(tvb, proto_offset);
  } else if (len < reported_len) {
    /*
     * The packet is claimed to have enough data for a 2-byte FCS, but
     * we didn't capture all of the packet.
     * Slice off the 2-byte FCS from the reported length, and trim the
     * captured length so it's no more than the reported length; that
     * will slice off what of the FCS, if any, is in the captured
     * length.
     */
    reported_len -= 2;
    if (len > reported_len)
      len = reported_len;
    next_tvb = tvb_new_subset_length_caplen(tvb, proto_offset, len, reported_len);
  } else {
    /*
     * We have the entire packet, and it includes a 2-byte FCS.
     * Slice it off.
     */
    len -= 2;
    reported_len -= 2;
    next_tvb = tvb_new_subset_length_caplen(tvb, proto_offset, len, reported_len);

    /*
     * Compute the FCS and put it into the tree.
     */
    proto_tree_add_checksum(fh_tree, tvb, proto_offset + len, hf_mtp2_fcs_16, hf_mtp2_fcs_16_status, &ei_mtp2_checksum_error, pinfo, mtp2_fcs16(tvb),
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
  }
  return next_tvb;
}


static void
dissect_mtp2_fisu(packet_info *pinfo)
{
  col_set_str(pinfo->cinfo, COL_INFO, "FISU ");
}

static const value_string status_field_vals[] = {
  { 0x0, "Status Indication O" },
  { 0x1, "Status Indication N" },
  { 0x2, "Status Indication E" },
  { 0x3, "Status Indication OS" },
  { 0x4, "Status Indication PO" },
  { 0x5, "Status Indication B" },
  { 0,   NULL}
};

/* Same as above but in acronym form (for the Info column) */
static const value_string status_field_acro_vals[] = {
  { 0x0, "SIO" },
  { 0x1, "SIN" },
  { 0x2, "SIE" },
  { 0x3, "SIOS" },
  { 0x4, "SIPO" },
  { 0x5, "SIB" },
  { 0,   NULL}
};

#define SF_OFFSET          (LI_OFFSET + LI_LENGTH)
#define EXTENDED_SF_OFFSET (EXTENDED_LI_OFFSET + EXTENDED_LI_LENGTH)

#define SF_LENGTH                       1
#define SF_EXTRA_OFFSET                 (SF_OFFSET + SF_LENGTH)
#define EXTENDED_SF_EXTRA_OFFSET        (EXTENDED_SF_OFFSET + SF_LENGTH)
#define SF_EXTRA_LENGTH                 1

static void
dissect_mtp2_lssu(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_tree,
                  gboolean use_extended_sequence_numbers)
{
  guint8 sf = 0xFF;
  guint8 sf_offset, sf_extra_offset;

  if (use_extended_sequence_numbers) {
    sf_offset = EXTENDED_SF_OFFSET;
    sf_extra_offset = EXTENDED_SF_EXTRA_OFFSET;
  } else {
    sf_offset = SF_OFFSET;
    sf_extra_offset = SF_EXTRA_OFFSET;
  }

  proto_tree_add_item(mtp2_tree, hf_mtp2_sf, su_tvb, sf_offset, SF_LENGTH, ENC_LITTLE_ENDIAN);
  sf = tvb_get_guint8(su_tvb, SF_OFFSET);

  /*  If the LI is 2 then there is an extra octet following the standard SF
   *  field but it is not defined what this octet is.
   *  (In any case the first byte of the SF always has the same meaning.)
   */
  if ((tvb_get_guint8(su_tvb, LI_OFFSET) & LI_MASK) == 2)
    proto_tree_add_item(mtp2_tree, hf_mtp2_sf_extra, su_tvb, sf_extra_offset, SF_EXTRA_LENGTH, ENC_LITTLE_ENDIAN);

  col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(sf, status_field_acro_vals, "Unknown"));
}

static void
dissect_mtp2_msu(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_item,
                 proto_item *tree, gboolean use_extended_sequence_numbers)
{
  gint sif_sio_length;
  tvbuff_t *sif_sio_tvb;

  col_set_str(pinfo->cinfo, COL_INFO, "MSU ");

  if (use_extended_sequence_numbers) {
    sif_sio_length = tvb_reported_length(su_tvb) - EXTENDED_HEADER_LENGTH;
    sif_sio_tvb = tvb_new_subset_length(su_tvb, EXTENDED_SIO_OFFSET, sif_sio_length);
  } else {
    sif_sio_length = tvb_reported_length(su_tvb) - HEADER_LENGTH;
    sif_sio_tvb = tvb_new_subset_length(su_tvb, SIO_OFFSET, sif_sio_length);
  }
  call_dissector(mtp3_handle, sif_sio_tvb, pinfo, tree);

  if (tree) {
    if (use_extended_sequence_numbers)
      proto_item_set_len(mtp2_item, EXTENDED_HEADER_LENGTH);
    else
      proto_item_set_len(mtp2_item, HEADER_LENGTH);
  }
}

static void
dissect_mtp2_su(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_item,
                proto_item *mtp2_tree, proto_tree *tree, gboolean validate_crc,
                gboolean use_extended_sequence_numbers)
{
  guint32 li=0;
  tvbuff_t  *next_tvb = NULL;

  dissect_mtp2_header(su_tvb, pinfo, mtp2_tree, use_extended_sequence_numbers, validate_crc, &li);
  /* In some capture files (like .rf5), CRC are not present */
  /* So, to avoid trouble, give the complete buffer if CRC validation is disabled */
  if (validate_crc)
    next_tvb = mtp2_decode_crc16(su_tvb, mtp2_tree, pinfo);
  else
    next_tvb = su_tvb;

  switch(li) {
  case 0:
    dissect_mtp2_fisu(pinfo);
    break;
  case 1:
  case 2:
    dissect_mtp2_lssu(next_tvb, pinfo, mtp2_tree, use_extended_sequence_numbers);
    break;
  default:
    dissect_mtp2_msu(next_tvb, pinfo, mtp2_item, tree, use_extended_sequence_numbers);
    break;
  }
}

static void
dissect_mtp2_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    gboolean validate_crc, gboolean use_extended_sequence_numbers)
{
  proto_item *mtp2_item;
  proto_tree *mtp2_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP2");

  mtp2_item = proto_tree_add_item(tree, proto_mtp2, tvb, 0, -1, ENC_NA);
  mtp2_tree = proto_item_add_subtree(mtp2_item, ett_mtp2);

  dissect_mtp2_su(tvb, pinfo, mtp2_item, mtp2_tree, tree, validate_crc,
                  use_extended_sequence_numbers);
}

/* Dissect MTP2 frame without CRC16 and with a pseudo-header */
static int
dissect_mtp2_with_phdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  if (pinfo->pseudo_header->mtp2.annex_a_used == MTP2_ANNEX_A_USED_UNKNOWN)
    dissect_mtp2_common(tvb, pinfo, tree, FALSE, use_extended_sequence_numbers_default);
  else
    dissect_mtp2_common(tvb, pinfo, tree, FALSE,
                        (pinfo->pseudo_header->mtp2.annex_a_used == MTP2_ANNEX_A_USED));

  return tvb_captured_length(tvb);
}

/* Dissect MTP2 frame with CRC16 included at end of payload. Used
 * if the user has associated "mtp2_with_crc" with a DLT or if the
 * packets come from an Endace ERF file.
 */
static int
dissect_mtp2_with_crc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_mtp2_common(tvb, pinfo, tree, TRUE, use_extended_sequence_numbers_default);
  return tvb_captured_length(tvb);
}

/* Dissect MTP2 frame where we don't know if the CRC16 is included at
 * end of payload or not.
 */
static int
dissect_mtp2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_mtp2_common(tvb, pinfo, tree, capture_contains_fcs_crc_default,
                      use_extended_sequence_numbers_default);
  return tvb_captured_length(tvb);
}

static void
mtp2_init_routine(void)
{
        reassembly_table_register(&mtp2_reassembly_table, &addresses_ports_reassembly_table_functions);
}

/*  get one bit of a guint8 byte
*   based on the order set in the preferences
*   reverse_bit_order_mtp2 = FALSE: as the Q.703 states
*   reverse_bit_order_mtp2 = TRUE: just the opposite
*/
static gboolean
get_bit(guint8 byte, guint8 bit)
{
  if (reverse_bit_order_mtp2 == FALSE) {
    return byte & ((0x80 >> (bit-1))) ? TRUE : FALSE;
  } else {
    return byte & ((0x01 << (bit-1))) ? TRUE : FALSE;
  }
}

/* store new byte of an MTP2 frame in an array
 * after the whole packet is stored the array will be used to construct a new tvb */
static void
new_byte(char full_byte, guint8 **data, guint8 *data_len)
{
  guint8  *new_data = NULL;
  int     i = 0;

  if ((*data_len) == 0) {
    /* if data was never stored in this buffer before */
    *data = wmem_new(wmem_packet_scope(), guint8);
    (**data) = full_byte;
    (*data_len)++;
  } else {
    /* if this buffer is used -> create a completely new one
     * note, that after the dissection of this packet
     * the old data will be freed automatically (because of the wmem_alloc) */
    new_data = (guint8 *)wmem_alloc(wmem_packet_scope(), sizeof(guint8)*((*data_len)+1));
    /* copy the old one's content */
    for (i = 0;i<(*data_len);i++) {
      *(new_data+i) = *((*data)+i);
    }
    /* store the new data */
    *(new_data+*data_len) = full_byte;
    /* re-point the pointer to the new structure's head */
    *data = new_data;
    (*data_len)++;
  }
}

#ifdef MTP2_BITSTREAM_DEBUG
/* print debug info to stderr if debug is enabled
 * this function prints the packet bytes as bits separated by new lines
 * and adds extra info to bytes (flag found, frame reset, zeros were skipped, etc. */
static void
debug(char *format, ...)
{
  guint32 max_buffer_length = 256;
  gchar *buffer = NULL;
  va_list args;

  buffer = (gchar *) wmem_alloc(wmem_packet_scope(), max_buffer_length);
  buffer[0] = '\0';

  va_start(args,format);
  vsnprintf(buffer,max_buffer_length,format,args);
  g_printf("%s",buffer);
  va_end (args);
}
#endif

/* based on the actual packet's addresses and ports,
 * this function determines the packet's direction */
static enum packet_direction_state_mtp2
get_direction_state(packet_info *pinfo, mtp2_convo_data_t *convo_data)
{
  if (convo_data != NULL) {
    if (addresses_equal(&convo_data->addr_a, &pinfo->src)
        && addresses_equal(&convo_data->addr_b, &pinfo->dst)
        && convo_data->port_a == pinfo->srcport
        && convo_data->port_b == pinfo->destport) {
      return FORWARD;
    } else if (addresses_equal(&convo_data->addr_b, &pinfo->src)
        && addresses_equal(&convo_data->addr_a, &pinfo->dst)
        && convo_data->port_b == pinfo->srcport
        && convo_data->port_a == pinfo->destport) {
      return BACKWARD;
    }
  }

  return FORWARD;
}

/* prepares the data to be stored as found packet in wmem_list */
static mtp2_recognized_packet_t*
prepare_data_for_found_packet(tvbuff_t *tvb, guint8 unalignment_offset)
{
  mtp2_recognized_packet_t *packet;

  packet = wmem_new(wmem_packet_scope(), mtp2_recognized_packet_t);
  /* store values */
  packet->data = tvb;
  packet->unalignment_offset = unalignment_offset;

  return packet;
}

/* this function does the actual dissection of a tvb got from the RTP dissector
 * sets the mtp2_flag_search, data_buffer, it's offset and the state to the one which was stored
 * at the end of the previous packet's dissection in the same direction */
static mtp2_dissect_tvb_res_t*
dissect_mtp2_tvb(tvbuff_t* tvb, mtp2_mtp2_flag_search_t back_mtp2_flag_search, guint8 back_data_buff, guint8 back_data_buff_offset,
    enum mtp2_bitstream_states back_state, guint8 back_last_flag_beginning_offset_for_align_check)
{
  guint8        mtp2_flag_search = 0x00,                        /* this helps to detect the flags in the bitstream */
                data_buff = 0x00,                               /* buffer to store the found bits without the stuffed zeros */
                data_buff_offset = 0,                           /* index of the data_buff_offset, where to store the next bit */
                available_bytes_in_rtp_payload = 0,             /* stores the tvb's length which need to be analized */
                *found_data_buff_byte = NULL,                   /* buffer to store the found data_buff bytes till they are assembled to a tvb */
                offset = 0,                                     /* offset of the tvb, needed to get the appropriate byte */
                data_len = 0,                                   /* the length of the array where the data_buff's are stored */
                flag_beginning_offset_for_align_check = 0;      /* this stores the offset of the fist bit in a flag */
#ifdef MTP2_BITSTREAM_DEBUG
  gboolean      zero_skip0 = 0,                                 /* needed for debug output */
                zero_skip1 = 0,                                 /* needed for debug output */
                flag = FALSE,                                   /* needed for debug to print flag found message. reseted at every new octet read from tvb */
                frame_reset = FALSE;                            /* needed for debug, informs about a frame reset */
#endif
  enum mtp2_bitstream_states    state = OUT_OF_SYNC;            /* actual state of the dissection */
  tvbuff_t                      *new_tvb = NULL;                /* tvbuff which stores the assembled data from the data pointer */
  mtp2_dissect_tvb_res_t        *result = NULL;                 /* the result structure */

  /* initialize the result structure, this will be returned at the end */
  result = wmem_new(wmem_packet_scope(), mtp2_dissect_tvb_res_t);
  result->mtp2_remain_data.before_first_flag = NULL;
  result->mtp2_remain_data.before_fh_unalignment_offset = 0;
  result->mtp2_remain_data.before_fh_frame_reset = FALSE;
  result->mtp2_remain_data.after_last_flag = NULL;
  result->found_packets = wmem_list_new(wmem_packet_scope());
  result->flag_found = FALSE;
  result->last_flag_beginning_offset_for_align_check = 0;

  /* set the mtp2_flag_search if it is set */
  if (back_mtp2_flag_search.set == TRUE) {
    mtp2_flag_search = back_mtp2_flag_search.mtp2_flag_search;
  }
  /* set every other variables from the prev. packet's end in the same direction */
  data_buff = back_data_buff;
  data_buff_offset = back_data_buff_offset;
  state = back_state;
  flag_beginning_offset_for_align_check = back_last_flag_beginning_offset_for_align_check;

  /* determine how many byte are in the RTP payload */
  available_bytes_in_rtp_payload = tvb_reported_length_remaining(tvb, offset);

  /* walk through the tvb in means of octets */
  while (offset < available_bytes_in_rtp_payload) {
    /* get actual packet's byte */
    guint8 byte = tvb_get_guint8(tvb,offset);
    /* for every bit in the byte */
    for (guint8 i=1; i <= 8; i++) {
      /* get the bit's boolean value got from byte[i] */
      gboolean bit = get_bit(byte, i);

#ifdef MTP2_BITSTREAM_DEBUG
      /* in case of debug, print just the pure RTP payload, not the previous packet's end */
      debug("%u",(bit==FALSE?0:1));
#endif

      /* update the mtp2_flag_search */
      mtp2_flag_search = (mtp2_flag_search << 1) | bit;

      /* this section contains actions to be taken when the state is not OUT_OF_SYNC like
       * skipping zeros after every 5 bits */
      if (state != OUT_OF_SYNC) {
        /* The only values of mtp2_flag_search if we need to drop a zero is 0xBE and 0x3E */
        if ( (mtp2_flag_search == 0xBE || mtp2_flag_search == 0x3E)) {
#ifdef MTP2_BITSTREAM_DEBUG
          /* set the debug variables */
          if (zero_skip0 == 0)
            zero_skip0 = i;
          else
            zero_skip1 = i;
#endif
          /* if we need to skip a zero, the next flag offset have to be incremented because the raw data
           * between 2 flags is not a multiple of 8 bits now */
          flag_beginning_offset_for_align_check = (flag_beginning_offset_for_align_check + 1) % 8;
        } else {
          /* No drop -> store the value */
          data_buff = data_buff | (bit << data_buff_offset);
          data_buff_offset++;
          /* when a new complete byte without zeros was found */
          if (data_buff_offset == 8) {
            /* we don't store flags */
            if (data_buff != 0x7E) {
              /* store the data and change the state */
              state = DATA;
              new_byte(data_buff, &found_data_buff_byte, &data_len);
            }
            /* clear data_buff and it's offset */
            data_buff = 0x00;
            data_buff_offset = 0;
          }
        }
      }
      /* we have a flag */
      if (mtp2_flag_search == 0x7E &&
          !(offset == 0 && i < 8 && back_mtp2_flag_search.set == FALSE))
        /* the second part of the '&&' is not to recognize the 1111110x pattern as flag in the beginning of the 1st packet in every direction
         * the 1111110 would be shifted into the mtp2_flag_search variable, this has a 0x00 initial value
         * so after shifting 7 bits, the value of mtp2_flag_search would be 01111110 however there was no leading 0*/
      {
        /* set the state */
        state = FLAGS;
        /* if before this flag, we found some real packet related btyes */
        if (data_len != 0) {
          guint8 unaligned_packet_offset = 0; /* !=0 signals if the packet just found was not a multiple of 8 bits in the bitstream */
          /* here we check if the just found MTP2 packet is unaligned or not
           * 0 is not valid value meaning the flag_beginning_offset_for_align_check was not set at the beginning of the func.
           * if flag_beginning_offset_for_align_check != i, we have an unaligned packet */
          if (flag_beginning_offset_for_align_check != 0 && flag_beginning_offset_for_align_check != i) {
            /* set the unaligned offset */
            unaligned_packet_offset = i;
            /* clear the data_buff and offset
             * this is needed because at the next flag we would have data_buff offset unaligned
             * and we would find a 1 length packet with a part of the flag in it */
            data_buff = 0x00;
            data_buff_offset = 0;
          }
          /* fill the temporary buffer with data */
          guint8 *buff = (guint8 *) wmem_memdup(wmem_packet_scope(), found_data_buff_byte, data_len);
          /* Allocate new tvb for the proto frame */
          new_tvb = tvb_new_child_real_data(tvb, buff, data_len, data_len);
          /* if there were no flags before, we've found the bytes before the first flag */
          if (result->flag_found == FALSE) {
            /* this tvb is the one we found before the 1st flag */
            result->mtp2_remain_data.before_first_flag = new_tvb;
            /* if the bytes before the first flag was unaligned -> the calling function needs this info */
            result->mtp2_remain_data.before_fh_unalignment_offset = unaligned_packet_offset;
          } else {
            /* add the packet to the processable packet's list */
            wmem_list_append(result->found_packets, prepare_data_for_found_packet(new_tvb,unaligned_packet_offset));
          }
          /* clear data array (free will be done automatically) */
          data_len = 0;
          found_data_buff_byte = NULL;
        }

        flag_beginning_offset_for_align_check = i;
#ifdef MTP2_BITSTREAM_DEBUG
        /* for local debug purposes */
        flag = TRUE;
#endif
        /* set the result found in the result to TRUE */
        result->flag_found = TRUE;
        /* 7 consecutive 1s => out of sync */
      } else if (mtp2_flag_search == 0x7F || mtp2_flag_search == 0xFE || mtp2_flag_search == 0xFF) {
        /* set the state and clear everything */
        state = OUT_OF_SYNC;
        data_len = 0;
        found_data_buff_byte = NULL;
        data_buff = 0x00;
        data_buff_offset = 0;
#ifdef MTP2_BITSTREAM_DEBUG
        frame_reset = TRUE;
#endif
        if (result->flag_found == FALSE)
          result->mtp2_remain_data.before_fh_frame_reset = TRUE;
      }
    }

#ifdef MTP2_BITSTREAM_DEBUG
    /* if there were flag, print debug info */
    if (flag) {
      debug("\tFLAG FOUND");
    }
    /* if there were zeros skipped, print the debug data */
    if (!zero_skip0 == 0) {
      debug("\tSKIPPED ZEROS: %u.",zero_skip0);
      if (!zero_skip1 == 0)
        debug(" %u",zero_skip1);
    }
    /* if there was frame reset, print debug info */
    if (frame_reset) {
      debug("\tFRAME RESET");
    }
    /* print a \n to print the next byte in a different row */
    debug("\n");
    /* after every byte read from tvb clear debug stuff */
    zero_skip0 = 0;
    zero_skip1 = 0;
    /* set the debug variables as well */
    flag = FALSE;
    frame_reset = FALSE;
#endif
    /* increment tvb offset */
    offset++;
  }

  if (data_len != 0) {
    /* fill the temporary buffer with data */
    guint8 * buff = (guint8 *) wmem_memdup(wmem_packet_scope(), found_data_buff_byte, data_len);
    /* Allocate new tvb for the MTP2 frame */
    new_tvb = tvb_new_child_real_data(tvb, buff, data_len, data_len);
    /* this tvb is the one we found after the last flag */
    result->mtp2_remain_data.after_last_flag = new_tvb;
  }

  /* we do not return NULL in before_first_flag because then the reassemble will not work
   * we have to add a 0 length tvb with the flag "no more packets" */
  if (result->mtp2_remain_data.before_first_flag == NULL) {
    /* fill the temporary buffer with data */
    guint8 *buff = (guint8 *) wmem_memdup(wmem_packet_scope(), found_data_buff_byte, 0);
    /* Allocate new tvb for the MTP2 frame */
    new_tvb = tvb_new_child_real_data(tvb, buff, 0, 0);
    /* this tvb is the one we found after the last flag */
    result->mtp2_remain_data.before_first_flag = new_tvb;
  }

  /* don't set mtp2_flag_search and other stuff if the packet ended in out_of_sync */
  if (state != OUT_OF_SYNC) {
    result->mtp2_flag_search.set = TRUE;
    result->mtp2_flag_search.mtp2_flag_search = mtp2_flag_search;
    result->data_buff = data_buff;
    result->data_buff_offset = data_buff_offset;
  } else {
    result->mtp2_flag_search.set = FALSE;
    result->mtp2_flag_search.mtp2_flag_search = result->data_buff = result->data_buff_offset = 0x00;
  }

  /* set the state as well, in every case */
  result->state = state;

  /* set the last_flag_beginning_offset_for_align_check in the result structure */
  result->last_flag_beginning_offset_for_align_check = flag_beginning_offset_for_align_check;

  /* return the result structure */
  return result;
}

/* function to get a new reass. sequence number  */
static guint32
get_new_reass_seq_num(void)
{
  /* fail if it reached the max value */
  DISSECTOR_ASSERT(mtp2_absolute_reass_seq_num < 0xFFFFFFFE);
  mtp2_absolute_reass_seq_num++;

  return mtp2_absolute_reass_seq_num;
}


/* sign if the packet is unaligned in proto tree */
static void
issue_unaligned_info(proto_tree *tree, tvbuff_t *tvb, guint8 unalignment_offset)
{
  proto_tree_add_none_format(tree, hf_mtp2_unexpect_end, tvb, 0, tvb_reported_length_remaining(tvb,0),
      "[Packet ended in the middle of an octet. Octet: last, Offset: %u]",
      unalignment_offset);
}

/* sign if the packet is unaligned in proto tree */
static void
issue_frame_reset_info(proto_tree *tree, tvbuff_t *tvb)
{
  proto_tree_add_none_format(tree, hf_mtp2_frame_reset, tvb, 0, 0,
              "[Frame Reset Occurred, No Reassembly]");
}

/* set per packet data based on direction data */
static void
set_ppd_fields_based_on_convo_directon_data(mtp2_ppd_t *mtp2_ppd, mtp2_convo_data_prev_packet_t *direction_data)
{
  mtp2_ppd->mtp2_flag_search = direction_data->mtp2_flag_search;
  mtp2_ppd->data_buff = direction_data->data_buff;
  mtp2_ppd->data_buff_offset = direction_data->data_buff_offset;
  mtp2_ppd->state = direction_data->state;
  /* this is because the segment which will be reassembled in this packet
   * is stored with the reass_seq_num stored in the convo data
   * therefore we have to save this value for dissection in the future */
  mtp2_ppd->reass_seq_num_for_reass_check_before_fh = direction_data->reass_seq_num;
  mtp2_ppd->last_flag_beginning_offset_for_align_check = direction_data->last_flag_beginning_offset_for_align_check;
}

/* set convo data based on dissection result and reass_seq_num */
static void
set_direction_fields_based_on_result_and_reass_seq_num(mtp2_convo_data_prev_packet_t *direction_data, mtp2_dissect_tvb_res_t *result, guint32 reass_seq_num)
{
  direction_data->mtp2_flag_search = result->mtp2_flag_search;
  direction_data->data_buff = result->data_buff;
  direction_data->data_buff_offset = result->data_buff_offset;
  direction_data->state = result->state;
  direction_data->reass_seq_num = reass_seq_num;
  direction_data->last_flag_beginning_offset_for_align_check = result->last_flag_beginning_offset_for_align_check;
}

/* function to dissect bitstream data of MTP2 */
static int
dissect_mtp2_bitstream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * user_data _U_)
{
  guint32                               reass_seq_num = 0;                      /* reassemble sequence number at the beginning of this packet's dissection */
  conversation_t                        *conversation = NULL;                   /* conversation of the mtp2 dissection */
  mtp2_convo_data_t                     *convo_data = NULL;                     /* conversation data of the mtp2 dissection */
  mtp2_dissect_tvb_res_t                *result = NULL;                         /* variable to store the result of dissect_mtp2_tvb */
  enum packet_direction_state_mtp2      dir_state = FORWARD;                    /* direction state of this packet in the conversation */
  mtp2_ppd_t                            *mtp2_ppd = NULL;                       /* per-packet data of this packet */

#ifdef MTP2_BITSTREAM_DEBUG
  debug("start_dissect_bitstream_packet: %u\n",pinfo->fd->num);
#endif

  /* find conversation related to this packet */
  conversation = find_conversation(pinfo->fd->num,&pinfo->src, &pinfo->dst,conversation_pt_to_endpoint_type(pinfo->ptype), pinfo->srcport, pinfo->destport, 0);
  /* if there is no conversation or it does not contain the per packet data we need */
  if (conversation == NULL) {
    /* there was no conversation => this packet is the first in a new conversation => let's create it */
    /* here we decide about the direction, every following packet with the same direction as this first one will be a forward packet */
    conversation = conversation_new(pinfo->fd->num,&pinfo->src, &pinfo->dst,conversation_pt_to_endpoint_type(pinfo->ptype), pinfo->srcport, pinfo->destport, 0);
  }

  /* there is no proto data in the conversation */
  if (conversation_get_proto_data(conversation, proto_mtp2) == NULL) {
    /* create a new convo data and fill it with initial data */
    convo_data = wmem_new(wmem_file_scope(), mtp2_convo_data_t);
    copy_address_wmem(wmem_file_scope(), &convo_data->addr_a, &pinfo->src);
    copy_address_wmem(wmem_file_scope(), &convo_data->addr_b, &pinfo->dst);
    convo_data->port_a = pinfo->srcport;
    convo_data->port_b = pinfo->destport;
    convo_data->forward = wmem_new(wmem_file_scope(), mtp2_convo_data_prev_packet_t);
    convo_data->backward = wmem_new(wmem_file_scope(), mtp2_convo_data_prev_packet_t);
    convo_data->forward->mtp2_flag_search.set = convo_data->backward->mtp2_flag_search.set= FALSE;
    convo_data->forward->mtp2_flag_search.mtp2_flag_search = convo_data->backward->mtp2_flag_search.mtp2_flag_search = 0x00;
    convo_data->forward->data_buff = convo_data->backward->data_buff = 0x00;
    convo_data->forward->data_buff_offset = convo_data->backward->data_buff_offset = 0;
    convo_data->forward->state = convo_data->backward->state = OUT_OF_SYNC;
    convo_data->forward->reass_seq_num = get_new_reass_seq_num();
    convo_data->backward->reass_seq_num = get_new_reass_seq_num();
    convo_data->forward->last_flag_beginning_offset_for_align_check = convo_data->backward->last_flag_beginning_offset_for_align_check = 0;
    /* store the convo data */
    conversation_add_proto_data(conversation, proto_mtp2, convo_data);
  } else {
    /* the packet is part of an existing conversation => get the conversation data */
    convo_data = (mtp2_convo_data_t*)conversation_get_proto_data(conversation, proto_mtp2);
  }

  /* get the packet's state */
  dir_state = get_direction_state(pinfo, convo_data);

  /* get the per packet data */
  mtp2_ppd = (mtp2_ppd_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_mtp2, pinfo->fd->num);

  /* if there is no per packet data -> create it */
  if (mtp2_ppd == NULL) {
    mtp2_ppd = wmem_new(wmem_file_scope(), mtp2_ppd_t);
    /* set the proto_data_fields
     * because these are the values which we would like to see
     * if this packet is seen again */
    if (dir_state == FORWARD) {
      set_ppd_fields_based_on_convo_directon_data(mtp2_ppd, convo_data->forward);
    } else {
      set_ppd_fields_based_on_convo_directon_data(mtp2_ppd, convo_data->backward);
    }
    /* store the ppd to be able to get in the next time we see this packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_mtp2, pinfo->fd->num, mtp2_ppd);
  }

  /* get the reass. seq num from the ppd
   * this is needed because it is modified and stored in the convo_data */
  reass_seq_num = mtp2_ppd->reass_seq_num_for_reass_check_before_fh;

  /* call the function to dissect this actual tvb */
  result = dissect_mtp2_tvb(tvb,
      mtp2_ppd->mtp2_flag_search,
      mtp2_ppd->data_buff,
      mtp2_ppd->data_buff_offset,
      mtp2_ppd->state,
      mtp2_ppd->last_flag_beginning_offset_for_align_check);

  /* if this is the first time, do the reassemble things
   * else just check for reassembled data */
  if (pinfo->fd->visited == FALSE) {
    /* if there was a flag in this tvb, the data found before the 1st flag
     * have to be treated differently than the data found after the last flag
     * this means we need to use different reass_seq_num when adding them to the reass. handler */
    if (result->flag_found == TRUE) {
      /* add the data found before the first flag with the same reass_seq_num as the
       * data found after the last flag in the previous packet in this direction */
      fragment_add_seq_next(&mtp2_reassembly_table, /* bookkeeping table */
          result->mtp2_remain_data.before_first_flag, /* tvb containing the data which was unidentified before the first flag */
          0, /* offset is 0 because this tvb contains the unidentified data only */
          pinfo,
          mtp2_ppd->reass_seq_num_for_reass_check_before_fh, /* sequence number of the fragment stream */
          NULL, /* additional data to identify the segment */
          tvb_reported_length_remaining(result->mtp2_remain_data.before_first_flag, 0), /* length is the whole tvb's length */
          FALSE); /* there are no more fragments */

      /* get a new reass seq num for the data found after the last flag */
      mtp2_ppd->reass_seq_num_for_reass_check_after_lh = reass_seq_num = get_new_reass_seq_num();

      /* if there were data found after the last flag, add it to the reass. handler with the new reass_seq_num */
      if (result->mtp2_remain_data.after_last_flag != NULL) {
        fragment_add_seq_next(&mtp2_reassembly_table, /* bookkeeping table */
            result->mtp2_remain_data.after_last_flag, /* tvb containing the data which was unidentified before the first flag */
            0, /* offset is 0 because this tvb contains the unidentified data only */
            pinfo,
            mtp2_ppd->reass_seq_num_for_reass_check_after_lh, /* sequence number of the fragment stream */
            NULL, /* additional data to identify the segment */
            tvb_reported_length_remaining(result->mtp2_remain_data.after_last_flag, 0), /* length is the whole tvb's length */
            TRUE); /* there are more fragments */
      }
    } else {
      /* here the increment of the reass_seq_num is not needed because this RTP frame was completely part
       * of an MTP2 frame beginning in the previous packet
       * this need to be added with the same reass_seq_num */
      if (result->mtp2_remain_data.after_last_flag != NULL) {
        fragment_add_seq_next(&mtp2_reassembly_table, /* bookkeeping table */
            result->mtp2_remain_data.after_last_flag, /* tvb containing the data which was unidentified before the first flag */
            0, /* offset is 0 because this tvb contains the unidentified data only */
            pinfo,
            mtp2_ppd->reass_seq_num_for_reass_check_before_fh, /* sequence number of the fragment stream */
            NULL, /* additional data to identify the segment */
            tvb_reported_length_remaining(result->mtp2_remain_data.after_last_flag, 0), /* length is the whole tvb's length */
            TRUE); /* there are more fragments */
      }
    }
    /* store the values in convo_data
     * but just in case if this packet was not seen before
     * if it was
     *   then the convo data shall not be used (contains inappropriate info for us
     *   the actual values needed for reassembly should be get from the mtp2_ppd
     *   therefore no need to set the convo data */
    /* differentiate between forward and backward directions */
    if (dir_state == FORWARD) {
      set_direction_fields_based_on_result_and_reass_seq_num(convo_data->forward, result, reass_seq_num);
    } else {
      set_direction_fields_based_on_result_and_reass_seq_num(convo_data->backward, result, reass_seq_num);
    }

  /* if the packet was seen before */
  } else {
    tvbuff_t            *new_tvb = NULL;
    fragment_head       *frag_msg_before_fh = NULL;
    fragment_head       *frag_msg_after_lh = NULL;
    gchar               *col_info_str = NULL;           /* char array to store temporary string for col info update */

    /* get the fragment data both for before first and after last flags */
    /* before first flag */
    frag_msg_before_fh = fragment_get_reassembled_id(&mtp2_reassembly_table,
        pinfo,
        mtp2_ppd->reass_seq_num_for_reass_check_before_fh);
    /* after last flag */
    frag_msg_after_lh = fragment_get_reassembled_id(&mtp2_reassembly_table,
        pinfo,
        mtp2_ppd->reass_seq_num_for_reass_check_after_lh);
    /* if there is reassembled data before the first flag */
    if (frag_msg_before_fh != NULL) {
      /* get the reassembled tvb */
      new_tvb = process_reassembled_data(result->mtp2_remain_data.before_first_flag,
          0,
          pinfo,
          (result->mtp2_remain_data.before_fh_unalignment_offset != 0
              ?"Reassembled MTP2 Packet [Unaligned]"
              :"Reassembled MTP2 Packet"),
          frag_msg_before_fh,
          &mtp2_frag_items,
          NULL,
          tree);
      /* there is reassembled data */
      if (new_tvb != NULL && tvb_reported_length_remaining(new_tvb, 0) > 0) {

        /* if there was a frame reset before the first flag */
        if (result->mtp2_remain_data.before_fh_frame_reset == TRUE) {
          /* issue frame reset */
          issue_frame_reset_info(tree, new_tvb);
          /* prepare col_info string */
          col_info_str = "[Frame Reset in reassembly]";
        } else {
          /* append the reassembled packet to the head of the packet list */
          wmem_list_prepend(result->found_packets, prepare_data_for_found_packet(new_tvb,result->mtp2_remain_data.before_fh_unalignment_offset));
          /* set the protocol name */
          col_add_str(pinfo->cinfo, COL_PROTOCOL, "MTP2");
        }
      }
    }

    /* if there were packets found */
    if (wmem_list_count(result->found_packets) != 0) {
      /* boolean variable to help to print proper col_info if unaligned packet is found */
      gboolean was_unaligned_packet = FALSE;
      /* pointer walking through the list of found packets */
      wmem_list_frame_t *recognized_packet = wmem_list_head(result->found_packets);

      /* info field pre-set, we can see the MTP2 strings even if there is an error in the dissection */
      col_add_str(pinfo->cinfo, COL_PROTOCOL, "MTP2");
      col_add_str(pinfo->cinfo, COL_INFO, "MTP2");
      /* while there are available packets */
      while (recognized_packet != NULL) {
        mtp2_recognized_packet_t *recognized_packet_data = (mtp2_recognized_packet_t *) wmem_list_frame_data(recognized_packet);
        if (recognized_packet_data->unalignment_offset == 0) {
          /* pass the data to the mtp2 dissector */
          add_new_data_source(pinfo, recognized_packet_data->data, "MTP2 packet");
          dissect_mtp2_common(recognized_packet_data->data, pinfo, tree, FALSE, use_extended_sequence_numbers_default);
        } else {
          add_new_data_source(pinfo, recognized_packet_data->data, "MTP2 packet [Unaligned]");
          issue_unaligned_info(tree, recognized_packet_data->data, recognized_packet_data->unalignment_offset);
          was_unaligned_packet = TRUE;
        }

        /* increment the pointer */
        recognized_packet = wmem_list_frame_next(recognized_packet);
      }
      /* insert how many packets were found */
      col_info_str = ws_strdup_printf("%s: %u Packet%s%s%s",
          "MTP2",
          wmem_list_count(result->found_packets),
          (wmem_list_count(result->found_packets) > 1
              ?"s"
              :""
          ),
          (was_unaligned_packet
              ?ws_strdup_printf(" [Unaligned Packet%s]", (wmem_list_count(result->found_packets)>1
                  ?"s"
                  :""))
              :""
          ),
          (col_info_str == NULL
              ?""
              :col_info_str
          )
          );
      col_add_str(pinfo->cinfo, COL_INFO, col_info_str);
      g_free(col_info_str);
    /* if there were no packets found */
    } else {
      if (tvb_reported_length_remaining(result->mtp2_remain_data.before_first_flag,0) == 0
          && result->mtp2_remain_data.after_last_flag != NULL
          && frag_msg_before_fh)
      {
        col_add_str(pinfo->cinfo, COL_PROTOCOL, "MTP2");
        col_info_str = ws_strdup_printf("[MTP2 Reassembled in: %u]", frag_msg_before_fh->reassembled_in);
        col_add_str(pinfo->cinfo, COL_INFO, col_info_str);
        g_free(col_info_str);
      } else {
        col_add_str(pinfo->cinfo, COL_PROTOCOL, "MTP2");
        col_info_str = "[MTP2 No Packets]";
        col_add_str(pinfo->cinfo, COL_INFO, col_info_str);
      }
    }
    /* this adds the "Reassembled in" text to the proto tree to the packet where there is leftover data at the end */
    process_reassembled_data(result->mtp2_remain_data.after_last_flag,
        0,
        pinfo,
        "Reassembled MTP2 Packet",
        frag_msg_after_lh,
        &mtp2_frag_items,
        NULL,
        tree);
  }

  /* the whole tvb was processed */
  return tvb_captured_length(tvb);
}

void
proto_register_mtp2(void)
{

  static hf_register_info hf[] = {
    { &hf_mtp2_bsn,       { "Backward sequence number", "mtp2.bsn",      FT_UINT8,  BASE_DEC, NULL,                    BSN_MASK,            NULL, HFILL } },
    { &hf_mtp2_ext_bsn,   { "Backward sequence number", "mtp2.bsn",      FT_UINT16, BASE_DEC, NULL,                    EXTENDED_BSN_MASK,   NULL, HFILL } },
    { &hf_mtp2_ext_res,   { "Reserved",                 "mtp2.res",      FT_UINT16, BASE_DEC, NULL,                    EXTENDED_RES_MASK,   NULL, HFILL } },
    { &hf_mtp2_bib,       { "Backward indicator bit",   "mtp2.bib",      FT_UINT8,  BASE_DEC, NULL,                    BIB_MASK,            NULL, HFILL } },
    { &hf_mtp2_ext_bib,   { "Backward indicator bit",   "mtp2.bib",      FT_UINT16, BASE_DEC, NULL,                    EXTENDED_BIB_MASK,   NULL, HFILL } },
    { &hf_mtp2_fsn,       { "Forward sequence number",  "mtp2.fsn",      FT_UINT8,  BASE_DEC, NULL,                    FSN_MASK,            NULL, HFILL } },
    { &hf_mtp2_ext_fsn,   { "Forward sequence number",  "mtp2.fsn",      FT_UINT16, BASE_DEC, NULL,                    EXTENDED_FSN_MASK,   NULL, HFILL } },
    { &hf_mtp2_fib,       { "Forward indicator bit",    "mtp2.fib",      FT_UINT8,  BASE_DEC, NULL,                    FIB_MASK,            NULL, HFILL } },
    { &hf_mtp2_ext_fib,   { "Forward indicator bit",    "mtp2.fib",      FT_UINT16, BASE_DEC, NULL,                    EXTENDED_FIB_MASK,   NULL, HFILL } },
    { &hf_mtp2_li,        { "Length Indicator",         "mtp2.li",       FT_UINT8,  BASE_DEC, NULL,                    LI_MASK,             NULL, HFILL } },
    { &hf_mtp2_ext_li,    { "Length Indicator",         "mtp2.li",       FT_UINT16, BASE_DEC, NULL,                    EXTENDED_LI_MASK,    NULL, HFILL } },
    { &hf_mtp2_spare,     { "Spare",                    "mtp2.spare",    FT_UINT8,  BASE_DEC, NULL,                    SPARE_MASK,          NULL, HFILL } },
    { &hf_mtp2_ext_spare, { "Spare",                    "mtp2.spare",    FT_UINT16, BASE_DEC, NULL,                    EXTENDED_SPARE_MASK, NULL, HFILL } },
    { &hf_mtp2_sf,        { "Status field",             "mtp2.sf",       FT_UINT8,  BASE_DEC, VALS(status_field_vals), 0x0,                 NULL, HFILL } },
    { &hf_mtp2_sf_extra,  { "Status field extra octet", "mtp2.sf_extra", FT_UINT8,  BASE_HEX, NULL,                    0x0,                 NULL, HFILL } },
    { &hf_mtp2_fcs_16,    { "FCS 16",                   "mtp2.fcs_16",   FT_UINT16, BASE_HEX, NULL,                    0x0,                 NULL, HFILL } },
    { &hf_mtp2_fcs_16_status, { "FCS 16",               "mtp2.fcs_16.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,          NULL, HFILL } },
    { &hf_mtp2_unexpect_end, { "Unexpected packet end","mtp2.unexpected_end", FT_NONE, BASE_NONE, NULL,                0x0,                 NULL, HFILL } },
    { &hf_mtp2_frame_reset, { "Frame reset",           "mtp2.frame_reset", FT_NONE, BASE_NONE, NULL,                   0x0,                 NULL, HFILL } },
    /* extend header fields with the reassemble ones */
    {&hf_mtp2_fragments,
        {"Message fragments", "mtp2.msg.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_mtp2_fragment,
        {"Message fragment", "mtp2.msg.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_mtp2_fragment_overlap,
        {"Message fragment overlap", "mtp2.msg.fragment.overlap",
        FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_mtp2_fragment_overlap_conflicts,
        {"Message fragment overlapping with conflicting data",
        "mtp2.msg.fragment.overlap.conflicts",
        FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_mtp2_fragment_multiple_tails,
        {"Message has multiple tail fragments",
        "mtp2.msg.fragment.multiple_tails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_mtp2_fragment_too_long_fragment,
        {"Message fragment too long", "mtp2.msg.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_mtp2_fragment_error,
        {"Message defragmentation error", "mtp2.msg.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_mtp2_fragment_count,
        {"Message defragmentation count", "mtp2.msg.fragment.count",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_mtp2_reassembled_in,
        {"Reassembled in", "mtp2.msg.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_mtp2_reassembled_length,
        {"Reassembled length", "mtp2.msg.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } }
  };

  static gint *ett[] = {
    &ett_mtp2,
    /* extend ett with the fragment fields */
    &ett_mtp2_fragment,
    &ett_mtp2_fragments
  };

  static ei_register_info ei[] = {
     { &ei_mtp2_checksum_error, { "mtp2.checksum.error", PI_CHECKSUM, PI_WARN, "MTP2 Frame CheckFCS 16 Error", EXPFILL }},
     { &ei_mtp2_li_bad, { "mtp2.li.bad", PI_PROTOCOL, PI_WARN, "Bad length indicator value", EXPFILL }},
  };

  module_t *mtp2_module;
  expert_module_t* expert_mtp2;

  proto_mtp2 = proto_register_protocol("Message Transfer Part Level 2", "MTP2", "mtp2");
  mtp2_handle = register_dissector("mtp2", dissect_mtp2, proto_mtp2);
  register_dissector("mtp2_with_crc", dissect_mtp2_with_crc, proto_mtp2);

  proto_register_field_array(proto_mtp2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_mtp2 = expert_register_protocol(proto_mtp2);
  expert_register_field_array(expert_mtp2, ei, array_length(ei));

  mtp2_module = prefs_register_protocol(proto_mtp2, NULL);
  prefs_register_bool_preference(mtp2_module,
                                 "use_extended_sequence_numbers",
                                 "Use extended sequence numbers",
                                 "Whether the MTP2 dissector should use extended sequence numbers as described in Q.703, Annex A as a default.",
                                 &use_extended_sequence_numbers_default);
  prefs_register_bool_preference(mtp2_module,
                                 "capture_contains_frame_check_sequence",
                                 "Assume packets have FCS",
                                 "Some SS7 capture hardware includes the FCS at the end of the packet, others do not.",
                                 &capture_contains_fcs_crc_default);

  /* register bool and range preferences */
  prefs_register_bool_preference(mtp2_module,
                                 "reverse_bit_order_mtp2",
                                 "Reverse bit order inside bytes",
                                 "Reverse the bit order inside bytes specified in Q.703.",
                                 &reverse_bit_order_mtp2);
  prefs_register_obsolete_preference(mtp2_module, "rtp_payload_type");

  register_init_routine(&mtp2_init_routine);
}

void
proto_reg_handoff_mtp2(void)
{
  dissector_handle_t mtp2_with_phdr_handle;
  dissector_handle_t mtp2_bitstream_handle;

  dissector_add_uint("wtap_encap", WTAP_ENCAP_MTP2, mtp2_handle);
  mtp2_with_phdr_handle = create_dissector_handle(dissect_mtp2_with_phdr,
                                                  proto_mtp2);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_MTP2_WITH_PHDR,
                                   mtp2_with_phdr_handle);

  mtp3_handle   = find_dissector_add_dependency("mtp3", proto_mtp2);

  mtp2_bitstream_handle = create_dissector_handle(dissect_mtp2_bitstream, proto_mtp2);
  dissector_add_string("rtp_dyn_payload_type", "MTP2", mtp2_bitstream_handle);

  dissector_add_uint_range_with_preference("rtp.pt", "", mtp2_bitstream_handle);
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
