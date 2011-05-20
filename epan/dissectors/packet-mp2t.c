/* packet-mp2t.c
 *
 * Routines for RFC 2250 MPEG2 (ISO/IEC 13818-1) Transport Stream dissection
 *
 * $Id$
 *
 * Copyright 2006, Erwin Rol <erwin@erwinrol.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <glib.h>
#include <epan/packet.h>

#include <epan/rtp_pt.h>
#include "packet-frame.h"

#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/reassemble.h>

/* The MPEG2 TS packet size */
#define MP2T_PACKET_SIZE 188
#define MP2T_SYNC_BYTE 0x47

static dissector_handle_t pes_handle;
static dissector_handle_t docsis_handle;
static dissector_handle_t data_handle;

static int proto_mp2t = -1;
static gint ett_mp2t = -1;
static gint ett_mp2t_header = -1;
static gint ett_mp2t_af = -1;
static gint ett_mp2t_analysis = -1;
static gint ett_dmpt = -1;

static int hf_mp2t_header = -1;
static int hf_mp2t_sync_byte = -1;
static int hf_mp2t_tei = -1;
static int hf_mp2t_pusi = -1;
static int hf_mp2t_tp = -1;
static int hf_mp2t_pid = -1;
static int hf_mp2t_tsc = -1;
static int hf_mp2t_afc = -1;
static int hf_mp2t_cc = -1;
static int hf_mp2t_cc_drop = -1;

static int hf_mp2t_analysis_flags = -1;
static int hf_mp2t_analysis_skips = -1;
static int hf_mp2t_analysis_drops = -1;

#define MP2T_SYNC_BYTE_MASK	0xFF000000
#define MP2T_TEI_MASK		0x00800000
#define MP2T_PUSI_MASK		0x00400000
#define MP2T_TP_MASK		0x00200000
#define MP2T_PID_MASK		0x001FFF00
#define MP2T_TSC_MASK		0x000000C0
#define MP2T_AFC_MASK		0x00000030
#define MP2T_CC_MASK		0x0000000F

#define MP2T_SYNC_BYTE_SHIFT	24
#define MP2T_TEI_SHIFT		23
#define MP2T_PUSI_SHIFT		22
#define MP2T_TP_SHIFT		21
#define MP2T_PID_SHIFT		8
#define MP2T_TSC_SHIFT		6
#define MP2T_AFC_SHIFT		4
#define MP2T_CC_SHIFT		0

static int hf_mp2t_af = -1;
static int hf_mp2t_af_length = -1;
static int hf_mp2t_af_di = -1;
static int hf_mp2t_af_rai = -1;
static int hf_mp2t_af_espi = -1;
static int hf_mp2t_af_pcr_flag = -1;
static int hf_mp2t_af_opcr_flag = -1;
static int hf_mp2t_af_sp_flag = -1;
static int hf_mp2t_af_tpd_flag = -1;
static int hf_mp2t_af_afe_flag = -1;

#define MP2T_AF_DI_MASK 	0x80
#define MP2T_AF_RAI_MASK	0x40
#define MP2T_AF_ESPI_MASK	0x20
#define MP2T_AF_PCR_MASK	0x10
#define MP2T_AF_OPCR_MASK	0x08
#define MP2T_AF_SP_MASK		0x04
#define MP2T_AF_TPD_MASK	0x02
#define MP2T_AF_AFE_MASK	0x01

#define MP2T_AF_DI_SHIFT 	7
#define MP2T_AF_RAI_SHIFT	6
#define MP2T_AF_ESPI_SHIFT	5
#define MP2T_AF_PCR_SHIFT	4
#define MP2T_AF_OPCR_SHIFT	3
#define MP2T_AF_SP_SHIFT	2
#define MP2T_AF_TPD_SHIFT	1
#define MP2T_AF_AFE_SHIFT	0

static int hf_mp2t_af_pcr = -1;
static int hf_mp2t_af_opcr = -1;

static int hf_mp2t_af_sc = -1;

static int hf_mp2t_af_tpd_length = -1;
static int hf_mp2t_af_tpd = -1;

static int hf_mp2t_af_e_length = -1;
static int hf_mp2t_af_e_ltw_flag = -1;
static int hf_mp2t_af_e_pr_flag = -1;
static int hf_mp2t_af_e_ss_flag = -1;
static int hf_mp2t_af_e_reserved = -1;

#define MP2T_AF_E_LTW_FLAG_MASK	0x80
#define MP2T_AF_E_PR_FLAG_MASK	0x40
#define MP2T_AF_E_SS_FLAG_MASK	0x20

static int hf_mp2t_af_e_reserved_bytes = -1;
static int hf_mp2t_af_stuffing_bytes = -1;

static int hf_mp2t_af_e_ltwv_flag = -1;
static int hf_mp2t_af_e_ltwo = -1;

static int hf_mp2t_af_e_pr_reserved = -1;
static int hf_mp2t_af_e_pr = -1;

static int hf_mp2t_af_e_st = -1;
static int hf_mp2t_af_e_dnau_32_30 = -1;
static int hf_mp2t_af_e_m_1 = -1;
static int hf_mp2t_af_e_dnau_29_15 = -1;
static int hf_mp2t_af_e_m_2 = -1;
static int hf_mp2t_af_e_dnau_14_0 = -1;
static int hf_mp2t_af_e_m_3 = -1;

static int hf_mp2t_payload = -1;
static int hf_mp2t_malformed_payload = -1;


static const value_string mp2t_sync_byte_vals[] = {
	{ MP2T_SYNC_BYTE, "Correct" },
	{ 0, NULL }
};

static const value_string mp2t_pid_vals[] = {
	{ 0x0000, "Program Association Table" },
	{ 0x0001, "Conditional Access Table" },
	{ 0x0002, "Transport Stream Description Table" },
	{ 0x0003, "Reserved" },
	{ 0x0004, "Reserved" },
	{ 0x0005, "Reserved" },
	{ 0x0006, "Reserved" },
	{ 0x0007, "Reserved" },
	{ 0x0008, "Reserved" },
	{ 0x0009, "Reserved" },
	{ 0x000A, "Reserved" },
	{ 0x000B, "Reserved" },
	{ 0x000C, "Reserved" },
	{ 0x000D, "Reserved" },
	{ 0x000E, "Reserved" },
	{ 0x000F, "Reserved" },
	{ 0x1FFE, "DOCSIS Data-over-cable well-known PID" },
	{ 0x1FFF, "Null packet" },
	{ 0, NULL }
};

static const value_string mp2t_tsc_vals[] = {
	{ 0, "Not scrambled" },
	{ 1, "User-defined" },
	{ 2, "User-defined" },
	{ 3, "User-defined" },
	{ 0, NULL }
};

static const value_string mp2t_afc_vals[] = {
	{ 0, "Reserved" },
	{ 1, "Payload only" },
	{ 2, "Adaptation Field only" },
	{ 3, "Adaptation Field and Payload" },
	{ 0, NULL }
};

static gint ett_depi_msg_fragment = -1;
static gint ett_depi_msg_fragments = -1;
static int hf_depi_msg_fragments = -1;
static int hf_depi_msg_fragment = -1;
static int hf_depi_msg_fragment_overlap = -1;
static int hf_depi_msg_fragment_overlap_conflicts = -1;
static int hf_depi_msg_fragment_multiple_tails = -1;
static int hf_depi_msg_fragment_too_long_fragment = -1;
static int hf_depi_msg_fragment_error = -1;
static int hf_depi_msg_fragment_count = -1;
static int hf_depi_msg_reassembled_in = -1;
static int hf_depi_msg_reassembled_length = -1;

static const fragment_items depi_msg_frag_items = {
    /* Fragment subtrees */
    &ett_depi_msg_fragment,
    &ett_depi_msg_fragments,
    /* Fragment fields */
    &hf_depi_msg_fragments,
    &hf_depi_msg_fragment,
    &hf_depi_msg_fragment_overlap,
    &hf_depi_msg_fragment_overlap_conflicts,
    &hf_depi_msg_fragment_multiple_tails,
    &hf_depi_msg_fragment_too_long_fragment,
    &hf_depi_msg_fragment_error,
    &hf_depi_msg_fragment_count,
    /* Reassembled in field */
    &hf_depi_msg_reassembled_in,
    /* Reassembled length field */
    &hf_depi_msg_reassembled_length,
    /* Tag */
    "Message fragments"
};

/* Structures to handle DOCSIS-DEPI packets, spanned across
 * multiple MPEG packets
 */
static GHashTable *mp2t_depi_fragment_table = NULL;
static GHashTable *mp2t_depi_reassembled_table = NULL;

/*****************   DOCSIS defragmentation support *******************/
/* definitions of DOCSIS payload type - from plugins/docsis/packet-docsis.c  */
#define DOCSIS_FC_TYPE_DATA         0x00
#define DOCSIS_FC_TYPE_ATM          0x01
#define DOCSIS_FC_TYPE_RESERVED     0x02
#define DOCSIS_FC_TYPE_MAC          0x03

static guint16
get_docsis_packet_length(tvbuff_t * tvb, gint offset)
{
    guint16 len;
    guint8  fc;
    guint8  fctype;

    /* Extract FC_TYPE and FC_PARM */
    fc = tvb_get_guint8 (tvb, offset);  /* Frame Control Byte */
    fctype = (fc >> 6) & 0x03;  /* Frame Control Type: 2 MSB Bits */

    if((fctype == DOCSIS_FC_TYPE_ATM) ||
       (fctype == DOCSIS_FC_TYPE_RESERVED)) {
        /* add text - this FC type is not supported */
        return 0;
    }

    /* The only case when this field is used for SID is for
     * request frames, but they are in upstream direction.
     */
    len = tvb_get_ntohs(tvb, offset + 2)  +  6;

    return (len);
}

static void
mp2t_depi_docsis_fragmentation_handle(tvbuff_t *tvb, guint offset,
				      packet_info *pinfo, proto_tree *tree,
				      guint frag_offset, guint frag_len,
				      gboolean fragment_last)
{
    fragment_data *frag_msg = NULL;
    tvbuff_t *new_tvb = NULL;
    tvbuff_t *next_tvb = NULL;
    proto_item *ti;
    proto_tree *dmpt_tree;

    pinfo->fragmented = TRUE;

    /* check length; send frame for reassembly */
    frag_msg = fragment_add_check(tvb, offset, pinfo,
                   0, mp2t_depi_fragment_table,
                   mp2t_depi_reassembled_table,
                   frag_offset,
                   frag_len,
                   !fragment_last);

    new_tvb = process_reassembled_data(tvb, offset, pinfo,
                  "Reassembled MP2T",
                  frag_msg, &depi_msg_frag_items,
                  NULL, tree);

    if (frag_msg) { /* Reassembled */
        col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
    } else { /* Not last packet of reassembled Short Message */
        col_append_fstr(pinfo->cinfo, COL_INFO," (Message fragment %u)", 0);
    }

    /* put DOCSIS handler here */
    if (new_tvb) { /* take it all */
        next_tvb = new_tvb;

        ti = proto_tree_add_text(tree, tvb, offset, 0, "DOCSIS MAC Frame (reassembled)");
        dmpt_tree = proto_item_add_subtree(ti, ett_dmpt);

        if (docsis_handle)
            call_dissector(docsis_handle, next_tvb, pinfo, dmpt_tree);
        else
            call_dissector(data_handle, next_tvb, pinfo, dmpt_tree);
    }
    return;
}

/*  Decoding of DOCSIS MAC frames within MPEG packets. MAC frames may begin anywhere
 *  within an MPEG packet or span multiple MPEG packets.
 *  payload_unit_start_indicator bit in MPEG header, and pointer field are used to
 *  decode fragmented DOCSIS frames within MPEG packet.
 *-------------------------------------------------------------------------------
 *MPEG Header | pointer_field | stuff_bytes | Start of MAC Frame #1              |
 *(PUSI = 1)  | (= 0)         | (0 or more) |(up to 183 bytes)                   |
 *-------------------------------------------------------------------------------
 *-------------------------------------------------------------------------------
 *MPEG Header |  Continuation of MAC Frame #1                                    |
 *(PUSI = 0)  |  (up to 183 bytes)                                               |
 *-------------------------------------------------------------------------------
 *-------------------------------------------------------------------------------
 *MPEG Header | pointer_field |Tail of MAC Frame| stuff_bytes |Start of MAC Frame|
 *(PUSI = 1)  | (= M)         | #1  (M bytes)   | (0 or more) |# 2 (N bytes)     |
 *-------------------------------------------------------------------------------
 *  Source - Data-Over-Cable Service Interface Specifications
 *  CM-SP-DRFI-I07-081209
 */
static void
mp2t_depi_docsis_process_payload(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                                 proto_tree *tree, proto_tree *header_tree)
{
    guint32  pusi_flag;
    tvbuff_t *next_tvb;
    guint8   pointer;
    proto_item *ti;
    proto_tree *dmpt_tree;
    static gboolean fragmentation = FALSE;
    static guint32 mac_frame_len, cumulative_len;

    pusi_flag = (tvb_get_ntohl(tvb, offset) & 0x00400000);

    offset += 4;

    if (pusi_flag) {
        pointer = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(header_tree, tvb, offset, 1,
            "Pointer: %u", tvb_get_guint8(tvb, offset));
        offset += 1;
    }

    /* get tail of MAC frame */
    if (pusi_flag && fragmentation) {
        fragmentation = FALSE;

        /* check length; send frame for reassembly */
        mp2t_depi_docsis_fragmentation_handle(tvb, offset, pinfo,
            tree,
            cumulative_len,
            pointer,
            TRUE);
        cumulative_len += pointer;

        if (cumulative_len != mac_frame_len) {
            proto_tree_add_text(tree, tvb, offset, mac_frame_len,
                "Invalid cumulative length %u",
                cumulative_len);
            return;
        }
    }

    /* Get start of MAC frame or get complete frame */
    if (pusi_flag && !fragmentation) {
        guint16 remaining_length;

        remaining_length = 183 - pointer;
        offset += pointer;

        while (remaining_length > 0) {
            while ((tvb_get_guint8(tvb, offset) == 0xFF)) {
                remaining_length--;
                if (remaining_length == 0)
                    return;
                offset += 1;
            }

            /* Here, we start DOCSIS frame */
            mac_frame_len = get_docsis_packet_length(tvb, offset);
            cumulative_len = 0;

            if (!mac_frame_len) {
                proto_tree_add_text(tree, tvb, offset, mac_frame_len,
                    "Invalid DOCSIS length %u", mac_frame_len);
                return;
            }

            if (mac_frame_len <= remaining_length) {
                fragmentation = FALSE;
                /* send for processing */
                ti = proto_tree_add_text(tree, tvb, offset,
                    mac_frame_len,
                    "DOCSIS MAC Frame: %u bytes", mac_frame_len);
                dmpt_tree = proto_item_add_subtree(ti, ett_dmpt);
                next_tvb = tvb_new_subset(tvb, offset, -1, -1);
                if (docsis_handle)
                    call_dissector(docsis_handle, next_tvb, pinfo, dmpt_tree);
                else
                    call_dissector(data_handle, next_tvb, pinfo, dmpt_tree);

                offset += mac_frame_len;
                remaining_length -= mac_frame_len;
            } else {
                fragmentation = TRUE;

                mp2t_depi_docsis_fragmentation_handle(tvb, offset, pinfo,
                    tree, 0, remaining_length, FALSE);
                cumulative_len = remaining_length;
                return;
            }
        }
    }

    /* if PUSI flag == 0 - check fragmentation flag */
    if (!pusi_flag) {
        gboolean last_fragment = FALSE;

        if (fragmentation == FALSE) {
            /* Error - fragmentation should be TRUE */
            proto_tree_add_text(tree, tvb, offset, mac_frame_len,
                "Error - PUSI is 0 in unfragmented DOCSIS packet");
            return;
        }

        /* If packet length is consistent with MAC frame length -
         * call function to handle all fragments
         */
        if ((cumulative_len + 184) == mac_frame_len) {
            last_fragment = TRUE;
            fragmentation = FALSE;
        }

        mp2t_depi_docsis_fragmentation_handle(tvb, offset, pinfo,
            tree, cumulative_len, 184, last_fragment);
        cumulative_len += 184;

        return;
    }
}


/* Data structure used for detecting CC drops
 *
 *  conversation
 *    |
 *    +-> mp2t_analysis_data
 *          |
 *          +-> pid_table (RB tree) (key: pid)
 *          |     |
 *          |     +-> pid_analysis_data (per pid)
 *          |     +-> pid_analysis_data
 *          |     +-> pid_analysis_data
 *          |
 *          +-> frame_table (RB tree) (key: pinfo->fd->num)
 *                |
 *                +-> frame_analysis_data (only created if drop detected)
 *                      |
 *                      +-> ts_table (RB tree)
 *                            |
 *                            +-> ts_analysis_data (per TS subframe)
 *                            +-> ts_analysis_data
 *                            +-> ts_analysis_data
 */

typedef struct mp2t_analysis_data {

	/* This structure contains a tree containing data for the
	 * individual pid's, this is only used when packets are
	 * processed sequencially.
	 */
	emem_tree_t	*pid_table;

	/* When detecting a CC drop, store that information for the
	 * given frame.  This info is needed, when clicking around in
	 * wireshark, as the pid table data only makes sence during
	 * sequencial processing. The flag pinfo->fd->flags.visited is
	 * used to tell the difference.
	 *
	 */
	emem_tree_t	*frame_table;

	/* Total counters per conversation / multicast stream */
	guint32 total_skips;
	guint32 total_discontinuity;

} mp2t_analysis_data_t;

/* Analysis TS frame info needed during sequential processing */
typedef struct pid_analysis_data {
	guint16 pid;
	gint8   cc_prev;  	/* Previous CC number */
} pid_analysis_data_t;

/* Analysis info stored for a TS frame */
typedef struct ts_analysis_data {
	guint16 pid;
	gint8   cc_prev;  	/* Previous CC number */
	guint8  skips;          /* Skips between CCs max 14 */
} ts_analysis_data_t;


typedef struct frame_analysis_data {

	/* As each frame has several pid's, thus need a pid data
	 * structure per TS frame.
	 */
	emem_tree_t	*ts_table;

} frame_analysis_data_t;

static mp2t_analysis_data_t *
init_mp2t_conversation_data(void)
{
	mp2t_analysis_data_t *mp2t_data = NULL;

	mp2t_data = se_alloc0(sizeof(struct mp2t_analysis_data));

	mp2t_data->pid_table =
		se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK,
					      "mp2t_pid_table");
	mp2t_data->frame_table =
		se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK,
					      "mp2t_frame_table");

	mp2t_data->total_skips = 0;
	mp2t_data->total_discontinuity = 0;

	return mp2t_data;
}

static mp2t_analysis_data_t *
get_mp2t_conversation_data(conversation_t *conv)
{
	mp2t_analysis_data_t *mp2t_data = NULL;

	mp2t_data = conversation_get_proto_data(conv, proto_mp2t);
	if (!mp2t_data) {
		mp2t_data = init_mp2t_conversation_data();
		conversation_add_proto_data(conv, proto_mp2t, mp2t_data);
	}

	return mp2t_data;
}

static frame_analysis_data_t *
init_frame_analysis_data(mp2t_analysis_data_t *mp2t_data, packet_info *pinfo)
{
	frame_analysis_data_t *frame_analysis_data_p = NULL;

	frame_analysis_data_p = se_alloc0(sizeof(struct frame_analysis_data));
	frame_analysis_data_p->ts_table =
	  se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK,
					"mp2t_frame_pid_table");
	/* Insert into mp2t tree */
	se_tree_insert32(mp2t_data->frame_table, pinfo->fd->num,
			 (void *)frame_analysis_data_p);

	return frame_analysis_data_p;
}


static frame_analysis_data_t *
get_frame_analysis_data(mp2t_analysis_data_t *mp2t_data, packet_info *pinfo)
{
	frame_analysis_data_t *frame_analysis_data_p = NULL;
	frame_analysis_data_p = se_tree_lookup32(mp2t_data->frame_table, pinfo->fd->num);
	return frame_analysis_data_p;
}

static pid_analysis_data_t *
get_pid_analysis(guint32 pid, conversation_t *conv)
{

	pid_analysis_data_t  *pid_data  = NULL;
	mp2t_analysis_data_t *mp2t_data = NULL;
	mp2t_data = get_mp2t_conversation_data(conv);

	pid_data = se_tree_lookup32(mp2t_data->pid_table, pid);
	if (!pid_data) {
		pid_data          = se_alloc0(sizeof(struct pid_analysis_data));
		pid_data->cc_prev = -1;
		pid_data->pid     = pid;

		se_tree_insert32(mp2t_data->pid_table, pid, (void *)pid_data);
	}
	return pid_data;
}

/* Calc the number of skipped CC numbers. Note that this can easy
 * overflow, and a value above 7 indicate several network packets
 * could be lost.
 */
static guint32
calc_skips(gint32 curr, gint32 prev)
{
	int res = 0;

	/* Only count the missing TS frames in between prev and curr.
	 * The "prev" frame CC number seen is confirmed received, its
	 * the next frames CC counter which is the first known missing
	 * TS frame
	 */
	prev += 1;

	/* Calc missing TS frame 'skips' */
	res = curr - prev;

	/* Handle wrap around */
	if (res < 0)
		res += 16;

	return res;
}

#define KEY(pid, cc) ((pid << 4)|cc)

static guint32
detect_cc_drops(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
		guint32 pid, gint32 cc_curr, conversation_t *conv)
{
	gint32 cc_prev = -1;
	pid_analysis_data_t   *pid_data              = NULL;
	ts_analysis_data_t    *ts_data               = NULL;
	mp2t_analysis_data_t  *mp2t_data             = NULL;
	frame_analysis_data_t *frame_analysis_data_p = NULL;
	proto_item            *flags_item;

	guint32 detected_drop = 0;
	guint32 skips = 0;

	mp2t_data = get_mp2t_conversation_data(conv);

	/* The initial sequencial processing stage */
	if (!pinfo->fd->flags.visited) {

		/* This is the sequencial processing stage */
		pid_data = get_pid_analysis(pid, conv);

		cc_prev = pid_data->cc_prev;
		pid_data->cc_prev = cc_curr;

		/* Null packet always have a CC value equal 0 */
		if (pid == 0x1fff)
			return 0;

		/* Its allowed that (cc_prev == cc_curr) if adaptation field */
		if (cc_prev == cc_curr)
			return 0;

		/* Have not seen this pid before */
		if (cc_prev == -1)
			return 0;

		/* Detect if CC is not increasing by one all the time */
		if (cc_curr != ((cc_prev+1) & MP2T_CC_MASK)) {
			detected_drop = 1;

			skips = calc_skips(cc_curr, cc_prev);

			mp2t_data->total_skips += skips;
			mp2t_data->total_discontinuity++;
			/* TODO: if (skips > 7) signal_loss++; ??? */
		}
	}

	/* Save the info about the dropped packet */
	if (detected_drop && !pinfo->fd->flags.visited) {

		/* Lookup frame data, contains TS pid data objects */
		frame_analysis_data_p = get_frame_analysis_data(mp2t_data, pinfo);
		if (!frame_analysis_data_p)
			frame_analysis_data_p = init_frame_analysis_data(mp2t_data, pinfo);

		/* Create and store a new TS frame pid_data object.
		   This indicate that we have a drop
		 */
		ts_data = se_alloc0(sizeof(struct ts_analysis_data));
		ts_data->cc_prev = cc_prev;
		ts_data->pid = pid;
		ts_data->skips = skips;
		se_tree_insert32(frame_analysis_data_p->ts_table, KEY(pid, cc_curr),
				 (void *)ts_data);
	}

	/* See if we stored info about drops */
	if (pinfo->fd->flags.visited) {

		/* Lookup frame data, contains TS pid data objects */
		frame_analysis_data_p = get_frame_analysis_data(mp2t_data, pinfo);
		if (!frame_analysis_data_p)
			return 0; /* No stored frame data -> no drops*/
		else {
			ts_data = se_tree_lookup32(frame_analysis_data_p->ts_table,
						   KEY(pid, cc_curr));

			if (ts_data) {
				if (ts_data->skips > 0) {
					detected_drop = 1;
					cc_prev = ts_data->cc_prev;
					skips   = ts_data->skips;
				}
			}
		}

	}

	/* Add info to the proto tree about drops */
	if (detected_drop) {

		flags_item =
			proto_tree_add_none_format(
				tree, hf_mp2t_cc_drop, tvb, 0, 0,
				"Detected %d missing TS frames before this"
				" (last_cc:%d total skips:%d discontinuity:%d)",
				skips, cc_prev,
				mp2t_data->total_skips,
				mp2t_data->total_discontinuity
				);

		PROTO_ITEM_SET_GENERATED(flags_item);
		expert_add_info_format(pinfo, flags_item, PI_MALFORMED,
				       PI_ERROR, "Detected TS frame loss");

		flags_item = proto_tree_add_uint(tree, hf_mp2t_analysis_skips,
					       tvb, 0, 0, skips);
		PROTO_ITEM_SET_GENERATED(flags_item);

		flags_item = proto_tree_add_uint(tree, hf_mp2t_analysis_drops,
					       tvb, 0, 0, 1);
		PROTO_ITEM_SET_GENERATED(flags_item);

	}
	return skips;
}


static gint
dissect_tsp(tvbuff_t *tvb, volatile gint offset, packet_info *pinfo,
	    proto_tree *tree, conversation_t *conv)
{
	guint32 header;
	guint afc;
	gint start_offset = offset;
	volatile gint payload_len;

	guint32 skips;
	guint32 pid;
	guint32 cc;

	proto_item *ti = NULL;
	proto_item *hi = NULL;
	proto_item *item = NULL;
	proto_tree *mp2t_tree = NULL;
	proto_tree *mp2t_header_tree = NULL;
	proto_tree *mp2t_af_tree = NULL;
	proto_tree *mp2t_analysis_tree = NULL;

	ti = proto_tree_add_item( tree, proto_mp2t, tvb, offset, MP2T_PACKET_SIZE, FALSE );
	mp2t_tree = proto_item_add_subtree( ti, ett_mp2t );

	header = tvb_get_ntohl(tvb, offset);

	pid = (header & MP2T_PID_MASK) >> MP2T_PID_SHIFT;
	cc  = (header & MP2T_CC_MASK)  >> MP2T_CC_SHIFT;
	proto_item_append_text(ti, " PID=0x%x CC=%d", pid, cc);

	hi = proto_tree_add_item( mp2t_tree, hf_mp2t_header, tvb, offset, 4, FALSE);
	mp2t_header_tree = proto_item_add_subtree( hi, ett_mp2t_header );

	proto_tree_add_item( mp2t_header_tree, hf_mp2t_sync_byte, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_tei, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_pusi, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_tp, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_pid, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_tsc, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_afc, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_cc, tvb, offset, 4, FALSE);

	/* If this is a DOCSIS packet - reassemble MPEG frames and call DOCSIS dissector */
	if (((header & MP2T_PID_MASK) >> MP2T_PID_SHIFT) == 0x1FFE) {
		mp2t_depi_docsis_process_payload(tvb, offset, pinfo, tree, mp2t_tree);
	}

	offset += 4;

	/* Create a subtree for analysis stuff */
	item = proto_tree_add_text(mp2t_tree, tvb, 0, 0, "MPEG2 PCR Analysis");
	PROTO_ITEM_SET_GENERATED(item);
	mp2t_analysis_tree = proto_item_add_subtree(item, ett_mp2t_analysis);

	skips = detect_cc_drops(tvb, mp2t_analysis_tree, pinfo, pid, cc, conv);
	if (skips > 0)
		proto_item_append_text(ti, " skips=%d", skips);


	afc = (header & MP2T_AFC_MASK) >> MP2T_AFC_SHIFT;

	if (afc == 2 || afc == 3)
	{
		gint af_start_offset = offset;

		guint8 af_length;
		guint8 af_flags;
		gint stuffing_len;


		af_length = tvb_get_guint8(tvb, offset);

		proto_tree_add_item( mp2t_tree, hf_mp2t_af_length, tvb, offset, 1, FALSE);
		offset += 1;
		/* fix issues where afc==3 but af_length==0
		 *  Adaptaion field...spec section 2.4.3.5: The value 0 is for inserting a single
		 *  stuffing byte in a Transport Stream packet. When the adaptation_field_control
		 *  value is '11', the value of the adaptation_field_length shall be in the range 0 to 182.
		 */
		if (af_length > 0 ) {
			hi = proto_tree_add_item( mp2t_tree, hf_mp2t_af, tvb, offset, af_length, FALSE);
			mp2t_af_tree = proto_item_add_subtree( hi, ett_mp2t_af );

			af_flags = tvb_get_guint8(tvb, offset);

			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_di, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_rai, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_espi, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_pcr_flag, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_opcr_flag, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_sp_flag, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_tpd_flag, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_afe_flag, tvb, offset, 1, FALSE);

			offset += 1;

			if (af_flags &  MP2T_AF_PCR_MASK) {
				guint64 pcr_base = 0;
				guint32 pcr_ext = 0;
				guint8 tmp;

				tmp = tvb_get_guint8(tvb, offset);
				pcr_base = (pcr_base << 8) | tmp;
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				pcr_base = (pcr_base << 8) | tmp;
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				pcr_base = (pcr_base << 8) | tmp;
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				pcr_base = (pcr_base << 8) | tmp;
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				pcr_base = (pcr_base << 1) | ((tmp >> 7) & 0x01);
				pcr_ext = (tmp & 0x01);
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				pcr_ext = (pcr_ext << 8) | tmp;
				offset += 1;

				proto_tree_add_none_format(mp2t_af_tree, hf_mp2t_af_pcr, tvb, offset - 6, 6,
						"Program Clock Reference: base(%" G_GINT64_MODIFIER "u) * 300 + ext(%u) = %" G_GINT64_MODIFIER "u",
						pcr_base, pcr_ext, pcr_base * 300 + pcr_ext);
			}

			if (af_flags &  MP2T_AF_OPCR_MASK) {
				guint64 opcr_base = 0;
				guint32 opcr_ext = 0;
				guint8 tmp = 0;

				tmp = tvb_get_guint8(tvb, offset);
				opcr_base = (opcr_base << 8) | tmp;
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				opcr_base = (opcr_base << 8) | tmp;
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				opcr_base = (opcr_base << 8) | tmp;
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				opcr_base = (opcr_base << 8) | tmp;
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				opcr_base = (opcr_base << 1) | ((tmp >> 7) & 0x01);
				opcr_ext = (tmp & 0x01);
				offset += 1;

				tmp = tvb_get_guint8(tvb, offset);
				opcr_ext = (opcr_ext << 8) | tmp;
				offset += 1;

				proto_tree_add_none_format(mp2t_af_tree, hf_mp2t_af_opcr, tvb, offset - 6, 6,
						"Original Program Clock Reference: base(%" G_GINT64_MODIFIER "u) * 300 + ext(%u) = %" G_GINT64_MODIFIER "u",
						opcr_base, opcr_ext, opcr_base * 300 + opcr_ext);

				offset += 6;
			}

			if (af_flags &  MP2T_AF_SP_MASK) {
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_sc, tvb, offset, 1, FALSE);
				offset += 1;
			}

			if (af_flags &  MP2T_AF_TPD_MASK) {
				guint8 tpd_len;

				tpd_len = tvb_get_guint8(tvb, offset);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_tpd_length, tvb, offset, 1, FALSE);
				offset += 1;

				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_tpd, tvb, offset, tpd_len, FALSE);
				offset += tpd_len;
			}

			if (af_flags &  MP2T_AF_AFE_MASK) {
				guint8 e_len;
				guint8 e_flags;
				gint e_start_offset = offset;
				gint reserved_len = 0;

				e_len = tvb_get_guint8(tvb, offset);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_length, tvb, offset, 1, FALSE);
				offset += 1;

				e_flags = tvb_get_guint8(tvb, offset);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ltw_flag, tvb, offset, 1, FALSE);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_pr_flag, tvb, offset, 1, FALSE);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ss_flag, tvb, offset, 1, FALSE);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_reserved, tvb, offset, 1, FALSE);
				offset += 1;

				if (e_flags & MP2T_AF_E_LTW_FLAG_MASK) {
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ltwv_flag, tvb, offset, 2, FALSE);
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ltwo, tvb, offset, 2, FALSE);
					offset += 2;
				}

				if (e_flags & MP2T_AF_E_PR_FLAG_MASK) {
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_pr_reserved, tvb, offset, 3, FALSE);
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_pr, tvb, offset, 3, FALSE);
					offset += 3;
				}

				if (e_flags & MP2T_AF_E_SS_FLAG_MASK) {
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_st, tvb, offset, 1, FALSE);
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_dnau_32_30, tvb, offset, 1, FALSE);
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_m_1, tvb, offset, 1, FALSE);
					offset += 1;
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_dnau_29_15, tvb, offset, 2, FALSE);
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_m_2, tvb, offset, 2, FALSE);
					offset += 2;
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_dnau_14_0, tvb, offset, 2, FALSE);
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_m_3, tvb, offset, 2, FALSE);
					offset += 2;
				}

				reserved_len = (e_len + 1) - (offset - e_start_offset);
				if (reserved_len > 0) {
					proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_reserved_bytes, tvb, offset, reserved_len, FALSE);
					offset += reserved_len;
				}
			}

			stuffing_len = (af_length + 1) - (offset - af_start_offset);
			if (stuffing_len > 0) {
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_stuffing_bytes, tvb, offset, stuffing_len, FALSE);
				offset += stuffing_len;
			}
		}
	}

	payload_len = MP2T_PACKET_SIZE - (offset - start_offset);
	if (payload_len > 0) {
		if (afc == 2) {	/* AF only */
			/* Packet is malformed */
			proto_tree_add_item( mp2t_tree, hf_mp2t_malformed_payload, tvb, offset, payload_len, FALSE);
			offset += payload_len;
		} else {
			/* Check to make sure if we are not at end of payload, if we have less than 3 bytes, the tvb_get_ntoh24 fails. */
			if (payload_len >=3 ) {
				if (tvb_get_ntoh24(tvb, offset) == 0x000001) {
					tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, payload_len, payload_len);
					const char *saved_proto = pinfo->current_proto;
					void *pd_save = pinfo->private_data;

					TRY {
						call_dissector(pes_handle, next_tvb, pinfo, mp2t_tree);
					}

					/*
					 Don't stop processing TS packets if somebody threw
					 BoundsError, which means that dissecting the payload found
					 that the packet was cut off by before the end of the
					 payload.  This is very likely as this protocol splits the
					 media stream up into chunks of MP2T_PACKET_SIZE.
					*/
					CATCH2(BoundsError, ReportedBoundsError) {
						/*  Restore the private_data structure in case one of the
						 *  called dissectors modified it (and, due to the exception,
						 *  was unable to restore it).
						 */
						pinfo->private_data = pd_save;
						show_exception(next_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
						pinfo->current_proto = saved_proto;
					}

					ENDTRY;
				} else {
					proto_tree_add_item( mp2t_tree, hf_mp2t_payload, tvb, offset, payload_len, FALSE);
				}
			} else {
				proto_tree_add_item( mp2t_tree, hf_mp2t_payload, tvb, offset, payload_len, FALSE);
			}
			offset += payload_len;
		}
	}

	return offset;
}


static void
dissect_mp2t( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	guint offset = 0;
	conversation_t *conv;
	conv = find_or_create_conversation(pinfo);

	while ( tvb_reported_length_remaining(tvb, offset) >= MP2T_PACKET_SIZE ) {
		offset = dissect_tsp(tvb, offset, pinfo, tree, conv);
	}
}

static gboolean
heur_dissect_mp2t( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	guint offset = 0;

	if (tvb_length_remaining(tvb, offset) % MP2T_PACKET_SIZE) {
		return FALSE;
	} else {
		while (tvb_length_remaining(tvb, offset)) {
			if (tvb_get_guint8(tvb, offset) != MP2T_SYNC_BYTE)
				return FALSE;
			offset += MP2T_PACKET_SIZE;
		}
	}

	dissect_mp2t(tvb, pinfo, tree);
	return TRUE;
}


static void
mp2t_init(void) {
	fragment_table_init(&mp2t_depi_fragment_table);
	reassembled_table_init(&mp2t_depi_reassembled_table);
}

void
proto_register_mp2t(void)
{
	static hf_register_info hf[] = {
		{ &hf_mp2t_header, {
			"Header", "mp2t.header",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
		} } ,
		{ &hf_mp2t_sync_byte, {
			"Sync Byte", "mp2t.sync_byte",
			FT_UINT32, BASE_HEX, VALS(mp2t_sync_byte_vals), MP2T_SYNC_BYTE_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_tei, {
			"Transport Error Indicator", "mp2t.tei",
			FT_UINT32, BASE_DEC, NULL, MP2T_TEI_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_pusi, {
			"Payload Unit Start Indicator", "mp2t.pusi",
			FT_UINT32, BASE_DEC, NULL, MP2T_PUSI_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_tp, {
			"Transport Priority", "mp2t.tp",
			FT_UINT32, BASE_DEC, NULL, MP2T_TP_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_pid, {
			"PID", "mp2t.pid",
			FT_UINT32, BASE_HEX, VALS(mp2t_pid_vals), MP2T_PID_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_tsc, {
			"Transport Scrambling Control", "mp2t.tsc",
			FT_UINT32, BASE_HEX, VALS(mp2t_tsc_vals), MP2T_TSC_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_afc, {
			"Adaption Field Control", "mp2t.afc",
			FT_UINT32, BASE_HEX, VALS(mp2t_afc_vals) , MP2T_AFC_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_cc, {
			"Continuity Counter", "mp2t.cc",
			FT_UINT32, BASE_DEC, NULL, MP2T_CC_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_cc_drop, {
			"Continuity Counter Drops", "mp2t.cc.drop",
			FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL
		} } ,
		{ &hf_mp2t_analysis_flags, {
			"MPEG2-TS Analysis Flags", "mp2t.analysis.flags",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"This frame has some of the MPEG2 analysis flags set", HFILL
		} } ,
		{ &hf_mp2t_analysis_skips, {
			"TS Continuity Counter Skips", "mp2t.analysis.skips",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Missing TS frames accoding to CC counter values", HFILL
		} } ,
		{ &hf_mp2t_analysis_drops, {
			"Some frames dropped", "mp2t.analysis.drops",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Discontinuity: A number of TS frames were dropped", HFILL
		} } ,
		{ &hf_mp2t_af, {
			"Adaption field", "mp2t.af",
			FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_length, {
			"Adaptation Field Length", "mp2t.af.length",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_di, {
			"Discontinuity Indicator", "mp2t.af.di",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_DI_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_rai, {
			"Random Access Indicator", "mp2t.af.rai",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_RAI_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_espi, {
			"Elementary Stream Priority Indicator", "mp2t.af.espi",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_ESPI_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_pcr_flag, {
			"PCR Flag", "mp2t.af.pcr_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_PCR_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_opcr_flag, {
			"OPCR Flag", "mp2t.af.opcr_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_OPCR_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_sp_flag, {
			"Splicing Point Flag", "mp2t.af.sp_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_SP_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_tpd_flag, {
			"Transport Private Data Flag", "mp2t.af.tpd_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_TPD_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_afe_flag, {
			"Adaptation Field Extension Flag", "mp2t.af.afe_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_AFE_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_pcr, {
			"Program Clock Reference", "mp2t.af.pcr",
			FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_opcr, {
			"Original Program Clock Reference", "mp2t.af.opcr",
			FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_sc, {
			"Splice Countdown", "mp2t.af.sc",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_tpd_length, {
			"Transport Private Data Length", "mp2t.af.tpd_length",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_tpd, {
			"Transport Private Data", "mp2t.af.tpd",
			FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_length, {
			"Adaptation Field Extension Length", "mp2t.af.e_length",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_ltw_flag, {
			"LTW Flag", "mp2t.af.e.ltw_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_E_LTW_FLAG_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_pr_flag, {
			"Piecewise Rate Flag", "mp2t.af.e.pr_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_E_PR_FLAG_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_ss_flag, {
			"Seamless Splice Flag", "mp2t.af.e.ss_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_E_SS_FLAG_MASK, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_reserved, {
			"Reserved", "mp2t.af.e.reserved",
			FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_reserved_bytes, {
			"Reserved", "mp2t.af.e.reserved_bytes",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_stuffing_bytes, {
			"Stuffing", "mp2t.af.stuffing_bytes",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_ltwv_flag, {
			"LTW Valid Flag", "mp2t.af.e.ltwv_flag",
			FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_ltwo, {
			"LTW Offset", "mp2t.af.e.ltwo",
			FT_UINT16, BASE_DEC, NULL, 0x7FFF, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_pr_reserved, {
			"Reserved", "mp2t.af.e.pr_reserved",
			FT_UINT24, BASE_DEC, NULL, 0xC00000, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_pr, {
			"Piecewise Rate", "mp2t.af.e.pr",
			FT_UINT24, BASE_DEC, NULL, 0x3FFFFF, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_st, {
			"Splice Type", "mp2t.af.e.st",
			FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_dnau_32_30, {
			"DTS Next AU[32...30]", "mp2t.af.e.dnau_32_30",
			FT_UINT8, BASE_DEC, NULL, 0x0E, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_m_1, {
			"Marker Bit", "mp2t.af.e.m_1",
			FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_dnau_29_15, {
			"DTS Next AU[29...15]", "mp2t.af.e.dnau_29_15",
			FT_UINT16, BASE_DEC, NULL, 0xFFFE, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_m_2, {
			"Marker Bit", "mp2t.af.e.m_2",
			FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_dnau_14_0, {
			"DTS Next AU[14...0]", "mp2t.af.e.dnau_14_0",
			FT_UINT16, BASE_DEC, NULL, 0xFFFE, NULL, HFILL
		} } ,
		{ &hf_mp2t_af_e_m_3, {
			"Marker Bit", "mp2t.af.e.m_3",
			FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL
		} } ,
		{ &hf_mp2t_payload, {
			"Payload", "mp2t.payload",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
		} } ,
		{ &hf_mp2t_malformed_payload, {
			"Malformed Payload", "mp2t.malformed_payload",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
		} },
		{  &hf_depi_msg_fragments, {
			"Message fragments", "mp2t.depi_msg.fragments",
			FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL
		} },
		{  &hf_depi_msg_fragment, {
			"Message fragment", "mp2t.depi_msg.fragment",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL
		} },
		{  &hf_depi_msg_fragment_overlap, {
			"Message fragment overlap", "mp2t.depi_msg.fragment.overlap",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
		} },
		{  &hf_depi_msg_fragment_overlap_conflicts, {
			"Message fragment overlapping with conflicting data",
			"mp2t.depi_msg.fragment.overlap.conflicts",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
		} },
		{  &hf_depi_msg_fragment_multiple_tails, {
			"Message has multiple tail fragments",
			"mp2t.depi_msg.fragment.multiple_tails",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
		} },
		{  &hf_depi_msg_fragment_too_long_fragment, {
			"Message fragment too long", "mp2t.depi_msg.fragment.too_long_fragment",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
		} },
		{  &hf_depi_msg_fragment_error, {
			"Message defragmentation error", "mp2t.depi_msg.fragment.error",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL
		} },
		{  &hf_depi_msg_fragment_count, {
			"Message fragment count", "mp2t.depi_msg.fragment.count",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL
		} },
		{  &hf_depi_msg_reassembled_in, {
			"Reassembled in", "mp2t.depi_msg.reassembled.in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL
		} },
		{  &hf_depi_msg_reassembled_length, {
			"Reassembled MP2T length", "mp2t.depi_msg.reassembled.length",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL
		} }
	};

	static gint *ett[] =
	{
		&ett_mp2t,
		&ett_mp2t_header,
		&ett_mp2t_af,
		&ett_mp2t_analysis,
		&ett_dmpt,
		&ett_depi_msg_fragment,
		&ett_depi_msg_fragments
	};

	proto_mp2t = proto_register_protocol("ISO/IEC 13818-1", "MP2T", "mp2t");
	register_dissector("mp2t", dissect_mp2t, proto_mp2t);
	proto_register_field_array(proto_mp2t, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	/* Register init of processing of fragmented DEPI packets */
        register_init_routine(mp2t_init);
}



void
proto_reg_handoff_mp2t(void)
{
	dissector_handle_t mp2t_handle;

	heur_dissector_add("udp", heur_dissect_mp2t, proto_mp2t);

	mp2t_handle = create_dissector_handle(dissect_mp2t, proto_mp2t);
	dissector_add_uint("rtp.pt", PT_MP2T, mp2t_handle);
	dissector_add_handle("udp.port", mp2t_handle);  /* for decode-as */
	heur_dissector_add("usb.bulk", heur_dissect_mp2t, proto_mp2t);

	pes_handle = find_dissector("mpeg-pes");
	docsis_handle = find_dissector("docsis");
	data_handle = find_dissector("data");
}

