/* Routines for UMTS RLC disassembly
 *
 * $Id$
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
#include "config.h"
#endif

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include "packet-umts_fp.h"
#include "packet-umts_mac.h"
#include "packet-rlc.h"
#include "packet-rrc.h"

/* TODO:
 * 	- AM SEQ wrap case
 * 	- UM/AM 'real' reordering (final packet must appear in-order right now)
 * 	- use sub_num in fragment identification?
 */

#define DEBUG_FRAME(number, msg) {if (pinfo->fd->num == number) printf("%u: %s\n", number, msg);}

int proto_rlc = -1;

extern int proto_fp;
extern int proto_malformed;

/* Preference to perform reassembly */
static gboolean global_rlc_perform_reassemby = TRUE;

/* Preference to expect RLC headers without payloads */
static gboolean global_rlc_headers_expected = FALSE;

/* Heuristic dissection */
static gboolean global_rlc_heur = FALSE;

/* fields */
static int hf_rlc_seq = -1;
static int hf_rlc_ext = -1;
static int hf_rlc_pad = -1;
static int hf_rlc_frags = -1;
static int hf_rlc_frag = -1;
static int hf_rlc_duplicate_of = -1;
static int hf_rlc_reassembled_in = -1;
static int hf_rlc_he = -1;
static int hf_rlc_dc = -1;
static int hf_rlc_p = -1;
static int hf_rlc_li = -1;
static int hf_rlc_li_value = -1;
static int hf_rlc_li_ext = -1;
static int hf_rlc_li_data = -1;
static int hf_rlc_data = -1;
static int hf_rlc_ctrl_type = -1;
static int hf_rlc_r1 = -1;
static int hf_rlc_rsn = -1;
static int hf_rlc_hfni = -1;
static int hf_rlc_sufi = -1;
static int hf_rlc_sufi_type = -1;
static int hf_rlc_sufi_lsn = -1;
static int hf_rlc_sufi_wsn = -1;
static int hf_rlc_sufi_sn = -1;
static int hf_rlc_sufi_l = -1;
static int hf_rlc_sufi_fsn = -1;
static int hf_rlc_sufi_len = -1;
static int hf_rlc_sufi_bitmap = -1;
static int hf_rlc_sufi_cw = -1;
static int hf_rlc_sufi_n = -1;
static int hf_rlc_sufi_sn_ack = -1;
static int hf_rlc_sufi_sn_mrw = -1;
static int hf_rlc_sufi_poll_sn = -1;
static int hf_rlc_header_only = -1;

/* subtrees */
static int ett_rlc = -1;
static int ett_rlc_frag = -1;
static int ett_rlc_fragments = -1;
static int ett_rlc_sdu = -1;
static int ett_rlc_sufi = -1;
static int ett_rlc_bitmap = -1;
static int ett_rlc_rlist = -1;

static dissector_handle_t ip_handle;
static dissector_handle_t rrc_handle;
static dissector_handle_t bmc_handle;

enum channel_type {
	PCCH,
	UL_CCCH,
	DL_CCCH,
	UL_DCCH,
	DL_DCCH,
	PS_DTCH,
	DL_CTCH,
	UNKNOWN
};

static const true_false_string rlc_header_only_val = {
	"RLC PDU header only", "RLC PDU header and body present"
};


static const true_false_string rlc_ext_val = {
	"Next field is Length Indicator and E Bit", "Next field is data, piggybacked STATUS PDU or padding"
};

static const true_false_string rlc_dc_val = {
	"Data", "Control"
};

static const true_false_string rlc_p_val = {
	"Request a status report", "Status report not requested"
};

static const value_string rlc_he_vals[] = {
	{ 0, "The succeeding octet contains data" },
	{ 1, "The succeeding octet contains a length indicator and E bit" },
	{ 2, "The succeeding octet contains data and the last octet of the PDU is the last octet of an SDU" },
	{ 0, NULL }
};

#define RLC_STATUS		0x0
#define RLC_RESET		0x1
#define RLC_RESET_ACK	0x2
static const value_string rlc_ctrl_vals[] = {
	{ RLC_STATUS,		"Status" },
	{ RLC_RESET,		"Reset" },
	{ RLC_RESET_ACK,	"Reset Ack" },
	{ 0, NULL }
};

#define RLC_SUFI_NOMORE		0x0
#define RLC_SUFI_WINDOW		0x1
#define RLC_SUFI_ACK		0x2
#define RLC_SUFI_LIST		0x3
#define RLC_SUFI_BITMAP		0x4
#define RLC_SUFI_RLIST		0x5
#define RLC_SUFI_MRW		0x6
#define RLC_SUFI_MRW_ACK	0x7
#define RLC_SUFI_POLL       0x8
static const value_string rlc_sufi_vals[] = {
	{ RLC_SUFI_NOMORE,	"No more data" },
	{ RLC_SUFI_WINDOW,	"Window size" },
	{ RLC_SUFI_ACK,		"Acknowledgement" },
	{ RLC_SUFI_LIST,	"List" },
	{ RLC_SUFI_BITMAP,	"Bitmap" },
	{ RLC_SUFI_RLIST,	"Relative list" },
	{ RLC_SUFI_MRW,		"Move receiving window" },
	{ RLC_SUFI_MRW_ACK,	"Move receiving window acknowledgement" },
	{ RLC_SUFI_POLL,	"Poll" },
	{ 0, NULL }
};

/* reassembly related data */
static GHashTable *fragment_table = NULL;	/* maps rlc_channel -> fragmented sdu */
static GHashTable *reassembled_table = NULL;    /* maps fragment -> complete sdu */
static GHashTable *sequence_table = NULL;       /* channel -> seq */

/* identify an RLC channel, using one of two options:
 *  - via Radio Bearer ID and U-RNTI
 *  - via Radio Bearer ID and (VPI/VCI/CID) + Link ID
 */
struct rlc_channel {
	guint32 urnti;
	guint16 vpi;
	guint16 vci;
	guint8 cid;
	guint16 link; /* link number */
	guint8 rbid; /* radio bearer ID */
	guint8 dir; /* direction */
	enum rlc_li_size li_size;
	enum rlc_mode mode;
};

/* used for duplicate detection */
struct rlc_seq {
	guint32 frame_num;
	nstime_t arrival;
	guint16 seq;
	guint16 oc; /* overflow counter */
};

struct rlc_seqlist {
	struct rlc_channel ch;

	GList *list;
};

/* fragment representation */
struct rlc_frag {
	guint32 frame_num;
	struct rlc_channel ch;
	guint16 seq; /* RLC sequence number */
	guint16 li; /* LI within current RLC frame */
	guint16 len; /* length of fragment data */
	guint8 *data; /* store fragment data here */

	struct rlc_frag *next; /* next fragment */
};

struct rlc_sdu {
	tvbuff_t *tvb; /* contains reassembled tvb */
	guint16 len; /* total length of reassembled SDU */
	guint16 fragcnt; /* number of fragments within this SDU */
	guint8 *data; /* reassembled data buffer */

	struct rlc_frag *reassembled_in;
	struct rlc_frag *frags; /* pointer to list of fragments */
	struct rlc_frag *last; /* pointer to last fragment */
};

struct rlc_li {
	guint16 li; /* original li */
	guint16 len; /* length of this data fragment */
	guint8 ext; /* extension bit value */

	proto_tree *tree; /* subtree for this LI */
};

/* hashtable functions for fragment table
 * rlc_channel -> SDU
 */
static guint rlc_channel_hash(gconstpointer key)
{
	const struct rlc_channel *ch = key;

	if (ch->urnti)
		return ch->urnti | ch->rbid | ch->mode;

	return (ch->vci << 16) | (ch->link << 16) | ch->vpi | ch->vci;
}

static gboolean rlc_channel_equal(gconstpointer a, gconstpointer b)
{
	const struct rlc_channel *x = a, *y = b;

	if (x->urnti || y->urnti)
		return x->urnti == y->urnti &&
			x->rbid == y->rbid &&
			x->mode == y->mode &&
			x->dir == y->dir ? TRUE : FALSE;

	return x->vpi == y->vpi &&
		x->vci == y->vci &&
		x->cid == y->cid &&
		x->rbid == y->rbid &&
		x->mode == y->mode &&
		x->dir == y->dir &&
		x->link == y->link ? TRUE : FALSE;
}

static int rlc_channel_assign(struct rlc_channel *ch, enum rlc_mode mode, packet_info *pinfo)
{
	struct atm_phdr *atm;
	rlc_info *rlcinf;
	fp_info *fpinf;

	atm = &pinfo->pseudo_header->atm;
	fpinf = p_get_proto_data(pinfo->fd, proto_fp);
	rlcinf = p_get_proto_data(pinfo->fd, proto_rlc);
	if (!fpinf || !rlcinf || !atm) return -1;

	if (rlcinf->urnti[fpinf->cur_tb]) {
		ch->urnti = rlcinf->urnti[fpinf->cur_tb];
		ch->vpi = ch->vci = ch->link = ch->cid = 0;
	} else {
		ch->urnti = 0;
		ch->vpi = atm->vpi;
		ch->vci = atm->vci;
		ch->cid = atm->aal2_cid;
		ch->link = pinfo->link_number;
	}
	ch->rbid = rlcinf->rbid[fpinf->cur_tb];
	ch->dir = pinfo->p2p_dir;
	ch->mode = mode;
	ch->li_size = rlcinf->li_size[fpinf->cur_tb];
	
	return 0;
}

static struct rlc_channel *rlc_channel_create(enum rlc_mode mode, packet_info *pinfo)
{
	struct rlc_channel *ch;
	int rv;

	ch = g_malloc0(sizeof(struct rlc_channel));
	rv = rlc_channel_assign(ch, mode, pinfo);

	if (rv != 0) {
		/* channel assignment failed */
		g_free(ch);
		ch = NULL;
	}
	return ch;
}

static void rlc_channel_delete(gpointer data)
{
	g_free(data);
}

/* hashtable functions for reassembled table
 * fragment -> SDU
 */
static guint rlc_frag_hash(gconstpointer key)
{
	const struct rlc_frag *frag = key;
	return rlc_channel_hash(&frag->ch) | frag->li | frag->seq;
}

static gboolean rlc_frag_equal(gconstpointer a, gconstpointer b)
{
	const struct rlc_frag *x = a, *y = b;

	return rlc_channel_equal(&x->ch, &y->ch) &&
		x->seq == y->seq &&
		x->frame_num == y->frame_num &&
		x->li == y->li ? TRUE : FALSE;
}


static struct rlc_sdu *rlc_sdu_create(void)
{
	struct rlc_sdu *sdu;
	sdu = se_alloc0(sizeof(struct rlc_sdu));
	return sdu;
}

static void rlc_frag_delete(gpointer data)
{
	struct rlc_frag *frag = data;
	if (frag->data) {
		g_free(frag->data);
		frag->data = NULL;
	}
}

static void rlc_sdu_frags_delete(gpointer data)
{
	struct rlc_sdu *sdu = data;
	struct rlc_frag *frag;

	frag = sdu->frags;
	while (frag) {
	 	if (frag->data) {
			g_free(frag->data);
		}
		frag->data = NULL;
		frag = frag->next;
	}
}

static int rlc_frag_assign(struct rlc_frag *frag, enum rlc_mode mode, packet_info *pinfo,
	guint16 seq, guint16 li)
{
	frag->frame_num = pinfo->fd->num;
	frag->seq = seq;
	frag->li = li;
	frag->len = 0;
	frag->data = NULL;
	rlc_channel_assign(&frag->ch, mode, pinfo);

	return 0;
}

static int rlc_frag_assign_data(struct rlc_frag *frag, tvbuff_t *tvb, 
	guint16 offset, guint16 length)
{
	frag->len = length;
	frag->data = g_malloc(length);
	tvb_memcpy(tvb, frag->data, offset, length);
	return 0;
}

static struct rlc_frag *rlc_frag_create(tvbuff_t *tvb, enum rlc_mode mode, packet_info *pinfo,
	guint16 offset, guint16 length, guint16 seq, guint16 li)
{
	struct rlc_frag *frag;
	frag = se_alloc0(sizeof(struct rlc_frag));
	rlc_frag_assign(frag, mode, pinfo, seq, li);
	rlc_frag_assign_data(frag, tvb, offset, length);

	return frag;
}

static int rlc_cmp_seq(gconstpointer a, gconstpointer b)
{
	const struct rlc_seq *_a = a, *_b = b;

	return	_a->seq < _b->seq ? -1 :
			_a->seq > _b->seq ?  1 :
			0;
}

/* callback function to use for g_hash_table_foreach_remove()
 * always return TRUE (=always delete the entry)
 * this is required for backwards compatibility
 * with older versions of glib which do not have
 * a g_hash_table_remove_all() (because of this,
 * hashtables are emptied using g_hash_table_foreach_remove()
 * in conjunction with this funcion)
 */
static gboolean free_table_entry(gpointer key _U_,
	gpointer value _U_, gpointer user_data _U_)
{
	return TRUE;
}

/* "Value destroy" function called each time an entry is removed
 *  from the sequence_table hash.
 * It frees the GList pointed to by the entry.
 */
static void free_sequence_table_entry_data(gpointer data)
{
	struct rlc_seqlist *list = data;
	if (list->list != NULL) {
		g_list_free(list->list);
		list->list = NULL;   /* for good measure */
	}
}

static void fragment_table_init(void)
{
	if (fragment_table) {
		g_hash_table_foreach_remove(fragment_table, free_table_entry, NULL);
		g_hash_table_destroy(fragment_table);
	}
	if (reassembled_table) {
		g_hash_table_foreach_remove(reassembled_table, free_table_entry, NULL);
		g_hash_table_destroy(reassembled_table);
	}
	if (sequence_table) {
		/* Note: "value destroy" function wil be called for each removed hash table entry */
		g_hash_table_foreach_remove(sequence_table, free_table_entry, NULL);
		g_hash_table_destroy(sequence_table);
	}
	fragment_table = g_hash_table_new_full(rlc_channel_hash, rlc_channel_equal,
		rlc_channel_delete, rlc_sdu_frags_delete);
	reassembled_table = g_hash_table_new_full(rlc_frag_hash, rlc_frag_equal,
		rlc_frag_delete, rlc_sdu_frags_delete);
	sequence_table = g_hash_table_new_full(rlc_channel_hash, rlc_channel_equal, 
		NULL, free_sequence_table_entry_data);
}

/* add the list of fragments for this sdu to 'tree' */
static void tree_add_fragment_list(struct rlc_sdu *sdu, tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *frag_tree;
	guint16 offset;
	struct rlc_frag *sdufrag;
	ti = proto_tree_add_item(tree, hf_rlc_frags, tvb, 0, -1, ENC_BIG_ENDIAN);
	frag_tree = proto_item_add_subtree(ti, ett_rlc_fragments);
	proto_item_append_text(ti, " (%u bytes, %u fragments): ",
		sdu->len, sdu->fragcnt);
	sdufrag = sdu->frags;
	offset = 0;
	while (sdufrag) {
		proto_tree_add_uint_format(frag_tree, hf_rlc_frag, tvb, offset,
			sdufrag->len, sdufrag->frame_num, "Frame: %u, payload %u-%u (%u bytes) (Seq: %u)",
			sdufrag->frame_num, offset, offset + sdufrag->len - 1, sdufrag->len, sdufrag->seq);
		offset += sdufrag->len;
		sdufrag = sdufrag->next;
	}
}

/* add the list of fragments for this sdu to 'tree' */
static void tree_add_fragment_list_incomplete(struct rlc_sdu *sdu, tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *frag_tree;
	guint16 offset;
	struct rlc_frag *sdufrag;
	ti = proto_tree_add_item(tree, hf_rlc_frags, tvb, 0, 0, ENC_BIG_ENDIAN);
	frag_tree = proto_item_add_subtree(ti, ett_rlc_fragments);
	proto_item_append_text(ti, " (%u bytes, %u fragments): ",
		sdu->len, sdu->fragcnt);
	sdufrag = sdu->frags;
	offset = 0;
	while (sdufrag) {
		proto_tree_add_uint_format(frag_tree, hf_rlc_frag, tvb, 0,
			0, sdufrag->frame_num, "Frame: %u, payload %u-%u (%u bytes) (Seq: %u)",
			sdufrag->frame_num, offset, offset + sdufrag->len - 1, sdufrag->len, sdufrag->seq);
		offset += sdufrag->len;
		sdufrag = sdufrag->next;
	}
}

/* add information for an LI to 'tree' */
static proto_tree *tree_add_li(enum rlc_mode mode, struct rlc_li *li, guint8 li_idx, guint8 hdr_offs,
                               gboolean li_is_on_2_bytes, tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *li_tree;
	guint8 li_offs;
	
	if (!tree) return NULL;

	if (li_is_on_2_bytes) {
		li_offs = hdr_offs + li_idx*2;
		ti = proto_tree_add_item(tree, hf_rlc_li, tvb, li_offs, 2, ENC_BIG_ENDIAN);
		li_tree = proto_item_add_subtree(ti, ett_rlc_frag);
		ti = proto_tree_add_bits_item(li_tree, hf_rlc_li_value, tvb, li_offs*8, 15, ENC_BIG_ENDIAN);
		switch (li->li) {
			case 0x0000:
				proto_item_append_text(ti, " (The previous RLC PDU was exactly filled with the last segment of an RLC SDU and there is no LI that indicates the end of the RLC SDU in the previous RLC PDU)");
				break;
			case 0x7ffa:
				if (mode == RLC_UM) {
					proto_item_append_text(ti, " (The first data octet in this RLC PDU is the first octet of an RLC SDU and the second last octet in this RLC PDU is the last octet of the same RLC SDU. The remaining octet in the RLC PDU is ignored)");
				} else {
					proto_item_append_text(ti, " (Reserved)");
				}
				break;
			case 0x7ffb:
				proto_item_append_text(ti, " (The second last octet in the previous RLC PDU is the last octet of an RLC SDU and there is no LI to indicate the end of SDU. The remaining octet in the previous RLC PDU is ignored)");
				break;
			case 0x7ffc:
				if (mode == RLC_UM) {
					proto_item_append_text(ti, " (The first data octet in this RLC PDU is the first octet of an RLC SDU)");
				} else {
					proto_item_append_text(ti, " (Reserved)");
				}
				break;
			case 0x7ffd:
				if (mode == RLC_UM) {
					proto_item_append_text(ti, " (The first data octet in this RLC PDU is the first octet of an RLC SDU and the last octet in this RLC PDU is the last octet of the same RLC SDU)");
				} else {
					proto_item_append_text(ti, " (Reserved)");
				}
				break;
			case 0x7ffe:
				if (mode == RLC_UM) {
					proto_item_append_text(ti, " (The RLC PDU contains a segment of an SDU but neither the first octet nor the last octet of this SDU)");
				} else {
					proto_item_append_text(ti, " (The rest of the RLC PDU includes a piggybacked STATUS PDU)");
				}
				break;
			case 0x7fff:
				proto_item_append_text(ti, " (The rest of the RLC PDU is padding)");
				break;
			default:
				break;
		}
		proto_tree_add_bits_item(li_tree, hf_rlc_li_ext, tvb, li_offs*8+15, 1, ENC_BIG_ENDIAN);
	} else {
		li_offs = hdr_offs + li_idx;
		ti = proto_tree_add_item(tree, hf_rlc_li, tvb, li_offs, 1, ENC_BIG_ENDIAN);
		li_tree = proto_item_add_subtree(ti, ett_rlc_frag);
		ti = proto_tree_add_bits_item(li_tree, hf_rlc_li_value, tvb, li_offs*8, 7, ENC_BIG_ENDIAN);
		switch (li->li) {
			case 0x00:
				proto_item_append_text(ti, " (The previous RLC PDU was exactly filled with the last segment of an RLC SDU and there is no LI that indicates the end of the RLC SDU in the previous RLC PDU)");
				break;
			case 0x7c:
				if (mode == RLC_UM) {
					proto_item_append_text(ti, " (The first data octet in this RLC PDU is the first octet of an RLC SDU)");
				} else {
					proto_item_append_text(ti, " (Reserved)");
				}
				break;
			case 0x7d:
				if (mode == RLC_UM) {
					proto_item_append_text(ti, " (The first data octet in this RLC PDU is the first octet of an RLC SDU and the last octet in this RLC PDU is the last octet of the same RLC SDU)");
				} else {
					proto_item_append_text(ti, " (Reserved)");
				}
				break;
			case 0x7e:
				if (mode == RLC_UM) {
					proto_item_append_text(ti, " (The RLC PDU contains a segment of an SDU but neither the first octet nor the last octet of this SDU)");
				} else {
					proto_item_append_text(ti, " (The rest of the RLC PDU includes a piggybacked STATUS PDU)");
				}
				break;
			case 0x7f:
				proto_item_append_text(ti, " (The rest of the RLC PDU is padding)");
				break;
			default:
				break;
		}
		proto_tree_add_bits_item(li_tree, hf_rlc_li_ext, tvb, li_offs*8+7, 1, ENC_BIG_ENDIAN);
	}

	if (li->len > 0) {
		if (li->li > tvb_length_remaining(tvb, hdr_offs)) return li_tree;
		if (li->len > li->li) return li_tree; 
		ti = proto_tree_add_item(li_tree, hf_rlc_li_data, tvb, hdr_offs + li->li - li->len, li->len, ENC_BIG_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(ti);
	}

	return li_tree;
}

/* add a fragment to an SDU */
static int rlc_sdu_add_fragment(enum rlc_mode mode, struct rlc_sdu *sdu,
	struct rlc_frag *frag)
{
	struct rlc_frag *tmp;

	if (!sdu->frags) {
		/* insert as first element */
		sdu->frags = frag;
		sdu->last = frag;
		sdu->fragcnt++;
		sdu->len += frag->len;
		return 0;
	}
	switch (mode) {
		case RLC_UM:
			/* insert as last element */
			sdu->last->next = frag;
			frag->next = NULL;
			sdu->last = frag;
			sdu->len += frag->len;
			break;
		case RLC_AM:
			/* insert ordered */
			tmp = sdu->frags;
			if (frag->seq < tmp->seq) {
				/* insert as first element */
				frag->next = tmp;
				sdu->frags = frag;
			} else {
				while (tmp->next && tmp->next->seq < frag->seq)
					tmp = tmp->next;
				frag->next = tmp->next;
				tmp->next = frag;
				if (frag->next == NULL) sdu->last = frag;
			}
			sdu->len += frag->len;
			break;
		default:
			return -2;
	}
	sdu->fragcnt++;
	return 0;
}

static void reassemble_message(struct rlc_channel *ch, struct rlc_sdu *sdu, struct rlc_frag *frag)
{
	struct rlc_frag *temp;
	guint16 offs = 0;

	if (!sdu || !ch || !sdu->frags) return;

	if (sdu->data) return; /* already assembled */

	if (frag)
		sdu->reassembled_in = frag;
	else
		sdu->reassembled_in = sdu->last;

	sdu->data = se_alloc(sdu->len);

	temp = sdu->frags;
	while (temp) {
		memcpy(sdu->data + offs, temp->data, temp->len);
		/* mark this fragment in reassembled table */
		g_hash_table_insert(reassembled_table, temp, sdu);

		offs += temp->len;
		temp = temp->next;
	}
	g_hash_table_remove(fragment_table, ch);
}

/* add a new fragment to an SDU
 * if length == 0, just finalize the specified SDU
 */
static struct rlc_frag *add_fragment(enum rlc_mode mode, tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, guint16 offset, guint16 seq, guint16 num_li, guint16 len, gboolean final)
{
	struct rlc_channel ch_lookup;
	struct rlc_frag frag_lookup, *frag = NULL, *tmp;
	gpointer orig_frag, orig_sdu;
	struct rlc_sdu *sdu;

	rlc_channel_assign(&ch_lookup, mode, pinfo);
	rlc_frag_assign(&frag_lookup, mode, pinfo, seq, num_li);

	/* look for an already assembled SDU */
	if (g_hash_table_lookup_extended(reassembled_table, &frag_lookup,
	    &orig_frag, &orig_sdu)) {
		/* this fragment is already reassembled somewhere */
		frag = orig_frag;
		sdu = orig_sdu;
		if (tree) {
			/* mark the fragment, if reassembly happened somewhere else */
			if (frag->seq != sdu->reassembled_in->seq ||
				frag->li != sdu->reassembled_in->li)
				proto_tree_add_uint(tree, hf_rlc_reassembled_in, tvb, 0, 0,
					sdu->reassembled_in->frame_num);
		}
		return frag;
	}

	/* if not already reassembled, search for a fragment entry */
	sdu = g_hash_table_lookup(fragment_table, &ch_lookup);

	if (final && len == 0) {
		/* just finish this SDU */
		if (sdu) {
			frag = rlc_frag_create(tvb, mode, pinfo, offset, len, seq, num_li);
			rlc_sdu_add_fragment(mode, sdu, frag);
			reassemble_message(&ch_lookup, sdu, frag);
		}
		return NULL;
	}
	/* create the SDU entry, if it does not already exist */
	if (!sdu) {
		/* this the first observed fragment of an SDU */
		struct rlc_channel *ch;
		ch = rlc_channel_create(mode, pinfo);
		sdu = rlc_sdu_create();
		g_hash_table_insert(fragment_table, ch, sdu);
	}

	/* check whether we have seen this fragment already */
	tmp = sdu->frags;
	while (tmp) {
		if (rlc_frag_equal(&frag_lookup, tmp) == TRUE)
			return tmp;
		tmp = tmp->next;
	}
	frag = rlc_frag_create(tvb, mode, pinfo, offset, len, seq, num_li);
	rlc_sdu_add_fragment(mode, sdu, frag);
	if (final) {
		reassemble_message(&ch_lookup, sdu, frag);
	}
	return frag;
}

/* is_data is used to identify rlc data parts that are not identified by an LI, but are at the end of
 * the RLC frame
 * these can be valid reassembly points, but only if the LI of the *next* relevant RLC frame is
 * set to '0' (this is indicated in the reassembled SDU
 */
static tvbuff_t *get_reassembled_data(enum rlc_mode mode, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	guint16 seq, guint16 num_li)
{
	gpointer orig_frag, orig_sdu;
	struct rlc_sdu *sdu;
	struct rlc_frag lookup, *frag;

	rlc_frag_assign(&lookup, mode, pinfo, seq, num_li);

	if (!g_hash_table_lookup_extended(reassembled_table, &lookup,
	    &orig_frag, &orig_sdu))
		return NULL;

	frag = orig_frag;
	sdu = orig_sdu;
	if (!sdu || !sdu->data)
		return NULL;

	/* TODO */
#if 0
	if (!rlc_frag_equal(&lookup, sdu->reassembled_in)) return NULL;
#endif

	if (tree) {
		frag = sdu->frags;
		while (frag->next) {
			if (frag->next->seq - frag->seq > 1) {
				proto_item *pi = proto_tree_add_text(tree, tvb, 0, 0,
					"Error: Incomplete sequence");
				PROTO_ITEM_SET_GENERATED(pi);
				tree_add_fragment_list_incomplete(sdu, tvb, tree);
				return NULL;
			}
			frag = frag->next;
		}
	}
	sdu->tvb = tvb_new_real_data(sdu->data, sdu->len, sdu->len);
	tvb_set_child_real_data_tvbuff(tvb, sdu->tvb);
	add_new_data_source(pinfo, sdu->tvb, "Reassembled RLC Message");

	/* reassembly happened here, so create the fragment list */
	if (tree)
		tree_add_fragment_list(sdu, sdu->tvb, tree);

	return sdu->tvb;
}

#define RLC_RETRANSMISSION_TIMEOUT 5 /* in seconds */
static gboolean rlc_is_duplicate(enum rlc_mode mode, packet_info *pinfo, guint16 seq, guint32 *original)
{
	GList *element;
	struct rlc_seqlist lookup, *list;
	struct rlc_seq seq_item, *seq_new;

	rlc_channel_assign(&lookup.ch, mode, pinfo);
	list = g_hash_table_lookup(sequence_table, &lookup.ch);
	if (!list) {
		/* we see this channel for the first time */
		list = se_alloc0(sizeof(*list));
		rlc_channel_assign(&list->ch, mode, pinfo);
		g_hash_table_insert(sequence_table, &list->ch, list);
	}
	seq_item.seq = seq;
	seq_item.frame_num = pinfo->fd->num;

	element = g_list_find_custom(list->list, &seq_item, rlc_cmp_seq);
	if (element) {
		seq_new = element->data;
		if (seq_new->frame_num != seq_item.frame_num) {
			nstime_t delta;
			nstime_delta(&delta, &pinfo->fd->abs_ts, &seq_new->arrival);
			if (delta.secs < RLC_RETRANSMISSION_TIMEOUT) {
				if (original)
					*original = seq_new->frame_num;
				return TRUE;
			}
			return FALSE;
		}
		return FALSE; /* we revisit the seq that was already seen */
	}
	seq_new = se_alloc0(sizeof(struct rlc_seq));
	*seq_new = seq_item;
	seq_new->arrival = pinfo->fd->abs_ts;
	list->list = g_list_insert_sorted(list->list, seq_new, rlc_cmp_seq);
	return FALSE;
}

static void rlc_call_subdissector(enum channel_type channel, tvbuff_t *tvb,
	packet_info *pinfo,	proto_tree *tree)
{
	enum rrc_message_type msgtype; 

	switch (channel) {
		case UL_CCCH:
			msgtype = RRC_MESSAGE_TYPE_UL_CCCH;
			break;
		case DL_CCCH:
			msgtype = RRC_MESSAGE_TYPE_DL_CCCH;
			break;
		case DL_CTCH:
			msgtype = RRC_MESSAGE_TYPE_INVALID;
			call_dissector(bmc_handle, tvb, pinfo, tree);
			break;
		case UL_DCCH:
			msgtype = RRC_MESSAGE_TYPE_UL_DCCH;
			break;
		case DL_DCCH:
			msgtype = RRC_MESSAGE_TYPE_DL_DCCH;
			break;
		case PCCH:
			msgtype = RRC_MESSAGE_TYPE_PCCH;
			break;
		case PS_DTCH:
			msgtype = RRC_MESSAGE_TYPE_INVALID;
			/* assume transparent PDCP for now */
			call_dissector(ip_handle, tvb, pinfo, tree);
			break;
		default:
			return; /* abort */
	}
	if (msgtype != RRC_MESSAGE_TYPE_INVALID) {
		struct rrc_info *rrcinf;
		fp_info *fpinf;
		fpinf = p_get_proto_data(pinfo->fd, proto_fp);
		rrcinf = p_get_proto_data(pinfo->fd, proto_rrc);
		if (!rrcinf) {
			rrcinf = se_alloc0(sizeof(struct rrc_info));
			p_add_proto_data(pinfo->fd, proto_rrc, rrcinf);
		}
		rrcinf->msgtype[fpinf->cur_tb] = msgtype;
		call_dissector(rrc_handle, tvb, pinfo, tree);
		/* once the packet has been dissected, protect it from further changes */
		col_set_writable(pinfo->cinfo, FALSE);
	}
}

static void dissect_rlc_tm(enum channel_type channel, tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *top_level, proto_tree *tree)
{
	if (tree) {
		proto_tree_add_item(tree, hf_rlc_data, tvb, 0, -1, ENC_BIG_ENDIAN);
	}
	rlc_call_subdissector(channel, tvb, pinfo, top_level);
}


static void rlc_um_reassemble(tvbuff_t *tvb, guint8 offs, packet_info *pinfo, proto_tree *tree,
                              proto_tree *top_level, enum channel_type channel, guint16 seq,
                              struct rlc_li *li, guint16 num_li, gboolean li_is_on_2_bytes)
{
	guint8 i;
	gboolean dissected = FALSE;
	gint length;
	tvbuff_t *next_tvb = NULL;
	/* perform reassembly now */
	for (i = 0; i < num_li; i++) {
		if ((!li_is_on_2_bytes && (li[i].li == 0x7f)) || (li[i].li == 0x7fff)) {
			/* padding, must be last LI */
			if (tree) {
				proto_tree_add_item(tree, hf_rlc_pad, tvb, offs, -1, ENC_BIG_ENDIAN);
			}
			offs += tvb_length_remaining(tvb, offs);
		} else if ((!li_is_on_2_bytes && (li[i].li == 0x7c)) || (li[i].li == 0x7ffc)) {
			/* a new SDU starts here, nothing to do */
		} else if (li[i].li == 0x7ffa) {
			/* the first data octet in this RLC PDU is the first octet of an RLC SDU
			   and the second last octet in this RLC PDU is the last octet of the same RLC SDU */
			length = tvb_length_remaining(tvb, offs);
			if (length > 1) {
				length--;
				if (tree && length) {
					proto_tree_add_item(tree, hf_rlc_data, tvb, offs, length, ENC_BIG_ENDIAN);
				}
				if (global_rlc_perform_reassemby) {
					add_fragment(RLC_UM, tvb, pinfo, li[i].tree, offs, seq, i, length, TRUE);
					next_tvb = get_reassembled_data(RLC_UM, tvb, pinfo, li[i].tree, seq, i);
				}
				offs += length;
			}
			if (tree) {
				proto_tree_add_item(tree, hf_rlc_pad, tvb, offs, 1, ENC_BIG_ENDIAN);
			}
			offs += 1;
		} else {
			if (tree && li[i].len) {
				proto_tree_add_item(tree, hf_rlc_data, tvb, offs, li[i].len, ENC_BIG_ENDIAN);
			}
			if (global_rlc_perform_reassemby) {
				add_fragment(RLC_UM, tvb, pinfo, li[i].tree, offs, seq, i, li[i].len, TRUE);
				next_tvb = get_reassembled_data(RLC_UM, tvb, pinfo, li[i].tree, seq, i);
			}
		}
		if (next_tvb) {
			dissected = TRUE;
			rlc_call_subdissector(channel, next_tvb, pinfo, top_level);
			next_tvb = NULL;
		} 
		offs += li[i].len;
	}

	/* is there data left? */
	if (tvb_length_remaining(tvb, offs) > 0) {
		if (tree) {
			proto_tree_add_item(tree, hf_rlc_data, tvb, offs, -1, ENC_BIG_ENDIAN);
		}
		if (global_rlc_perform_reassemby) {
			/* add remaining data as fragment */
			add_fragment(RLC_UM, tvb, pinfo, tree, offs, seq, i, tvb_length_remaining(tvb, offs), FALSE);
			if (dissected == FALSE)
				col_set_str(pinfo->cinfo, COL_INFO, "[RLC UM Fragment]");
		}
	}
}

static gint16 rlc_decode_li(enum rlc_mode mode, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	                        struct rlc_li *li, guint8 max_li, gboolean li_on_2_bytes)
{
	guint8 ext, hdr_len, offs = 0, num_li = 0, li_offs;
	guint16 next_bytes, prev_li = 0;
	proto_item *malformed;
	guint16 total_len;

	switch (mode) {
		case RLC_AM: offs = 1; break;
		case RLC_UM: offs = 0; break;
		case RLC_TM: return -1;
	}
	hdr_len = offs;
	/* calculate header length */
	ext = tvb_get_guint8(tvb, hdr_len++) & 0x01;
	while (ext) {
		next_bytes = li_on_2_bytes ? tvb_get_ntohs(tvb, hdr_len) : tvb_get_guint8(tvb, hdr_len);
		ext = next_bytes & 0x01;
		hdr_len += li_on_2_bytes ? 2 : 1;
	}
	total_len = tvb_length_remaining(tvb, hdr_len);
	
	/* do actual evaluation of LIs */
	ext = tvb_get_guint8(tvb, offs++) & 0x01;
	li_offs = offs;
	while (ext) {
		if (li_on_2_bytes) {
			next_bytes = tvb_get_ntohs(tvb, offs);
			offs += 2;
		} else {
			next_bytes = tvb_get_guint8(tvb, offs++);
		}
		ext = next_bytes & 0x01;
		li[num_li].ext = ext;
		li[num_li].li = next_bytes >> 1;

		if (li_on_2_bytes) {
			switch (li[num_li].li) {
				case 0x0000: /* previous segment was the last one */
				case 0x7ffb: /* previous PDU contains last segment of SDU (minus last byte) */
				case 0x7ffe: /* contains piggybacked STATUS in AM or segment in UM */
				case 0x7fff: /* padding */
					li[num_li].len = 0;
					break;
				case 0x7ffa: /* contains exactly one SDU (minus last byte), UM only */
				case 0x7ffc: /* start of a new SDU, UM only */
				case 0x7ffd: /* contains exactly one SDU, UM only */
					if (mode == RLC_UM) {
						/* valid for UM */
						li[num_li].len = 0;
						break;
					}
					/*invalid for AM */
					/* add malformed LI for investigation */
					tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
					malformed = proto_tree_add_protocol_format(tree,
						proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
					expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
						"Malformed Packet (Uses reserved LI)");
					col_append_str(pinfo->cinfo, COL_INFO, "[Malformed Packet]");
					return -1; /* just give up on this */
				default:
					/* since the LI is an offset (from the end of the header), it
					* may not be larger than the total remaining length and no
					* LI may be smaller than its preceding one
					*/
					if (((li[num_li].li > total_len) && !global_rlc_headers_expected)
						|| (li[num_li].li < prev_li)) {
						/* add malformed LI for investigation */
						tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
						malformed = proto_tree_add_protocol_format(tree,
							proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
						expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
							"Malformed Packet (incorrect LI value)");
						col_append_str(pinfo->cinfo, COL_INFO, "[Malformed Packet]");
						return -1; /* just give up on this */
					}
					li[num_li].len = li[num_li].li - prev_li;
					prev_li = li[num_li].li;
			}
		} else {
			switch (li[num_li].li) {
				case 0x00: /* previous segment was the last one */
				case 0x7e: /* contains piggybacked STATUS in AM or segment in UM */
				case 0x7f: /* padding */
					li[num_li].len = 0;
					break;
				case 0x7c: /* start of a new SDU, UM only */
				case 0x7d: /* contains exactly one SDU, UM only */
					if (mode == RLC_UM) {
						/* valid for UM */
						li[num_li].len = 0;
						break;
					}
					/*invalid for AM */
					/* add malformed LI for investigation */
					tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
					malformed = proto_tree_add_protocol_format(tree,
						proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
					expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
						"Malformed Packet (Uses reserved LI)");
					col_append_str(pinfo->cinfo, COL_INFO, "[Malformed Packet]");
					return -1; /* just give up on this */
				default:
					/* since the LI is an offset (from the end of the header), it
					* may not be larger than the total remaining length and no
					* LI may be smaller than its preceding one
					*/
					if (((li[num_li].li > total_len) && !global_rlc_headers_expected)
						|| (li[num_li].li < prev_li)) {
						/* add malformed LI for investigation */
						tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
						malformed = proto_tree_add_protocol_format(tree,
							proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
						expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
							"Malformed Packet (incorrect LI value)");
						col_append_str(pinfo->cinfo, COL_INFO, "[Malformed Packet]");
						return -1; /* just give up on this */
					}
					li[num_li].len = li[num_li].li - prev_li;
					prev_li = li[num_li].li;
			}
		}
		li[num_li].tree = tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
		num_li++;

		if (num_li > max_li) {
			/* OK, so this is not really a malformed packet, but for now,
 			* we will treat it as such, so that it is marked in some way */
			malformed = proto_tree_add_protocol_format(tree,
				proto_malformed, tvb, 0, 0, "[Dissector Problem: %s]", pinfo->current_proto);
			expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
				"Too many LI entries");
			return -1;
		}
	}
	return num_li;
}

static void dissect_rlc_um(enum channel_type channel, tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *top_level, proto_tree *tree)
{
#define MAX_LI 16
	struct rlc_li li[MAX_LI];
	fp_info *fpinf;
	rlc_info *rlcinf;
	guint32 orig_num;
	guint8 seq;
	guint8 next_byte, offs = 0;
	gint16 pos, num_li = 0;
	gboolean is_truncated, li_is_on_2_bytes;
	proto_item *truncated_ti;

	next_byte = tvb_get_guint8(tvb, offs++);
	seq = next_byte >> 1;

	/* show sequence number and extension bit */
	if (tree) {
		proto_tree_add_bits_item(tree, hf_rlc_seq, tvb, 0, 7, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(tree, hf_rlc_ext, tvb, 7, 1, ENC_BIG_ENDIAN);
	}

	fpinf = p_get_proto_data(pinfo->fd, proto_fp);
	rlcinf = p_get_proto_data(pinfo->fd, proto_rlc);
	if (!fpinf || !rlcinf) {
		proto_tree_add_text(tree, tvb, 0, -1,
			"Cannot dissect RLC frame because per-frame info is missing");
		return;
	}
	pos = fpinf->cur_tb;
	if (rlcinf->ciphered[pos] == TRUE && rlcinf->deciphered[pos] == FALSE) {
		proto_tree_add_text(tree, tvb, 0, -1,
			"Cannot dissect RLC frame because it is ciphered");
		return;
	}

	if (rlcinf->li_size[pos] == RLC_LI_VARIABLE) {
		li_is_on_2_bytes = (tvb_length(tvb) > 125) ? TRUE : FALSE;
	} else {
		li_is_on_2_bytes = (rlcinf->li_size[pos] == RLC_LI_15BITS) ? TRUE : FALSE;
	}

	num_li = rlc_decode_li(RLC_UM, tvb, pinfo, tree, li, MAX_LI, li_is_on_2_bytes);
	if (num_li == -1) return; /* something went wrong */
	offs += ((li_is_on_2_bytes) ? 2 : 1) * num_li;

	if (global_rlc_headers_expected) {
		/* There might not be any data, if only headerwas logged */
		is_truncated = (tvb_length_remaining(tvb, offs) == 0);
		truncated_ti = proto_tree_add_boolean(tree, hf_rlc_header_only, tvb, 0, 0,
		                                      is_truncated);
		if (is_truncated) {
			PROTO_ITEM_SET_GENERATED(truncated_ti);
			expert_add_info_format(pinfo, truncated_ti, PI_SEQUENCE, PI_NOTE,
			                       "RLC PDU SDUs have been omitted");
			return;
		} else {
			PROTO_ITEM_SET_HIDDEN(truncated_ti);
		}
	}

	/* do not detect duplicates or reassemble, if prefiltering is done */
	if (pinfo->fd->num == 0) return;
	/* check for duplicates */
	if (rlc_is_duplicate(RLC_UM, pinfo, seq, &orig_num) == TRUE) {
		col_set_str(pinfo->cinfo, COL_INFO, "[RLC UM Fragment] [Duplicate]");
		proto_tree_add_uint(tree, hf_rlc_duplicate_of, tvb, 0, 0, orig_num);
		return;
	}
	rlc_um_reassemble(tvb, offs, pinfo, tree, top_level, channel, seq, li, num_li, li_is_on_2_bytes);
}

static void dissect_rlc_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint8 offset)
{
	guint8 sufi_type, bits;
	guint64 len, sn, l;
	guint16 value, previous_sn;
	gboolean isErrorBurstInd;
	gint bit_offset, previous_bit_offset;
	guint i, j;
	proto_tree *sufi_tree, *bitmap_tree, *rlist_tree;
	proto_item *sufi_item, *malformed, *ti;
	#define BUFF_SIZE 40
	gchar *buff = NULL;
	guint8 cw[15];

	bit_offset = offset*8 + 4; /* first SUFI type is always 4 bit shifted */

	while (tvb_length_remaining(tvb, bit_offset/8) > 0) {
		sufi_type = tvb_get_bits8(tvb, bit_offset, 4);
		sufi_item = proto_tree_add_item(tree, hf_rlc_sufi, tvb, 0, 0, ENC_BIG_ENDIAN);
		sufi_tree = proto_item_add_subtree(sufi_item, ett_rlc_sufi);
		proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
		bit_offset += 4;
		switch (sufi_type) {
			case RLC_SUFI_NOMORE:
				return; /* must be last SUFI */
			case RLC_SUFI_ACK:
				proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_lsn, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
				return; /* must be last SUFI */
			case RLC_SUFI_WINDOW:
				proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_wsn, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
				bit_offset += 12;
				break;
			case RLC_SUFI_LIST:
				proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_len, tvb, bit_offset, 4, &len, ENC_BIG_ENDIAN);
				bit_offset += 4;
				if (len) {
					while (len) {
						ti = proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_sn, tvb, bit_offset, 12, &sn, ENC_BIG_ENDIAN);
						proto_item_append_text(ti, " (AMD PDU not correctly received)");
						bit_offset += 12;
						ti = proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_l, tvb, bit_offset, 4, &l, ENC_BIG_ENDIAN);
						if (l) {
							proto_item_append_text(ti, " (all consecutive AMD PDUs up to SN %u not correctly received)", (unsigned)(sn+l)&0xfff);
						}
						bit_offset += 4;
						len--;
					}
				} else {
					malformed = proto_tree_add_protocol_format(tree,
						proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
					expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
						"Malformed Packet (invalid length)");
					col_append_str(pinfo->cinfo, COL_INFO, " [Malformed Packet]");
				}
				break;
			case RLC_SUFI_BITMAP:
				proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_len, tvb, bit_offset, 4, &len, ENC_BIG_ENDIAN);
				bit_offset += 4;
				len++; /* bitmap is len + 1 */
				proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_fsn, tvb, bit_offset, 12, &sn, ENC_BIG_ENDIAN);
				bit_offset += 12;
				proto_tree_add_item(sufi_tree, hf_rlc_sufi_bitmap, tvb, bit_offset/8, (gint)len, ENC_BIG_ENDIAN);
				ti = proto_tree_add_text(sufi_tree, tvb, bit_offset/8, (gint)len, "Decoded bitmap:");
				bitmap_tree = proto_item_add_subtree(ti, ett_rlc_bitmap);
				buff = ep_alloc(BUFF_SIZE);
				for (i=0; i<len; i++) {
					bits = tvb_get_bits8(tvb, bit_offset, 8);
					for (l=0, j=0; l<8; l++) {
						if ((bits << l) & 0x80) {
							j += g_snprintf(&buff[j], BUFF_SIZE, "%04u,", (unsigned)(sn+(8*i)+l)&0xfff);
						} else {
							j += g_snprintf(&buff[j], BUFF_SIZE, "    ,");
						}
					}
					proto_tree_add_text(bitmap_tree, tvb, bit_offset/8, 1, "%s", buff);
					bit_offset += 8;
				}
				break;
			case RLC_SUFI_RLIST:
				previous_bit_offset = bit_offset;
				proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_len, tvb, bit_offset, 4, &len, ENC_BIG_ENDIAN);
				bit_offset += 4;
				proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_fsn, tvb, bit_offset, 12, &sn, ENC_BIG_ENDIAN);
				bit_offset += 12;
				for (i=0; i<len; i++) {
					ti = proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_cw, tvb, bit_offset, 4, &l, ENC_BIG_ENDIAN);
					if (l == 0x01) {
						proto_item_append_text(ti, " (Error burst indication)");
					}
					bit_offset += 4;
					cw[i] = (guint8)l;
				}
				if (len && (((cw[len-1] & 0x01) == 0) || (cw[len-1] == 0x01))) {
					malformed = proto_tree_add_protocol_format(tree,
						proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
					expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
						"Malformed Packet (invalid last codeword)");
					col_append_str(pinfo->cinfo, COL_INFO, " [Malformed Packet]");
				} else {
					ti = proto_tree_add_text(sufi_tree, tvb, previous_bit_offset/8, (bit_offset-previous_bit_offset)/8, "Decoded list:");
					rlist_tree = proto_item_add_subtree(ti, ett_rlc_rlist);
					proto_tree_add_text(rlist_tree, tvb, (previous_bit_offset+4)/8, 12/8, "Sequence Number = %u (AMD PDU not correctly received)",(unsigned)sn);
					for (i=0, isErrorBurstInd=FALSE, j=0, previous_sn=(guint16)sn, value=0; i<len; i++) {
						if (cw[i] == 0x01) {
							isErrorBurstInd = TRUE;
						} else {
							value |= (cw[i] >> 1) << j;
							j += 3;
							if (cw[i] & 0x01) {
								if (isErrorBurstInd) {
									previous_sn = (previous_sn + value) & 0xfff;
									ti = proto_tree_add_text(rlist_tree, tvb, (previous_bit_offset+16+4*i)/8, 1, "Length: %u", value);
									if (value) {
										proto_item_append_text(ti, "  (all consecutive AMD PDUs up to SN %u not correctly received)", previous_sn);
									}
									isErrorBurstInd = FALSE;
								} else {
									value = (value + previous_sn) & 0xfff;
									proto_tree_add_text(rlist_tree, tvb, (previous_bit_offset+16+4*i)/8, 1, "Sequence Number = %u (AMD PDU not correctly received)",value);
									previous_sn = value;
								}
								value = j = 0;
							}
						}
					}
				}
				break;
			case RLC_SUFI_MRW_ACK:
				proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_n, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
				bit_offset += 4;
				proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_sn_ack, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
				bit_offset += 12;
				break;
			case RLC_SUFI_MRW:
				proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_len, tvb, bit_offset, 4, &len, ENC_BIG_ENDIAN);
				bit_offset += 4;
				if (len) {
					while (len) {
						proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_sn_mrw, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
						bit_offset += 12;
						len--;
					}
				} else {
					/* only one SN_MRW field is present */
					ti = proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_sn_mrw, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
					proto_item_append_text(ti, " (RLC SDU to be discarded in the Receiver extends above the configured transmission window in the Sender)");
					bit_offset += 12;
				}
				proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_n, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
				bit_offset += 4;
				break;
			case RLC_SUFI_POLL:
				proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_poll_sn, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
				bit_offset += 12;
				break;
			default:
				malformed = proto_tree_add_protocol_format(tree,
					proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
				expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
					"Malformed Packet (invalid SUFI type)");
				col_append_str(pinfo->cinfo, COL_INFO, " [Malformed Packet]");
				return; /* invalid value, ignore the rest */
		}
	}
}

static void dissect_rlc_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 type, next_byte;
	proto_item *malformed;
	guint64 r1;

	next_byte = tvb_get_guint8(tvb, 0);
	type = (next_byte >> 4) & 0x07;

	proto_tree_add_bits_item(tree, hf_rlc_ctrl_type, tvb, 1, 3, ENC_BIG_ENDIAN);
	switch (type) {
		case RLC_STATUS:
			dissect_rlc_status(tvb, pinfo, tree, 0);
			break;
		case RLC_RESET:
		case RLC_RESET_ACK:
			proto_tree_add_bits_item(tree, hf_rlc_rsn, tvb, 4, 1, ENC_BIG_ENDIAN);
			proto_tree_add_bits_ret_val(tree, hf_rlc_r1, tvb, 5, 3, &r1, ENC_BIG_ENDIAN);
			if (r1) {
				proto_item *malformed;
				malformed = proto_tree_add_protocol_format(tree,
				proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
				expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
					"Malformed Packet (reserved bits not zero)");
				col_append_str(pinfo->cinfo, COL_INFO, "[Malformed Packet]");
				return;
			}
			proto_tree_add_bits_item(tree, hf_rlc_hfni, tvb, 8, 20, ENC_BIG_ENDIAN);
			break;
		default:
			malformed = proto_tree_add_protocol_format(tree,
				proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
			expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
				"Malformed Packet (invalid RLC AM control type %u)", type);
			col_append_str(pinfo->cinfo, COL_INFO, " [Malformed Packet]");
			return; /* invalid */
	}
}

static void rlc_am_reassemble(tvbuff_t *tvb, guint8 offs, packet_info *pinfo, proto_tree *tree,
	proto_tree *top_level, enum channel_type channel, guint16 seq, struct rlc_li *li, guint16 num_li,
	gboolean final, gboolean li_is_on_2_bytes)
{
	guint8 i;
	gboolean piggyback = FALSE, dissected = FALSE;
	tvbuff_t *next_tvb = NULL;
	/* perform reassembly now */
	for (i = 0; i < num_li; i++) {
		if ((!li_is_on_2_bytes && (li[i].li == 0x7e)) || (li[i].li == 0x7ffe)) {
			/* piggybacked status */
			piggyback = TRUE;
		} else if ((!li_is_on_2_bytes && (li[i].li == 0x7f)) || (li[i].li == 0x7fff)) {
			/* padding, must be last LI */
			if (tree && tvb_length_remaining(tvb, offs) > 0) {
				proto_tree_add_item(tree, hf_rlc_pad, tvb, offs, -1, ENC_BIG_ENDIAN);
			}
			offs += tvb_length_remaining(tvb, offs);
		} else {
			if (tree && li[i].len) {
				proto_tree_add_item(tree, hf_rlc_data, tvb, offs, li[i].len, ENC_BIG_ENDIAN);
			}
			if (global_rlc_perform_reassemby) {
				add_fragment(RLC_AM, tvb, pinfo, li[i].tree, offs, seq, i, li[i].len, TRUE);
				next_tvb = get_reassembled_data(RLC_AM, tvb, pinfo, li[i].tree, seq, i);
			}
		}
		if (next_tvb) {
			dissected = TRUE;
			rlc_call_subdissector(channel, next_tvb, pinfo, top_level);
			next_tvb = NULL;
		}
		offs += li[i].len;
	}

	if (piggyback) {
		dissect_rlc_status(tvb, pinfo, tree, offs);
	} else {
		if (tvb_length_remaining(tvb, offs) > 0) {
			/* we have remaining data, which we need to mark in the tree */
			if (tree) {
				proto_tree_add_item(tree, hf_rlc_data, tvb, offs, -1, ENC_BIG_ENDIAN);
			}
			if (global_rlc_perform_reassemby) {
				add_fragment(RLC_AM, tvb, pinfo, tree, offs, seq, i,
					tvb_length_remaining(tvb,offs), final);
				if (final) {
					next_tvb = get_reassembled_data(RLC_AM, tvb, pinfo, NULL, seq, i);
				}
			}
		}
		if (next_tvb) {
			dissected = TRUE;
			rlc_call_subdissector(channel, next_tvb, pinfo, top_level);
			next_tvb = NULL;
		}
	}
	if (dissected == FALSE)
		col_set_str(pinfo->cinfo, COL_INFO, "[RLC AM Fragment]");
}

static void dissect_rlc_am(enum channel_type channel, tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *top_level, proto_tree *tree)
{
#define MAX_LI 16
	struct rlc_li li[MAX_LI];
	fp_info *fpinf;
	rlc_info *rlcinf;
	guint8 ext, dc;
	guint8 next_byte, offs = 0;
	guint32 orig_num = 0;
	gint16 num_li = 0, seq, pos;
	gboolean is_truncated, li_is_on_2_bytes;
	proto_item *truncated_ti;

	next_byte = tvb_get_guint8(tvb, offs++);
	dc = next_byte >> 7;
	if (tree)
		proto_tree_add_bits_item(tree, hf_rlc_dc, tvb, 0, 1, ENC_BIG_ENDIAN);
	if (dc == 0) {
		col_set_str(pinfo->cinfo, COL_INFO, "RLC Control Frame");
		dissect_rlc_control(tvb, pinfo, tree);
		return;
	}

	seq = next_byte & 0x7f;
	seq <<= 5;
	next_byte = tvb_get_guint8(tvb, offs++);
	seq |= (next_byte >> 3);

	ext = next_byte & 0x03;
	/* show header fields */
	if (tree) {
		proto_tree_add_bits_item(tree, hf_rlc_seq, tvb, 1, 12, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(tree, hf_rlc_p, tvb, 13, 1, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(tree, hf_rlc_he, tvb, 14, 2, ENC_BIG_ENDIAN);
	}

	/* header extension may only be 00, 01 or 10 */
	if (ext > 2) {
		proto_item *malformed;
		malformed = proto_tree_add_protocol_format(tree,
			proto_malformed, tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
		expert_add_info_format(pinfo, malformed, PI_MALFORMED, PI_ERROR,
			"Malformed Packet (incorrect HE value)");
		col_append_str(pinfo->cinfo, COL_INFO, "[Malformed Packet]");
		return;
	}

	fpinf = p_get_proto_data(pinfo->fd, proto_fp);
	rlcinf = p_get_proto_data(pinfo->fd, proto_rlc);
	if (!fpinf || !rlcinf) {
		proto_tree_add_text(tree, tvb, 0, -1,
			"Cannot dissect RLC frame because per-frame info is missing");
		return;
	}
	pos = fpinf->cur_tb;
	if (rlcinf->ciphered[pos] == TRUE && rlcinf->deciphered[pos] == FALSE) {
		proto_tree_add_text(tree, tvb, 0, -1,
			"Cannot dissect RLC frame because it is ciphered");
		return;
	}

	if (rlcinf->li_size[pos] == RLC_LI_VARIABLE) {
		li_is_on_2_bytes = (tvb_length(tvb) > 126) ? TRUE : FALSE;
	} else {
		li_is_on_2_bytes = (rlcinf->li_size[pos] == RLC_LI_15BITS) ? TRUE : FALSE;
	}

	num_li = rlc_decode_li(RLC_AM, tvb, pinfo, tree, li, MAX_LI, li_is_on_2_bytes);
	if (num_li == -1) return; /* something went wrong */
	offs += ((li_is_on_2_bytes) ? 2 : 1) * num_li;

	if (global_rlc_headers_expected) {
		/* There might not be any data, if only header was logged */
		is_truncated = (tvb_length_remaining(tvb, offs) == 0);
		truncated_ti = proto_tree_add_boolean(tree, hf_rlc_header_only, tvb, 0, 0,
		                                      is_truncated);
		if (is_truncated) {
			PROTO_ITEM_SET_GENERATED(truncated_ti);
			expert_add_info_format(pinfo, truncated_ti, PI_SEQUENCE, PI_NOTE,
			                       "RLC PDU SDUs have been omitted");
			return;
		} else {
			PROTO_ITEM_SET_HIDDEN(truncated_ti);
		}
	}

	/* do not detect duplicates or reassemble, if prefiltering is done */
	if (pinfo->fd->num == 0) return;
	/* check for duplicates */
	if (rlc_is_duplicate(RLC_AM, pinfo, seq, &orig_num) == TRUE) {
		col_set_str(pinfo->cinfo, COL_INFO, "[RLC AM Fragment] [Duplicate]");
		proto_tree_add_uint(tree, hf_rlc_duplicate_of, tvb, 0, 0, orig_num);
		return;
	}
	rlc_am_reassemble(tvb, offs, pinfo, tree, top_level, channel, seq, li, num_li,
		ext == 2, li_is_on_2_bytes);
}

/* dissect entry functions */
static void dissect_rlc_pcch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *subtree = NULL;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
	col_clear(pinfo->cinfo, COL_INFO);

	/* PCCH is always RLC TM */
	if (tree) {
		proto_item *ti;
		ti = proto_tree_add_item(tree, proto_rlc, tvb, 0, -1, ENC_BIG_ENDIAN);
		subtree = proto_item_add_subtree(ti, ett_rlc);
		proto_item_append_text(ti, " TM (PCCH)");
	}
	dissect_rlc_tm(PCCH, tvb, pinfo, tree, subtree);
}

static void dissect_rlc_ccch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	fp_info *fpi;
	proto_item *ti = NULL;
	proto_tree *subtree = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
	col_clear(pinfo->cinfo, COL_INFO);

	fpi = p_get_proto_data(pinfo->fd, proto_fp);
	if (!fpi) return; /* dissection failure */

	if (tree) {
		ti = proto_tree_add_item(tree, proto_rlc, tvb, 0, -1, ENC_BIG_ENDIAN);
		subtree = proto_item_add_subtree(ti, ett_rlc);
	}

	if (fpi->is_uplink) {
		/* UL CCCH is always RLC TM */
		proto_item_append_text(ti, " TM (CCCH)");
		dissect_rlc_tm(UL_CCCH, tvb, pinfo, tree, subtree);
	} else {
		/* DL CCCH is always UM */
		proto_item_append_text(ti, " UM (CCCH)");
		dissect_rlc_um(DL_CCCH, tvb, pinfo, tree, subtree);
	}
}

static void dissect_rlc_ctch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    fp_info *fpi;
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
    col_clear(pinfo->cinfo, COL_INFO);

    fpi = p_get_proto_data(pinfo->fd, proto_fp);
    if (!fpi) return; /* dissection failure */

    if (tree) {
        ti = proto_tree_add_item(tree, proto_rlc, tvb, 0, -1, ENC_BIG_ENDIAN);
        subtree = proto_item_add_subtree(ti, ett_rlc);
    }

    /* CTCH is always UM */
    proto_item_append_text(ti, " UM (CTCH)");
    dissect_rlc_um(DL_CTCH, tvb, pinfo, tree, subtree);
}

static void dissect_rlc_dcch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti = NULL;
	proto_tree *subtree = NULL;
	fp_info *fpi;
	rlc_info *rlci;
	enum channel_type channel;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
	col_clear(pinfo->cinfo, COL_INFO);

	fpi = p_get_proto_data(pinfo->fd, proto_fp);
	rlci = p_get_proto_data(pinfo->fd, proto_rlc);

	if (!fpi || !rlci) return;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_rlc, tvb, 0, -1, ENC_BIG_ENDIAN);
		subtree = proto_item_add_subtree(ti, ett_rlc);
	}
	
	channel = fpi->is_uplink ? UL_DCCH : DL_DCCH;

	switch (rlci->mode[fpi->cur_tb]) {
		case RLC_UM:
			proto_item_append_text(ti, " UM (DCCH)");
			dissect_rlc_um(channel, tvb, pinfo, tree, subtree);
			break;
		case RLC_AM:
			proto_item_append_text(ti, " AM (DCCH)");
			dissect_rlc_am(channel, tvb, pinfo, tree, subtree);
			break;
	}
}

static void dissect_rlc_ps_dtch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti = NULL;
	proto_tree *subtree = NULL;
	fp_info *fpi;
	rlc_info *rlci;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
	col_clear(pinfo->cinfo, COL_INFO);

	fpi = p_get_proto_data(pinfo->fd, proto_fp);
	rlci = p_get_proto_data(pinfo->fd, proto_rlc);

	if (!fpi || !rlci) return;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_rlc, tvb, 0, -1, ENC_BIG_ENDIAN);
		subtree = proto_item_add_subtree(ti, ett_rlc);
	}
	
	switch (rlci->mode[fpi->cur_tb]) {
		case RLC_UM:
			proto_item_append_text(ti, " UM (PS DTCH)");
			dissect_rlc_um(PS_DTCH, tvb, pinfo, tree, subtree);
			break;
		case RLC_AM:
			proto_item_append_text(ti, " AM (PS DTCH)");
			dissect_rlc_am(PS_DTCH, tvb, pinfo, tree, subtree);
			break;
		case RLC_TM:
			proto_item_append_text(ti, " TM (PS DTCH)");
			dissect_rlc_tm(PS_DTCH, tvb, pinfo, tree, subtree);
			break;
	}
}

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static gboolean dissect_rlc_heur(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree)
{
	gint                 offset = 0;
	fp_info              *fpi;
	rlc_info             *rlci;
	tvbuff_t             *rlc_tvb;
	guint8               tag = 0;
	guint                channelType = CHANNEL_TYPE_UNSPECIFIED;
	gboolean             fpInfoAlreadySet = FALSE;
	gboolean             rlcInfoAlreadySet = FALSE;
	gboolean             channelTypePresent = FALSE;
	gboolean             rlcModePresent = FALSE;
	proto_item           *ti = NULL;
	proto_tree           *subtree = NULL;

	/* This is a heuristic dissector, which means we get all the UDP
	 * traffic not sent to a known dissector and not claimed by
	 * a heuristic dissector called before us!
	 */
	if (!global_rlc_heur) {
		return FALSE;
	}

	/* Do this again on re-dissection to re-discover offset of actual PDU */

	/* Needs to be at least as long as:
	   - the signature string
	   - conditional header bytes
	   - tag for data
	   - at least one byte of RLC PDU payload */
	if ((size_t)tvb_length_remaining(tvb, offset) < (strlen(RLC_START_STRING)+2+2)) {
		return FALSE;
	}

	/* OK, compare with signature string */
	if (tvb_strneql(tvb, offset, RLC_START_STRING, (gint)strlen(RLC_START_STRING)) != 0) {
		return FALSE;
	}
	offset += (gint)strlen(RLC_START_STRING);

	/* If redissecting, use previous info struct (if available) */
	fpi = p_get_proto_data(pinfo->fd, proto_fp);
	if (fpi == NULL) {
		/* Allocate new info struct for this frame */
		fpi = se_alloc0(sizeof(fp_info));
	} else {
		fpInfoAlreadySet = TRUE;
	}
	rlci = p_get_proto_data(pinfo->fd, proto_rlc);
	if (rlci == NULL) {
		/* Allocate new info struct for this frame */
		rlci = se_alloc0(sizeof(rlc_info));
	} else {
		rlcInfoAlreadySet = TRUE;
	}

	/* Read conditional/optional fields */
	while (tag != RLC_PAYLOAD_TAG) {
		/* Process next tag */
		tag = tvb_get_guint8(tvb, offset++);
		switch (tag) {
			case RLC_CHANNEL_TYPE_TAG:
				channelType = tvb_get_guint8(tvb, offset);
				offset++;
				channelTypePresent = TRUE;
				break;
			case RLC_MODE_TAG:
				rlci->mode[fpi->cur_tb] = tvb_get_guint8(tvb, offset);
				offset++;
				rlcModePresent = TRUE;
				break;
			case RLC_DIRECTION_TAG:
				fpi->is_uplink = (tvb_get_guint8(tvb, offset) == DIRECTION_UPLINK) ? TRUE : FALSE;
				offset++;
				break;
			case RLC_URNTI_TAG:
				rlci->urnti[fpi->cur_tb] = tvb_get_ntohl(tvb, offset);
				offset += 4;
				break;
			case RLC_RADIO_BEARER_ID_TAG:
				rlci->rbid[fpi->cur_tb] = tvb_get_guint8(tvb, offset);
				offset++;
				break;
			case RLC_LI_SIZE_TAG:
				rlci->li_size[fpi->cur_tb] = (enum rlc_li_size) tvb_get_guint8(tvb, offset);
				offset++;
				break;
			case RLC_PAYLOAD_TAG:
				/* Have reached data, so get out of loop */
				continue;
			default:
				/* It must be a recognised tag */
				return FALSE;
		}
	}

	if ((channelTypePresent == FALSE) && (rlcModePresent == FALSE)) {
		/* Conditional fields are missing */
		return FALSE;
	}

	/* Store info in packet if needed */
	if (!fpInfoAlreadySet) {
		p_add_proto_data(pinfo->fd, proto_fp, fpi);
	}
	if (!rlcInfoAlreadySet) {
		p_add_proto_data(pinfo->fd, proto_rlc, rlci);
	}

    /**************************************/
    /* OK, now dissect as RLC             */

    /* Create tvb that starts at actual RLC PDU */
    rlc_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
	switch (channelType) {
		case CHANNEL_TYPE_UNSPECIFIED:
			/* Call relevant dissector according to RLC mode */
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
			col_clear(pinfo->cinfo, COL_INFO);

			if (tree) {
				ti = proto_tree_add_item(tree, proto_rlc, rlc_tvb, 0, -1, ENC_BIG_ENDIAN);
				subtree = proto_item_add_subtree(ti, ett_rlc);
			}

			if (rlci->mode[fpi->cur_tb] == RLC_AM) {
				proto_item_append_text(ti, " AM");
				dissect_rlc_am(UNKNOWN, rlc_tvb, pinfo, tree, subtree);
			} else if (rlci->mode[fpi->cur_tb] == RLC_UM) {
				proto_item_append_text(ti, " UM");
				dissect_rlc_um(UNKNOWN, rlc_tvb, pinfo, tree, subtree);
			} else {
				proto_item_append_text(ti, " TM");
				dissect_rlc_tm(UNKNOWN, rlc_tvb, pinfo, tree, subtree);
			}
			break;
		case CHANNEL_TYPE_PCCH:
			dissect_rlc_pcch(rlc_tvb, pinfo, tree);
			break;
		case CHANNEL_TYPE_CCCH:
			dissect_rlc_ccch(rlc_tvb, pinfo, tree);
			break;
		case CHANNEL_TYPE_DCCH:
			dissect_rlc_dcch(rlc_tvb, pinfo, tree);
			break;
		case CHANNEL_TYPE_PS_DTCH:
			dissect_rlc_ps_dtch(rlc_tvb, pinfo, tree);
			break;
		case CHANNEL_TYPE_CTCH:
			dissect_rlc_ctch(rlc_tvb, pinfo, tree);
			break;
		default:
			/* Unknown channel type */
			return FALSE;
	}

    return TRUE;
}

void
proto_register_rlc(void)
{
	module_t *rlc_module;

	static hf_register_info hf[] = {
		{ &hf_rlc_dc, { "D/C Bit", "rlc.dc", FT_BOOLEAN, 8, TFS(&rlc_dc_val), 0, NULL, HFILL } },
		{ &hf_rlc_ctrl_type, { "Control PDU Type", "rlc.ctrl_pdu_type", FT_UINT8, BASE_DEC, VALS(rlc_ctrl_vals), 0, "PDU Type", HFILL } },
		{ &hf_rlc_r1, { "Reserved 1", "rlc.r1", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_rsn, { "Reset Sequence Number", "rlc.rsn", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_hfni, { "Hyper Frame Number Indicator", "rlc.hfni", FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_seq, { "Sequence Number", "rlc.seq", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_ext, { "Extension Bit", "rlc.ext", FT_BOOLEAN, BASE_DEC, TFS(&rlc_ext_val), 0, NULL, HFILL } },
		{ &hf_rlc_he, { "Header Extension Type", "rlc.he", FT_UINT8, BASE_DEC, VALS(rlc_he_vals), 0, NULL, HFILL } },
		{ &hf_rlc_p, { "Polling Bit", "rlc.p", FT_BOOLEAN, 8, TFS(&rlc_p_val), 0, NULL, HFILL } },
		{ &hf_rlc_pad, { "Padding", "rlc.padding", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_frags, { "Reassembled Fragments", "rlc.fragments", FT_NONE, BASE_NONE, NULL, 0, "Fragments", HFILL } },
		{ &hf_rlc_frag, { "RLC Fragment", "rlc.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_duplicate_of, { "Duplicate of", "rlc.duplicate_of", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_reassembled_in, { "Reassembled Message in frame", "rlc.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL } }, 
		{ &hf_rlc_data, { "Data", "rlc.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
		/* LI information */
		{ &hf_rlc_li, { "LI", "rlc.li", FT_NONE, BASE_NONE, NULL, 0, "Length Indicator", HFILL } },
		{ &hf_rlc_li_value, { "LI value", "rlc.li.value", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_li_ext, { "LI extension bit", "rlc.li.ext", FT_BOOLEAN, BASE_DEC, TFS(&rlc_ext_val), 0, NULL, HFILL } },
		{ &hf_rlc_li_data, { "LI Data", "rlc.li.data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
		/* SUFI information */
		{ &hf_rlc_sufi, { "SUFI", "rlc.sufi", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_type, { "SUFI Type", "rlc.sufi.type", FT_UINT8, BASE_DEC, VALS(rlc_sufi_vals), 0, NULL, HFILL } },
		{ &hf_rlc_sufi_lsn, { "Last Sequence Number", "rlc.sufi.lsn", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_wsn, { "Window Size Number", "rlc.sufi.wsn", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_sn, { "Sequence Number", "rlc.sufi.sn", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_l, { "Length", "rlc.sufi.l", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_len, { "Length", "rlc.sufi.len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_fsn, { "First Sequence Number", "rlc.sufi.fsn", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_bitmap, { "Bitmap", "rlc.sufi.bitmap", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_cw, { "Codeword", "rlc.sufi.cw", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_n, { "Nlength", "rlc.sufi.n", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_sn_ack, { "SN ACK", "rlc.sufi.sn_ack", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_sn_mrw, { "SN MRW", "rlc.sufi.sn_mrw", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rlc_sufi_poll_sn, { "Poll SN", "rlc.sufi.poll_sn", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		/* Other information */
		{ &hf_rlc_header_only, { "RLC PDU header only", "rlc.header_only", FT_BOOLEAN, BASE_DEC, TFS(&rlc_header_only_val), 0 ,NULL, HFILL } },
 	};
	static gint *ett[] = {
		&ett_rlc,
		&ett_rlc_frag,
		&ett_rlc_fragments,
		&ett_rlc_sdu,
		&ett_rlc_sufi,
		&ett_rlc_bitmap,
		&ett_rlc_rlist
	};
	proto_rlc = proto_register_protocol("RLC", "RLC", "rlc");
	register_dissector("rlc.pcch", dissect_rlc_pcch, proto_rlc);
	register_dissector("rlc.ccch", dissect_rlc_ccch, proto_rlc);
	register_dissector("rlc.ctch", dissect_rlc_ctch, proto_rlc);
	register_dissector("rlc.dcch", dissect_rlc_dcch, proto_rlc);
	register_dissector("rlc.ps_dtch", dissect_rlc_ps_dtch, proto_rlc);

	proto_register_field_array(proto_rlc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Preferences */
	rlc_module = prefs_register_protocol(proto_rlc, NULL);

	prefs_register_bool_preference(rlc_module, "heuristic_rlc_over_udp",
		"Try Heuristic RLC over UDP framing",
		"When enabled, use heuristic dissector to find RLC frames sent with "
		"UDP framing",
		&global_rlc_heur);

	prefs_register_bool_preference(rlc_module, "perform_reassembly",
		"Try to reassemble SDUs",
		"When enabled, try to reassemble SDUs from the various PDUs received",
		&global_rlc_perform_reassemby);

	prefs_register_bool_preference(rlc_module, "header_only_mode",
		"May see RLC headers only",
		"When enabled, if data is not present, don't report as an error, but instead "
		"add expert info to indicate that headers were omitted",
		&global_rlc_headers_expected);

	register_init_routine(fragment_table_init);
}

void
proto_reg_handoff_rlc(void)
{
	rrc_handle = find_dissector("rrc");
	ip_handle = find_dissector("ip");
	bmc_handle = find_dissector("bmc");
	/* Add as a heuristic UDP dissector */
	heur_dissector_add("udp", dissect_rlc_heur, proto_rlc);
}
