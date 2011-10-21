/* packet-ipmi.c
 * Routines for IPMI dissection
 * Copyright 2002-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <string.h>
#include <time.h>
#include <math.h>

#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>

#include "packet-ipmi.h"

/*
 * See the IPMI specifications at
 *
 *	http://www.intel.com/design/servers/ipmi/
 */

/* Define IPMI_DEBUG to enable printing the process of request-response pairing */
/* #define IPMI_DEBUG */

/* Top-level search structure: list of registered handlers for a given netFn */
struct ipmi_netfn_root {
	ipmi_netfn_t *list;
	const char *desc;
	guint32 siglen;
};

#define NSAVED_DATA 2

/* We need more than a conversation. Over the same RMCP session
   (or IPMB), there may be several addresses/SWIDs. Thus, in a single
   Wireshark-maintained conversation we might need to find our own... */
struct ipmi_saved_data {
	guint32 set_data;
	guint32 saved_data[NSAVED_DATA];
};

enum {
	RQ = 0,
	RS,
	RS2,

	MAX_RQRS_FRAMES
};

enum {
	MSGFMT_NONE = 0,
	MSGFMT_IPMB,
	MSGFMT_LAN,
	MSGFMT_GUESS
};

struct ipmi_reqresp {
	struct ipmi_reqresp *next;
	struct ipmi_saved_data *data;
	int (*whichresponse)(struct ipmi_header *hdr, struct ipmi_reqresp *rr);
	struct {
		guint32 num;
		nstime_t time;
	} frames[MAX_RQRS_FRAMES];
	guint8 netfn;
	guint8 cmd;
};

struct ipmi_keyhead {
	struct ipmi_reqresp *rr;
};

struct ipmi_keytree {
	emem_tree_t *heads;
};

struct ipmi_parse_typelen {
	void (*get_len)(guint *, guint *, tvbuff_t *, guint, guint, gboolean);
	void (*parse)(char *, tvbuff_t *, guint, guint);
	const char *desc;
};

struct ipmi_header *ipmi_current_hdr;

static gint proto_ipmi = -1;

static gboolean fru_langcode_is_english = TRUE;
static guint response_after_req = 5000;
static guint response_before_req = 0;
static guint message_format = MSGFMT_GUESS;
static guint selected_oem = IPMI_OEM_NONE;

static gint hf_ipmi_message = -1;
static gint hf_ipmi_session_handle = -1;
static gint hf_ipmi_header_broadcast = -1;
static gint hf_ipmi_header_trg = -1;
static gint hf_ipmi_header_trg_lun = -1;
static gint hf_ipmi_header_netfn = -1;
static gint hf_ipmi_header_crc = -1;
static gint hf_ipmi_header_src = -1;
static gint hf_ipmi_header_src_lun = -1;
static gint hf_ipmi_header_sequence = -1;
static gint hf_ipmi_header_command = -1;
static gint hf_ipmi_header_completion = -1;
static gint hf_ipmi_header_sig = -1;
static gint hf_ipmi_data_crc = -1;
static gint hf_ipmi_response_to = -1;
static gint hf_ipmi_response_in = -1;
static gint hf_ipmi_response_time = -1;
static gint hf_ipmi_bad_checksum = -1;

static gint ett_ipmi = -1;
static gint ett_header = -1;
static gint ett_header_byte_1 = -1;
static gint ett_header_byte_4 = -1;
static gint ett_data = -1;
static gint ett_typelen = -1;

static guint nest_level;
static packet_info *current_pinfo;
static struct ipmi_saved_data *current_saved_data;
static struct ipmi_netfn_root ipmi_cmd_tab[IPMI_NETFN_MAX];

/* Debug support */
static void
debug_printf(const gchar *fmt _U_, ...)
{
#if defined(IPMI_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
#endif
}

/* ----------------------------------------------------------------
   Support for request-response caching.
---------------------------------------------------------------- */

/* Key generation; returns the same key for requests and responses */
static guint32
makekey(struct ipmi_header *hdr)
{
	guint32 trg, src, res;

	trg = (hdr->trg_sa << 2) | hdr->trg_lun;
	src = (hdr->src_sa << 2) | hdr->src_lun;
	res = trg < src ? (trg << 10) | src : (src << 10) | trg;
	return (hdr->seq << 20) | res;
}

static struct ipmi_reqresp *
key_lookup_reqresp(struct ipmi_keyhead *kh, struct ipmi_header *hdr, frame_data *fd)
{
	struct ipmi_reqresp *rr, *best_rr = NULL;
	nstime_t delta;
	double d, best_d = (double)(2 * response_after_req);
	guint8 netfn = hdr->netfn & 0x3e;	/* disregard 'response' bit */
	guint8 is_resp = hdr->netfn & 0x01;
	int i;

	/* Source/target SA/LUN and sequence number are assumed to match; se_tree*
	   ensure that. While checking for "being here", we can't rely on flags.visited,
	   as we may have more than one IPMI message in a single frame. */
	for (rr = kh->rr; rr; rr = rr->next) {
		if (rr->netfn != netfn || rr->cmd != hdr->cmd) {
			continue;
		}

		for (i = 0; i < MAX_RQRS_FRAMES; i++) {
			/* RQ=0 - 0th element is request frame number; RS/RS2 -
			   responses are non zero */
			if (((!i) ^ is_resp) && rr->frames[i].num == fd->num) {
				/* Already been here */
				return rr;
			}
		}

		/* Reject responses before requests or more than 5 seconds ahead */
		if (is_resp) {
			nstime_delta(&delta, &fd->abs_ts, &rr->frames[RQ].time);
		} else {
			/* Use RS here, not RS2 - frames[RS] is always filled if we had
			   at least one response */ /* TBD */
			nstime_delta(&delta, &rr->frames[RS].time, &fd->abs_ts);
		}
		d = nstime_to_msec(&delta);
		if (d < -(double)response_before_req || d > (double)response_after_req) {
			continue;
		}

		if (fabs(d) < best_d) {
			best_rr = rr;
			best_d = fabs(d);
		}
	}

	return best_rr;
}

static void
key_insert_reqresp(struct ipmi_keyhead *kh, struct ipmi_reqresp *rr)
{
	/* Insert to head, so that the search would find most recent response */
	rr->next = kh->rr;
	kh->rr = rr;
}

static inline gboolean
set_framenums(struct ipmi_header *hdr, struct ipmi_reqresp *rr, frame_data *fd)
{
	int which = hdr->netfn & 0x01 ? rr->whichresponse ? rr->whichresponse(hdr, rr) : RS : RQ;

	if (rr->frames[which].num && rr->frames[which].num != fd->num) {
		return FALSE;
	}
	rr->frames[which].num = fd->num;
	rr->frames[which].time = fd->abs_ts;
	return TRUE;
}

#define	IS_SENDMSG(hdr) (((hdr)->netfn & 0x3e) == IPMI_APP_REQ && (hdr)->cmd == 0x34)

int
ipmi_sendmsg_whichresponse(struct ipmi_header *hdr, struct ipmi_reqresp *rr)
{
	if (!IS_SENDMSG(hdr)) {
		/* Not a Send Message: just a simple response */
		return RS;
	}

	if (hdr->data_len > 0) {
		/* Trivial case: response with non-null data can only be a
		   response in AMC.0 style */
		return RS2;
	}
	/* Otherwise, we need to somehow determine 1st and 2nd responses. Note
	   that both them may lack the data - in case that the embedded response
	   returned with error. Thus, employ the following algo:
	   - First, assign to [RS] frame (this also won't conflict with full response
	     received - it could only happen if send message succeeded)
	   - In case we see another data-less response, see that we assign the one
	     with success completion code to [RS] and with non-success code to [RS2].

	   We assume that we can't receive 2 responses with non-successful completion
	   (if the outmost Send Message failed, how was the embedded one sent?)
	*/
	if (!rr->frames[RS].num) {
		return RS;
	}

	/* In case we received "success", move the other response to [RS2] */
	if (!hdr->ccode) {
		if (!rr->frames[RS2].num) {
			rr->frames[RS2] = rr->frames[RS];
		}
		return RS;
	}

	/* [RS] occupied, non-successful */
	return RS2;
}

int
ipmi_sendmsg_otheridx(struct ipmi_header *hdr)
{
	return IS_SENDMSG(hdr) ? nest_level : RS;
}

struct ipmi_header *
ipmi_sendmsg_getheaders(struct ipmi_header *base, void *arg, guint i)
{
	static struct ipmi_header hdr;
	struct ipmi_header *wrapper = arg;

	/* The problem stems from the fact that the original IPMI
	   specification (before errata came) did not specify the response
	   to Send Message (and even the fact that there are 2 responses -
	   to Send Message and to embedded command). Even then, there is
	   one vagueness remaining - whether the response should use
	   the sequence number from the wrapper or from the embedded message.

	   Thus, there are 3 types of responses to Send Message

	   * AMC.0-style: the response is embedded in a normal Send Message
	     response. Easiest case: such responses will be correctly detected
	     with the default code in ipmi_do_dissect.

	   * IPMI-style, with both variants of sequence numbers. Note that
	     most tools dealing with Send Message (e.g. ipmitool) circumvent
	     this vagueness by using the same sequence number in both wrapper
	     and embedded messages. If we detect such "smart" messages, we
	     provide only one extra header. For correctness, we have to provide
	     for both variants, however.
	*/

	if (i >= 2 || (i == 1 && wrapper->seq == base->seq)) {
		return NULL;
	}

	/* Construct hybrid header */
	hdr.trg_sa = wrapper->trg_sa;
	hdr.trg_lun = wrapper->trg_lun;
	hdr.src_sa = wrapper->src_sa;
	hdr.src_lun = wrapper->src_lun;
	hdr.netfn = base->netfn;
	hdr.cmd = base->cmd;
	hdr.seq = i ? base->seq : wrapper->seq;
	hdr.ccode = base->ccode;
	hdr.data_len = base->data_len;
	return &hdr;
}

static void
maybe_insert_reqresp(ipmi_dissect_format_t *dfmt, struct ipmi_header *hdr)
{
	conversation_t *cnv;
	struct ipmi_keytree *kt;
	struct ipmi_keyhead *kh;
	struct ipmi_reqresp *rr;
	guint32 key, i;

	cnv = find_or_create_conversation(current_pinfo);

	kt = conversation_get_proto_data(cnv, proto_ipmi);
	if (!kt) {
		kt = se_alloc(sizeof(struct ipmi_keytree));
		kt->heads = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK,
				"ipmi_key_heads");
		conversation_add_proto_data(cnv, proto_ipmi, kt);
	}

	debug_printf("--> maybe_insert_reqresp( %d )\n", current_pinfo->fd->num);
	i = 0;
	do {
		debug_printf("Checking [ (%02x,%1x <-> %02x,%1x : %02x) %02x %02x ]\n",
				hdr->trg_sa, hdr->trg_lun, hdr->src_sa, hdr->src_lun, hdr->seq,
				hdr->netfn, hdr->cmd);
		key = makekey(hdr);
		kh = se_tree_lookup32(kt->heads, key);
		if (!kh) {
			kh = se_alloc0(sizeof(struct ipmi_keyhead));
			se_tree_insert32(kt->heads, key, kh);
		}
		if ((rr = key_lookup_reqresp(kh, hdr, current_pinfo->fd)) != NULL) {
			/* Already recorded - set frame number and be done. Look no
			   further - even if there are several responses, we have
			   found the right one. */
			debug_printf("Found existing [ <%d,%d,%d> (%02x,%1x <-> %02x,%1x : %02x) %02x %02x ]\n",
					rr->frames[0].num, rr->frames[1].num, rr->frames[2].num,
					hdr->trg_sa, hdr->trg_lun, hdr->src_sa, hdr->src_lun, hdr->seq,
					rr->netfn, rr->cmd);
			if (!rr->whichresponse) {
				rr->whichresponse = dfmt->whichresponse;
			}
			if (set_framenums(hdr, rr, current_pinfo->fd)) {
				debug_printf("Set frames     [ <%d,%d,%d> (%02x,%1x <-> %02x,%1x : %02x) %02x %02x ]\n",
						rr->frames[0].num, rr->frames[1].num, rr->frames[2].num,
						hdr->trg_sa, hdr->trg_lun, hdr->src_sa, hdr->src_lun, hdr->seq,
						rr->netfn, rr->cmd);
				current_saved_data = rr->data;
				return;
			}

			/* Found, but already occupied. Fall through to allocating the structures */
			current_saved_data = NULL;
		}
		/* Not found; allocate new structures */
		if (!current_saved_data) {
			/* One 'ipmi_saved_data' for all 'ipmi_req_resp' allocated */
			current_saved_data = se_alloc0(sizeof(struct ipmi_saved_data));
		}
		rr = se_alloc0(sizeof(struct ipmi_reqresp));
		rr->whichresponse = dfmt->whichresponse;
		rr->netfn = hdr->netfn & 0x3e;
		rr->cmd = hdr->cmd;
		rr->data = current_saved_data;
		set_framenums(hdr, rr, current_pinfo->fd);
		key_insert_reqresp(kh, rr);
		debug_printf("Inserted [ <%d,%d,%d> (%02x,%1x <-> %02x,%1x : %02x) %02x %02x ]\n",
				rr->frames[0].num, rr->frames[1].num, rr->frames[2].num,
				hdr->trg_sa, hdr->trg_lun, hdr->src_sa, hdr->src_lun, hdr->seq,
				rr->netfn, rr->cmd);

		/* Do we have other headers to insert? */
		hdr = dfmt->getmoreheaders ? dfmt->getmoreheaders(hdr, dfmt->arg, i++) : NULL;
	} while (hdr);
}

static void
add_reqresp_info(ipmi_dissect_format_t *dfmt, struct ipmi_header *hdr, proto_tree *tree, tvbuff_t *tvb)
{
	conversation_t *cnv;
	struct ipmi_keytree *kt;
	struct ipmi_keyhead *kh;
	struct ipmi_reqresp *rr = NULL;
	guint32 key, i, other_idx;
	proto_item *ti;
	nstime_t ns;

	debug_printf("--> add_reqresp_info( %d )\n", current_pinfo->fd->num);

	/* [0] is request; [1..MAX_RS_LEVEL] are responses */
	other_idx = (hdr->netfn & 0x01) ? RQ : dfmt->otheridx ? dfmt->otheridx(hdr) : RS;

	if (other_idx >= MAX_RQRS_FRAMES) {
		/* No chance; we don't look that deep into nested Send Message.
		   Note that we'll use the other_idx value to distinguish
		   request from response. */
		goto fallback;
	}

	/* Here, we don't try to create any object - everything is assumed
	   to be created in maybe_insert_reqresp() */
	if ((cnv = find_conversation(current_pinfo->fd->num, &current_pinfo->src,
			&current_pinfo->dst, current_pinfo->ptype,
			current_pinfo->srcport, current_pinfo->destport, 0)) == NULL) {
		goto fallback;
	}
	if ((kt = conversation_get_proto_data(cnv, proto_ipmi)) == NULL) {
		goto fallback;
	}

	i = 0;
	while (1) {
		debug_printf("Looking for [ (%02x,%1x <-> %02x,%1x : %02x) %02x %02x ]\n",
				hdr->trg_sa, hdr->trg_lun, hdr->src_sa, hdr->src_lun, hdr->seq,
				hdr->netfn, hdr->cmd);
		key = makekey(hdr);
		if ((kh = se_tree_lookup32(kt->heads, key)) != NULL &&
				(rr = key_lookup_reqresp(kh, hdr, current_pinfo->fd)) != NULL) {
			debug_printf("Found [ <%d,%d,%d> (%02x,%1x <-> %02x,%1x : %02x) %02x %02x ]\n",
					rr->frames[0].num, rr->frames[1].num, rr->frames[2].num,
					hdr->trg_sa, hdr->trg_lun, hdr->src_sa, hdr->src_lun, hdr->seq,
					rr->netfn, rr->cmd);
			if (rr->frames[other_idx].num) {
				break;
			}
		}

		/* Do we have other headers to check? */
		hdr = dfmt->getmoreheaders ? dfmt->getmoreheaders(hdr, dfmt->arg, i++) : NULL;
		if (!hdr) {
			goto fallback;
		}
	}

	if (hdr->netfn & 0x01) {
		/* Response */
		ti = proto_tree_add_uint(tree, hf_ipmi_response_to,
				tvb, 0, 0, rr->frames[RQ].num);
		PROTO_ITEM_SET_GENERATED(ti);
		nstime_delta(&ns, &current_pinfo->fd->abs_ts, &rr->frames[RQ].time);
		ti = proto_tree_add_time(tree, hf_ipmi_response_time,
				tvb, 0, 0, &ns);
		PROTO_ITEM_SET_GENERATED(ti);
	} else {
		/* Request */
		ti = proto_tree_add_uint(tree, hf_ipmi_response_in,
				tvb, 0, 0, rr->frames[other_idx].num);
		PROTO_ITEM_SET_GENERATED(ti);
	}
	return;

fallback:
	ti = proto_tree_add_text(tree, tvb, 0, 0, "No corresponding %s",
			other_idx ? "response" : "request");
	PROTO_ITEM_SET_GENERATED(ti);
}

/* Save data in request, retrieve in response */
void
ipmi_setsaveddata(guint idx, guint32 val)
{
	DISSECTOR_ASSERT(idx < NSAVED_DATA);
	current_saved_data->saved_data[idx] = val;
	current_saved_data->set_data |= (1 << idx);
}

gboolean
ipmi_getsaveddata(guint idx, guint32 *pval)
{
	DISSECTOR_ASSERT(idx < NSAVED_DATA);
	if (current_saved_data->set_data & (1 << idx)) {
		*pval = current_saved_data->saved_data[idx];
		return TRUE;
	}
	return FALSE;
}

/* ----------------------------------------------------------------
   Support for Type/Length fields parsing.
---------------------------------------------------------------- */

static void
get_len_binary(guint *clen, guint *blen, tvbuff_t *tvb _U_, guint offs _U_,
		guint len, gboolean len_is_bytes _U_)
{
	*clen = len * 3;
	*blen = len;
}

static void
parse_binary(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	static const char hex[] = "0123456789ABCDEF";
	guint8 v;
	guint i;

	for (i = 0; i < len / 3; i++) {
		v = tvb_get_guint8(tvb, offs + i);
		*p++ = hex[v >> 4];
		*p++ = hex[v & 0xf];
		*p++ = ' ';
	}

	if (i) {
		*--p = '\0';
	}
}

static struct ipmi_parse_typelen ptl_binary = {
	get_len_binary, parse_binary, "Binary"
};

static void
get_len_bcdplus(guint *clen, guint *blen, tvbuff_t *tvb _U_, guint offs _U_,
		guint len, gboolean len_is_bytes)
{
	if (len_is_bytes) {
		*clen = len * 2;
		*blen = len;
	} else {
		*blen = (len + 1) / 2;
		*clen = len;
	}
}

static void
parse_bcdplus(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	static const char bcd[] = "0123456789 -.:,_";
	guint i, msk = 0xf0, shft = 4;
	guint8 v;

	for (i = 0; i < len; i++) {
		v = (tvb_get_guint8(tvb, offs + i / 2) & msk) >> shft;
		*p++ = bcd[v];
		msk ^= 0xff;
		shft = 4 - shft;
	}
}

static struct ipmi_parse_typelen ptl_bcdplus = {
	get_len_bcdplus, parse_bcdplus, "BCD+"
};

static void
get_len_6bit_ascii(guint *clen, guint *blen, tvbuff_t *tvb _U_, guint offs _U_,
		guint len, gboolean len_is_bytes)
{
	if (len_is_bytes) {
		*clen = len * 4 / 3;
		*blen = len;
	} else {
		*blen = (len * 3 + 3) / 4;
		*clen = len;
	}
}

static void
parse_6bit_ascii(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	guint32 v;
	guint i;

	/* First, handle "full" triplets of bytes, 4 characters each */
	for (i = 0; i < len / 4; i++) {
		v = tvb_get_letoh24(tvb, offs + i * 3);
		p[0] = ' ' + (v & 0x3f);
		p[1] = ' ' + ((v >> 6) & 0x3f);
		p[2] = ' ' + ((v >> 12) & 0x3f);
		p[3] = ' ' + ((v >> 18) & 0x3f);
		p += 4;
	}

	/* Do we have any characters left? */
	offs += len / 4;
	len &= 0x3;
	switch (len) {
	case 3:
		v = (tvb_get_guint8(tvb, offs + 2) << 4) | (tvb_get_guint8(tvb, offs + 1) >> 4);
		p[2] = ' ' + (v & 0x3f);
		/* Fall thru */
	case 2:
		v = (tvb_get_guint8(tvb, offs + 1) << 2) | (tvb_get_guint8(tvb, offs) >> 6);
		p[1] = ' ' + (v & 0x3f);
		/* Fall thru */
	case 1:
		v = tvb_get_guint8(tvb, offs) & 0x3f;
		p[0] = ' ' + (v & 0x3f);
	}
}

static struct ipmi_parse_typelen ptl_6bit_ascii = {
	get_len_6bit_ascii, parse_6bit_ascii, "6-bit ASCII"
};

static void
get_len_8bit_ascii(guint *clen, guint *blen, tvbuff_t *tvb, guint offs,
		guint len, gboolean len_is_bytes _U_)
{
	guint i;
	guint8 ch;

	*blen = len;	/* One byte is one character */
	*clen = 0;
	for (i = 0; i < len; i++) {
		ch = tvb_get_guint8(tvb, offs + i);
		*clen += (ch >= 0x20 && ch <= 0x7f) ? 1 : 4;
	}
}

static void
parse_8bit_ascii(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	guint8 ch;
	char *pmax;

	pmax = p + len;
	while (p < pmax) {
		ch = tvb_get_guint8(tvb, offs++);
		if (ch >= 0x20 && ch <= 0x7f) {
			*p++ = ch;
		} else {
			g_snprintf(p, 5, "\\x%02x", ch);
			p += 4;
		}
	}
}

static struct ipmi_parse_typelen ptl_8bit_ascii = {
	get_len_8bit_ascii, parse_8bit_ascii, "ASCII+Latin1"
};

static void
get_len_unicode(guint *clen, guint *blen, tvbuff_t *tvb _U_, guint offs _U_,
		guint len _U_, gboolean len_is_bytes)
{
	if (len_is_bytes) {
		*clen = len * 3; /* Each 2 bytes result in 6 chars printed: \Uxxxx */
		*blen = len;
	} else {
		*clen = len * 6;
		*blen = len * 2;
	}
}

static void
parse_unicode(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	char *pmax = p + len;
	guint8 ch0, ch1;

	while (p < pmax) {
		ch0 = tvb_get_guint8(tvb, offs++);
		ch1 = tvb_get_guint8(tvb, offs++);
		g_snprintf(p, 7, "\\U%02x%02x", ch0, ch1);
		p += 6;
	}
}

static struct ipmi_parse_typelen ptl_unicode = {
	get_len_unicode, parse_unicode, "Unicode"
};

void
ipmi_add_typelen(proto_tree *tree, const char *desc, tvbuff_t *tvb,
		guint offs, gboolean is_fru)
{
	static struct ipmi_parse_typelen *fru_eng[4] = {
		&ptl_binary, &ptl_bcdplus, &ptl_6bit_ascii, &ptl_8bit_ascii
	};
	static struct ipmi_parse_typelen *fru_noneng[4] = {
		&ptl_binary, &ptl_bcdplus, &ptl_6bit_ascii, &ptl_unicode
	};
	static struct ipmi_parse_typelen *ipmi[4] = {
		&ptl_unicode, &ptl_bcdplus, &ptl_6bit_ascii, &ptl_8bit_ascii
	};
	struct ipmi_parse_typelen *ptr;
	proto_tree *s_tree;
	proto_item *ti;
	guint type, msk, clen, blen, len;
	const char *unit;
	char *str;
	guint8 typelen;

	typelen = tvb_get_guint8(tvb, offs);
	type = typelen >> 6;
	if (is_fru) {
		msk = 0x3f;
		ptr = (fru_langcode_is_english ? fru_eng : fru_noneng)[type];
		unit = "bytes";
	} else {
		msk = 0x1f;
		ptr = ipmi[type];
		unit = "characters";
	}

	len = typelen & msk;
	ptr->get_len(&clen, &blen, tvb, offs + 1, len, is_fru);

	str = ep_alloc(clen + 1);
	ptr->parse(str, tvb, offs + 1, clen);
	str[clen] = '\0';

	ti = proto_tree_add_text(tree, tvb, offs, 1, "%s Type/Length byte: %s, %d %s",
			desc, ptr->desc, len, unit);
	s_tree = proto_item_add_subtree(ti, ett_typelen);
	proto_tree_add_text(s_tree, tvb, offs, 1, "%sType: %s (0x%02x)",
			ipmi_dcd8(typelen, 0xc0), ptr->desc, type);
	proto_tree_add_text(s_tree, tvb, offs, 1, "%sLength: %d %s",
			ipmi_dcd8(typelen, msk), len, unit);

	proto_tree_add_text(tree, tvb, offs + 1, blen, "%s: [%s] '%s'",
			desc, ptr->desc, str);
}

/* ----------------------------------------------------------------
   Timestamp, IPMI-style.
---------------------------------------------------------------- */
void
ipmi_add_timestamp(proto_tree *tree, gint hf, tvbuff_t *tvb, guint offset)
{
	guint32 ts = tvb_get_letohl(tvb, offset);

	if (ts == 0xffffffff) {
		proto_tree_add_uint_format_value(tree, hf, tvb, offset, 4,
				ts, "Unspecified/Invalid");
	} else if (ts <= 0x20000000) {
		proto_tree_add_uint_format_value(tree, hf, tvb, offset, 4,
				ts, "%s since SEL device's initialization",
				time_secs_to_str_unsigned(ts));
	} else {
		proto_tree_add_uint_format_value(tree, hf, tvb, offset, 4,
				ts, "%s", abs_time_secs_to_str(ts, ABSOLUTE_TIME_UTC, TRUE));
	}
}

/* ----------------------------------------------------------------
   GUID, IPMI-style.
---------------------------------------------------------------- */

void
ipmi_add_guid(proto_tree *tree, gint hf, tvbuff_t *tvb, guint offset)
{
	e_guid_t guid;
	int i;

	guid.data1 = tvb_get_letohl(tvb, offset + 12);
	guid.data2 = tvb_get_letohs(tvb, offset + 10);
	guid.data3 = tvb_get_letohs(tvb, offset + 8);
	for (i = 0; i < 8; i++) {
		guid.data4[i] = tvb_get_guint8(tvb, offset + 7 - i);
	}
	proto_tree_add_guid(tree, hf, tvb, offset, 16, &guid);
}

/* ----------------------------------------------------------------
   Routines for registering/looking up command parsers.
---------------------------------------------------------------- */

static void
ipmi_netfn_setdesc(guint32 netfn, const char *desc, guint32 siglen)
{
	struct ipmi_netfn_root *inr;

	inr = &ipmi_cmd_tab[netfn >> 1];
	inr->desc = desc;
	inr->siglen = siglen;
}

void
ipmi_register_netfn_cmdtab(guint32 netfn, guint oem_selector,
		const guint8 *sig, guint32 siglen, const char *desc,
		ipmi_cmd_t *cmdtab, guint32 cmdtablen)
{
	struct ipmi_netfn_root *inr;
	ipmi_netfn_t *inh;

	netfn >>= 1;	/* Requests and responses grouped together */
	if (netfn >= IPMI_NETFN_MAX) {
		g_warning("NetFn too large: %x", netfn * 2);
		return;
	}

	inr = &ipmi_cmd_tab[netfn];
	if (inr->siglen != siglen) {
		/* All handlers per netFn should have the same signature length */
		g_warning("NetFn %d: different signature lengths: %d vs %d",
				netfn * 2, inr->siglen, siglen);
		return;
	}

	inh = g_malloc(sizeof(struct ipmi_netfn_handler));
	inh->desc = desc;
	inh->oem_selector = oem_selector;
	inh->sig = sig;
	inh->cmdtab = cmdtab;
	inh->cmdtablen = cmdtablen;

	inh->next = inr->list;
	inr->list = inh;
}

guint32
ipmi_getsiglen(guint32 netfn)
{
	return ipmi_cmd_tab[netfn >> 1].siglen;
}

const char *
ipmi_getnetfnname(guint32 netfn, ipmi_netfn_t *nf)
{
	const char *dn, *db;

	dn = ipmi_cmd_tab[netfn >> 1].desc ?
		ipmi_cmd_tab[netfn >> 1].desc : "Reserved";
	db = nf ? nf->desc : NULL;
	if (db) {
		return ep_strdup_printf("%s (%s)", db, dn);
	} else {
		return dn;
	}
}

ipmi_netfn_t *
ipmi_getnetfn(guint32 netfn, const guint8 *sig)
{
	struct ipmi_netfn_root *inr;
	ipmi_netfn_t *inh;

	inr = &ipmi_cmd_tab[netfn >> 1];
	for (inh = inr->list; inh; inh = inh->next) {
		if ((inh->oem_selector == selected_oem || inh->oem_selector == IPMI_OEM_NONE)
				&& (!inr->siglen || !memcmp(sig, inh->sig, inr->siglen))) {
			return inh;
		}
	}

	/* Either unknown netFn or signature does not match */
	return NULL;
}

ipmi_cmd_t *
ipmi_getcmd(ipmi_netfn_t *nf, guint32 cmd)
{
	static ipmi_cmd_t ipmi_cmd_unknown = {
		0x00,		/* Code */
		ipmi_notimpl,	/* request */
		ipmi_notimpl,	/* response */
		NULL,		/* command codes */
		NULL,		/* subfunctions */
		"Unknown command",
		0		/* flag */
	};
	ipmi_cmd_t *ic;
	size_t i, len;

	if (nf) {
		len = nf->cmdtablen;
		for (ic = nf->cmdtab, i = 0; i < len; i++, ic++) {
			if (ic->cmd == cmd) {
				return ic;
			}
		}
	}

	return &ipmi_cmd_unknown;
}

/* ----------------------------------------------------------------
   Various utility functions.
---------------------------------------------------------------- */

void
ipmi_notimpl(tvbuff_t *tvb, proto_tree *tree)
{
	if (tree) {
		proto_tree_add_text(tree, tvb, 0, -1, "[PARSER NOT IMPLEMENTED]");
	}
}

char *
ipmi_dcd8(guint32 val, guint32 mask)
{
	static char buf[64];

	decode_bitfield_value(buf, val, mask, 8);
	return buf;
}

void
ipmi_fmt_10ms_1based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%03d seconds", v / 100, (v % 100) * 10);
}

void
ipmi_fmt_500ms_0based(gchar *s, guint32 v)
{
	ipmi_fmt_500ms_1based(s, ++v);
}

void
ipmi_fmt_500ms_1based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%03d seconds", v / 2, (v % 2) * 500);
}

void
ipmi_fmt_1s_0based(gchar *s, guint32 v)
{
	ipmi_fmt_1s_1based(s, ++v);
}

void
ipmi_fmt_1s_1based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d seconds", v);
}

void
ipmi_fmt_2s_0based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d seconds", (v + 1) * 2);
}

void
ipmi_fmt_5s_1based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d seconds", v * 5);
}

void
ipmi_fmt_version(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%d", v & 0x0f, (v >> 4) & 0x0f);
}

void
ipmi_fmt_channel(gchar *s, guint32 v)
{
	static const value_string chan_vals[] = {
		{ 0x00, "Primary IPMB (IPMB-0)" },
		{ 0x07, "IPMB-L" },
		{ 0x0e, "Current channel" },
		{ 0x0f, "System Interface" },
		{ 0, NULL }
	};

	g_snprintf(s, ITEM_LABEL_LENGTH, "%s (0x%02x)",
			val_to_str(v, chan_vals, "Channel #%d"), v);
}

void
ipmi_fmt_udpport(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%s (%d)", get_udp_port(v), v);
}

void
ipmi_fmt_percent(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d%%", v);
}

const char *
ipmi_get_completion_code(guint8 completion, ipmi_cmd_t *cmd)
{
	static const value_string std_completion_codes[] = {
		{ 0x00, "Command Completed Normally" },
		{ 0xc0, "Node Busy" },
		{ 0xc1, "Invalid Command" },
		{ 0xc2, "Command invalid for given LUN" },
		{ 0xc3, "Timeout while processing command, response unavailable" },
		{ 0xc4, "Out of space" },
		{ 0xc5, "Reservation Canceled or Invalid Reservation ID" },
		{ 0xc6, "Request data truncated" },
		{ 0xc7, "Request data length invalid" },
		{ 0xc8, "Request data field length limit exceeded" },
		{ 0xc9, "Parameter out of range" },
		{ 0xca, "Cannot return number of requested data bytes" },
		{ 0xcb, "Requested Sensor, data, or record not present" },
		{ 0xcc, "Invalid data field in Request" },
		{ 0xcd, "Command illegal for specified sensor or record type" },
		{ 0xce, "Command response could not be provided" },
		{ 0xcf, "Cannot execute duplicated request" },
		{ 0xd0, "Command response could not be provided: SDR Repository in update mode" },
		{ 0xd1, "Command response could not be provided: device in firmware update mode" },
		{ 0xd2, "Command response could not be provided: BMC initialization or initialization agent in progress" },
		{ 0xd3, "Destination unavailable" },
		{ 0xd4, "Cannot execute command: insufficient privilege level or other security-based restriction" },
		{ 0xd5, "Cannot execute command: command, or request parameter(s), not supported in present state" },
		{ 0xd6, "Cannot execute command: parameter is illegal because subfunction is disabled or unavailable" },
		{ 0xff, "Unspecified error" },

		{ 0, NULL }
	};
	const char *res;

	if (completion >= 0x01 && completion <= 0x7e) {
		return "Device specific (OEM) completion code";
	}

	if (completion >= 0x80 && completion <= 0xbe) {
		if (cmd && cmd->cs_cc && (res = match_strval(completion, cmd->cs_cc)) != NULL) {
			return res;
		}
		return "Standard command-specific code";
	}

	return val_to_str(completion, std_completion_codes, "Unknown");
}

/* Guess the parsing flags for a message
 */
int
ipmi_guess_dissect_flags(tvbuff_t *tvb)
{
	int i;
	guint8 buf[6];

	switch (message_format) {
	case MSGFMT_NONE:
		return IPMI_D_NONE;
	case MSGFMT_IPMB:
		return IPMI_D_TRG_SA;
	case MSGFMT_LAN:
		return IPMI_D_TRG_SA|IPMI_D_SESSION_HANDLE;
	}

	/* Try to guess the format */
	DISSECTOR_ASSERT(message_format == MSGFMT_GUESS);

	/* 6 is shortest message - Get Message with empty data */
	if (tvb_length(tvb) < 6) {
		return IPMI_D_NONE;
	}

	/* Fetch the beginning */
	for (i = 0; i < 6; i++) {
		buf[i] = tvb_get_guint8(tvb, i);
	}

	if ((buf[0] + buf[1] + buf[2]) % 0x100 == 0) {
		/* Looks like IPMB: first 3 bytes are zero module 256 */
		return IPMI_D_TRG_SA;
	}

	if ((buf[1] + buf[2] + buf[3]) % 0x100 == 0) {
		/* Looks like LAN: like IPMB, prepended with extra byte (session handle) */
		return IPMI_D_TRG_SA|IPMI_D_SESSION_HANDLE;
	}

	/* Can't guess */
	return IPMI_D_NONE;
}

/* Print out IPMB packet.
 */
void
ipmi_do_dissect(tvbuff_t *tvb, proto_tree *ipmi_tree, ipmi_dissect_format_t *dfmt)
{
	proto_tree *hdr_tree, *data_tree, *s_tree;
	proto_item *ti;
	tvbuff_t *data_tvb;
	ipmi_netfn_t *in = NULL;
	ipmi_cmd_t *ic = NULL;
	ipmi_cmd_handler_t hnd = NULL;
	struct ipmi_saved_data *saved_saved_data;
	struct ipmi_header hdr, *saved_hdr;
	guint8 hdr_crc, hdr_exp_crc, data_crc, data_exp_crc;
	guint8 is_resp, is_broadcast = 0, tmp;
	guint i, len, siglen, hdrlen, offs, data_chk_offs;
	const char *bcast, *ndesc, *cdesc, *ccdesc;

	if (dfmt->flags & IPMI_D_NONE) {
		/* No parsing requested */
		g_snprintf(dfmt->info, ITEM_LABEL_LENGTH, "Unknown message (not parsed)");
		proto_tree_add_item(ipmi_tree, hf_ipmi_message, tvb, 0, tvb_length(tvb), ENC_NA);
		return;
	}

	nest_level++;
	offs = 0;
	memset(&hdr, 0, sizeof(hdr));
	debug_printf("--> do_dissect(%d, nl %u, tree %s null)\n",
			current_pinfo->fd->num, nest_level, ipmi_tree ? "IS NOT" : "IS");

	/* Optional byte: in Send Message targeted to session-based channels */
	if (dfmt->flags & IPMI_D_SESSION_HANDLE) {
		offs++;
	}

	/* Optional byte: 00 indicates General Call address - broadcast message */
	if ((dfmt->flags & IPMI_D_BROADCAST) && tvb_get_guint8(tvb, offs) == 0x00) {
		is_broadcast = 1;
		offs++;
	}

	/* Byte 1: target slave address, may be absent (in Get Message) */
	hdr.trg_sa = (dfmt->flags & IPMI_D_TRG_SA) ? tvb_get_guint8(tvb, offs++) : 0;

	/* Byte 2: network function + target LUN */
	tmp = tvb_get_guint8(tvb, offs++);
	hdr.trg_lun = tmp & 0x03;
	hdr.netfn = (tmp >> 2) & 0x3f;
	hdr_exp_crc = (0 - hdr.trg_sa - tmp) & 0xff;

	/* Byte 3: header checksum */
	hdr_crc = tvb_get_guint8(tvb, offs++);

	/* Byte 4: source slave address */
	hdr.src_sa = tvb_get_guint8(tvb, offs++);

	/* Byte 5: sequence number + source LUN */
	tmp = tvb_get_guint8(tvb, offs++);
	hdr.src_lun = tmp & 0x03;
	hdr.seq = (tmp >> 2) & 0x3f;

	/* Byte 6: command code */
	hdr.cmd = tvb_get_guint8(tvb, offs++);

	/* Byte 7: completion code (in response) */
	is_resp = (hdr.netfn & 0x1) ? 1 : 0;
	hdr.ccode = is_resp ? tvb_get_guint8(tvb, offs++) : 0;

	/* 0-3 bytes: signature of the defining body */
	siglen = ipmi_getsiglen(hdr.netfn);
	in = ipmi_getnetfn(hdr.netfn, tvb_get_ptr(tvb, offs, siglen));
	offs += siglen;

	/* Save header length */
	hdrlen = offs;
	hdr.data_len = tvb_length(tvb) - hdrlen - 1;

	/* Get some text descriptions */
	ic = ipmi_getcmd(in, hdr.cmd);
	ndesc = ipmi_getnetfnname(hdr.netfn, in);
	cdesc = ic->desc;
	ccdesc = ipmi_get_completion_code(hdr.ccode, ic);
	if (!is_broadcast) {
		bcast = "";
	} else if (ic->flags & CMD_MAYBROADCAST) {
		bcast = " (BROADCAST: command may not be broadcast)";
	} else {
		bcast = " (BROADCAST)";
	}


	/* Save globals - we may be called recursively */
	saved_hdr = ipmi_current_hdr;
	ipmi_current_hdr = &hdr;
	saved_saved_data = current_saved_data;
	current_saved_data = NULL;

	/* Select sub-handler */
	hnd = is_resp ? ic->parse_resp : ic->parse_req;

	/* Start new conversation if needed */
	if (!is_resp && (ic->flags & CMD_NEWCONV)) {
		conversation_new(current_pinfo->fd->num, &current_pinfo->src,
				&current_pinfo->dst, current_pinfo->ptype,
				current_pinfo->srcport, current_pinfo->destport, 0);
	}

	/* Check if we need to insert request-response pair */
	maybe_insert_reqresp(dfmt, &hdr);

	/* Create data subset: all but header and last byte (checksum) */
	data_tvb = tvb_new_subset(tvb, hdrlen, hdr.data_len, hdr.data_len);

	/* Brief description of a packet */
	g_snprintf(dfmt->info, ITEM_LABEL_LENGTH, "%s, %s, seq 0x%02x%s%s%s",
			is_resp ? "Rsp" : "Req", cdesc, hdr.seq, bcast,
			hdr.ccode ? ", " : "", hdr.ccode ? ccdesc : "");

	if (!is_resp && (ic->flags & CMD_CALLRQ)) {
		hnd(data_tvb, NULL);
	}

	if (ipmi_tree) {
		add_reqresp_info(dfmt, &hdr, ipmi_tree, tvb);

		ti = proto_tree_add_text(ipmi_tree, tvb, 0, hdrlen,
				"Header: %s (%s) from 0x%02x to 0x%02x%s", cdesc,
				is_resp ? "Response" : "Request", hdr.src_sa, hdr.trg_sa, bcast);
		hdr_tree = proto_item_add_subtree(ti, ett_header);

		offs = 0;

		if (dfmt->flags & IPMI_D_SESSION_HANDLE) {
			proto_tree_add_item(hdr_tree, hf_ipmi_session_handle,
					tvb, offs++, 1, ENC_LITTLE_ENDIAN);
		}

		/* Broadcast byte (optional) */
		if (is_broadcast) {
			proto_tree_add_uint_format(hdr_tree, hf_ipmi_header_broadcast,
					tvb, offs++, 1, 0x00, "Broadcast message");
		}

		/* Target SA, if present */
		if (dfmt->flags & IPMI_D_TRG_SA) {
			proto_tree_add_item(hdr_tree, hf_ipmi_header_trg, tvb, offs++, 1, ENC_LITTLE_ENDIAN);
		}

		/* Network function + target LUN */
		ti = proto_tree_add_text(hdr_tree, tvb, offs, 1,
				"Target LUN: 0x%02x, NetFN: %s %s (0x%02x)", hdr.trg_lun,
				ndesc, is_resp ? "Response" : "Request", hdr.netfn);
		s_tree = proto_item_add_subtree(ti, ett_header_byte_1);

		proto_tree_add_item(s_tree, hf_ipmi_header_trg_lun, tvb, offs, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_uint_format(s_tree, hf_ipmi_header_netfn, tvb, offs, 1,
				hdr.netfn << 2, "%sNetFn: %s %s (0x%02x)",
				ipmi_dcd8(hdr.netfn << 2, 0xfc),
				ndesc, is_resp ? "Response" : "Request", hdr.netfn);
		offs++;

		/* Header checksum */
		if (hdr_crc == hdr_exp_crc) {
			proto_tree_add_uint_format(hdr_tree, hf_ipmi_header_crc, tvb, offs++, 1,
					hdr_crc, "Header checksum: 0x%02x (correct)", hdr_crc);
		}
		else {
			ti = proto_tree_add_boolean(hdr_tree, hf_ipmi_bad_checksum, tvb, 0, 0, TRUE);
			PROTO_ITEM_SET_HIDDEN(ti);
			proto_tree_add_uint_format(hdr_tree, hf_ipmi_header_crc, tvb, offs++, 1,
					hdr_crc, "Header checksum: 0x%02x (incorrect, expected 0x%02x)",
				       	hdr_crc, hdr_exp_crc);
		}

		/* Remember where chk2 bytes start */
		data_chk_offs = offs;

		/* Source SA */
		proto_tree_add_item(hdr_tree, hf_ipmi_header_src, tvb, offs++, 1, ENC_LITTLE_ENDIAN);

		/* Sequence number + source LUN */
		ti = proto_tree_add_text(hdr_tree, tvb, offs, 1,
				"Source LUN: 0x%02x, SeqNo: 0x%02x",
				hdr.src_lun, hdr.seq);
		s_tree = proto_item_add_subtree(ti, ett_header_byte_4);

		proto_tree_add_item(s_tree, hf_ipmi_header_src_lun, tvb, offs, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(s_tree, hf_ipmi_header_sequence, tvb, offs, 1, ENC_LITTLE_ENDIAN);
		offs++;

		/* Command */
		proto_tree_add_uint_format(hdr_tree, hf_ipmi_header_command, tvb, offs++, 1,
				hdr.cmd, "Command: %s (0x%02x)", cdesc, hdr.cmd);

		/* Response code (if present) */
		if (is_resp) {
			proto_tree_add_uint_format(hdr_tree, hf_ipmi_header_completion, tvb, offs++, 1,
				hdr.ccode, "Completion code: %s (0x%02x)", ccdesc, hdr.ccode);
		}

		/* Defining body signature (if present) */
		if (siglen) {
			ti = proto_tree_add_item(hdr_tree, hf_ipmi_header_sig, tvb, offs, siglen, ENC_NA);
			proto_item_append_text(ti, " (%s)", ndesc);
			offs += siglen;
		}

		/* Call data parser */
		if (tvb_length(data_tvb) && hnd) {
			ti = proto_tree_add_text(ipmi_tree, data_tvb, 0, -1, "Data");
			data_tree = proto_item_add_subtree(ti, ett_data);
			hnd(data_tvb, data_tree);
		}

		/* Checksum all but the last byte */
		len = tvb_length(tvb) - 1;
		data_crc = tvb_get_guint8(tvb, len);
		data_exp_crc = 0;
		for (i = data_chk_offs; i < len; i++) {
			data_exp_crc += tvb_get_guint8(tvb, i);
		}
		data_exp_crc = (0 - data_exp_crc) & 0xff;

		if (data_crc == data_exp_crc) {
			proto_tree_add_uint_format(ipmi_tree, hf_ipmi_data_crc, tvb, len, 1,
					data_crc, "Data checksum: 0x%02x (correct)", data_crc);
		}
		else {
			ti = proto_tree_add_boolean(hdr_tree, hf_ipmi_bad_checksum, tvb, 0, 0, TRUE);
			PROTO_ITEM_SET_HIDDEN(ti);
			proto_tree_add_uint_format(ipmi_tree, hf_ipmi_data_crc, tvb, len, 1,
					data_crc, "Data checksum: 0x%02x (incorrect, expected 0x%02x)",
					data_crc, data_exp_crc);
		}
	}

	/* Restore globals, in case we've been called recursively */
	ipmi_current_hdr = saved_hdr;
	current_saved_data = saved_saved_data;
	nest_level--;
}

static void
dissect_ipmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *ipmi_tree = NULL;
	proto_item *ti;
	ipmi_dissect_format_t dfmt;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPMI/ATCA");

	current_pinfo = pinfo;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipmi, tvb, 0, -1, ENC_NA);
		ipmi_tree = proto_item_add_subtree(ti, ett_ipmi);
	}

	memset(&dfmt, 0, sizeof(dfmt));
	dfmt.flags = IPMI_D_BROADCAST | IPMI_D_TRG_SA;
	ipmi_do_dissect(tvb, ipmi_tree, &dfmt);

	col_add_str(pinfo->cinfo, COL_INFO, dfmt.info);

}

/* Register IPMB protocol.
 */
void
proto_reg_handoff_ipmi(void)
{
}

void
proto_register_ipmi(void)
{
	static hf_register_info	hf[] = {
		{ &hf_ipmi_message, { "Message", "ipmi.message", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_session_handle, { "Session handle", "ipmi.session_handle", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_broadcast, { "Broadcast message", "ipmi.header.broadcast", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_trg, { "Target Address", "ipmi.header.target", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_ipmi_header_trg_lun, { "Target LUN", "ipmi.header.trg_lun", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }},
		{ &hf_ipmi_header_netfn, { "NetFN", "ipmi.header.netfn", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL }},
		{ &hf_ipmi_header_crc, { "Header Checksum", "ipmi.header.crc", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_src, { "Source Address", "ipmi.header.source", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_src_lun, { "Source LUN", "ipmi.header.src_lun", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }},
		{ &hf_ipmi_header_sequence, { "Sequence Number", "ipmi.header.sequence", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL }},
		{ &hf_ipmi_header_command, { "Command", "ipmi.header.command", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_completion, { "Completion Code", "ipmi.header.completion", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_sig, { "Signature", "ipmi.header.signature", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_data_crc, { "Data checksum", "ipmi.data.crc", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_response_to, { "Response to", "ipmi.response_to", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_response_in, { "Response in", "ipmi.response_in", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_response_time, { "Responded in", "ipmi.response_time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_bad_checksum, { "Bad checksum", "ipmi.bad_checksum", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};
	static gint *ett[] = {
		&ett_ipmi,
		&ett_header,
		&ett_header_byte_1,
		&ett_header_byte_4,
		&ett_data,
		&ett_typelen
	};
	static const enum_val_t msgfmt_vals[] = {
		{ "none", "None", MSGFMT_NONE },
		{ "ipmb", "IPMB", MSGFMT_IPMB },
		{ "lan", "Session-based (LAN, ...)", MSGFMT_LAN },
		{ "guess", "Use heuristics", MSGFMT_GUESS },
		{ NULL, NULL, 0 }
	};
	static const enum_val_t oemsel_vals[] = {
		{ "none", "None", IPMI_OEM_NONE },
		{ "pps", "Pigeon Point Systems", IPMI_OEM_PPS },
		{ NULL, NULL, 0 }
	};
	module_t *m;
	guint32 i;

	proto_ipmi = proto_register_protocol("Intelligent Platform Management Interface",
	                        "IPMI/ATCA",
	                        "ipmi");

	proto_register_field_array(proto_ipmi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ipmi_netfn_setdesc(IPMI_CHASSIS_REQ, "Chassis", 0);
	ipmi_netfn_setdesc(IPMI_BRIDGE_REQ, "Bridge", 0);
	ipmi_netfn_setdesc(IPMI_SE_REQ, "Sensor/Event", 0);
	ipmi_netfn_setdesc(IPMI_APP_REQ, "Application", 0);
	ipmi_netfn_setdesc(IPMI_UPDATE_REQ, "Firmware Update", 0);
	ipmi_netfn_setdesc(IPMI_STORAGE_REQ, "Storage", 0);
	ipmi_netfn_setdesc(IPMI_TRANSPORT_REQ, "Transport", 0);
	ipmi_netfn_setdesc(IPMI_GROUP_REQ, "Group", 1);
	ipmi_netfn_setdesc(IPMI_OEM_REQ, "OEM/Group", 3);
	for (i = 0x30; i < 0x40; i += 2) {
		ipmi_netfn_setdesc(i, "OEM", 0);
	}

	ipmi_register_chassis(proto_ipmi);
	ipmi_register_bridge(proto_ipmi);
	ipmi_register_se(proto_ipmi);
	ipmi_register_app(proto_ipmi);
	ipmi_register_update(proto_ipmi);
	ipmi_register_storage(proto_ipmi);
	ipmi_register_transport(proto_ipmi);
	ipmi_register_picmg(proto_ipmi);
	ipmi_register_pps(proto_ipmi);

	register_dissector("ipmi", dissect_ipmi, proto_ipmi);

	m = prefs_register_protocol(proto_ipmi, NULL);
	prefs_register_bool_preference(m, "fru_langcode_is_english", "FRU Language Code is English",
			"FRU Language Code is English; strings are ASCII+LATIN1 (vs. Unicode)",
			&fru_langcode_is_english);
	prefs_register_uint_preference(m, "response_after_req", "Maximum delay of response message",
			"Do not search for responses coming after this timeout (milliseconds)",
			10, &response_after_req);
	prefs_register_uint_preference(m, "response_before_req", "Response ahead of request",
			"Allow for responses before requests (milliseconds)",
			10, &response_before_req);
	prefs_register_enum_preference(m, "msgfmt", "Format of embedded messages",
			"Format of messages embedded into Send/Get/Forward Message",
			&message_format, msgfmt_vals, FALSE);
	prefs_register_enum_preference(m, "selected_oem", "OEM commands parsed as",
			"Selects which OEM format is used for commands that IPMI does not define",
			&selected_oem, oemsel_vals, FALSE);
}
