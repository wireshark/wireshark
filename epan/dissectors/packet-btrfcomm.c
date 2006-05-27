/* old code to do unescaping of serial port data and reassembly of ppp frames
 * are left in but ifdeffed out.
 * This code should be rewritten when there are examples of ppp over rfcomm
 * captures made available to test with.
 * the old code is left in to show an example of what kind of operations need
 * to be done in the new (yet to be written) code.
 *
 * For now all this is decoded just as "data".
 * It might be enough to just check
 * If the first byte of payload is the 0x7e delimeter and if so just
 * de escape it into a ep_alloc() buffer and then pass it to the ppp 
 * dissector.
 */

/* packet-btrfcomm.c
 * Routines for Bluetooth RFCOMM protocol dissection
 * Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include <epan/value_string.h>
#include <etypes.h>
#include <epan/emem.h>
#include "packet-btl2cap.h"

static int hf_pf = -1;
static int hf_ea = -1;
static int hf_len = -1;
static int hf_frame_type = -1;
static int hf_cr = -1;
static int hf_dlci = -1;
static int hf_priority = -1;
static int hf_error_recovery_mode = -1;
static int hf_max_frame_size = -1;
static int hf_max_retrans = -1;
static int hf_fc_credits = -1;

static int hf_pn_i14 = -1;
static int hf_pn_c14 = -1;

static int hf_mcc_len = -1;
static int hf_mcc_ea = -1;
static int hf_mcc_cr = -1;
static int hf_mcc_cmd = -1;

static int hf_msc_fc = -1;
static int hf_msc_rtc = -1;
static int hf_msc_rtr = -1;
static int hf_msc_ic = -1;
static int hf_msc_dv = -1;
static int hf_msc_l = -1;

static int hf_fcs = -1;


/* Initialize the protocol and registered fields */
static int proto_btrfcomm = -1;


/* Initialize the subtree pointers */

static gint ett_btrfcomm = -1;
static gint ett_btrfcomm_ctrl = -1;
static gint ett_addr = -1;
static gint ett_control = -1;
static gint ett_mcc = -1;
static gint ett_ctrl_pn_ci = -1;
static gint ett_ctrl_pn_v24 = -1;


static se_tree_t *dlci_table=NULL;

typedef struct _dlci_stream_t {
	int len;
	int current;
	int is_escaped;
	int mode;
	guint8 *stream_buf;
} dlci_stream_t;

typedef struct _dlci_state_t {
	char do_credit_fc;
	dlci_stream_t direction[2];
} dlci_state_t;

static dissector_handle_t data_handle;
static dissector_handle_t ppp_handle;

static const value_string vs_ctl_pn_i[] = {
	{0x0, "use UIH Frames"},
	/* specified by 07.10, but not used by RFCOMM
	{0x1, "use UI Frames"},
	{0x2, "use I Frames"},
	*/
	{0, NULL}
};

static const value_string vs_ctl_pn_cl[] = {

	{0x0, "no credit based flow control scheme"},
	{0xe, "support of credit based flow control scheme (resp)"},
	{0xf, "support of credit based flow control scheme (req)"},
	/* specified by 07.10. Redefined by RFCOMM 
	{0x0, "type 1 (unstructured octet stream)"},
	{0x1, "type 2 (unstructured octet stream with flow control)"},
	{0x2, "type 3 (uninterruptible framed data)"},
	{0x3, "type 4 (interruptible framed data)"},
	*/
	{0, NULL}
};

static const value_string vs_ctl_rpn_b[] = {
	{0, "2400"},
	{1, "4800"},
	{2, "7200"},
	{3, "9600"},
	{4, "19200"},
	{5, "38400"},
	{6, "57600"},
	{7, "115200"},
	{8, "230400"},
	{0, NULL}
};


static const value_string vs_ctl_rpn_d[] = {
	{0x0, "5"},
	{0x2, "6"},
	{0x1, "7"},
	{0x3, "8"},
	{0, NULL}
};


static const value_string vs_ctl_rpn_s[] = {
	{0, "1"},
	{1, "1.5"},
	{0, NULL}
};


static const true_false_string tfs_ctl_rpn_p = {
	"parity", "no parity"
};


static const value_string vs_ctl_rpn_pt[] = {
	{0, "odd parity"},
	{1, "even parity"},
	{2, "mark parity"},
	{3, "space parity"},
	{0, NULL}
};


static const value_string vs_ctl_rls_l[] = {
	/* L1 == 1, masked 0x0e */
	{0x1, "Overrun error"},
	{0x2, "Parity error"},
	{0x4, "Framing error"},
	{0, NULL}
};


static const value_string vs_rfcomm_addr_d[] = {
        {1, "Server Device"}, 
	{0, "Initiating Device"},
	{0, NULL}
};


static const value_string vs_frame_type[] = {
	/* masked 0xef */
	{0x2f, "Set Asynchronous Balanced Mode (SABM)"},
        {0x63, "Unnumbered Acknowledgement (UA)"},
        {0x0f, "Disconnected Mode (DM)"},
        {0x43, "Disconnect (DISC)"},
        {0xef, "Unnumbered Information with Header check (UIH)"},
	/* specified by 07.10, but not used by RFCOMM
	{0x03, "Unnumbered Information (UI)"},
	*/
        {0, NULL}
};


static const value_string vs_frame_type_short[] = {
	/* masked 0xef */
	{0x2f, "SABM"},
        {0x63, "UA"},
        {0x0f, "DM"},
        {0x43, "DISC"},
        {0xef, "UIH"},
	/* specified by 07.10, but not used by RFCOMM
	{0x03, "UI"},
	*/
        {0, NULL}
};


static const value_string vs_ctl[] = {
       /* masked 0xfc */
	{0x20, "DLC parameter negotiation (PN)"},
	{0x08, "Test Command (Test)"},
	{0x28, "Flow Control On Command (FCon)"},
	{0x18, "Flow Control Off Command (FCoff)"},
	{0x38, "Modem Status Command (MSC)"},
	{0x04, "Non Supported Command Response (NSC)"},
	{0x24, "Remote Port Negotiation Command (RPN)"},
	{0x14, "Remote Line Status Command (RLS)"},
	/* Specified by 07.10, but not used by RFCOMM
	{0x10, "Power Saving Control (PSC)"},
	{0x30, "Multiplexer close down (CLD)"},
	{0x34, "Service Negotiation Command (SNC)"},
	*/
       /* old 
	{0x80, "DLC parameter negotiation (PN)"},
	{0x20, "Test Command (Test)"},
	{0xa0, "Flow Control On Command (FCon)"},
	{0x60, "Flow Control Off Command (FCoff)"},
	{0xe0, "Modem Status Command (MSC)"},
	{0x10, "Non Supported Command Response (NSC)"},
	{0x90, "Remote Port Negotiation Command (RPN)"},
	{0x50, "Remote Line Status Command (RLS)"},
	{0x40, "Power Saving Control (PSC)"},
	{0xc0, "Multiplexer close down (CLD)"},
	{0xd0, "Service Negotiation Command (SNC)"},
	*/
	{0x0, NULL}
};

static const value_string vs_ea[] = {
	{1, "Last field octet"},
	{0, "More field octets following"},
	{0, NULL}
};

static const value_string vs_cr[] = {
	{1, "Command"}, 
	{0, "Response"},
	{0, NULL}
};


static int 
get_le_multi_byte_value(tvbuff_t *tvb, int offset, proto_tree *tree, guint32 *val_ptr, int hf_index)
{
	guint8 byte, bc = 0;
	guint32 val = 0;
	int start_offset=offset;

	do{
		byte = tvb_get_guint8(tvb, offset);
		offset++;
		val |= ((byte>>1)&0xff) << (bc++ * 7);
	}while((byte & 0x1)==0);

	*val_ptr = val;

	if(hf_index>0){
		proto_tree_add_uint(tree, hf_index, tvb, start_offset, offset-start_offset, val);
	}

	return offset;
}


static int
dissect_ctrl_pn(packet_info *pinfo, proto_tree *t, tvbuff_t *tvb, int offset, int cr_flag)
{
	proto_tree *st;
	proto_item *ti;
	int dlci;
	int cl;
	dlci_state_t *dlci_state;
	guint8 flags;

	/* dlci */
	dlci=tvb_get_guint8(tvb, offset)&0x3f;
	proto_tree_add_uint(t, hf_dlci, tvb, offset, 1, dlci);
	offset++;

	/* cl */
	flags=tvb_get_guint8(tvb, offset);
	cl=flags&0xf0;

	ti = proto_tree_add_text(t, tvb, offset, 1, "I1-I4: 0x%x, C1-C4: 0x%x", flags&0xf, (flags>>4)&0xf);
	st = proto_item_add_subtree(ti, ett_ctrl_pn_ci);

	proto_tree_add_item(st, hf_pn_c14, tvb, offset, 1, TRUE);
	proto_tree_add_item(st, hf_pn_i14, tvb, offset, 1, TRUE);
	offset++;

	/* priority */
	proto_tree_add_item(t, hf_priority, tvb, offset, 1, TRUE);
	offset++;

	/* Ack timer */
	proto_tree_add_text(t, tvb, offset, 1, "Acknowledgement timer (T1): %d ms", (guint32)tvb_get_guint8(tvb, offset) * 100);
	offset++;

	/* max frame size */
	proto_tree_add_item(t, hf_max_frame_size, tvb, offset, 2, TRUE);
	offset+=2;

	/* max retrans */
	proto_tree_add_item(t, hf_max_retrans, tvb, offset, 1, TRUE);
	offset++;

	/* error recovery mode */
	proto_tree_add_item(t, hf_error_recovery_mode, tvb, offset, 1, TRUE);
	offset++;

	if(!pinfo->fd->flags.visited){
		dlci_state=se_tree_lookup32(dlci_table, dlci);
		if(!dlci_state){
			dlci_state=se_alloc(sizeof(dlci_state_t));
			dlci_state->do_credit_fc=0;
			dlci_state->direction[0].len=0;
			dlci_state->direction[0].current=-1;
			dlci_state->direction[0].stream_buf=NULL;
			dlci_state->direction[1].len=0;
			dlci_state->direction[1].current=-1;
			dlci_state->direction[1].stream_buf=NULL;
			se_tree_insert32(dlci_table, dlci, dlci_state);
		}
 
		if(!cl){
			/* sender does not do credit based flow control */
			dlci_state->do_credit_fc = 0;
		} else if(cr_flag && (cl==0xf0)){
			/* sender requests to use credit based flow control */
			dlci_state->do_credit_fc |= 1; 
		} else if((!cr_flag) && (cl==0xe0)){
			/* receiver also knows how to handle credit based 
			   flow control */
			dlci_state->do_credit_fc |= 2;
		}
	}
	return offset;
}



#ifdef REMOVED
/* to serve as inspiration when implementing ppp over rfcomm */
static void *my_malloc(int size) {

	void *p = calloc(size, 1);

	if (!p) {
		perror("calloc()");
		exit(1);
	}
	return p;
}


static void stream_buf_init(dlci_stream *s) 
{
	s->len = DEFAULT_STREAM_BUF_SIZE;
	s->mode = 0;
	s->is_escaped = 0;
	s->current = 0;
	s->stream_buf = my_malloc(DEFAULT_STREAM_BUF_SIZE);
}


static void stream_buf_append(rfcomm_packet_state *rps, 
			      dlci_stream *ds, tvbuff_t *tvb, 
			      int off, int len) {

	const guint8 *buf = tvb_get_ptr(tvb, off, len);
	int bytes_left = len, curr = 0;

	if (!ds->stream_buf)
		stream_buf_init(ds);

	for (bytes_left = len; bytes_left > 0 && ds->current < ds->len; bytes_left--) {

		/* fetch next byte */

		guint8 byte = buf[curr++];

		/* eventually check mode here */

		if (byte == 0x7e) {
			if (ds->current == 0)
				continue; /* was start delimeter */

			/* end delimeter*/

			add_ppp_frame(rps, ds->stream_buf, ds->current);

			ds->current = 0;
			ds->is_escaped = 0;
			continue;
		}

		if (ds->is_escaped) {
			ds->stream_buf[ds->current++] = byte ^ 0x20;
			ds->is_escaped = 0;
		} else {
			if (byte == 0x7d)
				ds->is_escaped = 1;
			else
				ds->stream_buf[ds->current++] = byte;		       
		}

	}
}


void add_ppp_frame(rfcomm_packet_state *rps, guint8 *buf, int len) {
	
	rfcomm_ppp_frame *ppp = my_malloc(len + sizeof(rfcomm_ppp_frame));

	ppp->next = NULL;
	ppp->len = len;
	memcpy(ppp + 1, buf, len);

	if (rps->ppp_first)
		rps->ppp_last->next = ppp;
	else
		rps->ppp_first = ppp;

	rps->ppp_last = ppp;
}

/*
int decode_fragments(dlci_stream *pstream, guint8 *buf) {

	int real_len = 0, is_escaped = 0, chunk_index = 0;
	ppp_chunk *chunk_curr = pstream->first;

	for (real_len = 0; chunk_curr;) {

		guint8 byte;

		byte = chunk_curr->buf[chunk_index++];
		if (chunk_index >= chunk_curr->len) {
			chunk_index = 0;
			chunk_curr = chunk_curr->next;
		}
		if (is_escaped) {
			buf[real_len++] = byte ^ 0x20;
			is_escaped = 0;
		} else {
			if (byte == 0x7d)
				is_escaped = 1;
			else
				buf[real_len++] = byte;		       
		}

	}
	return real_len;
}
*/
#endif


static int
dissect_ctrl_msc(proto_tree *t, tvbuff_t *tvb, int offset, int length)
{

	proto_tree *st;
	proto_item *it;
	guint8 status;
	int start_offset;

	proto_tree_add_uint(t, hf_dlci, tvb, offset, 1, tvb_get_guint8(tvb, offset)&0x3f);
	offset++;

	start_offset=offset;
	status = tvb_get_guint8(tvb, offset);
	it = proto_tree_add_text(t, tvb, offset, 1, "V.24 Signals: FC = %d, RTC = %d, RTR = %d, IC = %d, DV = %d", (status >> 1) & 1, 
				 (status >> 2) & 1, (status >> 3) & 1, 
				 (status >> 6) & 1, (status >> 7) & 1);
	st = proto_item_add_subtree(it, ett_ctrl_pn_v24);

	proto_tree_add_item(st, hf_msc_fc, tvb, offset, 1, TRUE);
	proto_tree_add_item(st, hf_msc_rtc, tvb, offset, 1, TRUE);
	proto_tree_add_item(st, hf_msc_rtr, tvb, offset, 1, TRUE);
	proto_tree_add_item(st, hf_msc_ic, tvb, offset, 1, TRUE);
	proto_tree_add_item(st, hf_msc_dv, tvb, offset, 1, TRUE);
	offset++;

	if(length==3){
		proto_tree_add_text(t, tvb, offset, 1, "Break bits B1-B3: 0x%x", (tvb_get_guint8(tvb, offset) & 0xf) >> 1);
		proto_tree_add_item(t, hf_msc_l, tvb, offset, 1, TRUE);
		offset++;
	}

	proto_item_set_len(it, offset-start_offset);

	return offset;
}

static int
dissect_btrfcomm_Address(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 *ea_flagp, guint8 *cr_flagp, guint8 *dlcip)
{
	proto_item *ti;
	proto_tree *addr_tree;
	guint8 dlci, cr_flag, ea_flag, flags;

	flags=tvb_get_guint8(tvb, offset);

	ea_flag=flags&0x01;
	if(ea_flagp){
		*ea_flagp=ea_flag;
	}

	cr_flag=(flags&0x02)?1:0;
	if(cr_flagp){
		*cr_flagp=cr_flag;
	}

	dlci=flags>>2;
	if(dlcip){
		*dlcip=dlci;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1, "Address: E/A flag: %d, C/R flag: %d, DLCI: 0x%02x", ea_flag, cr_flag, dlci);
	addr_tree = proto_item_add_subtree(ti, ett_addr);

	proto_tree_add_uint(addr_tree, hf_dlci, tvb, offset, 1, dlci);
	proto_tree_add_item(addr_tree, hf_cr, tvb, offset, 1, TRUE);
	proto_tree_add_item(addr_tree, hf_ea, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int
dissect_btrfcomm_Control(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 *pf_flagp, guint8 *frame_typep)
{
	proto_item *ti;
	proto_tree *hctl_tree;
	guint8 frame_type, pf_flag, flags;

	flags=tvb_get_guint8(tvb, offset);

	pf_flag=(flags&0x10)?1:0;
	if(pf_flagp){
		*pf_flagp=pf_flag;
	}

	frame_type=flags&0xef;
	if(frame_typep){
		*frame_typep=frame_type;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1, "Control: Frame type: %s (0x%x), P/F flag: %d", val_to_str(frame_type, vs_frame_type, "Unknown"), frame_type, pf_flag);
	hctl_tree = proto_item_add_subtree(ti, ett_control);

	proto_tree_add_item(hctl_tree, hf_pf, tvb, offset, 1, TRUE);
	proto_tree_add_item(hctl_tree, hf_frame_type, tvb, offset, 1, TRUE);

	offset++;
	return offset;
}



static int
dissect_btrfcomm_PayloadLen(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 *frame_lenp)
{
	guint16 frame_len;
	int start_offset=offset;

	frame_len = tvb_get_guint8(tvb, offset);
	offset++;

	if(frame_len&0x01){
		frame_len >>= 1; /* 0 - 127 */
	} else {
		frame_len >>= 1; /* 128 - ... */
		frame_len |= (tvb_get_guint8(tvb, offset)) << 7;
		offset++;
	}

	proto_tree_add_uint(tree, hf_len, tvb, start_offset, offset-start_offset, frame_len);

	if(frame_lenp){
		*frame_lenp=frame_len;
	}

	return offset;
}

static int
dissect_btrfcomm_MccType(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo, guint8 *mcc_cr_flagp, guint8 *mcc_ea_flagp, guint32 *mcc_typep)
{
	int start_offset=offset;
	proto_item *ti;
	proto_tree *mcc_tree;
	guint8 flags, mcc_cr_flag, mcc_ea_flag;
	guint32 mcc_type;

	flags=tvb_get_guint8(tvb, offset);

	mcc_cr_flag=(flags&0x2)?1:0;
	if(mcc_cr_flagp){
		*mcc_cr_flagp=mcc_cr_flag;
	}

	mcc_ea_flag=flags&0x1;
	if(mcc_ea_flagp){
		*mcc_ea_flagp=mcc_ea_flag;
	}


	offset = get_le_multi_byte_value(tvb, offset, tree, &mcc_type, -1);
	mcc_type =(mcc_type>>1)&0x3f; /* shift c/r flag off */
	if(mcc_typep){
		*mcc_typep=mcc_type;
	}


	if(mcc_type){
		if ((check_col(pinfo->cinfo, COL_INFO))){
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(mcc_type, vs_ctl, "Unknown"));
		}
	}


	ti = proto_tree_add_text(tree, tvb, start_offset, offset-start_offset, "Type: %s (0x%x), C/R flag = %d, E/A flag = %d", val_to_str(mcc_type, vs_ctl, "Unknown"), mcc_type, mcc_cr_flag, mcc_ea_flag);
	mcc_tree = proto_item_add_subtree(ti, ett_mcc);

	proto_tree_add_item(mcc_tree, hf_mcc_cmd, tvb, start_offset, offset-start_offset, TRUE);
	proto_tree_add_item(mcc_tree, hf_mcc_cr, tvb, start_offset, 1, TRUE);
	proto_tree_add_item(mcc_tree, hf_mcc_ea, tvb, start_offset, 1, TRUE);

	return offset;
}

/* This dissector is only called from L2CAP.
 * This dissector REQUIRES that pinfo->private_data points to a valid structure
 * since it needs this (future) to track which flow a fragment belongs to
 * in order to do reassembly of ppp streams.
 */
static void
dissect_btrfcomm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *rfcomm_tree;
	proto_tree *ctrl_tree;
	int offset=0;
	int start_offset;
	int fcs_offset;
	guint8 dlci, cr_flag, ea_flag;
	guint8 frame_type, pf_flag;
	guint16 frame_len;
	dlci_state_t *dlci_state;
	btl2cap_data_t *l2cap_data;

	l2cap_data=pinfo->private_data;

	ti = proto_tree_add_item(tree, proto_btrfcomm, tvb, offset, -1, TRUE);
	rfcomm_tree = proto_item_add_subtree(ti, ett_btrfcomm);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RFCOMM");
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_str(pinfo->cinfo, COL_INFO, pinfo->p2p_dir == P2P_DIR_SENT ? "Sent " : "Rcvd ");
	}


	/* flags and dlci */
	offset=dissect_btrfcomm_Address(tvb, offset, rfcomm_tree, &ea_flag, &cr_flag, &dlci);


	dlci_state=se_tree_lookup32(dlci_table, dlci);
	if(!dlci_state){
		dlci_state=se_alloc(sizeof(dlci_state_t));
		dlci_state->do_credit_fc=0;
		dlci_state->direction[0].len=0;
		dlci_state->direction[0].current=-1;
		dlci_state->direction[0].stream_buf=NULL;
		dlci_state->direction[1].len=0;
		dlci_state->direction[1].current=-1;
		dlci_state->direction[1].stream_buf=NULL;
		se_tree_insert32(dlci_table, dlci, dlci_state);
	}
 
	/* pf and frame type */
	offset=dissect_btrfcomm_Control(tvb, offset, rfcomm_tree, &pf_flag, &frame_type);


	if ((check_col(pinfo->cinfo, COL_INFO))){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s DLCI=%d ", val_to_str(frame_type, vs_frame_type_short, "Unknown"), dlci);	
	}


	/* payload length */
	offset=dissect_btrfcomm_PayloadLen(tvb, offset, rfcomm_tree, &frame_len);


	/* UID frame */ 
	if(frame_type==0xef && dlci && pf_flag) {
		if ((check_col(pinfo->cinfo, COL_INFO))){
			col_append_str(pinfo->cinfo, COL_INFO, "UID ");
		}
		if((dlci_state->do_credit_fc&0x03)==0x03){
/*QQQ use tvb_length_remaining()==2 and !frame_len as heuristics to catch this as well? */
			/* add credit based flow control byte */
			proto_tree_add_item(rfcomm_tree, hf_fc_credits, tvb, offset, 1, TRUE);
			offset++;
		}
	}


	fcs_offset = offset + frame_len;


	/* multiplexer control command */
	if((!dlci)&&frame_len){
		proto_item *mcc_ti;
		guint32 mcc_type, length;
		guint8 mcc_cr_flag, mcc_ea_flag;
		int start_offset=offset;

		if ((check_col(pinfo->cinfo, COL_INFO))){
			col_append_str(pinfo->cinfo, COL_INFO, "MPX_CTRL ");
		}

		mcc_ti = proto_tree_add_text(rfcomm_tree, tvb, offset, 1, "Multiplexer Control Command");
		ctrl_tree = proto_item_add_subtree(mcc_ti, ett_btrfcomm_ctrl);

		/* mcc type */
		offset=dissect_btrfcomm_MccType(tvb, offset, ctrl_tree, pinfo, &mcc_cr_flag, &mcc_ea_flag, &mcc_type);

		/* len */
		offset = get_le_multi_byte_value(tvb, offset, ctrl_tree, &length, hf_mcc_len);

		switch(mcc_type) {
		case 0x20: /* Parameter Negotiation */
			if ((check_col(pinfo->cinfo, COL_INFO))){
				col_append_str(pinfo->cinfo, COL_INFO, "Parameter Negotiation ");
			}
			dissect_ctrl_pn(pinfo, ctrl_tree, tvb, offset, mcc_cr_flag);
			break;
		case 0x38: /* Model Status Command */
			if ((check_col(pinfo->cinfo, COL_INFO))){
				col_append_str(pinfo->cinfo, COL_INFO, "Model Status Command ");
			}
			dissect_ctrl_msc(ctrl_tree, tvb, offset, length);
			break;
		}
		offset += length;

		proto_item_set_len(mcc_ti, offset-start_offset);
	}


	/* dissect everything as "data" for now until we get examples of
	 * ppp over rfcomm
	 *
	 * it might be sufficient to just check if the first byte is the 0x7e
	 * delimeter and if so just unescape it all into an ep_alloc() buffer
	 * and pass it to ppp.
	 */	
	if(dlci&&frame_len){
		tvbuff_t *next_tvb;
		next_tvb = tvb_new_subset(tvb, offset, frame_len, frame_len);
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}


	proto_tree_add_item(rfcomm_tree, hf_fcs, tvb, fcs_offset, 1, TRUE);


#ifdef REMOVED
/* to serve as inspiration when implementing ppp over rfcomm */
	rfcomm_packet_state *rps = p_get_proto_data(pinfo->fd, proto_btrfcomm);
	proto_item *ti_main, *ti_addr, *ti_hctl, *ti;
	proto_tree *st, *st_ctrl, *st_addr, *st_hctl;
	int size, off, off_fcs

	if (rps == NULL) {
		rps = my_malloc(sizeof(rfcomm_packet_state));
		rps->ppp_first = NULL;
		rps->ppp_last = NULL;
		p_add_proto_data(pinfo->fd, proto_btrfcomm, rps);	
	}



	if(dlci&&frame_len){
		tvbuff_t *next_tvb;

		if (frame_type == 0xef && !pinfo->fd->flags.visited) {
			dlci_stream *ds;

			ds = &state[dlci].direction[cr_flag];
			stream_buf_append(rps, ds, tvb, off, frame_len);
		}		

		if (rps && rps->ppp_first) {
			rfcomm_ppp_frame *p;

			for (p = rps->ppp_first; p; p = p->next) {
				next_tvb = tvb_new_real_data((guint8 *) (p + 1), p->len, p->len);
				tvb_set_child_real_data_tvbuff(tvb, next_tvb);
				add_new_data_source(pinfo, next_tvb, "Reassembled PPP frame");
				call_dissector(ppp_handle, next_tvb, pinfo, tree);
			}
		} else {
			next_tvb = tvb_new_subset(tvb, off, frame_len, frame_len);
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}
	}
#endif
}


void
proto_register_btrfcomm(void)
{                   
	static hf_register_info hf[] = {
		{&hf_dlci,
			{"DLCI", "btrfcomm.dlci",
			FT_UINT8, BASE_HEX, NULL, 0,          
			"RFCOMM DLCI", HFILL}
		},
		{&hf_priority,
			{"Priority", "btrfcomm.priority",
			FT_UINT8, BASE_DEC, NULL, 0x3f,          
			"Priority", HFILL}
		},
		{&hf_max_frame_size,
			{"Max Frame Size", "btrfcomm.max_frame_size",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Maximum Frame Size", HFILL}
		},
		{&hf_max_retrans,
			{"Max Retrans", "btrfcomm.max_retrans",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Maximum number of retransmissions", HFILL}
		},
		{&hf_error_recovery_mode,
			{"Error Recovery Mode", "btrfcomm.error_recovery_mode",
			FT_UINT8, BASE_DEC, NULL, 0x07,
			"Error Recovery Mode", HFILL}
		},
		{&hf_ea,
			{"EA Flag", "btrfcomm.ea",
			FT_UINT8, BASE_HEX, VALS(vs_ea), 0x1,
			"EA flag (should be always 1)", HFILL}
		},
		{&hf_cr,
			{"C/R Flag", "btrfcomm.cr",
			FT_UINT8, BASE_HEX, VALS(vs_cr), 0x2,
			"Command/Response flag", HFILL}
		},
		{&hf_mcc_ea,
			{"EA Flag", "btrfcomm.mcc.ea",
			FT_UINT8, BASE_HEX, VALS(vs_ea), 0x1,
			"EA flag (should be always 1)", HFILL}
		},
		{&hf_mcc_cr,
			{"C/R Flag", "btrfcomm.mcc.cr",
			FT_UINT8, BASE_HEX, VALS(vs_cr), 0x2,
			"Command/Response flag", HFILL}
		},
		{&hf_mcc_cmd,
			{"C/R Flag", "btrfcomm.mcc.cmd",
			FT_UINT8, BASE_HEX, VALS(vs_ctl), 0xfc,
			"Command/Response flag", HFILL}
		},
		{&hf_frame_type,
			{"Frame type", "btrfcomm.frame_type",
			FT_UINT8, BASE_HEX, VALS(vs_frame_type), 0xef,          
			"Command/Response flag", HFILL}
		},
		{&hf_pf,
			{"P/F flag", "btrfcomm.pf",
			FT_UINT8, BASE_HEX, NULL, 0x10,          
			"Poll/Final bit", HFILL}
		},
		{&hf_pn_i14,
			{"Type of frame", "btrfcomm.pn.i",
			FT_UINT8, BASE_HEX, VALS(vs_ctl_pn_i), 0x0f,          
			"Type of information frames used for that particular DLCI", 
			 HFILL}
		},
		{&hf_pn_c14,
			{"Convergence layer", "btrfcomm.pn.cl",
			FT_UINT8, BASE_HEX, VALS(vs_ctl_pn_cl), 0xf0,          
			"Convergence layer used for that particular DLCI", HFILL}
		},
		{&hf_len,
			{"Payload length", "btrfcomm.len",
			FT_UINT16, BASE_DEC, NULL, 0,          
			"Frame length", HFILL}
		},		
		{&hf_mcc_len,
			{"MCC Length", "btrfcomm.mcc.len",
			FT_UINT16, BASE_DEC, NULL, 0,          
			"Length of MCC data", HFILL}
		},		
		{&hf_fcs,
		         {"Frame Check Sequence", "btrfcomm.fcs",
			 FT_UINT8, BASE_HEX, NULL, 0,
			  "Checksum over frame", HFILL}
		},
		{&hf_msc_fc,
		         {"Flow Control (FC)", "btrfcomm.msc.fc",
			 FT_UINT8, BASE_HEX, NULL, 0x2,
			  "Flow Control", HFILL}
		},
		{&hf_msc_rtc,
		         {"Ready To Communicate (RTC)", "btrfcomm.msc.rtc",
			 FT_UINT8, BASE_HEX, NULL, 0x4,
			  "Ready To Communicate", HFILL}
		},
		{&hf_msc_rtr,
		         {"Ready To Receive (RTR)", "btrfcomm.msc.rtr",
			 FT_UINT8, BASE_HEX, NULL, 0x8,
			  "Ready To Receive", HFILL}
		},
		{&hf_msc_ic,
		         {"Incoming Call Indicator (IC)", "btrfcomm.msc.ic",
			 FT_UINT8, BASE_HEX, NULL, 0x40,
			  "Incoming Call Indicator", HFILL}
		},
		{&hf_msc_dv,
		         {"Data Valid (DV)", "btrfcomm.msc.dv",
			 FT_UINT8, BASE_HEX, NULL, 0x80,
			  "Data Valid", HFILL}
		},
		{&hf_msc_l,
		         {"Length of break in units of 200ms", "btrfcomm.msc.bl",
			 FT_UINT8, BASE_DEC, NULL, 0xf0,
			  "Length of break in units of 200ms", HFILL}
		},
		{&hf_fc_credits,
		         {"Credits", "btrfcomm.credits",
			 FT_UINT8, BASE_DEC, NULL, 0,
			  "Flow control: number of UIH frames allowed to send", HFILL}
		}

	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_btrfcomm,
		&ett_btrfcomm_ctrl,
		&ett_addr,
		&ett_control,
		&ett_mcc,
		&ett_ctrl_pn_ci,
		&ett_ctrl_pn_v24
	};

	/* Register the protocol name and description */
	proto_btrfcomm = proto_register_protocol("Bluetooth RFCOMM Packet", "RFCOMM", "btrfcomm");

	register_dissector("btrfcomm", dissect_btrfcomm, proto_btrfcomm);
	
	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_btrfcomm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	dlci_table=se_tree_create(SE_TREE_TYPE_RED_BLACK, "RFCOMM dlci table");
}


void
proto_reg_handoff_btrfcomm(void)
{
	dissector_handle_t btrfcomm_handle;

	btrfcomm_handle = find_dissector("btrfcomm");
	dissector_add("btl2cap.psm", BTL2CAP_PSM_RFCOMM, btrfcomm_handle);

	data_handle = find_dissector("data");
	ppp_handle = find_dissector("ppp_hdlc");
}
