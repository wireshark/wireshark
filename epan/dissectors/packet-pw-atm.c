/* packet-pw-atm.c
 * Routines for ATM PW dissection: it should be conform to RFC 4717.
 *
 * Copyright 2009 _FF_, _ATA_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
 * Artem Tamazov <artem [dot] tamazov [at] tellabs [dot] com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
    DONE:
        - ATM N-to-One Cell Mode (with CW)
        - ATM N-to-One Cell Mode (no CW)
        - ATM One-to-One Cell Mode
        - ATM AAL5 SDU Mode
        - ATM AAL5 PDU Mode
*/

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <wiretap/wtap.h> /*for atm pseudo header*/
#include "packet-mpls.h"
#include "packet-atm.h"
#include "packet-pw-atm.h"
#include "packet-pw-common.h"

void proto_register_pw_atm_ata(void);
void proto_reg_handoff_pw_atm_ata(void);
void proto_register_pw_atm(void);
void proto_reg_handoff_pw_atm(void);

static gint proto_n1_nocw = -1;
static gint proto_n1_cw = -1;
static gint proto_11_or_aal5_pdu = -1;
static gint proto_aal5_sdu = -1;
/* subordinate dissectors: */
static gint proto_control_word = -1;
static gint proto_cell_header = -1;
static gint proto_cell = -1;

static gint ett_encaps = -1;
static gint ett_cw = -1;
static gint ett_cell_header = -1;
static gint ett_cell = -1;

static int hf_pw_type_n1_cw = -1;
static int hf_pw_type_n1_nocw = -1;
static int hf_pw_type_11_vcc = -1;
static int hf_pw_type_11_vpc = -1;
static int hf_pw_type_aal5_sdu = -1;
static int hf_pw_type_aal5_pdu = -1;

static int hf_cell_h_vpi = -1;
static int hf_cell_h_vci = -1;
static int hf_cell_h_pti = -1;
static int hf_cell_h_clp = -1;
static int hf_cell_h_m = -1;
static int hf_cell_h_v = -1;
static int hf_cell_h_rsv = -1;
static int hf_aal5_pdu_rsv = -1;
static int hf_aal5_pdu_u = -1;
static int hf_aal5_pdu_e = -1;

static int hf_cw_bits03 = -1;
static int hf_pref_cw_rsv = -1;
static int hf_generic_cw_rsv = -1;
static int hf_pref_cw_flags = -1;
static int hf_pref_cw_a5s_t = -1;
static int hf_pref_cw_a5s_e = -1;
static int hf_pref_cw_a5s_c = -1;
static int hf_pref_cw_a5s_u = -1;
static int hf_pref_cw_len = -1;
static int hf_pref_cw_rsvlen = -1;
static int hf_cw_seq = -1;
static int hf_n1_cw_ncells = -1;
static int hf_n1_nocw_ncells = -1;
static int hf_11_ncells = -1;
static int hf_gen_cw_atmbyte = -1;
static int hf_cell_payload_len = -1;

static expert_field ei_cell_h_v_not_one = EI_INIT;
static expert_field ei_cell_h_pti_undecoded = EI_INIT;
static expert_field ei_pref_cw_flags = EI_INIT;
static expert_field ei_cell_h_v_not_zero = EI_INIT;
static expert_field ei_pw_payload_size_invalid_note = EI_INIT;
static expert_field ei_pw_payload_size_invalid_error = EI_INIT;
static expert_field ei_cell_h_pti_malformed = EI_INIT;
static expert_field ei_cell_h_rsv = EI_INIT;
static expert_field ei_cell_broken = EI_INIT;
static expert_field ei_cell_h_m = EI_INIT;
static expert_field ei_cw_bits03 = EI_INIT;
static expert_field ei_pw_packet_size_too_small = EI_INIT;
static expert_field ei_pref_cw_len = EI_INIT;

static dissector_handle_t dh_cell;
static dissector_handle_t dh_cell_header;
static dissector_handle_t dh_control_word;
static dissector_handle_t dh_atm_truncated;
static dissector_handle_t dh_atm_untruncated;
static dissector_handle_t dh_atm_oam_cell;
static dissector_handle_t dh_padding;
static dissector_handle_t dh_data;

#define PTI_IS_ADMIN(pti) ((pti) == 4 || (pti) == 5 || (pti) == 6)  /*see atm_pt_vals[]*/

#define MODE_11(mode) 			(PWATM_MODE_11_VCC == (mode) || PWATM_MODE_11_VPC == (mode))
#define MODE_N1(mode) 			(PWATM_MODE_N1_NOCW == (mode)|| PWATM_MODE_N1_CW == (mode))
#define MODE_11_OR_AAL5_PDU(mode)   	(MODE_11(mode) || PWATM_MODE_AAL5_PDU == (mode))

#define VALUE_SELECTOR_VPC_VCC_PDU(mode,val_vpc,val_vcc,val_pdu)\
	((PWATM_MODE_11_VPC == (mode))				\
		? (val_vpc)					\
		: ((PWATM_MODE_11_VCC == (mode))		\
			? (val_vcc)				\
			: ((PWATM_MODE_AAL5_PDU == (mode))	\
				? (val_pdu)			\
				: 0				\
			  )					\
		  )						\
	)

#define UPDATE_CUMULATIVE_VALUE(cumulative_val,new_val)\
	do\
	{\
		if (-2 >= (cumulative_val))\
		{\
		}\
		else if (-1 == (cumulative_val))\
		{\
			(cumulative_val) = (new_val);\
		}\
		else if ((new_val) != (cumulative_val))\
		{\
			(cumulative_val) = -2;\
		}\
	}\
	while(0)

#define SIZEOF_ATM_CELL_PAYLOAD      48
#define SIZEOF_N1_PW_CELL_HEADER      4
#define SIZEOF_11_VCC_PW_CELL_HEADER  1
#define SIZEOF_11_VPC_PW_CELL_HEADER  3
#define SIZEOF_N1_PW_CELL	(SIZEOF_ATM_CELL_PAYLOAD+SIZEOF_N1_PW_CELL_HEADER)
#define SIZEOF_11_VCC_PW_CELL	(SIZEOF_ATM_CELL_PAYLOAD+SIZEOF_11_VCC_PW_CELL_HEADER)
#define SIZEOF_11_VPC_PW_CELL	(SIZEOF_ATM_CELL_PAYLOAD+SIZEOF_11_VPC_PW_CELL_HEADER)

const char pwc_longname_pw_atm_n1_cw[]          = "MPLS PW ATM N-to-One encapsulation, with CW";
const char pwc_longname_pw_atm_n1_nocw[]        = "MPLS PW ATM N-to-One encapsulation, no CW";
const char pwc_longname_pw_atm_11_or_aal5_pdu[] = "MPLS PW ATM One-to-One or AAL5 PDU encapsulation";
const char pwc_longname_pw_atm_aal5_sdu[]       = "MPLS PW ATM AAL5 CPCS-SDU mode encapsulation";

static const char longname_pw_atm_11_vcc[]      = "MPLS PW ATM One-to-One VCC Cell Transport";
static const char longname_pw_atm_11_vpc[]      = "MPLS PW ATM One-to-One VPC Cell Transport";
static const char longname_pw_atm_aal5_pdu[]    = "MPLS PW ATM AAL5 PDU encapsulation";

static const char shortname_n1_cw[]             = "MPLS PW ATM N:1 CW";
static const char shortname_n1_nocw[]           = "MPLS PW ATM N:1 no CW";
static const char shortname_11_or_aal5_pdu[]    = "MPLS PW ATM 1:1 / AAL5 PDU";
static const char shortname_11_vpc[]            = "MPLS PW ATM 1:1 VPC";
static const char shortname_11_vcc[]            = "MPLS PW ATM 1:1 VCC";
static const char shortname_aal5_sdu[]          = "MPLS PW ATM AAL5 SDU";
static const char shortname_aal5_pdu[]          = "MPLS PW ATM AAL5 PDU";

/*
 * These options are needed to support Nokia AXE and stuff alike.
 * Note that these options will affect PW type auto-guessing, if such heuristic
 * implemented in the future.
 */
static gboolean pref_n1_cw_allow_cw_length_nonzero       = FALSE;
static gboolean pref_n1_cw_extend_cw_length_with_rsvd    = FALSE;
static gboolean pref_aal5_sdu_allow_cw_length_nonzero    = FALSE;
static gboolean pref_aal5_sdu_extend_cw_length_with_rsvd = FALSE;


static int
pw_cell_size(const pwatm_mode_t mode, const pwatm_submode_t submode)
{
	switch (mode)
	{
	case PWATM_MODE_N1_NOCW:
	case PWATM_MODE_N1_CW:
		return SIZEOF_N1_PW_CELL;
	case PWATM_MODE_11_VCC:
		return SIZEOF_11_VCC_PW_CELL;
	case PWATM_MODE_11_VPC:
		return SIZEOF_11_VPC_PW_CELL;
	case PWATM_MODE_AAL5_PDU:
		/* AAL5 PDU size is n*48 bytes */
		return SIZEOF_ATM_CELL_PAYLOAD;
	case PWATM_MODE_AAL5_SDU:
		if (PWATM_SUBMODE_ADMIN_CELL == submode)
		{
			return SIZEOF_N1_PW_CELL; /*n:1 encapsulation is used for admin cells*/
		}
		else
		{
			DISSECTOR_ASSERT_NOT_REACHED();
			return 0;
		}
	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		return 0;
	}
}

static int
pw_cell_header_size(const pwatm_mode_t mode, const pwatm_submode_t submode)
{
	switch (mode)
	{
	case PWATM_MODE_N1_NOCW:
	case PWATM_MODE_N1_CW:
		return SIZEOF_N1_PW_CELL_HEADER;
	case PWATM_MODE_11_VCC:
		return SIZEOF_11_VCC_PW_CELL_HEADER;
	case PWATM_MODE_11_VPC:
		return SIZEOF_11_VPC_PW_CELL_HEADER;
	case PWATM_MODE_AAL5_SDU:
		if (PWATM_SUBMODE_ADMIN_CELL == submode)
		{
			return SIZEOF_N1_PW_CELL_HEADER; /*n:1 encapsulation is used for admin cells*/
		}
		else
		{
			DISSECTOR_ASSERT_NOT_REACHED();
			return 0;
		}
	case PWATM_MODE_AAL5_PDU: /*not applicable*/
	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		return 0;
	}
}

static int
number_of_cells(const pwatm_mode_t mode
		,const pwatm_submode_t submode
		,const gint payload_size
		,gint* const remainder_size)
{
	int cells;

	DISSECTOR_ASSERT(payload_size >= 0);

	switch (mode)
	{
	case PWATM_MODE_N1_NOCW:
	case PWATM_MODE_N1_CW:
	case PWATM_MODE_11_VCC:
	case PWATM_MODE_11_VPC:
	case PWATM_MODE_AAL5_PDU:
		cells = payload_size / pw_cell_size(mode, submode);
		*remainder_size = payload_size - (cells * pw_cell_size(mode, submode));
		return cells;
	case PWATM_MODE_AAL5_SDU:
		if (PWATM_SUBMODE_ADMIN_CELL == submode)
		{
			cells = payload_size / pw_cell_size(mode, submode);
			if (cells > 1) cells = 1; /*max. 1 admin cell may be present in aal5 sdu mode */
			*remainder_size = payload_size - (cells * pw_cell_size(mode, submode));
			return cells;
		}
		else
		{
			/*not applicable*/
		}
		/*fallthrough*/
	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		*remainder_size = payload_size;
		return 0;
	}

}


static void
col_append_pw_info(packet_info * pinfo
	,const int payload_size
	,const int cells
	,const int padding_size
	,pwatm_private_data_t * pd)
{
	if (pd->props & PWC_ANYOF_CW_BAD)
	{
		col_append_str(pinfo->cinfo, COL_INFO, "CW:Bad");
	}

	if (pd->props & PWC_PAY_SIZE_BAD)
	{
		if (pd->props & PWC_ANYOF_CW_BAD)
		{
			col_append_str(pinfo->cinfo, COL_INFO, ", ");
		}
		col_append_str(pinfo->cinfo, COL_INFO, "Payload size:Bad, ");
		col_append_fstr(pinfo->cinfo, COL_INFO, "%d byte%s"
			,(int)payload_size
			,plurality(payload_size, "", "s"));
	}

	if (pd->props == 0) /*omit "atm cells" etc if something is wrong*/
	{
		/* number of cells may be not known */
		if (cells >=0)
			col_append_fstr(pinfo->cinfo, COL_INFO, "%d ATM cell%s"
				,cells
				,plurality(cells, "", "s"));
		/*
		 * Display ATM-specific attributes which are the same
		 * across all the cells in the pw packet.
		 * Meanings of values:
		 *   (-1) unknown - not displayed,
		 *   (-2) "not the same in all cells" - not displayed
		 *   positive values - ok, displayed
		 */
		if (pd->cumulative.vpi >= 0)
			col_append_fstr(pinfo->cinfo, COL_INFO, ", VPI:%.4d", pd->cumulative.vpi);
		if (pd->cumulative.vci >= 0)
			col_append_fstr(pinfo->cinfo, COL_INFO, ", VCI:%.5d", pd->cumulative.vci);
		if (pd->cumulative.pti >= 0)
			col_append_fstr(pinfo->cinfo, COL_INFO, ", PTI:%.1d", pd->cumulative.pti);
		if (pd->cumulative.clp >= 0)
			col_append_fstr(pinfo->cinfo, COL_INFO, ", CLP:%.1d", pd->cumulative.clp);
	}

	if (padding_size != 0)
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %d padding"
			,(int)padding_size);
	}
}


static void
prepare_pseudo_header_atm(
	union wtap_pseudo_header * const ph,
	const pwatm_private_data_t * const pdata,
	const guint aal)
{
	DISSECTOR_ASSERT(NULL != pdata);
	DISSECTOR_ASSERT(NULL != ph);

	memset(ph, 0 , sizeof(*ph));  /* it is OK to clear unknown values */
	ph->atm.flags		= 0; /* status flags */
	ph->atm.aal		= aal;
	ph->atm.type		= TRAF_UNKNOWN;
	ph->atm.subtype		= TRAF_ST_UNKNOWN;
	ph->atm.vpi		= (pdata->vpi >= 0) ? pdata->vpi : 0 /*unknown*/;
	ph->atm.vci		= (pdata->vci >= 0) ? pdata->vci : 0 /*unknown*/;
	ph->atm.aal2_cid	= 0; /*not applicable*//* channel id */
	ph->atm.channel		= 0; /*unknown*//* link: 0 for DTE->DCE, 1 for DCE->DTE */
	ph->atm.cells		= 0; /*zero indicates that we do not have trailer info*/
	/*user-to-user indicator & CPI*/
	ph->atm.aal5t_u2u	= 0; /* all bits unknown except lsb of UU */
	if (pdata->aal5_sdu_frame_relay_cr_bit)
	{ /* Let's give Frame Relay C/R bit to ATM dissector.*/
		ph->atm.aal5t_u2u |= (1<<8); /*UU octet is at << 8 in aal5t_u2u*/
	}
	ph->atm.aal5t_len	= 0; /*unknown*//* length of the packet from trailer*/
	ph->atm.aal5t_chksum	= 0; /*unknown*//* checksum for AAL5 packet from trailer */
	return;
}


static void
dissect_payload_and_padding(
	tvbuff_t     * tvb
	,packet_info * pinfo
	,proto_tree  * tree
	,const gint    payload_size
	,const gint    padding_size
	,pwatm_private_data_t * pd)
{
	int                    dissected;
	tvbuff_t             * tvb_2;

	for(dissected = 0, pd->pw_cell_number = 0;
		payload_size > dissected;
		++(pd->pw_cell_number))
	{
		tvb_2 = tvb_new_subset_remaining(tvb, dissected);
		dissected += call_dissector_with_data(dh_cell_header, tvb_2, pinfo, tree, pd);

		tvb_2 = tvb_new_subset_remaining(tvb, dissected);

		/*dissect as oam for specific vci/pti, just like atm dissector does*/
		if ((pd->vci >= 0) && (pd->pti >=0))
		{
			if (atm_is_oam_cell(pd->vci, pd->pti))
			{
				pd->cell_mode_oam = TRUE;
			}
		}

		if (pd->cell_mode_oam)
		{
			union wtap_pseudo_header * pseudo_header_save;
			union wtap_pseudo_header   ph;
			tvbuff_t* tvb_3;
			int bytes_to_dissect;
			/* prepare buffer for old-style dissector */
			/* oam cell is always 48 bytes, but payload_size maybe too small */
			if ((payload_size - dissected) >= SIZEOF_ATM_CELL_PAYLOAD)
				bytes_to_dissect = SIZEOF_ATM_CELL_PAYLOAD;
			else
				bytes_to_dissect = (payload_size - dissected);
			tvb_3 = tvb_new_subset(tvb_2, 0, bytes_to_dissect, -1);
			/*aal5_sdu: disable filling columns after 1st (valid) oam cell*/
			if (pd->mode == PWATM_MODE_AAL5_SDU && (pd->pw_cell_number > 0))
			{
				pd->enable_fill_columns_by_atm_dissector = FALSE;
			}
			/* save & prepare new pseudo header for atm aal5 decoding */
			pseudo_header_save = pinfo->pseudo_header;
			pinfo->pseudo_header = &ph;
			prepare_pseudo_header_atm(&ph, pd, AAL_OAMCELL);

			call_dissector_with_data(dh_atm_oam_cell, tvb_3, pinfo, tree, pd);
			dissected += bytes_to_dissect;
			/* restore pseudo header */
			pinfo->pseudo_header = pseudo_header_save;
		}
		else
		{
			dissected += call_dissector(dh_cell, tvb_2, pinfo, tree);
		}
	}

	if (padding_size != 0)
	{
		tvb_2 = tvb_new_subset_remaining(tvb, -padding_size);
		call_dissector(dh_padding, tvb_2, pinfo, tree);
	}
	return;
}


static gboolean
too_small_packet_or_notpw(tvbuff_t * tvb
	,packet_info * pinfo
	,proto_tree  * tree
	,const int     proto_handler
	,const char  * const proto_name_column)
{
	gint packet_size;
	packet_size = tvb_reported_length_remaining(tvb, 0);
	/*
	 * FIXME
	 * "4" below should be replaced by something like "min_packet_size_this_dissector"
	 * Also call to dissect_try_cw_first_nibble() should be moved before this block
	 */
	if (packet_size < 4) /* 4 is smallest size which may be sensible (for PWACH dissector) */
	{
		proto_item  * item;
		item = proto_tree_add_item(tree, proto_handler, tvb, 0, -1, ENC_NA);
		expert_add_info_format(pinfo, item, &ei_pw_packet_size_too_small,
				       "PW packet size (%d) is too small to carry sensible information"
				       ,(int)packet_size);
		/* represent problems in the Packet List pane */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_column);
		col_set_str(pinfo->cinfo, COL_INFO, "Malformed: PW packet is too small");
		return TRUE;
	}
	if (dissect_try_cw_first_nibble(tvb, pinfo, tree))
	{
		return TRUE;
	}
	return FALSE;
}


/*
 * NOTE. RFC describes ATM-specific byte in a cumbersome way.
 * It is a part of CW, but at the same time, it must be repeated
 * with each cell, _except_ first.
 *
 * Alternatively, ATM-specific byte may be considered as part of
 * PW payload (i.e., as part of pw atm cell header), so we can say that
 * it is being repeated with each cell.
 *
 * This dissector is written according to the latter consideration.
 */
static void
dissect_11_or_aal5_pdu(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	const char           * proto_name_column;
	const char           * proto_name_tree = NULL;
	gint                   payload_size;
	int                    cells;
	pwatm_private_data_t   pd              = PWATM_PRIVATE_DATA_T_INITIALIZER;

	proto_name_column = &shortname_11_or_aal5_pdu[0];
	if (too_small_packet_or_notpw(tvb, pinfo, tree, proto_11_or_aal5_pdu, proto_name_column))
	{
		return;
	}
	pd.packet_size = tvb_reported_length_remaining(tvb, 0);

	/*
	 * Guess encapsulation mode according to M & V bits from the 3rd byte of CW.
	 * Also adjust protocol name strings.
	 */
	{
		guint8 third_byte;
		third_byte = tvb_get_guint8(tvb, 3);
		if (0 == (third_byte & 0x80 /*generic_cw.m*/))
		{ /*1:1 modes*/
			if (0 != (third_byte & 0x40 /*generic_cw.v*/))
			{
				pd.mode = PWATM_MODE_11_VPC;
				proto_name_column = &shortname_11_vpc[0];
				proto_name_tree = &longname_pw_atm_11_vpc[0];
			}
			else
			{
				pd.mode = PWATM_MODE_11_VCC;
				proto_name_column = &shortname_11_vcc[0];
				proto_name_tree = &longname_pw_atm_11_vcc[0];
			}
		}
		else
		{
			pd.mode = PWATM_MODE_AAL5_PDU;
			proto_name_column = &shortname_aal5_pdu[0];
			proto_name_tree = &longname_pw_atm_aal5_pdu[0];
		}
	}


	/* check how "good" is this packet */
	pd.props = PWC_PACKET_PROPERTIES_T_INITIALIZER;
	if (0 != (tvb_get_guint8(tvb, 0) & 0xf0 /*bits03*/))
	{
		pd.props |= PWC_CW_BAD_BITS03;
	}
	if (0 != (tvb_get_guint8(tvb, 0) & 0x0f /*generic_cw.rsvd*/))
	{
		pd.props |= PWC_CW_BAD_RSV;
	}

	/*
	 * Do not dissect and validate atm-specific byte (3rd byte of CW).
	 * It will be dissected/validated as pw cell header.
	 */

	/*
	 * Decide about payload length and padding.
	 *
	 * Is padding allowed?
	 * 	eth header length  == 14
	 * 	mpls label length  ==  4
	 * 	cw length 	   ==  4
	 * 	min payload length == 48
	 * 	=> 14 + 4 + 4 + 48 == 70
	 *        => 70 >= 64
	 *	    => no padding allowed
	 */
	if (MODE_11(pd.mode))
	{
		gint bad_padding_size;
		payload_size = pd.packet_size - (PWC_SIZEOF_CW-1);
		cells = number_of_cells(pd.mode, pd.submode, payload_size, &bad_padding_size);
		if ((0 == cells) || (0 != bad_padding_size))
		{
			pd.props |= PWC_PAY_SIZE_BAD;
		}
	}
	else
	{ /*aal5_pdu mode*/
		gint bad_padding_size;
		payload_size = pd.packet_size - PWC_SIZEOF_CW;
		cells = number_of_cells(pd.mode, pd.submode, payload_size, &bad_padding_size);
		/* at least 1 cell must be present in the packet in this mode*/
		if ((1 > cells) || (0 != bad_padding_size))
		{
			pd.props |= PWC_PAY_SIZE_BAD;
		}
		cells = -1; /*this value not needed anymore, suppress pinting of it*/
	}

	if (PWATM_MODE_AAL5_PDU == pd.mode)
	{
		/* sub-dissectors _may_ overwrite columns in aal5_pdu mode */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_column);
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_pw_info(pinfo, payload_size, cells, 0, &pd);
	}

	{
		proto_item* item;
		item = proto_tree_add_item(tree, proto_11_or_aal5_pdu, tvb, 0, -1, ENC_NA);
		/*overwrite heading line*/
		proto_item_set_text(item, proto_name_tree, 0/*-warn gcc 3.4.4*/);
		pwc_item_append_text_n_items(item, cells, "good ATM cell");
		{
			proto_tree* tree2;
			tree2 = proto_item_add_subtree(item, ett_encaps);
			{
				proto_item* item2;
				item2 = proto_tree_add_boolean(tree2
					,VALUE_SELECTOR_VPC_VCC_PDU(pd.mode
						,hf_pw_type_11_vpc
						,hf_pw_type_11_vcc
						,hf_pw_type_aal5_pdu)
					,tvb, 0, 0, TRUE);
				PROTO_ITEM_SET_GENERATED(item2);
				if (MODE_11(pd.mode))
				{
					item2 = proto_tree_add_int(tree2, hf_11_ncells, tvb, 0, 0, cells);
					PROTO_ITEM_SET_GENERATED(item2);
				}
			}
		}
		if (pd.props & PWC_PAY_SIZE_BAD)
		{
			expert_add_info_format(pinfo, item, &ei_pw_payload_size_invalid_error,
				"PW payload size (%d) must be <> 0 and multiple of %d",
				(int)payload_size, pw_cell_size(pd.mode, pd.submode));
			if ((payload_size != 0) && MODE_11(pd.mode))
			{
				expert_add_info_format(pinfo, item, &ei_cell_broken,
					"PW ATM cell [%.3d] is broken", (int)cells);
			}
		}
	}

	{
		tvbuff_t* tvb_2;
		tvb_2 = tvb_new_subset_length(tvb, 0, PWC_SIZEOF_CW);
		call_dissector_with_data(dh_control_word, tvb_2, pinfo, tree, &pd);

		tvb_2 = tvb_new_subset_remaining(tvb, (PWC_SIZEOF_CW-1));
		if (MODE_11(pd.mode))
		{
			dissect_payload_and_padding(tvb_2, pinfo, tree, payload_size, 0, &pd);
		}
		else
		{ /*aal5_pdu mode*/
			if (payload_size != 0)
			{
				tvbuff_t* tvb_3;
				union wtap_pseudo_header* pseudo_header_save;
				union wtap_pseudo_header ph;

				tvb_3 = tvb_new_subset_remaining(tvb_2, 1);
				/* prepare pseudo header for atm aal5 decoding */
				pseudo_header_save = pinfo->pseudo_header;
				pinfo->pseudo_header = &ph;
				prepare_pseudo_header_atm(&ph, &pd, AAL_5);
				call_dissector_with_data(dh_atm_untruncated, tvb_3, pinfo, tree, &pd);
				/* restore pseudo header */
				pinfo->pseudo_header = pseudo_header_save;
			}
		}
	}

	if (MODE_11(pd.mode))
	{
		/* overwrite everything written by sub-dissectors in 1:1 modes*/
		col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_column);
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_pw_info(pinfo, payload_size, cells, 0, &pd);
	}

	return;
}


static void
dissect_aal5_sdu(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	const char           * proto_name_column;
	gint                   payload_size;
	gint                   padding_size;
	int                    cells;
	pwatm_private_data_t   pd      = PWATM_PRIVATE_DATA_T_INITIALIZER;

	pd.mode = PWATM_MODE_AAL5_SDU;

	proto_name_column = &shortname_aal5_sdu[0];
	if (too_small_packet_or_notpw(tvb, pinfo, tree, proto_aal5_sdu, proto_name_column))
	{
		return;
	}
	pd.packet_size = tvb_reported_length_remaining(tvb, 0);

	/* check how "good" is this packet */
	/* also decide payload length from packet size and CW */
	if (0 != (tvb_get_guint8(tvb, 0) & 0xf0 /*bits03*/))
	{
		pd.props |= PWC_CW_BAD_BITS03;
	}

	pd.submode = PWATM_SUBMODE_DEFAULT;
	if (0 != (tvb_get_guint8(tvb, 0) & 0x08 /*preferred_cw.T*/))
	{
		pd.submode = PWATM_SUBMODE_ADMIN_CELL;
	}

	if (! pref_aal5_sdu_extend_cw_length_with_rsvd)
	{
		if (0 != (tvb_get_guint8(tvb, 1) & 0xc0 /*preferred_cw.rsvd*/))
		{
			pd.props |= PWC_CW_BAD_RSV;
		}
	}
	{
		/* RFC4717:
		 * [ If the packet's length (defined as the length of the layer 2 payload
		 * plus the length of the control word) is less than 64 bytes, the
		 * length field MUST be set to the packet's length.  Otherwise, the
		 * length field MUST be set to zero... Note that the length field
		 * is not used in the N-to-one mode and MUST be set to 0. ]
		 *
		 * Also we allow some "extensions"conducted by pref_xxx.
		 */
		gint payload_size_from_packet;
		int cw_len; /*length field from cw*/

		payload_size_from_packet = pd.packet_size - PWC_SIZEOF_CW;
		if (pref_aal5_sdu_extend_cw_length_with_rsvd)
		{
			cw_len = tvb_get_guint8(tvb, 1) & 0xff;
		}
		else
		{
			cw_len = tvb_get_guint8(tvb, 1) & 0x3f;
		}

		/*
		 * Initial assumptions: no padding,
		 * payload size derived from psn packet size.
		 */
		payload_size = payload_size_from_packet;
		padding_size = 0;

		if (0 == cw_len)
		{
			/*keep initial assumptions*/
		}
		else if (!pref_aal5_sdu_allow_cw_length_nonzero
		         && (PWATM_SUBMODE_ADMIN_CELL == pd.submode))
		{
			/*
			 * The "allow CW.Length != 0" option affects
			 * ATM admin cell submode only, because this submode
			 * is equal to N:1 encapsulation.
			 * CW.Length !=0 is always OK for normal (AAL5 payload) submode.
			 */
			pd.props |= PWC_CW_BAD_LEN_MUST_BE_0;
		}
		else
		{
			gint payload_size_from_cw;
			payload_size_from_cw = cw_len - PWC_SIZEOF_CW;
			if (payload_size_from_cw <= 0)
			{
				pd.props |= PWC_CW_BAD_PAYLEN_LE_0;
			}
			else if (payload_size_from_cw > payload_size_from_packet)
			{
				pd.props |= PWC_CW_BAD_PAYLEN_GT_PACKET;
			}
			else
			{

				payload_size = payload_size_from_cw;
				padding_size = payload_size_from_packet - payload_size_from_cw; /* >=0 */
				if (padding_size != 0)
				{
					/*
					 * Padding is not allowed in ATM admin cell submode only,
					 * because this submode is equal to N:1 encapsulation.
					 * Padding is OK for normal (AAL5 payload) submode.
					 */
					if (PWATM_SUBMODE_ADMIN_CELL == pd.submode)
					{
						pd.props |= PWC_CW_BAD_PADDING_NE_0;
						/*restore sizes*/
						payload_size = payload_size_from_packet;
						padding_size = 0;
					}
				}
			}
		}

		if (PWATM_SUBMODE_ADMIN_CELL == pd.submode)
		{
			gint bad_padding_size;
			cells = number_of_cells(pd.mode, pd.submode, payload_size, &bad_padding_size);
			/* only one atm admin cell is allowed in the packet in this mode*/
			if ((1 != cells) || (0 != bad_padding_size))
			{
				pd.props |= PWC_PAY_SIZE_BAD;
			}
		}
		else
		{
			cells = -1; /*unknown*/
			/* Any size is allowed for AAL5 SDU payload */
		}
	}

	/* fill columns in Packet List */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_column);
	if (PWATM_SUBMODE_ADMIN_CELL == pd.submode)
	{
		col_append_str(pinfo->cinfo, COL_PROTOCOL, ", OAM cell");
	}

	col_clear(pinfo->cinfo, COL_INFO);
	col_append_pw_info(pinfo, payload_size, cells, padding_size, &pd);

	{
		proto_item* item;
		item = proto_tree_add_item(tree, proto_aal5_sdu, tvb, 0, -1, ENC_NA);
		{
			proto_tree* tree2;
			tree2 = proto_item_add_subtree(item, ett_encaps);
			{
				item = proto_tree_add_boolean(tree2, hf_pw_type_aal5_sdu, tvb, 0, 0, TRUE);
				PROTO_ITEM_SET_GENERATED(item);
			}
		}
		if (pd.props & PWC_PAY_SIZE_BAD)
		{
			DISSECTOR_ASSERT(PWATM_SUBMODE_ADMIN_CELL == pd.submode);
			expert_add_info_format(pinfo, item, &ei_pw_payload_size_invalid_error,
				"In ATM admin cell mode,"
				" PW payload size (%d) must be == %d (exactly 1 admin cell)",
				(int)payload_size, (int)SIZEOF_N1_PW_CELL);
		}
	}

	{
		tvbuff_t* tvb_2;
		tvb_2 = tvb_new_subset_length(tvb, 0, PWC_SIZEOF_CW);
		call_dissector_with_data(dh_control_word, tvb_2, pinfo, tree, &pd);

		tvb_2 = tvb_new_subset_remaining(tvb, PWC_SIZEOF_CW);
		if (PWATM_SUBMODE_ADMIN_CELL == pd.submode)
		{
			dissect_payload_and_padding(tvb_2, pinfo, tree, payload_size, padding_size, &pd);
		}
		else /*AAL5 payload*/
		{
			if (payload_size != 0)
			{
				tvbuff_t* tvb_3;
				union wtap_pseudo_header* pseudo_header_save;
				union wtap_pseudo_header ph;

				tvb_3 = tvb_new_subset_length(tvb_2, 0, payload_size);
				/* prepare pseudo header for atm aal5 decoding */
				pseudo_header_save = pinfo->pseudo_header;
				pinfo->pseudo_header = &ph;
				prepare_pseudo_header_atm(&ph, &pd, AAL_5);
				call_dissector_with_data(dh_atm_truncated, tvb_3, pinfo, tree, &pd); /* no PAD and trailer */
				/* restore pseudo header */
				pinfo->pseudo_header = pseudo_header_save;
			}
			if (padding_size != 0)
			{
				tvbuff_t* tvb_3;
				tvb_3 = tvb_new_subset(tvb_2, payload_size, padding_size, -1);
				call_dissector(dh_padding, tvb_3, pinfo, tree);
			}
		}
	}
}


static void
dissect_n1_cw(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	const char           * proto_name_column;
	gint                   payload_size;
	gint                   padding_size;
	int                    cells;
	pwatm_private_data_t   pd      = PWATM_PRIVATE_DATA_T_INITIALIZER;

	pd.mode = PWATM_MODE_N1_CW;

	proto_name_column = &shortname_n1_cw[0];
	if (too_small_packet_or_notpw(tvb, pinfo, tree, proto_n1_cw, proto_name_column))
	{
		return;
	}
	pd.packet_size = tvb_reported_length_remaining(tvb, 0);

	/* check how "good" is this packet */
	/* also decide payload length from packet size and CW */
	pd.props = PWC_PACKET_PROPERTIES_T_INITIALIZER;
	if (0 != (tvb_get_guint8(tvb, 0) & 0xf0 /*bits03*/))
	{
		pd.props |= PWC_CW_BAD_BITS03;
	}
	if (0 != (tvb_get_guint8(tvb, 0) & 0x0f /*preferred_cw.flags*/))
	{
		pd.props |= PWC_CW_BAD_FLAGS;
	}
	if (! pref_n1_cw_extend_cw_length_with_rsvd)
	{
		if (0 != (tvb_get_guint8(tvb, 1) & 0xc0 /*preferred_cw.rsvd*/))
		{
			pd.props |= PWC_CW_BAD_RSV;
		}
	}
	{
		/* RFC4717:
		 * [ If the packet's length (defined as the length of the layer 2 payload
		 * plus the length of the control word) is less than 64 bytes, the
		 * length field MUST be set to the packet's length.  Otherwise, the
		 * length field MUST be set to zero... Note that the length field
		 * is not used in the N-to-one mode and MUST be set to 0. ]
		 *
		 * Also we allow some "extensions"conducted by pref_xxx.
		 */
		gint payload_size_from_packet;
		int cw_len; /*length field from cw*/

		payload_size_from_packet = pd.packet_size - PWC_SIZEOF_CW;
		if (pref_n1_cw_extend_cw_length_with_rsvd)
		{
			cw_len = tvb_get_guint8(tvb, 1) & 0xff;
		}
		else
		{
			cw_len = tvb_get_guint8(tvb, 1) & 0x3f;
		}

		/*
		 * Initial assumptions: no padding,
		 * payload size derived from psn packet size.
		 */
		payload_size = payload_size_from_packet;
		padding_size = 0;

		if (0 == cw_len)
		{
			/*keep initial assumptions*/
		}
		else if (!pref_n1_cw_allow_cw_length_nonzero)
		{
			pd.props |= PWC_CW_BAD_LEN_MUST_BE_0;
		}
		else
		{
			gint payload_size_from_cw;
			payload_size_from_cw = cw_len - PWC_SIZEOF_CW;
			if (payload_size_from_cw <= 0)
			{
				pd.props |= PWC_CW_BAD_PAYLEN_LE_0;
			}
			else if (payload_size_from_cw > payload_size_from_packet)
			{
				pd.props |= PWC_CW_BAD_PAYLEN_GT_PACKET;
			}
			else
			{

				payload_size = payload_size_from_cw;
				padding_size = payload_size_from_packet - payload_size_from_cw; /* >=0 */
				if (padding_size != 0)
				{
					pd.props |= PWC_CW_BAD_PADDING_NE_0;
					/*restore sizes*/
					payload_size = payload_size_from_packet;
					padding_size = 0;
				}
			}
		}
		{
			gint bad_padding_size;
			cells = number_of_cells(pd.mode, pd.submode, payload_size, &bad_padding_size);
			if ((0 == cells) || (0 != bad_padding_size))
			{
				pd.props |= PWC_PAY_SIZE_BAD;
			}
		}
	}

	{
		proto_item* item;
		item = proto_tree_add_item(tree, proto_n1_cw, tvb, 0, -1, ENC_NA);
		pwc_item_append_text_n_items(item, cells, "good ATM cell");
		{
			proto_tree* tree2;
			tree2 = proto_item_add_subtree(item, ett_encaps);
			{
				proto_item* item2;
				item2 = proto_tree_add_boolean(tree2, hf_pw_type_n1_cw, tvb, 0, 0, TRUE);
				PROTO_ITEM_SET_GENERATED(item2);
				item2 = proto_tree_add_int(tree2, hf_n1_cw_ncells, tvb, 0, 0, cells);
				PROTO_ITEM_SET_GENERATED(item2);
			}
		}
		if (pd.props & PWC_PAY_SIZE_BAD)
		{
			if (payload_size != 0)
			{
				expert_add_info_format(pinfo, item, &ei_cell_broken,
					"PW ATM cell [%.3d] is broken", (int)cells);
				expert_add_info_format(pinfo, item, &ei_pw_payload_size_invalid_note,
					"PW payload size (%d) must be <>0 and multiple of %d",
					(int)payload_size, (int)SIZEOF_N1_PW_CELL);
			}
			else
			{
				expert_add_info_format(pinfo, item, &ei_pw_payload_size_invalid_error,
					"PW payload size (%d) must be <>0 and multiple of %d",
					(int)payload_size, (int)SIZEOF_N1_PW_CELL);
			}
		}
	}

	{
		tvbuff_t* tvb_2;
		tvb_2 = tvb_new_subset_length(tvb, 0, PWC_SIZEOF_CW);
		call_dissector_with_data(dh_control_word, tvb_2, pinfo, tree, &pd);

		tvb_2 = tvb_new_subset_remaining(tvb, PWC_SIZEOF_CW);
		dissect_payload_and_padding(tvb_2, pinfo, tree, payload_size, padding_size, &pd);
	}

	/* fill columns in Packet List */
	/* overwrite everything written by sub-dissectors */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_column);

	col_clear(pinfo->cinfo, COL_INFO);
	col_append_pw_info(pinfo, payload_size, cells, padding_size, &pd);
}


static void
dissect_n1_nocw(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	const char           * proto_name_column = &shortname_n1_nocw[0];
	gint                   payload_size;
	int                    cells;
	pwatm_private_data_t   pd                = PWATM_PRIVATE_DATA_T_INITIALIZER;

	pd.mode = PWATM_MODE_N1_NOCW;
	pd.packet_size = tvb_reported_length_remaining(tvb, 0);

	/* check how "good" is this packet */
	/* also decide payload length from packet size */
	pd.props = PWC_PACKET_PROPERTIES_T_INITIALIZER;
	payload_size = pd.packet_size;
	{
		gint bad_padding_size;
		cells = number_of_cells(pd.mode, pd.submode, pd.packet_size, &bad_padding_size);
		if ((cells == 0) || (bad_padding_size != 0))
		{
			pd.props |= PWC_PAY_SIZE_BAD;
		}
	}

	{
		proto_item* item;
		item = proto_tree_add_item(tree, proto_n1_nocw, tvb, 0, -1, ENC_NA);
		pwc_item_append_text_n_items(item, cells, "ATM cell");
		{
			proto_tree* tree2;
			tree2 = proto_item_add_subtree(item, ett_encaps);
			{
				proto_item* item2;
				item2 = proto_tree_add_boolean(tree2, hf_pw_type_n1_nocw, tvb, 0, 0, TRUE);
				PROTO_ITEM_SET_GENERATED(item2);
				item2 = proto_tree_add_int(tree2, hf_n1_nocw_ncells, tvb, 0, 0, cells);
				PROTO_ITEM_SET_GENERATED(item2);
			}
		}
		if (pd.props & PWC_PAY_SIZE_BAD)
		{
			if (payload_size != 0)
			{
				expert_add_info_format(pinfo, item, &ei_cell_broken,
					"Last PW ATM cell [%.3d] is broken", (int)cells);
				expert_add_info_format(pinfo, item, &ei_pw_payload_size_invalid_note,
					"PW payload size (%d) must be <>0 and multiple of %d",
					(int)payload_size, (int)SIZEOF_N1_PW_CELL);
			}
			else
			{
				expert_add_info_format(pinfo, item, &ei_pw_payload_size_invalid_error,
					"PW payload size (%d) must be <>0 and multiple of %d",
					(int)payload_size, (int)SIZEOF_N1_PW_CELL);
			}
		}
	}

	dissect_payload_and_padding(tvb, pinfo, tree, payload_size, 0, &pd);

	/* fill columns in Packet List */
	/* overwrite everything written by sub-dissectors */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_column);

	col_clear(pinfo->cinfo, COL_INFO);
	col_append_pw_info(pinfo, payload_size, cells, 0, &pd);
}


static void
proto_item_append_text_cwb3_fields(proto_item * item, const pwatm_private_data_t * const pd)
{
	if (NULL == item) return;
	DISSECTOR_ASSERT(NULL != pd);
	if (pd->cwb3.m   >= 0)
		proto_item_append_text(item, "M:%.1u  "  , (unsigned)(pd->cwb3.m));
	if (pd->cwb3.v   >= 0)
		proto_item_append_text(item, "V:%.1u  "  , (unsigned)(pd->cwb3.v));
	if (pd->cwb3.rsv >= 0)
		proto_item_append_text(item, "RSV:%.1u  ", (unsigned)(pd->cwb3.rsv));
	if (pd->cwb3.u >= 0)
		proto_item_append_text(item, "U:%.1u  "  , (unsigned)(pd->cwb3.u));
	if (pd->cwb3.e >= 0)
		proto_item_append_text(item, "EFCI:%.1u  ",(unsigned)(pd->cwb3.e));
	if (pd->cwb3.clp >= 0)
		proto_item_append_text(item, "CLP:%.1u  ", (unsigned)(pd->cwb3.clp));
	return;
}


static int
dissect_control_word(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data)
{
	pwatm_private_data_t* pd;

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;
	pd = (pwatm_private_data_t *)data;

	/*
	 * NB: do not touch columns -- keep info from previous dissector
	 */

	{
		gint size;
		size = tvb_reported_length_remaining(tvb, 0);
		if (size < PWC_SIZEOF_CW)
		{
			proto_item  *item;
			item = proto_tree_add_item(tree, proto_control_word, tvb, 0, -1, ENC_NA);
			expert_add_info_format(pinfo, item, &ei_pw_payload_size_invalid_error,
					       "Packet (size: %d) is too small to carry MPLS PW Control Word"
					       ,(int)size);
			return tvb_length(tvb);
		}
	}

	{
		proto_item* item_top;
		proto_tree* tree2;
		proto_item* item;

		item_top = proto_tree_add_item(tree, proto_control_word, tvb, 0, -1, ENC_NA);
		pwc_item_append_cw(item_top, tvb_get_ntohl(tvb, 0), FALSE);

		tree2 = proto_item_add_subtree(item_top, ett_cw);

		/* bits 0..3 */
		item = proto_tree_add_item(tree2, hf_cw_bits03, tvb, 0, 1, ENC_BIG_ENDIAN);
		if (pd->props & PWC_CW_BAD_BITS03)
		{
			/* add item to tree (and show it) only if its value is wrong*/
			expert_add_info(pinfo, item, &ei_cw_bits03);
		}
		else
		{
			PROTO_ITEM_SET_HIDDEN(item); /* show only in error cases */
		}

		/* flags */
		if (MODE_N1(pd->mode))
		{
			item = proto_tree_add_item(tree2, hf_pref_cw_flags, tvb, 0, 1, ENC_BIG_ENDIAN);
			if (pd->props & PWC_CW_BAD_FLAGS)
			{
				expert_add_info(pinfo, item, &ei_pref_cw_flags);
			}
		}
		if (pd->mode == PWATM_MODE_AAL5_SDU)
		{
			proto_tree_add_item(tree2, hf_pref_cw_a5s_t, tvb, 0, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree2, hf_pref_cw_a5s_e, tvb, 0, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree2, hf_pref_cw_a5s_c, tvb, 0, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree2, hf_pref_cw_a5s_u, tvb, 0, 1, ENC_BIG_ENDIAN);
			/*
			 * rfc4717: [When FRF.8.1 Frame Relay/ATM PVC Service Interworking [RFC3916]
			 * traffic is being transported, the CPCS-UU Least Significant Bit
			 * (LSB) of the AAL5 CPCS-PDU may contain the Frame Relay C/R bit.
			 * The ingress router, PE1, SHOULD copy this bit to the U bit of the
			 * control word.  The egress router, PE2, SHOULD copy the U bit to
			 * the CPCS-UU Least Significant Bit (LSB) of the AAL5 CPCS PDU.]
			 *
			 * Let's remember this bit (and then transfer it to ATM dissector).
			 */
			pd->aal5_sdu_frame_relay_cr_bit =
				(0 == (tvb_get_guint8(tvb, 0) & 0x01 /*preferred_cw.U*/))
				? FALSE : TRUE;
		}

		/* reserved bits */
		if (MODE_11_OR_AAL5_PDU(pd->mode)
		    || (MODE_N1(pd->mode) && !pref_n1_cw_extend_cw_length_with_rsvd)
		    /* for N:1 add RSV only if it is NOT used in length */
		    || ((pd->mode == PWATM_MODE_AAL5_SDU) && !pref_aal5_sdu_extend_cw_length_with_rsvd)
		    /* for AAl5 SDU add RSV only if it is NOT used in length */)
		{
			if (MODE_11_OR_AAL5_PDU(pd->mode))
			{
				item = proto_tree_add_item(tree2
							   ,hf_generic_cw_rsv, tvb, 0, 1, ENC_BIG_ENDIAN);
			}
			else
			{ /*preferred cw*/
				item = proto_tree_add_item(tree2
							   ,hf_pref_cw_rsv, tvb, 1, 1, ENC_BIG_ENDIAN);
			}

			if (pd->props & PWC_CW_BAD_RSV)
			{
				expert_add_info(pinfo, item, &ei_cw_bits03);
			}
			else
			{
				PROTO_ITEM_SET_HIDDEN(item); /*...and show only in error cases */
			}
		}

		/* length */
		if (MODE_N1(pd->mode)
		    || (PWATM_MODE_AAL5_SDU == pd->mode))
		{
			{
				int hf_len = hf_pref_cw_len;
				if (MODE_N1(pd->mode))
				{
					if (pref_n1_cw_extend_cw_length_with_rsvd)
						hf_len = hf_pref_cw_rsvlen;
				}
				else /*PW_MODE_AAL5_SDU*/
				{
					if (pref_aal5_sdu_extend_cw_length_with_rsvd)
						hf_len = hf_pref_cw_rsvlen;
				}
				item = proto_tree_add_item(tree2, hf_len, tvb, 1, 1, ENC_BIG_ENDIAN);
			}
			if (pd->props & PWC_CW_BAD_LEN_MUST_BE_0)
			{
				expert_add_info_format(pinfo, item, &ei_pref_cw_len,
						       "Bad Length: must be 0 for this encapsulation");
			}
			if (pd->props & PWC_CW_BAD_PAYLEN_LE_0)
			{
				expert_add_info_format(pinfo, item, &ei_pref_cw_len,
						       "Bad Length: too small, must be >= %d",
						       (int)(PWC_SIZEOF_CW+SIZEOF_N1_PW_CELL));
			}
			if (pd->props & PWC_CW_BAD_PAYLEN_GT_PACKET)
			{
				expert_add_info_format(pinfo, item, &ei_pref_cw_len,
						       "Bad Length: must be <= than PSN packet size (%d)",
						       (int)pd->packet_size);
			}
			if (pd->props & PWC_CW_BAD_PADDING_NE_0)
			{
				expert_add_info_format(pinfo, item, &ei_pref_cw_len,
						       "Bad Length: must be == PSN packet size (%d), no padding allowed",
						       (int)pd->packet_size);
			}
		}

		/* sequence number */
		proto_tree_add_item(tree2, hf_cw_seq, tvb
				    ,MODE_11_OR_AAL5_PDU(pd->mode) ? 1 : 2, 2, ENC_BIG_ENDIAN);

		/* atm-specific byte */
		if (MODE_11(pd->mode))
		{
			proto_tree_add_item(tree2, hf_gen_cw_atmbyte, tvb, 3, 1, ENC_BIG_ENDIAN);
			/*
			 * no need to highlight item in the tree, therefore
			 * expert_add_info_format() is not used here.
			 */
			item = proto_tree_add_text(tree2, tvb, 3, 1
						   ,"ATM-specific byte of CW is fully dissected below as %s%s"
						   ,(PWATM_MODE_11_VPC == pd->mode) ? "a part of "	: ""
						   ,"PW ATM Cell Header [000]");
			PROTO_ITEM_SET_GENERATED(item);
			/*
			 * Note: if atm-specific byte contains something wrong
			 * (e.g. non-zero RSV or inadequate V), CW is not
			 * marked as "bad".
			 */
		}

		/*3rd byte of CW*/
		if (PWATM_MODE_AAL5_PDU == pd->mode)
		{
			tvbuff_t* tvb_2;
			tvb_2 = tvb_new_subset_remaining(tvb, (PWC_SIZEOF_CW-1));
			call_dissector_with_data(dh_cell_header, tvb_2, pinfo, tree2, pd);
			proto_item_append_text(item_top, ", ");
			proto_item_append_text_cwb3_fields(item_top, pd);
		}
	}

	return tvb_length(tvb);
}


/*
 * This function is also used to dissect 3rd byte of CW in AAL5 PDU mode.
 */
static int
dissect_cell_header(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data)
{
	pwatm_private_data_t * pd;
	gboolean               is_enough_data;
	int                    dissect_size;

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;
	pd = (pwatm_private_data_t *)data;

	pd->vpi	     = pd->vci = pd->pti = -1;
	pd->cwb3.clp = pd->cwb3.m = pd->cwb3.v = pd->cwb3.rsv = pd->cwb3.u = pd->cwb3.e = -1;

	if (PWATM_MODE_AAL5_PDU == pd->mode)
	{
		if (tvb_reported_length_remaining(tvb, 0) < 1)
		{
			is_enough_data = FALSE;
			dissect_size = 0;
		}
		else
		{
			is_enough_data = TRUE;
			dissect_size = 1;
		}
	}
	else
	{
		gint size;
		size = tvb_reported_length_remaining(tvb, 0);

		if (size < pw_cell_header_size(pd->mode, pd->submode))
		{
			is_enough_data = FALSE;
			dissect_size = size;
		}
		else
		{
			is_enough_data = TRUE;
			dissect_size = pw_cell_header_size(pd->mode, pd->submode);
		}
	}

	/*
	 * NB: do not touch columns -- keep info from previous dissector
	 */

	/* Collect info for upper-level dissectors regardless of
	 * the presence of the tree
	 */
	if (is_enough_data)
	{
		guint8 tmp8;
		switch (pd->mode)
		{
		case PWATM_MODE_AAL5_SDU:
			DISSECTOR_ASSERT(pd->submode == PWATM_SUBMODE_ADMIN_CELL);
			/*fallthrough for ATM admin cell submode only*/
		case PWATM_MODE_N1_CW:
		case PWATM_MODE_N1_NOCW:
			pd->vpi		= (tvb_get_ntohs (tvb, 0) >> 4);
			pd->vci		= (tvb_get_ntoh24(tvb, 1) >> 4) & 0xffff;
			tmp8 		= (tvb_get_guint8(tvb, 3));
			pd->pti		= (tmp8 >> 1) & 0x07;
			pd->cwb3.clp 	= (tmp8 >> 0) & 0x01;
			UPDATE_CUMULATIVE_VALUE(pd->cumulative.vpi, pd->vpi);
			UPDATE_CUMULATIVE_VALUE(pd->cumulative.vci, pd->vci);
			UPDATE_CUMULATIVE_VALUE(pd->cumulative.pti, pd->pti);
			UPDATE_CUMULATIVE_VALUE(pd->cumulative.clp, pd->cwb3.clp);
			/*
			 * OAM cell mode is always used for aal5_sdu/admin_cell mode,
			 * even if pti indicates user cell.
			 */
			pd->cell_mode_oam =
				((pd->mode == PWATM_MODE_AAL5_SDU) && (pd->submode == PWATM_SUBMODE_ADMIN_CELL))
				|| PTI_IS_ADMIN(pd->pti);
			break;
		case PWATM_MODE_11_VPC:
			pd->vci = tvb_get_ntohs(tvb, 1);
			UPDATE_CUMULATIVE_VALUE(pd->cumulative.vci, pd->vci);
			/*fallthrough*/
		case PWATM_MODE_11_VCC:
			tmp8	= (tvb_get_guint8(tvb, 0));
			pd->cwb3.m	= (tmp8 >> 7) & 0x1;
			pd->cwb3.v	= (tmp8 >> 6) & 0x1;
			pd->cwb3.rsv	= (tmp8 >> 4) & 0x3;
			pd->pti		= (tmp8 >> 1) & 0x7;
			pd->cwb3.clp	= (tmp8 >> 0) & 0x1;
			UPDATE_CUMULATIVE_VALUE(pd->cumulative.pti, pd->pti);
			UPDATE_CUMULATIVE_VALUE(pd->cumulative.clp, pd->cwb3.clp);
			/*
			 * OAM cell mode is possible if packet contains atm cell (m == 0).
			 */
			pd->cell_mode_oam = PTI_IS_ADMIN(pd->pti) && (pd->cwb3.m == 0);
			break;
		case PWATM_MODE_AAL5_PDU:
			tmp8		= (tvb_get_guint8(tvb, 0));
			pd->cwb3.m	= (tmp8 >> 7) & 0x1;
			pd->cwb3.v	= (tmp8 >> 6) & 0x1;
			pd->cwb3.rsv	= (tmp8 >> 3) & 0x7;
			pd->cwb3.u	= (tmp8 >> 2) & 0x1;
			pd->cwb3.e	= (tmp8 >> 1) & 0x1;
			pd->cwb3.clp	= (tmp8 >> 0) & 0x1;
			UPDATE_CUMULATIVE_VALUE(pd->cumulative.clp, pd->cwb3.clp);
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
		}
	}

	{
		proto_item* item;

		item = proto_tree_add_item(tree, proto_cell_header, tvb
			,0
			,dissect_size
			,ENC_NA);
		if (PWATM_MODE_AAL5_PDU == pd->mode)
		{
			proto_item_set_text(item, "Third byte of Control Word"); /*overwrite heading line*/
			/* cwb3 fileds are appended to CW heading line, not here */
		}
		else
		{
			proto_item_append_text(item, " [%.3d]", pd->pw_cell_number);
			proto_item_append_text(item, ", ");
			if (pd->vpi >= 0)
				proto_item_append_text(item, "VPI:%.4u  ", (unsigned)(pd->vpi));
			if (pd->vci >= 0)
				proto_item_append_text(item, "VCI:%.5u  ", (unsigned)(pd->vci));
			if (pd->pti >= 0)
				proto_item_append_text(item, "PTI:%.1u  ", (unsigned)(pd->pti));
			proto_item_append_text_cwb3_fields(item, pd);
		}

		{
			proto_tree* tree2;
			tree2 = proto_item_add_subtree(item, ett_cell_header);
			if (is_enough_data)
			{
				proto_item* item2;
				if (MODE_N1(pd->mode)
				    || ((pd->mode == PWATM_MODE_AAL5_SDU) && (pd->submode == PWATM_SUBMODE_ADMIN_CELL)))
				{
					proto_tree_add_uint(tree2, hf_cell_h_vpi, tvb, 0, 2, (unsigned)pd->vpi);
					proto_tree_add_uint(tree2, hf_cell_h_vci, tvb, 1, 3, (unsigned)pd->vci);

					item2 = proto_tree_add_item(tree2, hf_cell_h_pti, tvb, 3, 1, ENC_BIG_ENDIAN);
					if (NULL == try_val_to_str(pd->pti, atm_pt_vals))
					{
						expert_add_info_format(pinfo, item2, &ei_cell_h_pti_undecoded,
							"Unknown value of PTI field (%d) in the ATM cell header",
							pd->pti);
					}
					else if ((pd->mode == PWATM_MODE_AAL5_SDU) && !PTI_IS_ADMIN(pd->pti))
					{
						expert_add_info_format(pinfo, item2, &ei_cell_h_pti_malformed,
							"ATM admin cell is transerred;"
							" PTI field (%d) should be 4, 5 or 6.",
							pd->pti);
					}

					proto_tree_add_item(tree2, hf_cell_h_clp, tvb, 3, 1, ENC_BIG_ENDIAN);
				}
				else if (MODE_11_OR_AAL5_PDU(pd->mode))
				{
					item2 = proto_tree_add_item(tree2, hf_cell_h_m  , tvb, 0, 1, ENC_BIG_ENDIAN);
					if ((0 != pd->cwb3.m) && MODE_11(pd->mode))
					{
						expert_add_info(pinfo, item2, &ei_cell_h_m);
					}

					item2 = proto_tree_add_item(tree2, hf_cell_h_v  , tvb, 0, 1, ENC_BIG_ENDIAN);
					if ((0 == pd->cwb3.v) && (PWATM_MODE_11_VPC == pd->mode))
					{
						expert_add_info(pinfo, item2, &ei_cell_h_v_not_zero);
					}
					if ((0 != pd->cwb3.v) && (PWATM_MODE_11_VCC == pd->mode))
					{
						expert_add_info_format(pinfo, item2, &ei_cell_h_v_not_one,
							"1:1 VCC mode:"
							" V bit must be 0 to indicate that VCI is absent");
					}
					if ((0 != pd->cwb3.v) && (PWATM_MODE_AAL5_PDU == pd->mode))
					{
						expert_add_info_format(pinfo, item2, &ei_cell_h_v_not_one,
							"AAL5 PDU mode:"
							" V bit must be 0 to indicate that VCI is absent");
					}

					item2 = proto_tree_add_item(tree2
						,(PWATM_MODE_AAL5_PDU == pd->mode)
							? hf_aal5_pdu_rsv
							: hf_cell_h_rsv
						,tvb, 0, 1, ENC_BIG_ENDIAN);
					if (0 != pd->cwb3.rsv)
					{
						expert_add_info(pinfo, item2, &ei_cell_h_rsv);
					}
					else
					{
				                PROTO_ITEM_SET_HIDDEN(item2); /*...and show only in error cases */
			                }

					if (MODE_11(pd->mode))
					{
						item2 = proto_tree_add_item(tree2, hf_cell_h_pti, tvb, 0, 1, ENC_BIG_ENDIAN);
						if (NULL == try_val_to_str(pd->pti, atm_pt_vals))
						{
							expert_add_info_format(pinfo, item2, &ei_cell_h_pti_undecoded,
								"Unknown value of PTI field (%d) in the atm-specific byte"
								,pd->pti);
						}
					}
					else
					{
						proto_tree_add_item(tree2, hf_aal5_pdu_u, tvb, 0, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree2, hf_aal5_pdu_e, tvb, 0, 1, ENC_BIG_ENDIAN);
					}

					proto_tree_add_item(tree2, hf_cell_h_clp, tvb, 0, 1, ENC_BIG_ENDIAN);

					if (PWATM_MODE_11_VPC == pd->mode)
					{
						proto_tree_add_uint(tree2, hf_cell_h_vci, tvb, 1, 2
							,(unsigned)pd->vci);
					}
				}
				else
				{
					DISSECTOR_ASSERT_NOT_REACHED();
				}
			}
			else
			{
				expert_add_info_format(pinfo, item, &ei_pw_payload_size_invalid_error,
					"Not enough data (size: %d), impossible to decode",
					(int)dissect_size);
			}
		}
	}
	return dissect_size;
}



static int
dissect_cell(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data)
{
	gboolean is_enough_data;
	int      dissect_size;
	gint size;
	proto_item* item;
	pwatm_private_data_t * pd = (pwatm_private_data_t *)data;

	size = tvb_reported_length_remaining(tvb, 0);
	if (size < SIZEOF_ATM_CELL_PAYLOAD)
	{
		is_enough_data = FALSE;
		dissect_size = size;
	}
	else
	{
		is_enough_data = TRUE;
		dissect_size = SIZEOF_ATM_CELL_PAYLOAD;
	}

	/*
	 * NB: do not touch columns -- keep info from previous dissector
	 */

	item = proto_tree_add_item(tree, proto_cell, tvb, 0, dissect_size, ENC_NA);
	if (NULL != pd)
		proto_item_append_text(item, " [%.3d]", pd->pw_cell_number);

	pwc_item_append_text_n_items(item, dissect_size, "byte");
	if (!is_enough_data)
	{
		expert_add_info_format(pinfo, item, &ei_pw_payload_size_invalid_error,
			"Bad length of cell payload: must be == %d",
			(int)SIZEOF_ATM_CELL_PAYLOAD);
	}

	{
		proto_tree* tree2;
		tvbuff_t* tvb_d;
		tree2 = proto_item_add_subtree(item, ett_cell);
		tvb_d = tvb_new_subset(tvb, 0, dissect_size, -1);
		call_dissector(dh_data, tvb_d, pinfo, tree2);
		item = proto_tree_add_int(tree2, hf_cell_payload_len, tvb, 0, 0, dissect_size);
		PROTO_ITEM_SET_HIDDEN(item);
	}

	return dissect_size;
}


void
proto_register_pw_atm_ata(void)
{
	static const value_string clp_vals[] = {
		{ 0, "High priority" },
		{ 1, "Low priority" },
		{ 0, NULL }
	};
	static const value_string m_vals[] = {
		{ 0, "ATM cell" },
		{ 1, "AAL5 payload" },
		{ 0, NULL }
	};
	static const value_string u_vals[] = {
		{ 0, "This frame does not contain the last cell of AAL5 PDU" },
		{ 1, "This frame contains the last cell of AAL5 PDU" },
		{ 0, NULL }
	};
	static const value_string e_vals[] = {
		{ 0, "Congestion is not experienced" },
		{ 1, "Congestion is experienced for one or more ATM AAL5 cells" },
		{ 0, NULL }
	};
	static hf_register_info hfa_cell_header[] = {
		{ &hf_cell_h_vpi	,{"VPI"				,"atm.vpi"
					  ,FT_UINT16	,BASE_DEC	,NULL           ,0
					  ,NULL						,HFILL }},

		{ &hf_cell_h_vci	,{"VCI"				,"atm.vci"
					  ,FT_UINT16	,BASE_DEC	,NULL		,0
					  ,NULL						,HFILL }},

		{ &hf_cell_h_pti	,{"Payload Type"		,"atm.pti"
					  ,FT_UINT8	,BASE_DEC	,VALS(atm_pt_vals),0x0e
					  ,"The 3-bit Payload Type Identifier (PTI) incorporates ATM Layer"
					  " PTI coding of the cell.  These bits are set to the value of the"
					  " PTI of the encapsulated ATM cell."
					  ,HFILL }},

		{ &hf_cell_h_clp	,{"Cell Loss Priority"		,"atm.clp"
					  ,FT_UINT8	,BASE_DEC	,VALS(clp_vals)	,0x01
					  ,"The Cell Loss Priority (CLP) field indicates CLP value"
					  " of the encapsulated cell."
					  ,HFILL }},

		{ &hf_cell_h_m		,{"Transport Mode"		,"atm.pw_control_byte.m"
					  ,FT_UINT8	,BASE_DEC	,VALS(m_vals)	,0x80
					  ,"Bit (M) of the control byte indicates  whether the packet"
					  " contains an ATM cell or a frame payload. If set to 0,"
					  " the packet contains an ATM cell. If set to 1, the PDU"
					  " contains an AAL5 payload."
					  ,HFILL }},

		{ &hf_cell_h_v		,{"VCI Present"			,"atm.pw_control_byte.v"
					  ,FT_BOOLEAN	,8		,TFS(&tfs_yes_no),0x40
					  ,"Bit (V) of the control byte indicates whether the VCI field"
					  " is present in the packet. If set to 1, the VCI field is present"
					  " for the cell. If set to 0, no VCI field is present."
					  ,HFILL }},

		{ &hf_cell_h_rsv	,{"Reserved bits"		,"atm.pw_control_byte.rsv"
					  ,FT_UINT8	,BASE_DEC	,NULL		,0x30
					  ,"The reserved bits should be set to 0 at the transmitter and"
					  " ignored upon reception."
					  ,HFILL }},

		{ &hf_aal5_pdu_rsv	,{"Reserved bits"		,"atm.pw_control_byte.rsv"
					  ,FT_UINT8	,BASE_DEC	,NULL		,0x38
					  ,"The reserved bits should be set to 0 at the transmitter and"
					  " ignored upon reception."
					  ,HFILL }},

		{ &hf_aal5_pdu_u	,{"U bit"			,"atm.pw_control_byte.u"
					  ,FT_UINT8	,BASE_DEC	,VALS(u_vals)	,0x04
					  ,"Indicates whether this frame contains the last cell of"
					  " an AAL5 PDU and represents the value of the ATM User-to-User"
					  " bit for the last ATM cell of the PSN frame. Note: The ATM"
					  " User-to-User bit is the least significant bit of the PTI"
					  " in the ATM header."
					  ,HFILL }},

		{ &hf_aal5_pdu_e	,{"EFCI"			,"atm.pw_control_byte.efci"
					  ,FT_UINT8	,BASE_DEC	,VALS(e_vals)	,0x02
					  ,"EFCI is set to the EFCI state of the last cell of the"
					  " AAL5 PDU or AAL5 fragment. Note: The EFCI state is"
					  " indicated in the middle bit of each ATM cell's PTI."
					  ,HFILL }}
	};
	static hf_register_info hfa_cell[] = {
		{&hf_cell_payload_len	,{"Length"			,"atm.cell.len"
					  ,FT_INT32	,BASE_DEC	,NULL		,0
					  ,NULL						,HFILL }}
	};

#define HF_INITIALIZER_NCELLS(hf_handle)				\
	{ &hf_handle		,{"Number of good encapsulated cells","pw.atm.cells" \
				,FT_INT32	,BASE_DEC	,NULL		,0 \
				,NULL						,HFILL }}

#define HF_INITIALIZER_PWTYPE(hf_handle,name)				\
	{ &hf_handle		,{name				,name	\
				,FT_BOOLEAN	,0		,NULL		,0x0 \
				,"Identifies type of ATM PW. May be used for filtering.",HFILL}}


	static hf_register_info hfa_n1_nocw[] = {
		 HF_INITIALIZER_NCELLS(hf_n1_nocw_ncells)
		,HF_INITIALIZER_PWTYPE(hf_pw_type_n1_nocw,"pw.type.atm.n1nocw")
	};

	static hf_register_info hfa_n1_cw[] = {
		 HF_INITIALIZER_NCELLS(hf_n1_cw_ncells)
		,HF_INITIALIZER_PWTYPE(hf_pw_type_n1_cw,"pw.type.atm.n1cw")
	};

	static hf_register_info hfa_11_aal5pdu[] = {
		 HF_INITIALIZER_NCELLS(hf_11_ncells)
		,HF_INITIALIZER_PWTYPE(hf_pw_type_11_vcc,"pw.type.atm.11vcc")
		,HF_INITIALIZER_PWTYPE(hf_pw_type_11_vpc,"pw.type.atm.11vpc")
		,HF_INITIALIZER_PWTYPE(hf_pw_type_aal5_pdu,"pw.type.atm.aal5pdu")
	};

	static hf_register_info hfa_aal5_sdu[] = {
		HF_INITIALIZER_PWTYPE(hf_pw_type_aal5_sdu,"pw.type.atm.aal5sdu")
	};

	static const value_string a5s_t_vals[] = {
		{ 0, "AAL5 payload" },
		{ 1, "ATM admin cell" },
		{ 0, NULL }
	};

	static const value_string a5s_e_vals[] = {
		{ 0, "No congestion" },
		{ 1, "Congestion experienced" },
		{ 0, NULL }
	};

	static hf_register_info hfa_cw[] = {
		{ &hf_cw_bits03		,{"Bits 0 to 3"			,"pw.cw.bits03"
					  ,FT_UINT8	,BASE_HEX	,NULL		,0xf0
					  ,NULL						,HFILL }},

		{ &hf_pref_cw_flags	,{"Flags"			,"pw.cw.flags"
					  ,FT_UINT8	,BASE_HEX	,NULL		,0x0f
					  ,NULL							,HFILL }},

		{ &hf_pref_cw_a5s_t	,{"Payload type"		,"atm.pt"
					  ,FT_UINT8	,BASE_DEC	,VALS(a5s_t_vals),0x08
					  ,"Bit (T) of the control word indicates whether the packet contains"
					  " an ATM admin cell or an AAL5 payload. If T = 1, the packet"
					  " contains an ATM admin cell, encapsulated according to the N:1"
					  " cell relay encapsulation. If not set, the PDU"
					  " contains an AAL5 payload."
					  ,HFILL }},

		{ &hf_pref_cw_a5s_e	,{"EFCI bit"			,"atm.efci"
					  ,FT_UINT8	,BASE_DEC	,VALS(a5s_e_vals),0x04
					  ,"The ingress router sets this bit to 1 if the EFCI bit"
					  " of the final cell of those that transported the AAL5 CPCS-SDU is"
					  " set to 1, or if the EFCI bit of the single ATM cell to be"
					  " transported in the packet is set to 1. Otherwise, this bit"
					  " is set to 0."
					  ,HFILL }},

		{ &hf_pref_cw_a5s_c	,{"CLP bit"			,"atm.clp"
					  ,FT_UINT8	,BASE_DEC	,VALS(clp_vals)	,0x02
					  ,"The ingress router sets this bit to 1 if the CLP bit"
					  " of any of the ATM cells that transported the AAL5 CPCS-SDU is set"
					  " to 1, or if the CLP bit of the single ATM cell to be transported"
					  " in the packet is set to 1. Otherwise this bit is set to 0."
					  ,HFILL }},

		{ &hf_pref_cw_a5s_u	,{"U bit (Command/Response)"	,"pw.cw.aal5sdu.u"
					  ,FT_UINT8	,BASE_DEC	,NULL		,0x01
					  ,"When FRF.8.1 Frame Relay/ATM PVC Service Interworking [RFC3916]"
					  " traffic is being transported, the Least-Significant Bit of CPCS-UU"
					  " of the AAL5 CPCS-PDU may contain the Frame Relay C/R bit."
					  " The ingress router copies this bit here."
					  ,HFILL }},

		{ &hf_pref_cw_rsv	,{"Reserved bits"		,"pw.cw.rsv"
					  ,FT_UINT8	,BASE_DEC	,NULL		,0xc0
					  ,NULL						,HFILL }},

		{ &hf_generic_cw_rsv	,{"Reserved bits"		,"pw.cw.rsv"
					  ,FT_UINT8	,BASE_DEC	,NULL		,0x0f
					  ,NULL						,HFILL }},

		{ &hf_pref_cw_len	,{"Length"			,"pw.cw.length"
					  ,FT_UINT8	,BASE_DEC	,NULL		,0x3f
					  ,NULL						,HFILL }},

		{ &hf_pref_cw_rsvlen	,{"Length (extended)"		,"pw.cw.length"
					  ,FT_UINT8	,BASE_DEC	,NULL		,0xff
					  ,NULL						,HFILL }},

		{ &hf_cw_seq		,{"Sequence number"		,"pw.cw.seqno"
					  ,FT_UINT16	,BASE_DEC	,NULL		,0
					  ,NULL						,HFILL }},

		{ &hf_gen_cw_atmbyte	,{"ATM-specific byte"		,"pw.cw.3rd_byte"
					  ,FT_UINT8	,BASE_HEX	,NULL		,0xFF
					  ,NULL						,HFILL }}
	};
	static gint *ett_array[] = {
		&ett_encaps
		,&ett_cw
		,&ett_cell_header
		,&ett_cell
	};
	static ei_register_info ei[] = {
		{ &ei_pw_packet_size_too_small, { "pw.packet_size_too_small", PI_MALFORMED, PI_ERROR, "PW packet size too small", EXPFILL }},
		{ &ei_pw_payload_size_invalid_error, { "pw.payload.size_invalid", PI_MALFORMED, PI_ERROR, "PW payload size invalid", EXPFILL }},
		{ &ei_cell_broken, { "atm.cell_broken", PI_MALFORMED, PI_ERROR, "PW ATM cell is broken", EXPFILL }},
		{ &ei_pw_payload_size_invalid_note, { "pw.payload.size_invalid", PI_MALFORMED, PI_NOTE, "PW payload size invalid", EXPFILL }},
		{ &ei_cw_bits03, { "pw.cw.bits03.not_zero", PI_MALFORMED, PI_ERROR, "Bits 0..3 of Control Word must be 0", EXPFILL }},
		{ &ei_pref_cw_flags, { "pw.cw.flags.not_zero", PI_MALFORMED, PI_ERROR, "Flags must be 0 for PW ATM N:1 encapsulation", EXPFILL }},
		{ &ei_pref_cw_len, { "pw.cw.length.invalid", PI_MALFORMED, PI_ERROR, "Bad Length: must be 0 for this encapsulation", EXPFILL }},
		{ &ei_cell_h_pti_undecoded, { "atm.pti.invalid", PI_UNDECODED, PI_WARN, "Unknown value of PTI field in the ATM cell header", EXPFILL }},
		{ &ei_cell_h_pti_malformed, { "atm.pti.invalid", PI_MALFORMED, PI_ERROR, "ATM admin cell is transerred. PTI field should be 4, 5 or 6.", EXPFILL }},
		{ &ei_cell_h_m, { "atm.pw_control_byte.m.not_zero", PI_MALFORMED, PI_ERROR, "1:1 mode: M bit must be 0 to distinguish from AAL5 PDU mode", EXPFILL }},
		{ &ei_cell_h_v_not_zero, { "atm.pw_control_byte.v.not_one", PI_MALFORMED, PI_ERROR, "1:1 VPC mode: V bit must be 1 to indicate that VCI is present", EXPFILL }},
		{ &ei_cell_h_v_not_one, { "atm.pw_control_byte.v.not_zero", PI_MALFORMED, PI_ERROR, "1:1 VCC mode: V bit must be 0 to indicate that VCI is absent", EXPFILL }},
		{ &ei_cell_h_rsv, { "atm.pw_control_byte.rsv.not_zero", PI_MALFORMED, PI_ERROR, "Reserved bits in the 3rd byte of CW must be 0", EXPFILL }},
	};
	expert_module_t* expert_cell;

	proto_n1_cw =
		proto_register_protocol(pwc_longname_pw_atm_n1_cw
					,shortname_n1_cw
					,"mplspwatmn1cw");
	proto_11_or_aal5_pdu =
		proto_register_protocol(pwc_longname_pw_atm_11_or_aal5_pdu
					,shortname_11_or_aal5_pdu
					,"mplspwatm11_or_aal5pdu");
	proto_aal5_sdu =
		proto_register_protocol(pwc_longname_pw_atm_aal5_sdu
					,shortname_aal5_sdu
					,"mplspwatmaal5sdu");
	proto_n1_nocw =
		proto_register_protocol(pwc_longname_pw_atm_n1_nocw
					,shortname_n1_nocw
					,"mplspwatmn1nocw");
	proto_control_word =
		proto_register_protocol("MPLS PW ATM Control Word"
					,"MPLS PW ATM Control Word"
					,"mplspwatmcontrolword");
	proto_cell_header =
		proto_register_protocol("MPLS PW ATM Cell Header"
					,"MPLS PW ATM Cell Header"
					,"mplspwatmcellheader");
	proto_cell =
		proto_register_protocol("ATM Cell"
					,"ATM Cell"
					,"mplspwatmcell");

	proto_register_field_array( proto_cell	 		,hfa_cell	,array_length(hfa_cell));
	expert_cell = expert_register_protocol(proto_cell);
	expert_register_field_array(expert_cell, ei, array_length(ei));

	proto_register_field_array( proto_cell_header		,hfa_cell_header,array_length(hfa_cell_header));
	proto_register_field_array( proto_control_word		,hfa_cw		,array_length(hfa_cw));
	proto_register_field_array( proto_n1_nocw		,hfa_n1_nocw	,array_length(hfa_n1_nocw));
	proto_register_field_array( proto_n1_cw			,hfa_n1_cw	,array_length(hfa_n1_cw));
	proto_register_field_array( proto_11_or_aal5_pdu	,hfa_11_aal5pdu	,array_length(hfa_11_aal5pdu));
	proto_register_field_array( proto_aal5_sdu		,hfa_aal5_sdu	,array_length(hfa_aal5_sdu));

	proto_register_subtree_array(ett_array, array_length(ett_array));

	register_dissector("mpls_pw_atm_aal5_sdu"	,dissect_aal5_sdu	,proto_aal5_sdu);
	register_dissector("mpls_pw_atm_11_or_aal5_pdu"	,dissect_11_or_aal5_pdu	,proto_11_or_aal5_pdu);
	register_dissector("mpls_pw_atm_n1_cw"		,dissect_n1_cw		,proto_n1_cw);
	register_dissector("mpls_pw_atm_n1_nocw"	,dissect_n1_nocw	,proto_n1_nocw);
	new_register_dissector("mpls_pw_atm_control_word"	,dissect_control_word	,proto_control_word);
	new_register_dissector("mpls_pw_atm_cell"	,dissect_cell		,proto_cell);
	new_register_dissector("mpls_pw_atm_cell_header",dissect_cell_header	,proto_cell_header);
	{
		static const char description_allow_cw_length_nonzero[] =
			"Enable to allow non-zero Length in Control Word."
			" This may be needed to correctly decode traffic from some legacy devices"
			" which generate non-zero Length even if there is no padding in the packet."
			" Note that Length should have proper value (dissector checks this anyway)."
			"\n\n"
			"Disable to blame all packets with CW.Length <> 0. This conforms to RFC4717."
			;
		static const char description_extend_cw_length_with_rsvd[] =
			"Enable to use reserved bits (8..9) of Control Word as an extension of CW.Length."
			" This may be needed to correctly decode traffic from some legacy devices"
			" which uses reserved bits as extension of Length"
			"\n\n"
			"Disable to blame all packets with CW.Reserved <> 0. This conforms to RFC4717."
			;
		module_t * module_n1_cw;
		module_t * module_aal5_sdu;

		module_n1_cw = prefs_register_protocol(proto_n1_cw,NULL);
		prefs_register_bool_preference(module_n1_cw
			,"allow_cw_length_nonzero"
			,"Allow CW.Length <> 0"
			,&description_allow_cw_length_nonzero[0]
			,&pref_n1_cw_allow_cw_length_nonzero);
		prefs_register_bool_preference(module_n1_cw
			,"extend_cw_length_with_rsvd"
			,"Use CW.Reserved as extension of CW.Length"
			,&description_extend_cw_length_with_rsvd[0]
			,&pref_n1_cw_extend_cw_length_with_rsvd);

		module_aal5_sdu = prefs_register_protocol(proto_aal5_sdu,NULL);
		prefs_register_bool_preference(module_aal5_sdu
			,"allow_cw_length_nonzero_aal5"
			,"Allow CW.Length <> 0"
			,&description_allow_cw_length_nonzero[0]
			,&pref_aal5_sdu_allow_cw_length_nonzero);
		prefs_register_bool_preference(module_aal5_sdu
			,"extend_cw_length_with_rsvd_aal5"
			,"Use CW.Reserved as extension of CW.Length"
			,&description_extend_cw_length_with_rsvd[0]
			,&pref_aal5_sdu_extend_cw_length_with_rsvd);
	}
}


void
proto_reg_handoff_pw_atm_ata(void)
{
	dissector_handle_t h;
	h = find_dissector("mpls_pw_atm_n1_cw");
	dissector_add_for_decode_as( "mpls.label", h );
	h = find_dissector("mpls_pw_atm_n1_nocw");
	dissector_add_for_decode_as( "mpls.label", h );
	h = find_dissector("mpls_pw_atm_11_or_aal5_pdu");
	dissector_add_for_decode_as( "mpls.label", h );
	h = find_dissector("mpls_pw_atm_aal5_sdu");
	dissector_add_for_decode_as( "mpls.label", h );

	dh_cell		   = find_dissector("mpls_pw_atm_cell");
	dh_cell_header	   = find_dissector("mpls_pw_atm_cell_header");
	dh_control_word	   = find_dissector("mpls_pw_atm_control_word");
	dh_atm_truncated   = find_dissector("atm_truncated");
	dh_atm_untruncated = find_dissector("atm_untruncated");
	dh_atm_oam_cell	   = find_dissector("atm_oam_cell");
	dh_padding	   = find_dissector("pw_padding");
	dh_data		   = find_dissector("data");
}
