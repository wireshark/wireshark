/* packet-bssap.c
 * Routines for Base Station Subsystem Application Part (BSSAP/BSAP) dissection
 * Specifications from 3GPP2 (www.3gpp2.org) and 3GPP (www.3gpp.org)
 *	IOS 4.0.1 (BSAP)
 *	GSM 08.06 (BSSAP)
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * $Id: packet-bssap.c,v 1.2 2003/10/24 00:38:34 guy Exp $
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

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>

#include "epan/packet.h"
#include "prefs.h"
#include "packet-bssap.h"

#define BSSAP 0
#define BSAP  1

#define BSSAP_OR_BSAP_DEFAULT BSSAP

#define PDU_TYPE_OFFSET 0
#define PDU_TYPE_LENGTH 1

/* Same as below but with names typed out */
static const value_string bssap_pdu_type_values[] = {
    { BSSAP_PDU_TYPE_BSSMAP,	"BSS Management" },
    { BSSAP_PDU_TYPE_DTAP,	"Direct Transfer" },
    { 0,			NULL } };

static const value_string bsap_pdu_type_values[] = {
    { BSSAP_PDU_TYPE_BSSMAP,	"BS Management" },
    { BSSAP_PDU_TYPE_DTAP,	"Direct Transfer" },
    { 0,			NULL } };

/* Same as above but in acronym for (for the Info column) */
static const value_string bssap_pdu_type_acro_values[] = {
    { BSSAP_PDU_TYPE_BSSMAP,	"BSSMAP" },
    { BSSAP_PDU_TYPE_DTAP,	"DTAP" },
    { 0,			NULL } };

/* Same as above but in acronym for (for the Info column) */
static const value_string bsap_pdu_type_acro_values[] = {
    { BSSAP_PDU_TYPE_BSSMAP,	"BSMAP" },
    { BSSAP_PDU_TYPE_DTAP,	"DTAP" },
    { 0,			NULL } };

#define PARAMETER_DLCI		0x00
#define PARAMETER_LENGTH	0x01
#define PARAMETER_DATA		0x02

#define DLCI_LENGTH		1
#define LENGTH_LENGTH		1
#define DATA_LENGTH		1

#define CC_MASK			0xc0
#define SAPI_MASK		0x07

static const value_string bssap_cc_values[] = {
    { 0x00,		"not further specified" },
    { 0x80,		"FACCH or SDCCH" },
    { 0xc0,		"SACCH" },
    { 0,		NULL } };

static const value_string bsap_cc_values[] = {
    { 0x00,		"default for TIA/EIA/IS-2000" },
    { 0,		NULL } };

static const value_string bssap_sapi_values[] = {
    { 0x00,		"RR/MM/CC" },
    { 0x03,		"SMS" },
    { 0,		NULL } };

static const value_string bsap_sapi_values[] = {
    { 0x00,		"Not used" },
    { 0,		NULL } };


/* Initialize the protocol and registered fields */
static int proto_bssap = -1;
static int hf_bssap_pdu_type = -1;
static int hf_bsap_pdu_type = -1;
static int hf_bssap_dlci_cc = -1;
static int hf_bsap_dlci_cc = -1;
static int hf_bssap_dlci_sapi = -1;
static int hf_bsap_dlci_sapi = -1;
static int hf_bssap_length = -1;

/* Initialize the subtree pointers */
static gint ett_bssap = -1;
static gint ett_bssap_dlci = -1;

static dissector_handle_t data_handle;

static dissector_table_t bssap_dissector_table;
static dissector_table_t bsap_dissector_table;

/*
 * Keep track of pdu_type so we can call appropriate sub-dissector
 */
static guint8	pdu_type = 0xFF;

static guint	bssap_or_bsap_global = BSSAP_OR_BSAP_DEFAULT;


/* FORWARD DECLARATIONS */

void proto_reg_handoff_bssap(void);

static void
dissect_bssap_unknown_message(tvbuff_t *message_tvb, proto_tree *bssap_tree)
{
    guint32	message_length;

    message_length = tvb_length(message_tvb);

    proto_tree_add_text(bssap_tree, message_tvb, 0, message_length,
	"Unknown message (%u byte%s)",
	message_length, plurality(message_length, "", "s"));
}

static void
dissect_bssap_unknown_param(tvbuff_t *tvb, proto_tree *tree, guint8 type, guint16 length)
{
    proto_tree_add_text(tree, tvb, 0, length,
	"Unknown parameter 0x%x (%u byte%s)",
	type, length, plurality(length, "", "s"));
}

static void
dissect_bssap_data_param(tvbuff_t *tvb, packet_info *pinfo,
			proto_tree *bssap_tree, proto_tree *tree)
{
    if ((pdu_type <= 0x01))
    {
	if (bssap_or_bsap_global == BSSAP)
	{
	    /* BSSAP */
	    if (dissector_try_port(bssap_dissector_table, pdu_type, tvb, pinfo, tree)) return;
	}
	else
	{
	    /* BSAP */
	    if (dissector_try_port(bsap_dissector_table, pdu_type, tvb, pinfo, tree)) return;
	}
    }

    /* No sub-dissection occured, treat it as raw data */
    call_dissector(data_handle, tvb, pinfo, bssap_tree);
}

static void
dissect_bssap_dlci_param(tvbuff_t *tvb, proto_tree *tree, guint8 length)
{
    proto_item	*dlci_item = 0;
    proto_tree	*dlci_tree = 0;
    guint8	cc, sapi;

    dlci_item =
	proto_tree_add_text(tree, tvb, 0, length,
	    "Data Link Connection Identifier");

    dlci_tree = proto_item_add_subtree(dlci_item, ett_bssap_dlci);

    cc = tvb_get_guint8(tvb, 0) & CC_MASK;
    sapi = tvb_get_guint8(tvb, 0) & SAPI_MASK;

    if (bssap_or_bsap_global == BSSAP)
    {
	proto_tree_add_uint(dlci_tree, hf_bssap_dlci_cc, tvb, 0, length, cc);
	proto_tree_add_uint(dlci_tree, hf_bssap_dlci_sapi, tvb, 0, length, sapi);
    }
    else
    {
	proto_tree_add_uint(dlci_tree, hf_bsap_dlci_cc, tvb, 0, length, cc);
	proto_tree_add_uint(dlci_tree, hf_bsap_dlci_sapi, tvb, 0, length, sapi);
    }
}

static void
dissect_bssap_length_param(tvbuff_t *tvb, proto_tree *tree, guint8 length)
{
    guint8	data_length;

    data_length = tvb_get_guint8(tvb, 0);
    proto_tree_add_uint(tree, hf_bssap_length, tvb, 0, length, data_length);
}

/*
 * Dissect a parameter given its type, offset into tvb, and length.
 */
static guint16
dissect_bssap_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bssap_tree,
		       proto_tree *tree, guint8 parameter_type, guint8 offset,
		       guint16 parameter_length)
{
    tvbuff_t *parameter_tvb;

    parameter_tvb = tvb_new_subset(tvb, offset, parameter_length, parameter_length);

    switch (parameter_type)
    {
    case PARAMETER_DLCI:
	dissect_bssap_dlci_param(parameter_tvb, bssap_tree, parameter_length);
	break;

    case PARAMETER_LENGTH:
	dissect_bssap_length_param(parameter_tvb, bssap_tree, parameter_length);
	break;

    case PARAMETER_DATA:
	dissect_bssap_data_param(parameter_tvb, pinfo, bssap_tree, tree);
	break;

    default:
	dissect_bssap_unknown_param(parameter_tvb, bssap_tree, parameter_type,
	    parameter_length);
	break;
    }

    return(parameter_length);
}

static guint16
dissect_bssap_var_parameter(tvbuff_t *tvb, packet_info *pinfo,
				proto_tree *bssap_tree, proto_tree *tree,
				guint8 parameter_type, guint8 offset)
{
    guint16	parameter_length;
    guint8	length_length;

    parameter_length = tvb_get_guint8(tvb, offset);
    length_length = LENGTH_LENGTH;

    offset += length_length;

    dissect_bssap_parameter(tvb, pinfo, bssap_tree, tree, parameter_type,
	offset, parameter_length);

    return(parameter_length + length_length);
}

static void
dissect_bssap_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bssap_tree,
		     proto_tree *tree)
{
    guint8	offset = 0;

    /*
     * Extract the PDU type
     */
    pdu_type = tvb_get_guint8(tvb, PDU_TYPE_OFFSET);
    offset = PDU_TYPE_LENGTH;

    if (bssap_tree)
    {
	/*
	 * add the message type to the protocol tree
	 */
	proto_tree_add_uint(bssap_tree,
	    (bssap_or_bsap_global == BSSAP) ? hf_bssap_pdu_type : hf_bsap_pdu_type,
	    tvb, PDU_TYPE_OFFSET, PDU_TYPE_LENGTH, pdu_type);
    }

    /* Starting a new message dissection */

    switch (pdu_type)
    {
    case BSSAP_PDU_TYPE_BSSMAP:
	offset += dissect_bssap_parameter(tvb, pinfo, bssap_tree, tree,
				     PARAMETER_LENGTH, offset,
				     LENGTH_LENGTH);
	offset += dissect_bssap_var_parameter(tvb, pinfo, bssap_tree, tree,
				    PARAMETER_DATA,
				    (offset - LENGTH_LENGTH));
	break;

    case BSSAP_PDU_TYPE_DTAP:
	offset += dissect_bssap_parameter(tvb, pinfo, bssap_tree, tree,
				     PARAMETER_DLCI,
				     offset, DLCI_LENGTH);
	offset += dissect_bssap_parameter(tvb, pinfo, bssap_tree, tree,
				     PARAMETER_LENGTH, offset,
				     LENGTH_LENGTH);
	offset += dissect_bssap_var_parameter(tvb, pinfo, bssap_tree, tree,
				    PARAMETER_DATA,
				    (offset - LENGTH_LENGTH));
	break;

    default:
	if (check_col(pinfo->cinfo, COL_INFO))
	{
	    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
		val_to_str(pdu_type, ((bssap_or_bsap_global == BSSAP) ?
		    bssap_pdu_type_acro_values : bsap_pdu_type_acro_values),
		    "Unknown"));

	}

	dissect_bssap_unknown_message(tvb, bssap_tree);
	break;
    }
}

static void
dissect_bssap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item	*bssap_item;
    proto_tree	*bssap_tree = NULL;

    /*
     * Make entry in the Protocol column on summary display
     */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, ((bssap_or_bsap_global == BSSAP) ? "BSSAP" : "BSAP"));
    }

    if (tree)
    {
	/*
	 * create the bssap protocol tree
	 */
	proto_tree_add_item_hidden(tree, proto_bssap, tvb, 0, -1, FALSE);
	bssap_item = proto_tree_add_text(tree, tvb, 0, -1, (bssap_or_bsap_global == BSSAP) ? "BSSAP" : "BSAP");
	bssap_tree = proto_item_add_subtree(bssap_item, ett_bssap);
    }

    /* dissect the message */

    dissect_bssap_message(tvb, pinfo, bssap_tree, tree);
}

static gboolean
dissect_bssap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Is it a BSSAP/BSAP packet?
     *    If octet_1 == 0x00 and octet_2 == length(tvb) - 2
     * or if octet_1 == 0x01 and octet_3 == length(tvb) - 3
     * then we'll assume it is a bssap packet
     */
    switch (tvb_get_guint8(tvb, 0))
    {
    case 0x00:
	if (tvb_get_guint8(tvb, 1) != (tvb_length(tvb) - 2)) { return(FALSE); }
	break;

    case 0x01:
	if (tvb_get_guint8(tvb, 2) != (tvb_length(tvb) - 3)) { return(FALSE); }
	break;

    default:
	return(FALSE);
    }

    dissect_bssap(tvb, pinfo, tree);

    return(TRUE);
}

/* Register the protocol with Ethereal */
void
proto_register_bssap(void)
{
    module_t	*bssap_module;

    /* Setup list of header fields */
    static hf_register_info hf[] = {
	{ &hf_bssap_pdu_type,
	    { "Message Type", "bssap.pdu_type",
		FT_UINT8, BASE_HEX, VALS(bssap_pdu_type_values), 0x0,
		"", HFILL}},
	{ &hf_bsap_pdu_type,
	    { "Message Type", "bsap.pdu_type",
		FT_UINT8, BASE_HEX, VALS(bsap_pdu_type_values), 0x0,
		"", HFILL}},
	{ &hf_bssap_dlci_cc,
	    { "Control Channel", "bssap.dlci.cc",
		FT_UINT8, BASE_HEX, VALS(bssap_cc_values), CC_MASK,
		"", HFILL}},
	{ &hf_bsap_dlci_cc,
	    { "Control Channel", "bsap.dlci.cc",
		FT_UINT8, BASE_HEX, VALS(bsap_cc_values), CC_MASK,
		"", HFILL}},
	{ &hf_bssap_dlci_sapi,
	    { "SAPI", "bssap.dlci.sapi",
		FT_UINT8, BASE_HEX, VALS(bssap_sapi_values), SAPI_MASK,
		"", HFILL}},
	{ &hf_bsap_dlci_sapi,
	    { "SAPI", "bsap.dlci.sapi",
		FT_UINT8, BASE_HEX, VALS(bsap_sapi_values), SAPI_MASK,
		"", HFILL}},
	{ &hf_bssap_length,
	    { "Length", "bssap.length",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"", HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_bssap,
	&ett_bssap_dlci,
    };

    static enum_val_t bssap_or_bsap_options[] = {
	{ "BSSAP",		BSSAP },
	{ "BSAP",		BSAP  },
	{ NULL,			0 }
    };


    /* Register the protocol name and description */
    proto_bssap = proto_register_protocol("BSSAP/BSAP", "BSSAP", "bssap");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bssap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bssap_module = prefs_register_protocol(proto_bssap, proto_reg_handoff_bssap);

    prefs_register_enum_preference(bssap_module,
	"bsap_or_bssap",
	"Identify to sub-dissector as",
	"For the sake of sub-dissectors registering to accept data from the BSSAP/BSAP dissector, this defines whether it is identified as BSSAP or BSAP.",
	&bssap_or_bsap_global,
	bssap_or_bsap_options,
	FALSE);

    bssap_dissector_table = register_dissector_table("bssap.pdu_type", "BSSAP Message Type", FT_UINT8, BASE_DEC);
    bsap_dissector_table = register_dissector_table("bsap.pdu_type", "BSAP Message Type", FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_bssap(void)
{
    static gboolean bssap_prefs_initialized = FALSE;


    if (!bssap_prefs_initialized)
    {
	heur_dissector_add("sccp", dissect_bssap_heur, proto_bssap);

	bssap_prefs_initialized = TRUE;
    }

    data_handle = find_dissector("data");
}
