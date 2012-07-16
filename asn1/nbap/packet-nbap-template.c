/* packet-nbap-template.c
 * Routines for UMTS Node B Application Part(NBAP) packet dissection
 * Copyright 2005, 2009 Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref: 3GPP TS 25.433 version 6.6.0 Release 6
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/asn1.h>
#include <epan/conversation.h>

#include "packet-per.h"
#include "packet-isup.h"
#include "packet-umts_fp.h"
#include "packet-umts_mac.h"
#include "packet-rrc.h"
#include "packet-rlc.h"
#include "packet-nbap.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iub interface NBAP signalling"
#define PSNAME "NBAP"
#define PFNAME "nbap"

/* Debug */
#if 0
#define nbap_debug0(str) g_warning(str)
#define nbap_debug1(str,p1) g_warning(str,p1)
#define nbap_debug2(str,p1,p2) g_warning(str,p1,p2)
#define nbap_debug3(str,p1,p2,p3) g_warning(str,p1,p2,p3)
#else
#define nbap_debug0(str)
#define nbap_debug1(str,p1)
#define nbap_debug2(str,p1,p2)
#define nbap_debug3(str,p1,p2,p3)
#endif

/* Global variables */
dissector_handle_t fp_handle;
static guint32	transportLayerAddress_ipv4;
static guint16	BindingID_port;

#include "packet-nbap-val.h"

/* Initialize the protocol and registered fields */
static int proto_nbap = -1;
static int hf_nbap_transportLayerAddress_ipv4 = -1;
static int hf_nbap_transportLayerAddress_ipv6 = -1;
static int hf_nbap_transportLayerAddress_nsap = -1;

#include "packet-nbap-hf.c"

/* Initialize the subtree pointers */
static int ett_nbap = -1;
static int ett_nbap_TransportLayerAddress = -1;
static int ett_nbap_TransportLayerAddress_nsap = -1;
static int ett_nbap_ib_sg_data = -1;

#include "packet-nbap-ett.c"


extern int proto_fp;

/*
 * Structure to build information needed to dissect the FP flow beeing set up.
 */
struct _nbap_msg_info_for_fp
{
	guint32 ProcedureCode;
	guint32 ddMode;
	gboolean is_uplink;
	gint channel;                       /* see definitions in packet-umts_fp.h Channel types */
	guint8  dch_crc_present;            /* 0=No, 1=Yes, 2=Unknown */
};

typedef struct
{
	gint num_dch_in_flow;
	gint next_dch;
	gint num_ul_chans;
	gint ul_chan_tf_size[MAX_FP_CHANS];
	gint ul_chan_num_tbs[MAX_FP_CHANS];
	gint num_dl_chans;
	gint dl_chan_tf_size[MAX_FP_CHANS];
	gint dl_chan_num_tbs[MAX_FP_CHANS];

}nbap_dch_channel_info_t;

nbap_dch_channel_info_t nbap_dch_chnl_info[maxNrOfDCHs];

/* Struct to collect E-DCH data in a packet 
 * As the address data comes before the ddi entries
 * we save the address to be able to find the conversation and update the
 * conversation data.
 */
typedef struct
{
	address 	crnc_address;
	guint16		crnc_port;
	gint		no_ddi_entries;
	guint8		edch_ddi[MAX_EDCH_DDIS];
	guint		edch_macd_pdu_size[MAX_EDCH_DDIS];
	guint8		edch_type;  /* 1 means T2 */
	guint8		lchId[MAX_EDCH_DDIS];	/*Logical channel ids.*/

} nbap_edch_channel_info_t;

nbap_edch_channel_info_t nbap_edch_channel_info[maxNrOfEDCHMACdFlows];

typedef struct
{
	address 			crnc_address;
	guint16				crnc_port;
	enum fp_rlc_mode	rlc_mode;
	guint32				hsdsch_physical_layer_category;
	guint8				entity;	/* "ns" means type 1 and "ehs" means type 2, type 3 == ?*/
} nbap_hsdsch_channel_info_t;

nbap_hsdsch_channel_info_t nbap_hsdsch_channel_info[maxNrOfMACdFlows];

typedef struct
{
	address 			crnc_address;
	guint16				crnc_port;
	enum fp_rlc_mode	rlc_mode;
} nbap_common_channel_info_t;

nbap_common_channel_info_t nbap_common_channel_info[maxNrOfMACdFlows];	/*TODO: Fix this!*/

gint g_num_dch_in_flow;
/* maxNrOfTFs					INTEGER ::= 32 */
gint g_dchs_in_flow_list[maxNrOfTFs];

gint hsdsch_macdflow_ids[maxNrOfMACdFlows];
struct _nbap_msg_info_for_fp g_nbap_msg_info_for_fp;

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ddMode;
static const gchar *ProcedureID;
static guint32 t_dch_id, dch_id, prev_dch_id, commonphysicalchannelid, e_dch_macdflow_id, hsdsch_macdflow_id=3, 
	   e_dch_ddi_value,logical_channel_id,common_macdflow_id;
static guint32 MACdPDU_Size, commontransportchannelid;
static guint num_items;
static gint paging_indications;
static guint32 ib_type, segment_type;

enum TransportFormatSet_type_enum
{
	NBAP_DCH_UL,
	NBAP_DCH_DL,
	NBAP_CPCH,
	NBAP_FACH,
	NBAP_PCH
};

enum TransportFormatSet_type_enum transportFormatSet_type;

/****************************/
/* GUI Stuff */
typedef struct _attribute_type_t {
  gchar* attribute_type;
  gchar* attribute_desc;
} attribute_type_t;
/*static attribute_type_t* attribute_types = NULL;
static guint num_attribute_types = 0;
static GHashTable* attribute_types_hash = NULL;*/

/* Dissector tables */
static dissector_table_t nbap_ies_dissector_table;
static dissector_table_t nbap_extension_dissector_table;
static dissector_table_t nbap_proc_imsg_dissector_table;
static dissector_table_t nbap_proc_sout_dissector_table;
static dissector_table_t nbap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


#include "packet-nbap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(nbap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(nbap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_imsg_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_sout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_uout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static void
dissect_nbap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*nbap_item = NULL;
	proto_tree	*nbap_tree = NULL;

	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBAP");

	/* create the nbap protocol tree */
	nbap_item = proto_tree_add_item(tree, proto_nbap, tvb, 0, -1, ENC_NA);
	nbap_tree = proto_item_add_subtree(nbap_item, ett_nbap);

	dissect_NBAP_PDU_PDU(tvb, pinfo, nbap_tree);
}

/*static void
attribute_types_initialize_cb(void)
{
}
static void
attribute_types_free_cb(void*r _U_)
{
}
static void
attribute_types_update_cb(void *r _U_, const char **err _U_)
{
	g_warning("Running attr types update");


}

static void *
attribute_types_copy_cb(void* n _U_, const void* o _U_, size_t siz _U_)
{


  return NULL;
}*/

/*--- proto_register_nbap -------------------------------------------*/
void proto_register_nbap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_nbap_transportLayerAddress_ipv4,
      { "transportLayerAddress IPv4", "nbap.transportLayerAddress_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nbap_transportLayerAddress_ipv6,
      { "transportLayerAddress IPv6", "nbap.transportLayerAddress_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nbap_transportLayerAddress_nsap,
      { "transportLayerAddress NSAP", "nbap.transportLayerAddress_NSAP",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-nbap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_nbap,
		  &ett_nbap_TransportLayerAddress,
		  &ett_nbap_TransportLayerAddress_nsap,
		  &ett_nbap_ib_sg_data,
#include "packet-nbap-ettarr.c"
  };

  /* UAT for header fields */
 /* static uat_field_t custom_attribute_types_uat_fields[] = {
     UAT_FLD_CSTRING(attribute_types, attribute_type, "Attribute type", "Attribute type"),
     UAT_FLD_CSTRING(attribute_types, attribute_desc, "Description", "Description of the value matching type"),
     UAT_END_FIELDS
  };
  */
	/*uat_t *attributes_uat;*/
	  
  /* Register protocol */
  proto_nbap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_nbap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("nbap", dissect_nbap, proto_nbap);

  /* Setting up GUI stuff*/
    /* UAT */
  /*attributes_uat = uat_new("Custom NBAP maps",
                           sizeof(attribute_type_t),
                           "custom_ldap_attribute_types",
                           TRUE,
                           (void*) &attribute_types,
                           &num_attribute_types,
                           UAT_CAT_FIELDS,
                           NULL,
                           attribute_types_copy_cb,
                           attribute_types_update_cb,
                           attribute_types_free_cb,
                           attribute_types_initialize_cb,
                           custom_attribute_types_uat_fields);*/

  /*prefs_register_uat_preference(nbap_module, "custom_ldap_attribute_types",
                                "Custom AttributeValue types",
                                "A table to define custom LDAP attribute type values for which fields can be setup and used for filtering/data extraction etc.",
                                attributes_uat);*/

  /* Register dissector tables */
  nbap_ies_dissector_table = register_dissector_table("nbap.ies", "NBAP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  nbap_extension_dissector_table = register_dissector_table("nbap.extension", "NBAP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  nbap_proc_imsg_dissector_table = register_dissector_table("nbap.proc.imsg", "NBAP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_STRING, BASE_NONE);
  nbap_proc_sout_dissector_table = register_dissector_table("nbap.proc.sout", "NBAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_STRING, BASE_NONE);
  nbap_proc_uout_dissector_table = register_dissector_table("nbap.proc.uout", "NBAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_STRING, BASE_NONE);

}


/*--- proto_reg_handoff_nbap ---------------------------------------*/
void
proto_reg_handoff_nbap(void)
{
	dissector_handle_t nbap_handle;

	nbap_handle = find_dissector("nbap");
	fp_handle = find_dissector("fp");
	dissector_add_uint("sctp.ppi", NBAP_PAYLOAD_PROTOCOL_ID, nbap_handle);
	dissector_add_handle("sctp.port", nbap_handle);  /* for "decode-as" */

#include "packet-nbap-dis-tab.c"
}


