/* packet-h245_asn1.c
 * Routines for h245 packet dissection
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * To quote the author of the previous H245 dissector:
 *   "This is a complete replacement of the previous limitied dissector
 * that Ronnie was crazy enough to write by hand. It was a lot of time
 * to hack it by hand, but it is incomplete and buggy and it is good when
 * it will go away."
 * Ronnie did a great job and all the VoIP users had made good use of it!
 * Credit to Tomas Kukosa for developing the Asn2eth compiler.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include <epan/prefs.h>
#include "tap.h"
#include "packet-h245.h"
#include "packet-tpkt.h"
#include "packet-per.h"
#include <epan/t35.h>
#include <epan/emem.h>
#include "packet-rtp.h"
#include "packet-rtcp.h"
#include "packet-ber.h"

#define PNAME  "MULTIMEDIA-SYSTEM-CONTROL"
#define PSNAME "H.245"
#define PFNAME "h245"

static dissector_handle_t rtp_handle=NULL;
static dissector_handle_t rtcp_handle=NULL;
static dissector_table_t nsp_object_dissector_table;
static dissector_table_t nsp_h221_dissector_table;
static dissector_handle_t nsp_handle;
static dissector_handle_t data_handle;
static dissector_handle_t h245_handle;
static dissector_handle_t MultimediaSystemControlMessage_handle;

static void reset_h245_packet_info(h245_packet_info *pi);
static int hf_h245_pdu_type = -1;
static int hf_h245Manufacturer = -1;
static int h245_tap = -1;
static int ett_h245 = -1;
static int h245dg_tap = -1;
h245_packet_info *h245_pi=NULL;

static gboolean h245_reassembly = TRUE;
static gboolean h245_shorttypes = FALSE;
static const value_string h245_RequestMessage_short_vals[] = {
	{  0,	"NSM" },
	{  1,	"MSD" },
	{  2,	"TCS" },
	{  3,	"OLC" },
	{  4,	"CLC" },
	{  5,	"RCC" },
	{  6,	"MES" },
	{  7,	"RME" },
	{  8,	"RM" },
	{  9,	"RTDR" },
	{ 10,	"MLR" },
	{ 11,	"CMR" },
	{ 12,	"CR" },
	{ 13,	"MR" },
	{ 14,	"LCRR" },
	{ 15,	"GR" },
	{  0, NULL }
};
static const value_string h245_ResponseMessage_short_vals[] = {
	{  0,	"NSM" },
	{  1,	"MSDAck" },
	{  2,	"MSDReject" },
	{  3,	"TCSAck" },
	{  4,	"TCSReject" },
	{  5,	"OLCAck" },
	{  6,	"OLCReject" },
	{  7,	"CLCAck" },
	{  8,	"RCCAck" },
	{  9,	"RCCReject" },
	{ 10,	"MESAck" },
	{ 11,	"MESReject" },
	{ 12,	"RMEAck" },
	{ 13,	"RMEReject" },
	{ 14,	"RMAck" },
	{ 15,	"RMReject" },
	{ 16,	"RTDResponse" },
	{ 17,	"MLAck" },
	{ 18,	"MLReject" },
	{ 19,	"CMResponse" },
	{ 20,	"CResponse" },
	{ 21,	"MResponse" },
	{ 22,	"LCRAck" },
	{ 23,	"LCRReject" },
	{ 24,	"GR" },
	{  0, NULL }
};
static const value_string h245_IndicationMessage_short_vals[] = {
	{  0,	"NSM" },
	{  1,	"FNU" },
	{  2,	"MSDRelease" },
	{  3,	"TCSRelease" },
	{  4,	"OLCConfirm" },
	{  5,	"RCCRelease" },
	{  6,	"MESRelease" },
	{  7,	"RMERelease" },
	{  8,	"RMRelease" },
	{  9,	"MI" },
	{ 10,	"JI" },
	{ 11,	"H223SI" },
	{ 12,	"NATMVCI" },
	{ 13,	"UII" },
	{ 14,	"H2250MSI" },
	{ 15,	"MCLI" },
	{ 16,	"CI" },
	{ 17,	"VI" },
	{ 18,	"FNS" },
	{ 19,	"MultilinkIndication" },
	{ 20,	"LCRRelease" },
	{ 21,	"FCIndication" },
	{ 22,	"MMRI" },
	{ 22,	"GI" },
	{  0, NULL }
};
static const value_string h245_CommandMessage_short_vals[] = {
	{  0,	"NSM" },
	{  1,	"MLOC" },
	{  2,	"STCS" },
	{  3,	"EC" },
	{  4,	"FCC" },
	{  5,	"ESC" },
	{  6,	"MC" },
	{  7,	"CMC" },
	{  8,	"CC" },
	{  9,	"H223MR" },
	{ 10,	"NATMVCC" },
	{ 11,	"MMRC" },
	{ 12,	"GC" },
	{  0, NULL }
};
static const value_string h245_AudioCapability_short_vals[] = {
        {  0, "nonStd" },
        {  1, "g711A" },
        {  2, "g711A56k" },
        {  3, "g711U" },
        {  4, "g711U56k" },
        {  5, "g722-64k" },
        {  6, "g722-56k" },
        {  7, "g722-48k" },
        {  8, "g7231" },
        {  9, "g728" },
        { 10, "g729" },
        { 11, "g729A" },
        { 12, "is11172" },
        { 13, "is13818" },
        { 14, "g729B" },
        { 15, "g729AB" },
        { 16, "g7231C" },
        { 17, "gsmFR" },
        { 18, "gsmHR" },
        { 19, "gsmEFR" },
        { 20, "generic" },
        { 21, "g729Ext" },
        { 22, "vbd" },
        { 23, "audioTelEvent" },
        { 24, "audioTone" },
        {  0, NULL }
};

/* To put the codec type only in COL_INFO when
   an OLC is read */

const char* codec_type = NULL;
static char *standard_oid_str;
static guint32 ipv4_address;
static guint32 ipv4_port;
static guint32 rtcp_ipv4_address;
static guint32 rtcp_ipv4_port;
static gboolean media_channel;
static gboolean media_control_channel;

/* NonStandardParameter */
static char *nsiOID;
static guint32 h221NonStandard;
static guint32 t35CountryCode;
static guint32 t35Extension;
static guint32 manufacturerCode;

static const value_string h245_RFC_number_vals[] = {
	{  2190,	"RFC 2190 - H.263 Video Streams" },
	{  2429,	"RFC 2429 - 1998 Version of ITU-T Rec. H.263 Video (H.263+)" },
	{  3267,	"RFC 3267 - Adaptive Multi-Rate (AMR) and Adaptive Multi-Rate Wideband (AMR-WB)" },
	{  0, NULL }
};
/* Initialize the protocol and registered fields */
int proto_h245 = -1;
#include "packet-h245-hf.c"

/* Initialize the subtree pointers */
#include "packet-h245-ett.c"

#include "packet-h245-fn.c"

static void
dissect_h245(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	/*
	 * MultimediaSystemControlMessage_handle is the handle for
	 * dissect_h245_h245, so we don't want to do any h245_pi or tap stuff here.
	 */
	dissect_tpkt_encap(tvb, pinfo, parent_tree, h245_reassembly, MultimediaSystemControlMessage_handle);
}

static void
dissect_h245_h245(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
	}

	it=proto_tree_add_protocol_format(parent_tree, proto_h245, tvb, 0, tvb_length(tvb), PSNAME);
	tr=proto_item_add_subtree(it, ett_h245);

	/* assume that whilst there is more tvb data, there are more h245 commands */
	while ( tvb_length_remaining( tvb, offset>>3 )>0 ){
		h245_pi=ep_alloc(sizeof(h245_packet_info));
		offset = dissect_h245_MultimediaSystemControlMessage(tvb, offset, pinfo ,tr, hf_h245_pdu_type);
		tap_queue_packet(h245dg_tap, pinfo, h245_pi);
		offset = (offset+0x07) & 0xfffffff8;
		h245_pi = NULL;
	}
}

void
dissect_h245_OpenLogicalChannelCodec(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, char *codec_str) {
  dissect_OpenLogicalChannel_PDU(tvb, pinfo, tree);

  if (h245_pi != NULL) h245_pi->msg_type = H245_OpenLogChn;

  if (codec_str && codec_type){
        strncpy(codec_str, codec_type, 50);
  }

}

/*--- proto_register_h245 -------------------------------------------*/
void proto_register_h245(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_h245_pdu_type,
 { "PDU Type", "h245.pdu_type", FT_UINT32, BASE_DEC,
		VALS(h245_MultimediaSystemControlMessage_vals), 0, "Type of H.245 PDU", HFILL }},
	{ &hf_h245Manufacturer,
		{ "H.245 Manufacturer", "h245.Manufacturer", FT_UINT32, BASE_HEX,
		VALS(H221ManufacturerCode_vals), 0, "h245.H.221 Manufacturer", HFILL }},
#include "packet-h245-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_h245,
#include "packet-h245-ettarr.c"
  };
  module_t *h245_module;

  /* Register protocol */
  proto_h245 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_h245, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* From Ronnie Sahlbergs original H245 dissector */
	
  h245_module = prefs_register_protocol(proto_h245, NULL);
  prefs_register_bool_preference(h245_module, "reassembly",
		"Reassemble H.245 messages spanning multiple TCP segments",
		"Whether the H.245 dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&h245_reassembly);
  prefs_register_bool_preference(h245_module, "shorttypes",
		"Show short message types",
		"Whether the dissector should show short names or the long names from the standard",
		&h245_shorttypes);
  register_dissector("h245dg", dissect_h245_h245, proto_h245);
  register_dissector("h245", dissect_h245, proto_h245);

  nsp_object_dissector_table = register_dissector_table("h245.nsp.object", "H.245 NonStandardParameter (object)", FT_STRING, BASE_NONE);
  nsp_h221_dissector_table = register_dissector_table("h245.nsp.h221", "H.245 NonStandardParameter (h221)", FT_UINT32, BASE_HEX);
  h245_tap = register_tap("h245");
  h245dg_tap = register_tap("h245dg");

  register_ber_oid_name("0.0.8.239.1.1","itu-t(0) recommendation(0) h(8) h239(239) generic-capabilities(1) h239ControlCapability(1)");
  register_ber_oid_name("0.0.8.239.1.2","itu-t(0) recommendation(0) h(8) h239(239) generic-capabilities(1) h239ExtendedVideoCapability(2)");
  register_ber_oid_name("0.0.8.239.2","itu-t(0) recommendation(0) h(8) h239(239) generic-message(2)");
  register_ber_oid_name("0.0.8.245.0.3","itu-t(0) recommendation(0) h(8) h245(245) version(0) 3");
  register_ber_oid_name("0.0.8.245.0.4","itu-t(0) recommendation(0) h(8) h245(245) version(0) 4");
  register_ber_oid_name("0.0.8.245.0.5","itu-t(0) recommendation(0) h(8) h245(245) version(0) 5");
  register_ber_oid_name("0.0.8.245.0.6","itu-t(0) recommendation(0) h(8) h245(245) version(0) 6");
  register_ber_oid_name("0.0.8.245.0.7","itu-t(0) recommendation(0) h(8) h245(245) version(0) 7");
  register_ber_oid_name("0.0.8.245.0.8","itu-t(0) recommendation(0) h(8) h245(245) version(0) 8");
  register_ber_oid_name("0.0.8.245.0.10","itu-t(0) recommendation(0) h(8) h245(245) version(0) 10");
  register_ber_oid_name("0.0.8.245.1.0.0","itu-t(0) recommendation(0) h(8) h245(245) generic-capabilities(1) video (0) ISO/IEC 14496-2 (0)= MPEG-4 video");
  register_ber_oid_name("0.0.8.245.1.1.0","itu-t(0) recommendation(0) h(8) h245(245) generic-capabilities(1) audio (1) ISO/IEC 14496-3 (0)= MPEG-4 audio");
  register_ber_oid_name("0.0.8.245.1.1.1","itu-t(0) recommendation(0) h(8) h245(245) generic-capabilities(1) audio(1) amr(1)");

  register_ber_oid_name("0.0.8.241.0.0.1","itu-t(0) recommendation(0) h(8) h241(241) specificVideoCodecCapabilities(0) h264(0) generic-capabilities(1)");


}


/*--- proto_reg_handoff_h245 ---------------------------------------*/
void proto_reg_handoff_h245(void) {
	rtp_handle = find_dissector("rtp");
	rtcp_handle = find_dissector("rtcp");
	data_handle = find_dissector("data");


	h245_handle=create_dissector_handle(dissect_h245, proto_h245);
	dissector_add_handle("tcp.port", h245_handle);
	MultimediaSystemControlMessage_handle=create_dissector_handle(dissect_h245_h245, proto_h245);
	dissector_add_handle("udp.port", MultimediaSystemControlMessage_handle);
}

static void reset_h245_packet_info(h245_packet_info *pi)
{
        if(pi == NULL) {
                return;
        }

        pi->msg_type = H245_OTHER;
		pi->frame_label[0] = '\0';
		g_snprintf(pi->comment, sizeof(pi->comment), "H245 ");
}

