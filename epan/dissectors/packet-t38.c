/* packet-t38.c
 * Routines for T.38 packet dissection
 * 2003  Hans Viens
 * 2004  Alejandro Vaquero, add support Conversations for SDP
 * 2006  Alejandro Vaquero, add T30 reassemble and dissection
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


/* Depending on what ASN.1 specification is used you may have to change
 * the preference setting regarding Pre-Corrigendum ASN.1 specification:
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/1998/T38.html  (Pre-Corrigendum=TRUE)
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2003/T38(1998).html (Pre-Corrigendum=TRUE)
 *
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2003/T38(2002).html (Pre-Corrigendum=FALSE)
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2002/t38.html  (Pre-Corrigendum=FALSE)
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2002-Amd1/T38.html (Pre-Corrigendum=FALSE)
 */

/* TO DO:  
 * - TCP desegmentation is currently not supported for T.38 IFP directly over TCP. 
 * - H.245 dissectors should be updated to start conversations for T.38 similar to RTP.
 * - Sometimes the last octet is not high-lighted when selecting something in the tree. Bug in PER dissector? 
 * - Add support for RTP payload audio/t38 (draft-jones-avt-audio-t38-03.txt), i.e. T38 in RTP packets.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/expert.h>

#include <stdio.h>
#include <string.h>

#include "packet-t38.h"
#include <epan/prefs.h>
#include <epan/ipproto.h>
#include "packet-per.h"
#include <epan/prefs.h>
#include "packet-tpkt.h"
#include <epan/emem.h>

#define PORT_T38 6004  
static guint global_t38_tcp_port = PORT_T38;
static guint global_t38_udp_port = PORT_T38;

static int t38_tap = -1;

/*
* Variables to allow for proper deletion of dissector registration when
* the user changes port from the gui.
*/
static guint tcp_port = 0;
static guint udp_port = 0;

/* dissect using the Pre Corrigendum T.38 ASN.1 specification (1998) */
static gboolean use_pre_corrigendum_asn1_specification = TRUE;

/* dissect packets that looks like RTP version 2 packets as RTP     */
/* instead of as T.38. This may result in that some T.38 UPTL       */
/* packets with sequence number values higher than 32767 may be     */
/* shown as RTP packets.                                            */ 
static gboolean dissect_possible_rtpv2_packets_as_rtp = FALSE;


/* Reassembly of T.38 PDUs over TPKT over TCP */
static gboolean t38_tpkt_reassembly = TRUE;

/* Preference setting whether TPKT header is used when sending T.38 over TCP.
 * The default setting is Maybe where the dissector will look on the first
 * bytes to try to determine whether TPKT header is used or not. This may not
 * work so well in some cases. You may want to change the setting to Always or
 * Newer.
 */
#define T38_TPKT_NEVER 0   /* Assume that there is never a TPKT header    */
#define T38_TPKT_ALWAYS 1  /* Assume that there is always a TPKT header   */
#define T38_TPKT_MAYBE 2   /* Assume TPKT if first octets are 03-00-xx-xx */
static gint t38_tpkt_usage = T38_TPKT_MAYBE;

static const enum_val_t t38_tpkt_options[] = {
  {"never", "Never", T38_TPKT_NEVER},
  {"always", "Always", T38_TPKT_ALWAYS},
  {"maybe", "Maybe", T38_TPKT_MAYBE},
  {NULL, NULL, -1}
};



/* T30 */
static int proto_t30 = -1;
static int hf_t30_Address = -1;
static int hf_t30_Control = -1;
static int hf_t30_Facsimile_Control = -1;
static int hf_t30_fif_sm = -1; 
static int hf_t30_fif_rtif = -1; 
static int hf_t30_fif_3gmn = -1; 
static int hf_t30_fif_v8c = -1; 
static int hf_t30_fif_op = -1; 
static int hf_t30_fif_rtfc = -1;
static int hf_t30_fif_rfo = -1;
static int hf_t30_fif_dsr = -1;
static int hf_t30_fif_dsr_dcs = -1;
static int hf_t30_fif_res = -1;
static int hf_t30_fif_tdcc = -1;
static int hf_t30_fif_rwc = -1;
static int hf_t30_fif_rw_dcs = -1;
static int hf_t30_fif_rlc = -1;
static int hf_t30_fif_rl_dcs = -1;
static int hf_t30_fif_msltcr = -1;
static int hf_t30_fif_mslt_dcs = -1;
static int hf_t30_fif_ext = -1;
static int hf_t30_fif_cm = -1;
static int hf_t30_fif_ecm = -1;
static int hf_t30_fif_fs_dcs = -1;
static int hf_t30_fif_t6 = -1;
static int hf_t30_fif_fvc = -1;
static int hf_t30_fif_mspc = -1;
static int hf_t30_fif_ps = -1;
static int hf_t30_fif_t43 = -1;
static int hf_t30_fif_pi = -1;
static int hf_t30_fif_vc32k = -1;
static int hf_t30_fif_r8x15 = -1;
static int hf_t30_fif_300x300 = -1;
static int hf_t30_fif_r16x15 = -1;
static int hf_t30_fif_ibrp = -1;
static int hf_t30_fif_mbrp = -1;
static int hf_t30_fif_msltchr = -1;
static int hf_t30_fif_rts = -1;
static int hf_t30_fif_sp = -1;
static int hf_t30_fif_sc = -1;
static int hf_t30_fif_passw = -1;
static int hf_t30_fif_sit = -1;
static int hf_t30_fif_rttd = -1;
static int hf_t30_fif_bft = -1;
static int hf_t30_fif_dtm = -1;
static int hf_t30_fif_edi = -1;
static int hf_t30_fif_btm = -1;
static int hf_t30_fif_rttcmmd = -1;
static int hf_t30_fif_chrm = -1;
static int hf_t30_fif_mm = -1;
static int hf_t30_fif_pm26 = -1;
static int hf_t30_fif_dnc = -1;
static int hf_t30_fif_do = -1;
static int hf_t30_fif_jpeg = -1;
static int hf_t30_fif_fcm = -1;
static int hf_t30_fif_pht = -1;
static int hf_t30_fif_12c = -1;
static int hf_t30_fif_ns = -1;
static int hf_t30_fif_ci = -1;
static int hf_t30_fif_cgr = -1;
static int hf_t30_fif_nalet = -1;
static int hf_t30_fif_naleg = -1;
static int hf_t30_fif_spscb = -1;
static int hf_t30_fif_spsco = -1;
static int hf_t30_fif_hkm = -1;
static int hf_t30_fif_rsa = -1;
static int hf_t30_fif_oc = -1;
static int hf_t30_fif_hfx40 = -1;
static int hf_t30_fif_acn2c = -1;
static int hf_t30_fif_acn3c = -1;
static int hf_t30_fif_hfx40i = -1;
static int hf_t30_fif_ahsn2 = -1;
static int hf_t30_fif_ahsn3 = -1;
static int hf_t30_fif_t441 = -1;
static int hf_t30_fif_t442 = -1;
static int hf_t30_fif_t443 = -1;
static int hf_t30_fif_plmss = -1;
static int hf_t30_fif_cg300 = -1;
static int hf_t30_fif_100x100cg = -1;
static int hf_t30_fif_spcbft = -1;
static int hf_t30_fif_ebft = -1;
static int hf_t30_fif_isp = -1;
static int hf_t30_fif_ira = -1;
static int hf_t30_fif_600x600 = -1;
static int hf_t30_fif_1200x1200 = -1;
static int hf_t30_fif_300x600 = -1;
static int hf_t30_fif_400x800 = -1;
static int hf_t30_fif_600x1200 = -1;
static int hf_t30_fif_cg600x600 = -1;
static int hf_t30_fif_cg1200x1200 = -1;
static int hf_t30_fif_dspcam = -1;
static int hf_t30_fif_dspccm = -1;
static int hf_t30_fif_bwmrcp = -1;
static int hf_t30_fif_t45 = -1;
static int hf_t30_fif_sdmc = -1;
static int hf_t30_fif_number = -1;
static int hf_t30_fif_country_code = -1;
static int hf_t30_fif_non_stand_bytes = -1;
static int hf_t30_t4_frame_num = -1;
static int hf_t30_t4_data = -1;
static int hf_t30_partial_page_fcf2 = -1;
static int hf_t30_partial_page_i1 = -1;
static int hf_t30_partial_page_i2 = -1;
static int hf_t30_partial_page_i3 = -1;

static gint ett_t30 = -1;
static gint ett_t30_fif = -1;

/* T38 */
static dissector_handle_t t38_udp_handle;
static dissector_handle_t t38_tcp_handle;
static dissector_handle_t t38_tcp_pdu_handle;
static dissector_handle_t rtp_handle;

static guint32 Type_of_msg_value;
static guint32 Data_Field_field_type_value;
static guint32 Data_value;
static guint32 T30ind_value;
static guint32 Data_Field_item_num;

static int proto_t38 = -1;
static int hf_t38_null = -1;
static int hf_t38_dummy = -1;
static int hf_t38_IFPPacket = -1;
static int hf_t38_Type_of_msg = -1;
static int hf_t38_t30_indicator = -1;
static int hf_t38_data = -1;
static int hf_t38_Data_Field = -1;
static int hf_t38_Data_Field_item = -1;
static int hf_t38_Data_Field_field_type = -1;
static int hf_t38_Data_Field_field_data = -1;
static int hf_t38_UDPTLPacket = -1;
static int hf_t38_seq_number = -1;
static int hf_t38_primary_ifp_packet = -1;
static int hf_t38_primary_ifp_packet_length = -1;
static int hf_t38_error_recovery = -1;
static int hf_t38_secondary_ifp_packets = -1;
static int hf_t38_secondary_ifp_packets_item = -1;
static int hf_t38_secondary_ifp_packets_item_length = -1;
static int hf_t38_fec_info = -1;
static int hf_t38_fec_npackets = -1;
static int hf_t38_fec_data = -1;
static int hf_t38_fec_data_item = -1;

/* T38 setup fields */
static int hf_t38_setup        = -1;
static int hf_t38_setup_frame  = -1;
static int hf_t38_setup_method = -1;

/* T38 Data reassemble fields */
static int hf_data_fragments = -1;
static int hf_data_fragment = -1;
static int hf_data_fragment_overlap = -1;
static int hf_data_fragment_overlap_conflicts = -1;
static int hf_data_fragment_multiple_tails = -1;
static int hf_data_fragment_too_long_fragment = -1;
static int hf_data_fragment_error = -1;
static int hf_data_reassembled_in = -1;

static gint ett_t38 = -1;
static gint ett_t38_IFPPacket = -1;
static gint ett_t38_Type_of_msg = -1;
static gint ett_t38_t30_indicator = -1;
static gint ett_t38_data = -1;
static gint ett_t38_Data_Field = -1;
static gint ett_t38_Data_Field_item = -1;
static gint ett_t38_Data_Field_field_type = -1;
static gint ett_t38_UDPTLPacket = -1;
static gint ett_t38_error_recovery = -1;
static gint ett_t38_secondary_ifp_packets = -1;
static gint ett_t38_fec_info = -1;
static gint ett_t38_fec_data = -1;
static gint ett_t38_setup = -1;

static gint ett_data_fragment = -1;
static gint ett_data_fragments = -1;

static gboolean primary_part = TRUE;
static guint32 seq_number = 0;

/* Tables for reassembly of Data fragments. */
static GHashTable *data_fragment_table = NULL;
static GHashTable *data_reassembled_table = NULL;

static const fragment_items data_frag_items = {
	/* Fragment subtrees */
	&ett_data_fragment,
	&ett_data_fragments,
	/* Fragment fields */
	&hf_data_fragments,
	&hf_data_fragment,
	&hf_data_fragment_overlap,
	&hf_data_fragment_overlap_conflicts,
	&hf_data_fragment_multiple_tails,
	&hf_data_fragment_too_long_fragment,
	&hf_data_fragment_error,
	/* Reassembled in field */
	&hf_data_reassembled_in,
	/* Tag */
	"Data fragments"
};

typedef struct _fragment_key {
	address src;
	address dst;
	guint32	id;
} fragment_key;

static conversation_t *p_conv= NULL;
static t38_conv *p_t38_conv = NULL;
static t38_conv *p_t38_packet_conv = NULL;
static t38_conv_info *p_t38_conv_info = NULL;
static t38_conv_info *p_t38_packet_conv_info = NULL;

/* RTP Version is the first 2 bits of the first octet in the UDP payload*/
#define RTP_VERSION(octet)	((octet) >> 6)

void proto_reg_handoff_t38(void);

static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, conversation_t *p_conv, t38_conv *p_t38_conv);
/* Preferences bool to control whether or not setup info should be shown */
static gboolean global_t38_show_setup_info = TRUE;

/* Can tap up to 4 T38 packets within same packet */
/* We only tap the primary part, not the redundancy */
#define MAX_T38_MESSAGES_IN_PACKET 4
static t38_packet_info t38_info_arr[MAX_T38_MESSAGES_IN_PACKET];
static int t38_info_current=0;
static t38_packet_info *t38_info=NULL;

static void t38_defragment_init(void)
{
	/* Init reassemble tables */
	fragment_table_init(&data_fragment_table);
	reassembled_table_init(&data_reassembled_table);
}


/* Set up an T38 conversation */
void t38_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method, guint32 setup_frame_number)
{
        address null_addr;
        conversation_t* p_conv;
        t38_conv* p_conv_data = NULL;

        /*
         * If this isn't the first time this packet has been processed,
         * we've already done this work, so we don't need to do it
         * again.
         */
        if (pinfo->fd->flags.visited)
        {
                return;
        }

        SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

        /*
         * Check if the ip address and port combination is not
         * already registered as a conversation.
         */
        p_conv = find_conversation( setup_frame_number, addr, &null_addr, PT_UDP, port, other_port,
                                NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

        /*
         * If not, create a new conversation.
         */
        if ( !p_conv || p_conv->setup_frame != setup_frame_number) {
                p_conv = conversation_new( setup_frame_number, addr, &null_addr, PT_UDP,
                                           (guint32)port, (guint32)other_port,
                                                                   NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
        }

        /* Set dissector */
        conversation_set_dissector(p_conv, t38_udp_handle);

        /*
         * Check if the conversation has data associated with it.
         */
        p_conv_data = conversation_get_proto_data(p_conv, proto_t38);

        /*
         * If not, add a new data item.
         */
        if ( ! p_conv_data ) {
                /* Create conversation data */
                p_conv_data = se_alloc(sizeof(t38_conv));

                conversation_add_proto_data(p_conv, proto_t38, p_conv_data);
        }

        /*
         * Update the conversation data.
         */
        strncpy(p_conv_data->setup_method, setup_method, MAX_T38_SETUP_METHOD_SIZE);
        p_conv_data->setup_method[MAX_T38_SETUP_METHOD_SIZE] = '\0';
        p_conv_data->setup_frame_number = setup_frame_number;
		p_conv_data->src_t38_info.reass_ID = 0;
		p_conv_data->src_t38_info.reass_start_seqnum = -1;
		p_conv_data->src_t38_info.reass_data_type = 0;
		p_conv_data->src_t38_info.last_seqnum = -1;
		p_conv_data->src_t38_info.packet_lost = 0;
		p_conv_data->src_t38_info.burst_lost = 0;
		p_conv_data->src_t38_info.time_first_t4_data = 0;


		p_conv_data->dst_t38_info.reass_ID = 0;
		p_conv_data->dst_t38_info.reass_start_seqnum = -1;
		p_conv_data->dst_t38_info.reass_data_type = 0;
		p_conv_data->dst_t38_info.last_seqnum = -1;
		p_conv_data->dst_t38_info.packet_lost = 0;
		p_conv_data->dst_t38_info.burst_lost = 0;
		p_conv_data->dst_t38_info.time_first_t4_data = 0;
}


/* T30 Routines */

static int
dissect_t30_NULL(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return offset;
}

static const value_string t30_control_vals[] = {
	{ 0xC0, "non-final frames within the procedure" },
	{ 0xC8, "final frames within the procedure" },
	{ 0,    NULL }
};


#define	T30_FC_DIS	0x01
#define	T30_FC_CSI	0x02
#define	T30_FC_NSF	0x04
#define	T30_FC_DTC	0x81
#define	T30_FC_CIG	0x82
#define	T30_FC_NSC	0x84
#define	T30_FC_PWD	0x83
#define	T30_FC_SEP	0x85
#define	T30_FC_PSA	0x86
#define	T30_FC_CIA	0x87
#define	T30_FC_ISP	0x88
#define	T30_FC_DCS	0x41
#define	T30_FC_TSI	0x42
#define	T30_FC_NSS	0x44
#define	T30_FC_SUB	0x43
#define	T30_FC_SID	0x45
#define	T30_FC_TSA	0x46
#define	T30_FC_IRA	0x47
#define	T30_FC_CFR	0x21
#define	T30_FC_FTT	0x22
#define	T30_FC_CSA	0x24
#define	T30_FC_EOM	0x71
#define	T30_FC_MPS	0x72
#define	T30_FC_EOP	0x74
#define	T30_FC_PRI_EOM	0x79
#define	T30_FC_PRI_MPS	0x7A
#define	T30_FC_PRI_EOP	0x7C
#define	T30_FC_PRI_EOP2	0x78
#define	T30_FC_MCF	0x31
#define	T30_FC_RTP	0x33
#define	T30_FC_RTN	0x32
#define	T30_FC_PIP	0x35
#define	T30_FC_PIN	0x34
#define	T30_FC_FDM	0x3F
#define	T30_FC_DCN	0x5F
#define	T30_FC_CRP	0x58
#define	T30_FC_FNV	0x53
#define	T30_FC_TNR	0x57
#define	T30_FC_TR	0x56
#define	T30_FC_MCF	0x31
#define	T30_FC_PID	0x36
#define	T30_FC_PPR	0x3D
#define	T30_FC_RNR	0x37
#define	T30_FC_CRP	0x58
#define	T30_FC_CTC	0x48
#define	T30_FC_CTR	0x23
#define	T30_FC_PPS	0x7D
#define	T30_FC_EOR	0x73
#define	T30_FC_RR	0x76
#define	T30_FC_ERR	0x38
#define	T30_FC_FCD	0x60
#define	T30_FC_RCP	0x61

const value_string t30_facsimile_control_field_vals[] = {
	{ T30_FC_DIS, "Digital Identification Signal" },
	{ T30_FC_CSI, "Called Subscriber Identification" },
	{ T30_FC_NSF, "Non-Standard Facilities" },
	{ T30_FC_DTC, "Digital Transmit Command" },
	{ T30_FC_CIG, "Calling Subscriber Identification" },
	{ T30_FC_NSC, "Non-Standard facilities Command" },
	{ T30_FC_PWD, "Password" },
	{ T30_FC_SEP, "Selective Polling" },
	{ T30_FC_PSA, "Polled Subaddress" },
	{ T30_FC_CIA, "Calling subscriber Internet Address" },
	{ T30_FC_ISP, "Internet Selective Polling Address" },
	{ T30_FC_DCS, "Digital Command Signal" },
	{ T30_FC_TSI, "Transmitting Subscriber Identification" },
	{ T30_FC_NSS, "Non-Standard facilities Set-up" },
	{ T30_FC_SUB, "Subaddress" },
	{ T30_FC_SID, "Sender Identification" },
	{ T30_FC_TSA, "Transmitting Subscriber Internet address" },
	{ T30_FC_IRA, "Internet Routing Address" },
	{ T30_FC_CFR, "Confirmation To Receive" },
	{ T30_FC_FTT, "Failure To Train" },
	{ T30_FC_CSA, "Called Subscriber Internet Address" },
	{ T30_FC_EOM, "End Of Message" },
	{ T30_FC_MPS, "MultiPage Signal" },
	{ T30_FC_EOP, "End Of Procedure" },
	{ T30_FC_PRI_EOM, "Procedure Interrupt-End Of Message" },
	{ T30_FC_PRI_MPS, "Procedure Interrupt-MultiPage Signal" },
	{ T30_FC_PRI_EOP, "Procedure Interrupt-End Of Procedure" },
	{ T30_FC_PRI_EOP2, "Procedure Interrupt-End Of Procedure" },
	{ T30_FC_MCF, "Message Confirmation" },
	{ T30_FC_RTP, "Retrain Positive" },
	{ T30_FC_RTN, "Retrain Negative" },
	{ T30_FC_PIP, "Procedure Interrupt Positive" },
	{ T30_FC_PIN, "Procedure Interrupt Negative" },
	{ T30_FC_FDM, "File Diagnostics Message" },
	{ T30_FC_DCN, "Disconnect" },
	{ T30_FC_CRP, "Command Repeat" },
	{ T30_FC_FNV, "Field Not Valid" },
	{ T30_FC_TNR, "Transmit not ready" },
	{ T30_FC_TR, "Transmit ready" },
	{ T30_FC_MCF, "Message Confirmation" },
	{ T30_FC_PID, "Procedure Interrupt Disconnect" },
	{ T30_FC_PPR, "Partial Page Request" },
	{ T30_FC_RNR, "Receive Not Ready" },
	{ T30_FC_CRP, "Command Repeat" },
	{ T30_FC_CTC, "Continue To Correct" },
	{ T30_FC_CTR, "Response for Continue To Correct" },
	{ T30_FC_PPS, "Partial Page Signal" },
	{ T30_FC_EOR, "End Of Retransmission" },
	{ T30_FC_RR, "Receive Ready" },
	{ T30_FC_ERR, "Response for End of Retransmission" },
	{ T30_FC_FCD, "Facsimile coded data" },
	{ T30_FC_RCP, "Return to control for partial page" },
	{ 0, NULL }
};

const value_string t30_facsimile_control_field_vals_short[] = {
	{ T30_FC_DIS, "DIS" },
	{ T30_FC_CSI, "CSI" },
	{ T30_FC_NSF, "NSF" },
	{ T30_FC_DTC, "DTC" },
	{ T30_FC_CIG, "CIG" },
	{ T30_FC_NSC, "NSC" },
	{ T30_FC_PWD, "PWD" },
	{ T30_FC_SEP, "SEP" },
	{ T30_FC_PSA, "PSA" },
	{ T30_FC_CIA, "CIA" },
	{ T30_FC_ISP, "ISP" },
	{ T30_FC_DCS, "DCS" },
	{ T30_FC_TSI, "TSI" },
	{ T30_FC_NSS, "NSS" },
	{ T30_FC_SUB, "SUB" },
	{ T30_FC_SID, "SID" },
	{ T30_FC_TSA, "TSA" },
	{ T30_FC_IRA, "IRA" },
	{ T30_FC_CFR, "CFR" },
	{ T30_FC_FTT, "FTT" },
	{ T30_FC_CSA, "CSA" },
	{ T30_FC_EOM, "EOM" },
	{ T30_FC_MPS, "MPS" },
	{ T30_FC_EOP, "EOP" },
	{ T30_FC_PRI_EOM, "PRI_EOM" },
	{ T30_FC_PRI_MPS, "PRI_MPS" },
	{ T30_FC_PRI_EOP, "EOP" },
	{ T30_FC_PRI_EOP2, "EOP2" },
	{ T30_FC_MCF, "MCF" },
	{ T30_FC_RTP, "RTP" },
	{ T30_FC_RTN, "RTN" },
	{ T30_FC_PIP, "PIP" },
	{ T30_FC_PIN, "PIN" },
	{ T30_FC_FDM, "FDM" },
	{ T30_FC_DCN, "DCN" },
	{ T30_FC_CRP, "CRP" },
	{ T30_FC_FNV, "FNV" },
	{ T30_FC_TNR, "TNR" },
	{ T30_FC_TR, "TR" },
	{ T30_FC_MCF, "MCF" },
	{ T30_FC_PID, "PID" },
	{ T30_FC_PPR, "PPR" },
	{ T30_FC_RNR, "RNR" },
	{ T30_FC_CRP, "CRP" },
	{ T30_FC_CTC, "CTC" },
	{ T30_FC_CTR, "CTR" },
	{ T30_FC_PPS, "PPS" },
	{ T30_FC_EOR, "EOR" },
	{ T30_FC_RR, "RR" },
	{ T30_FC_ERR, "ERR" },
	{ T30_FC_FCD, "FCD" },
	{ T30_FC_RCP, "RCP" },
	{ 0, NULL }
};

static const value_string t30_data_signalling_rate_vals[] = {
	{ 0x00, "ITU-T V.27 ter fall-back mode" },
	{ 0x04, "ITU-T V.27 ter" },
	{ 0x08, "ITU-T V.29" },
	{ 0x0C, "ITU-T V.27 ter and V.29" },
	{ 0x02, "Not used" },
	{ 0x06, "Reserved" },
	{ 0x0A, "Not used" },
	{ 0x0E, "Invalid" },
	{ 0x01, "Not used" },
	{ 0x05, "Reserved" },
	{ 0x09, "Not used" },
	{ 0x0D, "ITU-T V.27 ter, V.29, and V.17" },
	{ 0x03, "Not used" },
	{ 0x07, "Reserved" },
	{ 0x0B, "Not used" },
	{ 0x0F, "Reserved" },
};

static const value_string t30_data_signalling_rate_dcs_vals[] = {
	{ 0x00, "2400 bit/s, ITU-T V.27 ter" },
	{ 0x04, "4800 bit/s, ITU-T V.27 ter" },
	{ 0x08, "9600 bit/s, ITU-T V.29" },
	{ 0x0C, "7200 bit/s, ITU-T V.29" },
	{ 0x02, "Invalid" },
	{ 0x06, "Invalid" },
	{ 0x0A, "Reserved" },
	{ 0x0E, "Reserved" },
	{ 0x01, "14 400 bit/s, ITU-T V.17" },
	{ 0x05, "12 000 bit/s, ITU-T V.17" },
	{ 0x09, "9600 bit/s, ITU-T V.17" },
	{ 0x0D, "7200 bit/s, ITU-T V.17" },
	{ 0x03, "Reserved" },
	{ 0x07, "Reserved" },
	{ 0x0B, "Reserved" },
	{ 0x0F, "Reserved" },
};

static const value_string t30_recording_width_capabilities_vals[] = {
	{ 0x00, "Scan line length 215 mm +- 1%" },
	{ 0x01, "Scan line length 215 mm +- 1% and Scan line length 255 mm +- 1% and Scan line length 303 mm +- 1%" },
	{ 0x02, "Scan line length 215 mm +- 1% and Scan line length 255 mm +- 1%" },
	{ 0x03, "Invalid" },
};

static const value_string t30_recording_width_dcs_vals[] = {
	{ 0x00, "Scan line length 215 mm +- 1%" },
	{ 0x01, "Scan line length 303 mm +- 1%" },
	{ 0x02, "Scan line length 255 mm +- 1%" },
	{ 0x03, "Invalid" },
};

static const value_string t30_recording_length_capability_vals[] = {
	{ 0x00, "A4 (297 mm)" },
	{ 0x01, "Unlimited" },
	{ 0x02, "A4 (297 mm) and B4 (364 mm)" },
	{ 0x03, "Invalid" },
};

static const value_string t30_recording_length_dcs_vals[] = {
	{ 0x00, "A4 (297 mm)" },
	{ 0x01, "Unlimited" },
	{ 0x02, "B4 (364 mm)" },
	{ 0x03, "Invalid" },
};

static const value_string t30_minimum_scan_line_time_rec_vals[] = {
	{ 0x00, "20 ms at 3.85 l/mm: T7.7 = T3.85" },
	{ 0x01, "40 ms at 3.85 l/mm: T7.7 = T3.85" },
	{ 0x02, "10 ms at 3.85 l/mm: T7.7 = T3.85" },
	{ 0x04, "05 ms at 3.85 l/mm: T7.7 = T3.85" },
	{ 0x03, "10 ms at 3.85 l/mm: T7.7 = 1/2 T3.85" },
	{ 0x06, "20 ms at 3.85 l/mm: T7.7 = 1/2 T3.85" },
	{ 0x05, "40 ms at 3.85 l/mm: T7.7 = 1/2 T3.85" },
	{ 0x07, "00 ms at 3.85 l/mm: T7.7 = T3.85" },
};

static const value_string t30_partial_page_fcf2_vals[] = {
	{ 0x00, "NULL code which indicates the partial page boundary" },
	{ 0xF1, "EOM in optional T.4 error correction mode" },
	{ 0xF2, "MPS in optional T.4 error correction mode" },
	{ 0xF4, "EOP in optional T.4 error correction mode" },
	{ 0xF8, "EOS in optional T.4 error correction mode" },
	{ 0xF9, "PRI-EOM in optional T.4 error correction mode" },
	{ 0xFA, "PRI-MPS in optional T.4 error correction mode" },
	{ 0xFC, "PRI-EOP in optional T.4 error correction mode" },
};

static const value_string t30_minimum_scan_line_time_dcs_vals[] = {
	{ 0x00, "20 ms" },
	{ 0x01, "40 ms" },
	{ 0x02, "10 ms" },
	{ 0x04, "05 ms" },
	{ 0x07, "00 ms" },
};

static const value_string t30_SharedDataMemory_capacity_vals[] = {
	{ 0x00, "Not available" },
	{ 0x01, "Level 1 = 1.0 Mbytes" },
	{ 0x02, "Level 2 = 2.0 Mbytes" },
	{ 0x03, "Level 3 = unlimited (i.e. >= 32 Mbytes)" },
};

static const true_false_string t30_octets_preferred_value = {
  "64 octets preferred",
  "256 octets preferred",
};

static const true_false_string t30_extension_ind_value = {
  "information continues through the next octet",
  "last octet",
};

static const true_false_string t30_compress_value = {
  "Uncompressed mode",
  "Compressed mode",
};

static const true_false_string t30_minimum_scan_value = {
  "T15.4 = 1/2 T7.7",
  "T15.4 = T7.7",
};

static const true_false_string t30_duplex_operation_value = {
  "Duplex  and half duplex operation",
  "Half duplex operation only",
};

static const true_false_string t30_frame_size_dcs_value = {
  "64 octets",
  "256 octets",
};

static const true_false_string t30_res_type_sel_value = {
  "inch based resolution",
  "metric based resolution",
};

guint8 reverse_byte(guint8 val)
{
	return ( ((val & 0x80)>>7) | ((val & 0x40)>>5) |
		((val & 0x20)>>3) | ((val & 0x10)>>1) |
		((val & 0x08)<<1) | ((val & 0x04)<<3) |
		((val & 0x02)<<5) | ((val & 0x01)<<7) );
}

#define LENGTH_T30_NUM	20
gchar * 
t30_get_string_numbers(tvbuff_t *tvb, int offset, int len)
{
	gchar *buf;
	int i;

	/* the lenght must be 20 bytes per T30 rec*/
	if (len != LENGTH_T30_NUM) return NULL;

	buf=ep_alloc(LENGTH_T30_NUM+1);

	for (i=0; i<LENGTH_T30_NUM; i++) 
		buf[LENGTH_T30_NUM-i-1] = reverse_byte(tvb_get_guint8(tvb, offset+i));
	
	/* add end of string */
	buf[LENGTH_T30_NUM] = '\0';

	return g_strstrip(buf);

}

static void
dissect_t30_numbers(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree)
{
	gchar *str_num=NULL;

	str_num = t30_get_string_numbers(tvb, offset, len);
	if (str_num) {
		proto_tree_add_string_format(tree, hf_t30_fif_number, tvb, offset, LENGTH_T30_NUM, str_num, "Number: %s", str_num);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " - Number:%s", str_num );	

		g_snprintf(t38_info->desc, MAX_T38_DESC, "Num: %s", str_num);
	}
	else {
		proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), "[MALFORMED OR SHORT PACKET: number of digits must be 20]");

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET: number of digits must be 20]" );	
	}
}

static void
dissect_t30_facsimile_coded_data(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree)
{
	guint8 octet;
	gchar *t4_data;

	if (len < 2) {
		proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), "[MALFORMED OR SHORT PACKET: FCD length must be at least 2 bytes]");
		expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 FCD length must be at least 2 bytes");
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET]");				
		return;
	}
	
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_t30_t4_frame_num, tvb, offset, 1, reverse_byte(octet));
	offset++;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, " - Frame num:%d", reverse_byte(octet));

	g_snprintf(t38_info->desc, MAX_T38_DESC, "Frm num: %d", reverse_byte(octet));

	t4_data = ep_alloc(len-1);
	tvb_memcpy(tvb, t4_data, offset, len-1);
	proto_tree_add_bytes(tree, hf_t30_t4_data, tvb, offset, len-1, t4_data);
}

static void
dissect_t30_non_standard_cap(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree)
{
	guint8 octet;
	gchar *non_standard_bytes;

	if (len < 2) {
		proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), "[MALFORMED OR SHORT PACKET: NSC length must be at least 2 bytes]");
		expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 NSC length must be at least 2 bytes");
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET]");				
		return;
	}
	
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_t30_fif_country_code, tvb, offset, 1, octet);
	offset++;

	non_standard_bytes = ep_alloc(len-1);
	tvb_memcpy(tvb, non_standard_bytes, offset, len-1);
	proto_tree_add_bytes(tree, hf_t30_fif_non_stand_bytes, tvb, offset, len-1, non_standard_bytes);

}

static void
dissect_t30_partial_page_signal(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree)
{
	guint8 octet, page_count, block_count, frame_count;

	if (len != 4) {
		proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), "[MALFORMED OR SHORT PACKET: PPS length must be 4 bytes]");
		expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 PPS length must be 4 bytes");
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET]");				
		return;
	}

	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_t30_partial_page_fcf2, tvb, offset, 1, octet);
	offset += 1;

	octet = tvb_get_guint8(tvb, offset);
	page_count = reverse_byte(octet);
	proto_tree_add_uint(tree, hf_t30_partial_page_i1, tvb, offset, 1, page_count);
	offset++;

	octet = tvb_get_guint8(tvb, offset);
	block_count = reverse_byte(octet);
	proto_tree_add_uint(tree, hf_t30_partial_page_i2, tvb, offset, 1, block_count);
	offset++;

	octet = tvb_get_guint8(tvb, offset);
	frame_count = reverse_byte(octet);
	proto_tree_add_uint(tree, hf_t30_partial_page_i3, tvb, offset, 1, frame_count);
	offset++;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, " - PC:%d BC:%d FC:%d", page_count, block_count, frame_count);

	g_snprintf(t38_info->desc, MAX_T38_DESC, "PC:%d BC:%d FC:%d", page_count, block_count, frame_count);

}

static void
dissect_t30_dis_dtc(tvbuff_t *tvb, int offset, packet_info *pinfo, int len, proto_tree *tree, gboolean dis_dtc)
{
	guint8 octet;

	if (len < 3) {
		proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), "[MALFORMED OR SHORT PACKET: DIS length must be at least 4 bytes]");
		expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 DIS length must be at least 4 bytes");
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, " [MALFORMED OR SHORT PACKET]");				
		return;
	}

	/* bits 1 to 8 */
	octet = tvb_get_guint8(tvb, offset);
	
    proto_tree_add_boolean(tree, hf_t30_fif_sm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_rtif, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_3gmn, tvb, offset, 1, octet);
    if (dis_dtc) {
		proto_tree_add_boolean(tree, hf_t30_fif_v8c, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_t30_fif_op, tvb, offset, 1, octet);
	}
	/* bits 9 to 16 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	if (dis_dtc) proto_tree_add_boolean(tree, hf_t30_fif_rtfc, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_rfo, tvb, offset, 1, octet);
	if (dis_dtc) {
		proto_tree_add_uint(tree, hf_t30_fif_dsr, tvb, offset, 1, octet);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " - DSR:%s", val_to_str((octet&0x3C) >> 2, t30_data_signalling_rate_vals, "<unknown>"));

		g_snprintf(t38_info->desc, MAX_T38_DESC, "DSR:%s", val_to_str((octet&0x3C) >> 2, t30_data_signalling_rate_vals, "<unknown>"));
	}
	else {
		proto_tree_add_uint(tree, hf_t30_fif_dsr_dcs, tvb, offset, 1, octet);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " - DSR:%s", val_to_str((octet&0x3C) >> 2, t30_data_signalling_rate_dcs_vals, "<unknown>"));

		g_snprintf(t38_info->desc, MAX_T38_DESC, "DSR:%s", val_to_str((octet&0x3C) >> 2, t30_data_signalling_rate_dcs_vals, "<unknown>"));
	}
    proto_tree_add_boolean(tree, hf_t30_fif_res, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_tdcc, tvb, offset, 1, octet);

	/* bits 17 to 24 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	if (dis_dtc) {
		proto_tree_add_uint(tree, hf_t30_fif_rwc, tvb, offset, 1, octet);
		proto_tree_add_uint(tree, hf_t30_fif_rlc, tvb, offset, 1, octet);
		proto_tree_add_uint(tree, hf_t30_fif_msltcr, tvb, offset, 1, octet);
	} else {
		proto_tree_add_uint(tree, hf_t30_fif_rw_dcs, tvb, offset, 1, octet);
		proto_tree_add_uint(tree, hf_t30_fif_rl_dcs, tvb, offset, 1, octet);
		proto_tree_add_uint(tree, hf_t30_fif_mslt_dcs, tvb, offset, 1, octet);
	}
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 4) ) return;	/* no extension */

	/* bits 25 to 32 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_cm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ecm, tvb, offset, 1, octet);
	if (!dis_dtc) proto_tree_add_boolean(tree, hf_t30_fif_fs_dcs, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_t6, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 5) ) return;	/* no extension */	

	/* bits 33 to 40 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_fvc, tvb, offset, 1, octet);
    if (dis_dtc) {
		proto_tree_add_boolean(tree, hf_t30_fif_mspc, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_t30_fif_ps, tvb, offset, 1, octet);
	}
	proto_tree_add_boolean(tree, hf_t30_fif_t43, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_pi, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_vc32k, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 6) ) return;	/* no extension */	

	/* bits 41 to 48 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_r8x15, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_300x300, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_r16x15, tvb, offset, 1, octet);
	if (dis_dtc) {
	    proto_tree_add_boolean(tree, hf_t30_fif_ibrp, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_t30_fif_mbrp, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_t30_fif_msltchr, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_t30_fif_sp, tvb, offset, 1, octet);
	} else {
	    proto_tree_add_boolean(tree, hf_t30_fif_rts, tvb, offset, 1, octet);
	}
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 7) ) return;	/* no extension */	

	/* bits 49 to 56 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_sc, tvb, offset, 1, octet);
	if (dis_dtc) {
		proto_tree_add_boolean(tree, hf_t30_fif_passw, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_t30_fif_rttd, tvb, offset, 1, octet);
	} else {
		proto_tree_add_boolean(tree, hf_t30_fif_sit, tvb, offset, 1, octet);
    }
    proto_tree_add_boolean(tree, hf_t30_fif_bft, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_dtm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_edi, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 8) ) return;	/* no extension */	

	/* bits 57 to 64 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_boolean(tree, hf_t30_fif_btm, tvb, offset, 1, octet);
    if (dis_dtc) proto_tree_add_boolean(tree, hf_t30_fif_rttcmmd, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_chrm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_mm, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 9) ) return;	/* no extension */	

	/* bits 65 to 72 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_pm26, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_dnc, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_do, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_jpeg, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_fcm, tvb, offset, 1, octet);
	if (!dis_dtc) proto_tree_add_boolean(tree, hf_t30_fif_pht, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_12c, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 10) ) return;	/* no extension */	

	/* bits 73 to 80 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_ns, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_ci, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_cgr, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_nalet, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_naleg, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_spscb, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_spsco, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 11) ) return;	/* no extension */	

	/* bits 81 to 88 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_hkm, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_rsa, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_oc, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_hfx40, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_acn2c, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_acn3c, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_hfx40i, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 12) ) return;	/* no extension */	

	/* bits 89 to 96 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_ahsn2, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_ahsn3, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_t441, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_t442, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_t443, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_plmss, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 13) ) return;	/* no extension */	

	/* bits 97 to 104 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_cg300, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_100x100cg, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_spcbft, tvb, offset, 1, octet);
    if (dis_dtc) {
		proto_tree_add_boolean(tree, hf_t30_fif_ebft, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_t30_fif_isp, tvb, offset, 1, octet);
	}
    proto_tree_add_boolean(tree, hf_t30_fif_ira, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 14) ) return;	/* no extension */	

	/* bits 105 to 112 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_600x600, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_1200x1200, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_300x600, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_400x800, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_600x1200, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_cg600x600, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_cg1200x1200, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) || (len < 15) ) return;	/* no extension */	

	/* bits 113 to 120 */
	offset += 1;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_boolean(tree, hf_t30_fif_dspcam, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_dspccm, tvb, offset, 1, octet);
    if (dis_dtc) proto_tree_add_boolean(tree, hf_t30_fif_bwmrcp, tvb, offset, 1, octet);
    proto_tree_add_boolean(tree, hf_t30_fif_t45, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_t30_fif_sdmc, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_t30_fif_ext, tvb, offset, 1, octet);

	if ( !(octet & 0x01) ) return;	/* no extension */	
	
}

static int
dissect_t30_hdlc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *it;
	proto_tree *tr;
	proto_tree *tr_fif;
	proto_item *it_fcf;
	guint8 octet;
	guint32	frag_len;
	proto_item *item;

	if (tvb_reported_length_remaining(tvb, offset) < 3) {
		proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), "[MALFORMED OR SHORT PACKET: hdlc T30 length must be at least 4 bytes]");
		expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "T30 length must be at least 4 bytes");
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, " (HDLC Reassembled: [MALFORMED OR SHORT PACKET])");				
		return offset;
	}

/*	if (tree) {
		proto_item *item;*/
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, " (HDLC Reassembled:");				

		it=proto_tree_add_protocol_format(tree, proto_t30, tvb, offset, -1,
	    "ITU-T Recommendation T.30");
		tr=proto_item_add_subtree(it, ett_t30);

		octet = tvb_get_guint8(tvb, offset);
		item = proto_tree_add_uint(tr, hf_t30_Address, tvb, offset, 1, octet);
		if (octet != 0xFF) expert_add_info_format(pinfo, item, PI_REASSEMBLE, PI_WARN, "T30 Address must be 0xFF");
		offset += 1;

		octet = tvb_get_guint8(tvb, offset);
		item = proto_tree_add_uint(tr, hf_t30_Control, tvb, offset, 1, octet);
		if ((octet != 0xC0) && (octet != 0xC8)) expert_add_info_format(pinfo, item, PI_REASSEMBLE, PI_WARN, "T30 Control Field must be 0xC0 or 0xC8");
		offset += 1;

		octet = tvb_get_guint8(tvb, offset);
		it_fcf = proto_tree_add_uint(tr, hf_t30_Facsimile_Control, tvb, offset, 1, octet & 0x7F);
		offset += 1;

		tr_fif = proto_item_add_subtree(it_fcf, ett_t30_fif);

		frag_len = tvb_length_remaining(tvb, offset);
		t38_info->t30_Facsimile_Control = octet;

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s - %s", val_to_str(octet & 0x7F, t30_facsimile_control_field_vals_short, "<unknown>"),
				val_to_str(octet & 0x7F, t30_facsimile_control_field_vals, "<unknown>") );	

		switch (octet & 0x7F) {
		case T30_FC_DIS:
		case T30_FC_DTC:
			dissect_t30_dis_dtc(tvb, offset, pinfo, frag_len, tr_fif, TRUE);
			break;
		case T30_FC_DCS:
			dissect_t30_dis_dtc(tvb, offset, pinfo, frag_len, tr_fif, FALSE);
			break;
		case T30_FC_CSI:
		case T30_FC_CIG:
		case T30_FC_TSI:
		case T30_FC_PWD:
		case T30_FC_SEP:
		case T30_FC_SUB:
		case T30_FC_SID:
		case T30_FC_PSA:
			dissect_t30_numbers(tvb, offset, pinfo, frag_len, tr_fif);
			break;
		case T30_FC_NSF:
		case T30_FC_NSC:
		case T30_FC_NSS:
			dissect_t30_non_standard_cap(tvb, offset, pinfo, frag_len, tr_fif);
			break;
		case T30_FC_FCD:
			dissect_t30_facsimile_coded_data(tvb, offset, pinfo, frag_len, tr_fif);
			break;
		case T30_FC_PPS:
			dissect_t30_partial_page_signal(tvb, offset, pinfo, frag_len, tr_fif);
			break;
		}

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, ")");				

/*	}*/
	
	return offset;
}


/* T38 Routines */

static int
dissect_t38_NULL(tvbuff_t *tvb _U_, int offset, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	return offset;
}

static const per_choice_t t30_indicator_choice[] = {
	{ 0, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 1, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 2, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 3, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 4, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 5, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 6, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 7, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 8, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 9, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 10, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 11, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 12, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 13, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 14, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 15, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 16, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 17, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 18, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 19, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 20, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 21, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 22, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 0, NULL, 0, NULL }
};

const value_string t30_indicator_vals[] = {
	{ 0, "no-signal" },
	{ 1, "cng" },
	{ 2, "ced" },
	{ 3, "v21-preamble" },
	{ 4, "v27-2400-training" },
	{ 5, "v27-4800-training" },
	{ 6, "v29-7200-training" },
	{ 7, "v29-9600-training" },
	{ 8, "v17-7200-short-training" },
	{ 9, "v17-7200-long-training" },
	{ 10, "v17-9600-short-training" },
	{ 11, "v17-9600-long-training" },
	{ 12, "v17-12000-short-training" },
	{ 13, "v17-12000-long-training" },
	{ 14, "v17-14400-short-training" },
	{ 15, "v17-14400-long-training" },
    { 16, "v8-ansam" },
    { 17, "v8-signal" },
    { 18, "v34-cntl-channel-1200" },
    { 19, "v34-pri-channel" },
    { 20, "v34-CC-retrain" },
    { 21, "v33-12000-training" },
    { 22, "v33-14400-training" },
	{ 0, NULL },
};

static int
dissect_t38_T30_Indicator(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
    offset=dissect_per_choice(tvb, offset, actx,
        tree, hf_index, ett_t38_t30_indicator,
        t30_indicator_choice, &T30ind_value);

	if (check_col(actx->pinfo->cinfo, COL_INFO) && primary_part){
        col_append_fstr(actx->pinfo->cinfo, COL_INFO, " t30ind: %s",
         val_to_str(T30ind_value,t30_indicator_vals,"<unknown>"));
	}

	/* info for tap */
	if (primary_part)
		t38_info->t30ind_value = T30ind_value;

	return offset;
}

static const per_choice_t data_choice[] = {
	{ 0, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 1, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 2, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 3, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 4, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 5, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 6, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 7, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 8, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 9, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 10, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 11, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 12, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 13, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 14, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 0, NULL, 0, NULL }
};

const value_string t30_data_vals[] = {
	{ 0, "v21" },
	{ 1, "v27-2400" },
	{ 2, "v27-4800" },
	{ 3, "v29-7200" },
	{ 4, "v29-9600" },
	{ 5, "v17-7200" },
	{ 6, "v17-9600" },
	{ 7, "v17-12000" },
	{ 8, "v17-14400" },
	{ 9, "v8" },
	{ 10, "v34-pri-rate" },
	{ 11, "v34-CC-1200" },
	{ 12, "v34-pri-ch" },
	{ 13, "v33-12000" },
	{ 14, "v33-14400" },
	{ 0, NULL },
};

static int
dissect_t38_Data(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
    offset=dissect_per_choice(tvb, offset, actx,
        tree, hf_index, ett_t38_data,
        data_choice, &Data_value);

    if (check_col(actx->pinfo->cinfo, COL_INFO) && primary_part){
        col_append_fstr(actx->pinfo->cinfo, COL_INFO, " data:%s:",
         val_to_str(Data_value,t30_data_vals,"<unknown>"));
	}

	
	/* info for tap */
	if (primary_part)
		t38_info->data_value = Data_value;

	return offset;
}

static const per_choice_t Type_of_msg_choice[] = {
	{ 0, &hf_t38_t30_indicator, ASN1_NO_EXTENSIONS,
		dissect_t38_T30_Indicator},
	{ 1, &hf_t38_data, ASN1_NO_EXTENSIONS,
		dissect_t38_Data},
	{ 0, NULL, 0, NULL }
};

static const value_string Type_of_msg_vals[] = {
	{ 0, "t30-indicator" },
	{ 1, "data" },
    { 0, NULL}
};
static int
dissect_t38_Type_of_msg(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                              ett_t38_Type_of_msg, Type_of_msg_choice,
                              &Type_of_msg_value);

  /* info for tap */
  if (primary_part)
    t38_info->type_msg = Type_of_msg_value;

  return offset;
}

static const per_choice_t Data_Field_field_type_PreCorrigendum_choice[] = {
	{ 0, &hf_t38_null, ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 1, &hf_t38_null, ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 2, &hf_t38_null, ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 3, &hf_t38_null, ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 4, &hf_t38_null, ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 5, &hf_t38_null, ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 6, &hf_t38_null, ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 7, &hf_t38_null, ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 0, NULL, 0, NULL }
};


static const per_choice_t Data_Field_field_type_choice[] = {
	{ 0, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 1, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 2, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 3, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 4, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 5, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 6, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 7, &hf_t38_null, ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 8, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 9, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 10, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 11, &hf_t38_null, ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 0, NULL, 0, NULL }
};


static const value_string Data_Field_field_type_vals[] = {
	{ 0, "hdlc-data" },
	{ 1, "hdlc-sig-end" },
	{ 2, "hdlc-fcs-OK" },
	{ 3, "hdlc-fcs-BAD" },
	{ 4, "hdlc-fcs-OK-sig-end" },
	{ 5, "hdlc-fcs-BAD-sig-end" },
	{ 6, "t4-non-ecm-data" },
	{ 7, "t4-non-ecm-sig-end" },
	{ 8, "cm-message" },
	{ 9, "jm-message" },
	{ 10, "ci-message" },
	{ 11, "v34-rate" },
	{ 0, NULL },
};

fragment_data *
force_reassmeble_seq(tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 id,
	     GHashTable *fragment_table, guint32 frag_number)
{
	fragment_key key;
	fragment_data *fd_head;
	fragment_data *fd_i;
	fragment_data *last_fd;
	guint32 dfpos, size, packet_lost, burst_lost, seq_num;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

	/* have we already seen this frame ?*/
	if (pinfo->fd->flags.visited) {
		if (fd_head != NULL && fd_head->flags & FD_DEFRAGMENTED) {
			return fd_head;
		} else {
			return NULL;
		}
	}

	if (fd_head==NULL){
		/* we must have it to continue */
		return NULL;
	}

	/* check for packet lost and count the burst of packet lost */
	packet_lost = 0;
	burst_lost = 0;
	seq_num = 0;
	for(fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
		if (seq_num != fd_i->offset) {
			packet_lost += fd_i->offset - seq_num;
			if ( (fd_i->offset - seq_num) > burst_lost ) {
				burst_lost = fd_i->offset - seq_num;
			}
		}
		seq_num = fd_i->offset + 1;
	}

	/* we have received an entire packet, defragment it and
     * free all fragments
     */
	size=0;
	last_fd=NULL;
	for(fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
	  if(!last_fd || last_fd->offset!=fd_i->offset){
	    size+=fd_i->len;
	  }
	  last_fd=fd_i;
	}
	fd_head->data = g_malloc(size);
	fd_head->len = size;		/* record size for caller	*/

	/* add all data fragments */
	dfpos = 0;
	last_fd=NULL;
	for (fd_i=fd_head->next;fd_i && fd_i->len + dfpos <= size;fd_i=fd_i->next) {
	  if (fd_i->len) {
	    if(!last_fd || last_fd->offset!=fd_i->offset){
	      memcpy(fd_head->data+dfpos,fd_i->data,fd_i->len);
	      dfpos += fd_i->len;
	    } else {
	      /* duplicate/retransmission/overlap */
	      fd_i->flags    |= FD_OVERLAP;
	      fd_head->flags |= FD_OVERLAP;
	      if( (last_fd->len!=fd_i->datalen)
		  || memcmp(last_fd->data, fd_i->data, last_fd->len) ){
			fd_i->flags    |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
	      }
	    }
	  }
	  last_fd=fd_i;
	}

	/* we have defragmented the pdu, now free all fragments*/
	for (fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
	  if(fd_i->data){
	    g_free(fd_i->data);
	    fd_i->data=NULL;
	  }
	}

	/* mark this packet as defragmented */
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in=pinfo->fd->num;

	if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " (t4-data Reassembled: %d pack lost, %d pack burst lost)", packet_lost, burst_lost);
	
	p_t38_packet_conv_info->packet_lost = packet_lost;
	p_t38_packet_conv_info->burst_lost = burst_lost;

	return fd_head;
}

static int
dissect_t38_Data_Field_field_type(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
	if(use_pre_corrigendum_asn1_specification){
		offset=dissect_per_choice(tvb, offset, actx,
			tree, hf_index, ett_t38_Data_Field_field_type,
			Data_Field_field_type_PreCorrigendum_choice, &Data_Field_field_type_value);
	}
	else{
		offset=dissect_per_choice(tvb, offset, actx,
			tree, hf_index, ett_t38_Data_Field_field_type,
			Data_Field_field_type_choice, &Data_Field_field_type_value);
	}

    if (check_col(actx->pinfo->cinfo, COL_INFO) && primary_part){
        col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s",
         val_to_str(Data_Field_field_type_value,Data_Field_field_type_vals,"<unknown>"));
	}

	/* We only reassmeble packets in the Primary part and in the first two Items.						*/
	/* There maybe be t38 packets with more than two Items, but reassemble those packets is not easy	*/
	/* using the current ressaemble functions.															*/
	/* TODO: reassemble all the Items in one frame */
	if (primary_part && (Data_Field_item_num<2)) {
		if (Data_Field_field_type_value == 2 || Data_Field_field_type_value == 4 || Data_Field_field_type_value == 7) {/* hdlc-fcs-OK or hdlc-fcs-OK-sig-end or t4-non-ecm-sig-end*/
			fragment_data *frag_msg = NULL;
			tvbuff_t* new_tvb = NULL;
			gboolean save_fragmented = actx->pinfo->fragmented;

			actx->pinfo->fragmented = TRUE;

			/* if reass_start_seqnum=-1 it means we have received the end of the fragmente, without received any fragment data */
			if (p_t38_packet_conv_info->reass_start_seqnum != -1) {
				frag_msg = fragment_add_seq(tvb, offset, actx->pinfo,
					p_t38_packet_conv_info->reass_ID, /* ID for fragments belonging together */
					data_fragment_table, /* list of message fragments */
					seq_number + Data_Field_item_num - (guint32)p_t38_packet_conv_info->reass_start_seqnum,  /* fragment sequence number */
					/*0,*/
					0, /* fragment length */
					FALSE); /* More fragments */
				if ( Data_Field_field_type_value == 7 ) {
					/* if there was packet lost or other errors during the defrag then frag_msg is NULL. This could also means
					 * there are out of order packets (e.g, got the tail frame t4-non-ecm-sig-end before the last fragment), 
					 * but we will assume there was packet lost instead, which is more usual. So, we are going to reassemble the packet
					 * and get some stat, like packet lost and burst number of packet lost
					*/
					if (!frag_msg) {
						force_reassmeble_seq(tvb, offset, actx->pinfo,
							p_t38_packet_conv_info->reass_ID, /* ID for fragments belonging together */
							data_fragment_table, /* list of message fragments */
							seq_number + Data_Field_item_num - (guint32)p_t38_packet_conv_info->reass_start_seqnum);  /* fragment sequence number */
					} else {
						if (check_col(actx->pinfo->cinfo, COL_INFO))
							col_append_str(actx->pinfo->cinfo, COL_INFO, " (t4-data Reassembled: No packet lost)");	
						
						g_snprintf(t38_info->desc_comment, MAX_T38_DESC, "No packet lost");
					}

					
					if (p_t38_packet_conv_info->packet_lost) {
						g_snprintf(t38_info->desc_comment, MAX_T38_DESC, " Pack lost: %d, Pack burst lost: %d", p_t38_packet_conv_info->packet_lost, p_t38_packet_conv_info->burst_lost);
					} else {
						g_snprintf(t38_info->desc_comment, MAX_T38_DESC, "No packet lost");
					}

					new_tvb = process_reassembled_data(tvb, offset, actx->pinfo,
								"Reassembled Message", frag_msg, &data_frag_items, NULL, tree);

					/* Now reset fragmentation information in pinfo */
					actx->pinfo->fragmented = save_fragmented;

					t38_info->time_first_t4_data = p_t38_packet_conv_info->time_first_t4_data; 
					t38_info->frame_num_first_t4_data = p_t38_packet_conv_info->reass_ID; /* The reass_ID is the Frame number of the first t4 fragment */

				} else {
					new_tvb = process_reassembled_data(tvb, offset, actx->pinfo,
								"Reassembled Message", frag_msg, &data_frag_items, NULL, tree);

					/* Now reset fragmentation information in pinfo */
					actx->pinfo->fragmented = save_fragmented;

					if (new_tvb) dissect_t30_hdlc(new_tvb, 0, actx->pinfo, tree); 
				}
			} else {
				if(tree){
					proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
						"[RECEIVED END OF FRAGMENT W/OUT ANY FRAGMENT DATA]");
				}
				if (check_col(actx->pinfo->cinfo, COL_INFO)){
					col_append_fstr(actx->pinfo->cinfo, COL_INFO, " [Malformed?]");
				}
				actx->pinfo->fragmented = save_fragmented;
			}
		}

		/* reset the reassemble ID and the start seq number if it is not HDLC data */
		if ( p_t38_conv && ( ((Data_Field_field_type_value >0) && (Data_Field_field_type_value <6)) || (Data_Field_field_type_value == 7) ) ){
			p_t38_conv_info->reass_ID = 0;
			p_t38_conv_info->reass_start_seqnum = -1;
		}
		t38_info->Data_Field_field_type_value = Data_Field_field_type_value;
	}
    return offset;
}

static int
dissect_t38_Data_Field_field_data(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
	tvbuff_t *value_tvb = NULL;
	guint32 value_len;

	offset=dissect_per_octet_string(tvb, offset, actx,
        tree, hf_index, 1, 65535,
        &value_tvb);
	value_len = tvb_length(value_tvb);

	if (check_col(actx->pinfo->cinfo, COL_INFO) && primary_part){
        if(value_len < 8){
        	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "[%s]",
               tvb_bytes_to_str(value_tvb,0,value_len));
        }
        else {
        	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "[%s...]",
               tvb_bytes_to_str(value_tvb,0,7));
        }
	}

	/* We only reassmeble packets in the Primary part and in the first two Items.						*/
	/* There maybe be t38 packets with more than two Items, but reassemble those packets is not easy	*/
	/* using the current ressaemble functions.															*/
	/* TODO: reassemble all the Items in one frame */
	if (primary_part && (Data_Field_item_num<2)) {
		tvbuff_t* new_tvb = NULL;
		fragment_data *frag_msg = NULL;
	
		/* HDLC Data or t4-non-ecm-data */
		if (Data_Field_field_type_value == 0 || Data_Field_field_type_value == 6) { /* 0=HDLC Data or 6=t4-non-ecm-data*/
			gboolean save_fragmented = actx->pinfo->fragmented;

			actx->pinfo->fragmented = TRUE;

			/* if we have not reassembled this packet and it is the first fragment, reset the reassemble ID and the start seq number*/
			if (p_t38_packet_conv && p_t38_conv && (p_t38_packet_conv_info->reass_ID == 0)) {
				/* we use the first fragment's frame_number as fragment ID because the protocol doesn't provide it */
					p_t38_conv_info->reass_ID = actx->pinfo->fd->num;
					p_t38_conv_info->reass_start_seqnum = seq_number;
					p_t38_conv_info->time_first_t4_data = nstime_to_sec(&actx->pinfo->fd->rel_ts);
					p_t38_packet_conv_info->reass_ID = p_t38_conv_info->reass_ID;
					p_t38_packet_conv_info->reass_start_seqnum = p_t38_conv_info->reass_start_seqnum;
					p_t38_packet_conv_info->time_first_t4_data = p_t38_conv_info->time_first_t4_data;
			}

			frag_msg = fragment_add_seq(value_tvb, 0, actx->pinfo,
				p_t38_packet_conv_info->reass_ID, /* ID for fragments belonging together */
				data_fragment_table, /* list of message fragments */
				seq_number - (guint32)p_t38_packet_conv_info->reass_start_seqnum, /* fragment sequence number */
				value_len, /* fragment length */
				TRUE); /* More fragments */

			new_tvb = process_reassembled_data(tvb, offset, actx->pinfo,
						"Reassembled Message", frag_msg, &data_frag_items, NULL, tree);

			if (!frag_msg) { /* Not last packet of reassembled */
				if (Data_Field_field_type_value == 0) {
					if (check_col(actx->pinfo->cinfo, COL_INFO))
						col_append_fstr(actx->pinfo->cinfo, COL_INFO," (HDLC fragment %u)", seq_number - (guint32)p_t38_packet_conv_info->reass_start_seqnum);
				} else {
					if (check_col(actx->pinfo->cinfo, COL_INFO))
						col_append_fstr(actx->pinfo->cinfo, COL_INFO," (t4-data fragment %u)", seq_number - (guint32)p_t38_packet_conv_info->reass_start_seqnum);
				}
			}

			/* Now reset fragmentation information in pinfo */
			actx->pinfo->fragmented = save_fragmented;
		}
	}

	return offset;
}

static const per_sequence_t Data_Field_item_sequence[] = {
	{ &hf_t38_Data_Field_field_type, ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_Data_Field_field_type },
	{ &hf_t38_Data_Field_field_data, ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_t38_Data_Field_field_data },
	{ NULL, 0, 0, NULL }
};

static int
dissect_t38_Data_Field_item(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
	offset=dissect_per_sequence(tvb, offset, actx,
        tree, hf_index, ett_t38_Data_Field_item,
        Data_Field_item_sequence);

	if (primary_part) Data_Field_item_num++;

	return offset;
}

static const per_sequence_t t38_Data_Field_sequence_of[1] = {
  { &hf_t38_Data_Field_item,  ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t38_Data_Field_item },
};

static int
dissect_t38_Data_Field(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_t38_Data_Field, t38_Data_Field_sequence_of);

  return offset;
}

static const per_sequence_t IFPPacket_sequence[] = {
  { &hf_t38_Type_of_msg, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t38_Type_of_msg },
  { &hf_t38_Data_Field , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t38_Data_Field },
  { NULL, 0, 0, NULL }
};

static int
dissect_t38_IFPPacket(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, actx,
        tree, hf_t38_IFPPacket, ett_t38_IFPPacket,
        IFPPacket_sequence);
	return offset;
}

static int
dissect_t38_Seq_number(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
	offset=dissect_per_constrained_integer(tvb, offset, actx,
		tree, hf_index, 0, 65535,
		&seq_number, FALSE);
	
	/* info for tap */
	if (primary_part)
		t38_info->seq_num = seq_number;

      if (check_col(actx->pinfo->cinfo, COL_INFO)){
        col_append_fstr(actx->pinfo->cinfo, COL_INFO, "Seq=%05u ",seq_number);
	}
	return offset;
}

static int
dissect_t38_Primary_ifp_packet(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
    guint32 length;

	primary_part = TRUE;

    offset=dissect_per_length_determinant(tvb, offset, actx,
        tree, hf_t38_primary_ifp_packet_length, &length);
    offset=dissect_t38_IFPPacket(tvb, offset, actx, tree);

	/* if is a valid t38 packet, add to tap */
	if (p_t38_packet_conv && (!actx->pinfo->in_error_pkt) && ((gint32) seq_number != p_t38_packet_conv_info->last_seqnum))
		tap_queue_packet(t38_tap, actx->pinfo, t38_info);

	if (p_t38_conv) p_t38_conv_info->last_seqnum = (gint32) seq_number;

	return offset;
}

static int
dissect_t38_Secondary_ifp_packets_item(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
    guint32 length;

    offset=dissect_per_length_determinant(tvb, offset, actx,
        tree, hf_t38_secondary_ifp_packets_item_length, &length);
    offset=dissect_t38_IFPPacket(tvb, offset, actx, tree);
	return offset;
}

static const per_sequence_t SEQUENCE_OF_t38_secondary_ifp_packets_sequence_of[1] = {
  { &hf_t38_dummy, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t38_Secondary_ifp_packets_item },
};

static int
dissect_t38_Secondary_ifp_packets(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
    /* When the field-data is not present, we MUST offset 1 byte*/
    if((Data_Field_field_type_value != 0) &&
       (Data_Field_field_type_value != 6) &&
	   (Data_Field_field_type_value != 7))
    {
        offset=offset+8;
    }

    offset=dissect_per_sequence_of(tvb, offset, actx,
        tree, hf_index, ett_t38_secondary_ifp_packets,
        SEQUENCE_OF_t38_secondary_ifp_packets_sequence_of);
	return offset;
}

static int
dissect_t38_Fec_npackets(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
    offset=dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);
	return offset;
}

static int
dissect_t38_Fec_data_item(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
    offset=dissect_per_octet_string(tvb, offset, actx,
        tree, hf_index, NO_BOUND, NO_BOUND,
        NULL);
	return offset;
}
static const per_sequence_t T_t38_fec_data_sequence_of[1] = {
  { &hf_t38_fec_data_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t38_Fec_data_item },
};
static int
dissect_t38_Fec_data(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
    offset=dissect_per_sequence_of(tvb, offset, actx,
        tree, hf_index, ett_t38_fec_data,
        T_t38_fec_data_sequence_of);
	return offset;
}

static const per_sequence_t fec_info_sequence[] = {
	{ &hf_t38_fec_npackets, ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_Fec_npackets },
	{ &hf_t38_fec_data, ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_Fec_data },
	{ NULL, 0, 0, NULL }
};

static int
dissect_t38_Fec_info(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
	offset=dissect_per_sequence(tvb, offset, actx,
        tree, hf_index, ett_t38_fec_info,
        fec_info_sequence);
	return offset;
}

static const per_choice_t error_recovery_choice[] = {
	{ 0, &hf_t38_secondary_ifp_packets, ASN1_NO_EXTENSIONS,
		dissect_t38_Secondary_ifp_packets},
	{ 1, &hf_t38_fec_info, ASN1_NO_EXTENSIONS,
		dissect_t38_Fec_info},
	{ 0, NULL, 0, NULL }
};

static const value_string error_recovery_vals[] = {
	{ 0, "secondary-ifp-packets" },
	{ 1, "fec-info" },
    { 0, NULL}
};

static int
dissect_t38_Error_recovery(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
	primary_part = FALSE;

    offset=dissect_per_choice(tvb, offset, actx,
        tree, hf_index, ett_t38_error_recovery,
        error_recovery_choice, NULL);

	primary_part = TRUE;

	return offset;
}

static const per_sequence_t UDPTLPacket_sequence[] = {
	{ &hf_t38_seq_number, ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_Seq_number },
	{ &hf_t38_dummy, ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_Primary_ifp_packet },
	{ &hf_t38_error_recovery, ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_Error_recovery },
	{ NULL, 0, 0, NULL }
};

static int
dissect_t38_UDPTLPacket(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree)
{
    /* Initialize to something else than data type */
    Data_Field_field_type_value = 1;

	offset=dissect_per_sequence(tvb, offset, actx,
        tree, hf_t38_UDPTLPacket, ett_t38_UDPTLPacket,
        UDPTLPacket_sequence);
    return offset;
}

/* initialize the tap t38_info and the conversation */
static void
init_t38_info_conv(packet_info *pinfo)
{
	/* tap info */
	t38_info_current++;
	if (t38_info_current==MAX_T38_MESSAGES_IN_PACKET) {
		t38_info_current=0;
	}
	t38_info = &t38_info_arr[t38_info_current];

	t38_info->seq_num = 0;
	t38_info->type_msg = 0;
	t38_info->data_value = 0;
	t38_info->t30ind_value =0;
	t38_info->setup_frame_number = 0;
	t38_info->Data_Field_field_type_value = 0;
	t38_info->desc[0] = '\0';
	t38_info->desc_comment[0] = '\0';
	t38_info->time_first_t4_data = 0;
	t38_info->frame_num_first_t4_data = 0;


	/* 
		p_t38_packet_conv hold the conversation info in each of the packets.
		p_t38_conv hold the conversation info used to reassemble the HDLC packets, and also the Setup info (e.g SDP)
		If we already have p_t38_packet_conv in the packet, it means we already reassembled the HDLC packets, so we don't 
		need to use p_t38_conv 
	*/
	p_t38_packet_conv = NULL;
	p_t38_conv = NULL;

	/* Use existing packet info if available */
	 p_t38_packet_conv = p_get_proto_data(pinfo->fd, proto_t38);


	/* find the conversation used for Reassemble and Setup Info */
	p_conv = find_conversation(pinfo->fd->num, &pinfo->net_src, &pinfo->net_dst,
                                   pinfo->ptype,
                                   pinfo->srcport, pinfo->destport, NO_ADDR_B | NO_PORT_B);

	/* create a conv if it doen't exist */
	if (!p_conv) {
		p_conv = conversation_new(pinfo->fd->num, &pinfo->net_src, &pinfo->net_dst,
			      pinfo->ptype, pinfo->srcport, pinfo->destport, NO_ADDR_B | NO_PORT_B);

		/* Set dissector */
		conversation_set_dissector(p_conv, t38_udp_handle);
	}

	if (!p_t38_packet_conv) {
		p_t38_conv = conversation_get_proto_data(p_conv, proto_t38);

		/* create the conversation if it doen't exist */
		if (!p_t38_conv) {
			p_t38_conv = se_alloc(sizeof(t38_conv));
			p_t38_conv->setup_method[0] = '\0';
			p_t38_conv->setup_frame_number = 0;

			p_t38_conv->src_t38_info.reass_ID = 0;
			p_t38_conv->src_t38_info.reass_start_seqnum = -1;
			p_t38_conv->src_t38_info.reass_data_type = 0;
			p_t38_conv->src_t38_info.last_seqnum = -1;
			p_t38_conv->src_t38_info.packet_lost = 0;
			p_t38_conv->src_t38_info.burst_lost = 0;
			p_t38_conv->src_t38_info.time_first_t4_data = 0;

			p_t38_conv->dst_t38_info.reass_ID = 0;
			p_t38_conv->dst_t38_info.reass_start_seqnum = -1;
			p_t38_conv->dst_t38_info.reass_data_type = 0;
			p_t38_conv->dst_t38_info.last_seqnum = -1;
			p_t38_conv->dst_t38_info.packet_lost = 0;
			p_t38_conv->dst_t38_info.burst_lost = 0;
			p_t38_conv->dst_t38_info.time_first_t4_data = 0;

			conversation_add_proto_data(p_conv, proto_t38, p_t38_conv);
		}

		/* copy the t38 conversation info to the packet t38 conversation */
		p_t38_packet_conv = se_alloc(sizeof(t38_conv));
		strcpy(p_t38_packet_conv->setup_method, p_t38_conv->setup_method);
		p_t38_packet_conv->setup_frame_number = p_t38_conv->setup_frame_number;

		memcpy(&(p_t38_packet_conv->src_t38_info), &(p_t38_conv->src_t38_info), sizeof(t38_conv_info));
		memcpy(&(p_t38_packet_conv->dst_t38_info), &(p_t38_conv->dst_t38_info), sizeof(t38_conv_info));

		p_add_proto_data(pinfo->fd, proto_t38, p_t38_packet_conv);
	}

	if (ADDRESSES_EQUAL(&p_conv->key_ptr->addr1, &pinfo->net_src)) {
		p_t38_conv_info = &(p_t38_conv->src_t38_info);
		p_t38_packet_conv_info = &(p_t38_packet_conv->src_t38_info);
	} else {
		p_t38_conv_info = &(p_t38_conv->dst_t38_info);
		p_t38_packet_conv_info = &(p_t38_packet_conv->dst_t38_info);
	}

	/* update t38_info */
	t38_info->setup_frame_number = p_t38_packet_conv->setup_frame_number;
}

/* Entry point for dissection */
static void
dissect_t38_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 octet1;
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
	asn1_ctx_t asn1_ctx;

	/*
	 * XXX - heuristic to check for misidentified packets.
	 */
	if (dissect_possible_rtpv2_packets_as_rtp){
		octet1 = tvb_get_guint8(tvb, offset);
		if (RTP_VERSION(octet1) == 2){
			call_dissector(rtp_handle,tvb,pinfo,tree);
			return;
		}
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.38");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	primary_part = TRUE;

	/* This indicate the item number in the primary part of the T38 message, it is used for the reassemble of T30 packets */
	Data_Field_item_num = 0;

	it=proto_tree_add_protocol_format(tree, proto_t38, tvb, 0, -1, "ITU-T Recommendation T.38");
	tr=proto_item_add_subtree(it, ett_t38);

	/* init tap and conv info */
	init_t38_info_conv(pinfo);

	/* Show Conversation setup info if exists*/
	if (global_t38_show_setup_info) {
		show_setup_info(tvb, pinfo, tr, p_conv, p_t38_packet_conv);
	}

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "UDP: UDPTLPacket ");
	}

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
	offset=dissect_t38_UDPTLPacket(tvb, offset, &asn1_ctx, tr);

	if (offset&0x07){
		offset=(offset&0xfffffff8)+8;
	}
	if (tvb_length_remaining(tvb,offset>>3)>0){
		if (tr){
			proto_tree_add_text(tr, tvb, offset, tvb_reported_length_remaining(tvb, offset),
				"[MALFORMED PACKET or wrong preference settings]");
		}
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " [Malformed?]");
		}
	}
}

static void
dissect_t38_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
	guint16 ifp_packet_number=1;
	asn1_ctx_t asn1_ctx;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.38");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	primary_part = TRUE;

	/* This indicate the item number in the primary part of the T38 message, it is used for the reassemble of T30 packets */
	Data_Field_item_num = 0;

	it=proto_tree_add_protocol_format(tree, proto_t38, tvb, 0, -1, "ITU-T Recommendation T.38");
	tr=proto_item_add_subtree(it, ett_t38);

	/* init tap and conv info */
	init_t38_info_conv(pinfo);

	/* Show Conversation setup info if exists*/
	if (global_t38_show_setup_info) {
		show_setup_info(tvb, pinfo, tr, p_conv, p_t38_packet_conv);
	}

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "TCP: IFPPacket");
	}

	while(tvb_length_remaining(tvb,offset>>3)>0)
	{
		asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
		offset=dissect_t38_IFPPacket(tvb, offset, &asn1_ctx, tr);
		ifp_packet_number++;

		if(offset&0x07){
			offset=(offset&0xfffffff8)+8;
		}

		if(tvb_length_remaining(tvb,offset>>3)>0){
			if(t38_tpkt_usage == T38_TPKT_ALWAYS){
				if(tr){
					proto_tree_add_text(tr, tvb, offset, tvb_reported_length_remaining(tvb, offset),
						"[MALFORMED PACKET or wrong preference settings]");
				}
				if (check_col(pinfo->cinfo, COL_INFO)){
					col_append_fstr(pinfo->cinfo, COL_INFO, " [Malformed?]");
				}
				break;
			} 
			else {
				if (check_col(pinfo->cinfo, COL_INFO)){
					col_append_fstr(pinfo->cinfo, COL_INFO, " IFPPacket#%u",ifp_packet_number);
				}
			}
		}
	}

}

static void
dissect_t38_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	primary_part = TRUE;

	if(t38_tpkt_usage == T38_TPKT_ALWAYS){
		dissect_tpkt_encap(tvb,pinfo,tree,t38_tpkt_reassembly,t38_tcp_pdu_handle);
	} 
	else if((t38_tpkt_usage == T38_TPKT_NEVER) || (is_tpkt(tvb,1) == -1)){
		dissect_t38_tcp_pdu(tvb, pinfo, tree);
	} 
	else {
		dissect_tpkt_encap(tvb,pinfo,tree,t38_tpkt_reassembly,t38_tcp_pdu_handle);
	}
}

static void
dissect_t38(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if(pinfo->ipproto == IP_PROTO_TCP)
	{
		dissect_t38_tcp(tvb, pinfo, tree);
	}
	else if(pinfo->ipproto == IP_PROTO_UDP)
	{   
		dissect_t38_udp(tvb, pinfo, tree);
	}
}

/* Look for conversation info and display any setup info found */
void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, conversation_t *p_conv, t38_conv *p_t38_conv)
{
	proto_tree *t38_setup_tree;
	proto_item *ti;

	if (!p_t38_conv || p_t38_conv->setup_frame_number == 0) {
		/* there is no Setup info */
		return;
	}

	ti =  proto_tree_add_string_format(tree, hf_t38_setup, tvb, 0, 0,
                      "",
                      "Stream setup by %s (frame %u)",
                      p_t38_conv->setup_method,
                      p_t38_conv->setup_frame_number);
    PROTO_ITEM_SET_GENERATED(ti);
    t38_setup_tree = proto_item_add_subtree(ti, ett_t38_setup);
    if (t38_setup_tree)
    {
		/* Add details into subtree */
		proto_item* item = proto_tree_add_uint(t38_setup_tree, hf_t38_setup_frame,
                                                               tvb, 0, 0, p_t38_conv->setup_frame_number);
		PROTO_ITEM_SET_GENERATED(item);
		item = proto_tree_add_string(t38_setup_tree, hf_t38_setup_method,
                                                     tvb, 0, 0, p_t38_conv->setup_method);
		PROTO_ITEM_SET_GENERATED(item);
    }
}



/* Wireshark Protocol Registration */
void
proto_register_t38(void)
{
	static hf_register_info hf[] =
	{
        {  &hf_t38_IFPPacket,
            { "IFPPacket", "t38.IFPPacket", FT_NONE, BASE_NONE,
		      NULL, 0, "IFPPacket sequence", HFILL }},
        {  &hf_t38_Type_of_msg,
            { "Type of msg", "t38.Type_of_msg_type", FT_UINT32, BASE_DEC,
		      VALS(Type_of_msg_vals), 0, "Type_of_msg choice", HFILL }},
        {  &hf_t38_t30_indicator,
            { "T30 indicator", "t38.t30_indicator", FT_UINT32, BASE_DEC,
              VALS(t30_indicator_vals), 0, "t30_indicator", HFILL }},
        {  &hf_t38_data,
            { "data", "t38.t38_data", FT_UINT32, BASE_DEC,
              VALS(t30_data_vals), 0, "data", HFILL }},
        {  &hf_t38_Data_Field,
            { "Data Field", "t38.Data_Field", FT_NONE, BASE_NONE,
              NULL, 0, "Data_Field sequence of", HFILL }},
        {  &hf_t38_Data_Field_item,
            { "Data_Field_item", "t38.Data_Field_item", FT_NONE, BASE_NONE,
              NULL, 0, "Data_Field_item sequence", HFILL }},
        {  &hf_t38_Data_Field_field_type,
            { "Data_Field_field_type", "t38.Data_Field_field_type", FT_UINT32, BASE_DEC,
              VALS(Data_Field_field_type_vals), 0, "Data_Field_field_type choice", HFILL }},
        {  &hf_t38_Data_Field_field_data,
            { "Data_Field_field_data", "t38.Data_Field_field_data", FT_BYTES, BASE_HEX,
            NULL, 0, "Data_Field_field_data octet string", HFILL }},
        {  &hf_t38_UDPTLPacket,
            { "UDPTLPacket", "t38.UDPTLPacket", FT_NONE, BASE_NONE,
		      NULL, 0, "UDPTLPacket sequence", HFILL }},
        {  &hf_t38_seq_number,
            { "Sequence number", "t38.seq_number", FT_UINT32, BASE_DEC,
		      NULL, 0, "seq_number", HFILL }},
        {  &hf_t38_primary_ifp_packet,
            { "Primary IFPPacket", "t38.primary_ifp_packet", FT_BYTES, BASE_HEX,
              NULL, 0, "primary_ifp_packet octet string", HFILL }},
        {  &hf_t38_primary_ifp_packet_length,
            { "primary_ifp_packet_length", "t38.primary_ifp_packet_length", FT_UINT32, BASE_DEC,
            NULL, 0, "primary_ifp_packet_length", HFILL }},
        {  &hf_t38_error_recovery,
            { "Error recovery", "t38.error_recovery", FT_UINT32, BASE_DEC,
		      VALS(error_recovery_vals), 0, "error_recovery choice", HFILL }},
        {  &hf_t38_secondary_ifp_packets,
            { "Secondary IFPPackets", "t38.secondary_ifp_packets", FT_NONE, BASE_NONE,
              NULL, 0, "secondary_ifp_packets sequence of", HFILL }},
        {  &hf_t38_secondary_ifp_packets_item,
            { "Secondary IFPPackets item", "t38.secondary_ifp_packets_item", FT_BYTES, BASE_HEX,
              NULL, 0, "secondary_ifp_packets_item octet string", HFILL }},
        {  &hf_t38_secondary_ifp_packets_item_length,
            { "secondary_ifp_packets_item_length", "t38.secondary_ifp_packets_item_length", FT_UINT32, BASE_DEC,
            NULL, 0, "secondary_ifp_packets_item_length", HFILL }},
        {  &hf_t38_fec_info,
            { "Fec info", "t38.fec_info", FT_NONE, BASE_NONE,
		      NULL, 0, "fec_info sequence", HFILL }},
        {  &hf_t38_fec_npackets,
            { "Fec npackets", "h245.fec_npackets", FT_INT32, BASE_DEC,
              NULL, 0, "fec_npackets value", HFILL }},
        {  &hf_t38_fec_data,
            { "Fec data", "t38.fec_data", FT_NONE, BASE_NONE,
              NULL, 0, "fec_data sequence of", HFILL }},
        {  &hf_t38_fec_data_item,
            { "t38_fec_data_item", "t38.t38_fec_data_item", FT_BYTES, BASE_HEX,
            NULL, 0, "t38_fec_data_item octet string", HFILL }},
		{   &hf_t38_setup,
		    { "Stream setup", "t38.setup", FT_STRING, BASE_NONE,
		    NULL, 0x0, "Stream setup, method and frame number", HFILL }},
		{   &hf_t38_setup_frame,
            { "Stream frame", "t38.setup-frame", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "Frame that set up this stream", HFILL }},
        {   &hf_t38_setup_method,
            { "Stream Method", "t38.setup-method", FT_STRING, BASE_NONE,
            NULL, 0x0, "Method used to set up this stream", HFILL }},
		{&hf_data_fragments,
			{"Message fragments", "data.fragments",
			FT_NONE, BASE_NONE, NULL, 0x00,	NULL, HFILL } },
		{&hf_data_fragment,
			{"Message fragment", "data.fragment",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_data_fragment_overlap,
			{"Message fragment overlap", "data.fragment.overlap",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_data_fragment_overlap_conflicts,
			{"Message fragment overlapping with conflicting data",
			"data.fragment.overlap.conflicts",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_data_fragment_multiple_tails,
			{"Message has multiple tail fragments",
			"data.fragment.multiple_tails", 
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_data_fragment_too_long_fragment,
			{"Message fragment too long", "data.fragment.too_long_fragment",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_data_fragment_error,
			{"Message defragmentation error", "data.fragment.error",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_data_reassembled_in,
			{"Reassembled in", "data.reassembled.in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	};

	static gint *ett[] =
	{
		&ett_t38,
		&ett_t38_IFPPacket,
		&ett_t38_Type_of_msg,
		&ett_t38_t30_indicator,
		&ett_t38_data,
		&ett_t38_Data_Field,
		&ett_t38_Data_Field_item,
		&ett_t38_Data_Field_field_type,
		&ett_t38_UDPTLPacket,
		&ett_t38_error_recovery,
		&ett_t38_secondary_ifp_packets,
		&ett_t38_fec_info,
		&ett_t38_fec_data,
		&ett_t38_setup,
		&ett_data_fragment,
		&ett_data_fragments
	};

	static hf_register_info hf_t30[] =
	{
        {  &hf_t30_Address,
            { "Address", "t30.Address", FT_UINT8, BASE_HEX,
		      NULL, 0, "Address Field", HFILL }},
        {  &hf_t30_Control,
            { "Control", "t30.Control", FT_UINT8, BASE_HEX,
		      VALS(t30_control_vals), 0, "Address Field", HFILL }},
        {  &hf_t30_Facsimile_Control,
            { "Facsimile Control", "t30.FacsimileControl", FT_UINT8, BASE_DEC,
		      VALS(t30_facsimile_control_field_vals), 0, "Facsimile Control", HFILL }},

		{  &hf_t30_fif_sm,
            { "Store and forward Internet fax- Simple mode (ITU-T T.37)", "t30.fif.sm", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_rtif,
            { "Real-time Internet fax (ITU T T.38)", "t30.fif.rtif", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_3gmn,
            { "3rd Generation Mobile Network", "t30.fif.3gmn", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_v8c,
            { "V.8 capabilities", "t30.fif.v8c", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x04, "", HFILL }},
		{  &hf_t30_fif_op,
            { "Octets preferred", "t30.fif.op", FT_BOOLEAN,  8,
			  TFS(&t30_octets_preferred_value), 0x02, "", HFILL }},
		{  &hf_t30_fif_rtfc,
            { "Ready to transmit a facsimile document (polling)", "t30.fif.rtfc", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_rfo,
            { "Receiver fax operation", "t30.fif.rfo", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_dsr,
            { "Data signalling rate", "t30.fif.dsr", FT_UINT8,  BASE_HEX,
			  VALS(t30_data_signalling_rate_vals), 0x3C, "", HFILL }},
		{  &hf_t30_fif_dsr_dcs,
            { "Data signalling rate", "t30.fif.dsr_dcs", FT_UINT8,  BASE_HEX,
			  VALS(t30_data_signalling_rate_dcs_vals), 0x3C, "", HFILL }},
		{  &hf_t30_fif_res,
            { "R8x7.7 lines/mm and/or 200x200 pels/25.4 mm", "t30.fif.res", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x02, "", HFILL }},
		{  &hf_t30_fif_tdcc,
            { "Two dimensional coding capability", "t30.fif.tdcc", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x01, "", HFILL }},
		{  &hf_t30_fif_rwc,
            { "Recording width capabilities", "t30.fif.rwc", FT_UINT8,  BASE_HEX,
			  VALS(t30_recording_width_capabilities_vals), 0xC0, "", HFILL }},
		{  &hf_t30_fif_rw_dcs,
            { "Recording width", "t30.fif.rw_dcs", FT_UINT8,  BASE_HEX,
			  VALS(t30_recording_width_dcs_vals), 0xC0, "", HFILL }},
		{  &hf_t30_fif_rlc,
            { "Recording length capability", "t30.fif.rlc", FT_UINT8,  BASE_HEX,
			  VALS(t30_recording_length_capability_vals), 0x30, "", HFILL }},
		{  &hf_t30_fif_rl_dcs,
            { "Recording length capability", "t30.fif.rl_dcs", FT_UINT8,  BASE_HEX,
			  VALS(t30_recording_length_dcs_vals), 0x30, "", HFILL }},
		{  &hf_t30_fif_msltcr,
            { "Minimum scan line time capability at the receiver", "t30.fif.msltcr", FT_UINT8,  BASE_HEX,
			  VALS(t30_minimum_scan_line_time_rec_vals), 0x0E, "", HFILL }},
		{  &hf_t30_fif_mslt_dcs,
            { "Minimum scan line time", "t30.fif.mslt_dcs", FT_UINT8,  BASE_HEX,
			  VALS(t30_minimum_scan_line_time_dcs_vals), 0x0E, "", HFILL }},
		{  &hf_t30_fif_ext,
            { "Extension indicator", "t30.fif.ext", FT_BOOLEAN,  8,
			  TFS(&t30_extension_ind_value), 0x01, "", HFILL }},

		{  &hf_t30_fif_cm,
            { "Compress/Uncompress mode", "t30.fif.cm", FT_BOOLEAN,  8,
			  TFS(&t30_compress_value), 0x40, "", HFILL }},
		{  &hf_t30_fif_ecm,
            { "Error correction mode", "t30.fif.ecm", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_fs_dcs,
            { "Frame size", "t30.fif.fs_dcm", FT_BOOLEAN,  8,
			  TFS(&t30_frame_size_dcs_value), 0x10, "", HFILL }},
		{  &hf_t30_fif_t6,
            { "T.6 coding capability", "t30.fif.t6", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x02, "", HFILL }},

		{  &hf_t30_fif_fvc,
            { "Field valid capability", "t30.fif.fvc", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_mspc,
            { "Multiple selective polling capability", "t30.fif.mspc", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_ps,
            { "Polled Subaddress", "t30.fif.ps", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_t43,
            { "T.43 coding", "t30.fif.t43", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_pi,
            { "Plane interleave", "t30.fif.pi", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_vc32k,
            { "Voice coding with 32k ADPCM (ITU T G.726)", "t30.fif.vc32k", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x04, "", HFILL }},

		{  &hf_t30_fif_r8x15,
            { "R8x15.4 lines/mm", "t30.fif.r8x15", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_300x300,
            { "300x300 pels/25.4 mm", "t30.fif.300x300", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_r16x15,
            { "R16x15.4 lines/mm and/or 400x400 pels/25.4 mm", "t30.fif.r16x15", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_ibrp,
            { "Inch based resolution preferred", "t30.fif.ibrp", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_mbrp,
            { "Metric based resolution preferred", "t30.fif.mbrp", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_msltchr,
            { "Minimum scan line time capability for higher resolutions", "t30.fif.msltchr", FT_BOOLEAN,  8,
			  TFS(&t30_minimum_scan_value), 0x04, "", HFILL }},
		{  &hf_t30_fif_rts,
            { "Resolution type selection", "t30.fif.rts", FT_BOOLEAN,  8,
			  TFS(&t30_res_type_sel_value), 0x10, "", HFILL }},
		{  &hf_t30_fif_sp,
            { "Selective polling", "t30.fif.sp", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x02, "", HFILL }},

		{  &hf_t30_fif_sc,
            { "Subaddressing capability", "t30.fif.sc", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_passw,
            { "Password", "t30.fif.passw", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_sit,
            { "Sender Identification transmission", "t30.fif.sit", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_rttd,
            { "Ready to transmit a data file (polling)", "t30.fif.rttd", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_bft,
            { "Binary File Transfer (BFT)", "t30.fif.bft", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_dtm,
            { "Document Transfer Mode (DTM)", "t30.fif.dtm", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x04, "", HFILL }},
		{  &hf_t30_fif_edi,
            { "Electronic Data Interchange (EDI)", "t30.fif.edi", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x02, "", HFILL }},

		{  &hf_t30_fif_btm,
            { "Basic Transfer Mode (BTM)", "t30.fif.btm", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_rttcmmd,
            { "Ready to transmit a character or mixed mode document (polling)", "t30.fif.rttcmmd", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_chrm,
            { "Character mode", "t30.fif.cm", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_mm,
            { "Mixed mode (Annex E/T.4)", "t30.fif.mm", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x04, "", HFILL }},

		{  &hf_t30_fif_pm26,
            { "Processable mode 26 (ITU T T.505)", "t30.fif.pm26", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_dnc,
            { "Digital network capability", "t30.fif.dnc", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_do,
            { "Duplex operation", "t30.fif.do", FT_BOOLEAN,  8,
			  TFS(&t30_duplex_operation_value), 0x20, "", HFILL }},
		{  &hf_t30_fif_jpeg,
            { "JPEG coding", "t30.fif.jpeg", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_fcm,
            { "Full colour mode", "t30.fif.fcm", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_pht,
            { "Preferred Huffman tables", "t30.fif.pht", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_12c,
            { "12 bits/pel component", "t30.fif.12c", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x02, "", HFILL }},

		{  &hf_t30_fif_ns,
            { "No subsampling (1:1:1)", "t30.fif.ns", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_ci,
            { "Custom illuminant", "t30.fif.ci", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_cgr,
            { "Custom gamut range", "t30.fif.cgr", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_nalet,
            { "North American Letter (215.9 x 279.4 mm) capability", "t30.fif.nalet", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_naleg,
            { "North American Legal (215.9 x 355.6 mm) capability", "t30.fif.naleg", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_spscb,
            { "Single-progression sequential coding (ITU-T T.85) basic capability", "t30.fif.spscb", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x04, "", HFILL }},
		{  &hf_t30_fif_spsco,
            { "Single-progression sequential coding (ITU-T T.85) optional L0 capability", "t30.fif.spsco", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x02, "", HFILL }},

		{  &hf_t30_fif_hkm,
            { "HKM key management capability", "t30.fif.hkm", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_rsa,
            { "RSA key management capability", "t30.fif.rsa", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_oc,
            { "Override capability", "t30.fif.oc", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_hfx40,
            { "HFX40 cipher capability", "t30.fif.hfx40", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_acn2c,
            { "Alternative cipher number 2 capability", "t30.fif.acn2c", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_acn3c,
            { "Alternative cipher number 3 capability", "t30.fif.acn3c", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x04, "", HFILL }},
		{  &hf_t30_fif_hfx40i,
            { "HFX40-I hashing capability", "t30.fif.hfx40i", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x02, "", HFILL }},

		{  &hf_t30_fif_ahsn2,
            { "Alternative hashing system number 2 capability", "t30.fif.ahsn2", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_ahsn3,
            { "Alternative hashing system number 3 capability", "t30.fif.ahsn3", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_t441,
            { "T.44 (Mixed Raster Content)", "t30.fif.t441", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_t442,
            { "T.44 (Mixed Raster Content)", "t30.fif.t442", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_t443,
            { "T.44 (Mixed Raster Content)", "t30.fif.t443", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x04, "", HFILL }},
		{  &hf_t30_fif_plmss,
            { "Page length maximum strip size for T.44 (Mixed Raster Content)", "t30.fif.plmss", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x02, "", HFILL }},

		{  &hf_t30_fif_cg300,
            { "Colour/gray-scale 300 pels/25.4 mm x 300 lines/25.4 mm or 400 pels/25.4 mm x 400 lines/25.4 mm resolution", "t30.fif.cg300", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_100x100cg,
            { "100 pels/25.4 mm x 100 lines/25.4 mm for colour/gray scale", "t30.fif.100x100cg", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_spcbft,
            { "Simple Phase C BFT Negotiations capability", "t30.fif.spcbft", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_ebft,
            { "Extended BFT Negotiations capability", "t30.fif.ebft", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_isp,
            { "Internet Selective Polling Address (ISP)", "t30.fif.isp", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_ira,
            { "Internet Routing Address (IRA)", "t30.fif.ira", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x04, "", HFILL }},
	  
		{  &hf_t30_fif_600x600,
            { "600 pels/25.4 mm x 600 lines/25.4 mm", "t30.fif.600x600", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_1200x1200,
            { "1200 pels/25.4 mm x 1200 lines/25.4 mm", "t30.fif.1200x1200", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_300x600,
            { "300 pels/25.4 mm x 600 lines/25.4 mm", "t30.fif.300x600", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_400x800,
            { "400 pels/25.4 mm x 800 lines/25.4 mm", "t30.fif.400x800", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_600x1200,
            { "600 pels/25.4 mm x 1200 lines/25.4 mm", "t30.fif.600x1200", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x08, "", HFILL }},
		{  &hf_t30_fif_cg600x600,
            { "Colour/gray scale 600 pels/25.4 mm x 600 lines/25.4 mm resolution", "t30.fif.cg600x600", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x04, "", HFILL }},
		{  &hf_t30_fif_cg1200x1200,
            { "Colour/gray scale 1200 pels/25.4 mm x 1200 lines/25.4 mm resolution", "t30.fif.cg1200x1200", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x02, "", HFILL }},

		{  &hf_t30_fif_dspcam,
            { "Double sided printing capability (alternate mode)", "t30.fif.dspcam", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x80, "", HFILL }},
		{  &hf_t30_fif_dspccm,
            { "Double sided printing capability (continuous mode)", "t30.fif.dspccm", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x40, "", HFILL }},
		{  &hf_t30_fif_bwmrcp,
            { "Black and white mixed raster content profile (MRCbw)", "t30.fif.bwmrcp", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x20, "", HFILL }},
		{  &hf_t30_fif_t45,
            { "T.45 (run length colour encoding)", "t30.fif.t45", FT_BOOLEAN,  8,
			  TFS(&flags_set_truth), 0x10, "", HFILL }},
		{  &hf_t30_fif_sdmc,
            { "SharedDataMemory capacity", "t30.fif.sdmc", FT_UINT8,  BASE_HEX,
			  VALS(t30_SharedDataMemory_capacity_vals), 0x0C, "", HFILL }},

		{ &hf_t30_fif_number,
		  { "Number", "t30.fif.number", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

        {  &hf_t30_fif_country_code,
            { "ITU-T Country code", "t30.fif.country_code", FT_UINT8, BASE_DEC,
		      NULL, 0, "ITU-T Country code", HFILL }},
        {  &hf_t30_fif_non_stand_bytes,
            { "Non-standard capabilities", "t30.fif.non_standard_cap", FT_BYTES, BASE_HEX,
		      NULL, 0, "Non-standard capabilities", HFILL }},
 
		{  &hf_t30_t4_frame_num,
            { "T.4 Frame number", "t30.t4.frame_num", FT_UINT8, BASE_DEC,
		      NULL, 0, "T.4 Frame number", HFILL }},
        {  &hf_t30_t4_data,
            { "T.4 Facsimile data field", "t30.t4.data", FT_BYTES, BASE_HEX,
		      NULL, 0, "T.4 Facsimile data field", HFILL }},

        {  &hf_t30_partial_page_fcf2,
            { "Post-message command", "t30.pps.fcf2", FT_UINT8, BASE_DEC,
		      VALS(t30_partial_page_fcf2_vals), 0, "Post-message command", HFILL }},			  
		{  &hf_t30_partial_page_i1,
            { "Page counter", "t30.t4.page_count", FT_UINT8, BASE_DEC,
		      NULL, 0, "Page counter", HFILL }},
		{  &hf_t30_partial_page_i2,
            { "Block counter", "t30.t4.block_count", FT_UINT8, BASE_DEC,
		      NULL, 0, "Block counter", HFILL }},
		{  &hf_t30_partial_page_i3,
            { "Frame counter", "t30.t4.frame_count", FT_UINT8, BASE_DEC,
		      NULL, 0, "Frame counter", HFILL }},
	};

	static gint *t30_ett[] =
	{
		&ett_t30,
		&ett_t30_fif,
	};

	module_t *t38_module;

	proto_t38 = proto_register_protocol("T.38", "T.38", "t38");
	proto_register_field_array(proto_t38, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("t38", dissect_t38, proto_t38);

	/* Init reassemble tables for HDLC */
    register_init_routine(t38_defragment_init);

	t38_tap = register_tap("t38");

	t38_module = prefs_register_protocol(proto_t38, proto_reg_handoff_t38);
	prefs_register_bool_preference(t38_module, "use_pre_corrigendum_asn1_specification",
	    "Use the Pre-Corrigendum ASN.1 specification",
	    "Whether the T.38 dissector should decode using the Pre-Corrigendum T.38 "
		"ASN.1 specification (1998).",
	    &use_pre_corrigendum_asn1_specification);
	prefs_register_bool_preference(t38_module, "dissect_possible_rtpv2_packets_as_rtp",
	    "Dissect possible RTP version 2 packets with RTP dissector",
	    "Whether a UDP packet that looks like RTP version 2 packet will "
		"be dissected as RTP packet or T.38 packet. If enabled there is a risk that T.38 UDPTL "
		"packets with sequence number higher than 32767 may be dissected as RTP.",
	    &dissect_possible_rtpv2_packets_as_rtp);
	prefs_register_uint_preference(t38_module, "tcp.port",
		"T.38 TCP Port",
		"Set the TCP port for T.38 messages",
		10, &global_t38_tcp_port);
	prefs_register_uint_preference(t38_module, "udp.port",
		"T.38 UDP Port",
		"Set the UDP port for T.38 messages",
		10, &global_t38_udp_port);	
	prefs_register_bool_preference(t38_module, "reassembly",
		"Reassemble T.38 PDUs over TPKT over TCP",
		"Whether the dissector should reassemble T.38 PDUs spanning multiple TCP segments "
		"when TPKT is used over TCP. "
        "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&t38_tpkt_reassembly);
	prefs_register_enum_preference(t38_module, "tpkt_usage",
		"TPKT used over TCP",
		"Whether T.38 is used with TPKT for TCP",
		(gint *)&t38_tpkt_usage,t38_tpkt_options,FALSE);

	prefs_register_bool_preference(t38_module, "show_setup_info",
                "Show stream setup information",
                "Where available, show which protocol and frame caused "
                "this T.38 stream to be created",
                &global_t38_show_setup_info);

	/* T30 */
	proto_t30 = proto_register_protocol("T.30", "T.30", "t30");
	proto_register_field_array(proto_t30, hf_t30, array_length(hf_t30));
	proto_register_subtree_array(t30_ett, array_length(t30_ett));
}

void
proto_reg_handoff_t38(void)
{
	static int t38_prefs_initialized = FALSE;

	if (!t38_prefs_initialized) {
		t38_udp_handle=create_dissector_handle(dissect_t38_udp, proto_t38);
		t38_tcp_handle=create_dissector_handle(dissect_t38_tcp, proto_t38);
		t38_tcp_pdu_handle=create_dissector_handle(dissect_t38_tcp_pdu, proto_t38);
		t38_prefs_initialized = TRUE;
	}
	else {
		dissector_delete("tcp.port", tcp_port, t38_tcp_handle);
		dissector_delete("udp.port", udp_port, t38_udp_handle);
	}
	tcp_port = global_t38_tcp_port;
	udp_port = global_t38_udp_port;

	dissector_add("tcp.port", tcp_port, t38_tcp_handle);
	dissector_add("udp.port", udp_port, t38_udp_handle);

	rtp_handle = find_dissector("rtp");
}




