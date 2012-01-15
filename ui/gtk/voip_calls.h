/* voip_calls.h
 * VoIP calls summary addition for Wireshark
 *
 * $Id$
 *
 * Copyright 2004, Ericsson , Spain
 * By Francisco Alcoba <francisco.alcoba@ericsson.com>
 *
 * based on h323_calls.h
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * H323, RTP and Graph Support
 * By Alejandro Vaquero, alejandro.vaquero@verso.com
 * Copyright 2005, Verso Technologies Inc.
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __VOIP_CALLS_H__
#define __VOIP_CALLS_H__

#include <glib.h>
#include <stdio.h>
#include <epan/address.h>
#include <epan/guid-utils.h>
#include <epan/tap-voip.h>

/****************************************************************************/
extern const char *voip_call_state_name[8];

typedef enum _voip_protocol {
		VOIP_SIP,
		VOIP_ISUP,
		VOIP_H323,
		VOIP_MGCP,
		VOIP_AC_ISDN,
		VOIP_AC_CAS,
		MEDIA_T38,
		TEL_H248,
		TEL_SCCP,
		TEL_BSSMAP,
		TEL_RANAP,
		VOIP_UNISTIM,
		VOIP_SKINNY,
		VOIP_IAX2,
		VOIP_COMMON
} voip_protocol;

extern const char *voip_protocol_name[];

/* defines specific SIP data */

typedef enum _sip_call_state {
	SIP_INVITE_SENT,
	SIP_200_REC,
	SIP_CANCEL_SENT
} sip_call_state;

typedef struct _sip_calls_info {
	gchar *call_identifier;
	guint32 invite_cseq;
	sip_call_state sip_state;
} sip_calls_info_t;

/* defines specific ISUP data */
typedef struct _isup_calls_info {
	guint16			cic;
	guint32			opc, dpc;
	guint8			ni;
} isup_calls_info_t;

/* defines specific H245 data */
typedef struct _h245_address {
	address h245_address;
	guint16 h245_port;
} h245_address_t;

/* defines specific H323 data */
typedef struct _h323_calls_info {
	e_guid_t *guid;	/* Call ID to identify a H225 */
	GList*  h245_list;   /* list of H245 Address and ports for tunneling off calls*/
	address h225SetupAddr; /* we use the SETUP H225 IP to determine if packets are forward or reverse */					
	gboolean is_h245;
	gboolean is_faststart_Setup;	/* if faststart field is included in Setup*/
	gboolean is_faststart_Proc;		/* if faststart field is included in Proce, Alerting, Progress or Connect*/
	gboolean is_h245Tunneling;
	gint32 q931_crv;
	gint32 q931_crv2;
	guint requestSeqNum;
} h323_calls_info_t;

/* defines specific MGCP data */
typedef struct _mgcp_calls_info {
	gchar *endpointId;
	gboolean fromEndpoint; /* true if the call was originated from the Endpoint, false for calls from MGC */
} mgcp_calls_info_t;

/* defines specific ACTRACE ISDN data */
typedef struct _actrace_isdn_calls_info {
	gint32 crv;
	int trunk;
} actrace_isdn_calls_info_t;

/* defines specific ACTRACE CAS data */
typedef struct _actrace_cas_calls_info {
	gint32 bchannel;
	int trunk;
} actrace_cas_calls_info_t;

/* defines specific SKINNY data */
typedef struct _skinny_calls_info {
	guint32 callId;
} skinny_calls_info_t;

/* defines a voip call */
typedef struct _voip_calls_info {
	voip_call_state call_state;
	voip_call_active_state call_active_state;
	gchar *call_id;
	gchar *from_identity;
	gchar *to_identity;
	gpointer prot_info;
	void(*free_prot_info)(gpointer);
	address initial_speaker;
	guint32 npackets;
	voip_protocol protocol;
	gchar *protocol_name;
	gchar *call_comment;
	guint16 call_num;
	/* The frame_data struct holds the frame number and timing information needed. */
	frame_data *start_fd; 
	frame_data *stop_fd;
	gboolean selected;

} voip_calls_info_t;

/* structure that holds the information about all detected calls */
/* struct holding all information of the tap */

typedef struct _voip_calls_tapinfo {
	int     ncalls;       /* number of call */
	GList*  callsinfo_list;   /* list with all calls */
	int     npackets;       /* total number of packets of all calls */
	voip_calls_info_t* filter_calls_fwd;  /* used as filter in some tap modes */
	guint32 launch_count;   /* number of times the tap has been run */
	int start_packets;
	int completed_calls;
	int rejected_calls;
	graph_analysis_info_t* graph_analysis;
	gboolean redraw;
	/* 
	 * Now add dummy variables, one for each tap listener.
	 * Their address will be used to distinguish between them.
	 */
	int sip_dummy;
	int sdp_dummy;
	int h225_dummy;
	int h245dg_dummy;
	int mtp3_dummy;
	int m3ua_dummy;
	int isup_dummy;
	int q931_dummy;
	int mgcp_dummy;
	int actrace_dummy;
	int t38_dummy;
	int h248_dummy;
	int sccp_dummy;
	int sua_dummy;
	int megaco_dummy;
	int unistim_dummy;
	int skinny_dummy;
	int iax2_dummy;
	int voip_dummy;
} voip_calls_tapinfo_t;



/* structure that holds the information about all RTP streams associated with the calls */
/* struct holding all information of the RTP tap */
typedef struct _voip_rtp_tapinfo {
	int     nstreams;       /* number of rtp streams */
	GList*  list;			/* list with the rtp streams */
	int rtp_dummy;
	int rtp_event_dummy;
} voip_rtp_tapinfo_t;

/****************************************************************************/
/* INTERFACE */

/*
* Registers the voip_calls tap listeners (if not already done).
* From that point on, the calls list will be updated with every redissection.
* This function is also the entry point for the initialization routine of the tap system.
* So whenever voip_calls.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
* If not, it will be registered on demand by the voip_calls functions that need it.
*/
void sip_calls_init_tap(void);
void isup_calls_init_tap(void);
void mtp3_calls_init_tap(void);
void h225_calls_init_tap(void);
void h245dg_calls_init_tap(void);
void q931_calls_init_tap(void);
void sdp_calls_init_tap(void);
void rtp_init_tap(void);
void rtp_event_init_tap(void);
void mgcp_calls_init_tap(void);
void actrace_calls_init_tap(void);
void t38_init_tap(void);
void h248_calls_init_tap(void);
void sccp_calls_init_tap(void);
void unistim_calls_init_tap(void);
void skinny_calls_init_tap(void);
void iax2_calls_init_tap(void);
void VoIPcalls_init_tap(void);

/*
* Removes the voip_calls tap listener (if not already done)
* From that point on, the voip calls list won't be updated any more.
*/
void remove_tap_listener_sip_calls(void);
void remove_tap_listener_isup_calls(void);
void remove_tap_listener_mtp3_calls(void);
void remove_tap_listener_h225_calls(void);
void remove_tap_listener_h245dg_calls(void);
void remove_tap_listener_q931_calls(void);
void remove_tap_listener_sdp_calls(void);
void remove_tap_listener_rtp(void);
void remove_tap_listener_rtp_event(void);
void remove_tap_listener_mgcp_calls(void);
void remove_tap_listener_actrace_calls(void);
void remove_tap_listener_t38(void);
void remove_tap_listener_h248_calls(void);
void remove_tap_listener_sccp_calls(void);
void remove_tap_listener_unistim_calls(void);
void remove_tap_listener_skinny_calls(void);
void remove_tap_listener_iax2_calls(void);
void remove_tap_listener_voip_calls(void);

/*
* Retrieves a constant reference to the unique info structure of the voip_calls tap listener.
* The user should not modify the data pointed to.
*/
voip_calls_tapinfo_t* voip_calls_get_info(void);

/*
* Cleans up memory of voip calls tap.
*/
void isup_calls_reset(voip_calls_tapinfo_t *tapinfo);
void mtp3_calls_reset(voip_calls_tapinfo_t *tapinfo);
void q931_calls_reset(voip_calls_tapinfo_t *tapinfo);
void voip_calls_reset(voip_calls_tapinfo_t *tapinfo);

void graph_analysis_data_init(void);

#endif /* __VOIP_CALLS_H__ */
