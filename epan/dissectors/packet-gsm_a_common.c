/* packet-gsm_a_common.c
 * Common routines for GSM A Interface dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Split from packet-gsm_a.c by Neil Piercy <Neil [AT] littlebriars.co.uk>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <string.h>

#include <epan/packet.h>
#include <epan/tap.h>

#include "packet-bssap.h"
#include "packet-sccp.h"
#include "packet-gsm_a_common.h"

/* nasty globals as a result of the split of packet-gsm_a.c in need of further restructure */
/* nasty static for handling half octet mandatory V IEs */
gboolean lower_nibble=FALSE;

const value_string gsm_common_elem_strings[] = {
	/* Common Information Elements 10.5.1 */
	{ 0x00,	"Cell Identity" },
	{ 0x00,	"Ciphering Key Sequence Number" },
	{ 0x00,	"Location Area Identification" },
	{ 0x00,	"Mobile Identity" },
	{ 0x00,	"Mobile Station Classmark 1" },
	{ 0x00,	"Mobile Station Classmark 2" },
	{ 0x00,	"Mobile Station Classmark 3" },
	{ 0x00,	"Spare Half Octet" },
	{ 0x00,	"Descriptive group or broadcast call reference" },
	{ 0x00,	"Group Cipher Key Number" },
	{ 0x00,	"PD and SAPI $(CCBS)$" },
	{ 0x00,	"Priority Level" },
	{ 0x00,	"PLMN List" },
	{ 0, NULL }
};

/* Mobile Station Classmark Value strings
 */

/* Mobile Station Classmark
 * Revision level
 */
static const value_string gsm_a_msc_rev_vals[] = {
	{ 0,	"Reserved for GSM phase 1"},
	{ 1,	"Used by GSM phase 2 mobile stations"},
	{ 2,	"Used by mobile stations supporting R99 or later versions of the protocol"},
	{ 3,	"Reserved for future use"},
	{ 0,	NULL }
};

/* ES IND (octet 3, bit 5) "Controlled Early Classmark Sending" option implementation */
static const value_string ES_IND_vals[] = {
	{ 0,	"Controlled Early Classmark Sending option is not implemented in the MS"},
	{ 1,	"Controlled Early Classmark Sending option is implemented in the MS"},
	{ 0,	NULL }
};
/* A5/1 algorithm supported (octet 3, bit 4 */
static const value_string A5_1_algorithm_sup_vals[] = {
	{ 0,	"encryption algorithm A5/1 available"},
	{ 1,	"encryption algorithm A5/1 not available"},
	{ 0,	NULL }
};
/* RF Power Capability (Octet 3) */
static const value_string RF_power_capability_vals[] = {
	{ 0,	"class 1"},
	{ 1,	"class 2"},
	{ 2,	"class 3"},
	{ 3,	"class 4"},
	{ 4,	"class 5"},
	{ 7,	"RF Power capability is irrelevant in this information element"},
	{ 0,	NULL }
};
/* PS capability (pseudo-synchronization capability) (octet 4) */
static const value_string ps_sup_cap_vals[] = {
	{ 0,	"PS capability not present"},
	{ 1,	"PS capability present"},
	{ 0,	NULL }
};
/* SS Screening Indicator (octet 4)defined in 3GPP TS 24.080 */
static const value_string SS_screening_indicator_vals[] = {
	{ 0,	"Default value of phase 1"},
	{ 1,	"Capability of handling of ellipsis notation and phase 2 error handling "},
	{ 2,	"For future use"},
	{ 3,	"For future use"},
	{ 0,	NULL }
};
/* SM capability (MT SMS pt to pt capability) (octet 4)*/
static const value_string SM_capability_vals[] = {
	{ 0,	"Mobile station does not support mobile terminated point to point SMS"},
	{ 1,	"Mobile station supports mobile terminated point to point SMS"},
	{ 0,	NULL }
};
/* VBS notification reception (octet 4) */
static const value_string VBS_notification_rec_vals[] = {
	{ 0,	"no VBS capability or no notifications wanted"},
	{ 1,	"VBS capability and notifications wanted"},
	{ 0,	NULL }
};
/* VGCS notification reception (octet 4) */
static const value_string VGCS_notification_rec_vals[] = {
	{ 0,	"no VGCS capability or no notifications wanted"},
	{ 1,	"VGCS capability and notifications wanted"},
	{ 0,	NULL }
};
/* FC Frequency Capability (octet 4 ) */
static const value_string FC_frequency_cap_vals[] = {
	{ 0,	"The MS does not support the E-GSM or R-GSM band"},
	{ 1,	"The MS does support the E-GSM or R-GSM "},
	{ 0,	NULL }
};
/* CM3 (octet 5, bit 8) */
static const value_string CM3_vals[] = {
	{ 0,	"The MS does not support any options that are indicated in CM3"},
	{ 1,	"The MS supports options that are indicated in classmark 3 IE"},
	{ 0,	NULL }
};
/* LCS VA capability (LCS value added location request notification capability) (octet 5,bit 6) */
static const value_string LCS_VA_cap_vals[] = {
	{ 0,	"LCS value added location request notification capability not supported"},
	{ 1,	"LCS value added location request notification capability supported"},
	{ 0,	NULL }
};
/* UCS2 treatment (octet 5, bit 5) */
static const value_string UCS2_treatment_vals[] = {
	{ 0,	"the ME has a preference for the default alphabet"},
	{ 1,	"the ME has no preference between the use of the default alphabet and the use of UCS2"},
	{ 0,	NULL }
};
/* SoLSA (octet 5, bit 4) */
static const value_string SoLSA_vals[] = {
	{ 0,	"The ME does not support SoLSA"},
	{ 1,	"The ME supports SoLSA"},
	{ 0,	NULL }
};
/* CMSP: CM Service Prompt (octet 5, bit 3) */
static const value_string CMSP_vals[] = {
	{ 0,	"Network initiated MO CM connection request not supported"},
	{ 1,	"Network initiated MO CM connection request supported for at least one CM protocol"},
	{ 0,	NULL }
};
/* A5/4 algorithm supported */
static const value_string A5_7_algorithm_sup_vals[] = {
	{ 0,	"encryption algorithm A5/7 not available"},
	{ 1,	"encryption algorithm A5/7 available"},
	{ 0,	NULL }
};
/* A5/4 algorithm supported */
static const value_string A5_6_algorithm_sup_vals[] = {
	{ 0,	"encryption algorithm A5/6 not available"},
	{ 1,	"encryption algorithm A5/6 available"},
	{ 0,	NULL }
};
/* A5/5 algorithm supported */
static const value_string A5_5_algorithm_sup_vals[] = {
	{ 0,	"encryption algorithm A5/5 not available"},
	{ 1,	"encryption algorithm A5/5 available"},
	{ 0,	NULL }
};
/* A5/4 algorithm supported */
static const value_string A5_4_algorithm_sup_vals[] = {
	{ 0,	"encryption algorithm A5/4 not available"},
	{ 1,	"encryption algorithm A5/4 available"},
	{ 0,	NULL }
};

/* A5/3 algorithm supported (octet 5, bit 2) */
static const value_string A5_3_algorithm_sup_vals[] = {
	{ 0,	"encryption algorithm A5/3 not available"},
	{ 1,	"encryption algorithm A5/3 available"},
	{ 0,	NULL }
};

/* A5/2 algorithm supported (octet 5, bit 1) */
static const value_string A5_2_algorithm_sup_vals[] = {
	{ 0,	"encryption algorithm A5/2 not available"},
	{ 1,	"encryption algorithm A5/2 available"},
	{ 0,	NULL }
};

static const value_string mobile_identity_type_vals[] = {
	{ 1,	"IMSI"},
	{ 2,	"IMEI"},
	{ 3,	"IMEISV"},
	{ 4,	"TMSI/P-TMSI"},
	{ 5,	"TMGI and optional MBMS Session Identity"}, /* ETSI TS 124 008 V6.8.0 (2005-03) p326 */
	{ 0,	"No Identity"},
	{ 0,	NULL }
};

static const value_string oddevenind_vals[] = {
	{ 0,	"Even number of identity digits"},
	{ 1,	"Odd number of identity digits"},
	{ 0,	NULL }
};

static const value_string true_false_vals[] = {
    { 0, "false" },
    { 1, "true" },
    { 0, NULL}
};

static const value_string gsm_a_sms_vals[] = {
    {0, "1/4 timeslot (~144 microseconds)" },
    {1, "2/4 timeslot (~288 microseconds)" },
    {2, "3/4 timeslot (~433 microseconds)" },
    {3, "4/4 timeslot (~577 microseconds)" },
    {4, "5/4 timeslot (~721 microseconds)" },
    {5, "6/4 timeslot (~865 microseconds)" },
    {6, "7/4 timeslot (~1009 microseconds)" },
    {7, "8/4 timeslot (~1154 microseconds)" },
    {8, "9/4 timeslot (~1298 microseconds)" },
    {9, "10/4 timeslot (~1442 microseconds)" },
    {10, "11/4 timeslot (~1586 microseconds)" },
    {11, "12/4 timeslot (~1730 microseconds)" },
    {12, "13/4 timeslot (~1874 microseconds)" },
    {13, "14/4 timeslot (~2019 microseconds)" },
    {14, "15/4 timeslot (~2163 microseconds)" },
    {15, "16/4 timeslot (~2307 microseconds)" },
    { 0, NULL}
};

/* Initialize the protocol and registered fields */
static int proto_a_common = -1;

int gsm_a_tap = -1;

int hf_gsm_a_common_elem_id = -1;
static int hf_gsm_a_imsi = -1;
int hf_gsm_a_tmsi = -1;
static int hf_gsm_a_imei = -1;
static int hf_gsm_a_imeisv = -1;

static int hf_gsm_a_MSC_rev = -1;
static int hf_gsm_a_ES_IND			= -1;
static int hf_gsm_a_A5_1_algorithm_sup = -1;
static int hf_gsm_a_RF_power_capability = -1;
static int hf_gsm_a_ps_sup_cap		= -1;
static int hf_gsm_a_SS_screening_indicator = -1;
static int hf_gsm_a_SM_capability		 = -1;
static int hf_gsm_a_VBS_notification_rec = -1;
static int hf_gsm_a_VGCS_notification_rec = -1;
static int hf_gsm_a_FC_frequency_cap	= -1;
static int hf_gsm_a_CM3				= -1;
static int hf_gsm_a_LCS_VA_cap		= -1;
static int hf_gsm_a_UCS2_treatment	= -1;
static int hf_gsm_a_SoLSA				= -1;
static int hf_gsm_a_CMSP				= -1;
static int hf_gsm_a_A5_7_algorithm_sup= -1;
static int hf_gsm_a_A5_6_algorithm_sup= -1;
static int hf_gsm_a_A5_5_algorithm_sup= -1;
static int hf_gsm_a_A5_4_algorithm_sup= -1;
static int hf_gsm_a_A5_3_algorithm_sup= -1;
static int hf_gsm_a_A5_2_algorithm_sup = -1;

static int hf_gsm_a_odd_even_ind = -1;
static int hf_gsm_a_mobile_identity_type = -1;
static int hf_gsm_a_tmgi_mcc_mnc_ind = -1;
static int hf_gsm_a_mbs_ses_id_ind = -1;
static int hf_gsm_a_mbs_service_id = -1;
int hf_gsm_a_L3_protocol_discriminator = -1;
int hf_gsm_a_call_prio = -1;
int hf_gsm_a_skip_ind = -1;

static int hf_gsm_a_b7spare = -1;
int hf_gsm_a_b8spare = -1;
static int hf_gsm_a_spare_bits = -1;
static int hf_gsm_a_multi_bnd_sup_fields = -1;
static int hf_gsm_a_pgsm_supported = -1;
static int hf_gsm_a_egsm_supported = -1;
static int hf_gsm_a_gsm1800_supported = -1;
static int hf_gsm_a_ass_radio_cap1 = -1;
static int hf_gsm_a_ass_radio_cap2 = -1;
static int hf_gsm_a_rsupport = -1;
static int hf_gsm_a_r_capabilities = -1;
static int hf_gsm_a_multislot_capabilities = -1;
static int hf_gsm_a_multislot_class = -1;
static int hf_gsm_a_ucs2_treatment = -1;
static int hf_gsm_a_extended_measurement_cap = -1;
static int hf_gsm_a_ms_measurement_capability = -1;
static int hf_gsm_a_sms_value =-1;
static int hf_gsm_a_sm_value =-1;
static int hf_gsm_a_key_seq = -1;

static int hf_gsm_a_geo_loc_type_of_shape = -1;
static int hf_gsm_a_geo_loc_sign_of_lat	= -1;
static int hf_gsm_a_geo_loc_deg_of_lat =-1;
static int hf_gsm_a_geo_loc_deg_of_long =-1;
static int hf_gsm_a_geo_loc_uncertainty_code = -1;
static int hf_gsm_a_geo_loc_uncertainty_semi_major = -1;
static int hf_gsm_a_geo_loc_uncertainty_semi_minor = -1;
static int hf_gsm_a_geo_loc_orientation_of_major_axis = -1;
static int hf_gsm_a_geo_loc_uncertainty_altitude = -1;
static int hf_gsm_a_geo_loc_confidence = -1;
static int hf_gsm_a_geo_loc_no_of_points = -1;
static int hf_gsm_a_geo_loc_D = -1;
static int hf_gsm_a_geo_loc_altitude = -1;
static int hf_gsm_a_geo_loc_inner_radius = -1;
static int hf_gsm_a_geo_loc_uncertainty_radius = -1;
static int hf_gsm_a_geo_loc_offset_angle = -1;
static int hf_gsm_a_geo_loc_included_angle = -1;

static char a_bigbuf[1024];

sccp_msg_info_t* sccp_msg;
sccp_assoc_info_t* sccp_assoc;

#define	NUM_GSM_COMMON_ELEM (sizeof(gsm_common_elem_strings)/sizeof(value_string))
gint ett_gsm_common_elem[NUM_GSM_COMMON_ELEM];


#define  ELLIPSOID_POINT 0
#define  ELLIPSOID_POINT_WITH_UNCERT_CIRC 1
#define  ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE 3
#define  POLYGON 5
#define  ELLIPSOID_POINT_WITH_ALT 8
#define  ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID 9
#define  ELLIPSOID_ARC 10
/*
4 3 2 1
0 0 0 0 Ellipsoid Point
0 0 0 1 Ellipsoid point with uncertainty Circle
0 0 1 1 Ellipsoid point with uncertainty Ellipse
0 1 0 1 Polygon 
1 0 0 0 Ellipsoid point with altitude
1 0 0 1 Ellipsoid point with altitude and uncertainty Ellipsoid
1 0 1 0 Ellipsoid Arc
other values reserved for future use
*/

/* TS 23 032 Table 2a: Coding of Type of Shape */
static const value_string type_of_shape_vals[] = {
	{ ELLIPSOID_POINT,		"Ellipsoid Point"},
	{ ELLIPSOID_POINT_WITH_UNCERT_CIRC,		"Ellipsoid point with uncertainty Circle"},
	{ ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE,		"Ellipsoid point with uncertainty Ellipse"},
	{ POLYGON,		"Polygon"},
	{ ELLIPSOID_POINT_WITH_ALT,		"Ellipsoid point with altitude"},
	{ ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID,		"Ellipsoid point with altitude and uncertainty Ellipsoid"},
	{ ELLIPSOID_ARC,		"Ellipsoid Arc"},
	{ 0,	NULL }
};

/* 3GPP TS 23.032 7.3.1 */
static const value_string sign_of_latitude_vals[] = {
	{ 0,		"North"},
	{ 1,		"South"},
	{ 0,	NULL }
};

static const value_string dir_of_alt_vals[] = {
	{ 0,		"Altitude expresses height"},
	{ 1,		"Altitude expresses depth"},
	{ 0,	NULL }
};

void
dissect_geographical_description(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree){

	proto_item *lat_item, *long_item, *major_item, *minor_item, *alt_item, *uncer_item;
	/*proto_tree *subtree; */

	guint8 type_of_shape;
	guint8 no_of_points;
	int offset = 0;
	int length;
	guint8 value;
	guint32 value32;

	/*subtree = proto_item_add_subtree(item, ett_gsm_a_geo_desc);*/

	length = tvb_reported_length_remaining(tvb,0);
	/* Geographical Location 
	 * The Location Estimate field is composed of 1 or more octets with an internal structure 
	 * according to section 7 in [23.032].
	 */
	proto_tree_add_item(tree, hf_gsm_a_geo_loc_type_of_shape, tvb, 0, 1, FALSE);
	if (length<2)
		return;
	type_of_shape = tvb_get_guint8(tvb,offset)>>4;
	switch (type_of_shape){
	case ELLIPSOID_POINT:	
		/* Ellipsoid Point */
	case ELLIPSOID_POINT_WITH_UNCERT_CIRC:
		/* Ellipsoid Point with uncertainty Circle */
	case ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE:
		/* Ellipsoid Point with uncertainty Ellipse */
	case ELLIPSOID_POINT_WITH_ALT:
		/* Ellipsoid Point with Altitude */
	case ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID:
		/* Ellipsoid Point with altitude and uncertainty ellipsoid */
	case ELLIPSOID_ARC:
		/* Ellipsoid Arc */
		offset++;
		if (length<4)
			return;
		proto_tree_add_item(tree, hf_gsm_a_geo_loc_sign_of_lat, tvb, offset, 1, FALSE);

		value32 = tvb_get_ntoh24(tvb,offset)&0x7fffff;
		/* convert degrees (X/0x7fffff) * 90 = degrees */
		lat_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_deg_of_lat, tvb, offset, 3, FALSE);
		proto_item_append_text(lat_item,"(%.5f degrees)", (((double)value32/8388607) * 90));
		if (length<7)
			return;
		offset = offset + 3;
		value32 = tvb_get_ntoh24(tvb,offset)&0x7fffff;
		long_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_deg_of_long, tvb, offset, 3, FALSE);
		/* (X/0xffffff) *360 = degrees */
		proto_item_append_text(long_item,"(%.5f degrees)", (((double)value32/16777215) * 360));
		offset = offset + 3;
		if(type_of_shape==ELLIPSOID_POINT_WITH_UNCERT_CIRC){
			/* Ellipsoid Point with uncertainty Circle */
			if (length<8)
				return;
			/* Uncertainty code */
			value = tvb_get_guint8(tvb,offset)&0x7f;
			uncer_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_code, tvb, offset, 1, FALSE);
			proto_item_append_text(uncer_item,"(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
		}else if(type_of_shape==ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE){
			/* Ellipsoid Point with uncertainty Ellipse */
			/* Uncertainty semi-major octet 10
			 * To convert to metres 10*(((1.1)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			major_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_semi_major, tvb, offset, 1, FALSE);
			proto_item_append_text(major_item,"(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
			offset++;
			/* Uncertainty semi-minor Octet 11
			 * To convert to metres 10*(((1.1)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			minor_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_semi_minor, tvb, offset, 1, FALSE);
			proto_item_append_text(minor_item,"(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
			offset++;
			/* Orientation of major axis octet 12
			 * allowed value from 0-179 to convert 
			 * to actual degrees multiply by 2.
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f;
			proto_tree_add_uint(tree, hf_gsm_a_geo_loc_orientation_of_major_axis, tvb, offset, 1, value*2);
			offset++;
			/* Confidence */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_confidence, tvb, offset, 1, FALSE);
			offset++;
		}else if(type_of_shape==ELLIPSOID_POINT_WITH_ALT){
			/* Ellipsoid Point with Altitude */
			/*D: Direction of Altitude */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_D, tvb, offset, 1, FALSE);
			/* Altitude */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_altitude, tvb, offset, 2, FALSE);
		}else if(type_of_shape==ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID){
			/* Ellipsoid Point with altitude and uncertainty ellipsoid */
			/*D: Direction of Altitude octet 8,9 */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_D, tvb, offset, 1, FALSE);
			/* Altitude Octet 8,9*/
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_altitude, tvb, offset, 2, FALSE);
			offset = offset +2;
			/* Uncertainty semi-major octet 10
			 * To convert to metres 10*(((1.1)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			major_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_semi_major, tvb, offset, 1, FALSE);
			proto_item_append_text(major_item,"(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
			offset++;
			/* Uncertainty semi-minor Octet 11
			 * To convert to metres 10*(((1.1)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			minor_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_semi_minor, tvb, offset, 1, FALSE);
			proto_item_append_text(minor_item,"(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
			offset++;
			/* Orientation of major axis octet 12
			 * allowed value from 0-179 to convert 
			 * to actual degrees multiply by 2.
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f;
			proto_tree_add_uint(tree, hf_gsm_a_geo_loc_orientation_of_major_axis, tvb, offset, 1, value*2);
			offset++;
			/* Uncertainty Altitude 13
			 * to convert to metres 45*(((1.025)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			alt_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_altitude, tvb, offset, 1, FALSE);
			proto_item_append_text(alt_item,"(%.1f m)", 45 * (pow(1.025, (double)value) - 1));
			offset++;
			/* Confidence octet 14
			 */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_confidence, tvb, offset, 1, FALSE);
		}else if(type_of_shape==ELLIPSOID_ARC){
			/* Ellipsoid Arc */
			/* Inner radius */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_inner_radius, tvb, offset, 2, FALSE);
			offset= offset +2;
			/* Uncertainty radius */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_radius, tvb, offset, 1, FALSE);
			offset++;
			/* Offset angle */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_offset_angle, tvb, offset, 1, FALSE);
			offset++;
			/* Included angle */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_included_angle, tvb, offset, 1, FALSE);
			offset++;
			/* Confidence */
			proto_tree_add_item(tree, hf_gsm_a_geo_loc_confidence, tvb, offset, 1, FALSE);
		}

		break;
	case POLYGON:					/* Polygon */
		/* Number of points */
		no_of_points = tvb_get_guint8(tvb,offset)&0x0f;
		proto_tree_add_item(tree, hf_gsm_a_geo_loc_no_of_points, tvb, offset, 1, FALSE);
		/*
		while ( no_of_points > 0){
			offset++;

			no_of_points--;
		}
		*/
		break;
	default:
		break;
	}

}

const char* get_gsm_a_msg_string(int pdu_type, int idx)
{
	const char *msg_string=NULL;

	switch (pdu_type) {
		case GSM_A_PDU_TYPE_BSSMAP:
			msg_string = gsm_bssmap_elem_strings[idx].strptr;
			break;
		case GSM_A_PDU_TYPE_DTAP:
			msg_string = gsm_dtap_elem_strings[idx].strptr;
			break;
		case GSM_A_PDU_TYPE_RP:
			msg_string = gsm_rp_elem_strings[idx].strptr;
			break;
		case GSM_A_PDU_TYPE_RR:
			msg_string = gsm_rr_elem_strings[idx].strptr;
			break;
		case GSM_A_PDU_TYPE_COMMON:
			msg_string = gsm_common_elem_strings[idx].strptr;
			break;
		case GSM_A_PDU_TYPE_GM:
			msg_string = gsm_gm_elem_strings[idx].strptr;
			break;
		case GSM_A_PDU_TYPE_BSSLAP:
			msg_string = gsm_bsslap_elem_strings[idx].strptr;
			break;
		case GSM_PDU_TYPE_BSSMAP_LE:
			msg_string = gsm_bssmap_le_elem_strings[idx].strptr;
			break;
		case NAS_PDU_TYPE_COMMON:
			msg_string = nas_eps_common_elem_strings[idx].strptr;
			break;
		case NAS_PDU_TYPE_EMM:
			msg_string = nas_emm_elem_strings[idx].strptr;
			break;
		case NAS_PDU_TYPE_ESM:
			msg_string = nas_esm_elem_strings[idx].strptr;
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
	}

	return msg_string;
}

static int get_hf_elem_id(int pdu_type)
{
	int			hf_elem_id = 0;

	switch (pdu_type) {
		case GSM_A_PDU_TYPE_BSSMAP:
			hf_elem_id = hf_gsm_a_bssmap_elem_id;
			break;
		case GSM_A_PDU_TYPE_DTAP:
			hf_elem_id = hf_gsm_a_dtap_elem_id;
			break;
		case GSM_A_PDU_TYPE_RP:
			hf_elem_id = hf_gsm_a_rp_elem_id;
			break;
		case GSM_A_PDU_TYPE_RR:
			hf_elem_id = hf_gsm_a_rr_elem_id;
			break;
		case GSM_A_PDU_TYPE_COMMON:
			hf_elem_id = hf_gsm_a_common_elem_id;
			break;
		case GSM_A_PDU_TYPE_GM:
			hf_elem_id = hf_gsm_a_gm_elem_id;
			break;
		case GSM_A_PDU_TYPE_BSSLAP:
			hf_elem_id = hf_gsm_a_bsslap_elem_id;
			break;
		case GSM_PDU_TYPE_BSSMAP_LE:
			hf_elem_id = hf_gsm_bssmap_le_elem_id;
			break;
		case NAS_PDU_TYPE_COMMON:
			hf_elem_id = hf_nas_eps_common_elem_id;
			break;
		case NAS_PDU_TYPE_EMM:
			hf_elem_id = hf_nas_eps_emm_elem_id;
			break;
		case NAS_PDU_TYPE_ESM:
			hf_elem_id = hf_nas_eps_esm_elem_id;
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
	}

	return hf_elem_id;
}

/*
 * Type Length Value (TLV) element dissector
 */
guint16 elem_tlv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, guint len _U_, const gchar *name_add)
{
	guint8		oct;
	guint16		parm_len;
	guint8		lengt_length = 1;
	guint16		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == iei){
		parm_len = tvb_get_guint8(tvb, curr_offset + 1);

		item =
		proto_tree_add_text(tree,
			tvb, curr_offset, parm_len + 1 + lengt_length,
			"%s%s",
			elem_names[idx].strptr,
			(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

		subtree = proto_item_add_subtree(item, elem_ett[idx]);

		proto_tree_add_uint(subtree,
			get_hf_elem_id(pdu_type), tvb,
			curr_offset, 1, oct);

		proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
			curr_offset + 1, lengt_length, parm_len);

		if (parm_len > 0)
		{
			if (elem_funcs[idx] == NULL)
			{
				proto_tree_add_text(subtree,
					tvb, curr_offset + 1 + lengt_length, parm_len,
					"Element Value");
				/* See ASSERT above */
				consumed = (guint8)parm_len;
			}
			else
			{
				gchar *a_add_string;

				a_add_string=ep_alloc(1024);
				a_add_string[0] = '\0';
				consumed =
				(*elem_funcs[idx])(tvb, subtree, curr_offset + 2,
					parm_len, a_add_string, 1024);

				if (a_add_string[0] != '\0')
				{
					proto_item_append_text(item, "%s", a_add_string);
				}
			}
		}

		consumed += 1 + lengt_length;
	}

	return(consumed);
}

/*
 * Type Length Value Extended(TLV-E) element dissector
 * TS 24.007 
 * information elements of format LV-E or TLV-E with value part consisting of zero, 
 * one or more octets and a maximum of 65535 octets (type 6). This category is used in EPS only.
 */
guint16 elem_tlv_e(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, guint len _U_, const gchar *name_add)
{
	guint8		oct;
	guint16		parm_len;
	guint16		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == iei){
		parm_len = tvb_get_ntohs(tvb, curr_offset + 1);

		item = proto_tree_add_text(tree, tvb, curr_offset, parm_len + 1 + 2,
			"%s%s",
			elem_names[idx].strptr,
			(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

		subtree = proto_item_add_subtree(item, elem_ett[idx]);

		proto_tree_add_uint(subtree,
			get_hf_elem_id(pdu_type), tvb,
			curr_offset, 1, oct);

		proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
			curr_offset + 1, 2, parm_len);

		if (parm_len > 0)
		{
			if (elem_funcs[idx] == NULL)
			{
				proto_tree_add_text(subtree,
					tvb, curr_offset + 1 + 2, parm_len,
					"Element Value");
				/* See ASSERT above */
				consumed = parm_len;
			}
			else
			{
				gchar *a_add_string;

				a_add_string=ep_alloc(1024);
				a_add_string[0] = '\0';
				consumed =
				(*elem_funcs[idx])(tvb, subtree, curr_offset + 1 + 2,
					parm_len, a_add_string, 1024);

				if (a_add_string[0] != '\0')
				{
					proto_item_append_text(item, "%s", a_add_string);
				}
			}
		}

		consumed += 1 + 2;
	}

	return(consumed);
}

/*
 * Type Value (TV) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
guint16 elem_tv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
	guint8		oct;
	guint16		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == iei)
	{
		item =
			proto_tree_add_text(tree,
			tvb, curr_offset, -1,
			"%s%s",
			elem_names[idx].strptr,
				(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

		subtree = proto_item_add_subtree(item, elem_ett[idx]);

		proto_tree_add_uint(subtree,
			get_hf_elem_id(pdu_type), tvb,
			curr_offset, 1, oct);

		if (elem_funcs[idx] == NULL)
		{
			/* BAD THING, CANNOT DETERMINE LENGTH */

			proto_tree_add_text(subtree,
				tvb, curr_offset + 1, 1,
				"No element dissector, rest of dissection may be incorrect");

			consumed = 1;
		}
		else
		{
			gchar *a_add_string;

			a_add_string=ep_alloc(1024);
			a_add_string[0] = '\0';
			consumed = (*elem_funcs[idx])(tvb, subtree, curr_offset + 1, -1, a_add_string, 1024);

			if (a_add_string[0] != '\0')
			{
				proto_item_append_text(item, "%s", a_add_string);
			}
		}

		consumed++;

		proto_item_set_len(item, consumed);
	}

	return(consumed);
}

/*
 * Type Value (TV) element dissector
 * Where top half nibble is IEI and bottom half nibble is value.
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
guint16 elem_tv_short(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
	guint8		oct;
	guint16		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
	char buf[10+1];

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	oct = tvb_get_guint8(tvb, curr_offset);

	if ((oct & 0xf0) == (iei & 0xf0))
	{
		item =
			proto_tree_add_text(tree,
				tvb, curr_offset, -1,
				"%s%s",
				elem_names[idx].strptr,
				(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

		subtree = proto_item_add_subtree(item, elem_ett[idx]);

		other_decode_bitfield_value(buf, oct, 0xf0, 8);
		proto_tree_add_text(subtree,
			tvb, curr_offset, 1,
			"%s :  Element ID",
			buf);

		if (elem_funcs[idx] == NULL)
		{
			/* BAD THING, CANNOT DETERMINE LENGTH */

			proto_tree_add_text(subtree,
				tvb, curr_offset, 1,
				"No element dissector, rest of dissection may be incorrect");

			consumed++;
		}
		else
		{
			gchar *a_add_string;

			a_add_string=ep_alloc(1024);
			a_add_string[0] = '\0';
			consumed = (*elem_funcs[idx])(tvb, subtree, curr_offset, -1, a_add_string, 1024);

			if (a_add_string[0] != '\0')
			{
				proto_item_append_text(item, "%s", a_add_string);
			}
		}

		proto_item_set_len(item, consumed);
	}

	return(consumed);
}

/*
 * Type (T) element dissector
 */
guint16 elem_t(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
	guint8		oct;
	guint32		curr_offset;
	guint16		consumed;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == iei)
	{
		proto_tree_add_uint_format(tree,
			get_hf_elem_id(pdu_type), tvb,
			curr_offset, 1, oct,
			"%s%s",
			elem_names[idx].strptr,
			(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

		consumed = 1;
	}

	return(consumed);
}

/*
 * Length Value (LV) element dissector
 */
guint16
elem_lv(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset, guint len _U_, const gchar *name_add)
{
	guint8		parm_len;
	guint16		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	parm_len = tvb_get_guint8(tvb, curr_offset);

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, parm_len + 1,
			"%s%s",
			elem_names[idx].strptr,
			(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	subtree = proto_item_add_subtree(item, elem_ett[idx]);

	proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
		curr_offset, 1, parm_len);

	if (parm_len > 0)
	{
		if (elem_funcs[idx] == NULL)
		{
			proto_tree_add_text(subtree,
				tvb, curr_offset + 1, parm_len,
				"Element Value");

			consumed = parm_len;
		}
		else
		{
			gchar *a_add_string;

			a_add_string=ep_alloc(1024);
			a_add_string[0] = '\0';
			consumed =
				(*elem_funcs[idx])(tvb, subtree, curr_offset + 1,
					parm_len, a_add_string, 1024);

			if (a_add_string[0] != '\0')
			{
				proto_item_append_text(item, "%s", a_add_string);
			}
		}
	}

	return(consumed + 1);
}

/*
 * Length Value Extended(LV-E) element dissector
 */
guint16 elem_lv_e(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset, guint len _U_, const gchar *name_add)
{
	guint16		parm_len;
	guint16		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	parm_len = tvb_get_ntohs(tvb, curr_offset);

	item = proto_tree_add_text(tree, tvb, curr_offset, parm_len + 2,
			"%s%s",
			elem_names[idx].strptr,
			(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	subtree = proto_item_add_subtree(item, elem_ett[idx]);

	proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
		curr_offset, 2, parm_len);

	if (parm_len > 0)
	{
		if (elem_funcs[idx] == NULL)
		{
			proto_tree_add_text(subtree,
				tvb, curr_offset + 2, parm_len,
				"Element Value");

			consumed = parm_len;
		}
		else
		{
			gchar *a_add_string;

			a_add_string=ep_alloc(1024);
			a_add_string[0] = '\0';
			consumed =
				(*elem_funcs[idx])(tvb, subtree, curr_offset + 2,
					parm_len, a_add_string, 1024);

			if (a_add_string[0] != '\0')
			{
				proto_item_append_text(item, "%s", a_add_string);
			}
		}
	}

	return(consumed + 2);
}
/*
 * Value (V) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
guint16 elem_v(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset)
{
	guint16		consumed;
	guint32		curr_offset;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	if (elem_funcs[idx] == NULL)
	{
		/* BAD THING, CANNOT DETERMINE LENGTH */

		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"No element dissector, rest of dissection may be incorrect");

		consumed = 1;
	}
	else
	{
		gchar *a_add_string;

		a_add_string=ep_alloc(1024);
		a_add_string[0] = '\0';
		consumed = (*elem_funcs[idx])(tvb, tree, curr_offset, -1, a_add_string, 1024);
	}

	return(consumed);
}

/*
 * Short Value (V_SHORT) element dissector
 *
 * Length is (ab)used in these functions to indicate upper nibble of the octet (-2) or lower nibble (-1)
 * noting that the tv_short dissector always sets the length to -1, as the upper nibble is the IEI.
 * This is expected to be used upper nibble first, as the tables of 24.008.
 */

guint16 elem_v_short(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset)
{
	guint16		consumed;
	guint32		curr_offset;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	if (elem_funcs[idx] == NULL)
	{
		/* NOT A BAD THING - LENGTH IS HALF NIBBLE */

		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"No element dissector");

		consumed = 1;
	}
	else
	{
		gchar *a_add_string;

		a_add_string=ep_alloc(1024);
		a_add_string[0] = '\0';
		consumed = (*elem_funcs[idx])(tvb, tree, curr_offset, (lower_nibble?LOWER_NIBBLE:UPPER_NIBBLE), a_add_string, 1024);
	}
	if (!lower_nibble)	/* is this the first (upper) nibble ? */
	{
		consumed--; /* only half a nibble has been consumed, but all ie dissectors assume they consume 1 octet */
		lower_nibble = TRUE;
	}
	else	/* if it is the second (lower) nibble, move on... */
		lower_nibble = FALSE;

	return(consumed);
}


static dgt_set_t Dgt_tbcd = {
	{
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
	 '0','1','2','3','4','5','6','7','8','9','?','B','C','*','#'
	}
};

static dgt_set_t Dgt1_9_bcd = {
	{
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
	 '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?'
	}
};

/* FUNCTIONS */

/*
 * Unpack BCD input pattern into output ASCII pattern
 *
 * Input Pattern is supplied using the same format as the digits
 *
 * Returns: length of unpacked pattern
 */
int
my_dgt_tbcd_unpack(
	char	*out,		/* ASCII pattern out */
	guchar	*in,		/* packed pattern in */
	int		num_octs,	/* Number of octets to unpack */
	dgt_set_t	*dgt		/* Digit definitions */
	)
{
	int cnt = 0;
	unsigned char i;

	while (num_octs)
	{
		/*
		 * unpack first value in byte
		 */
		i = *in++;
		*out++ = dgt->out[i & 0x0f];
		cnt++;

		/*
		 * unpack second value in byte
		 */
		i >>= 4;

		if (i == 0x0f)	/* odd number bytes - hit filler */
			break;

		*out++ = dgt->out[i];
		cnt++;
		num_octs--;
	}

	*out = '\0';

	return(cnt);
}

/*
 * Decode the MCC/MNC from 3 octets in 'octs'
 */
static void
mcc_mnc_aux(guint8 *octs, gchar *mcc, gchar *mnc)
{
	if ((octs[0] & 0x0f) <= 9)
	{
		mcc[0] = Dgt_tbcd.out[octs[0] & 0x0f];
	}
	else
	{
		mcc[0] = (octs[0] & 0x0f) + 55;
	}

	if (((octs[0] & 0xf0) >> 4) <= 9)
	{
		mcc[1] = Dgt_tbcd.out[(octs[0] & 0xf0) >> 4];
	}
	else
	{
		mcc[1] = ((octs[0] & 0xf0) >> 4) + 55;
	}

	if ((octs[1] & 0x0f) <= 9)
	{
		mcc[2] = Dgt_tbcd.out[octs[1] & 0x0f];
	}
	else
	{
		mcc[2] = (octs[1] & 0x0f) + 55;
	}

	mcc[3] = '\0';

	if (((octs[1] & 0xf0) >> 4) <= 9)
	{
		mnc[2] = Dgt_tbcd.out[(octs[1] & 0xf0) >> 4];
	}
	else
	{
		mnc[2] = ((octs[1] & 0xf0) >> 4) + 55;
	}

	if ((octs[2] & 0x0f) <= 9)
	{
		mnc[0] = Dgt_tbcd.out[octs[2] & 0x0f];
	}
	else
	{
		mnc[0] = (octs[2] & 0x0f) + 55;
	}

	if (((octs[2] & 0xf0) >> 4) <= 9)
	{
		mnc[1] = Dgt_tbcd.out[(octs[2] & 0xf0) >> 4];
	}
	else
	{
		mnc[1] = ((octs[2] & 0xf0) >> 4) + 55;
	}

	if (mnc[1] == 'F')
	{
		/*
		 * only a 1 digit MNC (very old)
		 */
		mnc[1] = '\0';
	}
	else if (mnc[2] == 'F')
	{
		/*
		 * only a 2 digit MNC
		 */
		mnc[2] = '\0';
	}
	else
	{
		mnc[3] = '\0';
	}
}

/* 3GPP TS 24.008
 * [3] 10.5.1.1 Cell Identity
 */
guint16
de_cell_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint32	curr_offset;

	curr_offset = offset;

	curr_offset +=
	/* 0x02 CI */
	be_cell_id_aux(tvb, tree, offset, len, add_string, string_len, 0x02);

	/* no length check possible */

	return(curr_offset - offset);
}
/*
 * 10.5.1.2 Ciphering Key Sequence Number
 */


/*
 * Key sequence (octet 1)
 * Bits
 * 3 2 1
 * 0 0 0 
 * through 
 * 1 1 0 
 * Possible values for the ciphering key sequence number
 * 1 1 1 No key is available (MS to network);Reserved (network to MS)
 */

static const value_string gsm_a_key_seq_vals[] = {
	{ 0,		"Cipering key sequence number"},
	{ 1,		"Cipering key sequence number"},
	{ 2,		"Cipering key sequence number"},
	{ 3,		"Cipering key sequence number"},
	{ 4,		"Cipering key sequence number"},
	{ 5,		"Cipering key sequence number"},
	{ 6,		"Cipering key sequence number"},
	{ 7,		"No key is available (MS to network)"},
	{ 0,	NULL }
};

guint16
de_ciph_key_seq_num( tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_key_seq, tvb, curr_offset, 1, FALSE);
	curr_offset++;

	return(curr_offset - offset);
}


/*
 * [3] 10.5.1.3
 */

guint16
de_lai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	octs[3];
	guint16	value;
	guint32	curr_offset;
	proto_tree	*subtree;
	proto_item	*item;
	gchar	mcc[4];
	gchar	mnc[4];

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 5, "%s",
			gsm_common_elem_strings[DE_LAI].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_LAI]);

	octs[0] = tvb_get_guint8(tvb, curr_offset);
	octs[1] = tvb_get_guint8(tvb, curr_offset + 1);
	octs[2] = tvb_get_guint8(tvb, curr_offset + 2);

	mcc_mnc_aux(octs, mcc, mnc);


	proto_tree_add_text(subtree,
		tvb, curr_offset, 3,
		"Mobile Country Code (MCC): %s, Mobile Network Code (MNC): %s",
		mcc,
		mnc);

	curr_offset += 3;

	value = tvb_get_ntohs(tvb, curr_offset);

	proto_tree_add_text(subtree,
		tvb, curr_offset, 2,
		"Location Area Code (LAC): 0x%04x (%u)",
		value,
		value);

	proto_item_append_text(item, " - LAC (0x%04x)", value);

	curr_offset += 2;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.1.4 Mobile Identity
 * 3GPP TS 24.008 version 7.8.0 Release 7
 */
static const true_false_string gsm_a_present_vals = {
	"Present" ,
	"Not present"
};

guint16
de_mid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	oct;
	guint32	curr_offset;
	guint8	*poctets;
	guint32	value;
	gboolean	odd;

	curr_offset = offset;
	odd = FALSE;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct & 0x07)
	{
	case 0:	/* No Identity */
		other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"%s :  Unused",
			a_bigbuf);

		proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);

		proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);

		if (add_string)
			g_snprintf(add_string, string_len, " - No Identity Code");

		curr_offset++;

		if (len > 1)
		{
			proto_tree_add_text(tree, tvb, curr_offset, len - 1,
				"Format not supported");
		}

		curr_offset += len - 1;
		break;

	case 3:	/* IMEISV */
		/* FALLTHRU */

	case 1:	/* IMSI */
		other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"%s :  Identity Digit 1: %c",
			a_bigbuf,
			Dgt1_9_bcd.out[(oct & 0xf0) >> 4]);

		odd = oct & 0x08;

		proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);

		proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);

		a_bigbuf[0] = Dgt1_9_bcd.out[(oct & 0xf0) >> 4];
		curr_offset++;

		poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

		my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
			&Dgt1_9_bcd);

		proto_tree_add_string_format(tree,
			((oct & 0x07) == 3) ? hf_gsm_a_imeisv : hf_gsm_a_imsi,
			tvb, curr_offset, len - (curr_offset - offset),
			a_bigbuf,
			"BCD Digits: %s",
			a_bigbuf);

		if (sccp_assoc && ! sccp_assoc->calling_party) {
			sccp_assoc->calling_party = se_strdup_printf(
				((oct & 0x07) == 3) ? "IMEISV: %s" : "IMSI: %s",
				a_bigbuf );
		}

		if (add_string)
			g_snprintf(add_string, string_len, " - %s (%s)",
				((oct & 0x07) == 3) ? "IMEISV" : "IMSI",
				a_bigbuf);

		curr_offset += len - (curr_offset - offset);

		if (!odd)
		{
			oct = tvb_get_guint8(tvb, curr_offset - 1);

			other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
			proto_tree_add_text(tree,
				tvb, curr_offset - 1, 1,
				"%s :  Filler",
				a_bigbuf);
		}
		break;

	case 2:	/* IMEI */
		other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"%s :  Identity Digit 1: %c",
			a_bigbuf,
			Dgt1_9_bcd.out[(oct & 0xf0) >> 4]);

		proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);

		proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);

		a_bigbuf[0] = Dgt1_9_bcd.out[(oct & 0xf0) >> 4];
		curr_offset++;

		poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

		my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
			&Dgt1_9_bcd);

		proto_tree_add_string_format(tree,
			hf_gsm_a_imei,
			tvb, curr_offset, len - (curr_offset - offset),
			a_bigbuf,
			"BCD Digits: %s",
			a_bigbuf);

		if (add_string)
			g_snprintf(add_string, string_len, " - IMEI (%s)", a_bigbuf);

		curr_offset += len - (curr_offset - offset);
		break;

	case 4:	/* TMSI/P-TMSI */
		other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"%s :  Unused",
			a_bigbuf);

		proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);

		proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);

		curr_offset++;

		value = tvb_get_ntohl(tvb, curr_offset);

		proto_tree_add_uint(tree, hf_gsm_a_tmsi,
			tvb, curr_offset, 4,
			value);

		if (add_string)
			g_snprintf(add_string, string_len, " - TMSI/P-TMSI (0x%04x)", value);

		curr_offset += 4;
		break;

	case 5: /* TMGI and optional MBMS Session Identity */
		/* MBMS Session Identity indication (octet 3) Bit 6 */
		proto_tree_add_item(tree, hf_gsm_a_mbs_ses_id_ind, tvb, offset, 1, FALSE);
		/* MCC/MNC indication (octet 3) Bit 5 */
		proto_tree_add_item(tree, hf_gsm_a_tmgi_mcc_mnc_ind, tvb, offset, 1, FALSE);
		/* Odd/even indication (octet 3) Bit 4 */
		proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);
		curr_offset++;
		/* MBMS Service ID (octet 4, 5 and 6) */
		proto_tree_add_item(tree, hf_gsm_a_mbs_service_id, tvb, offset, 1, FALSE);
		curr_offset += 3;
		if((oct&0x10)==0x10){
			/* MCC/MNC*/
			/* MCC, Mobile country code (octet 6a, octet 6b bits 1 to 4)*/
			/* MNC, Mobile network code (octet 6b bits 5 to 8, octet 6c) */
			curr_offset += 3;
		}
		if((oct&0x20)==0x20){
			/* MBMS Session Identity (octet 7)
			 * The MBMS Session Identity field is encoded as the value part
			 * of the MBMS Session Identity IE as specified in 3GPP TS 48.018 [86].
			 */
			curr_offset++;
		}
		break;

	default:	/* Reserved */
		proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);
		proto_tree_add_text(tree, tvb, curr_offset, len,
			"Mobile station identity Format %u, Format Unknown",(oct & 0x07));

		if (add_string)
			g_snprintf(add_string, string_len, " - Format Unknown");

		curr_offset += len;
		break;
	}

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.1.5
 */
guint16
de_ms_cm_1(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	proto_tree	*subtree;
	proto_item	*item;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	item =
	proto_tree_add_text(tree,
		tvb, curr_offset, 1, "%s",
		gsm_common_elem_strings[DE_MS_CM_1].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_MS_CM_1]);

	proto_tree_add_item(subtree, hf_gsm_a_b8spare, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(subtree, hf_gsm_a_MSC_rev, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(subtree, hf_gsm_a_ES_IND, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(subtree, hf_gsm_a_A5_1_algorithm_sup, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(subtree, hf_gsm_a_RF_power_capability, tvb, curr_offset, 1, FALSE);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.1.6 Mobile Station Classmark 2 
 * 3GPP TS 24.008 version 7.8.0 Release 7
 */
guint16
de_ms_cm_2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_b8spare, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_MSC_rev, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_ES_IND, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_A5_1_algorithm_sup, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_RF_power_capability, tvb, curr_offset, 1, FALSE);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	proto_tree_add_item(tree, hf_gsm_a_b8spare, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_ps_sup_cap, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_SS_screening_indicator, tvb, curr_offset, 1, FALSE);

	/* SM capability (MT SMS pt to pt capability) (octet 4)*/
	proto_tree_add_item(tree, hf_gsm_a_SM_capability, tvb, curr_offset, 1, FALSE);
	/* VBS notification reception (octet 4) */
	proto_tree_add_item(tree, hf_gsm_a_VBS_notification_rec, tvb, curr_offset, 1, FALSE);
	/*VGCS notification reception (octet 4)*/
	proto_tree_add_item(tree, hf_gsm_a_VGCS_notification_rec, tvb, curr_offset, 1, FALSE);
	/* FC Frequency Capability (octet 4 ) */
	proto_tree_add_item(tree, hf_gsm_a_FC_frequency_cap, tvb, curr_offset, 1, FALSE);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	/* CM3 (octet 5, bit 8) */
	proto_tree_add_item(tree, hf_gsm_a_CM3, tvb, curr_offset, 1, FALSE);
	/* spare bit 7 */
	proto_tree_add_item(tree, hf_gsm_a_b7spare, tvb, curr_offset, 1, FALSE);
	/* LCS VA capability (LCS value added location request notification capability) (octet 5,bit 6) */
	proto_tree_add_item(tree, hf_gsm_a_LCS_VA_cap, tvb, curr_offset, 1, FALSE);
	/* UCS2 treatment (octet 5, bit 5) */
	proto_tree_add_item(tree, hf_gsm_a_UCS2_treatment, tvb, curr_offset, 1, FALSE);
	/* SoLSA (octet 5, bit 4) */
	proto_tree_add_item(tree, hf_gsm_a_SoLSA, tvb, curr_offset, 1, FALSE);
	/* CMSP: CM Service Prompt (octet 5, bit 3) */
	proto_tree_add_item(tree, hf_gsm_a_CMSP, tvb, curr_offset, 1, FALSE);
	/* A5/3 algorithm supported (octet 5, bit 2) */
	proto_tree_add_item(tree, hf_gsm_a_A5_3_algorithm_sup, tvb, curr_offset, 1, FALSE);
	/* A5/2 algorithm supported (octet 5, bit 1) */
	proto_tree_add_item(tree, hf_gsm_a_A5_2_algorithm_sup, tvb, curr_offset, 1, FALSE);

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.1.7 Mobile Station Classmark 3
 * 3GPP TS 24.008 version 7.8.0 Release 7
 */
guint16
de_ms_cm_3(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32 bit_offset; /* Offset in bits */
	proto_tree	*subtree;
	proto_item	*item;
	guint64 multi_bnd_sup_fields, rsupport, multislotCapability, msMeasurementCapability; 

	curr_offset = offset;

	bit_offset = curr_offset << 3;

	/* Spare bit */
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, FALSE);
    bit_offset++;

    /* Multiband supported field 
	 * { < Multiband supported : { 000 } >
	 * < A5 bits >
	 * | < Multiband supported : { 101 | 110 } >
	 * < A5 bits >
	 * < Associated Radio Capability 2 : bit(4) >
	 * < Associated Radio Capability 1 : bit(4) >
	 * | < Multiband supported : { 001 | 010 | 100 } >
	 * < A5 bits >
	 * < spare bit >(4)
	 * < Associated Radio Capability 1 : bit(4) > }
	 */
	
	item = proto_tree_add_bits_ret_val(tree, hf_gsm_a_multi_bnd_sup_fields, tvb, bit_offset, 3, &multi_bnd_sup_fields, FALSE);
	subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_MS_CM_3]);

    proto_tree_add_bits_item(subtree, hf_gsm_a_gsm1800_supported, tvb, bit_offset, 1, FALSE);
    bit_offset++;

    proto_tree_add_bits_item(subtree, hf_gsm_a_egsm_supported, tvb, bit_offset, 1, FALSE);
    bit_offset++;

    proto_tree_add_bits_item(subtree, hf_gsm_a_pgsm_supported, tvb, bit_offset, 1, FALSE);
    bit_offset++;

	/* < A5 bits > */
    proto_tree_add_bits_item(tree, hf_gsm_a_A5_7_algorithm_sup, tvb, bit_offset, 1, FALSE);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_gsm_a_A5_6_algorithm_sup, tvb, bit_offset, 1, FALSE);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_gsm_a_A5_5_algorithm_sup, tvb, bit_offset, 1, FALSE);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_gsm_a_A5_4_algorithm_sup, tvb, bit_offset, 1, FALSE);
    bit_offset++;

	switch(multi_bnd_sup_fields){
		case 0:
			/* A5 bits dissected is done */
			break;
		/*
		 * | < Multiband supported : { 001 | 010 | 100 } >
		 */
		case 1:
		case 2:
		case 4:
			/* < spare bit >(4) */
			proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 4, FALSE);
			bit_offset+=4;
			/* < Associated Radio Capability 1 : bit(4) > */
			proto_tree_add_bits_item(tree, hf_gsm_a_ass_radio_cap1, tvb, bit_offset, 4, FALSE);
			bit_offset+=4;
			break;
		/* < Multiband supported : { 101 | 110 } > */
		case 5:
			/* fall trough */
		case 6:
			/* < Associated Radio Capability 2 : bit(4) > */
			proto_tree_add_bits_item(tree, hf_gsm_a_ass_radio_cap2, tvb, bit_offset, 4, FALSE);
			bit_offset+=4;
			/* < Associated Radio Capability 1 : bit(4) > */
			proto_tree_add_bits_item(subtree, hf_gsm_a_ass_radio_cap1, tvb, bit_offset, 4, FALSE);
			bit_offset+=4;
			break;
		default:
			break;
	}
    /* Extract R Support */
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_rsupport, tvb, bit_offset, 1, &rsupport, FALSE);
    bit_offset++;

    if(rsupport == 1)
    {
        /* 
		 * { 0 | 1 < R Support > }
		 * Extract R Capabilities 
		 */
        proto_tree_add_bits_item(tree, hf_gsm_a_r_capabilities, tvb, bit_offset, 3, FALSE);
        bit_offset = bit_offset + 3;
    }

    /* 
	 * { 0 | 1 < HSCSD Multi Slot Capability > }
	 * Extract Multislot capability
	 */
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_multislot_capabilities, tvb, bit_offset, 1, &multislotCapability, FALSE);
    bit_offset++;

    if(multislotCapability == 1)
    {
        /* Extract Multislot Class */
        proto_tree_add_bits_item(tree, hf_gsm_a_multislot_class, tvb, bit_offset, 5, FALSE);
        bit_offset = bit_offset + 5;
    }

    /* < UCS2 treatment: bit > */
    proto_tree_add_bits_item(tree, hf_gsm_a_ucs2_treatment, tvb, bit_offset, 1, FALSE);
    bit_offset = bit_offset + 1;

    /* < Extended Measurement Capability : bit > */
    proto_tree_add_bits_item(tree, hf_gsm_a_extended_measurement_cap, tvb, bit_offset, 1, FALSE);
    bit_offset = bit_offset + 1;

    /* { 0 | 1 < MS measurement capability > } 
	 * Extract MS Measurement capability
	 */
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_ms_measurement_capability, tvb, bit_offset, 1, &msMeasurementCapability, FALSE);
    bit_offset = bit_offset + 1;

    if(msMeasurementCapability == 1)
    {
        /* Extract SMS Value n/4 */
        proto_tree_add_bits_item(tree, hf_gsm_a_sms_value, tvb, bit_offset, 4, FALSE);
        bit_offset = bit_offset + 4;

        /* Extract SM Value n/4 */
        proto_tree_add_bits_item(tree, hf_gsm_a_sm_value, tvb, bit_offset, 4, FALSE);
        bit_offset = bit_offset + 4;
    }

/*
{ 0 | 1 < MS Positioning Method Capability > }
{ 0 | 1 < ECSD Multi Slot Capability > }
{ 0 | 1 < 8-PSK Struct > }
{ 0 | 1 < GSM 400 Bands Supported : { 01 | 10 | 11 } >
< GSM 400 Associated Radio Capability: bit(4) > }
{ 0 | 1 <GSM 850 Associated Radio Capability : bit(4) > }
{ 0 | 1 <GSM 1900 Associated Radio Capability : bit(4) > }
< UMTS FDD Radio Access Technology Capability : bit >
< UMTS 3.84 Mcps TDD Radio Access Technology Capability : bit >
< CDMA 2000 Radio Access Technology Capability : bit >
{ 0 | 1 < DTM GPRS Multi Slot Class : bit(2) >
< Single Slot DTM : bit >
{0 | 1< DTM EGPRS Multi Slot Class : bit(2) > } }
{ 0 | 1 < Single Band Support > } -- Release 4 starts here:
{ 0 | 1 <GSM 750 Associated Radio Capability : bit(4)>}
< UMTS 1.28 Mcps TDD Radio Access Technology Capability : bit >
< GERAN Feature Package 1 : bit >
{ 0 | 1 < Extended DTM GPRS Multi Slot Class : bit(2) >
< Extended DTM EGPRS Multi Slot Class : bit(2) > }
{ 0 | 1 < High Multislot Capability : bit(2) > } ---Release 5 starts here.
{ 0 | 1 < GERAN Iu Mode Capabilities > } -- "1" also means support of GERAN Iu mode
< GERAN Feature Package 2 : bit >
< GMSK Multislot Power Profile : bit (2) >
< 8-PSK Multislot Power Profile : bit (2) >
{ 0 | 1 < T-GSM 400 Bands Supported : { 01 | 10 | 11 } > -- Release 6 starts here.
< T-GSM 400 Associated Radio Capability: bit(4) > }
{ 0 | 1 < T-GSM 900 Associated Radio Capability: bit(4) > }
< Downlink Advanced Receiver Performance : bit (2)>
< DTM Enhancements Capability : bit >
{ 0 | 1 < DTM GPRS High Multi Slot Class : bit(3) >
< Offset required : bit>
{ 0 | 1 < DTM EGPRS High Multi Slot Class : bit(3) > } }
< Repeated ACCH Capability : bit >
{ 0 | 1 <GSM 710 Associated Radio Capability : bit(4)>} -- Release 7 starts here.
{ 0 | 1 <T-GSM 810 Associated Radio Capability : bit(4)>}
< Ciphering Mode Setting Capability : bit >
0 | 1 < Multislot Capability Reduction for Downlink Dual Carrier : bit (3) > } -- "1" also means that
the mobile station supports dual carrier in the downlink during DTM
< spare bits > ;
*/
	/* translate to byte offset */
	curr_offset = (bit_offset+7)>>3;
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(len);
}
/*
 * [3] 10.5.1.8
 */
static guint16
de_spare_nibble(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Spare Nibble");

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.1.9 Descriptive group or broadcast call reference
 */
guint16
de_d_gb_call_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	value;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	value = tvb_get_ntohl(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, value, 0xffffffe0, 32);
	proto_tree_add_text(tree, tvb, curr_offset, 4,
		"%s :  Group or Broadcast call reference: %u (0x%04x)",
		a_bigbuf,
		(value & 0xffffffe0) >> 5,
		(value & 0xffffffe0) >> 5);

	other_decode_bitfield_value(a_bigbuf, value, 0x00000010, 32);
	proto_tree_add_text(tree, tvb, curr_offset, 4,
		"%s :  SF Service Flag: %s",
		a_bigbuf,
		(value & 0x00000010) ?
		"VGCS (Group call reference)" : "VBS (Broadcast call reference)");

	other_decode_bitfield_value(a_bigbuf, value, 0x00000008, 32);
	proto_tree_add_text(tree, tvb, curr_offset, 4,
		"%s :  AF Acknowledgement Flag: acknowledgment is %srequired",
		a_bigbuf,
		(value & 0x00000008) ? "" : "not ");

	switch (value & 0x00000007)
	{
	case 1: str = "call priority level 4"; break;
	case 2: str = "call priority level 3"; break;
	case 3: str = "call priority level 2"; break;
	case 4: str = "call priority level 1"; break;
	case 5: str = "call priority level 0"; break;
	case 6: str = "call priority level B"; break;
	case 7: str = "call priority level A"; break;
	default:
	str = "no priority applied";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, value, 0x00000007, 32);
	proto_tree_add_text(tree, tvb, curr_offset, 4,
		"%s :  Call Priority: %s",
		a_bigbuf,
		str);

	curr_offset += 4;

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree, tvb, curr_offset, 1,
		"%s :  Ciphering Information",
		a_bigbuf);

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 4, FALSE);
	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.1.10a PD and SAPI $(CCBS)$
 */
static guint16
de_pd_sapi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	item =
	proto_tree_add_text(tree,
		tvb, curr_offset, 1, "%s",
		gsm_dtap_elem_strings[DE_PD_SAPI].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_PD_SAPI]);

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 2, FALSE);

	switch ((oct & 0x30) >> 4)
	{
	case 0: str = "SAPI 0"; break;
	case 3: str = "SAPI 3"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x30, 8);
	proto_tree_add_text(subtree, tvb, curr_offset, 1,
		"%s :  SAPI (Service Access Point Identifier): %s",
		a_bigbuf,
		str);

	proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, curr_offset, 1, FALSE);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.1.11 Priority Level
 */
static const value_string gsm_a_call_prio_vals[] = {
	{ 0x00,	"no priority applied" },
	{ 0x01,	"call priority level 4" },
	{ 0x02,	"call priority level 3" },
	{ 0x03,	"call priority level 2" },
	{ 0x04,	"call priority level 1" },
	{ 0x05,	"call priority level 0" },
	{ 0x06,	"call priority level B" },
	{ 0x07,	"call priority level A" },
	{ 0,			NULL }
};

static guint16
de_prio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_b8spare, tvb, curr_offset, 1, FALSE);
	proto_tree_add_bits_item(tree, hf_gsm_a_call_prio, tvb, (curr_offset<<3)+5, 3, FALSE);
	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.1.13 PLMN list
 */
guint16
de_plmn_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	octs[3];
	guint32	curr_offset;
	gchar	mcc[4];
	gchar	mnc[4];
	guint8	num_plmn;

	curr_offset = offset;

	num_plmn = 0;
	while ((len - (curr_offset - offset)) >= 3)
	{
	octs[0] = tvb_get_guint8(tvb, curr_offset);
	octs[1] = tvb_get_guint8(tvb, curr_offset + 1);
	octs[2] = tvb_get_guint8(tvb, curr_offset + 2);

	mcc_mnc_aux(octs, mcc, mnc);

	proto_tree_add_text(tree,
		tvb, curr_offset, 3,
		"PLMN[%u]  Mobile Country Code (MCC): %s, Mobile Network Code (MNC): %s",
		num_plmn + 1,
		mcc,
		mnc);

	curr_offset += 3;

	num_plmn++;
	}

	if (add_string)
	g_snprintf(add_string, string_len, " - %u PLMN%s",
		num_plmn, plurality(num_plmn, "", "s"));

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

guint16 (*common_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* Common Information Elements 10.5.1 */
	de_cell_id,			/* Cell Identity */
	de_ciph_key_seq_num,/* Ciphering Key Sequence Number */
	de_lai,				/* Location Area Identification */
	de_mid,				/* Mobile Identity */
	de_ms_cm_1,			/* Mobile Station Classmark 1 */
	de_ms_cm_2,			/* Mobile Station Classmark 2 */
	de_ms_cm_3,			/* Mobile Station Classmark 3 */
	de_spare_nibble,	/* Spare Half Octet */
	de_d_gb_call_ref,	/* Descriptive group or broadcast call reference */
	NULL				/* handled inline */,	/* Group Cipher Key Number */
	de_pd_sapi,			/* PD and SAPI $(CCBS)$ */
	/* Pos 10 */
	de_prio				/* handled inline */,	/* Priority Level */
	de_plmn_list,		/* PLMN List */
	NULL,				/* NONE */
};

/* Register the protocol with Wireshark */
void
proto_register_gsm_a_common(void)
{
	guint	i;
	guint	last_offset;

	/* Setup list of header fields */
	static hf_register_info hf[] =
	{
	{ &hf_gsm_a_common_elem_id,
		{ "Element ID",	"gsm_a_common.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_imsi,
		{ "IMSI",	"gsm_a.imsi",
		FT_STRING, BASE_NONE, 0, 0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tmsi,
		{ "TMSI/P-TMSI",	"gsm_a.tmsi",
		FT_UINT32, BASE_HEX, 0, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_imei,
		{ "IMEI",	"gsm_a.imei",
		FT_STRING, BASE_NONE, 0, 0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_imeisv,
		{ "IMEISV",	"gsm_a.imeisv",
		FT_STRING, BASE_NONE, 0, 0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_MSC_rev,
		{ "Revision Level","gsm_a.MSC2_rev",
		FT_UINT8,BASE_DEC, VALS(gsm_a_msc_rev_vals), 0x60,
		NULL, HFILL }
	},
	{ &hf_gsm_a_ES_IND,
		{ "ES IND","gsm_a.MSC2_rev",
		FT_UINT8,BASE_DEC, VALS(ES_IND_vals), 0x10,
			NULL, HFILL }
	},
	{ &hf_gsm_a_A5_1_algorithm_sup,
		{ "A5/1 algorithm supported","gsm_a.MSC2_rev",
		FT_UINT8,BASE_DEC, VALS(A5_1_algorithm_sup_vals), 0x08,
		NULL, HFILL }
	},
	{ &hf_gsm_a_RF_power_capability,
		{ "RF Power Capability","gsm_a.MSC2_rev",
		FT_UINT8,BASE_DEC, VALS(RF_power_capability_vals), 0x07,
		NULL, HFILL }
	},
	{ &hf_gsm_a_ps_sup_cap,
		{ "PS capability (pseudo-synchronization capability)","gsm_a.ps_sup_cap",
		FT_UINT8,BASE_DEC, VALS(ps_sup_cap_vals), 0x40,
		NULL, HFILL }
	},
	{ &hf_gsm_a_SS_screening_indicator,
		{ "SS Screening Indicator","gsm_a.SS_screening_indicator",
		FT_UINT8,BASE_DEC, VALS(SS_screening_indicator_vals), 0x30,
		NULL, HFILL }
	},
	{ &hf_gsm_a_SM_capability,
		{ "SM capability (MT SMS pt to pt capability)","gsm_a.SM_cap",
		FT_UINT8,BASE_DEC, VALS(SM_capability_vals), 0x08,
		NULL, HFILL }
	},
	{ &hf_gsm_a_VBS_notification_rec,
		{ "VBS notification reception","gsm_a.VBS_notification_rec",
		FT_UINT8,BASE_DEC, VALS(VBS_notification_rec_vals), 0x04,
		NULL, HFILL }
	},
	{ &hf_gsm_a_VGCS_notification_rec,
		{ "VGCS notification reception","gsm_a.VGCS_notification_rec",
		FT_UINT8,BASE_DEC, VALS(VGCS_notification_rec_vals), 0x02,
		NULL, HFILL }
	},
	{ &hf_gsm_a_FC_frequency_cap,
		{ "FC Frequency Capability","gsm_a.FC_frequency_cap",
		FT_UINT8,BASE_DEC, VALS(FC_frequency_cap_vals), 0x01,
		NULL, HFILL }
	},
	{ &hf_gsm_a_CM3,
		{ "CM3","gsm_a.CM3",
		FT_UINT8,BASE_DEC, VALS(CM3_vals), 0x80,
		NULL, HFILL }
	},
	{ &hf_gsm_a_LCS_VA_cap,
		{ "LCS VA capability (LCS value added location request notification capability)","gsm_a.LCS_VA_cap",
		FT_UINT8,BASE_DEC, VALS(LCS_VA_cap_vals), 0x20,
		NULL, HFILL }
	},
	{ &hf_gsm_a_UCS2_treatment,
		{ "UCS2 treatment","gsm_a.UCS2_treatment",
		FT_UINT8,BASE_DEC, VALS(UCS2_treatment_vals), 0x10,
		NULL, HFILL }
	},
	{ &hf_gsm_a_SoLSA,
		{ "SoLSA","gsm_a.SoLSA",
		FT_UINT8,BASE_DEC, VALS(SoLSA_vals), 0x08,
		NULL, HFILL }
	},
	{ &hf_gsm_a_CMSP,
		{ "CMSP: CM Service Prompt","gsm_a.CMSP",
		FT_UINT8,BASE_DEC, VALS(CMSP_vals), 0x04,
		NULL, HFILL }
	},
	{ &hf_gsm_a_A5_7_algorithm_sup,
		{ "A5/7 algorithm supported","gsm_a.A5_7_algorithm_sup",
		FT_UINT8,BASE_DEC, VALS(A5_7_algorithm_sup_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_A5_6_algorithm_sup,
		{ "A5/6 algorithm supported","gsm_a.A5_6_algorithm_sup",
		FT_UINT8,BASE_DEC, VALS(A5_6_algorithm_sup_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_A5_5_algorithm_sup,
		{ "A5/5 algorithm supported","gsm_a.A5_5_algorithm_sup",
		FT_UINT8,BASE_DEC, VALS(A5_5_algorithm_sup_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_A5_4_algorithm_sup,
		{ "A5/4 algorithm supported","gsm_a.A5_4_algorithm_sup",
		FT_UINT8,BASE_DEC, VALS(A5_4_algorithm_sup_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_A5_3_algorithm_sup,
		{ "A5/3 algorithm supported","gsm_a.A5_3_algorithm_sup",
		FT_UINT8,BASE_DEC, VALS(A5_3_algorithm_sup_vals), 0x02,
		NULL, HFILL }
	},
	{ &hf_gsm_a_A5_2_algorithm_sup,
		{ "A5/2 algorithm supported","gsm_a.A5_2_algorithm_sup",
		FT_UINT8,BASE_DEC, VALS(A5_2_algorithm_sup_vals), 0x01,
		NULL, HFILL }
	},
	{ &hf_gsm_a_mobile_identity_type,
		{ "Mobile Identity Type","gsm_a.ie.mobileid.type",
		FT_UINT8, BASE_DEC, VALS(mobile_identity_type_vals), 0x07,
		NULL, HFILL }
	},
	{ &hf_gsm_a_odd_even_ind,
		{ "Odd/even indication","gsm_a.oddevenind",
		FT_UINT8, BASE_DEC, oddevenind_vals, 0x08,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tmgi_mcc_mnc_ind,
		{ "MCC/MNC indication", "gsm_a.tmgi_mcc_mnc_ind",
		FT_BOOLEAN, 8, TFS(&gsm_a_present_vals), 0x10,
		NULL, HFILL}
	},
	{ &hf_gsm_a_mbs_ses_id_ind,
		{ "MBMS Session Identity indication", "gsm_a.tmgi_mcc_mnc_ind",
		FT_BOOLEAN, 8, TFS(&gsm_a_present_vals), 0x20,
		NULL, HFILL}
	},
	{ &hf_gsm_a_mbs_service_id,
		{ "MBMS Service ID", "gsm_a.mbs_service_id",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_L3_protocol_discriminator,
		{ "Protocol discriminator","gsm_a.L3_protocol_discriminator",
		FT_UINT8,BASE_DEC, VALS(protocol_discriminator_vals), 0x0f,
		NULL, HFILL }
	},
	{ &hf_gsm_a_call_prio,
		{ "Call priority", "gsm_a.call_prio",
		FT_UINT8, BASE_DEC, VALS(gsm_a_call_prio_vals), 0x00,
		NULL, HFILL }
	},
	{ &hf_gsm_a_skip_ind,
		{ "Skip Indicator", "gsm_a.skip.ind",
		FT_UINT8, BASE_DEC, NULL, 0xf0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_b7spare,
		{ "Spare","gsm_a.spareb7",
		FT_UINT8,BASE_DEC, NULL, 0x40,
		NULL, HFILL }
	},
	{ &hf_gsm_a_b8spare,
		{ "Spare","gsm_a.spareb8",
		FT_UINT8,BASE_DEC, NULL, 0x80,
		NULL, HFILL }
	},
	{ &hf_gsm_a_spare_bits,
		{ "Spare bit(s)","gsm_a.spare_bits",
		FT_UINT8,BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_multi_bnd_sup_fields,
		{ "Multiband supported field","gsm_a.multi_bnd_sup_fields",
		FT_UINT8,BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_pgsm_supported,
		{ "P-GSM Supported", "gsm_a.classmark3.pgsmSupported", 
		FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_egsm_supported,
		{ "E-GSM or R-GSM Supported", "gsm_a.classmark3.egsmSupported", 
		FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_gsm1800_supported,
		{ "GSM 1800 Supported", "gsm_a.classmark3.gsm1800Supported",
		FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_ass_radio_cap1,
		{ "Associated Radio Capability 1", "gsm_a.classmark3.ass_radio_cap1",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_ass_radio_cap2,
		{ "Associated Radio Capability 2", "gsm_a.classmark3.ass_radio_cap2",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_rsupport,
		{ "R Support", "gsm_a.classmark3.rsupport",
		FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_r_capabilities,
		{ "R-GSM band Associated Radio Capability", "gsm_a.classmark3.r_capabilities",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_multislot_capabilities,
		{ "HSCSD Multi Slot Capability", "gsm_a.classmark3.multislot_capabilities",
		FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_multislot_class,
		{ "HSCSD Multi Slot Class", "gsm_a.classmark3.multislot_cap",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_ucs2_treatment,
		{ "UCS2 treatment","gsm_a.UCS2_treatment",
		FT_UINT8,BASE_DEC, VALS(UCS2_treatment_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_extended_measurement_cap,
		{ "Extended Measurement Capability", "gsm_a.classmark3.ext_meas_cap",
		FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_ms_measurement_capability,
		{ "MS measurement capability", "gsm_a.classmark3.ms_measurement_capability",
		FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_sms_value,
		{ "SMS_VALUE (Switch-Measure-Switch)", "gsm_a.classmark3.sms_value",
		FT_UINT8, BASE_DEC, VALS(gsm_a_sms_vals), 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_sm_value,
		{ "SM_VALUE (Switch-Measure)", "gsm_a.classmark3.sm_value",
		FT_UINT8, BASE_DEC, VALS(gsm_a_sms_vals), 0x0,
		NULL, HFILL}
	},
	{ &hf_gsm_a_geo_loc_type_of_shape,
		{ "Location estimate","gsm_a.gad.location_estimate",
		FT_UINT8,BASE_DEC, VALS(type_of_shape_vals), 0xf0,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_sign_of_lat,
		{ "Sign of latitude","gsm_a.gad.sign_of_latitude",
		FT_UINT8,BASE_DEC, VALS(sign_of_latitude_vals), 0x80,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_deg_of_lat,
		{ "Degrees of latitude","gsm_a.gad.sign_of_latitude",
		FT_UINT24,BASE_DEC, NULL, 0x7fffff,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_deg_of_long,
		{ "Degrees of longitude","gsm_a.gad.sign_of_longitude",
		FT_UINT24,BASE_DEC, NULL, 0xffffff,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_uncertainty_code,
		{ "Uncertainty code","gsm_a.gad.uncertainty_code",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_uncertainty_semi_major,
		{ "Uncertainty semi-major","gsm_a.gad.uncertainty_semi_major",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_uncertainty_semi_minor,
		{ "Uncertainty semi-minor","gsm_a.gad.uncertainty_semi_minor",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_orientation_of_major_axis,
		{ "Orientation of major axis","gsm_a.gad.orientation_of_major_axis",
		FT_UINT8,BASE_DEC, NULL, 0x0,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_uncertainty_altitude,
		{ "Uncertainty Altitude","gsm_a.gad.uncertainty_altitude",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_confidence,
		{ "Confidence(%)","gsm_a.gad.confidence",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_no_of_points,
		{ "Number of points","gsm_a.gad.no_of_points",
		FT_UINT8,BASE_DEC, NULL, 0x0f,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_D,
		{ "D: Direction of Altitude","gsm_a.gad.D",
		FT_UINT16,BASE_DEC, VALS(dir_of_alt_vals), 0x8000,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_altitude,
		{ "Altitude in meters","gsm_a.gad.altitude",
		FT_UINT16,BASE_DEC, NULL, 0x7fff,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_inner_radius,
		{ "Inner radius","gsm_a.gad.altitude",
		FT_UINT16,BASE_DEC, NULL, 0x0,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_uncertainty_radius,
		{ "Uncertainty radius","gsm_a.gad.no_of_points",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_offset_angle,
		{ "Offset angle","gsm_a.gad.offset_angle",
		FT_UINT8,BASE_DEC, NULL, 0x0,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_geo_loc_included_angle,
		{ "Included angle","gsm_a.gad.included_angle",
		FT_UINT8,BASE_DEC, NULL, 0x0,          
		NULL, HFILL }
	},
	{ &hf_gsm_a_key_seq,
		{ "key sequence","gsm_a.key_seq",
		FT_UINT8,BASE_DEC, VALS(gsm_a_key_seq_vals), 0x07,          
		NULL, HFILL }
	},
	};

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	0
	static gint *ett[NUM_INDIVIDUAL_ELEMS +
			NUM_GSM_COMMON_ELEM];

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_COMMON_ELEM; i++, last_offset++)
	{
		ett_gsm_common_elem[i] = -1;
		ett[last_offset] = &ett_gsm_common_elem[i];
	}

	/* Register the protocol name and description */

	proto_a_common =
	proto_register_protocol("GSM A-I/F COMMON", "GSM COMMON", "gsm_a_common");

	proto_register_field_array(proto_a_common, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	gsm_a_tap = register_tap("gsm_a");
}


void
proto_reg_handoff_gsm_a_common(void)
{
}
