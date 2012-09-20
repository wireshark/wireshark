/* packet-aprs.c
 *
 * Routines for Amateur Packet Radio protocol dissection
 * Copyright 2007,2008,2009,2010,2012 R.W. Stearn <richard@rns-stearn.demon.co.uk>
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

/*
 * This dissector is for APRS (Automatic Packet Reporting System)
 *
 * Information was drawn from:
 *    http://www.aprs.org/
 *
 * Inspiration on how to build the dissector drawn from
 *   packet-sdlc.c
 *   packet-x25.c
 *   packet-lapb.c
 *   paket-gprs-llc.c
 *   xdlc.c
 * with the base file built from README.developers.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include <glib.h>

#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/address.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/ftypes/ftypes.h>

#define AX25_ADDR_LEN		7  /* length of an AX.25 address */
#define STRLEN	100

/* Forward declaration we need below */
void proto_reg_handoff_aprs(void);

/* Dissector handles - all the possibles are listed */
static dissector_handle_t default_handle;

/* Initialize the protocol and registered fields */
static int proto_aprs			= -1;

/* aprs timestamp items */
static int hf_aprs_dhm			= -1;
static int hf_aprs_hms			= -1;
static int hf_aprs_mdhm			= -1;
static int hf_aprs_tz			= -1;

/* aprs position items */
static int hf_aprs_position		= -1;
static int hf_aprs_lat			= -1;
static int hf_aprs_long			= -1;

/* aprs msg items */
static int hf_aprs_msg			= -1;
static int hf_aprs_msg_rng		= -1;
static int hf_aprs_msg_cse		= -1;
static int hf_aprs_msg_spd		= -1;
static int hf_aprs_msg_dir		= -1;
static int hf_aprs_msg_brg		= -1;
static int hf_aprs_msg_nrq		= -1;

/* aprs compression type items */
static int hf_aprs_compression_type	= -1;
static int hf_aprs_ct_gps_fix		= -1;
static int hf_aprs_ct_nmea_src		= -1;
static int hf_aprs_ct_origin		= -1;

/* phg msg items */
static int hf_aprs_msg_phg_p		= -1;
static int hf_aprs_msg_phg_h		= -1;
static int hf_aprs_msg_phg_g		= -1;
static int hf_aprs_msg_phg_d		= -1;

/* dfs msg items */
static int hf_aprs_msg_dfs_s		= -1;
static int hf_aprs_msg_dfs_h		= -1;
static int hf_aprs_msg_dfs_g		= -1;
static int hf_aprs_msg_dfs_d		= -1;

/* weather items */
static int hf_aprs_weather_dir		= -1;
static int hf_aprs_weather_spd		= -1;
static int hf_aprs_weather_peak		= -1;
static int hf_aprs_weather_temp		= -1;
static int hf_aprs_weather_rain_1	= -1;
static int hf_aprs_weather_rain_24	= -1;
static int hf_aprs_weather_rain		= -1;
static int hf_aprs_weather_humidty	= -1;
static int hf_aprs_weather_press	= -1;
static int hf_aprs_weather_luminosity	= -1;
static int hf_aprs_weather_snow		= -1;
static int hf_aprs_weather_raw_rain	= -1;
static int hf_aprs_weather_software	= -1;
static int hf_aprs_weather_unit		= -1;

/* aod msg items */
static int hf_aprs_msg_aod_t		= -1;
static int hf_aprs_msg_aod_c		= -1;

/* mic-e msg items */
static int hf_aprs_mic_e_dst		= -1;
static int hf_aprs_mic_e_long_d		= -1;
static int hf_aprs_mic_e_long_m		= -1;
static int hf_aprs_mic_e_long_h		= -1;
static int hf_aprs_mic_e_spd_sp		= -1;
static int hf_aprs_mic_e_spd_dc		= -1;
static int hf_aprs_mic_e_spd_se		= -1;
static int hf_aprs_mic_e_telemetry	= -1;
static int hf_aprs_mic_e_status		= -1;

/* Storm items */
static int hf_aprs_storm_dir		= -1;
static int hf_aprs_storm_spd		= -1;
static int hf_aprs_storm_type		= -1;
static int hf_aprs_storm_sws		= -1;
static int hf_aprs_storm_pwg		= -1;
static int hf_aprs_storm_cp		= -1;
static int hf_aprs_storm_rhw		= -1;
static int hf_aprs_storm_rtsw		= -1;
static int hf_aprs_storm_rwg		= -1;

/* aprs sundry items */
static int hf_aprs_dti			= -1;
static int hf_aprs_sym_id		= -1;
static int hf_aprs_sym_code		= -1;
static int hf_aprs_comment		= -1;
static int hf_aprs_storm		= -1;

/* aprs main catgories items */
static int hf_ultimeter_2000		= -1;
static int hf_aprs_status		= -1;
static int hf_aprs_object		= -1;
static int hf_aprs_item			= -1;
static int hf_aprs_query		= -1;
static int hf_aprs_telemetry		= -1;
static int hf_aprs_raw			= -1;
static int hf_aprs_station		= -1;
static int hf_aprs_message		= -1;
static int hf_aprs_agrelo		= -1;
static int hf_aprs_maidenhead		= -1;
static int hf_aprs_weather		= -1;
static int hf_aprs_invalid_test		= -1;
static int hf_aprs_user_defined		= -1;
static int hf_aprs_third_party		= -1;
static int hf_aprs_mic_e_0_current	= -1;
static int hf_aprs_mic_e_0_old		= -1;
static int hf_aprs_mic_e_old		= -1;
static int hf_aprs_mic_e_current	= -1;
static int hf_aprs_peet_1		= -1;
static int hf_aprs_peet_2		= -1;
static int hf_aprs_map_feature		= -1;
static int hf_aprs_shelter_data		= -1;
static int hf_aprs_space_weather	= -1;


/* Global preferences */
static gboolean gPREF_APRS_LAX = FALSE;

/* Initialize the subtree pointers */
static gint ett_aprs		= -1;
static gint ett_aprs_msg	= -1;
static gint ett_aprs_ct		= -1;
static gint ett_aprs_weather	= -1;
static gint ett_aprs_storm	= -1;
static gint ett_aprs_mic_e	= -1;


const value_string ctype_vals[] = {
    { 0,   "Compressed" },
    { 1,   "TNC BText" },
    { 2,   "Software (DOS/Mac/Win/+SA)" },
    { 3,   "[tbd]" },
    { 4,   "KPC3" },
    { 5,   "Pico" },
    { 6,   "Other tracker [tbd]" },
    { 7,   "Digipeater conversion" },
    { 0,            NULL }
};

const value_string nmea_vals[] = {
    { 0,   "other" },
    { 1,   "GLL" },
    { 2,   "GGA" },
    { 3,   "RMC" },
    { 0,            NULL }
};

const value_string gps_vals[] = {
    { 0,   "old (last)" },
    { 1,   "current" },
    { 0,            NULL }
};

/*
 * Structure containing pointers to hf_ values for various subfields of
 * the compression type field.
 */
typedef struct {
	int	*hf_ct_gps_fix;
	int	*hf_ct_nmea_src;
	int	*hf_ct_origin;
} ct_items_s;

static const ct_items_s ct_items = {
	&hf_aprs_ct_gps_fix,
	&hf_aprs_ct_nmea_src,
	&hf_aprs_ct_origin
};

typedef struct {
	int	*hf_msg_phg_p;
	int	*hf_msg_phg_h;
	int	*hf_msg_phg_g;
	int	*hf_msg_phg_d;
	int	*hf_msg_rng;
	int	*hf_msg_dfs_p;
	int	*hf_msg_dfs_h;
	int	*hf_msg_dfs_g;
	int	*hf_msg_dfs_d;
	int	*hf_msg_aod_t;
	int	*hf_msg_aod_c;
	int	*hf_msg_cse;
	int	*hf_msg_spd;
	int	*hf_msg_dir;
	int	*hf_msg_brg;
	int	*hf_msg_nrq;
} msg_items_s;

static const msg_items_s msg_items = {
	&hf_aprs_msg_phg_p,
	&hf_aprs_msg_phg_h,
	&hf_aprs_msg_phg_g,
	&hf_aprs_msg_phg_d,
	&hf_aprs_msg_rng,
	&hf_aprs_msg_dfs_s,
	&hf_aprs_msg_dfs_h,
	&hf_aprs_msg_dfs_g,
	&hf_aprs_msg_dfs_d,
	&hf_aprs_msg_aod_t,
	&hf_aprs_msg_aod_c,
	&hf_aprs_msg_cse,
	&hf_aprs_msg_spd,
	&hf_aprs_msg_dir,
	&hf_aprs_msg_brg,
	&hf_aprs_msg_nrq
};

typedef struct {
	int	*hf_weather_dir;
	int	*hf_weather_spd;
	int	*hf_weather_peak;
	int	*hf_weather_temp;
	int	*hf_weather_rain_1;
	int	*hf_weather_rain_24;
	int	*hf_weather_rain;
	int	*hf_weather_humidty;
	int	*hf_weather_press;
	int	*hf_weather_luminosity;
	int	*hf_weather_snow;
	int	*hf_weather_raw_rain;
	int	*hf_weather_software;
	int	*hf_weather_unit;
} weather_items_s;

static const weather_items_s weather_items = {
	&hf_aprs_weather_dir,
	&hf_aprs_weather_spd,
	&hf_aprs_weather_peak,
	&hf_aprs_weather_temp,
	&hf_aprs_weather_rain_1,
	&hf_aprs_weather_rain_24,
	&hf_aprs_weather_rain,
	&hf_aprs_weather_humidty,
	&hf_aprs_weather_press,
	&hf_aprs_weather_luminosity,
	&hf_aprs_weather_snow,
	&hf_aprs_weather_raw_rain,
	&hf_aprs_weather_software,
	&hf_aprs_weather_unit
};

typedef struct {
	int	*hf_mic_e_dst;
	int	*hf_mic_e_long_d;
	int	*hf_mic_e_long_m;
	int	*hf_mic_e_long_h;
	int	*hf_mic_e_spd_sp;
	int	*hf_mic_e_spd_dc;
	int	*hf_mic_e_spd_se;
	int	*hf_mic_e_sym_id;
	int	*hf_mic_e_sym_code;
	int	*hf_mic_e_telemetry;
	int	*hf_mic_e_status;
} mic_e_items_s;

static const mic_e_items_s mic_e_items = {
	&hf_aprs_mic_e_dst,
	&hf_aprs_mic_e_long_d,
	&hf_aprs_mic_e_long_m,
	&hf_aprs_mic_e_long_h,
	&hf_aprs_mic_e_spd_sp,
	&hf_aprs_mic_e_spd_dc,
	&hf_aprs_mic_e_spd_se,
	&hf_aprs_sym_id,
	&hf_aprs_sym_code,
	&hf_aprs_mic_e_telemetry,
	&hf_aprs_mic_e_status
};

typedef struct {
	int	*hf_aprs_storm_dir;
	int	*hf_aprs_storm_spd;
	int	*hf_aprs_storm_type;
	int	*hf_aprs_storm_sws;
	int	*hf_aprs_storm_pwg;
	int	*hf_aprs_storm_cp;
	int	*hf_aprs_storm_rhw;
	int	*hf_aprs_storm_rtsw;
	int	*hf_aprs_storm_rwg;
} storm_items_s;

static const storm_items_s storm_items = {
	&hf_aprs_storm_dir,
	&hf_aprs_storm_spd,
	&hf_aprs_storm_type,
	&hf_aprs_storm_sws,
	&hf_aprs_storm_pwg,
	&hf_aprs_storm_cp,
	&hf_aprs_storm_rhw,
	&hf_aprs_storm_rtsw,
	&hf_aprs_storm_rwg
};

/* MIC-E destination field code table */
typedef struct
	{
	guint8 key;
	char digit;
	int msg;
	char n_s;
	int long_offset;
	char w_e;
	} mic_e_dst_code_table_s;

static const mic_e_dst_code_table_s dst_code[] =
	{
	{ '0' << 1, '0', 0, 'S',   0, 'E' },
	{ '1' << 1, '1', 0, 'S',   0, 'E' },
	{ '2' << 1, '2', 0, 'S',   0, 'E' },
	{ '3' << 1, '3', 0, 'S',   0, 'E' },
	{ '4' << 1, '4', 0, 'S',   0, 'E' },
	{ '5' << 1, '5', 0, 'S',   0, 'E' },
	{ '6' << 1, '6', 0, 'S',   0, 'E' },
	{ '7' << 1, '7', 0, 'S',   0, 'E' },
	{ '8' << 1, '8', 0, 'S',   0, 'E' },
	{ '9' << 1, '9', 0, 'S',   0, 'E' },
	{ 'A' << 1, '0', 1, '?',   0, '?' },
	{ 'B' << 1, '1', 1, '?',   0, '?' },
	{ 'C' << 1, '2', 1, '?',   0, '?' },
	{ 'D' << 1, '3', 1, '?',   0, '?' },
	{ 'E' << 1, '4', 1, '?',   0, '?' },
	{ 'F' << 1, '5', 1, '?',   0, '?' },
	{ 'G' << 1, '6', 1, '?',   0, '?' },
	{ 'H' << 1, '7', 1, '?',   0, '?' },
	{ 'I' << 1, '8', 1, '?',   0, '?' },
	{ 'J' << 1, '9', 1, '?',   0, '?' },
	{ 'K' << 1, ' ', 1, '?',   0, '?' },
	{ 'L' << 1, ' ', 0, 'S',   0, 'E' },
	{ 'P' << 1, '0', 1, 'N', 100, 'W' },
	{ 'Q' << 1, '1', 1, 'N', 100, 'W' },
	{ 'R' << 1, '2', 1, 'N', 100, 'W' },
	{ 'S' << 1, '3', 1, 'N', 100, 'W' },
	{ 'T' << 1, '4', 1, 'N', 100, 'W' },
	{ 'U' << 1, '5', 1, 'N', 100, 'W' },
	{ 'V' << 1, '6', 1, 'N', 100, 'W' },
	{ 'W' << 1, '7', 1, 'N', 100, 'W' },
	{ 'X' << 1, '8', 1, 'N', 100, 'W' },
	{ 'Y' << 1, '9', 1, 'N', 100, 'W' },
	{ 'Z' << 1, ' ', 1, 'N', 100, 'W' },
	{        0, '_', 3, '?',   3, '?' },
	};


/* MIC-E message table */
typedef struct
	{
	char *std;
	char *custom;
	} mic_e_msg_table_s;

static const mic_e_msg_table_s mic_e_msg_table[] =
	{
	{ "Emergency",  "Emergency" },
	{ "Priority",   "Custom 6" },
	{ "Special",    "Custom 5" },
	{ "Committed",  "Custom 4" },
	{ "Returning",  "Custom 3" },
	{ "In Service", "Custom 2" },
	{ "En Route",   "Custom 1" },
	{ "Off Duty",   "Custom 0" }
	};

/* Code to actually dissect the packets */

static int
dissect_aprs_compression_type(	tvbuff_t *tvb,
				int offset,
				proto_tree *parent_tree,
				int hf_aprs_ctype,
				gint ett_aprs_ctype,
				const ct_items_s *ct_items
				)
{
	proto_tree *tc;
	proto_tree *compression_tree;
	int new_offset;
	int data_len;
	guint8 compression_type;


	data_len = 1;
	new_offset = offset + data_len;

	if ( parent_tree )
		{
		compression_type = tvb_get_guint8( tvb, offset ) - 33;

		tc = proto_tree_add_uint( parent_tree, hf_aprs_ctype, tvb, offset, data_len,
					  compression_type );
		compression_tree = proto_item_add_subtree( tc, ett_aprs_ctype );

		proto_tree_add_item( compression_tree, *ct_items->hf_ct_gps_fix,  tvb, offset, data_len, FALSE );
		proto_tree_add_item( compression_tree, *ct_items->hf_ct_nmea_src, tvb, offset, data_len, FALSE );
		proto_tree_add_item( compression_tree, *ct_items->hf_ct_origin,   tvb, offset, data_len, FALSE );
		}

	return new_offset;
}

static int
dissect_aprs_msg(	tvbuff_t *tvb,
			int offset,
			proto_tree *parent_tree,
			int hf_aprs_msg,
			gint ett_aprs_msg,
			const msg_items_s *msg_items,
			int wind,
			int brg_nrq
			)
{
	proto_tree *tc;
	proto_tree *msg_tree;
	int new_offset;
	int data_len;
	guint8 ch;


	data_len = 7;
	new_offset = offset + data_len;

	ch = tvb_get_guint8( tvb, offset );

	if ( parent_tree )
		{
		tc = proto_tree_add_item( parent_tree, hf_aprs_msg, tvb, offset, data_len, ENC_ASCII );
		msg_tree = proto_item_add_subtree( tc, ett_aprs_msg );

		if ( isdigit( ch ) )
			{
			if ( wind )
				proto_tree_add_item( msg_tree, *msg_items->hf_msg_dir, tvb, offset, 3, FALSE );
			else
				proto_tree_add_item( msg_tree, *msg_items->hf_msg_cse, tvb, offset, 3, FALSE );
			offset += 3;
			/* verify the separator */
			offset += 1;
			proto_tree_add_item( msg_tree, *msg_items->hf_msg_spd, tvb, offset, 3, FALSE );
			offset += 3;
			}
		else
			{
			switch ( ch )
				{
				case 'D' :	/* dfs */
					offset += 3;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_dfs_p, tvb, offset, 1, FALSE );
					offset += 1;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_dfs_h, tvb, offset, 1, FALSE );
					offset += 1;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_dfs_g, tvb, offset, 1, FALSE );
					offset += 1;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_dfs_d, tvb, offset, 1, FALSE );
					break;
				case 'P' :	/* phgd */
					offset += 3;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_phg_p, tvb, offset, 1, FALSE );
					offset += 1;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_phg_h, tvb, offset, 1, FALSE );
					offset += 1;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_phg_g, tvb, offset, 1, FALSE );
					offset += 1;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_phg_d, tvb, offset, 1, FALSE );
					break;
				case 'R' :	/* rng */
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_rng, tvb, offset, data_len, FALSE );
					break;
				case 'T' :	/* aod */
					offset += 1;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_aod_t, tvb, offset, 2, FALSE );
					offset += 2;
					/* step over the /C */
					offset += 2;
					proto_tree_add_item( msg_tree, *msg_items->hf_msg_aod_c, tvb, offset, 2, FALSE );
					break;
				default  :	/* wtf */
					break;
				}
			offset = offset + data_len;
			}
		if ( brg_nrq )
			{
			proto_tree_add_item( msg_tree, *msg_items->hf_msg_brg, tvb, offset, 3, ENC_ASCII );
			offset += 3;
			/* verify the separator */
			offset += 1;
			proto_tree_add_item( msg_tree, *msg_items->hf_msg_nrq, tvb, offset, 3, ENC_ASCII );
			offset += 3;
			new_offset += 7;
			}

		}
	return new_offset;
}

static int
dissect_aprs_compressed_msg(	tvbuff_t *tvb,
				int offset,
				proto_tree *parent_tree,
				int hf_msg_type,
				gint ett_aprs_msg,
				const msg_items_s *msg_items
				)
{
	proto_tree *tc;
	proto_tree *msg_tree;
	int new_offset;
	int data_len;
	guint8 ch;
	guint8 course;
	double speed;
	double range;
	gchar *info_buffer;


	data_len = 2;
	new_offset = offset + data_len;

	if ( parent_tree )
		{
		tc = proto_tree_add_item( parent_tree, hf_msg_type, tvb, offset, data_len, ENC_ASCII );
		msg_tree = proto_item_add_subtree( tc, ett_aprs_msg );

		ch = tvb_get_guint8( tvb, offset );
		if ( ch != ' ' )
			{
			if ( ch == '{' )
				{ /* Pre-Calculated Radio Range */
				offset += 1;
				ch = tvb_get_guint8( tvb, offset );
				range = exp( log( 1.08 ) * (ch - 33) );
				info_buffer = ep_strdup_printf( "%7.2f", range );
				proto_tree_add_string( msg_tree, *msg_items->hf_msg_rng, tvb, offset, 1, info_buffer );
				}
			else
				if ( ch >= '!' && ch <= 'z' )
					{ /* Course/Speed */
					course = (ch - 33) * 4;
					info_buffer = ep_strdup_printf( "%d", course );
					proto_tree_add_string( msg_tree, *msg_items->hf_msg_cse, tvb, offset, 1, info_buffer );
					offset += 1;
					ch = tvb_get_guint8( tvb, offset );
					speed = exp( log( 1.08 ) * (ch - 33) );
					info_buffer = ep_strdup_printf( "%7.2f", speed );
					proto_tree_add_string( msg_tree, *msg_items->hf_msg_spd, tvb, offset, 1, info_buffer );
					}

			}
		}

	return new_offset;
}


static const mic_e_dst_code_table_s *
dst_code_lookup( guint8 ch )
{
	guint index;

	index = 0;
	while ( index < ( sizeof( dst_code ) / sizeof( mic_e_dst_code_table_s ) )
			&& dst_code[ index ].key != ch
			&& dst_code[ index ].key > 0 )
		index++;
	return &( dst_code[ index ] );
}

static int
d28_to_deg( guint8 code, int long_offset )
{
	int value;

	value = code - 28 + long_offset;
	if ( value >= 180 && value <= 189 )
		value -= 80;
	else
		if ( value >= 190 && value <= 199 )
			value -= 190;
	return value;
}

static int
d28_to_min( guint8 code )
{
	int value;

	value = code - 28;
	if ( value >= 60 )
		value -= 60;
	return value;
}

static int
dissect_mic_e(	tvbuff_t *tvb,
		int offset,
		packet_info *pinfo,
		proto_tree *parent_tree,
		int hf_mic_e,
		gint ett_mic_e,
		const mic_e_items_s *mic_e_items
		)
{
	proto_tree *tc;
	proto_tree *mic_e_tree;
	int new_offset;
	int data_len;
	char *info_buffer;
	char *latitude;
	int msg_a;
	int msg_b;
	int msg_c;
	char n_s;
	int long_offset;
	char w_e;
	int cse;
	int spd;
	guint8 ssid;
	const mic_e_dst_code_table_s *dst_code_entry;

	/*data_len = 8;*/
	data_len = tvb_length_remaining( tvb, offset );
	new_offset = offset + data_len;
	info_buffer = ep_alloc( STRLEN );
	latitude = ep_alloc( STRLEN );

	latitude[ 0 ] = '?';
	msg_a = 0;

	latitude[ 1 ] = '?';
	msg_b = 0;

	latitude[ 2 ] = '?';
	msg_c = 0;

	latitude[ 3 ] = '?';
	n_s = '?';

	latitude[ 4 ] = '.';

	latitude[ 5 ] = '?';
	long_offset = 0;

	latitude[ 6 ] = '?';
	w_e = '?';

	ssid = 0;

	if ( pinfo->dst.type == AT_AX25 && pinfo->dst.len == AX25_ADDR_LEN )
		{
		/* decode the AX.25 destination address */
		dst_code_entry = dst_code_lookup( ((guint8 *)pinfo->dst.data)[ 0 ] );
		latitude[ 0 ] = dst_code_entry->digit;
		msg_a = dst_code_entry->msg & 0x1;

		dst_code_entry = dst_code_lookup( ((guint8 *)pinfo->dst.data)[ 1 ] );
		latitude[ 1 ] = dst_code_entry->digit;
		msg_b = dst_code_entry->msg & 0x1;

		dst_code_entry = dst_code_lookup( ((guint8 *)pinfo->dst.data)[ 2 ] );
		latitude[ 2 ] = dst_code_entry->digit;
		msg_c = dst_code_entry->msg & 0x1;

		dst_code_entry = dst_code_lookup( ((guint8 *)pinfo->dst.data)[ 3 ] );
		latitude[ 3 ] = dst_code_entry->digit;
		n_s = dst_code_entry->n_s;

		latitude[ 4 ] = '.';

		dst_code_entry = dst_code_lookup( ((guint8 *)pinfo->dst.data)[ 4 ] );
		latitude[ 5 ] = dst_code_entry->digit;
		long_offset = dst_code_entry->long_offset;

		dst_code_entry = dst_code_lookup( ((guint8 *)pinfo->dst.data)[ 5 ] );
		latitude[ 6 ] = dst_code_entry->digit;
		w_e = dst_code_entry->w_e;

		ssid = (((guint8 *)pinfo->dst.data)[ 6 ] >> 1) & 0x0f;
		}

	/* decode the mic-e info fields */
	spd = ((tvb_get_guint8( tvb, offset + 3 ) - 28) * 10) + ((tvb_get_guint8( tvb, offset + 4 ) - 28) / 10);
	if ( spd >= 800 )
		spd -= 800;

	cse = (((tvb_get_guint8( tvb, offset + 4 ) - 28) % 10) * 100) + ((tvb_get_guint8( tvb, offset + 5 ) - 28) * 10);
	if ( cse >= 400 )
		cse -= 400;

	g_snprintf( info_buffer, STRLEN,
				"Lat: %7.7s%c Long: %03d%02d.%02d%c, Cse: %d, Spd: %d, SSID: %d, Msg %s",
				latitude,
				n_s,
				d28_to_deg( tvb_get_guint8( tvb, offset ), long_offset ),
				d28_to_min( tvb_get_guint8( tvb, offset + 1 ) ),
				tvb_get_guint8( tvb, offset + 2 ) - 28,
				w_e,
				cse,
				spd,
				ssid,
				mic_e_msg_table[ (msg_a << 2) + (msg_b << 1) + msg_c ].std
				);

	col_add_str( pinfo->cinfo, COL_INFO, "MIC-E " );
	col_append_str( pinfo->cinfo, COL_INFO, info_buffer );

	if ( parent_tree )
		{
		tc = proto_tree_add_string( parent_tree, hf_mic_e, tvb, offset, data_len, info_buffer );
		mic_e_tree = proto_item_add_subtree( tc, ett_mic_e );

		g_snprintf( info_buffer, STRLEN,
				"Lat %7.7s, Msg A %d, Msg B %d, Msg C %d, N/S %c, Long off %3d, W/E %c, SSID %d",
				latitude,
				msg_a,
				msg_b,
				msg_c,
				n_s,
				long_offset,
				w_e,
				ssid
				);

		proto_tree_add_string( mic_e_tree, *mic_e_items->hf_mic_e_dst,     tvb,      0, 0, info_buffer );

		proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_long_d,    tvb, offset, 1, FALSE );
		offset += 1;

		proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_long_m,    tvb, offset, 1, FALSE );
		offset += 1;

		proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_long_h,    tvb, offset, 1, FALSE );
		offset += 1;

		proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_spd_sp,    tvb, offset, 1, FALSE );
		offset += 1;

		proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_spd_dc,    tvb, offset, 1, FALSE );
		offset += 1;

		proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_spd_se,    tvb, offset, 1, FALSE );
		offset += 1;

		proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_sym_code,  tvb, offset, 1, FALSE );
		offset += 1;

		proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_sym_id,    tvb, offset, 1, FALSE );
		offset += 1;

		if ( offset < new_offset )
			{
			if (	tvb_get_guint8( tvb, offset ) == ','
				|| tvb_get_guint8( tvb, offset ) == 0x1d )
				proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_telemetry, tvb, offset, tvb_length_remaining( tvb, offset ), FALSE );
			else
				proto_tree_add_item( mic_e_tree, *mic_e_items->hf_mic_e_status,    tvb, offset, tvb_length_remaining( tvb, offset ), FALSE );
			}

		}

	return new_offset;
}

static int
dissect_aprs_storm(	tvbuff_t *tvb,
			int offset,
			proto_tree *parent_tree,
			int hf_aprs_storm,
			gint ett_aprs_storm,
			const storm_items_s *storm_items
			)
{
	proto_tree *tc;
	proto_tree *storm_tree;
	int new_offset;
	int data_len;
	char *info_buffer;
	char *storm_format = " (%*.*s)";


	data_len = tvb_length_remaining( tvb, offset );
	new_offset = offset + data_len;
	info_buffer = ep_alloc( STRLEN );

	g_snprintf( info_buffer, STRLEN, storm_format, data_len, data_len, tvb_get_ptr( tvb, offset, data_len ) );

	if ( parent_tree )
		{
		tc = proto_tree_add_string( parent_tree, hf_aprs_storm, tvb, offset, data_len, info_buffer );
		storm_tree = proto_item_add_subtree( tc, ett_aprs_storm );

		proto_tree_add_item( storm_tree, *storm_items->hf_aprs_storm_dir,  tvb, offset, 3, FALSE );
		offset += 3;
		offset += 1;
		proto_tree_add_item( storm_tree, *storm_items->hf_aprs_storm_spd,  tvb, offset, 3, FALSE );
		offset += 3;
		proto_tree_add_item( storm_tree, *storm_items->hf_aprs_storm_type, tvb, offset, 3, FALSE );
		offset += 3;
		proto_tree_add_item( storm_tree, *storm_items->hf_aprs_storm_sws,  tvb, offset, 4, FALSE );
		offset += 4;
		proto_tree_add_item( storm_tree, *storm_items->hf_aprs_storm_pwg,  tvb, offset, 4, FALSE );
		offset += 4;
		proto_tree_add_item( storm_tree, *storm_items->hf_aprs_storm_cp,   tvb, offset, 5, FALSE );
		offset += 5;
		proto_tree_add_item( storm_tree, *storm_items->hf_aprs_storm_rhw,  tvb, offset, 4, FALSE );
		offset += 4;
		proto_tree_add_item( storm_tree, *storm_items->hf_aprs_storm_rtsw, tvb, offset, 4, FALSE );
		offset += 4;
		proto_tree_add_item( storm_tree, *storm_items->hf_aprs_storm_rwg,  tvb, offset, 4, FALSE );
		offset += 4;
		}

	return new_offset;
}

static int
dissect_aprs_weather(	tvbuff_t *tvb,
			int offset,
			proto_tree *parent_tree,
			int hf_aprs_weather,
			gint ett_aprs_weather,
			const weather_items_s *weather_items
			)
{
	proto_tree *tc;
	proto_tree *weather_tree;
	int new_offset;
	int data_len;
	char *info_buffer;
	char *weather_format = " (%*.*s)";
	guint8 ch;


	data_len = tvb_length_remaining( tvb, offset );
	new_offset = offset + data_len;
	info_buffer = ep_alloc( STRLEN );

	g_snprintf( info_buffer, STRLEN, weather_format, data_len, data_len, tvb_get_ptr( tvb, offset, data_len ) );

	if ( parent_tree )
		{
		tc = proto_tree_add_string( parent_tree, hf_aprs_weather, tvb, offset, data_len, info_buffer );
		weather_tree = proto_item_add_subtree( tc, ett_aprs_weather );

		ch = tvb_get_guint8( tvb, offset );
		if ( isdigit( ch ) )
			{
			proto_tree_add_item( weather_tree, *weather_items->hf_weather_dir, tvb, offset, 3, FALSE );
			offset += 3;
			/* verify the separator */
			offset += 1;
			proto_tree_add_item( weather_tree, *weather_items->hf_weather_spd, tvb, offset, 3, FALSE );
			offset += 3;
			}

		while ( offset < new_offset )
			{
			ch = tvb_get_guint8( tvb, offset );
			switch ( ch )
				{
				case 'c' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_dir, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				case 's' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_spd, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				case 'g' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_peak, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				case 't' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_temp, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				case 'r' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_rain_1, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				case 'P' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_rain_24, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				case 'p' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_rain, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				case 'h' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_humidty, tvb, offset, 3, FALSE );
					offset += 3;
					break;
				case 'b' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_press, tvb, offset, 6, FALSE );
					offset += 6;
					break;
				case 'l' :
				case 'L' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_luminosity, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				case 'S' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_snow, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				case '#' :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_raw_rain, tvb, offset, 4, FALSE );
					offset += 4;
					break;
				default  :
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_software, tvb, offset, 1, FALSE );
					offset += 1;
					proto_tree_add_item( weather_tree, *weather_items->hf_weather_unit, tvb, offset, tvb_length_remaining( tvb, offset ), FALSE );
					offset = new_offset;
					break;
				}
			}

		}

	return new_offset;
}

static int
aprs_timestamp( proto_tree *aprs_tree, tvbuff_t *tvb, int offset )
{
	char *info_buffer;
	int data_len;
	char *timezone;


	info_buffer = ep_alloc( STRLEN );
	data_len = 8;
	timezone = "zulu";

	g_snprintf( info_buffer, STRLEN, "%*.*s", data_len, data_len, tvb_get_ptr( tvb, offset, data_len ) );
	if ( isdigit( info_buffer[ 6 ] ) )
		{ /* MDHM */
		proto_tree_add_item( aprs_tree, hf_aprs_mdhm, tvb, offset, data_len, FALSE );
		proto_tree_add_string( aprs_tree, hf_aprs_tz, tvb, offset, data_len, timezone );
		}
	else
		{
		data_len--;
		if ( info_buffer[ 6 ] == 'h' )
			{ /* HMS */
			proto_tree_add_item( aprs_tree, hf_aprs_hms, tvb, offset, data_len, FALSE );
			proto_tree_add_string( aprs_tree, hf_aprs_tz, tvb, offset, data_len, timezone );
			}
		else
			{ /* DHM */
			switch ( info_buffer[ 6 ] )
				{
				case 'z' : timezone = "zulu"; break;
				case '/' : timezone = "local"; break;
				default  : timezone = "unknown"; break;
				}
			proto_tree_add_item( aprs_tree, hf_aprs_dhm, tvb, offset, data_len, FALSE );
			proto_tree_add_string( aprs_tree, hf_aprs_tz, tvb, offset + 6, 1, timezone );
			}
		}

	return offset + data_len;
}

static int
aprs_latitude_compressed( proto_tree *aprs_tree, tvbuff_t *tvb, int offset )
{
	char *info_buffer;
	int data_len;
	int temp;

	info_buffer = ep_alloc( STRLEN );
	data_len = 4;
	g_snprintf( info_buffer, STRLEN, "%*.*s", data_len, data_len, tvb_get_ptr( tvb, offset, data_len ) );
	temp = ( tvb_get_guint8( tvb, offset + 0 ) - 33 );
	temp = ( tvb_get_guint8( tvb, offset + 1 ) - 33 ) + ( temp * 91 );
	temp = ( tvb_get_guint8( tvb, offset + 2 ) - 33 ) + ( temp * 91 );
	temp = ( tvb_get_guint8( tvb, offset + 3 ) - 33 ) + ( temp * 91 );

	g_snprintf( info_buffer, STRLEN, "%6.2f", 90.0 - (temp / 380926.0) );
	proto_tree_add_string( aprs_tree, hf_aprs_lat, tvb, offset, data_len, info_buffer );

	return offset + data_len;
}

static int
aprs_longitude_compressed( proto_tree *aprs_tree, tvbuff_t *tvb, int offset )
{
	char *info_buffer;
	int data_len;
	int temp;

	info_buffer = ep_alloc( STRLEN );
	data_len = 4;
	g_snprintf( info_buffer, STRLEN, "%*.*s", data_len, data_len, tvb_get_ptr( tvb, offset, data_len ) );
	temp = ( tvb_get_guint8( tvb, offset + 0 ) - 33 );
	temp = ( tvb_get_guint8( tvb, offset + 1 ) - 33 ) + ( temp * 91 );
	temp = ( tvb_get_guint8( tvb, offset + 2 ) - 33 ) + ( temp * 91 );
	temp = ( tvb_get_guint8( tvb, offset + 3 ) - 33 ) + ( temp * 91 );

	g_snprintf( info_buffer, STRLEN, "%7.2f", (temp / 190463.0) - 180.0 );
	proto_tree_add_string( aprs_tree, hf_aprs_long, tvb, offset, data_len, info_buffer );

	return offset + data_len;
}

static int
aprs_status( proto_tree *aprs_tree, tvbuff_t *tvb, int offset )
{
	char *info_buffer;
	int data_len;

	info_buffer = ep_alloc( STRLEN );
	data_len = tvb_length_remaining( tvb, offset );

	g_snprintf( info_buffer, STRLEN, "%*.*s", data_len, data_len, tvb_get_ptr( tvb, offset, data_len ) );
	if ( data_len > 7 && info_buffer[ 6 ] == 'z' )
		{
		proto_tree_add_item( aprs_tree, hf_aprs_dhm, tvb, offset, 6, FALSE );
		offset += 6;
		data_len -= 6;
		proto_tree_add_string( aprs_tree, hf_aprs_tz, tvb, offset, 1, "zulu" );
		offset += 1;
		data_len -= 1;
		}
	proto_tree_add_item( aprs_tree, hf_aprs_status, tvb, offset, data_len, FALSE );

	return offset + data_len;
}

static int
aprs_item( proto_tree *aprs_tree, tvbuff_t *tvb, int offset )
{
	char *info_buffer;
	int data_len;
	char *ch_ptr;

	info_buffer = ep_alloc( STRLEN );
	data_len = 10;

	g_snprintf( info_buffer, STRLEN, "%*.*s", data_len, data_len, tvb_get_ptr( tvb, offset, data_len ) );
	ch_ptr = strchr( info_buffer, '!' );
	if ( ch_ptr != NULL )
		{
		data_len = (int)(ch_ptr - info_buffer + 1);
		*ch_ptr = '\0';
		}
	else
		{
		ch_ptr = strchr( info_buffer, '!' );
		if ( ch_ptr != NULL )
			{
			data_len = (int)(ch_ptr - info_buffer + 1);
			*ch_ptr = '\0';
			}
		}
	proto_tree_add_string( aprs_tree, hf_aprs_item, tvb, offset, data_len, info_buffer );

	return offset + data_len;
}

static int
aprs_3rd_party( proto_tree *aprs_tree, tvbuff_t *tvb, int offset, int data_len )
{
	proto_tree_add_item( aprs_tree, hf_aprs_third_party, tvb, offset, data_len, FALSE );
	/* tnc-2 */
	/* aea */
	return offset + data_len;
}

static int
aprs_default( proto_tree *aprs_tree, tvbuff_t *tvb, int offset, int data_len, int hfindex )
{
	proto_tree_add_item( aprs_tree, hfindex, tvb, offset, data_len, FALSE );
	return offset + data_len;
}

static int
aprs_position( proto_tree *aprs_tree, tvbuff_t *tvb, int offset, int with_msg )
{
	guint8 symbol_table_id = 0;
	guint8 symbol_code = 0;
	int probably_a_msg = FALSE;
	int probably_not_a_msg = FALSE;

	if ( isdigit( tvb_get_guint8( tvb, offset ) ) )
		{
		offset = aprs_default( aprs_tree, tvb, offset, 8, hf_aprs_lat );
		symbol_table_id = tvb_get_guint8( tvb, offset );
		offset = aprs_default( aprs_tree, tvb, offset, 1, hf_aprs_sym_id );
		offset = aprs_default( aprs_tree, tvb, offset, 9, hf_aprs_long );
		symbol_code = tvb_get_guint8( tvb, offset );
		offset = aprs_default( aprs_tree, tvb, offset, 1, hf_aprs_sym_code );
		if ( gPREF_APRS_LAX )
			{
			switch ( tvb_get_guint8( tvb, offset ) )
				{
				case 'D'	: probably_a_msg = TRUE; break;
				case 'P'	: probably_a_msg = TRUE; break;
				case 'R'	: probably_a_msg = TRUE; break;
				case 'T'	: probably_a_msg = TRUE; break;
				default		: probably_not_a_msg = TRUE; break;
				}
			}
		if ( with_msg || probably_a_msg || ! probably_not_a_msg )
			offset = dissect_aprs_msg(	tvb,
							offset,
							aprs_tree,
							hf_aprs_msg,
							ett_aprs_msg,
							&msg_items,
							( symbol_code == '_' ),
							( symbol_table_id == '/' && symbol_code == '\\' )
							);
		}
	else
		{
		symbol_table_id = tvb_get_guint8( tvb, offset );
		offset = aprs_default( aprs_tree, tvb, offset, 1, hf_aprs_sym_id );
		offset = aprs_latitude_compressed( aprs_tree, tvb, offset );
		offset = aprs_longitude_compressed( aprs_tree, tvb, offset );
		symbol_code = tvb_get_guint8( tvb, offset );
		offset = aprs_default( aprs_tree, tvb, offset, 1, hf_aprs_sym_code );
		offset = dissect_aprs_compressed_msg(	tvb,
							offset,
							aprs_tree,
							hf_aprs_msg,
							ett_aprs_msg,
							&msg_items
							);
		offset = dissect_aprs_compression_type(	tvb,
							offset,
							aprs_tree,
							hf_aprs_compression_type,
							ett_aprs_ct,
							&ct_items
							);
		if ( symbol_table_id == '/' && symbol_code == '\\' )
			offset = aprs_default( aprs_tree, tvb, offset, 8, hf_aprs_msg_brg );
		}

	if ( symbol_code == '_' )
		offset = dissect_aprs_weather(	tvb,
						offset,
						aprs_tree,
						hf_aprs_weather,
						ett_aprs_weather,
						&weather_items
						);
	if ( ( symbol_table_id == '/' && symbol_code == '@' ) || ( symbol_table_id == '\\' && symbol_code == '@' ) )
		offset = dissect_aprs_storm(	tvb,
						offset,
						aprs_tree,
						hf_aprs_storm,
						ett_aprs_storm,
						&storm_items
						);

	return offset;
}

static char *
aprs_description( tvbuff_t *tvb, int offset )
{
	guint8 dti;
	char *dti_text = "";

	dti = tvb_get_guint8( tvb, offset );

	switch ( dti )
		{
		case '<'	: dti_text = "Station Capabilities"; break;
		case '>'	: dti_text = "Status"; break;
		case '?'	: dti_text = "Query"; break;
		case '$'	: dti_text = "Raw GPS data or Ultimeter 2000"; break;
		case '%'	: dti_text = "Agrelo DFJr / MicroFinder"; break;
		case 'T'	: dti_text = "Telemetry data"; break;
		case '['	: dti_text = "Maidenhead grid locator beacon (obsolete)"; break;
		case ')'	: dti_text = "Item"; break;
		case '_'	: dti_text = "Weather Report (without position)"; break;
		case ','	: dti_text = "Invalid data or test data"; break;
		case '{'	: dti_text = "User-Defined APRS packet format"; break;
		case '}'	: dti_text = "Third-party traffic"; break;
		case ':'	: dti_text = "Message"; break;
		case ';'	: dti_text = "Object"; break;
		case 0x1c	: dti_text = "Current Mic-E Data (Rev 0 beta)"; break;
		case 0x1d	: dti_text = "Old Mic-E Data (Rev 0 beta)"; break;
		case '\''	: dti_text = "Old Mic-E Data (current data for TM-D700)"; break;
		case '`'	: dti_text = "Current Mic-E Data (not used in TM-D700)"; break;
		case '#'	: dti_text = "Peet Bros U-II Weather Station"; break;
		case '*'	: dti_text = "Peet Bros U-II Weather Station"; break;
		case '&'	: dti_text = "[Reserved - Map Feature]"; break;
		case '+'	: dti_text = "[Reserved - Shelter data with time]"; break;
		case '.'	: dti_text = "[Reserved - Space weather]"; break;
		case '!'	:
			if ( tvb_get_guint8( tvb, offset + 1 ) == '!' )
				dti_text = "Ultimeter 2000 WX Station";
			else
				dti_text = "Position";
			break;
		case '/'	: dti_text = "Position + timestamp"; break;
		case '='	: dti_text = "Position + APRS data extension"; break;
		case '@'	: dti_text = "Position + timestamp + APRS data extension"; break;

		default		: break;
		}
	return dti_text;
}

static void
dissect_aprs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *ti;
	proto_tree *aprs_tree;

	char *info_buffer;
	int offset;
	guint8 dti;
	char *dti_text = "";


	info_buffer = ep_alloc( STRLEN );

	offset = 0;
	dti = tvb_get_guint8( tvb, offset );
	dti_text = aprs_description( tvb, offset );

	switch ( dti )
		{
		case '!'	: /* Position or Ultimeter 2000 WX Station */
			if ( tvb_get_guint8( tvb, offset + 1 ) == '!' )
				g_snprintf( info_buffer, STRLEN, "%s", dti_text );
			else
				g_snprintf( info_buffer, STRLEN, "%s (%8.8s %9.9s %1.1s%1.1s)",
							dti_text,
							tvb_get_ptr( tvb, offset + 1, 8 ),		/* Lat */
							tvb_get_ptr( tvb, offset + 1 + 8 + 1, 9 ),	/* Long */
							tvb_get_ptr( tvb, offset + 1 + 8 , 1 ),		/* Symbol table id */
							tvb_get_ptr( tvb, offset + 1 + 8 + 1 + 9, 1 )	/* Symbol Code */
							);
			break;
		case '='	: /* Position + Ext APRS message */
				g_snprintf( info_buffer, STRLEN, "%s (%8.8s %9.9s %1.1s%1.1s)",
							dti_text,
							tvb_get_ptr( tvb, offset + 1, 8 ),		/* Lat */
							tvb_get_ptr( tvb, offset + 1 + 8 + 1, 9 ),	/* Long */
							tvb_get_ptr( tvb, offset + 1 + 8 , 1 ),		/* Symbol table id */
							tvb_get_ptr( tvb, offset + 1 + 8 + 1 + 9, 1 )	/* Symbol Code */
							);
			break;
		case '/'	: /* Position + timestamp */
				g_snprintf( info_buffer, STRLEN, "%s (%7.7s %8.8s %9.9s %1.1s%1.1s)",
							dti_text,
							tvb_get_ptr( tvb, offset + 1, 7 ),		/* Timestamp */
							tvb_get_ptr( tvb, offset + 1 + 7 + 1, 8 ),	/* Lat */
							tvb_get_ptr( tvb, offset + 1 + 7 + 8 + 1, 9 ),	/* Long */
							tvb_get_ptr( tvb, offset + 1 + 7 , 1 ),		/* Symbol table id */
							tvb_get_ptr( tvb, offset + 1 + 7 + 1 + 9, 1 )	/* Symbol Code */
							);
			break;
		case '@'	: /* Position + timestamp + Ext APRS message */
				g_snprintf( info_buffer, STRLEN, "%s (%7.7s %8.8s %9.9s %1.1s%1.1s)",
							dti_text,
							tvb_get_ptr( tvb, offset + 1, 7 ),		/* Timestamp */
							tvb_get_ptr( tvb, offset + 1 + 7 + 1, 8 ),	/* Lat */
							tvb_get_ptr( tvb, offset + 1 + 7 + 8 + 1, 9 ),	/* Long */
							tvb_get_ptr( tvb, offset + 1 + 7 , 1 ),		/* Symbol table id */
							tvb_get_ptr( tvb, offset + 1 + 7 + 1 + 9, 1 )	/* Symbol Code */
							);
			break;
		default		:
			g_snprintf( info_buffer, STRLEN, "%s", dti_text );
			break;
		}

	col_set_str( pinfo->cinfo, COL_PROTOCOL, "APRS" );

	col_clear( pinfo->cinfo, COL_INFO );

	col_add_str( pinfo->cinfo, COL_INFO, info_buffer );

	if ( parent_tree )
		{
		/* create display subtree for the protocol */
		ti = proto_tree_add_protocol_format( parent_tree , proto_aprs, tvb, 0, tvb_length_remaining( tvb, offset ), "%s", info_buffer );
		aprs_tree = proto_item_add_subtree( ti, ett_aprs );

		offset = 0;

		dti = tvb_get_guint8( tvb, offset );
		proto_tree_add_item( aprs_tree, hf_aprs_dti, tvb, offset, 1, FALSE );
		offset += 1;
		switch ( dti )
			{
			case '<'	: /* Station Capabilities */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_station );
				break;
			case '>'	: /* Status */
				offset = aprs_status( aprs_tree, tvb, offset );
				break;
			case '?'	: /* Query */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_query );
				break;
			case '$'	: /* Raw GPS data or Ultimeter 2000 */
				if ( tvb_get_guint8( tvb, offset ) == 'U' )
					offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_ultimeter_2000 );
				else
					offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_raw );
				break;
			case '%'	: /* Agrelo DFJr / MicroFinder */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_agrelo );
				break;
			case 'T'	: /* Telemetry data */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_telemetry );
				break;
			case '['	: /* Maidenhead grid locator beacon (obsolete) */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_maidenhead );
				break;
			case '_'	: /* Weather Report (without position) */
				offset = aprs_timestamp( aprs_tree, tvb, offset );
				offset = dissect_aprs_weather(	tvb,
								offset,
								aprs_tree,
								hf_aprs_weather,
								ett_aprs_weather,
								&weather_items
								);
				break;
			case ','	: /* Invalid data or test data */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_invalid_test );
				break;
			case '{'	: /* User-Defined APRS packet format */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_user_defined );
				break;
			case '}'	: /* Third-party traffic */
				offset = aprs_3rd_party( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ) );
				break;
			case ':'	: /* Message */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_message );
				break;
			case 0x1c	: /* Current Mic-E Data (Rev 0 beta) */
				offset = dissect_mic_e(	tvb,
							offset,
							pinfo,
							aprs_tree,
							hf_aprs_mic_e_0_current,
							ett_aprs_mic_e,
							&mic_e_items
							);
				break;
			case 0x1d	: /* Old Mic-E Data (Rev 0 beta) */
				offset = dissect_mic_e(	tvb,
							offset,
							pinfo,
							aprs_tree,
							hf_aprs_mic_e_0_old,
							ett_aprs_mic_e,
							&mic_e_items
							);
				break;
			case '\''	: /* Old Mic-E Data (but Current data for TM-D700) */
				offset = dissect_mic_e(	tvb,
							offset,
							pinfo,
							aprs_tree,
							hf_aprs_mic_e_old,
							ett_aprs_mic_e,
							&mic_e_items
							);
				break;
			case '`'	: /* Current Mic-E Data (not used in TM-D700) */
				offset = dissect_mic_e(	tvb,
							offset,
							pinfo,
							aprs_tree,
							hf_aprs_mic_e_current,
							ett_aprs_mic_e,
							&mic_e_items
							);
				break;
			case '#'	: /* Peet Bros U-II Weather Station */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_peet_1 );
				break;
			case '*'	: /* Peet Bros U-II Weather Station */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_peet_2 );
				break;
			case '&'	: /* [Reserved - Map Feature] */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_map_feature );
				break;
			case '+'	: /* [Reserved - Shelter data with time] */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_shelter_data );
				break;
			case '.'	: /* [Reserved - Space weather] */
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_space_weather );
				break;
			case ')'	: /* Item */
				offset = aprs_item( aprs_tree, tvb, offset );
				offset = aprs_position( aprs_tree, tvb, offset, TRUE );
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_comment );
				break;
			case ';'	: /* Object */
				offset = aprs_default( aprs_tree, tvb, offset, 10, hf_aprs_object );
				offset = aprs_timestamp( aprs_tree, tvb, offset );
				offset = aprs_position( aprs_tree, tvb, offset, TRUE );
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_comment );
				break;
			case '!'	: /* Position or Ultimeter 2000 WX Station */
				if ( tvb_get_guint8( tvb, offset ) == '!' )
					offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_ultimeter_2000 );
				else
					{
					offset = aprs_position( aprs_tree, tvb, offset, FALSE );
					offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_comment );
					}
				break;
			case '='	: /* Position + Ext APRS message */
				offset = aprs_position( aprs_tree, tvb, offset, TRUE );
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_comment );
				break;
			case '/'	: /* Position + timestamp */
				offset = aprs_timestamp( aprs_tree, tvb, offset );
				offset = aprs_position( aprs_tree, tvb, offset, FALSE );
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_comment );
				break;
			case '@'	: /* Position + timestamp + Ext APRS message */
				offset = aprs_timestamp( aprs_tree, tvb, offset );
				offset = aprs_position( aprs_tree, tvb, offset, TRUE );
				offset = aprs_default( aprs_tree, tvb, offset, tvb_length_remaining( tvb, offset ), hf_aprs_comment );
				break;
			default	: break;
			}
		}
}

void
proto_register_aprs(void)
{
	module_t *aprs_module;

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aprs_dti,
			{ "DTI",		"aprs.dti",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Data type indicator", HFILL }
		},
		{ &hf_aprs_sym_code,
			{ "Symbol code",		"aprs.sym_code",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_sym_id,
			{ "Symbol table ID",		"aprs.sym_id",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

/* Position */
		{ &hf_aprs_position,
			{ "Position",		"aprs.position",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_lat,
			{ "Latitude",		"aprs.position.lat",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_long,
			{ "Longitude",		"aprs.position.long",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

/* APRS Messages */
		{ &hf_aprs_comment,
			{ "Comment",			"aprs.comment",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ultimeter_2000,
			{ "Ultimeter 2000",		"aprs.ultimeter_2000",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_status,
			{ "Status",			"aprs.status",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_object,
			{ "Object",			"aprs.object",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_item,
			{ "Item",			"aprs.item",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_query,
			{ "Query",			"aprs.query",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_telemetry,
			{ "Telemetry",			"aprs.telemetry",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_raw,
			{ "Raw",			"aprs.raw",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Raw NMEA position report format", HFILL }
		},
		{ &hf_aprs_station,
			{ "Station",			"aprs.station",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Station capabilities", HFILL }
		},
		{ &hf_aprs_message,
			{ "Message",			"aprs.message",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_agrelo,
			{ "Agrelo",			"aprs.agrelo",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Agrelo DFJr / MicroFinder", HFILL }
		},
		{ &hf_aprs_maidenhead,
			{ "Maidenhead",			"aprs.maidenhead",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Maidenhead grid locator beacon (obsolete)", HFILL }
		},
		{ &hf_aprs_invalid_test,
			{ "Invalid or test",		"aprs.invalid_test",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Invalid data or test data", HFILL }
		},
		{ &hf_aprs_user_defined,
			{ "User-Defined",		"aprs.user_defined",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"User-Defined APRS packet format", HFILL }
		},
		{ &hf_aprs_third_party,
			{ "Third-party",		"aprs.third_party",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Third-party traffic", HFILL }
		},
		{ &hf_aprs_peet_1,
			{ "Peet U-II (1)",		"aprs.peet_1",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Peet Bros U-II Weather Station", HFILL }
		},
		{ &hf_aprs_peet_2,
			{ "Peet U-II (2)",		"aprs.peet_2",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Peet Bros U-II Weather Station", HFILL }
		},
		{ &hf_aprs_map_feature,
			{ "Map Feature",		"aprs.map_feature",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"[Reserved - Map Feature", HFILL }
		},
		{ &hf_aprs_shelter_data,
			{ "Shelter data",		"aprs.shelter_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"[Reserved - Shelter data with time]", HFILL }
		},
		{ &hf_aprs_space_weather,
			{ "Space weather",		"aprs.space_weather",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"[Reserved - Space weather]", HFILL }
		},
		{ &hf_aprs_storm,
			{ "Storm",			"aprs.storm",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

/* Time stamp */
		{ &hf_aprs_dhm,
			{ "DHM",		"aprs.dhm",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Day/Hour/Minute", HFILL }
		},
		{ &hf_aprs_hms,
			{ "HMS",		"aprs.hms",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Hour/Minute/Second", HFILL }
		},
		{ &hf_aprs_mdhm,
			{ "MDHM",		"aprs.mdhm",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Month/Day/Hour/Minute", HFILL }
		},
		{ &hf_aprs_tz,
			{ "TZ",		"aprs.tz",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Time zone", HFILL }
		},

/* Compressed Msg */
		{ &hf_aprs_compression_type,
			{ "Compression type",		"aprs.ct",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_ct_gps_fix,
			{ "GPS fix type",		"aprs.ct.gps_fix",
			FT_UINT8, BASE_HEX, VALS(gps_vals), 0x20,
			NULL, HFILL }
		},
		{ &hf_aprs_ct_nmea_src,
			{ "NMEA source",		"aprs.ct.nmea_src",
			FT_UINT8, BASE_HEX, VALS(nmea_vals), 0x18,
			NULL, HFILL }
		},
		{ &hf_aprs_ct_origin,
			{ "Compression origin",		"aprs.ct.origin",
			FT_UINT8, BASE_HEX, VALS(ctype_vals), 0x07,
			NULL, HFILL }
		},

/* Ext Msg */
		{ &hf_aprs_msg,
			{ "Extended message",			"aprs.msg",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_rng,
			{ "Range",			"aprs.msg.rng",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Pre-calculated radio range", HFILL }
		},
		{ &hf_aprs_msg_cse,
			{ "Course",			"aprs.msg.cse",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_spd,
			{ "Speed",			"aprs.msg.spd",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_dir,
			{ "Wind direction",		"aprs.msg.dir",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_brg,
			{ "Bearing",			"aprs.msg.brg",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_nrq,
			{ "NRQ",			"aprs.msg.nrq",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Number/Range/Quality", HFILL }
		},

/* Msg PHGD */
		{ &hf_aprs_msg_phg_p,
			{ "Power",		"aprs.msg.phg.p",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_phg_h,
			{ "Height",		"aprs.msg.phg.h",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_phg_g,
			{ "Gain",		"aprs.msg.phg.g",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_phg_d,
			{ "Directivity",		"aprs.msg.phg.d",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

/* Msg DFS */
		{ &hf_aprs_msg_dfs_s,
			{ "Strength",			"aprs.msg.dfs.s",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_dfs_h,
			{ "Height",			"aprs.msg.dfs.h",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_dfs_g,
			{ "Gain",			"aprs.msg.dfs.g",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_dfs_d,
			{ "Directivity",		"aprs.msg.dfs.d",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

/* Msg AOD */
		{ &hf_aprs_msg_aod_t,
			{ "Type",			"aprs.msg.aod.t",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_msg_aod_c,
			{ "Colour",			"aprs.msg.aod.c",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

/* Weather */
		{ &hf_aprs_weather,
			{ "Weather",			"aprs.weather",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Weather report", HFILL }
		},
		{ &hf_aprs_weather_dir,
			{ "Wind direction",		"aprs.weather.dir",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_spd,
			{ "Wind speed",			"aprs.weather.speed",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Wind speed (1 minute)", HFILL }
		},
		{ &hf_aprs_weather_peak,
			{ "Peak wind speed",		"aprs.weather.peak",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_temp,
			{ "Temperature (F)",		"aprs.weather.temp",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_rain_1,
			{ "Rain (last 1 hour)",			"aprs.weather.1_hour",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_rain_24,
			{ "Rain (last 24 hours)",		"aprs.weather.24_hour",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_rain,
			{ "Rain",			"aprs.weather.rain",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_humidty,
			{ "Humidity",			"aprs.weather.humidity",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_press,
			{ "Pressure",			"aprs.weather.pressure",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_luminosity,
			{ "Luminosity",			"aprs.weather.luminosity",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_snow,
			{ "Snow",			"aprs.weather.snow",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_raw_rain,
			{ "Raw rain",			"aprs.weather.raw_rain",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_software,
			{ "Software",			"aprs.weather.software",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_weather_unit,
			{ "Unit",			"aprs.weather.unit",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

/* MIC-E */
		{ &hf_aprs_mic_e_0_current,
			{ "Current Mic-E (Rev 0)",	"aprs.mic_e_0_current",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_mic_e_0_old,
			{ "Old Mic-E (Rev 0)",		"aprs.mic_e_0_old",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_mic_e_old,
			{ "Old Mic-E",			"aprs.mic_e_old",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Old Mic-E Data (but Current data for TM-D700)", HFILL }
		},
		{ &hf_aprs_mic_e_current,
			{ "Current Mic-E",		"aprs.mic_e_current",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Current Mic-E Data (not used in TM-D700)", HFILL }
		},
		{ &hf_aprs_mic_e_dst,
			{ "Destination Address",		"aprs.mic_e.dst",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_mic_e_long_d,
			{ "Longitude degrees",		"aprs.mic_e.long_d",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_mic_e_long_m  ,
			{ "Longitude minutes",		"aprs.mic_e.long_m",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_mic_e_long_h,
			{ "Longitude hundreths of minutes",	"aprs.mic_e.long_h",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_aprs_mic_e_spd_sp,
			{ "Speed (H & T)",		"aprs.mic_e.speed_sp",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Speed (hundreds & tens)", HFILL }
		},
		{ &hf_aprs_mic_e_spd_dc,
			{ "Spd (U), Cse (H)",		"aprs.mic_e.speed_dc",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Speed (tens), Course (hundreds)", HFILL }
		},
		{ &hf_aprs_mic_e_spd_se,
			{ "Course (T & U)",	"aprs.mic_e.speed_se",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Course (tens & units)", HFILL }
		},
		{ &hf_aprs_mic_e_telemetry,
			{ "Telmetry",	"aprs.mic_e.telemetry",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Telemetry", HFILL }
		},
		{ &hf_aprs_mic_e_status,
			{ "Status",	"aprs.mic_e.status",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aprs,
		&ett_aprs_msg,
		&ett_aprs_ct,
		&ett_aprs_weather,
		&ett_aprs_storm,
		&ett_aprs_mic_e,
	};

	/* Register the protocol name and description */
	proto_aprs = proto_register_protocol("Automatic Position Reporting System", "APRS", "aprs");

	/* Register the dissector */
	register_dissector( "aprs", dissect_aprs, proto_aprs);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array( proto_aprs, hf, array_length(hf ) );
	proto_register_subtree_array( ett, array_length( ett ) );

	/* Register preferences module */
        aprs_module = prefs_register_protocol( proto_aprs, proto_reg_handoff_aprs);

	/* Register any preference */
        prefs_register_bool_preference(aprs_module, "showaprslax",
	     "Allow APRS violations.",
             "Attempt to display common APRS protocol violations correctly",
	     &gPREF_APRS_LAX );

}

void
proto_reg_handoff_aprs(void)
{
        static gboolean inited = FALSE;

        if( !inited ) {

		default_handle  = find_dissector( "data" );

        	inited = TRUE;
        }
}
