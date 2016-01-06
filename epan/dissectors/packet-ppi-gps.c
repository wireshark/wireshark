/* packet-ppi-gps.c
 * Routines for PPI-GEOLOCATION-GPS  dissection
 * Copyright 2010, Harris Corp, jellch@harris.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-radiotap.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-ppi-geolocation-common.h"

enum ppi_geotagging_type {
    PPI_GEOTAG_GPSFLAGS = 0,
    PPI_GEOTAG_LAT = 1,
    PPI_GEOTAG_LON = 2,
    PPI_GEOTAG_ALT = 3,
    PPI_GEOTAG_ALT_G = 4,
    PPI_GEOTAG_GPSTIME = 5,
    PPI_GEOTAG_FRACTIONALTIME = 6,
    PPI_GEOTAG_EPH = 7,
    PPI_GEOTAG_EPV = 8,
    PPI_GEOTAG_EPT = 9,
    PPI_GEOTAG_DESCRIPTIONSTR = 28,
    PPI_GEOTAG_APPID = 29,
    PPI_GEOTAG_APPDATA = 30,
    PPI_GEOTAG_EXT = 31
};
#define PPI_GPS_MAXTAGLEN  144 /* increase as fields are added */

#define PPI_GPS_MASK_GPSFLAGS       0x00000001
#define PPI_GPS_MASK_LAT            0x00000002
#define PPI_GPS_MASK_LON            0x00000004
#define PPI_GPS_MASK_ALT            0x00000008
#define PPI_GPS_MASK_ALT_G          0x00000010

#define PPI_GPS_MASK_GPSTIME        0x00000020
#define PPI_GPS_MASK_FRACTIME       0x00000040
#define PPI_GPS_MASK_EPH            0x00000080
#define PPI_GPS_MASK_EPV            0x00000100
#define PPI_GPS_MASK_EPT            0x00000200

#define PPI_GPS_MASK_DESCRSTR       0x10000000
#define PPI_GPS_MASK_APPID          0x20000000
#define PPI_GPS_MASK_APPDATA        0x40000000
#define PPI_GPS_MASK_EXT            0x80000000


void proto_register_ppi_gps(void);

/* protocol */
static int proto_ppi_gps = -1;

static int hf_ppi_gps_version = -1;
static int hf_ppi_gps_pad = -1;
static int hf_ppi_gps_length = -1;
static int hf_ppi_gps_present = -1;
static int hf_ppi_gps_gpsflags_flags = -1;
static int hf_ppi_gps_lon = -1;
static int hf_ppi_gps_lat = -1;
static int hf_ppi_gps_alt = -1;
static int hf_ppi_gps_alt_gnd = -1;
static int hf_ppi_gps_gpstime = -1;
/* static int hf_ppi_gps_fractime = -1; */
static int hf_ppi_gps_eph = -1;
static int hf_ppi_gps_epv = -1;
static int hf_ppi_gps_ept = -1;
static int hf_ppi_gps_descstr = -1;
static int hf_ppi_gps_appspecific_num = -1; /* 4-byte tag no */
static int hf_ppi_gps_appspecific_data = -1; /* 60 byte arbitrary data */
/* "Present" flags, tese represent decoded-bits in the gui */
static int hf_ppi_gps_present_gpsflags_flags = -1;
static int hf_ppi_gps_present_lon = -1;
static int hf_ppi_gps_present_lat = -1;
static int hf_ppi_gps_present_alt = -1;
static int hf_ppi_gps_present_alt_gnd = -1;
static int hf_ppi_gps_present_gpstime = -1;
static int hf_ppi_gps_present_fractime = -1;
static int hf_ppi_gps_present_eph = -1;
static int hf_ppi_gps_present_epv = -1;
static int hf_ppi_gps_present_ept = -1;
static int hf_ppi_gps_present_descr = -1;
static int hf_ppi_gps_present_appspecific_num = -1;
static int hf_ppi_gps_present_appspecific_data = -1;
static int hf_ppi_gps_present_ext = -1;

/* Devicetype flags. not to be confused with "present" flags. These are optional */
static int hf_ppi_gps_gpsflags_flag0_nofix = -1;
static int hf_ppi_gps_gpsflags_flag1_gpsfix = -1;
static int hf_ppi_gps_gpsflags_flag2_diffgps = -1;
static int hf_ppi_gps_gpsflags_flag3_PPS = -1;
static int hf_ppi_gps_gpsflags_flag4_RTK = -1;
static int hf_ppi_gps_gpsflags_flag5_floatRTK = -1;
static int hf_ppi_gps_gpsflags_flag6_dead_reck = -1;
static int hf_ppi_gps_gpsflags_flag7_manual = -1;
static int hf_ppi_gps_gpsflags_flag8_sim = -1;

/* These represent arrow-dropdownthings in the gui */
static gint ett_ppi_gps = -1;
static gint ett_ppi_gps_present = -1;
static gint ett_ppi_gps_gpsflags_flags= -1;

static expert_field ei_ppi_gps_present_bit = EI_INIT;
static expert_field ei_ppi_gps_version = EI_INIT;
static expert_field ei_ppi_gps_length = EI_INIT;

static int
dissect_ppi_gps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
    /* These are locals used for processing the current tvb */
    guint length;
    gint  length_remaining;
    int offset = 0;

    proto_tree *ppi_gps_tree = NULL;

    proto_item *version_item, *length_item, *pt;
    proto_item *gps_line = NULL;

    static const int * ppi_gps_present_flags[] = {
        &hf_ppi_gps_present_gpsflags_flags,
        &hf_ppi_gps_present_lat,
        &hf_ppi_gps_present_lon,
        &hf_ppi_gps_present_alt,
        &hf_ppi_gps_present_alt_gnd,
        &hf_ppi_gps_present_gpstime,
        &hf_ppi_gps_present_fractime,
        &hf_ppi_gps_present_eph,
        &hf_ppi_gps_present_epv,
        &hf_ppi_gps_present_ept,
        &hf_ppi_gps_present_descr,
        &hf_ppi_gps_present_appspecific_num,
        &hf_ppi_gps_present_appspecific_data,
        &hf_ppi_gps_present_ext,
        NULL
    };

    static const int * ppi_antenna_gps_flags[] = {
        &hf_ppi_gps_gpsflags_flag0_nofix,
        &hf_ppi_gps_gpsflags_flag1_gpsfix,
        &hf_ppi_gps_gpsflags_flag2_diffgps,
        &hf_ppi_gps_gpsflags_flag3_PPS,
        &hf_ppi_gps_gpsflags_flag4_RTK,
        &hf_ppi_gps_gpsflags_flag5_floatRTK,
        &hf_ppi_gps_gpsflags_flag6_dead_reck,
        &hf_ppi_gps_gpsflags_flag7_manual,
        &hf_ppi_gps_gpsflags_flag8_sim,
        NULL
    };

    /* bits */
    int bit;
    guint32 present, next_present;
    /* values actually read out, for displaying */
    guint32 version;
    gdouble lat, lon, alt, alt_gnd;
    nstime_t gps_timestamp;
    int gps_time_size, already_processed_fractime; /* we use this internally to track if this is a 4 or 8 byte wide timestamp */
    gdouble eph, epv, ept;
    gchar *curr_str;


    /* these are temporary intermediate values, used in the individual cases below */
    guint32 t_lat, t_lon, t_alt, t_alt_gnd;
    guint32 t_herr, t_verr, t_terr;
    guint32 t_appspecific_num;
    /* initialize the timestamp value(s) */
    gps_timestamp.secs = gps_timestamp.nsecs = already_processed_fractime = 0;

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* pull out the first three fields of the BASE-GEOTAG-HEADER */
    version = tvb_get_guint8(tvb, offset);
    length  = tvb_get_letohs(tvb, offset+2);
    present = tvb_get_letohl(tvb, offset+4);

    /* Setup basic column info */
    col_add_fstr(pinfo->cinfo, COL_INFO, "PPI_GPS Capture v%u, Length %u", version, length);

    /* Create the basic dissection tree*/
    gps_line = proto_tree_add_protocol_format(tree, proto_ppi_gps, tvb, 0, length, "GPS:");
    ppi_gps_tree = proto_item_add_subtree(gps_line, ett_ppi_gps);
    version_item = proto_tree_add_uint(ppi_gps_tree, hf_ppi_gps_version, tvb, offset, 1, version);
    proto_tree_add_item(ppi_gps_tree, hf_ppi_gps_pad, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
    length_item = proto_tree_add_uint(ppi_gps_tree, hf_ppi_gps_length, tvb, offset + 2, 2, length);

    /* We support v1 and v2 of GPS tags (identical) */
    if (! (version == 1 || version == 2) ) {
        expert_add_info_format(pinfo, version_item, &ei_ppi_gps_version, "Invalid version (got %d,  expected 1 or 2)", version);
    }

    /* initialize the length of the actual tag contents */
    length_remaining = length;
    /* minimum length check, should atleast be a fixed-size geotagging-base header*/
    if (length_remaining < PPI_GEOBASE_MIN_HEADER_LEN) {
        /*
         * Base-geotag-header (Radiotap lookalike) is shorter than the fixed-length portion
         * plus one "present" bitset.
         */
        expert_add_info_format(pinfo, length_item, &ei_ppi_gps_length, "Invalid PPI-GPS length - minimum length is 8");
        return 2;
    }

    /* perform tag-specific max length sanity checking */
    if (length > PPI_GPS_MAXTAGLEN ) {
        expert_add_info_format(pinfo, length_item, &ei_ppi_gps_length, "Invalid PPI-GPS length  (got %d, %d max\n)", length, PPI_GPS_MAXTAGLEN);
        return 2;
    }

    /* Subtree for the "present flags" bitfield. */
    pt = proto_tree_add_bitmask(ppi_gps_tree, tvb, offset + 4, hf_ppi_gps_present, ett_ppi_gps_present, ppi_gps_present_flags, ENC_LITTLE_ENDIAN);

    offset += PPI_GEOBASE_MIN_HEADER_LEN;
    length_remaining -= PPI_GEOBASE_MIN_HEADER_LEN;

    /* The fixed BASE-GEOTAG-HEADER has been handled at this point. move on to the individual fields */
    for (; present; present = next_present) {
        /* clear the least significant bit that is set */
        next_present = present & (present - 1);
        /* extract the least significant bit that is set */
        bit = BITNO_32(present ^ next_present);
        switch (bit) {
        case PPI_GEOTAG_GPSFLAGS:
            if (length_remaining < 4)
                break;
            proto_tree_add_bitmask(ppi_gps_tree, tvb, offset, hf_ppi_gps_gpsflags_flags, ett_ppi_gps_gpsflags_flags, ppi_antenna_gps_flags, ENC_LITTLE_ENDIAN);
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_GEOTAG_LAT:
            if (length_remaining < 4)
                break;
            t_lat = tvb_get_letohl(tvb, offset);
            lat =  ppi_fixed3_7_to_gdouble(t_lat);
            if (tree)
            {
                proto_tree_add_double(ppi_gps_tree, hf_ppi_gps_lat, tvb, offset, 4, lat);
                proto_item_append_text(gps_line, " Lat:%f ", lat);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_GEOTAG_LON:
            if (length_remaining < 4)
                break;
            t_lon = tvb_get_letohl(tvb, offset);
            lon =  ppi_fixed3_7_to_gdouble(t_lon);
            if (tree)
            {
                proto_tree_add_double(ppi_gps_tree, hf_ppi_gps_lon, tvb, offset, 4, lon);
                proto_item_append_text(gps_line, " Lon:%f ", lon);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_GEOTAG_ALT:
            if (length_remaining < 4)
                break;
            t_alt = tvb_get_letohl(tvb, offset);
            alt = ppi_fixed6_4_to_gdouble(t_alt);
            if (tree)
            {
                proto_tree_add_double(ppi_gps_tree, hf_ppi_gps_alt, tvb, offset, 4, alt);
                proto_item_append_text(gps_line, " Alt:%f ", alt);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_GEOTAG_ALT_G:
            if (length_remaining < 4)
                break;
            t_alt_gnd = tvb_get_letohl(tvb, offset);
            alt_gnd = ppi_fixed6_4_to_gdouble(t_alt_gnd);
            if (tree)
            {
                proto_tree_add_double(ppi_gps_tree, hf_ppi_gps_alt_gnd, tvb, offset, 4, alt_gnd);
                proto_item_append_text(gps_line, " Alt_g:%f ", alt_gnd);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_GEOTAG_GPSTIME:
            if (length_remaining < 4)
                break;
            gps_timestamp.secs =    tvb_get_letohl(tvb, offset);
            gps_timestamp.nsecs = 0;
            gps_time_size = 4;
            /* This is somewhat tricky, inside the GPSTIME case we test if the optional fractional time */
            /* is present. If so, we pull it out, and combine it with GPSTime. */
            /* If we do this, we set already_processed_fractime to avoid hitting it below */
            if (length_remaining < 4 && (present & PPI_GPS_MASK_FRACTIME))
                break;
            else if (present & PPI_GPS_MASK_FRACTIME) {
                gps_timestamp.nsecs =  tvb_get_letohl(tvb, offset + 4); /* manually offset seconds */
                already_processed_fractime = 1;
                gps_time_size = 8;
            }
            proto_tree_add_time(ppi_gps_tree, hf_ppi_gps_gpstime, tvb, offset, gps_time_size, &gps_timestamp);
            offset += gps_time_size;
            length_remaining -= gps_time_size;
            break;
        case  PPI_GEOTAG_FRACTIONALTIME:
            if (length_remaining < 4)
                break;
            if (already_processed_fractime)
                break;
            break;
        case  PPI_GEOTAG_EPH:
            if (length_remaining < 4)
                break;
            t_herr = tvb_get_letohl(tvb, offset);
            eph  =  ppi_fixed3_6_to_gdouble(t_herr);
            proto_tree_add_double(ppi_gps_tree, hf_ppi_gps_eph, tvb, offset, 4, eph);
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_GEOTAG_EPV:
            if (length_remaining < 4)
                break;
            t_verr = tvb_get_letohl(tvb, offset);
            epv  =  ppi_fixed3_6_to_gdouble(t_verr);
            proto_tree_add_double(ppi_gps_tree, hf_ppi_gps_epv, tvb, offset, 4, epv);
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_GEOTAG_EPT:
            if (length_remaining < 4)
                break;
            t_terr = tvb_get_letohl(tvb, offset);
            ept  =  ppi_ns_counter_to_gdouble(t_terr);
            proto_tree_add_double(ppi_gps_tree, hf_ppi_gps_ept, tvb, offset, 4, ept);
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_GEOTAG_DESCRIPTIONSTR:
            if (length_remaining < 32)
                break;
            if (tree)
            {
                /* proto_tree_add_item(ppi_gps_tree, hf_ppi_gps_descstr, tvb, offset, 32,  ENC_ASCII|ENC_NA); */
                curr_str = tvb_format_stringzpad(tvb, offset, 32); /* need to append_text this */
                proto_tree_add_string(ppi_gps_tree, hf_ppi_gps_descstr, tvb, offset, 32, curr_str);
                proto_item_append_text(gps_line, " (%s)", curr_str);
            }
            offset+=32;
            length_remaining-=32;
            break;
        case  PPI_GEOTAG_APPID:
            if (length_remaining < 4)
                break;
            t_appspecific_num  = tvb_get_letohl(tvb, offset); /* application specific parsers may switch on this later */
            proto_tree_add_uint(ppi_gps_tree, hf_ppi_gps_appspecific_num, tvb, offset, 4, t_appspecific_num);
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_GEOTAG_APPDATA:
            if (length_remaining < 60)
                break;
            proto_tree_add_item(ppi_gps_tree, hf_ppi_gps_appspecific_data, tvb, offset, 60,  ENC_NA);
            offset+=60;
            length_remaining-=60;
            break;

            /*
             * This indicates a field whose size we do not know, so we cannot proceed.
             */
        default:
            next_present = 0; /* this will terminate the loop */
            expert_add_info_format(pinfo, pt, &ei_ppi_gps_present_bit,
                 "Error: PPI-GEOLOCATION-GPS: unknown bit (%d) set in present field.", bit);
            continue;
        } /* switch (bit) */

    } /* (for present..)*/

    /* If there was any post processing of the elements, it could happen here. */
    return tvb_captured_length(tvb);
}

void
proto_register_ppi_gps(void) {
    /* The following array initializes those header fields declared above to the values displayed */
    static hf_register_info hf[] = {
        { &hf_ppi_gps_version,
          { "Header revision", "ppi_gps.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Version of ppi_gps header format", HFILL } },
        { &hf_ppi_gps_pad,
          { "Header pad", "ppi_gps.pad",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Padding", HFILL } },
        { &hf_ppi_gps_length,
          { "Header length", "ppi_gps.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of header including version, pad, length and data fields", HFILL } },
        { &hf_ppi_gps_present, /* these flag fields are composed of a uint32 on the display */
          { "Present", "ppi_gps.present",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Bitmask indicating which fields are present", HFILL } },

        /* Boolean 'present' flags */
        { &hf_ppi_gps_present_gpsflags_flags, /* followed by a lot of booleans */
          { "GPSFlags", "ppi_gps.present.gpsflagss",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_GPSFLAGS,
            "32-bit bitmask indicating type of GPS fix (GPS/INS/software/etc)", HFILL } },
        { &hf_ppi_gps_present_lat,
          { "Lat", "ppi_gps.present.lat",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_LAT,
            "Specifies if the latitude field is present", HFILL } },

        { &hf_ppi_gps_present_lon,
          { "Lon", "ppi_gps.present.lon",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_LON,
            "Specifies if the longitude field is present", HFILL } },

        { &hf_ppi_gps_present_alt,
          { "Alt", "ppi_gps.present.alt",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_ALT,
            "Specifies if the altitude field is present", HFILL } },

        { &hf_ppi_gps_present_alt_gnd,
          { "Alt-gnd", "ppi_gps.present.alt_gnd",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_ALT_G,
            "Specifies if the altitude-g field is present", HFILL } },

        { &hf_ppi_gps_present_gpstime,
          { "GPStime", "ppi_gps.present.gpstime",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_GPSTIME,
            "Specifies if the GPS time field is present", HFILL } },


        { &hf_ppi_gps_present_fractime,
          { "fractime", "ppi_gps.present.fractime",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_FRACTIME,
            "Specifies if the fractional time field is present", HFILL } },


        { &hf_ppi_gps_present_eph,
          { "error_h", "ppi_gps.present.eph",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_EPH,
            "Specifies if the horizontal error field is present (eph)", HFILL } },

        { &hf_ppi_gps_present_epv,
          { "error_v", "ppi_gps.present.epv",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_EPV,
            "Specifies if the vertical error field present (epv)", HFILL } },


        { &hf_ppi_gps_present_ept,
          { "error_t", "ppi_gps.present.ept",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_EPT,
            "Specifies if the estimated time error field is present (ept)", HFILL } },

        { &hf_ppi_gps_present_descr,
          { "Description", "ppi_gps.present.descr",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_DESCRSTR,
            "Specifies if the (ASCII) description is present", HFILL } },

        { &hf_ppi_gps_present_appspecific_num,
          { "AppId", "ppi_gps.present.appid",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_APPID,
            "Specifies if the application specific field id is present", HFILL } },

        { &hf_ppi_gps_present_appspecific_data,
          { "AppData", "ppi_gps.present.appdata",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_APPDATA,
            "Specifies if the application specific data field  is present", HFILL } },

        { &hf_ppi_gps_present_ext,
          { "Ext", "ppi_gps.present.ext",
            FT_BOOLEAN, 32, NULL, PPI_GPS_MASK_EXT,
            "Specifies if there are any extensions to the header present", HFILL } },

        /* ---Now we get to the actual data fields--- */

        { &hf_ppi_gps_gpsflags_flags,
          { "GPSFlags", "ppi_gps.gpsflags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Bitmask indicating GPS/INS/manual fix", HFILL } },
        { &hf_ppi_gps_lat,
          { "Latitude", "ppi_gps.lat",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Latitude packet was received at", HFILL } },
        { &hf_ppi_gps_lon,
          { "Longitude", "ppi_gps.lon",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Longitude packet was received at", HFILL } },
        { &hf_ppi_gps_alt,
          { "Altitude", "ppi_gps.alt",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Altitude packet was received at", HFILL } },
        { &hf_ppi_gps_alt_gnd,
          { "Altitude_gnd", "ppi_gps.alt_gnd",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Altitude packet was received at (relative to ground)", HFILL } },
        { &hf_ppi_gps_gpstime,
          { "GPSTimestamp", "ppi_gps.gpstime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            "GPSTimestamp packet was received at", HFILL } },
#if 0
        { &hf_ppi_gps_fractime,
          { "fractional Timestamp", "ppi_gps.fractime",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "fractional GPSTimestamp packet was received at", HFILL } },
#endif
        { &hf_ppi_gps_eph,
          { "Horizontal Error (m)", "ppi_gps.eph",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Horizontal margin of error (meters)", HFILL } },
        { &hf_ppi_gps_epv,
          { "Vertical Error (m)", "ppi_gps.epv",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Vertical margin of error (meters)", HFILL } },
        { &hf_ppi_gps_ept,
          { "Time Error (s)", "ppi_gps.ept",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Time margin of error (secs)", HFILL } },
        { &hf_ppi_gps_descstr,
          { "Description", "ppi_gps.descr",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ppi_gps_appspecific_num,
          { "Application Specific id", "ppi_gps.appid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ppi_gps_appspecific_data,
          { "Application specific data", "ppi_gps.appdata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },

        /* --- moving on to the 'FixType' flags --- */
#define PPI_GPS_GPSFLAGS_FLAG0_NOFIX     0x00000001
#define PPI_GPS_GPSFLAGS_FLAG1_GPS       0x00000002
#define PPI_GPS_GPSFLAGS_FLAG2_DIFFGPS   0x00000004
#define PPI_GPS_GPSFLAGS_FLAG3_PPS       0x00000008
#define PPI_GPS_GPSFLAGS_FLAG4_RTK       0x00000010
#define PPI_GPS_GPSFLAGS_FLAG5_FLOATRTK  0x00000020
#define PPI_GPS_GPSFLAGS_FLAG6_DEAD_RECK 0x00000040
#define PPI_GPS_GPSFLAGS_FLAG7_MANUAL    0x00000080
#define PPI_GPS_GPSFLAGS_FLAG8_SIM       0x00000100
        { &hf_ppi_gps_gpsflags_flag0_nofix, /* no fix available */
          { "No fix available", "ppi_gps.gpsflagss.nofix",
            FT_BOOLEAN, 32, NULL, PPI_GPS_GPSFLAGS_FLAG0_NOFIX,
            NULL, HFILL } },
        { &hf_ppi_gps_gpsflags_flag1_gpsfix, /* GPSfix available */
          { "GPS provided fix", "ppi_gps.gpsflagss.gps",
            FT_BOOLEAN, 32, NULL, PPI_GPS_GPSFLAGS_FLAG1_GPS,
            NULL, HFILL } },
        { &hf_ppi_gps_gpsflags_flag2_diffgps, /* Differential GPS fix  available */
          { "Differential GPS provided fix", "ppi_gps.gpsflagss.diffgps",
            FT_BOOLEAN, 32, NULL, PPI_GPS_GPSFLAGS_FLAG2_DIFFGPS,
            NULL, HFILL } },
        { &hf_ppi_gps_gpsflags_flag3_PPS, /* PPS fix  */
          { "PPS fix", "ppi_gps.gpsflagss.pps",
            FT_BOOLEAN, 32, NULL, PPI_GPS_GPSFLAGS_FLAG3_PPS,
            NULL, HFILL } },
        { &hf_ppi_gps_gpsflags_flag4_RTK, /* RTK fix*/
          { "RTK fix", "ppi_gps.gpsflagss.rtk",
            FT_BOOLEAN, 32, NULL, PPI_GPS_GPSFLAGS_FLAG4_RTK,
            NULL, HFILL } },
        { &hf_ppi_gps_gpsflags_flag5_floatRTK, /*float RTK */
          { "floatRTK fix", "ppi_gps.gpsflagss.frtk",
            FT_BOOLEAN, 32, NULL, PPI_GPS_GPSFLAGS_FLAG5_FLOATRTK,
            NULL, HFILL } },
        { &hf_ppi_gps_gpsflags_flag6_dead_reck, /*dead reckoning */
          { "dead reckoning fix", "ppi_gps.gpsflagss.dead_reck",
            FT_BOOLEAN, 32, NULL, PPI_GPS_GPSFLAGS_FLAG6_DEAD_RECK,
            NULL, HFILL } },
        { &hf_ppi_gps_gpsflags_flag7_manual, /* manual */
          { "manual fix", "ppi_gps.gpsflagss.manual",
            FT_BOOLEAN, 32, NULL, PPI_GPS_GPSFLAGS_FLAG7_MANUAL,
            NULL, HFILL } },
        { &hf_ppi_gps_gpsflags_flag8_sim, /* simulation */
          { "simulated fix", "ppi_gps.gpsflagss.simulation",
            FT_BOOLEAN, 32, NULL, PPI_GPS_GPSFLAGS_FLAG8_SIM,
            NULL, HFILL } },

    };
    static gint *ett[] = {
        &ett_ppi_gps,
        &ett_ppi_gps_present,
        &ett_ppi_gps_gpsflags_flags
    };

    static ei_register_info ei[] = {
        { &ei_ppi_gps_present_bit, { "ppi_gps.present.unknown_bit", PI_PROTOCOL, PI_WARN, "Error: PPI-GEOLOCATION-GPS: unknown bit set in present field.", EXPFILL }},
        { &ei_ppi_gps_version, { "ppi_gps.version.unsupported", PI_PROTOCOL, PI_WARN, "Invalid version", EXPFILL }},
        { &ei_ppi_gps_length, { "ppi_gps.length.invalid", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
    };

    expert_module_t* expert_ppi_gps;

    proto_ppi_gps = proto_register_protocol("PPI Geotagging GPS tag decoder", "PPI GPS Decoder", "ppi_gps");
    proto_register_field_array(proto_ppi_gps, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ppi_gps = expert_register_protocol(proto_ppi_gps);
    expert_register_field_array(expert_ppi_gps, ei, array_length(ei));
    register_dissector("ppi_gps", dissect_ppi_gps, proto_ppi_gps);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
