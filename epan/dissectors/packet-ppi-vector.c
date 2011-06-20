/* packet-ppi-vector.c
 * Routines for PPI-GEOLOCATION-VECTOR  dissection
 * Copyright 2010, Harris Corp, jellch@harris.com
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/ptvcursor.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include "packet-ppi-geolocation-common.h"

enum ppi_vector_type {
    PPI_VECTOR_VFLAGS       =  0,
    PPI_VECTOR_VCHARS       =  1,
    PPI_VECTOR_ROTX         =  2,
    PPI_VECTOR_ROTY         =  3,
    PPI_VECTOR_ROTZ         =  4,
    PPI_VECTOR_OFF_X        =  5,
    PPI_VECTOR_OFF_Y        =  6,
    PPI_VECTOR_OFF_Z        =  7,

    PPI_VECTOR_ERR_ROT      = 16,
    PPI_VECTOR_ERR_OFF      = 17,

    PPI_VECTOR_DESCSTR      = 28,
    PPI_VECTOR_APPID        = 29,
    PPI_VECTOR_APPDATA      = 30,
    PPI_VECTOR_EXT          = 31
};
#define PPI_VECTOR_MAXTAGLEN 144 /* increase as fields are added */

/*  There are currently eight vector characteristics.
 *  These are purely descriptive (no mathematical importance)
 */
#define PPI_VECTOR_VCHARS_ANTENNA                0x00000001
#define PPI_VECTOR_VCHARS_DIR_OF_TRAVEL          0x00000002
#define PPI_VECTOR_VCHARS_FRONT_OF_VEH           0x00000004
#define PPI_VECTOR_VCHARS_AOA                    0x00000008
#define PPI_VECTOR_VCHARS_TRANSMITTER_POS        0x00000010

#define PPI_VECTOR_VCHARS_GPS_DERIVED            0x00000100
#define PPI_VECTOR_VCHARS_INS_DERIVED            0x00000200
#define PPI_VECTOR_VCHARS_COMPASS_DERIVED        0x00000400
#define PPI_VECTOR_VCHARS_ACCELEROMETER_DERIVED  0x00000800
#define PPI_VECTOR_VCHARS_HUMAN_DERIVED          0x00001000

#define PPI_VECTOR_MASK_VFLAGS      0x00000001
#define PPI_VECTOR_MASK_VCHARS      0x00000002
#define PPI_VECTOR_MASK_ROTX        0x00000004
#define PPI_VECTOR_MASK_ROTY        0x00000008
#define PPI_VECTOR_MASK_ROTZ        0x00000010
#define PPI_VECTOR_MASK_OFF_X       0x00000020
#define PPI_VECTOR_MASK_OFF_Y       0x00000040
#define PPI_VECTOR_MASK_OFF_Z       0x00000080

#define PPI_VECTOR_MASK_ERR_ROT     0x00010000
#define PPI_VECTOR_MASK_ERR_OFF     0x00020000

#define PPI_VECTOR_MASK_DESCSTR     0x10000000  /* 28 */
#define PPI_VECTOR_MASK_APPID       0x20000000  /* 29 */
#define PPI_VECTOR_MASK_APPDATA     0x40000000  /* 30 */
#define PPI_VECTOR_MASK_EXT         0x80000000  /* 31 */

/*  There are currently only three vector flags.
 *  These control the units/interpreration of a vector
 */
#define PPI_VECTOR_VFLAGS_DEFINES_FORWARD   0x00000001
#define PPI_VECTOR_VFLAGS_RELATIVE_TO       0x00000006 /* 2 bits */

/* Values for the two-bit RelativeTo subfield of vflags */
static const value_string relativeto_string[] = {
{ 0x00, "Forward"},
{ 0x01, "Earth"},
{ 0x02, "Current"},
{ 0x03, "Reserved"},
{ 0x00, NULL}
};


/* protocol */
static int proto_ppi_vector = -1;

/* "top" level fields */
static int hf_ppi_vector_version = -1;
static int hf_ppi_vector_pad = -1;
static int hf_ppi_vector_length = -1;
static int hf_ppi_vector_present = -1;
static int hf_ppi_vector_vflags = -1;
static int hf_ppi_vector_vchars = -1;
static int hf_ppi_vector_rot_x = -1;
static int hf_ppi_vector_rot_y = -1;
static int hf_ppi_vector_rot_z = -1;
static int hf_ppi_vector_off_x = -1;
static int hf_ppi_vector_off_y = -1;
static int hf_ppi_vector_off_z = -1;

static int hf_ppi_vector_err_rot= -1;
static int hf_ppi_vector_err_off= -1;
static int hf_ppi_vector_descstr= -1;
static int hf_ppi_vector_appspecific_num = -1;
static int hf_ppi_vector_appspecific_data = -1;

/* "Present" flags */
static int hf_ppi_vector_present_vflags = -1;
static int hf_ppi_vector_present_vchars = -1;
static int hf_ppi_vector_present_val_x = -1;
static int hf_ppi_vector_present_val_y = -1;
static int hf_ppi_vector_present_val_z = -1;
static int hf_ppi_vector_present_off_x = -1;
static int hf_ppi_vector_present_off_y = -1;
static int hf_ppi_vector_present_off_z = -1;
static int hf_ppi_vector_present_err_rot = -1;
static int hf_ppi_vector_present_err_off = -1;
static int hf_ppi_vector_present_descstr= -1;
static int hf_ppi_vector_presenappsecific_num = -1;
static int hf_ppi_vector_present_appspecific_data = -1;
static int hf_ppi_vector_present_ext = -1;

/* VectorFlags bits */
/* There are currently only three bits and two fields defined in vector flags.
*  These control the units/interpreration of a vector
*/
static int hf_ppi_vector_vflags_defines_forward = -1; /* bit 0 */
static int hf_ppi_vector_vflags_relative_to= -1; /* bits 1 and 2 */

/*  There are currently eight vector characteristics.
*  These are purely descriptive (no mathematical importance)
*/
static int hf_ppi_vector_vchars_antenna = -1;
static int hf_ppi_vector_vchars_dir_of_travel = -1;
static int hf_ppi_vector_vchars_front_of_veh = -1;
static int hf_ppi_vector_vchars_angle_of_arrival= -1;
static int hf_ppi_vector_vchars_transmitter_pos= -1;

static int hf_ppi_vector_vchars_gps_derived = -1;
static int hf_ppi_vector_vchars_ins_derived = -1;
static int hf_ppi_vector_vchars_compass_derived = -1;
static int hf_ppi_vector_vchars_accelerometer_derived = -1;
static int hf_ppi_vector_vchars_human_derived = -1;

/*These represent arrow-dropdownthings in the gui */
static gint ett_ppi_vector = -1;
static gint ett_ppi_vector_present = -1;
static gint ett_ppi_vectorflags= -1;
static gint ett_ppi_vectorchars= -1;

static void dissect_ppi_vector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/* We want to abbreviate this field into a single line. Does so without any string maniuplation */
void
annotate_vector_chars(guint32 chars, proto_tree *my_pt)
{
    if (chars & PPI_VECTOR_VCHARS_ANTENNA)
        proto_item_append_text(my_pt, " (Antenna)");
    if (chars & PPI_VECTOR_VCHARS_DIR_OF_TRAVEL)
        proto_item_append_text(my_pt, " (DOT)");
    if (chars & PPI_VECTOR_VCHARS_FRONT_OF_VEH)
        proto_item_append_text(my_pt, " (Front_of_veh)");
    if (chars & PPI_VECTOR_VCHARS_AOA)
        proto_item_append_text(my_pt, " (AOA)");
    if (chars & PPI_VECTOR_VCHARS_TRANSMITTER_POS)
        proto_item_append_text(my_pt, " (TRANSMITTER_POS)");
}
void
dissect_ppi_vector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *ppi_vector_tree = NULL;
    proto_tree *vectorflags_tree = NULL;
    proto_tree *vectorchars_tree = NULL;
    proto_tree *my_pt, *pt, *present_tree = NULL;
    proto_item *ti = NULL;
    proto_item *vector_line = NULL;
    guint length_remaining;
    int offset = 0;

    /* bits */
    int bit;
    guint32 present, next_present;
    /* values actually read out, for displaying */
    guint32 version;
    guint length;
    gchar *curr_str;

    /* these are used to specially handle RelativeTo: */
    guint32  relativeto_int;
    const gchar *relativeto_str= "RelativeTo: Forward"; /* default if vflags is not present*/

    /* normal fields*/
    guint32 flags=0, chars=0;
    gdouble rot_x, rot_y, rot_z;
    gdouble off_x, off_y, off_z;
    gdouble err_rot, err_off;
    guint32  appsecific_num; /* appdata parser should add a subtree based on this value */

    /* temporary, conversion values */
    guint32 t_val;

    /* Clear out stuff in the info column */
    if (check_col(pinfo->cinfo,COL_INFO)) {
        col_clear(pinfo->cinfo,COL_INFO);
    }
    /* pull out the first three fields of the BASE-GEOTAG-HEADER */
    version = tvb_get_guint8(tvb, offset);
    length = tvb_get_letohs(tvb, offset+2);
    present = tvb_get_letohl(tvb, offset+4);

    /* Setup basic column info */
    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "PPI_Vector Capture v%u, Length %u",
                     version, length);

    /* Create the basic dissection tree*/
    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_ppi_vector, tvb, 0, length, "Vector:");
        vector_line = ti; /*save this for later, we will replace it with something more useful*/
        ppi_vector_tree= proto_item_add_subtree(ti, ett_ppi_vector);
        proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_version,
                            tvb, offset, 1, version);
        proto_tree_add_item(ppi_vector_tree, hf_ppi_vector_pad,
                            tvb, offset + 1, 1, FALSE);
        ti = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_length,
                                 tvb, offset + 2, 2, length);
    }

    /*We only support v2 of vectors (v1 deprecated) */
    if (! (version == 2) ) {
        if (tree)
            proto_item_append_text(ti, "invalid version (got %d,  expected 2)", version);
        return;
    }

    /* initialize remaining length */
    length_remaining = length;
    /* minimum length check, should atleast be a fixed-size geotagging-base header*/
    if (length_remaining < PPI_GEOBASE_MIN_HEADER_LEN) {
        /*
         * Base-geotag-header (Radiotap lookalike) is shorter than the fixed-length portion
         * plus one "present" bitset.
         */
        if (tree)
            proto_item_append_text(ti, " (invalid - minimum length is 8)");
        return;
    }

    /* perform max length sanity checking */
    if (length > PPI_VECTOR_MAXTAGLEN ) {
        if (tree)
            proto_item_append_text(ti, "Invalid PPI-Vector length  (got %d, %d max\n)", length, PPI_VECTOR_MAXTAGLEN);
        return;
    }


    if (length_remaining < PPI_GEOBASE_MIN_HEADER_LEN) {
        /*
         * Radiotap header is shorter than the fixed-length portion
         * plus one "present" bitset.
         */
        if (tree)
            proto_item_append_text(ti, " (bogus - minimum length is 8)");
        return;
    }
    /* Subtree for the "present flags" bitfield. */
    if (tree) {
        pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_present,
                                 tvb, offset + 4, 4, present);
        present_tree = proto_item_add_subtree(pt, ett_ppi_vector_present);

        proto_tree_add_item(present_tree, hf_ppi_vector_present_vflags, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vchars, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_val_x, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_val_y, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_val_z, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_x, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_y, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_z, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_rot, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_off, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_descstr, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_presenappsecific_num, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_appspecific_data, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_ext, tvb, 4, 4, TRUE);
    }
    offset += PPI_GEOBASE_MIN_HEADER_LEN;
    length_remaining -= PPI_GEOBASE_MIN_HEADER_LEN;

    /* Before we process any fields, we check what this vector is RelativeTo. */
    /* We do this so this up front so that it displays prominently in the summary line */
    /* Another reason to do this up here is that vflags may not be present (in which case it defaults to 0) */
    /* It also saves us from repeating this logic in any of the individual fields */
    if ( (present & PPI_VECTOR_MASK_VFLAGS) && length_remaining >= 4)
    {
         /*vflags is the first field, */
         flags = tvb_get_letohl(tvb, offset);
         relativeto_int = (flags & (PPI_VECTOR_VFLAGS_RELATIVE_TO)); /* mask out all other bits */
         relativeto_int = relativeto_int >> 1; /*scoot over 1 bit to align with the type string */
         relativeto_str = val_to_str_const (relativeto_int, relativeto_string, "Reserved"); /*re-use that type string up top */
         /* We will append this text to the vector line once all the other fields have processed */

        /* this is important enough to put in vector line */
         if (flags & PPI_VECTOR_VFLAGS_DEFINES_FORWARD)
            proto_item_append_text(vector_line, " (Forward)");

        /* Intentionally dont upset offset, length_remaining. This is taken care of in the normal vflags parser below*/
    }
    else /* No vflags means vlfags defaults to zero. RelativeTo: Forward */
    {
         relativeto_str = " RelativeTo: Forward";
    }
   /*
    * vchars is another field that we want to pre-process simillar to vflags and for the same reasons.
    * we perform seperate length checks depending on if vector_flags is present (which would precede vector_chars)
    */
    if      ( ( (present & PPI_VECTOR_MASK_VFLAGS)) && (present & PPI_VECTOR_MASK_VCHARS) && length_remaining >= 8)
            chars =  tvb_get_letohl(tvb, offset + 4);
    else if ( (!(present & PPI_VECTOR_MASK_VFLAGS)) && (present & PPI_VECTOR_MASK_VCHARS) && length_remaining >= 4)
            chars =  tvb_get_letohl(tvb, offset );

   if (chars)
   {
        /* Mark the most interesting characteristics on the vector dropdown line */
        annotate_vector_chars(chars, vector_line);
        /* Intentionally dont update offset, length_remaining. This is taken care of in the normal vchars parser below*/
    }

    /* Now all of the fixed length, fixed location stuff is over. Loop over the bits */
    for (; present; present = next_present) {
        /* clear the least significant bit that is set */
        next_present = present & (present - 1);
        /* extract the least significant bit that is set */
        bit = BITNO_32(present ^ next_present);
        switch (bit) {
        case  PPI_VECTOR_VFLAGS:
            if (length_remaining < 4)
                break;
            /* flags =  tvb_get_letohl(tvb, offset); */ /* Usually we read this in, but vflags is a special case handled above */
            if (tree) {
                my_pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_vflags, tvb, offset , 4, flags);
                vectorflags_tree= proto_item_add_subtree(my_pt, ett_ppi_vectorflags);

                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_defines_forward, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_relative_to, tvb, offset, 4, TRUE);

                if (flags & PPI_VECTOR_VFLAGS_DEFINES_FORWARD)
                    proto_item_append_text(vectorflags_tree, " (Forward)");

                proto_item_append_text (vectorflags_tree, " RelativeTo: %s", relativeto_str);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_VCHARS:
            if (length_remaining < 4)
                break;
            /* chars =  tvb_get_letohl(tvb, offset); */ /*Usually we read this in, but vchars specially handled above */
            if (tree) {
                my_pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_vchars, tvb, offset , 4, chars);
                vectorchars_tree= proto_item_add_subtree(my_pt, ett_ppi_vectorchars);

                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_antenna, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_dir_of_travel, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_front_of_veh, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_angle_of_arrival, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_transmitter_pos, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_gps_derived, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_ins_derived, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_compass_derived, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_accelerometer_derived, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_human_derived, tvb, offset, 4, TRUE);

                annotate_vector_chars(chars, my_pt);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ROTX:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            rot_x = fixed3_6_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_rot_x, tvb, offset, 4, rot_x);
                proto_item_append_text(ti, " Degrees RelativeTo: %s", relativeto_str);
                proto_item_append_text(vector_line, " Pitch:%3f ", rot_x);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ROTY:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            rot_y = fixed3_6_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_rot_y, tvb, offset, 4, rot_y);
                proto_item_append_text(ti, " Degrees RelativeTo: %s", relativeto_str);
                proto_item_append_text(vector_line, " Roll:%3f ", rot_y);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ROTZ:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            rot_z =  fixed3_6_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_rot_z, tvb, offset, 4, rot_z);
                proto_item_append_text(ti, " Degrees RelativeTo: %s", relativeto_str);
                proto_item_append_text(vector_line, " Heading:%3f ", rot_z);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_OFF_X:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            off_x = fixed6_4_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_off_x, tvb, offset, 4, off_x);
                proto_item_append_text(ti, " Meters RelativeTo: %s", relativeto_str);
                proto_item_append_text(vector_line, " Off-X:%3f ", off_x);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_OFF_Y:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            off_y = fixed6_4_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_off_y, tvb, offset, 4, off_y);
                proto_item_append_text(ti, " Meters RelativeTo: %s", relativeto_str);
                proto_item_append_text(vector_line, " Off-Y:%3f ", off_y);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_OFF_Z:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            off_z = fixed6_4_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_off_z, tvb, offset, 4, off_z);
                proto_item_append_text(ti, " Meters RelativeTo: %s", relativeto_str);
                proto_item_append_text(vector_line, " Off-Z:%3f ", off_z);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ERR_ROT:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            err_rot  = fixed3_6_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_rot, tvb, offset, 4, err_rot);
                proto_item_append_text(ti, " Degrees");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ERR_OFF:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            err_off  = fixed6_4_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_off, tvb, offset, 4, err_off);
                proto_item_append_text(ti, " Meters");
            }
            offset+=4;
            length_remaining-=4;
            break;

        case  PPI_VECTOR_DESCSTR:
            if (length_remaining < 32)
                break;
            if (tree)
            {
                /* proto_tree_add_item(ppi_vector_tree, hf_ppi_vector_descstr, tvb, offset, 32, ENC_NA); */
                curr_str = tvb_format_text(tvb, offset, 32); /* need to append_text this */
                proto_tree_add_string(ppi_vector_tree, hf_ppi_vector_descstr, tvb, offset, 32, curr_str);
                proto_item_append_text(vector_line, " (%s)", curr_str);
            }
            offset+=32;
            length_remaining-=32;
            break;
        case  PPI_VECTOR_APPID:
            if (length_remaining < 4)
                break;
            appsecific_num  = tvb_get_letohl(tvb, offset); /* application specific parsers may switch on this later */
            if (tree) {
                proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_appspecific_num, tvb, offset, 4, appsecific_num);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_APPDATA:
            if (length_remaining < 60)
                break;
            if (tree) {
                proto_tree_add_item(ppi_vector_tree, hf_ppi_vector_appspecific_data, tvb, offset, 60,  FALSE);
            }
            offset+=60;
            length_remaining-=60;
            break;

        default:
            /*
             * This indicates a field whose size we do not
             * know, so we cannot proceed.
             */
            proto_tree_add_text(ppi_vector_tree, tvb, offset, 0,  "Error: PPI-VECTOR: unknown bit (%d) set in present field.\n", bit);
            next_present = 0;
            continue;
        }

    };
    /* Append the RelativeTo string we computed up top */
    proto_item_append_text (vector_line, " RelativeTo: %s", relativeto_str);
    return;
}

void
proto_register_ppi_vector(void)
{
    /* The following array initializes those header fields declared above to the values displayed */
    static hf_register_info hf[] = {
        { &hf_ppi_vector_version,
            { "Header revision", "ppi_vector.version",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Version of ppi_vector header format", HFILL } },
        { &hf_ppi_vector_pad,
          { "Header pad", "ppi_vector.pad",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Padding", HFILL } },
        { &hf_ppi_vector_length,
          { "Header length", "ppi_vector.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of header including version, pad, length and data fields", HFILL } },
        { &hf_ppi_vector_present,
          { "Present", "ppi_vector.present",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask indicating which fields are present", HFILL } },

        /* Boolean 'present' flags */
        { &hf_ppi_vector_present_vflags,
          { "Vector flags", "ppi_vector.present.flags",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_VFLAGS,
            "Specifies if the Vector flags bitfield is present", HFILL } },

        { &hf_ppi_vector_present_vchars,
          { "Vector chararacteristics", "ppi_vector.present.chars",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_VCHARS,
            "Specifies if the Vector chars  bitfield is present", HFILL } },

        { &hf_ppi_vector_present_val_x,
          { "Pitch", "ppi_vector.present.pitch",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ROTX,
            "Specifies if the rotate-x field (pitch) is present", HFILL } },

        { &hf_ppi_vector_present_val_y,
          { "Roll", "ppi_vector.present.roll",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ROTY,
            "Specifies if the rotate-y field (roll) is present", HFILL } },

        { &hf_ppi_vector_present_val_z,
          { "Heading", "ppi_vector.present.heading",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ROTZ,
            "Specifies if the rotate-z field (heading) is present", HFILL } },


        { &hf_ppi_vector_present_off_x,
          { "Offset_R", "ppi_vector.present.off_x",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_OFF_X,
            "Specifies if the offset-x (right/east) field  is present", HFILL } },

        { &hf_ppi_vector_present_off_y,
          { "Offset_F", "ppi_vector.present.off_y",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_OFF_Y,
            "Specifies if the offset-y (forward/north)  field  is present", HFILL } },

        { &hf_ppi_vector_present_off_z,
          { "Offset_U", "ppi_vector.present.off_z",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_OFF_Z,
            "Specifies if the offset-z (up) field  is present", HFILL } },


        { &hf_ppi_vector_present_err_rot,
          { "err_rot", "ppi_vector.present.err_rot",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ERR_ROT,
            "Specifies if the rotation error field is present", HFILL } },

        { &hf_ppi_vector_present_err_off,
          { "err_off", "ppi_vector.present.err_off",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ERR_OFF,
            "Specifies if the offset error field is present", HFILL } },


        { &hf_ppi_vector_present_descstr,
          { "descstr", "ppi_vector.present.descstr",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_DESCSTR,
            "Specifies if the acceleration error field is present", HFILL } },

        { &hf_ppi_vector_presenappsecific_num,
          { "appid", "ppi_vector.present.appid",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_APPID,
            "Specifies if the application specific field id is present", HFILL } },

        { &hf_ppi_vector_present_appspecific_data,
          { "appdata", "ppi_vector.present.appdata",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_APPDATA,
            "Specifies if the application specific data field  is present", HFILL } },

        { &hf_ppi_vector_present_ext,
          { "Ext", "ppi_vector.present.ext",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_EXT,
            "Specifies if there are any extensions to the header present", HFILL } },

        /* Now we get to the actual data fields */
        /* This setups the "Vector fflags" hex dropydown thing */
        { &hf_ppi_vector_vflags,
          { "Vector flags", "ppi_vector.vector_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask indicating coordinate sys, among others, etc", HFILL } },
        { &hf_ppi_vector_vchars,
          { "Vector chars", "ppi_vector.vector_chars",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask indicating if vector tracks antenna, vehicle, motion, etc", HFILL } },
        { &hf_ppi_vector_rot_x,
          { "Pitch   ", "ppi_vector.pitch", /*extra spaces intentional. casuses field values to align*/
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Pitch (Rotation x) packet was received at", HFILL } },
        { &hf_ppi_vector_rot_y,
          { "Roll    ", "ppi_vector.roll", /*extra spaces intentional. casuses field values to align*/
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Roll (Rotation y) packet was received at", HFILL } },
        { &hf_ppi_vector_rot_z,
          { "Heading ", "ppi_vector.heading", /*extra spaces intentional. casuses field values to align*/
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Heading (Rotation z) packet was received at", HFILL } },
        { &hf_ppi_vector_off_x,
          { "Off-x", "ppi_vector.off_x",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Offset-x  (right/east)", HFILL } },
        { &hf_ppi_vector_off_y,
          { "Off-y", "ppi_vector.off_y",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Offset-y (forward/north)", HFILL } },
        { &hf_ppi_vector_off_z,
          { "Off-z", "ppi_vector.off_z",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Offset-z (up)", HFILL } },
        { &hf_ppi_vector_err_rot,
          { "Err-Rot", "ppi_vector.err_rot",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Rotation margin of error", HFILL } },
        { &hf_ppi_vector_err_off,
          { "Err-Off", "ppi_vector.err_off",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Offset margin of  error", HFILL } },

        { &hf_ppi_vector_descstr,
          { "Description", "ppi_vector.descr",
            FT_STRING,  BASE_NONE, NULL, 0x0,
            NULL, HFILL } } ,
        { &hf_ppi_vector_appspecific_num,
          { "Application Specific id", "ppi_vector.appid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Application-specific identifier", HFILL } },
        { &hf_ppi_vector_appspecific_data,
          { "Application specific data", "ppi_vector.appdata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Application-specific data", HFILL } },

        /* Boolean vector flags */
        { &hf_ppi_vector_vflags_defines_forward,
          { "Defines forward", "ppi_vector.vflags.forward",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VFLAGS_DEFINES_FORWARD,
            "Current vector indicates forward frame of reference", HFILL } },
        { &hf_ppi_vector_vflags_relative_to,
          { "RelativeTo", "ppi_vector.vflags.relative_to", FT_UINT32, BASE_HEX, VALS(&relativeto_string), PPI_VECTOR_VFLAGS_RELATIVE_TO,
            "Reference frame vectors are RelativeTo:", HFILL } },

        /* Boolean vector chars */
        { &hf_ppi_vector_vchars_antenna,
          { "Antenna", "ppi_vector.chars.antenna",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_ANTENNA,
            "Vector represents: Antenna", HFILL } },

        { &hf_ppi_vector_vchars_dir_of_travel,
          { "Dir of travel", "ppi_vector.chars.dir_of_travel",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_DIR_OF_TRAVEL,
            "Vector represents: Direction of travel", HFILL } },

        { &hf_ppi_vector_vchars_front_of_veh,
          { "Front of vehicle", "ppi_vector.chars.front_of_veh",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_FRONT_OF_VEH,
            "Vector represents: Front of vehicle", HFILL } },

        { &hf_ppi_vector_vchars_angle_of_arrival,
          { "Angle of arrival", "ppi_vector.chars.angle_of_arr",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_AOA,
            "Vector represents: Angle of Arrival", HFILL } },

        { &hf_ppi_vector_vchars_transmitter_pos,
          { "Transmitter Position", "ppi_vector.chars.transmitter_pos",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_TRANSMITTER_POS,
            "Vector position represents computed transmitter location", HFILL } },

        { &hf_ppi_vector_vchars_gps_derived,
          { "GPS Derived", "ppi_vector.vflags.gps_derived",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_GPS_DERIVED,
            "Vector derived from: gps", HFILL } },

        { &hf_ppi_vector_vchars_ins_derived,
          { "INS Derived", "ppi_vector.vflags.ins_derived",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_INS_DERIVED,
            "Vector derived from: inertial nav system", HFILL } },

        { &hf_ppi_vector_vchars_compass_derived,
          { "Compass derived", "ppi_vector.vflags.compass_derived",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_COMPASS_DERIVED,
            "Vector derived from: compass", HFILL } },

        { &hf_ppi_vector_vchars_accelerometer_derived,
          { "Accelerometer derived", "ppi_vector.vflags.accelerometer_derived",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_ACCELEROMETER_DERIVED,
            "Vector derived from: accelerometer", HFILL } },

        { &hf_ppi_vector_vchars_human_derived,
          { "Human derived", "ppi_vector.vflags.human_derived",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VCHARS_HUMAN_DERIVED,
            "Vector derived from: human", HFILL } },

    };
    static gint *ett[] = {
        &ett_ppi_vector,
        &ett_ppi_vector_present,
        &ett_ppi_vectorflags,
        &ett_ppi_vectorchars
    };

    proto_ppi_vector = proto_register_protocol("PPI vector decoder", "PPI vector Decoder", "ppi_vector");
    proto_register_field_array(proto_ppi_vector, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("ppi_vector", dissect_ppi_vector, proto_ppi_vector);

}
