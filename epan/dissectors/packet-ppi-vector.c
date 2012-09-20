/* packet-ppi-vector.c
 * Routines for PPI-GEOLOCATION-VECTOR  dissection
 * Copyright 2010, Harris Corp, jellch@harris.com
 *
 * See
 *
 *    http://new.11mercenary.net/~johnycsh/ppi_geolocation_spec/
 *
 * for specifications.
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

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include "packet-ppi-geolocation-common.h"

enum ppi_vector_type {
    PPI_VECTOR_VFLAGS       =  0,
    PPI_VECTOR_VCHARS       =  1,
    PPI_VECTOR_ROTX         =  2,
    PPI_VECTOR_ROTY         =  3,
    PPI_VECTOR_ROTZ         =  4,

    /* V1 */
    PPI_VECTOR_OFF_R        =  5,
    PPI_VECTOR_OFF_F        =  6,
    PPI_VECTOR_OFF_U        =  7,
    PPI_VECTOR_VEL_R        =  8,
    PPI_VECTOR_VEL_F        =  9,
    PPI_VECTOR_VEL_U        = 10,
    PPI_VECTOR_VEL_T        = 11,
    PPI_VECTOR_ACC_R        = 12,
    PPI_VECTOR_ACC_F        = 13,
    PPI_VECTOR_ACC_U        = 14,
    PPI_VECTOR_ACC_T        = 15,

    /* V2 */
    PPI_VECTOR_OFF_X        =  5,
    PPI_VECTOR_OFF_Y        =  6,
    PPI_VECTOR_OFF_Z        =  7,

    PPI_VECTOR_ERR_ROT      = 16,
    PPI_VECTOR_ERR_OFF      = 17,

    /* V1 only */
    PPI_VECTOR_ERR_VEL      = 18,
    PPI_VECTOR_ERR_ACC      = 19,

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

/* V1 */
#define PPI_VECTOR_MASK_OFF_R       0x00000020
#define PPI_VECTOR_MASK_OFF_F       0x00000040
#define PPI_VECTOR_MASK_OFF_U       0x00000080
#define PPI_VECTOR_MASK_VEL_R       0x00000100
#define PPI_VECTOR_MASK_VEL_F       0x00000200
#define PPI_VECTOR_MASK_VEL_U       0x00000400
#define PPI_VECTOR_MASK_VEL_T       0x00000800
#define PPI_VECTOR_MASK_ACC_R       0x00001000
#define PPI_VECTOR_MASK_ACC_F       0x00002000
#define PPI_VECTOR_MASK_ACC_U       0x00004000
#define PPI_VECTOR_MASK_ACC_T       0x00008000

/* V2 */
#define PPI_VECTOR_MASK_OFF_X       0x00000020
#define PPI_VECTOR_MASK_OFF_Y       0x00000040
#define PPI_VECTOR_MASK_OFF_Z       0x00000080

#define PPI_VECTOR_MASK_ERR_ROT     0x00010000
#define PPI_VECTOR_MASK_ERR_OFF     0x00020000

/* V1 only */
#define PPI_VECTOR_MASK_ERR_VEL     0x00040000
#define PPI_VECTOR_MASK_ERR_ACC     0x00080000

#define PPI_VECTOR_MASK_DESCSTR     0x10000000  /* 28 */
#define PPI_VECTOR_MASK_APPID       0x20000000  /* 29 */
#define PPI_VECTOR_MASK_APPDATA     0x40000000  /* 30 */
#define PPI_VECTOR_MASK_EXT         0x80000000  /* 31 */

/*  There are currently only three vector flags.
 *  These control the units/interpreration of a vector
 */
#define PPI_VECTOR_VFLAGS_DEFINES_FORWARD   0x00000001

/* V1 */
#define PPI_VECTOR_VFLAGS_ROTS_ABSOLUTE     0x00000002
#define PPI_VECTOR_VFLAGS_OFFSETS_FROM_GPS  0x00000004

/* V2 */
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

/* V1 */
static int hf_ppi_vector_off_r = -1;
static int hf_ppi_vector_off_f = -1;
static int hf_ppi_vector_off_u = -1;
static int hf_ppi_vector_vel_r = -1;
static int hf_ppi_vector_vel_f = -1;
static int hf_ppi_vector_vel_u = -1;
static int hf_ppi_vector_vel_t = -1;
static int hf_ppi_vector_acc_r = -1;
static int hf_ppi_vector_acc_f = -1;
static int hf_ppi_vector_acc_u = -1;
static int hf_ppi_vector_acc_t = -1;

/* V2 */
static int hf_ppi_vector_off_x = -1;
static int hf_ppi_vector_off_y = -1;
static int hf_ppi_vector_off_z = -1;

static int hf_ppi_vector_err_rot= -1;
static int hf_ppi_vector_err_off= -1;

/* V1 only */
static int hf_ppi_vector_err_vel= -1;
static int hf_ppi_vector_err_acc= -1;

static int hf_ppi_vector_descstr= -1;
static int hf_ppi_vector_appspecific_num = -1;
static int hf_ppi_vector_appspecific_data = -1;

/* "Present" flags */
static int hf_ppi_vector_present_vflags = -1;
static int hf_ppi_vector_present_vchars = -1;
static int hf_ppi_vector_present_val_x = -1;
static int hf_ppi_vector_present_val_y = -1;
static int hf_ppi_vector_present_val_z = -1;

/* V1 */
static int hf_ppi_vector_present_off_r = -1;
static int hf_ppi_vector_present_off_f = -1;
static int hf_ppi_vector_present_off_u = -1;
static int hf_ppi_vector_present_vel_r = -1;
static int hf_ppi_vector_present_vel_f = -1;
static int hf_ppi_vector_present_vel_u = -1;
static int hf_ppi_vector_present_vel_t = -1;
static int hf_ppi_vector_present_acc_r = -1;
static int hf_ppi_vector_present_acc_f = -1;
static int hf_ppi_vector_present_acc_u = -1;
static int hf_ppi_vector_present_acc_t = -1;

/* V2 */
static int hf_ppi_vector_present_off_x = -1;
static int hf_ppi_vector_present_off_y = -1;
static int hf_ppi_vector_present_off_z = -1;

static int hf_ppi_vector_present_err_rot = -1;
static int hf_ppi_vector_present_err_off = -1;

/* V1 only */
static int hf_ppi_vector_present_err_vel = -1;
static int hf_ppi_vector_present_err_acc = -1;

static int hf_ppi_vector_present_descstr= -1;
static int hf_ppi_vector_presenappsecific_num = -1;
static int hf_ppi_vector_present_appspecific_data = -1;
static int hf_ppi_vector_present_ext = -1;

/* VectorFlags bits */
/* There are currently only three bits and two fields defined in vector flags.
*  These control the units/interpretation of a vector
*/
static int hf_ppi_vector_vflags_defines_forward = -1; /* bit 0 */

/* V1 */
static int hf_ppi_vector_vflags_rots_absolute = -1; /* different ways to display the same bit, hi or low */
static int hf_ppi_vector_vflags_offsets_from_gps = -1; /* these are different ways to display the same bit, hi or low */

/* V2 */
static int hf_ppi_vector_vflags_relative_to= -1; /* bits 1 and 2 */

/*  There are currently eight vector characteristics.
*  These are purely descriptive (no mathematical importance)
*/
static int hf_ppi_vector_vchars_antenna = -1;
static int hf_ppi_vector_vchars_dir_of_travel = -1;
static int hf_ppi_vector_vchars_front_of_veh = -1;

/* V2 only */
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


/* We want to abbreviate this field into a single line. Does so without any string maniuplation */
static void
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

static void
dissect_ppi_vector_v1(tvbuff_t *tvb, int offset, gint length_remaining, proto_tree *ppi_vector_tree)
{
    proto_tree *vectorflags_tree = NULL;
    proto_tree *vectorchars_tree = NULL;
    proto_tree *my_pt, *pt, *present_tree = NULL;
    proto_item *ti;

    /* bits */
    int bit;
    guint32 present, next_present;
    /* values actually read out, for displaying */
    gdouble rot_x, rot_y, rot_z;
    gdouble off_r, off_f, off_u;
    gdouble vel_r, vel_f, vel_u, vel_t;
    gdouble acc_r, acc_f, acc_u, acc_t = 0;
    gdouble err_rot, err_off, err_vel, err_acc;
    guint32 appsecific_num; /* appdata parser should add a subtree based on this value */
    guint32 flags=0, chars=0;

    /* temporary, conversion values */
    guint32 t_val;

    present = tvb_get_letohl(tvb, offset+4);
    /* Subtree for the "present flags" bitfield. */
    if (ppi_vector_tree) {
        pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_present,
                                 tvb, offset + 4, 4, present);
        present_tree = proto_item_add_subtree(pt, ett_ppi_vector_present);

        proto_tree_add_item(present_tree, hf_ppi_vector_present_vflags, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vchars, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_val_x, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_val_y, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_val_z, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_r, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_f, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_u, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vel_r, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vel_f, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vel_u, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vel_t, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_acc_r, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_acc_f, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_acc_u, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_acc_t, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_rot, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_off, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_vel, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_acc, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_descstr, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_presenappsecific_num, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_appspecific_data, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_ext, tvb, 4, 4, ENC_LITTLE_ENDIAN);
    }
    offset += PPI_GEOBASE_MIN_HEADER_LEN;
    length_remaining -= PPI_GEOBASE_MIN_HEADER_LEN;


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
            flags =  tvb_get_letohl(tvb, offset);
            if (ppi_vector_tree) {
                my_pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_vflags, tvb, offset , 4, flags);
                vectorflags_tree= proto_item_add_subtree(my_pt, ett_ppi_vectorflags);

                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_defines_forward, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_rots_absolute, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_offsets_from_gps, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_VCHARS:
            if (length_remaining < 4)
                break;
            chars =  tvb_get_letohl(tvb, offset);
            if (ppi_vector_tree) {
                my_pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_vchars, tvb, offset , 4, chars);
                vectorchars_tree= proto_item_add_subtree(my_pt, ett_ppi_vectorchars);

                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_antenna, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_dir_of_travel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_front_of_veh, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_gps_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_ins_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_compass_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_accelerometer_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_human_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ROTX:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            rot_x = ppi_fixed3_6_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_rot_x, tvb, offset, 4, rot_x);
                if (flags &  PPI_VECTOR_VFLAGS_ROTS_ABSOLUTE)
                    proto_item_append_text(ti, " Degrees (Absolute)");
                else
                    proto_item_append_text(ti, " Degrees (Rel to forward)");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ROTY:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            rot_y = ppi_fixed3_6_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_rot_y, tvb, offset, 4, rot_y);
                if (flags &  PPI_VECTOR_VFLAGS_ROTS_ABSOLUTE)
                    proto_item_append_text(ti, " Degrees (Absolute)");
                else
                    proto_item_append_text(ti, " Degrees (Rel to forward)");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ROTZ:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            rot_z = ppi_fixed3_6_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_rot_z, tvb, offset, 4, rot_z);
                if (flags &  PPI_VECTOR_VFLAGS_ROTS_ABSOLUTE)
                    proto_item_append_text(ti, " Degrees (Absolute) ");
                else
                    proto_item_append_text(ti, " Degrees (Rel to forward)");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_OFF_R:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            off_r = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_off_r, tvb, offset, 4, off_r);
                if (flags &  PPI_VECTOR_VFLAGS_OFFSETS_FROM_GPS)
                    proto_item_append_text(ti, " m from Curr_GPS");
                else
                    proto_item_append_text(ti, " m from Curr_Pos");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_OFF_F:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            off_f = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_off_f, tvb, offset, 4, off_f);
                if (flags &  PPI_VECTOR_VFLAGS_OFFSETS_FROM_GPS)
                    proto_item_append_text(ti, " m from Curr_GPS");
                else
                    proto_item_append_text(ti, " m from Curr_Pos");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_OFF_U:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            off_u = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_off_u, tvb, offset, 4, off_u);
                if (flags &  PPI_VECTOR_VFLAGS_OFFSETS_FROM_GPS)
                    proto_item_append_text(ti, " m from Curr_GPS");
                else
                    proto_item_append_text(ti, " m from Curr_Pos");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_VEL_R:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            vel_r = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_vel_r, tvb, offset, 4, vel_r);
                proto_item_append_text(ti, " m/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_VEL_F:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            vel_f = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_vel_f, tvb, offset, 4, vel_f);
                proto_item_append_text(ti, " m/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_VEL_U:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            vel_u = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_vel_u, tvb, offset, 4, vel_u);
                proto_item_append_text(ti, " m/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_VEL_T:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            vel_t = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_vel_t, tvb, offset, 4, vel_t);
                proto_item_append_text(ti, " m/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ACC_R:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            acc_r = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_acc_r, tvb, offset, 4, acc_r);
                proto_item_append_text(ti, " (m/s)/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ACC_F:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            acc_f = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_acc_f, tvb, offset, 4, acc_f);
                proto_item_append_text(ti, " (m/s)/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ACC_U:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            acc_u = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_acc_u, tvb, offset, 4, acc_u);
                proto_item_append_text(ti, " (m/s)/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ACC_T:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            acc_t = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_acc_t, tvb, offset, 4, acc_t);
                proto_item_append_text(ti, " (m/s)/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ERR_ROT:
            if (length_remaining < 4)
                break;
            t_val   = tvb_get_letohl(tvb, offset);
            err_rot = ppi_fixed3_6_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_rot, tvb, offset, 4, err_rot);
                proto_item_append_text(ti, " degrees");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ERR_OFF:
            if (length_remaining < 4)
                break;
            t_val   = tvb_get_letohl(tvb, offset);
            err_off = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_off, tvb, offset, 4, err_off);
                proto_item_append_text(ti, " meters");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ERR_VEL:
            if (length_remaining < 4)
                break;
            t_val   = tvb_get_letohl(tvb, offset);
            err_vel = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_vel, tvb, offset, 4, err_vel);
                proto_item_append_text(ti, "m/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ERR_ACC:
            if (length_remaining < 4)
                break;
            t_val   = tvb_get_letohl(tvb, offset);
            err_acc = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_acc, tvb, offset, 4, err_acc);
                proto_item_append_text(ti, " (m/s)/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_DESCSTR:
            if (length_remaining < 32)
                break;
            proto_tree_add_item(ppi_vector_tree, hf_ppi_vector_descstr, tvb, offset, 32, ENC_ASCII|ENC_NA);
            offset+=32;
            length_remaining-=32;
            break;
        case  PPI_VECTOR_APPID:
            if (length_remaining < 4)
                break;
            appsecific_num  = tvb_get_letohl(tvb, offset); /* application specific parsers may switch on this later */
            if (ppi_vector_tree) {
                proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_appspecific_num, tvb, offset, 4, appsecific_num);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_APPDATA:
            if (length_remaining < 60)
                break;
            if (ppi_vector_tree) {
                proto_tree_add_item(ppi_vector_tree, hf_ppi_vector_appspecific_data, tvb, offset, 60,  ENC_NA);
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

    }
}

static void
dissect_ppi_vector_v2(tvbuff_t *tvb, int offset, gint length_remaining, proto_tree *ppi_vector_tree, proto_item *vector_line)
{
    proto_tree *vectorflags_tree = NULL;
    proto_tree *vectorchars_tree = NULL;
    proto_tree *my_pt, *pt, *present_tree = NULL;
    proto_item *ti;

    /* bits */
    int bit;
    guint32 present, next_present;

    /* values actually read out, for displaying */
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

    present = tvb_get_letohl(tvb, offset+4);
    /* Subtree for the "present flags" bitfield. */
    if (ppi_vector_tree) {
        pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_present,
                                 tvb, offset + 4, 4, present);
        present_tree = proto_item_add_subtree(pt, ett_ppi_vector_present);

        proto_tree_add_item(present_tree, hf_ppi_vector_present_vflags, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vchars, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_val_x, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_val_y, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_val_z, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_x, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_y, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_z, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_rot, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_off, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_descstr, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_presenappsecific_num, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_appspecific_data, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_ext, tvb, 4, 4, ENC_LITTLE_ENDIAN);
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
            if (ppi_vector_tree) {
                my_pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_vflags, tvb, offset , 4, flags);
                vectorflags_tree= proto_item_add_subtree(my_pt, ett_ppi_vectorflags);

                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_defines_forward, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_relative_to, tvb, offset, 4, ENC_LITTLE_ENDIAN);

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
            if (ppi_vector_tree) {
                my_pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_vchars, tvb, offset , 4, chars);
                vectorchars_tree= proto_item_add_subtree(my_pt, ett_ppi_vectorchars);

                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_antenna, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_dir_of_travel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_front_of_veh, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_angle_of_arrival, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_transmitter_pos, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_gps_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_ins_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_compass_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_accelerometer_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_human_derived, tvb, offset, 4, ENC_LITTLE_ENDIAN);

                annotate_vector_chars(chars, my_pt);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ROTX:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            rot_x = ppi_fixed3_6_to_gdouble(t_val);
            if (ppi_vector_tree) {
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
            rot_y = ppi_fixed3_6_to_gdouble(t_val);
            if (ppi_vector_tree) {
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
            rot_z =  ppi_fixed3_6_to_gdouble(t_val);
            if (ppi_vector_tree) {
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
            off_x = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
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
            off_y = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
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
            off_z = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
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
            t_val   = tvb_get_letohl(tvb, offset);
            err_rot = ppi_fixed3_6_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_rot, tvb, offset, 4, err_rot);
                proto_item_append_text(ti, " Degrees");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ERR_OFF:
            if (length_remaining < 4)
                break;
            t_val   = tvb_get_letohl(tvb, offset);
            err_off = ppi_fixed6_4_to_gdouble(t_val);
            if (ppi_vector_tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_off, tvb, offset, 4, err_off);
                proto_item_append_text(ti, " Meters");
            }
            offset+=4;
            length_remaining-=4;
            break;

        case  PPI_VECTOR_DESCSTR:
            if (length_remaining < 32)
                break;
            if (ppi_vector_tree)
            {
                /* proto_tree_add_item(ppi_vector_tree, hf_ppi_vector_descstr, tvb, offset, 32, ENC_ASCII|ENC_NA); */
                curr_str = tvb_format_stringzpad(tvb, offset, 32); /* need to append_text this */
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
            if (ppi_vector_tree) {
                proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_appspecific_num, tvb, offset, 4, appsecific_num);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_APPDATA:
            if (length_remaining < 60)
                break;
            if (ppi_vector_tree) {
                proto_tree_add_item(ppi_vector_tree, hf_ppi_vector_appspecific_data, tvb, offset, 60,  ENC_NA);
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
    }
    /* Append the RelativeTo string we computed up top */
    proto_item_append_text (vector_line, " RelativeTo: %s", relativeto_str);
}

static void
dissect_ppi_vector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *ppi_vector_tree = NULL;
    proto_item *ti = NULL;
    proto_item *vector_line = NULL;
    gint length_remaining;
    int offset = 0;

    /* values actually read out, for displaying */
    guint32 version;
    guint length;

    /* Clear out stuff in the info column */
        col_clear(pinfo->cinfo,COL_INFO);

    /* pull out the first three fields of the BASE-GEOTAG-HEADER */
    version = tvb_get_guint8(tvb, offset);
    length  = tvb_get_letohs(tvb, offset+2);

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
                            tvb, offset + 1, 1, ENC_NA);
        ti = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_length,
                                 tvb, offset + 2, 2, length);
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
            proto_item_append_text(ti, " (invalid - minimum length is %d)", PPI_GEOBASE_MIN_HEADER_LEN);
        return;
    }

    switch (version) {

    case 1:
        dissect_ppi_vector_v1(tvb, offset, length_remaining, ppi_vector_tree);
        break;

    case 2:
        /* perform max length sanity checking */
        if (length > PPI_VECTOR_MAXTAGLEN ) {
            if (tree)
                proto_item_append_text(ti, " (invalid - maximum length is %d\n)", PPI_VECTOR_MAXTAGLEN);
            return;
        }
        dissect_ppi_vector_v2(tvb, offset, length_remaining, ppi_vector_tree, vector_line);
        break;

    default:
        if (tree) {
            proto_tree_add_text(ppi_vector_tree, tvb, offset + 4, -1,
                "Data for unknown version");
        }
        break;
    }
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
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Bitmask indicating which fields are present", HFILL } },

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


        /* V1 */
        { &hf_ppi_vector_present_off_r,
          { "Offset_R", "ppi_vector.present.off_r",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_OFF_R,
            "Specifies if the offset-right field  is present", HFILL } },

        { &hf_ppi_vector_present_off_f,
          { "Offset_F", "ppi_vector.present.off_f",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_OFF_F,
            "Specifies if the offset-forward  field  is present", HFILL } },

        { &hf_ppi_vector_present_off_u,
          { "Offset_U", "ppi_vector.present.off_u",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_OFF_U,
            "Specifies if the offset-up  field  is present", HFILL } },

        { &hf_ppi_vector_present_vel_r,
          { "Velocity_R", "ppi_vector.present.vel_r",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_VEL_R,
            "Specifies if the velocity-right field  is present", HFILL } },

        { &hf_ppi_vector_present_vel_f,
          { "Velocity_F", "ppi_vector.present.vel_f",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_VEL_F,
            "Specifies if the velocity-forward  field  is present", HFILL } },

        { &hf_ppi_vector_present_vel_u,
          { "Velocity_U", "ppi_vector.present.vel_u",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_VEL_U,
            "Specifies if the velocity-up  field  is present", HFILL } },
        { &hf_ppi_vector_present_vel_t,
          { "Velocity_T", "ppi_vector.present.vel_t",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_VEL_T,
            "Specifies if the total velocity field  is present", HFILL } },

        { &hf_ppi_vector_present_acc_r,
          { "Acceleration_R", "ppi_vector.present.acc_r",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ACC_R,
            "Specifies if the accel-right field  is present", HFILL } },

        { &hf_ppi_vector_present_acc_f,
          { "Acceleration_F", "ppi_vector.present.acc_f",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ACC_F,
            "Specifies if the accel-forward  field  is present", HFILL } },

        { &hf_ppi_vector_present_acc_u,
          { "Acceleration_U", "ppi_vector.present.acc_u",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ACC_U,
            "Specifies if the accel-up  field  is present", HFILL } },
        { &hf_ppi_vector_present_acc_t,
          { "Acceleration_T", "ppi_vector.present.acc_t",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ACC_T,
            "Specifies if the total acceleration  field  is present", HFILL } },

        /* V2 */
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


        /* V1 only */
        { &hf_ppi_vector_present_err_vel,
          { "err_vel", "ppi_vector.present.err_vel",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ERR_VEL,
            "Specifies if the velocity  error field is present", HFILL } },

        { &hf_ppi_vector_present_err_acc,
          { "err_acc", "ppi_vector.present.err_acc",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ERR_ACC,
            "Specifies if the acceleration error field is present", HFILL } },


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
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Bitmask indicating coordinate sys, among others, etc", HFILL } },
        { &hf_ppi_vector_vchars,
          { "Vector chars", "ppi_vector.vector_chars",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Bitmask indicating if vector tracks antenna, vehicle, motion, etc", HFILL } },
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

        /* V1 */
        { &hf_ppi_vector_off_r,
          { "Off-r", "ppi_vector.off_r",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Offset right", HFILL } },
        { &hf_ppi_vector_off_f,
          { "Off-f", "ppi_vector.off_f",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Offation forward", HFILL } },
        { &hf_ppi_vector_off_u,
          { "Off-u", "ppi_vector.off_u",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Offset up", HFILL } },
        { &hf_ppi_vector_vel_r,
          { "Vel-r", "ppi_vector.vel_r",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Velocity-right", HFILL } },
        { &hf_ppi_vector_vel_f,
          { "Vel-f", "ppi_vector.vel_f",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Velocity-forward", HFILL } },
        { &hf_ppi_vector_vel_u,
          { "Vel-u", "ppi_vector.vel_u",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Velocity-up", HFILL } },
        { &hf_ppi_vector_vel_t,
          { "Vel-t", "ppi_vector.vel_t",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Velocity-Total", HFILL } },

        { &hf_ppi_vector_acc_r,
          { "Accel-r", "ppi_vector.acc_r",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Acceleration-right", HFILL } },
        { &hf_ppi_vector_acc_f,
          { "Accel-f", "ppi_vector.acc_f",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Acceleration-forward", HFILL } },
        { &hf_ppi_vector_acc_u,
          { "Accel-u", "ppi_vector.acc_u",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Acceleration-up", HFILL } },
        { &hf_ppi_vector_acc_t,
          { "Accel-t", "ppi_vector.acc_t",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Acceleration-Total", HFILL } },

        /* V2 */
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

        /* V1 only */
        { &hf_ppi_vector_err_vel,
          { "Err-Vel", "ppi_vector.err_vel",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Velocity margin of error", HFILL } },
        { &hf_ppi_vector_err_acc,
          { "Err-Accel", "ppi_vector.err_acc",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Acceleration margin of error", HFILL } },

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

        /* V1 */
        { &hf_ppi_vector_vflags_rots_absolute,
          { "Absolute (E/N/U)  rotations", "ppi_vector.vflags.abs_rots",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VFLAGS_ROTS_ABSOLUTE,
            "Rotations are in East/North/Up coord. sys", HFILL } },
        { &hf_ppi_vector_vflags_offsets_from_gps,
          { "Offsets from prev GPS TAG", "ppi_vector.vflags.offsets_from_gps",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VFLAGS_OFFSETS_FROM_GPS,
            "Offsets fied rel. to Curr_Gps", HFILL } },

        /* V2 */
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

        /* V2 only */
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


