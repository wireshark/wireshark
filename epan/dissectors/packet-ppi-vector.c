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
    PPI_VECTOR_ERR_ROT      = 16,
    PPI_VECTOR_ERR_OFF      = 17,
    PPI_VECTOR_ERR_VEL      = 18,
    PPI_VECTOR_ERR_ACC      = 19,

    PPI_VECTOR_DESCSTR      = 28,
    PPI_VECTOR_APPID        = 29,
    PPI_VECTOR_APPDATA      = 30,
    PPI_VECTOR_EXT          = 31
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

static int hf_ppi_vector_err_rot= -1;
static int hf_ppi_vector_err_off= -1;
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
static int hf_ppi_vector_present_err_rot = -1;
static int hf_ppi_vector_present_err_off = -1;
static int hf_ppi_vector_present_err_vel = -1;
static int hf_ppi_vector_present_err_acc = -1;
static int hf_ppi_vector_present_descstr= -1;
static int hf_ppi_vector_presenappsecific_num = -1;
static int hf_ppi_vector_present_appspecific_data = -1;
static int hf_ppi_vector_present_ext = -1;

/* VectorFlags bits */
/*  There are currently only three vector flags.
*  These control the units/interpreration of a vector
*/
static int hf_ppi_vector_vflags_defines_forward = -1;
static int hf_ppi_vector_vflags_rots_absolute = -1; /* different ways to display the same bit, hi or low */
static int hf_ppi_vector_vflags_offsets_from_gps = -1; /* these are different ways to display the same bit, hi or low */

/*  There are currently eight vector characteristics.
*  These are purely descriptive (no mathematical importance)
*/
static int hf_ppi_vector_vchars_antenna = -1;
static int hf_ppi_vector_vchars_dir_of_travel = -1;
static int hf_ppi_vector_vchars_front_of_veh = -1;

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

void proto_register_ppi_vector(void) {
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

#define PPI_VECTOR_MASK_VFLAGS      0x00000001
#define PPI_VECTOR_MASK_VCHARS      0x00000002
#define PPI_VECTOR_MASK_ROTX        0x00000004
#define PPI_VECTOR_MASK_ROTY        0x00000008
#define PPI_VECTOR_MASK_ROTZ        0x00000010
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

#define PPI_VECTOR_MASK_ERR_ROT     0x00010000
#define PPI_VECTOR_MASK_ERR_OFF     0x00020000
#define PPI_VECTOR_MASK_ERR_VEL     0x00040000
#define PPI_VECTOR_MASK_ERR_ACC     0x00080000

#define PPI_VECTOR_MASK_DESCSTR     0x10000000  /* 28 */
#define PPI_VECTOR_MASK_APPID       0x20000000  /* 29 */
#define PPI_VECTOR_MASK_APPDATA     0x40000000  /* 30 */
#define PPI_VECTOR_MASK_EXT         0x80000000  /* 31 */

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

        { &hf_ppi_vector_present_err_rot,
          { "err_rot", "ppi_vector.present.err_rot",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ERR_ROT,
            "Specifies if the rotation error field is present", HFILL } },

        { &hf_ppi_vector_present_err_off,
          { "err_off", "ppi_vector.present.err_off",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_MASK_ERR_OFF,
            "Specifies if the offset error field is present", HFILL } },

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
            FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask indicating coordinate sys, among others, etc", HFILL } },
        { &hf_ppi_vector_vchars,
          { "Vector chars", "ppi_vector.vector_chars",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask indicating if vector tracks antenna, vehicle, motion, etc", HFILL } },
        { &hf_ppi_vector_rot_x,
          { "Pitch", "ppi_vector.pitch",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Pitch (Rotation x) packet was receivd at", HFILL } },
        { &hf_ppi_vector_rot_y,
          { "Roll", "ppi_vector.roll",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Roll (Rotation y) packet was receivd at", HFILL } },
        { &hf_ppi_vector_rot_z,
          { "Heading", "ppi_vector.heading",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Heading (Rotation z) packet was receivd at", HFILL } },
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

        { &hf_ppi_vector_err_rot,
          { "Err-Rot", "ppi_vector.err_rot",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Rotation margin of error", HFILL } },
        { &hf_ppi_vector_err_off,
          { "Err-Off", "ppi_vector.err_off",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Offset margin of  error", HFILL } },
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

        /*  There are currently only three vector flags.
         *  These control the units/interpreration of a vector
         */
#define PPI_VECTOR_VFLAGS_DEFINES_FORWARD   0x00000001
#define PPI_VECTOR_VFLAGS_ROTS_ABSOLUTE     0x00000002
#define PPI_VECTOR_VFLAGS_OFFSETS_FROM_GPS  0x00000004
        /* Boolean vector flags */
        { &hf_ppi_vector_vflags_defines_forward,
          { "Defines forward", "ppi_vector.vflags.forward",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VFLAGS_DEFINES_FORWARD,
            "Current vector indicates forward frame of reference", HFILL } },
        { &hf_ppi_vector_vflags_rots_absolute,
          { "Absolute (E/N/U)  rotations", "ppi_vector.vflags.abs_rots",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VFLAGS_ROTS_ABSOLUTE,
            "Rotations are in East/North/Up coord. sys", HFILL } },
        { &hf_ppi_vector_vflags_offsets_from_gps,
          { "Offsets from prev GPS TAG", "ppi_vector.vflags.offsets_from_gps",
            FT_BOOLEAN, 32, NULL, PPI_VECTOR_VFLAGS_OFFSETS_FROM_GPS,
            "Offsets fied rel. to Curr_Gps", HFILL } },

        /*  There are currently eight vector characteristics.
         *  These are purely descriptive (no mathematical importance)
         */
#define PPI_VECTOR_VCHARS_ANTENNA                0x00000001
#define PPI_VECTOR_VCHARS_DIR_OF_TRAVEL          0x00000002
#define PPI_VECTOR_VCHARS_FRONT_OF_VEH           0x00000004

#define PPI_VECTOR_VCHARS_GPS_DERIVED            0x00000100
#define PPI_VECTOR_VCHARS_INS_DERIVED            0x00000200
#define PPI_VECTOR_VCHARS_COMPASS_DERIVED        0x00000400
#define PPI_VECTOR_VCHARS_ACCELEROMETER_DERIVED  0x00000800
#define PPI_VECTOR_VCHARS_HUMAN_DERIVED          0x00001000
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
void dissect_ppi_vector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    proto_tree *ppi_vector_tree = NULL;
    proto_tree *vectorflags_tree = NULL;
    proto_tree *vectorchars_tree = NULL;
    proto_tree *my_pt, *pt, *present_tree = NULL;
    proto_item *ti = NULL;
    guint length_remaining;
    int offset = 0;



    /* bits */
    int bit;
    guint32 present, next_present;
    /* values actually read out, for displaying */
    guint32 version;
    guint length;
    gdouble rot_x, rot_y, rot_z;
    gdouble off_r, off_f, off_u;
    gdouble vel_r, vel_f, vel_u, vel_t;
    gdouble acc_r, acc_f, acc_u, acc_t = 0;
    gdouble err_rot, err_off, err_vel, err_acc;
    char *curr_str; /* for description str */
    guint32  appsecific_num; /* appdata parser should add a subtree based on this value */
    guint32 flags=0, chars=0;

    /* temporary, conversion values */
    guint32 t_val;


    /* Clear out stuff in the info column */
    if (check_col(pinfo->cinfo,COL_INFO)) {
        col_clear(pinfo->cinfo,COL_INFO);
    }
    version = tvb_get_guint8(tvb, offset);
    length = tvb_get_letohs(tvb, offset+2);
    present = tvb_get_letohl(tvb, offset+4);
    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "PPI_Vector Capture v%u, Length %u",
                     version, length);

    /* Dissect the packet */
    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_ppi_vector,
                                            tvb, 0, length, "PPI Vector Header v%u, Length %u", version, length);
        ppi_vector_tree= proto_item_add_subtree(ti, ett_ppi_vector);
        proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_version,
                            tvb, offset, 1, version);
        proto_tree_add_item(ppi_vector_tree, hf_ppi_vector_pad,
                            tvb, offset + 1, 1, FALSE);
        ti = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_length,
                                 tvb, offset + 2, 2, length);
    }
    length_remaining = length;

    /*
     * FIXME: This only works if there is exactly 1 it_present
     *        field in the header
     */
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
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_r, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_f, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_off_u, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vel_r, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vel_f, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vel_u, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_vel_t, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_acc_r, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_acc_f, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_acc_u, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_acc_t, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_rot, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_off, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_vel, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_err_acc, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_descstr, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_presenappsecific_num, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_appspecific_data, tvb, 4, 4, TRUE);
        proto_tree_add_item(present_tree, hf_ppi_vector_present_ext, tvb, 4, 4, TRUE);
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
            if (tree) {
                my_pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_vflags, tvb, offset , 4, flags);
                vectorflags_tree= proto_item_add_subtree(my_pt, ett_ppi_vectorflags);

                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_defines_forward, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_rots_absolute, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorflags_tree, hf_ppi_vector_vflags_offsets_from_gps, tvb, offset, 4, TRUE);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_VCHARS:
            if (length_remaining < 4)
                break;
            chars =  tvb_get_letohl(tvb, offset);
            if (tree) {
                my_pt = proto_tree_add_uint(ppi_vector_tree, hf_ppi_vector_vchars, tvb, offset , 4, chars);
                vectorchars_tree= proto_item_add_subtree(my_pt, ett_ppi_vectorchars);

                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_antenna, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_dir_of_travel, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_front_of_veh, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_gps_derived, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_ins_derived, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_compass_derived, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_accelerometer_derived, tvb, offset, 4, TRUE);
                proto_tree_add_item(vectorchars_tree, hf_ppi_vector_vchars_human_derived, tvb, offset, 4, TRUE);
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
            rot_y = fixed3_6_to_gdouble(t_val);
            if (tree) {
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
            rot_z =  fixed3_6_to_gdouble(t_val);
            if (tree) {
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
            off_r = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            off_f = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            off_u = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            vel_r = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            vel_f = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            vel_u = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            vel_t = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            acc_r = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            acc_f = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            acc_u = fixed6_4_to_gdouble(t_val);
            if (tree) {
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
            acc_t = fixed6_4_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_acc_t, tvb, offset, 4, acc_t);
                proto_item_append_text(ti, " (m/s)/s");
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
                proto_item_append_text(ti, " degrees");
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
                proto_item_append_text(ti, " meters");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ERR_VEL:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            err_vel  = fixed6_4_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_vel, tvb, offset, 4, err_vel);
                proto_item_append_text(ti, "m/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_ERR_ACC:
            if (length_remaining < 4)
                break;
            t_val = tvb_get_letohl(tvb, offset);
            err_acc  = fixed6_4_to_gdouble(t_val);
            if (tree) {
                ti = proto_tree_add_double(ppi_vector_tree, hf_ppi_vector_err_acc, tvb, offset, 4, err_acc);
                proto_item_append_text(ti, " (m/s)/s");
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_VECTOR_DESCSTR:
            if (length_remaining < 32)
                break;
            if (tree) {
                curr_str= (char *)  tvb_get_ptr(tvb, offset, 32);
                proto_tree_add_string(ppi_vector_tree, hf_ppi_vector_descstr, tvb, offset, 32, curr_str);
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
    return;
}


