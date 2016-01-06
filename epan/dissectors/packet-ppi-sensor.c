/* packet-ppi-sensor.c
 * Routines for PPI-GEOLOCATION-SENSOR dissection
 * Copyright 2010, Harris Corp, jellch@harris.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-ppi-antenna.c
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

enum ppi_sensor_type {
    PPI_SENSOR_SENSORTYPE   = 0, /* Velocity, Acceleration, etc */
    PPI_SENSOR_SCALEFACTOR  = 1, /* 10^scalefactor applied to all values */
    PPI_SENSOR_VAL_X        = 2, /* X-dimension reading */
    PPI_SENSOR_VAL_Y        = 3, /* Y-dimension reading */
    PPI_SENSOR_VAL_Z        = 4, /* Z-dimension reading */
    PPI_SENSOR_VAL_T        = 5, /* Total reading */
    PPI_SENSOR_VAL_E        = 6, /* Error reading */
    PPI_SENSOR_DESCSTR     = 28, /*32 bytes, fixed length, null terminated description of what the sensor is for */
    PPI_SENSOR_APPID       = 29, /*4-byte identifier*/
    PPI_SENSOR_APPDATA     = 30, /* 60-byte app-id specific data*/
    PPI_SENSOR_EXT         = 31  /* Indicates n extended bitmap follows */
};
#define PPI_SENSOR_MAXTAGLEN 127 /* Increase as fields are added */


/*Sensor types */
#define SENSOR_RESERVED0       0
/*The values of these sensors corresponds to the order of their derivatives. double geek win */
#define SENSOR_VELOCITY        1
#define SENSOR_ACCELERATION    2
#define SENSOR_JERK            3
#define SENSOR_ROTATION      100
#define SENSOR_MAGNETIC      101
#define SENSOR_TEMPERATURE  1000
#define SENSOR_BAROMETER    1001
#define SENSOR_HUMIDITY     1002
#define SENSOR_TDOA_CLOCK   2000
#define SENSOR_PHASE        2001

static const value_string sensor_type_str[] = {
  { SENSOR_RESERVED0,    "Reserved" },
  { SENSOR_VELOCITY,     "Velocity"},
  { SENSOR_ACCELERATION, "Acceleration"},
  { SENSOR_JERK,         "Jerk"},
  { SENSOR_ROTATION,     "Rotation"},
  { SENSOR_MAGNETIC,     "Magnetic"},
  { SENSOR_TEMPERATURE,  "Temperature"},
  { SENSOR_BAROMETER,    "Barometer"},
  { SENSOR_HUMIDITY,     "Humidity"},
  { SENSOR_TDOA_CLOCK,   "TDOA_Clock"},
  { SENSOR_PHASE,         "Phase"},
  { 0, NULL}
  };

static const value_string sensor_unit_str[] = {
  { SENSOR_RESERVED0,    "Reserved" },
  { SENSOR_VELOCITY,     "Meters/sec"},
  { SENSOR_ACCELERATION, "Meters/sec/sec"},
  { SENSOR_JERK,         "Meters/sec/sec/sec"},
  { SENSOR_ROTATION,     "Degrees/sec"},
  { SENSOR_MAGNETIC,     "Tesla"},
  { SENSOR_TEMPERATURE,  "Degrees Celsius"},
  { SENSOR_BAROMETER,    "Pascal"},
  { SENSOR_HUMIDITY,     "Humidity"},
  { SENSOR_TDOA_CLOCK,   "Seconds"},
  { SENSOR_PHASE,        "Degrees"},
  { 0, NULL}
  };

void proto_register_ppi_sensor(void);
/* protocol */
static int proto_ppi_sensor = -1;

static int hf_ppi_sensor_version = -1;
static int hf_ppi_sensor_pad = -1;
static int hf_ppi_sensor_length = -1;
static int hf_ppi_sensor_present = -1;
static int hf_ppi_sensor_sensortype = -1;
static int hf_ppi_sensor_scalefactor = -1;
static int hf_ppi_sensor_val_x = -1;
static int hf_ppi_sensor_val_y= -1;
static int hf_ppi_sensor_val_z= -1;
static int hf_ppi_sensor_val_t= -1;
static int hf_ppi_sensor_val_e = -1;
static int hf_ppi_sensor_descstr = -1;
static int hf_ppi_sensor_appspecific_num = -1; /* 4-byte tag no */
static int hf_ppi_sensor_appspecific_data = -1; /* 60 byte arbitrary data */


/* "Present" flags */
/* These represent decoded-bits in the gui */
static int hf_ppi_sensor_present_sensortype = -1;
static int hf_ppi_sensor_present_scalefactor = -1;
static int hf_ppi_sensor_present_val_x= -1;
static int hf_ppi_sensor_present_val_y= -1;
static int hf_ppi_sensor_present_val_z= -1;
static int hf_ppi_sensor_present_val_t= -1;
static int hf_ppi_sensor_present_val_e = -1;
static int hf_ppi_sensor_present_descstr = -1;
static int hf_ppi_sensor_present_appspecific_num = -1;
static int hf_ppi_sensor_present_appspecific_data = -1;
static int hf_ppi_sensor_present_ext = -1;


/* These represent arrow-dropdownthings in the gui */
static gint ett_ppi_sensor = -1;
static gint ett_ppi_sensor_present = -1;

static expert_field ei_ppi_sensor_present_bit = EI_INIT;
static expert_field ei_ppi_sensor_version = EI_INIT;
static expert_field ei_ppi_sensor_length = EI_INIT;

/* used with ScaleFactor */
static gdouble
base_10_expt(int power)
{
    gdouble ret = 1;
    int provide_frac = 0;

    if (power == 0) /* likely*/
        return 1;

    /* if negative, negate when we return*/
    if (power < 0)
    {
        power *= -1;
        provide_frac = 1;
    }
    while (power > 0)
    {
        ret = ret * 10;
        power--;
    }
    if (! provide_frac)
        return ret;
    else
        return (1.0/ret);
}

static int
dissect_ppi_sensor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
    /* The fixed values up front */
    guint32 version;
    guint length;
    guint length_remaining;

    proto_tree *ppi_sensor_tree = NULL;
    proto_tree *pt, *my_pt;
    proto_item *version_item, *length_item;
    proto_tree *sensor_line;
    /* sensor type in english */
    const gchar *type_str = "Unknown sensor";
    const gchar *unit_str = "Unknown unit";

    static const int * ppi_sensor_present_flags[] = {
        &hf_ppi_sensor_present_sensortype,
        &hf_ppi_sensor_present_scalefactor,
        &hf_ppi_sensor_present_val_x,
        &hf_ppi_sensor_present_val_y,
        &hf_ppi_sensor_present_val_z,
        &hf_ppi_sensor_present_val_t,
        &hf_ppi_sensor_present_val_e,
        &hf_ppi_sensor_present_descstr,
        &hf_ppi_sensor_present_appspecific_num,
        &hf_ppi_sensor_present_appspecific_data,
        &hf_ppi_sensor_present_ext,
        NULL
    };

    /* bits*/
    int bit;
    guint32 present, next_present;
    int offset = 0;
    /* values actually read out, for displaying */
    guint16 sensortype =0;
    gchar  scalefactor = 0;
    gdouble c_val=0; /*curr val */
    guint32 val_t=0; /*temp curr val*/
    guint32 t_appspecific_num; /* temporary conversions */

    gdouble curr_native_val; /* this will have scaling_factor applied. displayed in sensor line */
    gchar* curr_str;



    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* pull out the first three fields of the BASE-GEOTAG-HEADER */
    version = tvb_get_guint8(tvb, offset);
    length = tvb_get_letohs(tvb, offset+2);
    present = tvb_get_letohl(tvb, offset+4);

    /* Setup basic column info */
    col_add_fstr(pinfo->cinfo, COL_INFO, "PPI Sensor info v%u, Length %u ",
                     version, length);

    /* Create the basic dissection tree*/
    sensor_line = proto_tree_add_protocol_format(tree, proto_ppi_sensor,
                                        tvb, 0, length, "PPI Sensor Header v%u, Length %u", version, length);
    /*Add in the fixed ppi-geotagging-header fields: ver, pad, len */
    ppi_sensor_tree = proto_item_add_subtree(sensor_line, ett_ppi_sensor);
    version_item = proto_tree_add_uint(ppi_sensor_tree, hf_ppi_sensor_version,
                        tvb, offset, 1, version);
    proto_tree_add_item(ppi_sensor_tree, hf_ppi_sensor_pad,
                        tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_uint(ppi_sensor_tree, hf_ppi_sensor_length,
                                tvb, offset + 2, 2, length);
    /*fixed ppi-geotagging-header fields finished, move onto the fields marked present*/

    /* We support v1 and v2 of Sensor tags (identical) */
    if (! (version == 1 || version == 2) ) {
        expert_add_info_format(pinfo, version_item, &ei_ppi_sensor_version, "Invalid version (got %d,  expected 1 or 2)", version);
    }

    length_remaining = length;
    /* minimum length check, should atleast be a fixed-size geotagging-base header*/
    if (length_remaining < PPI_GEOBASE_MIN_HEADER_LEN) {
        /*
         * Base-geotag-header (Radiotap lookalike) is shorter than the fixed-length portion
         * plus one "present" bitset.
         */
        expert_add_info_format(pinfo, length_item, &ei_ppi_sensor_length, "Invalid PPI-Sensor length - minimum length is 8");
        return 2;
    }

    /* perform max length sanity checking */
    if (length > PPI_SENSOR_MAXTAGLEN ) {
        expert_add_info_format(pinfo, length_item, &ei_ppi_sensor_length, "Invalid PPI-Sensor length  (got %d, %d max\n)", length, PPI_SENSOR_MAXTAGLEN);
        return 2;
    }

    /* Subtree for the "present flags" bitfield. */
    pt = proto_tree_add_bitmask(ppi_sensor_tree, tvb, offset + 4, hf_ppi_sensor_present, ett_ppi_sensor_present, ppi_sensor_present_flags, ENC_LITTLE_ENDIAN);

    offset += PPI_GEOBASE_MIN_HEADER_LEN;
    length_remaining -= PPI_GEOBASE_MIN_HEADER_LEN;

    /* Now all of the fixed length, fixed location stuff is over. Loop over the bits */
    for (; present; present = next_present) {
        /* clear the least significant bit that is set */
        next_present = present & (present - 1);
        /* extract the least significant bit that is set */
        bit = BITNO_32(present ^ next_present);
        switch (bit) {
        case  PPI_SENSOR_SENSORTYPE:
            if (length_remaining < 2)
                break;
            sensortype= tvb_get_letohs(tvb, offset);
            type_str = val_to_str_const (sensortype, sensor_type_str, "Unknown Sensor type");
            unit_str = val_to_str_const (sensortype, sensor_unit_str, "Unknown Unit");

            if (tree) {
                my_pt = proto_tree_add_uint(ppi_sensor_tree, hf_ppi_sensor_sensortype, tvb, offset , 2, sensortype);
                proto_item_append_text (my_pt, " %s", type_str);
                proto_item_set_text(sensor_line, "Sensor: %s", type_str);
            }
            offset+=2;
            length_remaining-=2;
            break;
        case PPI_SENSOR_SCALEFACTOR:
            if (length_remaining < 1)
                break;
            scalefactor = (gchar) tvb_get_guint8(tvb, offset);
            proto_tree_add_int(ppi_sensor_tree, hf_ppi_sensor_scalefactor, tvb, offset, 1, scalefactor);
            offset+=1;
            length_remaining-=1;
            break;
        case  PPI_SENSOR_VAL_X:
            if (length_remaining < 4)
                break;
            val_t = tvb_get_letohl(tvb, offset);
            c_val = ppi_fixed6_4_to_gdouble(val_t);
            if (tree) {
                my_pt = proto_tree_add_double(ppi_sensor_tree, hf_ppi_sensor_val_x, tvb, offset, 4, c_val);
                proto_item_append_text (my_pt, " %s", unit_str);
                curr_native_val = c_val * base_10_expt(scalefactor); /* this will almost always be equal to the original val */
                proto_item_set_text(sensor_line, "Sensor: %s %f %s", type_str, curr_native_val, unit_str);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_SENSOR_VAL_Y:
            if (length_remaining < 4)
                break;
            val_t = tvb_get_letohl(tvb, offset);
            c_val = ppi_fixed6_4_to_gdouble(val_t);
            if (tree) {
                my_pt = proto_tree_add_double(ppi_sensor_tree, hf_ppi_sensor_val_y, tvb, offset, 4, c_val);
                proto_item_append_text (my_pt, " %s", unit_str);
                curr_native_val = c_val * base_10_expt(scalefactor); /* this will almost always be equal to the original val */
                proto_item_set_text(sensor_line, "Sensor: %s %f %s", type_str, curr_native_val, unit_str);

            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_SENSOR_VAL_Z:
            if (length_remaining < 4)
                break;
            val_t = tvb_get_letohl(tvb, offset);
            c_val = ppi_fixed6_4_to_gdouble(val_t);
            if (tree) {
                my_pt = proto_tree_add_double(ppi_sensor_tree, hf_ppi_sensor_val_z, tvb, offset, 4, c_val);
                proto_item_append_text (my_pt, " %s", unit_str);
                curr_native_val = c_val * base_10_expt(scalefactor); /* this will almost always be equal to the original val */
                proto_item_set_text(sensor_line, "Sensor: %s %f %s", type_str, curr_native_val, unit_str);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_SENSOR_VAL_T:
            if (length_remaining < 4)
                break;
            val_t = tvb_get_letohl(tvb, offset);
            c_val = ppi_fixed6_4_to_gdouble(val_t);
            if (tree) {
                my_pt = proto_tree_add_double(ppi_sensor_tree, hf_ppi_sensor_val_t, tvb, offset, 4, c_val);
                proto_item_append_text (my_pt, " %s", unit_str);
                curr_native_val = c_val * base_10_expt(scalefactor); /* this will almost always be equal to the original val */
                proto_item_set_text(sensor_line, "Sensor: %s %f %s", type_str, curr_native_val, unit_str);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_SENSOR_VAL_E:
            if (length_remaining < 4)
                break;
            val_t = tvb_get_letohl(tvb, offset);
            c_val = ppi_fixed6_4_to_gdouble(val_t);
            if (tree) {
                my_pt = proto_tree_add_double(ppi_sensor_tree, hf_ppi_sensor_val_e, tvb, offset, 4, c_val);
                proto_item_append_text (my_pt, " %s", unit_str);
            }
            offset+=4;
            length_remaining-=4;
            break;

        case  PPI_SENSOR_DESCSTR:
            if (length_remaining < 32)
                break;
            if (tree)
            {
                /* proto_tree_add_item(ppi_vector_tree, hf_ppi_vector_descstr, tvb, offset, 32, ENC_NA); */
                curr_str = tvb_format_stringzpad(tvb, offset, 32);
                proto_tree_add_string(ppi_sensor_tree, hf_ppi_sensor_descstr, tvb, offset, 32, curr_str);
                proto_item_append_text(sensor_line, " (%s)", curr_str);
            }
            offset+=32;
            length_remaining-=32;
            break;
        case  PPI_SENSOR_APPID:
            if (length_remaining < 4)
                break;
            t_appspecific_num  = tvb_get_letohl(tvb, offset); /* application specific parsers may switch on this later */
            proto_tree_add_uint(ppi_sensor_tree, hf_ppi_sensor_appspecific_num, tvb, offset, 4, t_appspecific_num);
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_SENSOR_APPDATA:
            if (length_remaining < 60)
                break;
            proto_tree_add_item(ppi_sensor_tree, hf_ppi_sensor_appspecific_data, tvb, offset, 60,  ENC_NA);
            offset+=60;
            length_remaining-=60;
            break;
        default:
            /*
             * This indicates a field whose size we do not
             * know, so we cannot proceed.
             */
            expert_add_info_format(pinfo, pt, &ei_ppi_sensor_present_bit, "Error: PPI-SENSOR: unknown bit (%d) set in present field.", bit);
            next_present = 0;
            continue;
        }

    };
    return tvb_captured_length(tvb);
}

void
proto_register_ppi_sensor(void) {
    /* The following array initializes those header fields declared above to the values displayed */
    static hf_register_info hf[] = {
        { &hf_ppi_sensor_version,
          { "Header revision", "ppi_sensor.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Version of ppi_sensor header format", HFILL } },
        { &hf_ppi_sensor_pad,
          { "Header pad", "ppi_sensor.pad",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Padding", HFILL } },
        { &hf_ppi_sensor_length,
          { "Header length", "ppi_sensor.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of header including version, pad, length and data fields", HFILL } },
        { &hf_ppi_sensor_present,
          { "Present", "ppi_sensor.present",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask indicating which fields are present", HFILL } },

        /* This first set is for the base_tag_header.it_present bitfield */
#define PPI_SENSOR_MASK_SENSORTYPE      0x00000001  /* 0 */
#define PPI_SENSOR_MASK_SCALEFACTOR     0x00000002  /* 1 */
#define PPI_SENSOR_MASK_VAL_X           0x00000004  /* 2 */
#define PPI_SENSOR_MASK_VAL_Y           0x00000008  /* 3 */
#define PPI_SENSOR_MASK_VAL_Z           0x00000010  /* 4 */
#define PPI_SENSOR_MASK_VAL_T           0x00000020  /* 5 */
#define PPI_SENSOR_MASK_VAL_E           0x00000040  /* 6 */
#define PPI_SENSOR_MASK_SERIALNUM       0x04000000  /* 26 */
#define PPI_SENSOR_MASK_MODELSTR        0x08000000  /* 27 */
#define PPI_SENSOR_MASK_DESCSTR         0x10000000  /* 28 */
#define PPI_SENSOR_MASK_APPID           0x20000000  /* 29 */
#define PPI_SENSOR_MASK_APPDATA         0x40000000  /* 30 */
#define PPI_SENSOR_MASK_EXT             0x80000000  /* 31 */

        /* Boolean 'present' flags */
        { &hf_ppi_sensor_present_sensortype,
          { "sensortype", "ppi_sensor.present.sensortype",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_SENSORTYPE,
            "Specifies if the sensor type field  is present", HFILL } },
        { &hf_ppi_sensor_present_scalefactor,
          { "scalefactor", "ppi_sensor.present.scalefactor",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_SCALEFACTOR,
            "Specifies if the sensor scale factor field is present", HFILL } },

        { &hf_ppi_sensor_present_val_x,
          { "val_x", "ppi_sensor.present.val_x",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_VAL_X,
            "Specifies if the sensor val_x field is present", HFILL } },
        { &hf_ppi_sensor_present_val_y,
          { "val_y", "ppi_sensor.present.val_y",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_VAL_Y,
            "Specifies if the sensor val_y field is present", HFILL } },
        { &hf_ppi_sensor_present_val_z,
          { "val_z", "ppi_sensor.present.val_z",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_VAL_Z,
            "Specifies if the BeamID field is present", HFILL } },

        { &hf_ppi_sensor_present_val_t,
          { "val_t", "ppi_sensor.present.val_t",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_VAL_T,
            "Specifies if the val_t field is present", HFILL } },
        { &hf_ppi_sensor_present_val_e,
          { "val_e", "ppi_sensor.present.val_e",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_VAL_E,
            "Specifies if the val_e field is present", HFILL } },

        { &hf_ppi_sensor_present_descstr,
          { "Description", "ppi_sensor.present.descr",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_DESCSTR,
            "Specifies if the description string is present", HFILL } },
        { &hf_ppi_sensor_present_appspecific_num,
          { "appid", "ppi_sensor.present.appid",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_APPID,
            "Specifies if the application specific field id is present", HFILL } },
        { &hf_ppi_sensor_present_appspecific_data,
          { "appdata", "ppi_sensor.present.appdata",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_APPDATA,
            "Specifies if the application specific data field  is present", HFILL } },
        { &hf_ppi_sensor_present_ext,
          { "ext", "ppi_sensor.present.ext",
            FT_BOOLEAN, 32, NULL, PPI_SENSOR_MASK_EXT,
            "Specifies if there are any extensions to the header present", HFILL } },


        /* Now we get to the actual data fields */
        { &hf_ppi_sensor_sensortype,
          { "SensorType", "ppi_sensor.sensortype",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Type of sensor", HFILL } },
        { &hf_ppi_sensor_scalefactor,
          { "ScaleFactor", "ppi_sensor.scalefactor",
            FT_INT8, BASE_DEC, NULL, 0x0,
            "Scaling factor", HFILL } },
        { &hf_ppi_sensor_val_x,
          { "Val_X", "ppi_sensor.val_x",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Value in X-dimesion", HFILL } },
        { &hf_ppi_sensor_val_y,
          { "Val_Y", "ppi_sensor.val_y",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Value in Y-dimension", HFILL } },
        { &hf_ppi_sensor_val_z,
          { "Val_Z", "ppi_sensor.val_z",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Value in Z-dimension", HFILL } },
        { &hf_ppi_sensor_val_t,
          { "Val_T", "ppi_sensor.val_t",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Value total (dimensionless)", HFILL } },
        { &hf_ppi_sensor_val_e,
          { "Val_E", "ppi_sensor.val_e",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Margin of error", HFILL } },


        { &hf_ppi_sensor_descstr,
          { "Description", "ppi_sensor.descr",
            FT_STRING,  BASE_NONE, NULL, 0x0,
            NULL, HFILL } } ,
        { &hf_ppi_sensor_appspecific_num,
          { "Application Specific id", "ppi_sensor.appid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Application-specific identifier", HFILL } },
        { &hf_ppi_sensor_appspecific_data,
          { "Application specific data", "ppi_sensor.appdata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Application-specific data", HFILL } },
    };
    static gint *ett[] = {
        &ett_ppi_sensor,
        &ett_ppi_sensor_present,
    };

    static ei_register_info ei[] = {
        { &ei_ppi_sensor_present_bit, { "ppi_sensor.present.unknown_bit", PI_PROTOCOL, PI_WARN, "Error: PPI-ANTENNA: unknown bit set in present field.", EXPFILL }},
        { &ei_ppi_sensor_version, { "ppi_sensor.version.unsupported", PI_PROTOCOL, PI_WARN, "Invalid version", EXPFILL }},
        { &ei_ppi_sensor_length, { "ppi_sensor.length.invalid", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
    };

    expert_module_t* expert_ppi_sensor;

    proto_ppi_sensor = proto_register_protocol("PPI sensor decoder", "PPI sensor Decoder", "ppi_sensor");
    proto_register_field_array(proto_ppi_sensor, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ppi_sensor = expert_register_protocol(proto_ppi_sensor);
    expert_register_field_array(expert_ppi_sensor, ei, array_length(ei));
    register_dissector("ppi_sensor", dissect_ppi_sensor, proto_ppi_sensor);

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


