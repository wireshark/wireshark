/* packet-ppi-antenna.c
 * Routines for PPI-GEOLOCATION-ANNTENNA  dissection
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

#include <epan/packet.h>
#include "packet-ppi-geolocation-common.h"

enum ppi_antenna_type {
    PPI_ANTENNA_ANTFLAGS    = 0, /* Various flags about the antenna in use, Polarity, etc */
    PPI_ANTENNA_GAINDB      = 1, /* Antenna gain, in dBi */
    PPI_ANTENNA_HORIZBW     = 2, /* Antenna beamwidth, horizontal */
    PPI_ANTENNA_VERTBW      = 3, /* Antenna beamwidth, vertical */
    PPI_ANTENNA_PGAIN       = 4, /* precision gain */
    PPI_ANTENNA_BEAMID      = 5, /* beam identifier (electrically steerable only) */
    PPI_ANTENNA_RES6        = 6,
    PPI_ANTENNA_RES7        = 7,
    PPI_ANTENNA_SERIALNUM   = 26,
    PPI_ANTENNA_MODELSTR    = 27, /*32 bytes, fixed length, null terminated model of antenna */
    PPI_ANTENNA_DESCSTR     = 28, /*32 bytes, fixed length, null terminated description of what the antenna is for */
    PPI_ANTENNA_APPID       = 29, /*4-byte identifier*/
    PPI_ANTENNA_APPDATA     = 30, /* 60-byte app-id specific data*/
    PPI_ANTENNA_EXT         = 31  /* Indicates n extended bitmap follows */
};
#define PPI_ANTENNA_MAXTAGLEN  187 /* increase as fields are added */


/* protocol */
static int proto_ppi_antenna = -1;

static int hf_ppi_antenna_version = -1;
static int hf_ppi_antenna_pad = -1;
static int hf_ppi_antenna_length = -1;
static int hf_ppi_antenna_present = -1;
static int hf_ppi_antenna_flags = -1;
static int hf_ppi_antenna_gaindb = -1;
static int hf_ppi_antenna_horizbw = -1;
static int hf_ppi_antenna_vertbw = -1;
static int hf_ppi_antenna_pgain= -1;
static int hf_ppi_antenna_beamid= -1;
static int hf_ppi_antenna_serialnum= -1;
static int hf_ppi_antenna_modelname = -1;
static int hf_ppi_antenna_descstr = -1;
static int hf_ppi_antenna_appspecific_num = -1; /* 4-byte tag no */
static int hf_ppi_antenna_appspecific_data = -1; /* 60 byte arbitrary data */


/* "Present" flags */
/* These represent decoded-bits in the gui */
static int hf_ppi_antenna_present_flags= -1;
static int hf_ppi_antenna_present_gaindb = -1;
static int hf_ppi_antenna_present_horizbw = -1;
static int hf_ppi_antenna_present_vertbw= -1;
static int hf_ppi_antenna_present_pgain= -1;
static int hf_ppi_antenna_present_beamid= -1;
static int hf_ppi_antenna_present_serialnum= -1;
static int hf_ppi_antenna_present_modelname = -1;
static int hf_ppi_antenna_present_descstr = -1;
static int hf_ppi_antenna_present_appspecific_num = -1;
static int hf_ppi_antenna_present_appspecific_data = -1;
static int hf_ppi_antenna_present_ext = -1;

/*These are the few defined AntennaFlags bits*/
static int hf_ppi_antennaflags_mimo= -1;
static int hf_ppi_antennaflags_horizpol= -1;
static int hf_ppi_antennaflags_vertpol= -1;
static int hf_ppi_antennaflags_circpol_l= -1;
static int hf_ppi_antennaflags_circpol_r= -1;
static int hf_ppi_antennaflags_steer_elec= -1;
static int hf_ppi_antennaflags_steer_mech= -1;

/* These represent arrow-dropdownthings in the gui */
static gint ett_ppi_antenna = -1;
static gint ett_ppi_antenna_present = -1;
static gint ett_ppi_antennaflags= -1;


static void
dissect_ppi_antenna(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    /* The fixed values up front */
    guint32 version;
    guint length;
    gint  length_remaining;

    proto_tree *ppi_antenna_tree = NULL;
    proto_tree *present_tree = NULL;
    proto_tree *antennaflags_tree = NULL;
    proto_tree *pt, *my_pt;
    proto_item *ti = NULL;
    proto_item *antenna_line = NULL;


    /* bits */
    int bit;
    guint32 present, next_present;
    /* values actually read out, for displaying */
    guint8 gaindb;
    guint16 beamid;
    guint32 t_hbw, t_vbw, t_pgain, t_appspecific_num; /* temporary conversions */
    gdouble horizbw, vertbw, pgain;
    guint32 flags;
    gchar *curr_str;
    int offset = 0;

    /* Clear out stuff in the info column */
        col_clear(pinfo->cinfo,COL_INFO);

    /* pull out the first three fields of the BASE-GEOTAG-HEADER */
    version = tvb_get_guint8(tvb, offset);
    length  = tvb_get_letohs(tvb, offset+2);
    present = tvb_get_letohl(tvb, offset+4);

    /* Setup basic column info */
    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "PPI Antenna info v%u, Length %u",
                     version, length);


    /* Create the basic dissection tree*/
    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_ppi_antenna,
                                            tvb, 0, length, "Antenna: ");
        antenna_line = ti; /* save this for later, we will fill it in with more detail */

        ppi_antenna_tree= proto_item_add_subtree(ti, ett_ppi_antenna);
        proto_tree_add_uint(ppi_antenna_tree, hf_ppi_antenna_version,
                            tvb, offset, 1, version);
        proto_tree_add_item(ppi_antenna_tree, hf_ppi_antenna_pad,
                            tvb, offset + 1, 1, ENC_NA);
        ti = proto_tree_add_uint(ppi_antenna_tree, hf_ppi_antenna_length,
                                 tvb, offset + 2, 2, length);
    }
    /* We support v1 and v2 of Antenna tags (identical) */
    if (! (version == 1 || version == 2) ) {
        if (tree)
            proto_item_append_text(ti, "invalid version (got %d,  expected 1 or 2)", version);
        return;
    }

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
    if (length > PPI_ANTENNA_MAXTAGLEN ) {
        if (tree)
            proto_item_append_text(ti, "Invalid PPI-Antenna length  (got %d, %d max\n)", length, PPI_ANTENNA_MAXTAGLEN);
        return;
    }


    /* Subtree for the "present flags" bitfield. */
    if (tree) {
        pt = proto_tree_add_uint(ppi_antenna_tree, hf_ppi_antenna_present, tvb, offset + 4, 4, present);
        present_tree = proto_item_add_subtree(pt, ett_ppi_antenna_present);

        proto_tree_add_item(present_tree, hf_ppi_antenna_present_flags, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_gaindb, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_horizbw, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_vertbw, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_pgain, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_beamid, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_serialnum, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_modelname, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_descstr, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_appspecific_num, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(present_tree, hf_ppi_antenna_present_appspecific_data, tvb, 4, 4, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(present_tree, hf_ppi_antenna_present_ext, tvb, 4, 4, ENC_LITTLE_ENDIAN);
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
        case  PPI_ANTENNA_ANTFLAGS:
            if (length_remaining < 4)
                break;
            flags = tvb_get_letohl(tvb, offset);
            if (tree) {
                my_pt = proto_tree_add_uint(ppi_antenna_tree, hf_ppi_antenna_flags, tvb, offset , 4, flags);
                /*Add antenna_flags bitfields here */
                antennaflags_tree= proto_item_add_subtree(my_pt, ett_ppi_antennaflags);

                proto_tree_add_item(antennaflags_tree, hf_ppi_antennaflags_mimo, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(antennaflags_tree, hf_ppi_antennaflags_horizpol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(antennaflags_tree, hf_ppi_antennaflags_vertpol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(antennaflags_tree, hf_ppi_antennaflags_circpol_l, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(antennaflags_tree, hf_ppi_antennaflags_circpol_r, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(antennaflags_tree, hf_ppi_antennaflags_steer_elec, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(antennaflags_tree, hf_ppi_antennaflags_steer_mech, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case PPI_ANTENNA_GAINDB:
            if (length_remaining < 1)
                break;
            gaindb=  tvb_get_guint8(tvb, offset);
            if (tree) {
                proto_tree_add_uint(ppi_antenna_tree, hf_ppi_antenna_gaindb, tvb, offset, 1, gaindb);
                proto_item_append_text(antenna_line, " Gain: %d", gaindb);

            }
            offset+=1;
            length_remaining-=1;
            break;
        case  PPI_ANTENNA_HORIZBW:
            if (length_remaining < 4)
                break;
            t_hbw = tvb_get_letohl(tvb, offset);
            horizbw =  ppi_fixed3_6_to_gdouble(t_hbw);
            if (tree) {
                proto_tree_add_double(ppi_antenna_tree, hf_ppi_antenna_horizbw, tvb, offset, 4, horizbw);
                proto_item_append_text(antenna_line, " HorizBw: %f", horizbw);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_ANTENNA_VERTBW:
            if (length_remaining < 4)
                break;
            t_vbw = tvb_get_letohl(tvb, offset);
            vertbw =  ppi_fixed3_6_to_gdouble(t_vbw);
            if (tree) {
                proto_tree_add_double(ppi_antenna_tree, hf_ppi_antenna_vertbw, tvb, offset, 4, vertbw);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_ANTENNA_PGAIN:
            if (length_remaining < 4)
                break;
            t_pgain = tvb_get_letohl(tvb, offset);
            pgain   = ppi_fixed3_6_to_gdouble(t_pgain);
            if (tree) {
                proto_tree_add_double(ppi_antenna_tree, hf_ppi_antenna_pgain, tvb, offset, 4, pgain);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_ANTENNA_BEAMID:
            if (length_remaining < 2)
                break;
            beamid= tvb_get_letohs(tvb, offset); /* convert endianess */
            if (tree) {
                proto_tree_add_uint(ppi_antenna_tree, hf_ppi_antenna_beamid, tvb, offset, 2, beamid);
            }
            offset+=2;
            length_remaining-=2;
            break;
        case  PPI_ANTENNA_SERIALNUM:
            if (length_remaining < 32)
                break;
            if (tree) {
                proto_tree_add_item(ppi_antenna_tree, hf_ppi_antenna_serialnum, tvb, offset, 32, ENC_ASCII|ENC_NA);
            }
            offset+=32;
            length_remaining-=32;
            break;

        case  PPI_ANTENNA_MODELSTR:
            if (length_remaining < 32)
                break;
            if (tree) {
                /* proto_tree_add_item(ppi_antenna_tree, hf_ppi_antenna_modelname, tvb, offset, 32, ENC_ASCII|ENC_NA); */
                curr_str = tvb_format_stringzpad(tvb, offset, 32);
                proto_tree_add_string(ppi_antenna_tree, hf_ppi_antenna_modelname, tvb, offset, 32, curr_str);
                proto_item_append_text(antenna_line, " (%s)", curr_str);
            }
            offset+=32;
            length_remaining-=32;
            break;
        case  PPI_ANTENNA_DESCSTR:
            if (length_remaining < 32)
                break;
            if (tree) {
                /*proto_tree_add_item(ppi_antenna_tree, hf_ppi_antenna_descstr, tvb, offset, 32, ENC_ASCII|ENC_NA);*/
                curr_str = tvb_format_stringzpad(tvb, offset, 32);
                proto_tree_add_string(ppi_antenna_tree, hf_ppi_antenna_descstr, tvb, offset, 32, curr_str);
                proto_item_append_text(antenna_line, " (%s)", curr_str);
            }
            offset+=32;
            length_remaining-=32;
            break;
        case  PPI_ANTENNA_APPID:
            if (length_remaining < 4)
                break;
            t_appspecific_num  = tvb_get_letohl(tvb, offset); /* application specific parsers may switch on this later */
            if (tree) {
                proto_tree_add_uint(ppi_antenna_tree, hf_ppi_antenna_appspecific_num, tvb, offset, 4, t_appspecific_num);
            }
            offset+=4;
            length_remaining-=4;
            break;
        case  PPI_ANTENNA_APPDATA:
            if (length_remaining < 60)
                break;
            if (tree) {
                proto_tree_add_item(ppi_antenna_tree, hf_ppi_antenna_appspecific_data, tvb, offset, 60,  ENC_NA);
            }
            offset+=60;
            length_remaining-=60;
            break;
        default:
            /*
             * This indicates a field whose size we do not
             * know, so we cannot proceed.
             */
            proto_tree_add_text(ppi_antenna_tree, tvb, offset, 0,
                                "Error: PPI-ANTENNA: unknown bit (%d) set in present field.\n", bit);
            next_present = 0;
            continue;
        }

    };
    return;
}

void
proto_register_ppi_antenna(void) {
    static hf_register_info hf[] = {
        { &hf_ppi_antenna_version,
          { "Header revision", "ppi_antenna.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Version of ppi_antenna header format", HFILL } },
        { &hf_ppi_antenna_pad,
          { "Header pad", "ppi_antenna.pad",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Padding", HFILL } },
        { &hf_ppi_antenna_length,
          { "Header length", "ppi_antenna.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of header including version, pad, length and data fields", HFILL } },
        /* This setups the "Antenna flags" hex dropydown thing */
        { &hf_ppi_antenna_flags,
          { "Antenna flags", "ppi_antenna.antenna_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask indicating polarity, etc", HFILL } },
        { &hf_ppi_antenna_present,
          { "Present", "ppi_antenna.present",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask indicating which fields are present", HFILL } },

        /* This first set is for the base_tag_header.it_present bitfield */
#define PPI_ANTENNA_MASK_FLAGS      0x00000001  /* 0 */
#define PPI_ANTENNA_MASK_GAINDB     0x00000002  /* 1 */
#define PPI_ANTENNA_MASK_HORIZBW    0x00000004  /* 2 */
#define PPI_ANTENNA_MASK_VERTBW     0x00000008  /* 3 */
#define PPI_ANTENNA_MASK_PGAIN      0x00000010  /* 4 */
#define PPI_ANTENNA_MASK_BEAMID     0x00000020  /* 5 */
#define PPI_ANTENNA_MASK_RES7       0x00000080  /* 7 */
#define PPI_ANTENNA_MASK_SERIALNUM  0x04000000  /* 26 */
#define PPI_ANTENNA_MASK_MODELSTR   0x08000000  /* 27 */
#define PPI_ANTENNA_MASK_DESCSTR    0x10000000  /* 28 */
#define PPI_ANTENNA_MASK_APPID      0x20000000  /* 29 */
#define PPI_ANTENNA_MASK_APPDATA    0x40000000  /* 30 */
#define PPI_ANTENNA_MASK_EXT        0x80000000  /* 31 */

        /*This second set is for the AntennaFlags bitfield. */
#define PPI_ANTENNAFLAGS_MASK_MIMO              0x00000001  /* 0 */
#define PPI_ANTENNAFLAGS_MASK_HPOL              0x00000002  /* 1 */
#define PPI_ANTENNAFLAGS_MASK_VPOL              0x00000004  /* 2 */
#define PPI_ANTENNAFLAGS_MASK_CPOL_L            0x00000008  /* 3 */
#define PPI_ANTENNAFLAGS_MASK_CPOL_R            0x00000010  /* 4 */
#define PPI_ANTENNAFLAGS_MASK_STEER_ELEC        0x00010000  /* 16 */
#define PPI_ANTENNAFLAGS_MASK_STEER_MECH        0x00020000  /* 17 */


        /* Boolean 'present' flags */
        { &hf_ppi_antenna_present_flags,
          { "flags", "ppi_antenna.present.flags",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_FLAGS,
            "Specifies if the flags bitfield is present", HFILL } },
        { &hf_ppi_antenna_present_gaindb,
          { "gaindb", "ppi_antenna.present.gaindb",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_GAINDB,
            "Specifies if the antenna gain field  is present", HFILL } },
        { &hf_ppi_antenna_present_horizbw,
          { "horizbw", "ppi_antenna.present.horizbw",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_HORIZBW,
            "Specifies if the horizontal beamwidth field is present", HFILL } },
        { &hf_ppi_antenna_present_vertbw,
          { "vertbw", "ppi_antenna.present.vertbw",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_VERTBW,
            "Specifies if the vertical beamwidth field is present", HFILL } },
        { &hf_ppi_antenna_present_pgain,
          { "pgain", "ppi_antenna.present.pgain",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_PGAIN,
            "Specifies if the precision gain field is present", HFILL } },
        { &hf_ppi_antenna_present_beamid,
          { "beamid", "ppi_antenna.present.beamid",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_BEAMID,
            "Specifies if the BeamID field is present", HFILL } },
        { &hf_ppi_antenna_present_serialnum,
          { "serialnum", "ppi_antenna.present.serialnum",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_SERIALNUM,
            "Specifies if the serial num is present", HFILL } },
        { &hf_ppi_antenna_present_modelname,
          { "modelname", "ppi_antenna.present.modelname",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_MODELSTR,
            "Specifies if the model name is present", HFILL } },
        { &hf_ppi_antenna_present_descstr,
          { "Description", "ppi_antenna.present.descr",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_DESCSTR,
            "Specifies if the description string is present", HFILL } },

        { &hf_ppi_antenna_present_appspecific_num,
          { "appid", "ppi_antenna.present.appid",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_APPID,
            "Specifies if the application specific field id is present", HFILL } },

        { &hf_ppi_antenna_present_appspecific_data,
          { "appdata", "ppi_antenna.present.appdata",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_APPDATA,
            "Specifies if the application specific data field  is present", HFILL } },

        { &hf_ppi_antenna_present_ext,
          { "ext", "ppi_antenna.present.ext",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNA_MASK_EXT,
            "Specifies if there are any extensions to the header present", HFILL } },

        /*Here we switch to the antennflags bits*/
        /* Boolean AntennaFlags' flags */
        { &hf_ppi_antennaflags_mimo,
          { "mimo", "ppi_antenna.antennaflags.mimo",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNAFLAGS_MASK_MIMO,
            "Antena is part of MIMO system", HFILL } },
        { &hf_ppi_antennaflags_horizpol,
          { "horizontally polarized", "ppi_antenna.antennaflags.horizpol",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNAFLAGS_MASK_HPOL,
            "Specifies if the antenna is horizontally polarized", HFILL } },

        { &hf_ppi_antennaflags_vertpol,
          { "vertically polarized", "ppi_antenna.antennaflags.vertpol",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNAFLAGS_MASK_VPOL,
            "Specifies if the antenna is vertically polarized", HFILL } },

        { &hf_ppi_antennaflags_circpol_l,
          { "circularly polarized left", "ppi_antenna.antennaflags.circpol_l",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNAFLAGS_MASK_CPOL_L,
            "Specifies if the antenna is circularly polarized, left handed", HFILL } },

        { &hf_ppi_antennaflags_circpol_r,
          { "circularly polarized right", "ppi_antenna.antennaflags.circpol_r",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNAFLAGS_MASK_CPOL_R,
            "Specifies if the antenna is circularly polarized, right handed", HFILL } },

        { &hf_ppi_antennaflags_steer_elec,
          { "electrically steerable", "ppi_antenna.antennaflags.steer_elec",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNAFLAGS_MASK_STEER_ELEC,
            "Specifies if the antenna is electrically steerable", HFILL } },

        { &hf_ppi_antennaflags_steer_mech,
          { "mechanically steerable", "ppi_antenna.antennaflags.steer_mech",
            FT_BOOLEAN, 32, NULL, PPI_ANTENNAFLAGS_MASK_STEER_MECH,
            "Specifies if the antenna is mechanically steerable", HFILL } },

        /* Now we get to the actual data fields */
        { &hf_ppi_antenna_gaindb,
          { "Gain (dBi)", "ppi_antenna.gaindb",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Gain of antenna (dBi)", HFILL } },
        { &hf_ppi_antenna_horizbw,
          { "HorizBw", "ppi_antenna.horizbw",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Horizontal beamwidth", HFILL } },
        { &hf_ppi_antenna_vertbw,
          { "VertBw", "ppi_antenna.vertbw",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Vertical beamwidth", HFILL } },
        { &hf_ppi_antenna_pgain,
          { "Precision Gain (dBi)", "ppi_antenna.pgain",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ppi_antenna_beamid,
          { "BeamID", "ppi_antenna.beamid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },

        { &hf_ppi_antenna_serialnum,
          { "SerialNumber", "ppi_antenna.serialnum",
            FT_STRING,  BASE_NONE, NULL, 0x0,
            NULL, HFILL } } ,
        { &hf_ppi_antenna_modelname,
          { "ModelName", "ppi_antenna.modelname",
            FT_STRING,  BASE_NONE, NULL, 0x0,
            NULL, HFILL } } ,
        { &hf_ppi_antenna_descstr,
          { "Description", "ppi_antenna.descr",
            FT_STRING,  BASE_NONE, NULL, 0x0,
            NULL, HFILL } } ,
        { &hf_ppi_antenna_appspecific_num,
          { "Application Specific id", "ppi_antenna.appid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ppi_antenna_appspecific_data,
          { "Application specific data", "ppi_antenna.appdata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
    };
    static gint *ett[] = {
        &ett_ppi_antenna,
        &ett_ppi_antenna_present,
        &ett_ppi_antennaflags
    };

    proto_ppi_antenna = proto_register_protocol("PPI antenna decoder", "PPI antenna Decoder", "ppi_antenna");
    proto_register_field_array(proto_ppi_antenna, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("ppi_antenna", dissect_ppi_antenna, proto_ppi_antenna);

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
