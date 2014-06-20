/* file-mp4.c
 * routines for dissection of MP4 files
 * Copyright 2013-2014, Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

/* this dissector is based on
 * ISO/IEC 14496-12 (ISO base media file format) and
 * ISO/IEC 14496-14 (MP4 file format)
 *
 * at the moment, it dissects the basic box structure and the payload of
 * some simple boxes */


#include "config.h"

#include <math.h>
#include <glib.h>
#include <epan/expert.h>
#include <epan/packet.h>

#define MAKE_TYPE_VAL(a, b, c, d)   ((a)<<24 | (b)<<16 | (c)<<8 | (d))

void proto_register_mp4(void);
void proto_reg_handoff_mp4(void);

static int proto_mp4 = -1;

static gint ett_mp4 = -1;
static gint ett_mp4_box = -1;

static int hf_mp4_box_size = -1;
static int hf_mp4_box_type_str = -1;
static int hf_mp4_box_largesize = -1;
static int hf_mp4_full_box_ver = -1;
static int hf_mp4_ftyp_brand = -1;
static int hf_mp4_ftyp_ver = -1;
static int hf_mp4_ftyp_add_brand = -1;
static int hf_mp4_mfhd_seq_num = -1;
static int hf_mp4_tkhd_creat_time = -1;
static int hf_mp4_tkhd_mod_time = -1;
static int hf_mp4_tkhd_track_id = -1;
static int hf_mp4_tkhd_duration = -1;
static int hf_mp4_tkhd_width = -1;
static int hf_mp4_tkhd_height = -1;

static expert_field ei_mp4_box_too_large = EI_INIT;

/* a box must at least have a 32bit len field and a 32bit type */
#define MIN_BOX_SIZE 8
/* an extended box has the first length field set to 1 */
#define BOX_SIZE_EXTENDED 1

/* the box type is stored as four text characters
   it is in network byte order and contains only printable characters
   for our internal handling, we convert this to a 32bit value */

#define BOX_TYPE_NONE  0x0 /* used for parent_box_type of a top-level box */
#define BOX_TYPE_FTYP  MAKE_TYPE_VAL('f', 't', 'y', 'p')
#define BOX_TYPE_MOOV  MAKE_TYPE_VAL('m', 'o', 'o', 'v')
#define BOX_TYPE_MVHD  MAKE_TYPE_VAL('m', 'v', 'h', 'd')
#define BOX_TYPE_TRAK  MAKE_TYPE_VAL('t', 'r', 'a', 'k')
#define BOX_TYPE_TKHD  MAKE_TYPE_VAL('t', 'k', 'h', 'd')
#define BOX_TYPE_MDIA  MAKE_TYPE_VAL('m', 'd', 'i', 'a')
#define BOX_TYPE_MDHD  MAKE_TYPE_VAL('m', 'd', 'h', 'd')
#define BOX_TYPE_HDLR  MAKE_TYPE_VAL('h', 'd', 'l', 'r')
#define BOX_TYPE_MINF  MAKE_TYPE_VAL('m', 'i', 'n', 'f')
#define BOX_TYPE_VMHD  MAKE_TYPE_VAL('v', 'm', 'h', 'd')
#define BOX_TYPE_SMHD  MAKE_TYPE_VAL('s', 'm', 'h', 'd')
#define BOX_TYPE_DINF  MAKE_TYPE_VAL('d', 'i', 'n', 'f')
#define BOX_TYPE_DREF  MAKE_TYPE_VAL('d', 'r', 'e', 'f')
#define BOX_TYPE_STBL  MAKE_TYPE_VAL('s', 't', 'b', 'l')
#define BOX_TYPE_STTS  MAKE_TYPE_VAL('s', 't', 't', 's')
#define BOX_TYPE_CTTS  MAKE_TYPE_VAL('c', 't', 't', 's')
#define BOX_TYPE_STSD  MAKE_TYPE_VAL('s', 't', 's', 'd')
#define BOX_TYPE_STSZ  MAKE_TYPE_VAL('s', 't', 's', 'z')
#define BOX_TYPE_STSC  MAKE_TYPE_VAL('s', 't', 's', 'c')
#define BOX_TYPE_STCO  MAKE_TYPE_VAL('s', 't', 'c', 'o')
#define BOX_TYPE_STSS  MAKE_TYPE_VAL('s', 't', 's', 's')
#define BOX_TYPE_MVEX  MAKE_TYPE_VAL('m', 'v', 'e', 'x')
#define BOX_TYPE_MOOF  MAKE_TYPE_VAL('m', 'o', 'o', 'f')
#define BOX_TYPE_MEHD  MAKE_TYPE_VAL('m', 'e', 'h', 'd')
#define BOX_TYPE_TREX  MAKE_TYPE_VAL('t', 'r', 'e', 'x')
#define BOX_TYPE_MFHD  MAKE_TYPE_VAL('m', 'f', 'h', 'd')
#define BOX_TYPE_TRAF  MAKE_TYPE_VAL('t', 'r', 'a', 'f')
#define BOX_TYPE_TFHD  MAKE_TYPE_VAL('t', 'f', 'h', 'd')
#define BOX_TYPE_TRUN  MAKE_TYPE_VAL('t', 'r', 'u', 'n')
#define BOX_TYPE_MDAT  MAKE_TYPE_VAL('m', 'd', 'a', 't')
#define BOX_TYPE_UDTA  MAKE_TYPE_VAL('u', 'd', 't', 'a')


static const value_string box_types[] = {
    { BOX_TYPE_FTYP, "File Type Box" },
    { BOX_TYPE_MOOV, "Movie Box" },
    { BOX_TYPE_MVHD, "Movie Header Box" },
    { BOX_TYPE_TRAK, "Track Box" },
    { BOX_TYPE_TKHD, "Track Header Box" },
    { BOX_TYPE_MDIA, "Media Box" },
    { BOX_TYPE_MDHD, "Media Header Box" },
    { BOX_TYPE_HDLR, "Handler Reference Box" },
    { BOX_TYPE_MINF, "Media Information Box" },
    { BOX_TYPE_VMHD, "Video Media Header Box" },
    { BOX_TYPE_SMHD, "Sound Media Header Box" },
    { BOX_TYPE_DINF, "Data Information Box" },
    { BOX_TYPE_DREF, "Data Reference Box" },
    { BOX_TYPE_STBL, "Sample to Group Box" },
    { BOX_TYPE_STTS, "Decoding Time To Sample Box" },
    { BOX_TYPE_CTTS, "Composition Time To Sample Box" },
    { BOX_TYPE_STSD, "Sample Description Box" },
    { BOX_TYPE_STSZ, "Sample Size Box" },
    { BOX_TYPE_STSC, "Sample To Chunk Box" },
    { BOX_TYPE_STCO, "Chunk Offset Box" },
    { BOX_TYPE_STSS, "Sync Sample Table" },
    { BOX_TYPE_MVEX, "Movie Extends Box" },
    { BOX_TYPE_MOOF, "Movie Fragment Box" },
    { BOX_TYPE_MEHD, "Movie Extends Header Box" },
    { BOX_TYPE_TREX, "Track Extends Box" },
    { BOX_TYPE_MFHD, "Movie Fragment Header Box" },
    { BOX_TYPE_TRAF, "Track Fragment Box" },
    { BOX_TYPE_TFHD, "Track Fragment Header Box" },
    { BOX_TYPE_TRUN, "Track Fragment Run Box" },
    { BOX_TYPE_MDAT, "Media Data Box" },
    { BOX_TYPE_UDTA, "User Data Box" },
    { 0, NULL }
};

/* convert a decimal number x into a double 0.x (e.g. 123 becomes 0.123) */
static inline double
make_fract(guint x)
{
    if (x==0)
        return 0.0;

    return (double)(x / exp(log(10.0)*(1+floor(log((double)x)/log(10.0))))); 
}

static gint
dissect_mp4_mvhd_body(tvbuff_t *tvb, gint offset, gint len _U_,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset_start;

    offset_start = offset;
    proto_tree_add_item(tree, hf_mp4_full_box_ver,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    offset += 3;

    return offset-offset_start;
}

static gint
dissect_mp4_mfhd_body(tvbuff_t *tvb, gint offset, gint len _U_,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset_start;

    offset_start = offset;
    proto_tree_add_item(tree, hf_mp4_full_box_ver,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    offset += 3;

    proto_tree_add_item(tree, hf_mp4_mfhd_seq_num,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset-offset_start;
}


static gint
dissect_mp4_tkhd_body(tvbuff_t *tvb, gint offset, gint len _U_,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint     offset_start;
    guint8   version;
    guint8   time_len;
    double   width, height;
    guint16  fract_dec;

    offset_start = offset;

    version = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mp4_full_box_ver,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* XXX dissect the flags */
    proto_tree_add_text(tree, tvb, offset, 3, "Flags");
    offset += 3;

    time_len = (version==0) ? 4 : 8;
    proto_tree_add_item(tree, hf_mp4_tkhd_creat_time,
            tvb, offset, time_len, ENC_BIG_ENDIAN);
    offset += time_len;
    proto_tree_add_item(tree, hf_mp4_tkhd_mod_time,
            tvb, offset, time_len, ENC_BIG_ENDIAN);
    offset += time_len;

    proto_tree_add_item(tree, hf_mp4_tkhd_track_id,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset += 4;   /* 32bit reserved */

    proto_tree_add_item(tree, hf_mp4_tkhd_duration,
            tvb, offset, time_len, ENC_BIG_ENDIAN);
    offset += time_len;

    offset += 2*4; /* 2*32bit reserved */
    offset += 2;   /* 16bit layer */
    offset += 2;   /* 16bit alternate_group */
    offset += 2;   /* 16bit volume */
    offset += 2;   /* 16bit reserved */
    offset += 9*4; /* 9*32bit matrix */

    width = tvb_get_ntohs(tvb, offset);
    fract_dec = tvb_get_ntohs(tvb, offset+2);
    width += make_fract(fract_dec);
    proto_tree_add_double_format_value(tree, hf_mp4_tkhd_width,
            tvb, offset, 4, width, "%f", width);
    offset += 4;

    height = tvb_get_ntohs(tvb, offset);
    fract_dec = tvb_get_ntohs(tvb, offset+2);
    height += make_fract(fract_dec);
    proto_tree_add_double_format_value(tree, hf_mp4_tkhd_height,
            tvb, offset, 4, height, "%f", height);
    offset += 4;

    return offset-offset_start;
}


static gint
dissect_mp4_ftyp_body(tvbuff_t *tvb, gint offset, gint len,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset_start;

    offset_start = offset;
    proto_tree_add_item(tree, hf_mp4_ftyp_brand,
            tvb, offset, 4, ENC_ASCII|ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_mp4_ftyp_ver,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    while ((offset-offset_start) < len) {
        proto_tree_add_item(tree, hf_mp4_ftyp_add_brand,
                tvb, offset, 4, ENC_ASCII|ENC_NA);
        offset += 4;
    }

    return offset - offset_start;
}

/* dissect a box, return its (standard or extended) length or 0 for error */
static gint
dissect_mp4_box(guint32 parent_box_type _U_,
        tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    gint        offset_start;
    guint64     box_size;
    guint32     box_type;
    guint8     *box_type_str;
    proto_item *type_pi, *size_pi, *ext_size_pi = NULL;
    proto_tree *box_tree;
    gint        ret;
    gint        body_size;


    offset_start = offset;

    /* the following mechanisms are not supported for now
       - size==0, indicating that the box extends to the end of the file
       - extended box types */

    box_size = (guint64)tvb_get_ntohl(tvb, offset);
    if ((box_size != BOX_SIZE_EXTENDED) && (box_size < MIN_BOX_SIZE))
        return -1;

    box_type = tvb_get_ntohl(tvb, offset+4);
    box_type_str = tvb_get_string_enc(wmem_packet_scope(), tvb,
            offset+4, 4, ENC_ASCII|ENC_NA);

    box_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_mp4_box, &type_pi, "%s (%s)",
            val_to_str_const(box_type, box_types, "unknown"), box_type_str);

    size_pi = proto_tree_add_item(box_tree, hf_mp4_box_size,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    if (box_size == BOX_SIZE_EXTENDED)
        proto_item_append_text(size_pi, " (actual size is in largesize)");

    offset += 4;
    proto_tree_add_item(box_tree, hf_mp4_box_type_str,
            tvb, offset, 4, ENC_ASCII|ENC_NA);
    offset += 4;

    if (box_size == BOX_SIZE_EXTENDED) {
        box_size = tvb_get_ntoh64(tvb, offset);
        ext_size_pi = proto_tree_add_item(box_tree, hf_mp4_box_largesize,
                tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (box_size > G_MAXINT) {
        /* this should be ok for ext_size_pi==NULL */
        expert_add_info(pinfo, ext_size_pi, &ei_mp4_box_too_large);
        return -1;
    }
    proto_item_set_len(type_pi, (gint)box_size);
    body_size = (gint)box_size - (offset-offset_start);

    /* we do not dissect full box version and flags here
       these two components are required by the function dissecting the body
       some fields of the body depend on the version and flags */

    /* XXX - check parent box if supplied */
    switch (box_type) {
        case BOX_TYPE_FTYP:
            dissect_mp4_ftyp_body(tvb, offset, body_size, pinfo, box_tree);
            break;
        case BOX_TYPE_MVHD:
            dissect_mp4_mvhd_body(tvb, offset, body_size, pinfo, box_tree);
            break;
        case BOX_TYPE_MFHD:
            dissect_mp4_mfhd_body(tvb, offset, body_size, pinfo, box_tree);
            break;
        case BOX_TYPE_TKHD:
            dissect_mp4_tkhd_body(tvb, offset, body_size, pinfo, box_tree);
            break;
        case BOX_TYPE_MOOV:
        case BOX_TYPE_MOOF:
        case BOX_TYPE_STBL:
        case BOX_TYPE_MDIA:
        case BOX_TYPE_TRAK:
        case BOX_TYPE_TRAF:
        case BOX_TYPE_MINF:
        case BOX_TYPE_MVEX:
        case BOX_TYPE_DINF:
        case BOX_TYPE_UDTA:
            while (offset-offset_start < (gint)box_size) {
                ret = dissect_mp4_box(box_type, tvb, offset, pinfo, box_tree);
                if (ret <= 0)
                    break;
                offset += ret;
            }
            break;
        default:
            break;
    }

    return (gint)box_size;
}


static int
dissect_mp4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        offset = 0;
    guint32     box_type;
    proto_item *pi;
    proto_tree *mp4_tree;
    gint        ret;

    /* to make sure that we have an mp4 file, we check that it starts with
        a box of a known type
       please note that we do not allow the first box to be an extended box
       this detection should be safe as long as the dissector is only called for
        the video/mp4 mime type
       when we read mp4 files directly, we might need stricter checks here */
    if (tvb_reported_length(tvb) < MIN_BOX_SIZE)
        return 0;
    box_type = tvb_get_ntohl(tvb, 4);
    if (try_val_to_str(box_type, box_types) == NULL)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MP4");
    col_clear(pinfo->cinfo, COL_INFO);

    pi = proto_tree_add_protocol_format(tree, proto_mp4,
            tvb, 0, (gint)tvb_reported_length(tvb), "MP4");
    mp4_tree = proto_item_add_subtree(pi, ett_mp4);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        ret = dissect_mp4_box(BOX_TYPE_NONE, tvb, offset, pinfo, mp4_tree);
        if (ret <= 0)
            break;
        offset += ret;
    }

    return offset;
}

void
proto_register_mp4(void)
{
    static hf_register_info hf[] = {
        { &hf_mp4_box_size,
            { "Box size", "mp4.box.size", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_box_type_str,
            { "Box type", "mp4.box.type_str", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_box_largesize,
            { "Box size (largesize)", "mp4.box.largesize", FT_UINT64, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_full_box_ver,
            { "Box version", "mp4.full_box.version", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_ftyp_brand,
            { "Brand", "mp4.ftyp.brand", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_ftyp_ver,
            { "Version", "mp4.ftyp.version", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_ftyp_add_brand,
            { "Additional brand", "mp4.ftyp.additional_brand", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_mp4_mfhd_seq_num,
            { "Sequence number", "mp4.mfhd.sequence_number", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_creat_time,
            { "Creation time", "mp4.tkhd.creation_time", FT_UINT64,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_mod_time,
            { "Modification time", "mp4.tkhd.modification_time", FT_UINT64,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_track_id,
            { "Track ID", "mp4.tkhd.track_id", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_duration,
            { "Duration", "mp4.tkhd.duration", FT_UINT64,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_width,
            { "Width", "mp4.tkhd.width", FT_DOUBLE,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_height,
            { "Height", "mp4.tkhd.height", FT_DOUBLE,
                BASE_NONE, NULL, 0, NULL, HFILL } }
    };

    static gint *ett[] = {
        &ett_mp4,
        &ett_mp4_box
    };

    static ei_register_info ei[] = {
        { &ei_mp4_box_too_large,
            { "mp4.box_too_large", PI_PROTOCOL, PI_WARN,
                "box size too large, dissection of this box is not supported", EXPFILL }}
    };

    expert_module_t *expert_mp4;

    proto_mp4 = proto_register_protocol("MP4 / ISOBMFF file format", "mp4", "mp4");

    proto_register_field_array(proto_mp4, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mp4 = expert_register_protocol(proto_mp4);
    expert_register_field_array(expert_mp4, ei, array_length(ei));
}

void
proto_reg_handoff_mp4(void)
{
    dissector_handle_t mp4_handle = new_create_dissector_handle(dissect_mp4, proto_mp4);
    dissector_add_string("media_type", "video/mp4", mp4_handle);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
