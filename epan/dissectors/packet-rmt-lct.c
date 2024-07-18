/* packet-rmt-lct.c
 * Reliable Multicast Transport (RMT)
 * LCT Building Block dissector
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 * Copyright 2023, Sergey V. Lobanov <sergey@lobanov.in>
 *
 * Layered Coding Transport (LCT):
 * -------------------------------
 *
 * Provides transport level support for reliable content delivery
 * and stream delivery protocols. LCT is specifically designed to
 * support protocols using IP multicast, but also provides support
 * to protocols that use unicast. LCT is compatible with congestion
 * control that provides multiple rate delivery to receivers and
 * is also compatible with coding techniques that provide
 * reliable delivery of content.
 *
 * References:
 *     RFC 3451, Layered Coding Transport (LCT) Building Block
 *     RFC 5651, Layered Coding Transport (LCT) Building Block
 *     RFC 5775, Asynchronous Layered Coding (ALC) Protocol Instantiation
 *
 *     ATSC3 Signaling, Delivery, Synchronization, and Error Protection (A/331)
 *     https://www.atsc.org/atsc-documents/3312017-signaling-delivery-synchronization-error-protection/
 *
 *     IANA Layered Coding Transport (LCT) Header Extension Types
 *     https://www.iana.org/assignments/lct-header-extensions/lct-header-extensions.txt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>

#include "packet-rmt-common.h"

#define LCT_SCT_FLAG           0x0008
#define LCT_ERT_FLAG           0x0004
#define LCT_CLOSE_SESSION_FLAG 0x0002
#define LCT_CLOSE_OBJECT_FLAG  0x0001
#define LCT_PSI                0x0300
#define LCT_PSI_MSB            0x0200

void proto_register_rmt_lct(void);

static int proto_rmt_lct;

static int hf_version;
static int hf_psi;
static int hf_spi;
static int hf_fsize_header;
static int hf_fsize_cci;
static int hf_fsize_tsi;
static int hf_fsize_toi;
static int hf_flags_header;
static int hf_flags_sct_present;
static int hf_flags_ert_present;
static int hf_flags_close_session;
static int hf_flags_close_object;
static int hf_hlen;
static int hf_codepoint;
static int hf_codepoint_atsc3;
static int hf_cci;
static int hf_tsi16;
static int hf_tsi32;
static int hf_tsi48;
static int hf_toi16;
static int hf_toi32;
static int hf_toi48;
static int hf_toi64;
static int hf_toi_extended;
static int hf_sct;
static int hf_ert;
static int hf_ext;
static int hf_hec_type;
static int hf_hec_len;
static int hf_hec_data;
static int hf_send_rate;
static int hf_cenc;
static int hf_flute_version;
static int hf_fdt_instance_id;
static int hf_ext_tol_48_transfer_len;
static int hf_ext_tol_24_transfer_len;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_cc_rate;
static int hf_cc_rtt;
static int hf_cc_flags;
static int hf_cc_loss;
static int hf_cc_sequence;

static int ett_main;
static int ett_fsize;
static int ett_flags;
static int ett_ext;
static int ett_ext_ext;
static int ett_psi;

/* Enumerated data types for LCT preferences */
const enum_val_t enum_lct_ext_192[] =
{
    { "none",  "Don't decode", LCT_PREFS_EXT_192_NONE },
    { "flute", "Decode as FLUTE extension (EXT_FDT)", LCT_PREFS_EXT_192_FLUTE },
    { NULL, NULL, 0 }
};

const enum_val_t enum_lct_ext_193[] =
{
    { "none", "Don't decode", LCT_PREFS_EXT_193_NONE },
    { "flute", "Decode as FLUTE extension (EXT_CENC)", LCT_PREFS_EXT_193_FLUTE },
    { NULL, NULL, 0 }
};

const enum_val_t enum_lct_atsc3_mode[] =
{
    { "disabled", "Do not decode as ATSC3 data", LCT_ATSC3_MODE_DISABLED },
    { "auto", "Auto Detect (if encap is ALP)", LCT_ATSC3_MODE_AUTO },
    { "force", "Force to decode as ATSC3 data", LCT_ATSC3_MODE_FORCE },
    { NULL, NULL, 0 }
};

static const value_string hec_type_vals[] = {
    {   0,  "EXT_NOP, No-Operation" },
    {   1,  "EXT_AUTH, Packet authentication" },
    {   2,  "EXT_TIME" },
    {  64,  "EXT_FTI, FEC Object Transmission Information" },
    {  65,  "DVB-IPTV CDS Completion Poll Request LCT" },
    {  66,  "EXT_ROUTE_PRESENTATION_TIME" },
    {  67,  "EXT_TOL, Transport Object Length (48-bit version)" },
    { 128,  "EXT_RATE, Send Rate" },
    { 192,  "EXT_FDT, FDT Instance Header" },
    { 193,  "EXT_CENC, FDT Instance Content Encoding" },
    { 194,  "EXT_TOL, Transport Object Length (24-bit version)" },

    { 0,  NULL }
};

static const value_string cp_type_vals[] = {
    { 1,  "NRT, File Mode" },
    { 2,  "NRT, Entity Mode" },
    { 3,  "NRT, Unsigned Package Mode" },
    { 4,  "NRT, Signed Package Mode" },
    { 5,  "New IS, timeline changed" },
    { 6,  "New IS, timeline continued" },
    { 7,  "Redundant IS" },
    { 8,  "Media Segment, File Mode" },
    { 9,  "Media Segment, Entity Mode" },

    { 0,  NULL }
};

/* LCT helper functions */
/* ==================== */

static void lct_timestamp_parse(uint32_t t, nstime_t* s)
{
    s->secs  = t / 1000;
    s->nsecs = (t % 1000) * 1000000;
}

double rmt_decode_send_rate(uint16_t send_rate )
{
    double value;

    value = (send_rate >> 4) * 10.0 / 4096.0 * pow(10.0, (send_rate & 0xf));
    return value;
}


int lct_ext_decode(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, unsigned offset, unsigned offset_max, lct_data_exchange_t *data_exchange,
                   int hfext, int ettext)
{
    uint8_t     het;
    unsigned    i, count = 0;
    unsigned    length,
                tmp_offset   = offset,
                start_offset = offset;
    proto_item *ti;
    proto_tree *hec_tree, *ext_tree;
    double      cc_loss;

    /* Figure out the extension count */
    while (tmp_offset < offset_max)
    {
        het = tvb_get_uint8(tvb, tmp_offset);
        if (het <= 127)
        {
            length = tvb_get_uint8(tvb, tmp_offset+1)*4;
        }
        else
        {
            length = 4;
        }

        /* Prevents infinite loops */
        if (length == 0)
            break;

        tmp_offset += length;
        count++;
    }

    if (count == 0)
        return 0;

    ti = proto_tree_add_uint(tree, hfext, tvb, offset, tmp_offset - offset, count);
    hec_tree = proto_item_add_subtree(ti, ettext);

    for (i = 0; i < count; i++)
    {
        het = tvb_get_uint8(tvb, offset);
        if (het <= 127)
        {
            length = tvb_get_uint8(tvb, offset+1)*4;
        }
        else
        {
            length = 4;
        }

        ti = proto_tree_add_item(hec_tree, hf_hec_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        ext_tree = proto_item_add_subtree(ti, ett_ext_ext);
        proto_item_set_len(ti, length);

        if (het <= 127)
        {
            proto_tree_add_item(ext_tree, hf_hec_len, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        }

        switch (het)
        {
            case 0: /* EXT_NOP */
            case 1: /* EXT_AUTH */
            default:
                proto_tree_add_item(ext_tree, hf_hec_data, tvb, offset+2, length-2, ENC_NA);
                break;

            case 3: /* EXT_CC RATE */
                proto_tree_add_item(ext_tree, hf_cc_sequence, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(ext_tree, hf_cc_flags, tvb, offset+4, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ext_tree, hf_cc_rtt, tvb, offset+5, 1, ENC_BIG_ENDIAN);
                cc_loss = tvb_get_ntohs(tvb, offset+6)/65535.0;
                proto_tree_add_double(ext_tree, hf_cc_loss, tvb, offset+6, 2, cc_loss);
                proto_tree_add_item(ext_tree, hf_cc_rate, tvb, offset+8, 2, ENC_BIG_ENDIAN);
                break;

            case 64: /* EXT_FTI */
                fec_decode_ext_fti(tvb, pinfo, ext_tree, offset,
                                   (data_exchange == NULL) ? 0 :
                                   data_exchange->is_sp ? 0 :data_exchange->codepoint);
                break;

            case 67: /* EXT_TOL_48 */
                proto_tree_add_item(ext_tree, hf_ext_tol_48_transfer_len, tvb, offset+1, 6, ENC_BIG_ENDIAN);
                break;

            case 128: /* EXT_RATE */
                proto_tree_add_double(ext_tree, hf_send_rate, tvb, offset+2, 2,
                                      rmt_decode_send_rate(tvb_get_ntohs(tvb, offset+2)));
                break;

            case 192: /* EXT_FDT */
                if ((data_exchange != NULL) && (data_exchange->ext_192 == LCT_PREFS_EXT_192_FLUTE))
                {
                    proto_tree_add_item(ext_tree, hf_flute_version, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ext_tree, hf_fdt_instance_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                    data_exchange->is_flute = true;
                }
                break;

            case 193: /* EXT_CENC */
                if ((data_exchange != NULL) && (data_exchange->ext_193 == LCT_PREFS_EXT_193_FLUTE))
                {
                    proto_tree_add_item(ext_tree, hf_cenc, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                }
                break;

            case 194: /* EXT_TOL_24 */
                proto_tree_add_item(ext_tree, hf_ext_tol_24_transfer_len, tvb, offset+1, 3, ENC_BIG_ENDIAN);
                break;
        }

        offset += length;
    }

    return offset-start_offset;
}

/* LCT exported functions */
/* ====================== */

/* Dissection */
/* ---------- */

/* Dissect an LCT header:
 * l - ptr to the logical LCT packet representation to fill, and related wireshark stuffs
 * f - ptr to the FEC infos to fill (EXT_FTI), and related wireshark stuffs
 * tvb - buffer
 * pinfo - packet info
 * tree - tree where to add LCT header subtree
 * offset - ptr to offset to use and update
 */

/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   V   | C | r |S| O |H|T|R|A|B|   HDR_LEN     | Codepoint (CP)|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Congestion Control Information (CCI, length = 32*(C+1) bits)  |
  |                          ...                                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Transport Session Identifier (TSI, length = 32*S+16*H bits)  |
  |                          ...                                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Transport Object Identifier (TOI, length = 32*O+16*H bits)  |
  |                          ...                                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               Sender Current Time (SCT, if T = 1)             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |              Expected Residual Time (ERT, if R = 1)           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                Header Extensions (if applicable)              |
  |                          ...                                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Figure 1 - Default LCT header format

*/
static int
dissect_lct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int      offset = 0;
    uint16_t buffer16;

    uint8_t  cci_size;
    uint8_t  tsi_size;
    uint8_t  toi_size;
    uint64_t tsi;
    uint64_t toi    = 0;
    uint16_t hlen;
    nstime_t tmp_time;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *lct_tree = tree, *lct_fsize_tree, *lct_flags_tree;

    lct_data_exchange_t *data_exchange = (lct_data_exchange_t *)data;

    /* LCT fixed-size fields dissection */
    /* -------------------------------- */
    buffer16 = tvb_get_ntohs(tvb, offset);

    cci_size = ((buffer16 & 0x0C00) >> 10) * 4 + 4;
    tsi_size = ((buffer16 & 0x0080) >> 7) * 4 + ((buffer16 & 0x0010) >> 4) * 2;
    toi_size = ((buffer16 & 0x0060) >> 5) * 4 + ((buffer16 & 0x0010) >> 4) * 2;

    hlen = tvb_get_uint8(tvb, offset+2) * 4;

    if (data_exchange != NULL)
    {
        data_exchange->codepoint = tvb_get_uint8(tvb, offset+3);
        data_exchange->is_flute = false;
    }

    if (tree)
    {
        /* Create the LCT subtree */
        ti = proto_tree_add_item(tree, proto_rmt_lct, tvb, offset, hlen, ENC_NA);
        lct_tree = proto_item_add_subtree(ti, ett_main);

        /* Fill the LCT subtree */

        /* LCT version number (4 bits) */
        proto_tree_add_item(lct_tree, hf_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(lct_tree, hf_psi, tvb, offset, 2, ENC_BIG_ENDIAN);

        if ((data_exchange != NULL) && data_exchange->is_atsc3) {
            uint16_t psi_msb = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & LCT_PSI_MSB;
            data_exchange->is_sp = !!psi_msb;
            proto_tree *lct_psi_tree = proto_item_add_subtree(ti, ett_psi);
            proto_tree_add_item(lct_psi_tree, hf_spi, tvb, offset, 2, ENC_BIG_ENDIAN);
        }

        ti = proto_tree_add_item(lct_tree, hf_fsize_header, tvb, offset, 2, ENC_BIG_ENDIAN);
        lct_fsize_tree = proto_item_add_subtree(ti, ett_fsize);

        /* Fill the LCT fsize subtree */
        PROTO_ITEM_SET_GENERATED(
            proto_tree_add_uint(lct_fsize_tree, hf_fsize_cci, tvb, offset, 1, cci_size)
        );
        PROTO_ITEM_SET_GENERATED(
            proto_tree_add_uint(lct_fsize_tree, hf_fsize_tsi, tvb, offset, 2, tsi_size)
        );
        PROTO_ITEM_SET_GENERATED(
            proto_tree_add_uint(lct_fsize_tree, hf_fsize_toi, tvb, offset, 2, toi_size)
        );

        ti = proto_tree_add_item(lct_tree, hf_flags_header, tvb, offset, 2, ENC_BIG_ENDIAN);
        lct_flags_tree = proto_item_add_subtree(ti, ett_flags);

        /* Fill the LCT flags subtree */
        proto_tree_add_item(lct_flags_tree, hf_flags_sct_present, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(lct_flags_tree, hf_flags_ert_present, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(lct_flags_tree, hf_flags_close_session, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(lct_flags_tree, hf_flags_close_object, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree_add_uint(lct_tree, hf_hlen, tvb, offset+2, 1, hlen);
        if ((data_exchange != NULL) && data_exchange->is_atsc3) {
            if(data_exchange->codepoint < 128) {
                proto_tree_add_item(lct_tree, hf_codepoint_atsc3, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            } else {
                proto_tree_add_uint_format_value(lct_tree, hf_codepoint_atsc3, tvb, offset+3, 1,
                    data_exchange->codepoint, "Defined by SLS (%u)", data_exchange->codepoint);
            }
        } else {
            proto_tree_add_item(lct_tree, hf_codepoint, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }

    }

    offset += 4;

    /* LCT variable-size and optional fields dissection */
    /* ------------------------------------------------ */

    /* Congestion Control Information (CCI) */
    if (cci_size > 0) {
        proto_tree_add_item(lct_tree, hf_cci, tvb, offset, cci_size, ENC_NA);
        offset += cci_size;
    }

    /* Transmission Session Identifier (TSI) */
    if (tsi_size > 0) {

        switch (tsi_size)
        {
            case 2:
                proto_tree_add_item(lct_tree, hf_tsi16, tvb, offset, tsi_size, ENC_BIG_ENDIAN);
                tsi = tvb_get_ntohs(tvb, offset);
                break;

            case 4:
                proto_tree_add_item(lct_tree, hf_tsi32, tvb, offset, tsi_size, ENC_BIG_ENDIAN);
                tsi = tvb_get_ntohl(tvb, offset);
                break;

            case 6:
                proto_tree_add_item(lct_tree, hf_tsi48, tvb, offset, tsi_size, ENC_BIG_ENDIAN);
                tsi = tvb_get_ntoh48(tvb, offset);
                break;
            default:
                tsi = 0;
                break;
        }

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "TSI: %" PRIu64, tsi);
        offset += tsi_size;
    }

    /* Transmission Object Identifier (TOI) */
    if (toi_size > 0) {

        switch (toi_size)
        {
            case 2:
                proto_tree_add_item(lct_tree, hf_toi16, tvb, offset, toi_size, ENC_BIG_ENDIAN);
                toi = tvb_get_ntohs(tvb, offset);
                break;

            case 4:
                proto_tree_add_item(lct_tree, hf_toi32, tvb, offset, toi_size, ENC_BIG_ENDIAN);
                toi = tvb_get_ntohl(tvb, offset);
                break;

            case 6:
                proto_tree_add_item(lct_tree, hf_toi48, tvb, offset, toi_size, ENC_BIG_ENDIAN);
                toi = tvb_get_ntoh48(tvb, offset);
                break;

            case 8:
                proto_tree_add_item(lct_tree, hf_toi64, tvb, offset, toi_size, ENC_BIG_ENDIAN);
                toi = tvb_get_ntoh64(tvb, offset);
                break;

            case 10:
                proto_tree_add_item(lct_tree, hf_toi64, tvb, offset+2, 8, ENC_BIG_ENDIAN);
                proto_tree_add_item(lct_tree, hf_toi_extended, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;

            case 12:
                proto_tree_add_item(lct_tree, hf_toi64, tvb, offset+4, 8, ENC_BIG_ENDIAN);
                proto_tree_add_item(lct_tree, hf_toi_extended, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;

            case 14:
                proto_tree_add_item(lct_tree, hf_toi64, tvb, offset+6, 8, ENC_BIG_ENDIAN);
                proto_tree_add_item(lct_tree, hf_toi_extended, tvb, offset, 6, ENC_BIG_ENDIAN);
                break;
            default:
                break;
        }

        if (toi_size <= 8)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "TOI: %" PRIu64, toi);
        else
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "TOI: 0x%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, toi_size));
        offset += toi_size;
    }

    if (buffer16 & LCT_CLOSE_SESSION_FLAG)
        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "Close session");

    if (buffer16 & LCT_CLOSE_OBJECT_FLAG)
        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "Close object");

    if ((data_exchange != NULL) && data_exchange->is_atsc3) {
        if (data_exchange->is_sp) {
            /* According to A/331:2022-11 A.3.4 Usage of ALC and LCT */
            col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "(Source)");
        } else {
            /* According to A/331:2022-11 A.4.2.4 Repair Packet Structure */
            col_append_sep_str(pinfo->cinfo, COL_INFO, " ", " (Repair)");
        }
    }

    /* Sender Current Time (SCT) */
    if (buffer16 & LCT_SCT_FLAG) {
        lct_timestamp_parse(tvb_get_ntohl(tvb, offset), &tmp_time);
        proto_tree_add_time(lct_tree, hf_sct, tvb, offset, 4, &tmp_time);
        offset += 4;
    }

    /* Expected Residual Time (ERT) */
    if (buffer16 & LCT_ERT_FLAG) {
        lct_timestamp_parse(tvb_get_ntohl(tvb, offset), &tmp_time);
        proto_tree_add_time(lct_tree, hf_ert, tvb, offset, 4, &tmp_time);
        offset += 4;
    }

    /* LCT header extensions, if applicable */
    /* ------------------------------------ */
    lct_ext_decode(lct_tree, tvb, pinfo, offset, hlen, data_exchange, hf_ext, ett_ext);

    return hlen;
}

void
proto_register_rmt_lct(void)
{
    static hf_register_info hf[] = {
        { &hf_version,
          { "Version", "rmt-lct.version",
            FT_UINT16, BASE_DEC, NULL, 0xF000,
            NULL, HFILL }
        },
        { &hf_psi,
          { "Protocol-Specific Indication", "rmt-lct.psi",
            FT_UINT16, BASE_HEX, NULL, LCT_PSI,
            NULL, HFILL }
        },
        { &hf_spi,
          { "Source Packet Indicator", "rmt-lct.spi",
            FT_BOOLEAN, 16, NULL, LCT_PSI_MSB,
            NULL, HFILL }
        },
        { &hf_fsize_header,
          { "Field size flags", "rmt-lct.fsize",
            FT_UINT16, BASE_HEX, NULL, 0x0FC0,
            NULL, HFILL }
        },
        { &hf_fsize_cci,
          { "Congestion Control Information field size", "rmt-lct.fsize.cci",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsize_tsi,
          { "Transport Session Identifier field size", "rmt-lct.fsize.tsi",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsize_toi,
          { "Transport Object Identifier field size", "rmt-lct.fsize.toi",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_flags_header,
          { "Flags", "rmt-lct.flags",
            FT_UINT16, BASE_HEX, NULL, 0x001F,
            NULL, HFILL }
        },
        { &hf_flags_sct_present,
          { "Sender Current Time present flag", "rmt-lct.flags.sct_present",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), LCT_SCT_FLAG,
            NULL, HFILL }
        },
        { &hf_flags_ert_present,
          { "Expected Residual Time present flag", "rmt-lct.flags.ert_present",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), LCT_ERT_FLAG,
            NULL, HFILL }
        },
        { &hf_flags_close_session,
          { "Close Session flag", "rmt-lct.flags.close_session",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), LCT_CLOSE_SESSION_FLAG,
            NULL, HFILL }
        },
        { &hf_flags_close_object,
          { "Close Object flag", "rmt-lct.flags.close_object",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), LCT_CLOSE_OBJECT_FLAG,
            NULL, HFILL }
        },
        { &hf_hlen,
          { "Header length", "rmt-lct.hlen",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_codepoint,
          { "Codepoint", "rmt-lct.codepoint",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_codepoint_atsc3,
          { "Codepoint", "rmt-lct.codepoint",
            FT_UINT8, BASE_DEC, VALS(cp_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_cci,
          { "Congestion Control Information", "rmt-lct.cci",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tsi16,
          { "Transport Session Identifier", "rmt-lct.tsi",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tsi32,
          { "Transport Session Identifier", "rmt-lct.tsi",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tsi48,
          { "Transport Session Identifier", "rmt-lct.tsi64",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_toi16,
          { "Transport Object Identifier", "rmt-lct.toi",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_toi32,
          { "Transport Object Identifier", "rmt-lct.toi",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_toi48,
          { "Transport Object Identifier", "rmt-lct.toi64",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_toi64,
          { "Transport Object Identifier (up to 64 bits)", "rmt-lct.toi64",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_toi_extended,
          { "Transport Object Identifier (bits 64-112)", "rmt-lct.toi_extended",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sct,
          { "Sender Current Time", "rmt-lct.sct",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ert,
          { "Expected Residual Time", "rmt-lct.ert",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ext,
          { "Extension count", "rmt-lct.ext",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hec_type,
          { "Header Extension Type (HET)", "rmt-lct.hec.type",
            FT_UINT8, BASE_DEC, VALS(hec_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_hec_len,
          { "Header Extension Length (HEL)", "rmt-lct.hec.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hec_data,
          { "Header Extension Data", "rmt-lct.hec.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_send_rate,
          { "Send Rate", "rmt-lct.send_rate",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cenc,
          { "Content Encoding Algorithm (CENC)", "rmt-lct.cenc",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_flute_version,
          { "FLUTE version (V)", "rmt-lct.flute_version",
            FT_UINT32, BASE_DEC, NULL, 0x00F00000,
            NULL, HFILL }
        },
        { &hf_fdt_instance_id,
          { "FDT Instance ID", "rmt-lct.fdt_instance_id",
            FT_UINT32, BASE_DEC, NULL, 0x000FFFFF,
            NULL, HFILL }
        },
        { &hf_ext_tol_48_transfer_len,
          { "EXT_TOL_48 Transfer Length", "rmt-lct.ext_tol_transfer_len",
            FT_UINT48, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ext_tol_24_transfer_len,
          { "EXT_TOL_24 Transfer Length", "rmt-lct.ext_tol_transfer_len",
            FT_UINT24, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_cc_sequence,
          { "CC Sequence", "rmt-lct.cc_sequence",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cc_flags,
          { "CC Flags", "rmt-lct.cc_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cc_rtt,
          { "CC RTT", "rmt-lct.cc_rtt",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cc_loss,
          { "CC Loss", "rmt-lct.cc_loss",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cc_rate,
          { "CC Rate", "rmt-lct.cc_rate",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_main,
        &ett_fsize,
        &ett_flags,
        &ett_ext,
        &ett_ext_ext,
        &ett_psi,
    };

    /* Register the protocol name and description */
    proto_rmt_lct = proto_register_protocol("Layered Coding Transport", "RMT-LCT", "rmt-lct");
    register_dissector("rmt-lct", dissect_lct, proto_rmt_lct);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_rmt_lct, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
