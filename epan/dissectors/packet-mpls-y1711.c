/* packet-mpls-y1711.c
 * Routines for (old) ITU-T MPLS OAM: it conforms to ITU-T Y.1711 and RFC 3429
 *
 * Copyright 2006, 2011 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
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

/*
 * FF: NOTES
 *
 * - this should dissect OAM pdus (identified by the LABEL_OAM_ALERT = 14
 *   label) as described in ITU-T Y.1711 and RFC 3429.
 *
 * - this code used to be (since 2006) in packet-mpls.c ... nobody on this
 *   planet is using Y.1711 today (?), so thanks to the mpls subdissector
 *   table indexed by label value it has been moved here.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>

#include "packet-mpls.h"

static gint proto_mpls_y1711 = -1;

static int hf_mpls_y1711_function_type = -1;
static int hf_mpls_y1711_ttsi = -1;
static int hf_mpls_y1711_frequency = -1;
static int hf_mpls_y1711_defect_type = -1;
static int hf_mpls_y1711_defect_location = -1;
static int hf_mpls_y1711_bip16 = -1;

static gint ett_mpls_y1711 = -1;

static dissector_handle_t mpls_y1711_handle;

static const value_string y1711_function_type_vals[] = {
    {0x00, "Reserved"                               },
    {0x01, "CV (Connectivity Verification)"         },
    {0x02, "FDI (Forward Defect Indicator)"         },
    {0x03, "BDI (Backward Defect Indicator)"        },
    {0x04, "Reserved for Performance packets"       },
    {0x05, "Reserved for LB-Req (Loopback Request)" },
    {0x06, "Reserved for LB-Rsp (Loopback Response)"},
    {0x07, "FDD (Fast Failure Detection)"           },
    {0,    NULL                                     }
};

static const value_string y1711_frequency_vals[] = {
    {0x00, "Reserved"             },
    {0x01, "10 ms"                },
    {0x02, "20 ms"                },
    {0x03, "50 ms (default value)"},
    {0x04, "100 ms"               },
    {0x05, "200 ms"               },
    {0x06, "500 ms"               },
    /* 7-255 Reserved */
    {0,    NULL                   }
};

static const value_string y1711_defect_type_vals[] = {
    {0x0000, "Reserved"      },
    {0x0101, "dServer"       },
    {0x0102, "dPeerME"       },
    {0x0201, "dLOCV"         },
    {0x0202, "dTTSI_Mismatch"},
    {0x0203, "dTTSI_Mismerge"},
    {0x0204, "dExcess"       },
    {0x02FF, "dUnknown"      },
    {0xFFFF, "Reserved"      },
    {0,      NULL            }
};

static int
dissect_mpls_y1711(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree      *mpls_y1711_tree = NULL;
    struct mplsinfo *mplsinfo        = pinfo->private_data;
    proto_item      *ti              = NULL;
    int              functype        = -1;
    int              offset          = 0;

    const guint8 allone[]  = { 0xff, 0xff };
    const guint8 allzero[] = { 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00 };

    /*
     * if called with main tree == null just set col info with func type
     * string and return
     */
    if (!tree) {
        if (check_col(pinfo->cinfo, COL_INFO)) {
            if (tvb_bytes_exist(tvb, offset, 1)) {
                functype = tvb_get_guint8(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (Y.1711: %s)",
                                (functype == 0x01) ? "CV" :
                                (functype == 0x02) ? "FDI" :
                                (functype == 0x03) ? "BDI" :
                                (functype == 0x07) ? "FDD" :
                                "reserved/unknown");
            }
        }
        return 0;
    }

    /* sanity checks */
    if (!tvb_bytes_exist(tvb, offset, 44)) {
        /*
         * ITU-T Y.1711, 5.3: PDUs must have a minimum payload length of
         * 44 bytes
         */
        proto_tree_add_text(tree, tvb, offset, -1,
                            "Error: must have a minimum payload "
                            "length of 44 bytes");
        return 0;
    }

    ti = proto_tree_add_text(tree, tvb, offset, 44, "Y.1711 OAM");
    mpls_y1711_tree = proto_item_add_subtree(ti, ett_mpls_y1711);

    if (!mpls_y1711_tree)
        return 0;

    /* checks for exp, bos and ttl encoding */
    if (mplsinfo->label != LABEL_OAM_ALERT)
        proto_tree_add_text(mpls_y1711_tree, tvb, offset - 4, 3,
                            "Warning: Y.1711 but no OAM alert label (%d) ?!",
                            LABEL_OAM_ALERT);

    if (mplsinfo->exp != 0)
        proto_tree_add_text(mpls_y1711_tree, tvb, offset - 2, 1,
                            "Warning: Exp bits should be 0 for Y.1711");

    if (mplsinfo->bos != 1)
        proto_tree_add_text(mpls_y1711_tree, tvb, offset - 2, 1,
                            "Warning: S bit should be 1 for Y.1711");

    if (mplsinfo->ttl != 1)
        proto_tree_add_text(mpls_y1711_tree, tvb, offset - 1, 1,
                            "Warning: TTL should be 1 for Y.1711");

    /* starting dissection */
    functype = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(mpls_y1711_tree, hf_mpls_y1711_function_type, tvb,
                        offset, 1,
                        ENC_LITTLE_ENDIAN);
    offset++;

    switch (functype) {
    case 0x01: /* CV */
    {
        guint32 lsrid_ipv4addr;

        /* 3 octets reserved (all 0x00) */
        if (tvb_memeql(tvb, offset, allzero, 3) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 3,
                                "Error: these bytes are reserved and "
                                "must be 0x00");
        }
        offset += 3;

        /* ttsi (ipv4 flavor as in RFC 2373) */
        if (tvb_memeql(tvb, offset, allzero, 10) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 10,
                                "Error: these bytes are padding "
                                "and must be 0x00");
        }
        offset += 10;

        if (tvb_memeql(tvb, offset, allone, 2) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 2,
                                "Error: these bytes are padding "
                                "and must be 0xFF");
        }
        offset += 2;

        lsrid_ipv4addr = tvb_get_ipv4(tvb, offset);
        proto_tree_add_text(mpls_y1711_tree, tvb, offset, 4, "LSR ID: %s",
                            ip_to_str((guint8 *) &lsrid_ipv4addr));
        offset += 4;

        proto_tree_add_text(mpls_y1711_tree, tvb, offset, 4, "LSP ID: %d",
                            tvb_get_ntohl(tvb, offset));
        offset += 4;

        /* 18 octets of padding (all 0x00) */
        if (tvb_memeql(tvb, offset, allzero, 18) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 18,
                                "Error: these bytes are padding "
                                "and must be 0x00");
        }
        offset += 18;
    }
    break;

    case 0x02: /* FDI */
    case 0x03: /* BDI */
    {
        guint32 lsrid_ipv4addr;

        /* 1 octets reserved (all 0x00) */
        if (tvb_memeql(tvb, offset, allzero, 1) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 3,
                                "Error: this byte is reserved "
                                "and must be 0x00");
        }
        offset++;

        proto_tree_add_item(mpls_y1711_tree, hf_mpls_y1711_defect_type, tvb,
                            offset, 2,
                            ENC_LITTLE_ENDIAN);
        offset += 2;

        /*
         * ttsi (ipv4 flavor as in RFC 2373) is optional if not used must
         * be set to all 0x00
         */
        if (tvb_memeql(tvb, offset, allzero, 20) == 0) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 20,
                                "TTSI not preset (optional for FDI/BDI)");
            offset += 20;
        } else {
            if (tvb_memeql(tvb, offset, allzero, 10) == -1) {
                proto_tree_add_text(mpls_y1711_tree, tvb, offset, 10,
                                    "Error: these bytes are padding and "
                                    "must be 0x00");
            }
            offset += 10;

            if (tvb_memeql(tvb, offset, allone, 2) == -1) {
                proto_tree_add_text(mpls_y1711_tree, tvb, offset, 2,
                                    "Error: these bytes are padding and "
                                    "must be 0xFF");
            }
            offset += 2;

            lsrid_ipv4addr = tvb_get_ipv4(tvb, offset);
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 4, "LSR ID: %s",
                                ip_to_str((guint8 *) &lsrid_ipv4addr));
            offset += 4;

            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 4, "LSP ID: %d",
                                tvb_get_ntohl(tvb, offset));
            offset += 4;
        }

        /* defect location */
        proto_tree_add_item(mpls_y1711_tree, hf_mpls_y1711_defect_location, tvb,
                            offset, 4,
                            ENC_LITTLE_ENDIAN);
        offset += 4;

        /* 14 octets of padding (all 0x00) */
        if (tvb_memeql(tvb, offset, allzero, 14) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 14,
                                "Error: these bytes are padding "
                                "and must be 0x00");
        }
        offset += 14;
    }
    break;

    case 0x07: /* FDD */
    {
        guint32 lsrid_ipv4addr;

        /* 3 octets reserved (all 0x00) */
        if (tvb_memeql(tvb, offset, allzero, 3) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 3,
                                "Error: these bytes are "
                                "reserved and must be 0x00");
        }
        offset += 3;

        /* ttsi (ipv4 flavor as in RFC 2373) */
        if (tvb_memeql(tvb, offset, allzero, 10) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 10,
                                "Error: these bytes are padding and "
                                "must be 0x00");
        }
        offset += 10;

        if (tvb_memeql(tvb, offset, allone, 2) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 2,
                                "Error: these bytes are padding and "
                                "must be 0xFF");
        }
        offset += 2;

        lsrid_ipv4addr = tvb_get_ipv4(tvb, offset);
        proto_tree_add_text(mpls_y1711_tree, tvb, offset, 4, "LSR ID: %s",
                            ip_to_str((guint8 *)&lsrid_ipv4addr));
        offset += 4;

        proto_tree_add_text(mpls_y1711_tree, tvb, offset, 4, "LSP ID: %d",
                            tvb_get_ntohl(tvb,offset));
        offset += 4;

        proto_tree_add_item(mpls_y1711_tree, hf_mpls_y1711_frequency, tvb,
                            offset, 1,
                            ENC_LITTLE_ENDIAN);
        offset++;

        /* 17 octets of padding (all 0x00) */
        if (tvb_memeql(tvb, offset, allzero, 17) == -1) {
            proto_tree_add_text(mpls_y1711_tree, tvb, offset, 17,
                                "Error: these bytes are padding and "
                                "must be 0x00");
        }
        offset += 17;
    }
    break;

    default:
        proto_tree_add_text(mpls_y1711_tree, tvb, offset - 1, -1,
                            "Unknown MPLS Y.1711 PDU");
        return offset;
    }

    /* BIP16 */
    proto_tree_add_item(mpls_y1711_tree, hf_mpls_y1711_bip16, tvb, offset, 2,
                        ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

void
proto_register_mpls_y1711(void)
{
    static hf_register_info hf[] = {
        {
            &hf_mpls_y1711_function_type,
            {
                "Function Type", "mpls.y1711.function_type", FT_UINT8,
                BASE_HEX, VALS(y1711_function_type_vals),
                0x0, "Function Type codepoint", HFILL
            }
        },
        {
            &hf_mpls_y1711_ttsi,
            {
                "Trail Termination Source Identifier",
                "mpls.y1711.ttsi",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_mpls_y1711_frequency,
            {
                "Frequency", "mpls.y1711.frequency", FT_UINT8,
                BASE_HEX, VALS(y1711_frequency_vals), 0x0,
                "Frequency of probe injection", HFILL
            }
        },
        {
            &hf_mpls_y1711_defect_type,
            {
                "Defect Type", "mpls.y1711.defect_type", FT_UINT16,
                BASE_HEX, VALS(y1711_defect_type_vals), 0x0, NULL, HFILL
            }
        },
        {
            &hf_mpls_y1711_defect_location,
            {
                "Defect Location (AS)", "mpls.y1711.defect_location",
                FT_UINT32, BASE_DEC, NULL, 0x0, "Defect Location", HFILL
            }
        },
        {
            &hf_mpls_y1711_bip16,
            {
                "BIP16", "mpls.y1711.bip16", FT_UINT16,
                BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
    };

    static gint *ett[] = {
        &ett_mpls_y1711
    };

    proto_mpls_y1711 =
        proto_register_protocol("MPLS ITU-T Y.1711 OAM",
                                "MPLS ITU-T Y.1711 OAM",
                                "mplsy1711");
    proto_register_field_array(proto_mpls_y1711, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    new_register_dissector("mpls_y1711", dissect_mpls_y1711, proto_mpls_y1711);
}

void
proto_reg_handoff_mpls_y1711(void)
{
    mpls_y1711_handle = find_dissector("mpls_y1711");
    dissector_add_uint("mpls.label",
                       LABEL_OAM_ALERT /* 14 */,
                       mpls_y1711_handle);
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
