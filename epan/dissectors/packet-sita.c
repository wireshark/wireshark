/* packet-sita.c
 * Routines for SITA protocol dissection (ALC, UTS, Frame Relay, X.25)
 * with a SITA specific link layer information header
 *
 * Copyright 2007, Fulko Hew, SITA INC Canada, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/* Use indentation = 4 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/wmem/wmem.h>

void proto_register_sita(void);
void proto_reg_handoff_sita(void);

static dissector_table_t    sita_dissector_table;
static dissector_handle_t   data_handle;
static gint                 ett_sita            = -1;
static gint                 ett_sita_flags      = -1;
static gint                 ett_sita_signals    = -1;
static gint                 ett_sita_errors1    = -1;
static gint                 ett_sita_errors2    = -1;
static int                  proto_sita          = -1;       /* Initialize the protocol and registered fields */
static int                  hf_dir              = -1;
static int                  hf_framing          = -1;
static int                  hf_parity           = -1;
static int                  hf_collision        = -1;
static int                  hf_longframe        = -1;
static int                  hf_shortframe       = -1;
static int                  hf_droppedframe     = -1;
static int                  hf_nonaligned       = -1;
static int                  hf_abort            = -1;
static int                  hf_lostcd           = -1;
static int                  hf_lostcts          = -1;
static int                  hf_rxdpll           = -1;
static int                  hf_overrun          = -1;
static int                  hf_length           = -1;
static int                  hf_crc              = -1;
static int                  hf_break            = -1;
static int                  hf_underrun         = -1;
static int                  hf_uarterror        = -1;
static int                  hf_rtxlimit         = -1;
static int                  hf_proto            = -1;
static int                  hf_dsr              = -1;
static int                  hf_dtr              = -1;
static int                  hf_cts              = -1;
static int                  hf_rts              = -1;
static int                  hf_dcd              = -1;

#define MAX_FLAGS_LEN 64                                    /* max size of a 'flags' decoded string */
#define IOP                 "Local"
#define REMOTE              "Remote"

static const gchar *
format_flags_string(guchar value, const gchar *array[])
{
    int         i;
    guint       bpos;
    wmem_strbuf_t   *buf;
    const char  *sep = "";

    buf = wmem_strbuf_sized_new(wmem_packet_scope(), MAX_FLAGS_LEN, MAX_FLAGS_LEN);
    for (i = 0; i < 8; i++) {
        bpos = 1 << i;
        if (value & bpos) {
            if (array[i][0]) {
                /* there is a string to emit... */
                wmem_strbuf_append_printf(buf, "%s%s", sep,
                    array[i]);
                sep = ", ";
            }
        }
    }
    return wmem_strbuf_get_str(buf);
}

static void
dissect_sita(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    guchar      flags, signals, errors1, errors2, proto;
    const gchar *errors1_string, *errors2_string, *signals_string, *flags_string;
    proto_tree  *sita_tree          = NULL;
    proto_tree  *sita_flags_tree    = NULL;
    proto_tree  *sita_errors1_tree  = NULL;
    proto_tree  *sita_errors2_tree  = NULL;
    proto_tree  *sita_signals_tree  = NULL;
    static const gchar *rx_errors1_str[]   = {"Framing",       "Parity",   "Collision",    "Long-frame",   "Short-frame",  "",         "",     ""              };
    static const gchar *rx_errors2_str[]   = {"Non-Aligned",   "Abort",    "CD-lost",      "DPLL",         "Overrun",      "Length",   "CRC",  "Break"         };
#if 0
    static const gchar   *tx_errors1_str[]   = {"",              "",         "",             "",             "",             "",         "",     ""              };
#endif
    static const gchar *tx_errors2_str[]   = {"Underrun",      "CTS-lost", "UART",         "ReTx-limit",   "",             "",         "",     ""              };
    static const gchar *signals_str[]      = {"DSR",           "DTR",      "CTS",          "RTS",          "DCD",          "",         "",     ""              };
    static const gchar *flags_str[]        = {"",              "",         "",             "",             "",             "",         "",     "No-buffers"    };

    col_clear(pinfo->cinfo, COL_PROTOCOL);      /* erase the protocol */
    col_clear(pinfo->cinfo, COL_INFO);          /* and info columns so that the next decoder can fill them in */

    flags   = pinfo->pseudo_header->sita.sita_flags;
    signals = pinfo->pseudo_header->sita.sita_signals;
    errors1 = pinfo->pseudo_header->sita.sita_errors1;
    errors2 = pinfo->pseudo_header->sita.sita_errors2;
    proto   = pinfo->pseudo_header->sita.sita_proto;

    if ((flags & SITA_FRAME_DIR) == SITA_FRAME_DIR_TXED) {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, IOP);  /* set the source (direction) column accordingly */
    } else {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, REMOTE);
    }

    col_set_str(pinfo->cinfo, COL_INFO, "");

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_sita, tvb, 0, 0, "Link Layer");
        sita_tree = proto_item_add_subtree(ti, ett_sita);

        proto_tree_add_uint(sita_tree, hf_proto, tvb, 0, 0, proto);

        flags_string = format_flags_string(flags, flags_str);
        ti = proto_tree_add_text(sita_tree, tvb, 0, 0, "Flags: 0x%02x (From %s)%s%s",
                flags,
                ((flags & SITA_FRAME_DIR) == SITA_FRAME_DIR_TXED) ? IOP : REMOTE,
                strlen(flags_string) ? ", " : "",
                flags_string);
        sita_flags_tree = proto_item_add_subtree(ti, ett_sita_flags);
        proto_tree_add_boolean(sita_flags_tree, hf_droppedframe,    tvb, 0, 0, flags);
        proto_tree_add_boolean(sita_flags_tree, hf_dir,             tvb, 0, 0, flags);

        signals_string = format_flags_string(signals, signals_str);
        ti = proto_tree_add_text(sita_tree, tvb, 0, 0, "Signals: 0x%02x %s", signals, signals_string);
        sita_signals_tree = proto_item_add_subtree(ti, ett_sita_signals);
        proto_tree_add_boolean(sita_signals_tree, hf_dcd,       tvb, 0, 0, signals);
        proto_tree_add_boolean(sita_signals_tree, hf_rts,       tvb, 0, 0, signals);
        proto_tree_add_boolean(sita_signals_tree, hf_cts,       tvb, 0, 0, signals);
        proto_tree_add_boolean(sita_signals_tree, hf_dtr,       tvb, 0, 0, signals);
        proto_tree_add_boolean(sita_signals_tree, hf_dsr,       tvb, 0, 0, signals);

        if ((flags & SITA_FRAME_DIR) == SITA_FRAME_DIR_RXED) {
            errors1_string = format_flags_string(errors1, rx_errors1_str);
            ti = proto_tree_add_text(sita_tree, tvb, 0, 0, "Receive Status: 0x%02x %s", errors1, errors1_string);
            sita_errors1_tree = proto_item_add_subtree(ti, ett_sita_errors1);
            proto_tree_add_boolean(sita_errors1_tree, hf_shortframe,    tvb, 0, 0, errors1);
            proto_tree_add_boolean(sita_errors1_tree, hf_longframe,     tvb, 0, 0, errors1);
            proto_tree_add_boolean(sita_errors1_tree, hf_collision,     tvb, 0, 0, errors1);
            proto_tree_add_boolean(sita_errors1_tree, hf_parity,        tvb, 0, 0, errors1);
            proto_tree_add_boolean(sita_errors1_tree, hf_framing,       tvb, 0, 0, errors1);

            errors2_string = format_flags_string(errors2, rx_errors2_str);
            ti = proto_tree_add_text(sita_tree, tvb, 0, 0, "Receive Status: 0x%02x %s", errors2, errors2_string);
            sita_errors2_tree = proto_item_add_subtree(ti, ett_sita_errors2);
            proto_tree_add_boolean(sita_errors2_tree, hf_break,         tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors2_tree, hf_crc,           tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors2_tree, hf_length,        tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors2_tree, hf_overrun,       tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors2_tree, hf_rxdpll,        tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors2_tree, hf_lostcd,        tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors2_tree, hf_abort,         tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors2_tree, hf_nonaligned,    tvb, 0, 0, errors2);
        } else {
            errors2_string = format_flags_string(errors2, tx_errors2_str);
            ti = proto_tree_add_text(sita_tree, tvb, 0, 0, "Transmit Status: 0x%02x %s", errors2, errors2_string);
            sita_errors1_tree = proto_item_add_subtree(ti, ett_sita_errors1);
            proto_tree_add_boolean(sita_errors1_tree, hf_rtxlimit,      tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors1_tree, hf_uarterror,     tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors1_tree, hf_lostcts,       tvb, 0, 0, errors2);
            proto_tree_add_boolean(sita_errors1_tree, hf_underrun,      tvb, 0, 0, errors2);
        }
    }

    /* try to find and run an applicable dissector */
    if (!dissector_try_uint(sita_dissector_table, pinfo->pseudo_header->sita.sita_proto, tvb, pinfo, tree)) {
        /* if one can't be found... tell them we don't know how to decode this protocol
           and give them the details then */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
        col_add_fstr(pinfo->cinfo, COL_INFO, "IOP protocol number: %u", pinfo->pseudo_header->sita.sita_proto);
        call_dissector(data_handle, tvb, pinfo, tree);          /* call the generic (hex display) decoder instead */
    }
}

static const true_false_string tfs_sita_flags       = { "From Remote",  "From Local"    };
static const true_false_string tfs_sita_error       = { "Error",        ""              };
static const true_false_string tfs_sita_violation   = { "Violation",    ""              };
static const true_false_string tfs_sita_received    = { "Received",     ""              };
static const true_false_string tfs_sita_lost        = { "Lost",         ""              };
static const true_false_string tfs_sita_exceeded    = { "Exceeded",     ""              };
static const true_false_string tfs_sita_on_off      = { "On",           "Off"           };

static const value_string tfs_sita_proto[] = {
    { SITA_PROTO_UNUSED,        "Unused"                },
    { SITA_PROTO_BOP_LAPB,      "LAPB"                  },
    { SITA_PROTO_ETHERNET,      "Ethernet"              },
    { SITA_PROTO_ASYNC_INTIO,   "Async (Interrupt I/O)" },
    { SITA_PROTO_ASYNC_BLKIO,   "Async (Block I/O)"     },
    { SITA_PROTO_ALC,           "IPARS"                 },
    { SITA_PROTO_UTS,           "UTS"                   },
    { SITA_PROTO_PPP_HDLC,      "PPP/HDLC"              },
    { SITA_PROTO_SDLC,          "SDLC"                  },
    { SITA_PROTO_TOKENRING,     "Token Ring"            },
    { SITA_PROTO_I2C,           "I2C"                   },
    { SITA_PROTO_DPM_LINK,      "DPM Link"              },
    { SITA_PROTO_BOP_FRL,       "Frame Relay"           },
    { 0,                        NULL                    }
};

void
proto_register_sita(void)
{
    static hf_register_info hf[] = {
        { &hf_proto,
          { "Protocol", "sita.errors.protocol",
            FT_UINT8, BASE_HEX, VALS(tfs_sita_proto), 0,
            "Protocol value", HFILL }
        },

        { &hf_dir,
          { "Direction", "sita.flags.flags",
            FT_BOOLEAN, 8, TFS(&tfs_sita_flags), SITA_FRAME_DIR,
            "TRUE 'from Remote', FALSE 'from Local'",   HFILL }
        },
        { &hf_droppedframe,
          { "No Buffers", "sita.flags.droppedframe",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_NO_BUFFER,
            "TRUE if Buffer Failure", HFILL }
        },

        { &hf_framing,
          { "Framing", "sita.errors.framing",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_RX_FRAMING,
            "TRUE if Framing Error", HFILL }
        },
        { &hf_parity,
          { "Parity", "sita.errors.parity",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_RX_PARITY,
            "TRUE if Parity Error", HFILL }
        },
        { &hf_collision,
          { "Collision", "sita.errors.collision",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_RX_COLLISION,
            "TRUE if Collision", HFILL }
        },
        { &hf_longframe,
          { "Long Frame", "sita.errors.longframe",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_RX_FRAME_LONG,
            "TRUE if Long Frame Received", HFILL }
        },
        { &hf_shortframe,
          { "Short Frame", "sita.errors.shortframe",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_RX_FRAME_SHORT,
            "TRUE if Short Frame", HFILL }
        },
        { &hf_nonaligned,
          { "NonAligned", "sita.errors.nonaligned",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_RX_NONOCTET_ALIGNED,
            "TRUE if NonAligned Frame", HFILL }
        },
        { &hf_abort,
          { "Abort", "sita.errors.abort",
            FT_BOOLEAN, 8, TFS(&tfs_sita_received), SITA_ERROR_RX_ABORT,
            "TRUE if Abort Received", HFILL }
        },
        { &hf_lostcd,
          { "Carrier", "sita.errors.lostcd",
            FT_BOOLEAN, 8, TFS(&tfs_sita_lost), SITA_ERROR_RX_CD_LOST,
            "TRUE if Carrier Lost", HFILL }
        },
        { &hf_rxdpll,
          { "DPLL", "sita.errors.rxdpll",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_RX_DPLL,
            "TRUE if DPLL Error", HFILL }
        },
        { &hf_overrun,
          { "Overrun", "sita.errors.overrun",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_RX_OVERRUN,
            "TRUE if Overrun Error", HFILL }
        },
        { &hf_length,
          { "Length", "sita.errors.length",
            FT_BOOLEAN, 8, TFS(&tfs_sita_violation), SITA_ERROR_RX_FRAME_LEN_VIOL,
            "TRUE if Length Violation", HFILL }
        },
        { &hf_crc,
          { "CRC", "sita.errors.crc",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_RX_CRC,
            "TRUE if CRC Error", HFILL }
        },
        { &hf_break,
          { "Break", "sita.errors.break",
            FT_BOOLEAN, 8, TFS(&tfs_sita_received), SITA_ERROR_RX_BREAK,
            "TRUE if Break Received", HFILL }
        },

        { &hf_underrun,
          { "Underrun", "sita.errors.underrun",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_TX_UNDERRUN,
            "TRUE if Tx Underrun", HFILL }
        },
        { &hf_lostcts,
          { "Clear To Send", "sita.errors.lostcts",
            FT_BOOLEAN, 8, TFS(&tfs_sita_lost), SITA_ERROR_TX_CTS_LOST,
            "TRUE if Clear To Send Lost", HFILL }
        },
        { &hf_uarterror,
          { "UART", "sita.errors.uarterror",
            FT_BOOLEAN, 8, TFS(&tfs_sita_error), SITA_ERROR_TX_UART_ERROR,
            "TRUE if UART Error", HFILL }
        },
        { &hf_rtxlimit,
          { "Retx Limit", "sita.errors.rtxlimit",
            FT_BOOLEAN, 8, TFS(&tfs_sita_exceeded), SITA_ERROR_TX_RETX_LIMIT,
            "TRUE if Retransmit Limit reached", HFILL }
        },

        { &hf_dsr,
          { "DSR", "sita.signals.dsr",
            FT_BOOLEAN, 8, TFS(&tfs_sita_on_off), SITA_SIG_DSR,
            "TRUE if Data Set Ready", HFILL }
        },
        { &hf_dtr,
          { "DTR", "sita.signals.dtr",
            FT_BOOLEAN, 8, TFS(&tfs_sita_on_off), SITA_SIG_DTR,
            "TRUE if Data Terminal Ready", HFILL }
        },
        { &hf_cts,
          { "CTS", "sita.signals.cts",
            FT_BOOLEAN, 8, TFS(&tfs_sita_on_off), SITA_SIG_CTS,
            "TRUE if Clear To Send", HFILL }
        },
        { &hf_rts,
          { "RTS", "sita.signals.rts",
            FT_BOOLEAN, 8, TFS(&tfs_sita_on_off), SITA_SIG_RTS,
            "TRUE if Request To Send", HFILL }
        },
        { &hf_dcd,
          { "DCD", "sita.signals.dcd",
            FT_BOOLEAN, 8, TFS(&tfs_sita_on_off), SITA_SIG_DCD,
            "TRUE if Data Carrier Detect", HFILL }
        },

    };

    static gint *ett[] = {
        &ett_sita,
        &ett_sita_flags,
        &ett_sita_signals,
        &ett_sita_errors1,
        &ett_sita_errors2,
    };

    proto_sita = proto_register_protocol("Societe Internationale de Telecommunications Aeronautiques", "SITA", "sita"); /* name, short name,abbreviation */
    sita_dissector_table = register_dissector_table("sita.proto", "SITA protocol number", FT_UINT8, BASE_HEX);
    proto_register_field_array(proto_sita, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("sita", dissect_sita, proto_sita);
}

void
proto_reg_handoff_sita(void)
{
    dissector_handle_t  lapb_handle;
    dissector_handle_t  frame_relay_handle;
    dissector_handle_t  uts_handle;
    dissector_handle_t  ipars_handle;
    dissector_handle_t  sita_handle;

    lapb_handle     = find_dissector("lapb");
    frame_relay_handle  = find_dissector("fr");
    uts_handle      = find_dissector("uts");
    ipars_handle        = find_dissector("ipars");
    sita_handle         = find_dissector("sita");
    data_handle     = find_dissector("data");

    dissector_add_uint("sita.proto", SITA_PROTO_BOP_LAPB,   lapb_handle);
    dissector_add_uint("sita.proto", SITA_PROTO_BOP_FRL,        frame_relay_handle);
    dissector_add_uint("sita.proto", SITA_PROTO_UTS,        uts_handle);
    dissector_add_uint("sita.proto", SITA_PROTO_ALC,        ipars_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_SITA,       sita_handle);
}
