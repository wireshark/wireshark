/* packet-catapult-dct2000.c
 * Routines for Catapult DCT2000 packet stub header disassembly
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <stdio.h>
#include <ctype.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/emem.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>

#include <wiretap/catapult_dct2000.h>
#include "packet-umts_fp.h"
#include "packet-rlc.h"

#include "packet-mac-lte.h"
#include "packet-rlc-lte.h"
#include "packet-pdcp-lte.h"

/* Protocol and registered fields. */
static int proto_catapult_dct2000 = -1;

static int hf_catapult_dct2000_context = -1;
static int hf_catapult_dct2000_port_number = -1;
static int hf_catapult_dct2000_timestamp = -1;
static int hf_catapult_dct2000_protocol = -1;
static int hf_catapult_dct2000_variant = -1;
static int hf_catapult_dct2000_outhdr = -1;
static int hf_catapult_dct2000_direction = -1;
static int hf_catapult_dct2000_encap = -1;
static int hf_catapult_dct2000_unparsed_data = -1;
static int hf_catapult_dct2000_comment = -1;
static int hf_catapult_dct2000_error_comment = -1;
static int hf_catapult_dct2000_tty = -1;
static int hf_catapult_dct2000_tty_line = -1;
static int hf_catapult_dct2000_dissected_length = -1;

static int hf_catapult_dct2000_ipprim_addresses = -1;
static int hf_catapult_dct2000_ipprim_src_addr_v4 = -1;
static int hf_catapult_dct2000_ipprim_src_addr_v6 = -1;
static int hf_catapult_dct2000_ipprim_dst_addr_v4 = -1;
static int hf_catapult_dct2000_ipprim_dst_addr_v6 = -1;
static int hf_catapult_dct2000_ipprim_addr_v4 = -1;
static int hf_catapult_dct2000_ipprim_addr_v6 = -1;
static int hf_catapult_dct2000_ipprim_udp_src_port = -1;
static int hf_catapult_dct2000_ipprim_udp_dst_port = -1;
static int hf_catapult_dct2000_ipprim_udp_port = -1;
static int hf_catapult_dct2000_ipprim_tcp_src_port = -1;
static int hf_catapult_dct2000_ipprim_tcp_dst_port = -1;
static int hf_catapult_dct2000_ipprim_tcp_port = -1;
static int hf_catapult_dct2000_ipprim_conn_id = -1;

static int hf_catapult_dct2000_sctpprim_addresses = -1;
static int hf_catapult_dct2000_sctpprim_dst_addr_v4 = -1;
static int hf_catapult_dct2000_sctpprim_dst_addr_v6 = -1;
static int hf_catapult_dct2000_sctpprim_addr_v4 = -1;
static int hf_catapult_dct2000_sctpprim_addr_v6 = -1;
static int hf_catapult_dct2000_sctpprim_dst_port = -1;

static int hf_catapult_dct2000_lte_ueid = -1;
static int hf_catapult_dct2000_lte_srbid = -1;
static int hf_catapult_dct2000_lte_drbid = -1;
static int hf_catapult_dct2000_lte_cellid = -1;
static int hf_catapult_dct2000_lte_bcch_transport = -1;
static int hf_catapult_dct2000_lte_rlc_op = -1;
static int hf_catapult_dct2000_lte_rlc_channel_type = -1;
static int hf_catapult_dct2000_lte_rlc_mui = -1;
static int hf_catapult_dct2000_lte_rlc_cnf = -1;
static int hf_catapult_dct2000_lte_rlc_discard_req = -1;

static int hf_catapult_dct2000_lte_ccpri_opcode = -1;
static int hf_catapult_dct2000_lte_ccpri_status = -1;
static int hf_catapult_dct2000_lte_ccpri_channel = -1;

/* UMTS RLC fields */
static int hf_catapult_dct2000_ueid = -1;
static int hf_catapult_dct2000_rbid = -1;
static int hf_catapult_dct2000_ccch_id = -1;
static int hf_catapult_dct2000_no_crc_error = -1;
static int hf_catapult_dct2000_crc_error = -1;
static int hf_catapult_dct2000_clear_tx_buffer = -1;
static int hf_catapult_dct2000_buffer_occupancy = -1;
static int hf_catapult_dct2000_pdu_size = -1;
static int hf_catapult_dct2000_ueid_type = -1;
static int hf_catapult_dct2000_tx_priority = -1;
static int hf_catapult_dct2000_last_in_seg_set = -1;
static int hf_catapult_dct2000_rx_timing_deviation = -1;
static int hf_catapult_dct2000_transport_channel_type = -1;
static int hf_catapult_dct2000_no_padding_bits = -1;

/* Variables used for preferences */
static gboolean catapult_dct2000_try_ipprim_heuristic = TRUE;
static gboolean catapult_dct2000_try_sctpprim_heuristic = TRUE;
static gboolean catapult_dct2000_dissect_lte_rrc = TRUE;
static gboolean catapult_dct2000_dissect_lte_s1ap = TRUE;
static gboolean catapult_dct2000_dissect_mac_lte_oob_messages = TRUE;

/* Protocol subtree. */
static int ett_catapult_dct2000 = -1;
static int ett_catapult_dct2000_ipprim = -1;
static int ett_catapult_dct2000_sctpprim = -1;
static int ett_catapult_dct2000_tty = -1;

static const value_string direction_vals[] = {
    { 0,   "Sent" },
    { 1,   "Received" },
    { 0,   NULL },
};

static const value_string encap_vals[] = {
    { WTAP_ENCAP_RAW_IP,                 "Raw IP" },
    { WTAP_ENCAP_ETHERNET,               "Ethernet" },
    { WTAP_ENCAP_ISDN,                   "LAPD" },
    { WTAP_ENCAP_ATM_PDUS_UNTRUNCATED,   "ATM (PDUs untruncated)" },
    { WTAP_ENCAP_PPP,                    "PPP" },
    { DCT2000_ENCAP_SSCOP,               "SSCOP" },
    { WTAP_ENCAP_FRELAY,                 "Frame Relay" },
    { WTAP_ENCAP_MTP2,                   "MTP2" },
    { DCT2000_ENCAP_NBAP,                "NBAP" },
    { DCT2000_ENCAP_UNHANDLED,           "No Direct Encapsulation" },
    { 0,                                 NULL },
};

static const value_string bcch_transport_vals[] = {
    { BCH_TRANSPORT,    "BCH" },
    { DLSCH_TRANSPORT,  "DLSCH" },
    { 0,   NULL },
};


#define RLC_MGMT_ASSIGN                 0x41
#define RLC_AM_DATA_REQ                 0x60
#define RLC_AM_DATA_IND                 0x61
#define RLC_AM_DATA_CONF                0x62
#define RLC_UM_DATA_REQ                 0x70
#define RLC_UM_DATA_IND                 0x71
#define RLC_UM_DATA_CONF                0x74
#define RLC_TR_DATA_REQ                 0x80
#define RLC_TR_DATA_IND                 0x81
#define RLC_TR_DATA_CONF                0x83

static const value_string rlc_op_vals[] = {
    { RLC_AM_DATA_REQ,   "[UL] [AM]" },
    { RLC_AM_DATA_IND,   "[DL] [AM]" },
    { RLC_UM_DATA_REQ,   "[UL] [UM]"},
    { RLC_UM_DATA_IND,   "[DL] [UM]"},
    { RLC_TR_DATA_REQ,   "[UL] [TM]"},
    { RLC_TR_DATA_IND,   "[DL] [TM]"},
    { 0,   NULL }
};


static const value_string rlc_logical_channel_vals[] = {
    { Channel_DCCH,  "DCCH"},
    { Channel_BCCH,  "BCCH"},
    { Channel_CCCH,  "CCCH"},
    { Channel_PCCH,  "PCCH"},
    { 0,             NULL}
};


#define CCPRI_REQ 1
#define CCPRI_IND 2

static const value_string ccpri_opcode_vals[] = {
    { CCPRI_REQ,     "REQUEST"},
    { CCPRI_IND,     "INDICATION"},
    { 0,             NULL}
};

static const value_string ccpri_status_vals[] = {
    { 0,     "OK"},
    { 1,     "ERROR"},
    { 0,     NULL}
};

static const value_string rlc_rbid_vals[] = {
    { 1,     "DCH1"},
    { 2,     "DCH2"},
    { 3,     "DCH3"},
    { 4,     "DCH4"},
    { 5,     "DCH5"},
    { 6,     "DCH6"},
    { 7,     "DCH7"},
    { 8,     "DCH8"},
    { 9,     "DCH9"},
    { 10,    "DCH10"},
    { 11,    "DCH11"},
    { 12,    "DCH12"},
    { 13,    "DCH13"},
    { 14,    "DCH14"},
    { 15,    "DCH15"},
    { 17,    "BCCH"},
    { 18,    "CCCH"},
    { 19,    "PCCH"},
    { 20,    "SHCCH"},
    { 21,    "CTCH"},
    { 23,    "MCCH"},
    { 24,    "MSCH"},
    { 25,    "MTCH"},
    { 0,     NULL}
};

static const value_string ueid_type_vals[] = {
    { 0,     "URNTI"},
    { 1,     "CRNTI"},
    { 0,     NULL}
};

static const value_string tx_priority_vals[] = {
    { 0,     "Normal"},
    { 1,     "High"},
    { 0,     NULL}
};

static const value_string transport_channel_type_vals[] = {
    { 1,     "RACH"},
    { 2,     "FACH"},
    { 3,     "BCH"},
    { 4,     "PCH"},
    { 6,     "USCH"},
    { 7,     "DSCH"},
    { 8,     "DCH"},
    { 9,     "HSDSCH"},
    { 10,    "EDCH"},
    { 0,     NULL}
};


#define MAX_OUTHDR_VALUES 32

static guint outhdr_values[MAX_OUTHDR_VALUES];
static guint outhdr_values_found = 0;

extern int proto_fp;
extern int proto_rlc;

extern int proto_rlc_lte;
extern int proto_pdcp_lte;

static dissector_handle_t mac_lte_handle;
static dissector_handle_t rlc_lte_handle;
static dissector_handle_t pdcp_lte_handle;

void proto_register_catapult_dct2000(void);

static dissector_handle_t look_for_dissector(const char *protocol_name);
static void parse_outhdr_string(const guchar *outhdr_string);

static void attach_fp_info(packet_info *pinfo, gboolean received,
                           const char *protocol_name, int variant);
static void attach_rlc_info(packet_info *pinfo, guint32 urnti, guint8 rbid,
                            gboolean is_sent);

static void attach_mac_lte_info(packet_info *pinfo);
static void attach_rlc_lte_info(packet_info *pinfo);
static void attach_pdcp_lte_info(packet_info *pinfo);



/* Return the number of bytes used to encode the length field
   (we're not interested in the length value itself) */
static int skipASNLength(guint8 value)
{
    if ((value & 0x80) == 0)
    {
        return 1;
    }
    else
    {
        return ((value & 0x03) == 1) ? 2 : 3;
    }
}


/* Look for the protocol data within an ipprim packet.
   Only set *data_offset if data field found. */
static gboolean find_ipprim_data_offset(tvbuff_t *tvb, int *data_offset, guint8 direction,
                                        guint32 *source_addr_offset, guint8 *source_addr_length,
                                        guint32 *dest_addr_offset,   guint8 *dest_addr_length,
                                        guint32 *source_port_offset, guint32 *dest_port_offset,
                                        port_type *type_of_port,
                                        guint16 *conn_id_offset)
{
    guint8 length;
    int offset = *data_offset;

    /* Get the ipprim command code. */
    guint8 tag = tvb_get_guint8(tvb, offset++);

    /* Only accept UDP or TCP data request or indication */
    switch (tag) {
        case 0x23:  /* UDP data request */
        case 0x24:  /* UDP data indication */
            *type_of_port = PT_UDP;
            break;
        case 0x45:  /* TCP data request */
        case 0x46:  /* TCP data indication */
            *type_of_port = PT_TCP;
            break;
        default:
            return FALSE;
    }

    /* Skip any other TLC fields before reach payload */
    while (tvb_length_remaining(tvb, offset) > 2) {
        /* Look at next tag */
        tag = tvb_get_guint8(tvb, offset++);

        /* Is this the data payload we're expecting? */
        if (((tag == 0x34) && (*type_of_port == PT_UDP)) ||
            ((tag == 0x48) && (*type_of_port == PT_TCP))) {

            *data_offset = offset;
            return TRUE;
        }
        else {
            /* Read length in next byte */
            length = tvb_get_guint8(tvb, offset++);

            if (tag == 0x31 && length >=4) {
                /* Remote IP address */
                if (direction == 0) {
                    /* Sent *to* remote, so dest */
                    *dest_addr_offset = offset;
                    *dest_addr_length = (length/4) * 4;
                }
                else {
                    *source_addr_offset = offset;
                    *source_addr_length = (length/4) * 4;
                }

                /* Remote port follows (if present) */
                if ((length % 4) == 2) {
                    if (direction == 0) {
                        *dest_port_offset = offset + *dest_addr_length;
                    }
                    else {
                        *source_port_offset = offset + *source_addr_length;
                    }
                }
            }
            else
            if (tag == 0x32) {
                if (length == 4 || length == 16) {
                    /* Local IP address */
                    if (direction == 0) {
                        /* Sent *from* local, so source */
                        *source_addr_offset = offset;
                        *source_addr_length = length;
                    }
                    else {
                        *dest_addr_offset = offset;
                        *dest_addr_length = length;
                    }
                }
            }
            else
            if (tag == 0x33 && length == 2) {
                /* Get local port */
                if (direction == 0) {
                    /* Sent from local, so source */
                    *source_port_offset = offset;
                }
                else {
                    *dest_port_offset = offset;
                }
            }
            else
            if (tag == 0x36 && length == 2) {
                /* Get conn_id */
                *conn_id_offset = offset;
            }

            /* Skip the length of the indicated value */
            offset += length;
        }
    }

    /* No data found... */
    return FALSE;
}



/* Look for the protocol data within an sctpprim (variant 1 or 2...) packet.
   Only set *data_offset if data field found. */
static gboolean find_sctpprim_variant1_data_offset(tvbuff_t *tvb, int *data_offset,
                                                   guint32 *dest_addr_offset,
                                                   guint16 *dest_addr_length,
                                                   guint32 *dest_port_offset)
{
    int offset = *data_offset;

    /* Get the sctpprim command code. */
    guint8 first_tag = tvb_get_guint8(tvb, offset++);
    guint8 tag;
    guint8 first_length_byte;

    /* Only accept interested in data requests or indications */
    switch (first_tag) {
        case 0x04:  /* data request */
        case 0x62:  /* data indication */
            break;
        default:
            return FALSE;
    }

    first_length_byte = tvb_get_guint8(tvb, offset);
    offset += skipASNLength(first_length_byte);

    /* Skip any other fields before reach payload */
    while (tvb_length_remaining(tvb, offset) > 2) {
        /* Look at next tag */
        tag = tvb_get_guint8(tvb, offset++);

        /* Is this the data payload we're expecting? */
        if (tag == 0x19) {
            *data_offset = offset;
            return TRUE;
        }
        else {
            /* Skip length field */
            offset++;
            switch (tag) {
                case 0x0a: /* destPort */
                    *dest_port_offset = offset;
                    offset += 2;
                    break;

                case 0x01: /* sctpInstanceNum */
                case 0x1e: /* strseqnum */
                case 0x0d: /* streamnum */
                    offset += 2;
                    continue;

                case 0x09: /* ipv4Address */
                    *dest_addr_offset = offset;
                    *dest_addr_length = 4;
                    offset += 4;
                    break;

                case 0x1d:
                case 0x0c: /* payloadType */
                    offset += 4;
                    continue;

                default:
                    /* Fail if not a known header field */
                    return FALSE;
            }
        }
    }

    /* No data found... */
    return FALSE;
}

/* Look for the protocol data within an sctpprim (variant 3) packet.
   Only set *data_offset if data field found. */
static gboolean find_sctpprim_variant3_data_offset(tvbuff_t *tvb, int *data_offset,
                                                   guint32 *dest_addr_offset,
                                                   guint16 *dest_addr_length,
                                                   guint32 *dest_port_offset)
{
    guint16 tag = 0;
    guint16 length = 0;
    int offset = *data_offset;

    /* Get the sctpprim (2 byte) command code. */
    guint16 top_tag = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Only interested in data requests or indications */
    switch (top_tag) {
        case 0x0400:  /* SendDataReq */
        case 0x6200:  /* DataInd */
            break;

        default:
            return FALSE;
    }

    /* Overall length field is next 2 bytes */
    offset += 2;

    /* Rx/Tx ops have different formats */

    /*****************/
    /* DataInd        */
    if (top_tag == 0x6200) {
        /* Next 2 bytes are associate ID */
        offset += 2;

        /* Next 2 bytes are destination port */
        *dest_port_offset = offset;
        offset += 2;

        /* Destination address should follow - check tag */
        tag = tvb_get_ntohs(tvb, offset);
        if (tag != 0x0900) {
            return FALSE;
        }
        else {
            /* Skip tag */
            offset += 2;

            /* Length field */
            length = tvb_get_ntohs(tvb, offset) / 2;
            if ((length != 4) && (length != 16))
            {
                return FALSE;
            }
            offset += 2;

            /* Address data is here */
            *dest_addr_offset = offset;
            *dest_addr_length = length;

            offset += length;
        }

        /* Not interested in remaining (fixed) fields */
        if (tvb_reported_length_remaining(tvb, offset) > (4 + 2 + 2 + 4)) {
            offset += (4 + 2 + 2 + 4);
        }
        else {
            return FALSE;
        }

        /* Data should now be here */
        tag = tvb_get_ntohs(tvb, offset);
        offset += 2;
        if (tag == 0x1900) {
            /* 2-byte length field */
            offset += 2;

            /* Data is here!!! */
            *data_offset = offset;
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    /***************/
    /* SendDataReq */
    else if (top_tag == 0x0400) {
        /* AssociateId should follow - check tag */
        tag = tvb_get_ntohs(tvb, offset);
        if (tag != 0x2400) {
            return FALSE;
        }
        else {
            /* Skip tag */
            offset += 2;

            /* Skip 2-byte value */
            offset += 2;
        }

        /* Get tag */
        tag = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* Some optional params */
        while ((tag != 0x0c00) && (tvb_length_remaining(tvb, offset) > 4)) {
            switch (tag) {
                case 0x0900:   /* Dest address */
                    /* Length field */
                    length = tvb_get_ntohs(tvb, offset) / 2;
                    if ((length != 4) && (length != 16)) {
                        return FALSE;
                    }
                    offset += 2;

                    /* Address data is here */
                    *dest_addr_offset = offset;
                    *dest_addr_length = length;

                    offset += length;
                    break;

                case 0x0a00:   /* Dest port number */
                    *dest_port_offset = offset;
                    offset += 2;
                    break;

                case 0x0d00:   /* StreamNum */
                    *dest_port_offset = offset;
                    offset += 2;
                    break;


                default:
                    return FALSE;
            }

            /* Get the next tag */
            tag = tvb_get_ntohs(tvb, offset);
            offset += 2;
        }


        /* Mandatory payload type */
        if (tag != 0x0c00) {
            return FALSE;
        }
        length = tvb_get_ntohs(tvb, offset) / 2;
        offset += 2;
        offset += length;


        /* Optional options */
        tag = tvb_get_ntohs(tvb, offset);
        offset += 2;
        if (tag == 0x0b00) {
            length = tvb_get_ntohs(tvb, offset) / 2;
            offset += 2;

            offset += length;

            /* Get next tag */
            tag = tvb_get_ntohs(tvb, offset);
            offset += 2;
        }


        /* Data should now be here!! */
        if (tag == 0x1900) {
            /* 2-byte length field */
            offset += 2;

            /* Data is here!!! */
            *data_offset = offset;
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    return FALSE;
}


/* Dissect a UMTS RLC frame by:
   - parsing the primitive header
   - passing those values + outhdeader to dissector
   - calling the UMTS RLC dissector */
static void dissect_rlc_umts(tvbuff_t *tvb, gint offset,
                             packet_info *pinfo, proto_tree *tree,
                             gboolean is_sent)
{
    guint8  tag;
    gboolean ueid_set = FALSE, rbid_set=FALSE;
    guint32 ueid = 0;
    guint8  rbid = 0;
    guint8  length;
    tvbuff_t   *rlc_tvb;
    dissector_handle_t rlc_umts_handle = 0;

    /* Top-level opcode */
    tag = tvb_get_guint8(tvb, offset++);
    switch (tag) {
        case 0xc0:    /* mac data request */
        case 0xc1:    /* mac data indication */
            break;

        default:
            /* No data to dissect */
            return;
    }

    /* Keep going until reach data tag or end of frame */
    while ((tag != 0x41) && tvb_length_remaining(tvb, offset)) { /* i.e. Data */
        tag = tvb_get_guint8(tvb, offset++);
        switch (tag) {
            case 0x72:  /* UE Id */
                ueid = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(tree, hf_catapult_dct2000_ueid, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                ueid_set = TRUE;
                break;
            case 0xa2:  /* RBID */
                offset++;  /* skip length */
                rbid = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_catapult_dct2000_rbid, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                rbid_set = TRUE;
                break;
            case 0x22:  /* CCCH-id setting rbid to CCCH! */
                offset++;  /* skip length */
                proto_tree_add_item(tree, hf_catapult_dct2000_ccch_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                rbid = 18;
                break;
            case 0xc4:  /* No CRC error */
                proto_tree_add_item(tree, hf_catapult_dct2000_no_crc_error, tvb, offset-1, 1, ENC_NA);
                break;
            case 0xc5:  /* CRC error */
                proto_tree_add_item(tree, hf_catapult_dct2000_crc_error, tvb, offset-1, 1, ENC_NA);
                break;
            case 0xf7:  /* Clear Tx Buffer */
                proto_tree_add_item(tree, hf_catapult_dct2000_clear_tx_buffer, tvb, offset-1, 1, ENC_NA);
                break;

            case 0x41:  /* Data !!! */
                offset += skipASNLength(tvb_get_guint8(tvb, offset));
                break;

            default:
                /* For other fields, just skip length and following data */
                length = tvb_get_guint8(tvb, offset++);
                switch (tag) {
                    case 0x42:   /* Buffer Occupancy */
                        proto_tree_add_item(tree, hf_catapult_dct2000_buffer_occupancy, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case 0x49:   /* PDU Size */
                        proto_tree_add_item(tree, hf_catapult_dct2000_pdu_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        break;
                    case 0x47:   /* UEId type */
                        proto_tree_add_item(tree, hf_catapult_dct2000_ueid_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;
                    case 0x4e:   /* Tx Priority */
                        proto_tree_add_item(tree, hf_catapult_dct2000_tx_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;
                    case 0x4c:   /* Last in seg set */
                        proto_tree_add_item(tree, hf_catapult_dct2000_last_in_seg_set, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;
                    case 0x43:   /* Rx timing deviation */
                        proto_tree_add_item(tree, hf_catapult_dct2000_rx_timing_deviation, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;
                    case 0x46:   /* Transport channel type */
                        proto_tree_add_item(tree, hf_catapult_dct2000_transport_channel_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;
                    case 0xc2:   /* Number of padding bits */
                        proto_tree_add_item(tree, hf_catapult_dct2000_no_padding_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                    default:
                        break;


                }
                offset += length;
        }
    }

    /* Have we got enough info to call dissector */
    if ((tag == 0x41) && ueid_set && rbid_set) {
        attach_rlc_info(pinfo, ueid, rbid, is_sent);

        /* Set appropriate RLC dissector handle */
        switch (rbid) {
            case 1:  case 2:  case 3:  case 4:  case 5:
            case 6:  case 7:  case 8:  case 9:  case 10:
            case 11: case 12: case 13: case 14: case 15:
                /* DCH channels. */
                /*   TODO: can't really tell if these are control or transport...
                     maybe control with preferences (UAT?) between "rlc.ps_dtch" and "rlc.dcch" ? */
                rlc_umts_handle = find_dissector("rlc.dch_unknown");
                break;
            case 18:
                rlc_umts_handle = find_dissector("rlc.ccch");
                break;
            case 21:
                rlc_umts_handle = find_dissector("rlc.ctch");
                break;

            default:
                /* Give up here */
                return;
        }

        /* Call UMTS RLC dissector */
        if (rlc_umts_handle != 0) {
            rlc_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));
            call_dissector_only(rlc_umts_handle, rlc_tvb, pinfo, tree);
        }
    }
}



/* Dissect an RRC LTE frame by first parsing the header entries then passing
   the data to the RRC dissector, according to direction and channel type.
   TODO: factor out common code between this function and dissect_pdcp_lte() */
static void dissect_rrc_lte(tvbuff_t *tvb, gint offset,
                            packet_info *pinfo, proto_tree *tree)
{
    guint8  tag;
    dissector_handle_t protocol_handle = 0;
    gboolean isUplink = FALSE;
    LogicalChannelType logicalChannelType;
    guint16  cell_id;
    guint8   bcch_transport = 0;
    tvbuff_t *rrc_tvb;

    /* Top-level opcode */
    tag = tvb_get_guint8(tvb, offset++);
    switch (tag) {
        case 0x00:    /* Data_Req_UE */
        case 0x04:    /* Data_Ind_eNodeB */
            isUplink = TRUE;
            break;

        case 0x02:    /* Data_Req_eNodeB */
        case 0x03:    /* Data_Ind_UE */
            isUplink = FALSE;
            break;

        default:
            /* Unexpected opcode tag! */
            return;
    }

    /* Skip length */
    offset += skipASNLength(tvb_get_guint8(tvb, offset));

    /* Get next tag */
    tag = tvb_get_guint8(tvb, offset++);
    switch (tag) {
        case 0x12:    /* UE_Id_LCId */

            /* Dedicated channel info */

            /* Length will fit in one byte here */
            offset++;

            logicalChannelType = Channel_DCCH;

            /* UEId */
            proto_tree_add_item(tree, hf_catapult_dct2000_lte_ueid, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Get tag of channel type */
            tag = tvb_get_guint8(tvb, offset++);

            switch (tag) {
                case 0:
                    offset++;
                    col_append_fstr(pinfo->cinfo, COL_INFO, " SRB:%u",
                                    tvb_get_guint8(tvb, offset));
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_srbid,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    break;
                case 1:
                    offset++;
                    col_append_fstr(pinfo->cinfo, COL_INFO, " DRB:%u",
                                    tvb_get_guint8(tvb, offset));
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_drbid,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    break;

                default:
                    /* Unexpected channel type */
                    return;
            }
            break;

        case 0x1a:     /* Cell_LCId */

            /* Common channel info */

            /* Skip length */
            offset++;

            /* Cell-id */
            proto_tree_add_item(tree, hf_catapult_dct2000_lte_cellid,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            cell_id = tvb_get_ntohs(tvb, offset);
            offset += 2;

            /* Logical channel type */
            proto_tree_add_item(tree, hf_catapult_dct2000_lte_rlc_channel_type,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            logicalChannelType = (LogicalChannelType)tvb_get_guint8(tvb, offset);
            offset++;

            /* Won't be seen if RRC decoder is called... */
            col_append_fstr(pinfo->cinfo, COL_INFO, " cell-id=%u %s",
                            cell_id,
                            val_to_str_const(logicalChannelType, rlc_logical_channel_vals,
                                             "UNKNOWN-CHANNEL"));


            switch (logicalChannelType) {
                case Channel_BCCH:
                    /* Skip length */
                    offset++;

                    /* Transport channel type */
                    bcch_transport = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_bcch_transport,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    break;

                case Channel_CCCH:
                    /* Skip length */
                    offset++;

                    /* UEId */
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_ueid,
                                        tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;

                default:
                    break;
            }
            break;

        default:
            /* Unexpected tag */
            return;
    }

    /* Data tag should follow */
    tag = tvb_get_guint8(tvb, offset++);
    if (tag != 0xaa) {
        return;
    }

    /* Skip length */
    offset += skipASNLength(tvb_get_guint8(tvb, offset));

    /* Look up dissector handle corresponding to direction and channel type */
    if (isUplink) {

        /* Uplink channel types */
        switch (logicalChannelType) {
            case Channel_DCCH:
                protocol_handle = find_dissector("lte_rrc.ul_dcch");
                break;
            case Channel_CCCH:
                protocol_handle = find_dissector("lte_rrc.ul_ccch");
                break;

            default:
                /* Unknown Uplink channel type */
                break;
        }
    } else {

        /* Downlink channel types */
        switch (logicalChannelType) {
            case Channel_DCCH:
                protocol_handle = find_dissector("lte_rrc.dl_dcch");
                break;
            case Channel_CCCH:
                protocol_handle = find_dissector("lte_rrc.dl_ccch");
                break;
            case Channel_PCCH:
                protocol_handle = find_dissector("lte-rrc.pcch");
                break;
            case Channel_BCCH:
                if (bcch_transport == 1) {
                    protocol_handle = find_dissector("lte-rrc.bcch.bch");
                }
                else {
                    protocol_handle = find_dissector("lte-rrc.bcch.dl.sch");
                }
                break;

            default:
                /* Unknown Downlink channel type */
                break;
        }
    }

    /* Send to RRC dissector, if got here, have sub-dissector and some data left */
    if ((protocol_handle != NULL) && (tvb_length_remaining(tvb, offset) > 0)) {
        rrc_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));
        call_dissector_only(protocol_handle, rrc_tvb, pinfo, tree);
    }
}


/* Dissect an CCPRI LTE frame by first parsing the header entries then passing
   the data to the CPRI C&M dissector */
static void dissect_ccpri_lte(tvbuff_t *tvb, gint offset,
                              packet_info *pinfo, proto_tree *tree)
{
    guint8  opcode;
    guint8  tag;
    tvbuff_t *ccpri_tvb;
    dissector_handle_t protocol_handle = 0;
    guint16  length;

    /* Top-level opcode */
    proto_tree_add_item(tree, hf_catapult_dct2000_lte_ccpri_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    opcode = tvb_get_guint8(tvb, offset++);

    /* Skip 2-byte length field */
    offset += 2;

    /* Cell-id */
    proto_tree_add_item(tree, hf_catapult_dct2000_lte_cellid,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Status (ind only) */
    if (opcode == 2) {
        proto_item *ti;
        guint8 status = tvb_get_guint8(tvb, offset);
        ti = proto_tree_add_item(tree, hf_catapult_dct2000_lte_ccpri_status,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (status != 0) {
            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_ERROR,
                                   "CCPRI Indication has error status");

        }
    }

    /* Channel ID */
    proto_tree_add_item(tree, hf_catapult_dct2000_lte_ccpri_channel,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Data tag must follow */
    tag = tvb_get_guint8(tvb, offset++);
    if (tag != 2) {
        return;
    }

    /* Skip length */
    length = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Send remainder to lapb dissector (lapb needs patch with preference
       set to call cpri C&M dissector instead of X.25) */
    protocol_handle = find_dissector("lapb");
    if ((protocol_handle != NULL) && (tvb_length_remaining(tvb, offset) > 0)) {
        ccpri_tvb = tvb_new_subset(tvb, offset, length, length);
        call_dissector_only(protocol_handle, ccpri_tvb, pinfo, tree);
    }
}




/* Dissect a PDCP LTE frame by first parsing the RLCPrim header then passing
   the data to the PDCP LTE dissector */
static void dissect_pdcp_lte(tvbuff_t *tvb, gint offset,
                             packet_info *pinfo, proto_tree *tree)
{
    guint8                 opcode;
    guint8                 tag;
    struct pdcp_lte_info   *p_pdcp_lte_info = NULL;
    tvbuff_t               *pdcp_lte_tvb;
    guint16                ueid;
    guint8                 channelId;

    /* Look this up so can update channel info */
    p_pdcp_lte_info = p_get_proto_data(pinfo->fd, proto_pdcp_lte);
    if (p_pdcp_lte_info == NULL) {
        /* This really should be set...can't dissect anything without it */
        return;
    }

    /* Top-level opcode */
    opcode = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_item(tree, hf_catapult_dct2000_lte_rlc_op, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode, rlc_op_vals, "Unknown"));

    /* Assume UE side, so REQ is UL, IND is DL */
    switch (opcode) {
       case RLC_AM_DATA_REQ:
       case RLC_UM_DATA_REQ:
       case RLC_TR_DATA_REQ:
           p_pdcp_lte_info->direction = DIRECTION_UPLINK;
           break;

       default:
           p_pdcp_lte_info->direction = DIRECTION_DOWNLINK;
    }

    /* Parse header */
    switch (opcode) {
        case RLC_AM_DATA_REQ:
        case RLC_AM_DATA_IND:
        case RLC_UM_DATA_REQ:
        case RLC_UM_DATA_IND:
        case RLC_TR_DATA_REQ:
        case RLC_TR_DATA_IND:

            /* Get next tag */
            tag = tvb_get_guint8(tvb, offset++);
            switch (tag) {
                case 0x10:    /* UE_Id_LCId */

                    /* Dedicated channel info */

                    /* Length will fit in one byte here */
                    offset++;

                    p_pdcp_lte_info->channelType = Channel_DCCH;

                    /* UEId */
                    ueid = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_ueid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    col_append_fstr(pinfo->cinfo, COL_INFO,
                                    " UEId=%u", ueid);
                    p_pdcp_lte_info->ueid = ueid;
                    offset += 2;

                    /* Get tag of channel type */
                    tag = tvb_get_guint8(tvb, offset++);

                    switch (tag) {
                        case 0:
                            offset++;
                            channelId = tvb_get_guint8(tvb, offset);
                            col_append_fstr(pinfo->cinfo, COL_INFO, " SRB:%u",
                                            channelId);
                            proto_tree_add_item(tree, hf_catapult_dct2000_lte_srbid,
                                                tvb, offset++, 1, ENC_BIG_ENDIAN);
                            p_pdcp_lte_info->channelId = channelId;
                            break;
                        case 1:
                            offset++;
                            channelId = tvb_get_guint8(tvb, offset);
                            col_append_fstr(pinfo->cinfo, COL_INFO, " DRB:%u",
                                            channelId);
                            proto_tree_add_item(tree, hf_catapult_dct2000_lte_drbid,
                                                tvb, offset++, 1, ENC_BIG_ENDIAN);
                            p_pdcp_lte_info->channelId = channelId;
                            break;

                        default:
                            /* Unexpected channel type */
                            return;
                    }
                    break;

                case 0x1a:     /* Cell_LCId */

                    /* Common channel info */

                    /* Skip length */
                    offset++;

                    /* Cell-id */
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_cellid,
                                        tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* Logical channel type */
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_rlc_channel_type,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    p_pdcp_lte_info->channelType = tvb_get_guint8(tvb, offset++);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
                                    val_to_str_const(p_pdcp_lte_info->channelType, rlc_logical_channel_vals,
                                                     "UNKNOWN-CHANNEL"));

                    switch (p_pdcp_lte_info->channelType) {
                        case Channel_BCCH:
                            /* Skip length */
                            offset++;

                            /* Transport channel type */
                            p_pdcp_lte_info->BCCHTransport = tvb_get_guint8(tvb, offset);
                            proto_tree_add_item(tree, hf_catapult_dct2000_lte_bcch_transport,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            break;

                        case Channel_CCCH:
                            /* Skip length */
                            offset++;

                            /* UEId */
                            proto_tree_add_item(tree, hf_catapult_dct2000_lte_ueid,
                                                tvb, offset, 2, ENC_BIG_ENDIAN);
                            ueid = tvb_get_ntohs(tvb, offset);
                            offset += 2;

                            col_append_fstr(pinfo->cinfo, COL_INFO, " UEId=%u", ueid);
                            break;

                        default:
                            break;
                    }
                    break;

                default:
                    /* Unexpected tag */
                    return;
            }

            /* Other optional fields may follow */
            tag = tvb_get_guint8(tvb, offset++);
            while ((tag != 0x41) && (tvb_length_remaining(tvb, offset) > 2)) {

                if (tag == 0x35) {
                    /* This is MUI */
                    offset++;
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_rlc_mui,
                                        tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* CNF follows MUI in AM */
                    if ((opcode == RLC_AM_DATA_REQ) || (opcode == RLC_AM_DATA_IND)) {
                        proto_tree_add_boolean(tree, hf_catapult_dct2000_lte_rlc_cnf,
                                               tvb, offset, 1, tvb_get_guint8(tvb, offset));
                        offset++;
                    }
                }
                else if (tag == 0x45) {
                    /* Discard Req */
                    offset++;
                    proto_tree_add_boolean(tree, hf_catapult_dct2000_lte_rlc_discard_req,
                                           tvb, offset, 1, tvb_get_guint8(tvb, offset));
                    offset++;
                }

                tag = tvb_get_guint8(tvb, offset++);
            }


            /********************************/
            /* Should be at data tag now    */

            /* Call PDCP LTE dissector */
            pdcp_lte_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));
            call_dissector_only(pdcp_lte_handle, pdcp_lte_tvb, pinfo, tree);

            break;

        default:
            return;
    }
}





/* Look up dissector by protocol name.  Fix up known name mis-matches.
   This includes exact matches and prefixes (e.g. "diameter_rx" -> "diameter") */
static dissector_handle_t look_for_dissector(const char *protocol_name)
{
    /* Use known aliases and protocol name prefixes */
    if (strcmp(protocol_name, "tbcp") == 0) {
        return find_dissector("rtcp");
    }
    else
    if (strncmp(protocol_name, "diameter", strlen("diameter")) == 0) {
        return find_dissector("diameter");
    }
    else
    if ((strcmp(protocol_name, "xcap_caps") == 0) ||
        (strcmp(protocol_name, "soap") == 0) ||
        (strcmp(protocol_name, "mm1") == 0) ||
        (strcmp(protocol_name, "mm3") == 0) ||
        (strcmp(protocol_name, "mm7") == 0)) {

        return find_dissector("http");
    }
    else
    if ((strcmp(protocol_name, "fp") == 0) ||
        (strcmp(protocol_name, "fp_r4") == 0) ||
        (strcmp(protocol_name, "fp_r5") == 0) ||
        (strcmp(protocol_name, "fp_r6") == 0) ||
        (strcmp(protocol_name, "fp_r7") == 0) ||
        (strcmp(protocol_name, "fp_r8") == 0) ||
        (strcmp(protocol_name, "fpiur_r5") == 0)) {

        return find_dissector("fp");
    }
    else
    if ((strcmp(protocol_name, "iuup_rtp_r5") == 0) ||
        (strcmp(protocol_name, "iuup_rtp_r6") == 0)) {

        return find_dissector("rtp");
    }
    else
    if (strcmp(protocol_name, "sipt") == 0) {
        return find_dissector("sip");
    }
    else
    if (strncmp(protocol_name, "nbap_sctp", strlen("nbap_sctp")) == 0) {
        return find_dissector("nbap");
    }
    else
    if (strncmp(protocol_name, "gtp", strlen("gtp")) == 0) {
        return find_dissector("gtp");
    }
    else
    if (strcmp(protocol_name, "dhcpv4") == 0) {
        return find_dissector("bootp");
    }
    else
    if (strcmp(protocol_name, "wimax") == 0) {
        return find_dissector("wimaxasncp");
    }
    else
    if (strncmp(protocol_name, "sabp", strlen("sabp")) == 0) {
        return find_dissector("sabp");
    }
    else
    if (strcmp(protocol_name, "wtp") == 0) {
        return find_dissector("wtp-udp");
    }
    else
    /* Only match with s1ap if preference turned on */
    if (catapult_dct2000_dissect_lte_s1ap &&
        strncmp(protocol_name, "s1ap", strlen("s1ap")) == 0) {

        return find_dissector("s1ap");
    }
    else
    /* Always try lookup for now */
    if (strncmp(protocol_name, "x2ap_r8_lte", strlen("x2ap_r8_lte")) == 0) {

        return find_dissector("x2ap");
    }

    else
    if (strcmp(protocol_name, "gtpv2_r8_lte") == 0) {
        return find_dissector("gtpv2");
    }


    /* Try for an exact match */
    else {
        return find_dissector(protocol_name);
    }
}


/* Populate outhdr_values array with numbers found in outhdr_string */
static void parse_outhdr_string(const guchar *outhdr_string)
{
    int n = 0;
    guint outhdr_string_len = (guint)strlen((const gchar*)outhdr_string);

    /* Populate values array */
    for (outhdr_values_found=0; outhdr_values_found < MAX_OUTHDR_VALUES; ) {
        guint digits_start = n;
        guint digits;

        /* Find digits */
        for (digits = 0; digits < outhdr_string_len; digits++, n++) {
            if (!isdigit(outhdr_string[n])) {
                break;
            }
        }

        if (digits == 0) {
            /* No more numbers left */
            break;
        }

        /* Convert digits into value */
        outhdr_values[outhdr_values_found++] =
            atoi(format_text(outhdr_string+digits_start, digits));

        /* Skip comma */
        n++;
    }
}



/* Fill in an FP packet info struct and attach it to the packet for the FP
   dissector to use */
static void attach_fp_info(packet_info *pinfo, gboolean received, const char *protocol_name, int variant)
{
    int  i=0;
    int  chan;
    int  tf_start, num_chans_start;
    gint node_type;
    int  calculated_variant;

    /* Only need to set info once per session. */
    struct fp_info *p_fp_info = p_get_proto_data(pinfo->fd, proto_fp);
    if (p_fp_info != NULL) {
        return;
    }

    /* Allocate struct */
    p_fp_info = se_alloc0(sizeof(struct fp_info));

    /* Check that the number of outhdr values looks sensible */
    if (((strcmp(protocol_name, "fpiur_r5") == 0) && (outhdr_values_found != 2)) ||
        (outhdr_values_found < 5)) {

        return;
    }

    /* 3gpp release (99, 4, 5, 6, 7) */
    if (strcmp(protocol_name, "fp") == 0) {
        p_fp_info->release = 99;
    }
    else if (strcmp(protocol_name, "fp_r4") == 0) {
        p_fp_info->release = 4;
    }
    else if (strcmp(protocol_name, "fp_r5") == 0) {
        p_fp_info->release = 5;
    }
    else if (strcmp(protocol_name, "fp_r6") == 0) {
        p_fp_info->release = 6;
    }
    else if (strcmp(protocol_name, "fp_r7") == 0) {
        p_fp_info->release = 7;
    }
    else if (strcmp(protocol_name, "fp_r8") == 0) {
        p_fp_info->release = 8;
    }
    else if (strcmp(protocol_name, "fpiur_r5") == 0) {
        p_fp_info->release = 5;
    }
    else {
        /* Really shouldn't get here */
        DISSECTOR_ASSERT_NOT_REACHED();
        return;
    }

    /* Release date is derived from variant number */
    /* Only R6 sub-versions currently influence format within a release */
    switch (p_fp_info->release) {
        case 6:
            if (variant < 256) {
                calculated_variant = variant;
            }
            else {
                calculated_variant = variant / 256;
            }

            switch (calculated_variant) {
                case 1:
                    p_fp_info->release_year = 2005;
                    p_fp_info->release_month = 6;
                    break;
                case 2:
                    p_fp_info->release_year = 2005;
                    p_fp_info->release_month = 9;
                    break;
                case 3:
                default:
                    p_fp_info->release_year = 2006;
                    p_fp_info->release_month = 3;
                    break;
            }
            break;
        case 7:
            p_fp_info->release_year = 2008;
            p_fp_info->release_month = 3;
            break;

        case 8:
            p_fp_info->release_year = 2010;
            p_fp_info->release_month = 6;
            break;


        default:
            p_fp_info->release_year = 0;
            p_fp_info->release_month = 0;
    }


    /* Channel type */
    p_fp_info->channel = outhdr_values[i++];
    /* Sad hack until this value is filled in properly */
    if (p_fp_info->channel == 0) {
        p_fp_info->channel = CHANNEL_DCH;
    }

    /* Derive direction from node type/side */
    node_type = outhdr_values[i++];
    p_fp_info->is_uplink = (( received  && (node_type == 2)) ||
                            (!received  && (node_type == 1)));

    /* Division type introduced for R7 */
    if ((p_fp_info->release == 7) ||
        (p_fp_info->release == 8)) {
        p_fp_info->division = outhdr_values[i++];
    }

    /* HS-DSCH config */
    if (p_fp_info->channel == CHANNEL_HSDSCH) {
        if ((p_fp_info->release == 7) ||
            (p_fp_info->release == 8)) {
            /* Entity (MAC-hs or MAC-ehs) used */
            if (outhdr_values[i++]) {
                p_fp_info->hsdsch_entity = ehs;
            }
        }
        else {
            /* This is the pre-R7 default */
            p_fp_info->hsdsch_entity = hs;
        }
    }


    /* IUR only uses the above... */
    if (strcmp(protocol_name, "fpiur_r5") == 0) {
        /* Store info in packet */
        p_fp_info->iface_type = IuR_Interface;
        p_add_proto_data(pinfo->fd, proto_fp, p_fp_info);
        return;
    }

    /* DCH CRC present... */
    p_fp_info->dch_crc_present = outhdr_values[i++];

    /* ... but don't trust for edch */
    if (p_fp_info->channel == CHANNEL_EDCH) {
        p_fp_info->dch_crc_present = 2; /* unknown */
    }

    /* How many paging indications (if PCH data) */
    p_fp_info->paging_indications = outhdr_values[i++];

    /* Number of channels (for coordinated channels) */
    p_fp_info->num_chans = outhdr_values[i++];

    /* EDCH-Common is always T2 */
    if (p_fp_info->channel == CHANNEL_EDCH_COMMON) {
        p_fp_info->edch_type = 1;
    }

    if (p_fp_info->channel != CHANNEL_EDCH) {
        /* TF size for each channel */
        tf_start = i;
        for (chan=0; chan < p_fp_info->num_chans; chan++) {
            p_fp_info->chan_tf_size[chan] = outhdr_values[tf_start+chan];
        }

        /* Number of TBs for each channel */
        num_chans_start = tf_start + p_fp_info->num_chans;
        for (chan=0; chan < p_fp_info->num_chans; chan++) {
            p_fp_info->chan_num_tbs[chan] = outhdr_values[num_chans_start+chan];
        }
    }
    /* EDCH info */
    else {
        int n;

        p_fp_info->no_ddi_entries = outhdr_values[i++];

        /* DDI values */
        for (n=0; n < p_fp_info->no_ddi_entries; n++) {
            p_fp_info->edch_ddi[n] = outhdr_values[i++];
        }

        /* Corresponding MAC-d sizes */
        for (n=0; n < p_fp_info->no_ddi_entries; n++) {
            p_fp_info->edch_macd_pdu_size[n] = outhdr_values[i++];
        }

        if (strcmp(protocol_name, "fp_r8") == 0) {
            p_fp_info->edch_type = outhdr_values[i];
        }
        else {
            p_fp_info->edch_type = 0;
        }
    }

    /* Interface must be IuB */
    p_fp_info->iface_type = IuB_Interface;

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_fp, p_fp_info);
}


/* Fill in an RLC packet info struct and attach it to the packet for the RLC
   dissector to use */
static void attach_rlc_info(packet_info *pinfo, guint32 urnti, guint8 rbid, gboolean is_sent)
{
    /* Only need to set info once per session. */
    struct fp_info *p_fp_info = p_get_proto_data(pinfo->fd, proto_fp);
    struct rlc_info *p_rlc_info = p_get_proto_data(pinfo->fd, proto_rlc);
    if (p_rlc_info != NULL) {
        return;
    }

    /* Check that the number of outhdr values looks correct */
    if (outhdr_values_found != 2) {
        return;
    }

    /* Allocate structs */
    p_rlc_info = se_alloc0(sizeof(struct rlc_info));
    p_fp_info = se_alloc0(sizeof(struct fp_info));

    /* Fill in struct fields for first (only) PDU in this frame */

    /* Urnti.  Just use UEId */
    p_rlc_info->urnti[0] = urnti;

    /* ciphered (off by default) */
    p_rlc_info->ciphered[0] = FALSE;

    /* deciphered (off by default) */
    p_rlc_info->deciphered[0] = FALSE;

    /* Mode. */
    switch (outhdr_values[1]) {
        case 1:
            p_rlc_info->mode[0] = RLC_TM;
            break;
        case 2:
            p_rlc_info->mode[0] = RLC_UM;
            break;
        case 3:
            p_rlc_info->mode[0] = RLC_AM;
            break;
        case 4:
            p_rlc_info->mode[0] = RLC_UM;
            p_rlc_info->ciphered[0] = TRUE;
            break;
        case 5:
            p_rlc_info->mode[0] = RLC_AM;
            p_rlc_info->ciphered[0] = TRUE;
            break;
        default:
            return;
    }

    /* rbid. TODO: does this need conversion? */
    p_rlc_info->rbid[0] = rbid;

    /* li_size */
    p_rlc_info->li_size[0] = outhdr_values[0];

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_rlc, p_rlc_info);

    /* Also store minimal FP info consulted by RLC dissector
       TODO: Don't really know direction, but use S/R flag to make
       logs in same context consistent. Will be correct for NodeB logs,
       but RLC dissector seems to not use anyway... */
    p_fp_info->is_uplink = is_sent;
    p_fp_info->cur_tb = 0; /* Always the first/only one */
    p_add_proto_data(pinfo->fd, proto_fp, p_fp_info);
}


/* Fill in a MAC LTE packet info struct and attach it to the packet for that
   dissector to use */
static void attach_mac_lte_info(packet_info *pinfo)
{
    struct mac_lte_info *p_mac_lte_info;
    unsigned int i=0;

    /* Only need to set info once per session. */
    p_mac_lte_info = get_mac_lte_proto_data(pinfo);
    if (p_mac_lte_info != NULL) {
        return;
    }

    /* Allocate & zero struct */
    p_mac_lte_info = se_alloc0(sizeof(struct mac_lte_info));

    /* Populate the struct from outhdr values */
    p_mac_lte_info->crcStatusValid = FALSE;  /* not set yet */

    p_mac_lte_info->radioType = outhdr_values[i++] + 1;
    p_mac_lte_info->rntiType = outhdr_values[i++];
    p_mac_lte_info->direction = outhdr_values[i++];
    /* Set these extra PHY present flags to FALSE by default */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        p_mac_lte_info->detailed_phy_info.ul_info.present = FALSE;
    }
    else {
        p_mac_lte_info->detailed_phy_info.dl_info.present = FALSE;
    }

    p_mac_lte_info->subframeNumber = outhdr_values[i++];
    p_mac_lte_info->isPredefinedData = outhdr_values[i++];
    p_mac_lte_info->rnti = outhdr_values[i++];
    p_mac_lte_info->ueid = outhdr_values[i++];
    p_mac_lte_info->length = outhdr_values[i++];
    if (outhdr_values_found > 8) {
        p_mac_lte_info->reTxCount = outhdr_values[i++];
    }
    if (outhdr_values_found == 10) {
        /* CRC only valid for Downlink */
        if (p_mac_lte_info->direction == DIRECTION_DOWNLINK) {
            p_mac_lte_info->crcStatusValid = TRUE;
            p_mac_lte_info->detailed_phy_info.dl_info.crc_status = outhdr_values[i++];
        }
        else {
            i++;
        }
    }

    p_mac_lte_info->dl_retx = dl_retx_unknown;

    if (outhdr_values_found > 10) {
        /* Extra PHY parameters */
        if (p_mac_lte_info->direction == DIRECTION_DOWNLINK) {
            p_mac_lte_info->detailed_phy_info.dl_info.present = outhdr_values[i++];
            p_mac_lte_info->detailed_phy_info.dl_info.dci_format = outhdr_values[i++];
            p_mac_lte_info->detailed_phy_info.dl_info.resource_allocation_type = outhdr_values[i++];
            p_mac_lte_info->detailed_phy_info.dl_info.aggregation_level = outhdr_values[i++];
            p_mac_lte_info->detailed_phy_info.dl_info.mcs_index = outhdr_values[i++];
            p_mac_lte_info->detailed_phy_info.dl_info.redundancy_version_index = outhdr_values[i++];
            if (outhdr_values[i++]) {
                p_mac_lte_info->dl_retx = dl_retx_yes;
            }
            else {
                p_mac_lte_info->dl_retx = dl_retx_no;
            }
            p_mac_lte_info->detailed_phy_info.dl_info.resource_block_length = outhdr_values[i++];
            p_mac_lte_info->crcStatusValid = TRUE;
            p_mac_lte_info->detailed_phy_info.dl_info.crc_status = outhdr_values[i++];
            if (outhdr_values_found > 18) {
                p_mac_lte_info->detailed_phy_info.dl_info.harq_id = outhdr_values[i++];
                p_mac_lte_info->detailed_phy_info.dl_info.ndi = outhdr_values[i++];
            }
            if (outhdr_values_found > 20) {
                p_mac_lte_info->detailed_phy_info.dl_info.transport_block = outhdr_values[i++];
            }
        }
        else {
            /* Uplink */
            p_mac_lte_info->detailed_phy_info.ul_info.present = outhdr_values[i++];
            p_mac_lte_info->detailed_phy_info.ul_info.modulation_type = outhdr_values[i++];
            p_mac_lte_info->detailed_phy_info.ul_info.tbs_index = outhdr_values[i++];
            p_mac_lte_info->detailed_phy_info.ul_info.resource_block_length = outhdr_values[i++];
            p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start = outhdr_values[i++];
            /* Skip retx flag */
            i++;

            if (outhdr_values_found == 16) {
                p_mac_lte_info->subframeNumberOfGrantPresent = TRUE;
                p_mac_lte_info->subframeNumberOfGrant = outhdr_values[i++];
            }
            if (outhdr_values_found > 16) {
                p_mac_lte_info->detailed_phy_info.ul_info.harq_id = outhdr_values[i++];
                p_mac_lte_info->detailed_phy_info.ul_info.ndi = outhdr_values[i++];

                p_mac_lte_info->subframeNumberOfGrantPresent = TRUE;
                p_mac_lte_info->subframeNumberOfGrant = outhdr_values[i++];
            }
        }
    }

    /* System frame number */
    if (i < outhdr_values_found) {
        p_mac_lte_info->sysframeNumber = outhdr_values[i++];
    }

    if ((p_mac_lte_info->direction == DIRECTION_UPLINK) &&
        (i < outhdr_values_found)) {

        p_mac_lte_info->isPHICHNACK = outhdr_values[i];
    }

    /* Store info in packet */
    set_mac_lte_proto_data(pinfo, p_mac_lte_info);
}


/* Fill in a RLC LTE packet info struct and attach it to the packet for that
   dissector to use */
static void attach_rlc_lte_info(packet_info *pinfo)
{
    struct rlc_lte_info *p_rlc_lte_info;
    unsigned int i=0;

    /* Only need to set info once per session. */
    p_rlc_lte_info = p_get_proto_data(pinfo->fd, proto_rlc_lte);
    if (p_rlc_lte_info != NULL) {
        return;
    }

    /* Allocate & zero struct */
    p_rlc_lte_info = se_alloc0(sizeof(struct rlc_lte_info));

    p_rlc_lte_info->rlcMode = outhdr_values[i++];
    p_rlc_lte_info->direction = outhdr_values[i++];
    p_rlc_lte_info->priority = outhdr_values[i++];
    p_rlc_lte_info->UMSequenceNumberLength = outhdr_values[i++];
    p_rlc_lte_info->channelId = outhdr_values[i++];
    p_rlc_lte_info->channelType = outhdr_values[i++];
    p_rlc_lte_info->ueid = outhdr_values[i++];
    p_rlc_lte_info->pduLength = outhdr_values[i];

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_rlc_lte, p_rlc_lte_info);
}

/* Fill in a PDCP LTE packet info struct and attach it to the packet for the PDCP LTE
   dissector to use */
static void attach_pdcp_lte_info(packet_info *pinfo)
{
    struct pdcp_lte_info *p_pdcp_lte_info;
    unsigned int i=0;

    /* Only need to set info once per session. */
    p_pdcp_lte_info = p_get_proto_data(pinfo->fd, proto_pdcp_lte);
    if (p_pdcp_lte_info != NULL) {
        return;
    }

    /* Allocate & zero struct */
    p_pdcp_lte_info = se_alloc0(sizeof(struct pdcp_lte_info));

    p_pdcp_lte_info->no_header_pdu = outhdr_values[i++];
    p_pdcp_lte_info->plane = outhdr_values[i++];
    if (p_pdcp_lte_info->plane != USER_PLANE) {
        p_pdcp_lte_info->plane = SIGNALING_PLANE;
    }
    p_pdcp_lte_info->seqnum_length = outhdr_values[i++];

    p_pdcp_lte_info->rohc_compression = outhdr_values[i++];
    p_pdcp_lte_info->rohc_ip_version = outhdr_values[i++];
    p_pdcp_lte_info->cid_inclusion_info = outhdr_values[i++];
    p_pdcp_lte_info->large_cid_present = outhdr_values[i++];
    p_pdcp_lte_info->mode = outhdr_values[i++];
    p_pdcp_lte_info->rnd = outhdr_values[i++];
    p_pdcp_lte_info->udp_checkum_present = outhdr_values[i++];
    p_pdcp_lte_info->profile = outhdr_values[i];

    /* Remaining 2 (fixed) fields are ah_length and gre_checksum */

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_pdcp_lte, p_pdcp_lte_info);
}


/* Attempt to show tty (raw character messages) as text lines. */
static void dissect_tty_lines(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    gint        next_offset;
    proto_tree  *tty_tree;
    proto_item  *ti;
    int         lines = 0;

    /* Create tty tree. */
    ti = proto_tree_add_item(tree, hf_catapult_dct2000_tty, tvb, offset, -1, ENC_NA);
    tty_tree = proto_item_add_subtree(ti, ett_catapult_dct2000_tty);

    /* Show the tty lines one at a time. */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        /* Find the end of the line. */
        int linelen = tvb_find_line_end_unquoted(tvb, offset, -1, &next_offset);

        /* Extract & add the string. */
        char *string = (char*)tvb_get_ephemeral_string(tvb, offset, linelen);
        if (isascii(string[0])) {
            /* If looks printable treat as string... */
            proto_tree_add_string_format(tty_tree, hf_catapult_dct2000_tty_line,
                                         tvb, offset,
                                         linelen, string,
                                         "%s", string);
        }
        else {
            /* Otherwise show as $hex */
            int n, idx;
            char *hex_string;
            int tty_string_length = tvb_length_remaining(tvb, offset);
            int hex_string_length = 1+(2*tty_string_length)+1;
            hex_string = ep_alloc(hex_string_length);

            idx = g_snprintf(hex_string, hex_string_length, "$");

            /* Write hex out to new string */
            for (n=0; n < tty_string_length; n++) {
                idx += g_snprintf(hex_string+idx, 3, "%02x",
                                  tvb_get_guint8(tvb, offset+n));
            }
            string = hex_string;
        }
        lines++;

        /* Show first line in info column */
        if (lines == 1) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "tty (%s", string);
            proto_item_append_text(ti, " (%s)", string);
        }

        /* Move onto next line. */
        offset = next_offset;
    }

    /* Close off summary of tty message in info column */
    if (lines != 0) {
        col_append_str(pinfo->cinfo, COL_INFO, (lines > 1) ? "...)" : ")");
    }
}


/* Scan the log comment looking for notable out-of-band MAC events that should
   be sent to the MAC dissector */
static void check_for_oob_mac_lte_events(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                                         const char *string)
{
    guint number_of_ues;
    guint ueids[MAX_SRs];
    guint rntis[MAX_SRs];
    guint rapid;
    guint rach_attempt_number;
    mac_lte_oob_event oob_event;
    struct mac_lte_info *p_mac_lte_info;
    tvbuff_t *mac_lte_tvb = NULL;
    guint16 n;

    /* Look for strings matching expected formats */
    if (sscanf(string, ">> RACH Preamble Request[UE =  %u]    [RAPID =  %u]    [Attempt = %u]",
               &ueids[0], &rapid, &rach_attempt_number) == 3) {
        oob_event = ltemac_send_preamble;
    }
    else
    if (sscanf(string, ">> Schedule Request[UE =  %u] [RNTI = %u]", &ueids[0], &rntis[0]) == 2) {
        /* Older, single SR format */
        oob_event = ltemac_send_sr;
        number_of_ues = 1;
    }
    else
    if (sscanf(string, ">> Schedule Requests (%u)  [UE=%u][RNTI=%u]",
               &number_of_ues, &ueids[0], &rntis[0]) == 3) {
        const char *current_position;

        /* Newer, multi-UE format */
        oob_event = ltemac_send_sr;

        /* Parse other ueid/rnti pairs */
        number_of_ues = MIN(number_of_ues, MAX_SRs);
        if (number_of_ues > 1) {
            current_position = string;

            for (n=1; n < number_of_ues; n++) {

                /* Find the start of the next entry */
                current_position = strstr(current_position, "] ");
                if (current_position != NULL) {
                    current_position += 2;
                }
                else {
                    /* This is an error - shouldn't happen */
                    return;
                }

                /* Read this entry */
                sscanf(current_position, "[UE=%u][RNTI=%u]", &ueids[n], &rntis[n]);
            }
        }
    }
    else
    if (sscanf(string, ">> INFO MAC:    SR failed for UE %u (CRNTI=%u)", &ueids[0], &rntis[0]) == 2) {
        oob_event = ltemac_sr_failure;
    }
    else {
        /* No events found */
        return;
    }

    /* We have an event */
    /* Only need to set info once per session. */
    p_mac_lte_info = get_mac_lte_proto_data(pinfo);
    if (p_mac_lte_info == NULL) {

        /* Allocate & zero struct */
        p_mac_lte_info = se_alloc0(sizeof(struct mac_lte_info));

        /* This indicates to MAC dissector that it has an oob event */
        p_mac_lte_info->length = 0;

        switch (oob_event) {
            case ltemac_send_preamble:
                p_mac_lte_info->ueid = ueids[0];
                p_mac_lte_info->rapid = rapid;
                p_mac_lte_info->rach_attempt_number = rach_attempt_number;
                p_mac_lte_info->direction = DIRECTION_UPLINK;
                break;
            case ltemac_send_sr:
                for (n=0; n < number_of_ues; n++) {
                    p_mac_lte_info->oob_ueid[n] = ueids[n];
                    p_mac_lte_info->oob_rnti[n] = rntis[n];
                }
                p_mac_lte_info->number_of_srs = number_of_ues;
                p_mac_lte_info->direction = DIRECTION_UPLINK;
                break;
            case ltemac_sr_failure:
                p_mac_lte_info->rnti = rntis[0];
                p_mac_lte_info->ueid = ueids[0];
                p_mac_lte_info->direction = DIRECTION_DOWNLINK;
                break;
        }

        p_mac_lte_info->radioType = FDD_RADIO; /* TODO: will be the same as rest of log... */
        p_mac_lte_info->oob_event = oob_event;

        /* Store info in packet */
        set_mac_lte_proto_data(pinfo, p_mac_lte_info);
    }

    /* Call MAC dissector */
    mac_lte_tvb = tvb_new_subset(tvb, 0, 0, 0);
    call_dissector_only(mac_lte_handle, mac_lte_tvb, pinfo, tree);
}


/*****************************************/
/* Main dissection function.             */
/*****************************************/
static void
dissect_catapult_dct2000(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *dct2000_tree = NULL;
    proto_item  *ti = NULL;
    gint        offset = 0;
    gint        context_length;
    const char  *context_name;
    guint8      port_number;
    gint        protocol_length;
    gint        timestamp_length;
    const char  *timestamp_string;
    gint        variant_length;
    const char  *variant_string;
    gint        outhdr_length;
    const char  *outhdr_string;
    guint8      direction;
    tvbuff_t    *next_tvb;
    int         encap;
    dissector_handle_t protocol_handle = 0;
    dissector_handle_t heur_protocol_handle = 0;
    int sub_dissector_result = 0;
    const char   *protocol_name;
    gboolean    is_comment;

    /* Set Protocol */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCT2000");

    /* Clear Info */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Create root (protocol) tree. */
    if (tree) {
        ti = proto_tree_add_item(tree, proto_catapult_dct2000, tvb, offset, -1, ENC_NA);
        dct2000_tree = proto_item_add_subtree(ti, ett_catapult_dct2000);
    }

    /*********************************************************************/
    /* Note that these are the fields of the stub header as written out  */
    /* by the wiretap module                                             */

    /* Context Name */
    context_name = tvb_get_const_stringz(tvb, offset, &context_length);
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_context, tvb,
                            offset, context_length, ENC_ASCII|ENC_NA);
    }
    offset += context_length;

    /* Context port number */
    port_number = tvb_get_guint8(tvb, offset);
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_port_number, tvb,
                            offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    /* Timestamp in file */
    timestamp_string = tvb_get_const_stringz(tvb, offset, &timestamp_length);
    if (dct2000_tree) {
        /* TODO: this is *very* slow, but float version adds trailing digits when
                 displayed as a custom column... */
        proto_tree_add_double(dct2000_tree, hf_catapult_dct2000_timestamp, tvb,
                              offset, timestamp_length,
                              atof(timestamp_string));
    }
    offset += timestamp_length;


    /* DCT2000 protocol name */
    protocol_name = tvb_get_const_stringz(tvb, offset, &protocol_length);
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_protocol, tvb,
                            offset, protocol_length, ENC_ASCII|ENC_NA);
    }
    is_comment = (strcmp(protocol_name, "comment") == 0);
    offset += protocol_length;


    /* Protocol Variant */
    variant_string = tvb_get_const_stringz(tvb, offset, &variant_length);
    if (!is_comment) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_variant, tvb,
                            offset, variant_length, ENC_ASCII|ENC_NA);
    }
    offset += variant_length;

    /* Outhdr (shown as string) */
    outhdr_string = tvb_get_const_stringz(tvb, offset, &outhdr_length);
    if (!is_comment && (outhdr_length > 1)) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_outhdr, tvb,
                            offset, outhdr_length, ENC_ASCII|ENC_NA);
    }
    offset += outhdr_length;


    /* Direction */
    direction = tvb_get_guint8(tvb, offset);
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_direction, tvb,
                            offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    /* Read frame encapsulation set by wiretap */
    if (!is_comment) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_encap, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    encap = tvb_get_guint8(tvb, offset);
    offset++;

    /* Add useful details to protocol tree label */
    proto_item_append_text(ti, "   context=%s.%u   t=%s   %c   prot=%s (v=%s)",
                           context_name,
                           port_number,
                           timestamp_string,
                           (direction == 0) ? 'S' : 'R',
                           protocol_name,
                           variant_string);



    /* FP protocols need info from outhdr attached */
    if ((strcmp(protocol_name, "fp") == 0) ||
        (strcmp(protocol_name, "fp_r4") == 0) ||
        (strcmp(protocol_name, "fp_r5") == 0) ||
        (strcmp(protocol_name, "fp_r6") == 0) ||
        (strcmp(protocol_name, "fp_r7") == 0) ||
        (strcmp(protocol_name, "fp_r8") == 0) ||
        (strcmp(protocol_name, "fpiur_r5") == 0)) {

        parse_outhdr_string(outhdr_string);
        attach_fp_info(pinfo, direction, protocol_name, atoi(variant_string));
    }

    /* RLC protocols need info from outhdr attached */
    else if ((strcmp(protocol_name, "rlc") == 0) ||
             (strcmp(protocol_name, "rlc_r4") == 0) ||
             (strcmp(protocol_name, "rlc_r5") == 0) ||
             (strcmp(protocol_name, "rlc_r6") == 0) ||
             (strcmp(protocol_name, "rlc_r7") == 0) ||
             (strcmp(protocol_name, "rlc_r8") == 0) ||
             (strcmp(protocol_name, "rlc_r9") == 0)) {

        parse_outhdr_string(outhdr_string);
        /* Can't attach info yet.  Need combination of outheader values
           and fields parsed from primitive header... */
    }

    /* LTE MAC needs info attached */
    else if ((strcmp(protocol_name, "mac_r8_lte") == 0) ||
             (strcmp(protocol_name, "mac_r9_lte") == 0)) {
        parse_outhdr_string(outhdr_string);
        attach_mac_lte_info(pinfo);
    }

    /* LTE RLC needs info attached */
    else if ((strcmp(protocol_name, "rlc_r8_lte") == 0) ||
             (strcmp(protocol_name, "rlc_r9_lte") == 0)) {
        parse_outhdr_string(outhdr_string);
        attach_rlc_lte_info(pinfo);
    }

    /* LTE PDCP needs info attached */
    else if ((strcmp(protocol_name, "pdcp_r8_lte") == 0) ||
             (strcmp(protocol_name, "pdcp_r9_lte") == 0)) {
        parse_outhdr_string(outhdr_string);
        attach_pdcp_lte_info(pinfo);
    }


    else if ((strcmp(protocol_name, "nas_rrc_r8_lte") == 0) ||
             (strcmp(protocol_name, "nas_rrc_r9_lte") == 0)) {
        gboolean nas_body_found = TRUE;
        guint8 opcode = tvb_get_guint8(tvb, offset++);
        switch (opcode) {
            case 2:  /* DATA IND */
            case 3:  /* DATA REQ */
                /* UEId */
                offset += 2; /* tag */
                offset += 2; /* 2 wasted bytes */
                proto_tree_add_item(tree, hf_catapult_dct2000_lte_ueid,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case 6:  /* ESTABLISH REQ */
                /* UEId */
                offset += 2; /* tag */
                offset += 2; /* 2 wasted bytes */
                proto_tree_add_item(tree, hf_catapult_dct2000_lte_ueid,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                offset += 3;   /* Establish cause */
                offset += 3;   /* Priority */
                break;
            case 8:  /* RELEASE IND */
                /* UEId */
                offset += 2; /* tag */
                offset += 2; /* 2 wasted bytes */
                proto_tree_add_item(tree, hf_catapult_dct2000_lte_ueid,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                offset += 3;   /* Release cause */
                break;

            default:
                nas_body_found = FALSE;
                break;
        }

        /* Look up dissector if if looks right */
        if (nas_body_found) {
            offset += 2;  /* L3 tag + len */
            protocol_handle = find_dissector("nas-eps");
        }
    }

    /* Note that the first item of pinfo->pseudo_header->dct2000 will contain
       the pseudo-header needed (in some cases) by the Wireshark dissector that
       this packet data will be handed off to. */


    /***********************************************************************/
    /* Now hand off to the dissector of intended packet encapsulation type */

    /* Get protocol handle, and set p2p_dir where necessary.
       (packet-frame.c won't copy it from pseudo-header because it doesn't
        know about Catapult DCT2000 encap type...)
    */
    switch (encap) {
        case WTAP_ENCAP_RAW_IP:
            protocol_handle = find_dissector("ip");
#if 0
            /* TODO: this doesn't work yet.
               pseudo_header isn't copied from wtap to pinfo... */
            if ((pinfo->pseudo_header != NULL) &&
                (pinfo->pseudo_header->dct2000.inner_pseudo_header.pdcp.ueid != 0)) {

                proto_item *ti;

                /* Add PDCP thread info as generated fields */
                ti = proto_tree_add_uint(dct2000_tree, hf_catapult_dct2000_lte_ueid, tvb, 0, 0,
                                         pinfo->pseudo_header->dct2000.inner_pseudo_header.pdcp.ueid);
                PROTO_ITEM_SET_GENERATED(ti);
                ti = proto_tree_add_uint(dct2000_tree, hf_catapult_dct2000_lte_drbid, tvb, 0, 0,
                                         pinfo->pseudo_header->dct2000.inner_pseudo_header.pdcp.drbid);
                PROTO_ITEM_SET_GENERATED(ti);
            }
#endif
            break;
        case WTAP_ENCAP_ETHERNET:
            protocol_handle = find_dissector("eth_withoutfcs");
            break;
        case WTAP_ENCAP_ISDN:
            protocol_handle = find_dissector("lapd");
            pinfo->p2p_dir = pinfo->pseudo_header->isdn.uton;
            break;
        case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
            protocol_handle = find_dissector("atm_untruncated");
            break;
        case WTAP_ENCAP_PPP:
            protocol_handle = find_dissector("ppp_hdlc");
            pinfo->p2p_dir = pinfo->pseudo_header->p2p.sent;
            break;
        case DCT2000_ENCAP_SSCOP:
            protocol_handle = find_dissector("sscop");
            break;
        case WTAP_ENCAP_FRELAY:
            protocol_handle = find_dissector("fr");
            break;
        case DCT2000_ENCAP_MTP2:
            protocol_handle = find_dissector("mtp2");
            break;
        case DCT2000_ENCAP_NBAP:
            protocol_handle = find_dissector("nbap");
            break;

        case DCT2000_ENCAP_UNHANDLED:
            /**********************************************************/
            /* The wiretap module wasn't able to set an encapsulation */
            /* type, but it may still be possible to dissect the data */
            /* if we know about the protocol or if we can recognise   */
            /* and parse or skip a primitive header                   */
            /**********************************************************/

            /* Show context.port in src or dest column as appropriate */
            if (direction == 0) {
                col_add_fstr(pinfo->cinfo, COL_DEF_SRC,
                             "%s.%u",
                             context_name,
                             port_number);
            }
            else
            if (direction == 1) {
                col_add_fstr(pinfo->cinfo, COL_DEF_DST,
                             "%s.%u",
                             context_name,
                             port_number);
            }


            /**************************************************************************/
            /* These protocols have no encapsulation type, just look them up directly */

            if ((strcmp(protocol_name, "rlc") == 0) ||
                (strcmp(protocol_name, "rlc_r4") == 0) ||
                (strcmp(protocol_name, "rlc_r5") == 0) ||
                (strcmp(protocol_name, "rlc_r6") == 0) ||
                (strcmp(protocol_name, "rlc_r7") == 0) ||
                (strcmp(protocol_name, "rlc_r8") == 0) ||
                (strcmp(protocol_name, "rlc_r9") == 0)) {

                dissect_rlc_umts(tvb, offset, pinfo, tree, direction);
                return;
            }

            else
            if ((strcmp(protocol_name, "mac_r8_lte") == 0) ||
                (strcmp(protocol_name, "mac_r9_lte") == 0)) {
                protocol_handle = mac_lte_handle;
            }

            else
            if ((strcmp(protocol_name, "rlc_r8_lte") == 0) ||
                (strcmp(protocol_name, "rlc_r9_lte") == 0)) {
                protocol_handle = rlc_lte_handle;
            }

            else
            if ((strcmp(protocol_name, "pdcp_r8_lte") == 0) ||
                (strcmp(protocol_name, "pdcp_r9_lte") == 0)) {
                /* Dissect proprietary header, then pass remainder to PDCP */
                dissect_pdcp_lte(tvb, offset, pinfo, tree);
                return;
            }


            /* Work with generic XML protocol. */
            else
            if (strcmp(protocol_name, "xml") == 0) {
                protocol_handle = find_dissector("xml");
            }


            /* Attempt to show tty messages as raw text */
            else
            if (strcmp(protocol_name, "tty") == 0) {
                dissect_tty_lines(tvb, pinfo, dct2000_tree, offset);
                return;
            }

            else
            if (strcmp(protocol_name, "sipprim") == 0) {
                protocol_handle = find_dissector("sipprim");
            }

            else
            if (strcmp(protocol_name, "comment") == 0) {
                /* Extract & add the string. */
                proto_item *string_ti;
                char *string = (char*)tvb_get_ephemeral_string(tvb, offset, tvb_length_remaining(tvb, offset));

                /* Show comment string */
                string_ti = proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_comment, tvb,
                                                offset, -1, ENC_ASCII|ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", string);

                if (catapult_dct2000_dissect_mac_lte_oob_messages) {
                    /* Look into string for out-of-band MAC events, such as SRReq, SRInd */
                    check_for_oob_mac_lte_events(pinfo, tvb, tree, string);
                }

                /* Look for and flag generic error messages */
                if (strncmp(string, ">> ERR", 6) == 0) {
                    proto_item *error_ti = proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_error_comment, tvb,
                                                               offset, -1, ENC_NA);
                    PROTO_ITEM_SET_GENERATED(error_ti);
                    expert_add_info_format(pinfo, string_ti, PI_SEQUENCE, PI_ERROR,
                                          "%s", string);
                }
                return;
            }


            else
            if (catapult_dct2000_dissect_lte_rrc &&
                ((strcmp(protocol_name, "rrc_r8_lte") == 0) ||
                 (strcmp(protocol_name, "rrcpdcpprim_r8_lte") == 0))) {

                /* Dissect proprietary header, then pass remainder
                   to RRC (depending upon direction and channel type) */
                dissect_rrc_lte(tvb, offset, pinfo, tree);
                return;
            }

            else
            if (((strcmp(protocol_name, "ccpri_r8_lte") == 0))) {

                /* Dissect proprietary header, then pass remainder to lapb */
                dissect_ccpri_lte(tvb, offset, pinfo, tree);
                return;
            }

            /* Many DCT2000 protocols have at least one IPPrim variant. If the
               protocol name can be matched to a dissector, try to find the
               UDP/TCP data inside and dissect it.
            */

            if (!protocol_handle && catapult_dct2000_try_ipprim_heuristic) {
                guint32      source_addr_offset = 0, dest_addr_offset = 0;
                guint8       source_addr_length = 0, dest_addr_length = 0;
                guint32      source_port_offset = 0, dest_port_offset = 0;
                port_type    type_of_port = PT_NONE;
                guint16      conn_id_offset = 0;
                int          offset_before_ipprim_header = offset;

                /* Will give up if couldn't match protocol anyway... */
                heur_protocol_handle = look_for_dissector(protocol_name);
                if ((heur_protocol_handle != 0) &&
                    find_ipprim_data_offset(tvb, &offset, direction,
                                            &source_addr_offset, &source_addr_length,
                                            &dest_addr_offset, &dest_addr_length,
                                            &source_port_offset, &dest_port_offset,
                                            &type_of_port,
                                            &conn_id_offset)) {

                    proto_tree *ipprim_tree;
                    proto_item *ipprim_ti;
                    struct     e_in6_addr sourcev6, destv6;

                    /* Fetch IPv6 addresses */
                    if (source_addr_length != 4) {
                        tvb_get_ipv6(tvb, source_addr_offset, &sourcev6);
                    }
                    if (dest_addr_length != 4) {
                        tvb_get_ipv6(tvb, dest_addr_offset, &destv6);
                    }


                    /* Will use this dissector then. */
                    protocol_handle = heur_protocol_handle;

                    /* Add address parameters to tree */
                    /* Unfortunately can't automatically create a conversation filter for this...
                       I *could* create a fake IP header from these details, but then it would be tricky
                       to get the FP dissector called as it has no well-known ports or heuristics... */
                    ipprim_ti =  proto_tree_add_string_format(dct2000_tree, hf_catapult_dct2000_ipprim_addresses,
                                                       tvb, offset_before_ipprim_header, 0,
                                                       "", "IPPrim transport (%s): %s:%u -> %s:%u",
                                                       (type_of_port == PT_UDP) ? "UDP" : "TCP",
                                                       (source_addr_offset) ?
                                                           ((source_addr_length == 4) ?
                                                              get_hostname(tvb_get_ipv4(tvb, source_addr_offset)) :
                                                              get_hostname6(&sourcev6)
                                                            ) :
                                                           "0.0.0.0",
                                                       (source_port_offset) ?
                                                           tvb_get_ntohs(tvb, source_port_offset) :
                                                           0,
                                                       (dest_addr_offset) ?
                                                         ((source_addr_length == 4) ?
                                                              get_hostname(tvb_get_ipv4(tvb, dest_addr_offset)) :
                                                              get_hostname6(&destv6)
                                                            ) :
                                                           "0.0.0.0",
                                                       (dest_port_offset) ?
                                                           tvb_get_ntohs(tvb, dest_port_offset) :
                                                           0);
                    if ((type_of_port == PT_TCP) && (conn_id_offset != 0)) {
                        proto_item_append_text(ipprim_ti, " (conn_id=%u)", tvb_get_ntohs(tvb, conn_id_offset));
                    }

                    /* Add these IPPRIM fields inside an IPPRIM subtree */
                    ipprim_tree = proto_item_add_subtree(ipprim_ti, ett_catapult_dct2000_ipprim);

                    /* Try to add right stuff to pinfo so conversation stuff works... */
                    pinfo->ptype = type_of_port;
                    switch (type_of_port) {
                        case PT_UDP:
                            pinfo->ipproto = IP_PROTO_UDP;
                            break;
                        case PT_TCP:
                            pinfo->ipproto = IP_PROTO_TCP;
                            break;
                        default:
                            pinfo->ipproto = IP_PROTO_NONE;
                    }

                    /* Add addresses & ports into ipprim tree.
                       Also set address info in pinfo for conversations... */
                    if (source_addr_offset != 0) {
                        proto_item *addr_ti;

                        SET_ADDRESS(&pinfo->net_src,
                                    (source_addr_length == 4) ? AT_IPv4 : AT_IPv6,
                                    source_addr_length,
                                    (tvb_get_ptr(tvb, source_addr_offset, source_addr_length)));
                        SET_ADDRESS(&pinfo->src,
                                    (source_addr_length == 4) ? AT_IPv4 : AT_IPv6,
                                    source_addr_length,
                                    (tvb_get_ptr(tvb, source_addr_offset, source_addr_length)));

                        proto_tree_add_item(ipprim_tree,
                                            (source_addr_length == 4) ?
                                                hf_catapult_dct2000_ipprim_src_addr_v4 :
                                                hf_catapult_dct2000_ipprim_src_addr_v6,
                                            tvb, source_addr_offset, source_addr_length,
                                            (source_addr_length == 4) ? ENC_BIG_ENDIAN : ENC_NA);

                        /* Add hidden item for "side-less" addr */
                        addr_ti = proto_tree_add_item(ipprim_tree,
                                                      (source_addr_length == 4) ?
                                                          hf_catapult_dct2000_ipprim_addr_v4 :
                                                          hf_catapult_dct2000_ipprim_addr_v6,
                                                      tvb, source_addr_offset, source_addr_length,
                                                      (source_addr_length == 4) ? ENC_BIG_ENDIAN : ENC_NA);
                        PROTO_ITEM_SET_HIDDEN(addr_ti);
                    }
                    if (source_port_offset != 0) {
                        proto_item *port_ti;

                        pinfo->srcport = tvb_get_ntohs(tvb, source_port_offset);

                        proto_tree_add_item(ipprim_tree,
                                            (type_of_port == PT_UDP) ?
                                               hf_catapult_dct2000_ipprim_udp_src_port :
                                               hf_catapult_dct2000_ipprim_tcp_src_port,
                                            tvb, source_port_offset, 2, ENC_BIG_ENDIAN);
                        port_ti = proto_tree_add_item(ipprim_tree,
                                                      (type_of_port == PT_UDP) ?
                                                          hf_catapult_dct2000_ipprim_udp_port :
                                                          hf_catapult_dct2000_ipprim_tcp_port,
                                                      tvb, source_port_offset, 2, ENC_BIG_ENDIAN);
                        PROTO_ITEM_SET_HIDDEN(port_ti);
                    }
                    if (dest_addr_offset != 0) {
                        proto_item *addr_ti;

                        SET_ADDRESS(&pinfo->net_dst,
                                    (dest_addr_length == 4) ? AT_IPv4 : AT_IPv6,
                                    dest_addr_length,
                                    (tvb_get_ptr(tvb, dest_addr_offset, dest_addr_length)));
                        SET_ADDRESS(&pinfo->dst,
                                    (dest_addr_length == 4) ? AT_IPv4 : AT_IPv6,
                                    dest_addr_length,
                                    (tvb_get_ptr(tvb, dest_addr_offset, dest_addr_length)));
                        proto_tree_add_item(ipprim_tree,
                                            (dest_addr_length == 4) ?
                                                hf_catapult_dct2000_ipprim_dst_addr_v4 :
                                                hf_catapult_dct2000_ipprim_dst_addr_v6,
                                            tvb, dest_addr_offset, dest_addr_length,
                                            (dest_addr_length == 4) ? ENC_BIG_ENDIAN : ENC_NA);

                        /* Add hidden item for "side-less" addr */
                        addr_ti = proto_tree_add_item(ipprim_tree,
                                                      (dest_addr_length == 4) ?
                                                          hf_catapult_dct2000_ipprim_addr_v4 :
                                                          hf_catapult_dct2000_ipprim_addr_v6,
                                                      tvb, dest_addr_offset, dest_addr_length,
                                                      (dest_addr_length == 4) ? ENC_BIG_ENDIAN : ENC_NA);
                        PROTO_ITEM_SET_HIDDEN(addr_ti);
                    }
                    if (dest_port_offset != 0) {
                        proto_item *port_ti;

                        pinfo->destport = tvb_get_ntohs(tvb, dest_port_offset);

                        proto_tree_add_item(ipprim_tree,
                                            (type_of_port == PT_UDP) ?
                                               hf_catapult_dct2000_ipprim_udp_dst_port :
                                               hf_catapult_dct2000_ipprim_tcp_dst_port,
                                            tvb, dest_port_offset, 2, ENC_BIG_ENDIAN);
                        port_ti = proto_tree_add_item(ipprim_tree,
                                                      (type_of_port == PT_UDP) ?
                                                          hf_catapult_dct2000_ipprim_udp_port :
                                                          hf_catapult_dct2000_ipprim_tcp_port,
                                                      tvb, dest_port_offset, 2, ENC_BIG_ENDIAN);
                        PROTO_ITEM_SET_HIDDEN(port_ti);
                    }
                    if (conn_id_offset != 0) {
                        proto_tree_add_item(ipprim_tree,
                                            hf_catapult_dct2000_ipprim_conn_id,
                                            tvb, conn_id_offset, 2, ENC_BIG_ENDIAN);
                    }


                    /* Set source and dest columns now (will be overwriiten if
                       src and dst IP addresses set) */
                    if (source_addr_offset) {
                        col_append_fstr(pinfo->cinfo, COL_DEF_SRC,
                                        "(%s:%u)",
                                        get_hostname(tvb_get_ipv4(tvb, source_addr_offset)),
                                        tvb_get_ntohs(tvb, source_port_offset));
                    }
                    if (dest_addr_offset) {
                        col_append_fstr(pinfo->cinfo, COL_DEF_DST,
                                        "(%s:%u)",
                                        get_hostname(tvb_get_ipv4(tvb, dest_addr_offset)),
                                        tvb_get_ntohs(tvb, dest_port_offset));
                    }

                    /* Set length for IPPrim tree */
                    proto_item_set_len(ipprim_tree, offset - offset_before_ipprim_header);
                }
            }


            /* Try SCTP Prim heuristic if configured to */
            if (!protocol_handle && catapult_dct2000_try_sctpprim_heuristic) {
                guint32      dest_addr_offset = 0;
                guint16      dest_addr_length = 0;
                guint32      dest_port_offset = 0;
                int          offset_before_sctpprim_header = offset;

                heur_protocol_handle = look_for_dissector(protocol_name);
                if ((heur_protocol_handle != 0) &&
                    (find_sctpprim_variant1_data_offset(tvb, &offset,
                                                        &dest_addr_offset,
                                                        &dest_addr_length,
                                                        &dest_port_offset) ||
                     find_sctpprim_variant3_data_offset(tvb, &offset,
                                                        &dest_addr_offset,
                                                        &dest_addr_length,
                                                        &dest_port_offset))) {

                    proto_tree *sctpprim_tree;
                    proto_item *ti_local;

                    /* Will use this dissector then. */
                    protocol_handle = heur_protocol_handle;

                    ti_local =  proto_tree_add_string_format(dct2000_tree, hf_catapult_dct2000_sctpprim_addresses,
                                                       tvb, offset_before_sctpprim_header, 0,
                                                       "", "SCTPPrim transport:  -> %s:%u",
                                                       (dest_addr_offset) ?
                                                         ((dest_addr_length == 4) ?
                                                              get_hostname(tvb_get_ipv4(tvb, dest_addr_offset)) :
                                                              "<ipv6-address>"
                                                            ) :
                                                           "0.0.0.0",
                                                       (dest_port_offset) ?
                                                         tvb_get_ntohs(tvb, dest_port_offset) :
                                                         0);

                    /* Add these SCTPPRIM fields inside an SCTPPRIM subtree */
                    sctpprim_tree = proto_item_add_subtree(ti_local, ett_catapult_dct2000_sctpprim);

                    pinfo->ipproto = IP_PROTO_SCTP;

                    /* Destination address */
                    if (dest_addr_offset != 0) {
                        proto_item *addr_ti;

                        SET_ADDRESS(&pinfo->net_dst,
                                    (dest_addr_length == 4) ? AT_IPv4 : AT_IPv6,
                                    dest_addr_length,
                                    (tvb_get_ptr(tvb, dest_addr_offset, dest_addr_length)));
                        SET_ADDRESS(&pinfo->dst,
                                    (dest_addr_length == 4) ? AT_IPv4 : AT_IPv6,
                                    dest_addr_length,
                                    (tvb_get_ptr(tvb, dest_addr_offset, dest_addr_length)));
                        proto_tree_add_item(sctpprim_tree,
                                            (dest_addr_length == 4) ?
                                                hf_catapult_dct2000_sctpprim_dst_addr_v4 :
                                                hf_catapult_dct2000_sctpprim_dst_addr_v6,
                                            tvb, dest_addr_offset, dest_addr_length,
                                            (dest_addr_length == 4) ? ENC_BIG_ENDIAN : ENC_NA);

                        /* Add hidden item for "side-less" addr */
                        addr_ti = proto_tree_add_item(sctpprim_tree,
                                                      (dest_addr_length == 4) ?
                                                          hf_catapult_dct2000_sctpprim_addr_v4 :
                                                          hf_catapult_dct2000_sctpprim_addr_v6,
                                                      tvb, dest_addr_offset, dest_addr_length,
                                                      (dest_addr_length == 4) ? ENC_BIG_ENDIAN : ENC_NA);
                        PROTO_ITEM_SET_HIDDEN(addr_ti);
                    }

                    if (dest_port_offset != 0) {
                        pinfo->destport = tvb_get_ntohs(tvb, dest_port_offset);

                        proto_tree_add_item(sctpprim_tree,
                                            hf_catapult_dct2000_sctpprim_dst_port,
                                            tvb, dest_port_offset, 2, ENC_BIG_ENDIAN);
                    }

                    /* Set length for SCTPPrim tree */
                    proto_item_set_len(sctpprim_tree, offset - offset_before_sctpprim_header);
                }
            }

            /* Last chance: is there a (private) registered protocol of the form
               "dct2000.protocol" ? */
            if (protocol_handle == 0) {
                /* TODO: only look inside preference? */
                char dotted_protocol_name[64+128];
                g_snprintf(dotted_protocol_name, 64+128, "dct2000.%s", protocol_name);
                protocol_handle = find_dissector(dotted_protocol_name);
            }

            break;

        default:
            /* !! If get here, there is a mismatch between
               this dissector and the wiretap module catapult_dct2000.c !!
            */
            DISSECTOR_ASSERT_NOT_REACHED();
            return;
    }

    /* Set selection length of dct2000 tree */
    proto_item_set_len(dct2000_tree, offset);

    /* Try appropriate dissector, if one has been selected */
    if (protocol_handle != 0) {
        /* Dissect the remainder of the frame using chosen protocol handle */
        next_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
        sub_dissector_result = call_dissector_only(protocol_handle, next_tvb, pinfo, tree);
    }


    if (protocol_handle == 0 || sub_dissector_result == 0) {
        /* Could get here because:
           - encap is DCT2000_ENCAP_UNHANDLED and we still didn't handle it, OR
           - desired protocol is unavailable (probably disabled), OR
           - protocol rejected our data
           Show remaining bytes as unparsed data */
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_unparsed_data,
                            tvb, offset, -1, ENC_NA);

        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "Not dissected  (context=%s.%u   t=%s   %c   prot=%s (v=%s))",
                     context_name,
                     port_number,
                     timestamp_string,
                     (direction == 0) ? 'S' : 'R',
                     protocol_name,
                     variant_string);
    }
    else {
        /* Show number of dissected bytes */
        if (dct2000_tree) {
            proto_item *ti_local = proto_tree_add_uint(dct2000_tree,
                                                 hf_catapult_dct2000_dissected_length,
                                                 tvb, 0, 0, tvb_reported_length(tvb)-offset);
            PROTO_ITEM_SET_GENERATED(ti_local);
        }
    }
}



/******************************************************************************/
/* Associate this protocol with the Catapult DCT2000 file encapsulation type. */
/******************************************************************************/
void proto_reg_handoff_catapult_dct2000(void)
{
    dissector_handle_t catapult_dct2000_handle = find_dissector("dct2000");

    dissector_add_uint("wtap_encap", WTAP_ENCAP_CATAPULT_DCT2000, catapult_dct2000_handle);

    mac_lte_handle = find_dissector("mac-lte");
    rlc_lte_handle = find_dissector("rlc-lte");
    pdcp_lte_handle = find_dissector("pdcp-lte");
}

/****************************************/
/* Register the protocol                */
/****************************************/
void proto_register_catapult_dct2000(void)
{
    static hf_register_info hf[] =
    {
        { &hf_catapult_dct2000_context,
            { "Context",
              "dct2000.context", FT_STRING, BASE_NONE, NULL, 0x0,
              "Context name", HFILL
            }
        },
        { &hf_catapult_dct2000_port_number,
            { "Context Port number",
              "dct2000.context_port", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_timestamp,
            { "Timestamp",
              "dct2000.timestamp", FT_DOUBLE, BASE_NONE, NULL, 0x0,
              "File timestamp", HFILL
            }
        },
        { &hf_catapult_dct2000_protocol,
            { "DCT2000 protocol",
              "dct2000.protocol", FT_STRING, BASE_NONE, NULL, 0x0,
              "Original (DCT2000) protocol name", HFILL
            }
        },
        { &hf_catapult_dct2000_variant,
            { "Protocol variant",
              "dct2000.variant", FT_STRING, BASE_NONE, NULL, 0x0,
              "DCT2000 protocol variant", HFILL
            }
        },
        { &hf_catapult_dct2000_outhdr,
            { "Out-header",
              "dct2000.outhdr", FT_STRING, BASE_NONE, NULL, 0x0,
              "DCT2000 protocol outhdr", HFILL
            }
        },
        { &hf_catapult_dct2000_direction,
            { "Direction",
              "dct2000.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Frame direction (Sent or Received)", HFILL
            }
        },
        { &hf_catapult_dct2000_encap,
            { "Wireshark encapsulation",
              "dct2000.encapsulation", FT_UINT8, BASE_DEC, VALS(encap_vals), 0x0,
              "Wireshark frame encapsulation used", HFILL
            }
        },
        { &hf_catapult_dct2000_unparsed_data,
            { "Unparsed protocol data",
              "dct2000.unparsed_data", FT_BYTES, BASE_NONE, NULL, 0x0,
              "Unparsed DCT2000 protocol data", HFILL
            }
        },
        { &hf_catapult_dct2000_comment,
            { "Comment",
              "dct2000.comment", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_error_comment,
            { "Error comment",
              "dct2000.error-comment", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_dissected_length,
            { "Dissected length",
              "dct2000.dissected-length", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Number of bytes dissected by subdissector(s)", HFILL
            }
        },

        { &hf_catapult_dct2000_ipprim_addresses,
            { "IPPrim Addresses",
              "dct2000.ipprim", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_src_addr_v4,
            { "Source Address",
              "dct2000.ipprim.src", FT_IPv4, BASE_NONE, NULL, 0x0,
              "IPPrim IPv4 Source Address", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_src_addr_v6,
            { "Source Address",
              "dct2000.ipprim.srcv6", FT_IPv6, BASE_NONE, NULL, 0x0,
              "IPPrim IPv6 Source Address", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_dst_addr_v4,
            { "Destination Address",
              "dct2000.ipprim.dst", FT_IPv4, BASE_NONE, NULL, 0x0,
              "IPPrim IPv4 Destination Address", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_dst_addr_v6,
            { "Destination Address",
              "dct2000.ipprim.dstv6", FT_IPv6, BASE_NONE, NULL, 0x0,
              "IPPrim IPv6 Destination Address", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_addr_v4,
            { "Address",
              "dct2000.ipprim.addr", FT_IPv4, BASE_NONE, NULL, 0x0,
              "IPPrim IPv4 Address", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_addr_v6,
            { "Address",
              "dct2000.ipprim.addrv6", FT_IPv6, BASE_NONE, NULL, 0x0,
              "IPPrim IPv6 Address", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_udp_src_port,
            { "UDP Source Port",
              "dct2000.ipprim.udp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
              "IPPrim UDP Source Port", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_udp_dst_port,
            { "UDP Destination Port",
              "dct2000.ipprim.udp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
              "IPPrim UDP Destination Port", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_udp_port,
            { "UDP Port",
              "dct2000.ipprim.udp.port", FT_UINT16, BASE_DEC, NULL, 0x0,
              "IPPrim UDP Port", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_tcp_src_port,
            { "TCP Source Port",
              "dct2000.ipprim.tcp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
              "IPPrim TCP Source Port", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_tcp_dst_port,
            { "TCP Destination Port",
              "dct2000.ipprim.tcp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
              "IPPrim TCP Destination Port", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_tcp_port,
            { "TCP Port",
              "dct2000.ipprim.tcp.port", FT_UINT16, BASE_DEC, NULL, 0x0,
              "IPPrim TCP Port", HFILL
            }
        },
        { &hf_catapult_dct2000_ipprim_conn_id,
            { "Conn Id",
              "dct2000.ipprim.conn-id", FT_UINT16, BASE_DEC, NULL, 0x0,
              "IPPrim TCP Connection ID", HFILL
            }
        },

        { &hf_catapult_dct2000_sctpprim_addresses,
            { "SCTPPrim Addresses",
              "dct2000.sctpprim", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_sctpprim_dst_addr_v4,
            { "Destination Address",
              "dct2000.sctpprim.dst", FT_IPv4, BASE_NONE, NULL, 0x0,
              "SCTPPrim IPv4 Destination Address", HFILL
            }
        },
        { &hf_catapult_dct2000_sctpprim_dst_addr_v6,
            { "Destination Address",
              "dct2000.sctpprim.dstv6", FT_IPv6, BASE_NONE, NULL, 0x0,
              "SCTPPrim IPv6 Destination Address", HFILL
            }
        },
        { &hf_catapult_dct2000_sctpprim_addr_v4,
            { "Address",
              "dct2000.sctpprim.addr", FT_IPv4, BASE_NONE, NULL, 0x0,
              "SCTPPrim IPv4 Address", HFILL
            }
        },
        { &hf_catapult_dct2000_sctpprim_addr_v6,
            { "Address",
              "dct2000.sctpprim.addrv6", FT_IPv6, BASE_NONE, NULL, 0x0,
              "SCTPPrim IPv6 Address", HFILL
            }
        },
        { &hf_catapult_dct2000_sctpprim_dst_port,
            { "UDP Destination Port",
              "dct2000.sctprim.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
              "SCTPPrim Destination Port", HFILL
            }
        },

        { &hf_catapult_dct2000_tty,
            { "tty contents",
              "dct2000.tty", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_tty_line,
            { "tty line",
              "dct2000.tty-line", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_catapult_dct2000_lte_ueid,
            { "UE Id",
              "dct2000.lte.ueid", FT_UINT16, BASE_DEC, NULL, 0x0,
              "User Equipment Identifier", HFILL
            }
        },
        { &hf_catapult_dct2000_lte_srbid,
            { "srbid",
              "dct2000.lte.srbid", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Signalling Radio Bearer Identifier", HFILL
            }
        },
        { &hf_catapult_dct2000_lte_drbid,
            { "drbid",
              "dct2000.lte.drbid", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Data Radio Bearer Identifier", HFILL
            }
        },
        { &hf_catapult_dct2000_lte_cellid,
            { "Cell-Id",
              "dct2000.lte.cellid", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Cell Identifier", HFILL
            }
        },
        { &hf_catapult_dct2000_lte_bcch_transport,
            { "BCCH Transport",
              "dct2000.lte.bcch-transport", FT_UINT16, BASE_DEC, VALS(bcch_transport_vals), 0x0,
              "BCCH Transport Channel", HFILL
            }
        },
        { &hf_catapult_dct2000_lte_rlc_op,
            { "RLC Op",
              "dct2000.lte.rlc-op", FT_UINT8, BASE_DEC, VALS(rlc_op_vals), 0x0,
              "RLC top-level op", HFILL
            }
        },
        { &hf_catapult_dct2000_lte_rlc_channel_type,
            { "RLC Logical Channel Type",
              "dct2000.lte.rlc-logchan-type", FT_UINT8, BASE_DEC, VALS(rlc_logical_channel_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_lte_rlc_mui,
            { "MUI",
              "dct2000.lte.rlc-mui", FT_UINT16, BASE_DEC, NULL, 0x0,
              "RLC MUI", HFILL
            }
        },
        { &hf_catapult_dct2000_lte_rlc_cnf,
            { "CNF",
              "dct2000.lte.rlc-cnf", FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
              "RLC CNF", HFILL
            }
        },
        { &hf_catapult_dct2000_lte_rlc_discard_req,
            { "Discard Req",
              "dct2000.lte.rlc-discard-req", FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
              "RLC Discard Req", HFILL
            }
        },

        { &hf_catapult_dct2000_lte_ccpri_opcode,
            { "CCPRI opcode",
              "dct2000.lte.ccpri.opcode", FT_UINT8, BASE_DEC, VALS(ccpri_opcode_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_lte_ccpri_status,
            { "Status",
              "dct2000.lte.ccpri.status", FT_UINT8, BASE_DEC, VALS(ccpri_status_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_lte_ccpri_channel,
            { "Channel",
              "dct2000.lte.ccpri.channel", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_catapult_dct2000_ueid,
            { "UE Id",
              "dct2000.ueid", FT_UINT32, BASE_DEC, NULL, 0x0,
              "User Equipment Identifier", HFILL
            }
        },
        { &hf_catapult_dct2000_rbid,
            { "Channel",
              "dct2000.rbid", FT_UINT8, BASE_DEC, VALS(rlc_rbid_vals), 0x0,
              "Channel (rbid)", HFILL
            }
        },
        { &hf_catapult_dct2000_ccch_id,
            { "CCCH Id",
              "dct2000.ccch-id", FT_UINT8, BASE_DEC, NULL, 0x0,
              "CCCH Identifier", HFILL
            }
        },
        { &hf_catapult_dct2000_no_crc_error,
            { "No CRC Error",
              "dct2000.no-crc-error", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_crc_error,
            { "CRC Error",
              "dct2000.crc-error", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_clear_tx_buffer,
            { "Clear Tx Buffer",
              "dct2000.clear-tx-buffer", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_buffer_occupancy,
            { "Buffer Occupancy",
              "dct2000.buffer-occupancy", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_pdu_size,
            { "PDU Size",
              "dct2000.pdu-size", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_ueid_type,
            { "UEId Type",
              "dct2000.ueid-type", FT_UINT8, BASE_DEC, VALS(ueid_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_tx_priority,
            { "Tx Priority",
              "dct2000.tx-priority", FT_UINT8, BASE_DEC, VALS(tx_priority_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_last_in_seg_set,
            { "Last in seg set",
              "dct2000.last-in-seg-set", FT_BOOLEAN, BASE_DEC, TFS(&tfs_yes_no), 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_rx_timing_deviation,
            { "Tx Timing Deviation",
              "dct2000.rx-timing-deviation", FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_transport_channel_type,
            { "Transport Channel Type",
              "dct2000.transport_channel_type", FT_UINT8, BASE_DEC, VALS(transport_channel_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_catapult_dct2000_no_padding_bits,
            { "Number of padding bits",
              "dct2000.number-of-padding-bits", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_catapult_dct2000,
        &ett_catapult_dct2000_ipprim,
        &ett_catapult_dct2000_sctpprim,
        &ett_catapult_dct2000_tty
    };

    module_t *catapult_dct2000_module;

    /* Register protocol. */
    proto_catapult_dct2000 = proto_register_protocol("Catapult DCT2000 packet",
                                                     "DCT2000",
                                                     "dct2000");
    proto_register_field_array(proto_catapult_dct2000, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow dissector to find be found by name. */
    register_dissector("dct2000", dissect_catapult_dct2000, proto_catapult_dct2000);

    /* Preferences */
    catapult_dct2000_module = prefs_register_protocol(proto_catapult_dct2000, NULL);

    /* This preference no longer supported (introduces linkage dependency between
       dissectors and wiretap) */
    prefs_register_obsolete_preference(catapult_dct2000_module, "board_ports_only");

    /* Determines whether for not-handled protocols we should try to parse it if:
       - it looks like its embedded in an ipprim message, AND
       - the DCT2000 protocol name can be matched to a Wireshark dissector name */
    prefs_register_bool_preference(catapult_dct2000_module, "ipprim_heuristic",
                                   "Use IP Primitive heuristic",
                                   "If a payload looks like its embedded in an "
                                   "IP primitive message, and there is a Wireshark "
                                   "dissector matching the DCT2000 protocol name, "
                                   "try parsing the payload using that dissector",
                                   &catapult_dct2000_try_ipprim_heuristic);

    /* Determines whether for not-handled protocols we should try to parse it if:
       - it looks like its embedded in an sctpprim message, AND
       - the DCT2000 protocol name can be matched to a Wireshark dissector name */
    prefs_register_bool_preference(catapult_dct2000_module, "sctpprim_heuristic",
                                   "Use SCTP Primitive heuristic",
                                   "If a payload looks like its embedded in an "
                                   "SCTP primitive message, and there is a Wireshark "
                                   "dissector matching the DCT2000 protocol name, "
                                   "try parsing the payload using that dissector",
                                   &catapult_dct2000_try_sctpprim_heuristic);

    /* Determines whether LTE RRC messages should be dissected */
    prefs_register_bool_preference(catapult_dct2000_module, "decode_lte_rrc",
                                   "Attempt to decode LTE RRC frames",
                                   "When set, attempt to decode LTE RRC frames. "
                                   "Note that this won't affect other protocols "
                                   "that also call the LTE RRC dissector",
                                   &catapult_dct2000_dissect_lte_rrc);

    /* Determines whether LTE S1AP messages should be dissected */
    prefs_register_bool_preference(catapult_dct2000_module, "decode_lte_s1ap",
                                   "Attempt to decode LTE S1AP frames",
                                   "When set, attempt to decode LTE S1AP frames. "
                                   "Note that this won't affect other protocols "
                                   "that also call the LTE S1AP dissector",
                                   &catapult_dct2000_dissect_lte_s1ap);

    /* Determines whether out-of-band messages should dissected */
    prefs_register_bool_preference(catapult_dct2000_module, "decode_mac_lte_oob_messages",
                                   "Look for out-of-band LTE MAC events messages in comments",
                                   "When set, look for formatted messages indicating "
                                   "specific events.  This may be quite slow, so should "
                                   "be disabled if LTE MAC is not being analysed",
                                   &catapult_dct2000_dissect_mac_lte_oob_messages);
}

