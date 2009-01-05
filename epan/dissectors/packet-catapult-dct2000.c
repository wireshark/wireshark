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

#include <string.h>
#include <ctype.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/proto.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>

#include <wiretap/catapult_dct2000.h>
#include "packet-umts_fp.h"
#include "packet-mac-lte.h"
#include "packet-rlc-lte.h"
#if 0
#include "packet-pdcp.h"
#endif

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


/* Variables used for preferences */
gboolean catapult_dct2000_try_ipprim_heuristic = TRUE;
gboolean catapult_dct2000_try_sctpprim_heuristic = TRUE;

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
    { 1,   "BCH" },
    { 2,   "DLSCH" },
    { 0,   NULL },
};




#define MAX_OUTHDR_VALUES 32

static guint outhdr_values[MAX_OUTHDR_VALUES];
static gint outhdr_values_found = 0;

extern int proto_fp;
extern int proto_mac_lte;
extern int proto_rlc_lte;
#if 0
extern int proto_pdcp;
#endif

void proto_register_catapult_dct2000(void);

static dissector_handle_t look_for_dissector(char *protocol_name);
static void parse_outhdr_string(guchar *outhdr_string);
static void attach_fp_info(packet_info *pinfo, gboolean received,
                           const char *protocol_name, int variant);
static void attach_mac_lte_info(packet_info *pinfo);
static void attach_rlc_lte_info(packet_info *pinfo);
#if 0
static void attach_pdcp_info(packet_info *pinfo);
#endif



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
    switch (tag)
    {
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
    while (tvb_length_remaining(tvb, offset) > 2)
    {
        /* Look at next tag */
        tag = tvb_get_guint8(tvb, offset++);

        /* Is this the data payload we're expecting? */
        if (((tag == 0x34) && (*type_of_port == PT_UDP)) ||
            ((tag == 0x48) && (*type_of_port == PT_TCP)))
        {
            *data_offset = offset;
            return TRUE;
        }
        else
        {
            /* Read length in next byte */
            length = tvb_get_guint8(tvb, offset++);

            if (tag == 0x31 && length >=4)
            {
                /* Remote IP address */
                if (direction == 0)
                {
                    /* Sent *to* remote, so dest */
                    *dest_addr_offset = offset;
                    *dest_addr_length = (length/4) * 4;
                }
                else
                {
                    *source_addr_offset = offset;
                    *source_addr_length = (length/4) * 4;
                }

                /* Remote port follows (if present) */
                if ((length % 4) == 2)
                {
                    if (direction == 0)
                    {
                        *dest_port_offset = offset + 4;
                    }
                    else
                    {
                        *source_port_offset = offset + 4;
                    }
                }
            }
            else
            if (tag == 0x32)
            {
                if (length == 4 || length == 16)
                {
                    /* Local IP address */
                    if (direction == 0)
                    {
                        /* Sent *from* local, so source */
                        *source_addr_offset = offset;
                        *source_addr_length = length;
                    }
                    else
                    {
                        *dest_addr_offset = offset;
                        *dest_addr_length = length;
                    }
                }
            }
            else
            if (tag == 0x33 && length == 2)
            {
                /* Get local port */
                if (direction == 0)
                {
                    /* Sent from local, so source */
                    *source_port_offset = offset;
                }
                else
                {
                    *dest_port_offset = offset;
                }
            }
            else
            if (tag == 0x36 && length == 2)
            {
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
    switch (first_tag)
    {
        case 0x04:  /* data request */
        case 0x62:  /* data indication */
            break;
        default:
            return FALSE;
    }

    first_length_byte = tvb_get_guint8(tvb, offset);
    offset += skipASNLength(first_length_byte);

    /* Skip any other fields before reach payload */
    while (tvb_length_remaining(tvb, offset) > 2)
    {
        /* Look at next tag */
        tag = tvb_get_guint8(tvb, offset++);

        /* Is this the data payload we're expecting? */
        if (tag == 0x19)
        {
            *data_offset = offset;
            return TRUE;
        }
        else
        {
            /* Skip length field */
            offset++;
            switch (tag)
            {
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
    switch (top_tag)
    {
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
    if (top_tag == 0x6200)
    {
        /* Next 2 bytes are associate ID */
        offset += 2;

        /* Next 2 bytes are destination port */
        *dest_port_offset = offset;
        offset += 2;

        /* Destination address should follow - check tag */
        tag = tvb_get_ntohs(tvb, offset);
        if (tag != 0x0900)
        {
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
        if (tvb_reported_length_remaining(tvb, offset) > (4 + 2 + 2 + 4))
        {
            offset += (4 + 2 + 2 + 4);
        }
        else {
            return FALSE;
        }

        /* Data should now be here */
        tag = tvb_get_ntohs(tvb, offset);
        offset += 2;
        if (tag == 0x1900)
        {
            /* 2-byte length field */
            offset += 2;

            /* Data is here!!! */
            *data_offset = offset;
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    /***************/
    /* SendDataReq */
    else if (top_tag == 0x0400)
    {
        /* AssociateId should follow - check tag */
        tag = tvb_get_ntohs(tvb, offset);
        if (tag != 0x2400)
        {
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
        while ((tag != 0x0c00) && (tvb_length_remaining(tvb, offset) > 4))
        {
            switch (tag)
            {
                case 0x0900:   /* Dest address */
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
        if (tag != 0x0c00)
        {
            return FALSE;
        }
        length = tvb_get_ntohs(tvb, offset) / 2;
        offset += 2;
        offset += length;


        /* Optional options */
        tag = tvb_get_ntohs(tvb, offset);
        offset += 2;
        if (tag == 0x0b00)
        {
            length = tvb_get_ntohs(tvb, offset) / 2;
            offset += 2;

            offset += length;

            /* Get next tag */
            tag = tvb_get_ntohs(tvb, offset);
            offset += 2;
        }


        /* Data should now be here!! */
        if (tag == 0x1900)
        {
            /* 2-byte length field */
            offset += 2;

            /* Data is here!!! */
            *data_offset = offset;
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    return FALSE;
}


typedef enum LogicalChannelType
{
    Channel_DCCH=1,
    Channel_BCCH=2,
    Channel_CCCH=3,
    Channel_PCCH=4
} LogicalChannelType;
    

/* Dissect an RRC LTE frame by first parsing the header entries then passing
   the data to the RRC dissector, according to direction and channel type */
void dissect_rrc_lte(tvbuff_t *tvb, gint offset,
                     packet_info *pinfo _U_, proto_tree *tree)
{
    guint8  tag;
    dissector_handle_t protocol_handle = 0;
    gboolean isUplink = FALSE;
    LogicalChannelType logicalChannelType;
    guint8   bcch_transport = 0;
    tvbuff_t *rrc_tvb;

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
            /* Length will fit in one byte here */
            offset++;

            logicalChannelType = Channel_DCCH;

            /* UEId */
            proto_tree_add_item(tree, hf_catapult_dct2000_lte_ueid, tvb, offset, 2, FALSE);
            offset += 2;

            /* Get tag of channel type */
            tag = tvb_get_guint8(tvb, offset++);

            switch (tag) {
                case 0:
                    offset++;
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_srbid,
                                        tvb, offset, 1, FALSE);
                    break;
                case 1:
                    offset++;
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_drbid,
                                        tvb, offset, 1, FALSE);
                    break;

                default:
                    /* Unexpected channel type */
                    return;
            }
            break;

        case 0x1a:     /* Cell_LCId */

            /* Skip length */
            offset++;

            /* Cell-id */
            proto_tree_add_item(tree, hf_catapult_dct2000_lte_cellid,
                                tvb, offset, 2, FALSE);
            offset += 2;

            logicalChannelType = tvb_get_guint8(tvb, offset++);
            switch (logicalChannelType) {
                case Channel_BCCH:
                    /* Skip length */
                    offset++;

                    /* Transport channel type */
                    bcch_transport = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_bcch_transport,
                                        tvb, offset, 1, FALSE);
                    offset++;
                    break;

                case Channel_CCCH:
                    /* Skip length */
                    offset++;

                    /* UEId */
                    proto_tree_add_item(tree, hf_catapult_dct2000_lte_ueid,
                                        tvb, offset, 2, FALSE);
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
                protocol_handle = find_dissector("lte-rrc.ul.dcch");
                break;
            case Channel_CCCH:
                protocol_handle = find_dissector("lte-rrc.ul.ccch");
                break;

            default:
                /* Unknown Uplink channel type */
                break;
        }
    } else {

        /* Downlink channel types */
        switch (logicalChannelType) {
            case Channel_DCCH:
                protocol_handle = find_dissector("lte-rrc.dl.dcch");
                break;
            case Channel_CCCH:
                protocol_handle = find_dissector("lte-rrc.dl.ccch");
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



/* Look up dissector by protocol name.  Fix up known name mis-matches.
   This includes exact matches and prefixes (e.g. "diameter_rx" -> "diameter") */
dissector_handle_t look_for_dissector(char *protocol_name)
{
    /* Use known aliases and protocol name prefixes */
    if (strcmp(protocol_name, "tbcp") == 0)
    {
        return find_dissector("rtcp");
    }
    else
    if (strncmp(protocol_name, "diameter", strlen("diameter")) == 0)
    {
        return find_dissector("diameter");
    }
    else
    if ((strcmp(protocol_name, "xcap_caps") == 0) ||
        (strcmp(protocol_name, "soap") == 0) ||
        (strcmp(protocol_name, "mm1") == 0) ||
        (strcmp(protocol_name, "mm3") == 0) ||
        (strcmp(protocol_name, "mm7") == 0))
    {
        return find_dissector("http");
    }
    else
    if ((strcmp(protocol_name, "fp") == 0) ||
        (strcmp(protocol_name, "fp_r4") == 0) ||
        (strcmp(protocol_name, "fp_r5") == 0) ||
        (strcmp(protocol_name, "fp_r6") == 0) ||
        (strcmp(protocol_name, "fp_r7") == 0) ||
        (strcmp(protocol_name, "fpiur_r5") == 0))
    {
        return find_dissector("fp");
    }
    else
    if ((strcmp(protocol_name, "iuup_rtp_r5") == 0) ||
        (strcmp(protocol_name, "iuup_rtp_r6") == 0))
    {
        return find_dissector("rtp");
    }
    else
    if (strcmp(protocol_name, "sipt") == 0)
    {
        return find_dissector("sip");
    }
    else
    if (strncmp(protocol_name, "nbap_sctp", strlen("nbap_sctp")) == 0)
    {
        return find_dissector("nbap");
    }
    else
    if (strncmp(protocol_name, "gtp", strlen("gtp")) == 0)
    {
        return find_dissector("gtp");
    }
    else
    if (strcmp(protocol_name, "dhcpv4") == 0)
    {
        return find_dissector("bootp");
    }
    else
    if (strcmp(protocol_name, "wimax") == 0)
    {
        return find_dissector("wimaxasncp");
    }
    else
    if (strncmp(protocol_name, "sabp", strlen("sabp")) == 0)
    {
        return find_dissector("sabp");
    }
    else
    if (strcmp(protocol_name, "wtp") == 0)
    {
        return find_dissector("wtp-udp");
    }
    else
    if (strncmp(protocol_name, "s1ap", strlen("s1ap")) == 0)
    {
        return find_dissector("s1ap");
    }

    /* Try for an exact match */
    else
    {
        return find_dissector(protocol_name);
    }
}


/* Populate outhdr_values array with numbers found in outhdr_string */
void parse_outhdr_string(guchar *outhdr_string)
{
    int n = 0;

    /* Populate values array */
    for (outhdr_values_found=0; outhdr_values_found < MAX_OUTHDR_VALUES; )
    {
        guint digits_start = n;
        guint digits;

        /* Find digits */
        for (digits = 0; digits < strlen((gchar*)outhdr_string); digits++, n++)
        {
            if (!isdigit(outhdr_string[n]))
            {
                break;
            }
        }

        if (digits == 0)
        {
            /* No more numbers left */
            break;
        }

        /* Convert digits into value */
        outhdr_values[outhdr_values_found++] =
            atoi((char*)format_text((guchar*)outhdr_string+digits_start, digits));

        /* Skip comma */
        n++;
    }
}

/* Fill in an FP packet info struct and attach it to the packet for the FP
   dissector to use */
void attach_fp_info(packet_info *pinfo, gboolean received, const char *protocol_name, int variant)
{
    int  i=0;
    int  chan;
    int  tf_start, num_chans_start;
    gint node_type;

    /* Only need to set info once per session. */
    struct fp_info *p_fp_info = p_get_proto_data(pinfo->fd, proto_fp);
    if (p_fp_info != NULL)
    {
        return;
    }

    /* Allocate struct */
    p_fp_info = se_alloc0(sizeof(struct fp_info));
    if (!p_fp_info)
    {
        return;
    }

    /* Check that the number of outhdr values looks sensible */
    if (((strcmp(protocol_name, "fpiur_r5") == 0) && (outhdr_values_found != 2)) ||
        (outhdr_values_found < 5))
    {
        return;
    }

    /* 3gpp release (99, 4, 5, 6, 7) */
    if (strcmp(protocol_name, "fp") == 0)
    {
        p_fp_info->release = 99;
    }
    else if (strcmp(protocol_name, "fp_r4") == 0)
    {
        p_fp_info->release = 4;
    }
    else if (strcmp(protocol_name, "fp_r5") == 0)
    {
        p_fp_info->release = 5;
    }
    else if (strcmp(protocol_name, "fp_r6") == 0)
    {
        p_fp_info->release = 6;
    }
    else if (strcmp(protocol_name, "fp_r7") == 0)
    {
        p_fp_info->release = 7;
    }
    else if (strcmp(protocol_name, "fpiur_r5") == 0)
    {
        p_fp_info->release = 5;
    }
    else
    {
        /* Really shouldn't get here */
        DISSECTOR_ASSERT_NOT_REACHED();
        return;
    }

    /* Release date is derived from variant number */
    /* Only R6 sub-versions currently influence format within a release */
    switch (p_fp_info->release)
    {
        case 6:
            switch (variant % 256)
            {
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

        default:
            p_fp_info->release_year = 0;
            p_fp_info->release_month = 0;
    }


    /* Channel type */
    p_fp_info->channel = outhdr_values[i++];

    /* Derive direction from node type/side */
    node_type = outhdr_values[i++];
    p_fp_info->is_uplink = (( received  && (node_type == 2)) ||
                            (!received  && (node_type == 1)));

    /* Division type introduced for R7 */
    if (p_fp_info->release == 7)
    {
        p_fp_info->division = outhdr_values[i++];
    }

    /* HS-DSCH config */
    if (p_fp_info->channel == CHANNEL_HSDSCH)
    {
        if (p_fp_info->release == 7)
        {
            /* Entity (MAC-hs or MAC-ehs) used */
            if (outhdr_values[i++])
            {
                p_fp_info->hsdsch_entity = ehs;
            }
        }
        else
        {
            /* This is the pre-R7 default */
            p_fp_info->hsdsch_entity = hs;
        }
    }


    /* IUR only uses the above... */
    if (strcmp(protocol_name, "fpiur_r5") == 0)
    {
        /* Store info in packet */
        p_fp_info->iface_type = IuR_Interface;
        p_add_proto_data(pinfo->fd, proto_fp, p_fp_info);
        return;
    }

    /* DCH CRC present... */
    p_fp_info->dch_crc_present = outhdr_values[i++];

    /* ... but don't trust for edch */
    if (p_fp_info->channel == CHANNEL_EDCH)
    {
        p_fp_info->dch_crc_present = 2; /* unknown */
    }

    /* How many paging indications (if PCH data) */
    p_fp_info->paging_indications = outhdr_values[i++];

    /* Number of channels (for coordinated channels) */
    p_fp_info->num_chans = outhdr_values[i++];

    if (p_fp_info->channel != CHANNEL_EDCH)
    {
        /* TF size for each channel */
        tf_start = i;
        for (chan=0; chan < p_fp_info->num_chans; chan++)
        {
            p_fp_info->chan_tf_size[chan] = outhdr_values[tf_start+chan];
        }

        /* Number of TBs for each channel */
        num_chans_start = tf_start + p_fp_info->num_chans;
        for (chan=0; chan < p_fp_info->num_chans; chan++)
        {
            p_fp_info->chan_num_tbs[chan] = outhdr_values[num_chans_start+chan];
        }
    }
    /* EDCH info */
    else
    {
        int n;

        p_fp_info->no_ddi_entries = outhdr_values[i++];

        /* DDI values */
        for (n=0; n < p_fp_info->no_ddi_entries; n++)
        {
            p_fp_info->edch_ddi[n] = outhdr_values[i++];
        }

        /* Corresponding MAC-d sizes */
        for (n=0; n < p_fp_info->no_ddi_entries; n++)
        {
            p_fp_info->edch_macd_pdu_size[n] = outhdr_values[i++];
        }
    }

    /* Interface must be IuB */
    p_fp_info->iface_type = IuB_Interface;

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_fp, p_fp_info);
}


/* Fill in a MAC LTE packet info struct and attach it to the packet for that
   dissector to use */
static void attach_mac_lte_info(packet_info *pinfo)
{
    struct mac_lte_info *p_mac_lte_info;
    unsigned int i=0;

    /* Only need to set info once per session. */
    p_mac_lte_info = p_get_proto_data(pinfo->fd, proto_mac_lte);
    if (p_mac_lte_info != NULL)
    {
        return;
    }

    /* Allocate & zero struct */
    p_mac_lte_info = se_alloc0(sizeof(struct mac_lte_info));
    if (p_mac_lte_info == NULL)
    {
        return;
    }

    /* Populate the struct from outhdr values */
    p_mac_lte_info->radioType = outhdr_values[i++];
    p_mac_lte_info->rntiType = outhdr_values[i++];
    p_mac_lte_info->direction = outhdr_values[i++];
    p_mac_lte_info->subframeNumber = outhdr_values[i++];
    p_mac_lte_info->is_predefined_data = outhdr_values[i++];
    p_mac_lte_info->rnti = outhdr_values[i++];
    p_mac_lte_info->ueid = outhdr_values[i++];
    p_mac_lte_info->length = outhdr_values[i++];

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_mac_lte, p_mac_lte_info);
}


/* Fill in a RLC LTE packet info struct and attach it to the packet for that
   dissector to use */
static void attach_rlc_lte_info(packet_info *pinfo)
{
    struct rlc_lte_info *p_rlc_lte_info;
    unsigned int i=0;

    /* Only need to set info once per session. */
    p_rlc_lte_info = p_get_proto_data(pinfo->fd, proto_rlc_lte);
    if (p_rlc_lte_info != NULL)
    {
        return;
    }

    /* Allocate & zero struct */
    p_rlc_lte_info = se_alloc0(sizeof(struct rlc_lte_info));
    if (p_rlc_lte_info == NULL)
    {
        printf("Failed to allocate rlc_lte struct!\n");
        return;
    }

    p_rlc_lte_info->rlcMode = outhdr_values[i++];
    p_rlc_lte_info->direction = outhdr_values[i++];
    p_rlc_lte_info->priority = outhdr_values[i++];
    p_rlc_lte_info->UMSequenceNumberLength = outhdr_values[i++];
    p_rlc_lte_info->channelId = outhdr_values[i++];
    p_rlc_lte_info->channelType = outhdr_values[i++];
    p_rlc_lte_info->ueid = outhdr_values[i++];
    p_rlc_lte_info->pduLength = outhdr_values[i++];

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_rlc_lte, p_rlc_lte_info);
}

/* Fill in a PDCP packet info struct and attach it to the packet for the PDCP
   dissector to use */
#if 0
static void attach_pdcp_info(packet_info *pinfo)
{
    struct pdcp_info *p_pdcp_info;
    unsigned int i=0;

    /* Only need to set info once per session. */
    p_pdcp_info = p_get_proto_data(pinfo->fd, proto_pdcp);
    if (p_pdcp_info != NULL)
    {
        return;
    }

    /* Allocate & zero struct */
    p_pdcp_info = se_alloc0(sizeof(struct pdcp_info));
    if (p_pdcp_info == NULL)
    {
        printf("Failed to allocated pdcp struct!\n");
        return;
    }

    p_pdcp_info->no_header_pdu = outhdr_values[i++];
    p_pdcp_info->plane = outhdr_values[i++];
    p_pdcp_info->seqnum_length = outhdr_values[i++];

    p_pdcp_info->rohc_compression = outhdr_values[i++];
    p_pdcp_info->rohc_ip_version = outhdr_values[i++];
    p_pdcp_info->cid_inclusion_info = outhdr_values[i++];
    p_pdcp_info->large_cid_present = outhdr_values[i++];
    p_pdcp_info->mode = outhdr_values[i++];
    p_pdcp_info->rnd = outhdr_values[i++];
    p_pdcp_info->udp_checkum_present = outhdr_values[i++];
    p_pdcp_info->profile = outhdr_values[i++];

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_pdcp, p_pdcp_info);
}
#endif



/* Attempt to show tty (raw character messages) as text lines. */
void dissect_tty_lines(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    gint        next_offset;
    proto_tree  *tty_tree;
    proto_item  *ti;
    int         lines = 0;

    /* Create tty tree. */
    ti = proto_tree_add_item(tree, hf_catapult_dct2000_tty, tvb, offset, -1, FALSE);
    tty_tree = proto_item_add_subtree(ti, ett_catapult_dct2000);

    /* Show the tty lines one at a time. */
    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        /* Find the end of the line. */
        int linelen = tvb_find_line_end_unquoted(tvb, offset, -1, &next_offset);

        /* Extract & add the string. */
        char *string = (char*)tvb_get_ephemeral_string(tvb, offset, linelen);
        proto_tree_add_string_format(tty_tree, hf_catapult_dct2000_tty_line,
                                     tvb, offset,
                                     linelen, string,
                                     "%s", string);
        lines++;

        /* Show first line in info column */
        if (lines == 1 && check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "tty (%s", string);
        }

        /* Move onto next line. */
        offset = next_offset;
    }

    /* Close off summary of tty message in info column */
    if (lines != 0) {
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_str(pinfo->cinfo, COL_INFO, (lines > 1) ? "...)" : ")");
        }
    }
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
    guint8      port_number;
    gint        protocol_start;
    gint        protocol_length;
    gint        timestamp_start;
    gint        timestamp_length;
    gint        variant_start;
    gint        variant_length;
    gint        outhdr_start;
    gint        outhdr_length;
    guint8      direction;
    tvbuff_t    *next_tvb;
    int         encap;
    dissector_handle_t protocol_handle = 0;
    dissector_handle_t heur_protocol_handle = 0;
    int sub_dissector_result = 0;
    char        *protocol_name;

    /* Set Protocol */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCT2000");
    }

    /* Clear Info */
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    /* Create root (protocol) tree. */
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_catapult_dct2000, tvb, offset, -1, FALSE);
        dct2000_tree = proto_item_add_subtree(ti, ett_catapult_dct2000);
    }

    /*********************************************************************/
    /* Note that these are the fields of the stub header as written out  */
    /* by the wiretap module                                             */

    /* Context Name */
    context_length = tvb_strsize(tvb, offset);
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_context, tvb,
                            offset, context_length, FALSE);
    }
    offset += context_length;

    /* Context port number */
    port_number = tvb_get_guint8(tvb, offset);
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_port_number, tvb,
                            offset, 1, FALSE);
    }
    offset++;

    /* Timestamp in file */
    timestamp_start = offset;
    timestamp_length = tvb_strsize(tvb, offset);
    if (dct2000_tree) {
        proto_tree_add_double_format_value(dct2000_tree, hf_catapult_dct2000_timestamp, tvb,
                                           offset, timestamp_length,
                                           atof(tvb_format_text(tvb, offset, timestamp_length)),
                                           "%s", tvb_format_text(tvb, offset, timestamp_length-1));
    }
    offset += timestamp_length;


    /* DCT2000 protocol name */
    protocol_start = offset;
    protocol_length = tvb_strsize(tvb, offset);
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_protocol, tvb,
                            offset, protocol_length, FALSE);
    }
    offset += protocol_length;

    /* Protocol Variant */
    variant_start = offset;
    variant_length = tvb_strsize(tvb, offset);
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_variant, tvb,
                            offset, variant_length, FALSE);
    }
    offset += variant_length;

    /* Outhdr (shown as string) */
    outhdr_start = offset;
    outhdr_length = tvb_strsize(tvb, offset);
    if ((outhdr_length > 1) && dct2000_tree)
    {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_outhdr, tvb,
                            offset, outhdr_length, FALSE);
    }
    offset += outhdr_length;


    /* Direction */
    direction = tvb_get_guint8(tvb, offset);
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_direction, tvb,
                            offset, 1, FALSE);
    }
    offset++;

    /* Read frame encapsulation set by wiretap */
    if (dct2000_tree) {
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_encap, tvb, offset, 1, FALSE);
    }
    encap = tvb_get_guint8(tvb, offset);
    offset++;

    if (dct2000_tree)
    {
        /* Set selection length of dct2000 tree */
        proto_item_set_len(dct2000_tree, offset);
    }

    /* Add useful details to protocol tree label */
    protocol_name = (char*)tvb_get_ephemeral_string(tvb, protocol_start, protocol_length);
    if (tree)
    {
        proto_item_append_text(ti, "   context=%s.%u   t=%s   %c   prot=%s (v=%s)",
                               tvb_get_ephemeral_string(tvb, 0, context_length),
                               port_number,
                               tvb_get_ephemeral_string(tvb, timestamp_start, timestamp_length),
                               (direction == 0) ? 'S' : 'R',
                               protocol_name,
                               tvb_get_ephemeral_string(tvb, variant_start, variant_length));
    }


    /* FP protocols need info from outhdr attached */
    if ((strcmp(protocol_name, "fp") == 0) ||
        (strcmp(protocol_name, "fp_r4") == 0) ||
        (strcmp(protocol_name, "fp_r5") == 0) ||
        (strcmp(protocol_name, "fp_r6") == 0) ||
        (strcmp(protocol_name, "fp_r7") == 0) ||
        (strcmp(protocol_name, "fpiur_r5") == 0))
    {
        parse_outhdr_string(tvb_get_ephemeral_string(tvb, outhdr_start, outhdr_length));
        attach_fp_info(pinfo, direction, protocol_name,
                       atoi((char*)tvb_get_ephemeral_string(tvb, variant_start, variant_length)));
    }

    /* LTE MAC needs info attached */
    else if (strcmp(protocol_name, "mac_r8_lte") == 0)
    {
        parse_outhdr_string(tvb_get_ephemeral_string(tvb, outhdr_start, outhdr_length));
        attach_mac_lte_info(pinfo);
    }

    /* LTE RLC needs info attached */
    else if (strcmp(protocol_name, "rlc_r8_lte") == 0)
    {
        parse_outhdr_string(tvb_get_ephemeral_string(tvb, outhdr_start, outhdr_length));
        attach_rlc_lte_info(pinfo);
    }

#if 0
    /* LTE PDCP needs info attached */
    else if (strcmp(protocol_name, "pdcp_r8_lte") == 0)
    {
        parse_outhdr_string(tvb_get_ephemeral_string(tvb, outhdr_start, outhdr_length));
        attach_pdcp_info(pinfo);
    }
#endif


    /* Note that the first item of pinfo->pseudo_header->dct2000 will contain
       the pseudo-header needed (in some cases) by the Wireshark dissector that
       this packet data will be handed off to. */


    /***********************************************************************/
    /* Now hand off to the dissector of intended packet encapsulation type */

    /* Get protocol handle, and set p2p_dir where necessary.
       (packet-frame.c won't copy it from pseudo-header because it doesn't
        know about Catapult DCT2000 encap type...)
    */
    switch (encap)
    {
        case WTAP_ENCAP_RAW_IP:
            protocol_handle = find_dissector("ip");
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
            if (check_col(pinfo->cinfo, COL_DEF_SRC) && direction == 0)
            {
                col_add_fstr(pinfo->cinfo, COL_DEF_SRC,
                             "%s.%u",
                             tvb_get_ephemeral_string(tvb, 0, context_length),
                             port_number);
            }
            else
            if (check_col(pinfo->cinfo, COL_DEF_DST) && direction == 1)
            {
                col_add_fstr(pinfo->cinfo, COL_DEF_DST,
                             "%s.%u",
                             tvb_get_ephemeral_string(tvb, 0, context_length),
                             port_number);
            }


            /* Work with generic XML protocol.
               This is a bit of a hack, but xml isn't really a proper
               encapsulation type... */
            if (strcmp(protocol_name, "xml") == 0)
            {
                protocol_handle = find_dissector("xml");
            }
            else

            /* Attempt to show tty messages as raw text */
            if (strcmp(protocol_name, "tty") == 0)
            {
                dissect_tty_lines(tvb, pinfo, dct2000_tree, offset);
                return;
            }

            else
            if (strcmp(protocol_name, "sipprim") == 0)
            {
                protocol_handle = find_dissector("sipprim");
            }

            else
            if (strcmp(protocol_name, "mac_r8_lte") == 0)
            {
                protocol_handle = find_dissector("mac-lte");
            }

            else
            if (strcmp(protocol_name, "rlc_r8_lte") == 0)
            {
                protocol_handle = find_dissector("rlc-lte");
            }

#if 0
            else
            if (strcmp(protocol_name, "pdcp_r8_lte") == 0)
            {
                /* Send to intermediate dissector to parse/strip
                   proprietary RLC primitive header before passing to actual
                   PDCP dissector */
                protocol_handle = find_dissector("pdcp_r8");
            }
#endif

            else
            if ((strcmp(protocol_name, "rrc_r8_lte") == 0) ||
                (strcmp(protocol_name, "rrcpdcpprim_r8_lte") == 0))
                /* Dissect proprietary header, then pass remainder
                   to RRC (depending upon direction and channel type) */
            {
                dissect_rrc_lte(tvb, offset, pinfo, tree);
                return;
            }


            /* Many DCT2000 protocols have at least one IPPrim variant. If the
               protocol name can be matched to a dissector, try to find the
               UDP/TCP data inside and dissect it.
            */

            if (!protocol_handle && catapult_dct2000_try_ipprim_heuristic)
            {
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
                                            &conn_id_offset))
                {
                    proto_tree *ipprim_tree;
                    proto_item *ipprim_ti;

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
                                                              (char *)get_hostname(tvb_get_ipv4(tvb, source_addr_offset)) :
                                                              "<ipv6-address>"
                                                            ) :
                                                           "0.0.0.0",
                                                       (source_port_offset) ?
                                                           tvb_get_ntohs(tvb, source_port_offset) :
                                                           0,
                                                       (dest_addr_offset) ?
                                                         ((source_addr_length == 4) ?
                                                              (char *)get_hostname(tvb_get_ipv4(tvb, dest_addr_offset)) :
                                                              "<ipv6-address>"
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
                    if (source_addr_offset != 0)
                    {
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
                                            tvb, source_addr_offset, source_addr_length, FALSE);

                        /* Add hidden item for "side-less" addr */
                        addr_ti = proto_tree_add_item(ipprim_tree,
                                                      (source_addr_length == 4) ?
                                                          hf_catapult_dct2000_ipprim_addr_v4 :
                                                          hf_catapult_dct2000_ipprim_addr_v6,
                                                      tvb, source_addr_offset,
                                                      source_addr_length, FALSE);
                        PROTO_ITEM_SET_HIDDEN(addr_ti);
                    }
                    if (source_port_offset != 0)
                    {
                        proto_item *port_ti;

                        pinfo->srcport = tvb_get_ntohs(tvb, source_port_offset);

                        proto_tree_add_item(ipprim_tree,
                                            (type_of_port == PT_UDP) ?
                                               hf_catapult_dct2000_ipprim_udp_src_port :
                                               hf_catapult_dct2000_ipprim_tcp_src_port,
                                            tvb, source_port_offset, 2, FALSE);
                        port_ti = proto_tree_add_item(ipprim_tree,
                                                      (type_of_port == PT_UDP) ?
                                                          hf_catapult_dct2000_ipprim_udp_port :
                                                          hf_catapult_dct2000_ipprim_tcp_port,
                                                      tvb, source_port_offset, 2, FALSE);
                        PROTO_ITEM_SET_HIDDEN(port_ti);
                    }
                    if (dest_addr_offset != 0)
                    {
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
                                            tvb, dest_addr_offset, dest_addr_length, FALSE);

                        /* Add hidden item for "side-less" addr */
                        addr_ti = proto_tree_add_item(ipprim_tree,
                                                      (dest_addr_length == 4) ? 
                                                          hf_catapult_dct2000_ipprim_addr_v4 :
                                                          hf_catapult_dct2000_ipprim_addr_v6,
                                                      tvb, dest_addr_offset, dest_addr_length, FALSE);
                        PROTO_ITEM_SET_HIDDEN(addr_ti);
                    }
                    if (dest_port_offset != 0)
                    {
                        proto_item *port_ti;

                        pinfo->destport = tvb_get_ntohs(tvb, dest_port_offset);

                        proto_tree_add_item(ipprim_tree,
                                            (type_of_port == PT_UDP) ?
                                               hf_catapult_dct2000_ipprim_udp_dst_port :
                                               hf_catapult_dct2000_ipprim_tcp_dst_port,
                                            tvb, dest_port_offset, 2, FALSE);
                        port_ti = proto_tree_add_item(ipprim_tree,
                                                      (type_of_port == PT_UDP) ?
                                                          hf_catapult_dct2000_ipprim_udp_port :
                                                          hf_catapult_dct2000_ipprim_tcp_port,
                                                      tvb, dest_port_offset, 2, FALSE);
                        PROTO_ITEM_SET_HIDDEN(port_ti);
                    }
                    if (conn_id_offset != 0)
                    {
                        proto_tree_add_item(ipprim_tree,
                                            hf_catapult_dct2000_ipprim_conn_id,
                                            tvb, conn_id_offset, 2, FALSE);
                    }


                    /* Set source and dest columns now (will be overwriiten if
                       src and dst IP addresses set) */
                    if (source_addr_offset && check_col(pinfo->cinfo, COL_DEF_SRC))
                    {
                        col_append_fstr(pinfo->cinfo, COL_DEF_SRC,
                                        "(%s:%u)",
                                        (char*)get_hostname(tvb_get_ipv4(tvb, source_addr_offset)),
                                        tvb_get_ntohs(tvb, source_port_offset));
                    }
                    if (dest_addr_offset && check_col(pinfo->cinfo, COL_DEF_DST))
                    {
                        col_append_fstr(pinfo->cinfo, COL_DEF_DST,
                                        "(%s:%u)",
                                        (char*)get_hostname(tvb_get_ipv4(tvb, dest_addr_offset)),
                                        tvb_get_ntohs(tvb, dest_port_offset));
                    }

                    /* Set length for IPPrim tree */
                    proto_item_set_len(ipprim_tree, offset - offset_before_ipprim_header);
                }
            }


            /* Try SCTP Prim heuristic if configured to */
            if (!protocol_handle && catapult_dct2000_try_sctpprim_heuristic)
            {
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
                                                        &dest_port_offset)))
                {
                    proto_tree *sctpprim_tree;
                    proto_item *ti_local;

                    /* Will use this dissector then. */
                    protocol_handle = heur_protocol_handle;

                    ti_local =  proto_tree_add_string_format(dct2000_tree, hf_catapult_dct2000_sctpprim_addresses,
                                                       tvb, offset_before_sctpprim_header, 0,
                                                       "", "SCTPPrim transport:  -> %s:%u",
                                                       (dest_addr_offset) ?
                                                         ((dest_addr_length == 4) ?
                                                              (char *)get_hostname(tvb_get_ipv4(tvb, dest_addr_offset)) :
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
                    if (dest_addr_offset != 0)
                    {
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
                                            tvb, dest_addr_offset, dest_addr_length, FALSE);

                        /* Add hidden item for "side-less" addr */
                        addr_ti = proto_tree_add_item(sctpprim_tree,
                                                      (dest_addr_length == 4) ? 
                                                          hf_catapult_dct2000_sctpprim_addr_v4 :
                                                          hf_catapult_dct2000_sctpprim_addr_v6,
                                                      tvb, dest_addr_offset, dest_addr_length, FALSE);
                        PROTO_ITEM_SET_HIDDEN(addr_ti);
                    }

                    if (dest_port_offset != 0)
                    {
                        pinfo->destport = tvb_get_ntohs(tvb, dest_port_offset);

                        proto_tree_add_item(sctpprim_tree,
                                            hf_catapult_dct2000_sctpprim_dst_port,
                                            tvb, dest_port_offset, 2, FALSE);
                    }

                    /* Set length for SCTPPrim tree */
                    proto_item_set_len(sctpprim_tree, offset - offset_before_sctpprim_header);
                }
            }

            break;

        default:
            /* !! If get here, there is a mismatch between
               this dissector and the wiretap module catapult_dct2000.c !!
            */
            DISSECTOR_ASSERT_NOT_REACHED();
            return;
    }


    /* Try appropriate dissector, if one has been selected */
    if (protocol_handle != 0)
    {
        /* Dissect the remainder of the frame using chosen protocol handle */
        next_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
        sub_dissector_result = call_dissector_only(protocol_handle, next_tvb, pinfo, tree);
    }


    if (protocol_handle == 0 || sub_dissector_result == 0)
    {
        /* Could get here because:
           - encap is DCT2000_ENCAP_UNHANDLED and we still didn't handle it, OR
           - desired protocol is unavailable (probably disabled), OR
           - protocol rejected our data
           Show remaining bytes as unparsed data */
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_unparsed_data,
                            tvb, offset, -1, FALSE);

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "Not dissected  (context=%s.%u   t=%s   %c   prot=%s (v=%s))",
                         tvb_get_ephemeral_string(tvb, 0, context_length),
                         port_number,
                         tvb_get_ephemeral_string(tvb, timestamp_start, timestamp_length),
                         (direction == 0) ? 'S' : 'R',
                         tvb_get_ephemeral_string(tvb, protocol_start, protocol_length),
                         tvb_get_ephemeral_string(tvb, variant_start, variant_length));
        }
    }
    else
    {
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
    dissector_add("wtap_encap", WTAP_ENCAP_CATAPULT_DCT2000,
                  catapult_dct2000_handle);
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
              "Context port number", HFILL
            }
        },
        { &hf_catapult_dct2000_timestamp,
            { "Timestamp",
              "dct2000.timestamp", FT_DOUBLE, BASE_DEC, NULL, 0x0,
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
        { &hf_catapult_dct2000_dissected_length,
            { "Dissected length",
              "dct2000.dissected-length", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Number of bytes dissected by subdissector(s)", HFILL
            }
        },

        { &hf_catapult_dct2000_ipprim_addresses,
            { "IPPrim Addresses",
              "dct2000.ipprim", FT_STRING, BASE_NONE, NULL, 0x0,
              "IPPrim Addresses", HFILL
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
              "SCTPPrim Addresses", HFILL
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
              "tty contents", HFILL
            }
        },
        { &hf_catapult_dct2000_tty_line,
            { "tty line",
              "dct2000.tty-line", FT_STRING, BASE_NONE, NULL, 0x0,
              "tty line", HFILL
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
}

