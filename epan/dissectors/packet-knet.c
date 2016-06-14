/* packet-knet.c
 * Routines for the KristalliNet (kNet) protocol.
 * Kari Vatjus-Anttila <kari.vatjus-anttila@cie.fi>
 * Ville Saarinen <ville.saarinen@cie.fi>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

void proto_register_knet(void);
void proto_reg_handoff_knet(void);

#define PROTO_TAG_KNET      "KNET"    /*!< Definition of kNet Protocol */
#define PORT                2345

#define KNET_SCTP_PACKET    1000
#define KNET_TCP_PACKET     1001
#define KNET_UDP_PACKET     1002

/**
 * @addtogroup messageids kNet Message ID:s
 * Message ID:s of the kNet protocol
 */
/**@{*/
#define PINGREQUEST            1      /*!< Message ID definition: Ping Request */
#define PINGREPLY              2      /*!< Message ID definition: Ping Reply */
#define FLOWCONTROLREQUEST     3      /*!< Message ID definition: Flow Control Request */
#define PACKETACK              4      /*!< Message ID definition: Packet Acknowledge */
#define DISCONNECT           255      /*!< Message ID definition: Disconnect */
#define DISCONNECTACK        254      /*!< Message ID definition: Disconnect Ack */
#define CONNECTSYN           253      /*!< Message ID definition: Connect Syn */
#define CONNECTSYNACK        252      /*!< Message ID definition: Connect Syn Acknowledge */
#define CONNECTACK           251      /*!< Message ID definition: Connect Acknowledge */
/**@}*/

#define UDP_DATAGRAM_RELIABLE_FLAG    0x40
#define UDP_MSG_BLOCK_RELIABLE_FLAG   0x10

/**
 * @addtogroup protocols Protocol Variables
 * Protocol variables.
 */
/**@{*/
static int proto_knet        = -1;
/**@}*/

/**
 * @addtogroup headerfields Dissector Header Fields
 * Header fields of the kNet datagram
 */
/* *@{*/

/* Fields used by the TCP/SCTP dissector */
static int hf_knet_message_tree =   -1; /*!< Message tree */
static int hf_knet_content_length_vle = -1; /*!< Content Length */

/* Fields used by the UDP dissector */
static int hf_knet_content_length =              -1; /*!< Content Length */
static int hf_knet_datagram_tree =               -1; /*!< Datagram subtree */
static int hf_knet_flags =                       -1; /*!< UDP Flags subtree */
static int hf_knet_inorder =                     -1; /*!< Inorder Flag */
static int hf_knet_reliable =                    -1; /*!< Reliable Flag */
static int hf_knet_packetid =                    -1; /*!< PacketID */
static int hf_knet_rmib =                        -1; /*!< Reliable Message Index Base */
static int hf_knet_msg_flags =                   -1; /*!< Message Block Flags subtree */
static int hf_knet_msg_fs =                      -1; /*!< Fragment Start */
static int hf_knet_msg_ff =                      -1; /*!< Fragment Flag */
static int hf_knet_msg_inorder =                 -1; /*!< Inorder Flag */
static int hf_knet_msg_reliable =                -1; /*!< Reliable Flag */
static int hf_knet_msg_reliable_message_number = -1; /*!< Reliable Message Number */

static int hf_knet_payload_tree =    -1; /*!< Payload subtree */
static int hf_knet_payload =         -1; /*!< Payload subtree */
static int hf_knet_messageid =       -1; /*!< MessageID of the packet */
static int hf_knet_pingid =          -1;
static int hf_knet_flowctrlreq =     -1;
static int hf_knet_packetack =       -1;
static int hf_knet_seqnumber =       -1;
/**@}*/

/**
 * @addtogroup trees Subtrees used by the dissectors
 */
/* *@{*/

/*Knet Subtrees */
static gint ett_knet_main =          -1; /*!< Main kNet tree */
static gint ett_knet_message =       -1; /*!< Message tree */
static gint ett_knet_payload =       -1; /*!< Payload tree */
static gint ett_knet_message_flags = -1; /*!< Message flags tree */
static gint ett_knet_datagram =      -1;
static gint ett_knet_flags =         -1;
/**@}*/

static dissector_handle_t knet_handle_sctp;
static dissector_handle_t knet_handle_tcp;
static dissector_handle_t knet_handle_udp;

/* Ports used by the dissectors */
static guint32 knet_sctp_port =   PORT; /*!< Port used by kNet SCTP */
static guint32 knet_tcp_port =    PORT; /*!< Port used by kNet TCP */
static guint32 knet_udp_port =    PORT; /*!< Port used by kNet UDP */

static const value_string packettypenames[] = { /*!< Messageid List */
    { PINGREQUEST,          "Ping Request"        },
    { PINGREPLY,            "Ping Reply"          },
    { FLOWCONTROLREQUEST,   "Flowcontrol Request" },
    { PACKETACK,            "Packet Ack"          },
    { DISCONNECT,           "Disconnect"          },
    { DISCONNECTACK,        "Disconnect Ack"      },
    { CONNECTSYN,           "Connect Syn"         },
    { CONNECTSYNACK,        "Connect Syn Ack"     },
    { CONNECTACK,           "Connect Ack"         },
    { 0,                    NULL                  }
};

/**
 * counts length of the variable length encoded field
 *
 * @param  tvb the buffer to the data
 * @param  offset the offset of data in the buffer
 * @return int returns number of bytes used
 *
 */
static int
count_vle_bytes(tvbuff_t *tvb, int offset)
{
    int byte_count = 1;

    if(tvb_get_guint8(tvb, offset) & 0x80)     /* If the first bit of the first byte is 1 */
        byte_count = 2;                                     /* There's at least 2 bytes of content length */
    if(tvb_get_guint8(tvb, offset+1) & 0x80)   /* If the next one is also 1 */
        byte_count = 4;

    return byte_count;
}

/**
 * dissect_packetid is a utility function which calculates
 * the packets Packet ID from the data. Packet ID is a field
 * located in the datagram header.
 *
 * @see dissect_reliable_message_index_base()
 * @see dissect_reliable_message_number()
 * @see dissect_content_length()
 * @see dissect_messageid()
 * @see dissect_payload()
 * @param buffer the buffer to the data
 * @param offset the offset where to start reading the data
 * @param tree the parent tree where the dissected data is going to be inserted
 * @return int returns the new offset
 *
 */
static guint32
dissect_packetid(tvbuff_t *buffer, int offset, proto_tree *tree)
{
    guint32 packetid;

    packetid  = tvb_get_guint8(buffer, offset+2) << 14;
    packetid += tvb_get_guint8(buffer, offset+1) << 6;
    packetid += tvb_get_guint8(buffer, offset) & 63;

    proto_tree_add_uint(tree, hf_knet_packetid, buffer, 0, 3, packetid);
    return packetid;
}

/**
 * dissect_reliable_message_index_base is a utility function
 * which calculates the packets RMIB if and only if the reliable
 * flag is set to 1.
 *
 * @see dissect_packetid()
 * @see dissect_content_length()
 * @see dissect_reliable_message_number()
 * @see dissect_messageid()
 * @see dissect_payload()
 * @param buffer the buffer to the data
 * @param offset the offset where to start reading the data
 * @param tree the parent tree where the dissected data is going to be inserted
 * @return int returns the new offset
 *
 */
static int
dissect_reliable_message_index_base(tvbuff_t *buffer, int offset, proto_tree *tree)
{
    int byte_count = 2;

    if(tvb_get_guint8(buffer, offset+1) & 0x80)
        byte_count = 4;

    proto_tree_add_item(tree, hf_knet_rmib, buffer, offset, byte_count, ENC_LITTLE_ENDIAN);

    return byte_count;
}

/**
 * dissect_content_length_vle is a utility function which
 * calculates how long is the payload section of the message
 * in bytes which is VLE encoded.
 *
 * @see dissect_packetid()
 * @see dissect_reliable_message_index_base()
 * @see dissect_reliable_message_number()
 * @see dissect_messageid()
 * @see dissect_payload()
 * @param buffer the buffer to the data
 * @param offset the offset where to start reading the data
 * @param tree the parent tree where the dissected data is going to be inserted
 * @return int returns the content length of the packet
 *
 */
static int
dissect_content_length_vle(tvbuff_t *buffer, int *offset, proto_tree *tree)
{
    int     byte_count;
    guint32 length;

    length     = 0;
    byte_count = count_vle_bytes(buffer, *offset);

    switch(byte_count) /*We must calculate length by hand because we use the length later */
    {
        case 4:
            length = tvb_get_guint8(buffer, (*offset) + 3) << 23;
            length += (tvb_get_guint8(buffer, (*offset) + 2) << 15);
            /* FALLTHRU */
        case 2:
            length += (tvb_get_guint8(buffer, (*offset) + 1) << 7);
            /* FALLTHRU */
        case 1:
            length += (tvb_get_guint8(buffer, (*offset)) & 0x7F);
        break;
        default:
            REPORT_DISSECTOR_BUG("Error in Content Length calculation");
        break;
    }

    proto_tree_add_uint(tree, hf_knet_content_length_vle, buffer, (*offset), byte_count, length);
    (*offset) += byte_count;

    return length;
}

/**
 * dissect_content_length is a utility function which
 * calculates how long is the payload section of the message
 * in bytes. Used only by the UDP dissector.
 *
 * @see dissect_packetid()
 * @see dissect_reliable_message_index_base()
 * @see dissect_reliable_message_number()
 * @see dissect_messageid()
 * @see dissect_payload()
 * @param buffer the buffer to the data
 * @param offset the offset where to start reading the data
 * @param tree the parent tree where the dissected data is going to be inserted
 * @return int returns the content length of the packet
 *
 */
static int
dissect_content_length(tvbuff_t *buffer, int offset, proto_tree *tree)
{
    proto_item *msgflags_ti;
    proto_tree *msgflags_tree;
    guint32     length;

    length  = tvb_get_bits8(buffer, offset * 8 + 12, 4) << 8;
    length += tvb_get_bits8(buffer, offset * 8, 8);

    if(tree != NULL)
    {
        msgflags_ti   = proto_tree_add_item(tree, hf_knet_msg_flags, buffer, offset + 1, 1, ENC_NA);
        msgflags_tree = proto_item_add_subtree(msgflags_ti, ett_knet_message_flags);

        proto_tree_add_item(msgflags_tree, hf_knet_msg_fs, buffer, offset+1, 1, ENC_NA); /* Fragment start flag */
        proto_tree_add_item(msgflags_tree, hf_knet_msg_ff, buffer, offset+1, 1, ENC_NA);  /* Fragment flag */
        proto_tree_add_item(msgflags_tree, hf_knet_msg_inorder, buffer, offset+1, 1, ENC_NA); /* Inorder flag */
        proto_tree_add_item(msgflags_tree, hf_knet_msg_reliable, buffer, offset+1, 1, ENC_NA); /* Reliable flag */

        proto_tree_add_uint(tree, hf_knet_content_length, buffer, offset, 2, length);
    }

    return length;
}

/**
 * dissect_reliable_message_number is a utility function which
 * calculates the RMN if and only if the reliable flag in the
 * message block is set to 1.
 *
 * @see dissect_packetid()
 * @see dissect_reliable_message_index_base()
 * @see dissect_content_length()
 * @see dissect_messageid()
 * @see dissect_payload()
 * @param buffer the buffer to the data
 * @param offset the offset where to start reading the data
 * @param tree the parent tree where the dissected data is going to be inserted
 * @return int returns the new offset
 *
 */
static int
dissect_reliable_message_number(tvbuff_t *buffer, int offset, proto_tree *tree)
{
    int byte_count = 1;

    if(tvb_get_guint8(buffer, offset) & 0x80)
        byte_count = 2;

    proto_tree_add_item(tree, hf_knet_msg_reliable_message_number, buffer, offset, byte_count, ENC_LITTLE_ENDIAN);

    return byte_count;
}

/**
 * dissect_messageid is a utility function which
 * calculates the ID of the message.
 *
 * @see dissect_packetid()
 * @see dissect_reliable_message_index_base()
 * @see dissect_content_length()
 * @see dissect_reliable_message_number()
 * @see dissect_payload()
 * @param buffer the buffer to the data
 * @param offset the offset where to start reading the data
 * @param tree the parent tree where the dissected data is going to be inserted
 * @return int returns the messageid
 *
 */
static int
dissect_messageid(tvbuff_t *buffer, int *offset, proto_tree *tree, packet_info *pinfo, gboolean separator)
{
    gint   messageid_length;
    guint8 messageid;

    messageid = tvb_get_guint8(buffer, (*offset));

    switch(messageid)
    {
        case DISCONNECT:
        case DISCONNECTACK:
        case CONNECTSYN:
        case CONNECTSYNACK:
        case CONNECTACK:
            messageid_length = 4;
        break;
        default:
            messageid_length = 1;
        break;
    }

    proto_tree_add_uint_format_value(tree, hf_knet_messageid, buffer, *offset, messageid_length, messageid,
            "%s (%d)", val_to_str_const(messageid, packettypenames, "AppData or Malformed Message ID"), messageid);

    if (separator)
    {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s (%d)", val_to_str_const(messageid, packettypenames, "AppData"), messageid);
    }
    else
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s (%d)", val_to_str_const(messageid, packettypenames, "AppData"), messageid);
    }

    *offset += messageid_length;

    return messageid;
}

/**
 * dissect_payload is a utility function which
 * calculates the actual payload of the message.
 *
 * @see dissect_packetid()
 * @see dissect_reliable_message_index_base()
 * @see dissect_content_length()
 * @see dissect_reliable_message_number()
 * @see dissect_messageid()
 * @param buffer the buffer to the data
 * @param offset the offset where to start reading the data
 * @param messageid the messageid of the received message
 * @param tree the parent tree where the dissected data is going to be inserted
 * @param content_length the content length of the payload
 * @return int returns 0 at the moment
 *
 */
static int
dissect_payload(tvbuff_t *buffer, int offset, int messageid, proto_tree *tree, int content_length)
{
    proto_item *payload_ti;
    proto_tree *payload_tree;

    payload_ti   = proto_tree_add_item(tree, hf_knet_payload_tree, buffer, offset, content_length - 1, ENC_NA);
    payload_tree = proto_item_add_subtree(payload_ti, ett_knet_payload);

    switch(messageid)
    {
        case PINGREQUEST:
        case PINGREPLY:
            proto_tree_add_item(payload_tree, hf_knet_pingid, buffer, offset, 1, ENC_LITTLE_ENDIAN);
        break;
        case FLOWCONTROLREQUEST:
            proto_tree_add_item(payload_tree, hf_knet_flowctrlreq, buffer, offset, 3, ENC_LITTLE_ENDIAN);
        break;
        case PACKETACK:
            proto_tree_add_item(payload_tree, hf_knet_packetack, buffer, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
            proto_tree_add_item(payload_tree, hf_knet_seqnumber, buffer, offset, 4, ENC_LITTLE_ENDIAN);
        break;
        case DISCONNECT:    /*No payload*/
        case DISCONNECTACK: /*No payload*/
            proto_tree_add_bytes_format(payload_tree, hf_knet_payload, buffer, offset, 0, NULL, "No Payload");
        break;
        case CONNECTSYN:    /*TODO: Not yet implemented, implement when available*/
        case CONNECTSYNACK: /*TODO: Not yet implemented, implement when available*/
        case CONNECTACK:    /*TODO: Not yet implemented, implement when available*/
            proto_tree_add_item(payload_tree, hf_knet_payload, buffer, offset, content_length-1, ENC_NA);
        break;
        default: /* Application Specific Message */
            proto_tree_add_item(payload_tree, hf_knet_payload, buffer, offset, content_length-1, ENC_NA);
        break;
    }

    return 0;
}

/**
 * dissect_knet_message is the subdissector which is called
 * by dissect_knet when the dissector has dissected the
 * datagram header. This subdissector dissects all of the
 * messages which are encapsulated in the kNet datagram.
 *
 * @see dissect_knet()
 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted
 *
 */
static int
dissect_knet_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int messageindex)
{
    int content_length, total_length, messageid;
    int start_offset = offset;

    proto_item *msgblock_ti;
    proto_tree *msgblock_tree;

    msgblock_ti = proto_tree_add_item(tree, hf_knet_message_tree, tvb, offset, -1, ENC_NA);
    msgblock_tree = proto_item_add_subtree(msgblock_ti, ett_knet_message);

    content_length = dissect_content_length(tvb, offset, msgblock_tree); /* Calculates the Content Length of this packet. */

    if(tvb_get_guint8(tvb, offset+1) & UDP_MSG_BLOCK_RELIABLE_FLAG) /* If the reliable flag is 1 then calculate RMN */
        offset += dissect_reliable_message_number(tvb, offset+2, msgblock_tree);

    offset += 2; /* Move the offset the amount of contentlength and flags fields */

    total_length = (offset-start_offset)+content_length;
    proto_item_set_len(msgblock_ti, total_length);

    messageid = dissect_messageid(tvb, &offset, msgblock_tree, pinfo, messageindex != 0);

    dissect_payload(tvb, offset, messageid, msgblock_tree, content_length);

    return total_length;
}

/**
 * dissect_knet is the dissector which is called
 * by Wireshark when kNet packets are captured. Here
 * is dissected the SCTP and TCP packets in its own
 * section and UDP packets in its own, because UDP
 * packets differ quite a lot from SCTP and TCP.
 * SCTP and TCP in the other hand has quite the same
 * structure.
 *
 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted
 *
 */
static void
dissect_knet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int current_protocol)
{
    proto_item *knet_ti, *message_ti;
    proto_tree *knet_tree, *message_tree;

    int offset = 0, content_length, messageid;

    /* Attach kNet main tree to Wireshark tree */
    knet_ti   = proto_tree_add_item(tree, proto_knet, tvb, 0, -1, ENC_NA);
    knet_tree = proto_item_add_subtree(knet_ti, ett_knet_main);

    /* Attach message tree to kNet tree */
    message_ti = proto_tree_add_item(knet_tree, hf_knet_message_tree, tvb, offset, -1, ENC_NA);
    message_tree = proto_item_add_subtree(message_ti, ett_knet_message);

    content_length = dissect_content_length_vle(tvb, &offset, message_tree); /* Calculate length and add it to the tree-view */
    proto_item_set_len(message_ti, (current_protocol == KNET_SCTP_PACKET ? content_length + 1 : content_length + 2));

    messageid = dissect_messageid(tvb, &offset, message_tree, pinfo, TRUE); /* Calculate messageid and add it to the tree-view */

    dissect_payload(tvb, offset, messageid, message_tree, content_length); /* Calculate payload and add it to the tree-view */

    col_set_fence(pinfo->cinfo, COL_INFO);
}

/**
 * Callback function that returns the pdu length.
 * Used by TCP dissector.
 *
 * @param   pinfo the info about the packet
 * @param   tvb the data buffer
 * @param   offset the offset to the tvb buffer
 * @return  guint returns pdu length
 *
 */
static guint
get_knet_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return count_vle_bytes(tvb, offset) + dissect_content_length_vle(tvb, &offset, NULL);
}

/**
 * dissect_knet_tcp is the dissector which is called
 * by Wireshark when kNet TCP packets are captured.
 *
 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted
 *
 */
static int
dissect_knet_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_knet(tvb, pinfo, tree, KNET_TCP_PACKET);
    return tvb_captured_length(tvb);
}

static int
dissect_knet_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KNET");

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 2, get_knet_pdu_len, dissect_knet_tcp_pdu, data);
    return tvb_captured_length(tvb);
}

/**
 * dissect_knet_sctp is the dissector which is called
 * by Wireshark when kNet STCP packets are captured.
 *
 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted
 *
 */
static int
dissect_knet_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KNET");

    dissect_knet(tvb, pinfo, tree, KNET_SCTP_PACKET);
    return tvb_captured_length(tvb);
}

/**
 * dissect_knet_udp is the dissector which is called
 * by Wireshark when kNet UDP packets are captured.
 *
 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted
 *
 */
static int
dissect_knet_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* Common subtrees */
    proto_item *knet_ti;
    proto_tree *knet_tree;

    /* Subtrees used in kNet UDP dissector */
    proto_item *datagram_ti, *udpflags_ti;
    proto_tree *datagram_tree, /* Tree containing all header related info */
               *udpflags_tree; /* Tree containing UDP Datagram Flags */

    int offset = 0;
    guint32 packetid; /* Contains info about PacketID */
    int messageindex = 0; /*!< Index of the kNet message inside a datagram */

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KNET");

    /*kNet UDP Tree*/
    knet_ti = proto_tree_add_item(tree, proto_knet, tvb, 0, -1, ENC_NA); /* Attach kNet tree to wireshark main tree */
    knet_tree = proto_item_add_subtree(knet_ti, ett_knet_main);

    /*Datagram Header Tree*/
    datagram_ti = proto_tree_add_item(knet_ti, hf_knet_datagram_tree, tvb, 0, 3, ENC_NA); /* Attach Header tree to wireshark main tree */
    datagram_tree = proto_item_add_subtree(datagram_ti, ett_knet_datagram);

    packetid = dissect_packetid(tvb, 0, datagram_tree); /* Lets calculate our packetid! */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Packet ID %d: ", packetid);

    /*UDPFlags Tree*/
    udpflags_ti = proto_tree_add_item(datagram_ti, hf_knet_flags, tvb, 0, 1, ENC_NA);         /* Attach UDP Flags tree to kNet tree */
    udpflags_tree = proto_item_add_subtree(udpflags_ti, ett_knet_flags);

    proto_tree_add_item(udpflags_tree, hf_knet_inorder, tvb, 0, 1, ENC_NA); /* Add inorder flag to UDP Flags tree */
    proto_tree_add_item(udpflags_tree, hf_knet_reliable, tvb, 0, 1, ENC_NA); /* Add reliable flag to UDP Flags tree */

    offset += 3;

    if(tvb_get_guint8(tvb, 0) & UDP_DATAGRAM_RELIABLE_FLAG)
        offset += dissect_reliable_message_index_base(tvb, 3, datagram_tree); /* Calculate RMIB */

    while ((tvb_reported_length_remaining(tvb, offset) > 2) && /* If there's at least 2 bytes available in the buffer */
           (dissect_content_length(tvb, offset, NULL) > 0)) /* Empty data Abort */
    {
        offset += dissect_knet_message(tvb, pinfo, knet_tree, offset, messageindex); /* Call the message subdissector */
        messageindex++;
    }

    return tvb_captured_length(tvb);
}
/**
 * proto_register_knet registers our kNet protocol,
 * headerfield- and subtree-array to Wireshark.
 *
 */
void
proto_register_knet(void)
{
    module_t *knet_module;

    static hf_register_info hf_knet[] =
    {
        /* TCP & SCTP Header */
        {&hf_knet_content_length_vle,
         {"Content Length",      "knet.length",
          FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_message_tree,
         {"Message Block",       "knet.msg",
        FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},

        /* UDP Header */
        {&hf_knet_datagram_tree,
         {"Datagram Header",             "knet.datagram",
          FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_flags,
         {"Flags",                       "knet.datagram.flags",
          FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_inorder,
         {"Inorder Flag",                "knet.datagram.inorder",
          FT_BOOLEAN,  8,  NULL, 0x80, NULL, HFILL}},
        {&hf_knet_reliable,
         {"Reliable Flag",               "knet.datagram.reliable",
          FT_BOOLEAN,  8,  NULL, UDP_DATAGRAM_RELIABLE_FLAG, NULL, HFILL}},
        {&hf_knet_packetid,
         {"Packet ID",                   "knet.datagram.packetid",
          FT_UINT24, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_rmib,
         {"Reliable Message Index Base", "knet.datagram.rmib",
          FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_msg_flags,
         {"Flags",                       "knet.msg.flags",
          FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_msg_fs,
         {"Fragment Start",              "knet.msg.flags.fs",
          FT_BOOLEAN,  8,  NULL, 0x80, NULL, HFILL}},
        {&hf_knet_msg_ff,
         {"Fragment Flag",               "knet.msg.flags.ff",
          FT_BOOLEAN,  8,  NULL, 0x40, NULL, HFILL}},
        {&hf_knet_msg_inorder,
         {"Inorder Flag",                "knet.msg.flags.inorder",
          FT_BOOLEAN,  8,  NULL, 0x20, NULL, HFILL}},
        {&hf_knet_msg_reliable,
         {"Reliable Flag",               "knet.msg.flags.reliable",
          FT_BOOLEAN,  8,  NULL, UDP_MSG_BLOCK_RELIABLE_FLAG, NULL, HFILL}},
        {&hf_knet_content_length,
         {"Content Length",      "knet.length",
          FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_msg_reliable_message_number,
         {"Reliable Message Number",     "knet.msg.reliable_number",
          FT_UINT24, BASE_DEC,  NULL, 0x0, NULL, HFILL}},

        /* Payload */
        {&hf_knet_payload_tree,
         {"Payload",             "knet.payload.tree",
          FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_payload,
         {"Payload",             "knet.payload.data",
          FT_BYTES,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_messageid,
         {"Message ID",          "knet.payload.messageid",
          FT_UINT32,  BASE_DEC, VALS(packettypenames), 0x0, NULL, HFILL}},
        {&hf_knet_pingid,
         {"Ping ID",             "knet.payload.pingid",
          FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_flowctrlreq,
         {"Flowcontrol Request", "knet.payload.flowctrlreq",
          FT_UINT24, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_packetack,
         {"Packet Ack",          "knet.payload.packetack",
          FT_UINT24, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_seqnumber,
         {"Sequence Number",     "knet.payload.seqnumber",
          FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL}}
    };

    static gint *ett_knet[] =
    {
        &ett_knet_main,
        &ett_knet_datagram,
        &ett_knet_flags,
        &ett_knet_message,
        &ett_knet_message_flags,
        &ett_knet_payload
    };

    /* Register header field & subtree arrays */
    proto_register_field_array(proto_knet, hf_knet, array_length(hf_knet));
    proto_register_subtree_array(ett_knet, array_length(ett_knet));

    /* Register protocols */
    proto_knet = proto_register_protocol ("kNet Protocol", "KNET", "knet");

    knet_handle_sctp = register_dissector("knetsctp", dissect_knet_sctp, proto_knet);
    knet_handle_tcp = register_dissector("knettcp",  dissect_knet_tcp, proto_knet);
    knet_handle_udp = register_dissector("knetudp",  dissect_knet_udp, proto_knet);

    knet_module = prefs_register_protocol(proto_knet, proto_reg_handoff_knet);

    prefs_register_uint_preference(knet_module, "sctp.port", "kNet SCTP Port",
                                   "Set the SCTP port for kNet messages",
                                   10, &knet_sctp_port);

    prefs_register_uint_preference(knet_module, "tcp.port", "kNet TCP Port",
                                   "Set the TCP port for kNet messages",
                                   10, &knet_tcp_port);

    prefs_register_uint_preference(knet_module, "udp.port", "kNet UDP Port",
                                   "Set the UDP port for kNet messages",
                                   10, &knet_udp_port);
}

/**
 * proto_reg_handoff_knet registers our kNet dissectors to Wireshark
 *
 */
void
proto_reg_handoff_knet(void)
{
    static gboolean initialized = FALSE;

    static guint current_sctp_port;
    static guint current_tcp_port;
    static guint current_udp_port;

    if(!initialized)
    {
        initialized = TRUE;
    }
    else
    {
        dissector_delete_uint("sctp.port", current_sctp_port, knet_handle_sctp);
        dissector_delete_uint("tcp.port",  current_tcp_port,  knet_handle_tcp);
        dissector_delete_uint("udp.port",  current_udp_port,  knet_handle_udp);
    }

    current_sctp_port = knet_sctp_port;
    dissector_add_uint("sctp.port", current_sctp_port, knet_handle_sctp);

    current_tcp_port = knet_tcp_port;
    dissector_add_uint("tcp.port", current_tcp_port, knet_handle_tcp);

    current_udp_port = knet_udp_port;
    dissector_add_uint("udp.port", current_udp_port, knet_handle_udp);
}
/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
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
