/* packet-knet.c
 * Routines for the KristalliNet (kNet) protocol. 
 * Kari Vatjus-Anttila <kari.vatjus-anttila@cie.fi>
 * Ville Saarinen <ville.saarinen@cie.fi>
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

#include <stdio.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>
#include <string.h>

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
#define PINGREQUEST          1        /*!< Message ID definition: Ping Request */
#define PINGREPLY            2        /*!< Message ID definition: Ping Reply */
#define FLOWCONTROLREQUEST   3        /*!< Message ID definition: Flow Control Request */
#define PACKETACK            4        /*!< Message ID definition: Packet Acknowledge */
#define DISCONNECT           255      /*!< Message ID definition: Disconnect */
#define DISCONNECTACK        254      /*!< Message ID definition: Disconnect Ack */
#define CONNECTSYN           253      /*!< Message ID definition: Connect Syn */
#define CONNECTSYNACK        252      /*!< Message ID definition: Connect Syn Acknowledge */
#define CONNECTACK           251      /*!< Message ID definition: Connect Acknowledge */
/**@}*/


void proto_reg_handoff_knet(void); /* Forward declaration for use in preferences registration */

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
static int hf_knet_content_length = -1; /*!< Content Length */

/* Fields used by the UDP dissector */
static int hf_knet_datagram_tree =              -1; /*!< Datagram subtree */
static int hf_knet_flags =                      -1; /*!< UDP Flags subtree */
static int hf_knet_inorder =                    -1; /*!< Inorder Flag */
static int hf_knet_reliable =                   -1; /*!< Reliable Flag */
static int hf_knet_packetid =                   -1; /*!< PacketID */
static int hf_knet_rmib =                       -1; /*!< Reliable Message Index Base */
static int hf_knet_msg_flags =                   -1; /*!< Message Block Flags subtree */
static int hf_knet_msg_fs =                      -1; /*!< Fragment Start */
static int hf_knet_msg_ff =                      -1; /*!< Fragment Flag */
static int hf_knet_msg_inorder =                 -1; /*!< Inorder Flag */
static int hf_knet_msg_reliable =                -1; /*!< Reliable Flag */
static int hf_knet_msg_reliable_message_number = -1; /*!< Reliable Message Number */

static int hf_knet_payload_tree =    -1; /*!< Payload subtree */
static int hf_knet_payload =    -1; /*!< Payload subtree */
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
static gint ett_knet_main =      -1; /*!< Main kNet tree */
static gint ett_knet_message =   -1; /*!< Message tree */
static gint ett_knet_payload =   -1; /*!< Payload tree */
static gint ett_knet_message_flags =   -1; /*!< Message flags tree */
static gint ett_knet_datagram =      -1;
static gint ett_knet_flags =      -1;
/**@}*/

/* Few Utility Variables */
static int messageindex =         0; /*!< Index of the kNet message inside a datagram */
static int current_protocol =     0; /*!< Protocol currently dissected */

/* Ports used by the dissectors */
static guint32 knet_sctp_port =   PORT; /*!< Port used by kNet SCTP */
static guint32 knet_tcp_port =    PORT; /*!< Port used by kNet TCP */
static guint32 knet_udp_port =    PORT; /*!< Port used by kNet UDP */

static GString* info_field = NULL;   /*!< Contains the info string of the packet */

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
    int byte_count;

    byte_count = 1;

    if((tvb_get_bits8(tvb, (offset) * 8, 8) & 128) > 0)     /* If the first bit of the first byte is 1 */
        byte_count = 2;                                     /* There's at least 2 bytes of content length */
    if((tvb_get_bits8(tvb, (offset) * 8 + 8, 8) & 128) > 0) /* If the next one is also 1 */
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
static int
dissect_packetid(tvbuff_t *buffer, int offset, proto_tree *tree)
{
    guint32 packetid;

    packetid = tvb_get_bits8(buffer, offset * 8 + 16, 8) << 14;
    packetid += tvb_get_bits8(buffer, offset * 8 + 8, 8) << 6;
    packetid += tvb_get_bits8(buffer, offset * 8, 8) & 63;
    if(offset == 0 && tree != NULL)
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
    int byte_count;

    byte_count = 2;

    if((tvb_get_bits8(buffer, offset * 8 + 8, 8) & 128) > 0)
        byte_count = 4;

    if(tree != NULL)
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
    int byte_count;
    guint32 length;

    length = 0;
    byte_count = count_vle_bytes(buffer, *offset);

    switch(byte_count) /*We must calculate length by hand because we use the length later */
    {
        case 4:
            length = tvb_get_bits8(buffer,  ((*offset) + 3) * 8, 8) <<23;
            length += tvb_get_bits8(buffer,  ((*offset) + 2) * 8, 8) <<15;
        case 2:
            length +=(tvb_get_bits8(buffer,  ((*offset) + 1) * 8, 8) & 127) <<7;
        case 1:
            length +=(tvb_get_bits8(buffer,  (*offset) * 8, 8) & 127);
        break;
        default:
            g_print("Error in Content Length calculation\n");
        break;
    }

    if(tree != NULL)
    {
        proto_tree_add_uint(tree, hf_knet_content_length, buffer, (*offset), byte_count, length);
        (*offset) += byte_count;
    }

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
    guint32 length;

    msgflags_tree = NULL;

    length = tvb_get_bits8(buffer, offset * 8 + 12, 4) << 8;
    length += tvb_get_bits8(buffer, offset * 8, 8);

    if(tree != NULL)
    {
        msgflags_ti = proto_tree_add_item(tree, hf_knet_msg_flags, buffer, offset + 1, 1, ENC_NA);
        msgflags_tree = proto_item_add_subtree(msgflags_ti, ett_knet_message_flags);
    }

    proto_tree_add_bits_item(msgflags_tree, hf_knet_msg_fs, buffer, offset * 8 + 8, 1, ENC_LITTLE_ENDIAN); /* Fragment start flag */
    proto_tree_add_bits_item(msgflags_tree, hf_knet_msg_ff, buffer, offset * 8 + 9, 1, ENC_LITTLE_ENDIAN);  /* Fragment flag */
    proto_tree_add_bits_item(msgflags_tree, hf_knet_msg_inorder, buffer, offset * 8 + 10, 1, ENC_LITTLE_ENDIAN); /* Inorder flag */
    proto_tree_add_bits_item(msgflags_tree, hf_knet_msg_reliable, buffer, offset * 8 + 11, 1, ENC_LITTLE_ENDIAN); /* Reliable flag */

    proto_tree_add_uint(tree, hf_knet_content_length, buffer, offset, 2, length);

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
    int byte_count;

    byte_count = 1;

    if((tvb_get_bits8(buffer, offset * 8, 8) & 128) > 0)
        byte_count = 2;

    if(tree != NULL)
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
dissect_messageid(tvbuff_t *buffer, int *offset, proto_tree *tree, packet_info *pinfo)
{
    gint messageid_length;
    guint8 messageid;

    messageid = tvb_get_bits8(buffer, (*offset) * 8, 8);

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

    proto_tree_add_item(tree, hf_knet_messageid, buffer, *offset, messageid_length, NULL,
    "Message ID: %s (%d)", val_to_str(messageid, packettypenames, "AppData or Malformed Message ID"), messageid);

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(messageid, packettypenames, "AppData "));

    *offset += messageid_length;

    g_string_append_printf(info_field, "Msg ID (%d) ", messageid);

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

    payload_ti = proto_tree_add_item(tree, hf_knet_payload_tree, buffer, offset, content_length - 1, ENC_NA);
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
            proto_tree_add_text(payload_tree, buffer, offset, 0, "No Payload");
        break;
        case CONNECTSYN:    /*TODO: Not yet implemented, implement when available*/
        case CONNECTSYNACK: /*TODO: Not yet implemented, implement when available*/
        case CONNECTACK:    /*TODO: Not yet implemented, implement when available*/
            proto_tree_add_item(payload_tree, hf_knet_payload, buffer, offset, 0, ENC_NA);
        break;
        default: /* Application Specific Message */
            proto_tree_add_item(payload_tree, hf_knet_payload, buffer, offset, 0, ENC_NA);
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
 * @return void
 *
 */
static void
dissect_knet_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    int offset;
    int content_length;
    int total_length;
    int messageid;

    proto_item *msgblock_ti;
    proto_tree *msgblock_tree;

    offset = 0;

    total_length = dissect_content_length(tvb, offset, NULL) + 2;

    if(tvb_get_bits8(tvb, 11, 1) > 0) /* If reliable flag is 1 */
        total_length += dissect_reliable_message_number(tvb, offset + 2, NULL); /* We add the RMN into the length of the message */

    msgblock_ti = proto_tree_add_item(tree, hf_knet_message_tree, tvb, offset, total_length, ENC_NA);
    msgblock_tree = proto_item_add_subtree(msgblock_ti, ett_knet_message);

    content_length = dissect_content_length(tvb, offset, msgblock_tree); /* Calculates the Content Length of this packet. */

    g_string_append_printf(info_field, "%d: ", messageindex + 1);

    offset += 2; /* Move the offset the amount of contentlength and flags fields */

    if(tvb_get_bits8(tvb, 11, 1) > 0) /* If the reliable flag is 1 then calculate RMN */
        offset += dissect_reliable_message_number(tvb, offset, msgblock_tree);

    messageid = dissect_messageid(tvb, &offset, msgblock_tree, pinfo);

    dissect_payload(tvb, offset, messageid, msgblock_tree, content_length);

    messageindex++;
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
 * @return void
 *
 */
static void
dissect_knet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Common subtrees */
    proto_item *knet_ti;
    proto_tree *knet_tree;

    /* Subtrees used in kNet UDP dissector */
    proto_item *datagram_ti;
    proto_tree *datagram_tree; /* Tree containing all header related info */
    proto_item *udpflags_ti;
    proto_tree *udpflags_tree; /* Tree containing UDP Datagram Flags */

    /* Subtrees used by SCTP and TCP dissectors */
    proto_item *message_ti;
    proto_tree *message_tree;

    tvbuff_t *next_tvb;
    gboolean bytes_left;

    int offset;
    int length;
    int content_length;
    int messageid;
    int packetid; /* Variable used by the UDP dissector. Contains info about PacketID */

    offset = 0;
    messageindex = 0;
    bytes_left = TRUE;

    info_field = g_string_new(""); /* String that is going to be displayed in the info column in Wireshark */

    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_PROTOCOL, "KNET");

    if(current_protocol == KNET_SCTP_PACKET || current_protocol == KNET_TCP_PACKET)
    {
        /* Attach kNet main tree to Wireshark tree */
        knet_ti = proto_tree_add_item(tree, proto_knet, tvb, 0, -1, ENC_NA); 
        knet_tree = proto_item_add_subtree(knet_ti, ett_knet_main);

        next_tvb = tvb_new_subset(tvb, offset, -1, -1); /* Prepare the next tvb for the next message */

        if((tvb_length_remaining(next_tvb, offset)) > 0) /* If there's at least 2 bytes available in the buffer */
        {
            length = dissect_content_length_vle(next_tvb, &offset, NULL); /* Calculate the length so we can use it below */

            /* Attach message tree to kNet tree */
            message_ti = proto_tree_add_item(knet_tree, hf_knet_message_tree, next_tvb, offset, (current_protocol == KNET_SCTP_PACKET ? length + 1 : length + 2), ENC_NA);

            message_tree = proto_item_add_subtree(message_ti, ett_knet_message);

            content_length = dissect_content_length_vle(next_tvb, &offset, message_tree); /* Calculate length and add it to the tree-view */

            if(tree == NULL)
                offset += count_vle_bytes(next_tvb, offset);

            g_string_append_printf(info_field, "%d: ", messageindex + 1);

            messageid = dissect_messageid(next_tvb, &offset, message_tree, pinfo); /* Calculate messageid and add it to the tree-view */

            dissect_payload(next_tvb, offset, messageid, message_tree, content_length); /* Calculate payload and add it to the tree-view */

            offset += content_length - 1; /* Move the offset the amount of the payload */
        }
    }
    else /* This is an UDP packet */
    {
        /*kNet UDP Tree*/
        knet_ti = proto_tree_add_item(tree, proto_knet, tvb, 0, -1, ENC_NA); /* Attach kNet tree to wireshark main tree */
        knet_tree = proto_item_add_subtree(knet_ti, ett_knet_main);

        /*Datagram Header Tree*/
        datagram_ti = proto_tree_add_item(knet_ti, hf_knet_datagram_tree, tvb, 0, 3, ENC_NA); /* Attach Header tree to wireshark main tree */
        datagram_tree = proto_item_add_subtree(datagram_ti, ett_knet_datagram);

        /*UDPFlags Tree*/
        udpflags_ti = proto_tree_add_item(datagram_ti, hf_knet_flags, tvb, 0, 1, ENC_NA);         /* Attach UDP Flags tree to kNet tree */
        udpflags_tree = proto_item_add_subtree(udpflags_ti, ett_knet_flags);

        proto_tree_add_bits_item(udpflags_tree, hf_knet_inorder, tvb, 0, 1, ENC_LITTLE_ENDIAN); /* Add inorder flag to UDP Flags tree */
        proto_tree_add_bits_item(udpflags_tree, hf_knet_reliable, tvb, 1, 1, ENC_LITTLE_ENDIAN); /* Add reliable flag to UDP Flags tree */

        packetid = dissect_packetid(tvb, 0, datagram_tree); /* Lets calculate our packetid! */

        g_string_append_printf(info_field, "Packet ID: %d ", packetid);

        offset += 3;

        if(tvb_get_bits8(tvb, 1, 1) == 1) /* If Reliable flag is 1 */
            offset += dissect_reliable_message_index_base(tvb, 3, datagram_tree); /* Calculate RMIB */

        next_tvb = tvb_new_subset(tvb, offset, -1, -1);

        while(bytes_left)
        {
            offset = 0;

            if((tvb_length_remaining(next_tvb, offset)) > 2) /* If theres at least 2 bytes available in the buffer */
            {
                length = dissect_content_length(next_tvb, offset, NULL); /* Lets calculate how much data the whole message contains including the Payload and the Message ID */

                if(length == 0) /* Empty data Abort */
                {
                    break;
                }

                else length += 2; /* 2 is the length of contentlength field + flags */

                if(tvb_get_bits8(next_tvb, 11, 1) == 1) /* If reliable flag is 1 */
                    length += dissect_reliable_message_number(next_tvb, offset + 2, NULL); /* We add the RMN into the length of the message */

                dissect_knet_message(next_tvb, pinfo, knet_tree); /* Call the message subdissector */

                offset += length; /* Move the offset the amount of the payload */

                next_tvb = tvb_new_subset(next_tvb, offset, -1, -1); /* Prepare the next tvb for the next message */
            }

            else bytes_left = FALSE;  /* We dont have any bytes left to process... Hopefully */
        }
    }

    if(current_protocol == KNET_TCP_PACKET && ((struct tcpinfo*)(pinfo->private_data))->is_reassembled)
        col_add_str(pinfo->cinfo, COL_INFO, "REASSEMBLED PACKET");
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "Messages: %d %s", messageindex + 1,  info_field->str);

    g_string_free(info_field, TRUE);
    messageindex++;
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
get_knet_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    return dissect_content_length_vle(tvb, &offset, NULL) + count_vle_bytes(tvb, offset);
}

/**
 * dissect_knet_tcp is the dissector which is called
 * by Wireshark when kNet TCP packets are captured.
 * 
 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted
 * @return void
 *
 */
static void
dissect_knet_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    current_protocol = KNET_TCP_PACKET;

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 2, get_knet_pdu_len, dissect_knet);
}

/**
 * dissect_knet_sctp is the dissector which is called
 * by Wireshark when kNet STCP packets are captured.
 * 

 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted

 * @return void
 *
 */
static void
dissect_knet_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    current_protocol = KNET_SCTP_PACKET;

    dissect_knet(tvb, pinfo, tree);
}

/**
 * dissect_knet_udp is the dissector which is called
 * by Wireshark when kNet UDP packets are captured.
 * 

 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted

 * @return void
 *
 */
static void
dissect_knet_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    current_protocol = KNET_UDP_PACKET;

    dissect_knet(tvb, pinfo, tree);
}
/**
 * proto_register_knet registers our kNet protocol,
 * headerfield- and subtree-array to Wireshark.
 * 
 * @return void
 *
 */
void
proto_register_knet(void)
{
    module_t *knet_module;

    static hf_register_info hf_knet[] =
    {
        /* TCP & SCTP Header */ 
        {&hf_knet_content_length, {"Content Length",      "knet.length",              FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_message_tree,   {"Message Block",       "knet.msg",        FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        /* UDP Header */
        {&hf_knet_datagram_tree,              {"Datagram Header",             "knet.datagram",            FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_flags,                      {"Flags",                       "knet.datagram.flags",      FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_inorder,                    {"Inorder Flag",                "knet.datagram.inorder",    FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_reliable,                   {"Reliable Flag",               "knet.datagram.reliable",   FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_packetid,                   {"Packet ID",                   "knet.datagram.packetid",   FT_UINT24, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_rmib,                       {"Reliable Message Index Base", "knet.datagram.rmib",       FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_msg_flags,                  {"Flags",                       "knet.msg.flags",           FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_msg_fs,                     {"Fragment Start",              "knet.msg.flags.fs",        FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_msg_ff,                     {"Fragment Flag",               "knet.msg.flags.ff",        FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_msg_inorder,                {"Inorder Flag",                "knet.msg.flags.inorder",   FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_msg_reliable,               {"Reliable Flag",               "knet.msg.flags.reliable",  FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_msg_reliable_message_number, {"Reliable Message Number",     "knet.msg.reliable_number", FT_UINT24, BASE_DEC,  NULL, 0x0, NULL, HFILL}},

        /* Payload */
        {&hf_knet_payload_tree,   {"Payload",             "knet.payload.tree",        FT_NONE,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_payload,        {"Payload",             "knet.payload.data",        FT_BYTES,   BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_messageid,      {"Message ID",          "knet.payload.messageid",   FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_knet_pingid,         {"Ping ID",             "knet.payload.pingid",      FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}}, 
        {&hf_knet_flowctrlreq,    {"Flowcontrol Request", "knet.payload.flowctrlreq", FT_UINT24, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_packetack,      {"Packet Ack",          "knet.payload.packetack",   FT_UINT24, BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        {&hf_knet_seqnumber,      {"Sequence Number",     "knet.payload.seqnumber",   FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL}}
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

    register_dissector("knetsctp", dissect_knet_sctp, proto_knet);
    register_dissector("knettcp",  dissect_knet_tcp, proto_knet);
    register_dissector("knetudp",  dissect_knet_udp, proto_knet);

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
 * proto_reg_handoff_knet registers our kNet dissectors to Wireshark.
 *
 * @return void
 *
 */
void
proto_reg_handoff_knet(void)
{
    static gboolean initialized = FALSE;

    static dissector_handle_t knet_handle_sctp = 0;
    static dissector_handle_t knet_handle_tcp = 0;
    static dissector_handle_t knet_handle_udp = 0;

    static guint current_sctp_port;
    static guint current_tcp_port;
    static guint current_udp_port;

    if(!initialized)
    {
        knet_handle_sctp = create_dissector_handle(dissect_knet_sctp, proto_knet);
        knet_handle_tcp  = create_dissector_handle(dissect_knet_tcp, proto_knet);
        knet_handle_udp  = create_dissector_handle(dissect_knet_udp, proto_knet);

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
