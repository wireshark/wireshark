/* packet-bittorrent.c
 * Routines for bittorrent packet dissection
 * Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-tcp.h"

/*
 * See
 *
 * http://bittorrent.com/protocol.html
 * http://wiki.theory.org/BitTorrentSpecification
 * http://bitconjurer.org/BitTorrent/protocol.html
 */

#define BITTORRENT_MESSAGE_CHOKE          0
#define BITTORRENT_MESSAGE_UNCHOKE        1
#define BITTORRENT_MESSAGE_INTERESTED     2
#define BITTORRENT_MESSAGE_NOT_INTERESTED 3
#define BITTORRENT_MESSAGE_HAVE           4
#define BITTORRENT_MESSAGE_BITFIELD       5
#define BITTORRENT_MESSAGE_REQUEST        6
#define BITTORRENT_MESSAGE_PIECE          7
#define BITTORRENT_MESSAGE_CANCEL         8
#define BITTORRENT_MESSAGE_PORT           9
#define BITTORRENT_MESSAGE_EXTENDED      20

#define BITTORRENT_HEADER_LENGTH          4

/*
 * Azureus messages are specified by name so these are made up numbers
 * for internal identification only.
 *
 * Standard BT message types are a single byte, so these won't clash
 */
#define AZUREUS_MESSAGE_HANDSHAKE         256
#define AZUREUS_MESSAGE_KEEP_ALIVE        257
#define AZUREUS_MESSAGE_BT_HANDSHAKE      258
#define AZUREUS_MESSAGE_PEER_EXCHANGE     259
#define AZUREUS_MESSAGE_JPC_HELLO         260
#define AZUREUS_MESSAGE_JPC_REPLY         261


static const value_string bittorrent_messages[] = {
   { BITTORRENT_MESSAGE_CHOKE, "Choke" },
   { BITTORRENT_MESSAGE_UNCHOKE, "Unchoke" },
   { BITTORRENT_MESSAGE_INTERESTED, "Interested" },
   { BITTORRENT_MESSAGE_NOT_INTERESTED, "Not Interested" },
   { BITTORRENT_MESSAGE_HAVE, "Have" },
   { BITTORRENT_MESSAGE_BITFIELD, "Bitfield" },
   { BITTORRENT_MESSAGE_REQUEST, "Request" },
   { BITTORRENT_MESSAGE_PIECE, "Piece" },
   { BITTORRENT_MESSAGE_CANCEL, "Cancel" },
   { BITTORRENT_MESSAGE_PORT, "Port" },
   { BITTORRENT_MESSAGE_EXTENDED, "Extended" },
   { AZUREUS_MESSAGE_KEEP_ALIVE, "Keepalive" },
   { AZUREUS_MESSAGE_HANDSHAKE, "Azureus Handshake" },
   { AZUREUS_MESSAGE_BT_HANDSHAKE, "Azureus BitTorrent Handshake" },
   { AZUREUS_MESSAGE_PEER_EXCHANGE, "Azureus Peer Exchange" },
   { AZUREUS_MESSAGE_JPC_HELLO, "Azureus PeerCache Hello" },
   { AZUREUS_MESSAGE_JPC_REPLY, "Azureus PeerCache Reply" },
   { 0, NULL }
};

static const value_string azureus_priorities[] = {
   { 0, "Low" },
   { 1, "Normal" },
   { 2, "High" },
   { 0, NULL }
};


struct amp_message {
   const char *name;
   guint32 value;
};

static const struct amp_message amp_messages[] = {
   { "BT_KEEP_ALIVE", AZUREUS_MESSAGE_KEEP_ALIVE },
   { "BT_CHOKE", BITTORRENT_MESSAGE_CHOKE },
   { "BT_UNCHOKE", BITTORRENT_MESSAGE_UNCHOKE },
   { "BT_INTERESTED", BITTORRENT_MESSAGE_INTERESTED },
   { "BT_UNINTERESTED", BITTORRENT_MESSAGE_NOT_INTERESTED },
   { "BT_HAVE", BITTORRENT_MESSAGE_HAVE },
   { "BT_BITFIELD", BITTORRENT_MESSAGE_BITFIELD },
   { "BT_REQUEST", BITTORRENT_MESSAGE_REQUEST },
   { "BT_PIECE", BITTORRENT_MESSAGE_PIECE },
   { "BT_CANCEL", BITTORRENT_MESSAGE_CANCEL },
   { "BT_PORT", BITTORRENT_MESSAGE_PORT },
   { "BT_EXTENDED", BITTORRENT_MESSAGE_EXTENDED },
   { "AZ_HANDSHAKE", AZUREUS_MESSAGE_HANDSHAKE },
   { "BT_HANDSHAKE", AZUREUS_MESSAGE_BT_HANDSHAKE },
   { "AZ_PEER_EXCHANGE", AZUREUS_MESSAGE_PEER_EXCHANGE },
   { "JPC_HELLO", AZUREUS_MESSAGE_JPC_HELLO },
   { "JPC_REPLY", AZUREUS_MESSAGE_JPC_REPLY },
   { NULL, 0 }
};

static dissector_handle_t dissector_handle;
static int proto_bittorrent = -1;

static gint hf_bittorrent_field_length  = -1;
static gint hf_bittorrent_prot_name_len = -1;
static gint hf_bittorrent_prot_name     = -1;
static gint hf_bittorrent_reserved      = -1;
static gint hf_bittorrent_sha1_hash     = -1;
static gint hf_bittorrent_peer_id       = -1;
static gint hf_bittorrent_msg           = -1;
static gint hf_bittorrent_msg_len       = -1;
static gint hf_bittorrent_msg_type      = -1;
static gint hf_azureus_msg              = -1;
static gint hf_azureus_msg_type_len     = -1;
static gint hf_azureus_msg_type         = -1;
static gint hf_azureus_msg_prio         = -1;
static gint hf_bittorrent_bitfield_data = -1;
static gint hf_bittorrent_piece_index   = -1;
static gint hf_bittorrent_piece_begin   = -1;
static gint hf_bittorrent_piece_length  = -1;
static gint hf_bittorrent_piece_data    = -1;
static gint hf_bittorrent_bstr_length   = -1;
static gint hf_bittorrent_bstr          = -1;
static gint hf_bittorrent_bint          = -1;
static gint hf_bittorrent_bdict         = -1;
static gint hf_bittorrent_bdict_entry   = -1;
static gint hf_bittorrent_blist         = -1;
static gint hf_azureus_jpc_addrlen      = -1;
static gint hf_azureus_jpc_addr         = -1;
static gint hf_azureus_jpc_port         = -1;
static gint hf_azureus_jpc_session      = -1;
static gint hf_bittorrent_port          = -1;
static gint hf_bittorrent_extended      = -1;

static gint ett_bittorrent = -1;
static gint ett_bittorrent_msg = -1;
static gint ett_peer_id = -1;
static gint ett_bittorrent_bdict = -1;
static gint ett_bittorrent_bdict_entry = -1;
static gint ett_bittorrent_blist = -1;

static gboolean bittorrent_desegment = TRUE;
static gboolean decode_client_information = FALSE;

struct client_information {
   char id[5];       /* string length must be <= 4 to allow space for NUL termination byte */
   char ver_len;
   const char *name; /* NULL means array entry terminates the array */
};

static struct client_information peer_id[] = {
   {"-AG",  4, "Ares"},
   {"-A~",  4, "Ares"},
   {"-AR",  4, "Arctic"},
   {"-AT",  4, "Artemis"},
   {"-AV",  4, "Avicora"},
   {"-AX",  4, "BitPump"},
   {"-AZ",  4, "Azureus"},
   {"-BB",  4, "BitBuddy"},
   {"-BC",  4, "BitComet"},
   {"-BF",  4, "Bitflu"},
   {"-BG",  4, "BTG (uses Rasterbar libtorrent)"},
   {"-BOW", 3, "Bits on Wheels"},
   {"-BP",  4, "BitTorrent Pro (Azereus + spyware)"},
   {"-BR",  4, "BitRocket"},
   {"-BS",  4, "BTSlave"},
   {"-BW",  4, "BitWombat"},
   {"-BX",  4, "Bittorrent X"},
   {"-CD",  4, "Enhanced CTorrent"},
   {"-CT",  4, "CTorrent"},
   {"-DE",  4, "DelugeTorrent"},
   {"-DP",  4, "Propagate Data Client"},
   {"-EB",  4, "EBit"},
   {"-ES",  4, "electric sheep"},
   {"-FC",  4, "FileCroc"},
   {"-FG",  4, "FlashGet"},
   {"-FT",  4, "FoxTorrent"},
   {"-GS",  4, "GSTorrent"},
   {"-HK",  4, "Hekate"},
   {"-HL",  4, "Halite"},
   {"-HN",  4, "Hydranode"},
   {"-KG",  4, "KGet"},
   {"-KT",  4, "KTorrent"},
   {"-LC",  4, "LeechCraft"},
   {"-LH",  4, "LH-ABC"},
   {"-LP",  4, "Lphant"},
   {"-LT",  4, "libtorrent"},
   {"-lt",  4, "libTorrent"},
   {"-LW",  4, "LimeWire"},
   {"-MO",  4, "MonoTorrent"},
   {"-MP",  4, "MooPolice"},
   {"-MR",  4, "Miro"},
   {"-MT",  4, "MoonlightTorrent"},
   {"-NE",  4, "BT Next Evolution"},
   {"-NX",  4, "Net Transport"},
   {"-OS",  4, "OneSwarm"},
   {"-OT",  4, "OmegaTorrent"},
   {"-PD",  4, "Pando"},
   {"-qB",  4, "qBittorrent"},
   {"-QD",  4, "QQDownload"},
   {"-QT",  4, "Qt 4 Torrent example"},
   {"-RT",  4, "Retriever"},
   {"-S~",  4, "Shareaza alpha/beta"},
   {"-SB",  4, "Swiftbit"},
   {"-SD",  4, "Thunder (aka XunLei)"},
   {"-SS",  4, "SwarmScope"},
   {"-ST",  4, "SymTorrent"},
   {"-st",  4, "sharktorrent"},
   {"-SZ",  4, "Shareaza"},
   {"-TN",  4, "TorrentDotNET"},
   {"-TR",  4, "Transmission"},
   {"-TS",  4, "Torrentstorm"},
   {"-TT",  4, "TuoTu"},
   {"-UL",  4, "uLeecher!"},
   {"-UM",  4, "(my)Torrent for Mac"},
   {"-UT",  4, "(my)Torrent"},
   {"-VG",  4, "Vagaa"},
   {"-WT",  4, "BitLet"},
   {"-WY",  4, "FireTorrent"},
   {"-XL",  4, "Xunlei"},
   {"-XT",  4, "XanTorrent"},
   {"-XX",  4, "Xtorrent"},
   {"-ZT",  4, "ZipTorrent"},
   {"exbc", 2, "BitComet"},
   {"OP",   4, "Opera"},
   {"QVOD", 4, "Qvod"},
   {"XBT",  3, "XBT Client"},
   {"A",    3, "ABC"},
   {"O",    3, "Osprey Permaseed"},
   {"Q",    3, "BTQueue"},
   {"R",    3, "Tribler"},
   {"S",    3, "Shadow's client"},
   {"T",    3, "BitTornado"},
   {"U",    3, "UPnP NAT Bit Torrent"},
   {"",     0, NULL}
};

static guint get_bittorrent_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   guint8 type;
   guint32 length;

   if (tvb_get_guint8(tvb, offset) == 19 &&
       tvb_memeql(tvb, offset + 1, "BitTorrent protocol", 19) == 0) {
      /* Return the length of a Handshake message */
      return 1 + /* pstrlen */
         19 +    /* pstr */
         8 +     /* reserved */
         20 +    /* SHA1 hash of the info key */
         20;     /* peer id */
   } else {
      /* Try to validate the length of the message indicated by the header. */
      length = tvb_get_ntohl(tvb, offset);
      if(length == 0) {
        /* keep-alive - no message ID */
        return BITTORRENT_HEADER_LENGTH;
      }
      /* Do some sanity checking of the message, if we have the ID byte */
      if(tvb_offset_exists(tvb, offset + BITTORRENT_HEADER_LENGTH)) {
         type = tvb_get_guint8(tvb, offset + BITTORRENT_HEADER_LENGTH);
         if((type <= BITTORRENT_MESSAGE_PORT || type == BITTORRENT_MESSAGE_EXTENDED) && length<0x1000000) {
            /* This seems to be a valid BitTorrent header with a known
               type identifier */
            return BITTORRENT_HEADER_LENGTH + length;
         } else {
            /* The type is not known, so this message cannot be decoded
               properly by this dissector.  We assume it's continuation
               data from the middle of a message, and just return the
               remaining length in the tvbuff so the rest of the tvbuff
               is displayed as continuation data. */
            return tvb_length_remaining(tvb, offset);
         }
      } else {
         /* We don't have the type field, so we can't determine
            whether this is a valid message.  For now, we assume
            it's continuation data from the middle of a message,
            and just return the remaining length in the tvbuff so
            the rest of the tvbuff is displayed as continuation
            data. */
         return tvb_length_remaining(tvb, offset);
      }
   }
}

static int dissect_bencoding_str(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, int length, proto_tree *tree, proto_item *ti, int treeadd)
{
   guint8 ch;
   int stringlen = 0, nextstringlen;
   int used;
   int izero = 0;

   if (length<2) {
      if (tree) {
         proto_tree_add_text(tree, tvb, offset, length, "Decode Aborted: Invalid String");
      }
      return -1;
   }

   used = 0;

   while (length>=1) {
      ch = tvb_get_guint8(tvb, offset+used);
      length--;
      used++;

      if (ch==':' && used>1) {
         if (stringlen>length || stringlen<0) {
            if (tree) {
               proto_tree_add_text(tree, tvb, offset, length, "Decode Aborted: Invalid String Length");
            }
            return -1;
         }
         if (tree) {
            proto_tree_add_uint(tree, hf_bittorrent_bstr_length, tvb, offset, used, stringlen);
            proto_tree_add_item(tree, hf_bittorrent_bstr, tvb, offset+used, stringlen, ENC_ASCII|ENC_NA);

            if (treeadd==1) {
               proto_item_append_text(ti, " Key: %s", format_text(ep_tvb_memdup(tvb, offset+used, stringlen), stringlen));
            }
            if (treeadd==2) {
               proto_item_append_text(ti, "  Value: %s", format_text(ep_tvb_memdup(tvb, offset+used, stringlen), stringlen));
            }
         }
         return used+stringlen;
      }

      if (!izero && ch>='0' && ch<='9') {
         if (ch=='0' && used==1) {
            izero = 1;
         }

         nextstringlen = (stringlen * 10) + (ch - '0');
         if (nextstringlen>=stringlen) {
            stringlen = nextstringlen;
            continue;
         }
      }

      if (tree) {
         proto_tree_add_text(tree, tvb, offset, length, "Decode Aborted: Invalid String");
      }
      return -1;
   }

   if (tree) {
      proto_tree_add_text(tree, tvb, offset, length, "Truncated Data");
   }
   return -1;
}

static int dissect_bencoding_int(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, int length, proto_tree *tree, proto_item *ti, int treeadd)
{
   gint32 ival=0;
   int neg = 0;
   int izero = 0;
   int used;
   guint8 ch;

   if (length<3) {
      if (tree) {
         proto_tree_add_text(tree, tvb, offset, length, "Decode Aborted: Invalid Integer");
      }
      return -1;
   }

   length--;
   used = 1;

   while (length>=1) {
      ch = tvb_get_guint8(tvb, offset+used);
      length--;
      used++;

      switch (ch) {
      case 'e':
         if (tree) {
            if (neg) ival = -ival;
            proto_tree_add_int(tree, hf_bittorrent_bint, tvb, offset, used, ival);
            if (treeadd==2) {
               proto_item_append_text(ti, "  Value: %d", ival);
            }
         }
         return used;

      case '-':
         if (used==2) {
            neg = 1;
            break;
         }
         /* Fall through */

      default:
         if (!(ch=='0' && used==3 && neg)) { /* -0 is invalid */
            if (ch=='0' && used==2) { /* as is 0[0-9]+ */
               izero = 1;
               break;
            }
            if (!izero && ch>='0' && ch<='9') {
               ival = (ival * 10) + (ch - '0');
               break;
            }
         }

         if (tree) {
            proto_tree_add_text(tree, tvb, offset, length, "Decode Aborted: Invalid Integer");
         }
         return -1;
      }
   }

   if (tree) {
      proto_tree_add_text(tree, tvb, offset, length, "Truncated Data");
   }
   return -1;
}

static int dissect_bencoding_rec(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, int length, proto_tree *tree, int level, proto_item *treei, int treeadd)
{
   guint8 op;
   int oplen = 0, op1len, op2len;
   int used;

   proto_item *ti = NULL, *td = NULL;
   proto_tree *itree = NULL, *dtree = NULL;

   if (level>10) {
      proto_tree_add_text(tree, tvb, offset, -1, "Decode Aborted: Nested Too Deep");
      return -1;
   }
   if (length<1) {
      proto_tree_add_text(tree, tvb, offset, -1, "Truncated Data");
      return length;
   }

   op = tvb_get_guint8(tvb, offset);
   if (tree) {
      oplen = dissect_bencoding_rec(tvb, pinfo, offset, length, NULL, level, NULL, 0);
      if (oplen<0) oplen = length;
   }

   switch (op) {
   case 'd':
      if (tree) {
         td = proto_tree_add_item(tree, hf_bittorrent_bdict, tvb, offset, oplen, ENC_NA);
         dtree = proto_item_add_subtree(td, ett_bittorrent_bdict);
      }

      used = 1;
      length--;

      while (length>=1) {
         op = tvb_get_guint8(tvb, offset+used);

         if (op=='e') {
            return used+1;
         }

         op1len = dissect_bencoding_str(tvb, pinfo, offset+used, length, NULL, NULL, 0);
         if (op1len<0) {
            if (dtree) {
               proto_tree_add_text(dtree, tvb, offset+used, -1, "Decode Aborted: Invalid Dictionary Key");
            }
            return op1len;
         }

         op2len = -1;
         if (length-op1len>2)
            op2len = dissect_bencoding_rec(tvb, pinfo, offset+used+op1len, length-op1len, NULL, level+1, NULL, 0);
         if (op2len<0) {
            if (dtree) {
               proto_tree_add_text(dtree, tvb, offset+used+op1len, -1, "Decode Aborted: Invalid Dictionary Value");
            }
            return op2len;
         }

         if (dtree) {
            ti = proto_tree_add_item(dtree, hf_bittorrent_bdict_entry, tvb, offset+used, op1len+op2len, ENC_NA);
            itree = proto_item_add_subtree(ti, ett_bittorrent_bdict_entry);

            dissect_bencoding_str(tvb, pinfo, offset+used, length, itree, ti, 1);
            dissect_bencoding_rec(tvb, pinfo, offset+used+op1len, length-op1len, itree, level+1, ti, 2);
         }

         used += op1len+op2len;
         length -= op1len+op2len;
      }
      if (dtree) {
         proto_tree_add_text(dtree, tvb, offset+used, -1, "Truncated Data");
      }
      return -1;

   case 'l':
      if (tree) {
         ti = proto_tree_add_item(tree, hf_bittorrent_blist, tvb, offset, oplen, ENC_NA);
         itree = proto_item_add_subtree(ti, ett_bittorrent_blist);
      }

      used = 1;
      length--;

      while (length>=1) {
         op = tvb_get_guint8(tvb, offset+used);

         if (op=='e') {
            return used+1;
         }

         oplen = dissect_bencoding_rec(tvb, pinfo, offset+used, length, itree, level+1, ti, 0);
         if (oplen<1) return oplen;

         used += oplen;
         length -= oplen;
      }
      if (itree) {
         proto_tree_add_text(itree, tvb, offset+used, -1, "Truncated Data");
      }
      return -1;

   case 'i':
      return dissect_bencoding_int(tvb, pinfo, offset, length, tree, treei, treeadd);

   default:
      if (op>='1' && op<='9') {
         return dissect_bencoding_str(tvb, pinfo, offset, length, tree, treei, treeadd);
      }

      if (tree) {
         proto_tree_add_text(tree, tvb, offset, -1, "Decode Aborted: Invalid Bencoding");
      }
   }

   return -1;
}

static void dissect_bencoding(tvbuff_t *tvb, packet_info *pinfo _U_,
                              int offset, int length, proto_tree *tree)
{
  dissect_bencoding_rec(tvb, pinfo, offset, length, tree, 0, NULL, 0);
}

static void dissect_bittorrent_message (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   int offset = 0;
   int i;
   int isamp = 0;
   proto_tree *mtree;
   guint16 type = 0;
   guint32 typelen = 0;
   guint8 prio = 0;
   guint32 length;
   const char *msgtype = NULL;
   proto_item *ti;
   guint32 piece_index, piece_begin, piece_length;
   guint32 stringlen;

   if (tvb_bytes_exist(tvb, offset + BITTORRENT_HEADER_LENGTH, 1)) {
      /* Check for data from the middle of a message. */
      length = tvb_get_ntohl(tvb, offset);
      type = tvb_get_guint8(tvb, offset + BITTORRENT_HEADER_LENGTH);

      if (type==BITTORRENT_MESSAGE_CHOKE && length>4) {
         /*
          * Choke messages have no payload, so this is likely an Azureus
          * Messaging Protocol packet
          */
         if (!tvb_bytes_exist(tvb, offset + BITTORRENT_HEADER_LENGTH, 4))
            return;

         typelen = tvb_get_ntohl(tvb, offset + BITTORRENT_HEADER_LENGTH);
         if (4+typelen+1<=length) {
            if (!tvb_bytes_exist(tvb, offset + BITTORRENT_HEADER_LENGTH + 4, typelen+1))
               return;

            for ( i=0 ; amp_messages[i].name ; i++ ) {
               if (strlen(amp_messages[i].name)==typelen &&
                   tvb_memeql(tvb, offset + BITTORRENT_HEADER_LENGTH + 4,
                              amp_messages[i].name, (int)strlen(amp_messages[i].name))==0) {

                  prio = tvb_get_guint8(tvb, offset + BITTORRENT_HEADER_LENGTH + 4 + typelen);
                  if (prio==0 || prio==1 || prio==2) {
                     type = amp_messages[i].value;
                     isamp = 1;
                  }
                  break;
               }
            }
         }
      }

      msgtype = match_strval(type, bittorrent_messages);
#if 0
      if (msgtype == NULL && isamp) {
         msgtype = match_strval(type, azureus_messages);
      }
#endif
      if (msgtype == NULL) {
         proto_tree_add_text(tree, tvb, offset, -1, "Continuation data");
         col_set_str(pinfo->cinfo, COL_INFO, "Continuation data");
         return;
      }
   } else {
      /* not enough bytes of the header, stop here */
      return;
   }

   if (isamp) {
      ti = proto_tree_add_item(tree, hf_azureus_msg, tvb, offset, length + BITTORRENT_HEADER_LENGTH, ENC_NA);
   } else {
      ti = proto_tree_add_item(tree, hf_bittorrent_msg, tvb, offset, length + BITTORRENT_HEADER_LENGTH, ENC_NA);
   }
   mtree = proto_item_add_subtree(ti, ett_bittorrent_msg);

   /* Keepalive message */
   if (length == 0) {
      proto_tree_add_item(mtree, hf_bittorrent_msg_len, tvb, offset, BITTORRENT_HEADER_LENGTH, ENC_BIG_ENDIAN);
      col_set_str(pinfo->cinfo, COL_INFO, "KeepAlive");
      return;
   }

   proto_tree_add_item(mtree, hf_bittorrent_msg_len, tvb, offset, BITTORRENT_HEADER_LENGTH, ENC_BIG_ENDIAN);
   offset += BITTORRENT_HEADER_LENGTH;

   /* If the tvb_bytes_exist() call above returned FALSE, this will
      throw an exception, so we won't use msgtype or type. */
   if (isamp) {
      proto_tree_add_item(mtree, hf_azureus_msg_type_len, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(mtree, hf_azureus_msg_type, tvb, offset+4, typelen, ENC_ASCII|ENC_NA);
      proto_item_append_text(ti, ": Len %u, %s", length, msgtype);
      proto_tree_add_item(mtree, hf_azureus_msg_prio, tvb, offset+4+typelen, 1, ENC_BIG_ENDIAN);
      offset += 4+typelen+1;
      length -= 4+typelen+1;
   } else {
      proto_tree_add_item(mtree, hf_bittorrent_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_item_append_text(ti, ": Len:%u, %s", length, msgtype);
      offset += 1;
      length -= 1;
   }
   col_set_str(pinfo->cinfo, COL_INFO, msgtype);

   switch (type) {
   case BITTORRENT_MESSAGE_CHOKE:
   case BITTORRENT_MESSAGE_UNCHOKE:
   case BITTORRENT_MESSAGE_INTERESTED:
   case BITTORRENT_MESSAGE_NOT_INTERESTED:
      /* No payload */
      break;

   case BITTORRENT_MESSAGE_REQUEST:
   case BITTORRENT_MESSAGE_CANCEL:
      piece_index = tvb_get_ntohl(tvb, offset);
      proto_tree_add_uint(mtree, hf_bittorrent_piece_index, tvb, offset, 4, piece_index); offset += 4;
      piece_begin = tvb_get_ntohl(tvb, offset);
      proto_tree_add_uint(mtree, hf_bittorrent_piece_begin, tvb, offset, 4, piece_begin); offset += 4;
      piece_length = tvb_get_ntohl(tvb, offset);
      proto_tree_add_uint(mtree, hf_bittorrent_piece_length, tvb, offset, 4, piece_length);
      proto_item_append_text(ti, ", Piece (Idx:0x%x,Begin:0x%x,Len:0x%x)", piece_index, piece_begin, piece_length);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", Piece (Idx:0x%x,Begin:0x%x,Len:0x%x)", piece_index, piece_begin, piece_length);

	  break;

   case BITTORRENT_MESSAGE_PORT:
      /* port as payload */
      proto_tree_add_uint(mtree, hf_bittorrent_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;

   case BITTORRENT_MESSAGE_EXTENDED:
      /* extended message content */
      proto_tree_add_item(mtree, hf_bittorrent_extended, tvb, offset, length, ENC_NA);
      break;

   case BITTORRENT_MESSAGE_HAVE:
      piece_index = tvb_get_ntohl(tvb, offset);
      proto_tree_add_item(mtree, hf_bittorrent_piece_index, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(ti, ", Piece (Idx:0x%x)", piece_index);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", Piece (Idx:0x%x)", piece_index);

	  break;

   case BITTORRENT_MESSAGE_BITFIELD:
      proto_tree_add_item(mtree, hf_bittorrent_bitfield_data, tvb, offset, length, ENC_NA);
      proto_item_append_text(ti, ", Len:0x%x", length);
      col_append_fstr(pinfo->cinfo, COL_INFO, ", Len:0x%x", length);

	  break;

   case BITTORRENT_MESSAGE_PIECE:
      piece_index = tvb_get_ntohl(tvb, offset);
      proto_tree_add_uint(mtree, hf_bittorrent_piece_index, tvb, offset, 4, piece_index);
      offset += 4;
      length -= 4;
      piece_begin = tvb_get_ntohl(tvb, offset);
      proto_tree_add_uint(mtree, hf_bittorrent_piece_begin, tvb, offset, 4, piece_begin);
      offset += 4;
      length -= 4;
      proto_tree_add_item(mtree, hf_bittorrent_piece_data, tvb, offset, length, ENC_NA);
      proto_item_append_text(ti, ", Idx:0x%x,Begin:0x%x,Len:0x%x", piece_index, piece_begin, length);
      col_append_fstr(pinfo->cinfo, COL_INFO, ", Idx:0x%x,Begin:0x%x,Len:0x%x", piece_index, piece_begin, length);

	  break;

   case AZUREUS_MESSAGE_HANDSHAKE:
   case AZUREUS_MESSAGE_PEER_EXCHANGE:
      dissect_bencoding(tvb, pinfo, offset, length, mtree);
      break;

   case AZUREUS_MESSAGE_JPC_HELLO:
      stringlen = tvb_get_ntohl(tvb, offset);
      proto_tree_add_item(mtree, hf_azureus_jpc_addrlen, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(mtree, hf_azureus_jpc_addr, tvb, offset+4, stringlen, ENC_ASCII|ENC_NA);
      proto_tree_add_item(mtree, hf_azureus_jpc_port, tvb, offset+4+stringlen, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(mtree, hf_azureus_jpc_session, tvb, offset+4+stringlen+4, 4, ENC_BIG_ENDIAN);
      break;

   case AZUREUS_MESSAGE_JPC_REPLY:
      proto_tree_add_item(mtree, hf_azureus_jpc_session, tvb, offset, 4, ENC_BIG_ENDIAN);
      break;

   default:
      break;
   }
}

static int dissect_bittorrent_welcome (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
   int offset = 0;
   int i;
   char *version;

   col_set_str(pinfo->cinfo, COL_INFO, "Handshake");

   proto_tree_add_item(tree, hf_bittorrent_prot_name_len, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
   proto_tree_add_item(tree, hf_bittorrent_prot_name, tvb, offset, 19, ENC_ASCII|ENC_NA); offset += 19;
   proto_tree_add_item(tree, hf_bittorrent_reserved, tvb, offset, 8, ENC_NA); offset += 8;

   proto_tree_add_item(tree, hf_bittorrent_sha1_hash, tvb, offset, 20, ENC_NA);
   offset += 20;

   proto_tree_add_item(tree, hf_bittorrent_peer_id, tvb, offset, 20, ENC_NA);
   if(decode_client_information) {
      for(i = 0; peer_id[i].name != NULL; ++i)
      {
         if(tvb_memeql(tvb, offset, peer_id[i].id, (int)strlen(peer_id[i].id)) == 0) {
            version = tvb_get_ephemeral_string(tvb, offset + (int)strlen(peer_id[i].id),
                                               peer_id[i].ver_len);
            proto_tree_add_text(tree, tvb, offset, 20, "Client is %s v%s",
                                peer_id[i].name,
                                format_text((guchar*)version, peer_id[i].ver_len));
            break;
         }
      }
   }
   offset += 20;
   return offset;
}

static void dissect_bittorrent_tcp_pdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "BitTorrent");

   col_set_str(pinfo->cinfo, COL_INFO, "BitTorrent ");

   ti = proto_tree_add_item (tree, proto_bittorrent, tvb, 0, -1, ENC_NA);
   tree = proto_item_add_subtree(ti, ett_bittorrent);

   if (tvb_get_guint8(tvb, 0) == 19 &&
       tvb_memeql(tvb, 1, "BitTorrent protocol", 19) == 0) {
      dissect_bittorrent_welcome(tvb, pinfo, tree);
   } else {
      dissect_bittorrent_message(tvb, pinfo, tree);
   }

    col_append_str(pinfo->cinfo, COL_INFO, "  ");
    col_set_fence(pinfo->cinfo, COL_INFO);

}

static void dissect_bittorrent (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   tcp_dissect_pdus(tvb, pinfo, tree, bittorrent_desegment, BITTORRENT_HEADER_LENGTH,
                    get_bittorrent_pdu_length, dissect_bittorrent_tcp_pdu);
}

static gboolean test_bittorrent_packet (tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree)
{
   conversation_t *conversation;

   if (tvb_length(tvb) >= 20 &&
       tvb_get_guint8(tvb, 0) == 19 &&
       tvb_memeql(tvb, 1, "BitTorrent protocol", 19) == 0) {
      conversation = find_or_create_conversation(pinfo);
      conversation_set_dissector(conversation, dissector_handle);

      dissect_bittorrent(tvb, pinfo, tree);

      return TRUE;
   }

   return FALSE;
}

void
proto_register_bittorrent(void)
{
   static hf_register_info hf[] = {
      { &hf_bittorrent_field_length,
        { "Field Length", "bittorrent.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_prot_name_len,
        { "Protocol Name Length", "bittorrent.protocol.name.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_prot_name,
        { "Protocol Name", "bittorrent.protocol.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_reserved,
        { "Reserved Extension Bytes", "bittorrent.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_sha1_hash,
        { "SHA1 Hash of info dictionary", "bittorrent.info_hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_peer_id,
        { "Peer ID", "bittorrent.peer_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_msg,
        { "Message", "bittorrent.msg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_msg_len,
        { "Message Length", "bittorrent.msg.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_msg_type,
        { "Message Type", "bittorrent.msg.type", FT_UINT8, BASE_DEC, VALS(bittorrent_messages), 0x0, NULL, HFILL }
      },
      { &hf_azureus_msg,
        { "Azureus Message", "bittorrent.azureus_msg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_azureus_msg_type_len,
        { "Message Type Length", "bittorrent.msg.typelen", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_azureus_msg_type,
        { "Message Type", "bittorrent.msg.aztype", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_azureus_msg_prio,
        { "Message Priority", "bittorrent.msg.prio", FT_UINT8, BASE_DEC, VALS(azureus_priorities), 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_bitfield_data,
        { "Bitfield data", "bittorrent.msg.bitfield", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_piece_index,
        { "Piece index", "bittorrent.piece.index", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_piece_begin,
        { "Begin offset of piece", "bittorrent.piece.begin", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_piece_data,
        { "Data in a piece", "bittorrent.piece.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_piece_length,
        { "Piece Length", "bittorrent.piece.length", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_bstr_length,
        { "String Length", "bittorrent.bstr.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_bstr,
        { "String", "bittorrent.bstr", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_bint,
        { "Integer", "bittorrent.bint", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_bdict,
        { "Dictionary", "bittorrent.bdict", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_bdict_entry,
        { "Entry", "bittorrent.bdict.entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_blist,
        { "List", "bittorrent.blist", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_azureus_jpc_addrlen,
        { "Cache Address Length", "bittorrent.jpc.addr.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_azureus_jpc_addr,
        { "Cache Address", "bittorrent.jpc.addr", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_azureus_jpc_port,
        { "Port", "bittorrent.jpc.port", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_azureus_jpc_session,
        { "Session ID", "bittorrent.jpc.session", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_port,
        { "Port", "bittorrent.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_extended,
        { "Extended Message", "bittorrent.extended", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      }
   };

   static gint *ett[] = {
      &ett_bittorrent,
      &ett_bittorrent_msg,
      &ett_peer_id,
      &ett_bittorrent_bdict,
      &ett_bittorrent_bdict_entry,
      &ett_bittorrent_blist
   };

   module_t *bittorrent_module;

   proto_bittorrent = proto_register_protocol("BitTorrent", "BitTorrent", "bittorrent");
   proto_register_field_array(proto_bittorrent, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   register_dissector("bittorrent.tcp", dissect_bittorrent, proto_bittorrent);

   bittorrent_module = prefs_register_protocol(proto_bittorrent, NULL);
   prefs_register_bool_preference(bittorrent_module, "desegment",
                                  "Reassemble BitTorrent messages spanning multiple TCP segments",
                                  "Whether the BitTorrent dissector should reassemble messages spanning multiple TCP segments."
                                  " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                  &bittorrent_desegment);
   prefs_register_bool_preference(bittorrent_module, "decode_client",
                                  "Decode the peer_id of the handshake messages",
                                  "Enabling this will tell which BitTorrent client that produced the handshake message",
                                  &decode_client_information);
}


void
proto_reg_handoff_bittorrent(void)
{
   dissector_handle = find_dissector("bittorrent.tcp");
#if 0
   dissector_add_uint("tcp.port", 6881, dissector_handle);
   dissector_add_uint("tcp.port", 6882, dissector_handle);
   dissector_add_uint("tcp.port", 6883, dissector_handle);
   dissector_add_uint("tcp.port", 6884, dissector_handle);
   dissector_add_uint("tcp.port", 6885, dissector_handle);
   dissector_add_uint("tcp.port", 6886, dissector_handle);
   dissector_add_uint("tcp.port", 6887, dissector_handle);
   dissector_add_uint("tcp.port", 6888, dissector_handle);
   dissector_add_uint("tcp.port", 6889, dissector_handle);
#endif
   heur_dissector_add("tcp", test_bittorrent_packet, proto_bittorrent);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 3
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=3 expandtab:
 * :indentSize=3:tabSize=3:noTabs=true:
 */
