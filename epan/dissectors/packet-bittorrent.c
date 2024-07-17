/* packet-bittorrent.c
 * Routines for bittorrent packet dissection
 * Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

#include "packet-tcp.h"
#include "packet-bt-utp.h"

void proto_register_bittorrent(void);
void proto_reg_handoff_bittorrent(void);

/*
 * See
 *
 * http://bittorrent.com/protocol.html
 * http://wiki.theory.org/BitTorrentSpecification
 * http://bitconjurer.org/BitTorrent/protocol.html
 */

#define DEFAULT_TCP_PORT_RANGE  "6881-6889" /* Not IANA registered */

#define BITTORRENT_MESSAGE_CHOKE            0
#define BITTORRENT_MESSAGE_UNCHOKE          1
#define BITTORRENT_MESSAGE_INTERESTED       2
#define BITTORRENT_MESSAGE_NOT_INTERESTED   3
#define BITTORRENT_MESSAGE_HAVE             4
#define BITTORRENT_MESSAGE_BITFIELD         5
#define BITTORRENT_MESSAGE_REQUEST          6
#define BITTORRENT_MESSAGE_PIECE            7
#define BITTORRENT_MESSAGE_CANCEL           8
#define BITTORRENT_MESSAGE_PORT             9
/*
 * BitTorrent BEP 06
 * Fast Extension message type
 *
 */
#define BITT_FAST_EX_SUGGEST_PIECE         13
#define BITT_FAST_EX_HAVE_ALL              14
#define BITT_FAST_EX_HAVE_NONE             15
#define BITT_FAST_EX_REJECT_REQUEST        16
#define BITT_FAST_EX_ALLOWED_FAST          17
#define BITTORRENT_MESSAGE_EXTENDED        20

#define BITTORRENT_HEADER_LENGTH            4

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
   { BITTORRENT_MESSAGE_CHOKE,          "Choke" },
   { BITTORRENT_MESSAGE_UNCHOKE,        "Unchoke" },
   { BITTORRENT_MESSAGE_INTERESTED,     "Interested" },
   { BITTORRENT_MESSAGE_NOT_INTERESTED, "Not Interested" },
   { BITTORRENT_MESSAGE_HAVE,           "Have" },
   { BITTORRENT_MESSAGE_BITFIELD,       "Bitfield" },
   { BITTORRENT_MESSAGE_REQUEST,        "Request" },
   { BITTORRENT_MESSAGE_PIECE,          "Piece" },
   { BITTORRENT_MESSAGE_CANCEL,         "Cancel" },
   { BITTORRENT_MESSAGE_PORT,           "Port" },
   { BITT_FAST_EX_SUGGEST_PIECE,        "Suggest Piece" },
   { BITT_FAST_EX_HAVE_ALL,             "Have All" },
   { BITT_FAST_EX_HAVE_NONE,            "Have None" },
   { BITT_FAST_EX_REJECT_REQUEST,       "Reject Request" },
   { BITT_FAST_EX_ALLOWED_FAST,         "Allowed Fast" },
   { BITTORRENT_MESSAGE_EXTENDED,       "Extended" },
   { AZUREUS_MESSAGE_KEEP_ALIVE,        "Keepalive" },
   { AZUREUS_MESSAGE_HANDSHAKE,         "Azureus Handshake" },
   { AZUREUS_MESSAGE_BT_HANDSHAKE,      "Azureus BitTorrent Handshake" },
   { AZUREUS_MESSAGE_PEER_EXCHANGE,     "Azureus Peer Exchange" },
   { AZUREUS_MESSAGE_JPC_HELLO,         "Azureus PeerCache Hello" },
   { AZUREUS_MESSAGE_JPC_REPLY,         "Azureus PeerCache Reply" },
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
   uint32_t    value;
};

static const struct amp_message amp_messages[] = {
   { "BT_KEEP_ALIVE",    AZUREUS_MESSAGE_KEEP_ALIVE },
   { "BT_CHOKE",         BITTORRENT_MESSAGE_CHOKE },
   { "BT_UNCHOKE",       BITTORRENT_MESSAGE_UNCHOKE },
   { "BT_INTERESTED",    BITTORRENT_MESSAGE_INTERESTED },
   { "BT_UNINTERESTED",  BITTORRENT_MESSAGE_NOT_INTERESTED },
   { "BT_HAVE",          BITTORRENT_MESSAGE_HAVE },
   { "BT_BITFIELD",      BITTORRENT_MESSAGE_BITFIELD },
   { "BT_REQUEST",       BITTORRENT_MESSAGE_REQUEST },
   { "BT_PIECE",         BITTORRENT_MESSAGE_PIECE },
   { "BT_CANCEL",        BITTORRENT_MESSAGE_CANCEL },
   { "BT_PORT",          BITTORRENT_MESSAGE_PORT },
   { "BT_SUGGEST",       BITT_FAST_EX_SUGGEST_PIECE },
   { "BT_HAVE_ALL",      BITT_FAST_EX_HAVE_ALL },
   { "BT_HAVE_NONE",     BITT_FAST_EX_HAVE_NONE },
   { "BT_REJECT_REQUEST",BITT_FAST_EX_REJECT_REQUEST },
   { "BT_ALLOWED_FAST",  BITT_FAST_EX_ALLOWED_FAST },
   { "BT_EXTENDED",      BITTORRENT_MESSAGE_EXTENDED },
   { "AZ_HANDSHAKE",     AZUREUS_MESSAGE_HANDSHAKE },
   { "BT_HANDSHAKE",     AZUREUS_MESSAGE_BT_HANDSHAKE },
   { "AZ_PEER_EXCHANGE", AZUREUS_MESSAGE_PEER_EXCHANGE },
   { "JPC_HELLO",        AZUREUS_MESSAGE_JPC_HELLO },
   { "JPC_REPLY",        AZUREUS_MESSAGE_JPC_REPLY },
   { NULL, 0 }
};

static dissector_handle_t dissector_handle;
static dissector_handle_t bencode_handle;
static int proto_bittorrent;

/* static int hf_bittorrent_field_length; */
static int hf_bittorrent_prot_name_len;
static int hf_bittorrent_prot_name;
static int hf_bittorrent_reserved;
static int hf_bittorrent_sha1_hash;
static int hf_bittorrent_peer_id;
static int hf_bittorrent_msg;
static int hf_bittorrent_msg_len;
static int hf_bittorrent_msg_type;
static int hf_azureus_msg;
static int hf_azureus_msg_type_len;
static int hf_azureus_msg_type;
static int hf_azureus_msg_prio;
static int hf_bittorrent_bitfield_data;
static int hf_bittorrent_piece_index;
static int hf_bittorrent_piece_begin;
static int hf_bittorrent_piece_length;
static int hf_bittorrent_piece_data;
static int hf_azureus_jpc_addrlen;
static int hf_azureus_jpc_addr;
static int hf_azureus_jpc_port;
static int hf_azureus_jpc_session;
static int hf_bittorrent_port;
static int hf_bittorrent_extended_id;
static int hf_bittorrent_extended;
static int hf_bittorrent_continuous_data;
static int hf_bittorrent_version;

static int ett_bittorrent;
static int ett_bittorrent_msg;
static int ett_peer_id;

static bool bittorrent_desegment      = true;
static bool decode_client_information;

struct client_information {
   char        id[5];     /* string length must be <= 4 to allow space for NUL termination byte */
   char        ver_len;
   const char *name;      /* NULL means array entry terminates the array */
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

/* Tests a given length for a message type to see if it looks valid.
 * The exact length is known for many message types, which prevents us
 * from returning a false positive match based on a single byte when
 * we're in the middle of Continuation Data or an encrypted transfer.
 */
static bool
test_type_length(uint16_t type, uint32_t length)
{
   switch (type) {

   case BITTORRENT_MESSAGE_UNCHOKE:
   case BITTORRENT_MESSAGE_INTERESTED:
   case BITTORRENT_MESSAGE_NOT_INTERESTED:
   case BITT_FAST_EX_HAVE_ALL:
   case BITT_FAST_EX_HAVE_NONE:
      /* No payload */
      if (length != 1) {
         return false;
      }
      return true;

   case BITTORRENT_MESSAGE_PORT:
      if (length != 3) {
         return false;
      }
      return true;

   case BITTORRENT_MESSAGE_HAVE:
   case BITT_FAST_EX_SUGGEST_PIECE:
   case BITT_FAST_EX_ALLOWED_FAST:
      if (length != 5) {
         return false;
      }
      return true;

   case BITTORRENT_MESSAGE_REQUEST:
   case BITTORRENT_MESSAGE_CANCEL:
   case BITT_FAST_EX_REJECT_REQUEST:
      if (length != 13) {
         return false;
      }
      return true;

   /* Now to the messages that can have variable and longer lengths. */

   case BITTORRENT_MESSAGE_EXTENDED:
   case BITTORRENT_MESSAGE_PIECE:
      /* All known implementations use 0x4000 for the piece length by default
       * (only smaller for the last piece at EOF), and disconnect from clients
       * that use a larger value, which is mentioned in BEP-3. Including the
       * other parts of the message, that yields a length of 0x4009. There
       * might exist some non-standard traffic somewhere, I suppose.
       *
       * This is excessively long for any extension message.
       */
      if (length > 0x4009) {
         return false;
      }
      return true;

   case BITTORRENT_MESSAGE_CHOKE:
      /* Choke could be an Azureus message instead, which could be any
       * of the other messages, so it has to be as long as our longest
       * message. XXX: To reduce false positives (since 0 is a common
       * byte to see), a pref to disable Azureus support could be useful.
       * Alternatively, if we tracked conversations, we could disable
       * support for AMP if the extension bits in the handshake (if seen)
       * indicated that it's not supported.
       */
   case AZUREUS_MESSAGE_HANDSHAKE:
   case AZUREUS_MESSAGE_KEEP_ALIVE:
   case AZUREUS_MESSAGE_BT_HANDSHAKE:
   case AZUREUS_MESSAGE_PEER_EXCHANGE:
   case AZUREUS_MESSAGE_JPC_HELLO:
   case AZUREUS_MESSAGE_JPC_REPLY:
   case BITTORRENT_MESSAGE_BITFIELD:
      /* A bitfield length is N bits, where N is the number of pieces
       * in the torrent. The absolute boundary is 2^32 pieces (because
       * it has to fit in the piece message). In practice the piece
       * length varies to balance a number of factors. (Some clients
       * don't work with too many pieces; at one point 2^16 was a common
       * maximum.) The minimum common piece length is 2^18 bytes, and higher
       * powers of two are also frequently used.
       *
       * 0x20000 allows 0x100000 pieces, or over a million. That's more
       * than most clients support, and cuts down on false positives.
       */
      if (length > 0x20000) {
         return false;
      }
      return true;

   default:
      if (!try_val_to_str(type, bittorrent_messages)) {
         return false;
      }
   }

   return true;
}

static unsigned
get_bittorrent_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
                          int offset, void *data _U_)
{
   uint8_t type;
   uint32_t length;

   if (tvb_get_uint8(tvb, offset) == 19 &&
       tvb_memeql(tvb, offset + 1, (const uint8_t*)"BitTorrent protocol", 19) == 0) {
      /* Return the length of a Handshake message */
      return  1 + /* pstrlen */
             19 + /* pstr */
              8 + /* reserved */
             20 + /* SHA1 hash of the info key */
             20;  /* peer id */
   } else {
      /* Try to validate the length of the message indicated by the header. */
      length = tvb_get_ntohl(tvb, offset);
      if(length == 0) {
        /* keep-alive - no message ID */
        return BITTORRENT_HEADER_LENGTH;
      }
      /* Do some sanity checking of the message, if we have the ID byte */
      if(tvb_offset_exists(tvb, offset + BITTORRENT_HEADER_LENGTH)) {
         type = tvb_get_uint8(tvb, offset + BITTORRENT_HEADER_LENGTH);
         if (test_type_length(type, length)) {
            /* This seems to be a valid BitTorrent header with a known
               type identifier and valid length */
            return BITTORRENT_HEADER_LENGTH + length;
         } else {
            /* The type is not known, so this message cannot be decoded
               properly by this dissector.  We assume it's continuation
               data from the middle of a message, and just return the
               remaining length in the tvbuff so the rest of the tvbuff
               is displayed as continuation data. */
            return tvb_reported_length_remaining(tvb, offset);
         }
      } else {
         /* We don't have the type field, so we can't determine
            whether this is a valid message.  Return 0, which
            tcp_dissect_pdus (and utp_dissect_pdus) treats as
            "variable length, needs one more segment". */
         return 0;
      }
   }
}

static void
dissect_bittorrent_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   int         offset  = 0;
   int         i;
   int         isamp   = 0;
   proto_tree *mtree;
   uint16_t    type    = 0;
   uint32_t    typelen = 0;
   uint8_t     prio    = 0;
   uint32_t    ext_id  = 0;
   uint32_t    length;
   const char *msgtype = NULL;
   proto_item *ti;
   uint32_t    piece_index, piece_begin, piece_length;
   uint32_t    stringlen;
   tvbuff_t   *subtvb;

   /* Guaranteed BITTORRENT_HEADER_LENGTH by tcp_dissect_pdus */
   length = tvb_get_ntohl(tvb, offset);

   /* Keepalive message */
   if (length == 0) {
      ti = proto_tree_add_item(tree, hf_bittorrent_msg, tvb, offset, length + BITTORRENT_HEADER_LENGTH, ENC_NA);
      mtree = proto_item_add_subtree(ti, ett_bittorrent_msg);
      proto_tree_add_item(mtree, hf_bittorrent_msg_len, tvb, offset, BITTORRENT_HEADER_LENGTH, ENC_BIG_ENDIAN);
      col_set_str(pinfo->cinfo, COL_INFO, "KeepAlive");
      return;
   }

   if (tvb_bytes_exist(tvb, offset + BITTORRENT_HEADER_LENGTH, 1)) {
      /* Check for data from the middle of a message. */
      type = tvb_get_uint8(tvb, offset + BITTORRENT_HEADER_LENGTH);

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

                  prio = tvb_get_uint8(tvb, offset + BITTORRENT_HEADER_LENGTH + 4 + typelen);
                  if (prio==0 || prio==1 || prio==2) {
                     type = amp_messages[i].value;
                     isamp = 1;
                  }
                  break;
               }
            }
         }
      }

      msgtype = try_val_to_str(type, bittorrent_messages);
#if 0
      if (msgtype == NULL && isamp) {
         msgtype = try_val_to_str(type, azureus_messages);
      }
#endif
      if (msgtype == NULL || !(test_type_length(type, length))) {
         /* In modern captures, this is likely Protocol Encryption/
          * Message Stream Encryption, particularly if we're actually
          * desegmenting and have the whole connection starting from
          * the SYN. We don't try to do that yet.
          */
         proto_tree_add_item(tree, hf_bittorrent_continuous_data, tvb, offset, -1, ENC_NA);
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

   proto_tree_add_item(mtree, hf_bittorrent_msg_len, tvb, offset, BITTORRENT_HEADER_LENGTH, ENC_BIG_ENDIAN);
   offset += BITTORRENT_HEADER_LENGTH;

   /* If the tvb_bytes_exist() call above returned false, this will
      throw an exception, so we won't use msgtype or type. */
   if (isamp) {
      proto_tree_add_item(mtree, hf_azureus_msg_type_len, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(mtree, hf_azureus_msg_type, tvb, offset+4, typelen, ENC_ASCII);
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
   case BITT_FAST_EX_HAVE_ALL:
   case BITT_FAST_EX_HAVE_NONE:
      /* No payload */
      break;

   case BITTORRENT_MESSAGE_REQUEST:
   case BITTORRENT_MESSAGE_CANCEL:
   case BITT_FAST_EX_REJECT_REQUEST:
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
      proto_tree_add_item(mtree, hf_bittorrent_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;

   case BITTORRENT_MESSAGE_EXTENDED:
      /* extended message content */
      proto_tree_add_item_ret_uint(mtree, hf_bittorrent_extended_id, tvb, offset, 1, ENC_NA, &ext_id);
      offset += 1;
      length -= 1;
      if (ext_id == 0) {
         call_dissector(bencode_handle, tvb_new_subset_length(tvb, offset, length), pinfo, mtree);
      } else {
         proto_tree_add_item(mtree, hf_bittorrent_extended, tvb, offset, length, ENC_NA);
      }
      break;

   case BITTORRENT_MESSAGE_HAVE:
   case BITT_FAST_EX_SUGGEST_PIECE:
   case BITT_FAST_EX_ALLOWED_FAST:
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
      subtvb = tvb_new_subset_length(tvb, offset, length);
      call_dissector(bencode_handle, subtvb, pinfo, mtree);
      break;

   case AZUREUS_MESSAGE_JPC_HELLO:
      stringlen = tvb_get_ntohl(tvb, offset);
      proto_tree_add_item(mtree, hf_azureus_jpc_addrlen, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(mtree, hf_azureus_jpc_addr, tvb, offset+4, stringlen, ENC_ASCII);
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

static int
dissect_bittorrent_welcome (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   int   offset = 0;
   int   i;
   char *version;

   col_set_str(pinfo->cinfo, COL_INFO, "Handshake");

   proto_tree_add_item(tree, hf_bittorrent_prot_name_len, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
   proto_tree_add_item(tree, hf_bittorrent_prot_name, tvb, offset, 19, ENC_ASCII); offset += 19;
   proto_tree_add_item(tree, hf_bittorrent_reserved, tvb, offset, 8, ENC_NA); offset += 8;

   proto_tree_add_item(tree, hf_bittorrent_sha1_hash, tvb, offset, 20, ENC_NA);
   offset += 20;

   proto_tree_add_item(tree, hf_bittorrent_peer_id, tvb, offset, 20, ENC_NA);
   if(decode_client_information) {
      for(i = 0; peer_id[i].name != NULL; ++i)
      {
         if(tvb_memeql(tvb, offset, (const uint8_t*)peer_id[i].id, (int)strlen(peer_id[i].id)) == 0) {
            version = tvb_get_string_enc(pinfo->pool, tvb, offset + (int)strlen(peer_id[i].id),
                                     peer_id[i].ver_len, ENC_ASCII);
            proto_tree_add_string_format(tree, hf_bittorrent_version, tvb, offset, 20, version, "Client is %s v%s",
                                peer_id[i].name, format_text(pinfo->pool, (unsigned char*)version, peer_id[i].ver_len));
            break;
         }
      }
   }
   offset += 20;
   return offset;
}

static
int dissect_bittorrent_tcp_pdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   proto_item *ti;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "BitTorrent");

   col_set_str(pinfo->cinfo, COL_INFO, "BitTorrent ");

   ti = proto_tree_add_item (tree, proto_bittorrent, tvb, 0, -1, ENC_NA);
   tree = proto_item_add_subtree(ti, ett_bittorrent);

   if (tvb_get_uint8(tvb, 0) == 19 &&
       tvb_memeql(tvb, 1, (const uint8_t*)"BitTorrent protocol", 19) == 0) {
      dissect_bittorrent_welcome(tvb, pinfo, tree);
   } else {
      dissect_bittorrent_message(tvb, pinfo, tree);
   }

    col_append_str(pinfo->cinfo, COL_INFO, "  ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    return tvb_reported_length(tvb);
}

static
int dissect_bittorrent (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
   tcp_dissect_pdus(tvb, pinfo, tree, bittorrent_desegment, BITTORRENT_HEADER_LENGTH,
                    get_bittorrent_pdu_length, dissect_bittorrent_tcp_pdu, data);
   return tvb_reported_length(tvb);
}

static
int dissect_bittorrent_utp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
   utp_dissect_pdus(tvb, pinfo, tree, bittorrent_desegment, BITTORRENT_HEADER_LENGTH,
                    get_bittorrent_pdu_length, dissect_bittorrent_tcp_pdu, data);
   return tvb_reported_length(tvb);
}

static
bool test_bittorrent_packet (tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, void *data)
{
   conversation_t *conversation;

   if (tvb_captured_length(tvb) >= 20 &&
       tvb_get_uint8(tvb, 0) == 19 &&
       tvb_memeql(tvb, 1, (const uint8_t*)"BitTorrent protocol", 19) == 0) {
      conversation = find_or_create_conversation(pinfo);
      conversation_set_dissector(conversation, dissector_handle);

      dissect_bittorrent(tvb, pinfo, tree, data);

      return true;
   }

   return false;
}

void
proto_register_bittorrent(void)
{
   static hf_register_info hf[] = {
#if 0
      { &hf_bittorrent_field_length,
        { "Field Length", "bittorrent.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
#endif
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
      { &hf_bittorrent_extended_id,
        { "Extended Message ID", "bittorrent.extended.id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_extended,
        { "Extended Message", "bittorrent.extended", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_continuous_data,
        { "Extended Message", "bittorrent.continuous_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bittorrent_version,
        { "Client version", "bittorrent.version", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
   };

   static int *ett[] = {
      &ett_bittorrent,
      &ett_bittorrent_msg,
      &ett_peer_id,
   };

   module_t *bittorrent_module;

   proto_bittorrent = proto_register_protocol("BitTorrent", "BitTorrent", "bittorrent");
   proto_register_field_array(proto_bittorrent, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   dissector_handle = register_dissector("bittorrent.tcp", dissect_bittorrent, proto_bittorrent);
   register_dissector("bittorrent.utp", dissect_bittorrent_utp, proto_bittorrent);

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
   bencode_handle = find_dissector_add_dependency("bencode", proto_bittorrent);

   dissector_add_uint_range_with_preference("tcp.port", DEFAULT_TCP_PORT_RANGE, dissector_handle);

   heur_dissector_add("tcp", test_bittorrent_packet, "BitTorrent over TCP", "bittorrent_tcp", proto_bittorrent, HEURISTIC_ENABLE);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
