/* packet-isakmp.c
 * Routines for the Internet Security Association and Key Management Protocol
 * (ISAKMP) (RFC 2408) and the Internet IP Security Domain of Interpretation
 * for ISAKMP (RFC 2407)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * $Id: packet-isakmp.c,v 1.47 2001/10/26 10:30:16 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "ipproto.h"

static int proto_isakmp = -1;

static gint ett_isakmp = -1;
static gint ett_isakmp_flags = -1;
static gint ett_isakmp_payload = -1;

#define UDP_PORT_ISAKMP	500
#define TCP_PORT_ISAKMP 500

#define NUM_PROTO_TYPES	5
#define proto2str(t)	\
  ((t < NUM_PROTO_TYPES) ? prototypestr[t] : "UNKNOWN-PROTO-TYPE")

static const char *prototypestr[NUM_PROTO_TYPES] = {
  "RESERVED",
  "ISAKMP",
  "IPSEC_AH",
  "IPSEC_ESP",
  "IPCOMP"
};

#define NUM_P1_ATT_TYPES	17
#define p1_atttype2str(t)	\
  ((t < NUM_P1_ATT_TYPES) ? p1_atttypestr[t] : "UNKNOWN-ATTRIBUTE-TYPE")

static const char *p1_atttypestr[NUM_P1_ATT_TYPES] = {
  "UNKNOWN-ATTRIBUTE-TYPE",
  "Encryption-Algorithm",
  "Hash-Algorithm",
  "Authentication-Method",
  "Group-Description",
  "Group-Type",
  "Group-Prime",
  "Group-Generator-One",
  "Group-Generator-Two",
  "Group-Curve-A",
  "Group-Curve-B",
  "Life-Type",
  "Life-Duration",
  "PRF",
  "Key-Length",
  "Field-Size",
  "Group-Order"
};

#define NUM_ATT_TYPES	11
#define atttype2str(t)	\
  ((t < NUM_ATT_TYPES) ? atttypestr[t] : "UNKNOWN-ATTRIBUTE-TYPE")

static const char *atttypestr[NUM_ATT_TYPES] = {
  "UNKNOWN-ATTRIBUTE-TYPE",
  "SA-Life-Type",
  "SA-Life-Duration",
  "Group-Description",
  "Encapsulation-Mode",
  "Authentication-Algorithm",
  "Key-Length",
  "Key-Rounds",
  "Compress-Dictinary-Size",
  "Compress-Private-Algorithm",
  "ECN Tunnel"
};

#define NUM_TRANS_TYPES	2
#define trans2str(t)	\
  ((t < NUM_TRANS_TYPES) ? transtypestr[t] : "UNKNOWN-TRANS-TYPE")

static const char *transtypestr[NUM_TRANS_TYPES] = {
  "RESERVED",
  "KEY_IKE"
};

#define NUM_AH_TRANS_TYPES	8
#define ah_trans2str(t)		\
  ((t < NUM_AH_TRANS_TYPES) ? ah_transtypestr[t] : "UNKNOWN-AH-TRANS-TYPE")

static const char *ah_transtypestr[NUM_AH_TRANS_TYPES] = {
  "RESERVED",
  "RESERVED",
  "MD5",
  "SHA",
  "DES",
  "SHA2-256",
  "SHA2-384",
  "SHA2-512"
};

#define NUM_ESP_TRANS_TYPES	13
#define esp_trans2str(t)	\
  ((t < NUM_ESP_TRANS_TYPES) ? esp_transtypestr[t] : "UNKNOWN-ESP-TRANS-TYPE")

static const char *esp_transtypestr[NUM_ESP_TRANS_TYPES] = {
  "RESERVED",
  "DES-IV64",
  "DES",
  "3DES",
  "RC5",
  "IDEA",
  "CAST",
  "BLOWFISH",
  "3IDEA",
  "DES-IV32",
  "RC4",
  "NULL",
  "AES"
};

#define NUM_ID_TYPES	12
#define id2str(t)	\
  ((t < NUM_ID_TYPES) ? idtypestr[t] : "UNKNOWN-ID-TYPE")

static const char *idtypestr[NUM_ID_TYPES] = {
  "RESERVED",
  "IPV4_ADDR",
  "FQDN",
  "USER_FQDN",
  "IPV4_ADDR_SUBNET",
  "IPV6_ADDR",
  "IPV6_ADDR_SUBNET",
  "IPV4_ADDR_RANGE",
  "IPV6_ADDR_RANGE",
  "DER_ASN1_DN",
  "DER_ASN1_GN",
  "KEY_ID"
};

struct isakmp_hdr {
  guint8	icookie[8];
  guint8	rcookie[8];
  guint8	next_payload;
  guint8	version;
  guint8	exch_type;
  guint8	flags;
#define E_FLAG		0x01
#define C_FLAG		0x02
#define A_FLAG		0x04
  guint8	message_id[4];
  guint8	length[4];
};

struct udp_encap_hdr {
  guint8	non_ike_marker[8];
  guint32	esp_SPI;
};

static proto_tree *dissect_payload_header(tvbuff_t *, int, int, guint8,
    guint8 *, guint16 *, proto_tree *);

static void dissect_sa(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_proposal(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_transform(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_key_exch(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_id(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_cert(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_certreq(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_hash(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_sig(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_nonce(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_notif(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_delete(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_vid(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_config(tvbuff_t *, int, int, proto_tree *, int);

static const char *payloadtype2str(guint8);
static const char *exchtype2str(guint8);
static const char *doitype2str(guint32);
static const char *msgtype2str(guint16);
static const char *situation2str(guint32);
static const char *value2str(int, guint16, guint16);
static const char *attrtype2str(guint8);
static const char *cfgattrident2str(guint16);
static const char *certtype2str(guint8);

static gboolean get_num(tvbuff_t *, int, guint16, guint32 *);

#define LOAD_TYPE_NONE		0	/* payload type for None */
#define LOAD_TYPE_PROPOSAL	2	/* payload type for Proposal */
#define	LOAD_TYPE_TRANSFORM	3	/* payload type for Transform */
#define NUM_LOAD_TYPES		15
#define loadtype2str(t)	\
  ((t < NUM_LOAD_TYPES) ? strfuncs[t].str : "Unknown payload type")

static struct strfunc {
  const char *	str;
  void          (*func)(tvbuff_t *, int, int, proto_tree *, int);
} strfuncs[NUM_LOAD_TYPES] = {
  {"NONE",			NULL              },
  {"Security Association",	dissect_sa        },
  {"Proposal",			dissect_proposal  },
  {"Transform",			dissect_transform },
  {"Key Exchange",		dissect_key_exch  },
  {"Identification",		dissect_id        },
  {"Certificate",		dissect_cert      },
  {"Certificate Request",	dissect_certreq   },
  {"Hash",			dissect_hash      },
  {"Signature",			dissect_sig       },
  {"Nonce",			dissect_nonce     },
  {"Notification",		dissect_notif     },
  {"Delete",			dissect_delete    },
  {"Vendor ID",			dissect_vid       },
  {"Attrib",			dissect_config	  }
};

static dissector_handle_t esp_handle;
static dissector_handle_t ah_handle;

static void
dissect_payloads(tvbuff_t *tvb, proto_tree *tree, guint8 initial_payload,
		 int offset, int length)
{
  guint8 payload, next_payload;
  guint16		payload_length;
  proto_tree *		ntree;

  for (payload = initial_payload; length != 0; payload = next_payload) {
    if (payload == LOAD_TYPE_NONE) {
      /*
       * What?  There's more stuff in this chunk of data, but the
       * previous payload had a "next payload" type of None?
       */
      proto_tree_add_text(tree, tvb, offset, length,
			  "Extra data: %s",
			  tvb_bytes_to_str(tvb, offset, length));
      break;
    }
    ntree = dissect_payload_header(tvb, offset, length, payload,
      &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (payload_length >= 4) {	/* XXX = > 4? */
      if (payload < NUM_LOAD_TYPES) {
        (*strfuncs[payload].func)(tvb, offset + 4, payload_length - 4, ntree,
				  -1);
      }
      else {
        proto_tree_add_text(ntree, tvb, offset + 4, payload_length - 4,
            "Payload");
      }
    }
    else {
        proto_tree_add_text(ntree, tvb, offset + 4, 0,
            "Payload (bogus, length is %u, must be at least 4)",
            payload_length);
        payload_length = 4;
    }
    offset += payload_length;
    length -= payload_length;
  }
}

static void
dissect_isakmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int			offset = 0;
  struct isakmp_hdr *	hdr;
  proto_item *		ti;
  proto_tree *		isakmp_tree = NULL;
  struct udp_encap_hdr * encap_hdr;
  guint32		len;
  static const guint8	non_ike_marker[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
  tvbuff_t *		next_tvb;

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "ISAKMP");
  if (check_col(pinfo->fd, COL_INFO))
    col_clear(pinfo->fd, COL_INFO);

  hdr = (struct isakmp_hdr *)tvb_get_ptr(tvb, 0, sizeof (struct isakmp_hdr));
  len = pntohl(&hdr->length);
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_isakmp, tvb, offset, len, FALSE);
    isakmp_tree = proto_item_add_subtree(ti, ett_isakmp);
  }
    
  encap_hdr = (struct udp_encap_hdr *)tvb_get_ptr(tvb, 0, sizeof(struct udp_encap_hdr));
  
  if (encap_hdr->non_ike_marker[0] == 0xFF) {
    if (check_col(pinfo->fd, COL_INFO)) 
      col_add_str(pinfo->fd, COL_INFO, "UDP encapsulated IPSec - NAT Keepalive");
    return;
  }
  if (memcmp(encap_hdr->non_ike_marker,non_ike_marker,8) == 0) {
    if (check_col(pinfo->fd, COL_INFO)) {
      if (encap_hdr->esp_SPI != 0)
          col_add_str(pinfo->fd, COL_INFO, "UDP encapsulated IPSec - ESP");
      else
         col_add_str(pinfo->fd, COL_INFO, "UDP encapsulated IPSec - AH");
    } 
    if (tree)
      proto_tree_add_text(isakmp_tree, tvb, offset,
			  sizeof(encap_hdr->non_ike_marker),
			  "Non-IKE-Marker");
    offset += sizeof(encap_hdr->non_ike_marker);
      
    if (encap_hdr->esp_SPI != 0) {
      next_tvb = tvb_new_subset(tvb, offset, -1, -1);
      call_dissector(esp_handle, next_tvb, pinfo, tree);
    } else {
      if (tree)
        proto_tree_add_text(isakmp_tree, tvb, offset,
			    sizeof(encap_hdr->esp_SPI),
			    "Non-ESP-Marker");
      offset += sizeof(encap_hdr->esp_SPI);

      if (tree)
        proto_tree_add_text(isakmp_tree, tvb, offset, 1,
			    "AH Envelope Version: %u",
			    tvb_get_guint8(tvb, offset) >> 4);
      offset += 1;

      if (tree)
        proto_tree_add_text(isakmp_tree, tvb, offset, 1,
			    "AH Envelope Header Length: %u",
			    (tvb_get_guint8(tvb, offset) & 0xF)*4);
      offset += 1;

      if (tree)
        proto_tree_add_text(isakmp_tree, tvb, offset, 2,
			    "AH Envelope Identification: 0x%04X",
			    tvb_get_ntohs(tvb, offset));
      offset += 2;

      next_tvb = tvb_new_subset(tvb, offset, -1, -1);
      call_dissector(ah_handle, next_tvb, pinfo, tree);
    }
    return;
  }

  if (check_col(pinfo->fd, COL_INFO))
    col_add_str(pinfo->fd, COL_INFO, exchtype2str(hdr->exch_type));

  if (tree) {
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr->icookie),
			"Initiator cookie");
    offset += sizeof(hdr->icookie);
    
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr->rcookie),
			"Responder cookie");
    offset += sizeof(hdr->rcookie);

    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr->next_payload),
			"Next payload: %s (%u)",
			payloadtype2str(hdr->next_payload), hdr->next_payload);
    offset += sizeof(hdr->next_payload);

    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr->version),
			"Version: %u.%u",
			hi_nibble(hdr->version), lo_nibble(hdr->version));
    offset += sizeof(hdr->version);
    
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr->exch_type),
			"Exchange type: %s (%u)",
			exchtype2str(hdr->exch_type), hdr->exch_type);
    offset += sizeof(hdr->exch_type);
    
    {
      proto_item *	fti;
      proto_tree *	ftree;
      
      fti   = proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr->flags), "Flags");
      ftree = proto_item_add_subtree(fti, ett_isakmp_flags);
      
      proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr->flags, E_FLAG, sizeof(hdr->flags)*8,
						  "Encryption", "No encryption"));
      proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr->flags, C_FLAG, sizeof(hdr->flags)*8,
						  "Commit", "No commit"));
      proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr->flags, A_FLAG, sizeof(hdr->flags)*8,
						  "Authentication", "No authentication"));
      offset += sizeof(hdr->flags);
    }

    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr->message_id),
        "Message ID: 0x%02x%02x%02x%02x", hdr->message_id[0],
        hdr->message_id[1], hdr->message_id[2], hdr->message_id[3]);
    offset += sizeof(hdr->message_id);
    
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr->length),
			"Length: %u", len);
    offset += sizeof(hdr->length);
    len -= sizeof(*hdr);

    if (hdr->flags & E_FLAG) {
      if (len && isakmp_tree) {
        proto_tree_add_text(isakmp_tree, tvb, offset, len,
			"Encrypted payload (%d byte%s)",
			len, plurality(len, "", "s"));
      }
    } else
      dissect_payloads(tvb, isakmp_tree, hdr->next_payload, offset, len);
  }
}

static proto_tree *
dissect_payload_header(tvbuff_t *tvb, int offset, int length, guint8 payload,
    guint8 *next_payload_p, guint16 *payload_length_p, proto_tree *tree)
{
  guint8		next_payload;
  guint16		payload_length;
  proto_item *		ti;
  proto_tree *		ntree;

  if (length < 4) {
    proto_tree_add_text(tree, tvb, offset, length,
          "Not enough room in payload for all transforms");
    return NULL;
  }
  next_payload = tvb_get_guint8(tvb, offset);
  payload_length = tvb_get_ntohs(tvb, offset + 2);

  ti = proto_tree_add_text(tree, tvb, offset, payload_length,
            "%s payload", loadtype2str(payload));
  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);

  proto_tree_add_text(ntree, tvb, offset, 1,
		      "Next payload: %s (%u)",
		      payloadtype2str(next_payload), next_payload);
  proto_tree_add_text(ntree, tvb, offset+2, 2, "Length: %u", payload_length);

  *next_payload_p = next_payload;
  *payload_length_p = payload_length;
  return ntree;
}

static void
dissect_sa(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  guint32		doi;
  guint32		situation;

  if (length < 4) {
    proto_tree_add_text(tree, tvb, offset, length,
			"DOI %s (length is %u, should be >= 4)",
			tvb_bytes_to_str(tvb, offset, length), length);
    return;
  }
  doi = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Domain of interpretation: %s (%u)",
		      doitype2str(doi), doi);
  offset += 4;
  length -= 4;
  
  if (doi == 1) {
    /* IPSEC */
    if (length < 4) {
      proto_tree_add_text(tree, tvb, offset, length,
			  "Situation: %s (length is %u, should be >= 4)",
			  tvb_bytes_to_str(tvb, offset, length), length);
      return;
    }
    situation = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4,
			"Situation: %s (%u)",
			situation2str(situation), situation);
    offset += 4;
    length -= 4;
  
    dissect_payloads(tvb, tree, LOAD_TYPE_PROPOSAL, offset, length);
  } else {
    /* Unknown */
    proto_tree_add_text(tree, tvb, offset, length,
			"Situation: %s",
			tvb_bytes_to_str(tvb, offset, length));
  }
}

static void
dissect_proposal(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  guint8		protocol_id;
  guint8		spi_size;
  guint8		num_transforms;
  guint8		next_payload;
  guint16		payload_length;
  proto_tree *		ntree;

  proto_tree_add_text(tree, tvb, offset, 1,
		      "Proposal number: %u", tvb_get_guint8(tvb, offset));
  offset += 1;
  length -= 1;
  
  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Protocol ID: %s (%u)",
		      proto2str(protocol_id), protocol_id);
  offset += 1;
  length -= 1;
  
  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "SPI size: %u", spi_size);
  offset += 1;
  length -= 1;

  num_transforms = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Number of transforms: %u", num_transforms);
  offset += 1;
  length -= 1;

  if (spi_size) {
    proto_tree_add_text(tree, tvb, offset, spi_size, "SPI: %s",
			tvb_bytes_to_str(tvb, offset, spi_size));
    offset += spi_size;
    length -= spi_size;
  }

  while (num_transforms > 0) {
    ntree = dissect_payload_header(tvb, offset, length, LOAD_TYPE_TRANSFORM,
      &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (length < payload_length) {
      proto_tree_add_text(tree, tvb, offset + 4, length,
          "Not enough room in payload for all transforms");
      break;
    }
    if (payload_length >= 4)
      dissect_transform(tvb, offset + 4, payload_length - 4, ntree, protocol_id);
    else
      proto_tree_add_text(ntree, tvb, offset + 4, payload_length - 4, "Payload");
    offset += payload_length;
    length -= payload_length;
    num_transforms--;
  }
}

static void
dissect_transform(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int protocol_id)
{
  guint8		transform_id;

  proto_tree_add_text(tree, tvb, offset, 1,
		      "Transform number: %u", tvb_get_guint8(tvb, offset));
  offset += 1;
  length -= 1;

  transform_id = tvb_get_guint8(tvb, offset);
  switch (protocol_id) {
  default:
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %u", transform_id);
    break;
  case 1:	/* ISAKMP */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			trans2str(transform_id), transform_id);
    break;
  case 2:	/* AH */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			ah_trans2str(transform_id), transform_id);
    break;
  case 3:	/* ESP */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			esp_trans2str(transform_id), transform_id);
    break;
  }
  offset += 3;
  length -= 3;
  
  while (length>0) {
    const char *str;
    int ike_phase1 = 0;
    guint16 aft     = tvb_get_ntohs(tvb, offset);
    guint16 type    = aft & 0x7fff;
    guint16 len;
    guint32 val;
    guint pack_len;

    if (protocol_id == 1 && transform_id == 1) {
      ike_phase1 = 1;
      str = p1_atttype2str(type);
    }
    else {
      str = atttype2str(type);
    }

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u): %s (%u)",
			  str, type,
			  value2str(ike_phase1, type, val), val);
      offset += 4;
      length -= 4;
    }
    else {
      len = tvb_get_ntohs(tvb, offset + 2);
      pack_len = 4 + len;
      if (!get_num(tvb, offset + 4, len, &val)) {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): <too big (%u bytes)>",
			    str, type, len);
      } else {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): %s (%u)",
			    str, type,
			    value2str(ike_phase1, type, val), val);
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

static void
dissect_key_exch(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  proto_tree_add_text(tree, tvb, offset, length, "Key Exchange Data");
}

static void
dissect_id(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  guint8		id_type;
  guint8		protocol_id;
  guint16		port;

  id_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "ID type: %s (%u)", id2str(id_type), id_type);
  offset += 1;
  length -= 1;

  protocol_id = tvb_get_guint8(tvb, offset);
  if (protocol_id == 0) {
    proto_tree_add_text(tree, tvb, offset, 1,
			"Protocol ID: Unused");
  } else {
    proto_tree_add_text(tree, tvb, offset, 1,
			"Protocol ID: %s (%u)",
			ipprotostr(protocol_id), protocol_id);
  }
  offset += 1;
  length -= 1;

  port = tvb_get_ntohs(tvb, offset);
  if (port == 0)
    proto_tree_add_text(tree, tvb, offset, 2, "Port: Unused");
  else
    proto_tree_add_text(tree, tvb, offset, 2, "Port: %u", port);
  offset += 2;
  length -= 2;
  
  switch (id_type) {
    case 1:
    case 4:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s",
			  ip_to_str(tvb_get_ptr(tvb, offset, 4)));
      break;
    case 2:
    case 3:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %.*s", length,
			  tvb_get_ptr(tvb, offset, length));
      break;
    default:
      proto_tree_add_text(tree, tvb, offset, length, "Identification Data");
      break;
  }
}

static void
dissect_cert(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  guint8		cert_enc;

  cert_enc = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Certificate encoding: %u - %s",
		      cert_enc, certtype2str(cert_enc));
  offset += 1;
  length -= 1;

  proto_tree_add_text(tree, tvb, offset, length, "Certificate Data");
}

static void
dissect_certreq(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  guint8		cert_type;

  cert_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Certificate type: %u - %s",
		      cert_type, certtype2str(cert_type));
  offset += 1;
  length -= 1;

  proto_tree_add_text(tree, tvb, offset, length, "Certificate Authority");
}

static void
dissect_hash(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  proto_tree_add_text(tree, tvb, offset, length, "Hash Data");
}

static void
dissect_sig(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  proto_tree_add_text(tree, tvb, offset, length, "Signature Data");
}

static void
dissect_nonce(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  proto_tree_add_text(tree, tvb, offset, length, "Nonce Data");
}

static void
dissect_notif(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  guint32		doi;
  guint8		protocol_id;
  guint8		spi_size;
  guint16		msgtype;

  doi = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Domain of Interpretation: %s (%u)",
		      doitype2str(doi), doi);
  offset += 4;
  length -= 4;

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Protocol ID: %s (%u)",
		      proto2str(protocol_id), protocol_id);
  offset += 1;
  length -= 1;
  
  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "SPI size: %u", spi_size);
  offset += 1;
  length -= 1;
  
  msgtype = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Message type: %s (%u)", msgtype2str(msgtype), msgtype);
  offset += 2;
  length -= 2;

  if (spi_size) {
    proto_tree_add_text(tree, tvb, offset, spi_size, "Security Parameter Index");
    offset += spi_size;
    length -= spi_size;
  }

  if (length > 0)
    proto_tree_add_text(tree, tvb, offset, length, "Notification Data");
}

static void
dissect_delete(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  guint32		doi;
  guint8		protocol_id;
  guint8		spi_size;
  guint16		num_spis;
  guint16		i;
  
  doi = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Domain of Interpretation: %s (%u)",
		      doitype2str(doi), doi);
  offset += 4;
  length -= 4;

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Protocol ID: %s (%u)",
		      proto2str(protocol_id), protocol_id);
  offset += 1;
  length -= 1;
  
  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "SPI size: %u", spi_size);
  offset += 1;
  length -= 1;

  num_spis = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Number of SPIs: %u", num_spis);
  offset += 2;
  length -= 2;
  
  for (i = 0; i < num_spis; ++i) {
    if (length < spi_size) {
      proto_tree_add_text(tree, tvb, offset, length,
          "Not enough room in payload for all SPI's");
      break;
    }
    proto_tree_add_text(tree, tvb, offset, spi_size,
			"SPI (%d)", i);
    offset += spi_size;
    length -= spi_size;
  }
}

static void
dissect_vid(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  proto_tree_add_text(tree, tvb, offset, length, "Vendor ID");
}

static void
dissect_config(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused)
{
  guint8		type;

  type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Type %s (%u)",attrtype2str(type),type);
  
  offset += 2;
  length -= 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
                      "Identifier: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  length -= 2;
  
  while(length>0) {
    guint16 aft     = tvb_get_ntohs(tvb, offset);
    guint16 type    = aft & 0x7fff;
    guint16 len;
    guint32 val;
    guint pack_len;

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u)", cfgattrident2str(type), val);
      offset += 4;
      length -= 4;
    }
    else {
      len = tvb_get_ntohs(tvb, offset + 2);
      pack_len = 4 + len;
      if (!get_num(tvb, offset + 4, len, &val)) {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s: <too big (%u bytes)>",
			    cfgattrident2str(type), len);
      } else {
        proto_tree_add_text(tree, tvb, offset, 4,
			    "%s (%ue)", cfgattrident2str(type),
			    val);
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

static const char *
payloadtype2str(guint8 type) {

  if (type < NUM_LOAD_TYPES) return strfuncs[type].str;
  if (type < 128)            return "RESERVED";
  if (type < 256)            return "Private USE";

  return "Huh? You should never see this! Shame on you!";
}

static const char *
exchtype2str(guint8 type) {

#define NUM_EXCHSTRS	7
  static const char * exchstrs[NUM_EXCHSTRS] = {
    "NONE",
    "Base",
    "Identity Protection (Main Mode)",
    "Authentication Only",
    "Aggressive",
    "Informational",
    "Transaction (Config Mode)"
  };
  
  if (type < NUM_EXCHSTRS) return exchstrs[type];
  if (type < 32)           return "ISAKMP Future Use";
  switch (type) {
  case 32:
    return "Quick Mode";
  case 33:
    return "New Group Mode";
  }
  if (type < 240)          return "DOI Specific Use";
  if (type < 256)          return "Private Use";
  
  return "Huh? You should never see this! Shame on you!";
}

static const char *
doitype2str(guint32 type) {
  if (type == 1) return "IPSEC";
  return "Unknown DOI Type";
}

static const char *
msgtype2str(guint16 type) {

#define NUM_PREDEFINED	31
  static const char *msgs[NUM_PREDEFINED] = {
    "<UNKNOWN>",
    "INVALID-PAYLOAD-TYPE",
    "DOI-NOT-SUPPORTED",
    "SITUATION-NOT-SUPPORTED",
    "INVALID-COOKIE",
    "INVALID-MAJOR-VERSION",
    "INVALID-MINOR-VERSION",
    "INVALID-EXCHANGE-TYPE",
    "INVALID-FLAGS",
    "INVALID-MESSAGE-ID",
    "INVALID-PROTOCOL-ID",
    "INVALID-SPI",
    "INVALID-TRANSFORM-ID",
    "ATTRIBUTES-NOT-SUPPORTED",
    "NO-PROPOSAL-CHOSEN",
    "BAD-PROPOSAL-SYNTAX",
    "PAYLOAD-MALFORMED",
    "INVALID-KEY-INFORMATION",
    "INVALID-ID-INFORMATION",
    "INVALID-CERT-ENCODING",
    "INVALID-CERTIFICATE",
    "CERT-TYPE-UNSUPPORTED",
    "INVALID-CERT-AUTHORITY",
    "INVALID-HASH-INFORMATION",
    "AUTHENTICATION-FAILED",
    "INVALID-SIGNATURE",
    "ADDRESS-NOTIFICATION",
    "NOTIFY-SA-LIFETIME",
    "CERTIFICATE-UNAVAILABLE",
    "UNSUPPORTED-EXCHANGE-TYPE",
    "UNEQUAL-PAYLOAD-LENGTHS"
  };

  if (type < NUM_PREDEFINED) return msgs[type];
  if (type < 8192)           return "RESERVED (Future Use)";
  if (type < 16384)          return "Private Use";
  if (type < 16385)          return "CONNECTED";
  if (type < 24576)          return "RESERVED (Future Use) - status";
  if (type < 24577)          return "RESPONDER-LIFETIME";
  if (type < 24578)          return "REPLAY-STATUS";
  if (type < 24579)          return "INITIAL-CONTACT";
  if (type < 32768)          return "DOI-specific codes";
  if (type < 40960)          return "Private Use - status";
  if (type < 65535)          return "RESERVED (Future Use) - status (2)";

  return "Huh? You should never see this! Shame on you!";
}

static const char *
situation2str(guint32 type) {

#define SIT_MSG_NUM	1024
#define SIT_IDENTITY	0x01
#define SIT_SECRECY	0x02
#define SIT_INTEGRITY	0x04

  static char	msg[SIT_MSG_NUM];
  int		n = 0;
  char *	sep = "";
  int		ret;
  
  if (type & SIT_IDENTITY) {
    ret = snprintf(msg, SIT_MSG_NUM-n, "%sIDENTITY", sep);
    if (ret == -1) {
      /* Some versions of snprintf return -1 if they'd truncate the output. */
      return msg;
    }
    n += ret;
    sep = " & ";
  }
  if (type & SIT_SECRECY) {
    if (n >= SIT_MSG_NUM) {
      /* No more room. */
      return msg;
    }
    ret = snprintf(msg, SIT_MSG_NUM-n, "%sSECRECY", sep);
    if (ret == -1) {
      /* Some versions of snprintf return -1 if they'd truncate the output. */
      return msg;
    }
    n += ret;
    sep = " & ";
  }
  if (type & SIT_INTEGRITY) {
    if (n >= SIT_MSG_NUM) {
      /* No more room. */
      return msg;
    }
    ret = snprintf(msg, SIT_MSG_NUM-n, "%sINTEGRITY", sep);
    if (ret == -1) {
      /* Some versions of snprintf return -1 if they'd truncate the output. */
      return msg;
    }
    n += ret;
    sep = " & ";
  }

  return msg;
}

static const char *
value2str(int ike_p1, guint16 att_type, guint16 value) {
  
  if (value == 0) return "RESERVED";
  
  if (!ike_p1) {
  switch (att_type) {
    case 1:
      switch (value) {
        case 1:  return "Seconds";
        case 2:  return "Kilobytes";
        default: return "UNKNOWN-SA-VALUE";
      }
    case 2:
      return "Duration-Value";
    case 3:
      return "Group-Value";
    case 4:
      switch (value) {
        case 1:  return "Tunnel";
        case 2:  return "Transport";
	case 61440: return "Check Point IPSec UDP Encapsulation";
	case 61443: return "UDP-Encapsulated-Tunnel (draft)";
	case 61444: return "UDP-Encapsulated-Transport (draft)";
        default: return "UNKNOWN-ENCAPSULATION-VALUE";
      }
    case 5:
      switch (value) {
        case 1:  return "HMAC-MD5";
        case 2:  return "HMAC-SHA";
        case 3:  return "DES-MAC";
        case 4:  return "KPDK";
	case 5:  return "HMAC-SHA2-256";
	case 6:  return "HMAC-SHA2-384";
	case 7:  return "HMAC-SHA2-512";
        default: return "UNKNOWN-AUTHENTICATION-VALUE";
      }
    case 6:
      return "Key-Length";
    case 7:
      return "Key-Rounds";
    case 8:
      return "log2-size";
    default: return "UNKNOWN-ATTRIBUTE-TYPE";
  }
  }
  else {
    switch (att_type) {
      case 1:
        switch (value) {
          case 1:  return "DES-CBC";
          case 2:  return "IDEA-CBC";
          case 3:  return "BLOWFISH-CBC";
          case 4:  return "RC5-R16-B64-CBC";
          case 5:  return "3DES-CBC";
          case 6:  return "CAST-CBC";
	  case 7:  return "AES-CBC";
          default: return "UNKNOWN-ENCRYPTION-ALG";
        }
      case 2:
        switch (value) {
          case 1:  return "MD5";
          case 2:  return "SHA";
          case 3:  return "TIGER";
	  case 4:  return "SHA2-256";
	  case 5:  return "SHA2-384";
	  case 6:  return "SHA2-512";
          default: return "UNKNOWN-HASH-ALG";
        }
      case 3:
        switch (value) {
          case 1:  return "PSK";
          case 2:  return "DSS-SIG";
          case 3:  return "RSA-SIG";
          case 4:  return "RSA-ENC";
          case 5:  return "RSA-Revised-ENC";
	  case 64221: return "HybridInitRSA";
	  case 64222: return "HybridRespRSA";
	  case 64223: return "HybridInitDSS";
	  case 64224: return "HybridRespDSS";
          case 65001: return "XAUTHInitPreShared";
          case 65002: return "XAUTHRespPreShared";
          case 65003: return "XAUTHInitDSS";
          case 65004: return "XAUTHRespDSS";
          case 65005: return "XAUTHInitRSA";
          case 65006: return "XAUTHRespRSA";
          case 65007: return "XAUTHInitRSAEncryption";
          case 65008: return "XAUTHRespRSAEncryption";
          case 65009: return "XAUTHInitRSARevisedEncryption";
          case 65010: return "XAUTHRespRSARevisedEncryption";
	  default: return "UNKNOWN-AUTH-METHOD";
        }
      case 4:
      case 6:
      case 7:
      case 8:
      case 9:
      case 10:
      case 16:
        return "Group-Value";
      case 5:
        switch (value) {
          case 1:  return "MODP";
          case 2:  return "ECP";
          case 3:  return "EC2N";
          default: return "UNKNOWN-GROUPT-TYPE";
        }
      case 11:
        switch (value) {
          case 1:  return "Seconds";
          case 2:  return "Kilobytes";
          default: return "UNKNOWN-SA-VALUE";
        }
      case 12:
        return "Duration-Value";
      case 13:
        return "PRF-Value";
      case 14:
        return "Key-Length";
      case 15:
        return "Field-Size";
      default: return "UNKNOWN-ATTRIBUTE-TYPE";
    }
  }
}

static const char * 
attrtype2str(guint8 type) {
  switch (type) {
  case 0: return "Reserved";
  case 1: return "ISAKMP_CFG_REQUEST";
  case 2: return "ISAKMP_CFG_REPLY";
  case 3: return "ISAKMP_CFG_SET";
  case 4: return "ISAKMP_CFG_ACK";
  }
  if(type < 127)
    return "Future use";
  return "Private use";
}

static const char * 
cfgattrident2str(guint16 ident) {
#define NUM_ATTR_DEFINED	12
  static const char *msgs[NUM_PREDEFINED] = {
    "RESERVED",
    "INTERNAL_IP4_ADDRESS",
    "INTERNAL_IP4_NETMASK",
    "INTERNAL_IP4_DNS",
    "INTERNAL_IP4_NBNS",
    "INTERNAL_ADDRESS_EXPIREY",
    "INTERNAL_IP4_DHCP",
    "APPLICATION_VERSION"
    "INTERNAL_IP6_ADDRESS",
    "INTERNAL_IP6_NETMASK",
    "INTERNAL_IP6_DNS",
    "INTERNAL_IP6_NBNS",
    "INTERNAL_IP6_DHCP",
  }; 
  if(ident < NUM_ATTR_DEFINED)
    return msgs[ident];
  if(ident < 16383)
    return "Future use";
  switch(ident) {
  case 16520: return "XAUTH_TYPE";
  case 16521: return "XAUTH_USER_NAME";
  case 16522: return "XAUTH_USER_PASSWORD";
  case 16523: return "XAUTH_PASSCODE";
  case 16524: return "XAUTH_MESSAGE";
  case 16525: return "XAUTH_CHALLANGE";
  case 16526: return "XAUTH_DOMAIN";
  case 16527: return "XAUTH_STATUS";
  default: return "Private use";
  }
}

static const char *
certtype2str(guint8 type) {
#define NUM_CERTTYPE 11
  static const char *msgs[NUM_CERTTYPE] = {
    "NONE",
    "PKCS #7 wrapped X.509 certificate",
    "PGP Certificate",
    "DNS Signed Key",
    "X.509 Certificate - Signature",
    "X.509 Certificate - Key Exchange",
    "Kerberos Tokens",
    "Certificate Revocation List (CRL)",
    "Authority Revocation List (ARL)",
    "SPKI Certificate",
    "X.509 Certificate - Attribute",
  };
  if(type > NUM_CERTTYPE)
    return "RESERVED";
  return msgs[type];
}

static gboolean
get_num(tvbuff_t *tvb, int offset, guint16 len, guint32 *num_p) {

  switch (len) {
  case 1:
    *num_p = tvb_get_guint8(tvb, offset);
    break;
  case 2:
    *num_p = tvb_get_ntohs(tvb, offset);
    break;
  case 3:
    *num_p = tvb_get_ntoh24(tvb, offset);
    break;
  case 4:
    *num_p = tvb_get_ntohl(tvb, offset);
    break;
  default:
    return FALSE;
  }

  return TRUE;
}

void
proto_register_isakmp(void)
{
/*  static hf_register_info hf[] = {
    { &variable,
    { "Name",           "isakmp.abbreviation", TYPE, VALS_POINTER }},
  };*/
  static gint *ett[] = {
    &ett_isakmp,
    &ett_isakmp_flags,
    &ett_isakmp_payload,
  };

  proto_isakmp = proto_register_protocol("Internet Security Association and Key Management Protocol",
					       "ISAKMP", "isakmp");
/*  proto_register_field_array(proto_isakmp, hf, array_length(hf));*/
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_isakmp(void)
{
  /*
   * Get handle for the AH & ESP dissectors.
   */
  esp_handle = find_dissector("esp");
  ah_handle = find_dissector("ah");

  dissector_add("udp.port", UDP_PORT_ISAKMP, dissect_isakmp, proto_isakmp);
  dissector_add("tcp.port", TCP_PORT_ISAKMP, dissect_isakmp, proto_isakmp);
}
