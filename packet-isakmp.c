/* packet-gre.c
 * Routines for the Internet Security Association and Key Management Protocol (ISAKMP)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * $Id: packet-isakmp.c,v 1.21 2000/05/22 17:59:53 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

static int proto_isakmp = -1;

static gint ett_isakmp = -1;
static gint ett_isakmp_flags = -1;
static gint ett_isakmp_payload = -1;

#define UDP_PORT_ISAKMP	500

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

#define NUM_ATT_TYPES	10
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
  "Compress-Private-Algorithm"
};

#define NUM_TRANS_TYPES	2
#define trans2str(t)	\
  ((t < NUM_TRANS_TYPES) ? transtypestr[t] : "UNKNOWN-TRANS-TYPE")

static const char *transtypestr[NUM_TRANS_TYPES] = {
  "RESERVED",
  "KEY_IKE"
};

#define NUM_AH_TRANS_TYPES	5
#define ah_trans2str(t)		\
  ((t < NUM_AH_TRANS_TYPES) ? ah_transtypestr[t] : "UNKNOWN-AH-TRANS-TYPE")

static const char *ah_transtypestr[NUM_AH_TRANS_TYPES] = {
  "RESERVED",
  "RESERVED",
  "MD5",
  "SHA",
  "DES"
};

#define NUM_ESP_TRANS_TYPES	12
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
  "NULL"
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
  guint32	message_id;
  guint32	length;
};

struct sa_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
  guint32	doi;
  guint32	situation;
};

struct proposal_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
  guint8	proposal_num;
  guint8	protocol_id;
  guint8	spi_size;
  guint8	num_transforms;
};

struct trans_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
  guint8	transform_num;
  guint8	transform_id;
  guint16	reserved2;
};

#define TRANS_LEN(p)	(pntohs(&((struct trans_hdr *)(p))->length))

struct ke_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
};

struct id_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
  guint8	id_type;
  guint8	protocol_id;
  guint16	port;
};

struct cert_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
  guint8	cert_enc;
};

struct certreq_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
  guint8	cert_type;
};

struct hash_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
};

struct sig_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
};

struct nonce_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
};

struct notif_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
  guint32	doi;
  guint8	protocol_id;
  guint8	spi_size;
  guint16	msgtype;
};

struct delete_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
  guint32	doi;
  guint8	protocol_id;
  guint8	spi_size;
  guint16	num_spis;
};

struct vid_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint16	length;
};

struct cfg_hdr {
  guint8	next_payload;
  guint8	reserved;
  guint8	length;
  guint8	type;
  guint8	reserved2;
  guint16	identifier;
};

static void dissect_none(const u_char *, int, frame_data *, proto_tree *);
static void dissect_sa(const u_char *, int, frame_data *, proto_tree *);
static void dissect_proposal(const u_char *, int, frame_data *, proto_tree *);
static void dissect_transform(const u_char *, int, frame_data *, proto_tree *,
		guint8);
static void dissect_key_exch(const u_char *, int, frame_data *, proto_tree *);
static void dissect_id(const u_char *, int, frame_data *, proto_tree *);
static void dissect_cert(const u_char *, int, frame_data *, proto_tree *);
static void dissect_certreq(const u_char *, int, frame_data *, proto_tree *);
static void dissect_hash(const u_char *, int, frame_data *, proto_tree *);
static void dissect_sig(const u_char *, int, frame_data *, proto_tree *);
static void dissect_nonce(const u_char *, int, frame_data *, proto_tree *);
static void dissect_notif(const u_char *, int, frame_data *, proto_tree *);
static void dissect_delete(const u_char *, int, frame_data *, proto_tree *);
static void dissect_vid(const u_char *, int, frame_data *, proto_tree *);
static void dissect_config(const u_char *, int, frame_data *, proto_tree *);

static const char *payloadtype2str(guint8);
static const char *exchtype2str(guint8);
static const char *doitype2str(guint32);
static const char *msgtype2str(guint16);
static const char *situation2str(guint32);
static const char *value2str(int, guint16, guint16);
static const char *num2str(const guint8 *, guint16);
static const char *attrtype2str(guint8);
static const char *cfgattrident2str(guint16);

#define NUM_LOAD_TYPES		15
#define loadtype2str(t)	\
  ((t < NUM_LOAD_TYPES) ? strfuncs[t].str : "Unknown payload type")
#define	LOAD_TYPE_TRANSFORM	3

static struct strfunc {
  const char *	str;
  void          (*func)(const u_char *, int, frame_data *, proto_tree *);
} strfuncs[NUM_LOAD_TYPES] = {
  {"NONE",			dissect_none      },
  {"Security Association",	dissect_sa        },
  {"Proposal",			dissect_proposal  },
  {"Transform",			NULL },
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

static void
dissect_isakmp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  
  struct isakmp_hdr *	hdr = (struct isakmp_hdr *)(pd + offset);
  guint32		len;
  
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "ISAKMP");
  
  len = pntohl(&hdr->length);
  
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "%s", exchtype2str(hdr->exch_type));
  
  if (IS_DATA_IN_FRAME(offset) && tree) {
    proto_item *	ti;
    proto_tree *	isakmp_tree;
    
    ti = proto_tree_add_item(tree, proto_isakmp, NullTVB, offset, len, NULL);
    isakmp_tree = proto_item_add_subtree(ti, ett_isakmp);
    
    proto_tree_add_text(isakmp_tree, NullTVB, offset, sizeof(hdr->icookie),
			"Initiator cookie");
    offset += sizeof(hdr->icookie);
    
    proto_tree_add_text(isakmp_tree, NullTVB, offset, sizeof(hdr->rcookie),
			"Responder cookie");
    offset += sizeof(hdr->rcookie);

    proto_tree_add_text(isakmp_tree, NullTVB, offset, sizeof(hdr->next_payload),
			"Next payload: %s (%u)",
			payloadtype2str(hdr->next_payload), hdr->next_payload);
    offset += sizeof(hdr->next_payload);

    proto_tree_add_text(isakmp_tree, NullTVB, offset, sizeof(hdr->version),
			"Version: %u.%u",
			hi_nibble(hdr->version), lo_nibble(hdr->version));
    offset += sizeof(hdr->version);
    
    proto_tree_add_text(isakmp_tree, NullTVB, offset, sizeof(hdr->exch_type),
			"Exchange type: %s (%u)",
			exchtype2str(hdr->exch_type), hdr->exch_type);
    offset += sizeof(hdr->exch_type);
    
    {
      proto_item *	fti;
      proto_tree *	ftree;
      
      fti   = proto_tree_add_text(isakmp_tree, NullTVB, offset, sizeof(hdr->flags), "Flags");
      ftree = proto_item_add_subtree(fti, ett_isakmp_flags);
      
      proto_tree_add_text(ftree, NullTVB, offset, 1, "%s",
			  decode_boolean_bitfield(hdr->flags, E_FLAG, sizeof(hdr->flags)*8,
						  "Encryption", "No encryption"));
      proto_tree_add_text(ftree, NullTVB, offset, 1, "%s",
			  decode_boolean_bitfield(hdr->flags, C_FLAG, sizeof(hdr->flags)*8,
						  "Commit", "No commit"));
      proto_tree_add_text(ftree, NullTVB, offset, 1, "%s",
			  decode_boolean_bitfield(hdr->flags, A_FLAG, sizeof(hdr->flags)*8,
						  "Authentication", "No authentication"));
      offset += sizeof(hdr->flags);
    }

    proto_tree_add_text(isakmp_tree, NullTVB, offset, sizeof(hdr->message_id), "Message ID");
    offset += sizeof(hdr->message_id);
    
    proto_tree_add_text(isakmp_tree, NullTVB, offset, sizeof(hdr->length),
			"Length: %u", len);
    offset += sizeof(hdr->length);

    if (hdr->flags & E_FLAG) {
      if (IS_DATA_IN_FRAME(offset) && isakmp_tree) {
        proto_tree_add_text(isakmp_tree, NullTVB, offset, END_OF_FRAME,
			"Encrypted payload (%d byte%s)",
			END_OF_FRAME, plurality(END_OF_FRAME, "", "s"));
      }
    } else {
      if (hdr->next_payload < NUM_LOAD_TYPES) {
        if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
          dissect_transform(pd, offset, fd, isakmp_tree, 0);	/* XXX - protocol ID? */
        else
          (*strfuncs[hdr->next_payload].func)(pd, offset, fd, isakmp_tree);
      }
      else
        dissect_data(pd, offset, fd, isakmp_tree);
    }
  }
}

static void
dissect_none(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
}

static void
dissect_sa(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct sa_hdr *	hdr	  = (struct sa_hdr *)(pd + offset);
  guint16		length	  = pntohs(&hdr->length);
  guint32		doi	  = pntohl(&hdr->doi);
  guint32		situation = pntohl(&hdr->situation);
  proto_item *		ti	  = proto_tree_add_text(tree, NullTVB, offset, length, "Security Association payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(doi),
		      "Domain of interpretation: %s (%u)",
		      doitype2str(doi), doi);
  offset += sizeof(doi);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(situation),
		      "Situation: %s (%u)",
		      situation2str(situation), situation);
  offset += sizeof(situation);
  
  dissect_proposal(pd, offset, fd, ntree);
  offset += (length - sizeof(*hdr));
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_proposal(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct proposal_hdr *	hdr	= (struct proposal_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Proposal payload");
  proto_tree *		ntree;

  int			next_hdr_offset = offset + length;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->proposal_num),
		      "Proposal number: %u", hdr->proposal_num);
  offset += sizeof(hdr->proposal_num);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->protocol_id),
		      "Protocol ID: %s (%u)",
		      proto2str(hdr->protocol_id), hdr->protocol_id);
  offset += sizeof(hdr->protocol_id);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->spi_size),
		      "SPI size: %u", hdr->spi_size);
  offset += sizeof(hdr->spi_size);

  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->num_transforms),
		      "Number of transforms: %u", hdr->num_transforms);
  offset += sizeof(hdr->num_transforms);

  if (hdr->spi_size) {
    proto_tree_add_text(ntree, NullTVB, offset, hdr->spi_size, "SPI");
    offset += hdr->spi_size;
  }

  if (hdr->num_transforms > 0)
    dissect_transform(pd, offset, fd, ntree, hdr->protocol_id);

  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, next_hdr_offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, next_hdr_offset, fd, tree);
  }
  else
    dissect_data(pd, next_hdr_offset, fd, tree);
}

static void
dissect_transform(const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree, guint8 protocol_id)
{

  struct trans_hdr *	hdr	= (struct trans_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Transform payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->transform_num),
		      "Transform number: %u", hdr->transform_num);
  offset += sizeof(hdr->transform_num);

  switch (protocol_id) {
  default:
  case 1:	/* ISAKMP */
    proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->transform_id),
			"Transform ID: %s (%u)",
			trans2str(hdr->transform_id), hdr->transform_id);
    break;
  case 2:	/* AH */
    proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->transform_id),
			"Transform ID: %s (%u)",
			ah_trans2str(hdr->transform_id), hdr->transform_id);
    break;
  case 3:	/* ESP */
    proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->transform_id),
			"Transform ID: %s (%u)",
			esp_trans2str(hdr->transform_id), hdr->transform_id);
    break;
  }
  offset += sizeof(hdr->transform_id) + sizeof(hdr->reserved2);
  
  length -= sizeof(*hdr);
  while (length) {
    const char *str = NULL;
    int ike_phase1 = 0;
    guint16 type    = pntohs(pd + offset) & 0x7fff;
    guint16 val_len = pntohs(pd + offset + 2);

    if (protocol_id == 1 && hdr->transform_id == 1) {
      ike_phase1 = 1;
      str = p1_atttype2str(type);
    }
    else {
      str = atttype2str(type);
    }

    if (pd[offset] & 0x80) {
      proto_tree_add_text(ntree, NullTVB, offset, 4,
			  "%s (%u): %s (%u)",
			  str, type,
			  value2str(ike_phase1, type, val_len), val_len);
      offset += 4;
      length -= 4;
    }
    else {
      guint16	pack_len = 4 + val_len;
      
      proto_tree_add_text(ntree, NullTVB, offset, pack_len,
			  "%s (%u): %s",
			  str, type,
			  num2str(pd + offset + 4, val_len));
      offset += pack_len;
      length -= pack_len;
    }
  }

  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, protocol_id);
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_key_exch(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct ke_hdr *	hdr	= (struct ke_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Key Exchange payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, length - sizeof(*hdr), "Key Exchange Data");
  offset += (length - sizeof(*hdr));
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_id(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct id_hdr *	hdr	= (struct id_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Identification payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->id_type),
		      "ID type: %s (%u)", id2str(hdr->id_type), hdr->id_type);
  offset += sizeof(hdr->id_type);

  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->protocol_id),
		      "Protocol ID: %u", hdr->protocol_id);
  offset += sizeof(hdr->protocol_id);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->port),
		      "Port: %u", pntohs(&hdr->port));
  offset += sizeof(hdr->port);
  
  switch (hdr->id_type) {
    case 1:
    case 4:
      proto_tree_add_text(ntree, NullTVB, offset, length-sizeof(*hdr),
			  "Identification data: %s", ip_to_str(pd+offset));
      break;
    case 2:
    case 3:
      proto_tree_add_text(ntree, NullTVB, offset, length-sizeof(*hdr),
			  "Identification data: %s", (char *)(pd+offset));
      break;
    default:
      proto_tree_add_text(ntree, NullTVB, offset, length - sizeof(*hdr), "Identification Data");
  }
  offset += (length - sizeof(*hdr));
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_cert(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct cert_hdr *	hdr	= (struct cert_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Certificate payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->cert_enc),
		      "Certificate encoding: %u", hdr->cert_enc);
  offset += sizeof(hdr->cert_enc);

  proto_tree_add_text(ntree, NullTVB, offset, length - sizeof(*hdr), "Certificate Data");
  offset += (length - sizeof(*hdr));
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_certreq(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct certreq_hdr *	hdr	= (struct certreq_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Certificate Request payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->cert_type),
		      "Certificate type: %u", hdr->cert_type);
  offset += sizeof(hdr->cert_type);

  proto_tree_add_text(ntree, NullTVB, offset, length - sizeof(*hdr), "Certificate Authority");
  offset += (length - sizeof(*hdr));
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_hash(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct hash_hdr *	hdr	= (struct hash_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Hash payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, length - sizeof(*hdr), "Hash Data");
  offset += (length - sizeof(*hdr));
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_sig(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct sig_hdr *	hdr	= (struct sig_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Signature payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, length - sizeof(*hdr), "Signature Data");
  offset += (length - sizeof(*hdr));
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_nonce(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct nonce_hdr *	hdr	= (struct nonce_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Nonce payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, length - sizeof(*hdr), "Nonce Data");
  offset += (length - sizeof(*hdr));
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_notif(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct notif_hdr *	hdr	= (struct notif_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  guint32		doi	= pntohl(&hdr->doi);
  guint16		msgtype = pntohs(&hdr->msgtype);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Notification payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(doi),
		      "Domain of Interpretation: %s (%u)", doitype2str(doi), doi);
  offset += sizeof(doi);

  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->protocol_id),
		      "Protocol ID: %s (%u)",
		      proto2str(hdr->protocol_id), hdr->protocol_id);
  offset += sizeof(hdr->protocol_id);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->spi_size),
		      "SPI size: %u", hdr->spi_size);
  offset += sizeof(hdr->spi_size);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(msgtype),
		      "Message type: %s (%u)", msgtype2str(msgtype), msgtype);
  offset += sizeof(msgtype);

  if (hdr->spi_size) {
    proto_tree_add_text(ntree, NullTVB, offset, hdr->spi_size, "Security Parameter Index");
    offset += hdr->spi_size;
  }

  if (length - sizeof(*hdr)) {
    proto_tree_add_text(ntree, NullTVB, offset, length - sizeof(*hdr) - hdr->spi_size,
			"Notification Data");
    offset += (length - sizeof(*hdr) - hdr->spi_size);
  }
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_delete(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct delete_hdr *	hdr	 = (struct delete_hdr *)(pd + offset);
  guint16		length	 = pntohs(&hdr->length);
  guint32		doi	 = pntohl(&hdr->doi);
  guint16		num_spis = pntohs(&hdr->num_spis);
  proto_item *		ti	 = proto_tree_add_text(tree, NullTVB, offset, length, "Delete payload");
  proto_tree *		ntree;
  guint16		i;
  
  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(doi),
		      "Domain of Interpretation: %s (%u)", doitype2str(doi), doi);
  offset += sizeof(doi);

  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->protocol_id),
		      "Protocol ID: %s (%u)",
		      proto2str(hdr->protocol_id), hdr->protocol_id);
  offset += sizeof(hdr->protocol_id);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->spi_size),
		      "SPI size: %u", hdr->spi_size);
  offset += sizeof(hdr->spi_size);
  
  proto_tree_add_text(ntree, NullTVB, offset, num_spis,
		      "Number of SPIs: %u", num_spis);
  offset += sizeof(hdr->num_spis);
  
  for (i = 0; i < num_spis; ++i) {
    proto_tree_add_text(ntree, NullTVB, offset, hdr->spi_size,
			"SPI (%d)", i);
    offset += hdr->spi_size;
  }

  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_vid(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct vid_hdr *	hdr	= (struct vid_hdr *)(pd + offset);
  guint16		length	= pntohs(&hdr->length);
  proto_item *		ti	= proto_tree_add_text(tree, NullTVB, offset, length, "Vendor ID payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) * 2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		      "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree, NullTVB, offset, length - sizeof(*hdr), "Vendor ID");
  offset += (length - sizeof(*hdr));
  
  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);	/* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
}

static void
dissect_config(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct cfg_hdr * 	hdr	 = (struct cfg_hdr *)(pd + offset);
  guint16		length	 = pntohs(&hdr->length);
  proto_item *		ti	 = proto_tree_add_text(tree, NullTVB, offset, length, "Attribute payload");
  proto_tree *		ntree;

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);

  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->next_payload),
		      "Next payload: %s (%u)",
		      payloadtype2str(hdr->next_payload), hdr->next_payload);
  offset += sizeof(hdr->next_payload) *2;
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(length),
		     "Length: %u", length);
  offset += sizeof(length);
  
  proto_tree_add_text(ntree,NullTVB, offset, sizeof(hdr->type),
		      "Type %s (%u)",attrtype2str(hdr->type),hdr->type);
  
  offset += (sizeof(hdr->type) + sizeof(hdr->reserved2));
  
  proto_tree_add_text(ntree, NullTVB, offset, sizeof(hdr->identifier),
                      "Identifier: %u",hdr->identifier);
  offset += sizeof(hdr->identifier);
  length -= sizeof(*hdr);
  
  while(length) {
    guint16 type = pntohs(pd + offset) & 0x7fff;
    guint16 val_len = pntohs(pd + offset + 2);
    
    if(pd[offset] & 0x80) {
      proto_tree_add_text(ntree, NullTVB, offset, 4,
			  "%s (%u)",cfgattrident2str(type),val_len);
      offset += 4;
      length -= 4;
    }
    else {
      guint pack_len = 4 + val_len;

      proto_tree_add_text(ntree, NullTVB, offset, 4,
			  "%s (%se)", cfgattrident2str(type), num2str(pd + offset + 4, val_len));
      offset += pack_len;
      length -= pack_len;
    }
  }

  if (hdr->next_payload < NUM_LOAD_TYPES) {
    if (hdr->next_payload == LOAD_TYPE_TRANSFORM)
      dissect_transform(pd, offset, fd, tree, 0);       /* XXX - protocol ID? */
    else
      (*strfuncs[hdr->next_payload].func)(pd, offset, fd, tree);
  }
  else
    dissect_data(pd, offset, fd, tree);
 
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
  
  if (type & SIT_IDENTITY) {
    n += snprintf(msg, SIT_MSG_NUM-n, "%sIDENTITY", sep);
    sep = " & ";
  }
  if (type & SIT_SECRECY) {
    n += snprintf(msg, SIT_MSG_NUM-n, "%sSECRECY", sep);
    sep = " & ";
  }
  if (type & SIT_INTEGRITY) {
    n += snprintf(msg, SIT_MSG_NUM-n, "%sINTEGRITY", sep);
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
        default: return "UNKNOWN-ENCAPSULATION-VALUE";
      }
    case 5:
      switch (value) {
        case 1:  return "HMAC-MD5";
        case 2:  return "HMAC-SHA";
        case 3:  return "DES-MAC";
        case 4:  return "KPDK";
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
          default: return "UNKNOWN-ENCRYPTION-ALG";
        }
      case 2:
        switch (value) {
          case 1:  return "MD5";
          case 2:  return "SHA";
          case 3:  return "TIGER";
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
num2str(const guint8 *pd, guint16 len) {

#define NUMSTR_LEN	1024
  static char		numstr[NUMSTR_LEN];
  
  switch (len) {
  case 1:
    snprintf(numstr, NUMSTR_LEN, "%u", *pd);
    break;
  case 2:
    snprintf(numstr, NUMSTR_LEN, "%u", pntohs(pd));
    break;
  case 3:
    snprintf(numstr, NUMSTR_LEN, "%u", pntohl(pd) & 0x0fff);
    break;
  case 4:
    snprintf(numstr, NUMSTR_LEN, "%u", pntohl(pd));
    break;
  default:
    snprintf(numstr, NUMSTR_LEN, "<too big>");
  }

  return numstr;
}

void
proto_register_isakmp(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "isakmp.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_isakmp,
		&ett_isakmp_flags,
		&ett_isakmp_payload,
	};

        proto_isakmp = proto_register_protocol("Internet Security Association and Key Management Protocol", "isakmp");
 /*       proto_register_field_array(proto_isakmp, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_isakmp(void)
{
	dissector_add("udp.port", UDP_PORT_ISAKMP, dissect_isakmp);
}
