/* packet-nbns.c
 * Routines for NetBIOS-over-TCP packet disassembly (the name dates back
 * to when it had only NBNS)
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id$
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

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include "packet-dns.h"
#include "packet-netbios.h"
#include "packet-tcp.h"
#include "packet-frame.h"
#include <epan/prefs.h>

static int proto_nbns = -1;
static int hf_nbns_flags = -1;
static int hf_nbns_flags_response = -1;
static int hf_nbns_flags_opcode = -1;
static int hf_nbns_flags_authoritative = -1;
static int hf_nbns_flags_truncated = -1;
static int hf_nbns_flags_recdesired = -1;
static int hf_nbns_flags_recavail = -1;
static int hf_nbns_flags_broadcast = -1;
static int hf_nbns_flags_rcode = -1;
static int hf_nbns_transaction_id = -1;
static int hf_nbns_count_questions = -1;
static int hf_nbns_count_answers = -1;
static int hf_nbns_count_auth_rr = -1;
static int hf_nbns_count_add_rr = -1;

static gint ett_nbns = -1;
static gint ett_nbns_qd = -1;
static gint ett_nbns_flags = -1;
static gint ett_nbns_nb_flags = -1;
static gint ett_nbns_name_flags = -1;
static gint ett_nbns_rr = -1;
static gint ett_nbns_qry = -1;
static gint ett_nbns_ans = -1;

static int proto_nbdgm = -1;
static int hf_nbdgm_type = -1;
static int hf_nbdgm_fragment = -1;
static int hf_nbdgm_first = -1;
static int hf_nbdgm_node_type = -1;
static int hf_nbdgm_datagram_id = -1;
static int hf_nbdgm_src_ip = -1;
static int hf_nbdgm_src_port = -1;

static gint ett_nbdgm = -1;

static int proto_nbss = -1;
static int hf_nbss_type = -1;
static int hf_nbss_flags = -1;

static gint ett_nbss = -1;
static gint ett_nbss_flags = -1;

/* desegmentation of NBSS over TCP */
static gboolean nbss_desegment = TRUE;

/* See RFC 1001 and 1002 for information on the first three, and see

	http://www.cifs.com/specs/draft-leach-cifs-v1-spec-01.txt

   Appendix B, and various messages on the CIFS mailing list such as

	http://discuss.microsoft.com/SCRIPTS/WA-MSD.EXE?A2=ind9811A&L=cifs&P=R386

   for information on the fourth. */
#define UDP_PORT_NBNS	137
#define UDP_PORT_NBDGM	138
#define TCP_PORT_NBSS	139
#define TCP_PORT_CIFS	445

/* Packet structure taken from RFC 1002. See also RFC 1001.
 * Opcode, flags, and rcode treated as "flags", similarly to DNS,
 * to make it easier to lift the dissection code from "packet-dns.c". */

/* Offsets of fields in the NBNS header. */
#define	NBNS_ID		0
#define	NBNS_FLAGS	2
#define	NBNS_QUEST	4
#define	NBNS_ANS	6
#define	NBNS_AUTH	8
#define	NBNS_ADD	10

/* Length of NBNS header. */
#define	NBNS_HDRLEN	12

/* type values  */
#define T_NB            32              /* NetBIOS name service RR */
#define T_NBSTAT        33              /* NetBIOS node status RR */

/* Bit fields in the flags */
#define F_RESPONSE      (1<<15)         /* packet is response */
#define F_OPCODE        (0xF<<11)       /* query opcode */
#define OPCODE_SHIFT	11
#define F_AUTHORITATIVE (1<<10)         /* response is authoritative */
#define F_TRUNCATED     (1<<9)          /* response is truncated */
#define F_RECDESIRED    (1<<8)          /* recursion desired */
#define F_RECAVAIL      (1<<7)          /* recursion available */
#define F_BROADCAST     (1<<4)          /* broadcast/multicast packet */
#define F_RCODE         (0xF<<0)        /* reply code */

static const true_false_string tfs_flags_response = {
	"Message is a response",
	"Message is a query"
};

static const true_false_string tfs_flags_authoritative = {
	"Server is an authority for domain",
	"Server is not an authority for domain"
};

static const true_false_string tfs_flags_truncated = {
	"Message is truncated",
	"Message is not truncated"
};

static const true_false_string tfs_flags_recdesired = {
	"Do query recursively",
	"Don't do query recursively"
};

static const true_false_string tfs_flags_recavail = {
	"Server can do recursive queries",
	"Server can't do recursive queries"
};

static const true_false_string tfs_flags_broadcast = {
	"Broadcast packet",
	"Not a broadcast packet"
};

/* Opcodes */
#define OPCODE_QUERY          0         /* standard query */
#define OPCODE_REGISTRATION   5         /* registration */
#define OPCODE_RELEASE        6         /* release name */
#define OPCODE_WACK           7         /* wait for acknowledgement */
#define OPCODE_REFRESH        8         /* refresh registration */
#define OPCODE_REFRESHALT     9         /* refresh registration (alternate opcode) */
#define OPCODE_MHREGISTRATION 15        /* multi-homed registration */

static const value_string opcode_vals[] = {
	  { OPCODE_QUERY,          "Name query"                 },
	  { OPCODE_REGISTRATION,   "Registration"               },
	  { OPCODE_RELEASE,        "Release"                    },
	  { OPCODE_WACK,           "Wait for acknowledgment"    },
	  { OPCODE_REFRESH,        "Refresh"                    },
	  { OPCODE_REFRESHALT,     "Refresh (alternate opcode)" },
	  { OPCODE_MHREGISTRATION, "Multi-homed registration"   },
	  { 0,                     NULL                         }
};

/* Reply codes */
#define RCODE_NOERROR   0
#define RCODE_FMTERROR  1
#define RCODE_SERVFAIL  2
#define RCODE_NAMEERROR 3
#define RCODE_NOTIMPL   4
#define RCODE_REFUSED   5
#define RCODE_ACTIVE    6
#define RCODE_CONFLICT  7

static const value_string rcode_vals[] = {
	  { RCODE_NOERROR,   "No error"                        },
	  { RCODE_FMTERROR,  "Request was invalidly formatted" },
	  { RCODE_SERVFAIL,  "Server failure"                  },
	  { RCODE_NAMEERROR, "Requested name does not exist"   },
	  { RCODE_NOTIMPL,   "Request is not implemented"      },
	  { RCODE_REFUSED,   "Request was refused"             },
	  { RCODE_ACTIVE,    "Name is owned by another node"   },
	  { RCODE_CONFLICT,  "Name is in conflict"             },
	  { 0,               NULL                              }
};

/* Values for the "NB_FLAGS" field of RR data.  From RFC 1001 and 1002,
 * except for NB_FLAGS_ONT_H_NODE, which was discovered by looking at
 * packet traces. */
#define	NB_FLAGS_ONT		(3<<(15-2))	/* bits for node type */
#define	NB_FLAGS_ONT_B_NODE	(0<<(15-2))	/* B-mode node */
#define	NB_FLAGS_ONT_P_NODE	(1<<(15-2))	/* P-mode node */
#define	NB_FLAGS_ONT_M_NODE	(2<<(15-2))	/* M-mode node */
#define	NB_FLAGS_ONT_H_NODE	(3<<(15-2))	/* H-mode node */

#define	NB_FLAGS_G		(1<<(15-0))	/* group name */

/* Values for the "NAME_FLAGS" field of a NODE_NAME entry in T_NBSTAT
 * RR data.  From RFC 1001 and 1002, except for NAME_FLAGS_ONT_H_NODE,
 * which was discovered by looking at packet traces. */
#define	NAME_FLAGS_PRM		(1<<(15-6))	/* name is permanent node name */

#define	NAME_FLAGS_ACT		(1<<(15-5))	/* name is active */

#define	NAME_FLAGS_CNF		(1<<(15-4))	/* name is in conflict */

#define	NAME_FLAGS_DRG		(1<<(15-3))	/* name is being deregistered */

#define	NAME_FLAGS_ONT		(3<<(15-2))	/* bits for node type */
#define	NAME_FLAGS_ONT_B_NODE	(0<<(15-2))	/* B-mode node */
#define	NAME_FLAGS_ONT_P_NODE	(1<<(15-2))	/* P-mode node */
#define	NAME_FLAGS_ONT_M_NODE	(2<<(15-2))	/* M-mode node */

#define	NAME_FLAGS_G		(1<<(15-0))	/* group name */

static const char *
nbns_type_name (int type)
{
	switch (type) {
	case T_NB:
		return "NB";
	case T_NBSTAT:
		return "NBSTAT";
	}

	return "unknown";
}

#define NBNAME_BUF_LEN 128

static proto_tree *
add_rr_to_tree(proto_item *trr, int rr_type, tvbuff_t *tvb, int offset,
			   const char *name, int namelen,
			   const char *type_name, const char *class_description,
			   guint ttl, gushort data_len)
{
	proto_tree *rr_tree;
	
	rr_tree = proto_item_add_subtree(trr, rr_type);
	proto_tree_add_text(rr_tree, tvb, offset+1, namelen-1, "Name: %s", name);
	offset += namelen;
	proto_tree_add_text(rr_tree, tvb, offset, 2, "Type: %s", type_name);
	offset += 2;
	proto_tree_add_text(rr_tree, tvb, offset, 2, "Class: %s", class_description);
	offset += 2;
	proto_tree_add_text(rr_tree, tvb, offset, 4, "Time to live: %s",
	    time_secs_to_str(ttl));
	offset += 4;
	proto_tree_add_text(rr_tree, tvb, offset, 2, "Data length: %u", data_len);
	return rr_tree;
}

static int
get_nbns_name(tvbuff_t *tvb, int offset, int nbns_data_offset,
    char *name_ret, int *name_type_ret)
{
	int name_len;
	char name[MAXDNAME];
	char nbname[NBNAME_BUF_LEN];
	char *pname, *pnbname, cname, cnbname;
	int name_type;

	name_len = get_dns_name(tvb, offset, nbns_data_offset, name,
	    sizeof(name));

	/* OK, now undo the first-level encoding. */
	pname = &name[0];
	pnbname = &nbname[0];
	for (;;) {
		/* Every two characters of the first level-encoded name
		 * turn into one character in the decoded name. */
		cname = *pname;
		if (cname == '\0')
			break;		/* no more characters */
		if (cname == '.')
			break;		/* scope ID follows */
		if (cname < 'A' || cname > 'Z') {
			/* Not legal. */
			strcpy(nbname,
			    "Illegal NetBIOS name (character not between A and Z in first-level encoding)");
			goto bad;
		}
		cname -= 'A';
		cnbname = cname << 4;
		pname++;

		cname = *pname;
		if (cname == '\0' || cname == '.') {
			/* No more characters in the name - but we're in
			 * the middle of a pair.  Not legal. */
			strcpy(nbname,
			    "Illegal NetBIOS name (odd number of bytes)");
			goto bad;
		}
		if (cname < 'A' || cname > 'Z') {
			/* Not legal. */
			strcpy(nbname,
			    "Illegal NetBIOS name (character not between A and Z in first-level encoding)");
			goto bad;
		}
		cname -= 'A';
		cnbname |= cname;
		pname++;

		/* Do we have room to store the character? */
		if (pnbname < &nbname[NETBIOS_NAME_LEN]) {
			/* Yes - store the character. */
			*pnbname = cnbname;
		}

		/* We bump the pointer even if it's past the end of the
		   name, so we keep track of how long the name is. */
		pnbname++;
	}

	/* NetBIOS names are supposed to be exactly 16 bytes long. */
	if (pnbname - nbname != NETBIOS_NAME_LEN) {
		/* It's not. */
		sprintf(nbname, "Illegal NetBIOS name (%ld bytes long)",
		    (long)(pnbname - nbname));
		goto bad;
	}

	/* This one is; make its name printable. */
	name_type = process_netbios_name(nbname, name_ret);
	name_ret += strlen(name_ret);
	sprintf(name_ret, "<%02x>", name_type);
	name_ret += 4;
	if (cname == '.') {
		/* We have a scope ID, starting at "pname"; append that to
		 * the decoded host name. */
		strcpy(name_ret, pname);
	}
	if (name_type_ret != NULL)
		*name_type_ret = name_type;
	return name_len;

bad:
	if (name_type_ret != NULL)
		*name_type_ret = -1;
	strcpy (name_ret, nbname);
	return name_len;
}


static int
get_nbns_name_type_class(tvbuff_t *tvb, int offset, int nbns_data_offset,
    char *name_ret, int *name_len_ret, int *name_type_ret, int *type_ret,
    int *class_ret)
{
	int name_len;
	int type;
	int class;

	name_len = get_nbns_name(tvb, offset, nbns_data_offset, name_ret,
	   name_type_ret);
	offset += name_len;

	type = tvb_get_ntohs(tvb, offset);
	offset += 2;

	class = tvb_get_ntohs(tvb, offset);

	*type_ret = type;
	*class_ret = class;
	*name_len_ret = name_len;

	return name_len + 4;
}

static void
add_name_and_type(proto_tree *tree, tvbuff_t *tvb, int offset, int len,
    const char *tag, const char *name, int name_type)
{
	if (name_type != -1) {
		proto_tree_add_text(tree, tvb, offset, len, "%s: %s (%s)",
		    tag, name, netbios_name_type_descr(name_type));
	} else {
		proto_tree_add_text(tree, tvb, offset, len, "%s: %s",
		    tag, name);
	}
}

static int
dissect_nbns_query(tvbuff_t *tvb, int offset, int nbns_data_offset,
    column_info *cinfo, proto_tree *nbns_tree)
{
	int len;
	char name[(NETBIOS_NAME_LEN - 1)*4 + MAXDNAME];
	int name_len;
	int name_type;
	int type;
	int class;
	const char *type_name;
	int data_offset;
	int data_start;
	proto_tree *q_tree;
	proto_item *tq;

	data_start = data_offset = offset;

	len = get_nbns_name_type_class(tvb, offset, nbns_data_offset, name,
	    &name_len, &name_type, &type, &class);
	data_offset += len;

	type_name = nbns_type_name(type);

	if (cinfo != NULL)
		col_append_fstr(cinfo, COL_INFO, " %s %s", type_name, name);
	if (nbns_tree != NULL) {
		tq = proto_tree_add_text(nbns_tree, tvb, offset, len,
		    "%s: type %s, class %s",  name, type_name,
		    dns_class_name(class));
		q_tree = proto_item_add_subtree(tq, ett_nbns_qd);

		add_name_and_type(q_tree, tvb, offset, name_len, "Name", name,
		    name_type);
		offset += name_len;

		proto_tree_add_text(q_tree, tvb, offset, 2, "Type: %s", type_name);
		offset += 2;

		proto_tree_add_text(q_tree, tvb, offset, 2, "Class: %s",
		    dns_class_name(class));
		offset += 2;
	}

	return data_offset - data_start;
}

static void
nbns_add_nbns_flags(column_info *cinfo, proto_tree *nbns_tree, tvbuff_t *tvb, int offset,
		    gushort flags, int is_wack)
{
	char buf[128+1];
	guint16 opcode;
	proto_tree *field_tree;
	proto_item *tf;

	opcode = (guint16) ((flags & F_OPCODE) >> OPCODE_SHIFT);
	strcpy(buf, val_to_str(opcode, opcode_vals, "Unknown operation"));
	if (flags & F_RESPONSE && !is_wack) {
		strcat(buf, " response");
		strcat(buf, ", ");
		strcat(buf, val_to_str(flags & F_RCODE, rcode_vals,
		    "Unknown error"));

		if ((flags & F_RCODE) && check_col(cinfo, COL_INFO))
			col_append_fstr(cinfo, COL_INFO, ", %s",
					val_to_str(flags & F_RCODE, rcode_vals,
						   "Unknown error"));
	}
	tf = proto_tree_add_uint_format(nbns_tree, hf_nbns_flags,
	    tvb, offset, 2, flags, "Flags: 0x%04x (%s)", flags, buf);
	field_tree = proto_item_add_subtree(tf, ett_nbns_flags);
	proto_tree_add_item(field_tree, hf_nbns_flags_response,
	    tvb, offset, 2, FALSE);
	proto_tree_add_item(field_tree, hf_nbns_flags_opcode,
	    tvb, offset, 2, FALSE);
	if (flags & F_RESPONSE) {
		proto_tree_add_item(field_tree, hf_nbns_flags_authoritative,
			  tvb, offset, 2, FALSE);
	}
	proto_tree_add_item(field_tree, hf_nbns_flags_truncated,
	    tvb, offset, 2, FALSE);
	proto_tree_add_item(field_tree, hf_nbns_flags_recdesired,
	    tvb, offset, 2, FALSE);
	if (flags & F_RESPONSE) {
		proto_tree_add_item(field_tree, hf_nbns_flags_recavail,
		    tvb, offset, 2, FALSE);
	}
	proto_tree_add_item(field_tree, hf_nbns_flags_broadcast,
	    tvb, offset, 2, FALSE);
	if (flags & F_RESPONSE && !is_wack) {
		proto_tree_add_item(field_tree, hf_nbns_flags_rcode,
		    tvb, offset, 2, FALSE);
	}
}

static void
nbns_add_nb_flags(proto_tree *rr_tree, tvbuff_t *tvb, int offset, gushort flags)
{
	char buf[128+1];
	proto_tree *field_tree;
	proto_item *tf;
	static const value_string nb_flags_ont_vals[] = {
		  { NB_FLAGS_ONT_B_NODE, "B-node" },
		  { NB_FLAGS_ONT_P_NODE, "P-node" },
		  { NB_FLAGS_ONT_M_NODE, "M-node" },
		  { NB_FLAGS_ONT_H_NODE, "H-node" },
		  { 0,                   NULL     }
	};

	strcpy(buf, val_to_str(flags & NB_FLAGS_ONT, nb_flags_ont_vals,
	    "Unknown"));
	strcat(buf, ", ");
	if (flags & NB_FLAGS_G)
		strcat(buf, "group");
	else
		strcat(buf, "unique");
	tf = proto_tree_add_text(rr_tree, tvb, offset, 2, "Flags: 0x%x (%s)", flags,
			buf);
	field_tree = proto_item_add_subtree(tf, ett_nbns_nb_flags);
	proto_tree_add_text(field_tree, tvb, offset, 2, "%s",
			decode_boolean_bitfield(flags, NB_FLAGS_G,
				2*8,
				"Group name",
				"Unique name"));
	proto_tree_add_text(field_tree, tvb, offset, 2, "%s",
			decode_enumerated_bitfield(flags, NB_FLAGS_ONT,
				2*8, nb_flags_ont_vals, "%s"));
}

static void
nbns_add_name_flags(proto_tree *rr_tree, tvbuff_t *tvb, int offset,
    gushort flags)
{
	char buf[128+1];
	proto_item *field_tree;
	proto_item *tf;
	static const value_string name_flags_ont_vals[] = {
		  { NAME_FLAGS_ONT_B_NODE, "B-node" },
		  { NAME_FLAGS_ONT_P_NODE, "P-node" },
		  { NAME_FLAGS_ONT_M_NODE, "M-node" },
		  { 0,                     NULL     }
	};

	strcpy(buf, val_to_str(flags & NAME_FLAGS_ONT, name_flags_ont_vals,
	    "Unknown"));
	strcat(buf, ", ");
	if (flags & NAME_FLAGS_G)
		strcat(buf, "group");
	else
		strcat(buf, "unique");
	if (flags & NAME_FLAGS_DRG)
		strcat(buf, ", being deregistered");
	if (flags & NAME_FLAGS_CNF)
		strcat(buf, ", in conflict");
	if (flags & NAME_FLAGS_ACT)
		strcat(buf, ", active");
	if (flags & NAME_FLAGS_PRM)
		strcat(buf, ", permanent node name");
	tf = proto_tree_add_text(rr_tree, tvb, offset, 2, "Name flags: 0x%x (%s)",
			flags, buf);
	field_tree = proto_item_add_subtree(tf, ett_nbns_name_flags);
	proto_tree_add_text(field_tree, tvb, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_G,
				2*8,
				"Group name",
				"Unique name"));
	proto_tree_add_text(field_tree, tvb, offset, 2, "%s",
			decode_enumerated_bitfield(flags, NAME_FLAGS_ONT,
				2*8, name_flags_ont_vals, "%s"));
	proto_tree_add_text(field_tree, tvb, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_DRG,
				2*8,
				"Name is being deregistered",
				"Name is not being deregistered"));
	proto_tree_add_text(field_tree, tvb, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_CNF,
				2*8,
				"Name is in conflict",
				"Name is not in conflict"));
	proto_tree_add_text(field_tree, tvb, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_ACT,
				2*8,
				"Name is active",
				"Name is not active"));
	proto_tree_add_text(field_tree, tvb, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_PRM,
				2*8,
				"Permanent node name",
				"Not permanent node name"));
}

static int
dissect_nbns_answer(tvbuff_t *tvb, int offset, int nbns_data_offset,
    column_info *cinfo, proto_tree *nbns_tree, int opcode)
{
	int len;
	char name[(NETBIOS_NAME_LEN - 1)*4 + MAXDNAME + 64];
	int name_len;
	int name_type;
	int type;
	int class;
	const char *class_name;
	const char *type_name;
	int data_offset;
	int cur_offset;
	int data_start;
	guint ttl;
	gushort data_len;
	gushort flags;
	proto_tree *rr_tree;
	proto_item *trr;
	char name_str[(NETBIOS_NAME_LEN - 1)*4 + 1];
	guint num_names;
	char nbname[16+4+1];	/* 4 for [<last char>] */
	gushort name_flags;

	data_start = data_offset = offset;
	cur_offset = offset;

	len = get_nbns_name_type_class(tvb, offset, nbns_data_offset, name,
	    &name_len, &name_type, &type, &class);
	data_offset += len;
	cur_offset += len;

	type_name = nbns_type_name(type);
	class_name = dns_class_name(class);

	ttl = tvb_get_ntohl(tvb, data_offset);
	data_offset += 4;
	cur_offset += 4;

	data_len = tvb_get_ntohs(tvb, data_offset);
	data_offset += 2;
	cur_offset += 2;

	switch (type) {
	case T_NB: 		/* "NB" record */
		if (cinfo != NULL) {
			if (opcode != OPCODE_WACK) {
				col_append_fstr(cinfo, COL_INFO, " %s %s",
				    type_name,
				    ip_to_str(tvb_get_ptr(tvb, data_offset+2, 4)));
			}
		}
		if (nbns_tree == NULL)
			break;
		trr = proto_tree_add_text(nbns_tree, tvb, offset,
		    (data_offset - data_start) + data_len,
		    "%s: type %s, class %s",
		    name, type_name, class_name);
		strcat(name, " (");
		strcat(name, netbios_name_type_descr(name_type));
		strcat(name, ")");
		rr_tree = add_rr_to_tree(trr, ett_nbns_rr, tvb, offset, name,
		    name_len, type_name, dns_class_name(class), ttl, data_len);
		while (data_len > 0) {
			if (opcode == OPCODE_WACK) {
				/* WACK response.  This doesn't contain the
				 * same type of RR data as other T_NB
				 * responses.  */
				if (data_len < 2) {
					proto_tree_add_text(rr_tree, tvb, cur_offset,
					    data_len, "(incomplete entry)");
					break;
				}
				flags = tvb_get_ntohs(tvb, cur_offset);
				nbns_add_nbns_flags(cinfo, rr_tree, tvb, cur_offset,
				    flags, 1);
				cur_offset += 2;
				data_len -= 2;
			} else {
				if (data_len < 2) {
					proto_tree_add_text(rr_tree, tvb, cur_offset,
					    data_len, "(incomplete entry)");
					break;
				}
				flags = tvb_get_ntohs(tvb, cur_offset);
				nbns_add_nb_flags(rr_tree, tvb, cur_offset,
				    flags);
				cur_offset += 2;
				data_len -= 2;

				if (data_len < 4) {
					proto_tree_add_text(rr_tree, tvb, cur_offset,
					    data_len, "(incomplete entry)");
					break;
				}
				proto_tree_add_text(rr_tree, tvb, cur_offset, 4,
				    "Addr: %s",
				    ip_to_str(tvb_get_ptr(tvb, cur_offset, 4)));
				cur_offset += 4;
				data_len -= 4;
			}
		}
		break;

	case T_NBSTAT: 	/* "NBSTAT" record */
		if (cinfo != NULL)
			col_append_fstr(cinfo, COL_INFO, " %s", type_name);
		if (nbns_tree == NULL)
			break;
		trr = proto_tree_add_text(nbns_tree, tvb, offset,
		    (data_offset - data_start) + data_len,
		    "%s: type %s, class %s",
		    name, type_name, class_name);
		rr_tree = add_rr_to_tree(trr, ett_nbns_rr, tvb, offset, name,
		    name_len, type_name, dns_class_name(class), ttl, data_len);
		if (data_len < 1) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		num_names = tvb_get_guint8(tvb, cur_offset);
		proto_tree_add_text(rr_tree, tvb, cur_offset, 1,
		    "Number of names: %u", num_names);
		cur_offset += 1;

		while (num_names != 0) {
			if (data_len < NETBIOS_NAME_LEN) {
				proto_tree_add_text(rr_tree, tvb, cur_offset,
				    data_len, "(incomplete entry)");
				goto out;
			}
			tvb_memcpy(tvb, (guint8 *)nbname, cur_offset,
			    NETBIOS_NAME_LEN);
			name_type = process_netbios_name(nbname,
			    name_str);
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    NETBIOS_NAME_LEN, "Name: %s<%02x> (%s)",
			    name_str, name_type,
			    netbios_name_type_descr(name_type));
			cur_offset += NETBIOS_NAME_LEN;
			data_len -= NETBIOS_NAME_LEN;

			if (data_len < 2) {
				proto_tree_add_text(rr_tree, tvb, cur_offset,
				    data_len, "(incomplete entry)");
				goto out;
			}
			name_flags = tvb_get_ntohs(tvb, cur_offset);
			nbns_add_name_flags(rr_tree, tvb, cur_offset,
			    name_flags);
			cur_offset += 2;
			data_len -= 2;

			num_names--;
		}

		if (data_len < 6) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 6,
		    "Unit ID: %s",
		    ether_to_str(tvb_get_ptr(tvb, cur_offset, 6)));
		cur_offset += 6;
		data_len -= 6;

		if (data_len < 1) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 1,
		    "Jumpers: 0x%x", tvb_get_guint8(tvb, cur_offset));
		cur_offset += 1;
		data_len -= 1;

		if (data_len < 1) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 1,
		    "Test result: 0x%x", tvb_get_guint8(tvb, cur_offset));
		cur_offset += 1;
		data_len -= 1;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Version number: 0x%x", tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Period of statistics: 0x%x",
		    tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Number of CRCs: %u", tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Number of alignment errors: %u",
		    tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Number of collisions: %u", tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Number of send aborts: %u", tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 4) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 4,
		    "Number of good sends: %u", tvb_get_ntohl(tvb, cur_offset));
		cur_offset += 4;
		data_len -= 4;

		if (data_len < 4) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 4,
		    "Number of good receives: %u",
		    tvb_get_ntohl(tvb, cur_offset));
		cur_offset += 4;
		data_len -= 4;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Number of retransmits: %u", tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Number of no resource conditions: %u",
		    tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Number of command blocks: %u",
		    tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Number of pending sessions: %u",
		    tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Max number of pending sessions: %u",
		    tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Max total sessions possible: %u",
		    tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;

		if (data_len < 2) {
			proto_tree_add_text(rr_tree, tvb, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, tvb, cur_offset, 2,
		    "Session data packet size: %u",
		    tvb_get_ntohs(tvb, cur_offset));
		cur_offset += 2;
		data_len -= 2;
	out:
		break;

	default:
		if (cinfo != NULL)
			col_append_fstr(cinfo, COL_INFO, " %s", type_name);
		if (nbns_tree == NULL)
			break;
		trr = proto_tree_add_text(nbns_tree, tvb, offset,
		    (data_offset - data_start) + data_len,
                    "%s: type %s, class %s",
		    name, type_name, class_name);
		rr_tree = add_rr_to_tree(trr, ett_nbns_rr, tvb, offset, name,
		    name_len, type_name, dns_class_name(class), ttl, data_len);
		proto_tree_add_text(rr_tree, tvb, cur_offset, data_len, "Data");
		cur_offset += data_len;
		break;
	}

	return cur_offset - data_start;
}

static int
dissect_query_records(tvbuff_t *tvb, int cur_off, int nbns_data_offset,
    int count, column_info *cinfo, proto_tree *nbns_tree)
{
	int start_off, add_off;
	proto_tree *qatree = NULL;
	proto_item *ti = NULL;

	start_off = cur_off;
	if (nbns_tree != NULL) {
		ti = proto_tree_add_text(nbns_tree, tvb, start_off, -1, "Queries");
		qatree = proto_item_add_subtree(ti, ett_nbns_qry);
	}
	while (count-- > 0) {
		add_off = dissect_nbns_query(tvb, cur_off, nbns_data_offset,
		    cinfo, qatree);
		cur_off += add_off;
	}
	if (ti != NULL)
		proto_item_set_len(ti, cur_off - start_off);

	return cur_off - start_off;
}



static int
dissect_answer_records(tvbuff_t *tvb, int cur_off, int nbns_data_offset,
    int count, column_info *cinfo, proto_tree *nbns_tree, int opcode,
    const char *name)
{
	int start_off, add_off;
	proto_tree *qatree = NULL;
	proto_item *ti = NULL;

	start_off = cur_off;
	if (nbns_tree != NULL) {
		ti = proto_tree_add_text(nbns_tree, tvb, start_off, -1, name);
		qatree = proto_item_add_subtree(ti, ett_nbns_ans);
	}
	while (count-- > 0) {
		add_off = dissect_nbns_answer(tvb, cur_off, nbns_data_offset,
					cinfo, qatree, opcode);
		cur_off += add_off;
	}
	if (ti != NULL)
		proto_item_set_len(ti, cur_off - start_off);
	return cur_off - start_off;
}

static void
dissect_nbns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int			offset = 0;
	int			nbns_data_offset;
	column_info		*cinfo;
	proto_tree		*nbns_tree = NULL;
	proto_item		*ti;
	guint16			id, flags, opcode, rcode, quest, ans, auth, add;
	int			cur_off;

	nbns_data_offset = offset;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBNS");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	/* To do: check for runts, errs, etc. */
	id    = tvb_get_ntohs(tvb, offset + NBNS_ID);
	flags = tvb_get_ntohs(tvb, offset + NBNS_FLAGS);
	opcode = (guint16) ((flags & F_OPCODE) >> OPCODE_SHIFT);
	rcode  = (guint16)  (flags & F_RCODE);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s",
		    val_to_str(opcode, opcode_vals, "Unknown operation (%u)"),
		    (flags & F_RESPONSE) ? " response" : "");
		cinfo = pinfo->cinfo;
	} else {
		/* Set "cinfo" to NULL; we pass a NULL "cinfo" to the query
		   and answer dissectors, as a way of saying that they
		   shouldn't add stuff to the COL_INFO column (a call to
		   "check_col(cinfo, COL_INFO)" is more expensive than
		   a check that a pointer isn't NULL). */
		cinfo = NULL;
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbns, tvb, offset, -1,
		    FALSE);
		nbns_tree = proto_item_add_subtree(ti, ett_nbns);

		proto_tree_add_uint(nbns_tree, hf_nbns_transaction_id, tvb,
				    offset + NBNS_ID, 2, id);

		nbns_add_nbns_flags(pinfo->cinfo, nbns_tree, tvb, offset + NBNS_FLAGS,
				    flags, 0);
	}
	quest = tvb_get_ntohs(tvb, offset + NBNS_QUEST);
	if (tree) {
		proto_tree_add_uint(nbns_tree, hf_nbns_count_questions, tvb,
				    offset + NBNS_QUEST, 2, quest);
	}
	ans = tvb_get_ntohs(tvb, offset + NBNS_ANS);
	if (tree) {
		proto_tree_add_uint(nbns_tree, hf_nbns_count_answers, tvb,
				    offset + NBNS_ANS, 2, ans);
	}
	auth = tvb_get_ntohs(tvb, offset + NBNS_AUTH);
	if (tree) {
		proto_tree_add_uint(nbns_tree, hf_nbns_count_auth_rr, tvb,
				    offset + NBNS_AUTH, 2, auth);
	}
	add = tvb_get_ntohs(tvb, offset + NBNS_ADD);
	if (tree) {
		proto_tree_add_uint(nbns_tree, hf_nbns_count_add_rr, tvb,
				    offset + NBNS_ADD, 2, add);
	}

	cur_off = offset + NBNS_HDRLEN;

	if (quest > 0) {
		/* If this is a response, don't add information about the
		   queries to the summary, just add information about the
		   answers. */
		cur_off += dissect_query_records(tvb, cur_off,
		    nbns_data_offset, quest,
		    (!(flags & F_RESPONSE) ? cinfo : NULL), nbns_tree);
	}

	if (ans > 0) {
		/* If this is a request, don't add information about the
		   answers to the summary, just add information about the
		   queries. */
		cur_off += dissect_answer_records(tvb, cur_off,
			nbns_data_offset, ans,
			((flags & F_RESPONSE) ? cinfo : NULL), nbns_tree,
			opcode, "Answers");
	}

	if (tree) {
		/* Don't add information about the authoritative name
		   servers, or the additional records, to the summary. */
		if (auth > 0)
			cur_off += dissect_answer_records(tvb, cur_off,
					nbns_data_offset,
					auth, NULL, nbns_tree, opcode,
					"Authoritative nameservers");

		if (add > 0)
			cur_off += dissect_answer_records(tvb, cur_off,
					nbns_data_offset,
					add, NULL, nbns_tree, opcode,
					"Additional records");
	}
}

/* NetBIOS datagram packet, from RFC 1002, page 32 */
struct nbdgm_header {
	guint8		msg_type;
	struct {
		guint8	more;
		guint8	first;
		guint8	node_type;
	} flags;
	guint16		dgm_id;
	guint32		src_ip;
	guint16		src_port;

	/* For packets with data */
	guint16		dgm_length;
	guint16		pkt_offset;

	/* For error packets */
	guint8		error_code;
};

/*
 * NBDS message types.
 */
#define NBDS_DIRECT_UNIQUE	0x10
#define NBDS_DIRECT_GROUP	0x11
#define NBDS_BROADCAST		0x12
#define NBDS_ERROR		0x13
#define NBDS_QUERY_REQUEST	0x14
#define NBDS_POS_QUERY_RESPONSE	0x15
#define NBDS_NEG_QUERY_RESPONSE	0x16

static const value_string nbds_msgtype_vals[] = {
	{ NBDS_DIRECT_UNIQUE,      "Direct_unique datagram" },
	{ NBDS_DIRECT_GROUP,       "Direct_group datagram" },
	{ NBDS_BROADCAST,          "Broadcast datagram" },
	{ NBDS_ERROR,              "Datagram error" },
	{ NBDS_QUERY_REQUEST,      "Datagram query request" },
	{ NBDS_POS_QUERY_RESPONSE, "Datagram positive query response" },
	{ NBDS_NEG_QUERY_RESPONSE, "Datagram negative query response" },
	{ 0,                       NULL }
};

static const true_false_string yesno = {
	"Yes",
	"No"
};

static const value_string node_type_vals[] = {
	{ 0, "B node" },
	{ 1, "P node" },
	{ 2, "M node" },
	{ 3, "NBDD" },
	{ 0, NULL }
};

static void
dissect_nbdgm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int			offset = 0;
	proto_tree		*nbdgm_tree = NULL;
	proto_item		*ti = NULL;
	struct nbdgm_header	header;
	int			flags;
	int			message_index;
	tvbuff_t		*next_tvb;

	static const value_string error_codes[] = {
		{ 0x82, "Destination name not present" },
		{ 0x83, "Invalid source name format" },
		{ 0x84, "Invalid destination name format" },
		{ 0x00,	NULL }
	};

	char name[(NETBIOS_NAME_LEN - 1)*4 + MAXDNAME];
	int name_type;
	int len;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBDS");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	header.msg_type = tvb_get_guint8(tvb, offset);

	flags = tvb_get_guint8(tvb, offset+1);
	header.flags.more = flags & 1;
	header.flags.first = (flags & 2) >> 1;
	header.flags.node_type = (flags & 12) >> 2;

	header.dgm_id = tvb_get_ntohs(tvb, offset+2);
	tvb_memcpy(tvb, (guint8 *)&header.src_ip, offset+4, 4);
	header.src_port = tvb_get_ntohs(tvb, offset+8);

	switch (header.msg_type) {

	case NBDS_DIRECT_UNIQUE:
	case NBDS_DIRECT_GROUP:
	case NBDS_BROADCAST:
		header.dgm_length = tvb_get_ntohs(tvb, offset+10);
		header.pkt_offset = tvb_get_ntohs(tvb, offset+12);
		break;

	case NBDS_ERROR:
		header.error_code = tvb_get_guint8(tvb, offset+10);
		break;
	}

	message_index = header.msg_type - 0x0f;
	if (message_index < 1 || message_index > 8) {
		message_index = 0;
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(header.msg_type, nbds_msgtype_vals,
		      "Unknown message type (0x%02X)"));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbdgm, tvb, offset, -1,
		    FALSE);
		nbdgm_tree = proto_item_add_subtree(ti, ett_nbdgm);

		proto_tree_add_uint(nbdgm_tree, hf_nbdgm_type, tvb,
				     offset, 1,
				     header.msg_type);
		proto_tree_add_boolean(nbdgm_tree, hf_nbdgm_fragment, tvb,
				       offset+1, 1,
				       header.flags.more);
		proto_tree_add_boolean(nbdgm_tree, hf_nbdgm_first, tvb,
				       offset+1, 1,
				       header.flags.first);
		proto_tree_add_uint(nbdgm_tree, hf_nbdgm_node_type, tvb,
				     offset+1, 1,
				     header.flags.node_type);

		proto_tree_add_uint(nbdgm_tree, hf_nbdgm_datagram_id, tvb,
				    offset+2, 2, header.dgm_id);
		proto_tree_add_ipv4(nbdgm_tree, hf_nbdgm_src_ip, tvb,
				    offset+4, 4, header.src_ip);
		proto_tree_add_uint(nbdgm_tree, hf_nbdgm_src_port, tvb,
				    offset+8, 2, header.src_port);

	}

	offset += 10;

	switch (header.msg_type) {

	case NBDS_DIRECT_UNIQUE:
	case NBDS_DIRECT_GROUP:
	case NBDS_BROADCAST:
		if (tree) {
			proto_tree_add_text(nbdgm_tree, tvb, offset, 2,
					"Datagram length: %d bytes", header.dgm_length);
			proto_tree_add_text(nbdgm_tree, tvb, offset+2, 2,
					"Packet offset: %d bytes", header.pkt_offset);
		}

		offset += 4;

		/* Source name */
		len = get_nbns_name(tvb, offset, offset, name, &name_type);

		if (tree) {
			add_name_and_type(nbdgm_tree, tvb, offset, len,
			    "Source name", name, name_type);
		}
		offset += len;

		/* Destination name */
		len = get_nbns_name(tvb, offset, offset, name, &name_type);

		if (tree) {
			add_name_and_type(nbdgm_tree, tvb, offset, len,
			    "Destination name", name, name_type);
		}
		offset += len;

		/*
		 * Here we can pass the packet off to the next protocol.
		 * Set the length of our top-level tree item to include
		 * only our stuff.
		 *
		 * XXX - take the datagram length into account?
		 */
		proto_item_set_len(ti, offset);
		next_tvb = tvb_new_subset(tvb, offset, -1, -1);
		dissect_netbios_payload(next_tvb, pinfo, tree);
		break;

	case NBDS_ERROR:
		if (tree) {
			proto_tree_add_text(nbdgm_tree, tvb, offset, 1, "Error code: %s",
				val_to_str(header.error_code, error_codes, "Unknown (0x%x)"));
		}
		offset += 1;
		proto_item_set_len(ti, offset);
		break;

	case NBDS_QUERY_REQUEST:
	case NBDS_POS_QUERY_RESPONSE:
	case NBDS_NEG_QUERY_RESPONSE:
		/* Destination name */
		len = get_nbns_name(tvb, offset, offset, name, &name_type);

		if (tree) {
			add_name_and_type(nbdgm_tree, tvb, offset, len,
			    "Destination name", name, name_type);
		}
		offset += len;
		proto_item_set_len(ti, offset);
		break;
	}
}

/*
 * NetBIOS Session Service message types.
 */
#define	SESSION_MESSAGE			0x00
#define	SESSION_REQUEST			0x81
#define	POSITIVE_SESSION_RESPONSE	0x82
#define	NEGATIVE_SESSION_RESPONSE	0x83
#define	RETARGET_SESSION_RESPONSE	0x84
#define	SESSION_KEEP_ALIVE		0x85

static const value_string message_types[] = {
	{ SESSION_MESSAGE,           "Session message" },
	{ SESSION_REQUEST,           "Session request" },
	{ POSITIVE_SESSION_RESPONSE, "Positive session response" },
	{ NEGATIVE_SESSION_RESPONSE, "Negative session response" },
	{ RETARGET_SESSION_RESPONSE, "Retarget session response" },
	{ SESSION_KEEP_ALIVE,        "Session keep-alive" },
	{ 0x0,                       NULL }
};

/*
 * NetBIOS Session Service flags.
 */
#define	NBSS_FLAGS_E			0x1

static const value_string error_codes[] = {
	{ 0x80, "Not listening on called name" },
	{ 0x81, "Not listening for called name" },
	{ 0x82, "Called name not present" },
	{ 0x83, "Called name present, but insufficient resources" },
	{ 0x8F, "Unspecified error" },
	{ 0x0,  NULL }
};

/*
 * Dissect a single NBSS packet (there may be more than one in a given
 * TCP segment).
 *
 * [ Hmmm, in my experience, I have never seen more than one NBSS in a
 * single segment, since they mostly contain SMBs which are essentially
 * a request response type protocol (RJS). ]
 *
 * [ However, under heavy load with many requests multiplexed on one
 * session it is not unusual to see multiple requests in one TCP
 * segment. Unfortunately, in this case a single session message is
 * frequently split over multiple segments, which frustrates decoding
 * (MMM). ]
 */
static int
dissect_nbss_packet(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, int is_cifs)
{
	proto_tree	*nbss_tree = NULL;
	proto_item	*ti = NULL;
	proto_tree	*field_tree;
	proto_item	*tf;
	guint8		msg_type;
	guint8		flags;
	volatile int	length;
	int		length_remaining;
	int		len;
	char		name[(NETBIOS_NAME_LEN - 1)*4 + MAXDNAME];
	int		name_type;
	gint		reported_len;
	tvbuff_t	*next_tvb;
	const char	*saved_proto;

	/* Desegmentation */
	length_remaining = tvb_length_remaining(tvb, offset);

	/*
	 * Can we do reassembly?
	 */
	if (nbss_desegment && pinfo->can_desegment) {
		/*
		 * Yes - is the NBSS header split across segment boundaries?
		 */
		if (length_remaining < 4) {
			/*
			 * Yes.  Tell our caller how many more bytes
			 * we need.
			 */
			return -(4 - length_remaining);
		}
	}

	/*
	 * Get the length of the NBSS message.
	 */
	if (is_cifs) {
		flags = 0;
		length = tvb_get_ntoh24(tvb, offset + 1);
	} else {
		flags = tvb_get_guint8(tvb, offset + 1);
		length = tvb_get_ntohs(tvb, offset + 2);
		if (flags & NBSS_FLAGS_E)
			length += 65536;
	}

	/* give a hint to TCP where the next PDU starts
	 * so that it can attempt to find it in case it starts
	 * somewhere in the middle of a segment.
	 */
	if(!pinfo->fd->flags.visited){
		/* 'Only' SMB is transported ontop of this  so make sure
		 * there is an SMB header there ...
		 */
		if( ((length+4)>tvb_reported_length_remaining(tvb, offset))
		  &&(tvb_length_remaining(tvb, offset)>=8)
		  &&(tvb_get_guint8(tvb,offset+5)=='S')
		  &&(tvb_get_guint8(tvb,offset+6)=='M')
		  &&(tvb_get_guint8(tvb,offset+7)=='B') ){
			pinfo->want_pdu_tracking=2;
			pinfo->bytes_until_next_pdu=(length+4)-tvb_reported_length_remaining(tvb, offset);
		}
	}

	/*
	 * Can we do reassembly?
	 */
	if (nbss_desegment && pinfo->can_desegment) {
		/*
		 * Yes - is the NBSS message split across segment boundaries?
		 */
		if (length_remaining < length + 4) {
			/*
			 * Yes.  Tell our caller how many more bytes
			 * we need.
			 */
			return -((length + 4) - length_remaining);
		}
	}

	msg_type = tvb_get_guint8(tvb, offset);

	if (tree) {
	  ti = proto_tree_add_item(tree, proto_nbss, tvb, offset, length + 4, FALSE);
	  nbss_tree = proto_item_add_subtree(ti, ett_nbss);

	  proto_tree_add_uint_format(nbss_tree, hf_nbss_type, tvb,
				     offset, 1,
				     msg_type,
				     "Message Type: %s",
				     val_to_str(msg_type, message_types,
						"Unknown (%x)"));
	}

	offset += 1;

	if (is_cifs) {
		if (tree) {
		  proto_tree_add_text(nbss_tree, tvb, offset, 3, "Length: %u", length);
		}
		offset += 3;
	} else {
		if (tree) {
		  tf = proto_tree_add_uint(nbss_tree, hf_nbss_flags, tvb, offset, 1, flags);
		  field_tree = proto_item_add_subtree(tf, ett_nbss_flags);
		  proto_tree_add_text(field_tree, tvb, offset, 1, "%s",
			      decode_boolean_bitfield(flags, NBSS_FLAGS_E,
							      8, "Add 65536 to length", "Add 0 to length"));
		}
		offset += 1;

		if (tree) {
		  proto_tree_add_text(nbss_tree, tvb, offset, 2, "Length: %u", length);
		}

		offset += 2;
	}

	switch (msg_type) {

	case SESSION_REQUEST:
	  len = get_nbns_name(tvb, offset, offset, name, &name_type);
	  if (tree)
	    add_name_and_type(nbss_tree, tvb, offset, len,
				"Called name", name, name_type);
	  offset += len;

	  if (check_col(pinfo->cinfo, COL_INFO))
		  col_append_fstr(pinfo->cinfo, COL_INFO, ", to %s ", name);

	  len = get_nbns_name(tvb, offset, offset, name, &name_type);

	  if (tree)
	    add_name_and_type(nbss_tree, tvb, offset, len,
				"Calling name", name, name_type);

	  if (check_col(pinfo->cinfo, COL_INFO))
		  col_append_fstr(pinfo->cinfo, COL_INFO, "from %s", name);

	  break;

	case NEGATIVE_SESSION_RESPONSE:
	  if (tree)
	    proto_tree_add_text(nbss_tree, tvb, offset, 1,
				"Error code: %s",
				val_to_str(tvb_get_guint8(tvb, offset),
					   error_codes, "Unknown (%x)"));

	  if (check_col(pinfo->cinfo, COL_INFO))
		  col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				  val_to_str(tvb_get_guint8(tvb, offset),
					     error_codes, "Unknown (%x)"));

	  break;

	case RETARGET_SESSION_RESPONSE:
	  if (tree)
	    proto_tree_add_text(nbss_tree, tvb, offset, 4,
				"Retarget IP address: %s",
				ip_to_str(tvb_get_ptr(tvb, offset, 4)));

	  offset += 4;

	  if (tree)
	    proto_tree_add_text(nbss_tree, tvb, offset, 2,
				"Retarget port: %u",
				tvb_get_ntohs(tvb, offset));

	  break;

	case SESSION_MESSAGE:
	  /*
	   * Here we can pass the message off to the next protocol.
	   * Set the length of our top-level tree item to include
	   * only our stuff.
	   */
	  proto_item_set_len(ti, offset);
	  len = tvb_length_remaining(tvb, offset);
	  reported_len = tvb_reported_length_remaining(tvb, offset);
	  if (len > length)
	    len = length;
	  if (reported_len > length)
	    reported_len = length;

	  next_tvb = tvb_new_subset(tvb, offset, len, reported_len);

	  /*
	   * Catch the ReportedBoundsError exception; if this
	   * particular message happens to get a ReportedBoundsError
	   * exception, that doesn't mean that we should stop
	   * dissecting NetBIOS messages within this frame or chunk
	   * of reassembled data.
	   *
	   * If it gets a BoundsError, we can stop, as there's nothing
	   * more to see, so we just re-throw it.
	   */
	  saved_proto = pinfo->current_proto;
	  TRY {
	    dissect_netbios_payload(next_tvb, pinfo, tree);
	  }
	  CATCH(BoundsError) {
	    RETHROW;
	  }
	  CATCH(ReportedBoundsError) {
	    show_reported_bounds_error(tvb, pinfo, tree);
	    pinfo->current_proto = saved_proto;
	  }
	  ENDTRY;
	  break;

	}
	return length + 4;
}

static void
dissect_nbss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct tcpinfo	*tcpinfo = pinfo->private_data;
	int		offset = 0;
	int		max_data;
	guint8		msg_type;
	guint8		flags;
	guint32		length;
	int		len;
	gboolean	is_cifs;
	proto_tree	*nbss_tree;
	proto_item	*ti;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBSS");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	max_data = tvb_length(tvb);

	msg_type = tvb_get_guint8(tvb, offset);

	if (pinfo->match_port == TCP_PORT_CIFS) {
		/*
		 * Windows 2000 CIFS clients can dispense completely
		 * with the NETBIOS encapsulation and directly use CIFS
		 * over TCP. As would be expected, the framing is
		 * identical, except that the length is 24 bits instead
		 * of 17. The only message types used are
		 * SESSION_MESSAGE and SESSION_KEEP_ALIVE.
		 */
		is_cifs = TRUE;
	} else {
		is_cifs = FALSE;
	}

	/*
	 * This might be a continuation of an earlier message.
	 * (Yes, that might be true even if we're doing TCP reassembly,
	 * as the first TCP segment in the capture might start in the
	 * middle of an NBNS message.)
	 */

	/*
	 * If this isn't reassembled data, check to see whether it
	 * looks like a continuation of a message.
	 * (If it is reassembled data, it shouldn't be a continuation,
	 * as reassembly should've gathered the continuations together
	 * into a message.)
	 */
	if (!tcpinfo->is_reassembled) {
		if (max_data < 4) {
			/*
			 * Not enough data for an NBSS header; assume
			 * it's a continuation of a message.
			 *
			 * XXX - if there's not enough data, we should
			 * attempt to reassemble the data, if the first byte
			 * is a valid message type.
			 */
			goto continuation;
		}

		/*
		 * We have enough data for an NBSS header.
		 * Get the flags and length of the message,
		 * and see if they're sane.
		 */
		if (is_cifs) {
			flags = 0;
			length = tvb_get_ntoh24(tvb, offset + 1);
		} else {
			flags = tvb_get_guint8(tvb, offset + 1);
			length = tvb_get_ntohs(tvb, offset + 2);
			if (flags & NBSS_FLAGS_E)
				length += 65536;
		}
		if ((flags & (~NBSS_FLAGS_E)) != 0) {
			/*
			 * A bogus flag was set; assume it's a continuation.
			 */
			goto continuation;
		}

		switch (msg_type) {

		case SESSION_MESSAGE:
			/*
			 * This is variable-length.
			 * All we know is that it shouldn't be zero.
			 * (XXX - can we get zero-length messages?
			 * Not with SMB, but perhaps other NetBIOS-based
			 * protocols have them.)
			 */
			if (length == 0)
				goto continuation;
			break;

		case SESSION_REQUEST:
			/*
			 * This is variable-length.
			 * The names are DNS-encoded 32-byte values;
			 * we need at least 2 bytes (one for each name;
			 * actually, we should have more for the first
			 * name, as there's no name preceding it so
			 * there should be no compression), and we
			 * shouldn't have more than 128 bytes (actually,
			 * we shouldn't have that many).
			 *
			 * XXX - actually, MacOS X 10.1 (yes, that's
			 * redundant, but that's what Apple calls it,
			 * not MacOS X.1) puts names longer than 16
			 * characters into session request messages,
			 * so we can have more than 32 bytes of
			 * name value, so we can have more than 128
			 * bytes of data.
			 */
			if (length < 2 || length > 256)
				goto continuation;
			break;

		case POSITIVE_SESSION_RESPONSE:
			/*
			 * This has no data, so the length must be zero.
			 */
			if (length != 0)
				goto continuation;
			break;

		case NEGATIVE_SESSION_RESPONSE:
			/*
			 * This has 1 byte of data.
			 */
			if (length != 1)
				goto continuation;
			break;

		case RETARGET_SESSION_RESPONSE:
			/*
			 * This has 6 bytes of data.
			 */
			if (length != 6)
				goto continuation;
			break;

		case SESSION_KEEP_ALIVE:
			/*
			 * This has no data, so the length must be zero.
			 */
			if (length != 0)
				goto continuation;
			break;

		default:
			/*
			 * Unknown message type; assume it's a continuation.
			 */
			goto continuation;
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
		    val_to_str(msg_type, message_types, "Unknown (%02x)"));
	}

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		len = dissect_nbss_packet(tvb, offset, pinfo, tree, is_cifs);
		if (len < 0) {
			/*
			 * We need more data to dissect this, and
			 * desegmentation is enabled.  "-len" is the
			 * number of additional bytes of data we need.
			 *
			 * Tell the TCP dissector where the data for this
			 * message starts in the data it handed us, and
			 * how many more bytes we need, and return.
			 */
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = -len;
			return;
		}
		offset += len;
	}

	return;

continuation:
	/*
	 * It looks like a continuation.
	 */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "NBSS Continuation Message");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbss, tvb, 0, -1, FALSE);
		nbss_tree = proto_item_add_subtree(ti, ett_nbss);
		proto_tree_add_text(nbss_tree, tvb, 0, -1, "Continuation data");
	}
}

void
proto_register_nbt(void)
{

  static hf_register_info hf_nbns[] = {
    { &hf_nbns_flags,
      { "Flags",		"nbns.flags",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"", HFILL }},
    { &hf_nbns_flags_response,
      { "Response",		"nbns.flags.response",
	FT_BOOLEAN, 16, TFS(&tfs_flags_response), F_RESPONSE,
	"Is the message a response?", HFILL }},
    { &hf_nbns_flags_opcode,
      { "Opcode",		"nbns.flags.opcode",
	FT_UINT16, BASE_DEC, VALS(opcode_vals), F_OPCODE,
	"Operation code", HFILL }},
    { &hf_nbns_flags_authoritative,
      { "Authoritative",	"nbns.flags.authoritative",
	FT_BOOLEAN, 16, TFS(&tfs_flags_authoritative), F_AUTHORITATIVE,
	"Is the server is an authority for the domain?", HFILL }},
    { &hf_nbns_flags_truncated,
      { "Truncated",	"nbns.flags.truncated",
	FT_BOOLEAN, 16, TFS(&tfs_flags_truncated), F_TRUNCATED,
	"Is the message truncated?", HFILL }},
    { &hf_nbns_flags_recdesired,
      { "Recursion desired",	"nbns.flags.recdesired",
	FT_BOOLEAN, 16, TFS(&tfs_flags_recdesired), F_RECDESIRED,
	"Do query recursively?", HFILL }},
    { &hf_nbns_flags_recavail,
      { "Recursion available",	"nbns.flags.recavail",
	FT_BOOLEAN, 16, TFS(&tfs_flags_recavail), F_RECAVAIL,
	"Can the server do recursive queries?", HFILL }},
    { &hf_nbns_flags_broadcast,
      { "Broadcast",		"nbns.flags.broadcast",
	FT_BOOLEAN, 16, TFS(&tfs_flags_broadcast), F_BROADCAST,
	"Is this a broadcast packet?", HFILL }},
    { &hf_nbns_flags_rcode,
      { "Reply code",		"nbns.flags.rcode",
	FT_UINT16, BASE_DEC, VALS(rcode_vals), F_RCODE,
	"Reply code", HFILL }},
    { &hf_nbns_transaction_id,
      { "Transaction ID",      	"nbns.id",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"Identification of transaction", HFILL }},
    { &hf_nbns_count_questions,
      { "Questions",		"nbns.count.queries",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of queries in packet", HFILL }},
    { &hf_nbns_count_answers,
      { "Answer RRs",		"nbns.count.answers",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of answers in packet", HFILL }},
    { &hf_nbns_count_auth_rr,
      { "Authority RRs",       	"nbns.count.auth_rr",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of authoritative records in packet", HFILL }},
    { &hf_nbns_count_add_rr,
      { "Additional RRs",      	"nbns.count.add_rr",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of additional records in packet", HFILL }}
  };

  static hf_register_info hf_nbdgm[] = {
    { &hf_nbdgm_type,
      { "Message Type",		"nbdgm.type",
	FT_UINT8, BASE_DEC, VALS(nbds_msgtype_vals), 0x0,
	"NBDGM message type", HFILL }},
    { &hf_nbdgm_fragment,
      { "More fragments follow",	"nbdgm.next",
	FT_BOOLEAN, BASE_NONE, TFS(&yesno), 0x0,
	"TRUE if more fragments follow", HFILL }},
    { &hf_nbdgm_first,
      { "This is first fragment",	"nbdgm.first",
	FT_BOOLEAN, BASE_NONE, TFS(&yesno), 0x0,
	"TRUE if first fragment", HFILL }},
    { &hf_nbdgm_node_type,
      { "Node Type",		"nbdgm.node_type",
	FT_UINT8, BASE_DEC, VALS(node_type_vals), 0x0,
	"Node type", HFILL }},
    { &hf_nbdgm_datagram_id,
      { "Datagram ID",		"nbdgm.dgram_id",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"Datagram identifier", HFILL }},
    { &hf_nbdgm_src_ip,
      { "Source IP",		"nbdgm.src.ip",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Source IPv4 address", HFILL }},
    { &hf_nbdgm_src_port,
      { "Source Port",		"nbdgm.src.port",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Source port", HFILL }}
  };

  static hf_register_info hf_nbss[] = {
    { &hf_nbss_type,
      { "Message Type",		"nbss.type",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"NBSS message type", HFILL }},
    { &hf_nbss_flags,
      { "Flags",		"nbss.flags",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	"NBSS message flags", HFILL }}
  };
  static gint *ett[] = {
    &ett_nbns,
    &ett_nbns_qd,
    &ett_nbns_flags,
    &ett_nbns_nb_flags,
    &ett_nbns_name_flags,
    &ett_nbns_rr,
    &ett_nbns_qry,
    &ett_nbns_ans,
    &ett_nbdgm,
    &ett_nbss,
    &ett_nbss_flags,
  };
  module_t *nbss_module;

  proto_nbns = proto_register_protocol("NetBIOS Name Service", "NBNS", "nbns");
  proto_register_field_array(proto_nbns, hf_nbns, array_length(hf_nbns));

  proto_nbdgm = proto_register_protocol("NetBIOS Datagram Service",
					"NBDS", "nbdgm");
  proto_register_field_array(proto_nbdgm, hf_nbdgm, array_length(hf_nbdgm));

  proto_nbss = proto_register_protocol("NetBIOS Session Service",
				       "NBSS", "nbss");
  proto_register_field_array(proto_nbss, hf_nbss, array_length(hf_nbss));

  proto_register_subtree_array(ett, array_length(ett));

  nbss_module = prefs_register_protocol(proto_nbss, NULL);
  prefs_register_bool_preference(nbss_module, "desegment_nbss_commands",
    "Reassemble NBSS packets spanning multiple TCP segments",
    "Whether the NBSS dissector should reassemble packets spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &nbss_desegment);
}

void
proto_reg_handoff_nbt(void)
{
  dissector_handle_t nbns_handle, nbdgm_handle, nbss_handle;

  nbns_handle = create_dissector_handle(dissect_nbns, proto_nbns);
  dissector_add("udp.port", UDP_PORT_NBNS, nbns_handle);
  nbdgm_handle = create_dissector_handle(dissect_nbdgm, proto_nbdgm);
  dissector_add("udp.port", UDP_PORT_NBDGM, nbdgm_handle);
  nbss_handle = create_dissector_handle(dissect_nbss, proto_nbss);
  dissector_add("tcp.port", TCP_PORT_NBSS, nbss_handle);
  dissector_add("tcp.port", TCP_PORT_CIFS, nbss_handle);
}
