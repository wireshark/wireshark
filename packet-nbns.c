/* packet-nbns.c
 * Routines for NetBIOS-over-TCP packet disassembly (the name dates back
 * to when it had only NBNS)
 * Gilbert Ramirez <gram@xiexie.org>
 * Much stuff added by Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-nbns.c,v 1.38 2000/03/12 04:47:42 gram Exp $
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
#include <string.h>
#include <glib.h>

#include "packet.h"
#include "packet-dns.h"
#include "packet-netbios.h"
#include "packet-smb.h"

static int proto_nbns = -1;
static int hf_nbns_response = -1;
static int hf_nbns_query = -1;
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
#define F_AUTHORITATIVE (1<<10)         /* response is authoritative */
#define F_TRUNCATED     (1<<9)          /* response is truncated */
#define F_RECDESIRED    (1<<8)          /* recursion desired */
#define F_RECAVAIL      (1<<7)          /* recursion available */
#define F_BROADCAST     (1<<4)          /* broadcast/multicast packet */
#define F_RCODE         (0xF<<0)        /* reply code */

/* Opcodes */
#define OPCODE_QUERY          (0<<11)    /* standard query */
#define OPCODE_REGISTRATION   (5<<11)    /* registration */
#define OPCODE_RELEASE        (6<<11)    /* release name */
#define OPCODE_WACK           (7<<11)    /* wait for acknowledgement */
#define OPCODE_REFRESH        (8<<11)    /* refresh registration */
#define OPCODE_REFRESHALT     (9<<11)    /* refresh registration (alternate opcode) */
#define OPCODE_MHREGISTRATION (15<<11)   /* multi-homed registration */

/* Reply codes */
#define RCODE_NOERROR   (0<<0)
#define RCODE_FMTERROR  (1<<0)
#define RCODE_SERVFAIL  (2<<0)
#define RCODE_NAMEERROR (3<<0)
#define RCODE_NOTIMPL   (4<<0)
#define RCODE_REFUSED   (5<<0)
#define RCODE_ACTIVE    (6<<0)
#define RCODE_CONFLICT  (7<<0)

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

static char *
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

static int
get_nbns_name(const u_char *pd, int offset, int nbns_data_offset,
    char *name_ret, int *name_type_ret)
{
	int name_len;
	char name[MAXDNAME];
	char nbname[NETBIOS_NAME_LEN];
	char *pname, *pnbname, cname, cnbname;
	int name_type;

	name_len = get_dns_name(pd, offset, nbns_data_offset, name,
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
get_nbns_name_type_class(const u_char *pd, int offset, int nbns_data_offset,
    char *name_ret, int *name_len_ret, int *name_type_ret, int *type_ret,
    int *class_ret)
{
	int name_len;
	int type;
	int class;

	name_len = get_nbns_name(pd, offset, nbns_data_offset, name_ret,
	   name_type_ret);
	offset += name_len;
	
	if (!BYTES_ARE_IN_FRAME(offset, 2)) {
		/* We ran past the end of the captured data in the packet. */
		return -1;
	}
	type = pntohs(&pd[offset]);
	offset += 2;

	if (!BYTES_ARE_IN_FRAME(offset, 2)) {
		/* We ran past the end of the captured data in the packet. */
		return -1;
	}
	class = pntohs(&pd[offset]);

	*type_ret = type;
	*class_ret = class;
	*name_len_ret = name_len;

	return name_len + 4;
}

static void
add_name_and_type(proto_tree *tree, int offset, int len, char *tag,
    char *name, int name_type)
{
	if (name_type != -1) {
		proto_tree_add_text(tree, offset, len, "%s: %s (%s)",
		    tag, name, netbios_name_type_descr(name_type));
	} else {
		proto_tree_add_text(tree, offset, len, "%s: %s",
		    tag, name);
	}
}

static int
dissect_nbns_query(const u_char *pd, int offset, int nbns_data_offset,
    frame_data *fd, proto_tree *nbns_tree)
{
	int len;
	char name[(NETBIOS_NAME_LEN - 1)*4 + MAXDNAME];
	int name_len;
	int name_type;
	int type;
	int class;
	char *class_name;
	char *type_name;
	const u_char *dptr;
	const u_char *data_start;
	proto_tree *q_tree;
	proto_item *tq;

	data_start = dptr = pd + offset;

	len = get_nbns_name_type_class(pd, offset, nbns_data_offset, name,
	    &name_len, &name_type, &type, &class);
	if (len < 0) {
		/* We ran past the end of the data in the packet. */
		return 0;
	}
	dptr += len;

	type_name = nbns_type_name(type);
	class_name = dns_class_name(class);

	if (fd != NULL)
		col_append_fstr(fd, COL_INFO, " %s %s", type_name, name);
	if (nbns_tree != NULL) {
		tq = proto_tree_add_text(nbns_tree, offset, len,
		    "%s: type %s, class %s",  name, type_name, class_name);
		q_tree = proto_item_add_subtree(tq, ett_nbns_qd);

		add_name_and_type(q_tree, offset, name_len, "Name", name,
		    name_type);
		offset += name_len;

		proto_tree_add_text(q_tree, offset, 2, "Type: %s", type_name);
		offset += 2;

		proto_tree_add_text(q_tree, offset, 2, "Class: %s", class_name);
		offset += 2;
	}
	
	return dptr - data_start;
}

static void
nbns_add_nbns_flags(proto_tree *nbns_tree, int offset, u_short flags,
    int is_wack)
{
	char buf[128+1];
	proto_tree *field_tree;
	proto_item *tf;
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

	strcpy(buf, val_to_str(flags & F_OPCODE, opcode_vals,
				"Unknown operation"));
	if (flags & F_RESPONSE && !is_wack) {
		strcat(buf, " response");
		strcat(buf, ", ");
		strcat(buf, val_to_str(flags & F_RCODE, rcode_vals,
		    "Unknown error"));
	}
	tf = proto_tree_add_text(nbns_tree, offset, 2,
			"Flags: 0x%04x (%s)", flags, buf);
	field_tree = proto_item_add_subtree(tf, ett_nbns_flags);
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, F_RESPONSE,
				2*8, "Response", "Query"));
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_enumerated_bitfield(flags, F_OPCODE,
				2*8, opcode_vals, "%s"));
	if (flags & F_RESPONSE) {
		proto_tree_add_text(field_tree, offset, 2,
			"%s",
			decode_boolean_bitfield(flags, F_AUTHORITATIVE,
				2*8,
				"Server is an authority for domain",
				"Server isn't an authority for domain"));
	}
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, F_TRUNCATED,
				2*8,
				"Message is truncated",
				"Message is not truncated"));
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, F_RECDESIRED,
				2*8,
				"Do query recursively",
				"Don't do query recursively"));
	if (flags & F_RESPONSE) {
		proto_tree_add_text(field_tree, offset, 2,
			"%s",
			decode_boolean_bitfield(flags, F_RECAVAIL,
				2*8,
				"Server can do recursive queries",
				"Server can't do recursive queries"));
	}
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, F_BROADCAST,
				2*8,
				"Broadcast packet",
				"Not a broadcast packet"));
	if (flags & F_RESPONSE && !is_wack) {
		proto_tree_add_text(field_tree, offset, 2,
			"%s",
			decode_enumerated_bitfield(flags, F_RCODE,
				2*8,
				rcode_vals, "%s"));
	}
}

static void
nbns_add_nb_flags(proto_tree *rr_tree, int offset, u_short flags)
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
	tf = proto_tree_add_text(rr_tree, offset, 2, "Flags: 0x%x (%s)", flags,
			buf);
	field_tree = proto_item_add_subtree(tf, ett_nbns_nb_flags);
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NB_FLAGS_G,
				2*8,
				"Group name",
				"Unique name"));
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_enumerated_bitfield(flags, NB_FLAGS_ONT,
				2*8, nb_flags_ont_vals, "%s"));
}

static void
nbns_add_name_flags(proto_tree *rr_tree, int offset, u_short flags)
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
	tf = proto_tree_add_text(rr_tree, offset, 2, "Name flags: 0x%x (%s)",
			flags, buf);
	field_tree = proto_item_add_subtree(tf, ett_nbns_name_flags);
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_G,
				2*8,
				"Group name",
				"Unique name"));
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_enumerated_bitfield(flags, NAME_FLAGS_ONT,
				2*8, name_flags_ont_vals, "%s"));
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_DRG,
				2*8,
				"Name is being deregistered",
				"Name is not being deregistered"));
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_CNF,
				2*8,
				"Name is in conflict",
				"Name is not in conflict"));
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_ACT,
				2*8,
				"Name is active",
				"Name is not active"));
	proto_tree_add_text(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_PRM,
				2*8,
				"Permanent node name",
				"Not permanent node name"));
}

static int
dissect_nbns_answer(const u_char *pd, int offset, int nbns_data_offset,
    frame_data *fd, proto_tree *nbns_tree, int opcode)
{
	int len;
	char name[(NETBIOS_NAME_LEN - 1)*4 + MAXDNAME + 64];
	int name_len;
	int name_type;
	int type;
	int class;
	char *class_name;
	char *type_name;
	const u_char *dptr;
	int cur_offset;
	const u_char *data_start;
	u_int ttl;
	u_short data_len;
	u_short flags;
	proto_tree *rr_tree;
	proto_item *trr;
	char name_str[(NETBIOS_NAME_LEN - 1)*4 + 1];
	u_int num_names;
	char nbname[16+4+1];	/* 4 for [<last char>] */
	u_short name_flags;

	data_start = dptr = pd + offset;
	cur_offset = offset;

	len = get_nbns_name_type_class(pd, offset, nbns_data_offset, name,
	    &name_len, &name_type, &type, &class);
	if (len < 0) {
		/* We ran past the end of the data in the packet. */
		return 0;
	}
	dptr += len;
	cur_offset += len;

	type_name = nbns_type_name(type);
	class_name = dns_class_name(class);

	if (!BYTES_ARE_IN_FRAME(cur_offset, 4)) {
		/* We ran past the end of the captured data in the packet. */
		return 0;
	}
	ttl = pntohl(dptr);
	dptr += 4;
	cur_offset += 4;

	if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
		/* We ran past the end of the captured data in the packet. */
		return 0;
	}
	data_len = pntohs(dptr);
	dptr += 2;
	cur_offset += 2;

	switch (type) {
	case T_NB: 		/* "NB" record */
		if (fd != NULL) {
			if (opcode != OPCODE_WACK) {
				col_append_fstr(fd, COL_INFO, " %s %s",
				    type_name, ip_to_str((guint8 *)(dptr + 2)));
			}
		}
		if (nbns_tree == NULL)
			break;
		trr = proto_tree_add_text(nbns_tree, offset,
		    (dptr - data_start) + data_len,
		    "%s: type %s, class %s",
		    name, type_name, class_name);
		strcat(name, " (");
		strcat(name, netbios_name_type_descr(name_type));
		strcat(name, ")");
		rr_tree = add_rr_to_tree(trr, ett_nbns_rr, offset, name,
		    name_len, type_name, class_name, ttl, data_len);
		while (data_len > 0) {
			if (opcode == OPCODE_WACK) {
				/* WACK response.  This doesn't contain the
				 * same type of RR data as other T_NB
				 * responses.  */
				if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
					/* We ran past the end of the captured
					   data in the packet. */
					return 0;
				}
				if (data_len < 2) {
					proto_tree_add_text(rr_tree, cur_offset,
					    data_len, "(incomplete entry)");
					break;
				}
				flags = pntohs(dptr);
				dptr += 2;
				nbns_add_nbns_flags(rr_tree, cur_offset,
				    flags, 1);
				cur_offset += 2;
				data_len -= 2;
			} else {
				if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
					/* We ran past the end of the captured
					   data in the packet. */
					return 0;
				}
				if (data_len < 2) {
					proto_tree_add_text(rr_tree, cur_offset,
					    data_len, "(incomplete entry)");
					break;
				}
				flags = pntohs(dptr);
				dptr += 2;
				nbns_add_nb_flags(rr_tree, cur_offset, flags);
				cur_offset += 2;
				data_len -= 2;

				if (!BYTES_ARE_IN_FRAME(cur_offset, 4)) {
					/* We ran past the end of the captured
					   data in the packet. */
					return 0;
				}
				if (data_len < 4) {
					proto_tree_add_text(rr_tree, cur_offset,
					    data_len, "(incomplete entry)");
					break;
				}
				proto_tree_add_text(rr_tree, cur_offset, 4,
				    "Addr: %s",
				    ip_to_str((guint8 *)dptr));
				dptr += 4;
				cur_offset += 4;
				data_len -= 4;
			}
		}
		break;

	case T_NBSTAT: 	/* "NBSTAT" record */
		if (fd != NULL)
			col_append_fstr(fd, COL_INFO, " %s", type_name);
		if (nbns_tree == NULL)
			break;
		trr = proto_tree_add_text(nbns_tree, offset,
		    (dptr - data_start) + data_len,
		    "%s: type %s, class %s",
		    name, type_name, class_name);
		rr_tree = add_rr_to_tree(trr, ett_nbns_rr, offset, name,
		    name_len, type_name, class_name, ttl, data_len);
		if (!BYTES_ARE_IN_FRAME(cur_offset, 1)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 1) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		num_names = *dptr;
		dptr += 1;
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Number of names: %u", num_names);
		cur_offset += 1;

		while (num_names != 0) {
			if (!BYTES_ARE_IN_FRAME(cur_offset, NETBIOS_NAME_LEN)) {
				/* We ran past the end of the captured
				   data in the packet. */
				return 0;
			}
			if (data_len < NETBIOS_NAME_LEN) {
				proto_tree_add_text(rr_tree, cur_offset,
				    data_len, "(incomplete entry)");
				goto out;
			}
			memcpy(nbname, dptr, NETBIOS_NAME_LEN);
			dptr += NETBIOS_NAME_LEN;
			name_type = process_netbios_name(nbname,
			    name_str);
			proto_tree_add_text(rr_tree, cur_offset,
			    NETBIOS_NAME_LEN, "Name: %s<%02x> (%s)",
			    name_str, name_type,
			    netbios_name_type_descr(name_type));
			cur_offset += NETBIOS_NAME_LEN;
			data_len -= NETBIOS_NAME_LEN;

			if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
				/* We ran past the end of the captured
				   data in the packet. */
				return 0;
			}
			if (data_len < 2) {
				proto_tree_add_text(rr_tree, cur_offset,
				    data_len, "(incomplete entry)");
				goto out;
			}
			name_flags = pntohs(dptr);
			dptr += 2;
			nbns_add_name_flags(rr_tree, cur_offset, name_flags);
			cur_offset += 2;
			data_len -= 2;

			num_names--;
		}

		if (!BYTES_ARE_IN_FRAME(cur_offset, 6)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 6) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 6,
		    "Unit ID: %s",
		    ether_to_str((guint8 *)dptr));
		dptr += 6;
		cur_offset += 6;
		data_len -= 6;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 1)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 1) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 1,
		    "Jumpers: 0x%x", *dptr);
		dptr += 1;
		cur_offset += 1;
		data_len -= 1;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 1)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 1) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 1,
		    "Test result: 0x%x", *dptr);
		dptr += 1;
		cur_offset += 1;
		data_len -= 1;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Version number: 0x%x", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Period of statistics: 0x%x", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Number of CRCs: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Number of alignment errors: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Number of collisions: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Number of send aborts: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 4)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 4) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 4,
		    "Number of good sends: %u", pntohl(dptr));
		dptr += 4;
		cur_offset += 4;
		data_len -= 4;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 4)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 4) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 4,
		    "Number of good receives: %u", pntohl(dptr));
		dptr += 4;
		cur_offset += 4;
		data_len -= 4;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Number of retransmits: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Number of no resource conditions: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Number of command blocks: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Number of pending sessions: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Max number of pending sessions: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Max total sessions possible: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;

		if (!BYTES_ARE_IN_FRAME(cur_offset, 2)) {
			/* We ran past the end of the captured
			   data in the packet. */
			return 0;
		}
		if (data_len < 2) {
			proto_tree_add_text(rr_tree, cur_offset,
			    data_len, "(incomplete entry)");
			break;
		}
		proto_tree_add_text(rr_tree, cur_offset, 2,
		    "Session data packet size: %u", pntohs(dptr));
		dptr += 2;
		cur_offset += 2;
		data_len -= 2;
	out:
		break;

	default:
		if (fd != NULL)
			col_append_fstr(fd, COL_INFO, " %s", type_name);
		if (nbns_tree == NULL)
			break;
		trr = proto_tree_add_text(nbns_tree, offset,
		    (dptr - data_start) + data_len,
                    "%s: type %s, class %s",
		    name, type_name, class_name);
		rr_tree = add_rr_to_tree(trr, ett_nbns_rr, offset, name,
		    name_len, type_name, class_name, ttl, data_len);
		proto_tree_add_text(rr_tree, cur_offset, data_len, "Data");
		break;
	}
	dptr += data_len;
	
	return dptr - data_start;
}

static int
dissect_query_records(const u_char *pd, int cur_off, int nbns_data_offset,
    int count, frame_data *fd, proto_tree *nbns_tree)
{
	int start_off, add_off;
	proto_tree *qatree = NULL;
	proto_item *ti = NULL;
	
	start_off = cur_off;
	if (nbns_tree != NULL) {
		ti = proto_tree_add_text(nbns_tree, start_off, 0, "Queries");
		qatree = proto_item_add_subtree(ti, ett_nbns_qry);
	}
	while (count-- > 0) {
		add_off = dissect_nbns_query(pd, cur_off, nbns_data_offset,
		    fd, qatree);
		if (add_off <= 0) {
			/* We ran past the end of the captured data in the
			   packet. */
			break;
		}
		cur_off += add_off;
	}
	if (ti != NULL)
		proto_item_set_len(ti, cur_off - start_off);

	return cur_off - start_off;
}



static int
dissect_answer_records(const u_char *pd, int cur_off, int nbns_data_offset,
    int count, frame_data *fd, proto_tree *nbns_tree, int opcode, char *name)
{
	int start_off, add_off;
	proto_tree *qatree = NULL;
	proto_item *ti = NULL;
	
	start_off = cur_off;
	if (nbns_tree != NULL) {
		ti = proto_tree_add_text(nbns_tree, start_off, 0, name);
		qatree = proto_item_add_subtree(ti, ett_nbns_ans);
	}
	while (count-- > 0) {
		add_off = dissect_nbns_answer(pd, cur_off, nbns_data_offset,
					fd, qatree, opcode);
		if (add_off <= 0) {
			/* We ran past the end of the captured data in the
			   packet. */
			break;
		}
		cur_off += add_off;
	}
	if (ti != NULL)
		proto_item_set_len(ti, cur_off - start_off);
	return cur_off - start_off;
}

void
dissect_nbns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	int			nbns_data_offset;
	proto_tree		*nbns_tree = NULL;
	proto_item		*ti;
	guint16			id, flags, quest, ans, auth, add;
	int			cur_off;

	nbns_data_offset = offset;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NBNS");

	if (pi.captured_len < NBNS_HDRLEN) {
		col_add_str(fd, COL_INFO, "Short NBNS packet");
		dissect_data(pd, offset, fd, tree);
		return;
	}

	/* To do: check for runts, errs, etc. */
	id    = pntohs(&pd[offset + NBNS_ID]);
	flags = pntohs(&pd[offset + NBNS_FLAGS]);
	quest = pntohs(&pd[offset + NBNS_QUEST]);
	ans   = pntohs(&pd[offset + NBNS_ANS]);
	auth  = pntohs(&pd[offset + NBNS_AUTH]);
	add   = pntohs(&pd[offset + NBNS_ADD]);

	if (check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "%s%s",
		    val_to_str(flags & F_OPCODE, opcode_vals,
		      "Unknown operation (%x)"),
		    (flags & F_RESPONSE) ? " response" : "");
	} else {
		/* Set "fd" to NULL; we pass a NULL "fd" to the query and
		   answer dissectors, as a way of saying that they shouldn't
		   add stuff to the COL_INFO column (a call to
		   "check_col(fd, COL_INFO)" is more expensive than a check
		   that a pointer isn't NULL). */
		fd = NULL;
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbns, offset, END_OF_FRAME, NULL);
		nbns_tree = proto_item_add_subtree(ti, ett_nbns);

		if (flags & F_RESPONSE) {
			proto_tree_add_item_hidden(nbns_tree, hf_nbns_response, 
					     0, 0, TRUE);
		} else {
			proto_tree_add_item_hidden(nbns_tree, hf_nbns_query, 
					     0, 0, TRUE);
		}

		proto_tree_add_item(nbns_tree, hf_nbns_transaction_id,
				    offset + NBNS_ID, 2, id);

		nbns_add_nbns_flags(nbns_tree, offset + NBNS_FLAGS, flags, 0);
		proto_tree_add_item(nbns_tree, hf_nbns_count_questions,
				    offset + NBNS_QUEST, 2, quest);
		proto_tree_add_item(nbns_tree, hf_nbns_count_answers,
				    offset + NBNS_ANS, 2, ans);
		proto_tree_add_item(nbns_tree, hf_nbns_count_auth_rr,
				    offset + NBNS_AUTH, 2, auth);
		proto_tree_add_item(nbns_tree, hf_nbns_count_add_rr,
				    offset + NBNS_ADD, 2, add);
	}

	cur_off = offset + NBNS_HDRLEN;
    
	if (quest > 0) {
		/* If this is a response, don't add information about the
		   queries to the summary, just add information about the
		   answers. */
		cur_off += dissect_query_records(pd, cur_off,
		    nbns_data_offset, quest,
		    (!(flags & F_RESPONSE) ? fd : NULL), nbns_tree);
	}

	if (ans > 0) {
		/* If this is a request, don't add information about the
		   answers to the summary, just add information about the
		   queries. */
		cur_off += dissect_answer_records(pd, cur_off,
			nbns_data_offset, ans,
			((flags & F_RESPONSE) ? fd : NULL), nbns_tree,
			flags & F_OPCODE, "Answers");
	}

	if (tree) {
		/* Don't add information about the authoritative name
		   servers, or the additional records, to the summary. */
		if (auth > 0)
			cur_off += dissect_answer_records(pd, cur_off,
					nbns_data_offset,
					auth, NULL, nbns_tree,
					flags & F_OPCODE,
					"Authoritative nameservers");

		if (add > 0)
			cur_off += dissect_answer_records(pd, cur_off,
					nbns_data_offset,
					add, NULL, nbns_tree,
					flags & F_OPCODE,
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

void
dissect_nbdgm(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree		*nbdgm_tree = NULL;
	proto_item		*ti;
	struct nbdgm_header	header;
	int			flags;
	int			message_index;
	int			max_data = pi.captured_len - offset;

	char *message[] = {
		"Unknown",
		"Direct_unique datagram",
		"Direct_group datagram",
		"Broadcast datagram",
		"Datagram error",
		"Datagram query request",
		"Datagram positive query response",
		"Datagram negative query response"
	};

	char *node[] = {
		"B node",
		"P node",
		"M node",
		"NBDD"
	};

	static value_string error_codes[] = {
		{ 0x82, "Destination name not present" },
		{ 0x83, "Invalid source name format" },
		{ 0x84, "Invalid destination name format" },
		{ 0x00,	NULL }
	};

	char *yesno[] = { "No", "Yes" };

	char name[(NETBIOS_NAME_LEN - 1)*4 + MAXDNAME];
	int name_type;
	int len;

	header.msg_type = pd[offset];
	
	flags = pd[offset+1];
	header.flags.more = flags & 1;
	header.flags.first = (flags & 2) >> 1;
	header.flags.node_type = (flags & 12) >> 2;

	header.dgm_id = pntohs(&pd[offset+2]);
	memcpy(&header.src_ip, &pd[offset+4], 4);
	header.src_port = pntohs(&pd[offset+8]);

	if (header.msg_type == 0x10 ||
			header.msg_type == 0x11 || header.msg_type == 0x12) {
		header.dgm_length = pntohs(&pd[offset+10]);
		header.pkt_offset = pntohs(&pd[offset+12]);
	}
	else if (header.msg_type == 0x13) {
		header.error_code = pntohs(&pd[offset+10]);
	}

	message_index = header.msg_type - 0x0f;
	if (message_index < 1 || message_index > 8) {
		message_index = 0;
	}

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NBDS");
	if (check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "%s", message[message_index]);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbdgm, offset, header.dgm_length, NULL);
		nbdgm_tree = proto_item_add_subtree(ti, ett_nbdgm);

		proto_tree_add_uint_format(nbdgm_tree, hf_nbdgm_type,
					   offset, 1, 
					   header.msg_type,   
					   "Message Type: %s",
					   message[message_index]);
		proto_tree_add_boolean_format(nbdgm_tree, hf_nbdgm_fragment,
					   offset+1, 1, 
					   header.flags.more,
					   "More fragments follow: %s",
					   yesno[header.flags.more]);
		proto_tree_add_boolean_format(nbdgm_tree, hf_nbdgm_first,
					   offset+1, 1, 
					   header.flags.first,
					   "This is first fragment: %s",
					   yesno[header.flags.first]);
		proto_tree_add_uint_format(nbdgm_tree, hf_nbdgm_node_type,
					   offset+1, 1, 
					   header.flags.node_type,
					   "Node Type: %s",
					   node[header.flags.node_type]);

		proto_tree_add_item(nbdgm_tree, hf_nbdgm_datagram_id,
				    offset+2, 2, header.dgm_id);
		proto_tree_add_item(nbdgm_tree, hf_nbdgm_src_ip,
				    offset+4, 4, header.src_ip);
		proto_tree_add_item(nbdgm_tree, hf_nbdgm_src_port,
				    offset+8, 2, header.src_port);

	}

	offset += 10;
	max_data -= 10;

	if (header.msg_type == 0x10 ||
			header.msg_type == 0x11 || header.msg_type == 0x12) {

		if (tree) {
			proto_tree_add_text(nbdgm_tree, offset, 2,
					"Datagram length: %d bytes", header.dgm_length);
			proto_tree_add_text(nbdgm_tree, offset+2, 2,
					"Packet offset: %d bytes", header.pkt_offset);
		}

		offset += 4;
		max_data -= 4;

		/* Source name */
		len = get_nbns_name(pd, offset, offset, name, &name_type);

		if (tree) {
			add_name_and_type(nbdgm_tree, offset, len,
			    "Source name", name, name_type);
		}
		offset += len;
		max_data -= len;

		/* Destination name */
		len = get_nbns_name(pd, offset, offset, name, &name_type);

		if (tree) {
			add_name_and_type(nbdgm_tree, offset, len,
			    "Destination name", name, name_type);
		}
		offset += len;
		max_data -= len;

		/* here we can pass the packet off to the next protocol */
		dissect_smb(pd, offset, fd, tree, max_data);
	}
	else if (header.msg_type == 0x13) {
		if (tree) {
			proto_tree_add_text(nbdgm_tree, offset, 1, "Error code: %s",
				val_to_str(header.error_code, error_codes, "Unknown (0x%x)"));
		}
	}
	else if (header.msg_type == 0x14 ||
			header.msg_type == 0x15 || header.msg_type == 0x16) {
		/* Destination name */
		len = get_nbns_name(pd, offset, offset, name, &name_type);

		if (tree) {
			add_name_and_type(nbdgm_tree, offset, len,
			    "Destination name", name, name_type);
		}
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
 * Dissect a single NBSS packet (there may be more than one in a given TCP
 * segment). Hmmm, in my experience, I have never seen more than one NBSS
 * in a single segment, since they mostly contain SMBs which are essentially
 * a request response type protocol (RJS). Also, a single session message 
 * may be split over multiple segments.
 */
static int
dissect_nbss_packet(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int max_data)
{
	proto_tree	*nbss_tree = NULL;
	proto_item	*ti;
	proto_tree	*field_tree;
	proto_item	*tf;
	guint8		msg_type;
	guint8		flags;
	guint16		length;
	int		len;
	char		name[(NETBIOS_NAME_LEN - 1)*4 + MAXDNAME];
	int		name_type;

	msg_type = pd[offset];
	flags = pd[offset + 1];
	length = pntohs(&pd[offset + 2]);
	if (flags & NBSS_FLAGS_E)
		length += 65536;

	if (tree) {
	  ti = proto_tree_add_item(tree, proto_nbss, offset, length + 4, NULL);
	  nbss_tree = proto_item_add_subtree(ti, ett_nbss);
	  
	  proto_tree_add_uint_format(nbss_tree, hf_nbss_type,
				     offset, 1, 
				     msg_type,
				     "Message Type: %s",
				     val_to_str(msg_type, message_types, 
						"Unknown (%x)"));
	}

	offset += 1;

	if (tree) {
	  tf = proto_tree_add_item(nbss_tree, hf_nbss_flags, offset, 1, flags);
	  field_tree = proto_item_add_subtree(tf, ett_nbss_flags);
	  proto_tree_add_text(field_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags, NBSS_FLAGS_E,
						      8, "Add 65536 to length", "Add 0 to length"));
	}

	offset += 1;

	if (tree) {
	  proto_tree_add_text(nbss_tree, offset, 2, "Length: %u", length);
	}

	offset += 2;

	switch (msg_type) {

	case SESSION_REQUEST:
	  len = get_nbns_name(pd, offset, offset, name, &name_type);
	  if (tree)
	    add_name_and_type(nbss_tree, offset, len,
				"Called name", name, name_type);
	  offset += len;

	  len = get_nbns_name(pd, offset, offset, name, &name_type);
	  
	  if (tree)
	    add_name_and_type(nbss_tree, offset, len,
				"Calling name", name, name_type);

	  break;

	case NEGATIVE_SESSION_RESPONSE:
	  if (tree) 
	    proto_tree_add_text(nbss_tree, offset, 1,
				"Error code: %s",
				val_to_str(pd[offset], error_codes, "Unknown (%x)"));
	  break;

	case RETARGET_SESSION_RESPONSE:
	  if (tree)
	    proto_tree_add_text(nbss_tree, offset, 4,
				"Retarget IP address: %s",
				ip_to_str((guint8 *)&pd[offset]));
	  
	  offset += 4;

	  if (tree)
	    proto_tree_add_text(nbss_tree, offset, 2,
				"Retarget port: %u", pntohs(&pd[offset]));

	  break;

	case SESSION_MESSAGE:
	  /*
	   * Here we can pass the packet off to the next protocol.
	   */

	  dissect_smb(pd, offset, fd, tree, max_data - 4);

	  break;

	}
	return length + 4;
}

void
dissect_nbss(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint8		msg_type;
	guint8		flags;
	guint16		length;
	int		len;
	int		max_data;

	msg_type = pd[offset];
	flags = pd[offset + 1];
	length = pntohs(&pd[offset + 2]);
	if (flags & NBSS_FLAGS_E)
		length += 65536;

	/*
	 * XXX - we should set this based on both "pi.captured_len"
	 * and "length"....
	 */
	max_data = pi.captured_len - offset;

	/* Hmmm, it may be a continuation message ... */

#define RJSHACK 1
#ifdef RJSHACK
	if (((msg_type != SESSION_REQUEST) && 
	     (msg_type != POSITIVE_SESSION_RESPONSE) &&
	     (msg_type != NEGATIVE_SESSION_RESPONSE) &&
	     (msg_type != RETARGET_SESSION_RESPONSE) &&
	     (msg_type != SESSION_MESSAGE)) ||
	    ((msg_type == SESSION_MESSAGE) &&
	    (memcmp(pd + offset + 4, "\377SMB", 4) != 0))) {
 
	  if (check_col(fd, COL_PROTOCOL))
	    col_add_str(fd, COL_PROTOCOL, "NBSS");
	  if (check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "NBSS Continuation Message");
	  }

	  if (tree)
	    proto_tree_add_text(tree, offset, max_data, "Continuation data");

	  return;
	}
#endif

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NBSS");
	if (check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO,
		    val_to_str(msg_type, message_types, "Unknown (%x)"));
	}

	while (max_data > 0) {
		len = dissect_nbss_packet(pd, offset, fd, tree, max_data);
		offset += len;
		max_data -= len;
	}

}

void
proto_register_nbt(void)
{

  static hf_register_info hf_nbns[] = {
    { &hf_nbns_response,
      { "Response",		"nbns.response",  
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"TRUE if NBNS response" }},
    { &hf_nbns_query,
      { "Query",		"nbns.query",  
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"TRUE if NBNS query" }},
    { &hf_nbns_transaction_id,
      { "Transaction ID",      	"nbns.id",  
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"Identification of transaction" }},
    { &hf_nbns_count_questions,
      { "Questions",		"nbns.count.queries",  
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of queries in packet" }},
    { &hf_nbns_count_answers,
      { "Answer RRs",		"nbns.count.answers",  
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of answers in packet" }},
    { &hf_nbns_count_auth_rr,
      { "Authority RRs",       	"nbns.count.auth_rr",  
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of authoritative records in packet" }},
    { &hf_nbns_count_add_rr,
      { "Additional RRs",      	"nbns.count.add_rr",  
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of additional records in packet" }}
  };

  static hf_register_info hf_nbdgm[] = {
    { &hf_nbdgm_type,
      { "Message Type",		"nbdgm.type",  
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"NBDGM message type" }},
    { &hf_nbdgm_fragment,
      { "Fragmented",		"nbdgm.next",  
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"TRUE if more fragments follow" }},
    { &hf_nbdgm_first,
      { "First fragment",	"nbdgm.first",  
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"TRUE if first fragment" }},
    { &hf_nbdgm_node_type,
      { "Node Type",		"nbdgm.node_type",  
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Node type" }},
    { &hf_nbdgm_datagram_id,
      { "Datagram ID",		"nbdgm.dgram_id",  
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"Datagram identifier" }},
    { &hf_nbdgm_src_ip,
      { "Source IP",		"nbdgm.src.ip",  
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Source IPv4 address" }},
    { &hf_nbdgm_src_port,
      { "Source Port",		"nbdgm.src.port",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Source port" }}
  };

  static hf_register_info hf_nbss[] = {
    { &hf_nbss_type,
      { "Message Type",		"nbss.type",  
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"NBSS message type" }},
    { &hf_nbss_flags,
      { "Flags",		"nbss.flags",  
	FT_UINT8, BASE_HEX, NULL, 0x0,
	"NBSS message flags" }}
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

  proto_nbns = proto_register_protocol("NetBIOS Name Service", "nbns");
  proto_register_field_array(proto_nbns, hf_nbns, array_length(hf_nbns));
  
  proto_nbdgm = proto_register_protocol("NetBIOS Datagram Service", "nbdgm");
  proto_register_field_array(proto_nbdgm, hf_nbdgm, array_length(hf_nbdgm));

  proto_nbss = proto_register_protocol("NetBIOS Session Service", "nbss");
  proto_register_field_array(proto_nbss, hf_nbss, array_length(hf_nbss));

  proto_register_subtree_array(ett, array_length(ett));
}
