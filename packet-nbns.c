/* packet-nbns.c
 * Routines for NetBIOS Name Service, Datagram Service, and Session Service
 * packet disassembly (the name dates back to when it had only NBNS)
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 * Much stuff added by Guy Harris <guy@netapp.com>
 *
 * $Id: packet-nbns.c,v 1.19 1999/05/10 22:07:09 guy Exp $
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
#include "util.h"

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

/* "Canonicalize" a 16-character NetBIOS name by:
 *
 *	removing and saving the last byte;
 *
 *	stripping trailing blanks;
 *
 *	appending the trailing byte, as a hex number, in square brackets. */
static char *
canonicalize_netbios_name(char *nbname)
{
	char *pnbname;
	u_char lastchar;

	/* Get the last character of the name, as it's a special number
	 * indicating the type of the name, rather than part of the name
	 * *per se*. */
	pnbname = nbname + 15;	/* point to the 16th character */
	lastchar = *(unsigned char *)pnbname;

	/* Now strip off any trailing blanks used to pad it to
	 * 16 bytes. */
	while (pnbname > &nbname[0]) {
		if (*(pnbname - 1) != ' ')
			break;		/* found non-blank character */
		pnbname--;		/* blank - skip over it */
	}

	/* Replace the last character with its hex value, in square
	 * brackets, to make it easier to tell what it is. */
	sprintf(pnbname, "[%02X]", lastchar);
	pnbname += 4;
	return pnbname;
}

static int
get_nbns_name(const u_char *nbns_data_ptr, const u_char *pd,
    int offset, char *name_ret)
{
	int name_len;
	char name[MAXDNAME];
	char nbname[MAXDNAME+4];	/* 4 for [<last char>] */
	char *pname, *pnbname, cname, cnbname;

	name_len = get_dns_name(nbns_data_ptr, pd, offset, name, sizeof(name));
	
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

		/* Store the character. */
		*pnbname++ = cnbname;
	}

	/* NetBIOS names are supposed to be exactly 16 bytes long. */
	if (pnbname - nbname == 16) {
		/* This one is; canonicalize its name. */
		pnbname = canonicalize_netbios_name(nbname);
	} else {
		sprintf(nbname, "Illegal NetBIOS name (%ld bytes long)",
		    (long)(pnbname - nbname));
		goto bad;
	}
	if (cname == '.') {
		/* We have a scope ID, starting at "pname"; append that to
		 * the decoded host name. */
		strcpy(pnbname, pname);
	} else {
		/* Terminate the decoded host name. */
		*pnbname = '\0';
	}

bad:
	strcpy (name_ret, nbname);
	return name_len;
}


static int
get_nbns_name_type_class(const u_char *nbns_data_ptr, const u_char *pd,
    int offset, char *name_ret, int *name_len_ret, int *type_ret,
    int *class_ret)
{
	int name_len;
	int type;
	int class;

	name_len = get_nbns_name(nbns_data_ptr, pd, offset, name_ret);
	offset += name_len;
	
	type = pntohs(&pd[offset]);
	offset += 2;
	class = pntohs(&pd[offset]);

	*type_ret = type;
	*class_ret = class;
	*name_len_ret = name_len;

	return name_len + 4;
}


static int
dissect_nbns_query(const u_char *nbns_data_ptr, const u_char *pd, int offset,
    proto_tree *nbns_tree)
{
	int len;
	char name[MAXDNAME];
	int name_len;
	int type;
	int class;
	char *class_name;
	char *type_name;
	const u_char *dptr;
	const u_char *data_start;
	proto_tree *q_tree;
	proto_item *tq;

	data_start = dptr = pd + offset;

	len = get_nbns_name_type_class(nbns_data_ptr, pd, offset, name,
	    &name_len, &type, &class);
	dptr += len;

	type_name = nbns_type_name(type);
	class_name = dns_class_name(class);

	tq = proto_tree_add_item(nbns_tree, offset, len, "%s: type %s, class %s", 
	    name, type_name, class_name);
	q_tree = proto_tree_new();
	proto_item_add_subtree(tq, q_tree, ETT_NBNS_QD);

	proto_tree_add_item(q_tree, offset, name_len, "Name: %s", name);
	offset += name_len;

	proto_tree_add_item(q_tree, offset, 2, "Type: %s", type_name);
	offset += 2;

	proto_tree_add_item(q_tree, offset, 2, "Class: %s", class_name);
	offset += 2;
	
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
	tf = proto_tree_add_item(nbns_tree, offset, 2,
			"Flags: 0x%04x (%s)", flags, buf);
	field_tree = proto_tree_new();
	proto_item_add_subtree(tf, field_tree, ETT_NBNS_FLAGS);
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, F_RESPONSE,
				2*8, "Response", "Query"));
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_enumerated_bitfield(flags, F_OPCODE,
				2*8, opcode_vals, "%s"));
	if (flags & F_RESPONSE) {
		proto_tree_add_item(field_tree, offset, 2,
			"%s",
			decode_boolean_bitfield(flags, F_AUTHORITATIVE,
				2*8,
				"Server is an authority for domain",
				"Server isn't an authority for domain"));
	}
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, F_TRUNCATED,
				2*8,
				"Message is truncated",
				"Message is not truncated"));
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, F_RECDESIRED,
				2*8,
				"Do query recursively",
				"Don't do query recursively"));
	if (flags & F_RESPONSE) {
		proto_tree_add_item(field_tree, offset, 2,
			"%s",
			decode_boolean_bitfield(flags, F_RECAVAIL,
				2*8,
				"Server can do recursive queries",
				"Server can't do recursive queries"));
	}
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, F_BROADCAST,
				2*8,
				"Broadcast packet",
				"Not a broadcast packet"));
	if (flags & F_RESPONSE && !is_wack) {
		proto_tree_add_item(field_tree, offset, 2,
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
	tf = proto_tree_add_item(rr_tree, offset, 2, "Flags: 0x%x (%s)", flags,
			buf);
	field_tree = proto_tree_new();
	proto_item_add_subtree(tf, field_tree, ETT_NBNS_NB_FLAGS);
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NB_FLAGS_G,
				2*8,
				"Group name",
				"Unique name"));
	proto_tree_add_item(field_tree, offset, 2, "%s",
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
	tf = proto_tree_add_item(rr_tree, offset, 2, "Name flags: 0x%x (%s)",
			flags, buf);
	field_tree = proto_tree_new();
	proto_item_add_subtree(tf, field_tree, ETT_NBNS_NAME_FLAGS);
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_G,
				2*8,
				"Group name",
				"Unique name"));
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_enumerated_bitfield(flags, NAME_FLAGS_ONT,
				2*8, name_flags_ont_vals, "%s"));
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_DRG,
				2*8,
				"Name is being deregistered",
				"Name is not being deregistered"));
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_CNF,
				2*8,
				"Name is in conflict",
				"Name is not in conflict"));
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_ACT,
				2*8,
				"Name is active",
				"Name is not active"));
	proto_tree_add_item(field_tree, offset, 2, "%s",
			decode_boolean_bitfield(flags, NAME_FLAGS_PRM,
				2*8,
				"Permanent node name",
				"Not permanent node name"));
}

static int
dissect_nbns_answer(const u_char *nbns_data_ptr, const u_char *pd, int offset,
    proto_tree *nbns_tree, int opcode)
{
	int len;
	char name[MAXDNAME];
	int name_len;
	int type;
	int class;
	char *class_name;
	char *type_name;
	const u_char *dptr;
	const u_char *data_start;
	u_int ttl;
	u_short data_len;
	u_short flags;
	proto_tree *rr_tree;
	proto_item *trr;

	data_start = dptr = pd + offset;

	len = get_nbns_name_type_class(nbns_data_ptr, pd, offset, name,
	    &name_len, &type, &class);
	dptr += len;

	type_name = nbns_type_name(type);
	class_name = dns_class_name(class);

	ttl = pntohl(dptr);
	dptr += 4;

	data_len = pntohs(dptr);
	dptr += 2;

	switch (type) {
	case T_NB: 		/* "NB" record */
		trr = proto_tree_add_item(nbns_tree, offset,
		    (dptr - data_start) + data_len,
		    "%s: type %s, class %s",
		    name, type_name, class_name);
		rr_tree = add_rr_to_tree(trr, ETT_NBNS_RR, offset, name,
		    name_len, type_name, class_name, ttl, data_len);
		offset += (dptr - data_start);
		while (data_len > 0) {
			if (opcode == OPCODE_WACK) {
				/* WACK response.  This doesn't contain the
				 * same type of RR data as other T_NB
				 * responses.  */
				if (data_len < 2) {
					proto_tree_add_item(rr_tree, offset,
					    data_len, "(incomplete entry)");
					break;
				}
				flags = pntohs(dptr);
				dptr += 2;
				nbns_add_nbns_flags(rr_tree, offset, flags, 1);
				offset += 2;
				data_len -= 2;
			} else {
				if (data_len < 2) {
					proto_tree_add_item(rr_tree, offset,
					    data_len, "(incomplete entry)");
					break;
				}
				flags = pntohs(dptr);
				dptr += 2;
				nbns_add_nb_flags(rr_tree, offset, flags);
				offset += 2;
				data_len -= 2;

				if (data_len < 4) {
					proto_tree_add_item(rr_tree, offset,
					    data_len, "(incomplete entry)");
					break;
				}
				proto_tree_add_item(rr_tree, offset, 4,
				    "Addr: %s",
				    ip_to_str((guint8 *)dptr));
				dptr += 4;
				offset += 4;
				data_len -= 4;
			}
		}
		break;

	case T_NBSTAT: 	/* "NBSTAT" record */
		{
			u_int num_names;
			char nbname[16+4+1];	/* 4 for [<last char>] */
			u_short name_flags;
			
			trr = proto_tree_add_item(nbns_tree, offset,
			    (dptr - data_start) + data_len,
			    "%s: type %s, class %s",
			    name, type_name, class_name);
			rr_tree = add_rr_to_tree(trr, ETT_NBNS_RR, offset, name,
			    name_len, type_name, class_name, ttl, data_len);
			offset += (dptr - data_start);
			if (data_len < 1) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			num_names = *dptr;
			dptr += 1;
			proto_tree_add_item(rr_tree, offset, 2,
			    "Number of names: %u", num_names);
			offset += 1;

			while (num_names != 0) {
				if (data_len < 16) {
					proto_tree_add_item(rr_tree, offset,
					    data_len, "(incomplete entry)");
					goto out;
				}
				memcpy(nbname, dptr, 16);
				dptr += 16;
				canonicalize_netbios_name(nbname);
				proto_tree_add_item(rr_tree, offset, 16,
				    "Name: %s", nbname);
				offset += 16;
				data_len -= 16;

				if (data_len < 2) {
					proto_tree_add_item(rr_tree, offset,
					    data_len, "(incomplete entry)");
					goto out;
				}
				name_flags = pntohs(dptr);
				dptr += 2;
				nbns_add_name_flags(rr_tree, offset, name_flags);
				offset += 2;
				data_len -= 2;

				num_names--;
			}

			if (data_len < 6) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 6,
			    "Unit ID: %s",
			    ether_to_str((guint8 *)dptr));
			dptr += 6;
			offset += 6;
			data_len -= 6;

			if (data_len < 1) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 1,
			    "Jumpers: 0x%x", *dptr);
			dptr += 1;
			offset += 1;
			data_len -= 1;

			if (data_len < 1) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 1,
			    "Test result: 0x%x", *dptr);
			dptr += 1;
			offset += 1;
			data_len -= 1;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Version number: 0x%x", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Period of statistics: 0x%x", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Number of CRCs: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Number of alignment errors: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Number of collisions: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Number of send aborts: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 4) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 4,
			    "Number of good sends: %u", pntohl(dptr));
			dptr += 4;
			offset += 4;
			data_len -= 4;

			if (data_len < 4) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 4,
			    "Number of good receives: %u", pntohl(dptr));
			dptr += 4;
			offset += 4;
			data_len -= 4;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Number of retransmits: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Number of no resource conditions: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Number of command blocks: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Number of pending sessions: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Max number of pending sessions: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;

			proto_tree_add_item(rr_tree, offset, 2,
			    "Max total sessions possible: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				proto_tree_add_item(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			proto_tree_add_item(rr_tree, offset, 2,
			    "Session data packet size: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;
		}
	out:
		break;

	default:
		trr = proto_tree_add_item(nbns_tree, offset,
		    (dptr - data_start) + data_len,
                    "%s: type %s, class %s",
		    name, type_name, class_name);
		rr_tree = add_rr_to_tree(trr, ETT_NBNS_RR, offset, name,
		    name_len, type_name, class_name, ttl, data_len);
		offset += (dptr - data_start);
		proto_tree_add_item(rr_tree, offset, data_len, "Data");
		break;
	}
	dptr += data_len;
	
	return dptr - data_start;
}

static int
dissect_query_records(const u_char *nbns_data_ptr, int count, const u_char *pd, 
    int cur_off, proto_tree *nbns_tree)
{
	int start_off;
	proto_tree *qatree;
	proto_item *ti;
	
	start_off = cur_off;
	ti = proto_tree_add_item(nbns_tree, start_off, 0, "Queries");
	qatree = proto_tree_new();
	proto_item_add_subtree(ti, qatree, ETT_NBNS_QRY);
	while (count-- > 0)
		cur_off += dissect_nbns_query(nbns_data_ptr, pd, cur_off, qatree);
	proto_item_set_len(ti, cur_off - start_off);

	return cur_off - start_off;
}



static int
dissect_answer_records(const u_char *nbns_data_ptr, int count,
    const u_char *pd, int cur_off, proto_tree *nbns_tree, int opcode, char *name)
{
	int start_off;
	proto_tree *qatree;
	proto_item *ti;
	
	start_off = cur_off;
	ti = proto_tree_add_item(nbns_tree, start_off, 0, name);
	qatree = proto_tree_new();
	proto_item_add_subtree(ti, qatree, ETT_NBNS_ANS);
	while (count-- > 0)
		cur_off += dissect_nbns_answer(nbns_data_ptr, pd, cur_off,
					qatree, opcode);
	proto_item_set_len(ti, cur_off - start_off);
	return cur_off - start_off;
}

void
dissect_nbns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	const u_char		*nbns_data_ptr;
	proto_tree		*nbns_tree;
	proto_item		*ti;
	guint16			id, flags, quest, ans, auth, add;
	int			cur_off;

	nbns_data_ptr = &pd[offset];

	/* To do: check for runts, errs, etc. */
	id    = pntohs(&pd[offset + NBNS_ID]);
	flags = pntohs(&pd[offset + NBNS_FLAGS]);
	quest = pntohs(&pd[offset + NBNS_QUEST]);
	ans   = pntohs(&pd[offset + NBNS_ANS]);
	auth  = pntohs(&pd[offset + NBNS_AUTH]);
	add   = pntohs(&pd[offset + NBNS_ADD]);

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NBNS (UDP)");
	if (check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "%s%s",
		    val_to_str(flags & F_OPCODE, opcode_vals,
		      "Unknown operation (%x)"),
		    (flags & F_RESPONSE) ? " response" : "");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, offset, END_OF_FRAME,
				"NetBIOS Name Service");
		nbns_tree = proto_tree_new();
		proto_item_add_subtree(ti, nbns_tree, ETT_NBNS);

		proto_tree_add_item(nbns_tree, offset + NBNS_ID, 2,
				"Transaction ID: 0x%04X", id);

		nbns_add_nbns_flags(nbns_tree, offset + NBNS_FLAGS, flags, 0);
		proto_tree_add_item(nbns_tree, offset + NBNS_QUEST, 2,
					"Questions: %d",
					quest);
		proto_tree_add_item(nbns_tree, offset + NBNS_ANS, 2,
					"Answer RRs: %d",
					ans);
		proto_tree_add_item(nbns_tree, offset + NBNS_AUTH, 2,
					"Authority RRs: %d",
					auth);
		proto_tree_add_item(nbns_tree, offset + NBNS_ADD, 2,
					"Additional RRs: %d",
					add);

		cur_off = offset + NBNS_HDRLEN;
    
		if (quest > 0)
			cur_off += dissect_query_records(nbns_data_ptr,
					quest, pd, cur_off, nbns_tree);

		if (ans > 0)
			cur_off += dissect_answer_records(nbns_data_ptr,
					ans, pd, cur_off, nbns_tree,
					flags & F_OPCODE,
					"Answers");

		if (auth > 0)
			cur_off += dissect_answer_records(nbns_data_ptr,
					auth, pd, cur_off, nbns_tree, 
					flags & F_OPCODE,
					"Authoritative nameservers");

		if (add > 0)
			cur_off += dissect_answer_records(nbns_data_ptr,
					add, pd, cur_off, nbns_tree, 
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
dissect_nbdgm(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
    int max_data)
{
	proto_tree		*nbdgm_tree = NULL;
	proto_item		*ti;
	struct nbdgm_header	header;
	int			flags;
	int			message_index;

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

	char name[32];
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
		col_add_str(fd, COL_PROTOCOL, "NBDS (UDP)");
	if (check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "%s", message[message_index]);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, offset, header.dgm_length,
				"NetBIOS Datagram Service");
		nbdgm_tree = proto_tree_new();
		proto_item_add_subtree(ti, nbdgm_tree, ETT_NBDGM);

		proto_tree_add_item(nbdgm_tree, offset, 1, "Message Type: %s",
				message[message_index]);
		proto_tree_add_item(nbdgm_tree, offset+1, 1, "More fragments follow: %s",
				yesno[header.flags.more]);
		proto_tree_add_item(nbdgm_tree, offset+1, 1, "This is first fragment: %s",
				yesno[header.flags.first]);
		proto_tree_add_item(nbdgm_tree, offset+1, 1, "Node Type: %s",
				node[header.flags.node_type]);

		proto_tree_add_item(nbdgm_tree, offset+2, 2, "Datagram ID: 0x%04X",
				header.dgm_id);
		proto_tree_add_item(nbdgm_tree, offset+4, 4, "Source IP: %s",
				ip_to_str((guint8 *)&header.src_ip));
		proto_tree_add_item(nbdgm_tree, offset+8, 2, "Source Port: %d",
				header.src_port);
	}

	offset += 10;
	max_data -= 10;

	if (header.msg_type == 0x10 ||
			header.msg_type == 0x11 || header.msg_type == 0x12) {

		if (tree) {
			proto_tree_add_item(nbdgm_tree, offset, 2,
					"Datagram length: %d bytes", header.dgm_length);
			proto_tree_add_item(nbdgm_tree, offset+2, 2,
					"Packet offset: %d bytes", header.pkt_offset);
		}

		offset += 4;
		max_data -= 4;

		/* Source name */
		len = get_nbns_name(&pd[offset], pd, offset, name);

		if (tree) {
			proto_tree_add_item(nbdgm_tree, offset, len, "Source name: %s",
					name);
		}
		offset += len;
		max_data -= len;

		/* Destination name */
		len = get_nbns_name(&pd[offset], pd, offset, name);

		if (tree) {
			proto_tree_add_item(nbdgm_tree, offset, len, "Destination name: %s",
					name);
		}
		offset += len;
		max_data -= len;

		/* here we can pass the packet off to the next protocol */
		dissect_smb(pd, offset, fd, tree, max_data);
	}
	else if (header.msg_type == 0x13) {
		if (tree) {
			proto_tree_add_item(nbdgm_tree, offset, 1, "Error code: %s",
				val_to_str(header.error_code, error_codes, "Unknown (0x%x)"));
		}
	}
	else if (header.msg_type == 0x14 ||
			header.msg_type == 0x15 || header.msg_type == 0x16) {
		/* Destination name */
		len = get_nbns_name(&pd[offset], pd, offset, name);

		if (tree) {
			proto_tree_add_item(nbdgm_tree, offset, len, "Destination name: %s",
					name);
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
	char		name[32];

	msg_type = pd[offset];
	flags = pd[offset + 1];
	length = pntohs(&pd[offset + 2]);
	if (flags & NBSS_FLAGS_E)
		length += 65536;

	if (tree) {
	  ti = proto_tree_add_item(tree, offset, length + 4,
				   "NetBIOS Session Service");
	  nbss_tree = proto_tree_new();
	  proto_item_add_subtree(ti, nbss_tree, ETT_NBSS);
	  
	  proto_tree_add_item(nbss_tree, offset, 1, "Message Type: %s",
			      val_to_str(msg_type, message_types, "Unknown (%x)"));
	}

	offset += 1;

	if (tree) {
	  tf = proto_tree_add_item(nbss_tree, offset, 1, "Flags: 0x%04x", flags);
	  field_tree = proto_tree_new();
	  proto_item_add_subtree(tf, field_tree, ETT_NBSS_FLAGS);
	  proto_tree_add_item(field_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags, NBSS_FLAGS_E,
						      8, "Add 65536 to length", "Add 0 to length"));
	}

	offset += 1;

	if (tree) {
	  proto_tree_add_item(nbss_tree, offset, 2, "Length: %u", length);
	}

	offset += 2;

	switch (msg_type) {

	case SESSION_REQUEST:
	  len = get_nbns_name(&pd[offset], pd, offset, name);
	  if (tree)
	    proto_tree_add_item(nbss_tree, offset, len,
				"Called name: %s", name);
	  offset += len;

	  len = get_nbns_name(&pd[offset], pd, offset, name);
	  
	  if (tree)
	    proto_tree_add_item(nbss_tree, offset, len,
				"Calling name: %s", name);

	  break;

	case NEGATIVE_SESSION_RESPONSE:
	  if (tree) 
	    proto_tree_add_item(nbss_tree, offset, 1,
				"Error code: %s",
				val_to_str(pd[offset], error_codes, "Unknown (%x)"));
	  break;

	case RETARGET_SESSION_RESPONSE:
	  if (tree)
	    proto_tree_add_item(nbss_tree, offset, 4,
				"Retarget IP address: %s",
				ip_to_str((guint8 *)&pd[offset]));
	  
	  offset += 4;

	  if (tree)
	    proto_tree_add_item(nbss_tree, offset, 2,
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
dissect_nbss(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int max_data)
{
	guint8		msg_type;
	guint8		flags;
	guint16		length;
	int		len;

	msg_type = pd[offset];
	flags = pd[offset + 1];
	length = pntohs(&pd[offset + 2]);
	if (flags & NBSS_FLAGS_E)
		length += 65536;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NBSS (TCP)");
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
