/* packet-nbns.c
 * Routines for NetBIOS Name Service packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 * Much stuff added by Guy Harris <guy@netapp.com>
 *
 * $Id: packet-nbns.c,v 1.8 1998/11/20 05:54:08 gram Exp $
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

#include <gtk/gtk.h>

#include <stdio.h>
#include <memory.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "packet-dns.h"

/* Packet structure taken from RFC 1002. See also RFC 1001.
 * The Samba source code, specifically nmblib.c, also helps a lot. */

struct nbns_header {

	guint16		name_tran_id;
	guint8		r;
	guint8		opcode;
	struct {
		guint8	bcast;
		guint8	recursion_available;
		guint8	recursion_desired;
		guint8	trunc;
		guint8	authoritative;
	} nm_flags;
	guint8		rcode;
	guint16		qdcount;
	guint16		ancount;
	guint16		nscount;
	guint16		arcount;
};

/* type values  */
#define T_NB            32              /* NetBIOS name service RR */
#define T_NBSTAT        33              /* NetBIOS node status RR */

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
get_nbns_name_type_class(const u_char *nbns_data_ptr, const u_char *pd,
    int offset, char *name_ret, int *name_len_ret, int *type_ret,
    int *class_ret)
{
	int len;
	int name_len;
	int type;
	int class;
	char name[MAXDNAME];
	char nbname[MAXDNAME+4];	/* 4 for [<last char>] */
	char *pname, *pnbname, cname, cnbname;
	const u_char *pd_save;

	name_len = get_dns_name(nbns_data_ptr, pd, offset, name, sizeof(name));
	pd += offset;
	pd_save = pd;
	pd += name_len;
	
	type = pntohs(pd);
	pd += 2;
	class = pntohs(pd);
	pd += 2;

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
	*type_ret = type;
	*class_ret = class;
	*name_len_ret = name_len;

	len = pd - pd_save;
	return len;
}


static int
dissect_nbns_query(const u_char *nbns_data_ptr, const u_char *pd, int offset,
    GtkWidget *nbns_tree)
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
	GtkWidget *q_tree, *tq;

	data_start = dptr = pd + offset;

	len = get_nbns_name_type_class(nbns_data_ptr, pd, offset, name,
	    &name_len, &type, &class);
	dptr += len;

	type_name = nbns_type_name(type);
	class_name = dns_class_name(class);

	tq = add_item_to_tree(nbns_tree, offset, len, "%s: type %s, class %s", 
	    name, type_name, class_name);
	q_tree = gtk_tree_new();
	add_subtree(tq, q_tree, ETT_NBNS_QD);

	add_item_to_tree(q_tree, offset, name_len, "Name: %s", name);
	offset += name_len;

	add_item_to_tree(q_tree, offset, 2, "Type: %s", type_name);
	offset += 2;

	add_item_to_tree(q_tree, offset, 2, "Class: %s", class_name);
	offset += 2;
	
	return dptr - data_start;
}


static int
dissect_nbns_answer(const u_char *nbns_data_ptr, const u_char *pd, int offset,
    GtkWidget *nbns_tree, int opcode)
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
	GtkWidget *rr_tree, *trr;

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
		trr = add_item_to_tree(nbns_tree, offset,
		    (dptr - data_start) + data_len,
		    "%s: type %s, class %s",
		    name, type_name, class_name);
		rr_tree = add_rr_to_tree(trr, ETT_NBNS_RR, offset, name,
		    name_len, type_name, class_name, ttl, data_len);
		offset += (dptr - data_start);
		while (data_len > 0) {
			if (opcode == 0x7) {
				/* WACK response.  This doesn't contain the
				 * same type of RR data as other T_NB
				 * responses.  */
				if (data_len < 2) {
					add_item_to_tree(rr_tree, offset,
					    data_len, "(incomplete entry)");
					break;
				}
				flags = pntohs(dptr);
				dptr += 2;
				add_item_to_tree(rr_tree, offset, 2,
				    "Flags: 0x%x", flags);
				offset += 2;
				data_len -= 2;
			} else {
				if (data_len < 2) {
					add_item_to_tree(rr_tree, offset,
					    data_len, "(incomplete entry)");
					break;
				}
				flags = pntohs(dptr);
				dptr += 2;
				add_item_to_tree(rr_tree, offset, 2,
				    "Flags: 0x%x", flags);
				offset += 2;
				data_len -= 2;

				if (data_len < 4) {
					add_item_to_tree(rr_tree, offset,
					    data_len, "(incomplete entry)");
					break;
				}
				add_item_to_tree(rr_tree, offset, 4,
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
			
			trr = add_item_to_tree(nbns_tree, offset,
			    (dptr - data_start) + data_len,
			    "%s: type %s, class %s",
			    name, type_name, class_name);
			rr_tree = add_rr_to_tree(trr, ETT_NBNS_RR, offset, name,
			    name_len, type_name, class_name, ttl, data_len);
			offset += (dptr - data_start);
			if (data_len < 1) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			num_names = *dptr;
			dptr += 1;
			add_item_to_tree(rr_tree, offset, 2,
			    "Number of names: %u", num_names);
			offset += 1;

			while (num_names != 0) {
				if (data_len < 16) {
					add_item_to_tree(rr_tree, offset,
					    data_len, "(incomplete entry)");
					goto out;
				}
				memcpy(nbname, dptr, 16);
				dptr += 16;
				canonicalize_netbios_name(nbname);
				add_item_to_tree(rr_tree, offset, 16,
				    "Name: %s", nbname);
				offset += 16;
				data_len -= 16;

				if (data_len < 2) {
					add_item_to_tree(rr_tree, offset,
					    data_len, "(incomplete entry)");
					goto out;
				}
				name_flags = pntohs(dptr);
				dptr += 2;
				add_item_to_tree(rr_tree, offset, 2,
				    "Name flags: 0x%x", name_flags);
				offset += 2;
				data_len -= 2;

				num_names--;
			}

			if (data_len < 6) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 6,
			    "Unit ID: %s",
			    ether_to_str((guint8 *)dptr));
			dptr += 6;
			offset += 6;
			data_len -= 6;

			if (data_len < 1) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 1,
			    "Jumpers: 0x%x", *dptr);
			dptr += 1;
			offset += 1;
			data_len -= 1;

			if (data_len < 1) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 1,
			    "Test result: 0x%x", *dptr);
			dptr += 1;
			offset += 1;
			data_len -= 1;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Version number: 0x%x", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Period of statistics: 0x%x", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Number of CRCs: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Number of alignment errors: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Number of collisions: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Number of send aborts: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 4) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 4,
			    "Number of good sends: %u", pntohl(dptr));
			dptr += 4;
			offset += 4;
			data_len -= 4;

			if (data_len < 4) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 4,
			    "Number of good receives: %u", pntohl(dptr));
			dptr += 4;
			offset += 4;
			data_len -= 4;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Number of retransmits: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Number of no resource conditions: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Number of command blocks: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Number of pending sessions: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Max number of pending sessions: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;

			add_item_to_tree(rr_tree, offset, 2,
			    "Max total sessions possible: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;

			if (data_len < 2) {
				add_item_to_tree(rr_tree, offset,
				    data_len, "(incomplete entry)");
				break;
			}
			add_item_to_tree(rr_tree, offset, 2,
			    "Session data packet size: %u", pntohs(dptr));
			dptr += 2;
			offset += 2;
			data_len -= 2;
		}
	out:
		break;

	default:
		trr = add_item_to_tree(nbns_tree, offset,
		    (dptr - data_start) + data_len,
                    "%s: type %s, class %s",
		    name, type_name, class_name);
		rr_tree = add_rr_to_tree(trr, ETT_NBNS_RR, offset, name,
		    name_len, type_name, class_name, ttl, data_len);
		offset += (dptr - data_start);
		add_item_to_tree(rr_tree, offset, data_len, "Data");
		break;
	}
	dptr += data_len;
	
	return dptr - data_start;
}

static int
dissect_query_records(const u_char *nbns_data_ptr, int count, const u_char *pd, 
    int cur_off, GtkWidget *nbns_tree)
{
	int start_off;
	GtkWidget *qatree, *ti;
	
	qatree = gtk_tree_new();
	start_off = cur_off;
	
	while (count-- > 0)
		cur_off += dissect_nbns_query(nbns_data_ptr, pd, cur_off, qatree);
	ti = add_item_to_tree(GTK_WIDGET(nbns_tree), 
			start_off, cur_off - start_off, "Queries");
	add_subtree(ti, qatree, ETT_NBNS_QRY);

	return cur_off - start_off;
}



static int
dissect_answer_records(const u_char *nbns_data_ptr, int count,
    const u_char *pd, int cur_off, GtkWidget *nbns_tree, int opcode, char *name)
{
	int start_off;
	GtkWidget *qatree, *ti;
	
	qatree = gtk_tree_new();
	start_off = cur_off;

	while (count-- > 0)
		cur_off += dissect_nbns_answer(nbns_data_ptr, pd, cur_off,
					qatree, opcode);
	ti = add_item_to_tree(GTK_WIDGET(nbns_tree), start_off, cur_off - start_off, name);
	add_subtree(ti, qatree, ETT_NBNS_ANS);

	return cur_off - start_off;
}

void
dissect_nbns(const u_char *pd, int offset, frame_data *fd, GtkTree *tree)
{
	GtkWidget		*nbns_tree, *ti;
	struct nbns_header	header;
	int			nm_flags;
	const u_char		*nbns_data_ptr;
	int			cur_off;

	char *opcode[] = {
		"Query",
		"Unknown operation (1)",
		"Unknown operation (2)",
		"Unknown operation (3)",
		"Unknown operation (4)",
		"Registration",
		"Release",
		"Wait and Acknowledge",
		"Refresh",
		"Refresh(altcode)",
		"Unknown operation (10)",
		"Unknown operation (11)",
		"Unknown operation (12)",
		"Unknown operation (13)",
		"Unknown operation (14)",
		"Multi-Homed Registration",
	};

	nbns_data_ptr = &pd[offset];

	/* This is taken from samba/source/nmlib.c, parse_nmb() */
	header.name_tran_id = pntohs(&pd[offset]);
	header.opcode = (pd[offset+2] >> 3) & 0xf;
	header.r = (pd[offset+2] >> 7) & 1;

	nm_flags = ((pd[offset+2] & 0x7) << 4) + (pd[offset+3] >> 4);
	header.nm_flags.bcast = (nm_flags & 1) ? 1 : 0;
	header.nm_flags.recursion_available = (nm_flags & 8) ? 1 : 0;
	header.nm_flags.recursion_desired = (nm_flags & 0x10) ? 1 : 0;
	header.nm_flags.trunc = (nm_flags & 0x20) ? 1 : 0;
	header.nm_flags.authoritative = (nm_flags & 0x40) ? 1 : 0;

	header.rcode = pd[offset+3] & 0xf;
	header.qdcount = pntohs(&pd[offset+4]);
	header.ancount = pntohs(&pd[offset+6]);
	header.nscount = pntohs(&pd[offset+8]);
	header.arcount = pntohs(&pd[offset+10]);

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NBNS (UDP)");
	if (check_col(fd, COL_INFO)) {
		if (header.opcode <= 15) {
			col_add_fstr(fd, COL_INFO, "%s %s",
			    opcode[header.opcode], header.r ? "reply" : "request");
		} else {
			col_add_fstr(fd, COL_INFO, "Unknown operation (%d) %s",
			    header.opcode, header.r ? "reply" : "request");
		}
	}

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, END_OF_FRAME,
				"NetBIOS Name Service");
		nbns_tree = gtk_tree_new();
		add_subtree(ti, nbns_tree, ETT_NBNS);

		add_item_to_tree(nbns_tree, offset,	 2, "Transaction ID: 0x%04X",
				header.name_tran_id);
		add_item_to_tree(nbns_tree, offset +  2, 1, "Type: %s",
				header.r == 0 ? "Request" : "Response" );
		
		if (header.opcode <= 15) {
			add_item_to_tree(nbns_tree, offset + 2, 1, "Operation: %s (%d)",
					opcode[header.opcode], header.opcode);
		}
		else {
			add_item_to_tree(nbns_tree, offset + 2, 1, "Operation: Unknown (%d)",
					header.opcode);
		}
		add_item_to_tree(nbns_tree, offset +  4, 2, "Questions: %d",
					header.qdcount);
		add_item_to_tree(nbns_tree, offset +  6, 2, "Answer RRs: %d",
					header.ancount);
		add_item_to_tree(nbns_tree, offset +  8, 2, "Authority RRs: %d",
					header.nscount);
		add_item_to_tree(nbns_tree, offset + 10, 2, "Additional RRs: %d",
					header.arcount);

		cur_off = offset + 12;
    
		if (header.qdcount > 0)
			cur_off += dissect_query_records(nbns_data_ptr,
					header.qdcount, pd, cur_off, nbns_tree);

		if (header.ancount > 0)
			cur_off += dissect_answer_records(nbns_data_ptr,
					header.ancount, pd, cur_off, nbns_tree,
					header.opcode, "Answers");

		if (header.nscount > 0)
			cur_off += dissect_answer_records(nbns_data_ptr,
					header.nscount,	pd, cur_off, nbns_tree, 
					header.opcode,
					"Authoritative nameservers");

		if (header.arcount > 0)
			cur_off += dissect_answer_records(nbns_data_ptr,
					header.arcount, pd, cur_off, nbns_tree, 
					header.opcode, "Additional records");
	}
}


void
dissect_nbdgm(const u_char *pd, int offset, frame_data *fd, GtkTree *tree)
{
	GtkWidget		*nbdgm_tree, *ti;
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
	int len, name_len, type, class;

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
		col_add_str(fd, COL_PROTOCOL, "NetBIOS");
	if (check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "%s", message[message_index]);
	}

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, header.dgm_length,
				"NetBIOS Datagram");
		nbdgm_tree = gtk_tree_new();
		add_subtree(ti, nbdgm_tree, ETT_NBDGM);

		add_item_to_tree(nbdgm_tree, offset, 1, "Message Type: %s",
				message[message_index]);
		add_item_to_tree(nbdgm_tree, offset+1, 1, "More fragments follow: %s",
				yesno[header.flags.more]);
		add_item_to_tree(nbdgm_tree, offset+1, 1, "This is first fragment: %s",
				yesno[header.flags.first]);
		add_item_to_tree(nbdgm_tree, offset+1, 1, "Node Type: %s",
				node[header.flags.node_type]);

		add_item_to_tree(nbdgm_tree, offset+2, 2, "Datagram ID: 0x%04X",
				header.dgm_id);
		add_item_to_tree(nbdgm_tree, offset+4, 4, "Source IP: %s",
				ip_to_str((guint8 *)&header.src_ip));
		add_item_to_tree(nbdgm_tree, offset+8, 2, "Source Port: %d",
				header.src_port);

		offset += 10;

		if (header.msg_type == 0x10 ||
				header.msg_type == 0x11 || header.msg_type == 0x12) {

			add_item_to_tree(nbdgm_tree, offset, 2,
					"Datagram length: %d bytes", header.dgm_length);
			add_item_to_tree(nbdgm_tree, offset+2, 2,
					"Packet offset: %d bytes", header.pkt_offset);

			offset += 4;

			/* Source name */
			len = get_nbns_name_type_class(&pd[offset], pd, offset, name,
				&name_len, &type, &class);

			len -= 4;
			add_item_to_tree(nbdgm_tree, offset, len, "Source name: %s",
					name);
			offset += len;

			/* Destination name */
			len = get_nbns_name_type_class(&pd[offset], pd, offset, name,
				&name_len, &type, &class);

			len -= 4;
			add_item_to_tree(nbdgm_tree, offset, len, "Destination name: %s",
					name);
			offset += len;

			/* here we can pass the packet off to the next protocol */
		}
		else if (header.msg_type == 0x13) {
			add_item_to_tree(nbdgm_tree, offset, 1, "Error code: %s",
				match_strval(header.error_code, error_codes));
		}
		else {
			/* Destination name */
			len = get_nbns_name_type_class(&pd[offset], pd, offset, name,
				&name_len, &type, &class);

			len -= 4;
			add_item_to_tree(nbdgm_tree, offset, len, "Destination name: %s",
					name);
		}

	}
}
