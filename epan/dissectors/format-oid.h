/* format-oid.h
 * Declare routine for formatting OIDs
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Didier Jorand
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

#ifndef __FORMAT_OID_H__
#define __FORMAT_OID_H__

/*
 * Oh, this is hellish.
 *
 * The CMU SNMP library defines an OID as a sequence of "u_int"s,
 * unless EIGHTBIT_SUBIDS is defined, in which case it defines
 * an OID as a sequence of "u_char"s.  None of its header files
 * define EIGHTBIT_SUBIDS, and if a program defines it, that's
 * not going to change the library to treat OIDs as sequences
 * of "u_chars", so I'll assume that it'll be "u_int"s.
 *
 * The UCD SNMP library does the same, except it defines an OID
 * as a sequence of "u_long"s, by default.
 *
 * "libsmi" defines it as a sequence of "unsigned int"s.
 *
 * I don't want to oblige all users of ASN.1 to include the SNMP
 * library header files, so I'll assume none of the SNMP libraries
 * will rudely surprise me by changing the definition; if they
 * do, there will be compiler warnings, so we'll at least be able
 * to catch it.
 *
 * This requires that, if you're going to use "asn1_subid_decode()",
 * "asn1_oid_value_decode()", or "asn1_oid_decode()", you include
 * "config.h", to get the right #defines defined, so that we properly
 * typedef "subid_t".
 */
#if defined(HAVE_NET_SNMP)
typedef gulong	subid_t;	/* Net-SNMP */
#else
typedef guint	subid_t;	/* CMU SNMP, UCD SNMP, libsmi, or nothing */
#endif

extern int oid_to_subid_buf(const guint8 *oid, gint oid_len, subid_t *buf, int buf_len);
extern gchar *format_oid(subid_t *oid, guint oid_length);
extern void new_format_oid(subid_t *oid, guint oid_length, 
			   gchar **non_decoded, gchar **decoded);

#endif
