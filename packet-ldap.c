/* packet-ldap.c
 * Routines for ldap packet dissection
 *
 * $Id: packet-ldap.c,v 1.1 1999/12/09 04:06:53 nneul Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

static int proto_ldap = -1;
static int hf_ldap_request = -1;
static int hf_ldap_response = -1;
static int hf_ldap_command = -1;

static gint ett_ldap = -1;

void dissect_ldap_request(proto_tree *tree, char *line, int offset, int len)
{
	proto_tree_add_item_hidden(tree, hf_ldap_request,
		offset, len, TRUE);
	proto_tree_add_text(tree, offset, 
		len, "Request Line: %s", line);
}

void dissect_ldap_response(proto_tree *tree, char *line, int offset, int len)
{
	proto_tree_add_item_hidden(tree, hf_ldap_response,
		offset, len, TRUE);
	proto_tree_add_text(tree, offset, 
		len, "Response Line: %s", line);
}

void
dissect_ldap(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *ldap_tree, *ti;
	char *tmpline;
	int start, cur, len;
	const u_char *i;

	if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "LDAP");

	if (check_col(fd, COL_INFO))
	{
		col_add_fstr(fd, COL_INFO, "%s", 
			(pi.match_port == pi.destport) ? "Request" : "Response");	  
	}

	if (tree) 
	{
		ti = proto_tree_add_item(tree, proto_ldap, offset, END_OF_FRAME, NULL);
		ldap_tree = proto_item_add_subtree(ti, ett_ldap);

		tmpline = (char *)g_malloc( pi.captured_len );
		i = pd+offset;
		while ( i < pd + pi.captured_len )
		{
			start = i - pd;
			cur = 0;
			len = 0;
			tmpline[cur] = 0;

			/* copy up to end or cr/nl */
			while ( i < pd + pi.captured_len && *i != '\r' && *i != '\n' )
			{
				tmpline[cur++] = *(i++);
				len++;
			}
			tmpline[cur] = 0;

			/* skip any CR/NL */
			while ( i < pd + pi.captured_len && 
				(*i == '\r' || *i == '\n') )
			{
				i++;
				len++;
			}

			if ( strlen(tmpline) > 0 )
			{
				if (pi.match_port == pi.destport)
				{
					dissect_ldap_request(ldap_tree, tmpline, start, len);
				}
				else
				{
					dissect_ldap_response(ldap_tree, tmpline, start, len);
				}
			}
		}
		g_free(tmpline);
		tmpline = 0;
	}
}

void
proto_register_ldap(void)
{
	static hf_register_info hf[] = {
	  { &hf_ldap_response,
	    { "Response",           "ldap.response",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if LDAP response" }},
	  
	  { &hf_ldap_request,
	    { "Request",            "ldap.request",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if LDAP request" }},

	  { &hf_ldap_command,
	    { "Command",            "ldap.command",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Command associated with request" }}
	};

	static gint *ett[] = {
		&ett_ldap,
	};
	proto_ldap = proto_register_protocol("Lightweight Directory Access Protocol", "ldap");
	proto_register_field_array(proto_ldap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
