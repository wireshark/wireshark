/* packet-pw-common.c
 * Common functions and objects for PWE3 dissectors.
 * Copyright 2009, Artem Tamazov <artem.tamazov@tellabs.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include "packet-pw-common.h"

static const char string_ok[] = "Ok";

const value_string
pwc_vals_cw_l_bit[] = {
	{ 0x0,	string_ok },
	{ 0x1,	"Attachment Circuit Fault" },
	{ 0,	NULL }
};
	

const value_string
pwc_vals_cw_r_bit[] = {
	{ 0x0,	string_ok },
	{ 0x1,	"Packet Loss State" },
	{ 0,	NULL }
};

const value_string
pwc_vals_cw_frag[] = {
	{ 0x0,	"Unfragmented" },
	{ 0x1,	"First fragment" },
	{ 0x2,	"Last fragment" },
	{ 0x3,	"Intermediate fragment" },
	{ 0,	NULL }
};


int pwc_value_listed_in_vals(const guint32 val, const value_string * vals)
{
	if (NULL != vals)
	{
		while (vals->strptr != NULL)
		{
			if (val == vals->value)
			{
				return (1==1);
			}
			++vals;
		}
	}
	return 0;
}

void pwc_item_append_cw(proto_item* item, const guint32 cw, const gboolean append_text)
{
	if (item != NULL)
	{
		if (append_text)
		{
			proto_item_append_text(item, ", CW");
		}
		proto_item_append_text(item, ": 0x%.8" G_GINT32_MODIFIER "x", cw);
	}
	return;
}


void pwc_item_append_text_n_items(proto_item* item, const int n, const char * const item_text)
{
	assert(item != 0);
	proto_item_append_text(item, ", %d %s%s", n, item_text, plurality(n,"","s"));
	return;
}


