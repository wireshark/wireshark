/* expert.c
 * Collecting Expert information.
 *
 * Implemented as a tap named "expert".
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

#include "packet.h"
#include "expert.h"
#include "emem.h"
#include "tap.h"



static int expert_tap = -1;


void
expert_init(void)
{
	if(expert_tap == -1) {
		expert_tap = register_tap("expert");
	}
}

void
expert_cleanup(void)
{
	/* memory cleanup will be done by se_... */
}


/* set's the PI_ flags to a protocol item 
 * (and it's parent items till the toplevel) */
static void
expert_set_item_flags(proto_item *pi, int group, int severity)
{

	if(proto_item_set_expert_flags(pi, group, severity)) {
		/* propagate till toplevel item */
		pi = proto_item_get_parent(pi);
		expert_set_item_flags(pi, group, severity);
	}
}


static void
expert_set_info_vformat(
packet_info *pinfo, proto_item *pi, int group, int severity, const char *format, va_list ap)
{
	int				ret;	/*tmp return value */
	char			formatted[300];
	expert_info_t	*ei;


	/* if this packet isn't loaded because of a read filter, don't output anything */
	if(pinfo->fd->num == 0) {
		return;
	}

	/* XXX - use currently nonexistant se_vsnprintf instead */
	ret = g_vsnprintf(formatted, sizeof(formatted), format, ap);
	if ((ret == -1) || (ret >= sizeof(formatted)))
		formatted[sizeof(formatted) - 1] = '\0';

	ei = se_alloc(sizeof(expert_info_t));
	ei->packet_num	= pinfo ? pinfo->fd->num : 0;
	ei->group		= group;
	ei->severity	= severity;
	ei->protocol	= se_strdup(pinfo->current_proto);
	ei->summary		= se_strdup(formatted);

	/* if we have a proto_item (not a faked item), set expert attributes to it */
	if(pi != NULL && pi->finfo != NULL) {	
		expert_set_item_flags(pi, group, severity);
	}

	tap_queue_packet(expert_tap, pinfo, ei);
}


void
expert_add_info_format(
packet_info *pinfo, proto_item *pi, int group, int severity, const char *format, ...)
{
	va_list	ap;


	va_start(ap, format);
	expert_set_info_vformat(pinfo, pi, group, severity, format, ap);
	va_end(ap);
}


