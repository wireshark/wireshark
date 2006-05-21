/* packet-msn-messenger.c
 * Routines for MSN Messenger Service packet dissection
 * Copyright 2003, Chris Waters <chris@waters.co.nz>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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
#include <epan/strutil.h>

/*
 * The now-expired Internet-Draft for the MSN Messenger 1.0 protocol
 * can, as of the time of the writing of this comment, be found at:
 *
 *	http://praya.sourceforge.net/draft-movva-msn-messenger-protocol-00.txt
 *
 *	http://mono.es.gnome.org/imsharp/tutoriales/msn/appendixa.html
 *
 *	http://www.hypothetic.org/docs/msn/ietf_draft.php
 *
 *	http://babble.wundsam.net/docs/protocol-msn-im.txt
 *
 * Note that it's Yet Another FTP-Like Command/Response Protocol,
 * so it arguably should be dissected as such, although you do have
 * to worry about the MSG command, as only the first line of it
 * should be parsed as a command, the rest should be parsed as the
 * message body.  We therefore leave "hf_msnms_command", "tokenlen",
 * and "next_token", even though they're unused, as reminders that
 * this should be done.
 */

static int proto_msnms = -1;
/* static int hf_msnms_command = -1; */

static gint ett_msnms = -1;

static dissector_handle_t data_handle;

#define TCP_PORT_MSNMS			1863

static void
dissect_msnms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_tree      *msnms_tree;
	proto_item	*ti;
	gint		offset = 0;
	const guchar	*line;
	gint		next_offset;
	int		linelen;
	/* int		tokenlen; */
	/* const guchar	*next_token; */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSNMS");

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	line = tvb_get_ptr(tvb, offset, linelen);


	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary.
		 */
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
			    format_text(line, linelen));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_msnms, tvb, offset, -1,
		    FALSE);
		msnms_tree = proto_item_add_subtree(ti, ett_msnms);

		/*
		 * Show the rest of the packet as text,
		 * a line at a time.
		 */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * Find the end of the line.
			 */
			linelen = tvb_find_line_end(tvb, offset, -1,
			    &next_offset, FALSE);

			/*
			 * Put this line.
			 */
			proto_tree_add_text(msnms_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
		}
	}
}

void
proto_register_msnms(void)
{
  static gint *ett[] = {
    &ett_msnms,
  };

  proto_msnms = proto_register_protocol("MSN Messenger Service", "MSNMS", "msnms");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_msnms(void)
{
  dissector_handle_t msnms_handle;

  msnms_handle = create_dissector_handle(dissect_msnms, proto_msnms);
  dissector_add("tcp.port", TCP_PORT_MSNMS, msnms_handle);
  data_handle = find_dissector("data");
  /*
   * For MSN Messenger Protocol over HTTP
   */
  dissector_add_string("media_type", "application/x-msn-messenger", msnms_handle);
}
