/* epan.h
 *
 * $Id: epan.h,v 1.12 2001/12/18 19:09:03 gram Exp $
 *
 * Ethereal Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@ethereal.com>
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
 *
 */

#ifndef EPAN_H
#define EPAN_H

#include <glib.h>
#include "frame_data.h"
#include "column_info.h"

typedef struct _epan_dissect_t epan_dissect_t;

#include "dfilter/dfilter.h"

void epan_init(const char * plugindir, void (register_all_protocols)(void),
	       void (register_all_handoffs)(void));
void epan_cleanup(void);
void epan_conversation_init(void);



/* A client will create one epan_t for an entire dissection session.
 * A single epan_t will be used to analyze the entire sequence of packets,
 * sequentially, in a single session. A session corresponds to a single
 * packet trace file. The reaons epan_t exists is that some packets in
 * some protocols cannot be decoded without knowledge of previous packets.
 * This inter-packet "state" is stored in the epan_t.
 */
typedef struct epan_session epan_t;

epan_t*
epan_new(void);

void
epan_free(epan_t*);


epan_dissect_t*
epan_dissect_new(gboolean create_proto_tree, gboolean proto_tree_visible);

void
epan_dissect_run(epan_dissect_t *edt, void* pseudo_header,
        const guint8* data, frame_data *fd, column_info *cinfo);

void
epan_dissect_prime_dfilter(epan_dissect_t *edt, dfilter_t*);

void
epan_dissect_fill_in_columns(epan_dissect_t *edt);

void
epan_dissect_free(epan_dissect_t* edt);

#endif /* EPAN_H */
