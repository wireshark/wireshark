/* epan.h
 *
 * $Id: epan.h,v 1.11 2001/12/16 22:16:13 guy Exp $
 *
 * Ethereal Protocol Analyzer Library
 *
 */

#ifndef EPAN_H
#define EPAN_H

#include <glib.h>

struct _epan_dissect_t;

/* XXX - for now */
#include "packet.h"
#include "packet_info.h"

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




/* Dissection of a single byte array. Holds tvbuff info as
 * well as proto_tree info. As long as the epan_dissect_t for a byte
 * array is in existence, you must not free or move that byte array,
 * as the structures that the epan_dissect_t contains might have pointers
 * to addresses in your byte array.
 */
typedef struct _epan_dissect_t {
	tvbuff_t	*tvb;
	proto_tree	*tree;
	packet_info	pi;
} epan_dissect_t;

epan_dissect_t*
epan_dissect_new(void* pseudo_header, const guint8* data, frame_data *fd,
		gboolean create_proto_tree, gboolean proto_tree_visible,
		column_info *cinfo);

void
epan_dissect_free(epan_dissect_t* edt);

#endif /* EPAN_H */
