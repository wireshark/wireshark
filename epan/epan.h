/* epan.h
 *
 * Ethereal Protocol Analyzer Library
 *
 */

#ifndef EPAN_H

#include <glib.h>
	
void epan_init(void);
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
typedef struct epan_dissect epan_dissect_t;


epan_dissect_t*
epan_dissect_new(epan_t*, guint8* data, guint len, guint32 wtap_encap,
		void* pseudo_header);

void
epan_dissect_free(epan_t*, epan_dissect_t*);

/* Should this be ".libepan"? For backwards-compatibility, I'll keep
 * it ".ethereal" for now.
 */
#define PF_DIR ".ethereal"

#endif /* EPAN_H */
