
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan.h>

#include "plugins.h"
#include "conversation.h"
#include "dfilter.h"
#include "except.h"
#include "packet.h"
#include "proto.h"
#include "tvbuff.h"

void
epan_init(void)
{
	except_init();
	tvbuff_init();
	packet_init();
	proto_init();
	dfilter_init();
#ifdef HAVE_PLUGINS
	init_plugins();
#endif
}

void
epan_cleanup(void)
{
	dfilter_cleanup();
	proto_cleanup();
	packet_cleanup();
	tvbuff_cleanup();
	except_deinit();
}


void
epan_conversation_init(void)
{
	conversation_init();
}


struct epan_dissect {

	tvbuff_t	*tvb;
	proto_tree	*tree;
};

epan_dissect_t*
epan_dissect_new(void* pseudo_header, const guint8* data, frame_data *fd, proto_tree *tree)
{
	epan_dissect_t	*edt;

	edt = g_new(epan_dissect_t, 1);

	/* XXX - init tree */
	dissect_packet(&edt->tvb, pseudo_header, data, fd, tree);

	return edt;
}


void
epan_dissect_free(epan_dissect_t* edt)
{
	/* Free all tvb's created from this tvb, unless dissector
	 * wanted to store the pointer (in which case, the dissector
	 * would have incremented the usage count on that tvbuff_t*) */
	tvb_free_chain(edt->tvb);

	g_free(edt);
}
