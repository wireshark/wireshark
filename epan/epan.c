
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan.h>

#include "plugins.h"
#include "conversation.h"
#include "dfilter.h"
#include "except.h"
#include "proto.h"
#include "tvbuff.h"

void
epan_init(void)
{
	except_init();
	tvbuff_init();
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
	tvbuff_cleanup();
	except_deinit();
}


void
epan_conversation_init(void)
{
	conversation_init();
}
