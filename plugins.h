/* plugins.h
 * definitions for plugins structures
 *
 * $Id: plugins.h,v 1.6 2000/03/31 21:42:24 oabad Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1999 Gerald Combs
 *
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

#ifndef __PLUGINS_H__
#define __PLUGINS_H__

#include <glib.h>
#include <gmodule.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#ifdef HAVE_DLFCN_H
#define HAVE_PLUGINS 1
#endif
#endif /* HAVE_CONFIG_H */

#ifndef __DFILTER_H__
#include "dfilter.h"
#endif

#ifndef __PACKET_H__
#include "packet.h"
#endif

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

typedef struct _plugin {
    GModule	*handle;          /* handle returned by dlopen */
    gchar       *name;            /* plugin name */
    gchar       *version;         /* plugin version */
    gboolean     enabled;         /* is it active ? */
    gchar       *protocol;        /* protocol which should call the dissector
                                   * for this plugin eg "tcp" */
    gchar       *filter_string;   /* display filter string matching frames for
			           * which the dissector should be used */
    dfilter     *filter;          /* compiled display filter */
    /* the dissector */
    void (*dissector) (const u_char *, int, frame_data *, proto_tree *);
    struct _plugin *next;     /* forward link */
} plugin;

extern plugin *plugin_list;
extern guint32 enabled_plugins_number;

int add_plugin(void *, gchar *, gchar *, gchar *, gchar *, dfilter *,
	          void (*) (const u_char *, int, frame_data *, proto_tree *));
void *enable_plugin(const gchar *, const gchar *);
void *disable_plugin(const gchar *, const gchar *);
void *find_plugin(const gchar *, const gchar *);
gboolean is_enabled(const gchar *, const gchar *);
void plugin_replace_filter(const gchar *, const gchar *, const gchar *, dfilter *);
int save_plugin_status();
void init_plugins();

#endif /* __PLUGINS_H__ */
