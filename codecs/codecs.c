/* codecs.c
 * codecs interface   2007 Tomas Kukosa
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include "codecs.h"

#include "G711a/G711adecode.h"
#include "G711u/G711udecode.h"

#ifdef HAVE_SBC
#include "sbc/sbc_private.h"
#endif

#ifdef HAVE_PLUGINS

#include <gmodule.h>

#include <wsutil/plugins.h>

/*
 * List of codec plugins.
 */
typedef struct {
    void (*register_codec_module)(void);  /* routine to call to register a codec */
} codec_plugin;

static GSList *codec_plugins = NULL;

/*
 * Callback for each plugin found.
 */
static gboolean
check_for_codec_plugin(GModule *handle)
{
    gpointer gp;
    void (*register_codec_module)(void);
    codec_plugin *plugin;

    /*
     * Do we have a register_codec_module routine?
     */
    if (!g_module_symbol(handle, "register_codec_module", &gp)) {
        /* No, so this isn't a codec plugin. */
        return FALSE;
    }

    /*
     * Yes - this plugin includes one or more codecs.
     */
    register_codec_module = (void (*)(void))gp;

    /*
     * Add this one to the list of codec plugins.
     */
    plugin = (codec_plugin *)g_malloc(sizeof (codec_plugin));
    plugin->register_codec_module = register_codec_module;
    codec_plugins = g_slist_append(codec_plugins, plugin);
    return TRUE;
}

void
codec_register_plugin_types(void)
{
    add_plugin_type("codec", check_for_codec_plugin);
}

static void
register_codec_plugin(gpointer data, gpointer user_data _U_)
{
    codec_plugin *plugin = (codec_plugin *)data;

    (plugin->register_codec_module)();
}


/*
 * For all codec plugins, call their register routines.
 */
void
register_all_codecs(void)
{
    register_codec("g711U", codec_g711u_init, codec_g711u_release,
            codec_g711u_get_channels, codec_g711u_get_frequency, codec_g711u_decode);
    register_codec("g711A", codec_g711a_init, codec_g711a_release,
            codec_g711a_get_channels, codec_g711a_get_frequency, codec_g711a_decode);
#ifdef HAVE_SPANDSP
    register_codec("g722", codec_g722_init, codec_g722_release,
            codec_g722_get_channels, codec_g722_get_frequency, codec_g722_decode);
    register_codec("g726", codec_g726_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
#endif
#ifdef HAVE_SBC
    register_codec("SBC", codec_sbc_init, codec_sbc_release,
            codec_sbc_get_channels, codec_sbc_get_frequency, codec_sbc_decode);
#endif

    g_slist_foreach(codec_plugins, register_codec_plugin, NULL);
}
#endif /* HAVE_PLUGINS */

struct codec_handle {
    const char *name;
    codec_init_fn init_fn;
    codec_release_fn release_fn;
    codec_get_channels_fn channels_fn;
    codec_get_frequency_fn frequency_fn;
    codec_decode_fn decode_fn;
};

/*
 * List of registered codecs.
 */
static GHashTable *registered_codecs = NULL;


/* Find a registered codec by name. */
codec_handle_t
find_codec(const char *name)
{
    return (registered_codecs) ? (codec_handle_t)g_hash_table_lookup(registered_codecs, name) : NULL;
}

/* Register a codec by name. */
gboolean
register_codec(const char *name, codec_init_fn init_fn, codec_release_fn release_fn,
        codec_get_channels_fn channels_fn, codec_get_frequency_fn frequency_fn,
        codec_decode_fn decode_fn)
{
    struct codec_handle *handle;

    /* Create our hash table if it doesn't already exist */
    if (registered_codecs == NULL)
        registered_codecs = g_hash_table_new(g_str_hash, g_str_equal);

    /* Make sure the registration is unique */
    if (g_hash_table_lookup(registered_codecs, name) != NULL)
        return FALSE;    /* report an error, or have our caller do it? */

    handle = (struct codec_handle *)g_malloc(sizeof (struct codec_handle));
    handle->name = name;
    handle->init_fn = init_fn;
    handle->release_fn = release_fn;
    handle->channels_fn = channels_fn;
    handle->frequency_fn = frequency_fn;
    handle->decode_fn = decode_fn;

    g_hash_table_insert(registered_codecs, (gpointer)name, (gpointer) handle);
    return TRUE;
}

/* Deregister a codec by name. */
gboolean
deregister_codec(const char *name)
{
    gpointer key, value;

    if (registered_codecs && g_hash_table_lookup_extended(registered_codecs, name, &key, &value)) {
        g_hash_table_remove(registered_codecs, name);
        g_free(value);
        return TRUE;
    }
    return FALSE;
}

void *codec_init(codec_handle_t codec)
{
    if (!codec) return NULL;
    return (codec->init_fn)();
}

void codec_release(codec_handle_t codec, void *context)
{
    if (!codec) return;
    (codec->release_fn)(context);
}

unsigned codec_get_channels(codec_handle_t codec, void *context)
{
    if (!codec) return 0;
    return (codec->channels_fn)(context);
}

unsigned codec_get_frequency(codec_handle_t codec, void *context)
{
    if (!codec) return 0;
    return (codec->frequency_fn)(context);
}

size_t codec_decode(codec_handle_t codec, void *context, const void *input, size_t inputSizeBytes, void *output, size_t *outputSizeBytes)
{
    if (!codec) return 0;
    return (codec->decode_fn)(context, input, inputSizeBytes, output, outputSizeBytes);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
