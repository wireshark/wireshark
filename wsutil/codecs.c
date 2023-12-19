/* codecs.c
 * codecs interface   2007 Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "codecs.h"

#include <wsutil/wslog.h>
#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#ifdef HAVE_PLUGINS
static plugins_t *libwscodecs_plugins;
#endif

static GSList *codecs_plugins;

#ifdef HAVE_PLUGINS
void
codecs_register_plugin(const codecs_plugin *plug)
{
    codecs_plugins = g_slist_prepend(codecs_plugins, (codecs_plugin *)plug);
}
#else /* HAVE_PLUGINS */
void
codecs_register_plugin(const codecs_plugin *plug _U_)
{
	ws_warning("codecs_register_plugin: built without support for binary plugins");
}
#endif /* HAVE_PLUGINS */

static void
call_plugin_register_codec_module(void * data, void * user_data _U_)
{
    codecs_plugin *plug = (codecs_plugin *)data;

    if (plug->register_codec_module) {
        plug->register_codec_module();
    }
}


/*
 * For all codec plugins, call their register routines.
 */
void
codecs_init(void)
{
#ifdef HAVE_PLUGINS
    libwscodecs_plugins = plugins_init(WS_PLUGIN_CODEC);
#endif
    g_slist_foreach(codecs_plugins, call_plugin_register_codec_module, NULL);
}

void
codecs_cleanup(void)
{
    g_slist_free(codecs_plugins);
    codecs_plugins = NULL;
#ifdef HAVE_PLUGINS
    plugins_cleanup(libwscodecs_plugins);
    libwscodecs_plugins = NULL;
#endif
}


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
static GHashTable *registered_codecs;


/* Find a registered codec by name. */
codec_handle_t
find_codec(const char *name)
{
    codec_handle_t ret;
    char *key = g_ascii_strup(name, -1);

    ret = (registered_codecs) ? (codec_handle_t)g_hash_table_lookup(registered_codecs, key) : NULL;
    g_free(key);
    return ret;
}

/* Register a codec by name. */
bool
register_codec(const char *name, codec_init_fn init_fn, codec_release_fn release_fn,
        codec_get_channels_fn channels_fn, codec_get_frequency_fn frequency_fn,
        codec_decode_fn decode_fn)
{
    struct codec_handle *handle;
    char *key;

    /* Create our hash table if it doesn't already exist */
    if (registered_codecs == NULL)
        registered_codecs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    /* RFC 4855 3. Mapping to SDP Parameters "Note that the payload format
     * (encoding) names... are commonly shown in upper case. These names
     * are case-insensitive in both places."
     */
    key = g_ascii_strup(name, -1);

    /* Make sure the registration is unique */
    if (g_hash_table_lookup(registered_codecs, key) != NULL) {
        g_free(key);
        return false;    /* report an error, or have our caller do it? */
    }

    handle = g_new(struct codec_handle, 1);
    handle->name = name;
    handle->init_fn = init_fn;
    handle->release_fn = release_fn;
    handle->channels_fn = channels_fn;
    handle->frequency_fn = frequency_fn;
    handle->decode_fn = decode_fn;

    g_hash_table_insert(registered_codecs, (void *)key, (void *) handle);
    return true;
}

/* Deregister a codec by name. */
bool
deregister_codec(const char *name)
{
    bool ret = false;
    if (registered_codecs) {
        char *key = g_ascii_strup(name, -1);

        ret = g_hash_table_remove(registered_codecs, key);
        g_free(key);
    }
    return ret;
}

void *codec_init(codec_handle_t codec, codec_context_t *context)
{
    if (!codec) return NULL;
    return (codec->init_fn)(context);
}

void codec_release(codec_handle_t codec, codec_context_t *context)
{
    if (!codec) return;
    (codec->release_fn)(context);
}

unsigned codec_get_channels(codec_handle_t codec, codec_context_t *context)
{
    if (!codec) return 0;
    return (codec->channels_fn)(context);
}

unsigned codec_get_frequency(codec_handle_t codec, codec_context_t *context)
{
    if (!codec) return 0;
    return (codec->frequency_fn)(context);
}

size_t codec_decode(codec_handle_t codec, codec_context_t *context, const void *input, size_t inputSizeBytes, void *output, size_t *outputSizeBytes)
{
    if (!codec) return 0;
    return (codec->decode_fn)(context, input, inputSizeBytes, output, outputSizeBytes);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
