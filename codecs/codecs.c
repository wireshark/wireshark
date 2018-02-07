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

#include <glib.h>
#include "codecs.h"

#include "G711a/G711adecode.h"
#include "G711u/G711udecode.h"

#ifdef HAVE_SBC
#include "sbc/sbc_private.h"
#endif

#ifdef HAVE_SPANDSP
#include "G722/G722decode.h"
#include "G726/G726decode.h"
#endif

#ifdef HAVE_BCG729
#include "G729/G729decode.h"
#endif

#ifdef HAVE_PLUGINS


static plugins_t *libwscodecs_plugins;
static GSList *codecs_plugins = NULL;

void
codecs_register_plugin(const codecs_plugin *plug)
{
    codecs_plugins = g_slist_prepend(codecs_plugins, (codecs_plugin *)plug);
}

static void
call_plugin_register_codec_module(gpointer data, gpointer user_data _U_)
{
    codecs_plugin *plug = (codecs_plugin *)data;

    if (plug->register_codec_module) {
        plug->register_codec_module();
    }
}
#endif /* HAVE_PLUGINS */


/*
 * For all codec plugins, call their register routines.
 */
void
codecs_init(void)
{
    register_codec("g711U", codec_g711u_init, codec_g711u_release,
            codec_g711u_get_channels, codec_g711u_get_frequency, codec_g711u_decode);
    register_codec("g711A", codec_g711a_init, codec_g711a_release,
            codec_g711a_get_channels, codec_g711a_get_frequency, codec_g711a_decode);
#ifdef HAVE_SPANDSP
    register_codec("g722", codec_g722_init, codec_g722_release,
            codec_g722_get_channels, codec_g722_get_frequency, codec_g722_decode);
    register_codec("G726-16", codec_g726_16_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("G726-24", codec_g726_24_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("G726-32", codec_g726_32_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("G726-40", codec_g726_40_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("AAL2-G726-16", codec_aal2_g726_16_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("AAL2-G726-24", codec_aal2_g726_24_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("AAL2-G726-32", codec_aal2_g726_32_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("AAL2-G726-40", codec_aal2_g726_40_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
#endif
#ifdef HAVE_BCG729
    register_codec("g729", codec_g729_init, codec_g729_release,
            codec_g729_get_channels, codec_g729_get_frequency, codec_g729_decode);
#endif
#ifdef HAVE_SBC
    register_codec("SBC", codec_sbc_init, codec_sbc_release,
            codec_sbc_get_channels, codec_sbc_get_frequency, codec_sbc_decode);
#endif

#ifdef HAVE_PLUGINS
    libwscodecs_plugins = plugins_init(WS_PLUGIN_CODEC);
    g_slist_foreach(codecs_plugins, call_plugin_register_codec_module, NULL);
#endif /* HAVE_PLUGINS */
}

void
codecs_cleanup(void)
{
#ifdef HAVE_PLUGINS
    g_slist_free(codecs_plugins);
    codecs_plugins = NULL;
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

/**
 * Get compile-time information for libraries used by libwscodecs.
 */
void codec_get_compiled_version_info(GString *str)
{
    /* SBC */
#ifdef HAVE_SBC
    g_string_append(str, ", with SBC");
#else
    g_string_append(str, ", without SBC");
#endif

    /* SpanDSP (G.722, G.726) */
#ifdef HAVE_SPANDSP
    g_string_append(str, ", with SpanDSP");
#else
    g_string_append(str, ", without SpanDSP");
#endif

    /* BCG729 (G.729) */
#ifdef HAVE_BCG729
    g_string_append(str, ", with bcg729");
#else
    g_string_append(str, ", without bcg729");
#endif
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
