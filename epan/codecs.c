/* codecs.c
 * codecs interface   2007 Tomas Kukosa
 *
 * $Id$
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

#include <epan/codecs.h>

struct codec_handle {
	const char *name;
	codec_init_fn init_fn;
	codec_release_fn release_fn;
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
	return (registered_codecs) ? g_hash_table_lookup(registered_codecs, name) : NULL;
}

/* Register a codec by name. */
void
register_codec(const char *name, codec_init_fn init_fn, codec_release_fn release_fn, codec_decode_fn decode_fn)
{
	struct codec_handle *handle;

	/* Create our hash table if it doesn't already exist */
	if (registered_codecs == NULL) {
		registered_codecs = g_hash_table_new(g_str_hash, g_str_equal);
		g_assert(registered_codecs != NULL);
	}

	/* Make sure the registration is unique */
	g_assert(g_hash_table_lookup(registered_codecs, name) == NULL);

	handle = g_malloc(sizeof (struct codec_handle));
	handle->name = name;
	handle->init_fn = init_fn;
	handle->release_fn = release_fn;
	handle->decode_fn = decode_fn;

	g_hash_table_insert(registered_codecs, (gpointer)name, (gpointer) handle);
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

int codec_decode(codec_handle_t codec, void *context, const void *input, int inputSizeBytes, void *output, int *outputSizeBytes)
{
	if (!codec) return 0;
	return (codec->decode_fn)(context, input, inputSizeBytes, output, outputSizeBytes);
}
