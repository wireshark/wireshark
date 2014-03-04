/* codecs.h
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

#ifndef _CODECS_H_
#define _CODECS_H_

#include "config.h"

#include <epan/epan.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef HAVE_PLUGINS
extern void codec_register_plugin_types(void);
extern void register_all_codecs(void);
#endif

struct codec_handle;
typedef struct codec_handle *codec_handle_t;

typedef void *(*codec_init_fn)(void);
typedef void (*codec_release_fn)(void *context);
typedef int (*codec_get_channels_fn)(void *context);
typedef int (*codec_get_frequency_fn)(void *context);
typedef int (*codec_decode_fn)(void *context, const void *input, int inputSizeBytes,
        void *output, int *outputSizeBytes);

extern gboolean register_codec(const char *name, codec_init_fn init_fn,
        codec_release_fn release_fn, codec_get_channels_fn channels_fn,
        codec_get_frequency_fn frequency_fn, codec_decode_fn decode_fn);
extern codec_handle_t find_codec(const char *name);
extern void *codec_init(codec_handle_t codec);
extern void codec_release(codec_handle_t codec, void *context);
extern int codec_get_channels(codec_handle_t codec, void *context);
extern int codec_get_frequency(codec_handle_t codec, void *context);
extern int codec_decode(codec_handle_t codec, void *context, const void *input,
        int inputSizeBytes, void *output, int *outputSizeBytes);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CODECS_H_ */

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
