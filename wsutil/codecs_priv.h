/** @file
 * codecs interface   2007 Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _CODECS_INT_H_
#define _CODECS_INT_H_

#include "codecs.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct codec_handle;
typedef struct codec_handle *codec_handle_t;

WS_DLL_PUBLIC bool deregister_codec(const char *name);

WS_DLL_PUBLIC codec_handle_t find_codec(const char *name);

WS_DLL_PUBLIC void *codec_init(codec_handle_t codec, codec_context_t *context);

WS_DLL_PUBLIC void codec_release(codec_handle_t codec, codec_context_t *context);

WS_DLL_PUBLIC unsigned codec_get_channels(codec_handle_t codec, codec_context_t *context);

WS_DLL_PUBLIC unsigned codec_get_frequency(codec_handle_t codec, codec_context_t *context);

WS_DLL_PUBLIC size_t codec_decode(codec_handle_t codec, codec_context_t *context,
        const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize);

/**
 * For all built-in codecs and codec plugins, call their register routines.
 */
WS_DLL_PUBLIC void codecs_init(void);

WS_DLL_PUBLIC void codecs_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CODECS_INT_H_ */

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
