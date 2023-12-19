/** @file
 * codecs interface   2007 Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _CODECS_H_
#define _CODECS_H_

#include "ws_symbol_export.h"
#include "ws_attributes.h"

#include <stdbool.h>

#include "wsutil/wmem/wmem_map.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    void (*register_codec_module)(void);  /* routine to call to register a codec */
} codecs_plugin;

WS_DLL_PUBLIC void codecs_register_plugin(const codecs_plugin *plug);

/**
 * For all built-in codecs and codec plugins, call their register routines.
 */
WS_DLL_PUBLIC void codecs_init(void);

WS_DLL_PUBLIC void codecs_cleanup(void);

/**
 * Get compile-time information for libraries used by libwscodecs.
 */
WS_DLL_PUBLIC void codec_get_compiled_version_info(GString *str);

struct codec_handle;
typedef struct codec_handle *codec_handle_t;

typedef struct _codec_context_t {
    unsigned sample_rate;
    unsigned channels;
    wmem_map_t *fmtp_map;
    void *priv; /* Private state set by the decoder */
} codec_context_t;

/*****************************************************************************/
/* Interface which must be implemented by a codec */
/* Codec decodes bytes to samples. Sample is 2 bytes! Codec writer must
 * be careful when API refers bytes and when samples and its counts.
 */
/*****************************************************************************/

/** Initialize context of codec.
 * Context can contain any information required by codec to pass between calls
 * Note: There is just one codec context in runtime therefore no RTP stream
 * related information should be stored in the context!
 *
 * @return Pointer to codec context
 */
typedef void *(*codec_init_fn)(codec_context_t *context);

/** Destroy context of codec
 *
 * @param context Pointer to codec context
 */
typedef void (*codec_release_fn)(codec_context_t *context);

/** Get count of channels provided by the codec
 *
 * @param context Pointer to codec context
 *
 * @return Count of channels (e.g. 1)
 */
typedef unsigned (*codec_get_channels_fn)(codec_context_t *context);

/** Get frequency/rate provided by the codec
 *
 * @param context Pointer to codec context
 *
 * @return Frequency (e.g. 8000)
 */
typedef unsigned (*codec_get_frequency_fn)(codec_context_t *context);

/** Decode one frame of payload
 *  Function is called twice, with different values of parameters:
 *  (1) To query size of required buffer in bytes for decoded samples
 *      pointed by inputBytes:
 *      outputSamples or outputSamplesSize must be set NULL
 *  (2) To decode samples:
 *      outputSamples points to allocated memory, outputSamplesSize is set to
 *      value returned in step (1)
 *
 * @param context Pointer to codec context
 * @param inputBytes Pointer to input frame
 * @param inputBytesSize Length of input frame in bytes
 *        (count of bytes to decode)
 * @param outputSamples Pointer to output buffer with samples
 * @param outputSamplesSize Length of output buffer in bytes (not samples!)
 *        Function can override this value. All codecs set it to same value as it returns in (2) when (2) is called.
 *
 * @return Count of reqired bytes (!not samples) to allocate in (1) or
 *         Count of decoded bytes (!not samples) in (2)
 */
typedef size_t (*codec_decode_fn)(codec_context_t *context,
        const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize);

/*****************************************************************************/
/* Codec registering interface */
/*****************************************************************************/

WS_DLL_PUBLIC bool register_codec(const char *name, codec_init_fn init_fn,
        codec_release_fn release_fn, codec_get_channels_fn channels_fn,
        codec_get_frequency_fn frequency_fn, codec_decode_fn decode_fn);
WS_DLL_PUBLIC bool deregister_codec(const char *name);
WS_DLL_PUBLIC codec_handle_t find_codec(const char *name);
WS_DLL_PUBLIC void *codec_init(codec_handle_t codec, codec_context_t *context);
WS_DLL_PUBLIC void codec_release(codec_handle_t codec, codec_context_t *context);
WS_DLL_PUBLIC unsigned codec_get_channels(codec_handle_t codec, codec_context_t *context);
WS_DLL_PUBLIC unsigned codec_get_frequency(codec_handle_t codec, codec_context_t *context);
WS_DLL_PUBLIC size_t codec_decode(codec_handle_t codec, codec_context_t *context,
        const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CODECS_H_ */

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
