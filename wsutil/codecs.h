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

/**
 * @brief Register a codec plugin with the system.
 *
 * Adds the specified codec plugin to the internal registry, enabling support
 * for additional encoding or decoding formats. This function is typically
 * called during plugin initialization to make custom codecs available for
 * dissection or playback.
 *
 * @param plug Pointer to a `codecs_plugin` structure describing the plugin.
 */
WS_DLL_PUBLIC void codecs_register_plugin(const codecs_plugin *plug);

/**
 * @brief Initialize all built-in and plugin-based codecs.
 *
 * Invokes the registration routines for all supported codecs, including
 * statically linked and dynamically loaded plugins. This function should
 * be called during application startup or dissector initialization to
 * ensure codec availability for decoding and playback.
 */
WS_DLL_PUBLIC void codecs_init(void);

/**
 * @brief Clean up all registered codecs.
 *
 * Releases resources associated with built-in and plugin-based codecs.
 * This function is typically called during shutdown or when reinitializing
 * codec support (e.g., after preference changes).
 */
WS_DLL_PUBLIC void codecs_cleanup(void);

/**
 * @brief Retrieve compile-time version information for codec-related libraries.
 *
 * Appends version details for all libraries linked with `libwscodecs` at build time
 * to the provided `GString`.
 *
 * @param str Pointer to a `GString` that will receive the formatted version info.
 */
WS_DLL_PUBLIC void codec_get_compiled_version_info(GString *str);

struct codec_handle;
typedef struct codec_handle *codec_handle_t;

/**
 * @brief Context structure for audio codec configuration and state.
 *
 * Encapsulates codec-specific parameters and decoder state used during
 * media processing. This structure is typically initialized by the codec
 * registration or setup routines and passed to encoding/decoding functions.
 *
 * @struct codec_context_t
 * @var sample_rate Sample rate in Hz (e.g., 8000, 44100).
 * @var channels    Number of audio channels (e.g., 1 for mono, 2 for stereo).
 * @var fmtp_map    Optional format parameters (FMTP) as a key-value map.
 * @var priv        Pointer to codec-specific private state, set by the decoder.
 */
typedef struct _codec_context_t {
    unsigned sample_rate;
    unsigned channels;
    wmem_map_t *fmtp_map;
    void *priv;
} codec_context_t;

/*****************************************************************************/
/* Interface which must be implemented by a codec */
/* Codec decodes bytes to samples. Sample is 2 bytes! Codec writer must
 * be careful when API refers bytes and when samples and its counts.
 */
/*****************************************************************************/

/**
 * @brief Initialize context of codec.
 * Context can contain any information required by codec to pass between calls
 * Note: There is just one codec context in runtime therefore no RTP stream
 * related information should be stored in the context!
 *
 * @return Pointer to codec context
 */
typedef void *(*codec_init_fn)(codec_context_t *context);

/**
 * @brief Destroy context of codec
 *
 * @param context Pointer to codec context
 */
typedef void (*codec_release_fn)(codec_context_t *context);

/**
 * @brief Get count of channels provided by the codec
 *
 * @param context Pointer to codec context
 * @return Count of channels (e.g. 1)
 */
typedef unsigned (*codec_get_channels_fn)(codec_context_t *context);

/**
 * @brief Get frequency/rate provided by the codec
 *
 * @param context Pointer to codec context
 * @return Frequency (e.g. 8000)
 */
typedef unsigned (*codec_get_frequency_fn)(codec_context_t *context);

/**
 * @brief Decode one frame of payload
 *
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
 * @return Count of required bytes (!not samples) to allocate in (1) or
 *         Count of decoded bytes (!not samples) in (2)
 */
typedef size_t (*codec_decode_fn)(codec_context_t *context,
        const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize);

/*****************************************************************************/
/* Codec registering interface */
/*****************************************************************************/

/**
 * @brief Register a new codec implementation.
 *
 * Adds a codec to the internal registry using the provided function pointers.
 * This enables support for custom decoding logic and metadata access.
 *
 * @param name          Unique name identifying the codec.
 * @param init_fn       Function to initialize codec state.
 * @param release_fn    Function to release codec resources.
 * @param channels_fn   Function to query channel count.
 * @param frequency_fn  Function to query sample rate.
 * @param decode_fn     Function to decode input bytes into audio samples.
 * @return              `true` if registration succeeded, `false` otherwise.
 */
WS_DLL_PUBLIC bool register_codec(const char *name, codec_init_fn init_fn,
        codec_release_fn release_fn, codec_get_channels_fn channels_fn,
        codec_get_frequency_fn frequency_fn, codec_decode_fn decode_fn);

/**
 * @brief Deregister a previously registered codec.
 *
 * Removes the codec identified by `name` from the internal registry.
 *
 * @param name Name of the codec to remove.
 * @return     `true` if the codec was found and removed, `false` otherwise.
 */
WS_DLL_PUBLIC bool deregister_codec(const char *name);

/**
 * @brief Find a registered codec by name.
 *
 * Retrieves a handle to the codec identified by `name`, if available.
 *
 * @param name Name of the codec to locate.
 * @return     Handle to the codec, or `NULL` if not found.
 */
WS_DLL_PUBLIC codec_handle_t find_codec(const char *name);

/**
 * @brief Initialize codec-specific state.
 *
 * Prepares the codec for decoding using the provided context.
 *
 * @param codec   Handle to the codec.
 * @param context Pointer to a `codec_context_t` structure.
 * @return        Pointer to codec-specific state, or `NULL` on failure.
 */
WS_DLL_PUBLIC void *codec_init(codec_handle_t codec, codec_context_t *context);

/**
 * @brief Release codec-specific resources.
 *
 * Cleans up any state associated with the codec and context.
 *
 * @param codec   Handle to the codec.
 * @param context Pointer to the associated context.
 */
WS_DLL_PUBLIC void codec_release(codec_handle_t codec, codec_context_t *context);

/**
 * @brief Query the number of audio channels for a codec.
 *
 * Returns the channel count (e.g., 1 for mono, 2 for stereo).
 *
 * @param codec   Handle to the codec.
 * @param context Pointer to the associated context.
 * @return        Number of channels.
 */
WS_DLL_PUBLIC unsigned codec_get_channels(codec_handle_t codec, codec_context_t *context);

/**
 * @brief Query the sample rate for a codec.
 *
 * Returns the sample rate in Hz (e.g., 8000, 44100).
 *
 * @param codec   Handle to the codec.
 * @param context Pointer to the associated context.
 * @return        Sample rate in Hz.
 */
WS_DLL_PUBLIC unsigned codec_get_frequency(codec_handle_t codec, codec_context_t *context);

/**
 * @brief Decode input bytes into audio samples.
 *
 * Converts encoded input data into raw audio samples. The output buffer must
 * be large enough to hold the decoded samples. The actual number of samples
 * written is returned via `outputSamplesSize`.
 *
 * @param codec              Handle to the codec.
 * @param context            Pointer to the associated context.
 * @param inputBytes         Pointer to encoded input data.
 * @param inputBytesSize     Size of the input data in bytes.
 * @param outputSamples      Pointer to output buffer for decoded samples.
 * @param outputSamplesSize  Pointer to variable receiving the number of bytes written.
 * @return                   Number of bytes consumed from input.
 */
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
