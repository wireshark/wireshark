/* iLBCdecode.c
 * iLBC codec
 *
 * https://datatracker.ietf.org/doc/html/rfc3952
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>

#include <glib.h>

#include "ilbc.h"
#include "wsutil/codecs.h"
#include "ws_attributes.h"

#define ILBC_20MS 20
#define ILBC_30MS 30
#define ILBC_PAYLOAD_LEN_20MS 38
#define ILBC_PAYLOAD_LEN_30MS 50
#define SAMPLE_SIZE 2

typedef struct {
#ifdef LIBILBC_VERSION_MAJOR
    IlbcDecoderInstance *ilbc_ctx;  /* Real iLBC context */
#else
    iLBC_decinst_t *ilbc_ctx;  /* Real iLBC context */
#endif
    uint8_t payload_len; /* Remember last payload_len */
} ilbc_ctx_t;

void codec_register_iLBC(void);

static void *
codec_iLBC_init(codec_context_t *ctx _U_)
{
    ilbc_ctx_t *priv;

    priv=(ilbc_ctx_t *)g_malloc0(sizeof(*priv));
    WebRtcIlbcfix_DecoderCreate(&(priv->ilbc_ctx));

    return priv;
}

static void
codec_iLBC_release(codec_context_t *ctx)
{
    ilbc_ctx_t *dataCtx = (ilbc_ctx_t *)ctx->priv;
    WebRtcIlbcfix_DecoderFree(dataCtx->ilbc_ctx);
    g_free(dataCtx);
}

static unsigned
codec_iLBC_get_channels(codec_context_t *ctx _U_)
{
    return 1;
}

static unsigned
codec_iLBC_get_frequency(codec_context_t *ctx _U_)
{
    return 8000;
}

static size_t
codec_iLBC_decode(codec_context_t *ctx,
        const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize)
{
    int16_t speechType; // Not used in Wireshark code
#ifdef LIBILBC_VERSION_MAJOR
    int8_t *dataIn  = (int8_t *)inputBytes;
#else
    int16_t *dataIn  = (int16_t *)inputBytes;
#endif
    int16_t *dataOut = (int16_t *)outputSamples;
    ilbc_ctx_t *dataCtx = (ilbc_ctx_t *)ctx->priv;
    size_t outputSamplesCount, outputFramesCount;

    if (!outputSamples || !outputSamplesSize)
    {
        /* XXX - If the payload size is a multiple of 950 (the GCM of the
         * 20 ms and 30 ms payload lengths), we don't know which variant it
         * is and the iLBC library doesn't seem to autodetect but uses what
         * we initialize as. RFC 3952 3.2 is of no help here, suggesting
         * only this algorithm.
         * Do we need a codec preference? */
        if (0 == inputBytesSize%ILBC_PAYLOAD_LEN_20MS) {
            /* 20ms packet size = 160 samples = 320 bytes */
            outputFramesCount = inputBytesSize / ILBC_PAYLOAD_LEN_20MS;
            return outputFramesCount*BLOCKL_20MS*SAMPLE_SIZE;
        } else if (0 == inputBytesSize%ILBC_PAYLOAD_LEN_30MS) {
            /* 30ms packet size = 240 samples = 480 bytes */
            outputFramesCount = inputBytesSize / ILBC_PAYLOAD_LEN_30MS;
            return outputFramesCount*BLOCKL_30MS*SAMPLE_SIZE;
        } else {
            /* unknown packet size */
            return 0;
        }
    }

    if (0 == inputBytesSize%ILBC_PAYLOAD_LEN_20MS) {
        /* 20ms packet size */
        if (dataCtx->payload_len != ILBC_20MS) {
            WebRtcIlbcfix_DecoderInit(dataCtx->ilbc_ctx, ILBC_20MS);
            dataCtx->payload_len = ILBC_20MS;
        }
        outputSamplesCount = WebRtcIlbcfix_Decode(dataCtx->ilbc_ctx, dataIn,
                               (int16_t)inputBytesSize, dataOut, &speechType);
    } else if (0 == inputBytesSize%ILBC_PAYLOAD_LEN_30MS) {
        /* 30ms packet size */
        if (dataCtx->payload_len != ILBC_30MS) {
            WebRtcIlbcfix_DecoderInit(dataCtx->ilbc_ctx, ILBC_30MS);
            dataCtx->payload_len = ILBC_30MS;
        }
        outputSamplesCount = WebRtcIlbcfix_Decode(dataCtx->ilbc_ctx, dataIn,
                               (int16_t)inputBytesSize, dataOut, &speechType);
    } else {
        /* unknown packet size */
        outputSamplesCount = 0;
    }

    /* WebRtcIlbcfix_Decode returns count of samples, but we return count of bytes */
    *outputSamplesSize = outputSamplesCount*SAMPLE_SIZE;
    return *outputSamplesSize;
}

void
codec_register_iLBC(void)
{
    register_codec("iLBC", codec_iLBC_init, codec_iLBC_release,
            codec_iLBC_get_channels, codec_iLBC_get_frequency, codec_iLBC_decode);
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
