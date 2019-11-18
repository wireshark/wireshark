/* iLBCdecode.c
 * iLBC codec
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
    iLBC_decinst_t *ilbc_ctx;  /* Real iLBC context */
    guint8 payload_len; /* Remember last payload_len */
} ilbc_ctx_t;

static void *
codec_iLBC_init(void)
{
    ilbc_ctx_t *ctx;

    ctx=(ilbc_ctx_t *)g_malloc0(sizeof(*ctx));
    WebRtcIlbcfix_DecoderCreate(&(ctx->ilbc_ctx));

    return ctx;
}

static void
codec_iLBC_release(void *ctx)
{
    WebRtcIlbcfix_DecoderFree(((ilbc_ctx_t *)ctx)->ilbc_ctx);
    g_free(ctx);
}

static unsigned
codec_iLBC_get_channels(void *ctx _U_)
{
    return 1;
}

static unsigned
codec_iLBC_get_frequency(void *ctx _U_)
{
    return 8000;
}

static size_t
codec_iLBC_decode(void *ctx, const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize)
{
    int16_t speechType; // Not used in Wireshark code
    int16_t *dataIn  = (int16_t *)inputBytes;
    int16_t *dataOut = (int16_t *)outputSamples;
    ilbc_ctx_t *dataCtx = (ilbc_ctx_t *)ctx;
    size_t outputSamplesCount;

    if (!outputSamples || !outputSamplesSize)
    {
        if (0 == inputBytesSize%ILBC_PAYLOAD_LEN_20MS) {
            /* 20ms packet size = 160 samples = 320 bytes */
            return BLOCKL_20MS*SAMPLE_SIZE;
        } else if (0 == inputBytesSize%ILBC_PAYLOAD_LEN_30MS) {
            /* 30ms packet size = 240 samples = 480 bytes */
            return BLOCKL_30MS*SAMPLE_SIZE;
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
