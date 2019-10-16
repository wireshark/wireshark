/* iax2_codec_type.h
 * Defines IAX2 codec types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __IAX2_CODEC_TYPE_H__
#define __IAX2_CODEC_TYPE_H__


/* Ref: format_compatibility.h from Asterisk source */

/* Data formats for capabilities and frames alike */
/* suitable for use in iax2.codec dissector table */
/*! G.723.1 compression */
#define AST_FORMAT_G723_1	0
/*! GSM compression */
#define AST_FORMAT_GSM		1
/*! Raw mu-law data (G.711) */
#define AST_FORMAT_ULAW		2
/*! Raw A-law data (G.711) */
#define AST_FORMAT_ALAW		3
/*! ADPCM (G.726, 32kbps, AAL2 codeword packing) */
#define AST_FORMAT_G726_AAL2	4
/*! ADPCM (IMA) */
#define AST_FORMAT_ADPCM	5
/*! Raw 16-bit Signed Linear (8000 Hz) PCM */
#define AST_FORMAT_SLINEAR	6
/*! LPC10, 180 samples/frame */
#define AST_FORMAT_LPC10	7
/*! G.729A audio */
#define AST_FORMAT_G729A	8
/*! SpeeX Free Compression */
#define AST_FORMAT_SPEEX	9
/*! iLBC Free Compression */
#define AST_FORMAT_ILBC		10
/*! ADPCM (G.726, 32kbps, RFC3551 codeword packing) */
#define AST_FORMAT_G726		11
/*! G.722 */
#define AST_FORMAT_G722		12
/*! G.722.1 (also known as Siren7, 32kbps assumed) */
#define AST_FORMAT_SIREN7	13
/*! G.722.1 Annex C (also known as Siren14, 48kbps assumed) */
#define AST_FORMAT_SIREN14	14
/*! Raw 16-bit Signed Linear (16000 Hz) PCM */
#define AST_FORMAT_SLINEAR16	15
/*! JPEG Images */
#define AST_FORMAT_JPEG		16
/*! PNG Images */
#define AST_FORMAT_PNG		17
/*! H.261 Video */
#define AST_FORMAT_H261		18
/*! H.263 Video */
#define AST_FORMAT_H263		19
/*! H.263+ Video */
#define AST_FORMAT_H263_PLUS	20
/*! H.264 Video */
#define AST_FORMAT_H264		21
/*! MPEG4 Video */
#define AST_FORMAT_MP4_VIDEO	22
/*! VP8 Video */
#define AST_FORMAT_VP8		23
/*! T.140 RED Text format RFC 4103 */
#define AST_FORMAT_T140_RED	26
/*! T.140 Text format - ITU T.140, RFC 4103 */
#define AST_FORMAT_T140		27
/*! G.719 (64 kbps assumed) */
#define AST_FORMAT_G719		32
/*! SpeeX Wideband (16kHz) Free Compression */
#define AST_FORMAT_SPEEX16	33
/*! Opus audio (8kHz, 16kHz, 24kHz, 48Khz) */
#define AST_FORMAT_OPUS		34
/*! Raw testing-law data (G.711) */
#define AST_FORMAT_TESTLAW	47


/* data format for IAX_IE_DATAFORMAT ie */
/* suitable for use in iax2.dataformat dissector table */
typedef enum {
    AST_DATAFORMAT_NULL,	/* N/A: analogue call etc */
    AST_DATAFORMAT_V110,	/* ITU-T V.110 rate adaption */
    AST_DATAFORMAT_H223_H245	/* ITU-T H.223/H.245 */
} iax_dataformat_t;

#endif
