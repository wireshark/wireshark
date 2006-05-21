/* iax2_codec_type.h
 * Defines IAX2 codec types
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __IAX2_CODEC_TYPE_H__
#define __IAX2_CODEC_TYPE_H__


/* Ref: frame.h from Asterisk source */

/* Data formats for capabilities and frames alike */
/* suitable for use in iax2.codec dissector table */
/*! G.723.1 compression */
#define AST_FORMAT_G723_1	(1 << 0)
/*! GSM compression */
#define AST_FORMAT_GSM		(1 << 1)
/*! Raw mu-law data (G.711) */
#define AST_FORMAT_ULAW		(1 << 2)
/*! Raw A-law data (G.711) */
#define AST_FORMAT_ALAW		(1 << 3)
/*! ADPCM (G.726, 32kbps) */
#define AST_FORMAT_G726		(1 << 4)
/*! ADPCM (IMA) */
#define AST_FORMAT_ADPCM	(1 << 5)
/*! Raw 16-bit Signed Linear (8000 Hz) PCM */
#define AST_FORMAT_SLINEAR	(1 << 6)
/*! LPC10, 180 samples/frame */
#define AST_FORMAT_LPC10	(1 << 7)
/*! G.729A audio */
#define AST_FORMAT_G729A	(1 << 8)
/*! SpeeX Free Compression */
#define AST_FORMAT_SPEEX	(1 << 9)
/*! iLBC Free Compression */
#define AST_FORMAT_ILBC		(1 << 10)
/*! Maximum audio format */
#define AST_FORMAT_MAX_AUDIO	(1 << 15)
/*! JPEG Images */
#define AST_FORMAT_JPEG		(1 << 16)
/*! PNG Images */
#define AST_FORMAT_PNG		(1 << 17)
/*! H.261 Video */
#define AST_FORMAT_H261		(1 << 18)
/*! H.263 Video */
#define AST_FORMAT_H263		(1 << 19)
/*! Max one */
#define AST_FORMAT_MAX_VIDEO	(1 << 24)


/* data format for IAX_IE_DATAFORMAT ie */
/* suitable for use in iax2.dataformat dissector table */
typedef enum {
    AST_DATAFORMAT_NULL,	/* N/A: analogue call etc */
    AST_DATAFORMAT_V110,	/* ITU-T V.110 rate adaption */
    AST_DATAFORMAT_H223_H245	/* ITU-T H.223/H.245 */
} iax_dataformat_t;

#endif
