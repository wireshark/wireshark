/** @file
 *
 * MPEG Audio header dissection
 * Written by Shaun Jackman <sjackman@gmail.com>
 * Copyright 2007 Shaun Jackman
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MPA_H
#define MPA_H 1

#include <stdint.h>
#include "ws_symbol_export.h"

struct mpa {
	unsigned int emphasis   :2;
	unsigned int original   :1;
	unsigned int copyright  :1;
	unsigned int modeext    :2;
	unsigned int mode       :2;
	unsigned int priv       :1;
	unsigned int padding    :1;
	unsigned int frequency  :2;
	unsigned int bitrate    :4;
	unsigned int protection :1;
	unsigned int layer      :2;
	unsigned int version    :2;
	unsigned int sync       :11;
};

#define MPA_UNMARSHAL_SYNC(n)       ((n) >> 21 & 0x7ff)
#define MPA_UNMARSHAL_VERSION(n)    ((n) >> 19 & 0x3)
#define MPA_UNMARSHAL_LAYER(n)      ((n) >> 17 & 0x3)
#define MPA_UNMARSHAL_PROTECTION(n) ((n) >> 16 & 0x1)
#define MPA_UNMARSHAL_BITRATE(n)    ((n) >> 12 & 0xf)
#define MPA_UNMARSHAL_FREQUENCY(n)  ((n) >> 10 & 0x3)
#define MPA_UNMARSHAL_PADDING(n)    ((n) >>  9 & 0x1)
#define MPA_UNMARSHAL_PRIVATE(n)    ((n) >>  8 & 0x1)
#define MPA_UNMARSHAL_MODE(n)       ((n) >>  6 & 0x3)
#define MPA_UNMARSHAL_MODEEXT(n)    ((n) >>  4 & 0x3)
#define MPA_UNMARSHAL_COPYRIGHT(n)  ((n) >>  3 & 0x1)
#define MPA_UNMARSHAL_ORIGINAL(n)   ((n) >>  2 & 0x1)
#define MPA_UNMARSHAL_EMPHASIS(n)   ((n) >>  0 & 0x3)

#define MPA_UNMARSHAL(mpa, n) do { \
	(mpa)->sync       = MPA_UNMARSHAL_SYNC(n);       \
	(mpa)->version    = MPA_UNMARSHAL_VERSION(n);    \
	(mpa)->layer      = MPA_UNMARSHAL_LAYER(n);      \
	(mpa)->protection = MPA_UNMARSHAL_PROTECTION(n); \
	(mpa)->bitrate    = MPA_UNMARSHAL_BITRATE(n);    \
	(mpa)->frequency  = MPA_UNMARSHAL_FREQUENCY(n);  \
	(mpa)->padding    = MPA_UNMARSHAL_PADDING(n);    \
	(mpa)->priv       = MPA_UNMARSHAL_PRIVATE(n);    \
	(mpa)->mode       = MPA_UNMARSHAL_MODE(n);       \
	(mpa)->modeext    = MPA_UNMARSHAL_MODEEXT(n);    \
	(mpa)->copyright  = MPA_UNMARSHAL_COPYRIGHT(n);  \
	(mpa)->original   = MPA_UNMARSHAL_ORIGINAL(n);   \
	(mpa)->emphasis   = MPA_UNMARSHAL_EMPHASIS(n);   \
	} while (0)

WS_DLL_PUBLIC
int mpa_version(const struct mpa *);
WS_DLL_PUBLIC
int mpa_layer(const struct mpa *);
WS_DLL_PUBLIC
unsigned int mpa_samples(const struct mpa *);
WS_DLL_PUBLIC
unsigned int mpa_bitrate(const struct mpa *);
WS_DLL_PUBLIC
unsigned int mpa_frequency(const struct mpa *);
WS_DLL_PUBLIC
unsigned int mpa_padding(const struct mpa *);
WS_DLL_PUBLIC
uint32_t decode_synchsafe_int(uint32_t);

#define MPA_DATA_BYTES(mpa) (mpa_bitrate(mpa) * mpa_samples(mpa) \
		/ mpa_frequency(mpa) / 8)
#define MPA_BYTES(mpa) (MPA_DATA_BYTES(mpa) + mpa_padding(mpa))
#define MPA_DURATION_NS(mpa) \
	(1000000000 / mpa_frequency(mpa) * mpa_samples(mpa))

enum { MPA_SYNC = 0x7ff };

#define MPA_SYNC_VALID(mpa)      ((mpa)->sync == MPA_SYNC)
#define MPA_VERSION_VALID(mpa)   (mpa_version(mpa) >= 0)
#define MPA_LAYER_VALID(mpa)     (mpa_layer(mpa) >= 0)
#define MPA_BITRATE_VALID(mpa)   (mpa_bitrate(mpa) > 0)
#define MPA_FREQUENCY_VALID(mpa) (mpa_frequency(mpa) > 0)
#define MPA_VALID(mpa) (MPA_SYNC_VALID(mpa) \
		&& MPA_VERSION_VALID(mpa) && MPA_LAYER_VALID(mpa) \
		&& MPA_BITRATE_VALID(mpa) && MPA_FREQUENCY_VALID(mpa))

#endif
