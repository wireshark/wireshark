/* mpeg-audio.h
 *
 * MPEG Audio header dissection
 * Written by Shaun Jackman <sjackman@gmail.com>
 * Copyright 2007 Shaun Jackman
 *
 * $Id$
 *
 * Wiretap Library
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

#ifndef MPA_H
#define MPA_H 1

struct mpa {
	unsigned emphasis   :2;
	unsigned original   :1;
	unsigned copyright  :1;
	unsigned modeext    :2;
	unsigned mode       :2;
	unsigned private    :1;
	unsigned padding    :1;
	unsigned frequency  :2;
	unsigned bitrate    :4;
	unsigned protection :1;
	unsigned layer      :2;
	unsigned version    :2;
	unsigned sync       :11;
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
	(mpa)->private    = MPA_UNMARSHAL_PRIVATE(n);    \
	(mpa)->mode       = MPA_UNMARSHAL_MODE(n);       \
	(mpa)->modeext    = MPA_UNMARSHAL_MODEEXT(n);    \
	(mpa)->copyright  = MPA_UNMARSHAL_COPYRIGHT(n);  \
	(mpa)->original   = MPA_UNMARSHAL_ORIGINAL(n);   \
	(mpa)->emphasis   = MPA_UNMARSHAL_EMPHASIS(n);   \
	} while (0)

int mpa_version(const struct mpa *);
int mpa_layer(const struct mpa *);
unsigned mpa_samples(const struct mpa *);
unsigned mpa_bitrate(const struct mpa *);
unsigned mpa_frequency(const struct mpa *);
unsigned mpa_padding(const struct mpa *);

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
