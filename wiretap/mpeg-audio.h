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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

extern const int mpa_versions[4];
extern const int mpa_layers[4];
extern const unsigned mpa_samples[3][3];
extern const unsigned mpa_bitrates[3][3][16]; /* kb/s */
extern const unsigned mpa_frequencies[3][4]; /* Hz */
extern const unsigned mpa_padding[3];

#define MPA_VERSION(mpa)   (mpa_versions[(mpa)->version])
#define MPA_LAYER(mpa)     (mpa_layers[(mpa)->layer])
#define MPAV(mpa) MPA_VERSION(mpa)
#define MPAL(mpa) MPA_LAYER(mpa)

#define MPA_SAMPLES(mpa) (mpa_samples[MPAV(mpa)][MPAL(mpa)])
#define MPA_BITRATE(mpa) (1000 * \
	(mpa_bitrates[MPAV(mpa)][MPAL(mpa)][(mpa)->bitrate]))
#define MPA_FREQUENCY(mpa) \
	(mpa_frequencies[MPAV(mpa)][(mpa)->frequency])
#define MPA_PADDING(mpa)((mpa)->padding ? mpa_padding[MPAL(mpa)] : 0)

#define MPA_DATA_BYTES(mpa) (MPA_BITRATE(mpa) * MPA_SAMPLES(mpa) \
		/ MPA_FREQUENCY(mpa) / 8)
#define MPA_BYTES(mpa) (MPA_DATA_BYTES(mpa) + MPA_PADDING(mpa))
#define MPA_DURATION_NS(mpa) \
	(1000000000 / MPA_FREQUENCY(mpa) * MPA_SAMPLES(mpa))

enum { MPA_SYNC = 0x7ff };

#define MPA_SYNC_VALID(mpa)      ((mpa)->sync == MPA_SYNC)
#define MPA_VERSION_VALID(mpa)   (MPA_VERSION(mpa) >= 0)
#define MPA_LAYER_VALID(mpa)     (MPA_LAYER(mpa) >= 0)
#define MPA_BITRATE_VALID(mpa)   (MPA_BITRATE(mpa) > 0)
#define MPA_FREQUENCY_VALID(mpa) (MPA_FREQUENCY(mpa) > 0)
#define MPA_VALID(mpa) (MPA_SYNC_VALID(mpa) \
		&& MPA_VERSION_VALID(mpa) && MPA_LAYER_VALID(mpa) \
		&& MPA_BITRATE_VALID(mpa) && MPA_FREQUENCY_VALID(mpa))

#endif
