/* mpeg-audio.c
 *
 * MPEG Audio header dissection
 * Written by Shaun Jackman <sjackman@gmail.com>
 * Copyright 2007 Shaun Jackman
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

#include "mpeg-audio.h"

static const int mpa_versions[4] = { 2, -1, 1, 0 };
static const int mpa_layers[4] = { -1, 2, 1, 0 };

static const unsigned int mpa_samples_data[3][3] = {
	{ 384, 1152, 1152 },
	{ 384, 1152, 576 },
	{ 384, 1152, 576 },
};

static const unsigned int mpa_bitrates[3][3][16] = { /* kb/s */
	{
		{ 0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },
		{ 0, 32, 48, 56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, 384 },
		{ 0, 32, 40, 48,  56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320 },
	},
	{
		{ 0, 32, 48, 56,  64,  80,  96, 112, 128, 144, 160, 176, 192, 224, 256 },
		{ 0,  8, 16, 24,  32,  40,  48,  56,  64,  80,  96, 112, 128, 144, 160 },
		{ 0,  8, 16, 24,  32,  40,  48,  56,  64,  80,  96, 112, 128, 144, 160 },
	},
	{
		{ 0, 32, 48, 56,  64,  80,  96, 112, 128, 144, 160, 176, 192, 224, 256 },
		{ 0,  8, 16, 24,  32,  40,  48,  56,  64,  80,  96, 112, 128, 144, 160 },
		{ 0,  8, 16, 24,  32,  40,  48,  56,  64,  80,  96, 112, 128, 144, 160 },
	},
};

static const unsigned int mpa_frequencies[3][4] = {
	{ 44100, 48000, 32000 },
	{ 22050, 24000, 16000 },
	{ 11025, 12000, 8000 },
};

static const unsigned int mpa_padding_data[3] = { 4, 1, 1 };

int
mpa_version(const struct mpa *mpa)
{
	return mpa_versions[mpa->version];
}

int
mpa_layer(const struct mpa *mpa)
{
	return mpa_layers[mpa->layer];
}

unsigned
mpa_samples(const struct mpa *mpa)
{
	return mpa_samples_data[mpa_versions[mpa->version]][mpa_layer(mpa)];
}

unsigned
mpa_bitrate(const struct mpa *mpa)
{
	return (1000 * (mpa_bitrates[mpa_versions[mpa->version]][mpa_layers[mpa->layer]][mpa->bitrate]));
}

unsigned
mpa_frequency(const struct mpa *mpa)
{
	return(mpa_frequencies[mpa_versions[mpa->version]][mpa->frequency]);
}

unsigned
mpa_padding(const struct mpa *mpa)
{
	return(mpa->padding ? mpa_padding_data[mpa_layers[mpa->layer]] : 0);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
