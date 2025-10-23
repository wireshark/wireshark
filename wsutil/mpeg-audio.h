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

/**
 * @brief Extracts the MPEG audio version from the given header.
 *
 * Parses the MPEG audio header and returns the version identifier (e.g., MPEG-1, MPEG-2).
 *
 * @param mpa Pointer to the MPEG audio header structure.
 * @return The MPEG version as an integer code.
 */
WS_DLL_PUBLIC int mpa_version(const struct mpa *mpa);

/**
 * @brief Extracts the MPEG audio layer from the given header.
 *
 * Parses the MPEG audio header and returns the layer identifier (e.g., Layer I, II, III).
 *
 * @param mpa Pointer to the MPEG audio header structure.
 * @return The MPEG layer as an integer code.
 */
WS_DLL_PUBLIC int mpa_layer(const struct mpa *mpa);

/**
 * @brief Returns the number of audio samples per frame.
 *
 * Determines the sample count based on MPEG version and layer.
 *
 * @param mpa Pointer to the MPEG audio header structure.
 * @return The number of samples per frame.
 */
WS_DLL_PUBLIC unsigned int mpa_samples(const struct mpa *mpa);

/**
 * @brief Extracts the bitrate from the MPEG audio header.
 *
 * Parses the header to determine the encoded bitrate in kilobits per second.
 *
 * @param mpa Pointer to the MPEG audio header structure.
 * @return The bitrate in kbps.
 */
WS_DLL_PUBLIC unsigned int mpa_bitrate(const struct mpa *mpa);

/**
 * @brief Extracts the sampling frequency from the MPEG audio header.
 *
 * Parses the header to determine the sample rate in Hz.
 *
 * @param mpa Pointer to the MPEG audio header structure.
 * @return The sampling frequency in Hz.
 */
WS_DLL_PUBLIC unsigned int mpa_frequency(const struct mpa *mpa);

/**
 * @brief Checks whether padding is present in the MPEG audio frame.
 *
 * Determines if the frame includes padding bits used to adjust frame size.
 *
 * @param mpa Pointer to the MPEG audio header structure.
 * @return 1 if padding is present, 0 otherwise.
 */
WS_DLL_PUBLIC unsigned int mpa_padding(const struct mpa *mpa);

/**
 * @brief Decodes a synchsafe integer from ID3 metadata.
 *
 * Converts a 32-bit synchsafe integer (used in ID3v2 tags) to its raw integer value.
 * Synchsafe integers avoid false MPEG syncs by ensuring no byte has all bits set.
 *
 * @param val The synchsafe encoded 32-bit integer.
 * @return The decoded raw integer value.
 */
WS_DLL_PUBLIC uint32_t decode_synchsafe_int(uint32_t val);

/**
 * @def MPA_DATA_BYTES(mpa)
 * @brief Calculates the number of data bytes in an MPEG audio frame.
 *
 * Computes the size of the audio payload (excluding padding) based on bitrate,
 * sample count, and sampling frequency.
 *
 * @param mpa Pointer to the MPEG audio header structure.
 * @return The number of data bytes in the frame.
 */
#define MPA_DATA_BYTES(mpa) (mpa_bitrate(mpa) * mpa_samples(mpa) \
		/ mpa_frequency(mpa) / 8)

/**
 * @def MPA_BYTES(mpa)
 * @brief Calculates the total number of bytes in an MPEG audio frame.
 *
 * Includes both the audio payload and any padding bytes.
 *
 * @param mpa Pointer to the MPEG audio header structure.
 * @return The total number of bytes in the frame.
 */
#define MPA_BYTES(mpa) (MPA_DATA_BYTES(mpa) + mpa_padding(mpa))

/**
 * @def MPA_DURATION_NS(mpa)
 * @brief Calculates the duration of an MPEG audio frame in nanoseconds.
 *
 * Uses the sample count and sampling frequency to compute the frame duration.
 *
 * @param mpa Pointer to the MPEG audio header structure.
 * @return The duration of the frame in nanoseconds.
 */
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
