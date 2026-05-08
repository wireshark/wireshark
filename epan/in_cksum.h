/** @file
 * Declaration of Internet checksum routine.
 *
 * Copyright (c) 1988, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include "ws_symbol_export.h"

typedef struct {
	const uint8_t *ptr;
	int	len;
} vec_t;

#define SET_CKSUM_VEC_PTR(vecelem, data, length) \
	G_STMT_START { \
		vecelem.ptr = (data); \
		vecelem.len = (length); \
	} G_STMT_END

#define SET_CKSUM_VEC_TVB(vecelem, tvb, offset, length) \
	G_STMT_START { \
		vecelem.len = (length); \
		vecelem.ptr = tvb_get_ptr((tvb), (offset), vecelem.len); \
	} G_STMT_END

/**
 * @brief Calculate the IP checksum for a given buffer.
 *
 * @param ptr Pointer to the data buffer.
 * @param len Length of the data buffer.
 * @return uint16_t The calculated IP checksum.
 */
WS_DLL_PUBLIC uint16_t ip_checksum(const uint8_t *ptr, int len);

/**
 * @brief Calculate the IP checksum for a given TVB.
 *
 * @param tvb The TVB containing the data to be checksummed.
 * @param offset The starting offset within the TVB.
 * @param len The length of the data to be checksummed.
 * @return The calculated IP checksum.
 */
WS_DLL_PUBLIC uint16_t ip_checksum_tvb(tvbuff_t *tvb, int offset, int len);

/**
 * @brief Calculates a partial checksum for a vector of data.
 *
 * This function computes a partial checksum for a given vector of data,
 * storing the intermediate result in the provided partial pointer if it is not null.
 *
 * @param vec Pointer to the vector containing the data to be checksummed.
 * @param veclen Number of elements in the vector.
 * @param partial Pointer to store the partial checksum result, can be null.
 * @return The final checksum value.
 */
WS_DLL_PUBLIC int in_cksum_ret_partial(const vec_t *vec, int veclen, uint16_t *partial);

/**
 * @brief Calculate the IP checksum for a given vector of data.
 *
 * This function computes the IP checksum for a given vector of data.
 *
 * @param vec Pointer to the vector containing the data to be checksummed.
 * @param veclen Number of elements in the vector.
 * @return The calculated IP checksum.
 */
WS_DLL_PUBLIC int in_cksum(const vec_t *vec, int veclen);

/**
 * @brief Calculate the expected checksum value based on the computed checksum and the checksum field value.
 *
 * This function computes the expected checksum value that should be present in the checksum field of a packet,
 * given the computed checksum of the packet's data and the value of the checksum field itself.
 *
 * @param sum The value of the checksum field from the packet header.
 * @param computed_sum The computed checksum of the packet's data (excluding the checksum field).
 * @return The expected checksum value that should be in the packet's header for it to be considered valid.
 */
WS_DLL_PUBLIC uint16_t in_cksum_shouldbe(uint16_t sum, uint16_t computed_sum);
