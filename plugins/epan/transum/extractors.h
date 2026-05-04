/* extractors.h
 * Header file for the TRANSUM response time analyzer post-dissector
 * By Paul Offord <paul.offord@advance7.com>
 * Copyright 2016 Advance Seven Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <epan/prefs.h>
#include <epan/packet.h>

#define MAX_RETURNED_ELEMENTS 16

/**
 * @brief Extracts 32-bit unsigned integers from a protocol tree.
 *
 * @param tree The protocol tree to extract from.
 * @param field_id The ID of the field to extract.
 * @param result_array Array to store the extracted values.
 * @param element_count Pointer to store the number of elements extracted.
 * @return 0 on success, -1 on failure.
 */
int extract_uint(proto_tree *tree, int field_id, uint32_t *result_array, size_t *element_count);

/**
 * @brief Extracts 64-bit unsigned integers from a protocol tree.
 *
 * @param tree The protocol tree to extract from.
 * @param field_id The ID of the field to extract.
 * @param result_array Array to store the extracted values.
 * @param element_count Pointer to store the number of elements extracted.
 * @return 0 on success, -1 on failure.
 */
int extract_ui64(proto_tree *tree, int field_id, uint64_t *result_array, size_t *element_count);

/**
 * @brief Extracts signed 64-bit integers from a protocol tree.
 *
 * @param tree The protocol tree to extract from.
 * @param field_id The ID of the field to extract.
 * @param result_array Array to store the extracted values.
 * @param element_count Pointer to store the number of elements extracted.
 * @return 0 on success, -1 on failure.
 */
int extract_si64(proto_tree *tree, int field_id, uint64_t *result_array, size_t *element_count);

/**
 * @brief Extracts boolean values from a protocol tree.
 *
 * @param tree The protocol tree to extract from.
 * @param field_id The ID of the field to extract.
 * @param result_array Array to store the extracted values.
 * @param element_count Pointer to store the number of elements extracted.
 * @return 0 on success, -1 on failure.
 */
int extract_bool(proto_tree *tree, int field_id, bool *result_array, size_t *element_count);

/**
 * @brief Extracts instance counts from a protocol tree.
 *
 * @param tree The protocol tree to extract from.
 * @param field_id The ID of the field to extract.
 * @param element_count Pointer to store the number of elements extracted.
 * @return 0 on success, -1 on failure.
 */
int extract_instance_count(proto_tree *tree, int field_id, size_t *element_count);
