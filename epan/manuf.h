/* manuf.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MANUF_BLOCK_SIZE 5

struct ws_manuf {
    uint8_t block[MANUF_BLOCK_SIZE];
    uint8_t mask;
    const char *short_name;
    const char *long_name;
};

/* Internal structure, not supposed to be accessed by users. */
struct ws_manuf_iter {
    size_t idx24, idx28, idx36;
    struct ws_manuf buf24;
    struct ws_manuf buf28;
    struct ws_manuf buf36;
};

typedef struct ws_manuf_iter ws_manuf_iter_t;

/**
 * @brief Lookup the manufacturer name for a given MAC address.
 *
 * @param addr The MAC address to lookup.
 * @param long_name_ptr Optional pointer to return the full manufacturer name.
 * @return The short manufacturer name.
 */
WS_DLL_PUBLIC
const char *
ws_manuf_lookup_str(const uint8_t addr[6], const char **long_name_ptr);

/**
 * @brief Lookup the manufacturer name for a given MAC address.
 *
 * @param addr The MAC address to lookup.
 * @param long_name_ptr Optional pointer to return the full manufacturer name.
 * @param mask_ptr Optional pointer to return the length of the mask.
 * @return The short manufacturer name.
 */
WS_DLL_PUBLIC
const char *
ws_manuf_lookup(const uint8_t addr[6], const char **long_name_ptr, unsigned *mask_ptr);

/**
 * @brief Lookup the manufacturer name for a given 24-bit OUI.
 *
 * Search only in the OUI/MA-L/CID tables for a 24-bit OUI. Returns the short
 * name. Takes an optional pointer to return the long time.
 *
 * @param oui The 24-bit OUI to lookup.
 * @param long_name_ptr Optional pointer to return the full manufacturer name.
 * @return The short manufacturer name.
*/
WS_DLL_PUBLIC
const char *
ws_manuf_lookup_oui24(const uint8_t oui[3], const char **long_name_ptr);

/**
 * @brief Initialize a manufacturer iterator.
 *
 * @param iter Pointer to the iterator structure to be initialized.
 */
WS_DLL_PUBLIC
void
ws_manuf_iter_init(ws_manuf_iter_t *iter);

/**
 * @brief Get the next manufacturer entry from the iterator.
 *
 * @param iter Pointer to the iterator structure.
 * @param result Pointer to store the next manufacturer entry.
 * @return bool True if a manufacturer entry was found, false otherwise.
 */
WS_DLL_PUBLIC
bool
ws_manuf_iter_next(ws_manuf_iter_t *iter, struct ws_manuf *result);

/**
 * @brief Convert a manufacturer block to a string representation.
 *
 * @param buf Buffer to store the resulting string.
 * @param buf_size Size of the buffer.
 * @param ptr Pointer to the manufacturer block structure.
 * @return char* Pointer to the buffer containing the string representation.
 */
WS_DLL_PUBLIC
const char *
ws_manuf_block_str(char *buf, size_t buf_size, const struct ws_manuf *ptr);

/**
 * @brief Dumps the contents of the manuf database to a file.
 *
 * @param fp The file pointer where the data will be written.
 */
WS_DLL_PUBLIC void
ws_manuf_dump(FILE *fp);

/**
 * @brief Returns the total count of manufacturer entries.
 *
 * This function calculates and returns the total number of manufacturer entries
 * by summing up the counts from different tables.
 *
 * @return The total count of manufacturer entries.
 */
WS_DLL_PUBLIC
size_t
ws_manuf_count(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
