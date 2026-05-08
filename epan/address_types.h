/** @file
 * Definitions for address types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "address.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef int (*AddrValueToString)(const address* addr, char *buf, int buf_len);
typedef int (*AddrValueToStringLen)(const address* addr);
typedef unsigned (*AddrValueToByte)(const address* addr, uint8_t *buf, unsigned buf_len);
typedef int (*AddrFixedLen)(void);
typedef const char* (*AddrColFilterString)(const address* addr, bool src);
typedef int (*AddrNameResolutionLen)(void);
typedef const char* (*AddrNameResolutionToString)(const address* addr);

struct _address_type_t;
typedef struct _address_type_t address_type_t;

/**
 * @brief Registers a new address type with various associated functions.
 *
 * @param name The unique identifier for the address type.
 * @param pretty_name A human-readable name for the address type.
 * @param to_str_func Function to convert an address value to a string.
 * @param str_len_func Function to get the length of the string representation of an address value.
 * @param to_bytes_func Function to convert an address value to bytes.
 * @param col_filter_str_func Function to generate a column filter string for the address type.
 * @param fixed_len_func Function to get the fixed length of the address value.
 * @param name_res_str_func Function to resolve the name of an address value to a string.
 * @param name_res_len_func Function to get the length of the resolved name string.
 * @return The registered address type identifier.
 */
WS_DLL_PUBLIC int address_type_dissector_register(const char* name, const char* pretty_name,
                                    AddrValueToString to_str_func, AddrValueToStringLen str_len_func,
                                    AddrValueToByte to_bytes_func, AddrColFilterString col_filter_str_func, AddrFixedLen fixed_len_func,
                                    AddrNameResolutionToString name_res_str_func, AddrNameResolutionLen name_res_len_func);

/**
 * @brief Retrieves the address type by its name.
 *
 * @param name The name of the address type to retrieve.
 * @return The address type if found, otherwise -1.
 */
WS_DLL_PUBLIC int address_type_get_by_name(const char* name);

/**
 * @brief Convert an IPv4 address to a string.
 *
 * @param addr Pointer to the address structure containing the IPv4 address.
 * @param buf Buffer to store the resulting string.
 * @param buf_len Length of the buffer.
 * @return Number of characters written to the buffer, including the null terminator.
 */
int ipv4_to_str(const address* addr, char *buf, int buf_len);

/**
 * @brief Initialize the address types system.
 *
 * Initializes the address types system by registering predefined address types such as AT_NONE and AT_ETHER.
 */
void address_types_initialize(void);

/* Address type functions used by multiple (dissector) address types */

/**
 * @brief Converts a none address to a string.
 *
 * @param addr The address to convert.
 * @param buf Buffer to store the resulting string.
 * @param buf_len Length of the buffer.
 * @return Number of characters written to the buffer, which is always 1 (null byte).
 */
int none_addr_to_str(const address* addr, char *buf, int buf_len);

/**
 * @brief Calculates the length of a string representation for an address with no type.
 *
 * @param addr Pointer to the address structure.
 * @return Length of the string representation, including the null terminator, which is always 1.
 */
int none_addr_str_len(const address* addr);

/**
 * @brief Returns the length of a none address.
 *
 * This function calculates and returns the length of a none address.
 *
 * @return The length of the none address, which is always 0.
 */
int none_addr_len(void);

/**
 * @brief Convert an Ethernet address to a string representation.
 *
 * @param addr Pointer to the address structure containing the Ethernet address.
 * @param buf Buffer to store the resulting string.
 * @param buf_len Length of the buffer.
 * @return Length of the formatted string, which is always 18
 */
WS_DLL_PUBLIC int ether_to_str(const address* addr, char *buf, int buf_len);

/**
 * @brief Calculates the length of a string representation for an Ethernet address.
 *
 * @return int Length of the string representation, which is always 18.
 */
int ether_str_len(const address* addr);

/**
 * @brief Get the length of an Ethernet address.
 *
 * @return The length of an Ethernet address in bytes, which is always 6.
 */
int ether_len(void);

/**
 * @brief Get a string representation of an Ethernet address for name resolution.
 *
 * @param addr The address structure containing the Ethernet address.
 * @return A logical name if found in ethers files, or a vendor-prefixed string
 * if the vendor is known, or a full MAC address string otherwise.
 */
const char* ether_name_resolution_str(const address* addr);

/**
 * @brief Returns the length of the Ethernet name resolution.
 *
 * @return The maximum address string length.
 */
int ether_name_resolution_len(void);

/* XXX - Temporary?  Here at least until all of the address type handling is finalized
 * Otherwise should be folded into address_types.c or just be handled with function pointers
 */
/**
 * @brief Return a display‑filter string for the given address and direction.
 *
 * Produces a column‑filter expression appropriate for the specified address,
 * indicating either a source or destination field depending on @p src.
 *
 * @param addr  The address to convert into a filter string.
 * @param src   true for a source‑address filter, false for destination.
 *
 * @return The column filter string, or an empty string if not found.
 */
const char* address_type_column_filter_string(const address* addr, bool src);


#ifdef __cplusplus
}
#endif /* __cplusplus */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
