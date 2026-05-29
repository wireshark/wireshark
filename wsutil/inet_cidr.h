/** @file
 * Definitions of IPv4 address-and-mask structure, which is what an
 * FT_IPV4 value is (even if there's no mask in a packet, those
 * values can be compared against an address+mask in a filter
 * expression).
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __IPV4_H__
#define __IPV4_H__

#include <wireshark.h>
#include <wsutil/inet_addr.h>

/**
 * @brief Holds an IPv4 address paired with its subnet mask, both in host byte order.
 */
typedef struct {
    uint32_t addr;  /**< IPv4 address in host byte order. */
    uint32_t nmask; /**< IPv4 subnet mask in host byte order (e.g. 0xFFFFFF00 for /24). */
} ipv4_addr_and_mask;

/**
 * @brief Holds an IPv6 address paired with its prefix length.
 */
typedef struct {
    ws_in6_addr addr;   /**< 128-bit IPv6 address in network byte order. */
    uint32_t    prefix; /**< Prefix length in bits defining the network portion of @ref addr (e.g. 64 for a /64 prefix). */
} ipv6_addr_and_prefix;

/*
 ********** IPv4 *********
 */

/**
 * @brief Returns the IPv4 subnet mask of the specified length.
 *
 * Constructs a subnet mask with the given number of leading 1 bits.
 * For example, a mask length of 24 yields 255.255.255.0.
 *
 * @param mask_length The number of bits in the subnet mask (0–32).
 * @return The subnet mask as a 32-bit unsigned integer in host byte order.
 */
WS_DLL_PUBLIC
uint32_t ws_ipv4_get_subnet_mask(const uint32_t mask_length);

/**
 * @brief Initializes an IPv4 address-and-mask structure.
 *
 * Sets up an address-mask pair using the given address and prefix length.
 *
 * @param dst Pointer to the destination structure to initialize.
 * @param src_addr The IPv4 address to use.
 * @param src_bits The number of bits in the subnet mask (must be <= 32).
 */
WS_DLL_PUBLIC
void ws_ipv4_addr_and_mask_init(ipv4_addr_and_mask *dst, ws_in4_addr src_addr, unsigned src_bits);

/**
 * @brief Checks whether an IPv4 address is contained within a subnet.
 *
 * Tests whether the given address falls within the subnet defined by the address-mask pair.
 *
 * @param ipv4 Pointer to the address-mask structure representing the subnet.
 * @param addr Pointer to the IPv4 address to test.
 * @return true if the address is within the subnet, false otherwise.
 */
WS_DLL_PUBLIC
bool ws_ipv4_addr_and_mask_contains(const ipv4_addr_and_mask *ipv4, const ws_in4_addr *addr);

/*
 ********** IPv6 *********
 */

/**
 * @brief Checks whether an IPv6 address is contained within a subnet.
 *
 * Determines if the specified IPv6 address falls within the subnet defined by
 * the given address and prefix length. This is useful for routing, filtering,
 * and address classification tasks.
 *
 * @param ipv6 Pointer to the IPv6 address-and-prefix structure representing the subnet.
 * @param addr Pointer to the IPv6 address to test.
 * @return true if the address is within the subnet, false otherwise.
 */
WS_DLL_PUBLIC
bool
ws_ipv6_addr_and_prefix_contains(const ipv6_addr_and_prefix *ipv6, const ws_in6_addr *addr);

#endif
