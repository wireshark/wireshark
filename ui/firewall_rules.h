/** @file
 *
 * Produce ACL rules for various products from a packet.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_FIREWALL_RULES_H__
#define __UI_FIREWALL_RULES_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Rule types */
typedef enum {
    RT_NONE,
    RT_MAC_SRC,
    RT_MAC_DST,
    RT_IPv4_SRC,
    RT_IPv4_DST,
    RT_PORT_SRC,
    RT_PORT_DST,
    RT_IPv4_PORT_SRC,
    RT_IPv4_PORT_DST,
    NUM_RULE_TYPES
} rule_type_e;

/** Fetch the number of firewall products.
 * @return The number of firewall products. Should be used as the index for
 * the rest of the functions below.
 */
size_t firewall_product_count(void);

/** Product name
 * Given an index, return the product name.
 * @param product_idx Product index.
 * @return Product name or "Unknown".
 */
const char *firewall_product_name(size_t product_idx);

/** Product rule hint
 * Given an index, return the product's rule hint.
 * @param product_idx Product index.
 * @return Product rule hint, e.g. "Change le0 to a valid interface." or "".
 */
const char *firewall_product_rule_hint(size_t product_idx);

/** Comment prefix
 * @param product_idx Product index.
 * @return The comment prefix, e.g. "#" or an empty string.
 */
const char *firewall_product_comment_prefix(size_t product_idx);

/* Syntax function prototypes */
typedef void (*syntax_func)(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);

/** MAC filter function
 * @param product_idx Product index.
 * @return A pointer to the MAC filter function or NULL.
 */
syntax_func firewall_product_mac_func(size_t product_idx);

/** IPv4 filter function
 * @param product_idx Product index.
 * @return A pointer to the IPv4 filter function or NULL.
 */
syntax_func firewall_product_ipv4_func(size_t product_idx);

/** Port filter function
 * @param product_idx Product index.
 * @return A pointer to the port filter function or NULL.
 */
syntax_func firewall_product_port_func(size_t product_idx);

/** IPv4+port filter function
 * @param product_idx Product index.
 * @return A pointer to the IPv4+port filter function or NULL.
 */
syntax_func firewall_product_ipv4_port_func(size_t product_idx);

/** Product inbound support
 * Given an index, return the product's ability to support inbound rules.
 * @param product_idx Product index.
 * @return true or false.
 */
bool firewall_product_does_inbound(size_t product_idx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_FIREWALL_RULES_H__ */
