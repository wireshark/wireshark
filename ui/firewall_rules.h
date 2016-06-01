/* firewall_rules.h
 * Produce ACL rules for various products from a packet.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
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
 * Foundation,  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
typedef void (*syntax_func)(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);

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
 * @return TRUE or FALSE.
 */
gboolean firewall_product_does_inbound(size_t product_idx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_FIREWALL_RULES_H__ */
