/* address_to_str.c
 * Routines for utilities to convert addresses to strings.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>         /* needed for <netinet/in.h> */
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>        /* needed for <arpa/inet.h> on some platforms */
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>         /* needed to define AF_ values on UNIX */
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>           /* needed to define AF_ values on Windows */
#endif

#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif

#include "to_str-int.h"
#include "to_str.h"
#include "value_string.h"
#include "addr_resolv.h"
#include "address_types.h"
#include "wsutil/pint.h"
#include "wsutil/str_util.h"
#include "osi-utils.h"
#include <epan/dissectors/packet-mtp3.h>
#include <stdio.h>
#include "wmem/wmem.h"

static void
ip6_to_str_buf_len(const guchar* src, char *buf, size_t buf_len);

/*
 * If a user _does_ pass in a too-small buffer, this is probably
 * going to be too long to fit.  However, even a partial string
 * starting with "[Buf" should provide enough of a clue to be
 * useful.
 */
#define BUF_TOO_SMALL_ERR "[Buffer too small]"

#define IPV4_LENGTH 4
#define IPV6_LENGTH 16

/* const char *
 * inet_ntop6(src, dst, size)
 *  convert IPv6 binary address into presentation (printable) format
 * author:
 *  Paul Vixie, 1996.
 */
static void
ip6_to_str_buf_len(const guchar* src, char *buf, size_t buf_len)
{
    struct { int base, len; } best, cur;
    guint words[8];
    int i;

    if (buf_len < MAX_IP6_STR_LEN) { /* buf_len < 40 */
        g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len); /* Let the unexpected value alert user */
        return;
    }

    /*
     * Preprocess:
     *  Copy the input (bytewise) array into a wordwise array.
     *  Find the longest run of 0x00's in src[] for :: shorthanding.
     */
    for (i = 0; i < 16; i += 2) {
        words[i / 2] = (src[i+1] << 0);
        words[i / 2] |= (src[i] << 8);
    }
    best.base = -1; best.len = 0;
    cur.base = -1;  cur.len = 0;
    for (i = 0; i < 8; i++) {
        if (words[i] == 0) {
            if (cur.base == -1) {
                cur.base = i;
                cur.len = 1;
            } else
                cur.len++;
        } else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                    best = cur;
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
            best = cur;
    }
    if (best.base != -1 && best.len < 2)
        best.base = -1;

    /* Is this address an encapsulated IPv4? */
    /* XXX,
     * Orginal code dated 1996 uses ::/96 as a valid IPv4-compatible addresses
     * but since Feb 2006 ::/96 is deprecated one.
     * Quoting wikipedia [0]:
     * > The 96-bit zero-value prefix ::/96, originally known as IPv4-compatible
     * > addresses, was mentioned in 1995[35] but first described in 1998.[41]
     * > This class of addresses was used to represent IPv4 addresses within
     * > an IPv6 transition technology. Such an IPv6 address has its first
     * > (most significant) 96 bits set to zero, while its last 32 bits are the
     * > IPv4 address that is represented.
     * > In February 2006 the Internet Engineering Task Force (IETF) has deprecated
     * > the use of IPv4-compatible addresses.[1] The only remaining use of this address
     * > format is to represent an IPv4 address in a table or database with fixed size
     * > members that must also be able to store an IPv6 address.
     *
     * If needed it can be fixed by changing next line:
     *   if (best.base == 0 && (best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
     * to:
     *   if (best.base == 0 && best.len == 5 && words[5] == 0xffff)
     *
     * [0] http://en.wikipedia.org/wiki/IPv6_address#Historical_notes
     */

    if (best.base == 0 && (best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
    {
        /* best.len == 6 -> ::IPv4; 5 -> ::ffff:IPv4 */
        buf = g_stpcpy(buf, "::");
        if (best.len == 5)
        buf = g_stpcpy(buf, "ffff:");
        ip_to_str_buf(src + 12, buf, MAX_IP_STR_LEN);
        /* max: 2 + 5 + 16 == 23 bytes */
        return;
    }

    /*
     * Format the result.
     */
    for (i = 0; i < 8; i++) {
        /* Are we inside the best run of 0x00's? */
        if (i == best.base) {
            *buf++ = ':';
            i += best.len;

            /* Was it a trailing run of 0x00's? */
            if (i == 8) {
                *buf++ = ':';
                break;
            }
        }
        /* Are we following an initial run of 0x00s or any real hex? */
        if (i != 0)
            *buf++ = ':';

        buf = word_to_hex_npad(buf, words[i]); /* max: 4B */
        /* max: 8 * 4 + 7 == 39 bytes */
    }
    *buf = '\0'; /* 40 byte */
}

void
ip6_to_str_buf(const struct e_in6_addr *ad, gchar *buf)
{
    ip6_to_str_buf_len((const guchar*)ad, buf, MAX_IP6_STR_LEN);
}

gchar*
ipx_addr_to_str(const guint32 net, const guint8 *ad)
{
    gchar   *buf;
    char    *name;

    name = get_ether_name_if_known(ad);

    if (name) {
        buf = wmem_strdup_printf(wmem_packet_scope(), "%s.%s", get_ipxnet_name(wmem_packet_scope(), net), name);
    }
    else {
        buf = wmem_strdup_printf(wmem_packet_scope(), "%s.%s", get_ipxnet_name(wmem_packet_scope(), net),
            bytestring_to_str(wmem_packet_scope(), ad, 6, '\0'));
    }
    return buf;
}

gchar *
ipxnet_to_str_punct(wmem_allocator_t *scope, const guint32 ad, const char punct)
{
    gchar *buf = (gchar *)wmem_alloc(scope, 12);

    *dword_to_hex_punct(buf, ad, punct) = '\0';
    return buf;
}

/*
 This function is very fast and this function is called a lot.
 XXX update the address_to_str stuff to use this function.
*/
gchar *
eui64_to_str(wmem_allocator_t *scope, const guint64 ad) {
    gchar *buf;
    guint8 *p_eui64;

    p_eui64=(guint8 *)wmem_alloc(scope, 8);
    buf=(gchar *)wmem_alloc(scope, EUI64_STR_LEN);

    /* Copy and convert the address to network byte order. */
    *(guint64 *)(void *)(p_eui64) = pntoh64(&(ad));

    g_snprintf(buf, EUI64_STR_LEN, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
    p_eui64[0], p_eui64[1], p_eui64[2], p_eui64[3],
    p_eui64[4], p_eui64[5], p_eui64[6], p_eui64[7] );
    return buf;
}

static void
atalk_addr_to_str_buf(const struct atalk_ddp_addr *addrp, gchar *buf, int buf_len)
{
  g_snprintf(buf, buf_len, "%u.%u", addrp->net, addrp->node );
}

gchar *
atalk_addr_to_str(const struct atalk_ddp_addr *addrp)
{
  gchar *cur;

  cur=(gchar *)wmem_alloc(wmem_packet_scope(), 14);
  atalk_addr_to_str_buf(addrp, cur, 14);
  return cur;
}

gchar*
tvb_address_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, address_type type, const gint offset)
{
    address addr;

    addr.type = type;
    addr.hf = -1;

    switch(type)
    {
    case AT_NONE:
        addr.len = 0;
        break;
    case AT_ETHER:
        addr.len = 6;
        break;
    case AT_IPv4:
        addr.len = IPV4_LENGTH;
        break;
    case AT_IPv6:
        addr.len = IPV6_LENGTH;
        break;
    case AT_IPX:
        addr.len = 10;
        break;
    case AT_ATALK:
    case AT_FC:
        addr.len = 3;
        break;
    case AT_VINES:
        addr.len = VINES_ADDR_LEN;
        break;
    case AT_FCWWN:
        addr.len = FCWWN_ADDR_LEN;
        break;
    case AT_EUI64:
        addr.len = 8;
        break;
    case AT_AX25:
        addr.len = AX25_ADDR_LEN;
        break;
    case AT_ARCNET:
        addr.len = 1;
        break;
    case AT_SS7PC:
    case AT_STRINGZ:
    case AT_URI:
    case AT_IB:
        /* Have variable length fields, use tvb_address_var_to_str() */
    case AT_USB:
        /* These addresses are not supported through tvb accessor */
    default:
        /* XXX - Removed because of dynamic address type range
           XXX - Should we check that range?
        g_assert_not_reached();
        return NULL;
        */
        break;
    }

    switch (addr.len) {
    case 0:
        addr.data = NULL;
        break;
    case 1:
        addr.data = GUINT_TO_POINTER((guint)tvb_get_guint8(tvb, offset));
        break;
    default:
        addr.data = tvb_get_ptr(tvb, offset, addr.len);
        break;
    }

    return address_to_str(scope, &addr);
}

gchar* tvb_address_var_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, address_type type, const gint offset, int length)
{
    address addr;

    TVB_SET_ADDRESS(&addr, type, tvb, offset, length);

    return address_to_str(scope, &addr);
}

/*XXX FIXME the code below may be called very very frequently in the future.
  optimize it for speed and get rid of the slow sprintfs */
/* XXX - perhaps we should have individual address types register
   a table of routines to do operations such as address-to-name translation,
   address-to-string translation, and the like, and have this call them,
   and also have an address-to-string-with-a-name routine */
/* XXX - use this, and that future address-to-string-with-a-name routine,
   in "col_set_addr()"; it might also be useful to have address types
   export the names of the source and destination address fields, so
   that "col_set_addr()" need know nothing whatsoever about particular
   address types */
/* convert an address struct into a printable string */

gchar*
address_to_str(wmem_allocator_t *scope, const address *addr)
{
    gchar *str;
    int len = address_type_get_length(addr);

    if (len <= 0)
        len = MAX_ADDR_STR_LEN;

    str=(gchar *)wmem_alloc(scope, len);
    address_to_str_buf(addr, str, len);
    return str;
}

void
address_to_str_buf(const address *addr, gchar *buf, int buf_len)
{
    /* XXX - Keep this here for now to save changing all of the include headers */
    address_type_to_string(addr, buf, buf_len);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
