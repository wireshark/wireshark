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
#include "wsutil/pint.h"
#include "wsutil/str_util.h"
#include "sna-utils.h"
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

static void
vines_addr_to_str_buf(const guint8 *addrp, gchar *buf, int buf_len)
{
    if (buf_len < 14) {
        g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len); /* Let the unexpected value alert user */
        return;
    }

    buf = dword_to_hex(buf, pntoh32(&addrp[0])); /* 8 bytes */
    *buf++ = '.'; /* 1 byte */
    buf = word_to_hex(buf, pntoh16(&addrp[4])); /* 4 bytes */
    *buf = '\0'; /* 1 byte */
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
usb_addr_to_str_buf(const guint8 *addrp, gchar *buf, int buf_len)
{
    if(pletoh32(&addrp[0])==0xffffffff){
        g_snprintf(buf, buf_len, "host");
    } else {
        g_snprintf(buf, buf_len, "%d.%d.%d", pletoh16(&addrp[8]),
                        pletoh32(&addrp[0]), pletoh32(&addrp[4]));
    }
}

static void
tipc_addr_to_str_buf( const guint8 *data, gchar *buf, int buf_len){
    guint8 zone;
    guint16 subnetwork;
    guint16 processor;
    guint32 tipc_address;

    tipc_address = data[0];
    tipc_address = (tipc_address << 8) ^ data[1];
    tipc_address = (tipc_address << 8) ^ data[2];
    tipc_address = (tipc_address << 8) ^ data[3];

    processor = tipc_address & 0x0fff;

    tipc_address = tipc_address >> 12;
    subnetwork = tipc_address & 0x0fff;

    tipc_address = tipc_address >> 12;
    zone = tipc_address & 0xff;

    g_snprintf(buf,buf_len,"%u.%u.%u",zone,subnetwork,processor);
}

static void
ib_addr_to_str_buf( const address *addr, gchar *buf, int buf_len){
    if (addr->len >= 16) { /* GID is 128bits */
        #define PREAMBLE_STR_LEN ((int)(sizeof("GID: ") - 1))
        g_snprintf(buf,buf_len,"GID: ");
        if (buf_len < PREAMBLE_STR_LEN ||
                inet_ntop(AF_INET6, addr->data, buf + PREAMBLE_STR_LEN,
                          buf_len - PREAMBLE_STR_LEN) == NULL ) /* Returns NULL if no space and does not touch buf */
            g_snprintf ( buf, buf_len, BUF_TOO_SMALL_ERR ); /* Let the unexpected value alert user */
    } else {    /* this is a LID (16 bits) */
        guint16 lid_number;

        memcpy((void *)&lid_number, addr->data, sizeof lid_number);
        g_snprintf(buf,buf_len,"LID: %u",lid_number);
    }
}

/* FC Network Header Network Address Authority Identifiers */

#define FC_NH_NAA_IEEE          1   /* IEEE 802.1a */
#define FC_NH_NAA_IEEE_E        2   /* IEEE Exteneded */
#define FC_NH_NAA_LOCAL         3
#define FC_NH_NAA_IP            4   /* 32-bit IP address */
#define FC_NH_NAA_IEEE_R        5   /* IEEE Registered */
#define FC_NH_NAA_IEEE_R_E      6   /* IEEE Registered Exteneded */
/* according to FC-PH 3 draft these are now reclaimed and reserved */
#define FC_NH_NAA_CCITT_INDV    12  /* CCITT 60 bit individual address */
#define FC_NH_NAA_CCITT_GRP     14  /* CCITT 60 bit group address */

static void
fcwwn_addr_to_str_buf(const guint8 *addrp, gchar *buf, int buf_len)
{
    int fmt;
    guint8 oui[6];
    gchar *ethptr, *manuf_name;

    if (buf_len < 200) {  /* This is mostly for manufacturer name */
        g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len); /* Let the unexpected value alert user */
        return;
    }

    ethptr = bytes_to_hexstr_punct(buf, addrp, 8, ':'); /* 23 bytes */
    fmt = (addrp[0] & 0xF0) >> 4;
    switch (fmt) {

    case FC_NH_NAA_IEEE:
    case FC_NH_NAA_IEEE_E:
        memcpy (oui, &addrp[2], 6);

        manuf_name = get_manuf_name(NULL, oui);
        g_snprintf (ethptr, buf_len-23, " (%s)", manuf_name);
        wmem_free(NULL, manuf_name);
        break;

    case FC_NH_NAA_IEEE_R:
        oui[0] = ((addrp[0] & 0x0F) << 4) | ((addrp[1] & 0xF0) >> 4);
        oui[1] = ((addrp[1] & 0x0F) << 4) | ((addrp[2] & 0xF0) >> 4);
        oui[2] = ((addrp[2] & 0x0F) << 4) | ((addrp[3] & 0xF0) >> 4);
        oui[3] = ((addrp[3] & 0x0F) << 4) | ((addrp[4] & 0xF0) >> 4);
        oui[4] = ((addrp[4] & 0x0F) << 4) | ((addrp[5] & 0xF0) >> 4);
        oui[5] = ((addrp[5] & 0x0F) << 4) | ((addrp[6] & 0xF0) >> 4);

        manuf_name = get_manuf_name(NULL, oui);
        g_snprintf (ethptr, buf_len-23, " (%s)", manuf_name);
        wmem_free(NULL, manuf_name);
        break;

    default:
        *ethptr = '\0';
        break;
    }
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
    case AT_IEEE_802_15_4_SHORT:
        addr.len = 2;
        break;
    case AT_ARCNET:
    case AT_J1939:
        addr.len = 1;
        break;
    case AT_DEVICENET:
        addr.len = 1;
        addr.data = GUINT_TO_POINTER((tvb_get_guint8(tvb, offset) & 0x3F));
        return address_to_str(scope, &addr);
    case AT_OSI:
    case AT_SNA:
    case AT_SS7PC:
    case AT_STRINGZ:
    case AT_URI:
    case AT_TIPC:
    case AT_IB:
        /* Have variable length fields, use tvb_address_var_to_str() */
    case AT_USB:
        /* These addresses are not supported through tvb accessor */
    default:
        g_assert_not_reached();
        return NULL;
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

    str=(gchar *)wmem_alloc(scope, MAX_ADDR_STR_LEN);
    address_to_str_buf(addr, str, MAX_ADDR_STR_LEN);
    return str;
}

void
address_to_str_buf(const address *addr, gchar *buf, int buf_len)
{
    const guint8 *addrdata;
    struct atalk_ddp_addr ddp_addr;
    guint16 ieee_802_15_4_short_addr;

    char temp[32];
    char *tempptr = temp;

    if (!buf || !buf_len)
        return;

    switch(addr->type){
    case AT_NONE:
        buf[0] = '\0';
        break;
    case AT_ETHER: /* 18 bytes */
        tempptr = bytes_to_hexstr_punct(tempptr, (const guint8 *)addr->data, 6, ':'); /* 17 bytes */
        break;
    case AT_IPv4:
        ip_to_str_buf((const guint8 *)addr->data, buf, buf_len);
        break;
    case AT_IPv6:
        ip6_to_str_buf_len((const guchar *)addr->data, buf, buf_len);
        break;
    case AT_IPX: /* 22 bytes */
        addrdata = (const guint8 *)addr->data;
        tempptr = bytes_to_hexstr(tempptr, &addrdata[0], 4); /* 8 bytes */
        *tempptr++ = '.'; /*1 byte */
        tempptr = bytes_to_hexstr(tempptr, &addrdata[4], 6); /* 12 bytes */
        break;
    case AT_SNA:
        sna_fid_to_str_buf(addr, buf, buf_len);
        break;
    case AT_ATALK:
        memcpy(&ddp_addr, addr->data, sizeof ddp_addr);
        atalk_addr_to_str_buf(&ddp_addr, buf, buf_len);
        break;
    case AT_VINES:
        vines_addr_to_str_buf((const guint8 *)addr->data, buf, buf_len);
        break;
    case AT_USB:
        usb_addr_to_str_buf((const guint8 *)addr->data, buf, buf_len);
        break;
    case AT_OSI:
        print_nsap_net_buf((const guint8 *)addr->data, addr->len, buf, buf_len);
        break;
    case AT_ARCNET: /* 5 bytes */
        tempptr = g_stpcpy(tempptr, "0x"); /* 2 bytes */
        tempptr = bytes_to_hexstr(tempptr, (const guint8 *)addr->data, 1); /* 2 bytes */
        break;
    case AT_FC: /* 9 bytes */
        tempptr = bytes_to_hexstr_punct(tempptr, (const guint8 *)addr->data, 3, '.'); /* 8 bytes */
        break;
    case AT_FCWWN:
        fcwwn_addr_to_str_buf((const guint8 *)addr->data, buf, buf_len);
        break;
    case AT_SS7PC:
        mtp3_addr_to_str_buf((const mtp3_addr_pc_t *)addr->data, buf, buf_len);
        break;
    case AT_STRINGZ:
        g_strlcpy(buf, (const gchar *)addr->data, buf_len);
        break;
        case AT_EUI64: /* 24 bytes */
        tempptr = bytes_to_hexstr_punct(tempptr, (const guint8 *)addr->data, 8, ':'); /* 23 bytes */
        break;
    case AT_URI: {
        int copy_len = addr->len < (buf_len - 1) ? addr->len : (buf_len - 1);
        memcpy(buf, addr->data, copy_len );
        buf[copy_len] = '\0';
        }
        break;
    case AT_TIPC:
        tipc_addr_to_str_buf((const guint8 *)addr->data, buf, buf_len);
        break;
    case AT_IB:
        ib_addr_to_str_buf(addr, buf, buf_len);
        break;
    case AT_AX25:
        addrdata = (const guint8 *)addr->data;
        g_snprintf(buf, buf_len, "%c%c%c%c%c%c-%02d",
                printable_char_or_period(addrdata[0] >> 1),
                printable_char_or_period(addrdata[1] >> 1),
                printable_char_or_period(addrdata[2] >> 1),
                printable_char_or_period(addrdata[3] >> 1),
                printable_char_or_period(addrdata[4] >> 1),
                printable_char_or_period(addrdata[5] >> 1),
                (addrdata[6] >> 1) & 0x0f );
        break;
    case AT_IEEE_802_15_4_SHORT:
        ieee_802_15_4_short_addr = pletoh16(addr->data);
        if (ieee_802_15_4_short_addr == 0xffff)
            g_snprintf(buf, buf_len, "Broadcast");
        else
            g_snprintf(buf, buf_len, "0x%04x", ieee_802_15_4_short_addr);
        break;
    case AT_J1939:
        addrdata = (const guint8 *)addr->data;
        g_snprintf(buf, buf_len, "%d", addrdata[0]);
        break;
    case AT_DEVICENET:
        addrdata = (const guint8 *)addr->data;
        g_snprintf(buf, buf_len, "%d", addrdata[0] & 0x3f);
        break;
    default:
        g_assert_not_reached();
    }

    /* copy to output buffer */
    if (tempptr != temp) {
        size_t temp_len = (size_t) (tempptr - temp);

        if (temp_len < (size_t) buf_len) {
            memcpy(buf, temp, temp_len);
            buf[temp_len] = '\0';
        } else
            g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);/* Let the unexpected value alert user */
    }
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
