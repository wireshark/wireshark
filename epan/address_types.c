/* address_types.c
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

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>        /* needed for <arpa/inet.h> on some platforms */
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>         /* needed to define AF_ values on UNIX */
#endif

#include <string.h>     /* for memcmp */
#include "packet.h"
#include "address_types.h"
#include "to_str.h"
#include "to_str-int.h"
#include "addr_resolv.h"
#include "wsutil/pint.h"
#include "wsutil/str_util.h"
#include "wsutil/inet_v6defs.h"

#include <epan/dissectors/packet-mtp3.h>

struct _address_type_t {
    int                     addr_type; /* From address_type enumeration or registered value */
    const char             *name;
    const char             *pretty_name;
    AddrValueToString       addr_to_str;
    AddrValueToStringLen    addr_str_len;
    AddrColFilterString     addr_col_filter;
    AddrFixedLen            addr_fixed_len;

    /* XXX - Some sort of compare functions (like ftype)? ***/
    /* XXX - Include functions for name resolution? ***/
};

#define MAX_DISSECTOR_ADDR_TYPE     20
#define MAX_ADDR_TYPE_VALUE (AT_END_OF_LIST+MAX_DISSECTOR_ADDR_TYPE)

static int num_dissector_addr_type;
static address_type_t dissector_type_addresses[MAX_DISSECTOR_ADDR_TYPE];

/* Keep track of address_type_t's via their id number */
static address_type_t* type_list[MAX_ADDR_TYPE_VALUE];

/*
 * If a user _does_ pass in a too-small buffer, this is probably
 * going to be too long to fit.  However, even a partial string
 * starting with "[Buf" should provide enough of a clue to be
 * useful.
 */
#define BUF_TOO_SMALL_ERR "[Buffer too small]"

static void address_type_register(int addr_type, address_type_t *at)
{
    /* Check input */
    g_assert(addr_type < MAX_ADDR_TYPE_VALUE);
    g_assert(addr_type == at->addr_type);

    /* Don't re-register. */
    g_assert(type_list[addr_type] == NULL);

    type_list[addr_type] = at;
}

int address_type_dissector_register(const char* name, const char* pretty_name,
                                    AddrValueToString to_str_func, AddrValueToStringLen str_len_func,
                                    AddrColFilterString col_filter_str_func, AddrFixedLen fixed_len_func)
{
    int addr_type;

    /* Ensure valid data/functions for required fields */
    DISSECTOR_ASSERT(name);
    DISSECTOR_ASSERT(pretty_name);
    DISSECTOR_ASSERT(to_str_func);
    DISSECTOR_ASSERT(str_len_func);

    /* This shouldn't happen, so flag it for fixing */
    DISSECTOR_ASSERT(num_dissector_addr_type < MAX_DISSECTOR_ADDR_TYPE);

    addr_type = AT_END_OF_LIST+num_dissector_addr_type;
    dissector_type_addresses[num_dissector_addr_type].addr_type = addr_type;
    dissector_type_addresses[num_dissector_addr_type].name = name;
    dissector_type_addresses[num_dissector_addr_type].pretty_name = pretty_name;
    dissector_type_addresses[num_dissector_addr_type].addr_to_str = to_str_func;
    dissector_type_addresses[num_dissector_addr_type].addr_str_len = str_len_func;
    dissector_type_addresses[num_dissector_addr_type].addr_col_filter = col_filter_str_func;
    dissector_type_addresses[num_dissector_addr_type].addr_fixed_len = fixed_len_func;

    type_list[addr_type] = &dissector_type_addresses[num_dissector_addr_type];

    num_dissector_addr_type++;

    return addr_type;
}

/******************************************************************************
 * AT_NONE
 ******************************************************************************/
gboolean none_addr_to_str(const address* addr _U_, gchar *buf, int buf_len _U_)
{
    buf[0] = '\0';
    return TRUE;
}

int none_addr_str_len(const address* addr _U_)
{
    return 1; /* NULL character for empty string */
}

int none_addr_len(void)
{
    return 0;
}

/******************************************************************************
 * AT_ETHER
 ******************************************************************************/
gboolean ether_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    bytes_to_hexstr_punct(buf, (const guint8*)addr->data, 6, ':');
    buf[17] = '\0';
    return TRUE;
}

int ether_str_len(const address* addr _U_)
{
    return 18;
}

static const char* ether_col_filter_str(const address* addr _U_, gboolean is_src)
{
    if (is_src)
        return "eth.src";

    return "eth.dst";
}

int ether_len(void)
{
    return 6;
}

/******************************************************************************
 * AT_IPv4
 ******************************************************************************/
static gboolean ipv4_to_str(const address* addr, gchar *buf, int buf_len)
{
    ip_to_str_buf((const guint8*)addr->data, buf, buf_len);
    return TRUE;
}

static int ipv4_str_len(const address* addr _U_)
{
    return MAX_IP_STR_LEN;
}

static const char* ipv4_col_filter_str(const address* addr _U_, gboolean is_src)
{
    if (is_src)
        return "ip.src";

    return "ip.dst";
}

static int ipv4_len(void)
{
    return 4;
}

/******************************************************************************
 * AT_IPv6
 ******************************************************************************/
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

static gboolean ipv6_to_str(const address* addr, gchar *buf, int buf_len)
{
    ip6_to_str_buf_len((const guchar*)addr->data, buf, buf_len);
    return TRUE;
}

static int ipv6_str_len(const address* addr _U_)
{
    return MAX_IP6_STR_LEN;
}

static const char* ipv6_col_filter_str(const address* addr _U_, gboolean is_src)
{
    if (is_src)
        return "ipv6.src";

    return "ipv6.dst";
}

static int ipv6_len(void)
{
    return 16;
}

/******************************************************************************
 * AT_IPX
 ******************************************************************************/
static gboolean ipx_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    const guint8 *addrdata = (const guint8 *)addr->data;

    buf = bytes_to_hexstr(buf, &addrdata[0], 4); /* 8 bytes */
    *buf++ = '.'; /*1 byte */
    buf = bytes_to_hexstr(buf, &addrdata[4], 6); /* 12 bytes */
    *buf++ = '\0'; /* NULL terminate */
    return TRUE;
}

static int ipx_str_len(const address* addr _U_)
{
    return 22;
}

static int ipx_len(void)
{
    return 10;
}

/******************************************************************************
 * AT_VINES
 * XXX - This functionality should really be in packet-vines.c as a dissector
 * address type, but need to resolve "address type" as "field type"
 ******************************************************************************/
static gboolean vines_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    const guint8 *addr_data = (const guint8 *)addr->data;

    buf = dword_to_hex(buf, pntoh32(&addr_data[0])); /* 8 bytes */
    *buf++ = '.'; /* 1 byte */
    buf = word_to_hex(buf, pntoh16(&addr_data[4])); /* 4 bytes */
    *buf = '\0'; /* NULL terminate */

    return TRUE;
}

static int vines_str_len(const address* addr _U_)
{
    return 14;
}

static int vines_len(void)
{
    return VINES_ADDR_LEN;
}

/******************************************************************************
 * AT_FC
 ******************************************************************************/
static gboolean fc_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    buf = bytes_to_hexstr_punct(buf, (const guint8 *)addr->data, 3, '.');
    *buf = '\0'; /* NULL terminate */

    return TRUE;
}

static int fc_str_len(const address* addr _U_)
{
    return 9;
}

static int fc_len(void)
{
    return 3;
}

/******************************************************************************
 * AT_FCWWN
 * XXX - Doubles as a "field type", should it be defined here?
 * XXX - currently this has some address resolution worked into the "base" string
 ******************************************************************************/
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

static gboolean fcwwn_to_str(const address* addr, gchar *buf, int buf_len)
{
    const guint8 *addrp = (const guint8*)addr->data;
    int fmt;
    guint8 oui[6];
    gchar *ethptr, *manuf_name;

    if (buf_len < 200) {  /* This is mostly for manufacturer name */
        g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len); /* Let the unexpected value alert user */
        return FALSE;
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

    return TRUE;
}

static int fcwwn_str_len(const address* addr _U_)
{
    return 200;
}

static int fcwwn_len(void)
{
    return FCWWN_ADDR_LEN;
}

/******************************************************************************
 * AT_SS7PC
 * XXX - This should really be a dissector address type as its address string
 * is partially determined by a dissector preference.
 ******************************************************************************/
static gboolean ss7pc_to_str(const address* addr, gchar *buf, int buf_len)
{
    mtp3_addr_to_str_buf((const mtp3_addr_pc_t *)addr->data, buf, buf_len);
    return TRUE;
}

static int ss7pc_str_len(const address* addr _U_)
{
    return 50;
}

/******************************************************************************
 * AT_STRINGZ
 ******************************************************************************/
static gboolean stringz_addr_to_str(const address* addr, gchar *buf, int buf_len)
{
    g_strlcpy(buf, (const gchar *)addr->data, buf_len);
    return TRUE;
}

static int stringz_addr_str_len(const address* addr)
{
    return addr->len+1;
}

/******************************************************************************
 * AT_EUI64
 ******************************************************************************/
static gboolean eui64_addr_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    buf = bytes_to_hexstr_punct(buf, (const guint8 *)addr->data, 8, ':');
    *buf = '\0'; /* NULL terminate */
    return TRUE;
}

static int eui64_str_len(const address* addr _U_)
{
    return EUI64_STR_LEN;
}

static int eui64_len(void)
{
    return 8;
}

/******************************************************************************
 * AT_IB
 ******************************************************************************/
static gboolean
ib_addr_to_str( const address *addr, gchar *buf, int buf_len){
    if (addr->len >= 16) { /* GID is 128bits */
        #define PREAMBLE_STR_LEN ((int)(sizeof("GID: ") - 1))
        g_strlcpy(buf, "GID: ", buf_len);
        if (buf_len < PREAMBLE_STR_LEN ||
                inet_ntop(AF_INET6, addr->data, buf + PREAMBLE_STR_LEN,
                          buf_len - PREAMBLE_STR_LEN) == NULL ) /* Returns NULL if no space and does not touch buf */
            g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len); /* Let the unexpected value alert user */
    } else {    /* this is a LID (16 bits) */
        guint16 lid_number;

        memcpy((void *)&lid_number, addr->data, sizeof lid_number);
        g_snprintf(buf,buf_len,"LID: %u",lid_number);
    }

    return TRUE;
}

static int ib_str_len(const address* addr _U_)
{
    return MAX_ADDR_STR_LEN; /* XXX - This is overkill */
}

/******************************************************************************
 * AT_USB
 * XXX - This functionality should really be in packet-usb.c as a dissector
 * address type, but currently need support of AT_USB in conversation_table.c
 ******************************************************************************/
static gboolean usb_addr_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    const guint8 *addrp = (const guint8 *)addr->data;

    if(pletoh32(&addrp[0])==0xffffffff){
        g_strlcpy(buf, "host", buf_len);
    } else {
        g_snprintf(buf, buf_len, "%d.%d.%d", pletoh16(&addrp[8]),
                        pletoh32(&addrp[0]), pletoh32(&addrp[4]));
    }

    return TRUE;
}

static int usb_addr_str_len(const address* addr _U_)
{
    return 50;
}

/******************************************************************************
 * AT_AX25
 ******************************************************************************/
static gboolean ax25_addr_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    const guint8 *addrdata = (const guint8 *)addr->data;

    *buf++ = printable_char_or_period(addrdata[0] >> 1);
    *buf++ = printable_char_or_period(addrdata[1] >> 1);
    *buf++ = printable_char_or_period(addrdata[2] >> 1);
    *buf++ = printable_char_or_period(addrdata[3] >> 1);
    *buf++ = printable_char_or_period(addrdata[4] >> 1);
    *buf++ = printable_char_or_period(addrdata[5] >> 1);
    *buf++ = '-';
    buf = uint_to_str_back(buf, (addrdata[6] >> 1) & 0x0f);
    *buf = '\0'; /* NULL terminate */

    return TRUE;
}

static int ax25_addr_str_len(const address* addr _U_)
{
    return 21; /* Leaves extra space (10 bytes) just for uint_to_str_back() */
}

static const char* ax25_col_filter_str(const address* addr _U_, gboolean is_src)
{
    if (is_src)
        return "ax25.src";

    return "ax25.dst";
}

static int ax25_len(void)
{
    return AX25_ADDR_LEN;
}

/******************************************************************************
 * END OF PROVIDED ADDRESS TYPES
 ******************************************************************************/




void address_types_initialize(void)
{
    static address_type_t none_address = {
        AT_NONE,            /* addr_type */
        "AT_NONE",          /* name */
        "No address",       /* pretty_name */
        none_addr_to_str,   /* addr_to_str */
        none_addr_str_len,  /* addr_str_len */
        NULL,               /* addr_col_filter */
        none_addr_len       /* addr_fixed_len */
    };

    static address_type_t ether_address = {
        AT_ETHER,           /* addr_type */
        "AT_ETHER",         /* name */
        "Ethernet address", /* pretty_name */
        ether_to_str,       /* addr_to_str */
        ether_str_len,      /* addr_str_len */
        ether_col_filter_str, /* addr_col_filter */
        ether_len           /* addr_fixed_len */
    };

    static address_type_t ipv4_address = {
        AT_IPv4,            /* addr_type */
        "AT_IPv4",          /* name */
        "IPv4 address",     /* pretty_name */
        ipv4_to_str,        /* addr_to_str */
        ipv4_str_len,       /* addr_str_len */
        ipv4_col_filter_str, /* addr_col_filter */
        ipv4_len            /* addr_fixed_len */
    };

    static address_type_t ipv6_address = {
        AT_IPv6,            /* addr_type */
        "AT_IPv6",          /* name */
        "IPv6 address",     /* pretty_name */
        ipv6_to_str,        /* addr_to_str */
        ipv6_str_len,       /* addr_str_len */
        ipv6_col_filter_str, /* addr_col_filter */
        ipv6_len            /* addr_fixed_len */
   };

    static address_type_t ipx_address = {
        AT_IPX,             /* addr_type */
        "AT_IPX",           /* name */
        "IPX address",      /* pretty_name */
        ipx_to_str,         /* addr_to_str */
        ipx_str_len,        /* addr_str_len */
        NULL,               /* addr_col_filter */
        ipx_len             /* addr_fixed_len */
    };

    static address_type_t vines_address = {
        AT_VINES,           /* addr_type */
        "AT_VINES",         /* name */
        "Banyan Vines address", /* pretty_name */
        vines_to_str,       /* addr_to_str */
        vines_str_len,      /* addr_str_len */
        NULL,                /* addr_col_filter */
        vines_len          /*addr_fixed_len */
    };

    static address_type_t fc_address = {
        AT_FC,          /* addr_type */
        "AT_FC",        /* name */
        "FC address",   /* pretty_name */
        fc_to_str,      /* addr_to_str */
        fc_str_len,     /* addr_str_len */
        NULL,           /* addr_col_filter */
        fc_len          /*addr_fixed_len */
    };

    static address_type_t fcwwn_address = {
        AT_FCWWN,       /* addr_type */
        "AT_FCWWN",     /* name */
        "Fibre Channel WWN",    /* pretty_name */
        fcwwn_to_str,   /* addr_to_str */
        fcwwn_str_len,  /* addr_str_len */
        NULL,           /* addr_col_filter */
        fcwwn_len          /* addr_fixed_len */
    };

    static address_type_t ss7pc_address = {
        AT_SS7PC,          /* addr_type */
        "AT_SS7PC",        /* name */
        "SS7 Point Code",  /* pretty_name */
        ss7pc_to_str,      /* addr_to_str */
        ss7pc_str_len,     /* addr_str_len */
        NULL,              /* addr_col_filter */
        NULL               /* addr_fixed_len */
    };

    static address_type_t stringz_address = {
        AT_STRINGZ,          /* addr_type */
        "AT_STRINGZ",        /* name */
        "String address",   /* pretty_name */
        stringz_addr_to_str, /* addr_to_str */
        stringz_addr_str_len, /* addr_str_len */
        NULL,              /* addr_col_filter */
        NULL               /* addr_fixed_len */
    };

    static address_type_t eui64_address = {
        AT_EUI64,          /* addr_type */
        "AT_EUI64",        /* name */
        "IEEE EUI-64",     /* pretty_name */
        eui64_addr_to_str, /* addr_to_str */
        eui64_str_len,     /* addr_str_len */
        NULL,              /* addr_col_filter */
        eui64_len          /* addr_fixed_len */
    };

    static address_type_t ib_address = {
        AT_IB,           /* addr_type */
        "AT_IB",         /* name */
        "Infiniband GID/LID",   /* pretty_name */
        ib_addr_to_str,  /* addr_to_str */
        ib_str_len,      /* addr_str_len */
        NULL,              /* addr_col_filter */
        NULL               /* addr_fixed_len */
    };

    static address_type_t usb_address = {
        AT_USB,          /* addr_type */
        "AT_USB",        /* name */
        "USB Address",   /* pretty_name */
        usb_addr_to_str, /* addr_to_str */
        usb_addr_str_len, /* addr_str_len */
        NULL,              /* addr_col_filter */
        NULL               /* addr_fixed_len */
    };

    static address_type_t ax25_address = {
        AT_AX25,          /* addr_type */
        "AT_AX25",        /* name */
        "AX.25 Address",  /* pretty_name */
        ax25_addr_to_str, /* addr_to_str */
        ax25_addr_str_len,/* addr_str_len */
        ax25_col_filter_str, /* addr_col_filter */
        ax25_len          /* addr_fixed_len */
    };

    num_dissector_addr_type = 0;

    /* Initialize the type array.  This is mostly for handling
       "dissector registered" address type range (for NULL checking) */
    memset(type_list, 0, MAX_ADDR_TYPE_VALUE*sizeof(address_type_t*));

    address_type_register(AT_NONE, &none_address );
    address_type_register(AT_ETHER, &ether_address );
    address_type_register(AT_IPv4, &ipv4_address );
    address_type_register(AT_IPv6, &ipv6_address );
    address_type_register(AT_IPX, &ipx_address );
    address_type_register(AT_VINES, &vines_address );
    address_type_register(AT_FC, &fc_address );
    address_type_register(AT_FCWWN, &fcwwn_address );
    address_type_register(AT_SS7PC, &ss7pc_address );
    address_type_register(AT_STRINGZ, &stringz_address );
    address_type_register(AT_EUI64, &eui64_address );
    address_type_register(AT_IB, &ib_address );
    address_type_register(AT_USB, &usb_address );
    address_type_register(AT_AX25, &ax25_address );
}

/* Given an address type id, return an address_type_t* */
#define ADDR_TYPE_LOOKUP(addr_type, result)    \
    /* Check input */                          \
    g_assert(addr_type < MAX_ADDR_TYPE_VALUE); \
    result = type_list[addr_type];

static int address_type_get_length(const address* addr)
{
    address_type_t *at;

    ADDR_TYPE_LOOKUP(addr->type, at);

    if ((at == NULL) || (at->addr_str_len == NULL))
        return 0;

    return at->addr_str_len(addr);
}

/*XXX FIXME the code below may be called very very frequently in the future.
  optimize it for speed and get rid of the slow sprintfs */
/* XXX - perhaps we should have individual address types register
   a table of routines to do operations such as address-to-name translation,
   address-to-string translation, and the like, and have this call them,
   and also have an address-to-string-with-a-name routine */
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

void address_to_str_buf(const address* addr, gchar *buf, int buf_len)
{
    address_type_t *at;

    if (!buf || !buf_len)
        return;

    ADDR_TYPE_LOOKUP(addr->type, at);

    if ((at == NULL) || (at->addr_to_str == NULL))
    {
        buf[0] = '\0';
        return;
    }

    at->addr_to_str(addr, buf, buf_len);
}

const char* address_type_column_filter_string(const address* addr, gboolean src)
{
    address_type_t *at;

    ADDR_TYPE_LOOKUP(addr->type, at);

    if ((at == NULL) || (at->addr_col_filter == NULL))
    {
        return "";
    }

    return at->addr_col_filter(addr, src);
}

gchar*
tvb_address_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int type, const gint offset)
{
    address addr;
    address_type_t *at;

    ADDR_TYPE_LOOKUP(type, at);

    if (at == NULL)
    {
        return NULL;
    }

    /* The address type must have a fixed length to use this function */
    /* For variable length fields, use tvb_address_var_to_str() */
    if (at->addr_fixed_len == NULL)
    {
        g_assert_not_reached();
        return NULL;
    }

    TVB_SET_ADDRESS(&addr, type, tvb, offset, at->addr_fixed_len());

    return address_to_str(scope, &addr);
}

gchar* tvb_address_var_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, address_type type, const gint offset, int length)
{
    address addr;

    TVB_SET_ADDRESS(&addr, type, tvb, offset, length);

    return address_to_str(scope, &addr);
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
