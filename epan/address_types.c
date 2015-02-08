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
	int              addr_type; /* From address_type enumeration or registered value */
	const char		*name;
	const char		*pretty_name;
	AddrValueToString       addr_to_str;
	AddrValueToStringLen    addr_str_len;

    /* XXX - Some sort of compare functions (like ftype)? ***/
    /* XXX - Include functions for name resolution? ***/
};

#define MAX_DISSECTOR_ADDR_TYPE     15
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

void address_type_register(int addr_type, address_type_t *at)
{
	/* Check input */
	g_assert(addr_type < MAX_ADDR_TYPE_VALUE);
	g_assert(addr_type == at->addr_type);

	/* Don't re-register. */
	g_assert(type_list[addr_type] == NULL);

	type_list[addr_type] = at;
}

int address_type_dissector_register(const char* name, const char* pretty_name,
                                    AddrValueToString to_str_func, AddrValueToStringLen str_len_func)
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

	type_list[addr_type] = &dissector_type_addresses[num_dissector_addr_type];

    num_dissector_addr_type++;

    return addr_type;
}

/******************************************************************************
 * AT_NONE
 ******************************************************************************/
static gboolean none_addr_to_str(const address* addr _U_, gchar *buf, int buf_len _U_)
{
    buf[0] = '\0';
    return TRUE;
}

static int none_addr_str_len(const address* addr _U_)
{
    return 1; /* NULL character for empty string */
}

/******************************************************************************
 * AT_ETHER
 ******************************************************************************/
static gboolean ether_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    bytes_to_hexstr_punct(buf, (const guint8*)addr->data, 6, ':');
    buf[17] = '\0';
    return TRUE;
}

static int ether_str_len(const address* addr _U_)
{
    return 18;
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

/******************************************************************************
 * AT_IPv6
 ******************************************************************************/
static gboolean ipv6_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    /* XXX - pull in ip6_to_str_buf_len as this should be the module for it */

    ip6_to_str_buf((const struct e_in6_addr*)addr->data, buf/*, buf_len*/);
    return TRUE;
}

static int ipv6_str_len(const address* addr _U_)
{
    return MAX_IP6_STR_LEN;
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


/******************************************************************************
 * AT_ATALK
 * XXX - This functionality should really be in packet-atalk.c as a dissector
 * address type, but currently need support of AT_ATALK in column-utils.c
 ******************************************************************************/
static gboolean atalk_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    struct atalk_ddp_addr atalk;
    memcpy(&atalk, addr->data, sizeof atalk);

    buf = word_to_hex(buf, atalk.net);
    *buf++ = '.';
    buf = bytes_to_hexstr(buf, &atalk.node, 1);
    *buf++ = '\0'; /* NULL terminate */

    return TRUE;
}

static int atalk_str_len(const address* addr _U_)
{
    return 14;
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

/******************************************************************************
 * AT_ARCNET
 * XXX - This functionality should really be in packet-arcnet.c as a dissector
 * address type, but currently need support of AT_ARCNET in column-utils.c
 ******************************************************************************/
static gboolean arcnet_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    *buf++ = '0';
    *buf++ = 'x';
    buf = bytes_to_hexstr(buf, (const guint8 *)addr->data, 1);
    *buf = '\0'; /* NULL terminate */

    return TRUE;
}

static int arcnet_str_len(const address* addr _U_)
{
    return 5;
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
    return 24;
}

/******************************************************************************
 * AT_URI
 * XXX - This functionality should really be in packet-jxta.c as a dissector
 * address type, but currently need support of AT_URI in column-utils.c
 ******************************************************************************/
static gboolean uri_to_str(const address* addr, gchar *buf, int buf_len)
{
    int copy_len = addr->len < (buf_len - 1) ? addr->len : (buf_len - 1);
    memcpy(buf, addr->data, copy_len );
    buf[copy_len] = '\0';
    return TRUE;
}

static int uri_str_len(const address* addr)
{
    return addr->len+1;
}

/******************************************************************************
 * AT_IB
 ******************************************************************************/
static gboolean
ib_addr_to_str( const address *addr, gchar *buf, int buf_len){
    if (addr->len >= 16) { /* GID is 128bits */
        #define PREAMBLE_STR_LEN ((int)(sizeof("GID: ") - 1))
        g_snprintf(buf,buf_len,"GID: ");
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

/******************************************************************************
 * END OF PROVIDED ADDRESS TYPES
 ******************************************************************************/




void address_types_initialize(void)
{
    static address_type_t none_address = {
		AT_NONE,			/* addr_type */
		"AT_NONE",			/* name */
		"No address",		/* pretty_name */
		none_addr_to_str,   /* addr_to_str */
		none_addr_str_len   /* addr_str_len */
    };

    static address_type_t ether_address = {
		AT_ETHER,			/* addr_type */
		"AT_ETHER",			/* name */
		"Ethernet address",	/* pretty_name */
		ether_to_str,       /* addr_to_str */
		ether_str_len       /* addr_str_len */
    };

    static address_type_t ipv4_address = {
		AT_IPv4,			/* addr_type */
		"AT_IPv4",			/* name */
		"IPv4 address",		/* pretty_name */
		ipv4_to_str,        /* addr_to_str */
		ipv4_str_len        /* addr_str_len */
    };

    static address_type_t ipv6_address = {
		AT_IPv6,			/* addr_type */
		"AT_IPv6",			/* name */
		"IPv6 address",		/* pretty_name */
		ipv6_to_str,        /* addr_to_str */
		ipv6_str_len        /* addr_str_len */
    };

    static address_type_t ipx_address = {
		AT_IPX,			    /* addr_type */
		"AT_IPX",			/* name */
		"IPX address",		/* pretty_name */
		ipx_to_str,         /* addr_to_str */
		ipx_str_len         /* addr_str_len */
    };

    static address_type_t atalk_address = {
		AT_ATALK,			/* addr_type */
		"AT_ATALK",			/* name */
		"ATALK address",	/* pretty_name */
		atalk_to_str,       /* addr_to_str */
		atalk_str_len       /* addr_str_len */
    };

    static address_type_t vines_address = {
		AT_VINES,			/* addr_type */
		"AT_VINES",			/* name */
		"Banyan Vines address",	/* pretty_name */
		vines_to_str,       /* addr_to_str */
		vines_str_len       /* addr_str_len */
    };

    static address_type_t arcnet_address = {
		AT_ARCNET,          /* addr_type */
		"AT_ARCNET",        /* name */
		"ARCNET address",	/* pretty_name */
		arcnet_to_str,      /* addr_to_str */
		arcnet_str_len      /* addr_str_len */
    };

    static address_type_t fc_address = {
		AT_FC,          /* addr_type */
		"AT_FC",        /* name */
		"FC address",	/* pretty_name */
		fc_to_str,      /* addr_to_str */
		fc_str_len      /* addr_str_len */
    };

    static address_type_t fcwwn_address = {
		AT_FCWWN,       /* addr_type */
		"AT_FCWWN",     /* name */
		"Fibre Channel WWN",    /* pretty_name */
		fcwwn_to_str,   /* addr_to_str */
		fcwwn_str_len   /* addr_str_len */
    };

    static address_type_t ss7pc_address = {
		AT_SS7PC,          /* addr_type */
		"AT_SS7PC",        /* name */
		"SS7 Point Code",  /* pretty_name */
		ss7pc_to_str,      /* addr_to_str */
		ss7pc_str_len      /* addr_str_len */
    };

    static address_type_t stringz_address = {
		AT_STRINGZ,          /* addr_type */
		"AT_STRINGZ",        /* name */
		"String address",   /* pretty_name */
		stringz_addr_to_str, /* addr_to_str */
		stringz_addr_str_len /* addr_str_len */
    };

    static address_type_t eui64_address = {
		AT_EUI64,          /* addr_type */
		"AT_EUI64",        /* name */
		"IEEE EUI-64",   /* pretty_name */
		eui64_addr_to_str, /* addr_to_str */
		eui64_str_len /* addr_str_len */
    };

    static address_type_t uri_address = {
		AT_URI,          /* addr_type */
		"AT_URI",        /* name */
		"URI/URL/URN",   /* pretty_name */
		uri_to_str, /* addr_to_str */
		uri_str_len /* addr_str_len */
    };

    static address_type_t ib_address = {
		AT_IB,          /* addr_type */
		"AT_IB",        /* name */
		"Infiniband GID/LID",   /* pretty_name */
		ib_addr_to_str, /* addr_to_str */
		ib_str_len      /* addr_str_len */
    };

    static address_type_t usb_address = {
		AT_USB,          /* addr_type */
		"AT_USB",        /* name */
		"USB Address",   /* pretty_name */
		usb_addr_to_str, /* addr_to_str */
		usb_addr_str_len /* addr_str_len */
    };

    static address_type_t ax25_address = {
		AT_AX25,          /* addr_type */
		"AT_AX25",        /* name */
		"AX.25 Address",  /* pretty_name */
		ax25_addr_to_str, /* addr_to_str */
		ax25_addr_str_len /* addr_str_len */
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
    address_type_register(AT_ATALK, &atalk_address );
    address_type_register(AT_VINES, &vines_address );
    address_type_register(AT_ARCNET, &arcnet_address );
    address_type_register(AT_FC, &fc_address );
    address_type_register(AT_FCWWN, &fcwwn_address );
    address_type_register(AT_SS7PC, &ss7pc_address );
    address_type_register(AT_STRINGZ, &stringz_address );
    address_type_register(AT_EUI64, &eui64_address );
    address_type_register(AT_URI, &uri_address );
    address_type_register(AT_IB, &ib_address );
    address_type_register(AT_USB, &usb_address );
    address_type_register(AT_AX25, &ax25_address );
}

/* Given an address type id, return an address_type_t* */
#define ADDR_TYPE_LOOKUP(addr_type, result)	\
	/* Check input */		\
	g_assert(addr_type < MAX_ADDR_TYPE_VALUE);	\
	result = type_list[addr_type];

/* XXX - Temporary?  Here at least until all of the address type handling is finalized */
int address_type_get_length(const address* addr)
{
	address_type_t	*at;

    ADDR_TYPE_LOOKUP(addr->type, at);

    if ((at == NULL) || (at->addr_str_len == NULL))
        return 0;

	return at->addr_str_len(addr);
}

void address_type_to_string(const address* addr, gchar *buf, int buf_len)
{
	address_type_t	*at;

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
