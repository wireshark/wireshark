/* address_to_str.c
 * Routines for utilities to convert addresses to strings.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>		/* needed for <netinet/in.h> */
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>	/* needed for <arpa/inet.h> on some platforms */
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>		/* needed to define AF_ values on UNIX */
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>		/* needed to define AF_ values on Windows */
#endif

#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif

#include "to_str.h"
#include "value_string.h"
#include "addr_resolv.h"
#include "pint.h"
#include "atalk-utils.h"
#include "sna-utils.h"
#include "osi-utils.h"
#include <epan/dissectors/packet-mtp3.h>
#include <stdio.h>
#include "emem.h"

/* private to_str.c API, don't export to .h! */
char *word_to_hex(char *out, guint16 word);
char *dword_to_hex_punct(char *out, guint32 dword, char punct);
char *dword_to_hex(char *out, guint32 dword);
char *bytes_to_hexstr(char *out, const guint8 *ad, guint32 len);
char *bytes_to_hexstr_punct(char *out, const guint8 *ad, guint32 len, char punct);

/*
 * If a user _does_ pass in a too-small buffer, this is probably
 * going to be too long to fit.  However, even a partial string
 * starting with "[Buf" should provide enough of a clue to be
 * useful.
 */
#define BUF_TOO_SMALL_ERR "[Buffer too small]"

/* Wrapper for the most common case of asking
 * for a string using a colon as the hex-digit separator.
 */
/* XXX FIXME
remove this one later when every call has been converted to ep_address_to_str()
*/
gchar *
ether_to_str(const guint8 *ad)
{
	return bytestring_to_str(ad, 6, ':');
}

gchar *
tvb_ether_to_str(tvbuff_t *tvb, const gint offset)
{
	return bytestring_to_str(tvb_get_ptr(tvb, offset, 6), 6, ':');
}

/*
 This function is very fast and this function is called a lot.
 XXX update the ep_address_to_str stuff to use this function.
*/
const gchar *
ip_to_str(const guint8 *ad) {
  gchar *buf;

  buf=ep_alloc(MAX_IP_STR_LEN);
  ip_to_str_buf(ad, buf, MAX_IP_STR_LEN);
  return buf;
}

#define IPV4_LENGTH 4
const gchar *
tvb_ip_to_str(tvbuff_t *tvb, const gint offset)
{
  gchar *buf;

  buf=ep_alloc(MAX_IP_STR_LEN);
  ip_to_str_buf(tvb_get_ptr(tvb, offset, IPV4_LENGTH), buf, MAX_IP_STR_LEN);
  return buf;
}

/* XXX FIXME
remove this one later when every call has been converted to ep_address_to_str()
*/
gchar *
ip6_to_str(const struct e_in6_addr *ad) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
  gchar *str;

  str=ep_alloc(INET6_ADDRSTRLEN+1);

  ip6_to_str_buf(ad, str);
  return str;
}

#define IPV6_LENGTH 16
gchar *
tvb_ip6_to_str(tvbuff_t *tvb, const gint offset)
{
  gchar *buf;

  buf=ep_alloc(INET6_ADDRSTRLEN+1);
  ip6_to_str_buf((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, IPV6_LENGTH), buf);
  return buf;
}

void
ip6_to_str_buf(const struct e_in6_addr *ad, gchar *buf)
{
  inet_ntop(AF_INET6, (const guchar*)ad, buf, INET6_ADDRSTRLEN);
}

gchar*
ipx_addr_to_str(const guint32 net, const guint8 *ad)
{
	gchar	*buf;
	char	*name;

	name = get_ether_name_if_known(ad);

	if (name) {
		buf = ep_strdup_printf("%s.%s", get_ipxnet_name(net), name);
	}
	else {
		buf = ep_strdup_printf("%s.%s", get_ipxnet_name(net),
		    bytestring_to_str(ad, 6, '\0'));
	}
	return buf;
}

gchar*
ipxnet_to_string(const guint8 *ad)
{
	guint32	addr = pntohl(ad);
	return ipxnet_to_str_punct(addr, ' ');
}

gchar *
ipxnet_to_str_punct(const guint32 ad, const char punct)
{
  gchar *buf = ep_alloc(12);

  *dword_to_hex_punct(buf, ad, punct) = '\0';
  return buf;
}

static void
vines_addr_to_str_buf(const guint8 *addrp, gchar *buf, int buf_len)
{
  if (buf_len < 14) {
     g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);	/* Let the unexpected value alert user */
     return;
  }

  buf    = dword_to_hex(buf, pntohl(&addrp[0]));	/* 8 bytes */
  *buf++ = '.';						/* 1 byte */
  buf    = word_to_hex(buf, pntohs(&addrp[4]));		/* 4 bytes */
  *buf   = '\0';					/* 1 byte */
}

gchar *
tvb_vines_addr_to_str(tvbuff_t *tvb, const gint offset)
{
  gchar	*buf;

  buf=ep_alloc(214); /* XXX, 14 here? */

  vines_addr_to_str_buf(tvb_get_ptr(tvb, offset, VINES_ADDR_LEN), buf, 214);
  return buf;
}

static void
usb_addr_to_str_buf(const guint8 *addrp, gchar *buf, int buf_len)
{
  if(pletohl(&addrp[0])==0xffffffff){
    g_snprintf(buf, buf_len, "host");
  } else {
    g_snprintf(buf, buf_len, "%d.%d", pletohl(&addrp[0]), pletohl(&addrp[4]));
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
	if (addr->len >= 16) {	/* GID is 128bits */
		#define PREAMBLE_STR_LEN		(sizeof("GID: ") - 1)
		g_snprintf(buf,buf_len,"GID: ");
		if (buf_len < (int)PREAMBLE_STR_LEN ||
				inet_ntop(AF_INET6, addr->data, buf + PREAMBLE_STR_LEN, 
						  buf_len - PREAMBLE_STR_LEN) == NULL ) /* Returns NULL if no space and does not touch buf */
			g_snprintf ( buf, buf_len, BUF_TOO_SMALL_ERR ); /* Let the unexpected value alert user */
	} else {	/* this is a LID (16 bits) */
		guint16 lid_number = *((guint16*) addr->data);
		g_snprintf(buf,buf_len,"LID: %u",lid_number);
	}
}

/* XXX FIXME
remove this one later when every call has been converted to ep_address_to_str()
*/
gchar *
fc_to_str(const guint8 *ad)
{
    return bytestring_to_str (ad, 3, '.');
}

gchar *
tvb_fc_to_str(tvbuff_t *tvb, const gint offset)
{
    return bytestring_to_str (tvb_get_ptr(tvb, offset, 3), 3, '.');
}

/* FC Network Header Network Address Authority Identifiers */

#define FC_NH_NAA_IEEE		1	/* IEEE 802.1a */
#define FC_NH_NAA_IEEE_E	2	/* IEEE Exteneded */
#define FC_NH_NAA_LOCAL		3
#define FC_NH_NAA_IP		4	/* 32-bit IP address */
#define FC_NH_NAA_IEEE_R	5	/* IEEE Registered */
#define FC_NH_NAA_IEEE_R_E	6	/* IEEE Registered Exteneded */
/* according to FC-PH 3 draft these are now reclaimed and reserved */
#define FC_NH_NAA_CCITT_INDV	12	/* CCITT 60 bit individual address */
#define FC_NH_NAA_CCITT_GRP	14	/* CCITT 60 bit group address */

gchar *
fcwwn_to_str (const guint8 *ad)
{
    int fmt;
    guint8 oui[6];
    gchar *ethstr;
    gchar *ethptr;

    if (ad == NULL) return NULL;

    ethstr=ep_alloc(512);
    ethptr = bytes_to_hexstr_punct(ethstr, ad, 8, ':');	/* 23 bytes */

    fmt = (ad[0] & 0xF0) >> 4;

    switch (fmt) {

    case FC_NH_NAA_IEEE:
    case FC_NH_NAA_IEEE_E:
        memcpy (oui, &ad[2], 6);

        g_snprintf (ethptr, 512-23, " (%s)", get_manuf_name (oui));
        break;

    case FC_NH_NAA_IEEE_R:
        oui[0] = ((ad[0] & 0x0F) << 4) | ((ad[1] & 0xF0) >> 4);
        oui[1] = ((ad[1] & 0x0F) << 4) | ((ad[2] & 0xF0) >> 4);
        oui[2] = ((ad[2] & 0x0F) << 4) | ((ad[3] & 0xF0) >> 4);
        oui[3] = ((ad[3] & 0x0F) << 4) | ((ad[4] & 0xF0) >> 4);
        oui[4] = ((ad[4] & 0x0F) << 4) | ((ad[5] & 0xF0) >> 4);
        oui[5] = ((ad[5] & 0x0F) << 4) | ((ad[6] & 0xF0) >> 4);

        g_snprintf (ethptr, 512-23, " (%s)", get_manuf_name (oui));
        break;

    default:
        *ethptr = '\0';
        break;
    }
    return (ethstr);
}

gchar *
tvb_fcwwn_to_str(tvbuff_t *tvb, const gint offset)
{
	return fcwwn_to_str (tvb_get_ptr(tvb, offset, 8));
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
ep_address_to_str(const address *addr)
{
  gchar *str;

  str=ep_alloc(MAX_ADDR_STR_LEN);
  address_to_str_buf(addr, str, MAX_ADDR_STR_LEN);
  return str;
}

/* The called routines use se_alloc'ed memory */
gchar*
se_address_to_str(const address *addr)
{
  gchar *str;

  str=se_alloc(MAX_ADDR_STR_LEN);
  address_to_str_buf(addr, str, MAX_ADDR_STR_LEN);
  return str;
}

void
address_to_str_buf(const address *addr, gchar *buf, int buf_len)
{
  const guint8 *addrdata;
  struct atalk_ddp_addr ddp_addr;

  char temp[32];
  char *tempptr = temp;

  if (!buf || !buf_len)
    return;

  switch(addr->type){
  case AT_NONE:
    buf[0] = '\0';
    break;
  case AT_ETHER:					/* 18 bytes */
    tempptr = bytes_to_hexstr_punct(tempptr, addr->data, 6, ':');	/* 17 bytes */
    break;
  case AT_IPv4:
    ip_to_str_buf(addr->data, buf, buf_len);
    break;
  case AT_IPv6:
    if ( inet_ntop(AF_INET6, addr->data, buf, buf_len) == NULL ) /* Returns NULL if no space and does not touch buf */
    	g_snprintf ( buf, buf_len, BUF_TOO_SMALL_ERR );                 /* Let the unexpected value alert user */
    break;
  case AT_IPX:						/* 22 bytes */
    addrdata = addr->data;
    tempptr = bytes_to_hexstr(tempptr, &addrdata[0], 4);		/*  8 bytes */
    *tempptr++ = '.';							/*  1 byte  */
    tempptr = bytes_to_hexstr(tempptr, &addrdata[4], 6);		/* 12 bytes */
    break;
  case AT_SNA:
    sna_fid_to_str_buf(addr, buf, buf_len);
    break;
  case AT_ATALK:
    memcpy(&ddp_addr, addr->data, sizeof ddp_addr);
    atalk_addr_to_str_buf(&ddp_addr, buf, buf_len);
    break;
  case AT_VINES:
    vines_addr_to_str_buf(addr->data, buf, buf_len);
    break;
  case AT_USB:
    usb_addr_to_str_buf(addr->data, buf, buf_len);
    break;
  case AT_OSI:
    print_nsap_net_buf(addr->data, addr->len, buf, buf_len);
    break;
  case AT_ARCNET:					/* 5 bytes */
    tempptr = g_stpcpy(tempptr, "0x");					/* 2 bytes */
    tempptr = bytes_to_hexstr(tempptr, addr->data, 1);			/* 2 bytes */
    break;
  case AT_FC:						/* 9 bytes */
    tempptr = bytes_to_hexstr_punct(tempptr, addr->data, 3, '.');	/* 8 bytes */
    break;
  case AT_SS7PC:
    mtp3_addr_to_str_buf((const mtp3_addr_pc_t *)addr->data, buf, buf_len);
    break;
  case AT_STRINGZ:
    g_strlcpy(buf, addr->data, buf_len);
    break;
  case AT_EUI64:					/* 24 bytes */
    tempptr = bytes_to_hexstr_punct(tempptr, addr->data, 8, ':');	/* 23 bytes */
    break;
  case AT_URI: {
    int copy_len = addr->len < (buf_len - 1) ? addr->len : (buf_len - 1);
    memcpy(buf, addr->data, copy_len );
    buf[copy_len] = '\0';
    }
    break;
  case AT_TIPC:
    tipc_addr_to_str_buf(addr->data, buf, buf_len);
    break;
  case AT_IB:
    ib_addr_to_str_buf(addr, buf, buf_len);
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

