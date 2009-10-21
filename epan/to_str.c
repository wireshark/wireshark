/* to_str.c
 * Routines for utilities to convert various other types to strings.
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
# include "inet_v6defs.h"
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
#include <time.h>
#include "emem.h"

/*
 * If a user _does_ pass in a too-small buffer, this is probably
 * going to be too long to fit.  However, even a partial string
 * starting with "[Buf" should provide enough of a clue to be
 * useful.
 */
#define BUF_TOO_SMALL_ERR "[Buffer too small]"

/* Routine to convert a sequence of bytes to a hex string, one byte/two hex
 * digits at at a time, with a specified punctuation character between
 * the bytes.
 *
 * If punct is '\0', no punctuation is applied (and thus
 * the resulting string is (len-1) bytes shorter)
 */
gchar *
bytestring_to_str(const guint8 *ad, guint32 len, char punct) {
  gchar *buf;
  gchar        *p;
  int          i = (int) len - 1;
  guint32      octet;
  size_t       buflen;
  /* At least one version of Apple's C compiler/linker is buggy, causing
     a complaint from the linker about the "literal C string section"
     not ending with '\0' if we initialize a 16-element "char" array with
     a 16-character string, the fact that initializing such an array with
     such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
     '\0' byte in the string nonwithstanding. */
  static const gchar hex_digits[16] =
      { '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

  if (punct)
    buflen=len*3;
  else
    buflen=len*2 + 1;

  if (buflen < 3 || i < 0) {
    return "";
  }

  buf=ep_alloc(buflen);
  p = &buf[buflen - 1];
  *p = '\0';
  for (;;) {
    octet = ad[i];
    *--p = hex_digits[octet&0xF];
    octet >>= 4;
    *--p = hex_digits[octet&0xF];
    if (i <= 0)
      break;
    if (punct)
      *--p = punct;
    i--;
  }
  return p;
}

/* Wrapper for the most common case of asking
 * for a string using a colon as the hex-digit separator.
 */
/* XXX FIXME
remove this one later when every call has been converted to address_to_str()
*/
gchar *
ether_to_str(const guint8 *ad)
{
	return bytestring_to_str(ad, 6, ':');
}

/*
 This function is very fast and this function is called a lot.
 XXX update the address_to_str stuff to use this function.
*/
const gchar *
ip_to_str(const guint8 *ad) {
  gchar *buf;

  buf=ep_alloc(MAX_IP_STR_LEN);
  ip_to_str_buf(ad, buf, MAX_IP_STR_LEN);
  return buf;
}

/*
 This function is very fast and this function is called a lot.
 XXX update the address_to_str stuff to use this function.
*/
static const char * const fast_strings[] = {
"0", "1", "2", "3", "4", "5", "6", "7",
"8", "9", "10", "11", "12", "13", "14", "15",
"16", "17", "18", "19", "20", "21", "22", "23",
"24", "25", "26", "27", "28", "29", "30", "31",
"32", "33", "34", "35", "36", "37", "38", "39",
"40", "41", "42", "43", "44", "45", "46", "47",
"48", "49", "50", "51", "52", "53", "54", "55",
"56", "57", "58", "59", "60", "61", "62", "63",
"64", "65", "66", "67", "68", "69", "70", "71",
"72", "73", "74", "75", "76", "77", "78", "79",
"80", "81", "82", "83", "84", "85", "86", "87",
"88", "89", "90", "91", "92", "93", "94", "95",
"96", "97", "98", "99", "100", "101", "102", "103",
"104", "105", "106", "107", "108", "109", "110", "111",
"112", "113", "114", "115", "116", "117", "118", "119",
"120", "121", "122", "123", "124", "125", "126", "127",
"128", "129", "130", "131", "132", "133", "134", "135",
"136", "137", "138", "139", "140", "141", "142", "143",
"144", "145", "146", "147", "148", "149", "150", "151",
"152", "153", "154", "155", "156", "157", "158", "159",
"160", "161", "162", "163", "164", "165", "166", "167",
"168", "169", "170", "171", "172", "173", "174", "175",
"176", "177", "178", "179", "180", "181", "182", "183",
"184", "185", "186", "187", "188", "189", "190", "191",
"192", "193", "194", "195", "196", "197", "198", "199",
"200", "201", "202", "203", "204", "205", "206", "207",
"208", "209", "210", "211", "212", "213", "214", "215",
"216", "217", "218", "219", "220", "221", "222", "223",
"224", "225", "226", "227", "228", "229", "230", "231",
"232", "233", "234", "235", "236", "237", "238", "239",
"240", "241", "242", "243", "244", "245", "246", "247",
"248", "249", "250", "251", "252", "253", "254", "255"
};
void
ip_to_str_buf(const guint8 *ad, gchar *buf, int buf_len)
{
	register gchar const *p;
	register gchar *b=buf;

	if (buf_len < MAX_IP_STR_LEN) {
		g_snprintf ( buf, buf_len, BUF_TOO_SMALL_ERR );                 /* Let the unexpected value alert user */
		return;
	}

	p=fast_strings[*ad++];
	do {
		*b++=*p;
		p++;
	} while(*p);
	*b++='.';

	p=fast_strings[*ad++];
	do {
		*b++=*p;
		p++;
	} while(*p);
	*b++='.';

	p=fast_strings[*ad++];
	do {
		*b++=*p;
		p++;
	} while(*p);
	*b++='.';

	p=fast_strings[*ad];
	do {
		*b++=*p;
		p++;
	} while(*p);
	*b=0;
}


/* XXX FIXME
remove this one later when every call has been converted to address_to_str()
*/
gchar *
ip6_to_str(const struct e_in6_addr *ad) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
  static gchar *str;

  str=ep_alloc(INET6_ADDRSTRLEN+1);

  ip6_to_str_buf(ad, str);
  return str;
}

void
ip6_to_str_buf(const struct e_in6_addr *ad, gchar *buf)
{
  inet_ntop(AF_INET6, (const guchar*)ad, buf, INET6_ADDRSTRLEN);
}

gchar*
ipx_addr_to_str(guint32 net, const guint8 *ad)
{
	gchar	*buf;
	char	*name;

	buf=ep_alloc(8+1+MAXNAMELEN+1); /* 8 digits, 1 period, NAME, 1 null */
	name = get_ether_name_if_known(ad);

	if (name) {
		g_snprintf(buf, 8+1+MAXNAMELEN+1, "%s.%s", get_ipxnet_name(net), name);
	}
	else {
		g_snprintf(buf, 8+1+MAXNAMELEN+1, "%s.%s", get_ipxnet_name(net),
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
ipxnet_to_str_punct(const guint32 ad, char punct)
{
  gchar        *buf;
  gchar        *p;
  int          i;
  guint32      octet;
  /* At least one version of Apple's C compiler/linker is buggy, causing
     a complaint from the linker about the "literal C string section"
     not ending with '\0' if we initialize a 16-element "char" array with
     a 16-character string, the fact that initializing such an array with
     such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
     '\0' byte in the string nonwithstanding. */
  static const gchar hex_digits[16] =
      { '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
  static const guint32  octet_mask[4] =
	  { 0xff000000 , 0x00ff0000, 0x0000ff00, 0x000000ff };

  buf=ep_alloc(12);
  p = &buf[12];
  *--p = '\0';
  i = 3;
  for (;;) {
    octet = (ad & octet_mask[i]) >> ((3 - i) * 8);
    *--p = hex_digits[octet&0xF];
    octet >>= 4;
    *--p = hex_digits[octet&0xF];
    if (i == 0)
      break;
    if (punct)
      *--p = punct;
    i--;
  }
  return p;
}

gchar *
vines_addr_to_str(const guint8 *addrp)
{
  gchar	*buf;

  buf=ep_alloc(214);

  vines_addr_to_str_buf(addrp, buf, 214);
  return buf;
}

void
vines_addr_to_str_buf(const guint8 *addrp, gchar *buf, int buf_len)
{
  g_snprintf(buf, buf_len, "%08x.%04x", pntohl(&addrp[0]), pntohs(&addrp[4]));
}


void
usb_addr_to_str_buf(const guint8 *addrp, gchar *buf, int buf_len)
{
  if(pletohl(&addrp[0])==0xffffffff){
    g_snprintf(buf, buf_len, "host");
  } else {
    g_snprintf(buf, buf_len, "%d.%d", pletohl(&addrp[0]), pletohl(&addrp[4]));
  }
}

#define	PLURALIZE(n)	(((n) > 1) ? "s" : "")
#define	COMMA(do_it)	((do_it) ? ", " : "")

/*
 * Maximum length of a string showing days/hours/minutes/seconds.
 * (Does not include the terminating '\0'.)
 * Includes space for a '-' sign for any negative components.
 * -12345 days, 12 hours, 12 minutes, 12.123 seconds
 */
#define TIME_SECS_LEN	(10+1+4+2+2+5+2+2+7+2+2+7+4)

/*
 * Convert a value in seconds and fractions of a second to a string,
 * giving time in days, hours, minutes, and seconds, and put the result
 * into a buffer.
 * "is_nsecs" says that "frac" is microseconds if true and milliseconds
 * if false.
 * If time is negative, add a '-' to all non-null components.
 */
static void
time_secs_to_str_buf(gint32 time, guint32 frac, gboolean is_nsecs,
			   emem_strbuf_t *buf)
{
  int hours, mins, secs;
  const gchar *msign = "";
  gboolean do_comma = FALSE;

  if(time == G_MININT32) {	/* That Which Shall Not Be Negated */
    ep_strbuf_append_printf(buf, "Unable to cope with time value %d", time);
    return;
  }

  if(time < 0){
    time = -time;
    msign = "-";
  }

  secs = time % 60;
  time /= 60;
  mins = time % 60;
  time /= 60;
  hours = time % 24;
  time /= 24;

  if (time != 0) {
    ep_strbuf_append_printf(buf, "%s%u day%s", msign, time, PLURALIZE(time));
    do_comma = TRUE;
    msign="";
  }
  if (hours != 0) {
    ep_strbuf_append_printf(buf, "%s%s%u hour%s", COMMA(do_comma), msign, hours, PLURALIZE(hours));
    do_comma = TRUE;
    msign="";
  }
  if (mins != 0) {
    ep_strbuf_append_printf(buf, "%s%s%u minute%s", COMMA(do_comma), msign, mins, PLURALIZE(mins));
    do_comma = TRUE;
    msign="";
  }
  if (secs != 0 || frac != 0) {
    if (frac != 0) {
      if (is_nsecs)
        ep_strbuf_append_printf(buf, "%s%s%u.%09u seconds", COMMA(do_comma), msign, secs, frac);
      else
        ep_strbuf_append_printf(buf, "%s%s%u.%03u seconds", COMMA(do_comma), msign, secs, frac);
    } else
      ep_strbuf_append_printf(buf, "%s%s%u second%s", COMMA(do_comma), msign, secs, PLURALIZE(secs));
  }
}

gchar *
time_secs_to_str(gint32 time)
{
  emem_strbuf_t *buf;

  buf=ep_strbuf_sized_new(TIME_SECS_LEN+1, TIME_SECS_LEN+1);

  if (time == 0) {
    ep_strbuf_append(buf, "0 time");
    return buf->str;
  }

  time_secs_to_str_buf(time, 0, FALSE, buf);
  return buf->str;
}

static void
time_secs_to_str_buf_unsigned(guint32 time, guint32 frac, gboolean is_nsecs,
			 emem_strbuf_t *buf)
{
  int hours, mins, secs;
  const gchar *msign = "";
  gboolean do_comma = FALSE;

  secs = time % 60;
  time /= 60;
  mins = time % 60;
  time /= 60;
  hours = time % 24;
  time /= 24;

  if (time != 0) {
    ep_strbuf_append_printf(buf, "%s%u day%s", msign, time, PLURALIZE(time));
    do_comma = TRUE;
  }
  if (hours != 0) {
    ep_strbuf_append_printf(buf, "%s%s%u hour%s", COMMA(do_comma), msign, hours, PLURALIZE(hours));
    do_comma = TRUE;
  }
  if (mins != 0) {
    ep_strbuf_append_printf(buf, "%s%s%u minute%s", COMMA(do_comma), msign, mins, PLURALIZE(mins));
    do_comma = TRUE;
  }
  if (secs != 0 || frac != 0) {
    if (frac != 0) {
      if (is_nsecs)
        ep_strbuf_append_printf(buf, "%s%s%u.%09u seconds", COMMA(do_comma), msign, secs, frac);
      else
        ep_strbuf_append_printf(buf, "%s%s%u.%03u seconds", COMMA(do_comma), msign, secs, frac);
    } else
      ep_strbuf_append_printf(buf, "%s%s%u second%s", COMMA(do_comma), msign, secs, PLURALIZE(secs));
  }
}

gchar *
time_secs_to_str_unsigned(guint32 time)
{
  emem_strbuf_t *buf;

  buf=ep_strbuf_sized_new(TIME_SECS_LEN+1, TIME_SECS_LEN+1);

  if (time == 0) {
    ep_strbuf_append(buf, "0 time");
    return buf->str;
  }

  time_secs_to_str_buf_unsigned(time, 0, FALSE, buf);
  return buf->str;
}


gchar *
time_msecs_to_str(gint32 time)
{
  emem_strbuf_t *buf;
  int msecs;

  buf=ep_strbuf_sized_new(TIME_SECS_LEN+1+3+1, TIME_SECS_LEN+1+3+1);

  if (time == 0) {
    ep_strbuf_append(buf, "0 time");
    return buf->str;
  }

  if(time<0){
    /* oops we got passed a negative time */
    time= -time;
    msecs = time % 1000;
    time /= 1000;
    time= -time;
  } else {
    msecs = time % 1000;
    time /= 1000;
  }

  time_secs_to_str_buf(time, msecs, FALSE, buf);
  return buf->str;
}

static const char *mon_names[12] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

gchar *
abs_time_to_str(nstime_t *abs_time)
{
        struct tm *tmp;
        gchar *buf;

        buf=ep_alloc(3+1+2+2+4+1+2+1+2+1+2+1+9+1);


#ifdef _MSC_VER
        /* calling localtime() on MSVC 2005 with huge values causes it to crash */
        /* XXX - find the exact value that still does work */
        /* XXX - using _USE_32BIT_TIME_T might be another way to circumvent this problem */
        if(abs_time->secs > 2000000000) {
            tmp = NULL;
        } else
#endif
        tmp = localtime(&abs_time->secs);
        if (tmp) {
		g_snprintf(buf, 3+1+2+2+4+1+2+1+2+1+2+1+9+1,
		    "%s %2d, %d %02d:%02d:%02d.%09ld",
		    mon_names[tmp->tm_mon],
		    tmp->tm_mday,
		    tmp->tm_year + 1900,
		    tmp->tm_hour,
		    tmp->tm_min,
		    tmp->tm_sec,
		    (long)abs_time->nsecs);
        } else
		strncpy(buf, "Not representable", 3+1+2+2+4+1+2+1+2+1+2+1+9+1);
        return buf;
}

gchar *
abs_time_secs_to_str(time_t abs_time)
{
        struct tm *tmp;
        gchar *buf;

	buf=ep_alloc(3+1+2+2+4+1+2+1+2+1+2+1);

        tmp = localtime(&abs_time);
        if (tmp) {
		g_snprintf(buf, 3+1+2+2+4+1+2+1+2+1+2+1,
		    "%s %2d, %d %02d:%02d:%02d",
		    mon_names[tmp->tm_mon],
		    tmp->tm_mday,
		    tmp->tm_year + 1900,
		    tmp->tm_hour,
		    tmp->tm_min,
		    tmp->tm_sec);
        } else
		strncpy(buf, "Not representable", 3+1+2+2+4+1+2+1+2+1+2+1);
        return buf;
}

void
display_signed_time(gchar *buf, int buflen, gint32 sec, gint32 frac,
    time_res_t units)
{
	const char *sign;

	/* If the fractional part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	sign = "";
	if (frac < 0) {
		frac = -frac;
		if (sec >= 0)
			sign = "-";
	}
	switch (units) {

	case SECS:
		g_snprintf(buf, buflen, "%s%d", sign, sec);
		break;

	case DSECS:
		g_snprintf(buf, buflen, "%s%d.%01d", sign, sec, frac);
		break;

	case CSECS:
		g_snprintf(buf, buflen, "%s%d.%02d", sign, sec, frac);
		break;

	case MSECS:
		g_snprintf(buf, buflen, "%s%d.%03d", sign, sec, frac);
		break;

	case USECS:
		g_snprintf(buf, buflen, "%s%d.%06d", sign, sec, frac);
		break;

	case NSECS:
		g_snprintf(buf, buflen, "%s%d.%09d", sign, sec, frac);
		break;
	}
}


void
display_epoch_time(gchar *buf, int buflen, time_t sec, gint32 frac,
    time_res_t units)
{
	const char *sign;
	double elapsed_secs;

	elapsed_secs = difftime(sec,(time_t)0);

	/* This code copied from display_signed_time; keep it in case anyone
	   is looking at captures from before 1970 (???).
	   If the fractional part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	sign = "";
	if (frac < 0) {
		frac = -frac;
		if (elapsed_secs >= 0)
			sign = "-";
	}
	switch (units) {

	case SECS:
		g_snprintf(buf, buflen, "%s%0.0f", sign, elapsed_secs);
		break;

	case DSECS:
		g_snprintf(buf, buflen, "%s%0.0f.%01d", sign, elapsed_secs, frac);
		break;

	case CSECS:
		g_snprintf(buf, buflen, "%s%0.0f.%02d", sign, elapsed_secs, frac);
		break;

	case MSECS:
		g_snprintf(buf, buflen, "%s%0.0f.%03d", sign, elapsed_secs, frac);
		break;

	case USECS:
		g_snprintf(buf, buflen, "%s%0.0f.%06d", sign, elapsed_secs, frac);
		break;

	case NSECS:
		g_snprintf(buf, buflen, "%s%0.0f.%09d", sign, elapsed_secs, frac);
		break;
	}
}

/*
 * Display a relative time as days/hours/minutes/seconds.
 */
gchar *
rel_time_to_str(nstime_t *rel_time)
{
	emem_strbuf_t *buf;
	const char *sign;
	gint32 time;
	gint32 nsec;

	buf=ep_strbuf_sized_new(1+TIME_SECS_LEN+1+6+1, 1+TIME_SECS_LEN+1+6+1);

	/* If the nanoseconds part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	sign = "";
	time = (gint) rel_time->secs;
	nsec = rel_time->nsecs;
	if (time == 0 && nsec == 0) {
		ep_strbuf_append(buf, "0.000000000 seconds");
		return buf->str;
	}
	if (nsec < 0) {
		nsec = -nsec;
		ep_strbuf_append_c(buf, '-');

		/*
		 * We assume here that "rel_time->secs" is negative
		 * or zero; if it's not, the time stamp is bogus,
		 * with a positive seconds and negative microseconds.
		 */
		time = (gint) -rel_time->secs;
	}

	time_secs_to_str_buf(time, nsec, TRUE, buf);
	return buf->str;
}

#define REL_TIME_SECS_LEN	(1+10+1+9+1)

/*
 * Display a relative time as seconds.
 */
gchar *
rel_time_to_secs_str(nstime_t *rel_time)
{
        gchar *buf;

	buf=ep_alloc(REL_TIME_SECS_LEN);

        display_signed_time(buf, REL_TIME_SECS_LEN, (gint32) rel_time->secs,
            rel_time->nsecs, NSECS);
        return buf;
}


/* XXX FIXME
remove this one later when every call has been converted to address_to_str()
*/
gchar *
fc_to_str(const guint8 *ad)
{
    return bytestring_to_str (ad, 3, '.');
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

    if (ad == NULL) return NULL;

    ethstr=ep_alloc(512);

    fmt = (ad[0] & 0xF0) >> 4;

    switch (fmt) {

    case FC_NH_NAA_IEEE:
    case FC_NH_NAA_IEEE_E:
        memcpy (oui, &ad[2], 6);
        g_snprintf (ethstr, 512, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x (%s)", ad[0],
                 ad[1], ad[2], ad[3], ad[4], ad[5], ad[6], ad[7],
                 get_manuf_name (oui));
        break;

    case FC_NH_NAA_IEEE_R:
        oui[0] = ((ad[0] & 0x0F) << 4) | ((ad[1] & 0xF0) >> 4);
        oui[1] = ((ad[1] & 0x0F) << 4) | ((ad[2] & 0xF0) >> 4);
        oui[2] = ((ad[2] & 0x0F) << 4) | ((ad[3] & 0xF0) >> 4);
        oui[3] = ((ad[3] & 0x0F) << 4) | ((ad[4] & 0xF0) >> 4);
        oui[4] = ((ad[4] & 0x0F) << 4) | ((ad[5] & 0xF0) >> 4);
        oui[5] = ((ad[5] & 0x0F) << 4) | ((ad[6] & 0xF0) >> 4);

        g_snprintf (ethstr, 512, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x (%s)", ad[0],
                 ad[1], ad[2], ad[3], ad[4], ad[5], ad[6], ad[7],
                 get_manuf_name (oui));
        break;

    default:
        g_snprintf (ethstr, 512, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", ad[0],
                 ad[1], ad[2], ad[3], ad[4], ad[5], ad[6], ad[7]);
        break;
    }
    return (ethstr);
}
/*
 * Generates a string representing the bits in a bitfield at "bit_offset" from an 8 bit boundary
 * with the length in bits of no_of_bits based on value.
 * Ex: ..xx x...
 */

char *
decode_bits_in_field(gint bit_offset, gint no_of_bits, guint64 value)
{
	guint64 mask = 0,tmp;
	char *str;
	int bit;
	int i;

	mask = 1;
	mask = mask << (no_of_bits-1);

	/* prepare the string */
	str=ep_alloc(256);
	str[0]='\0';
	for(bit=0;bit<((int)(bit_offset&0x07));bit++){
		if(bit&&(!(bit%4))){
			strcat(str, " ");
		}
		strcat(str,".");
	}

	/* read the bits for the int */
	for(i=0;i<no_of_bits;i++){
		if(bit&&(!(bit%4))){
			strcat(str, " ");
		}
		if(bit&&(!(bit%8))){
			strcat(str, " ");
		}
		bit++;
		tmp = value & mask;
		if(tmp != 0){
			strcat(str, "1");
		} else {
			strcat(str, "0");
		}
		mask = mask>>1;
	}

	for(;bit%8;bit++){
		if(bit&&(!(bit%4))){
			strcat(str, " ");
		}
		strcat(str,".");
	}
	return str;
}

/* Generate, into "buf", a string showing the bits of a bitfield.
   Return a pointer to the character after that string. */
/*XXX this needs a buf_len check */
char *
other_decode_bitfield_value(char *buf, guint32 val, guint32 mask, int width)
{
  int i;
  guint32 bit;
  char *p;

  i = 0;
  p = buf;
  bit = 1 << (width - 1);
  for (;;) {
    if (mask & bit) {
      /* This bit is part of the field.  Show its value. */
      if (val & bit)
        *p++ = '1';
      else
        *p++ = '0';
    } else {
      /* This bit is not part of the field. */
      *p++ = '.';
    }
    bit >>= 1;
    i++;
    if (i >= width)
      break;
    if (i % 4 == 0)
      *p++ = ' ';
  }
  *p = '\0';
  return p;
}

char *
decode_bitfield_value(char *buf, guint32 val, guint32 mask, int width)
{
  char *p;

  p = other_decode_bitfield_value(buf, val, mask, width);
  strcpy(p, " = ");
  p += 3;
  return p;
}

/* Generate a string describing a Boolean bitfield (a one-bit field that
   says something is either true of false). */
const char *
decode_boolean_bitfield(guint32 val, guint32 mask, int width,
    const char *truedesc, const char *falsedesc)
{
  char *buf;
  char *p;

  buf=ep_alloc(1025); /* is this a bit overkill? */
  p = decode_bitfield_value(buf, val, mask, width);
  if (val & mask)
    strcpy(p, truedesc);
  else
    strcpy(p, falsedesc);
  return buf;
}

/* Generate a string describing a numeric bitfield (an N-bit field whose
   value is just a number). */
const char *
decode_numeric_bitfield(guint32 val, guint32 mask, int width,
    const char *fmt)
{
  char *buf;
  char *p;
  int shift = 0;

  buf=ep_alloc(1025); /* isnt this a bit overkill? */
  /* Compute the number of bits we have to shift the bitfield right
     to extract its value. */
  while ((mask & (1<<shift)) == 0)
    shift++;

  p = decode_bitfield_value(buf, val, mask, width);
  g_snprintf(p, (gulong) (1025-(p-buf)), fmt, (val & mask) >> shift);
  return buf;
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
address_to_str(const address *addr)
{
  gchar *str;

  str=ep_alloc(MAX_ADDR_STR_LEN);
  address_to_str_buf(addr, str, MAX_ADDR_STR_LEN);
  return str;
}

void
address_to_str_buf(const address *addr, gchar *buf, int buf_len)
{
  const guint8 *addrdata;
  const char *addrstr;
  struct atalk_ddp_addr ddp_addr;

  if (!buf)
    return;

  switch(addr->type){
  case AT_NONE:
    g_snprintf(buf, buf_len, "%s", "");
    break;
  case AT_ETHER:
    addrdata = addr->data;
    g_snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x", addrdata[0], addrdata[1], addrdata[2], addrdata[3], addrdata[4], addrdata[5]);
    break;
  case AT_IPv4:
    ip_to_str_buf(addr->data, buf, buf_len);
    break;
  case AT_IPv6:
    if ( inet_ntop(AF_INET6, addr->data, buf, buf_len) == NULL ) /* Returns NULL if no space and does not touch buf */
    	g_snprintf ( buf, buf_len, BUF_TOO_SMALL_ERR );                 /* Let the unexpected value alert user */
    break;
  case AT_IPX:
    addrdata = addr->data;
    g_snprintf(buf, buf_len, "%02x%02x%02x%02x.%02x%02x%02x%02x%02x%02x", addrdata[0], addrdata[1], addrdata[2], addrdata[3], addrdata[4], addrdata[5], addrdata[6], addrdata[7], addrdata[8], addrdata[9]);
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
  case AT_ARCNET:
    addrdata = addr->data;
    g_snprintf(buf, buf_len, "0x%02X", addrdata[0]);
    break;
  case AT_FC:
    addrdata = addr->data;
    g_snprintf(buf, buf_len, "%02x.%02x.%02x", addrdata[0], addrdata[1], addrdata[2]);
    break;
  case AT_SS7PC:
    mtp3_addr_to_str_buf((const mtp3_addr_pc_t *)addr->data, buf, buf_len);
    break;
  case AT_STRINGZ:
    addrstr = addr->data;
    g_snprintf(buf, buf_len, "%s", addrstr);
    break;
  case AT_EUI64:
    addrdata = addr->data;
    g_snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            addrdata[0], addrdata[1], addrdata[2], addrdata[3],
            addrdata[4], addrdata[5], addrdata[6], addrdata[7]);
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
  default:
    g_assert_not_reached();
  }
}

gchar* guid_to_str(const e_guid_t *guid) {
  gchar *buf;

  buf=ep_alloc(GUID_STR_LEN);
  return guid_to_str_buf(guid, buf, GUID_STR_LEN);
}

gchar* guid_to_str_buf(const e_guid_t *guid, gchar *buf, int buf_len) {
  g_snprintf(buf, buf_len, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
          guid->data1, guid->data2, guid->data3,
          guid->data4[0], guid->data4[1], guid->data4[2], guid->data4[3], guid->data4[4], guid->data4[5], guid->data4[6], guid->data4[7]);
  return buf;
}

void
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

