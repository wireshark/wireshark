/* to_str.c
 * Routines for utilities to convert various other types to strings.
 *
 * $Id: to_str.c,v 1.41 2003/12/08 23:40:13 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
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
#include "resolv.h"
#include "pint.h"
#include "atalk-utils.h"
#include "sna-utils.h"
#include "osi-utils.h"
#include "packet-mtp3.h"
#include <stdio.h>
#include <time.h>

#define MAX_BYTESTRING_LEN	6

/* Routine to convert a sequence of bytes to a hex string, one byte/two hex
 * digits at at a time, with a specified punctuation character between
 * the bytes.  The sequence of bytes must be no longer than
 * MAX_BYTESTRING_LEN.
 *
 * If punct is '\0', no punctuation is applied (and thus
 * the resulting string is (len-1) bytes shorter)
 */
static gchar *
bytestring_to_str(const guint8 *ad, guint32 len, char punct) {
  static gchar  str[3][MAX_BYTESTRING_LEN*3];
  static gchar *cur;
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
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

  g_assert(len > 0 && len <= MAX_BYTESTRING_LEN);
  len--;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }
  p = &cur[18];
  *--p = '\0';
  i = len;
  for (;;) {
    octet = ad[i];
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
gchar *
ip_to_str(const guint8 *ad) {
  static gchar  str[4][16];
  static int   cur_idx=0;
  gchar *cur;

  cur_idx++;
  if(cur_idx>3){ 
     cur_idx=0;
  }
  cur=&str[cur_idx][0];

  ip_to_str_buf(ad, cur);
  return cur;
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
ip_to_str_buf(const guint8 *ad, gchar *buf)
{
	register gchar const *p;
	register gchar *b=buf;
	register gchar c;

	p=fast_strings[*ad++];
	while((c=*p)){
		*b++=c;
		p++;
	}
	*b++='.';

	p=fast_strings[*ad++];
	while((c=*p)){
		*b++=c;
		p++;
	}
	*b++='.';

	p=fast_strings[*ad++];
	while((c=*p)){
		*b++=c;
		p++;
	}
	*b++='.';

	p=fast_strings[*ad++];
	while((c=*p)){
		*b++=c;
		p++;
	}
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
  static int i=0;
  static gchar *strp, str[4][INET6_ADDRSTRLEN];

  i++;
  if(i>=4){
    i=0;
  }
  strp=str[i];

  inet_ntop(AF_INET6, (const guchar*)ad, (gchar*)strp, INET6_ADDRSTRLEN);
  return strp;
}

gchar*
ipx_addr_to_str(guint32 net, const guint8 *ad)
{
	static gchar	str[3][8+1+MAXNAMELEN+1]; /* 8 digits, 1 period, NAME, 1 null */
	static gchar	*cur;
	char		*name;

	if (cur == &str[0][0]) {
		cur = &str[1][0];
	} else if (cur == &str[1][0]) {
		cur = &str[2][0];
	} else {
		cur = &str[0][0];
	}

	name = get_ether_name_if_known(ad);

	if (name) {
		sprintf(cur, "%s.%s", get_ipxnet_name(net), name);
	}
	else {
		sprintf(cur, "%s.%s", get_ipxnet_name(net),
		    bytestring_to_str(ad, 6, '\0'));
	}
	return cur;
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
  static gchar  str[3][12];
  static gchar *cur;
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

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }
  p = &cur[12];
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
  static gchar	str[3][214];
  static gchar	*cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }
  vines_addr_to_str_buf(addrp, cur);
  return cur;
}

void
vines_addr_to_str_buf(const guint8 *addrp, gchar *buf)
{
  sprintf(buf, "%08x.%04x", pntohl(&addrp[0]), pntohs(&addrp[4]));
}

#define	PLURALIZE(n)	(((n) > 1) ? "s" : "")
#define	COMMA(do_it)	((do_it) ? ", " : "")

/*
 * Maximum length of a string showing days/hours/minutes/seconds.
 * (Does not include the terminating '\0'.)
 */
#define TIME_SECS_LEN	(8+1+4+2+2+5+2+2+7+2+2+7)

/*
 * Convert a value in seconds and fractions of a second to a string,
 * giving time in days, hours, minutes, and seconds, and put the result
 * into a buffer.
 * "is_nsecs" says that "frac" is microseconds if true and milliseconds
 * if false.
 */
static void
time_secs_to_str_buf(guint32 time, guint32 frac, gboolean is_nsecs,
			   gchar *buf)
{
  static gchar *p;
  int hours, mins, secs;
  int do_comma;

  secs = time % 60;
  time /= 60;
  mins = time % 60;
  time /= 60;
  hours = time % 24;
  time /= 24;

  p = buf;
  if (time != 0) {
    sprintf(p, "%u day%s", time, PLURALIZE(time));
    p += strlen(p);
    do_comma = 1;
  } else
    do_comma = 0;
  if (hours != 0) {
    sprintf(p, "%s%u hour%s", COMMA(do_comma), hours, PLURALIZE(hours));
    p += strlen(p);
    do_comma = 1;
  } else
    do_comma = 0;
  if (mins != 0) {
    sprintf(p, "%s%u minute%s", COMMA(do_comma), mins, PLURALIZE(mins));
    p += strlen(p);
    do_comma = 1;
  } else
    do_comma = 0;
  if (secs != 0 || frac != 0) {
    if (frac != 0) {
      if (is_nsecs)
        sprintf(p, "%s%u.%09u seconds", COMMA(do_comma), secs, frac);
      else
        sprintf(p, "%s%u.%03u seconds", COMMA(do_comma), secs, frac);
    } else
      sprintf(p, "%s%u second%s", COMMA(do_comma), secs, PLURALIZE(secs));
  }
}

gchar *
time_secs_to_str(guint32 time)
{
  static gchar  str[3][TIME_SECS_LEN+1];
  static gchar *cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }

  if (time == 0) {
    sprintf(cur, "0 time");
    return cur;
  }

  time_secs_to_str_buf(time, 0, FALSE, cur);
  return cur;
}

gchar *
time_msecs_to_str(guint32 time)
{
  static gchar  str[3][TIME_SECS_LEN+1+3+1];
  static gchar *cur;
  int msecs;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }

  if (time == 0) {
    sprintf(cur, "0 time");
    return cur;
  }

  msecs = time % 1000;
  time /= 1000;

  time_secs_to_str_buf(time, msecs, FALSE, cur);
  return cur;
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
        static gchar *cur;
        static char str[3][3+1+2+2+4+1+2+1+2+1+2+1+9+1];

        if (cur == &str[0][0]) {
                cur = &str[1][0];
        } else if (cur == &str[1][0]) {
                cur = &str[2][0];
        } else {
                cur = &str[0][0];
        }

        tmp = localtime(&abs_time->secs);
        if (tmp) {
		sprintf(cur, "%s %2d, %d %02d:%02d:%02d.%09ld",
		    mon_names[tmp->tm_mon],
		    tmp->tm_mday,
		    tmp->tm_year + 1900,
		    tmp->tm_hour,
		    tmp->tm_min,
		    tmp->tm_sec,
		    (long)abs_time->nsecs);
        } else
		strncpy(cur, "Not representable", sizeof(str[0]));
        return cur;
}

gchar *
abs_time_secs_to_str(time_t abs_time)
{
        struct tm *tmp;
        static gchar *cur;
        static char str[3][3+1+2+2+4+1+2+1+2+1+2+1];

        if (cur == &str[0][0]) {
                cur = &str[1][0];
        } else if (cur == &str[1][0]) {
                cur = &str[2][0];
        } else {
                cur = &str[0][0];
        }

        tmp = localtime(&abs_time);
        if (tmp) {
		sprintf(cur, "%s %2d, %d %02d:%02d:%02d",
		    mon_names[tmp->tm_mon],
		    tmp->tm_mday,
		    tmp->tm_year + 1900,
		    tmp->tm_hour,
		    tmp->tm_min,
		    tmp->tm_sec);
        } else
		strncpy(cur, "Not representable", sizeof(str[0]));
        return cur;
}

void
display_signed_time(gchar *buf, int buflen, gint32 sec, gint32 frac,
    time_res_t units)
{
	char *sign;

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

	case MSECS:
		snprintf(buf, buflen, "%s%d.%03d", sign, sec, frac);
		break;

	case USECS:
		snprintf(buf, buflen, "%s%d.%06d", sign, sec, frac);
		break;

	case NSECS:
		snprintf(buf, buflen, "%s%d.%09d", sign, sec, frac);
		break;
	}
}

/*
 * Display a relative time as days/hours/minutes/seconds.
 */
gchar *
rel_time_to_str(nstime_t *rel_time)
{
	static gchar *cur;
	static char str[3][1+TIME_SECS_LEN+1+6+1];
	char *p;
	char *sign;
	guint32 time;
	gint32 nsec;

	if (cur == &str[0][0]) {
		cur = &str[1][0];
	} else if (cur == &str[1][0]) {
		cur = &str[2][0];
	} else {
		cur = &str[0][0];
	}
	p = cur;

	/* If the nanoseconds part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	sign = "";
	time = rel_time->secs;
	nsec = rel_time->nsecs;
	if (time == 0 && nsec == 0) {
		sprintf(cur, "0.000000000 seconds");
		return cur;
	}
	if (nsec < 0) {
		nsec = -nsec;
		*p++ = '-';

		/*
		 * We assume here that "rel_time->secs" is negative
		 * or zero; if it's not, the time stamp is bogus,
		 * with a positive seconds and negative microseconds.
		 */
		time = -rel_time->secs;
	}

	time_secs_to_str_buf(time, nsec, TRUE, p);
	return cur;
}

#define REL_TIME_SECS_LEN	(1+10+1+9+1)

/*
 * Display a relative time as seconds.
 */
gchar *
rel_time_to_secs_str(nstime_t *rel_time)
{
        static gchar *cur;
        static char str[3][REL_TIME_SECS_LEN];

        if (cur == &str[0][0]) {
                cur = &str[1][0];
        } else if (cur == &str[1][0]) {
                cur = &str[2][0];
        } else {
                cur = &str[0][0];
        }

        display_signed_time(cur, REL_TIME_SECS_LEN, rel_time->secs,
            rel_time->nsecs, NSECS);
        return cur;
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
    static gchar ethstr[512];
    
    if (ad == NULL) return NULL;
    
    fmt = (ad[0] & 0xF0) >> 4;

    switch (fmt) {

    case FC_NH_NAA_IEEE:
    case FC_NH_NAA_IEEE_E:
        memcpy (oui, &ad[2], 6);
        sprintf (ethstr, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x (%s)", ad[0], 
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

        sprintf (ethstr, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x (%s)", ad[0],
                 ad[1], ad[2], ad[3], ad[4], ad[5], ad[6], ad[7],
                 get_manuf_name (oui));
        break;

    default:
        sprintf (ethstr, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", ad[0],
                 ad[1], ad[2], ad[3], ad[4], ad[5], ad[6], ad[7]);
        break;
    }
    return (ethstr);
}

/* Generate, into "buf", a string showing the bits of a bitfield.
   Return a pointer to the character after that string. */
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
  static char buf[1025];
  char *p;

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
  static char buf[1025];
  char *p;
  int shift = 0;

  /* Compute the number of bits we have to shift the bitfield right
     to extract its value. */
  while ((mask & (1<<shift)) == 0)
    shift++;

  p = decode_bitfield_value(buf, val, mask, width);
  sprintf(p, fmt, (val & mask) >> shift);
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
address_to_str(address *addr)
{
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
  static int i=0;
  static gchar *strp, str[16][INET6_ADDRSTRLEN];/* IPv6 is the largest one */

  i++;
  if(i>=16){
    i=0;
  }
  strp=str[i];

  address_to_str_buf(addr, strp);
  return strp;
}

void
address_to_str_buf(address *addr, gchar *buf)
{
  struct atalk_ddp_addr ddp_addr;

  switch(addr->type){
  case AT_ETHER:
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", addr->data[0], addr->data[1], addr->data[2], addr->data[3], addr->data[4], addr->data[5]);
    break;
  case AT_IPv4:
    ip_to_str_buf(addr->data, buf);
    break;
  case AT_IPv6:
    inet_ntop(AF_INET6, addr->data, buf, INET6_ADDRSTRLEN);
    break;
  case AT_IPX:
    sprintf(buf, "%02x%02x%02x%02x.%02x%02x%02x%02x%02x%02x", addr->data[0], addr->data[1], addr->data[2], addr->data[3], addr->data[4], addr->data[5], addr->data[6], addr->data[7], addr->data[8], addr->data[9]);
    break;
  case AT_SNA:
    sna_fid_to_str_buf(addr, buf);
    break;
  case AT_ATALK:
    memcpy(&ddp_addr, addr->data, sizeof ddp_addr);
    atalk_addr_to_str_buf(&ddp_addr, buf);
    break;
  case AT_VINES:
    vines_addr_to_str_buf(addr->data, buf);
    break;
  case AT_OSI:
    print_nsap_net_buf(addr->data, addr->len, buf);
    break;
  case AT_ARCNET:
    sprintf(buf, "0x%02X", addr->data[0]);
    break;
  case AT_FC:
    sprintf(buf, "%02x.%02x.%02x", addr->data[0], addr->data[1], addr->data[2]);
    break;
  case AT_SS7PC:
    mtp3_addr_to_str_buf(addr->data, buf);
    break;
  default:
    g_assert_not_reached();
  }
}
