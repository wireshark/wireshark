/* wsutil/to_str.c
 * Routines for utilities to convert various other types to strings.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "to_str.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/wslog.h>
#include <wsutil/inet_addr.h>
#include <wsutil/pint.h>
#include <wsutil/time_util.h>

/*
 * If a user _does_ pass in a too-small buffer, this is probably
 * going to be too long to fit.  However, even a partial string
 * starting with "[Buf" should provide enough of a clue to be
 * useful.
 */
#define _return_if_nospace(str_len, buf, buf_len) \
	do { \
		if ((str_len) > (buf_len)) { \
			(void)g_strlcpy(buf, "[Buffer too small]", buf_len); \
			return; \
		} \
	} while (0)

static const char fast_strings[][4] = {
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

static inline char
low_nibble_of_octet_to_hex(uint8_t oct)
{
	/* At least one version of Apple's C compiler/linker is buggy, causing
	   a complaint from the linker about the "literal C string section"
	   not ending with '\0' if we initialize a 16-element "char" array with
	   a 16-character string, the fact that initializing such an array with
	   such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
	   '\0' byte in the string nonwithstanding. */
	static const char hex_digits[16] =
	{ '0', '1', '2', '3', '4', '5', '6', '7',
	  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	return hex_digits[oct & 0xF];
}

static inline char *
byte_to_hex(char *out, uint32_t dword)
{
	*out++ = low_nibble_of_octet_to_hex(dword >> 4);
	*out++ = low_nibble_of_octet_to_hex(dword);
	return out;
}

char *
guint8_to_hex(char *out, uint8_t val)
{
	return byte_to_hex(out, val);
}

char *
word_to_hex(char *out, uint16_t word)
{
	out = byte_to_hex(out, word >> 8);
	out = byte_to_hex(out, word);
	return out;
}

char *
word_to_hex_punct(char *out, uint16_t word, char punct)
{
	out = byte_to_hex(out, word >> 8);
	*out++ = punct;
	out = byte_to_hex(out, word);
	return out;
}

char *
word_to_hex_npad(char *out, uint16_t word)
{
	if (word >= 0x1000)
		*out++ = low_nibble_of_octet_to_hex((uint8_t)(word >> 12));
	if (word >= 0x0100)
		*out++ = low_nibble_of_octet_to_hex((uint8_t)(word >> 8));
	if (word >= 0x0010)
		*out++ = low_nibble_of_octet_to_hex((uint8_t)(word >> 4));
	*out++ = low_nibble_of_octet_to_hex((uint8_t)(word >> 0));
	return out;
}

char *
dword_to_hex(char *out, uint32_t dword)
{
	out = word_to_hex(out, dword >> 16);
	out = word_to_hex(out, dword);
	return out;
}

char *
dword_to_hex_punct(char *out, uint32_t dword, char punct)
{
	out = word_to_hex_punct(out, dword >> 16, punct);
	*out++ = punct;
	out = word_to_hex_punct(out, dword, punct);
	return out;
}

char *
qword_to_hex(char *out, uint64_t qword)
{
	out = dword_to_hex(out, (uint32_t)(qword >> 32));
	out = dword_to_hex(out, (uint32_t)(qword & 0xffffffff));
	return out;
}

char *
qword_to_hex_punct(char *out, uint64_t qword, char punct)
{
	out = dword_to_hex_punct(out, (uint32_t)(qword >> 32), punct);
	*out++ = punct;
	out = dword_to_hex_punct(out, (uint32_t)(qword & 0xffffffff), punct);
	return out;
}

/*
 * This does *not* null-terminate the string.  It returns a pointer
 * to the position in the string following the last character it
 * puts there, so that the caller can either put the null terminator
 * in or can append more stuff to the buffer.
 *
 * There needs to be at least len * 2 bytes left in the buffer.
 */
char *
bytes_to_hexstr(char *out, const uint8_t *ad, size_t len)
{
	size_t i;

	ws_return_val_if(!ad, NULL);

	for (i = 0; i < len; i++)
		out = byte_to_hex(out, ad[i]);
	return out;
}

/*
 * This does *not* null-terminate the string.  It returns a pointer
 * to the position in the string following the last character it
 * puts there, so that the caller can either put the null terminator
 * in or can append more stuff to the buffer.
 *
 * There needs to be at least len * 3 - 1 bytes left in the buffer.
 */
char *
bytes_to_hexstr_punct(char *out, const uint8_t *ad, size_t len, char punct)
{
	size_t i;

	ws_return_val_if(!ad, NULL);

	out = byte_to_hex(out, ad[0]);
	for (i = 1; i < len; i++) {
		*out++ = punct;
		out = byte_to_hex(out, ad[i]);
	}
	return out;
}

/* Routine to convert a sequence of bytes to a hex string, one byte/two hex
 * digits at a time, with a specified punctuation character between
 * the bytes.
 *
 * If punct is '\0', no punctuation is applied (and thus
 * the resulting string is (len-1) bytes shorter)
 */
char *
bytes_to_str_punct_maxlen(wmem_allocator_t *scope,
			const uint8_t *src, size_t src_size,
			char punct, size_t max_bytes_len)
{
	char *buf;
	size_t max_char_size;
	char *buf_ptr;
	int truncated = 0;

	ws_return_str_if(!src, scope);

	if (!src_size) {
		return wmem_strdup(scope, "");
	}

	if (!punct)
		return bytes_to_str_maxlen(scope, src, src_size, max_bytes_len);

	if (max_bytes_len == 0 || max_bytes_len > src_size) {
		max_bytes_len = src_size;
	}
	else if (max_bytes_len < src_size) {
		truncated = 1;
	}

	/* Include space for ellipsis and '\0'. Optional extra punct
	 * at the end is already accounted for. */
	max_char_size = max_bytes_len * 3 + strlen(UTF8_HORIZONTAL_ELLIPSIS) + 1;

	buf = wmem_alloc(scope, max_char_size);
	buf_ptr = bytes_to_hexstr_punct(buf, src, max_bytes_len, punct);

	if (truncated) {
		*buf_ptr++ = punct;
		buf_ptr = g_stpcpy(buf_ptr, UTF8_HORIZONTAL_ELLIPSIS);
	}

	*buf_ptr = '\0';
	return buf;
}

char *
bytes_to_str_maxlen(wmem_allocator_t *scope,
			const uint8_t *src, size_t src_size,
			size_t max_bytes_len)
{
	char *buf;
	size_t max_char_size;
	char *buf_ptr;
	int truncated = 0;

	ws_return_str_if(!src, scope);

	if (!src_size) {
		return wmem_strdup(scope, "");
	}

	if (max_bytes_len == 0 || max_bytes_len > src_size) {
		max_bytes_len = src_size;
	}
	else if (max_bytes_len < src_size) {
		truncated = 1;
	}

	max_char_size = max_bytes_len * 2 + strlen(UTF8_HORIZONTAL_ELLIPSIS) + 1;

	buf = wmem_alloc(scope, max_char_size);
	buf_ptr = bytes_to_hexstr(buf, src, max_bytes_len);

	if (truncated)
		buf_ptr = g_stpcpy(buf_ptr, UTF8_HORIZONTAL_ELLIPSIS);

	*buf_ptr = '\0';
	return buf;
}

/*
 * The *_to_str_back() functions measured approx. a x7.5 speed-up versus
 * snprintf() on my Linux system with GNU libc.
 */

char *
oct_to_str_back(char *ptr, uint32_t value)
{
	while (value) {
		*(--ptr) = '0' + (value & 0x7);
		value >>= 3;
	}

	*(--ptr) = '0';
	return ptr;
}

char *
oct64_to_str_back(char *ptr, uint64_t value)
{
	while (value) {
		*(--ptr) = '0' + (value & 0x7);
		value >>= 3;
	}

	*(--ptr) = '0';
	return ptr;
}

char *
hex_to_str_back_len(char *ptr, uint32_t value, int len)
{
	do {
		*(--ptr) = low_nibble_of_octet_to_hex(value);
		value >>= 4;
		len--;
	} while (value);

	/* pad */
	while (len > 0) {
		*(--ptr) = '0';
		len--;
	}

	*(--ptr) = 'x';
	*(--ptr) = '0';

	return ptr;
}

char *
hex64_to_str_back_len(char *ptr, uint64_t value, int len)
{
	do {
		*(--ptr) = low_nibble_of_octet_to_hex(value & 0xF);
		value >>= 4;
		len--;
	} while (value);

	/* pad */
	while (len > 0) {
		*(--ptr) = '0';
		len--;
	}

	*(--ptr) = 'x';
	*(--ptr) = '0';

	return ptr;
}

char *
uint_to_str_back(char *ptr, uint32_t value)
{
	char const *p;

	/* special case */
	if (value == 0)
		*(--ptr) = '0';

	while (value >= 10) {
		p = fast_strings[100 + (value % 100)];

		value /= 100;

		*(--ptr) = p[2];
		*(--ptr) = p[1];
	}

	if (value)
		*(--ptr) = (value) | '0';

	return ptr;
}

char *
uint64_to_str_back(char *ptr, uint64_t value)
{
	char const *p;

	/* special case */
	if (value == 0)
		*(--ptr) = '0';

	while (value >= 10) {
		p = fast_strings[100 + (value % 100)];

		value /= 100;

		*(--ptr) = p[2];
		*(--ptr) = p[1];
	}

	/* value will be 0..9, so using '& 0xF' is safe, and faster than '% 10' */
	if (value)
		*(--ptr) = (value & 0xF) | '0';

	return ptr;
}

char *
uint_to_str_back_len(char *ptr, uint32_t value, int len)
{
	char *new_ptr;

	new_ptr = uint_to_str_back(ptr, value);

	/* subtract from len number of generated characters */
	len -= (int)(ptr - new_ptr);

	/* pad remaining with '0' */
	while (len > 0)
	{
		*(--new_ptr) = '0';
		len--;
	}

	return new_ptr;
}

char *
uint64_to_str_back_len(char *ptr, uint64_t value, int len)
{
	char *new_ptr;

	new_ptr = uint64_to_str_back(ptr, value);

	/* subtract from len number of generated characters */
	len -= (int)(ptr - new_ptr);

	/* pad remaining with '0' */
	while (len > 0)
	{
		*(--new_ptr) = '0';
		len--;
	}

	return new_ptr;
}

char *
int_to_str_back(char *ptr, int32_t value)
{
	if (value < 0) {
		ptr = uint_to_str_back(ptr, -value);
		*(--ptr) = '-';
	} else
		ptr = uint_to_str_back(ptr, value);

	return ptr;
}

char *
int64_to_str_back(char *ptr, int64_t value)
{
	if (value < 0) {
		ptr = uint64_to_str_back(ptr, -value);
		*(--ptr) = '-';
	} else
		ptr = uint64_to_str_back(ptr, value);

	return ptr;
}

static size_t
guint32_to_str_buf_len(const uint32_t u)
{
	/* ((2^32)-1) == 2147483647 */
	if (u >= 1000000000)return 10;
	if (u >= 100000000) return 9;
	if (u >= 10000000)  return 8;
	if (u >= 1000000)   return 7;
	if (u >= 100000)    return 6;
	if (u >= 10000)     return 5;
	if (u >= 1000)      return 4;
	if (u >= 100)       return 3;
	if (u >= 10)        return 2;

	return 1;
}

void
guint32_to_str_buf(uint32_t u, char *buf, size_t buf_len)
{
	size_t str_len = guint32_to_str_buf_len(u)+1;

	char *bp = &buf[str_len];

	_return_if_nospace(str_len, buf, buf_len);

	*--bp = '\0';

	uint_to_str_back(bp, u);
}

static size_t
guint64_to_str_buf_len(const uint64_t u)
{
	/* ((2^64)-1) == 18446744073709551615 */

	if (u >= UINT64_C(10000000000000000000)) return 20;
	if (u >= UINT64_C(1000000000000000000))  return 19;
	if (u >= UINT64_C(100000000000000000))   return 18;
	if (u >= UINT64_C(10000000000000000))    return 17;
	if (u >= UINT64_C(1000000000000000))     return 16;
	if (u >= UINT64_C(100000000000000))      return 15;
	if (u >= UINT64_C(10000000000000))       return 14;
	if (u >= UINT64_C(1000000000000))        return 13;
	if (u >= UINT64_C(100000000000))         return 12;
	if (u >= UINT64_C(10000000000))          return 11;
	if (u >= UINT64_C(1000000000))           return 10;
	if (u >= UINT64_C(100000000))            return 9;
	if (u >= UINT64_C(10000000))             return 8;
	if (u >= UINT64_C(1000000))              return 7;
	if (u >= UINT64_C(100000))               return 6;
	if (u >= UINT64_C(10000))                return 5;
	if (u >= UINT64_C(1000))                 return 4;
	if (u >= UINT64_C(100))                  return 3;
	if (u >= UINT64_C(10))                   return 2;

	return 1;
}

void
guint64_to_str_buf(uint64_t u, char *buf, size_t buf_len)
{
	size_t str_len = guint64_to_str_buf_len(u)+1;

	char *bp = &buf[str_len];

	_return_if_nospace(str_len, buf, buf_len);

	*--bp = '\0';

	uint64_to_str_back(bp, u);
}

/*
   This function is very fast and this function is called a lot.
   XXX update the address_to_str stuff to use this function.
   */
void
ip_addr_to_str_buf(const ws_in4_addr *_ad, char *buf, const int buf_len)
{
	uint8_t *ad = (uint8_t *)_ad;
	register char const *p;
	register char *b=buf;

	_return_if_nospace(WS_INET_ADDRSTRLEN, buf, buf_len);

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

char *
ip_addr_to_str(wmem_allocator_t *scope, const ws_in4_addr *ad)
{
	char *buf = wmem_alloc(scope, WS_INET_ADDRSTRLEN * sizeof(char));

	ip_addr_to_str_buf(ad, buf, WS_INET_ADDRSTRLEN);

	return buf;
}

void
ip_num_to_str_buf(uint32_t ad, char *buf, const int buf_len)
{
	ws_in4_addr addr = g_htonl(ad);
	ip_addr_to_str_buf(&addr, buf, buf_len);
}

/* Host byte order */
char *
ip_num_to_str(wmem_allocator_t *scope, uint32_t ad)
{
	ws_in4_addr addr = g_htonl(ad);
	return ip_addr_to_str(scope, &addr);
}

void
ip_to_str_buf(const uint8_t *ad, char *buf, const int buf_len)
{
	ip_addr_to_str_buf((const ws_in4_addr *)ad, buf, buf_len);
}

char *
ip_to_str(wmem_allocator_t *scope, const uint8_t *ad)
{
	return ip_addr_to_str(scope, (const ws_in4_addr *)ad);
}

void
ip6_to_str_buf(const ws_in6_addr *addr, char *buf, size_t buf_size)
{
	/*
	 * If there is not enough space then ws_inet_ntop6() will leave
	 * an error message in the buffer, we don't need
	 * to use _return_if_nospace().
	 */
	ws_inet_ntop6(addr, buf, (unsigned)buf_size);
}

char *ip6_to_str(wmem_allocator_t *scope, const ws_in6_addr *ad)
{
	char *buf = wmem_alloc(scope, WS_INET6_ADDRSTRLEN * sizeof(char));

	ws_inet_ntop6(ad, buf, WS_INET6_ADDRSTRLEN);

	return buf;
}

char *
ipxnet_to_str_punct(wmem_allocator_t *allocator, const uint32_t ad, const char punct)
{
	char *buf = (char *)wmem_alloc(allocator, 12);

	*dword_to_hex_punct(buf, ad, punct) = '\0';
	return buf;
}

#define WS_EUI64_STRLEN	24

char *
eui64_to_str(wmem_allocator_t *scope, const uint64_t ad) {
	char *buf, *tmp;
	uint8_t *p_eui64;

	p_eui64=(uint8_t *)wmem_alloc(NULL, 8);
	buf=(char *)wmem_alloc(scope, WS_EUI64_STRLEN);

	/* Copy and convert the address to network byte order. */
	*(uint64_t *)(void *)(p_eui64) = pntoh64(&(ad));

	tmp = bytes_to_hexstr_punct(buf, p_eui64, 8, ':');
	*tmp = '\0'; /* NULL terminate */
	wmem_free(NULL, p_eui64);
	return buf;
}

/*
 * Number of characters required by a 64-bit signed number.
 */
#define CHARS_64_BIT_SIGNED	20	/* sign plus 19 digits */

/*
 * Number of characters required by a fractional part, in nanoseconds,
 * not counting the decimal point.
 */
#define CHARS_NANOSECONDS	9	/* 000000001 */

/*
 * Format the fractional part of a time, with the specified precision.
 * Returns the number of bytes formatted.
 */
int
format_fractional_part_nsecs(char *buf, size_t buflen, uint32_t nsecs, const char *decimal_point, int precision)
{
	char *ptr;
	size_t remaining;
	int num_bytes;
	size_t decimal_point_len;
	uint32_t frac_part;
	int8_t num_buf[CHARS_NANOSECONDS];
	int8_t *num_end = &num_buf[CHARS_NANOSECONDS];
	int8_t *num_ptr;
	size_t num_len;

	ws_assert(precision != 0);

	if (buflen == 0) {
		/*
		 * No room in the buffer for anything, including
		 * a terminating '\0'.
		 */
		return 0;
	}

	/*
	 * If the fractional part is >= 1, don't show it as a
	 * fractional part.
	 */
	if (nsecs >= 1000000000U) {
		num_bytes = snprintf(buf, buflen, "%s(%u nanoseconds)",
		    decimal_point, nsecs);
		if ((unsigned int)num_bytes >= buflen) {
			/*
			 * That filled up or would have overflowed
			 * the buffer.  Nothing more to do; return
			 * the remaining space in the buffer, minus
			 * one byte for the terminating '\0',* as
			 * that's the number of bytes we copied.
			 */
			return (int)(buflen - 1);
		}
		return num_bytes;
	}

	ptr = buf;
	remaining = buflen;
	num_bytes = 0;

	/*
	 * Copy the decimal point.
	 * (We assume here that the locale's decimal point does
	 * not contain so many characters that its size doesn't
	 * fit in an int. :-))
	 */
	decimal_point_len = g_strlcpy(buf, decimal_point, buflen);
	if (decimal_point_len >= buflen) {
		/*
		 * The decimal point didn't fit in the buffer
		 * and was truncated.  Nothing more to do;
		 * return the remaining space in the buffer,
		 * minus one byte for the terminating '\0',
		 * as that's the number of bytes we copied.
		 */
		return (int)(buflen - 1);
	}
	ptr += decimal_point_len;
	remaining -= decimal_point_len;
	num_bytes += (int)decimal_point_len;

	/*
	 * Fill in num_buf with the nanoseconds value, padded with
	 * leading zeroes, to the specified precision.
	 *
	 * We scale the fractional part in advance, as that just
	 * takes one division by a constant (which may be
	 * optimized to a faster multiplication by a constant)
	 * and gets rid of some divisions and remainders by 100
	 * done to generate the digits.
	 *
	 * We pass preciions as the last argument to
	 * uint_to_str_back_len(), as that might mean that
	 * all of the cases end up using common code to
	 * do part of the call to uint_to_str_back_len().
	 */
	switch (precision) {

	case 1:
		/*
		 * Scale down to units of 1/10 second.
		 */
		frac_part = nsecs / 100000000U;
		break;

	case 2:
		/*
		 * Scale down to units of 1/100 second.
		 */
		frac_part = nsecs / 10000000U;
		break;

	case 3:
		/*
		 * Scale down to units of 1/1000 second.
		 */
		frac_part = nsecs / 1000000U;
		break;

	case 4:
		/*
		 * Scale down to units of 1/10000 second.
		 */
		frac_part = nsecs / 100000U;
		break;

	case 5:
		/*
		 * Scale down to units of 1/100000 second.
		 */
		frac_part = nsecs / 10000U;
		break;

	case 6:
		/*
		 * Scale down to units of 1/1000000 second.
		 */
		frac_part = nsecs / 1000U;
		break;

	case 7:
		/*
		 * Scale down to units of 1/10000000 second.
		 */
		frac_part = nsecs / 100U;
		break;

	case 8:
		/*
		 * Scale down to units of 1/100000000 second.
		 */
		frac_part = nsecs / 10U;
		break;

	case 9:
		/*
		 * We're already in units of 1/1000000000 second.
		 */
		frac_part = nsecs;
		break;

	default:
		ws_assert_not_reached();
		break;
	}

	num_ptr = uint_to_str_back_len(num_end, frac_part, precision);

	/*
	 * The length of the string that we want to copy to the buffer
	 * is the minimum of:
	 *
	 *    the length of the digit string;
	 *    the remaining space in the buffer, minus 1 for the
	 *      terminating '\0'.
	 */
	num_len = MIN((size_t)(num_end - num_ptr), remaining - 1);
	if (num_len == 0) {
		/*
		 * Not enough room to copy anything.
		 * Return the number of bytes we've generated.
		 */
		return num_bytes;
	}

	/*
	 * Copy over the fractional part.
	 * (We assume here that the fractional part does not contain
	 * so many characters that its size doesn't fit in an int. :-))
	 */
	memcpy(ptr, num_ptr, num_len);
	ptr += num_len;
	num_bytes += (int)num_len;

	/*
	 * '\0'-terminate it.
	 */
	*ptr = '\0';
	return num_bytes;
}

void
display_epoch_time(char *buf, size_t buflen, const nstime_t *ns, int precision)
{
	display_signed_time(buf, buflen, ns, precision);
}

void
display_signed_time(char *buf, size_t buflen, const nstime_t *ns, int precision)
{
	int nsecs;
	/* this buffer is not NUL terminated */
	int8_t num_buf[CHARS_64_BIT_SIGNED];
	int8_t *num_end = &num_buf[CHARS_64_BIT_SIGNED];
	int8_t *num_ptr;
	size_t num_len;

	if (buflen < 1)
		return;

	/* If the fractional part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	nsecs = ns->nsecs;
	if (nsecs < 0) {
		nsecs = -nsecs;
		if (ns->secs >= 0) {
			buf[0] = '-';
			buf++;
			buflen--;
		}
	}

	/*
	 * Fill in num_buf with the seconds value.
	 */
	num_ptr = int64_to_str_back(num_end, ns->secs);

	/*
	 * The length of the string that we want to copy to the buffer
	 * is the minimum of:
	 *
	 *    the length of the digit string;
	 *    the size of the buffer, minus 1 for the terminating
	 *      '\0'.
	 */
	num_len = MIN((size_t)(num_end - num_ptr), buflen - 1);
	if (num_len == 0) {
		/*
		 * Not enough room to copy anything.
		 */
		return;
	}

	/*
	 * Copy over the seconds value.
	 */
	memcpy(buf, num_ptr, num_len);
	buf += num_len;
	buflen -= num_len;

	if (precision == 0) {
		/*
		 * Seconds precision, so no nanosecond.
		 * Nothing more to do other than to
		 * '\0'-terminate the string.
		 */
		*buf = '\0';
		return;
	}

	/*
	 * Append the fractional part.
	 */
	format_fractional_part_nsecs(buf, buflen, (uint32_t)nsecs, ".", precision);
}

void
format_nstime_as_iso8601(char *buf, size_t buflen, const nstime_t *ns,
    char *decimal_point, bool local, int precision)
{
	struct tm tm, *tmp;
	char *ptr;
	size_t remaining;
	int num_bytes;

	if (local)
		tmp = ws_localtime_r(&ns->secs, &tm);
	else
		tmp = ws_gmtime_r(&ns->secs, &tm);
	if (tmp == NULL) {
		snprintf(buf, buflen, "Not representable");
		return;
	}
	ptr = buf;
	remaining = buflen;
	num_bytes = snprintf(ptr, remaining,
	    "%04d-%02d-%02d %02d:%02d:%02d",
	    tmp->tm_year + 1900,
	    tmp->tm_mon + 1,
	    tmp->tm_mday,
	    tmp->tm_hour,
	    tmp->tm_min,
	    tmp->tm_sec);
	if (num_bytes < 0) {
		/*
		 * That got an error.
		 * Not much else we can do.
		 */
		snprintf(buf, buflen, "snprintf() failed");
		return;
	}
	if ((unsigned int)num_bytes >= remaining) {
		/*
		 * That filled up or would have overflowed the buffer.
		 * Nothing more we can do.
		 */
		return;
	}
	ptr += num_bytes;
	remaining -= num_bytes;

	if (precision != 0) {
		/*
		 * Append the fractional part.
		 * Get the nsecs as a 32-bit unsigned value, as it should
		 * never be negative, so we treat it as unsigned.
		 */
		format_fractional_part_nsecs(ptr, remaining, (uint32_t)ns->nsecs, decimal_point, precision);
	}
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
