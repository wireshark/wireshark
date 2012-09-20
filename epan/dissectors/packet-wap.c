/* packet-wap.c
 *
 * Utility routines for WAP dissectors
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
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

#include <glib.h>
#include <epan/packet.h>
#include "packet-wap.h"

/*
 * Accessor to retrieve variable length int as used in WAP protocol.
 * The value is encoded in the lower 7 bits. If the top bit is set, then the
 * value continues into the next byte.
 * The octetCount parameter holds the number of bytes read in order to return
 * the final value. Can be pre-initialised to start at offset+count.
*/
guint
tvb_get_guintvar (tvbuff_t *tvb, guint offset, guint *octetCount)
{
	guint value = 0;
	guint octet;
	guint counter = 0;
	char cont = 1;

#ifdef DEBUG
	if (octetCount != NULL)
	{
		fprintf (stderr, "dissect_wap: Starting tvb_get_guintvar at offset %d, count=%d\n", offset, *octetCount);
		/* counter = *octetCount; */
	}
	else
	{
		fprintf (stderr, "dissect_wap: Starting tvb_get_guintvar at offset %d, count=NULL\n", offset);
	}
#endif

	while (cont != 0)
	{
		value<<=7;	/* Value only exists in 7 of the 8 bits */
		octet = tvb_get_guint8 (tvb, offset+counter);
		counter++;
		value += (octet & 0x7F);
		cont = (octet & 0x80);
#ifdef DEBUG
		fprintf (stderr, "dissect_wap: computing: octet is %d (0x%02x), count=%d, value=%d, cont=%d\n", octet, octet, counter, value, cont);
#endif
	}

	if (octetCount != NULL)
	{
		*octetCount = counter;
#ifdef DEBUG
		fprintf (stderr, "dissect_wap: Leaving tvb_get_guintvar count=%d, value=%u\n", *octetCount, value);
#endif
	}

	return (value);
}

/* See http://www.iana.org/assignments/character-sets for the MIBenum mapping */
static const value_string vals_character_sets[] = {
	{ 0x0000, "*" },
	{ 0x0003, "us-ascii" },
	{ 0x0004, "iso-8859-1" },
	{ 0x0005, "iso-8859-2" },
	{ 0x0006, "iso-8859-3" },
	{ 0x0007, "iso-8859-4" },
	{ 0x0008, "iso-8859-5" },
	{ 0x0009, "iso-8859-6" },
	{ 0x000A, "iso-8859-7" },
	{ 0x000B, "iso-8859-8" },
	{ 0x000C, "iso-8859-9" },
	{ 0x000D, "iso-8859-10" },
	{ 0x000E, "iso_6937-2-add" },
	{ 0x000F, "jis_x0201" },
	{ 0x0010, "jis_encoding" },
	{ 0x0011, "shift_jis" },
	{ 0x0012, "euc-jp" },
	{ 0x0013, "extended_unix_code_fixed_width_for_japanese" },
	{ 0x0014, "bs_4730" },
	{ 0x0015, "sen_850200_c" },
	{ 0x0016, "it" },
	{ 0x0017, "es" },
	{ 0x0018, "din_66003" },
	{ 0x0019, "ns_4551-1" },
	{ 0x001A, "nf_z_62-010" },
	{ 0x001B, "iso-10646-utf-1" },
	{ 0x001C, "iso_646.basic:1983" },
	{ 0x001D, "invariant" },
	{ 0x001E, "iso_646.irv:1983" },
	{ 0x001F, "nats-sefi" },
	{ 0x0020, "nats-sefi-add" },
	{ 0x0021, "nats-dano" },
	{ 0x0022, "nats-dano-add" },
	{ 0x0023, "sen_850200_b" },
	{ 0x0024, "ks_c_5601-1987" },
	{ 0x0025, "iso-2022-kr" },
	{ 0x0026, "euc-kr" },
	{ 0x0027, "iso-2022-jp" },
	{ 0x0028, "iso-2022-jp-2" },
	{ 0x0029, "jis_c6220-1969-jp" },
	{ 0x002A, "jis_c6220-1969-ro" },
	{ 0x002B, "pt" },
	{ 0x002C, "greek7-old" },
	{ 0x002D, "latin-greek" },
	{ 0x002E, "nf_z_62-010_(1973)" },
	{ 0x002F, "latin-greek-1" },
	{ 0x0030, "iso_5427" },
	{ 0x0031, "jis_c6226-1978" },
	{ 0x0032, "bs_viewdata" },
	{ 0x0033, "inis" },
	{ 0x0034, "inis-8" },
	{ 0x0035, "inis-cyrillic" },
	{ 0x0036, "iso_5427:1981" },
	{ 0x0037, "iso_5428:1980" },
	{ 0x0038, "gb_1988-80" },
	{ 0x0039, "gb_2312-80" },
	{ 0x003A, "ns_4551-2" },
	{ 0x003B, "videotex-suppl" },
	{ 0x003C, "pt2" },
	{ 0x003D, "es2" },
	{ 0x003E, "msz_7795.3" },
	{ 0x003F, "jis_c6226-1983" },
	{ 0x0040, "greek7" },
	{ 0x0041, "asmo_449" },
	{ 0x0042, "iso-ir-90" },
	{ 0x0043, "jis_c6229-1984-a" },
	{ 0x0044, "jis_c6229-1984-b" },
	{ 0x0045, "jis_c6229-1984-b-add" },
	{ 0x0046, "jis_c6229-1984-hand" },
	{ 0x0047, "jis_c6229-1984-hand-add" },
	{ 0x0048, "jis_c6229-1984-kana" },
	{ 0x0049, "iso_2033-1983" },
	{ 0x004A, "ansi_x3.110-1983" },
	{ 0x004B, "t.61-7bit" },
	{ 0x004C, "t.61-8bit" },
	{ 0x004D, "ecma-cyrillic" },
	{ 0x004E, "csa_z243.4-1985-1" },
	{ 0x004F, "csa_z243.4-1985-2" },
	{ 0x0050, "csa_z243.4-1985-gr" },
	{ 0x0051, "iso_8859-6-e" },
	{ 0x0052, "iso_8859-6-i" },
	{ 0x0053, "t.101-g2" },
	{ 0x0054, "iso_8859-8-e" },
	{ 0x0055, "iso_8859-8-i" },
	{ 0x0056, "csn_369103" },
	{ 0x0057, "jus_i.b1.002" },
	{ 0x0058, "iec_p27-1" },
	{ 0x0059, "jus_i.b1.003-serb" },
	{ 0x005A, "jus_i.b1.003-mac" },
	{ 0x005B, "greek-ccitt" },
	{ 0x005C, "nc_nc00-10:81" },
	{ 0x005D, "iso_6937-2-25" },
	{ 0x005E, "gost_19768-74" },
	{ 0x005F, "iso_8859-supp" },
	{ 0x0060, "iso_10367-box" },
	{ 0x0061, "latin-lap" },
	{ 0x0062, "jis_x0212-1990" },
	{ 0x0063, "ds_2089" },
	{ 0x0064, "us-dk" },
	{ 0x0065, "dk-us" },
	{ 0x0066, "ksc5636" },
	{ 0x0067, "unicode-1-1-utf-7" },
	{ 0x0068, "iso-2022-cn" },
	{ 0x0069, "iso-2022-cn-ext" },
	{ 0x006A, "utf-8" },
	{ 0x006D, "iso-8859-13" },
	{ 0x006E, "iso-8859-14" },
	{ 0x006F, "iso-8859-15" },
	{ 0x03E8, "iso-10646-ucs-2" },
	{ 0x03E9, "iso-10646-ucs-4" },
	{ 0x03EA, "iso-10646-ucs-basic" },
	{ 0x03EB, "iso-10646-j-1" },
	{ 0x03EB, "iso-10646-unicode-latin1" },
	{ 0x03ED, "iso-unicode-ibm-1261" },
	{ 0x03EE, "iso-unicode-ibm-1268" },
	{ 0x03EF, "iso-unicode-ibm-1276" },
	{ 0x03F0, "iso-unicode-ibm-1264" },
	{ 0x03F1, "iso-unicode-ibm-1265" },
	{ 0x03F2, "unicode-1-1" },
	{ 0x03F3, "scsu" },
	{ 0x03F4, "utf-7" },
	{ 0x03F5, "utf-16be" },
	{ 0x03F6, "utf-16le" },
	{ 0x03F7, "utf-16" },
	{ 0x07D0, "iso-8859-1-windows-3.0-latin-1" },
	{ 0x07D1, "iso-8859-1-windows-3.1-latin-1" },
	{ 0x07D2, "iso-8859-2-windows-latin-2" },
	{ 0x07D3, "iso-8859-9-windows-latin-5" },
	{ 0x07D4, "hp-roman8" },
	{ 0x07D5, "adobe-standard-encoding" },
	{ 0x07D6, "ventura-us" },
	{ 0x07D7, "ventura-international" },
	{ 0x07D8, "dec-mcs" },
	{ 0x07D9, "ibm850" },
	{ 0x07DA, "ibm852" },
	{ 0x07DB, "ibm437" },
	{ 0x07DC, "pc8-danish-norwegian" },
	{ 0x07DD, "ibm862" },
	{ 0x07DE, "pc8-turkish" },
	{ 0x07DF, "ibm-symbols" },
	{ 0x07E0, "ibm-thai" },
	{ 0x07E1, "hp-legal" },
	{ 0x07E2, "hp-pi-font" },
	{ 0x07E3, "hp-math8" },
	{ 0x07E4, "adobe-symbol-encoding" },
	{ 0x07E5, "hp-desktop" },
	{ 0x07E6, "ventura-math" },
	{ 0x07E7, "microsoft-publishing" },
	{ 0x07E8, "windows-31j" },
	{ 0x07E9, "gb2312" },
	{ 0x07EA, "big5" },
	{ 0x07EB, "macintosh" },
	{ 0x07EC, "ibm037" },
	{ 0x07ED, "ibm038" },
	{ 0x07EE, "ibm273" },
	{ 0x07EF, "ibm274" },
	{ 0x07F0, "ibm275" },
	{ 0x07F1, "ibm277" },
	{ 0x07F2, "ibm278" },
	{ 0x07F3, "ibm280" },
	{ 0x07F4, "ibm281" },
	{ 0x07F5, "ibm284" },
	{ 0x07F6, "ibm285" },
	{ 0x07F7, "ibm290" },
	{ 0x07F8, "ibm297" },
	{ 0x07F9, "ibm420" },
	{ 0x07FA, "ibm423" },
	{ 0x07FB, "ibm424" },
	{ 0x07FC, "ibm500" },
	{ 0x07FD, "ibm851" },
	{ 0x07FE, "ibm855" },
	{ 0x07FF, "ibm857" },
	{ 0x0800, "ibm860" },
	{ 0x0801, "ibm861" },
	{ 0x0802, "ibm863" },
	{ 0x0803, "ibm864" },
	{ 0x0804, "ibm865" },
	{ 0x0805, "ibm868" },
	{ 0x0806, "ibm869" },
	{ 0x0807, "ibm870" },
	{ 0x0808, "ibm871" },
	{ 0x0809, "ibm880" },
	{ 0x080A, "ibm891" },
	{ 0x080B, "ibm903" },
	{ 0x080C, "ibm904" },
	{ 0x080D, "ibm905" },
	{ 0x080E, "ibm918" },
	{ 0x080F, "ibm1026" },
	{ 0x0810, "ebcdic-at-de" },
	{ 0x0811, "ebcdic-at-de-a" },
	{ 0x0812, "ebcdic-ca-fr" },
	{ 0x0813, "ebcdic-dk-no" },
	{ 0x0814, "ebcdic-dk-no-a" },
	{ 0x0815, "ebcdic-fi-se" },
	{ 0x0816, "ebcdic-fi-se-a" },
	{ 0x0817, "ebcdic-fr" },
	{ 0x0818, "ebcdic-it" },
	{ 0x0819, "ebcdic-pt" },
	{ 0x081A, "ebcdic-es" },
	{ 0x081B, "ebcdic-es-a" },
	{ 0x081C, "ebcdic-es-s" },
	{ 0x081D, "ebcdic-uk" },
	{ 0x081E, "ebcdic-us" },
	{ 0x081F, "unknown-8bit" },
	{ 0x0820, "mnemonic" },
	{ 0x0821, "mnem" },
	{ 0x0822, "viscii" },
	{ 0x0823, "viqr" },
	{ 0x0824, "koi8-r" },
	{ 0x0825, "hz-gb-2312" },
	{ 0x0826, "ibm866" },
	{ 0x0827, "ibm775" },
	{ 0x0828, "koi8-u" },
	{ 0x0829, "ibm00858" },
	{ 0x082A, "ibm00924" },
	{ 0x082B, "ibm01140" },
	{ 0x082C, "ibm01141" },
	{ 0x082D, "ibm01142" },
	{ 0x082E, "ibm01143" },
	{ 0x082F, "ibm01144" },
	{ 0x0830, "ibm01145" },
	{ 0x0831, "ibm01146" },
	{ 0x0832, "ibm01147" },
	{ 0x0833, "ibm01148" },
	{ 0x0834, "ibm01149" },
	{ 0x0835, "big5-hkscs" },
	{ 0x08CA, "windows-1250" },
	{ 0x08CB, "windows-1251" },
	{ 0x08CC, "windows-1252" },
	{ 0x08CD, "windows-1253" },
	{ 0x08CE, "windows-1254" },
	{ 0x08CF, "windows-1255" },
	{ 0x08D0, "windows-1256" },
	{ 0x08D1, "windows-1257" },
	{ 0x08D2, "windows-1258" },
	{ 0x08D3, "tis-620" },
	{ 0x0000, NULL }
};
value_string_ext vals_character_sets_ext = VALUE_STRING_EXT_INIT(vals_character_sets);
