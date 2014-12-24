/* packet-e164.c
 * Routines for output and filtering of E164 numbers common
 * to many dissectors.
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Ref ITU-T E.164 05/97
 *     Annex to ITU Operational Bulletin No. 991 - 1.XI.2011
 *     Amendment No. 10 ITU Operational Bulletin No. 1057 - 1.VIII.2014
 * Find the bulletins here:
 * http://www.itu.int/pub/T-SP-OB
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-e164.h"
#include "expert.h"

void proto_register_e164(void);

const value_string E164_country_code_value[] = {
	{ 0,	"Reserved"},
	{ 1,	"Americas"},
	{ 7,	"Russian Federation, Kazakstan (Republic of)"},
	{ 20,	"Egypt (Arab Republic of)"},
	{ 27,	"South Africa (Republic of)"},
	{ 30,	"Greece"},
	{ 31,	"Netherlands (Kingdom of the)"},
	{ 32,	"Belgium"},
	{ 33,	"France"},
	{ 34,	"Spain"},
	{ 36,	"Hungary (Republic of)"},
	{ 39,	"Italy"},
	{ 40,	"Romania"},
	{ 41,	"Switzerland (Confederation of)"},
	{ 43,	"Austria"},
	{ 44,	"United Kingdom of Great Britain and Northern Ireland"},
	{ 45,	"Denmark"},
	{ 46,	"Sweden"},
	{ 47,	"Norway"},
	{ 48,	"Poland (Republic of)"},
	{ 49,	"Germany (Federal Republic of)"},
	{ 51,	"Peru"},
	{ 52,	"Mexico"},
	{ 53,	"Cuba"},
	{ 54,	"Argentine Republic"},
	{ 55,	"Brazil (Federative Republic of)"},
	{ 56,	"Chile"},
	{ 57,	"Colombia (Republic of)"},
	{ 58,	"Venezuela(Bolivarian Republic of)"},
	{ 60,	"Malaysia"},
	{ 61,	"Australia"},
	{ 62,	"Indonesia (Republic of)"},
	{ 63,	"Philippines (Republic of the)"},
	{ 64,	"New Zealand"},
	{ 65,	"Singapore (Republic of)"},
	{ 66,	"Thailand"},
	{ 81,	"Japan"},
	{ 82,	"Korea (Republic of)"},
	{ 84,	"Viet Nam (Socialist Republic of)"},
	{ 86,	"China (People's Republic of)"},
	{ 90,	"Turkey"},
	{ 91,	"India (Republic of)"},
	{ 92,	"Pakistan (Islamic Republic of)"},
	{ 93,	"Afghanistan"},
	{ 94,	"Sri Lanka (Democratic Socialist Republic of)"},
	{ 95,	"Myanmar (the Republic of the Union of)"},
	{ 98,	"Iran (Islamic Republic of)"},
	{ 210,	"Spare code"},
	{ 211,	"South Sudan (Republic of)"},
	{ 212,	"Morocco (Kingdom of)"},
	{ 213,	"Algeria (People's Democratic Republic of)"},
	{ 214,	"Spare code"},
	{ 215,	"Spare code"},
	{ 216,	"Tunisia"},
	{ 217,	"Spare code"},
	{ 218,	"Libya (Socialist People's Libyan Arab Jamahiriya)"},
	{ 219,	"Spare code"},
	{ 220,	"Gambia (Republic of)"},
	{ 221,	"Senegal (Republic of)"},
	{ 222,	"Mauritania (Islamic Republic of)"},
	{ 223,	"Mali (Republic of)"},
	{ 224,	"Guinea (Republic of)"},
	{ 225,	"Cote d'Ivoire (Republic of)"},
	{ 226,	"Burkina Faso"},
	{ 227,	"Niger (Republic of the)"},
	{ 228,	"Togolese Republic"},
	{ 229,	"Benin (Republic of)"},
	{ 230,	"Mauritius (Republic of)"},
	{ 231,	"Liberia (Republic of)"},
	{ 232,	"Sierra Leone"},
	{ 233,	"Ghana"},
	{ 234,	"Nigeria (Federal Republic of)"},
	{ 235,	"Chad (Republic of)"},
	{ 236,	"Central African Republic"},
	{ 237,	"Cameroon (Republic of)"},
	{ 238,	"Cape Verde (Republic of)"},
	{ 239,	"Sao Tome and Principe (Democratic Republic of)"},
	{ 240,	"Equatorial Guinea (Republic of)"},
	{ 241,	"Gabonese Republic"},
	{ 242,	"Congo (Republic of the)"},
	{ 243,	"Democratic Republic of Congo"},
	{ 244,	"Angola (Republic of)"},
	{ 245,	"Guinea-Bissau (Republic of)"},
	{ 246,	"Diego Garcia"},
	{ 247,	"Saint Helena, Ascension and Tristan da Cunha"},
	{ 248,	"Seychelles (Republic of)"},
	{ 249,	"Sudan (Republic of the)"},
	{ 250,	"Rwanda (Republic of)"},
	{ 251,	"Ethiopia (Federal Democratic Republic of)"},
	{ 252,	"Somali Democratic Republic"},
	{ 253,	"Djibouti (Republic of)"},
	{ 254,	"Kenya (Republic of)"},
	{ 255,	"Tanzania (United Republic of)"},
	{ 256,	"Uganda (Republic of)"},
	{ 257,	"Burundi (Republic of)"},
	{ 258,	"Mozambique (Republic of)"},
	{ 259,	"Spare code"},
	{ 260,	"Zambia (Republic of)"},
	{ 261,	"Madagascar (Republic of)"},
	{ 262,	"French Departments and Territories in the Indian Ocean"},
	{ 263,	"Zimbabwe (Republic of)"},
	{ 264,	"Namibia (Republic of)"},
	{ 265,	"Malawi"},
	{ 266,	"Lesotho (Kingdom of)"},
	{ 267,	"Botswana (Republic of)"},
	{ 268,	"Swaziland (Kingdom of)"},
	{ 269,	"Comoros (Union of the)"},
	{ 280,	"Spare code"},
	{ 281,	"Spare code"},
	{ 282,	"Spare code"},
	{ 283,	"Spare code"},
	{ 284,	"Spare code"},
	{ 285,	"Spare code"},
	{ 286,	"Spare code"},
	{ 287,	"Spare code"},
	{ 288,	"Spare code"},
	{ 289,	"Spare code"},
	{ 290,	"Saint Helena, Ascension and Tristan da Cunha"},
	{ 291,	"Eritrea"},
	{ 292,	"Spare code"},
	{ 293,	"Spare code"},
	{ 294,	"Spare code"},
	{ 295,	"Spare code"},
	{ 296,	"Spare code"},
	{ 297,	"Aruba"},
	{ 298,	"Faroe Islands"},
	{ 299,	"Greenland (Denmark)"},
	{ 350,	"Gibraltar"},
	{ 351,	"Portugal"},
	{ 352,	"Luxembourg"},
	{ 353,	"Ireland"},
	{ 354,	"Iceland"},
	{ 355,	"Albania (Republic of)"},
	{ 356,	"Malta"},
	{ 357,	"Cyprus (Republic of)"},
	{ 358,	"Finland"},
	{ 359,	"Bulgaria (Republic of)"},
	{ 370,	"Lithuania (Republic of)"},
	{ 371,	"Latvia (Republic of)"},
	{ 372,	"Estonia (Republic of)"},
	{ 373,	"Moldova (Republic of)"},
	{ 374,	"Armenia (Republic of)"},
	{ 375,	"Belarus (Republic of)"},
	{ 376,	"Andorra (Principality of)"},
	{ 377,	"Monaco (Principality of)"},
	{ 378,	"San Marino (Republic of)"},
	{ 379,	"Vatican City State"},
	{ 380,	"Ukraine"},
	{ 381,	"Serbia (Republic of)"},
	{ 382,	"Montenegro (Republic of)"},
	{ 383,	"Spare code"},
	{ 384,	"Spare code"},
	{ 385,	"Croatia (Republic of)"},
	{ 386,	"Slovenia (Republic of)"},
	{ 387,	"Bosnia and Herzegovina"},
	{ 388,	"Group of countries, shared code"},
	{ 389,	"The Former Yugoslav Republic of Macedonia"},
	{ 420,	"Czech Republic"},
	{ 421,	"Slovak Republic"},
	{ 422,	"Spare code"},
	{ 423,	"Liechtenstein (Principality of)"},
	{ 424,	"Spare code"},
	{ 425,	"Spare code"},
	{ 426,	"Spare code"},
	{ 427,	"Spare code"},
	{ 428,	"Spare code"},
	{ 429,	"Spare code"},
	{ 500,	"Falkland Islands (Malvinas)"},
	{ 501,	"Belize"},
	{ 502,	"Guatemala (Republic of)"},
	{ 503,	"El Salvador (Republic of)"},
	{ 504,	"Honduras (Republic of)"},
	{ 505,	"Nicaragua"},
	{ 506,	"Costa Rica"},
	{ 507,	"Panama (Republic of)"},
	{ 508,	"Saint Pierre and Miquelon (Collectivite territoriale de la Republique francaise)"},
	{ 509,	"Haiti (Republic of)"},
	{ 590,	"Guadeloupe (French Department of)"},
	{ 591,	"Bolivia (Plurinational State of)"},
	{ 592,	"Guyana"},
	{ 593,	"Ecuador"},
	{ 594,	"French Guiana (French Department of)"},
	{ 595,	"Paraguay (Republic of)"},
	{ 596,	"Martinique (French Department of)"},
	{ 597,	"Suriname (Republic of)"},
	{ 598,	"Uruguay (Eastern Republic of)"},
	{ 599,	"Bonaire, Saint Eustatius and Saba, Curacao"},
	{ 670,	"Democratic Republic of Timor-Leste"},
	{ 671,	"Spare code"},
	{ 672,	"Australian External Territories"},
	{ 673,	"Brunei Darussalam"},
	{ 674,	"Nauru (Republic of)"},
	{ 675,	"Papua New Guinea"},
	{ 676,	"Tonga (Kingdom of)"},
	{ 677,	"Solomon Islands"},
	{ 678,	"Vanuatu (Republic of)"},
	{ 679,	"Fiji (Republic of)"},
	{ 680,	"Palau (Republic of)"},
	{ 681,	"Wallis and Futuna (Territoire francais d'outre-mer)"},
	{ 682,	"Cook Islands"},
	{ 683,	"Niue"},
	{ 684,	"Spare code"},
	{ 685,	"Samoa (Independent State of)"},
	{ 686,	"Kiribati (Republic of)"},
	{ 687,	"New Caledonia (Territoire francais d'outre-mer)"},
	{ 688,	"Tuvalu"},
	{ 689,	"French Polynesia (Territoire francais d'outre-mer)"},
	{ 690,	"Tokelau"},
	{ 691,	"Micronesia (Federated States of)"},
	{ 692,	"Marshall Islands (Republic of the)"},
	{ 693,	"Spare code"},
	{ 694,	"Spare code"},
	{ 695,	"Spare code"},
	{ 696,	"Spare code"},
	{ 697,	"Spare code"},
	{ 698,	"Spare code"},
	{ 699,	"Spare code"},
	{ 800,	"International Freephone Service"},
	{ 801,	"Spare code"},
	{ 802,	"Spare code"},
	{ 803,	"Spare code"},
	{ 804,	"Spare code"},
	{ 805,	"Spare code"},
	{ 806,	"Spare code"},
	{ 807,	"Spare code"},
	{ 808,	"International Shared Cost Service (ISCS)"},
	{ 809,	"Spare code"},
	{ 830,	"Spare code"},
	{ 831,	"Spare code"},
	{ 832,	"Spare code"},
	{ 833,	"Spare code"},
	{ 834,	"Spare code"},
	{ 835,	"Spare code"},
	{ 836,	"Spare code"},
	{ 837,	"Spare code"},
	{ 838,	"Spare code"},
	{ 839,	"Spare code"},
	{ 850,	"Democratic People's Republic of Korea"},
	{ 851,	"Spare code"},
	{ 852,	"Hong Kong, China"},
	{ 853,	"Macau, China"},
	{ 854,	"Spare code"},
	{ 855,	"Cambodia (Kingdom of)"},
	{ 856,	"Lao People's Democratic Republic"},
	{ 857,	"Spare code"},
	{ 858,	"Spare code"},
	{ 859,	"Spare code"},
	{ 870,	"Inmarsat SNAC"},
	{ 871,	"Spare code"},
	{ 872,	"Spare code"},
	{ 873,	"Spare code"},
	{ 874,	"Spare code"},
	{ 875,	"Reserved - Maritime Mobile Service Applications"},
	{ 876,	"Reserved - Maritime Mobile Service Applications"},
	{ 877,	"Reserved - Maritime Mobile Service Applications"},
	{ 878,	"Universal Personal Telecommunication Service (UPT)"},
	{ 879,	"Reserved for national non-commercial purposes"},
	{ 880,	"Bangladesh"},
	{ 881,	"Global Mobile Satellite System (GMSS), shared code"},
	{ 882,	"International Networks, shared code"},
	{ 883,	"International Networks, shared code"},
	{ 884,	"Spare code"},
	{ 885,	"Spare code"},
	{ 886,	"Taiwan, China"},
	{ 887,	"Spare code"},
	{ 888,	"Telecommunications for Disaster Relief (TDR)"},
	{ 889,	"Spare code"},
	{ 890,	"Spare code"},
	{ 891,	"Spare code"},
	{ 892,	"Spare code"},
	{ 893,	"Spare code"},
	{ 894,	"Spare code"},
	{ 895,	"Spare code"},
	{ 896,	"Spare code"},
	{ 897,	"Spare code"},
	{ 898,	"Spare code"},
	{ 899,	"Spare code"},
	{ 960,	"Maldives (Republic of)"},
	{ 961,	"Lebanon"},
	{ 962,	"Jordan (Hashemite Kingdom of)"},
	{ 963,	"Syrian Arab Republic"},
	{ 964,	"Iraq (Republic of)"},
	{ 965,	"Kuwait (State of)"},
	{ 966,	"Saudi Arabia (Kingdom of)"},
	{ 967,	"Yemen (Republic of)"},
	{ 968,	"Oman (Sultanate of)"},
	{ 969,	"Reserved - reservation currently under investigation"},
	{ 970,	"Reserved"},
	{ 971,	"United Arab Emirates"},
	{ 972,	"Israel (State of)"},
	{ 973,	"Bahrain (Kingdom of)"},
	{ 974,	"Qatar (State of)"},
	{ 975,	"Bhutan (Kingdom of)"},
	{ 976,	"Mongolia"},
	{ 977,	"Nepal (Federal Democratic Republic of)"},
	{ 978,	"Spare code"},
	{ 979,	"International Premium Rate Service (IPRS)"},
	{ 990,	"Spare code"},
	{ 991,	"Trial of a proposed new international telecommunication public correspondence service, shared code"},
	{ 992,	"Tajikstan (Republic of)"},
	{ 993,	"Turkmenistan"},
	{ 994,	"Azerbaijan"},
	{ 995,	"Georgia"},
	{ 996,	"Kyrgyz Republic"},
	{ 997,	"Spare code"},
	{ 998,	"Uzbekistan (Republic of)"},
	{ 999,	"Reserved for future global service"},
	{ 0,	NULL }
};
static value_string_ext E164_country_code_value_ext = VALUE_STRING_EXT_INIT(E164_country_code_value);

const value_string E164_GMSS_vals[] = {
	{ 6,	"Iridium Satellite LLC"},
	{ 7,	"Iridium Satellite LLC"},
	{ 8,	"Globalstar"},
	{ 9,	"Globalstar"},
	{ 0,	NULL }
};

const value_string E164_International_Networks_882_vals[] = {
	{ 10,	"Global Office Application"},
	{ 12,	"HyperStream International (HSI) Data Network"},
	{ 13,	"EMS Regional Mobile Satellite System"},
	{ 15,	"Global international ATM Network"},
	{ 16,	"Thuraya RMSS Network"},
	{ 20,	"Garuda Mobile Telecommunication Satellite System"},
	{ 22,	"Cable & Wireless Global Network"},
	{ 23,	"Sita-Equant Network"},
	{ 24,	"TeliaSonera Sverige AB"},
	{ 28,	"Deutsche Telekom's Next Generation Network"},
	{ 31,	"Global International ATM Network"},
	{ 32,	"MCP network"},
	{ 33,	"Oration Technologies Network"},
	{ 34,	"BebbiCell AG"},
	{ 35,	"Jasper System"},
	{ 36,	"Jersey Telecom"},
	{ 37,	"Cingular Wireless netwok"},
	{ 39,	"Vodafone Malta"},
	{ 40,	"Oy Communications"},
	{ 41,	"Intermatica"},
	{ 42,	"Seanet Maritime Communication"},
	{ 43,	"Beeline"},
	{ 45,	"Telecom Italia"},
	{ 46,	"Tyntec GmbH"},
	{ 47,	"Transatel"},
	{ 97,	"Smart Communications Inc"},
	{ 98,	"Onair GSM services"},
	{ 99,	"Telenor GSM network - services in aircraft"},
	{ 0,	NULL }
};
static value_string_ext E164_International_Networks_882_vals_ext = VALUE_STRING_EXT_INIT(E164_International_Networks_882_vals);

const value_string E164_International_Networks_883_vals[] = {
	{ 100,	"MediaLincc Ltd"},
	{ 110,	"Aicent Inc"},
	{ 120,	"Telenor Connexion AB"},
	{ 130,	"France Telecom Orange"},
	{ 140,	"Multiregional TransitTelecom (MTT)"},
	{ 150,	"BodyTrace Netherlands B.V"},
	{ 5100,	"Voxbone SA"},
	{ 5110,	"Bandwith.com Inc"},
	{ 5120,	"MTX Connect Ltd"},
	{ 5130,	"SIMPE Ltd"},
	{ 5140,	"Ellipsat Inc"},
	{ 5150,	"Wins Limited"},
	{ 0,	NULL }
};

static int proto_e164				= -1;
static int hf_E164_calling_party_number		= -1;
static int hf_E164_called_party_number		= -1;
static int hf_E164_number			= -1;
static int hf_E164_identification_code		= -1;
static int hf_E164_country_code			= -1;

static int ett_e164_msisdn = -1;

static expert_field ei_E164_country_code_non_decimal = EI_INIT;
static expert_field ei_E164_identification_code_non_decimal = EI_INIT;

void
dissect_e164_number(tvbuff_t *tvb, proto_tree *tree, int offset, int length, e164_info_t e164_info)
{
	proto_item *pi;

	switch (e164_info.e164_number_type) {
	case CALLING_PARTY_NUMBER:
		proto_tree_add_string(tree, hf_E164_calling_party_number, tvb, offset,
				      length, e164_info.E164_number_str);
		break;

	case CALLED_PARTY_NUMBER:
		proto_tree_add_string(tree, hf_E164_called_party_number, tvb, offset,
				      length, e164_info.E164_number_str);
		break;

	default:
		break;
	}

	if (e164_info.nature_of_address == E164_NA_INTERNATIONAL_NUMBER) {
		pi = proto_tree_add_string(tree, hf_E164_number, tvb, offset, length, e164_info.E164_number_str);
		PROTO_ITEM_SET_HIDDEN(pi);
	}
}

/**
 * Convert 16bit integer in BCD encoding to decimal.
 * @param bcd		BCD value to convert.
 * @param[out] dec	Pointer to decimal result.
 * @return TRUE if ok, FALSE if bcd contains a nibble > 9.
 */
static gboolean
convert_bcd_to_dec(guint16 bcd, guint16 * dec)
{
	gboolean rok = TRUE;
	guint16 result = 0;
	guint16 mult = 1;
	while (bcd) {
		if ((bcd & 0x0f) > 9)
			rok = FALSE;
		result += (bcd & 0x0f) * mult;
		bcd >>= 4;
		mult *= 10;
	}
	*dec = result;
	return rok;
}

void
dissect_e164_cc(tvbuff_t *tvb, proto_tree *tree, int offset, e164_encoding_t encoding)
{
	int	cc_offset;
	guint8	address_digit_pair;
	guint16	id_code = 0;
	guint8	cc_length;
	guint8	length;
	guint16 cc = 0;
	gboolean bcd_ok = FALSE;
	proto_item *item = NULL;

	cc_offset = offset;
	address_digit_pair = tvb_get_guint8(tvb, cc_offset);

	/* Get the first 3 digits of the MSISDN */
	switch (encoding) {
	case E164_ENC_BINARY:
		/* Dissect country code after removing non significant zeros */
		while (address_digit_pair == 0) {
			cc_offset = cc_offset + 1;
			address_digit_pair = tvb_get_guint8(tvb, cc_offset);
		}
		cc = tvb_get_ntohs(tvb, cc_offset);
		if ((address_digit_pair & 0xf0) != 0) {
			cc = cc >> 4;
		}
		break;
	case E164_ENC_BCD:
		cc = address_digit_pair &0x0f;
		cc = cc << 4;
		cc = cc | (address_digit_pair &0xf0)>>4;
		cc = cc << 4;
		if (tvb_bytes_exist(tvb, cc_offset+1, 1)) {
			address_digit_pair = tvb_get_guint8(tvb, cc_offset+1);
			cc = cc | (address_digit_pair &0x0f);
		}
		break;
	case E164_ENC_UTF8:
		/* XXX - do we need to worry about leading 0s? */
		cc  = (tvb_get_guint8(tvb, cc_offset)   - '0') << 8;
		cc |= (tvb_get_guint8(tvb, cc_offset+1) - '0') << 4;
		cc |= (tvb_get_guint8(tvb, cc_offset+2) - '0');
		break;
	}

	/* Determine how many of those digits are the Country Code */
	switch (cc & 0x0f00) {
	case 0x0:
		cc_length = 1;
		break;
	case 0x0100:
		cc_length = 1;
		break;
	case 0x0200:
		switch (cc & 0x00f0) {
		case 0:
		case 0x70:
			cc_length = 2;
			break;
		default:
			cc_length = 3;
			break;
		}
		break;
	case 0x0300:
		switch (cc & 0x00f0) {
		case 0:
		case 0x10:
		case 0x20:
		case 0x30:
		case 0x40:
		case 0x60:
		case 0x90:
			cc_length = 2;
			break;
		default:
			cc_length = 3;
			break;
		}
		break;
	case 0x0400:
		switch (cc & 0x00f0) {
		case 0x20:
			cc_length = 3;
			break;
		default:
			cc_length = 2;
			break;
		}
		break;
	case 0x0500:
		switch (cc & 0x00f0) {
		case 0:
		case 0x90:
			cc_length = 3;
			break;
		default:
			cc_length = 2;
			break;
		}
		break;
	case 0x0600:
		switch (cc & 0x00f0) {
		case 0x70:
		case 0x80:
		case 0x90:
			cc_length = 3;
			break;
		default:
			cc_length = 2;
			break;
		}
		break;
	case 0x0700:
		cc_length = 1;
		break;
	case 0x0800:
		switch (cc & 0x00f0) {
		case 0x10:
		case 0x20:
		case 0x40:
		case 0x60:
			cc_length = 2;
			break;
		default:
			cc_length = 3;
			break;
		}
		break;
	case 0x0900:
		switch (cc & 0x00f0) {
		case 0:
		case 0x10:
		case 0x20:
		case 0x30:
		case 0x40:
		case 0x50:
		case 0x80:
			cc_length = 2;
			break;
		default:
			cc_length = 3;
			break;
		}
		break;

	default:
		cc_length = 0;
		break;
	} /* End switch cc */

	/* (Now that we know how long the CC is,)
	 * shift off any extra digits we got.
	 */
	switch (cc_length) {
	case 1:
		cc = cc >> 8;
		length = 1;
		break;
	case 2:
		cc = cc >> 4;
		length = 1;
		break;
	default:
		length = 2;
		break;
	} /* end switch cc_length */

	/* Now process the CC as decimal */
	bcd_ok = convert_bcd_to_dec(cc, &cc);

	/* Display the CC */
	if (encoding == E164_ENC_UTF8)
	    item = proto_tree_add_uint(tree, hf_E164_country_code, tvb, cc_offset, cc_length, cc);
	else
	    item = proto_tree_add_uint(tree, hf_E164_country_code, tvb, cc_offset, length, cc);
	if (!bcd_ok) {
		expert_add_info(NULL, item, &ei_E164_country_code_non_decimal);
	}

	/* Handle special Country Codes */
	switch (cc) {
	case 881:
		/* Get the 1-digit ID code */
		switch (encoding) {
		case E164_ENC_BINARY:
			id_code = tvb_get_guint8(tvb, cc_offset + 1) & 0x0f;
			break;
		case E164_ENC_BCD:
			id_code = (tvb_get_guint8(tvb, cc_offset + 1) & 0xf0) >> 4;
			break;
		case E164_ENC_UTF8:
			id_code = tvb_get_guint8(tvb, cc_offset + cc_length) - '0';
			break;
		}
		bcd_ok = (id_code <= 9);
		item = proto_tree_add_uint_format_value(tree, hf_E164_identification_code, tvb, (cc_offset + 1), 1,
						id_code, "%d %s", id_code, val_to_str_const(id_code, E164_GMSS_vals, "Unknown"));
		if (!bcd_ok) {
			expert_add_info(NULL, item, &ei_E164_identification_code_non_decimal);
		}
		break;
	case 882:
		/* Get the 2-digit ID code */
		switch (encoding) {
		case E164_ENC_BINARY:
			id_code = tvb_get_ntohs(tvb, cc_offset + 1);
			id_code = (id_code & 0x0ff0) >> 4;
			break;
		case E164_ENC_BCD:
			id_code  = tvb_get_guint8(tvb, cc_offset + 1) & 0xf0;
			id_code |= tvb_get_guint8(tvb, cc_offset + 2) & 0x0f;
			break;
		case E164_ENC_UTF8:
			id_code  = (tvb_get_guint8(tvb, cc_offset+cc_length)   - '0') << 4;
			id_code |= (tvb_get_guint8(tvb, cc_offset+cc_length+1) - '0');
			break;
		}
		bcd_ok = convert_bcd_to_dec(id_code, &id_code);
		item = proto_tree_add_uint_format_value(tree, hf_E164_identification_code, tvb, (cc_offset + 1), 2,
						id_code, "%d %s", id_code, val_to_str_ext_const(id_code, &E164_International_Networks_882_vals_ext, "Unknown"));
		if (!bcd_ok) {
			expert_add_info(NULL, item, &ei_E164_identification_code_non_decimal);
		}
		break;
	case 883:
		/* Get the 3-digit ID code */
		switch (encoding) {
		case E164_ENC_BINARY:
			id_code = tvb_get_ntohs(tvb, cc_offset + 1);
			id_code = id_code & 0x0fff;
			break;
		case E164_ENC_BCD:
			id_code  = (tvb_get_guint8(tvb, cc_offset + 1) & 0xf0) << 4;
			id_code |= (tvb_get_guint8(tvb, cc_offset + 2) & 0x0f) << 4;
			id_code |= (tvb_get_guint8(tvb, cc_offset + 2) & 0xf0) >> 4;
			break;
		case E164_ENC_UTF8:
			id_code  = (tvb_get_guint8(tvb, cc_offset+cc_length)   - '0') << 8;
			id_code |= (tvb_get_guint8(tvb, cc_offset+cc_length+1) - '0') << 4;
			id_code |= (tvb_get_guint8(tvb, cc_offset+cc_length+2) - '0');
			break;
		}
		if ((id_code & 0x0ff0) == 0x510) {
			/* Get the 4th digit of the ID code */
			switch (encoding) {
			case E164_ENC_BINARY:
				id_code = (id_code << 4) | ((tvb_get_guint8(tvb, cc_offset + 3) & 0xf0) >> 4);
				break;
			case E164_ENC_BCD:
				id_code = (id_code << 4) | (tvb_get_guint8(tvb, cc_offset + 3) & 0x0f);
				break;
			case E164_ENC_UTF8:
				id_code = (id_code << 4) | (tvb_get_guint8(tvb, cc_offset + cc_length + 3) - '0');
				break;
			}
			bcd_ok = convert_bcd_to_dec(id_code, &id_code);
			item = proto_tree_add_uint_format_value(tree, hf_E164_identification_code, tvb, (cc_offset + 1), 3,
					id_code, "%d %s", id_code, val_to_str_const(id_code, E164_International_Networks_883_vals, "Unknown"));
			if (!bcd_ok) {
				expert_add_info(NULL, item, &ei_E164_identification_code_non_decimal);
			}
		} else {
			bcd_ok = convert_bcd_to_dec(id_code, &id_code);
			item = proto_tree_add_uint_format_value(tree, hf_E164_identification_code, tvb, (cc_offset + 1), 2,
					id_code, "%d %s", id_code, val_to_str_const(id_code, E164_International_Networks_883_vals, "Unknown"));
			if (!bcd_ok) {
				expert_add_info(NULL, item, &ei_E164_identification_code_non_decimal);
			}
		}
		break;
	default:
		break;
	}

}

const gchar *
dissect_e164_msisdn(tvbuff_t *tvb, proto_tree *tree, int offset, int length, e164_encoding_t encoding)
{
	proto_item *pi;
	proto_tree *subtree;
	const gchar *msisdn_str;

	switch (encoding) {
	case E164_ENC_UTF8:
		msisdn_str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_UTF_8);
		break;
	case E164_ENC_BCD:
		msisdn_str = tvb_bcd_dig_to_wmem_packet_str(tvb, offset, length, NULL, FALSE);
		break;
	case E164_ENC_BINARY:
	default:
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	pi = proto_tree_add_string(tree, hf_E164_number, tvb, offset, length, msisdn_str);

	subtree = proto_item_add_subtree(pi, ett_e164_msisdn);

	dissect_e164_cc(tvb, subtree, offset, encoding);

	return msisdn_str;
}

/*
 * Register the protocol with Wireshark.
 */

void
proto_register_e164(void)
{

	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		{ &hf_E164_calling_party_number,
		  { "E.164 Calling party number digits", "e164.calling_party_number.digits",
		  FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_E164_called_party_number,
		  { "E.164 Called party number digits", "e164.called_party_number.digits",
		  FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_E164_number,
		  { "E.164 number (MSISDN)", "e164.msisdn",
		  FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_E164_identification_code,
		  { "Identification Code", "e164.identification_code",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_E164_country_code,
		  { "Country Code", "e164.country_code",
		  FT_UINT16, BASE_DEC|BASE_EXT_STRING, &E164_country_code_value_ext, 0x0,
			NULL, HFILL }},
	};

	static gint *ett_e164_array[] = {
	    &ett_e164_msisdn,
	};

	static ei_register_info ei[] = {
	{ &ei_E164_country_code_non_decimal, { "e164.country_code.non_decimal", PI_MALFORMED, PI_WARN, "Country Code contains non-decimal digits", EXPFILL }},
	{ &ei_E164_identification_code_non_decimal, { "e164.identification_code.non_decimal", PI_MALFORMED, PI_WARN, "Identification Code contains non-decimal digits", EXPFILL }},
	};

	expert_module_t* expert_e164;


	proto_e164 = proto_register_protocol("ITU-T E.164 number", "E.164", "e164");

	proto_register_field_array(proto_e164, hf, array_length(hf));
	proto_register_subtree_array(ett_e164_array, array_length(ett_e164_array));

	expert_e164 = expert_register_protocol(proto_e164);
	expert_register_field_array(expert_e164, ei, array_length(ei));
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
