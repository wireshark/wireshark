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
 *     Amendment No. 6 ITU Operational Bulletin No. 1038 - 15.X.2013
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "packet-e164.h"

void proto_register_e164(void);

const value_string E164_country_code_value[] = {
	{ 0x00, "Reserved"},
	{ 0x01, "Americas"},
	{ 0x07, "Russian Federation, Kazakstan (Republic of)"},
	{ 0x020, "Egypt (Arab Republic of)"},
	{ 0x027, "South Africa (Republic of)"},
	{ 0x030, "Greece"},
	{ 0x031, "Netherlands (Kingdom of the)"},
	{ 0x032, "Belgium"},
	{ 0x033, "France"},
	{ 0x034, "Spain"},
	{ 0x036, "Hungary (Republic of)"},
	{ 0x039, "Italy"},
	{ 0x040, "Romania"},
	{ 0x041, "Switzerland (Confederation of)"},
	{ 0x043, "Austria"},
	{ 0x044, "United Kingdom of Great Britain and Northern Ireland"},
	{ 0x045, "Denmark"},
	{ 0x046, "Sweden"},
	{ 0x047, "Norway"},
	{ 0x048, "Poland (Republic of)"},
	{ 0x049, "Germany (Federal Republic of)"},
	{ 0x051, "Peru"},
	{ 0x052, "Mexico"},
	{ 0x053, "Cuba"},
	{ 0x054, "Argentine Republic"},
	{ 0x055, "Brazil (Federative Republic of)"},
	{ 0x056, "Chile"},
	{ 0x057, "Colombia (Republic of)"},
	{ 0x058, "Venezuela(Bolivarian Republic of)"},
	{ 0x060, "Malaysia"},
	{ 0x061, "Australia"},
	{ 0x062, "Indonesia (Republic of)"},
	{ 0x063, "Philippines (Republic of the)"},
	{ 0x064, "New Zealand"},
	{ 0x065, "Singapore (Republic of)"},
	{ 0x066, "Thailand"},
	{ 0x081, "Japan"},
	{ 0x082, "Korea (Republic of)"},
	{ 0x084, "Viet Nam (Socialist Republic of)"},
	{ 0x086, "China (People's Republic of)"},
	{ 0x090, "Turkey"},
	{ 0x091, "India (Republic of)"},
	{ 0x092, "Pakistan (Islamic Republic of)"},
	{ 0x093, "Afghanistan"},
	{ 0x094, "Sri Lanka (Democratic Socialist Republic of)"},
	{ 0x095, "Myanmar (the Republic of the Union of)"},
	{ 0x098, "Iran (Islamic Republic of)"},
	{ 0x0210, "Spare code"},
	{ 0x0211, "South Sudan (Republic of)"},
	{ 0x0212, "Morocco (Kingdom of)"},
	{ 0x0213, "Algeria (People's Democratic Republic of)"},
	{ 0x0214, "Spare code"},
	{ 0x0215, "Spare code"},
	{ 0x0216, "Tunisia"},
	{ 0x0217, "Spare code"},
	{ 0x0218, "Libya (Socialist People's Libyan Arab Jamahiriya)"},
	{ 0x0219, "Spare code"},
	{ 0x0220, "Gambia (Republic of)"},
	{ 0x0221, "Senegal (Republic of)"},
	{ 0x0222, "Mauritania (Islamic Republic of)"},
	{ 0x0223, "Mali (Republic of)"},
	{ 0x0224, "Guinea (Republic of)"},
	{ 0x0225, "Cote d'Ivoire (Republic of)"},
	{ 0x0226, "Burkina Faso"},
	{ 0x0227, "Niger (Republic of the)"},
	{ 0x0228, "Togolese Republic"},
	{ 0x0229, "Benin (Republic of)"},
	{ 0x0230, "Mauritius (Republic of)"},
	{ 0x0231, "Liberia (Republic of)"},
	{ 0x0232, "Sierra Leone"},
	{ 0x0233, "Ghana"},
	{ 0x0234, "Nigeria (Federal Republic of)"},
	{ 0x0235, "Chad (Republic of)"},
	{ 0x0236, "Central African Republic"},
	{ 0x0237, "Cameroon (Republic of)"},
	{ 0x0238, "Cape Verde (Republic of)"},
	{ 0x0239, "Sao Tome and Principe (Democratic Republic of)"},
	{ 0x0240, "Equatorial Guinea (Republic of)"},
	{ 0x0241, "Gabonese Republic"},
	{ 0x0242, "Congo (Republic of the)"},
	{ 0x0243, "Democratic Republic of Congo"},
	{ 0x0244, "Angola (Republic of)"},
	{ 0x0245, "Guinea-Bissau (Republic of)"},
	{ 0x0246, "Diego Garcia"},
	{ 0x0247, "Saint Helena, Ascension and Tristan da Cunha"},
	{ 0x0248, "Seychelles (Republic of)"},
	{ 0x0249, "Sudan (Republic of the)"},
	{ 0x0250, "Rwanda (Republic of)"},
	{ 0x0251, "Ethiopia (Federal Democratic Republic of)"},
	{ 0x0252, "Somali Democratic Republic"},
	{ 0x0253, "Djibouti (Republic of)"},
	{ 0x0254, "Kenya (Republic of)"},
	{ 0x0255, "Tanzania (United Republic of)"},
	{ 0x0256, "Uganda (Republic of)"},
	{ 0x0257, "Burundi (Republic of)"},
	{ 0x0258, "Mozambique (Republic of)"},
	{ 0x0259, "Spare code"},
	{ 0x0260, "Zambia (Republic of)"},
	{ 0x0261, "Madagascar (Republic of)"},
	{ 0x0262, "French Departments and Territories in the Indian Ocean"},
	{ 0x0263, "Zimbabwe (Republic of)"},
	{ 0x0264, "Namibia (Republic of)"},
	{ 0x0265, "Malawi"},
	{ 0x0266, "Lesotho (Kingdom of)"},
	{ 0x0267, "Botswana (Republic of)"},
	{ 0x0268, "Swaziland (Kingdom of)"},
	{ 0x0269, "Comoros (Union of the)"},
	{ 0x0280, "Spare code"},
	{ 0x0281, "Spare code"},
	{ 0x0282, "Spare code"},
	{ 0x0283, "Spare code"},
	{ 0x0284, "Spare code"},
	{ 0x0285, "Spare code"},
	{ 0x0286, "Spare code"},
	{ 0x0287, "Spare code"},
	{ 0x0288, "Spare code"},
	{ 0x0289, "Spare code"},
	{ 0x0290, "Saint Helena, Ascension and Tristan da Cunha"},
	{ 0x0291, "Eritrea"},
	{ 0x0292, "Spare code"},
	{ 0x0293, "Spare code"},
	{ 0x0294, "Spare code"},
	{ 0x0295, "Spare code"},
	{ 0x0296, "Spare code"},
	{ 0x0297, "Aruba"},
	{ 0x0298, "Faroe Islands"},
	{ 0x0299, "Greenland (Denmark)"},
	{ 0x0350, "Gibraltar"},
	{ 0x0351, "Portugal"},
	{ 0x0352, "Luxembourg"},
	{ 0x0353, "Ireland"},
	{ 0x0354, "Iceland"},
	{ 0x0355, "Albania (Republic of)"},
	{ 0x0356, "Malta"},
	{ 0x0357, "Cyprus (Republic of)"},
	{ 0x0358, "Finland"},
	{ 0x0359, "Bulgaria (Republic of)"},
	{ 0x0370, "Lithuania (Republic of)"},
	{ 0x0371, "Latvia (Republic of)"},
	{ 0x0372, "Estonia (Republic of)"},
	{ 0x0373, "Moldova (Republic of)"},
	{ 0x0374, "Armenia (Republic of)"},
	{ 0x0375, "Belarus (Republic of)"},
	{ 0x0376, "Andorra (Principality of)"},
	{ 0x0377, "Monaco (Principality of)"},
	{ 0x0378, "San Marino (Republic of)"},
	{ 0x0379, "Vatican City State"},
	{ 0x0380, "Ukraine"},
	{ 0x0381, "Serbia (Republic of)"},
	{ 0x0382, "Montenegro (Republic of)"},
	{ 0x0383, "Spare code"},
	{ 0x0384, "Spare code"},
	{ 0x0385, "Croatia (Republic of)"},
	{ 0x0386, "Slovenia (Republic of)"},
	{ 0x0387, "Bosnia and Herzegovina"},
	{ 0x0388, "Group of countries, shared code"},
	{ 0x0389, "The Former Yugoslav Republic of Macedonia"},
	{ 0x0420, "Czech Republic"},
	{ 0x0421, "Slovak Republic"},
	{ 0x0422, "Spare code"},
	{ 0x0423, "Liechtenstein (Principality of)"},
	{ 0x0424, "Spare code"},
	{ 0x0425, "Spare code"},
	{ 0x0426, "Spare code"},
	{ 0x0427, "Spare code"},
	{ 0x0428, "Spare code"},
	{ 0x0429, "Spare code"},
	{ 0x0500, "Falkland Islands (Malvinas)"},
	{ 0x0501, "Belize"},
	{ 0x0502, "Guatemala (Republic of)"},
	{ 0x0503, "El Salvador (Republic of)"},
	{ 0x0504, "Honduras (Republic of)"},
	{ 0x0505, "Nicaragua"},
	{ 0x0506, "Costa Rica"},
	{ 0x0507, "Panama (Republic of)"},
	{ 0x0508, "Saint Pierre and Miquelon (Collectivite territoriale de la Republique francaise)"},
	{ 0x0509, "Haiti (Republic of)"},
	{ 0x0590, "Guadeloupe (French Department of)"},
	{ 0x0591, "Bolivia (Plurinational State of)"},
	{ 0x0592, "Guyana"},
	{ 0x0593, "Ecuador"},
	{ 0x0594, "French Guiana (French Department of)"},
	{ 0x0595, "Paraguay (Republic of)"},
	{ 0x0596, "Martinique (French Department of)"},
	{ 0x0597, "Suriname (Republic of)"},
	{ 0x0598, "Uruguay (Eastern Republic of)"},
	{ 0x0599, "Bonaire, Saint Eustatius and Saba, Curacao"},
	{ 0x0670, "Democratic Republic of Timor-Leste"},
	{ 0x0671, "Spare code"},
	{ 0x0672, "Australian External Territories"},
	{ 0x0673, "Brunei Darussalam"},
	{ 0x0674, "Nauru (Republic of)"},
	{ 0x0675, "Papua New Guinea"},
	{ 0x0676, "Tonga (Kingdom of)"},
	{ 0x0677, "Solomon Islands"},
	{ 0x0678, "Vanuatu (Republic of)"},
	{ 0x0679, "Fiji (Republic of)"},
	{ 0x0680, "Palau (Republic of)"},
	{ 0x0681, "Wallis and Futuna (Territoire francais d'outre-mer)"},
	{ 0x0682, "Cook Islands"},
	{ 0x0683, "Niue"},
	{ 0x0684, "Spare code"},
	{ 0x0685, "Samoa (Independent State of)"},
	{ 0x0686, "Kiribati (Republic of)"},
	{ 0x0687, "New Caledonia (Territoire francais d'outre-mer)"},
	{ 0x0688, "Tuvalu"},
	{ 0x0689, "French Polynesia (Territoire francais d'outre-mer)"},
	{ 0x0690, "Tokelau"},
	{ 0x0691, "Micronesia (Federated States of)"},
	{ 0x0692, "Marshall Islands (Republic of the)"},
	{ 0x0693, "Spare code"},
	{ 0x0694, "Spare code"},
	{ 0x0695, "Spare code"},
	{ 0x0696, "Spare code"},
	{ 0x0697, "Spare code"},
	{ 0x0698, "Spare code"},
	{ 0x0699, "Spare code"},
	{ 0x0800, "International Freephone Service"},
	{ 0x0801, "Spare code"},
	{ 0x0802, "Spare code"},
	{ 0x0803, "Spare code"},
	{ 0x0804, "Spare code"},
	{ 0x0805, "Spare code"},
	{ 0x0806, "Spare code"},
	{ 0x0807, "Spare code"},
	{ 0x0808, "International Shared Cost Service (ISCS)"},
	{ 0x0809, "Spare code"},
	{ 0x0830, "Spare code"},
	{ 0x0831, "Spare code"},
	{ 0x0832, "Spare code"},
	{ 0x0833, "Spare code"},
	{ 0x0834, "Spare code"},
	{ 0x0835, "Spare code"},
	{ 0x0836, "Spare code"},
	{ 0x0837, "Spare code"},
	{ 0x0838, "Spare code"},
	{ 0x0839, "Spare code"},
	{ 0x0850, "Democratic People's Republic of Korea"},
	{ 0x0851, "Spare code"},
	{ 0x0852, "Hong Kong, China"},
	{ 0x0853, "Macau, China"},
	{ 0x0854, "Spare code"},
	{ 0x0855, "Cambodia (Kingdom of)"},
	{ 0x0856, "Lao People's Democratic Republic"},
	{ 0x0857, "Spare code"},
	{ 0x0858, "Spare code"},
	{ 0x0859, "Spare code"},
	{ 0x0870, "Inmarsat SNAC"},
	{ 0x0871, "Spare code"},
	{ 0x0872, "Spare code"},
	{ 0x0873, "Spare code"},
	{ 0x0874, "Spare code"},
	{ 0x0875, "Reserved - Maritime Mobile Service Applications"},
	{ 0x0876, "Reserved - Maritime Mobile Service Applications"},
	{ 0x0877, "Reserved - Maritime Mobile Service Applications"},
	{ 0x0878, "Universal Personal Telecommunication Service (UPT)"},
	{ 0x0879, "Reserved for national non-commercial purposes"},
	{ 0x0880, "Bangladesh"},
	{ 0x0881, "Global Mobile Satellite System (GMSS), shared code"},
	{ 0x0882, "International Networks, shared code"},
	{ 0x0883, "International Networks, shared code"},
	{ 0x0884, "Spare code"},
	{ 0x0885, "Spare code"},
	{ 0x0886, "Taiwan, China"},
	{ 0x0887, "Spare code"},
	{ 0x0888, "Telecommunications for Disaster Relief (TDR)"},
	{ 0x0889, "Spare code"},
	{ 0x0890, "Spare code"},
	{ 0x0891, "Spare code"},
	{ 0x0892, "Spare code"},
	{ 0x0893, "Spare code"},
	{ 0x0894, "Spare code"},
	{ 0x0895, "Spare code"},
	{ 0x0896, "Spare code"},
	{ 0x0897, "Spare code"},
	{ 0x0898, "Spare code"},
	{ 0x0899, "Spare code"},
	{ 0x0960, "Maldives (Republic of)"},
	{ 0x0961, "Lebanon"},
	{ 0x0962, "Jordan (Hashemite Kingdom of)"},
	{ 0x0963, "Syrian Arab Republic"},
	{ 0x0964, "Iraq (Republic of)"},
	{ 0x0965, "Kuwait (State of)"},
	{ 0x0966, "Saudi Arabia (Kingdom of)"},
	{ 0x0967, "Yemen (Republic of)"},
	{ 0x0968, "Oman (Sultanate of)"},
	{ 0x0969, "Reserved - reservation currently under investigation"},
	{ 0x0970, "Reserved"},
	{ 0x0971, "United Arab Emirates"},
	{ 0x0972, "Israel (State of)"},
	{ 0x0973, "Bahrain (Kingdom of)"},
	{ 0x0974, "Qatar (State of)"},
	{ 0x0975, "Bhutan (Kingdom of)"},
	{ 0x0976, "Mongolia"},
	{ 0x0977, "Nepal (Federal Democratic Republic of)"},
	{ 0x0978, "Spare code"},
	{ 0x0979, "International Premium Rate Service (IPRS)"},
	{ 0x0990, "Spare code"},
	{ 0x0991, "Trial of a proposed new international telecommunication public correspondence service, shared code"},
	{ 0x0992, "Tajikstan (Republic of)"},
	{ 0x0993, "Turkmenistan"},
	{ 0x0994, "Azerbaijan"},
	{ 0x0995, "Georgia"},
	{ 0x0996, "Kyrgyz Republic"},
	{ 0x0997, "Spare code"},
	{ 0x0998, "Uzbekistan (Republic of)"},
	{ 0x0999, "Reserved for future global service"},
	{ 0,	NULL }
};
static value_string_ext E164_country_code_value_ext = VALUE_STRING_EXT_INIT(E164_country_code_value);
const value_string E164_GMSS_vals[] = {
	{ 0x6, "Iridium Satellite LLC"},
	{ 0x7, "Iridium Satellite LLC"},
	{ 0x8, "Globalstar"},
	{ 0x9, "Globalstar"},
	{ 0,	NULL }
};
const value_string E164_International_Networks_882_vals[] = {
	{ 0x10, "Global Office Application"},
	{ 0x12, "HyperStream International (HSI) Data Network"},
	{ 0x13, "EMS Regional Mobile Satellite System"},
	{ 0x15, "Global international ATM Network"},
	{ 0x16, "Thuraya RMSS Network"},
	{ 0x20, "Garuda Mobile Telecommunication Satellite System"},
	{ 0x22, "Cable & Wireless Global Network"},
	{ 0x23, "Sita-Equant Network"},
	{ 0x24, "TeliaSonera Sverige AB"},
	{ 0x28, "Deutsche Telekom's Next Generation Network"},
	{ 0x31, "Global International ATM Network"},
	{ 0x32, "MCP network"},
	{ 0x33, "Oration Technologies Network"},
	{ 0x34, "BebbiCell AG"},
	{ 0x35, "Jasper System"},
	{ 0x36, "Jersey Telecom"},
	{ 0x37, "Cingular Wireless netwok"},
	{ 0x39, "Vodafone Malta"},
	{ 0x40, "Oy Communications"},
	{ 0x41, "Intermatica"},
	{ 0x42, "Seanet Maritime Communication"},
	{ 0x43, "Beeline"},
	{ 0x45, "Telecom Italia"},
	{ 0x46, "Tyntec GmbH"},
	{ 0x47, "Transatel"},
	{ 0x97, "Smart Communications Inc"},
	{ 0x98, "Onair GSM services"},
	{ 0x99, "Telenor GSM network - services in aircraft"},
	{ 0,	NULL }
};
static value_string_ext E164_International_Networks_882_vals_ext = VALUE_STRING_EXT_INIT(E164_International_Networks_882_vals);
const value_string E164_International_Networks_883_vals[] = {
	{ 0x100, "MediaLincc Ltd"},
	{ 0x110, "Aicent Inc"},
	{ 0x120, "Telenor Connexion AB"},
	{ 0x130, "France Telecom Orange"},
	{ 0x140, "Multiregional TransitTelecom (MTT)"},
	{ 0x5100, "Voxbone SA"},
	{ 0x5110, "Bandwith.com Inc"},
	{ 0x5120, "MTX Connect Ltd"},
	{ 0x5130, "SIMPE Ltd"},
	{ 0,	NULL }
};

static int proto_e164						= -1;
static int hf_E164_calling_party_number		= -1;
static int hf_E164_called_party_number		= -1;



void
dissect_e164_number(tvbuff_t *tvb, proto_tree *tree, int offset, int length,e164_info_t e164_info)
{
	switch (e164_info.e164_number_type){
	case CALLING_PARTY_NUMBER :
		proto_tree_add_string(tree, hf_E164_calling_party_number, tvb, offset,
				length, e164_info.E164_number_str);
		break;

	case CALLED_PARTY_NUMBER :
		proto_tree_add_string(tree, hf_E164_called_party_number, tvb, offset,
				length, e164_info.E164_number_str);
		break;

	default:
		break;
	}

}
void
dissect_e164_cc(tvbuff_t *tvb, proto_tree *tree, int offset, gboolean bcd_coded){

	int	cc_offset;
	guint8	address_digit_pair;
	guint16	id_code;
	guint8	cc_length;
	guint8	length;
	guint16 cc;

	cc_offset = offset;
	address_digit_pair = tvb_get_guint8(tvb, cc_offset);

	if(!bcd_coded){
		/* Dissect country code after removing non significant zeros */
		while ( address_digit_pair == 0 ) {
			cc_offset = cc_offset + 1;
			address_digit_pair = tvb_get_guint8(tvb, cc_offset);
		}
		cc = tvb_get_ntohs(tvb, cc_offset);
		if (( address_digit_pair & 0xf0 ) != 0 ){
			cc = cc >> 4;
		}
	}else{
		cc = address_digit_pair &0x0f;
		cc = cc << 4;
		cc = cc | (address_digit_pair &0xf0)>>4;
		cc = cc << 4;
		if (tvb_bytes_exist(tvb, cc_offset+1, 1)){
			address_digit_pair = tvb_get_guint8(tvb, cc_offset+1);
			cc = cc | (address_digit_pair &0x0f);
		}

	}

	switch ( cc & 0x0f00 ) {

	case 0x0:
		cc_length = 1;
		break;

	case 0x0100:
		cc_length = 1;
		break;

	case 0x0200:
		switch ( cc & 0x00f0 ) {
		case 0:
		case 0x70 :
			cc_length = 2;
			break;
		default :
			cc_length = 3;
			break;
		}
		break;

	case 0x0300 :
		switch ( cc & 0x00f0 ) {
		case 0 :
		case 0x10 :
		case 0x20 :
		case 0x30 :
		case 0x40 :
		case 0x60 :
		case 0x90 :
			cc_length = 2;
			break;
		default :
			cc_length = 3;
			break;
		}
		break;
	case 0x0400 :
		switch ( cc & 0x00f0 ) {
		case 0x20 :
			cc_length = 3;
			break;
		default :
			cc_length = 2;
			break;
		}
		break;

	case 0x0500 :
		switch ( cc & 0x00f0 ) {
		case 0 :
		case 0x90 :
			cc_length = 3;
			break;
		default :
			cc_length = 2;
			break;
		}
		break;

	case 0x0600 :
		switch ( cc & 0x00f0 ) {
		case 0x70 :
		case 0x80 :
		case 0x90 :
			cc_length = 3;
			break;
		default :
			cc_length = 2;
			break;
		}
		break;

	case 0x0700 :
		cc_length = 1;
		break;

	case 0x0800 :
		switch ( cc & 0x00f0 ) {
		case 0x10:
		case 0x20:
		case 0x40:
		case 0x60:
			cc_length = 2;
			break;
		default :
			cc_length = 3;
			break;
		}
		break;

	case 0x0900 :
		switch ( cc & 0x00f0 ) {
		case 0 :
		case 0x10 :
		case 0x20 :
		case 0x30 :
		case 0x40 :
		case 0x50 :
		case 0x80 :
			cc_length = 2;
			break;
		default :
			cc_length = 3;
			break;
		}
		break;

	default :
		cc_length = 0;
		break;
	}/* End switch cc */

	switch ( cc_length ) {
	case 1 :
		cc = cc >> 8;
		length = 1;
		break;
	case 2 :
		cc = cc >> 4;
		length = 1;
		break;
	default:
		length = 2;
		break;
	}/* end switch cc_length */

	proto_tree_add_text(tree, tvb, cc_offset, length,"Country Code: %x %s (length %u)", cc,
			    val_to_str_ext_const(cc,&E164_country_code_value_ext,"Unknown"), cc_length);

	switch ( cc ) {
	case 0x881 :
		if (!bcd_coded) {
			id_code = tvb_get_guint8(tvb, cc_offset + 1) & 0x0f;
		} else {
			id_code = (tvb_get_guint8(tvb, cc_offset + 1) & 0xf0) >> 4;
		}
		proto_tree_add_text(tree,tvb, (cc_offset + 1), 1,"Identification Code: %x %s ",id_code,
				    val_to_str_const(id_code,E164_GMSS_vals,"Unknown"));
		break;
	case 0x882 :
		if (!bcd_coded) {
			id_code = tvb_get_ntohs(tvb, cc_offset + 1);
			id_code = (id_code & 0x0ff0) >> 4;
		} else {
			id_code  = tvb_get_guint8(tvb, cc_offset + 1) & 0xf0;
			id_code |= tvb_get_guint8(tvb, cc_offset + 2) & 0x0f;
		}
		proto_tree_add_text(tree,tvb, (cc_offset + 1), 2,"Identification Code: %x %s ",id_code,
				    val_to_str_ext_const(id_code,&E164_International_Networks_882_vals_ext,"Unknown"));
		break;
	case 0x883 :
		if (!bcd_coded) {
			id_code = tvb_get_ntohs(tvb, cc_offset + 1);
			id_code = id_code & 0x0fff;
		} else {
			id_code  = (tvb_get_guint8(tvb, cc_offset + 1) & 0xf0) << 4;
			id_code |= (tvb_get_guint8(tvb, cc_offset + 2) & 0x0f) << 4;
			id_code |= (tvb_get_guint8(tvb, cc_offset + 2) & 0xf0) >> 4;
		}
		if ((id_code & 0x0ff0) == 0x510) {
			if (!bcd_coded) {
				id_code = (id_code << 4) | ((tvb_get_guint8(tvb, cc_offset + 3) & 0xf0) >> 4);
			} else {
				id_code = (id_code << 4) | (tvb_get_guint8(tvb, cc_offset + 3) & 0x0f);
			}
			proto_tree_add_text(tree,tvb, (cc_offset + 1), 3,"Identification Code: %x %s ",id_code,
					    val_to_str_const(id_code,E164_International_Networks_883_vals,"Unknown"));
		} else {
			proto_tree_add_text(tree,tvb, (cc_offset + 1), 2,"Identification Code: %x %s ",id_code,
					    val_to_str_const(id_code,E164_International_Networks_883_vals,"Unknown"));
		}
		break;
	default:
		break;
	}

}

/*
 * Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function
 * that calls all the protocol registration.
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
			NULL, HFILL }}
	};

	/*
	 * Register the protocol name and description
	 */
	proto_e164 = proto_register_protocol(
			"ITU-T E.164 number",
			"E.164",
			"e164");

	/*
	 * Required function calls to register
	 * the header fields and subtrees used.
	 */
	proto_register_field_array(proto_e164, hf, array_length(hf));

}
