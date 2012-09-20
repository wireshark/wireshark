/* packet-e164.c
 * Routines for output and filtering of E164 numbers common
 * to many dissectors.
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Ref ITU-T E.164 05/97
 *     Annex to ITU Operational Bulletin No. 835 - 1.V.2005
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "packet-e164.h"

const value_string E164_country_code_value[] = {
	{ 0x00, "Reserved (Assignment of all 0XX codes will be feasible after 31 December 2000. This question is currently under study.)"},
	{ 0x01, "Americas"},
	{ 0x020,"Egypt"},
	{ 0x0210,"Spare code"},
	{ 0x0211,"Spare code"},
	{ 0x0212,"Morocco"},
	{ 0x0213,"Algeria"},
	{ 0x0214,"spare code"},
	{ 0x0215,"spare code"},
	{ 0x0216,"Tunisia"},
	{ 0x0217,"Spare code"},
	{ 0x0218,"Libya"},
	{ 0x0219,"Spare code"},
	{ 0x0220,"Gambia"},
	{ 0x0221,"Senegal"},
	{ 0x0222,"Mauritania"},
	{ 0x0223,"Mali"},
	{ 0x0224,"Guinea"},
	{ 0x0225,"Ivory Coast"},
	{ 0x0226,"Burkina Faso"},
	{ 0x0227,"Niger"},
	{ 0x0228,"Togolese Republic"},
	{ 0x0229,"Benin"},
	{ 0x0230,"Mauritius"},
	{ 0x0231,"Liberia "},
	{ 0x0232,"Sierra Leone"},
	{ 0x0233,"Ghana"},
	{ 0x0234,"Nigeria"},
	{ 0x0235,"Chad"},
	{ 0x0236,"Central African Republic"},
	{ 0x0237,"Cameroon"},
	{ 0x0238,"Cape Verde"},
	{ 0x0239,"Sao Tome and Principe"},
	{ 0x0240,"Equatorial Guinea"},
	{ 0x0241,"Gabonese Republic"},
	{ 0x0242,"Republic of Congo"},
	{ 0x0243,"Democratic Republic of Congo"},
	{ 0x0244,"Angola"},
	{ 0x0245,"Guinea-Bissau"},
	{ 0x0246,"Diego Garcia"},
	{ 0x0247,"Ascension"},
	{ 0x0248,"Seychelles"},
	{ 0x0249,"Sudan"},
	{ 0x0250,"Rwandese Republic"},
	{ 0x0251,"Ethiopia"},
	{ 0x0252,"Somali"},
	{ 0x0253,"Djibouti"},
	{ 0x0254,"Kenya"},
	{ 0x0255,"Tanzania"},
	{ 0x0256,"Uganda"},
	{ 0x0257,"Burundi"},
	{ 0x0258,"Mozambique"},
	{ 0x0259,"Spare code"},
	{ 0x0260,"Zambia"},
	{ 0x0261,"Madagascar"},
	{ 0x0262,"Reunion Island"},
	{ 0x0263,"Zimbabwe"},
	{ 0x0264,"Namibia"},
	{ 0x0265,"Malawi"},
	{ 0x0266,"Lesotho"},
	{ 0x0267,"Botswana"},
	{ 0x0268,"Swaziland"},
	{ 0x0269,"Comoros Mayotte"},
	{ 0x027,"South Africa"},
	{ 0x0280,"spare code"},
	{ 0x0281,"spare code"},
	{ 0x0282,"spare code"},
	{ 0x0283,"spare code"},
	{ 0x0284,"spare code"},
	{ 0x0285,"spare code"},
	{ 0x0286,"spare code"},
	{ 0x0287,"spare code"},
	{ 0x0288,"spare code"},
	{ 0x0289,"spare code"},
	{ 0x0290,"Saint Helena"},
	{ 0x0291,"Eritrea"},
	{ 0x0292,"spare code"},
	{ 0x0293,"spare code"},
	{ 0x0294,"spare code"},
	{ 0x0295,"spare code"},
	{ 0x0296,"spare code"},
	{ 0x0297,"Aruba"},
	{ 0x0298,"Faroe Islands"},
	{ 0x0299,"Greenland"},
	{ 0x030,"Greece"},
	{ 0x031,"Netherlands"},
	{ 0x032,"Belgium"},
	{ 0x033,"France"},
	{ 0x034,"Spain"},
	{ 0x0350,"Gibraltar"},
	{ 0x0351,"Portugal"},
	{ 0x0352,"Luxembourg"},
	{ 0x0353,"Ireland"},
	{ 0x0354,"Iceland"},
	{ 0x0355,"Albania"},
	{ 0x0356,"Malta"},
	{ 0x0357,"Cyprus"},
	{ 0x0358,"Finland"},
	{ 0x0359,"Bulgaria"},
	{ 0x036,"Hungary"},
	{ 0x0370,"Lithuania"},
	{ 0x0371,"Latvia"},
	{ 0x0372,"Estonia"},
	{ 0x0373,"Moldova"},
	{ 0x0374,"Armenia"},
	{ 0x0375,"Belarus"},
	{ 0x0376,"Andorra"},
	{ 0x0377,"Monaco"},
	{ 0x0378,"San Marino"},
	{ 0x0379,"Vatican"},
	{ 0x0380,"Ukraine"},
	{ 0x0381,"Serbia and Montenegro"},
	{ 0x0382,"spare code"},
	{ 0x0383,"spare code"},
	{ 0x0384,"spare code"},
	{ 0x0385,"Croatia"},
	{ 0x0386,"Slovenia"},
	{ 0x0387,"Bosnia and Herzegovina"},
	{ 0x0388,"Groups of countries:"},
	{ 0x0389,"Macedonia"},
	{ 0x039,"Italy"},
	{ 0x040,"Romania"},
	{ 0x041,"Switzerland"},
	{ 0x0420,"Czech Republic"},
	{ 0x0421,"Slovak Republic"},
	{ 0x0422,"Spare code"},
	{ 0x0423,"Liechtenstein"},
	{ 0x0424,"spare code"},
	{ 0x0425,"spare code"},
	{ 0x0426,"spare code"},
	{ 0x0427,"spare code"},
	{ 0x0428,"spare code"},
	{ 0x0429,"spare code"},
	{ 0x043,"Austria"},
	{ 0x044,"United Kingdom"},
	{ 0x045,"Denmark"},
	{ 0x046,"Sweden"},
	{ 0x047,"Norway"},
	{ 0x048,"Poland"},
	{ 0x049,"Germany"},
	{ 0x0500,"Falkland Islands (Malvinas)"},
	{ 0x0501,"Belize"},
	{ 0x0502,"Guatemala"},
	{ 0x0503,"El Salvador"},
	{ 0x0504,"Honduras"},
	{ 0x0505,"Nicaragua"},
	{ 0x0506,"Costa Rica"},
	{ 0x0507,"Panama"},
	{ 0x0508,"Saint Pierre and Miquelon"},
	{ 0x0509,"Haiti"},
	{ 0x051,"Peru"},
	{ 0x052,"Mexico"},
	{ 0x053,"Cuba"},
	{ 0x054,"Argentina"},
	{ 0x055,"Brazil"},
	{ 0x056,"Chile"},
	{ 0x057,"Colombia"},
	{ 0x058,"Venezuela"},
	{ 0x0590,"Guadeloupe"},
	{ 0x0591,"Bolivia"},
	{ 0x0592,"Guyana"},
	{ 0x0593,"Ecuador"},
	{ 0x0594,"French Guiana"},
	{ 0x0595,"Paraguay"},
	{ 0x0596,"Martinique"},
	{ 0x0597,"Suriname"},
	{ 0x0598,"Uruguay"},
	{ 0x0599,"Netherlands Antilles"},
	{ 0x060,"Malaysia"},
	{ 0x061,"Australia"},
	{ 0x062,"Indonesia"},
	{ 0x063,"Philippines"},
	{ 0x064,"New Zealand"},
	{ 0x065,"Singapore"},
	{ 0x066,"Thailand"},
	{ 0x0670,"East Timor"},
	{ 0x0671,"Spare code"},
	{ 0x0672,"Australian External Territories"},
	{ 0x0673,"Brunei Darussalam"},
	{ 0x0674,"Nauru"},
	{ 0x0675,"Papua New Guinea"},
	{ 0x0676,"Tonga"},
	{ 0x0677,"Solomon Islands"},
	{ 0x0678,"Vanuatu"},
	{ 0x0679,"Fiji"},
	{ 0x0680,"Palau"},
	{ 0x0681,"Wallis and Futuna"},
	{ 0x0682,"Cook Islands"},
	{ 0x0683,"Niue"},
	{ 0x0684,"Spare code"},
	{ 0x0685,"Samoa"},
	{ 0x0686,"Kiribati"},
	{ 0x0687,"New Caledonia"},
	{ 0x0688,"Tuvalu"},
	{ 0x0689,"French Polynesia"},
	{ 0x0690,"Tokelau"},
	{ 0x0691,"Micronesia"},
	{ 0x0692,"Marshall Islands"},
	{ 0x0693,"spare code"},
	{ 0x0694,"spare code"},
	{ 0x0695,"spare code"},
	{ 0x0696,"spare code"},
	{ 0x0697,"spare code"},
	{ 0x0698,"spare code"},
	{ 0x0699,"spare code"},
	{ 0x07,"Russian Federation,Kazakstan"},
	{ 0x0800,"International Freephone Service (see E.169.1)"},
	{ 0x0801,"spare code"},
	{ 0x0802,"spare code"},
	{ 0x0803,"spare code"},
	{ 0x0804,"spare code"},
	{ 0x0805,"spare code"},
	{ 0x0806,"spare code"},
	{ 0x0807,"spare code"},
	{ 0x0808,"Universal International Shared Cost Number (see E.169.3)"},
	{ 0x0809,"Spare code"},
	{ 0x081,"Japan"},
	{ 0x082,"Korea (Republic of)"},
	{ 0x0830,"Spare code"},
	{ 0x0831,"Spare code"},
	{ 0x0832,"Spare code"},
	{ 0x0833,"Spare code"},
	{ 0x0834,"Spare code"},
	{ 0x0835,"Spare code"},
	{ 0x0836,"Spare code"},
	{ 0x0837,"Spare code"},
	{ 0x0838,"Spare code"},
	{ 0x0839,"Spare code"},
	{ 0x084,"Viet Nam"},
	{ 0x0850,"Democratic People's Republic of Korea"},
	{ 0x0851,"Spare code"},
	{ 0x0852,"Hong Kong, China"},
	{ 0x0853,"Macau, China"},
	{ 0x0854,"Spare code"},
	{ 0x0855,"Cambodia"},
	{ 0x0856,"Laos"},
	{ 0x0857,"Spare code"},
	{ 0x0858,"Spare code"},
	{ 0x0859,"Spare code"},
	{ 0x086,"China (People's Republic of)"},
	{ 0x0870,"Inmarsat SNAC"},
	{ 0x0871,"Inmarsat (Atlantic Ocean-East)"},
	{ 0x0872,"Inmarsat (Pacific Ocean)"},
	{ 0x0873,"Inmarsat (Indian Ocean)"},
	{ 0x0874,"Inmarsat (Atlantic Ocean-West)"},
	{ 0x0875,"Reserved - Maritime Mobile Service Applications"},
	{ 0x0876,"Reserved - Maritime Mobile Service Applications"},
	{ 0x0877,"Reserved - Maritime Mobile Service Applications"},
	{ 0x0878,"Reserved - Universal Personal Telecommunication Service (UPT)"},
	{ 0x0879,"Reserved for national non-commercial purposes"},
	{ 0x0880,"Bangladesh"},
	{ 0x0881,"Global Mobile Satellite System (GMSS), shared code:"},
	{ 0x0882,"International Networks: (see E.164)"},
	{ 0x0883,"Spare code"},
	{ 0x0884,"Spare code"},
	{ 0x0885,"Spare code"},
	{ 0x0886,"Reserved"},
	{ 0x0887,"Spare code"},
	{ 0x0888,"Reserved for future global services (see E.164)"},
	{ 0x0889,"Spare code"},
	{ 0x0890,"Spare code"},
	{ 0x0891,"Spare code"},
	{ 0x0892,"Spare code"},
	{ 0x0893,"Spare code"},
	{ 0x0894,"Spare code"},
	{ 0x0895,"Spare code"},
	{ 0x0896,"Spare code"},
	{ 0x0897,"Spare code"},
	{ 0x0898,"Spare code"},
	{ 0x0899,"Spare code"},
	{ 0x090,"Turkey"},
	{ 0x091,"India"},
	{ 0x092,"Pakistan"},
	{ 0x093,"Afghanistan"},
	{ 0x094,"Sri Lanka"},
	{ 0x095,"Myanmar"},
	{ 0x0960,"Maldives"},
	{ 0x0961,"Lebanon"},
	{ 0x0962,"Jordan"},
	{ 0x0963,"Syrian Arab Republic"},
	{ 0x0964,"Iraq"},
	{ 0x0965,"Kuwait"},
	{ 0x0966,"Saudi Arabia"},
	{ 0x0967,"Yemen"},
	{ 0x0968,"Oman"},
	{ 0x0969,"Reserved"},
	{ 0x0970,"Reserved"},
	{ 0x0971,"United Arab Emirates"},
	{ 0x0972,"Israel"},
	{ 0x0973,"Bahrain"},
	{ 0x0974,"Qatar"},
	{ 0x0975,"Bhutan"},
	{ 0x0976,"Mongolia"},
	{ 0x0977,"Nepal"},
	{ 0x0978,"Spare code"},
	{ 0x0979,"Universal International Premium Rate Number (see E.169.2)"},
	{ 0x098,"Iran"},
	{ 0x0990,"Spare code"},
	{ 0x0991,"Trial service (see E.164.2)"},
	{ 0x0992,"Tajikstan"},
	{ 0x0993,"Turkmenistan"},
	{ 0x0994,"Azerbaijani Republic"},
	{ 0x0995,"Georgia"},
	{ 0x0996,"Kyrgyz Republic"},
	{ 0x0997,"Spare code"},
	{ 0x0998,"Uzbekistan"},
	{ 0x0999,"Reserved"},
	{ 0,	NULL }
};
const value_string E164_International_Networks_vals[] = {
	{   0x10, "British Telecommunications"},
	{   0x11, "Singapore Telecommunications"},
	{   0x12, "MCI"},
	{   0x13, "Telespazio"},
	{   0x14, "GTE"},
	{   0x15, "Reach"},
	{   0x16, "United Arab Emirates"},
	{   0x17, "AT&T"},
	{   0x18, "Teledesic"},
	{   0x19, "Telecom Italia"},
	{   0x20, "Asia Cellular Satellite"},
	{   0x21, "Ameritech"},
	{   0x22, "Cable & Wireless"},
	{   0x23, "Sita-Equant"},
	{   0x24, "TeliaSonera AB"},
	{   0x25, "Constellation Communications"},
	{   0x26, "SBC Communications"},
	{   0x28, "Deutsche Telekom"},
	{   0x29, "Q-Tel"},
	{   0x30, "Singapore Telecom"},
	{   0x31, "Telekom Malaysia"},
	{   0x32, "Maritime Communications Partners"},
	{   0x33, "Oration Technologies"},
	{   0x34, "Global Networks"},
	{   0x98, "SITA"},
	{   0x99, "Telenor"},
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
		address_digit_pair = tvb_get_guint8(tvb, cc_offset+1);
		cc = cc | (address_digit_pair &0x0f);

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
			    val_to_str(cc,E164_country_code_value,"unknown (%x)"), cc_length);

	switch ( cc ) {
	case 0x882 :
		id_code = tvb_get_ntohs(tvb, cc_offset + 1);
		id_code = (id_code & 0x0fff) >> 4;
		proto_tree_add_text(tree,tvb, (cc_offset + 1), 2,"Identification Code: %x %s ",id_code,
				    val_to_str(id_code,E164_International_Networks_vals,"unknown (%x)"));
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
