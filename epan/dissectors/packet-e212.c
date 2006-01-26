/* packet-e212.c
 * Routines for output and filtering of E.212 numbers common
 * to many dissectors.
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
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
 *
 * Ref COMPLEMENT TO ITU-T RECOMMENDATION E.212 (11/98)
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>

#include "packet-e212.h"


const value_string E212_codes[] = {
	{  202,	"Greece" },
	{  204,	"Netherlands (Kingdom of the)" },
	{  206,	"Belgium" },
	{  208,	"France" },
	{  212,	"Monaco (Principality of)" },
	{  213,	"Andorra (Principality of)" },
	{  214,	"Spain" },
	{  216,	"Hungary (Republic of)" },
	{  218,	"Bosnia and Herzegovina" },
	{  219,	"Croatia (Republic of)" },
	{  220,	"Serbia and Montenegro" },
	{  222,	"Italy" },
	{  225,	"Vatican City State" },
	{  226,	"Romania" },
	{  228,	"Switzerland (Confederation of)" },
	{  230,	"Czech Republic" },
	{  231,	"Slovak Republic" },
	{  232,	"Austria" },
	{  234,	"United Kingdom of Great Britain and Northern Ireland" },
	{  235,	"United Kingdom of Great Britain and Northern Ireland" },
	{  238,	"Denmark" },
	{  240,	"Sweden" },
	{  242,	"Norway" },
	{  244,	"Finland" },
	{  246,	"Lithuania (Republic of)" },
	{  247,	"Latvia (Republic of)" },
	{  248,	"Estonia (Republic of)" },
	{  250,	"Russian Federation" },
	{  255,	"Ukraine" },
	{  257,	"Belarus (Republic of)" },
	{  259,	"Moldova (Republic of)" },
	{  260,	"Poland (Republic of)" },
	{  262,	"Germany (Federal Republic of)" },
	{  266,	"Gibraltar" },
	{  268,	"Portugal" },
	{  270,	"Luxembourg" },
	{  272,	"Ireland" },
	{  274,	"Iceland" },
	{  276,	"Albania (Republic of)" },
	{  278,	"Malta" },
	{  280,	"Cyprus (Republic of)" },
	{  282,	"Georgia" },
	{  283,	"Armenia (Republic of)" },
	{  284,	"Bulgaria (Republic of)" },
	{  286,	"Turkey" },
	{  288,	"Faroe Islands" },
	{  290,	"Greenland (Denmark)" },
	{  292,	"San Marino (Republic of)" },
	{  293,	"Slovenia (Republic of)" },
	{  294,	"The Former Yugoslav Republic of Macedonia" },
	{  295,	"Liechtenstein (Principality of)" },
	{  302,	"Canada" },
	{  308,	"Saint Pierre and Miquelon (Collectivité territoriale de la République française)" },
	{  310,	"United States of America" },
	{  311,	"United States of America" },
	{  312,	"United States of America" },
	{  313,	"United States of America" },
	{  314,	"United States of America" },
	{  315,	"United States of America" },
	{  316,	"United States of America" },
	{  330,	"Puerto Rico" },
	{  332,	"United States Virgin Islands" },
	{  334,	"Mexico" },
	{  338,	"Jamaica" },
	{  340,	"Martinique (French Department of)" },
	{  340,	"Guadeloupe (French Department of)" },
	{  342,	"Barbados" },
	{  344,	"Antigua and Barbuda" },
	{  346,	"Cayman Islands" },
	{  348,	"British Virgin Islands" },
	{  350,	"Bermuda" },
	{  352,	"Grenada" },
	{  354,	"Montserrat" },
	{  356,	"Saint Kitts and Nevis" },
	{  358,	"Saint Lucia" },
	{  360,	"Saint Vincent and the Grenadines" },
	{  362,	"Netherlands Antilles" },
	{  363,	"Aruba" },
	{  364,	"Bahamas (Commonwealth of the)" },
	{  365,	"Anguilla" },
	{  366,	"Dominica (Commonwealth of)" },
	{  368,	"Cuba" },
	{  370,	"Dominican Republic" },
	{  372,	"Haiti (Republic of)" },
	{  374,	"Trinidad and Tobago" },
	{  376,	"Turks and Caicos Islands" },
	{  400,	"Azerbaijani Republic" },
	{  401,	"Kazakhstan (Republic of)" },
	{  402,	"Bhutan (Kingdom of)" },
	{  404,	"India (Republic of)" },
	{  410,	"Pakistan (Islamic Republic of)" },
	{  412,	"Afghanistan" },
	{  413,	"Sri Lanka (Democratic Socialist Republic of)" },
	{  414,	"Myanmar (Union of)" },
	{  415,	"Lebanon" },
	{  416,	"Jordan (Hashemite Kingdom of)" },
	{  417,	"Syrian Arab Republic" },
	{  418,	"Iraq (Republic of)" },
	{  419,	"Kuwait (State of)" },
	{  420,	"Saudi Arabia (Kingdom of)" },
	{  421,	"Yemen (Republic of)" },
	{  422,	"Oman (Sultanate of)" },
	{  424,	"United Arab Emirates" },
	{  425,	"Israel (State of)" },
	{  426,	"Bahrain (Kingdom of)" },
	{  427,	"Qatar (State of)" },
	{  428,	"Mongolia" },
	{  429,	"Nepal" },
	{  430,	"United Arab Emirates (Abu Dhabi)" },
	{  431,	"United Arab Emirates (Dubai)" },
	{  432,	"Iran (Islamic Republic of)" },
	{  434,	"Uzbekistan (Republic of)" },
	{  436,	"Tajikistan (Republic of)" },
	{  437,	"Kyrgyz Republic" },
	{  438,	"Turkmenistan" },
	{  440,	"Japan" },
	{  441,	"Japan" },
	{  450,	"Korea (Republic of)" },
	{  452,	"Viet Nam (Socialist Republic of)" },
	{  454,	"Hongkong, China" },
	{  455,	"Macao, China" },
	{  456,	"Cambodia (Kingdom of)" },
	{  457,	"Lao People's Democratic Republic" },
	{  460,	"China (People's Republic of)" },
	{  461,	"China (People's Republic of)" },
	{  466,	"Taiwan, China" },
	{  467,	"Democratic People's Republic of Korea" },
	{  470,	"Bangladesh (People's Republic of)" },
	{  472,	"Maldives (Republic of)" },
	{  502,	"Malaysia" },
	{  505,	"Australia" },
	{  510,	"Indonesia (Republic of)" },
	{  514,	"Democratique Republic of Timor-Leste" },
	{  515,	"Philippines (Republic of the)" },
	{  520,	"Thailand" },
	{  525,	"Singapore (Republic of)" },
	{  528,	"Brunei Darussalam" },
	{  530,	"New Zealand" },
	{  534,	"Northern Mariana Islands (Commonwealth of the)" },
	{  535,	"Guam" },
	{  536,	"Nauru (Republic of)" },
	{  537,	"Papua New Guinea" },
	{  539,	"Tonga (Kingdom of)" },
	{  540,	"Solomon Islands" },
	{  541,	"Vanuatu (Republic of)" },
	{  542,	"Fiji (Republic of)" },
	{  543,	"Wallis and Futuna (Territoire français d'outre-mer)" },
	{  544,	"American Samoa" },
	{  545,	"Kiribati (Republic of)" },
	{  546,	"New Caledonia (Territoire français d'outre-mer)" },
	{  547,	"French Polynesia (Territoire français d'outre-mer)" },
	{  548,	"Cook Islands" },
	{  549,	"Samoa (Independent State of)" },
	{  550,	"Micronesia (Federated States of)" },
	{  551,	"Marshall Islands (Republic of the)" },
	{  552,	"Palau (Republic of)" },
	{  602,	"Egypt (Arab Republic of)" },
	{  603,	"Algeria (People's Democratic Republic of)" },
	{  604,	"Morocco (Kingdom of)" },
	{  605,	"Tunisia" },
	{  606,	"Libya (Socialist People's Libyan Arab Jamahiriya)" },
	{  607,	"Gambia (Republic of the)" },
	{  608,	"Senegal (Republic of)" },
	{  609,	"Mauritania (Islamic Republic of)" },
	{  610,	"Mali (Republic of)" },
	{  611,	"Guinea (Republic of)" },
	{  612,	"Côte d'Ivoire (Republic of)" },
	{  613,	"Burkina Faso" },
	{  614,	"Niger (Republic of the)" },
	{  615,	"Togolese Republic" },
	{  616,	"Benin (Republic of)" },
	{  617,	"Mauritius (Republic of)" },
	{  618,	"Liberia (Republic of)" },
	{  619,	"Sierra Leone" },
	{  620,	"Ghana" },
	{  621,	"Nigeria (Federal Republic of)" },
	{  622,	"Chad (Republic of)" },
	{  623,	"Central African Republic" },
	{  624,	"Cameroon (Republic of)" },
	{  625,	"Cape Verde (Republic of)" },
	{  626,	"Sao Tome and Principe (Democratic Republic of)" },
	{  627,	"Equatorial Guinea (Republic of)" },
	{  628,	"Gabonese Republic" },
	{  629,	"Congo (Republic of the)" },
	{  630,	"Democratic Republic of the Congo" },
	{  631,	"Angola (Republic of)" },
	{  632,	"Guinea-Bissau (Republic of)" },
	{  633,	"Seychelles (Republic of)" },
	{  634,	"Sudan (Republic of the)" },
	{  635,	"Rwandese Republic" },
	{  636,	"Ethiopia (Federal Democratic Republic of)" },
	{  637,	"Somali Democratic Republic" },
	{  638,	"Djibouti (Republic of)" },
	{  639,	"Kenya (Republic of)" },
	{  640,	"Tanzania (United Republic of)" },
	{  641,	"Uganda (Republic of)" },
	{  642,	"Burundi (Republic of)" },
	{  643,	"Mozambique (Republic of)" },
	{  645,	"Zambia (Republic of)" },
	{  646,	"Madagascar (Republic of)" },
	{  647,	"Reunion (French Department of)" },
	{  648,	"Zimbabwe (Republic of)" },
	{  649,	"Namibia (Republic of)" },
	{  650,	"Malawi" },
	{  651,	"Lesotho (Kingdom of)" },
	{  652,	"Botswana (Republic of)" },
	{  653,	"Swaziland (Kingdom of)" },
	{  654,	"Comoros (Union of the)" },
	{  655,	"South Africa (Republic of)" },
	{  657,	"Eritrea" },
	{  702,	"Belize" },
	{  704,	"Guatemala (Republic of)" },
	{  706,	"El Salvador (Republic of)" },
	{  708,	"Honduras (Republic of)" },
	{  710,	"Nicaragua" },
	{  712,	"Costa Rica" },
	{  714,	"Panama (Republic of)" },
	{  716,	"Peru" },
	{  722,	"Argentine Republic" },
	{  724,	"Brazil (Federative Republic of)" },
	{  730,	"Chile" },
	{  732,	"Colombia (Republic of)" },
	{  734,	"Venezuela (Bolivarian Republic of)" },
	{  736,	"Bolivia (Republic of)" },
	{  738,	"Guyana" },
	{  740,	"Ecuador" },
	{  742,	"French Guiana (French Department of)" },
	{  744,	"Paraguay (Republic of)" },
	{  746,	"Suriname (Republic of)" },
	{  748,	"Uruguay (Eastern Republic of)" },
	{  901,	"International Mobile, shared code" },
	{ 0, NULL }
};

static int proto_e212						= -1;
static int hf_E212_mcc						= -1;
static int hf_E212_mnc						= -1;
static int hf_E212_msin						= -1;



int
dissect_e212_mcc_mnc(tvbuff_t *tvb, proto_tree *tree, int offset){

	int			start_offset;	
	guint8		octet;
	guint16		mcc, mnc;
	guint8		mcc1, mcc2, mcc3, mnc1, mnc2, mnc3;

	start_offset = offset;
	/* Mobile country code MCC */
	octet = tvb_get_guint8(tvb,offset);
	mcc1 = octet & 0x0f;
	mcc2 = octet >> 4;
	offset++;
	octet = tvb_get_guint8(tvb,offset);
	mcc3 = octet & 0x0f;
	/* MNC, Mobile network code (octet 3 bits 5 to 8, octet 4)  */
	mnc3 = octet >> 4;
	offset++;
	octet = tvb_get_guint8(tvb,offset);
	mnc1 = octet & 0x0f;
	mnc2 = octet >> 4;

	mcc = 100 * mcc1 + 10 * mcc2 + mcc3;
	mnc = 10 * mnc1 + mnc2;
	if (mnc3 != 0xf) {
		mnc += 10 * mnc + mnc3;
	}
	proto_tree_add_uint(tree, hf_E212_mcc , tvb, start_offset, 2, mcc );
	proto_tree_add_uint(tree, hf_E212_mnc , tvb, start_offset + 1, 2, mnc );
	offset++;
	return offset;
}

/*
 * Register the protocol with Ethereal.
 *
 * This format is required because a script is used to build the C function
 * that calls all the protocol registration.
 */


void
proto_register_e212(void)
{

/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
	{ &hf_E212_mcc,
		{ "Mobile Country Code (MCC)","e212.mcc",
		FT_UINT16, BASE_DEC, NULL, 0x0,          
		"Mobile Country Code MCC", HFILL }
	},
	{ &hf_E212_mnc,
		{ "Mobile network code (MNC)","e212.mnc",
		FT_UINT16, BASE_DEC, NULL, 0x0,          
		"Mobile network code ", HFILL }
	},
	{ &hf_E212_msin,
      { "Mobile Subscriber Identification Number (MSIN)", "e212.msin",
        FT_STRING, BASE_NONE, NULL, 0,
        "Mobile Subscriber Identification Number(MSIN)", HFILL }},
	};

	/*
	 * Register the protocol name and description
	 */
	proto_e212 = proto_register_protocol(
			"ITU-T E.212 number",
			"E.212",
			"e.212");

	/*
	 * Required function calls to register
	 * the header fields and subtrees used.
	 */
	proto_register_field_array(proto_e212, hf, array_length(hf));

}