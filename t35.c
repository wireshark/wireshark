/* t35.c
 * T.35 and H.221 tables
 * 2003  Tomas Kukosa
 *
 * $Id: t35.c,v 1.3 2003/10/07 17:21:04 guy Exp $
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

#include "t35.h"

/*Recommendation T.35 (02/2000) 3  */
const value_string T35CountryCode_vals[] = {
	{ 0x00, "Japan"},
	{ 0x01, "Albania"},
	{ 0x02, "Algeria"},
	{ 0x03, "American Samoa"},
	{ 0x04, "Germany (Federal Republic of)"},
	{ 0x05, "Anguilla"},
	{ 0x06, "Antigua and Barbuda"},
	{ 0x07, "Argentina"},
	{ 0x08, "Ascension (see S. Helena)"},
	{ 0x09, "Australia"},
	{ 0x0a, "Austria"},
	{ 0x0b, "Bahamas"},
	{ 0x0c, "Bahrain"},
	{ 0x0d, "Bangladesh"},
	{ 0x0e, "Barbados"},
	{ 0x0f, "Belgium"},
	{ 0x10, "Belize"},
	{ 0x11, "Benin (Republic of)"},
	{ 0x12, "Bermudas"},
	{ 0x13, "Bhutan (Kingdom of)"},
	{ 0x14, "Bolivia"},
	{ 0x15, "Botswana"},
	{ 0x16, "Brazil"},
	{ 0x17, "British Antarctic Territory"},
	{ 0x18, "British Indian Ocean Territory"},
	{ 0x19, "British Virgin Islands"},
	{ 0x1a, "Brunei Darussalam"},
	{ 0x1b, "Bulgaria"},
	{ 0x1c, "Myanmar (Union of)"},
	{ 0x1d, "Burundi"},
	{ 0x1e, "Byelorussia"},
	{ 0x1f, "Cameroon"},
	{ 0x20, "Canada"},
	{ 0x21, "Cape Verde"},
	{ 0x22, "Cayman Islands"},
	{ 0x23, "Central African Republic"},
	{ 0x24, "Chad"},
	{ 0x25, "Chile"},
	{ 0x26, "China"},
	{ 0x27, "Colombia"},
	{ 0x28, "Comoros"},
	{ 0x29, "Congo"},
	{ 0x2a, "Cook Islands"},
	{ 0x2b, "Costa Rica"},
	{ 0x2c, "Cuba"},
	{ 0x2d, "Cyprus"},
	{ 0x2e, "Czech and Slovak Federal Republic"},
	{ 0x2f, "Cambodia"},
	{ 0x30, "Democratic People's Republic of Korea"},
	{ 0x31, "Denmark"},
	{ 0x32, "Djibouti"},
	{ 0x33, "Dominican Republic"},
	{ 0x34, "Dominica"},
	{ 0x35, "Ecuador"},
	{ 0x36, "Egypt"},
	{ 0x37, "El Salvador"},
	{ 0x38, "Equatorial Guinea"},
	{ 0x39, "Ethiopia"},
	{ 0x3a, "Falkland Islands"},
	{ 0x3b, "Fiji"},
	{ 0x3c, "Finland"},
	{ 0x3d, "France"},
	{ 0x3e, "French Polynesia"},
	{ 0x3f, "French Southern and Antarctic Lands"},
	{ 0x40, "Gabon"},
	{ 0x41, "Gambia"},
	{ 0x42, "Germany (Federal Republic of)"},
	{ 0x43, "Angola"},
	{ 0x44, "Ghana"},
	{ 0x45, "Gibraltar"},
	{ 0x46, "Greece"},
	{ 0x47, "Grenada"},
	{ 0x48, "Guam"},
	{ 0x49, "Guatemala"},
	{ 0x4a, "Guernsey"},
	{ 0x4b, "Guinea"},
	{ 0x4c, "Guinea-Bissau"},
	{ 0x4d, "Guayana"},
	{ 0x4e, "Haiti"},
	{ 0x4f, "Honduras"},
	{ 0x50, "Hongkong"},
	{ 0x51, "Hungary (Republic of)"},
	{ 0x52, "Iceland"},
	{ 0x53, "India"},
	{ 0x54, "Indonesia"},
	{ 0x55, "Iran (Islamic Republic of)"},
	{ 0x56, "Iraq"},
	{ 0x57, "Ireland"},
	{ 0x58, "Israel"},
	{ 0x59, "Italy"},
	{ 0x5a, "Cte d'Ivoire"},
	{ 0x5b, "Jamaica"},
	{ 0x5c, "Afghanistan"},
	{ 0x5d, "Jersey"},
	{ 0x5e, "Jordan"},
	{ 0x5f, "Kenya"},
	{ 0x60, "Kiribati"},
	{ 0x61, "Korea (Republic of)"},
	{ 0x62, "Kuwait"},
	{ 0x63, "Lao (People's Democratic Republic)"},
	{ 0x64, "Lebanon"},
	{ 0x65, "Lesotho"},
	{ 0x66, "Liberia"},
	{ 0x67, "Libya"},
	{ 0x68, "Liechtenstein"},
	{ 0x69, "Luxembourg"},
	{ 0x6a, "Macau"},
	{ 0x6b, "Madagascar"},
	{ 0x6c, "Malaysia"},
	{ 0x6d, "Malawi"},
	{ 0x6e, "Maldives"},
	{ 0x6f, "Mali"},
	{ 0x70, "Malta"},
	{ 0x71, "Mauritania"},
	{ 0x72, "Mauritius"},
	{ 0x73, "Mexico"},
	{ 0x74, "Monaco"},
	{ 0x75, "Mongolia"},
	{ 0x76, "Montserrat"},
	{ 0x77, "Morocco"},
	{ 0x78, "Mozambique"},
	{ 0x79, "Nauru"},
	{ 0x7a, "Nepal"},
	{ 0x7b, "Netherlands"},
	{ 0x7c, "Netherlands Antilles"},
	{ 0x7d, "New Caledonia"},
	{ 0x7e, "New Zealand"},
	{ 0x7f, "Nicaragua"},
	{ 0x80, "Niger"},
	{ 0x81, "Nigeria"},
	{ 0x82, "Norway"},
	{ 0x83, "Oman"},
	{ 0x84, "Pakistan"},
	{ 0x85, "Panama"},
	{ 0x86, "Papua New Guinea"},
	{ 0x87, "Paraguay"},
	{ 0x88, "Peru"},
	{ 0x89, "Philippines"},
	{ 0x8a, "Poland (Republic of)"},
	{ 0x8b, "Portugal"},
	{ 0x8c, "Puerto Rico"},
	{ 0x8d, "Qatar"},
	{ 0x8e, "Romania"},
	{ 0x8f, "Rwanda"},
	{ 0x90, "Saint Kitts and Nevis"},
	{ 0x91, "Saint Croix"},
	{ 0x92, "Saint Helena and Ascension"},
	{ 0x93, "Saint Lucia"},
	{ 0x94, "San Marino"},
	{ 0x95, "Saint Thomas"},
	{ 0x96, "Sao Tomï¿½and Principe"},
	{ 0x97, "Saint Vincent and the Grenadines"},
	{ 0x98, "Saudi Arabia"},
	{ 0x99, "Senegal"},
	{ 0x9a, "Seychelles"},
	{ 0x9b, "Sierra Leone"},
	{ 0x9c, "Singapore"},
	{ 0x9d, "Solomon Islands"},
	{ 0x9e, "Somalia"},
	{ 0x9f, "South Africa"},
	{ 0xa0, "Spain"},
	{ 0xa1, "Sri Lanka"},
	{ 0xa2, "Sudan"},
	{ 0xa3, "Suriname"},
	{ 0xa4, "Swaziland"},
	{ 0xa5, "Sweden"},
	{ 0xa6, "Switzerland"},
	{ 0xa7, "Syria"},
	{ 0xa8, "Tanzania"},
	{ 0xa9, "Thailand"},
	{ 0xaa, "Togo"},
	{ 0xab, "Tonga"},
	{ 0xac, "Trinidad and Tobago"},
	{ 0xad, "Tunisia"},
	{ 0xae, "Turkey"},
	{ 0xaf, "Turks and Caicos Islands"},
	{ 0xb0, "Tuvalu"},
	{ 0xb1, "Uganda"},
	{ 0xb2, "Ukraine"},
	{ 0xb3, "United Arab Emirates"},
	{ 0xb4, "United Kingdom"},
	{ 0xb5, "United States"},
	{ 0xb6, "Burkina Faso"},
	{ 0xb7, "Uruguay"},
	{ 0xb8, "U.S.S.R."},
	{ 0xb9, "Vanuatu"},
	{ 0xba, "Vatican City State"},
	{ 0xbb, "Venezuela"},
	{ 0xbc, "Viet Nam"},
	{ 0xbd, "Wallis and Futuna"},
	{ 0xbe, "Western Samoa"},
	{ 0xbf, "Yemen (Republic of)"},
	{ 0xc0, "Yemen (Republic of)"},
	{ 0xc1, "Yugoslavia"},
	{ 0xc2, "Zaire"},
	{ 0xc3, "Zambia"},
	{ 0xc4, "Zimbabwe"},
	{  0, NULL }
};


const value_string T35Extension_vals[] = {
	{  0, NULL }
};

const value_string H221ManufacturerCode_vals[] = {
	{  0x04000042, "Deutsche Telekom AG" },                             /* From Ref. 3 */
	{  0x04000043, "Deutsche Telekom AG" },                             /* From Ref. 3 */
	{  0x04000082, "Siemens AG" },                                      /* From Ref. 3 */
	{  0x04000084, "ITO Communication" },                               /* From Ref. 3 */
	{  0x04000086, "Hauni Elektronik" },                                /* From Ref. 3 */
	{  0x04000088, "Dr.Neuhaus Mikroelektronik" },                      /* From Ref. 3 */
	{  0x0400008a, "mps Software" },                                    /* From Ref. 3 */
	{  0x0400008b, "Ferrari electronik GmbH" },                         /* From Ref. 3 */
	{  0x0400008c, "mbp Kommunikationssysteme GmbH" },                  /* From Ref. 3 */
	{  0x0400008d, "Schneider Rundfunkwerke AG" },                      /* From Ref. 3 */
	{  0x0400008e, "Digitronic computersysteme gmbh" },                 /* From Ref. 3 */
	{  0x0400008f, "DeTeWe - Deutsche Telephonwerke AG &Co" },          /* From Ref. 3 */
	{  0x04000082, "SITK Institut für Telekommunikation GmbH & Co KG" },/* From Ref. 3 */
	{  0x0900003D, "Equivalence (OpenH323)" },                          /* From captures */
	{  0x20000081, "Mediatrix Telecom" },                               /* From Ref. 1 */
	{  0x82000002, "Ericsson" },                                        /* From captures */
	{  0xa5000001, "Ericsson" },                                        /* From captures */
	{  0xb4000000, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000001, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000002, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000003, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000004, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000005, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000006, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000007, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000008, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000009, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb400000a, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb400000b, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb400000c, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb400000d, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb400000e, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb400000f, "British Telecommunications" },                      /* From Ref. 2 */
	{  0xb4000010, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000011, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000012, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000013, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000014, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000015, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000016, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000017, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000018, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000019, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb400001a, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb400001b, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb400001c, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb400001d, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb400001e, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb400001f, "GPT Video Systems" },                               /* From Ref. 2 */
	{  0xb4000020, "Marconi Communications" },                          /* From Ref. 2 */ 
	{  0xb4000021, "Indigo Active Vision Systems" },                    /* From Ref. 2 */ 
	{  0xb4000022, "LiveWorks Limited" },                               /* From Ref. 2 */ 
	{  0xb4000023, "ATL Telecom Limited" },                             /* From Ref. 2 */ 
	{  0xb400002a, "Network Alchemy Limited" },                         /* From Ref. 2 */ 
	{  0xb4000042, "Motion Media Technology" },                         /* From Ref. 2 */ 
	{  0xb4000044, "Data Connection" },                                 /* From Ref. 2 */ 
	{  0xb4000045, "Westbay Engineers" },                               /* From Ref. 2 */ 
	{  0xb4000049, "ImageCom" },                                        /* From Ref. 2 */ 
	{  0xb400004d, "Madge Networks" },                                  /* From Ref. 2 */ 
	{  0xb4000052, "Ridgeway Systems and Software" },                   /* From Ref. 2 */ 
	{  0xb4000053, "SpliceCom" },                                       /* From Ref. 2 */ 
	{  0xb4000054, "TeleWare" },                                        /* From Ref. 2 */ 
	{  0xb4000056, "Vegastream" },                                      /* From Ref. 2 */ 
	{  0xb4000066, "Westell" },                                         /* From Ref. 2 */ 
	{  0xb4000069, "ISDN Communications" },                             /* From Ref. 2 */ 
	{  0xb40000c0, "Codian" },                                          /* From Ref. 2 */ 

	{  0xb5000000, "Compression Labs" },                                /* From Ref. 1 */
	{  0xb5000001, "PictureTel" },                                      /* From Ref. 1 */
	{  0xb5000002, "Compression Labs" },                                /* From Ref. 1 */
	{  0xb5000003, "VTEL" },                                            /* From Ref. 1 */
	{  0xb5000005, "ERIS" },                                            /* From Ref. 1 */
	{  0xb5000007, "AT&T Worldworx" },                                  /* From Ref. 1 */
	{  0xb5000009, "VideoServer" },                                     /* From Ref. 1 */
	{  0xb500000b, "3Com Corporation" },                                /* From Ref. 1 */
	{  0xb500000c, "Clarent Corporation" },                             /* From Ref. 1 */
	{  0xb500000d, "Genesys Telecommunications Labs Inc" },             /* From Ref. 1 */
	{  0xb500000e, "C-Phone Corporation." },                            /* From Ref. 1 */
	{  0xb500000f, "Science Dynamics Corporation" },                    /* From Ref. 1 */
	{  0xb5000010, "AT&T Starpoint" },                                  /* From Ref. 1 */
	{  0xb5000011, "Netscape Conference" },                             /* From Ref. 1 */
	{  0xb5000012, "Cisco" },                                           /* From Ref. 1 */
	{  0xb5000013, "Cirilium, Inc." },                                  /* From Ref. 1 */
	{  0xb5000014, "Ascend Communications, Inc." },                     /* From Ref. 1 */
	{  0xb5000015, "RADVision, Inc." },                                 /* From Ref. 1 */
	{  0xb5000016, "Objective Communications" },                        /* From Ref. 1 */
	{  0xb5000017, "VocalTec Communications, Inc." },                   /* From Ref. 1 */
	{  0xb5000018, "Serome Technology, Inc." },                         /* From Ref. 1 */
	{  0xb5000019, "Aspect Communications" },                           /* From Ref. 1 */
	{  0xb500001a, "Cintech Tele-Management" },                         /* From Ref. 1 */
	{  0xb500001b, "Philips Video Conferencing Systems" },              /* From Ref. 1 */
	{  0xb500001c, "Vertical Networks, Inc." },                         /* From Ref. 1 */
	{  0xb500001d, "Syndeo Corp." },                                    /* From Ref. 1 */
	{  0xb500001e, "Telxon Corporation" },                              /* From Ref. 1 */
	{  0xb500001f, "Network Equipment Technologies" },                  /* From Ref. 1 */
	{  0xb5000020, "Pagoo, Inc." },                                     /* From Ref. 1 */
	{  0xb5000021, "General Dynamics" },                                /* From Ref. 1 */
	{  0xb5000022, "Vanguard Managed Solutions" },                      /* From Ref. 1 */
	{  0xb5000023, "TeleStream Technologies, Inc." },                   /* From Ref. 1 */
	{  0xb5000024, "Spirent Communications" },                          /* From Ref. 1 */
	{  0xb5000025, "CrystalVoice Communications" },                     /* From Ref. 1 */
	{  0xb5000026, "Xiph.org" },                                        /* From Ref. 1 */
	{  0xb5000027, "NACT Telecommunications" },                         /* From Ref. 1 */
	{  0xb5000028, "AudioCodes, Inc." },                                /* From Ref. 1 */
	{  0xb5000120, "AT&T - GBCS" },                                     /* From Ref. 1 */
	{  0xb5000168, "Leadtek Research Inc." },                           /* From Ref. 1 */
	{  0xb5000247, "Lucent Technologies" },                             /* From Ref. 1 */
	{  0xb500029a, "Symbol Technologies Inc." },                        /* From Ref. 1 */
	{  0xb5000378, "StarVox, Inc." },                                   /* From Ref. 1 */
	{  0xb50003f7, "Inari Inc." },                                      /* From Ref. 1 */
	{  0xb5000727, "Quintum Technologies, Inc." },                      /* From Ref. 1 */
	{  0xb5000918, "Netrix Corporation" },                              /* From Ref. 1 */
	{  0xb500101e, "SysMaster Corporation" },                           /* From Ref. 1 */
	{  0xb5001a1a, "Alpha Telecom, Inc. U.S.A." },                      /* From Ref. 1 */
	{  0xb5002331, "ViaVideo" },                                        /* From Ref. 1 */
	{  0xb500301c, "Congruency, Inc." },                                /* From Ref. 1 */
	{  0xb5003039, "MiBridge Inc." },                                   /* From Ref. 1 */
	{  0xb5003838, "8x8 Inc." },                                        /* From Ref. 1 */
	{  0xb5004147, "Agere Systems" },                                   /* From Ref. 1 */
	{  0xb5004153, "Artisoft Inc." },                                   /* From Ref. 1 */
	{  0xb5004156, "Avaya" },                                           /* From Ref. 1 */
	{  0xb5004242, "IBM." },                                            /* From Ref. 1 */
	{  0xb5004257, "StreamComm" },                                      /* From Ref. 1 */

	{  0xb5004c54, "Lucent Technologies" },                             /* From Ref. 1 */
	{  0xb5004d47, "MediaGate" },                                       /* From Ref. 1 */
	{  0xb5004e54, "Nortel Networks" },                                 /* From Ref. 1 */

	{  0xb5005243, "Siemens Business Communication Systems" },          /* From Ref. 1 */
	{  0xb500534c, "Microsoft" },                                       /* From Ref. 1 */

	{  0xb500600d, "Lucent Technologies" },                             /* From Ref. 1 */

	{  0xb5008080, "Intel" },                                           /* From Ref. 1 */
	{  0xa5000001, "Ericsson" },                                        /* From captures */
	{  0, NULL }
};
/* Ref 1 http://www.delta-info.com/Protocol_Test/Manufacturer_codes.html 	*/
/* Ref 2 http://www.cix.co.uk/~bpechey/H221/h221code.htm			*/
/* Ref 3 http://www.regtp.de/reg_tele/start/in_05-06-03-11-00_m/index.html 	*/

