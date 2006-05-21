/* packet-cip.h
 * Routines for CIP (Common Industrial Protocol) dissection
 * CIP Home: www.odva.org
 *
 * Copyright 2004
 * Magnus Hansson <mah@hms.se>
 * Joakim Wiberg <jow@hms.se>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* CIP Service Codes */
#define SC_GET_ATT_ALL           0x01
#define SC_SET_ATT_ALL           0x02
#define SC_GET_ATT_LIST          0x03
#define SC_SET_ATT_LIST          0x04
#define SC_RESET                 0x05
#define SC_START                 0x06
#define SC_STOP                  0x07
#define SC_CREATE                0x08
#define SC_DELETE                0x09
#define SC_MULT_SERV_PACK        0x0A
#define SC_APPLY_ATTRIBUTES      0x0D
#define SC_GET_ATT_SINGLE        0x0E
#define SC_SET_ATT_SINGLE        0x10
#define SC_FIND_NEXT_OBJ_INST    0x11
#define SC_RESTOR                0x15
#define SC_SAVE                  0x16
#define SC_NO_OP                 0x17
#define SC_GET_MEMBER            0x18
#define SC_SET_MEMBER            0x19
/* Class specific services */
#define SC_FWD_CLOSE             0x4E
#define SC_UNCON_SEND            0x52
#define SC_FWD_OPEN              0x54

/* CIP Genral status codes */
#define CI_GRC_SUCCESS              0x00
#define CI_GRC_FAILURE              0x01
#define CI_GRC_NO_RESOURCE          0x02
#define CI_GRC_BAD_DATA             0x03
#define CI_GRC_BAD_PATH             0x04
#define CI_GRC_BAD_CLASS_INSTANCE   0x05
#define CI_GRC_PARTIAL_DATA         0x06
#define CI_GRC_CONN_LOST            0x07
#define CI_GRC_BAD_SERVICE          0x08
#define CI_GRC_BAD_ATTR_DATA        0x09
#define CI_GRC_ATTR_LIST_ERROR      0x0A
#define CI_GRC_ALREADY_IN_MODE      0x0B
#define CI_GRC_BAD_OBJ_MODE         0x0C
#define CI_GRC_OBJ_ALREADY_EXISTS   0x0D
#define CI_GRC_ATTR_NOT_SETTABLE    0x0E
#define CI_GRC_PERMISSION_DENIED    0x0F
#define CI_GRC_DEV_IN_WRONG_STATE   0x10
#define CI_GRC_REPLY_DATA_TOO_LARGE 0x11
#define CI_GRC_FRAGMENT_PRIMITIVE   0x12
#define CI_GRC_CONFIG_TOO_SMALL     0x13
#define CI_GRC_UNDEFINED_ATTR       0x14
#define CI_GRC_CONFIG_TOO_BIG       0x15
#define CI_GRC_OBJ_DOES_NOT_EXIST   0x16
#define CI_GRC_NO_FRAGMENTATION     0x17
#define CI_GRC_DATA_NOT_SAVED       0x18
#define CI_GRC_DATA_WRITE_FAILURE   0x19
#define CI_GRC_REQUEST_TOO_LARGE    0x1A
#define CI_GRC_RESPONSE_TOO_LARGE   0x1B
#define CI_GRC_MISSING_LIST_DATA    0x1C
#define CI_GRC_INVALID_LIST_STATUS  0x1D
#define CI_GRC_SERVICE_ERROR        0x1E
#define CI_GRC_CONN_RELATED_FAILURE 0x1F
#define CI_GRC_INVALID_PARAMETER    0x20
#define CI_GRC_WRITE_ONCE_FAILURE   0x21
#define CI_GRC_INVALID_REPLY        0x22
#define CI_GRC_BAD_KEY_IN_PATH      0x25
#define CI_GRC_BAD_PATH_SIZE        0x26
#define CI_GRC_UNEXPECTED_ATTR      0x27
#define CI_GRC_INVALID_MEMBER       0x28
#define CI_GRC_MEMBER_NOT_SETTABLE  0x29

#define CI_GRC_STILL_PROCESSING     0xFF


/* IOI Path types */
#define CI_SEGMENT_TYPE_MASK        0xE0

#define CI_PORT_SEGMENT             0x00
#define CI_LOGICAL_SEGMENT          0x20
#define CI_NETWORK_SEGMENT          0x40
#define CI_SYMBOLIC_SEGMENT         0x60
#define CI_DATA_SEGMENT             0x80

#define CI_LOGICAL_SEG_TYPE_MASK    0x1C
#define CI_LOGICAL_SEG_CLASS_ID     0x00
#define CI_LOGICAL_SEG_INST_ID      0x04
#define CI_LOGICAL_SEG_MBR_ID       0x08
#define CI_LOGICAL_SEG_CON_POINT    0x0C
#define CI_LOGICAL_SEG_ATTR_ID      0x10
#define CI_LOGICAL_SEG_SPECIAL      0x14
#define CI_LOGICAL_SEG_SERV_ID      0x18
#define CI_LOGICAL_SEG_RES_1        0x1C

#define CI_LOGICAL_SEG_FORMAT_MASK  0x03
#define CI_LOGICAL_SEG_8_BIT        0x00
#define CI_LOGICAL_SEG_16_BIT       0x01
#define CI_LOGICAL_SEG_32_BIT       0x02
#define CI_LOGICAL_SEG_RES_2        0x03
#define CI_LOGICAL_SEG_E_KEY        0x00

#define CI_E_KEY_FORMAT_VAL         0x04

#define CI_DATA_SEG_SIMPLE          0x80
#define CI_DATA_SEG_SYMBOL          0x91

#define CI_NETWORK_SEG_TYPE_MASK    0x07
#define CI_NETWORK_SEG_SCHEDULE     0x01
#define CI_NETWORK_SEG_FIXED_TAG    0x02
#define CI_NETWORK_SEG_PROD_INHI    0x03

/* Device Profile:s */
#define DP_GEN_DEV                           0x00
#define DP_AC_DRIVE	                        0x02
#define DP_MOTOR_OVERLOAD                    0x03
#define DP_LIMIT_SWITCH                      0x04
#define DP_IND_PROX_SWITCH                   0x05
#define DP_PHOTO_SENSOR                      0x06
#define DP_GENP_DISC_IO                      0x07
#define DP_RESOLVER                          0x09
#define DP_COM_ADAPTER                       0x0C
#define DP_POS_CNT                           0x10
#define DP_DC_DRIVE                          0x13
#define DP_CONTACTOR                         0x15
#define DP_MOTOR_STARTER                     0x16
#define DP_SOFT_START                        0x17
#define DP_HMI                               0x18
#define DP_MASS_FLOW_CNT                     0x1A
#define DP_PNEUM_VALVE                       0x1B
#define DP_VACUUM_PRES_GAUGE                 0x1C

/* Define vendor IDs (ControlNet + DeviceNet + EtherNet/IP) */
#define VENDOR_ID_LIST \
   { 1,     "Rockwell Automation/Allen-Bradley" }, \
   { 2,     "Namco Controls Corp." }, \
   { 4,     "Parker Hannifin Corp. (Veriflo Division)" }, \
   { 5,     "Rockwell Automation/Reliance Electric" }, \
   { 7,     "SMC Corporation of America" }, \
   { 8,     "Woodhead Software & Electronics (SST)" }, \
   { 9,     "Western Reserve Controls Inc." }, \
   { 10,    "Advanced Micro Controls Inc. (AMCI)" }, \
   { 11,    "ASCO Pneumatic Controls" }, \
   { 12,    "Banner Engineering Corp." }, \
   { 13,    "Belden Wire & Cable Company" }, \
   { 14,    "Crouse-Hinds Molded Products" }, \
   { 16,    "Daniel Woodhead Co. (Woodhead Connectivity)" }, \
   { 17,    "Dearborn Group Inc." }, \
   { 19,    "Helm Instrument" }, \
   { 20,    "Huron Net Works" }, \
   { 21,    "Lumberg, Inc." }, \
   { 22,    "Online Development Inc. (Automation Value)" }, \
   { 23,    "Vorne Industries, Inc." }, \
   { 24,    "ODVA Special Reserve" }, \
   { 25,    "ACCU-Sort Systems, Inc." }, \
   { 26,    "Festo Corporation" }, \
   { 28,    "Crouzet Automatismes SA" }, \
   { 30,    "Unico, Inc." }, \
   { 31,    "Ross Controls" }, \
   { 34,    "Hohner Corp." }, \
   { 35,    "Micro Mo Electronics, Inc." }, \
   { 36,    "MKS Instruments, Inc." }, \
   { 37,    "Yaskawa Electric America formerly Magnetek Drives" }, \
   { 39,    "AVG Automation (Uticor)" }, \
   { 40,    "WAGO Corporation" }, \
   { 41,    "CELERITY (Kinetics/Unit Instruments)" }, \
   { 42,    "IMI Norgren Limited" }, \
   { 43,    "BALLUFF GmbH" }, \
   { 44,    "Yaskawa Electric America, Inc." }, \
   { 45,    "Eurotherm Controls Inc." }, \
   { 46,    "ABB Inc." }, \
   { 47,    "Omron Corporation" }, \
   { 48,    "Turck, Inc." }, \
   { 49,    "Grayhill Inc." }, \
   { 50,    "Real Time Automation (C&ID)" }, \
   { 51,    "Microsmith, Inc." }, \
   { 52,    "Numatics, Inc." }, \
   { 53,    "Lutze, Inc." }, \
   { 56,    "Softing AG" }, \
   { 57,    "Pepperl + Fuchs" }, \
   { 58,    "Spectrum Controls, Inc." }, \
   { 59,    "MKS Instruments, CIT Group (formerly - D.I.P.)" }, \
   { 60,    "Applied Motion Products, Inc." }, \
   { 61,    "Sencon Inc." }, \
   { 62,    "High Country Tek" }, \
   { 63,    "SWAC Automation Consult GmbH" }, \
   { 64,    "Clippard Instrument Laboratory" }, \
   { 68,    "Cutler-Hammer Products" }, \
   { 71,    "Toshiba International Corp." }, \
   { 72,    "Control Technology Incorporated" }, \
   { 73,    "Tait Control Systems  Ltd." }, \
   { 74,    "Hitachi, Ltd." }, \
   { 75,    "ABB Automation Technology Products AB/Robotics" }, \
   { 76,    "NKE Corporation" }, \
   { 77,    "Rockwell Software, Inc." }, \
   { 78,    "Escort Memory Systems" }, \
   { 80,    "Industrial Devices Corporation" }, \
   { 81,    "IXXAT Automation GmbH" }, \
   { 82,    "Mitsubishi Electric Automation, Inc." }, \
   { 83,    "OPTO-22" }, \
   { 86,    "Horner Electric" }, \
   { 87,    "Burkert Werke GmbH & Co. KG" }, \
   { 89,    "Industrial Indexing Systems, Inc." }, \
   { 90,    "HMS Industrial Networks AB" }, \
   { 91,    "Robicon" }, \
   { 92,    "Helix Technology Corp (Granville-Phillips)" }, \
   { 93,    "Arlington Laboratory" }, \
   { 94,    "Advantech Co. Ltd." }, \
   { 95,    "Square D Company" }, \
   { 96,    "Digital Electronics Corp." }, \
   { 97,    "Danfoss" }, \
   { 98,    "Hewlett-Packard" }, \
   { 100,   "Bosch Rexroth (Mecman)" }, \
   { 101,   "Applied Materials, Inc." }, \
   { 102,   "Showa Electric Wire & Cable Co." }, \
   { 103,   "Pacific Scientific" }, \
   { 104,   "Sharp Manufacturing Systems Corp." }, \
   { 105,   "Lapp USA, Inc.(Olflex Wire & Cable)" }, \
   { 107,   "Unitrode" }, \
   { 108,   "Beckhoff Industrie Elektronik" }, \
   { 109,   "National Instruments" }, \
   { 110,   "Mykrolis Corporation (Millipore)" }, \
   { 111,   "International Motion Controls Corp." }, \
   { 113,   "SEG Kempen GmbH" }, \
   { 116,   "MTS Systems Corp." }, \
   { 117,   "Krones, Inc" }, \
   { 118,   "Molex Incorporated" }, \
   { 119,   "EXOR Electronic R & D" }, \
   { 120,   "SIEI S.p.A." }, \
   { 121,   "KUKA Roboter GmbH" }, \
   { 123,   "SEC (Samsung Electronics Co., Ltd)" }, \
   { 124,   "Binary Electronics Ltd" }, \
   { 125,   "Flexible Machine Controls" }, \
   { 127,   "ABB Inc. (Entrelec)" }, \
   { 128,   "MAC Valves, Inc." }, \
   { 129,   "Auma Actuators Inc." }, \
   { 130,   "Toyoda Machine Works, Ltd." }, \
   { 133,   "Balogh T.A.G., Corporation" }, \
   { 134,   "TR Systemtechnik GmbH" }, \
   { 135,   "UNIPULSE Corporation" }, \
   { 138,   "Conxall Corporation Inc." }, \
   { 141,   "Kuramo Electric Co., Ltd." }, \
   { 142,   "Creative Micro Designs" }, \
   { 143,   "GE Industrial Systems" }, \
   { 144,   "Leybold Vakuum GmbH" }, \
   { 145,   "Siemens Energy & Automation/Drives" }, \
   { 146,   "Kodensha Ltd" }, \
   { 147,   "Motion Engineering, Inc." }, \
   { 148,   "Honda Engineering Co., Ltd" }, \
   { 149,   "EIM Valve Controls" }, \
   { 150,   "Melec Inc." }, \
   { 151,   "Sony Precision Technology Inc." }, \
   { 152,   "North American Mfg." }, \
   { 153,   "Watlow Electric Inc." }, \
   { 154,   "Japan Radio Co., Ltd" }, \
   { 155,   "NADEX Co., Ltd" }, \
   { 156,   "Ametek Automation & Process Technologies" }, \
   { 158,   "Kvaser-AB" }, \
   { 159,   "IDEC IZUMI Corporation" }, \
   { 160,   "Mitsubishi Heavy Industries Ltd" }, \
   { 161,   "Mitsubishi Electric Corporation" }, \
   { 162,   "Horiba-STEC Inc." }, \
   { 163,   "esd electronic system design gmbh" }, \
   { 164,   "DAIHEN Corporation" }, \
   { 165,   "Tyco Valves & Controls/Keystone" }, \
   { 166,   "EBARA Corporation" }, \
   { 169,   "Hokuyo Automatic Co., Ltd." }, \
   { 170,   "Pyramid Solutions, Inc." }, \
   { 171,   "Denso Wave Incorporated" }, \
   { 172,   "HLS Hard-Line Solutions Inc" }, \
   { 173,   "Caterpillar, Inc." }, \
   { 174,   "PDL Electronics Ltd." }, \
   { 176,   "Red Lion Controls" }, \
   { 177,   "ANELVA Corporation" }, \
   { 178,   "Toyo Denki Seizo KK" }, \
   { 179,   "Sanyo Denki Co., Ltd." }, \
   { 180,   "Aera Japan Ltd." }, \
   { 181,   "Pilz GmbH & Co" }, \
   { 182,   "Bellofram Corp." }, \
   { 184,   "M-SYSTEM Co., Ltd." }, \
   { 185,   "Nissin Electric Co., Ltd" }, \
   { 186,   "Hitachi Metals, Ltd" }, \
   { 187,   "Oriental Motor Company" }, \
   { 188,   "A&D Co., Ltd" }, \
   { 189,   "Phasetronics, Inc." }, \
   { 190,   "Cummins Engine Company" }, \
   { 191,   "Deltron Inc." }, \
   { 192,   "Geneer Corporation" }, \
   { 193,   "Anatol Automation, Inc." }, \
   { 196,   "Medar, Inc." }, \
   { 197,   "Comdel Inc." }, \
   { 198,   "Advanced Energy Industries, Inc." }, \
   { 200,   "DAIDEN Co., Ltd" }, \
   { 201,   "CKD Corporation" }, \
   { 202,   "Toyo Electric Corporation" }, \
   { 203,   "HM Computing Ltd." }, \
   { 204,   "AuCom Electronics Ltd" }, \
   { 205,   "Shinko Electric Co., Ltd" }, \
   { 206,   "Vector Informatik GmbH" }, \
   { 208,   "Moog Inc." }, \
   { 209,   "Contemporary Controls" }, \
   { 210,   "Tokyo Sokki Kenkyujo Co., Ltd" }, \
   { 211,   "Schenck-AccuRate, Inc." }, \
   { 212,   "The Oilgear Company" }, \
   { 214,   "ASM Japan K.K." }, \
   { 215,   "HIRATA Corp." }, \
   { 216,   "SUNX Limited" }, \
   { 217,   "Meidensha Corporation" }, \
   { 218,   "Sankyo Seiki Mfg. Co., Ltd" }, \
   { 219,   "KAMRO Corp." }, \
   { 220,   "Nippon System Development Co., Ltd" }, \
   { 221,   "EBARA Technologies Inc." }, \
   { 222,   "JP Tech" }, \
   { 224,   "SG Co., Ltd" }, \
   { 225,   "Vaasa Institute of Technology" }, \
   { 226,   "ENI (Electronic Navigation Industry)" }, \
   { 227,   "Tateyama System Laboratory Co., Ltd." }, \
   { 228,   "QLOG Corporation" }, \
   { 229,   "Matric Limited Inc." }, \
   { 230,   "NSD Corporation" }, \
   { 232,   "Sumitomo Wiring Systems, Ltd." }, \
   { 233,   "Group3 Technology Ltd" }, \
   { 234,   "CTI Cryogenics" }, \
   { 235,   "POLSYS CORP" }, \
   { 236,   "Ampere Inc." }, \
   { 238,   "Simplatroll Ltd" }, \
   { 241,   "Leading Edge Design" }, \
   { 242,   "Humphrey Products" }, \
   { 243,   "Schneider Automation, Inc." }, \
   { 244,   "Westlock Controls Corp." }, \
   { 245,   "Nihon Weidmuller Co., Ltd" }, \
   { 246,   "Brooks Instrument (Div. of Emerson)" }, \
   { 248,   "Moeller GmbH" }, \
   { 249,   "Varian Vacuum Products" }, \
   { 250,   "Yokogawa Electric Corporation" }, \
   { 251,   "Electrical Design Daiyu Co., Ltd" }, \
   { 252,   "Omron Software Co., Ltd." }, \
   { 253,   "BOC Edwards" }, \
   { 254,   "Control Technology Corporation" }, \
   { 255,   "Bosch Rexroth (Bosch)" }, \
   { 256,   "InterlinkBT LLC" }, \
   { 257,   "Control Techniques PLC" }, \
   { 258,   "Hardy Instruments, Inc." }, \
   { 259,   "LG Industrial System Co., Ltd." }, \
   { 260,   "E.O.A. Systems Inc." }, \
   { 262,   "New Cosmos Electric Co., Ltd." }, \
   { 263,   "Sense Eletronica LTDA." }, \
   { 264,   "Xycom, Inc." }, \
   { 265,   "Baldor Electric" }, \
   { 267,   "Patlite Corporation" }, \
   { 269,   "Mogami Wire & Cable Corporation" }, \
   { 270,   "Welding Technology Corporation (WTC)" }, \
   { 272,   "Deutschmann Automation GmbH" }, \
   { 273,   "ICP Panel-Tec, Inc." }, \
   { 274,   "Bray Controls USA" }, \
   { 275,   "Lantronix, Inc." }, \
   { 276,   "Status Technologies" }, \
   { 278,   "Sherrex Systems Ltd" }, \
   { 279,   "Adept Technology, Inc." }, \
   { 280,   "Spang Power Electronics" }, \
   { 282,   "Acrosser Technology Co. Ltd" }, \
   { 283,   "Hilscher GmbH" }, \
   { 284,   "Imax Corporation" }, \
   { 285,   "Electronic Innovation, Inc.(Falter Engineering)" }, \
   { 286,   "Netlogic Inc." }, \
   { 287,   "Bosch Rexroth Corporation" }, \
   { 290,   "Murata Machinery, Ltd." }, \
   { 291,   "MTT Company Ltd." }, \
   { 292,   "Kanematsu Semiconductor Corp." }, \
   { 293,   "Takehishi Electric Sales Co." }, \
   { 294,   "Tokyo Electron Device Limited" }, \
   { 295,   "PFU Limited" }, \
   { 296,   "Hakko Automation Co., Ltd." }, \
   { 297,   "Advanet Inc." }, \
   { 298,   "Tokyo Electron Software Technologies Ltd." }, \
   { 300,   "Shinagawa Electric Wire Co. Ltd." }, \
   { 301,   "Yokogawa M&C Corporation" }, \
   { 302,   "KONAN Electric Co., Ltd" }, \
   { 303,   "Binar Elektronik AB" }, \
   { 304,   "The Furukawa Electric Co." }, \
   { 305,   "Cooper Energy Services" }, \
   { 306,   "Schleicher GmbH & Co." }, \
   { 307,   "Hirose Electric Co., Ltd" }, \
   { 308,   "Western Servo Design Inc." }, \
   { 309,   "Prosoft Technology" }, \
   { 311,   "Towa Shoko Co., Ltd" }, \
   { 312,   "Kyopal Co., Ltd" }, \
   { 313,   "Extron Co." }, \
   { 314,   "Wieland Electric GmbH" }, \
   { 315,   "SEW Eurodrive GmbH" }, \
   { 316,   "Aera Corporation" }, \
   { 317,   "STA Reutlingen" }, \
   { 319,   "Fuji Electric Co., Ltd." }, \
   { 322,   "ifm efector, inc." }, \
   { 324,   "IDEACOD-Hohner AUTOMATION S.A." }, \
   { 325,   "CommScope, Inc." }, \
   { 326,   "GE Fanuc Automation North America, Inc." }, \
   { 327,   "Matsushita Electric Industrial Co., Ltd" }, \
   { 328,   "Okaya Electronics Corporation" }, \
   { 329,   "KASHIYAMA Industries, Ltd." }, \
   { 330,   "JVC" }, \
   { 331,   "Interface Corporation" }, \
   { 332,   "Grape Systems Inc." }, \
   { 335,   "Toshiba IT & Control Systems Corporation" }, \
   { 336,   "Sanyo Machine Works, Ltd." }, \
   { 337,   "Vansco Electronics Ltd." }, \
   { 338,   "Dart Container Corp." }, \
   { 339,   "Livingston & Co., Inc." }, \
   { 340,   "Alfa Laval LKM as" }, \
   { 341,   "BF ENTRON Ltd. (British Federal)" }, \
   { 342,   "Bekaert Engineering NV" }, \
   { 343,   "Ferran  Scientific Inc." }, \
   { 344,   "KEBA AG" }, \
   { 345,   "Endress + Hauser" }, \
   { 346,   "The Lincoln Electric Company" }, \
   { 347,   "ABB ALSTOM Power UK Ltd. (EGT)" }, \
   { 348,   "Berger Lahr GmbH 3333" }, \
   { 350,   "Federal Signal Corporation" }, \
   { 351,   "Kawasaki Robotics (USA), Inc." }, \
   { 352,   "Bently Nevada Corporation" }, \
   { 353,   "JP Tech, Inc." }, \
   { 354,   "FRABA Posital GmbH" }, \
   { 355,   "Elsag Bailey, Inc." }, \
   { 356,   "Fanuc Robotics America" }, \
   { 358,   "Surface Combustion, Inc." }, \
   { 359,   "Redwood MicroSystems, Inc." }, \
   { 360,   "AILES Electronics Ind. Co, Ltd." }, \
   { 361,   "Wonderware Corporation" }, \
   { 362,   "Particle Measuring Systems, Inc." }, \
   { 365,   "BITS Co., Ltd" }, \
   { 366,   "Japan Aviation Electronics Industry Ltd" }, \
   { 367,   "Keyence Corporation" }, \
   { 368,   "Kuroda Precision Industries Ltd." }, \
   { 369,   "Mitsubishi Electric Semiconductor Application" }, \
   { 370,   "Nippon Seisen Cable, Ltd." }, \
   { 371,   "Omron ASO Co., Ltd" }, \
   { 372,   "Seiko Seiki Co., Ltd." }, \
   { 373,   "Sumitomo Heavy Industries, Ltd." }, \
   { 374,   "Tango Computer Service Corporation" }, \
   { 375,   "Technology Service, Inc." }, \
   { 376,   "Toshiba Information Systems (Japan) Corporation" }, \
   { 377,   "TOSHIBA Schneider Inverter Corporation" }, \
   { 378,   "Toyooki Kogyo Co., Ltd." }, \
   { 379,   "XEBEC" }, \
   { 380,   "Madison Cable Corporation" }, \
   { 381,   "Hitachi Engineering & Services Co., Ltd" }, \
   { 382,   "TEM-TECH Lab Co., Ltd" }, \
   { 383,   "International Laboratory Corporation" }, \
   { 384,   "Dyadic Systems Co., Ltd." }, \
   { 385,   "SETO Electronics Industry Co., Ltd" }, \
   { 386,   "Tokyo Electron Kyushu Limited" }, \
   { 387,   "KEI System Co., Ltd" }, \
   { 389,   "Asahi Engineering Co., Ltd" }, \
   { 390,   "Contrex Inc." }, \
   { 391,   "Paradigm Controls Ltd." }, \
   { 393,   "Ohm Electric Co., Ltd." }, \
   { 394,   "RKC Instrument Inc." }, \
   { 395,   "Suzuki Motor Corporation" }, \
   { 396,   "Custom Servo Motors Inc." }, \
   { 397,   "PACE Control Systems" }, \
   { 400,   "LINTEC Co., Ltd" }, \
   { 401,   "Hitachi Cable Ltd." }, \
   { 402,   "BUSWARE Direct" }, \
   { 403,   "Holec Holland N.V." }, \
   { 404,   "VAT Vakuumventile AG" }, \
   { 405,   "Scientific Technologies, Inc." }, \
   { 406,   "Alfa Instrumentos Eletronicos Ltda" }, \
   { 407,   "TWK Elektronik GmbH" }, \
   { 408,   "ABB Welding Systems AB" }, \
   { 409,   "Bystronic Maschinen AG" }, \
   { 410,   "Kimura Electric Co., Ltd" }, \
   { 411,   "Nissei Plastic Industrial Co., Ltd" }, \
   { 412,   "Hitachi Naka Electronics Co. Ltd." }, \
   { 413,   "Kistler-Morse Corporation" }, \
   { 414,   "Proteus Industries Inc." }, \
   { 415,   "IDC Corporation" }, \
   { 416,   "Nordson Corporation" }, \
   { 417,   "Rapistan Systems" }, \
   { 418,   "LP-Elektronik GmbH" }, \
   { 419,   "GERBI & FASE S.p.A (Fase Saldatura)" }, \
   { 420,   "Phoenix Digital Corporation" }, \
   { 421,   "Z-World Engineering" }, \
   { 422,   "Honda R&D Co., Ltd." }, \
   { 423,   "Bionics Instrument Co., Ltd." }, \
   { 424,   "Teknic, Inc." }, \
   { 425,   "R. Stahl, Inc." }, \
   { 427,   "Ryco Graphic Manufacturing Inc." }, \
   { 428,   "Giddings & Lewis, Inc." }, \
   { 429,   "Koganei Corporation" }, \
   { 431,   "Nichigoh Communication Electric Wire Co., Ltd." }, \
   { 433,   "Fujikura Ltd." }, \
   { 434,   "AD Link Technology Inc." }, \
   { 435,   "StoneL Corp." }, \
   { 436,   "Computer Optical Products, Inc." }, \
   { 437,   "CONOS Inc." }, \
   { 438,   "Erhardt + Leimer GmbH" }, \
   { 439,   "UNIQUE Co. Ltd." }, \
   { 440,   "Roboticsware, Inc." }, \
   { 441,   "Nachi Fujikoshi Corporation" }, \
   { 442,   "Hengstler GmbH" }, \
   { 444,   "SUNNY GIKEN Inc." }, \
   { 445,   "Lenze" }, \
   { 446,   "CD Systems B.V." }, \
   { 447,   "FMT/Aircraft Gate Support Systems AB" }, \
   { 448,   "Axiomatic Technologies Corporation" }, \
   { 449,   "Embedded System Products, Inc." }, \
   { 450,   "AMC Technologies Corporation" }, \
   { 451,   "Mencom Corporation" }, \
   { 452,   "Danaher Motion/Kollmorgen" }, \
   { 453,   "Matsushita Welding Systems Co., Ltd." }, \
   { 454,   "Dengensha Mfg. Co. Ltd." }, \
   { 455,   "Quin Systems Ltd" }, \
   { 456,   "Tellima Technology Ltd" }, \
   { 457,   "MDT, Software" }, \
   { 458,   "Taiwan Keiso Co., Ltd" }, \
   { 459,   "Pinnacle Systems" }, \
   { 460,   "Ascom Hasler Mailing Sys" }, \
   { 461,   "INSTRUMAR Limited" }, \
   { 463,   "Navistar International Transportation Corp" }, \
   { 464,   "Huettinger Elektronik GmbH + Co. KG" }, \
   { 465,   "OCM Technology Inc." }, \
   { 466,   "Professional Supply Inc." }, \
   { 467,   "Control Solutions" }, \
   { 468,   "IVO GmbH & Co." }, \
   { 469,   "Worcester Controls Corporation" }, \
   { 470,   "Pyramid Technical Consultants, Inc." }, \
   { 471,   "Eilersen Electric A/S" }, \
   { 472,   "Apollo Fire Detectors Limited" }, \
   { 473,   "Avtron Manufacturing, Inc." }, \
   { 475,   "Tokyo Keiso Co., Ltd." }, \
   { 476,   "Daishowa Swiki Co., Ltd." }, \
   { 477,   "Kojima Instruments Inc." }, \
   { 478,   "Shimadzu Corporation" }, \
   { 479,   "Tatsuta Electric Wire & Cable Co., Ltd." }, \
   { 480,   "MECS Corporation" }, \
   { 481,   "Tahara Electric" }, \
   { 482,   "Koyo Electronics" }, \
   { 483,   "Clever Devices" }, \
   { 484,   "GCD Hardware & Software GmbH" }, \
   { 486,   "Miller Electric Mfg Co." }, \
   { 487,   "GEA Tuchenhagen GmbH" }, \
   { 488,   "Riken Keiki Co., Ltd." }, \
   { 489,   "Keisokugiken Corporation" }, \
   { 490,   "Fuji Machine Mfg. Co., Ltd" }, \
   { 492,   "Nidec-Shimpo Corp." }, \
   { 493,   "UTEC Corporation" }, \
   { 494,   "SANYO Electric Co. Ltd." }, \
   { 497,   "Okano Electric Wire Co. Ltd" }, \
   { 498,   "Shimaden Co. Ltd." }, \
   { 499,   "Teddington Controls Ltd" }, \
   { 500,   "Control Logic Inc." }, \
   { 501,   "VIPA GmbH" }, \
   { 502,   "Warwick Manufacturing Group" }, \
   { 503,   "Danaher Controls" }, \
   { 506,   "American Science & Engineering" }, \
   { 507,   "Accutron Technologies Inc." }, \
   { 508,   "Norcott Technologies Ltd" }, \
   { 509,   "T.B. Wood's, Incorporated" }, \
   { 510,   "Proportion-Air, Inc." }, \
   { 511,   "Max Stegmann GmbH" }, \
   { 513,   "Edwards Signaling" }, \
   { 514,   "Sumitomo Metal Industries, Ltd" }, \
   { 515,   "Cosmo Instruments Co., Ltd." }, \
   { 516,   "Denshosha Co., Ltd." }, \
   { 517,   "Kaijo Corp." }, \
   { 518,   "Michiproducts Co., Ltd." }, \
   { 519,   "Miura Corporation" }, \
   { 520,   "TG Information Network Co., Ltd." }, \
   { 521,   "Fujikin , Inc." }, \
   { 522,   "Estic Corp." }, \
   { 523,   "GS Hydraulic Sales" }, \
   { 525,   "MTE Limited" }, \
   { 526,   "Hyde Park Electronics, Inc." }, \
   { 527,   "Pfeiffer Vacuum GmbH" }, \
   { 528,   "Cyberlogic Technologies" }, \
   { 529,   "OKUMA Corporation FA System Division" }, \
   { 530,   "NSK Precision Co., Ltd." }, \
   { 531,   "Hitachi Kokusai Electric Co., Ltd." }, \
   { 532,   "Shinko Technos Co. Ltd." }, \
   { 533,   "Itoh Electric Co., Ltd." }, \
   { 534,   "Colorado Flow Tech Inc." }, \
   { 535,   "Love Controls Division/Dwyer Instruments" }, \
   { 536,   "Alstom Drives and Controls" }, \
   { 537,   "The Foxboro Company" }, \
   { 538,   "Tescom Corporation" }, \
   { 540,   "Atlas Copco Controls UK" }, \
   { 542,   "Autojet Technologies" }, \
   { 543,   "Prima Electronics S.p.A." }, \
   { 544,   "PMA GmbH" }, \
   { 545,   "Shimafuji Electric Co., Ltd" }, \
   { 546,   "Oki Electric Industry Co., Ltd" }, \
   { 547,   "Kyushu Matsushita Electric Co., Ltd" }, \
   { 548,   "Nihon Electric Wire & Cable Co., Ltd" }, \
   { 549,   "Tsuken Electric Ind Co., Ltd" }, \
   { 550,   "Tamadic Co." }, \
   { 551,   "MAATEL SA" }, \
   { 552,   "OKUMA America" }, \
   { 553,   "Control Techniques PLC-NA" }, \
   { 554,   "TPC Wire & Cable" }, \
   { 555,   "ATI Industrial Automation" }, \
   { 556,   "Microcontrol (Australia) Pty Ltd" }, \
   { 557,   "Serra Soldadura, S.A." }, \
   { 558,   "Southwest Research Institute" }, \
   { 559,   "Cabinplant International" }, \
   { 560,   "GWT/Global Weighing Technologies GmbH" }, \
   { 561,   "Comau Robotics & Final Assembly" }, \
   { 562,   "Phoenix Contact" }, \
   { 563,   "Yokogawa MAT Corporation" }, \
   { 564,   "asahi sangyo co., ltd." }, \
   { 566,   "Akita Myotoku Ltd." }, \
   { 567,   "OBARA Corp." }, \
   { 568,   "Suetron Electronic GmbH" }, \
   { 570,   "Serck Controls Limited" }, \
   { 571,   "Fairchild Industrial Products Company" }, \
   { 572,   "ARO Controls S.A.S." }, \
   { 573,   "M2C GmbH" }, \
   { 574,   "Shin Caterpillar Mitsubishi Ltd." }, \
   { 575,   "Santest Co., Ltd." }, \
   { 576,   "Cosmotechs Co., Ltd." }, \
   { 577,   "Hitachi Electric Systems" }, \
   { 578,   "Smartscan Ltd" }, \
   { 579,   "Applicom international" }, \
   { 580,   "Athena Controls Incorporated" }, \
   { 581,   "Syron Engineering & Manufacturing, Inc." }, \
   { 582,   "Asahi Optical Co., Ltd." }, \
   { 583,   "Sansha Electric Mfg. Co.,Ltd." }, \
   { 584,   "Nikki Denso Co., Ltd." }, \
   { 585,   "Star Micronics, Co., Ltd." }, \
   { 586,   "Ecotecnia Socirtat Corp." }, \
   { 587,   "AC Technology Corp" }, \
   { 588,   "West Instruments Limited" }, \
   { 589,   "NTI Limited" }, \
   { 590,   "Delta Computer Systems Inc." }, \
   { 591,   "FANUC Ltd." }, \
   { 592,   "HEARN-GU LEE" }, \
   { 593,   "ABB Automation Products" }, \
   { 594,   "Orion Machinery Co., Ltd." }, \
   { 596,   "Wire-Pro, Inc." }, \
   { 597,   "Beijing Huakong Technology Co. Ltd." }, \
   { 598,   "Yokoyama Shokai Co., Ltd." }, \
   { 599,   "Toyogiken Co., Ltd." }, \
   { 600,   "Coester Equipamentos Eletronicos Ltda." }, \
   { 601,   "Kawasaki Heavy Industries, Ltd." }, \
   { 602,   "Electroplating Engineers of Japan Ltd." }, \
   { 603,   "Robox S.p.a." }, \
   { 604,   "Spraying Systems Company" }, \
   { 605,   "Benshaw Inc." }, \
   { 606,   "ZPA-DP A.S." }, \
   { 607,   "Wired Rite Systems" }, \
   { 608,   "Tandis Research, Inc." }, \
   { 609,   "Eurotherm Antriebstechnik GmbH" }, \
   { 610,   "ULVAC, Inc." }, \
   { 611,   "DYNAX Corporation" }, \
   { 612,   "Nor-Cal Products, Inc." }, \
   { 613,   "Aros Electronics AB" }, \
   { 614,   "Jun-Tech Co., Ltd." }, \
   { 615,   "HAN-MI Co. Ltd." }, \
   { 616,   "SungGi Internet Co.,  Ltd." }, \
   { 617,   "Hae Pyung Electronics Research Institute" }, \
   { 618,   "Milwaukee Electronics" }, \
   { 619,   "OBERG Industries" }, \
   { 620,   "Parker Hannifin/Compumotor Division" }, \
   { 621,   "TECHNO DIGITAL CORPORATION" }, \
   { 622,   "network supply Co., Ltd." }, \
   { 623,   "Union Electronics Co., Ltd." }, \
   { 624,   "Tritronics Services PM Ltd." }, \
   { 625,   "Rockwell Automation/Sprecher+Schuh" }, \
   { 626,   "Matsushita Electric Industrial Co., Ltd/Motor Co." }, \
   { 627,   "Rolls-Royce Energy Systems, Inc." }, \
   { 628,   "JEONGIL INTERCOM CO., LTD" }, \
   { 629,   "Interroll Corp." }, \
   { 630,   "Hubbell Wiring Device-Kellems (Delaware)" }, \
   { 631,   "Intelligent Motion Systems" }, \
   { 632,   "Shanghai Aton Electric Co., Ltd" }, \
   { 633,   "INFICON AG" }, \
   { 634,   "Hirschmann, Inc." }, \
   { 635,   "The Siemon Company" }, \
   { 636,   "YAMAHA Motor Co. Ltd." }, \
   { 637,   "aska corporation" }, \
   { 638,   "Woodhead Connectivity" }, \
   { 639,   "Trimble AB" }, \
   { 640,   "Murrelektronik GmbH" }, \
   { 641,   "Creatrix Labs, Inc." }, \
   { 642,   "TopWorx" }, \
   { 643,   "Kumho Industrial Co., Ltd." }, \
   { 644,   "Wind River Systems, Inc." }, \
   { 645,   "Bihl & Wiedemann GmbH" }, \
   { 646,   "Harmonic Drive Systems Inc." }, \
   { 647,   "Rikei Corporation" }, \
   { 648,   "BL Autotec, Ltd." }, \
   { 649,   "HANA Information Technology Co., Ltd." }, \
   { 650,   "Seoil Electric Co., Ltd." }, \
   { 651,   "Fife Corporation" }, \
   { 652,   "Shanghai Electrical Apparatus Research Institute" }, \
   { 653,   "UniControls as" }, \
   { 654,   "Parasense Development Centre" }, \
   { 657,   "Six Tau SpA" }, \
   { 658,   "Aucos GmbH" }, \
   { 659,   "Rotork Controls Ltd." }, \
   { 660,   "Automationdirect.com" }, \
   { 661,   "Thermo BLH" }, \
   { 662,   "System Controls, Limited" }, \
   { 663,   "Univer S.p.A." }, \
   { 664,   "MKS - Tenta Technology" }, \
   { 665,   "Lika Electronic SNC" }, \
   { 666,   "Mettler-Toledo" }, \
   { 667,   "DXL USA, Inc." }, \
   { 668,   "Rockwell Automation/Entek IRD Intl." }, \
   { 669,   "Nippon Otis Elevator Company" }, \
   { 670,   "Sinano Electric, Co., Ltd." }, \
   { 673,   "CONTEC CO., LTD." }, \
   { 674,   "Automated Solutions" }, \
   { 675,   "Controlweigh" }, \
   { 676,   "SICK AG" }, \
   { 677,   "Fincor Electronics" }, \
   { 678,   "Cognex Corporation" }, \
   { 679,   "Qualiflow" }, \
   { 680,   "Weidmuller Inc." }, \
   { 681,   "Morinaga Milk Industry Co., Ltd." }, \
   { 682,   "Takagi Industrial Co., Ltd." }, \
   { 683,   "Wittenstein AG" }, \
   { 684,   "Sena Technologies, Inc." }, \
   { 685,   "Marathon Ltd." }, \
   { 686,   "APV Products Unna" }, \
   { 687,   "Creator Teknisk Utvedkling AB" }, \
   { 689,   "Mibu Denki Industrial Co., Ltd." }, \
   { 690,   "Takamatsu Machineer Section" }, \
   { 691,   "Startco Engineering Ltd." }, \
   { 693,   "Holjeron" }, \
   { 694,   "ALCATEL High Vacuum Technology" }, \
   { 695,   "Taesan LCD Co., Ltd." }, \
   { 696,   "POSCON" }, \
   { 697,   "VMIC" }, \
   { 698,   "Matsushita Electric Works, Ltd." }, \
   { 699,   "IAI Corporation" }, \
   { 700,   "Horst GmbH" }, \
   { 701,   "MicroControl GmbH & Co." }, \
   { 702,   "Leine & Linde AB" }, \
   { 703,   "Hastings Instruments" }, \
   { 704,   "EC Elettronica Srl" }, \
   { 705,   "VIT Software HB" }, \
   { 706,   "Bronkhorst High-Tech B.V." }, \
   { 707,   "Optex Co.,Ltd." }, \
   { 708,   "Yosio Electronic Co." }, \
   { 709,   "Terasaki Electric Co., Ltd." }, \
   { 710,   "Sodick Co., Ltd." }, \
   { 711,   "MTS Systems Corporation-Automation Division" }, \
   { 712,   "Mesa Systemtechnik" }, \
   { 713,   "SHIN HO SYSTEM Co., Ltd." }, \
   { 714,   "Kokusai Denki Engineering Co., Ltd." }, \
   { 715,   "Loreme" }, \
   { 716,   "SAB Brockskes GmbH & Co. KG" }, \
   { 717,   "Trumpf Laser GmbH + Co. KG" }, \
   { 718,   "Niigata Electronic Instruments Co., Ltd." }, \
   { 719,   "Yokogawa Digital Computer Corporation" }, \
   { 720,   "O.N. Electronic Co., Ltd." }, \
   { 721,   "Industrial Control Communication, Inc." }, \
   { 722,   "ABB Inc. (Elsag Bailey)" }, \
   { 723,   "Electrowave USA, Inc." }, \
   { 724,   "Industrial Network Controls, LLC" }, \
   { 725,   "KDT Systems Co., Ltd." }, \
   { 726,   "SEFA Technology Inc." }, \
   { 727,   "Nippon POP Rivets and Fasteners Ltd." }, \
   { 728,   "Yamato Scale Co., Ltd." }, \
   { 729,   "Zener Electric" }, \
   { 730,   "GSE Scale Systems" }, \
   { 731,   "ISAS (Integrated Switchgear & Sys. Pty Ltd)" }, \
   { 732,   "Beta LaserMike Limited" }, \
   { 733,   "TOEI Electric Co., Ltd." }, \
   { 734,   "Hakko Electronics Co., Ltd" }, \
   { 735,   "Tang & Associates" }, \
   { 736,   "RFID, Inc." }, \
   { 737,   "Adwin Corporation" }, \
   { 738,   "Osaka Vacuum, Ltd." }, \
   { 739,   "A-Kyung Motion, Inc." }, \
   { 740,   "Camozzi S.P. A." }, \
   { 741,   "Crevis Co., LTD" }, \
   { 742,   "Rice Lake Weighing Systems" }, \
   { 743,   "Linux Network Services" }, \
   { 744,   "KEB Antriebstechnik GmbH" }, \
   { 745,   "Hagiwara Electric Co., Ltd." }, \
   { 746,   "Glass Inc. International" }, \
   { 748,   "DVT Corporation" }, \
   { 749,   "Woodward Governor" }, \
   { 750,   "Mosaic Systems, Inc." }, \
   { 751,   "Laserline GmbH" }, \
   { 752,   "COM-TEC, Inc." }, \
   { 754,   "Prof-face European Technology Center" }, \
   { 755,   "Fuji Automation Co.,Ltd." }, \
   { 756,   "Matsutame Co., Ltd." }, \
   { 757,   "Hitachi Via Mechanics, Ltd." }, \
   { 758,   "Dainippon Screen Mfg. Co. Ltd." }, \
   { 759,   "FLS Automation A/S" }, \
   { 760,   "ABB Stotz Kontakt GmbH" }, \
   { 761,   "Technical Marine Service" }, \
   { 762,   "Advanced Automation Associates, Inc." }, \
   { 763,   "Baumer Ident GmbH" }, \
   { 764,   "Tsubaki Emerson Co." }, \
   { 766,   "Furukawa Co.,Ltd." }, \
   { 767,   "Active Power" }, \
   { 768,   "CSIRO Mining Automation" }, \
   { 769,   "Matrix Integrated Systems" }, \
   { 770,   "Digitronic Automationsanlagen GmbH" }, \
   { 771,   "Stegmann, Inc." }, \
   { 772,   "TAE-Antriebstechnik GmbH" }, \
   { 773,   "Electronic Solutions" }, \
   { 774,   "Rocon L.L.C." }, \
   { 775,   "Dijitized Communications Inc." }, \
   { 776,   "Asahi Organic Chemicals Industry Co.,Ltd." }, \
   { 777,   "Hodensha" }, \
   { 778,   "Harting, Inc. NA" }, \
   { 779,   "Kuebler GmbH" }, \
   { 780,   "Yamatake Corporation" }, \
   { 781,   "JOEL" }, \
   { 782,   "Yamatake Industrial Systems Co.,Ltd." }, \
   { 783,   "HAEHNE Elektronische Messgerate GmbH" }, \
   { 784,   "Ci Technologies Pty Ltd (for Pelamos Industries)" }, \
   { 785,   "N. SCHLUMBERGER" }, \
   { 786,   "Teijin Seiki Co., Ltd." }, \
   { 787,   "DAIKIN Industries, Ltd" }, \
   { 788,   "RyuSyo Industrial Co., Ltd." }, \
   { 789,   "SAGINOMIYA SEISAKUSHO, INC." }, \
   { 790,   "Seishin Engineering Co., Ltd." }, \
   { 791,   "Japan Support System Ltd." }, \
   { 792,   "Decsys" }, \
   { 793,   "Metronix Messgerate u. Elektronik GmbH" }, \
   { 795,   "Vaccon Company, Inc." }, \
   { 796,   "Siemens Energy & Automation, Inc." }, \
   { 797,   "Ten X Technology, Inc." }, \
   { 798,   "Tyco Electronics" }, \
   { 799,   "Delta Power Electronics Center" }, \
   { 800,   "Denker" }, \
   { 801,   "Autonics Corporation" }, \
   { 802,   "JFE Electronic Engineering Pty. Ltd." }, \
   { 803,   "ICP DAS Co., LTD" }, \
   { 804,   "Electro-Sensors, Inc." }, \
   { 805,   "Digi International, Inc." }, \
   { 806,   "Texas Instruments" }, \
   { 807,   "ADTEC Plasma Technology Co., Ltd" }, \
   { 808,   "SICK AG" }, \
   { 809,   "Ethernet Peripherals, Inc." }, \
   { 810,   "Animatics Corporation" }, \
   { 811,   "Partlow" }, \
   { 812,   "Process Control Corporation" }, \
   { 813,   "SystemV. Inc." }, \
   { 814,   "Danaher Motion SRL" }, \
   { 815,   "SHINKAWA Sensor Technology, Inc." }, \
   { 816,   "Tesch GmbH & Co. KG" }, \
   { 817,   "Advance Electric Company, Inc." }, \
   { 818,   "Trend Controls Systems Ltd." }, \
   { 819,   "Guangzhou ZHIYUAN Electronic Co., Ltd." }, \
   { 820,   "Mykrolis Corporation" }, \
   { 821,   "Bethlehem Steel Corporation" }, \
   { 822,   "KK ICP" }, \
   { 823,   "Takemoto Denki Corporation" }, \
   { 824,   "The Montalvo Corporation" }, \
   { 825,   "General Controls Sistemas Ltd." }, \
   { 826,   "LEONI Special Cables GmbH" }, \
   { 828,   "ONO SOKKI CO.,LTD." }, \
   { 829,   "Rockwell Samsung Automation" }, \
   { 830,   "Shindengen Electric Mfg. Co. Ltd." }, \
   { 831,   "Origin Electric Co. Ltd" }, \
   { 832,   "Quest Technical Solutions, Inc." }, \
   { 833,   "LG Cable Ltd." }, \
   { 834,   "Enercon-Nord Electronic GmbH" }, \
   { 835,   "Northwire Inc." }, \
   { 836,   "Engel Elektroantriebe GmbH" }, \
   { 837,   "The Stanley Works" }, \
   { 838,   "Celesco Transducer Products, Inc." }, \
   { 839,   "Chugoku Electric Wire and Cable Co." }, \
   { 840,   "Kongsberg Simrad AS" }, \
   { 841,   "Panduit Corporation" }, \
   { 842,   "Spellman High Voltage Electronics Corporation" }, \
   { 843,   "Kokusai Electric Alpha Co., Ltd." }, \
   { 844,   "Brooks Automation, Inc." }, \
   { 845,   "ANYWIRE CORPORATION" }, \
   { 846,   "Honda Electronics Co. Ltd" }, \
   { 847,   "REO Elektronik AG" }, \
   { 848,   "Fusion UV Systems, Inc." }, \
   { 849,   "ASI Advanced Semiconductor Instruments GmbH" }, \
   { 850,   "Datalogic, Inc." }, \
   { 851,   "SoftPLC Corporation" }, \
   { 852,   "Dynisco Instruments LLC" }, \
   { 853,   "WEG Industrias SA" }, \
   { 854,   "Frontline Test Equipment, Inc." }, \
   { 855,   "Tamagawa Seiki Co Ltd" }, \
   { 856,   "Multi Computing Co., Ltd." }, \
   { 857,   "RVSI" }, \
   { 858,   "Commercial Timesharing Inc." }, \
   { 859,   "Tennessee Rand Automation" }, \
   { 860,   "Wacogiken Co., Ltd" }, \
   { 861,   "Reflex Integration Inc." }, \
   { 862,   "Siemens AG, A&D PI Flow Instruments" }, \
   { 863,   "G. Bachmann Electronik GmbH" }, \
   { 864,   "NT International" }, \
   { 865,   "Schweitzer Engineering Laboratories" }, \
   { 866,   "ATR Industrie-Elektronik GmbH Co." }, \
   { 867,   "PLASMATECH CO. LTD" }, \
   { 868,   "Unaxis USA Inc." }, \
   { 869,   "GEMU GmbH & Co. KG" }, \
   { 870,   "Alcorn McBride Inc." }, \
   { 871,   "MORI SEIKI CO., LTD" }, \
   { 872,   "NodeTech Systems Ltd." }, \
   { 873,   "Emhart Teknologies" }, \
   { 874,   "Cervis, Inc." }, \
   { 875,   "FieldServer Technologies (Div Sierra Monitor Corp)" }, \
   { 876,   "NEDAP Power Supplies" }, \
   { 877,   "Nippon Sanso Corporation" }, \
   { 878,   "Mitomi Giken Co. Ltd." }, \
   { 879,   "PULS GmbH " }, \
   { 880,   "Elotech Industrieelektronik GmbH" }, \
   { 881,   "Japan Control Engineering Co Ltd" }, \
   { 882,   "Zues Emtek Co Ltd" }, \
   { 883,   "Automa SRL" }, \
   { 884,   "Harms+Wende GmbH & Co KG" }, \
   { 887,   "Bernecker + Rainer Industrie-Elektronik GmbH" }, \
   { 888,   "Hiprom (Pty) Ltd." }, \
   { 889,   "Agilicom" }, \
   { 890,   "Nitta Corporation" }, \
   { 891,   "Kontron Modular Computers GmbH" }, \
   { 892,   "Marlin Control" }, \
   { 893,   "ELCIS srl" }, \
   { 895,   "Avery Weigh-Tronix" }, \
   { 896,   "Vital Systems Inc." }, \
   { 897,   "Draka USA" }, \
   { 899,   "Practicon Ltd" }, \
   { 900,   "Schunk GmbH & Co. KG" }, \
   { 902,   "Defontaine Groupe" }, \
   { 903,   "Emerson Process Management Power & Water Solutions" },


/*
** Exported variables
*/

extern const value_string cip_devtype_vals[];
extern const value_string cip_vendor_vals[];
