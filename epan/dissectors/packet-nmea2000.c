/* packet-nmea2000.c
 * Routines for NMEA 2000 dissection
 * Copyright 2025, Anders Broman <a.broman58@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * NMEA 2000, abbreviated to NMEA2k or N2K and standardized as IEC 61162-3,
 * is a plug-and-play communications standard used for connecting marine sensors
 * and display units within ships and boats.
 * The standard is maintaned by the National Marine Electronics Association (NMEA).
 * https://en.wikipedia.org/wiki/NMEA_2000
 * https://canboat.github.io/canboat/canboat.html
 * https://github.com/fkie-cad/maritime-dissector/tree/master
 *
 * Relies on the J1939 dissector to dissect CAN messages.
 */

#include "config.h"
#include <wireshark.h>

#include <epan/packet.h>
#include <epan/reassemble.h>

 /* Define the name for the logging domain (try to avoid collisions with existing domains) */
#define WS_LOG_DOMAIN "packet-nmea2000"


/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_nmea2000(void);
void proto_register_nmea2000(void);

/* Initialize the protocol and registered fields */
static int proto_nmea2000;
static int hf_nmea2000_seq;
static int hf_nmea2000_f_cnt;
static int hf_nmea2000_num_bytes;
static int hf_nmea2000_version;
static int hf_nmea2000_prod_code;
static int hf_nmea2000_model_id;
static int hf_nmea2000_sw_ver_code;
static int hf_nmea2000_model_ver;
static int hf_nmea2000_model_ser_code;
static int hf_nmea2000_cert_lev;
static int hf_nmea2000_load_eq;

static int hf_nmea2000_man_code;
static int hf_nmea2000_reserved_b4b3;
static int hf_nmea2000_ind_code;
static int hf_nmea2000_reserved16;
static int hf_nmea2000_ap_mode;
static int hf_nmea2000_reserved8;
static int hf_nmea2000_angle;

static dissector_handle_t nmea2000_handle;

/* Initialize the subtree pointers */
static int ett_nmea2000;
static int ett_nmea2000_fragment;
static int ett_nmea2000_fragments;

static reassembly_table nmea2000_reassembly_table;

/*
* Fast Message fragment handling
*/
static int hf_nmea2000_fragments;
static int hf_nmea2000_fragment;
static int hf_nmea2000_fragment_overlap;
static int hf_nmea2000_fragment_overlap_conflicts;
static int hf_nmea2000_fragment_multiple_tails;
static int hf_nmea2000_fragment_too_long_fragment;
static int hf_nmea2000_fragment_error;
static int hf_nmea2000_fragment_count;
static int hf_nmea2000_reassembled_in;
static int hf_nmea2000_reassembled_length;

static const fragment_items nmea2000_frag_items = {
    /* Fragment subtrees */
    &ett_nmea2000_fragment,
    &ett_nmea2000_fragments,
    /* Fragment fields */
    &hf_nmea2000_fragments,
    &hf_nmea2000_fragment,
    &hf_nmea2000_fragment_overlap,
    &hf_nmea2000_fragment_overlap_conflicts,
    &hf_nmea2000_fragment_multiple_tails,
    &hf_nmea2000_fragment_too_long_fragment,
    &hf_nmea2000_fragment_error,
    &hf_nmea2000_fragment_count,
    /* Reassembled in field */
    &hf_nmea2000_reassembled_in,
    /* Reassembled length field */
    &hf_nmea2000_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Fast Message fragments"
};

#define NMEA2000_PGN_126996 126996

/* MANUFACTURER_CODE (0 - 2047) */


static const value_string nmea2000_manufacturer_code_vals[] = {
    { 69, "ARKS Enterprises, Inc." },
    { 78, "FW Murphy/Enovation Controls" },
    { 80, "Twin Disc" },
    { 85, "Kohler Power Systems" },
    { 88, "Hemisphere GPS Inc" },
    { 116, "BEP Marine" },
    { 135, "Airmar" },
    { 137, "Maretron" },
    { 140, "Lowrance" },
    { 144, "Mercury Marine" },
    { 147, "Nautibus Electronic GmbH" },
    { 148, "Blue Water Data" },
    { 154, "Westerbeke" },
    { 157, "ISSPRO Inc" },
    { 161, "Offshore Systems (UK) Ltd." },
    { 163, "Evinrude/BRP" },
    { 165, "CPAC Systems AB" },
    { 168, "Xantrex Technology Inc." },
    { 169, "Marlin Technologies, Inc." },
    { 172, "Yanmar Marine" },
    { 174, "Volvo Penta" },
    { 175, "Honda Marine" },
    { 176, "Carling Technologies Inc. (Moritz Aerospace)" },
    { 185, "Beede Instruments" },
    { 192, "Floscan Instrument Co. Inc." },
    { 193, "Nobletec" },
    { 198, "Mystic Valley Communications" },
    { 199, "Actia" },
    { 200, "Honda Marine" },
    { 201, "Disenos Y Technologia" },
    { 211, "Digital Switching Systems" },
    { 215, "Xintex/Atena" },
    { 224, "EMMI NETWORK S.L." },
    { 225, "Honda Marine" },
    { 228, "ZF" },
    { 229, "Garmin" },
    { 233, "Yacht Monitoring Solutions" },
    { 235, "Sailormade Marine Telemetry/Tetra Technology LTD" },
    { 243, "Eride" },
    { 250, "Honda Marine" },
    { 257, "Honda Motor Company LTD" },
    { 272, "Groco" },
    { 273, "Actisense" },
    { 274, "Amphenol LTW Technology" },
    { 275, "Navico" },
    { 283, "Hamilton Jet" },
    { 285, "Sea Recovery" },
    { 286, "Coelmo SRL Italy" },
    { 295, "BEP Marine" },
    { 304, "Empir Bus" },
    { 305, "NovAtel" },
    { 306, "Sleipner Motor AS" },
    { 307, "MBW Technologies" },
    { 311, "Fischer Panda" },
    { 315, "ICOM" },
    { 328, "Qwerty" },
    { 329, "Dief" },
    { 341, "Boening Automationstechnologie GmbH & Co. KG" },
    { 345, "Korean Maritime University" },
    { 351, "Thrane and Thrane" },
    { 355, "Mastervolt" },
    { 356, "Fischer Panda Generators" },
    { 358, "Victron Energy" },
    { 370, "Rolls Royce Marine" },
    { 373, "Electronic Design" },
    { 374, "Northern Lights" },
    { 378, "Glendinning" },
    { 381, "B & G" },
    { 384, "Rose Point Navigation Systems" },
    { 385, "Johnson Outdoors Marine Electronics Inc Geonav" },
    { 394, "Capi 2" },
    { 396, "Beyond Measure" },
    { 400, "Livorsi Marine" },
    { 404, "ComNav" },
    { 409, "Chetco" },
    { 419, "Fusion Electronics" },
    { 421, "Standard Horizon" },
    { 422, "True Heading AB" },
    { 426, "Egersund Marine Electronics AS" },
    { 427, "em-trak Marine Electronics" },
    { 431, "Tohatsu Co, JP" },
    { 437, "Digital Yacht" },
    { 438, "Comar Systems Limited" },
    { 440, "Cummins" },
    { 443, "VDO (aka Continental-Corporation)" },
    { 451, "Parker Hannifin aka Village Marine Tech" },
    { 459, "Alltek Marine Electronics Corp" },
    { 460, "SAN GIORGIO S.E.I.N" },
    { 466, "Veethree Electronics & Marine" },
    { 467, "Humminbird Marine Electronics" },
    { 470, "SI-TEX Marine Electronics" },
    { 471, "Sea Cross Marine AB" },
    { 475, "GME aka Standard Communications Pty LTD" },
    { 476, "Humminbird Marine Electronics" },
    { 478, "Ocean Sat BV" },
    { 481, "Chetco Digitial Instruments" },
    { 493, "Watcheye" },
    { 499, "Lcj Capteurs" },
    { 502, "Attwood Marine" },
    { 503, "Naviop S.R.L." },
    { 504, "Vesper Marine Ltd" },
    { 510, "Marinesoft Co. LTD" },
    { 513, "Simarine" },
    { 517, "NoLand Engineering" },
    { 518, "Transas USA" },
    { 529, "National Instruments Korea" },
    { 530, "National Marine Electronics Association" },
    { 532, "Onwa Marine" },
    { 540, "Webasto" },
    { 571, "Marinecraft (South Korea)" },
    { 573, "McMurdo Group aka Orolia LTD" },
    { 578, "Advansea" },
    { 579, "KVH" },
    { 580, "San Jose Technology" },
    { 583, "Yacht Control" },
    { 586, "Suzuki Motor Corporation" },
    { 591, "US Coast Guard" },
    { 595, "Ship Module aka Customware" },
    { 600, "Aquatic AV" },
    { 605, "Aventics GmbH" },
    { 606, "Intellian" },
    { 612, "SamwonIT" },
    { 614, "Arlt Tecnologies" },
    { 637, "Bavaria Yacts" },
    { 641, "Diverse Yacht Services" },
    { 644, "Wema U.S.A dba KUS" },
    { 645, "Garmin" },
    { 658, "Shenzhen Jiuzhou Himunication" },
    { 688, "Rockford Corp" },
    { 699, "Harman International" },
    { 704, "JL Audio" },
    { 708, "Lars Thrane" },
    { 715, "Autonnic" },
    { 717, "Yacht Devices" },
    { 734, "REAP Systems" },
    { 735, "Au Electronics Group" },
    { 739, "LxNav" },
    { 741, "Littelfuse, Inc (formerly Carling Technologies)" },
    { 743, "DaeMyung" },
    { 744, "Woosung" },
    { 748, "ISOTTA IFRA srl" },
    { 773, "Clarion US" },
    { 776, "HMI Systems" },
    { 777, "Ocean Signal" },
    { 778, "Seekeeper" },
    { 781, "Poly Planar" },
    { 785, "Fischer Panda DE" },
    { 795, "Broyda Industries" },
    { 796, "Canadian Automotive" },
    { 797, "Tides Marine" },
    { 798, "Lumishore" },
    { 799, "Still Water Designs and Audio" },
    { 802, "BJ Technologies (Beneteau)" },
    { 803, "Gill Sensors" },
    { 811, "Blue Water Desalination" },
    { 815, "FLIR" },
    { 824, "Undheim Systems" },
    { 826, "Lewmar Inc" },
    { 838, "TeamSurv" },
    { 844, "Fell Marine" },
    { 847, "Oceanvolt" },
    { 862, "Prospec" },
    { 868, "Data Panel Corp" },
    { 890, "L3 Technologies" },
    { 894, "Rhodan Marine Systems" },
    { 896, "Nexfour Solutions" },
    { 905, "ASA Electronics" },
    { 909, "Marines Co (South Korea)" },
    { 911, "Nautic-on" },
    { 917, "Sentinel" },
    { 929, "JL Marine ystems" },
    { 930, "Ecotronix" },
    { 944, "Zontisa Marine" },
    { 951, "EXOR International" },
    { 962, "Timbolier Industries" },
    { 963, "TJC Micro" },
    { 968, "Cox Powertrain" },
    { 969, "Blue Seas" },
    { 981, "Kobelt Manufacturing Co. Ltd" },
    { 992, "Blue Ocean IOT" },
    { 997, "Xenta Systems" },
    { 1004, "Ultraflex SpA" },
    { 1008, "Lintest SmartBoat" },
    { 1011, "Soundmax" },
    { 1020, "Team Italia Marine (Onyx Marine Automation s.r.l)" },
    { 1021, "Entratech" },
    { 1022, "ITC Inc." },
    { 1029, "The Marine Guardian LLC" },
    { 1047, "Sonic Corporation" },
    { 1051, "ProNav" },
    { 1053, "Vetus Maxwell INC." },
    { 1056, "Lithium Pros" },
    { 1059, "Boatrax" },
    { 1062, "Marol Co ltd" },
    { 1065, "CALYPSO Instruments" },
    { 1066, "Spot Zero Water" },
    { 1069, "Lithionics Battery LLC" },
    { 1070, "Quick-teck Electronics Ltd" },
    { 1075, "Uniden America" },
    { 1083, "Nauticoncept" },
    { 1084, "Shadow-Caster LED lighting LLC" },
    { 1085, "Wet Sounds, LLC" },
    { 1088, "E-T-A Circuit Breakers" },
    { 1092, "Scheiber" },
    { 1100, "Smart Yachts International Limited" },
    { 1109, "Dockmate" },
    { 1114, "Bobs Machine" },
    { 1118, "L3Harris ASV" },
    { 1119, "Balmar LLC" },
    { 1120, "Elettromedia spa" },
    { 1127, "Electromaax" },
    { 1140, "Across Oceans Systems Ltd." },
    { 1145, "Kiwi Yachting" },
    { 1150, "BSB Artificial Intelligence GmbH" },
    { 1151, "Orca Technologoes AS" },
    { 1154, "TBS Electronics BV" },
    { 1158, "Technoton Electroics" },
    { 1160, "MG Energy Systems B.V." },
    { 1169, "Sea Macine Robotics Inc." },
    { 1171, "Vista Manufacturing" },
    { 1183, "Zipwake" },
    { 1186, "Sailmon BV" },
    { 1192, "Airmoniq Pro Kft" },
    { 1194, "Sierra Marine" },
    { 1200, "Xinuo Information Technology (Xiamen)" },
    { 1218, "Septentrio" },
    { 1233, "NKE Marine Elecronics" },
    { 1238, "SuperTrack Aps" },
    { 1239, "Honda Electronics Co., LTD" },
    { 1245, "Raritan Engineering Company, Inc" },
    { 1249, "Integrated Power Solutions AG" },
    { 1260, "Interactive Technologies, Inc." },
    { 1283, "LTG-Tech" },
    { 1299, "Energy Solutions (UK) LTD." },
    { 1300, "WATT Fuel Cell Corp" },
    { 1302, "Pro Mainer" },
    { 1305, "Dragonfly Energy" },
    { 1306, "Koden Electronics Co., Ltd" },
    { 1311, "Humphree AB" },
    { 1316, "Hinkley Yachts" },
    { 1317, "Global Marine Management GmbH (GMM)" },
    { 1320, "Triskel Marine Ltd" },
    { 1330, "Warwick Control Technologies" },
    { 1331, "Dolphin Charger" },
    { 1337, "Barnacle Systems Inc" },
    { 1348, "Radian IoT, Inc." },
    { 1353, "Ocean LED Marine Ltd" },
    { 1359, "BluNav" },
    { 1361, "OVA (Nantong Saiyang Electronics Co., Ltd)" },
    { 1368, "RAD Propulsion" },
    { 1369, "Electric Yacht" },
    { 1372, "Elco Motor Yachts" },
    { 1384, "Tecnoseal Foundry S.r.l" },
    { 1385, "Pro Charging Systems, LLC" },
    { 1389, "EVEX Co., LTD" },
    { 1398, "Gobius Sensor Technology AB" },
    { 1403, "Arco Marine" },
    { 1408, "Lenco Marine Inc." },
    { 1413, "Naocontrol S.L." },
    { 1417, "Revatek" },
    { 1438, "Aeolionics" },
    { 1439, "PredictWind Ltd" },
    { 1440, "Egis Mobile Electric" },
    { 1445, "Starboard Yacht Group" },
    { 1446, "Roswell Marine" },
    { 1451, "ePropulsion (Guangdong ePropulsion Technology Ltd.)" },
    { 1452, "Micro-Air LLC" },
    { 1453, "Vital Battery" },
    { 1458, "Ride Controller LLC" },
    { 1460, "Tocaro Blue" },
    { 1461, "Vanquish Yachts" },
    { 1471, "FT Technologies" },
    { 1478, "Alps Alpine Co., Ltd." },
    { 1481, "E-Force Marine" },
    { 1482, "CMC Marine" },
    { 1483, "Nanjing Sandemarine Information Technology Co., Ltd." },
    { 1850, "Teleflex Marine (SeaStar Solutions)" },
    { 1851, "Raymarine" },
    { 1852, "Navionics" },
    { 1853, "Japan Radio Co" },
    { 1854, "Northstar Technologies" },
    { 1855, "Furuno" },
    { 1856, "Trimble" },
    { 1857, "Simrad" },
    { 1858, "Litton" },
    { 1859, "Kvasar AB" },
    { 1860, "MMP" },
    { 1861, "Vector Cantech" },
    { 1862, "Yamaha Marine" },
    { 1863, "Faria Instruments" },
    { 0,    NULL }
};

/* INDUSTRY_CODE (0 - 7)*/
static const value_string nmea2000_industry_code_vals[] = {
    { 0, "Global" },
    { 1, "Highway" },
    { 2, "Agriculture" },
    { 3, "Construction" },
    { 4, "Marine Industry" },
    { 5, "Industrial" },
    { 0,    NULL }
};
/**
 * Generic fast packet dissection and reassembly
 * @param tvb tvb with packet data
 * @param pinfo packety info struct
 * @param tree the protocol tree or NULL
 * @param num_bytes the number of bytes needed to reassemble
 * @return msg_tvb A tvb holding the complete reassembled packet when/if reassembly completes or NULL.
 */

static tvbuff_t *
dissect_nmea2000_fast_pkt(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, uint32_t num_bytes)
{
    int offset = 0;
    uint32_t frame_count, sequence_no, fragment_length = 7;

    fragment_head* fd_fast_pkt = NULL;
    uint32_t fragment_id;
    bool more_frags = true;
    bool save_fragmented = false;
    tvbuff_t* msg_tvb = NULL;
    uint32_t num_frag = num_bytes / 7 + 1;

    /*
     * Packet Type Fast Packet
     * The first byte in all frames contains a sequence counter in the high 3 bits and a frame counter in the lower 5 bits
     * The second byte in the first frame contains the total number of bytes in all packets that will be sent
     * (excluding the single header byte in each of the following packets).
     */
    proto_tree_add_item_ret_uint(tree, hf_nmea2000_seq, tvb, offset, 1, ENC_NA, &sequence_no);
    proto_tree_add_item_ret_uint(tree, hf_nmea2000_f_cnt, tvb, offset, 1, ENC_NA, &frame_count);
    fragment_id = (NMEA2000_PGN_126996 << 8) | sequence_no;
    offset++;
    if (frame_count == 0) {
        fragment_length = 6;
        proto_tree_add_item(tree, hf_nmea2000_num_bytes, tvb, offset, 1, ENC_NA);
        offset++;
    }
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = true;
    /* */
    if (frame_count == (num_frag-1)) {
        /* Number of fragments needed to get a full msg */
        more_frags = false;
    }
    fd_fast_pkt = fragment_add_seq_check(&nmea2000_reassembly_table, tvb, offset,
        pinfo,
        fragment_id, /* uint32_t ID for fragments belonging together */
        NULL,        /* data? */
        frame_count, /* uint32_t fragment sequence number */
        fragment_length, /* uint32_t fragment length */
        more_frags); /* More fragments? */

    msg_tvb = process_reassembled_data(tvb, offset, pinfo,
        "Reassembled Fast Message", fd_fast_pkt, &nmea2000_frag_items,
        NULL, tree);

    pinfo->fragmented = save_fragmented;

    if (fd_fast_pkt != NULL) { /* Reassembled */
        col_append_str(pinfo->cinfo, COL_INFO,
            " (Message Reassembled)");
    } else { /* Not last packet of reassembled Fast Message */
        col_append_fstr(pinfo->cinfo, COL_INFO,
            " (Message fragment %u(%u))", frame_count + 1, num_frag);
    }

    return msg_tvb;
}

/* 0xFF00-0xFFFF(65280 - 65535): Manufacturer Proprietary single-frame non-addressed */

/* 0xFF3D: PGN 65341 - Simnet: Autopilot Angle */
#define NMEA2000_PGN_65341 65341
/*
 * Range Hex          Range Dec          PDU     Step    Number of possible PGNs  Use                     Framing
 * 0x1ED00-0x1EE00    126208 - 126464    PDU1    256     2                        Standardized (protocol) Fast packet
 */

static const value_string nmea2000_ap_mode_vals[] = {
    { 2, "Heading" },
    { 3, "Wind" },
    { 10, "Nav" },
    { 11, "No Drift" },
    { 0,    NULL }
};


static int
dissect_nmea2000_65341(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* ti;
    proto_tree* nmea2000_tree, * top_tree = proto_tree_get_root(tree);

    int bit_offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "nmea2000");
    ti = proto_tree_add_item(top_tree, proto_nmea2000, tvb, 0, -1, ENC_NA);
    nmea2000_tree = proto_item_add_subtree(ti, ett_nmea2000);

    /* Manufacturer Code    1857: Simrad    0 .. 2044 11 bits lookup MANUFACTURER_CODE */
    proto_tree_add_bits_item(nmea2000_tree, hf_nmea2000_man_code, tvb, bit_offset, 11, ENC_LITTLE_ENDIAN);
    bit_offset += 11;
    /* Reserved                                        2 bits RESERVED */
    proto_tree_add_bits_item(nmea2000_tree, hf_nmea2000_reserved_b4b3, tvb, bit_offset, 2, ENC_LITTLE_ENDIAN);
    bit_offset += 2;
    /* Industry Code    4: Marine Industry    0 .. 6   3 bits lookup INDUSTRY_CODE */
    proto_tree_add_bits_item(nmea2000_tree, hf_nmea2000_ind_code, tvb, bit_offset, 3, ENC_LITTLE_ENDIAN);
    bit_offset += 3;
    /* Reserved                                       16 bits RESERVED */
    proto_tree_add_item(nmea2000_tree, hf_nmea2000_reserved16, tvb, bit_offset>>3, 2, ENC_LITTLE_ENDIAN);
    bit_offset += 16;
    /* Mode             0 .. 252                       8 bits lookup SIMNET_AP_MODE*/
    proto_tree_add_item(nmea2000_tree, hf_nmea2000_ap_mode, tvb, bit_offset >> 3, 1, ENC_LITTLE_ENDIAN);
    bit_offset += 8;
    /* Reserved                                        8 bits RESERVED */
    proto_tree_add_item(nmea2000_tree, hf_nmea2000_reserved8, tvb, bit_offset>>3, 1, ENC_LITTLE_ENDIAN);
    bit_offset += 8;
    /* Angle        0.0001 rad0 .. 6.2831852          16 bits unsigned NUMBER*/
    proto_tree_add_item(nmea2000_tree, hf_nmea2000_angle, tvb, bit_offset >> 3, 2, ENC_LITTLE_ENDIAN);
    //bit_offset += 16;

    return tvb_captured_length(tvb);

}

static const value_string nmea2000_cert_lev_vals[] = {
    { 0x0,  "Level A" },
    { 0x1,  "Level B" },
    { 0,    NULL }
};

/*
 * 0x1F105: PGN 127237 - Heading/Track control
 * This fast-packet PGN is 21 bytes long and contains 18 fields.
 */
#define NMEA2000_PGN_127237 127237
static int
     dissect_nmea2000_127237(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
 {
     proto_item* ti;
     proto_tree* nmea2000_tree, * top_tree = proto_tree_get_root(tree);

     tvbuff_t* msg_tvb;
     //int offset = 0;

     col_set_str(pinfo->cinfo, COL_PROTOCOL, "nmea2000");
     ti = proto_tree_add_item(top_tree, proto_nmea2000, tvb, 0, -1, ENC_NA);
     nmea2000_tree = proto_item_add_subtree(ti, ett_nmea2000);

     msg_tvb = dissect_nmea2000_fast_pkt(tvb, pinfo, nmea2000_tree, 21);

     if (msg_tvb) { /* Reassembled  */

     }

     return tvb_captured_length(tvb);
 }

/*
 * 0x1F014: PGN 126996 - Product Information
 * This fast-packet PGN is 134 bytes long and contains 8 fields.
 */

static int
dissect_nmea2000_126996(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* ti;
    proto_tree* nmea2000_tree, *top_tree = proto_tree_get_root(tree);

    tvbuff_t* msg_tvb;
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "nmea2000");
    ti = proto_tree_add_item(top_tree, proto_nmea2000, tvb, 0, -1, ENC_NA);
    nmea2000_tree = proto_item_add_subtree(ti, ett_nmea2000);

    msg_tvb = dissect_nmea2000_fast_pkt(tvb, pinfo, nmea2000_tree, 134);

    if (msg_tvb) { /* Reassembled  */
        /* NMEA 2000 Version, 16 bits unsigned NUMBER, Unit 0.001*/
        proto_tree_add_item(nmea2000_tree, hf_nmea2000_version, msg_tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        /* Product Code 16 bits unsigned NUMBER */
        proto_tree_add_item(nmea2000_tree, hf_nmea2000_prod_code, msg_tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        /* Model ID 256 bits STRING_FIX*/
        proto_tree_add_item(nmea2000_tree, hf_nmea2000_model_id, msg_tvb, offset, 32, ENC_ASCII);
        offset += 32;
        /* Software Version Code 256 bits STRING_FIX */
        proto_tree_add_item(nmea2000_tree, hf_nmea2000_sw_ver_code, msg_tvb, offset, 32, ENC_ASCII);
        offset += 32;
        /* Model Version 256 bits STRING_FIX */
        proto_tree_add_item(nmea2000_tree, hf_nmea2000_model_ver, msg_tvb, offset, 32, ENC_ASCII);
        offset += 32;
        /* Model Serial Code 256 bits STRING_FIX */
        proto_tree_add_item(nmea2000_tree, hf_nmea2000_model_ser_code, msg_tvb, offset, 32, ENC_ASCII);
        offset += 32;
        /* Certification Level 8 bits lookup CERTIFICATION_LEVEL */
        proto_tree_add_item(nmea2000_tree, hf_nmea2000_cert_lev, msg_tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        /* Load Equivalency 8 bits unsigned NUMBER */
        proto_tree_add_item(nmea2000_tree, hf_nmea2000_load_eq, msg_tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea2000(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    //proto_item *ti;
    //proto_tree *nmea2000_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "nmea2000");

#if 0
    /* If you will be fetching any data from the packet before filling in
     * the Info column, clear that column first in case the calls to fetch
     * data from the packet throw an exception so that the Info column doesn't
     * contain data left over from the previous dissector: */
    col_clear(pinfo->cinfo, COL_INFO);
#endif

    /*ti = */proto_tree_add_item(tree, proto_nmea2000, tvb, 0, -1, ENC_NA);
    /*nmea2000_tree = proto_item_add_subtree(ti, ett_nmea2000);*/


    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/*
 * Register the protocol with Wireshark.
 */
void
proto_register_nmea2000(void)
{

    static hf_register_info hf[] = {
        { &hf_nmea2000_seq,
          { "Sequence number", "nmea2000.seq",
            FT_UINT8, BASE_DEC, NULL, 0xe0,
            NULL, HFILL }
        },
        { &hf_nmea2000_f_cnt,
          { "Frame counter", "nmea2000.f_cnt",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_nmea2000_num_bytes,
          { "Number of bytes", "nmea2000.num_bytes",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_version,
          { "Version", "nmea2000.version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_prod_code,
          { "Product Code", "nmea2000.prod_code",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_model_id,
          { "Model ID", "nmea2000.model_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_sw_ver_code,
          { "Software Version Code", "nmea2000.sw_ver_code",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_model_ver,
          { "Model Version", "nmea2000.model_ver",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_model_ser_code,
          { "Model Serial Code", "nmea2000.model_ser_code",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_cert_lev,
          { "Certification Level", "nmea2000.cert_lev",
            FT_UINT16, BASE_DEC, VALS(nmea2000_cert_lev_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_load_eq,
          { "Load Equivalency", "nmea2000.load_eq",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        /*
         * Fast Message fragment reassembly
         */
        { &hf_nmea2000_fragments,
          { "Fast Message fragments", "nmea2000.fragments",
             FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }
        },
        { &hf_nmea2000_fragment,
          { "Fast Message fragment", "nmea2000.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_fragment_overlap,
          { "Fast Message fragment overlap", "nmea2000.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_fragment_overlap_conflicts,
          { "Fast Message fragment overlapping with conflicting data", "nmea2000.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_fragment_multiple_tails,
          { "Fast Message has multiple tail fragments", "nmea2000.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_fragment_too_long_fragment,
          { "Fast Message fragment too long", "nmea2000.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_fragment_error,
          { "Fast Message defragmentation error", "nmea2000.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_fragment_count,
          { "Fast Message fragment count", "nmea2000.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_reassembled_in,
          { "Reassembled in", "nmea2000.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_reassembled_length,
          { "Reassembled Fast Message length", "nmea2000.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_man_code,
          { "Manufacturer Code", "nmea2000.man_code",
            FT_UINT16, BASE_DEC, VALS(nmea2000_manufacturer_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_reserved_b4b3,
          { "Reserved", "nmea2000.reserved_b4b3",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_ind_code,
          { "Industry Code", "nmea2000.ind_code",
            FT_UINT16, BASE_DEC, VALS(nmea2000_industry_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_reserved16,
          { "Reserved", "nmea2000.reserved16",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_ap_mode,
          { "Mode", "nmea2000.ap_mode",
            FT_UINT8, BASE_DEC, VALS(nmea2000_ap_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_reserved8,
          { "Reserved", "nmea2000.reserved8",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nmea2000_angle,
          { "Angle", "nmea2000.angle",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_nmea2000,
        &ett_nmea2000_fragment,
        &ett_nmea2000_fragments
    };


    /* Register the protocol name and description */
    proto_nmea2000 = proto_register_protocol("NMEA 2000", "nmea2000", "nmea2000");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_nmea2000, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));


    nmea2000_handle = register_dissector("nmea2000", dissect_nmea2000, proto_nmea2000);


}


void
proto_reg_handoff_nmea2000(void)
{
    reassembly_table_register(&nmea2000_reassembly_table, &addresses_reassembly_table_functions);

    dissector_add_uint("j1939.pgn", NMEA2000_PGN_65341, create_dissector_handle(dissect_nmea2000_65341, proto_nmea2000));


    dissector_add_uint("j1939.pgn", NMEA2000_PGN_127237, create_dissector_handle(dissect_nmea2000_127237, proto_nmea2000));

    dissector_add_uint("j1939.pgn", NMEA2000_PGN_126996, create_dissector_handle(dissect_nmea2000_126996, proto_nmea2000));
}



/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
