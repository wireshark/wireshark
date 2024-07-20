/* packet-vmware-hb.c
 * Routines for VMware HeartBeat dissection
 * Copyright 2023, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * No spec/doc is available based on reverse/analysis of protocol...
 *
 */

#include "config.h"

#include <wireshark.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/etypes.h>

void proto_reg_handoff_vmware_hb(void);
void proto_register_vmware_hb(void);

static int proto_vmware_hb;
static int hf_vmware_hb_magic;
static int hf_vmware_hb_build_number;
static int hf_vmware_hb_server_id;
static int hf_vmware_hb_host_key_length;
static int hf_vmware_hb_host_key;
static int hf_vmware_hb_change_gen;
static int hf_vmware_hb_spec_gen;
static int hf_vmware_hb_bundle_version;
static int hf_vmware_hb_heartbeat_counter;
static int hf_vmware_hb_ip4_address_length;
static int hf_vmware_hb_ip4_address;
static int hf_vmware_hb_verification_signature;

static dissector_handle_t vmware_hb_handle;

static int ett_vmware_hb;

static const value_string vmware_hb_build_number[] = {
    { 164009, "ESXi 4.0.0 GA" },
    { 175625, "ESXi 4.0.0 Patch 1" },
    { 181792, "ESXi 4.0.0 Patch 2" },
    { 193498, "ESXi 4.0.0 Patch 3" },
    { 208167, "ESXi 4.0.0 U1" },
    { 219382, "ESXi 4.0.0 Patch 4" },
    { 236512, "ESXi 4.0.0 Patch 5" },
    { 244038, "ESXi 4.0.0 Patch 6" },
    { 256968, "ESXi 4.0.0 Patch 7" },
    { 260247, "ESXi 4.1.0 GA" },
    { 261974, "ESXi 4.0.0 U2" },
    { 294855, "ESXi 4.0.0 Patch 8" },
    { 320092, "ESXi 4.1.0 Patch 1" },
    { 320137, "ESXi 4.1.0 Express Patch 1" },
    { 332073, "ESXi 4.0.0 Patch 9" },
    { 348481, "ESXi 4.1.0 U1" },
    { 360236, "ESXi 4.0.0 Patch 10" },
    { 381591, "ESXi 4.1.0 Patch 2" },
    { 392990, "ESXi 4.0.0 Patch 11" },
    { 398348, "ESXi 4.0.0 U3" },
    { 433742, "ESXi 4.1.0 Patch 3" },
    { 469512, "ESXi 5.0.0" },
    { 474610, "ESXi 5.0.0 Patch 1" },
    { 480973, "ESXi 4.0.0 Patch 12" },
    { 502767, "ESXi 4.1.0 U2" },
    { 504850, "ESXi 4.0.0 U4" },
    { 504890, "ESXi 5.0.0 Express Patch 1" },
    { 515841, "ESXi 5.0.0 Patch 2" },
    { 582267, "ESXi 4.1.0 Patch 4" },
    { 608089, "ESXi 5.0.0 Update 1 (Security Only)" },
    { 623860, "ESXi 5.0.0 Update 1" },
    { 653509, "ESXi 5.0.0 Express Patch 2" },
    { 659051, "ESXi 4.1.0 Patch 5" },
    { 660575, "ESXi 4.0.0 Patch 13" },
    { 702113, "ESXi 4.1.0 Express Patch 2" },
    { 702116, "ESXi 4.0.0 Patch 14" },
    { 702118, "ESXi 5.0.0 Express Patch 3" },
    { 721871, "ESXi 4.1.0 Express Patch 3" },
    { 721882, "ESXi 5.0.0 Express Patch 4" },
    { 721907, "ESXi 4.0.0 Patch 15" },
    { 764879, "ESXi 5.0.0 Patch 3 (Security Only)" },
    { 768111, "ESXi 5.0.0 Patch 3" },
    { 787047, "ESXi 4.0.0 Patch 16" },
    { 799733, "ESXi 5.1.0 GA" },
    { 800380, "ESXi 4.1.0 U3" },
    { 821926, "ESXi 5.0.0 Patch 4" },
    { 822948, "ESXi 5.0.0 Patch 4 (Security Only)" },
    { 837262, "PP Hot-Patch" },
    { 838463, "ESXi 5.1.0a" },
    { 874690, "ESXi 4.1.0 Patch 6" },
    { 911593, "ESXi 5.1.0 Patch 1 (Security Only)" },
    { 912577, "ESXi 5.0.0 Update 2 (Security Only)" },
    { 914586, "ESXi 5.0.0 Update 2" },
    { 914609, "ESXi 5.1.0 Patch 1" },
    { 988178, "ESXi 4.1.0 Patch 7" },
    { 989856, "ESXi 4.0.0 Patch 17" },
    { 1021289, "ESXi 5.1.0 Express Patch 2" },
    { 1022489, "ESXi 5.0.0 Patch 5 (Security Only)" },
    { 1024429, "ESXi 5.0.0 Patch 5" },
    { 1050704, "ESXi 4.1.0 Patch 8" },
    { 1063671, "ESXi 5.1.0 Update 1 (Security Only)" },
    { 1065491, "ESXi 5.1.0 Update 1" },
    { 1070634, "ESXi 4.0.0 Patch 18" },
    { 1117897, "ESXi 5.0.0 Express Patch 5" },
    { 1117900, "ESXi 5.1.0 Express Patch 3" },
    { 1142907, "ESXi 5.1.0 Patch 2 (Security Only)" },
    { 1157734, "ESXi 5.1.0 Patch 2" },
    { 1197855, "ESXi 5.0.0 Patch 6 (Security Only)" },
    { 1198252, "ESXi 4.1.0 Patch 9" },
    { 1254542, "ESXi 5.0.0 Patch 6" },
    { 1311175, "ESXi 5.0.0 Update 3" },
    { 1311177, "ESXi 5.0.0 Update 3 (Security Only)" },
    { 1312873, "ESXi 5.1.0 Patch 3" },
    { 1312874, "ESXi 5.1.0 Patch 3 (Security Only)" },
    { 1331820, "ESXi 5.5 GA" },
    { 1335992, "ESXi 4.0.0 Patch 19" },
    { 1363503, "ESXi 4.1.0 Patch 10" },
    { 1439689, "vSAN Beta Refresh" },
    { 1472666, "ESXi 5.1.0 Update 2 (Security Only)" },
    { 1474526, "ESXi 5.5 Patch 1 (Security Only)" },
    { 1474528, "ESXi 5.5 Patch 1" },
    { 1478905, "ESXi 5.0.0 Patch 7 (Security Only)" },
    { 1483097, "ESXi 5.1.0 Update 2" },
    { 1489271, "ESXi 5.0.0 Patch 7" },
    { 1598313, "ESXi 5.5 Update 1 (Security Only)" },
    { 1612806, "ESXi 5.1.0 Express Patch 4" },
    { 1623387, "ESXi 5.5 Update 1" },
    { 1636597, "VMware ESXi 5.5.1 Driver Rollup" },
    { 1682696, "ESXi 4.0.0 Patch 20" },
    { 1682698, "ESXi 4.1.0 Patch 11" },
    { 1743201, "ESXi 5.1.0 Patch 4 (Security Only)" },
    { 1743533, "ESXi 5.1.0 Patch 4" },
    { 1746018, "ESXi 5.5 Update 1a" },
    { 1746974, "ESXi 5.5 Express Patch 3" },
    { 1749766, "ESXi 5.0.0 Patch 8 (Security Only)" },
    { 1851670, "ESXi 5.0.0 Patch 8" },
    { 1881737, "ESXi 5.5 Express Patch 4" },
    { 1892623, "ESXi 5.5 Patch 2 (Security Only)" },
    { 1892794, "ESXi 5.5 Patch 2" },
    { 1900470, "ESXi 5.1.0 Express Patch 5" },
    { 1904929, "ESXi 5.1.0 Patch 5 (Security Only)" },
    { 1918656, "ESXi 5.0.0 Express Patch 6" },
    { 1979317, "ESXi 5.0.0 Patch 9 (Security Only)" },
    { 1980513, "ESXi 5.5 Update 2 (Security Only)" },
    { 2000251, "ESXi 5.1.0 Patch 5" },
    { 2000308, "ESXi 5.0.0 Patch 9" },
    { 2068190, "ESXi 5.5 Update 2" },
    { 2093874, "ESXi 5.5 Patch 3 (Security Only)" },
    { 2143827, "ESXi 5.5 Patch 3" },
    { 2191354, "ESXi 5.1.0 Patch 6 (Security Only)" },
    { 2191751, "ESXi 5.1.0 Patch 6" },
    { 2216931, "ESXi 5.0.0 Patch 10 (Security Only)" },
    { 2302651, "ESXi 5.5 Express Patch 5" },
    { 2312428, "ESXi 5.0.0 Patch 10" },
    { 2323231, "ESXi 5.1.0 Update 3 (Security Only)" },
    { 2323236, "ESXi 5.1.0 Update 3" },
    { 2352327, "ESXi 5.5 Patch 4 (Security Only)" },
    { 2403361, "ESXi 5.5 Patch 4" },
    { 2456374, "ESXi 5.5 Express Patch 6" },
    { 2486588, "ESXi 5.0.0 Patch 11 (Security Only)" },
    { 2494585, "ESXi 6.0 GA" },
    { 2509828, "ESXi 5.0.0 Patch 11" },
    { 2575044, "ESXi 5.1.0 Patch 7 (Security Only)" },
    { 2583090, "ESXi 5.1.0 Patch 7" },
    { 2615704, "ESXi 6.0 Express Patch 1" },
    { 2638301, "ESXi 5.5 Express Patch 7" },
    { 2702864, "ESXi 5.5 Patch 5 (Recalled)" },
    { 2702869, "ESXi 5.5 Patch 5 (Security Only)" },
    { 2715440, "ESXi 6.0 Express Patch 2" },
    { 2718055, "ESXi 5.5 Patch 5 re-release" },
    { 2809111, "ESXi 6.0b (Security Only)" },
    { 2809209, "ESXi 6.0b" },
    { 3017641, "ESXi 6.0 Update 1 (Security only)" },
    { 3021178, "ESXi 5.1.0 Patch 8 (Security Only)" },
    { 3021432, "ESXi 5.0.0 Patch 12 (Security Only)" },
    { 3029758, "ESXi 6.0 Update 1" },
    { 3029837, "ESXi 5.5 Update 3 (Security Only)" },
    { 3029944, "ESXi 5.5 Update 3" },
    { 3070626, "ESXi 5.1.0 Patch 8" },
    { 3073146, "ESXi 6.0 Update 1a" },
    { 3086167, "ESXi 5.0.0 Patch 12" },
    { 3116895, "ESXi 5.5 Update 3a" },
    { 3247226, "ESXi 5.5 Update 3b (Security Only)" },
    { 3247720, "ESXi 6.0 Express Patch 4" },
    { 3248547, "ESXi 5.5 Update 3b" },
    { 3341439, "ESXi 6.0 Update 1b (Security only)" },
    { 3343343, "ESXi 5.5 Express Patch 9" },
    { 3380124, "ESXi 6.0 Update 1b" },
    { 3568722, "ESXi 5.5 Express Patch 10" },
    { 3568940, "ESXi 6.0 Express Patch 5" },
    { 3568943, "ESXi 6.0 Update 2 (Security Only)" },
    { 3620759, "ESXi 6.0 Update 2" },
    { 3825889, "ESXi 6.0 Express Patch 6" },
    { 3872638, "ESXi 5.1.0 Patch 9" },
    { 3872664, "ESXi 5.1.0 Patch 9" },
    { 3982819, "ESXi 5.0.0 Patch 13 (Security Only)" },
    { 3982828, "ESXi 5.0.0 Patch 13" },
    { 4179598, "ESXi 6.0 Patch 3 (Security Only)" },
    { 4179631, "ESXi 5.5 Patch 8 (Security only)" },
    { 4179633, "ESXi 5.5 Patch 8" },
    { 4192238, "ESXi 6.0 Patch 3" },
    { 4345810, "ESXi 5.5 Patch 9 (Security only)" },
    { 4345813, "ESXi 5.5 Patch 9" },
    { 4510822, "ESXi 6.0 Express Patch 7" },
    { 4558694, "ESXi 6.0 Patch 4 (Security Only)" },
    { 4564106, "ESXi 6.5 GA" },
    { 4600944, "ESXi 6.0 Patch 4" },
    { 4722766, "ESXi 5.5 Patch 10" },
    { 4756874, "ESXi 5.5 Patch 10 (Security only)" },
    { 4887370, "ESXi 6.5a" },
    { 5047589, "ESXi 6.0 Update 3 (Security Only)" },
    { 5050593, "ESXi 6.0 Update 3" },
    { 5146843, "ESXi 6.5 Patch 1 (Security Only)" },
    { 5146846, "ESXi 6.5 Patch 1" },
    { 5224529, "ESXi 6.5 Express Patch 1a" },
    { 5224934, "ESXi 6.0 Express Patch 7a" },
    { 5230635, "ESXi 5.5 Express Patch 11" },
    { 5251621, "ESXi 6.0 Update 1 (VMSA-2017-0006)" },
    { 5251623, "ESXi 6.0 Update 2 (VMSA-2017-0006)" },
    { 5310538, "ESXi 6.5d (vSAN 6.6 Patch)" },
    { 5485776, "ESXi 6.0 Update 3a (Patch 5) (Security Only)" },
    { 5572656, "ESXi 6.0 Update 3a (Patch 5)" },
    { 5969300, "ESXi 6.5 Update 1 (Security only)" },
    { 5969303, "ESXi 6.5 Update 1" },
    { 6480267, "ESXi 5.5 Patch 11 (Security only)" },
    { 6480324, "ESXi 5.5 Patch 11" },
    { 6765062, "ESXi 6.0 Express Patch 11" },
    { 6765664, "ESXi 6.5 Express Patch 4" },
    { 6856897, "ESXi 6.0 Patch 6 (Security Only)" },
    { 6921384, "ESXi 6.0 Patch 6" },
    { 7273056, "ESXi 6.5 Patch 2 (Security only)" },
    { 7388607, "ESXi 6.5 Patch 2" },
    { 7504623, "ESXi 5.5 U3g (Recalled)" },
    { 7504637, "ESXi 6.0 U3d (Recalled)" },
    { 7526125, "ESXi 6.5 U1e (Recalled)" },
    { 7618464, "ESXi 5.5 U3h" },
    { 7967571, "ESXi 5.5 U3h" },
    { 7967591, "ESXi 6.5 U1g" },
    { 7967664, "ESXi 6.0 U3e" },
    { 8169922, "ESXi 6.7 GA" },
    { 8285314, "ESXi 6.5 Update 2 (Security only)" },
    { 8294253, "ESXi 6.5 Update 2" },
    { 8934887, "ESXi 5.5 U3i" },
    { 8934903, "ESXi 6.0 U3f" },
    { 8935087, "ESXi 6.5 U2b" },
    { 8941472, "ESXi 6.7 Express Patch 2" },
    { 9214924, "ESXi 6.7 Express Patch 2a" },
    { 9239792, "ESXi 6.0 Patch 7 (Security only)" },
    { 9239799, "ESXi 6.0 Patch 7" },
    { 9298722, "ESXi 6.5 U2c" },
    { 9313066, "ESXi 5.5 U3j" },
    { 9313334, "ESXi 6.0 Express Patch 15" },
    { 9484548, "ESXi 6.7 Express Patch 3" },
    { 9919047, "ESXi 5.5 U3k" },
    { 9919195, "ESXi 6.0 Express Patch 17" },
    { 10175896, "ESXi 6.5 Express Patch 9" },
    { 10176752, "ESXi 6.7 Express Patch 4" },
    { 10176879, "ESXi 6.7 Update 1 (Security only)" },
    { 10302608, "ESXi 6.7 Update 1" },
    { 10390116, "ESXi 6.5 Express Patch 10" },
    { 10474991, "ESXi 6.0 Express Patch 18" },
    { 10719125, "ESXi 6.5 Express Patch 11" },
    { 10719132, "ESXi 6.0 Express Patch 19" },
    { 10764712, "ESXi 6.7 Express Patch 5" },
    { 10868328, "ESXi 6.5 Patch 3 (Security only)" },
    { 10884925, "ESXi 6.5 Patch 3" },
    { 11675023, "ESXi 6.7 Express Patch 6" },
    { 11925212, "ESXi 6.5 Express Patch 12" },
    { 12986307, "ESXi 6.7 Update 2 (Security Only)" },
    { 13003896, "ESXi 6.0 Express Patch 20" },
    { 13004031, "ESXi 6.5 Express Patch 13" },
    { 13004448, "ESXi 6.7 Express Patch 7" },
    { 13006603, "ESXi 6.7 Update 2" },
    { 13473784, "ESXi 6.7 Express Patch 8" },
    { 13635687, "ESXi 6.0 Express Patch 21" },
    { 13635690, "ESXi 6.5 Express Patch 14" },
    { 13644319, "ESXi 6.7 Express Patch 9" },
    { 13873656, "ESXi 6.5 Update 3 (Security Only)" },
    { 13932383, "ESXi 6.5 Update 3" },
    { 13981272, "ESXi 6.7 Express Patch 10" },
    { 14141615, "ESXi 6.7 Update 3 (Security Only)" },
    { 14320388, "ESXi 6.7 Update 3" },
    { 14320405, "ESXi 6.5  Express Patch 15" },
    { 14513180, "ESXi 6.0 Patch 8" },
    { 14516143, "ESXi 6.0 Patch 8 (Security Only)" },
    { 14874964, "ESXi 6.5 Express Patch 16" },
    { 14990892, "ESXi 6.5 Express Patch 17" },
    { 15018017, "ESXi 6.7 Express Patch 13" },
    { 15018929, "ESXi 6.0  Express Patch 22" },
    { 15160138, "ESXi 6.7 Patch 1" },
    { 15169789, "ESXi 6.0  Express Patch 23" },
    { 15177306, "ESXi 6.5 Express Patch 18" },
    { 15256549, "ESXi 6.5 Patch 4" },
    { 15517548, "ESXi 6.0 Express Patch 25" },
    { 15820472, "ESXi 6.7 Express Patch 14" },
    { 15843807, "ESXi 7.0 GA" },
    { 15999342, "ESXi 6.7 Patch 2 (Security Only)" },
    { 16075168, "ESXi 6.7 Patch 2" },
    { 16207673, "ESXi 6.5 Express Patch 19" },
    { 16316930, "ESXi 6.7 Express Patch 15" },
    { 16321839, "ESXi 7.0b (Security Only)" },
    { 16324942, "ESXi 7.0b" },
    { 16389870, "ESXi 6.5 Express Patch 20" },
    { 16576879, "ESXi 6.5 Patch 5 (Security Only)" },
    { 16576891, "ESXi 6.5 Patch 5" },
    { 16701467, "ESXi 6.7 Patch 3 (Security Only)" },
    { 16713306, "ESXi 6.7 Patch 3" },
    { 16773714, "ESXi 6.7 Express Patch 16" },
    { 16850804, "ESXi 7.0 Update 1" },
    { 16901156, "ESXi 6.5 Express Patch 21" },
    { 16966451, "ESXi 7.0 for ARM Fling v1.0" },
    { 17068872, "ESXi 7.0 for ARM Fling v1.1" },
    { 17097218, "ESXi 6.5 Express Patch 22" },
    { 17098360, "ESXi 6.7 Express Patch 17" },
    { 17119627, "ESXi 7.0 Update 1a" },
    { 17167537, "ESXi 6.5 Express Patch 23" },
    { 17167699, "ESXi 6.7 Patch 4 (Security Only)" },
    { 17167734, "ESXi 6.7 Patch 4" },
    { 17168206, "ESXi 7.0 Update 1b" },
    { 17230755, "ESXi 7.0 for ARM Fling v1.2" },
    { 17325020, "ESXi 7.0 Update 1c (Security Only)" },
    { 17325551, "ESXi 7.0 Update 1c" },
    { 17459147, "ESXi 6.5 Patch 6 (Security Only)" },
    { 17477841, "ESXi 6.5 Patch 6" },
    { 17499825, "ESXi 6.7 Express Patch 18" },
    { 17551050, "ESXi 7.0 Update 1d" },
    { 17630552, "ESXi 7.0 Update 2" },
    { 17700514, "ESXi 6.7 Patch 5 (Security Only)" },
    { 17700523, "ESXi 6.7 Patch 5" },
    { 17839012, "ESXi 7.0 for ARM Fling v1.3" },
    { 17867351, "ESXi 7.0 Update 2a" },
    { 18071574, "ESXi 6.5 Express Patch 24" },
    { 18175197, "ESXi 7.0 for ARM Fling v1.4" },
    { 18295176, "ESXi 7.0 Update 2c (Security Only)" },
    { 18426014, "ESXi 7.0 Update 2c" },
    { 18427252, "ESXi 7.0 for ARM Fling v1.5" },
    { 18538813, "ESXi 7.0 Update 2d" },
    { 18644231, "ESXi 7.0 Update 3" },
    { 18677441, "ESXi 6.5 Patch 7 (Security Only)" },
    { 18678235, "ESXi 6.5 Patch 7" },
    { 18812553, "ESXi 6.7 Patch 6 (Security Only)" },
    { 18825058, "ESXi 7.0 Update 3a" },
    { 18828794, "ESXi 6.7 Patch 6" },
    { 18905247, "ESXi 7.0 Update 3b" },
    { 19025766, "ESXi 7.0 for ARM Fling v1.7" },
    { 19076756, "ESXi 7.0 for ARM Fling v1.8" },
    { 19092475, "ESXi 6.5 February 2022 Patch" },
    { 19193900, "ESXi 7.0 Update 3c" },
    { 19195723, "ESXi 6.7 Express Patch 23" },
    { 19290878, "ESXi 7.0 Update 2e" },
    { 19324898, "ESXi 7.0 Update 1e" },
    { 19482531, "ESXi 7.0 Update 3d (Security Only)" },
    { 19482537, "ESXi 7.0 Update 3d" },
    { 19546333, "ESXi 7.0 for ARM Fling v1.9" },
    { 19581852, "ESXi 6.5 May 2022 (Security Only)" },
    { 19588618, "ESXi 6.5 May 2022" },
    { 19898894, "ESXi 6.7 June 2022 Patch (Security Only)" },
    { 19898904, "ESXi 7.0 Update 3e" },
    { 19898906, "ESXi 6.7 June 2022 Patch" },
    { 19997716, "ESXi 6.5 July 2022" },
    { 19997733, "ESXi 6.7 July 2022 Patch" },
    { 20036586, "ESXi 7.0 Update 3f (Security Only)" },
    { 20036589, "ESXi 7.0 Update 3f" },
    { 20133114, "ESXi 7.0 for ARM Fling v1.10" },
    { 20328353, "ESXi 7.0 Update 3g" },
    { 20448942, "ESXi 6.5 October 2022 (Security Only)" },
    { 20491463, "ESXi 6.7 October 2022 Patch (Security Only)" },
    { 20497097, "ESXi 6.7 October 2022 Patch" },
    { 20502893, "ESXi 6.5 October 2022" },
    { 20513097, "ESXi 8.0 IA" },
    { 20693597, "ESXi 7.0 for ARM Fling v1.11" },
    { 20841705, "ESXi 7.0 Update 3i (Security Only)" },
    { 20842708, "ESXi 7.0 Update 3i" },
    { 20842819, "ESXi 8.0a" },
    { 21053776, "ESXi 7.0 Update 3j" },
    { 21203431, "ESXi 8.0b (Security Only)" },
    { 21203435, "ESXi 8.0b" },
    { 21313628, "ESXi 7.0 Update 3k" },
    { 21422485, "ESXi 7.0 Update 3l (Security Only)" },
    { 21424296, "ESXi 7.0 Update 3l" },
    { 21447677, "ESXi 7.0 for ARM Fling v1.12" },
    { 21493926, "ESXi 8.0c" },
    { 21495797, "ESXi 8.0 Update 1" },
    { 21686933, "ESXi 7.0 Update 3m" },
    { 21813344, "ESXi 8.0 Update 1a" },
    { 21921575, "ESXi 7.0 for ARM Fling v1.13" },
    { 21930508, "ESXi 7.0 Update 3n" },
    { 22082334, "ESXi 8.0 Update 1c (Security Only)" },
    { 22088125, "ESXi 8.0 Update 1c" },
    { 22346715, "ESXi 7.0 for ARM Fling v1.14" },
    { 22348808, "ESXi 7.0 Update 3o (Security Only)" },
    { 22348816, "ESXi 7.0 Update 3o" },
    { 22380479, "ESXi 8.0 Update 2" },
    { 23299997, "ESXi 8.0 Update 1d" },
    { 23305545, "ESXi 8.0 Update 2b (Security Only)" },
    { 23305546, "ESXi 8.0 Update 2b" },
    { 23307199, "ESXi 7.0 Update 3p" },
    { 23794019, "ESXi 7.0 Update 3q (Security Only)" },
    { 23794027, "ESXi 7.0 Update 3q" },
    { 23825572, "ESXi 8.0 Update 2c" },
    {0, NULL}
};
static value_string_ext vmware_hb_build_number_ext = VALUE_STRING_EXT_INIT(vmware_hb_build_number);

static int
dissect_vmware_hb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *vmware_hb_tree;
    unsigned    offset = 0, host_key_length, ip4_length;
    const uint8_t *host_key, *ip4_str;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VMWARE-HB");

    ti = proto_tree_add_item(tree, proto_vmware_hb, tvb, 0, -1, ENC_NA);

    vmware_hb_tree = proto_item_add_subtree(ti, ett_vmware_hb);

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_build_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_server_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_uint(vmware_hb_tree, hf_vmware_hb_host_key_length, tvb, offset, 1, ENC_BIG_ENDIAN, &host_key_length);
    offset += 1;

    proto_tree_add_item_ret_string(vmware_hb_tree, hf_vmware_hb_host_key, tvb, offset, host_key_length, ENC_ASCII, pinfo->pool, &host_key);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Host Key: %s", host_key);
    offset += host_key_length;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_change_gen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_spec_gen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_bundle_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_heartbeat_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_uint(vmware_hb_tree, hf_vmware_hb_ip4_address_length, tvb, offset, 1, ENC_BIG_ENDIAN, &ip4_length);
    offset += 1;

    if (ip4_length) {
        proto_tree_add_item_ret_string(vmware_hb_tree, hf_vmware_hb_ip4_address, tvb, offset, ip4_length, ENC_ASCII, pinfo->pool, &ip4_str);
        col_append_fstr(pinfo->cinfo, COL_INFO, " - IP: %s", ip4_str);
        offset += ip4_length;
    }

    if (tvb_reported_length_remaining(tvb, offset)) {
        proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_verification_signature, tvb, offset, -1, ENC_NA);
        offset += tvb_reported_length_remaining(tvb, offset);
    }

    return offset;
}

void
proto_register_vmware_hb(void)
{

    static hf_register_info hf[] = {
        /* HeartBeat */
        { &hf_vmware_hb_magic,
            { "Magic Number", "vmware_hb.magic",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
            "Magic Number ?", HFILL }
        },

        { &hf_vmware_hb_build_number,
            { "Build Number", "vmware_hb.build_number",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING, &vmware_hb_build_number_ext, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_server_id,
            { "Server ID", "vmware_hb.server_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_host_key_length,
            { "Length Host Key", "vmware_hb.host_key.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_host_key,
            { "Host Key", "vmware_hb.host_key",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_change_gen,
            { "Change Gen", "vmware_hb.change_gen",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_spec_gen,
            { "Spec Gen", "vmware_hb.spec_gen",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_bundle_version,
            { "Bundle Version", "vmware_hb.bundle_version",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_heartbeat_counter,
            { "Heartbeat Counter", "vmware_hb.heartbeat_counter",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_ip4_address_length,
            { "IP4 Address Length", "vmware_hb.ip4_address.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_ip4_address,
            { "IP4 Address", "vmware_hb.ip4_address",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_verification_signature,
            { "Verification Signature", "vmware_hb.verification_signature",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_vmware_hb
    };

    /* Register the protocol name and description */
    proto_vmware_hb = proto_register_protocol("VMware - HeartBeat",
            "vmware_hb", "vmware_hb");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_vmware_hb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    vmware_hb_handle = register_dissector("vmware_hb", dissect_vmware_hb,
            proto_vmware_hb);

}


void
proto_reg_handoff_vmware_hb(void)
{
      dissector_add_uint("udp.port", 902, vmware_hb_handle);
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
