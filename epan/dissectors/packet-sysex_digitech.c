/* packet-sysex-digitech.c
 *
 * MIDI SysEx dissector for Digitech devices (DOD Electronics Corp.)
 * Tomasz Mon 2012
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

void proto_register_sysex_digitech(void);

/* protocols and header fields */
static int proto_sysex_digitech;
static int hf_digitech_device_id;
static int hf_digitech_family_id;
static int hf_digitech_rp_product_id;
static int hf_digitech_unknown_product_id;
static int hf_digitech_procedure_id;

static int hf_digitech_desired_device_id;
static int hf_digitech_desired_family_id;
static int hf_digitech_desired_product_id;
static int hf_digitech_received_device_id;
static int hf_digitech_os_mode;

static int hf_digitech_preset_bank;
static int hf_digitech_preset_index;
static int hf_digitech_preset_count;
static int hf_digitech_preset_name;
static int hf_digitech_preset_modified;

static int hf_digitech_message_count;

static int hf_digitech_parameter_count;
static int hf_digitech_parameter_id;
static int hf_digitech_parameter_id_global;
static int hf_digitech_parameter_id_pickup;
static int hf_digitech_parameter_id_wah;
static int hf_digitech_parameter_id_compressor;
static int hf_digitech_parameter_id_gnx3k_whammy;
static int hf_digitech_parameter_id_distortion;
static int hf_digitech_parameter_id_amp_channel;
static int hf_digitech_parameter_id_amp;
static int hf_digitech_parameter_id_amp_cabinet;
static int hf_digitech_parameter_id_amp_b;
static int hf_digitech_parameter_id_amp_cabinet_b;
static int hf_digitech_parameter_id_noisegate;
static int hf_digitech_parameter_id_volume_pre_fx;
static int hf_digitech_parameter_id_chorusfx;
static int hf_digitech_parameter_id_delay;
static int hf_digitech_parameter_id_reverb;
static int hf_digitech_parameter_id_volume_post_fx;
static int hf_digitech_parameter_id_preset;
static int hf_digitech_parameter_id_wah_min_max;
static int hf_digitech_parameter_id_equalizer;
static int hf_digitech_parameter_id_equalizer_b;
static int hf_digitech_parameter_id_amp_loop;

static int hf_digitech_parameter_position;
static int hf_digitech_parameter_data;
static int hf_digitech_parameter_data_count;
static int hf_digitech_parameter_data_two_byte_count;
static int hf_digitech_parameter_multibyte_data;

static int hf_digitech_ack_request_proc_id;
static int hf_digitech_nack_request_proc_id;

static int hf_digitech_checksum;
static int hf_digitech_checksum_status;

static int ett_sysex_digitech;

static expert_field ei_digitech_checksum_bad;
static expert_field ei_digitech_undecoded;

typedef struct _digitech_conv_data_t {
    int protocol_version;
} digitech_conv_data_t;

#define DIGITECH_FAMILY_X_FLOOR  0x5C
#define DIGITECH_FAMILY_JAMMAN   0x5D
#define DIGITECH_FAMILY_RP       0x5E
#define DIGITECH_FAMILY_RACK     0x5F
#define DIGITECH_FAMILY_VOCALIST 0x60

static const value_string digitech_family_id[] = {
    {DIGITECH_FAMILY_X_FLOOR,  "\"X\" Floor Guitar Processor"},
    {DIGITECH_FAMILY_JAMMAN,   "JamMan"},
    {DIGITECH_FAMILY_RP,       "RP series"},
    {DIGITECH_FAMILY_RACK,     "Rack"},
    {DIGITECH_FAMILY_VOCALIST, "Vocalist"},
    {0x7F, "All"},
    {0, NULL}
};

static const value_string digitech_rp_product_id[] = {
    {0x01, "RP150"},
    {0x02, "RP250"},
    {0x03, "RP350"},
    {0x04, "RP370"},
    {0x05, "RP500"},
    {0x06, "RP1000"},
    {0x07, "RP155"},
    {0x08, "RP255"},
    {0x09, "RP355"},
    {0, NULL}
};

typedef enum _digitech_procedure_id {
    DIGITECH_PROCEDURE_REQUEST_WHO_AM_I = 0x01,
    DIGITECH_PROCEDURE_RECEIVE_WHO_AM_I = 0x02,

    DIGITECH_PROCEDURE_REQUEST_DEVICE_CONFIGURATION = 0x08,
    DIGITECH_PROCEDURE_RECEIVE_DEVICE_CONFIGURATION = 0x09,

    DIGITECH_PROCEDURE_REQUEST_GLOBAL_PARAMETERS = 0x10,
    DIGITECH_PROCEDURE_RECEIVE_GLOBAL_PARAMETERS = 0x11,

    DIGITECH_PROCEDURE_REQUEST_BULK_DUMP = 0x18,
    DIGITECH_PROCEDURE_RECEIVE_BULK_DUMP_START = 0x19,
    DIGITECH_PROCEDURE_RECEIVE_BULK_DUMP_END = 0x1B,

    DIGITECH_PROCEDURE_RECEIVE_USER_PRESET_INDEX_TABLE = 0x20,

    DIGITECH_PROCEDURE_REQUEST_PRESET_NAMES = 0x21,
    DIGITECH_PROCEDURE_RECEIVE_PRESET_NAMES = 0x22,

    DIGITECH_PROCEDURE_REQUEST_PRESET_NAME = 0x28,
    DIGITECH_PROCEDURE_RECEIVE_PRESET_NAME = 0x29,

    DIGITECH_PROCEDURE_REQUEST_PRESET = 0x2A,
    DIGITECH_PROCEDURE_RECEIVE_PRESET_START = 0x2B,
    DIGITECH_PROCEDURE_RECEIVE_PRESET_END = 0x2C,
    DIGITECH_PROCEDURE_RECEIVE_PRESET_PARAMETERS = 0x2D,

    DIGITECH_PROCEDURE_LOAD_EDIT_BUFFER_PRESET = 0x38, /* version 0 only
                                       use move preset in later versions */

    DIGITECH_PROCEDURE_MOVE_PRESET = 0x39,

    DIGITECH_PROCEDURE_REQUEST_MODIFIER_LINKABLE_LIST = 0x3A,
    DIGITECH_PROCEDURE_RECEIVE_MODIFIER_LINKABLE_LIST = 0x3B,

    DIGITECH_PROCEDURE_REQUEST_PARAMETER_VALUE = 0x40,
    DIGITECH_PROCEDURE_RECEIVE_PARAMETER_VALUE = 0x41,

    /* version 1 and later */
    DIGITECH_PROCEDURE_REQUEST_OBJECT_NAMES = 0x50,
    DIGITECH_PROCEDURE_RECEIVE_OBJECT_NAMES = 0x51,
    DIGITECH_PROCEDURE_REQUEST_OBJECT_NAME = 0x52,
    DIGITECH_PROCEDURE_RECEIVE_OBJECT_NAME = 0x53,
    DIGITECH_PROCEDURE_REQUEST_OBJECT = 0x54,
    DIGITECH_PROCEDURE_RECEIVE_OBJECT = 0x55,
    DIGITECH_PROCEDURE_MOVE_OBJECT = 0x56,
    DIGITECH_PROCEDURE_DELETE_OBJECT = 0x57,
    DIGITECH_PROCEDURE_REQUEST_TABLE = 0x5A,
    DIGITECH_PROCEDURE_RECEIVE_TABLE = 0x5B,

    DIGITECH_PROCEDURE_RECEIVE_DEVICE_NOTIFICATION = 0x70,

    DIGITECH_PROCEDURE_START_OS_DOWNLOAD = 0x71,
    DIGITECH_PROCEDURE_RESTART_DEVICE = 0x72,
    DIGITECH_PROCEDURE_REQUEST_DEBUG_DATA = 0x73,
    DIGITECH_PROCEDURE_RECEIVE_DEBUG_DATA = 0x74,

    DIGITECH_PROCEDURE_ACK = 0x7E,
    DIGITECH_PROCEDURE_NACK = 0x7F
} digitech_procedure_id;

static const value_string digitech_procedures[] = {
    {DIGITECH_PROCEDURE_REQUEST_WHO_AM_I, "Request WhoAmI"},
    {DIGITECH_PROCEDURE_RECEIVE_WHO_AM_I, "Receive WhoAmI"},
    {DIGITECH_PROCEDURE_REQUEST_DEVICE_CONFIGURATION, "Request Device Configuration"},
    {DIGITECH_PROCEDURE_RECEIVE_DEVICE_CONFIGURATION, "Receive Device Configuration"},
    {DIGITECH_PROCEDURE_REQUEST_GLOBAL_PARAMETERS, "Request Global Parameters"},
    {DIGITECH_PROCEDURE_RECEIVE_GLOBAL_PARAMETERS, "Receive Global Parameters"},
    {DIGITECH_PROCEDURE_REQUEST_BULK_DUMP, "Request Bulk Dump"},
    {DIGITECH_PROCEDURE_RECEIVE_BULK_DUMP_START, "Receive Bulk Dump Start"},
    {DIGITECH_PROCEDURE_RECEIVE_BULK_DUMP_END, "Receive Bulk Dump End"},
    {DIGITECH_PROCEDURE_RECEIVE_USER_PRESET_INDEX_TABLE, "Receive User Preset Index Table"},
    {DIGITECH_PROCEDURE_REQUEST_PRESET_NAMES, "Request Preset Names"},
    {DIGITECH_PROCEDURE_RECEIVE_PRESET_NAMES, "Receive Preset Names"},
    {DIGITECH_PROCEDURE_REQUEST_PRESET_NAME, "Request Preset Name"},
    {DIGITECH_PROCEDURE_RECEIVE_PRESET_NAME, "Receive Preset Name"},
    {DIGITECH_PROCEDURE_REQUEST_PRESET, "Request Preset"},
    {DIGITECH_PROCEDURE_RECEIVE_PRESET_START, "Receive Preset Start"},
    {DIGITECH_PROCEDURE_RECEIVE_PRESET_END, "Receive Preset End"},
    {DIGITECH_PROCEDURE_RECEIVE_PRESET_PARAMETERS, "Receive Preset Parameters"},
    {DIGITECH_PROCEDURE_LOAD_EDIT_BUFFER_PRESET, "Load Edit Buffer Preset"},
    {DIGITECH_PROCEDURE_MOVE_PRESET, "Move Preset"},
    {DIGITECH_PROCEDURE_REQUEST_MODIFIER_LINKABLE_LIST, "Request Modifier-Linkable List"},
    {DIGITECH_PROCEDURE_RECEIVE_MODIFIER_LINKABLE_LIST, "Receive Modifier-Linkable List"},
    {DIGITECH_PROCEDURE_REQUEST_PARAMETER_VALUE, "Request Parameter Value"},
    {DIGITECH_PROCEDURE_RECEIVE_PARAMETER_VALUE, "Receive Parameter Value"},
    {DIGITECH_PROCEDURE_REQUEST_OBJECT_NAMES, "Request Object Names"},
    {DIGITECH_PROCEDURE_RECEIVE_OBJECT_NAMES, "Receive Object Names"},
    {DIGITECH_PROCEDURE_REQUEST_OBJECT_NAME, "Request Object Name"},
    {DIGITECH_PROCEDURE_RECEIVE_OBJECT_NAME, "Receive Object Name"},
    {DIGITECH_PROCEDURE_REQUEST_OBJECT, "Request Object"},
    {DIGITECH_PROCEDURE_RECEIVE_OBJECT, "Receive Object"},
    {DIGITECH_PROCEDURE_MOVE_OBJECT, "Move Object"},
    {DIGITECH_PROCEDURE_DELETE_OBJECT, "Delete Object"},
    {DIGITECH_PROCEDURE_REQUEST_TABLE, "Request Table"},
    {DIGITECH_PROCEDURE_RECEIVE_TABLE, "Receive Table"},
    {DIGITECH_PROCEDURE_RECEIVE_DEVICE_NOTIFICATION, "Receive Device Notification"},
    {DIGITECH_PROCEDURE_START_OS_DOWNLOAD, "Start OS Download"},
    {DIGITECH_PROCEDURE_RESTART_DEVICE, "Restart Device"},
    {DIGITECH_PROCEDURE_REQUEST_DEBUG_DATA, "Request Debug Data"},
    {DIGITECH_PROCEDURE_RECEIVE_DEBUG_DATA, "Receive Debug Data"},
    {DIGITECH_PROCEDURE_ACK, "ACK"},
    {DIGITECH_PROCEDURE_NACK, "NACK"},
    {0, NULL}
};
static value_string_ext digitech_procedures_ext =
    VALUE_STRING_EXT_INIT(digitech_procedures);

static const value_string digitech_os_modes[] = {
    {0, "Normal"},
    {1, "Flash update"},
    {0, NULL}
};

static const value_string digitech_preset_banks[] = {
    {0, "Factory (fixed) bank"},
    {1, "User bank"},
    {2, "Artist bank"},
    {3, "Media card (CF or other)"},
    {4, "Current preset edit buffer"},
    {5, "Second factory bank"},
    {6, "External preset"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_global[] = {
    {12361, "Amp/Cab Bypass On/Off"},
    {12298, "GUI Mode On/Off"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_pickup[] = {
    {65, "Pickup On/Off"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_wah[] = {
    {129, "Wah On/Off"},
    {133, "Wah Level"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_compressor[] = {
    {193, "Compressor On/Off"},
    {194, "Compressor Attack"},
    {195, "Compressor Ratio"},
    {200, "Compressor Threshold"},
    {201, "Compressor Gain"},
    {208, "Compressor Sustain"},
    {209, "Compressor Tone"},
    {210, "Compressor Level"},
    {211, "Compressor Attack"},
    {212, "Compressor Output"},
    {213, "Compressor Sensitivity"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_gnx3k_whammy[] = {
    {769, "Whammy/IPS On/Off"},
    {1667, "Whammy/IPS Detune Level"},
    {1670, "Whammy/IPS Detune Shift Amount"},
    {1731, "Whammy/IPS Pitch Shift Level"},
    {1732, "Whammy/IPS Pitch Shift Shift Amount"},
    {1795, "Whammy/IPS Whammy Pedal"},
    {1796, "Whammy/IPS Whammy Mix"},
    {1797, "Whammy/IPS Whammy Shift Amount"},
    {2754, "Whammy/IPS IPS Shift Amount"},
    {2755, "Whammy/IPS IPS Scale"},
    {2756, "Whammy/IPS IPS Key"},
    {2757, "Whammy/IPS IPS Level"},
    {2818, "Whammy/IPS Talker Mic Level"},
    {0, NULL}
};
static value_string_ext digitech_parameter_ids_gnx3k_whammy_ext =
    VALUE_STRING_EXT_INIT(digitech_parameter_ids_gnx3k_whammy);

static const value_string digitech_parameter_ids_distortion[] = {
    {2433, "Distortion On/Off"},
    {2434, "Distortion Screamer Drive"},
    {2435, "Distortion Screamer Tone"},
    {2436, "Distortion Screamer Level"},
    {2437, "Distortion Rodent Dist"},
    {2438, "Distortion Rodent Filter"},
    {2439, "Distortion Rodent Level"},
    {2440, "Distortion DS Gain"},
    {2441, "Distortion DS Tone"},
    {2442, "Distortion DS Level"},
    {2443, "Distortion DOD250 Gain"},
    {2444, "Distortion DOD250 Level"},
    {2445, "Distortion Big MP Sustain"},
    {2446, "Distortion Big MP Tone"},
    {2447, "Distortion Big MP Volume"},
    {2448, "Distortion GuyOD Drive"},
    {2449, "Distortion GuyOD Level"},
    {2450, "Distortion Sparkdrive Gain"},
    {2451, "Distortion Sparkdrive Tone"},
    {2452, "Distortion Sparkdrive Clean"},
    {2453, "Distortion Sparkdrive Volume"},
    {2454, "Distortion Grunge Grunge"},
    {2455, "Distortion Grunge Butt"},
    {2456, "Distortion Grunge Face"},
    {2457, "Distortion Grunge Loud"},
    {2458, "Distortion Fuzzy Fuzz"},
    {2459, "Distortion Fuzzy Volume"},
    {2460, "Distortion Zone Gain"},
    {2461, "Distortion Zone Mid freq"},
    {2462, "Distortion Zone Mid level"},
    {2463, "Distortion Zone Low"},
    {2464, "Distortion Zone High"},
    {2465, "Distortion Zone Level"},
    {2466, "Distortion 8tavia Drive"},
    {2467, "Distortion 8tavia Volume"},
    {2468, "Distortion MX Dist"},
    {2469, "Distortion MX Output"},
    {2470, "Distortion Gonk Suck"},
    {2471, "Distortion Gonk Smear"},
    {2472, "Distortion Gonk Heave"},
    {2473, "Distortion 808 Overdrive"},
    {2474, "Distortion 808 Tone"},
    {2475, "Distortion 808 Level"},
    {2476, "Distortion Death Mid"},
    {2477, "Distortion Death Low"},
    {2478, "Distortion Death Level"},
    {2479, "Distortion Death High"},
    {2480, "Distortion Gonk Gonk"},
    {2481, "Distortion Fuzzlator Fuzz"},
    {2482, "Distortion Fuzzlator Tone"},
    {2483, "Distortion Fuzzlator LooseTight"},
    {2484, "Distortion Fuzzlator Volume"},
    {2485, "Distortion Classic Fuzz Fuzz"},
    {2486, "Distortion Classic Fuzz Tone"},
    {2487, "Distortion Classic Fuzz Volume"},
    {2488, "Distortion Redline Gain"},
    {2489, "Distortion Redline Low"},
    {2490, "Distortion Redline High"},
    {2491, "Distortion Redline Level"},
    {2492, "Distortion OC Drive Drive"},
    {2493, "Distortion OC Drive HP/LP"},
    {2494, "Distortion OC Drive Tone"},
    {2495, "Distortion OC Drive Level"},
    {2562, "Distortion TS Mod Drive"},
    {2563, "Distortion TS Mod Level"},
    {2564, "Distortion TS Mod Tone"},
    {2565, "Distortion SD Overdrive Drive"},
    {2566, "Distortion SD Overdrive Tone"},
    {2567, "Distortion SD Overdrive Level"},
    {2568, "Distortion OD Overdrive Overdrive"},
    {2569, "Distortion OD Overdrive Level"},
    {2570, "Distortion Amp Driver Gain"},
    {2571, "Distortion Amp Driver Mid Boost"},
    {2572, "Distortion Amp Driver Level"},
    {0, NULL}
};
static value_string_ext digitech_parameter_ids_distortion_ext =
    VALUE_STRING_EXT_INIT(digitech_parameter_ids_distortion);

static const value_string digitech_parameter_ids_amp_channel[] = {
    {260, "Amp Channel Amp Channel"},
    {261, "Amp Channel Warp"},
    {262, "Amp Channel Amp Warp"},
    {263, "Amp Channel Cabinet Warp"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_amp[] = {
    {265, "Amplifier On/Off"},
    {2497, "Amplifier Gain"},
    {2498, "Amplifier Level"},
    {2499, "Channel 1 Bass Freq"},
    {2500, "Channel 1 Bass Level"},
    {2501, "Channel 1 Mid Freq"},
    {2502, "Channel 1 Mid Level"},
    {2503, "Channel 1 Treb Freq"},
    {2504, "Channel 1 Treb Level"},
    {2505, "EQ Enable On/Off"},
    {2506, "Channel 1 Presence"},
    {2507, "Amplifier Bass"},
    {2508, "Amplifier Mid"},
    {2509, "Amplifier Treble"},
    {0, NULL}
};
static value_string_ext digitech_parameter_ids_amp_ext =
    VALUE_STRING_EXT_INIT(digitech_parameter_ids_amp);

static const value_string digitech_parameter_ids_amp_cabinet[] = {
    {2561, "Channel 1 Tuning"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_amp_b[] = {
    {265, "Amplifier B On/Off"},
    {2497, "Amplifier B Gain"},
    {2498, "Amplifier B Level"},
    {2499, "Channel 2 Bass Freq"},
    {2500, "Channel 2 Bass Level"},
    {2501, "Channel 2 Mid Freq"},
    {2502, "Channel 2 Mid Level"},
    {2503, "Channel 2 Treb Freq"},
    {2504, "Channel 2 Treb Level"},
    {2505, "EQ Enable On/Off"},
    {2506, "Channel 2 Presence"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_amp_cabinet_b[] = {
    {2561, "Channel 2 Tuning"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_noisegate[] = {
    {705, "Noisegate On/Off"},
    {706, "Noisegate Attack"},
    {710, "Noisegate Threshold"},
    {711, "Noisegate Sens"},
    {712, "Noisegate Attack"},
    {713, "Noisegate Release"},
    {714, "Noisegate Attn"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_volume_pre_fx[] = {
    {2626, "Pickup Volume Pre FX"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_chorusfx[] = {
    {769, "Chorus/FX On/Off"},
    {836, "Chorus/FX Chorus Level"},
    {837, "Chorus/FX Chorus Speed"},
    {838, "Chorus/FX CE/Dual/Multi Chorus Depth"},
    {839, "Chorus/FX Chorus Predelay"},
    {840, "Chorus/FX Dual/Multi Chorus Wave"},
    {841, "Chorus/FX Chorus Balance"},
    {848, "Chorus/FX Chorus Width"},
    {849, "Chorus/FX Chorus Intensity"},
    {850, "Chorus/FX Small Clone Rate"},
    {901, "Chorus/FX Flanger Level/Mix"},
    {902, "Chorus/FX Flanger Speed"},
    {903, "Chorus/FX Flanger Depth"},
    {904, "Chorus/FX Flanger Regen"},
    {905, "Chorus/FX Flanger Waveform"},
    {906, "Chorus/FX Flanger Balance"},
    {914, "Chorus/FX Flanger Width"},
    {916, "Chorus/FX Flanger Color"},
    {917, "Chorus/FX Flanger Manual"},
    {918, "Chorus/FX Flanger Rate"},
    {919, "Chorus/FX Flanger Range"},
    {920, "Chorus/FX Flanger Enhance"},
    {921, "Chorus/FX Flanger Harmonics"},
    {922, "Chorus/FX Filter Flanger Frequency"},
    {962, "Chorus/FX Phaser Speed"},
    {963, "Chorus/FX Phaser Depth"},
    {965, "Chorus/FX Phaser Level"},
    {966, "Chorus/FX Phaser Regen"},
    {967, "Chorus/FX Phaser Waveform"},
    {968, "Chorus/FX Phaser Balance"},
    {976, "Chorus/FX MX Phaser Intensity"},
    {977, "Chorus/FX EH Phaser Color"},
    {979, "Chorus/FX EH Phaser Rate"},
    {1028, "Chorus/FX Triggered Flanger Lfo Start"},
    {1029, "Chorus/FX Triggered Flanger/Phaser Mix"},
    {1030, "Chorus/FX Triggered Flanger Speed"},
    {1031, "Chorus/FX Triggered Flanger Sens"},
    {1032, "Chorus/FX Triggered Flanger Level"},
    {1092, "Chorus/FX Triggered Phaser Lfo Start"},
    {1094, "Chorus/FX Triggered Phaser Speed"},
    {1095, "Chorus/FX Triggered Phaser Sens"},
    {1096, "Chorus/FX Triggered Phaser Level"},
    {1155, "Chorus/FX Tremolo Depth"},
    {1156, "Chorus/FX Tremolo Speed"},
    {1157, "Chorus/FX Tremolo Wave"},
    {1219, "Chorus/FX Panner Depth"},
    {1220, "Chorus/FX Panner Speed"},
    {1221, "Chorus/FX Panner Wave"},
    {1284, "Chorus/FX Vibrato Speed"},
    {1285, "Chorus/FX Vibrato Depth"},
    {1286, "Chorus/FX Vibrato Waveform"},
    {1314, "Chorus/FX Vibropan Speed"},
    {1315, "Chorus/FX Vibropan Depth"},
    {1316, "Chorus/FX Vibropan Vibra"},
    {1317, "Chorus/FX Vibropan Wave"},
    {1346, "Chorus/FX Rotary Speed"},
    {1348, "Chorus/FX Rotary Intensity"},
    {1349, "Chorus/FX Rotary Mix"},
    {1350, "Chorus/FX Rotary Doppler"},
    {1351, "Chorus/FX Rotary Crossover"},
    {1352, "Chorus/FX Rotary Balance"},
    {1410, "Chorus/FX YaYa Pedal"},
    {1412, "Chorus/FX YaYa Range"},
    {1413, "Chorus/FX YaYa Mix"},
    {1414, "Chorus/FX YaYa Depth"},
    {1416, "Chorus/FX YaYa Balance"},
    {1417, "Chorus/FX YaYa Intensity"},
    {1418, "Chorus/FX YaYa Range"},
    {1476, "Chorus/FX AutoYa Range"},
    {1477, "Chorus/FX AutoYa Mix"},
    {1478, "Chorus/FX AutoYa Speed"},
    {1479, "Chorus/FX AutoYa Depth"},
    {1481, "Chorus/FX AutoYa Balance"},
    {1482, "Chorus/FX AutoYa Intensity"},
    {1483, "Chorus/FX AutoYa Range"},
    {1540, "Chorus/FX Synthtalk Vox"},
    {1542, "Chorus/FX Synthtalk Attack"},
    {1543, "Chorus/FX Synthtalk Release"},
    {1544, "Chorus/FX Synthtalk Sens"},
    {1545, "Chorus/FX Synthtalk Balance"},
    {1604, "Chorus/FX Envelope Mix"},
    {1605, "Chorus/FX Envelope/FX25 Range"},
    {1606, "Chorus/FX Envelope/FX25 Sensitivity"},
    {1607, "Chorus/FX Envelope Balance"},
    {1608, "Chorus/FX FX25 Blend"},
    {1667, "Chorus/FX Detune Level"},
    {1668, "Chorus/FX Detune Amount"},
    {1669, "Chorus/FX Detune Balance"},
    {1730, "Chorus/FX Pitch Shift Amount"},
    {1731, "Chorus/FX Pitch Level"},
    {1733, "Chorus/FX Pitch Balance"},
    {1745, "Chorus/FX Pitch Shift Mix"},
    {1746, "Chorus/FX Octaver Octave 1"},
    {1747, "Chorus/FX Octaver Octave 2"},
    {1748, "Chorus/FX Octaver Dry Level"},
    {1795, "Chorus/FX Whammy Pedal"},
    {1796, "Chorus/FX Whammy Mix"},
    {1797, "Chorus/FX Whammy Amount"},
    {2754, "Chorus/FX IPS/Harmony Pitch Shift"},
    {2755, "Chorus/FX IPS/Harmony Pitch Scale"},
    {2756, "Chorus/FX IPS/Harmony Pitch Key"},
    {2757, "Chorus/FX IPS/Harmony Pitch Level"},
    {2882, "Chorus/FX Unovibe Chorus/Vibrato"},
    {2883, "Chorus/FX Unovibe Intensity"},
    {2884, "Chorus/FX Unovibe Pedal Speed"},
    {2885, "Chorus/FX Unovibe Volume"},
    {3010, "Chorus/FX Step Filter Speed"},
    {3011, "Chorus/FX Step Filter Intensity"},
    {3012, "Chorus/FX Sample/Hold Speed"},
    {3013, "Chorus/FX Sample/Hold Intensity"},
    {0, NULL}
};
static value_string_ext digitech_parameter_ids_chorusfx_ext =
    VALUE_STRING_EXT_INIT(digitech_parameter_ids_chorusfx);

static const value_string digitech_parameter_ids_delay[] = {
    {1857, "Delay On/Off"},
    {1860, "Delay Level"},
    {1862, "Delay Time"},
    {1863, "Delay Repeats"},
    {1864, "Delay Thresh"},
    {1865, "Delay Atten"},
    {1866, "Delay Balance"},
    {1867, "Delay Spread"},
    {1868, "Delay Tap Time"},
    {1873, "Delay Depth"},
    {1874, "Delay Repeats"},
    {1888, "Delay Time"},
    {1889, "Delay Ducker thresh"},
    {1890, "Delay Ducker level"},
    {1891, "Delay Tape Wow"},
    {1892, "Delay Tape Flutter"},
    {1893, "Delay Echo Plex Volume"},
    {1894, "Delay DM Repeat Rate"},
    {1895, "Delay DM Echo"},
    {1896, "Delay DM Intensity"},
    {1897, "Delay Echo Plex Time"},
    {1898, "Delay DM Delay Repeat Rate"},
    {1899, "Delay Echo Plex Time"},
    {1900, "Delay Tap Time"},
    {1901, "Delay Reverse Time"},
    {1902, "Delay Reverse Mix"},
    {1905, "Delay 2-tap Ratio"},
    {0, NULL}
};
static value_string_ext digitech_parameter_ids_delay_ext =
    VALUE_STRING_EXT_INIT(digitech_parameter_ids_delay);

static const value_string digitech_parameter_ids_reverb[] = {
    {1921, "Reverb On/Off"},
    {1922, "Reverb Predelay"},
    {1924, "Reverb Damping"},
    {1925, "Reverb Level"},
    {1927, "Reverb Decay"},
    {1928, "Reverb Balance"},
    {1933, "Reverb Liveliness"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_volume_post_fx[] = {
    {2626, "Pickup Volume Post FX"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_preset[] = {
    {2626, "Pickup Preset Level"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_wah_min_max[] = {
    {8195, "Wah Min"},
    {8196, "Wah Max"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_equalizer[] = {
    {3203, "Equalizer Bass"},
    {3204, "Equalizer Mid"},
    {3205, "Equalizer Treble"},
    {3206, "Equalizer Mid Hz"},
    {3207, "Equalizer Presence"},
    {3211, "Equalizer Treb Hz"},
    {3212, "Equalizer On/Off"},
    {3213, "Equalizer Low Freq"},
    {3215, "Equalizer High Freq"},
    {3216, "Equalizer Low Bandwidth"},
    {3217, "Equalizer Mid Bandwidth"},
    {3218, "Equalizer High Bandwidth"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_equalizer_b[] = {
    {3203, "Equalizer B Bass"},
    {3204, "Equalizer B Mid"},
    {3205, "Equalizer B Treble"},
    {3206, "Equalizer B Mid Hz"},
    {3207, "Equalizer B Presence"},
    {3211, "Equalizer B Treb Hz"},
    {3212, "Equalizer B On/Off"},
    {0, NULL}
};

static const value_string digitech_parameter_ids_amp_loop[] = {
    {3649, "Amp Loop On/Off"},
    {0, NULL}
};

#define DIGITECH_POSITION_GLOBAL 0
#define DIGITECH_POSITION_PICKUP 2
#define DIGITECH_POSITION_WAH 3
#define DIGITECH_POSITION_COMPRESSOR 4
#define DIGITECH_POSITION_GNX3K_WHAMMY 5
#define DIGITECH_POSITION_DISTORTION 6
#define DIGITECH_POSITION_AMP_CHANNEL 7
#define DIGITECH_POSITION_AMP 8
#define DIGITECH_POSITION_AMP_CABINET 9
#define DIGITECH_POSITION_AMP_B 10
#define DIGITECH_POSITION_AMP_CABINET_B 11
#define DIGITECH_POSITION_NOISEGATE 12
#define DIGITECH_POSITION_VOLUME_PRE_FX 13
#define DIGITECH_POSITION_CHORUS_FX 14
#define DIGITECH_POSITION_DELAY 15
#define DIGITECH_POSITION_REVERB 16
#define DIGITECH_POSITION_VOLUME_POST_FX 17
#define DIGITECH_POSITION_PRESET 18
#define DIGITECH_POSITION_EXPRESSION 19
#define DIGITECH_POSITION_WAH_MIN_MAX 20
#define DIGITECH_POSITION_V_SWITCH_ASSIGN 21
#define DIGITECH_POSITION_LFO_1 22
#define DIGITECH_POSITION_LFO_2 23
#define DIGITECH_POSITION_EQUALIZER 24
#define DIGITECH_POSITION_EQUALIZER_B 25
#define DIGITECH_POSITION_LIBRARY 26
#define DIGITECH_POSITION_AMP_LOOP 33
#define DIGITECH_POSITION_WAH_PEDAL 132

static const value_string digitech_parameter_positions[] = {
    {DIGITECH_POSITION_GLOBAL,          "Global"},
    {DIGITECH_POSITION_PICKUP,          "Pickup"},
    {DIGITECH_POSITION_WAH,             "Wah"},
    {DIGITECH_POSITION_COMPRESSOR,      "Compressor"},
    {DIGITECH_POSITION_GNX3K_WHAMMY,    "GNX3K Whammy"},
    {DIGITECH_POSITION_DISTORTION,      "Distortion"},
    {DIGITECH_POSITION_AMP_CHANNEL,     "Amp Channel"},
    {DIGITECH_POSITION_AMP,             "Amp"},
    {DIGITECH_POSITION_AMP_CABINET,     "Amp Cabinet"},
    {DIGITECH_POSITION_AMP_B,           "Amp B"},
    {DIGITECH_POSITION_AMP_CABINET_B,   "Amp Cabinet B"},
    {DIGITECH_POSITION_NOISEGATE,       "Noisegate"},
    {DIGITECH_POSITION_VOLUME_PRE_FX,   "Volume Pre Fx"},
    {DIGITECH_POSITION_CHORUS_FX,       "Chorus/FX"},
    {DIGITECH_POSITION_DELAY,           "Delay"},
    {DIGITECH_POSITION_REVERB,          "Reverb"},
    {DIGITECH_POSITION_VOLUME_POST_FX,  "Volume Post Fx"},
    {DIGITECH_POSITION_PRESET,          "Preset"},
    {DIGITECH_POSITION_EXPRESSION,      "Expression"},
    {DIGITECH_POSITION_WAH_MIN_MAX,     "Wah Min-Max"},
    {DIGITECH_POSITION_V_SWITCH_ASSIGN, "V-Switch Assign"},
    {DIGITECH_POSITION_LFO_1,           "LFO 1"},
    {DIGITECH_POSITION_LFO_2,           "LFO 2"},
    {DIGITECH_POSITION_EQUALIZER,       "Equalizer"},
    {DIGITECH_POSITION_EQUALIZER_B,     "Equalizer B"},
    {DIGITECH_POSITION_LIBRARY,         "Library"},
    {DIGITECH_POSITION_AMP_LOOP,        "Amp Loop"},
    {DIGITECH_POSITION_WAH_PEDAL,       "Wah Pedal"},
    {0, NULL}
};
static value_string_ext digitech_parameter_positions_ext =
    VALUE_STRING_EXT_INIT(digitech_parameter_positions);

static tvbuff_t *
unpack_digitech_message(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    tvbuff_t *next_tvb;
    int length = tvb_reported_length(tvb);
    int data_len = length - offset - 1;
    const uint8_t* data_ptr;
    int remaining = data_len;
    unsigned char* unpacked;
    unsigned char* unpacked_ptr;
    int unpacked_size;
    uint8_t msb;
    int i;

    unpacked_size = data_len - (data_len / 8);
    if (data_len % 8)
    {
        unpacked_size--;
    }

    data_ptr = tvb_get_ptr(tvb, offset, data_len);
    unpacked = (unsigned char*)wmem_alloc(pinfo->pool, unpacked_size);
    unpacked_ptr = unpacked;

    while (remaining > 0)
    {
        msb = *data_ptr++;
        remaining--;

        for (i = 0; (i < 7) && (remaining > 0); ++i, --remaining)
        {
            *unpacked_ptr = *data_ptr | ((msb << (i + 1)) & 0x80);
            unpacked_ptr++;
            data_ptr++;
        }
    }

    /* Create new tvb with unpacked data */
    next_tvb = tvb_new_child_real_data(tvb, unpacked, unpacked_size, unpacked_size);

    return next_tvb;
}

static int
get_digitech_hf_parameter_id_by_position(uint8_t position)
{
    int hf_parameter = hf_digitech_parameter_id;

    switch (position)
    {
        case DIGITECH_POSITION_GLOBAL:
            hf_parameter = hf_digitech_parameter_id_global;
            break;
        case DIGITECH_POSITION_PICKUP:
            hf_parameter = hf_digitech_parameter_id_pickup;
            break;
        case DIGITECH_POSITION_WAH:
            hf_parameter = hf_digitech_parameter_id_wah;
            break;
        case DIGITECH_POSITION_COMPRESSOR:
            hf_parameter = hf_digitech_parameter_id_compressor;
            break;
        case DIGITECH_POSITION_GNX3K_WHAMMY:
            hf_parameter = hf_digitech_parameter_id_gnx3k_whammy;
            break;
        case DIGITECH_POSITION_DISTORTION:
            hf_parameter = hf_digitech_parameter_id_distortion;
            break;
        case DIGITECH_POSITION_AMP_CHANNEL:
            hf_parameter = hf_digitech_parameter_id_amp_channel;
            break;
        case DIGITECH_POSITION_AMP:
            hf_parameter = hf_digitech_parameter_id_amp;
            break;
        case DIGITECH_POSITION_AMP_CABINET:
            hf_parameter = hf_digitech_parameter_id_amp_cabinet;
            break;
        case DIGITECH_POSITION_AMP_B:
            hf_parameter = hf_digitech_parameter_id_amp_b;
            break;
        case DIGITECH_POSITION_AMP_CABINET_B:
            hf_parameter = hf_digitech_parameter_id_amp_cabinet_b;
            break;
        case DIGITECH_POSITION_NOISEGATE:
            hf_parameter = hf_digitech_parameter_id_noisegate;
            break;
        case DIGITECH_POSITION_VOLUME_PRE_FX:
            hf_parameter = hf_digitech_parameter_id_volume_pre_fx;
            break;
        case DIGITECH_POSITION_CHORUS_FX:
            hf_parameter = hf_digitech_parameter_id_chorusfx;
            break;
        case DIGITECH_POSITION_DELAY:
            hf_parameter = hf_digitech_parameter_id_delay;
            break;
        case DIGITECH_POSITION_REVERB:
            hf_parameter = hf_digitech_parameter_id_reverb;
            break;
        case DIGITECH_POSITION_VOLUME_POST_FX:
            hf_parameter = hf_digitech_parameter_id_volume_post_fx;
            break;
        case DIGITECH_POSITION_PRESET:
            hf_parameter = hf_digitech_parameter_id_preset;
            break;
        case DIGITECH_POSITION_WAH_MIN_MAX:
            hf_parameter = hf_digitech_parameter_id_wah_min_max;
            break;
        case DIGITECH_POSITION_EQUALIZER:
            hf_parameter = hf_digitech_parameter_id_equalizer;
            break;
        case DIGITECH_POSITION_EQUALIZER_B:
            hf_parameter = hf_digitech_parameter_id_equalizer_b;
            break;
        case DIGITECH_POSITION_AMP_LOOP:
            hf_parameter = hf_digitech_parameter_id_amp_loop;
            break;

        case DIGITECH_POSITION_EXPRESSION:
        case DIGITECH_POSITION_V_SWITCH_ASSIGN:
        case DIGITECH_POSITION_LFO_1:
        case DIGITECH_POSITION_LFO_2:
        case DIGITECH_POSITION_LIBRARY:
        case DIGITECH_POSITION_WAH_PEDAL:
            /* TODO */
        default:
            break;
    }

    return hf_parameter;
}

/* Dissects DigiTech parameter starting at data_offset.
 * Returns new data_offset.
 */
static int
dissect_digitech_parameter(tvbuff_t *data_tvb, proto_tree *tree,
                           digitech_conv_data_t *conv_data, int data_offset)
{
    uint8_t digitech_helper;
    int hf_parameter = hf_digitech_parameter_id;

    /* Version 1 and later specify parameter position */
    if (conv_data->protocol_version >= 1)
    {
        digitech_helper = tvb_get_uint8(data_tvb, data_offset+2);
        hf_parameter = get_digitech_hf_parameter_id_by_position(digitech_helper);
    }

    proto_tree_add_item(tree, hf_parameter, data_tvb, data_offset, 2, ENC_BIG_ENDIAN);
    data_offset += 2;

    /* Add (optional) position to tree */
    if (conv_data->protocol_version >= 1)
    {
        proto_tree_add_item(tree, hf_digitech_parameter_position, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
        data_offset++;
    }

    digitech_helper = tvb_get_uint8(data_tvb, data_offset);
    /* Values 0-127 fit in one byte */
    if (digitech_helper < 0x80)
    {
        proto_tree_add_item(tree, hf_digitech_parameter_data, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
        data_offset++;
    }
    else /* digitech_helper >= 0x80 */
    {
        uint16_t data_count;

        /* Single byte data count */
        if (digitech_helper > 0x80)
        {
            data_count = (uint16_t)(digitech_helper & ~0x80);
            proto_tree_add_uint(tree, hf_digitech_parameter_data_count, data_tvb,
                                data_offset, 1, (uint32_t)data_count);
            data_offset++;
        }
        /* Two-byte data count */
        else /* digitech_helper == 0x80 */
        {
            data_count = (uint16_t)tvb_get_ntohs(data_tvb, data_offset+1);
            proto_tree_add_uint(tree, hf_digitech_parameter_data_two_byte_count, data_tvb,
                                data_offset, 3, (uint32_t)data_count);
            data_offset += 3;
        }

        proto_tree_add_item(tree, hf_digitech_parameter_multibyte_data, data_tvb,
                            data_offset, (int)data_count, ENC_NA);
        data_offset += data_count;
    }

    return data_offset;
}

static int
get_digitech_hf_product_by_family(uint8_t family)
{
    int hf_product = hf_digitech_unknown_product_id;

    switch (family)
    {
        case DIGITECH_FAMILY_RP:
            hf_product = hf_digitech_rp_product_id;
            break;
        default:
            break;
    }

    return hf_product;
}

static void
dissect_digitech_procedure(uint8_t procedure, const int offset,
                           tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *data_tvb;
    int data_offset;
    int data_len;
    uint8_t *tmp_string;
    unsigned str_size;
    uint16_t count;
    uint8_t digitech_helper;
    conversation_t *conversation;
    digitech_conv_data_t *conv_data;

    conversation = find_or_create_conversation(pinfo);
    conv_data = (digitech_conv_data_t *)conversation_get_proto_data(conversation, proto_sysex_digitech);

    if (conv_data == NULL)
    {
        conv_data = wmem_new(wmem_file_scope(), digitech_conv_data_t);
        conv_data->protocol_version = 1; /* Default to version 1 */
    }

    /* Procedure data starts at offset and ends one byte before end
     * of System Exclusive manufacturer payload (last byte is checksum)
     */
    if (tvb_reported_length(tvb) - offset < 1)
    {
        /* There is no DigiTech procedure data, do not attempt further
         * dissection */
        return;
    }

    data_tvb = unpack_digitech_message(pinfo, tvb, offset);
    add_new_data_source(pinfo, data_tvb, "Unpacked Procedure Data");

    data_offset = 0;
    data_len = tvb_reported_length(data_tvb);

    switch (procedure)
    {
        case DIGITECH_PROCEDURE_REQUEST_WHO_AM_I:
            proto_tree_add_item(tree, hf_digitech_desired_device_id, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;
            proto_tree_add_item(tree, hf_digitech_desired_family_id, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;
            proto_tree_add_item(tree, hf_digitech_desired_product_id, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;
            break;
        case DIGITECH_PROCEDURE_RECEIVE_WHO_AM_I:
            proto_tree_add_item(tree, hf_digitech_received_device_id, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            digitech_helper = tvb_get_uint8(data_tvb, data_offset);
            proto_tree_add_item(tree, hf_digitech_family_id, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            proto_tree_add_item(tree, get_digitech_hf_product_by_family(digitech_helper),
                                data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            if (data_len == 3)
            {
                /* Version 0, everything already decoded */
                conv_data->protocol_version = 0;
            }
            else if (data_len == 4)
            {
                /* Version 1 and later */
                conv_data->protocol_version = 1;

                proto_tree_add_item(tree, hf_digitech_os_mode, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
                data_offset++;
            }
            break;
        case DIGITECH_PROCEDURE_REQUEST_PRESET_NAMES:
            proto_tree_add_item(tree, hf_digitech_preset_bank, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            break;
        case DIGITECH_PROCEDURE_RECEIVE_PRESET_NAMES:
            proto_tree_add_item(tree, hf_digitech_preset_bank, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            count = (uint16_t)tvb_get_uint8(data_tvb, data_offset);
            proto_tree_add_item(tree, hf_digitech_preset_count, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            while ((count > 0) && (str_size = tvb_strsize(data_tvb, data_offset)))
            {
                tmp_string = tvb_get_string_enc(pinfo->pool, data_tvb, data_offset, str_size - 1, ENC_ASCII);
                proto_tree_add_string(tree, hf_digitech_preset_name, data_tvb, data_offset, str_size, tmp_string);
                data_offset += (int)str_size;
                count--;
            }
            break;
        case DIGITECH_PROCEDURE_REQUEST_PRESET:
            proto_tree_add_item(tree, hf_digitech_preset_bank, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            proto_tree_add_item(tree, hf_digitech_preset_index, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;
            break;
        case DIGITECH_PROCEDURE_RECEIVE_PRESET_START:
            /* Preset bank */
            proto_tree_add_item(tree, hf_digitech_preset_bank, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            /* Preset index */
            proto_tree_add_item(tree, hf_digitech_preset_index, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            /* Preset name (NULL-terminated) */
            str_size = tvb_strsize(data_tvb, data_offset);
            tmp_string = tvb_get_string_enc(pinfo->pool, data_tvb, data_offset, str_size - 1, ENC_ASCII);
            proto_tree_add_string(tree, hf_digitech_preset_name, data_tvb, data_offset, str_size, tmp_string);
            data_offset += (int)str_size;

            /* Preset modified (0 = unmodified, !0 = modified) */
            proto_tree_add_item(tree, hf_digitech_preset_modified, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;

            /* Message Count */
            proto_tree_add_item(tree, hf_digitech_message_count, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;
            break;
        case DIGITECH_PROCEDURE_RECEIVE_PRESET_PARAMETERS:
            count = tvb_get_ntohs(data_tvb, data_offset);
            proto_tree_add_item(tree, hf_digitech_parameter_count, data_tvb, data_offset, 2, ENC_BIG_ENDIAN);
            data_offset += 2;
            while (count > 0)
            {
                data_offset = dissect_digitech_parameter(data_tvb, tree, conv_data, data_offset);
                count--;
            }
            break;
        case DIGITECH_PROCEDURE_RECEIVE_PARAMETER_VALUE:
            data_offset = dissect_digitech_parameter(data_tvb, tree, conv_data, data_offset);
            break;
        case DIGITECH_PROCEDURE_ACK:
            proto_tree_add_item(tree, hf_digitech_ack_request_proc_id, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;
            break;
        case DIGITECH_PROCEDURE_NACK:
            proto_tree_add_item(tree, hf_digitech_nack_request_proc_id, data_tvb, data_offset, 1, ENC_BIG_ENDIAN);
            data_offset++;
            break;
        default:
            break;
    }

    if (data_offset < data_len)
    {
        proto_tree_add_expert(tree, pinfo, &ei_digitech_undecoded,
                                  data_tvb, data_offset, data_len - data_offset);
    }
}

static int
dissect_sysex_digitech_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    int offset = 0;
    uint8_t procedure_id;
    uint8_t digitech_helper;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    const uint8_t *data_ptr;
    int len;
    int i;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "X MIDI");
    col_set_str(pinfo->cinfo, COL_INFO, "DigiTech X MIDI SysEx");

    ti = proto_tree_add_protocol_format(parent_tree, proto_sysex_digitech, tvb, 0, -1, "DigiTech X MIDI SysEx");
    tree = proto_item_add_subtree(ti, ett_sysex_digitech);

    proto_tree_add_item(tree, hf_digitech_device_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    digitech_helper = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_digitech_family_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, get_digitech_hf_product_by_family(digitech_helper),
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    procedure_id = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_digitech_procedure_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    dissect_digitech_procedure(procedure_id, offset, tvb, pinfo, tree);

    len = tvb_reported_length(tvb) - 1;
    offset = len; /* Last byte is checksum */
    data_ptr = tvb_get_ptr(tvb, 0, len);
    /* Calculate checksum. Start with 0x10 as that's the XOR of DOD Electronics Corp.
     * The Extended Manufacturer ID is part of checksum but is not part of payload tvb.
     */
    for (i = 0, digitech_helper = 0x10; i < len; ++i)
    {
        digitech_helper ^= *data_ptr++;
    }

    proto_tree_add_checksum(tree, tvb, offset, hf_digitech_checksum, hf_digitech_checksum_status, &ei_digitech_checksum_bad, pinfo, digitech_helper,
                            ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset++;

    return offset;
}

void
proto_register_sysex_digitech(void)
{
    static hf_register_info hf[] = {
        /* DigiTech manufacturer-specific fields */
        { &hf_digitech_device_id,
            { "Device ID", "sysex_digitech.device_id", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_family_id,
            { "Family ID", "sysex_digitech.family_id", FT_UINT8, BASE_HEX,
              VALS(digitech_family_id), 0, NULL, HFILL }},
        { &hf_digitech_unknown_product_id,
            { "Product ID", "sysex_digitech.product_id", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_rp_product_id,
            { "Product ID", "sysex_digitech.product_id", FT_UINT8, BASE_HEX,
              VALS(digitech_rp_product_id), 0, NULL, HFILL }},
        { &hf_digitech_procedure_id,
            { "Procedure ID", "sysex_digitech.procedure_id", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
              &digitech_procedures_ext, 0, NULL, HFILL }},

        { &hf_digitech_desired_device_id,
            { "Desired Device ID", "sysex_digitech.desired_device_id", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_desired_family_id,
            { "Desired Family ID", "sysex_digitech.desired_family_id", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_desired_product_id,
            { "Desired Product ID", "sysex_digitech.desired_product_id", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_received_device_id,
            { "Device ID", "sysex_digitech.received_device_id", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_os_mode,
            { "OS Mode", "sysex_digitech.os_mode", FT_UINT8, BASE_HEX,
              VALS(digitech_os_modes), 0, "DigiTech OS Mode", HFILL }},

        { &hf_digitech_preset_bank,
            { "Preset Bank", "sysex_digitech.preset_bank", FT_UINT8, BASE_HEX,
              VALS(digitech_preset_banks), 0, NULL, HFILL }},
        { &hf_digitech_preset_index,
            { "Preset Index", "sysex_digitech.preset_index", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_preset_count,
            { "Preset Count", "sysex_digitech.preset_count", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_preset_name,
            { "Preset Name", "sysex_digitech.preset_name", FT_STRING, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_preset_modified,
            { "Preset Modified", "sysex_digitech.preset_modified", FT_BOOLEAN, BASE_NONE,
              TFS(&tfs_yes_no), 0, "Modified flag (0 = unmodified)", HFILL }},

        { &hf_digitech_message_count,
            { "Messages to follow", "sysex_digitech.message_count", FT_UINT8, BASE_DEC,
              NULL, 0, "Number of messages to follow", HFILL }},

        { &hf_digitech_parameter_count,
            { "Parameter Count", "sysex_digitech.parameter_count", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},

        { &hf_digitech_parameter_id,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_global,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_global), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_pickup,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_pickup), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_wah,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_wah), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_compressor,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_compressor), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_gnx3k_whammy,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC | BASE_EXT_STRING,
              &digitech_parameter_ids_gnx3k_whammy_ext, 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_distortion,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC | BASE_EXT_STRING,
              &digitech_parameter_ids_distortion_ext, 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_amp_channel,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_amp_channel), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_amp,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC | BASE_EXT_STRING,
              &digitech_parameter_ids_amp_ext, 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_amp_cabinet,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_amp_cabinet), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_amp_b,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_amp_b), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_amp_cabinet_b,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_amp_cabinet_b), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_noisegate,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_noisegate), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_volume_pre_fx,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_volume_pre_fx), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_chorusfx,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC | BASE_EXT_STRING,
              &digitech_parameter_ids_chorusfx_ext, 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_delay,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC | BASE_EXT_STRING,
              &digitech_parameter_ids_delay_ext, 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_reverb,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_reverb), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_volume_post_fx,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_volume_post_fx), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_preset,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_preset), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_wah_min_max,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_wah_min_max), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_equalizer,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_equalizer), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_equalizer_b,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_equalizer_b), 0, NULL, HFILL }},
        { &hf_digitech_parameter_id_amp_loop,
            { "Parameter ID", "sysex_digitech.parameter_id", FT_UINT16, BASE_DEC,
              VALS(digitech_parameter_ids_amp_loop), 0, NULL, HFILL }},


        { &hf_digitech_parameter_position,
            { "Parameter position", "sysex_digitech.parameter_position", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
              &digitech_parameter_positions_ext, 0, NULL, HFILL }},
        { &hf_digitech_parameter_data,
            { "Parameter data", "sysex_digitech.parameter_data", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_parameter_data_count,
            { "Parameter value count", "sysex_digitech.parameter_value_count", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_parameter_data_two_byte_count,
            { "Parameter data count", "sysex_digitech.parameter_data_count", FT_UINT24, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_parameter_multibyte_data,
            { "Parameter data", "sysex_digitech.parameter_multibyte_data", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }},

        { &hf_digitech_ack_request_proc_id,
            { "Requesting Procedure ID", "sysex_digitech.ack.procedure_id", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
              &digitech_procedures_ext, 0, "Procedure ID of the request being ACKed", HFILL }},
        { &hf_digitech_nack_request_proc_id,
            { "Requesting Procedure ID", "sysex_digitech.ack.procedure_id", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
              &digitech_procedures_ext, 0, "Procedure ID of the request being NACKed", HFILL }},

        { &hf_digitech_checksum,
            { "Checksum", "sysex_digitech.checksum", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_digitech_checksum_status,
            { "Checksum Status", "sysex_digitech.checksum.status", FT_UINT8, BASE_NONE,
              VALS(proto_checksum_vals), 0, NULL, HFILL }},
    };

    static int *sysex_digitech_subtrees[] = {
        &ett_sysex_digitech
    };

    static ei_register_info ei[] = {
        { &ei_digitech_checksum_bad, { "sysex_digitech.checksum_bad", PI_CHECKSUM, PI_WARN, "Bad checksum", EXPFILL }},
        { &ei_digitech_undecoded, { "sysex_digitech.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
    };

    expert_module_t* expert_sysex_digitech;

    proto_sysex_digitech = proto_register_protocol("MIDI System Exclusive DigiTech", "SYSEX DigiTech", "sysex_digitech");
    proto_register_field_array(proto_sysex_digitech, hf, array_length(hf));
    proto_register_subtree_array(sysex_digitech_subtrees, array_length(sysex_digitech_subtrees));
    expert_sysex_digitech = expert_register_protocol(proto_sysex_digitech);
    expert_register_field_array(expert_sysex_digitech, ei, array_length(ei));

    register_dissector("sysex_digitech", dissect_sysex_digitech_command, proto_sysex_digitech);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
