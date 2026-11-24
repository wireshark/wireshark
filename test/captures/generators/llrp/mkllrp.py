#!/usr/bin/env python3
# Generates test/captures/llrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the LLRP coverage captures: mkllrp.py <outdir> [-v]

llrp-coverage.pcap            main capture (no malformed frames)
llrp-coverage-malformed.pcap  length errors, deep nesting, truncated parameters

LAYOUTS (the field layout of every parameter) was extracted from packet-llrp.c
with extract_llrp.py and is pasted here so that this file is self-contained.
"""
LAYOUTS = {'allimp': {'ACCESS_SPEC_CONFIGURATION': 40,
            'ACCESS_SPEC_ORDERING': 66,
            'ADVANCE_GPO_CONFIG': 64,
            'ARRAY_VERSION': 1520,
            'BLOCK_PERMALOCK': 42,
            'BLOCK_PERMALOCK_OPSPEC_RESULT': 43,
            'BLOCK_WRITE_WORD_COUNT': 41,
            'DETAILED_VERSION': 29,
            'ENABLE_GPS_COORDINATES': 54,
            'ENABLE_OPTIM_READ': 65,
            'ENABLE_PEAK_RSSI': 53,
            'ENABLE_RF_DOPPLER_FREQ': 67,
            'ENABLE_RF_PHASE_ANGLE': 52,
            'ENABLE_SERIALIZED_TID': 51,
            'FIXED_FREQUENCY_LIST': 26,
            'FORKLIFT_COMPANION_BOARD_INFO': 35,
            'FORKLIFT_CONFIGURATION': 32,
            'FORKLIFT_HEIGHT_THRESHOLD': 33,
            'FORKLIFT_ZEROMOTION_TIME_THRESHOLD': 34,
            'FREQUENCY_CAPABILITIES': 30,
            'GET_BLOCK_PERMALOCK_STATUS': 44,
            'GET_BLOCK_PERMALOCK_STATUS_OPSPEC_RESULT': 45,
            'GET_QT_CONFIG': 48,
            'GET_QT_CONFIG_OPSPEC_RESULT': 49,
            'GGA_SENTENCE': 61,
            'GPI_DEBOUNCE_CONFIGURATION': 36,
            'GPS_COORDINATES': 58,
            'GPS_NMEA_SENTENCES': 60,
            'HUB_CONFIGURATION': 1538,
            'HUB_VERSIONS': 1537,
            'INVENTORY_SEARCH_MODE': 23,
            'LINK_MONITOR_CONFIGURATION': 38,
            'LOOP_SPEC': 59,
            'LOW_DUTY_CYCLE': 28,
            'OPSPEC_RETRY_COUNT': 63,
            'PEAK_RSSI': 57,
            'READER_TEMPERATURE': 37,
            'REDUCED_POWER_FREQUENCY_LIST': 27,
            'REPORT_BUFFER_CONFIGURATION': 39,
            'REQUESTED_DATA': 21,
            'RF_DOPPLER_FREQ': 68,
            'RF_PHASE_ANGLE': 56,
            'RMC_SENTENCE': 62,
            'SERIALIZED_TID': 55,
            'SET_QT_CONFIG': 46,
            'SET_QT_CONFIG_OPSPEC_RESULT': 47,
            'SUBREGULATORY_REGION': 22,
            'TAG_DIRECTION': 25,
            'TAG_DIRECTION_REPORTING': 24,
            'TAG_INFORMATION': 31,
            'TAG_REPORT_CONTENT_SELECTOR': 50},
 'alltlv': {'ACCESS_COMMAND': 209,
            'ACCESS_REPORT_SPEC': 239,
            'ACCESS_SPEC': 207,
            'ACCESS_SPEC_STOP_TRIG': 208,
            'AI_SPEC': 183,
            'AI_SPEC_EVENT': 254,
            'AI_SPEC_STOP': 184,
            'ANTENNA_AIR_PROTO': 140,
            'ANTENNA_CONF': 222,
            'ANTENNA_EVENT': 255,
            'ANTENNA_PROPS': 221,
            'ANTENNA_RCV_SENSE_RANGE': 149,
            'C1G2_BLK_ERASE': 346,
            'C1G2_BLK_ERS_OP_SPC_RES': 353,
            'C1G2_BLK_PERMALOCK': 358,
            'C1G2_BLK_PRL_OP_SPC_RES': 361,
            'C1G2_BLK_PRL_STAT_RES': 362,
            'C1G2_BLK_WRITE': 347,
            'C1G2_BLK_WRT_OP_SPC_RES': 354,
            'C1G2_EPC_MEMORY_SLCTOR': 348,
            'C1G2_FILTER': 331,
            'C1G2_GET_BLK_PERMALOCK': 359,
            'C1G2_INVENTORY_COMMAND': 330,
            'C1G2_KILL': 343,
            'C1G2_KILL_OP_SPEC_RES': 351,
            'C1G2_LLRP_CAP': 327,
            'C1G2_LOCK': 344,
            'C1G2_LOCK_OP_SPEC_RES': 352,
            'C1G2_LOCK_PAYLOAD': 345,
            'C1G2_READ': 341,
            'C1G2_READ_OP_SPEC_RES': 349,
            'C1G2_RECOMMISSION': 357,
            'C1G2_RECOM_OP_SPEC_RES': 360,
            'C1G2_RF_CONTROL': 335,
            'C1G2_SINGULATION_CTRL': 336,
            'C1G2_TAG_INV_AWARE_FLTR': 333,
            'C1G2_TAG_INV_AWARE_SING': 337,
            'C1G2_TAG_INV_MASK': 332,
            'C1G2_TAG_INV_UNAWR_FLTR': 334,
            'C1G2_TAG_SPEC': 338,
            'C1G2_TARGET_TAG': 339,
            'C1G2_UHF_RF_MD_TBL': 328,
            'C1G2_UHF_RF_MD_TBL_ENT': 329,
            'C1G2_WRITE': 342,
            'C1G2_WRT_OP_SPEC_RES': 350,
            'CLIENT_REQ_OP_SPEC': 210,
            'CLIENT_REQ_RESPONSE': 211,
            'CONN_ATTEMPT_EVENT': 256,
            'CONN_CLOSE_EVENT': 257,
            'CUSTOM_PARAMETER': 1023,
            'EPC_DATA': 241,
            'EVENTS_AND_REPORTS': 226,
            'EVENT_NOTIF_STATE': 245,
            'FIELD_ERROR': 288,
            'FIXED_FREQ_TABLE': 148,
            'FREQ_HOP_TABLE': 147,
            'FREQ_INFORMATION': 146,
            'FREQ_RSSI_LEVEL_ENTRY': 243,
            'GENERAL_DEVICE_CAP': 137,
            'GPIO_CAPABILITIES': 141,
            'GPI_EVENT': 248,
            'GPI_PORT_CURRENT_STATE': 225,
            'GPI_TRIGGER_VAL': 181,
            'GPO_WRITE_DATA': 219,
            'HOPPING_EVENT': 247,
            'IDENT': 218,
            'INVENTORY_PARAM_SPEC': 186,
            'KEEPALIVE_SPEC': 220,
            'LLRP_CAPABILITIES': 142,
            'LLRP_CONF_STATE_VAL': 217,
            'LLRP_STATUS': 287,
            'LOOP_SPEC': 355,
            'MAX_RECEIVE_SENSE': 363,
            'PARAM_ERROR': 289,
            'PER_TRIGGER_VAL': 180,
            'READER_EVENT_NOTI_DATA': 246,
            'READER_EVENT_NOTI_SPEC': 244,
            'READER_EXCEPTION_EVENT': 252,
            'RECEIVE_SENSE_ENTRY': 139,
            'REGU_CAPABILITIES': 143,
            'REPORT_BUF_LEVEL_WARN': 250,
            'REPORT_BUF_OVERFLOW_ERR': 251,
            'RF_RECEIVER': 223,
            'RF_SURVEY_EVENT': 253,
            'RF_SURVEY_FREQ_CAP': 365,
            'RF_SURVEY_REPORT_DATA': 242,
            'RF_SURVEY_SPEC': 187,
            'RF_SURVEY_SPEC_STOP_TR': 188,
            'RF_TRANSMITTER': 224,
            'RO_BOUND_SPEC': 178,
            'RO_REPORT_SPEC': 237,
            'RO_SPEC': 177,
            'RO_SPEC_EVENT': 249,
            'RO_SPEC_START_TRIGGER': 179,
            'RO_SPEC_STOP_TRIGGER': 182,
            'SPEC_LOOP_EVENT': 356,
            'TAG_OBSERV_TRIGGER': 185,
            'TAG_REPORT_CONTENT_SEL': 238,
            'TAG_REPORT_DATA': 240,
            'UHF_CAPABILITIES': 144,
            'UPTIME': 129,
            'UTC_TIMESTAMP': 128,
            'XMIT_POWER_LEVEL_ENTRY': 145},
 'imp': {'ACCESS_SPEC_CONFIGURATION': (40, []),
         'ACCESS_SPEC_ORDERING': (66, [('n', 2)]),
         'ADVANCE_GPO_CONFIG': (64, [('n', 2), ('n', 2), ('n', 4)]),
         'ARRAY_VERSION': (1520, [('str',), ('str',), ('str',)]),
         'BLOCK_PERMALOCK': (42, [('n', 2), ('n', 4), ('n', 1), ('n', 2), ('n', 2)]),
         'BLOCK_PERMALOCK_OPSPEC_RESULT': (43, [('n', 1), ('n', 2)]),
         'BLOCK_WRITE_WORD_COUNT': (41, [('n', 2)]),
         'DETAILED_VERSION': (29, [('str',), ('str',), ('str',), ('str',), ('str',), ('str',)]),
         'ENABLE_GPS_COORDINATES': (54, [('n', 2)]),
         'ENABLE_OPTIM_READ': (65, [('n', 2)]),
         'ENABLE_PEAK_RSSI': (53, [('n', 2)]),
         'ENABLE_RF_DOPPLER_FREQ': (67, [('n', 2)]),
         'ENABLE_RF_PHASE_ANGLE': (52, [('n', 2)]),
         'ENABLE_SERIALIZED_TID': (51, [('n', 2)]),
         'FIXED_FREQUENCY_LIST': (26, [('n', 2), ('n', 2), ('arr', 2)]),
         'FORKLIFT_COMPANION_BOARD_INFO': (35, [('str',), ('n', 2), ('n', 2)]),
         'FORKLIFT_CONFIGURATION': (32, []),
         'FORKLIFT_HEIGHT_THRESHOLD': (33, [('n', 2)]),
         'FORKLIFT_ZEROMOTION_TIME_THRESHOLD': (34, [('n', 2)]),
         'FREQUENCY_CAPABILITIES': (30, [('arr', 4)]),
         'GET_BLOCK_PERMALOCK_STATUS': (44, [('n', 2), ('n', 4), ('n', 1), ('n', 2), ('n', 2)]),
         'GET_BLOCK_PERMALOCK_STATUS_OPSPEC_RESULT': (45, [('n', 1), ('n', 2)]),
         'GET_QT_CONFIG': (48, [('n', 2), ('n', 4)]),
         'GET_QT_CONFIG_OPSPEC_RESULT': (49, [('n', 1), ('n', 2), ('n', 1), ('n', 1), ('n', 4)]),
         'GGA_SENTENCE': (61, [('str',)]),
         'GPI_DEBOUNCE_CONFIGURATION': (36, [('n', 2), ('n', 4)]),
         'GPS_COORDINATES': (58, [('n', 4), ('n', 4)]),
         'GPS_NMEA_SENTENCES': (60, []),
         'HUB_CONFIGURATION': (1538, [('n', 2), ('n', 2), ('n', 2), ('kids',)]),
         'HUB_VERSIONS': (1537, []),
         'INVENTORY_SEARCH_MODE': (23, [('n', 2)]),
         'LINK_MONITOR_CONFIGURATION': (38, [('n', 2), ('n', 2)]),
         'LOOP_SPEC': (59, [('n', 4)]),
         'LOW_DUTY_CYCLE': (28, [('n', 2), ('n', 2), ('n', 2)]),
         'OPSPEC_RETRY_COUNT': (63, [('n', 2)]),
         'PEAK_RSSI': (57, [('n', 2)]),
         'READER_TEMPERATURE': (37, [('n', 2)]),
         'REDUCED_POWER_FREQUENCY_LIST': (27, [('n', 2), ('n', 2), ('arr', 2)]),
         'REPORT_BUFFER_CONFIGURATION': (39, [('n', 2)]),
         'REQUESTED_DATA': (21, [('n', 4)]),
         'RF_DOPPLER_FREQ': (68, [('n', 2)]),
         'RF_PHASE_ANGLE': (56, [('n', 2)]),
         'RMC_SENTENCE': (62, [('str',)]),
         'SERIALIZED_TID': (55, [('n', 2)]),
         'SET_QT_CONFIG': (46, [('n', 2), ('n', 4), ('n', 1), ('n', 1), ('n', 1), ('n', 4)]),
         'SET_QT_CONFIG_OPSPEC_RESULT': (47, [('n', 1), ('n', 2)]),
         'SUBREGULATORY_REGION': (22, [('n', 2)]),
         'TAG_DIRECTION': (25, [('n', 8), ('n', 2), ('n', 2)]),
         'TAG_DIRECTION_REPORTING': (24, [('n', 2), ('n', 2), ('n', 4)]),
         'TAG_INFORMATION': (31, []),
         'TAG_REPORT_CONTENT_SELECTOR': (50, [])},
 'imp_msg': {'ENABLE_EXTENSIONS': 21, 'ENABLE_EXTENSIONS_RESPONSE': 22, 'SAVE_SETTINGS': 23, 'SAVE_SETTINGS_RESPONSE': 24},
 'msg': {'ADD_ACCESSSPEC': 40,
         'ADD_ACCESSSPEC_RESPONSE': 50,
         'ADD_ROSPEC': 20,
         'ADD_ROSPEC_RESPONSE': 30,
         'CLIENT_REQUEST_OP': 45,
         'CLIENT_RESQUEST_OP_RESPONSE': 55,
         'CLOSE_CONNECTION': 14,
         'CLOSE_CONNECTION_RESPONSE': 4,
         'CUSTOM_MESSAGE': 1023,
         'DELETE_ACCESSSPEC': 41,
         'DELETE_ACCESSSPEC_RESPONSE': 51,
         'DELETE_ROSPEC': 21,
         'DELETE_ROSPEC_RESPONSE': 31,
         'DISABLE_ACCESSSPEC': 43,
         'DISABLE_ACCESSSPEC_RESPONSE': 53,
         'DISABLE_ROSPEC': 25,
         'DISABLE_ROSPEC_RESPONSE': 35,
         'ENABLE_ACCESSSPEC': 42,
         'ENABLE_ACCESSSPEC_RESPONSE': 52,
         'ENABLE_EVENTS_AND_REPORTS': 64,
         'ENABLE_ROSPEC': 24,
         'ENABLE_ROSPEC_RESPONSE': 34,
         'ERROR_MESSAGE': 100,
         'GET_ACCESSSPECS': 44,
         'GET_ACCESSSPECS_RESPONSE': 54,
         'GET_READER_CAPABILITIES': 1,
         'GET_READER_CAPABILITIES_RESPONSE': 11,
         'GET_READER_CONFIG': 2,
         'GET_READER_CONFIG_RESPONSE': 12,
         'GET_REPORT': 60,
         'GET_ROSPECS': 26,
         'GET_ROSPECS_RESPONSE': 36,
         'GET_SUPPORTED_VERSION': 46,
         'GET_SUPPORTED_VERSION_RESPONSE': 56,
         'KEEPALIVE': 62,
         'KEEPALIVE_ACK': 72,
         'READER_EVENT_NOTIFICATION': 63,
         'RO_ACCESS_REPORT': 61,
         'SET_PROTOCOL_VERSION': 47,
         'SET_PROTOCOL_VERSION_RESPONSE': 57,
         'SET_READER_CONFIG': 3,
         'SET_READER_CONFIG_RESPONSE': 13,
         'START_ROSPEC': 22,
         'START_ROSPEC_RESPONSE': 32,
         'STOP_ROSPEC': 23,
         'STOP_ROSPEC_RESPONSE': 33},
 'tlv': {'ACCESS_COMMAND': (209, [('kids',)]),
         'ACCESS_REPORT_SPEC': (239, [('n', 1)]),
         'ACCESS_SPEC': (207, [('n', 4), ('n', 2), ('n', 1), ('n', 1), ('n', 4), ('kids',)]),
         'ACCESS_SPEC_STOP_TRIG': (208, [('n', 1), ('n', 2)]),
         'AI_SPEC': (183, [('arr', 2), ('kids',)]),
         'AI_SPEC_EVENT': (254, [('n', 1), ('n', 4), ('n', 2), ('kids',)]),
         'AI_SPEC_STOP': (184, [('n', 1), ('n', 4), ('kids',)]),
         'ANTENNA_AIR_PROTO': (140, [('n', 2), ('arr', 1)]),
         'ANTENNA_CONF': (222, [('n', 2), ('kids',)]),
         'ANTENNA_EVENT': (255, [('n', 1), ('n', 2)]),
         'ANTENNA_PROPS': (221, [('n', 1), ('n', 2), ('n', 2)]),
         'ANTENNA_RCV_SENSE_RANGE': (149, [('n', 2), ('n', 2), ('n', 2)]),
         'C1G2_BLK_ERASE': (346, [('n', 2), ('n', 4), ('n', 1), ('n', 2), ('n', 2)]),
         'C1G2_BLK_ERS_OP_SPC_RES': (353, [('n', 1), ('n', 2)]),
         'C1G2_BLK_PERMALOCK': (358, [('n', 2), ('n', 4), ('n', 1), ('n', 2), ('words',)]),
         'C1G2_BLK_PRL_OP_SPC_RES': (361, [('n', 1), ('n', 2)]),
         'C1G2_BLK_PRL_STAT_RES': (362, [('n', 1), ('n', 2), ('words',)]),
         'C1G2_BLK_WRITE': (347, [('n', 2), ('n', 4), ('n', 1), ('n', 2), ('words',)]),
         'C1G2_BLK_WRT_OP_SPC_RES': (354, [('n', 1), ('n', 2), ('n', 2)]),
         'C1G2_EPC_MEMORY_SLCTOR': (348, [('n', 1)]),
         'C1G2_FILTER': (331, [('n', 1), ('kids',)]),
         'C1G2_GET_BLK_PERMALOCK': (359, [('n', 2), ('n', 4), ('n', 1), ('n', 2), ('n', 2)]),
         'C1G2_INVENTORY_COMMAND': (330, [('n', 1), ('kids',)]),
         'C1G2_KILL': (343, [('n', 2), ('n', 4)]),
         'C1G2_KILL_OP_SPEC_RES': (351, [('n', 1), ('n', 2)]),
         'C1G2_LLRP_CAP': (327, [('n', 1), ('n', 2)]),
         'C1G2_LOCK': (344, [('n', 2), ('n', 4), ('kids',)]),
         'C1G2_LOCK_OP_SPEC_RES': (352, [('n', 1), ('n', 2)]),
         'C1G2_LOCK_PAYLOAD': (345, [('n', 1), ('n', 1)]),
         'C1G2_READ': (341, [('n', 2), ('n', 4), ('n', 1), ('n', 2), ('n', 2)]),
         'C1G2_READ_OP_SPEC_RES': (349, [('n', 1), ('n', 2), ('words',)]),
         'C1G2_RECOMMISSION': (357, [('n', 2), ('n', 4), ('n', 1)]),
         'C1G2_RECOM_OP_SPEC_RES': (360, [('n', 1), ('n', 2)]),
         'C1G2_RF_CONTROL': (335, [('n', 2), ('n', 2)]),
         'C1G2_SINGULATION_CTRL': (336, [('n', 1), ('n', 2), ('n', 4), ('kids',)]),
         'C1G2_TAG_INV_AWARE_FLTR': (333, [('n', 1), ('n', 1)]),
         'C1G2_TAG_INV_AWARE_SING': (337, [('n', 1)]),
         'C1G2_TAG_INV_MASK': (332, [('n', 1), ('n', 2), ('bits',)]),
         'C1G2_TAG_INV_UNAWR_FLTR': (334, [('n', 1)]),
         'C1G2_TAG_SPEC': (338, [('kids',)]),
         'C1G2_TARGET_TAG': (339, [('n', 1), ('n', 2), ('bits',), ('bits',)]),
         'C1G2_UHF_RF_MD_TBL': (328, [('kids',)]),
         'C1G2_UHF_RF_MD_TBL_ENT': (329,
                                    [('n', 4), ('n', 1), ('n', 1), ('n', 1), ('n', 1), ('n', 4), ('n', 4), ('n', 4), ('n', 4),
                                     ('n', 4)]),
         'C1G2_WRITE': (342, [('n', 2), ('n', 4), ('n', 1), ('n', 2), ('words',)]),
         'C1G2_WRT_OP_SPEC_RES': (350, [('n', 1), ('n', 2), ('n', 2)]),
         'CLIENT_REQ_OP_SPEC': (210, [('n', 2)]),
         'CLIENT_REQ_RESPONSE': (211, [('n', 4), ('kids',)]),
         'CONN_ATTEMPT_EVENT': (256, [('n', 2)]),
         'CONN_CLOSE_EVENT': (257, []),
         'CUSTOM_PARAMETER': (1023, [('n', 4), ('impinj',)]),
         'EPC_DATA': (241, [('bits',)]),
         'EVENTS_AND_REPORTS': (226, [('n', 1)]),
         'EVENT_NOTIF_STATE': (245, [('n', 2), ('n', 1)]),
         'FIELD_ERROR': (288, [('n', 2), ('n', 2)]),
         'FIXED_FREQ_TABLE': (148, [('arr', 4)]),
         'FREQ_HOP_TABLE': (147, [('n', 1), ('n', 1), ('arr', 4)]),
         'FREQ_INFORMATION': (146, [('n', 1), ('kids',)]),
         'FREQ_RSSI_LEVEL_ENTRY': (243, [('n', 4), ('n', 4), ('n', 1), ('n', 1), ('kids',)]),
         'GENERAL_DEVICE_CAP': (137, [('n', 2), ('n', 2), ('n', 4), ('n', 4), ('str',), ('kids',)]),
         'GPIO_CAPABILITIES': (141, [('n', 2), ('n', 2)]),
         'GPI_EVENT': (248, [('n', 2), ('n', 1)]),
         'GPI_PORT_CURRENT_STATE': (225, [('n', 2), ('n', 1), ('n', 1)]),
         'GPI_TRIGGER_VAL': (181, [('n', 2), ('n', 1), ('n', 4)]),
         'GPO_WRITE_DATA': (219, [('n', 2), ('n', 1)]),
         'HOPPING_EVENT': (247, [('n', 2), ('n', 2)]),
         'IDENT': (218, [('n', 1), ('ident',)]),
         'INVENTORY_PARAM_SPEC': (186, [('n', 2), ('n', 1), ('kids',)]),
         'KEEPALIVE_SPEC': (220, [('n', 1), ('n', 4)]),
         'LLRP_CAPABILITIES': (142, [('n', 1), ('n', 1), ('n', 2), ('n', 4), ('n', 4), ('n', 4), ('n', 4), ('n', 4)]),
         'LLRP_CONF_STATE_VAL': (217, [('n', 4)]),
         'LLRP_STATUS': (287, [('n', 2), ('str',), ('kids',)]),
         'LOOP_SPEC': (355, [('n', 4)]),
         'MAX_RECEIVE_SENSE': (363, [('n', 2)]),
         'PARAM_ERROR': (289, [('n', 2), ('n', 2), ('kids',)]),
         'PER_TRIGGER_VAL': (180, [('n', 4), ('n', 4), ('kids',)]),
         'READER_EVENT_NOTI_DATA': (246, [('kids',)]),
         'READER_EVENT_NOTI_SPEC': (244, [('kids',)]),
         'READER_EXCEPTION_EVENT': (252, [('str',), ('kids',)]),
         'RECEIVE_SENSE_ENTRY': (139, [('n', 2), ('n', 2)]),
         'REGU_CAPABILITIES': (143, [('n', 2), ('n', 2), ('kids',)]),
         'REPORT_BUF_LEVEL_WARN': (250, [('n', 1)]),
         'REPORT_BUF_OVERFLOW_ERR': (251, []),
         'RF_RECEIVER': (223, [('n', 2)]),
         'RF_SURVEY_EVENT': (253, [('n', 1), ('n', 4), ('n', 2)]),
         'RF_SURVEY_FREQ_CAP': (365, [('n', 4), ('n', 4)]),
         'RF_SURVEY_REPORT_DATA': (242, [('kids',)]),
         'RF_SURVEY_SPEC': (187, [('n', 2), ('n', 4), ('n', 4), ('kids',)]),
         'RF_SURVEY_SPEC_STOP_TR': (188, [('n', 1), ('n', 4), ('n', 4)]),
         'RF_TRANSMITTER': (224, [('n', 2), ('n', 2), ('n', 2)]),
         'RO_BOUND_SPEC': (178, [('kids',)]),
         'RO_REPORT_SPEC': (237, [('n', 1), ('n', 2), ('kids',)]),
         'RO_SPEC': (177, [('n', 4), ('n', 1), ('n', 1), ('kids',)]),
         'RO_SPEC_EVENT': (249, [('n', 1), ('n', 4), ('n', 4)]),
         'RO_SPEC_START_TRIGGER': (179, [('n', 1), ('kids',)]),
         'RO_SPEC_STOP_TRIGGER': (182, [('n', 1), ('n', 4), ('kids',)]),
         'SPEC_LOOP_EVENT': (356, [('n', 4), ('n', 4)]),
         'TAG_OBSERV_TRIGGER': (185, [('n', 1), ('n', 1), ('n', 2), ('n', 2), ('n', 2), ('n', 4)]),
         'TAG_REPORT_CONTENT_SEL': (238, [('n', 2), ('kids',)]),
         'TAG_REPORT_DATA': (240, [('kids',)]),
         'UHF_CAPABILITIES': (144, [('kids',)]),
         'UPTIME': (129, [('n', 8)]),
         'UTC_TIMESTAMP': (128, [('n', 8)]),
         'XMIT_POWER_LEVEL_ENTRY': (145, [('n', 2), ('n', 2)])},
 'tv': {'ACCESS_SPEC_ID': (16, 4),
        'ANTENNA_ID': (1, 2),
        'C1G2_CRC': (11, 2),
        'C1G2_PC': (12, 2),
        'C1G2_SINGULATION_DET': (18, 4),
        'C1G2_XPC_W1': (19, 2),
        'C1G2_XPC_W2': (20, 2),
        'CHANNEL_INDEX': (7, 2),
        'CLIENT_REQ_OP_SPEC_RES': (15, 2),
        'EPC96': (13, 12),
        'FIRST_SEEN_TIME_UPTIME': (3, 8),
        'FIRST_SEEN_TIME_UTC': (2, 8),
        'INVENTORY_PARAM_SPEC_ID': (10, 2),
        'LAST_SEEN_TIME_UPTIME': (5, 8),
        'LAST_SEEN_TIME_UTC': (4, 8),
        'OP_SPEC_ID': (17, 2),
        'PEAK_RSSI': (6, 1),
        'RO_SPEC_ID': (9, 4),
        'SPEC_INDEX': (14, 2),
        'TAG_SEEN_COUNT': (8, 2)}}

# ---------------------------------------------------------------- generator
import struct
import sys
import os
from pylib import Pcap, Tcp

IMPINJ = 25882
TLV = LAYOUTS['tlv']
IMP = LAYOUTS['imp']
TV = LAYOUTS['tv']
MSG = LAYOUTS['msg']
IMPMSG = LAYOUTS['imp_msg']


def tlv_param(t, body):
    return struct.pack('>HH', t, 4 + len(body)) + body


def tv_param(t, body):
    return bytes((0x80 | t,)) + body


def tv_by_name(name, fill=0):
    t, n = TV[name]
    return tv_param(t, bytes((fill,)) * n)


def leaf_kids():
    """A couple of small valid child parameters"""
    return tlv_param(TLV['UTC_TIMESTAMP'][0], bytes(8)) + tv_by_name('ANTENNA_ID')


def body_for(layout, fill, kids=None, impinj_sub=None):
    out = b''
    f = bytes((fill,))
    for u in layout:
        k = u[0]
        if k == 'n':
            out += f * u[1]
        elif k == 'str':
            out += struct.pack('>H', 4) + b'abcd'
        elif k == 'bits':
            out += struct.pack('>H', 16) + f * 2
        elif k == 'words':
            out += struct.pack('>H', 2) + f * 4
        elif k == 'arr':
            out += struct.pack('>H', 2) + f * (2 * u[1])
        elif k == 'kids':
            out += kids if kids is not None else leaf_kids()
        elif k == 'ident':
            out += struct.pack('>H', 4) + b'ID01'
    return out


def std_param(name, fill=0):
    t, lay = TLV[name]
    if name == 'CUSTOM_PARAMETER':
        return None
    return tlv_param(t, body_for(lay, fill))


def impinj_param(name, fill=0, tail=b''):
    t, lay = IMP[name]
    body = struct.pack('>II', IMPINJ, t) + body_for(lay, fill) + tail
    return tlv_param(TLV['CUSTOM_PARAMETER'][0], body)


def msg(mtype, body=b'', mid=1, ver=1):
    return struct.pack('>HII', (ver << 10) | mtype, 10 + len(body), mid) + body


def custom_msg(subtype, body=b'', mid=1, vendor=IMPINJ):
    return msg(MSG['CUSTOM_MESSAGE'], struct.pack('>I', vendor) + bytes((subtype,)) + body, mid)


def main(out, verbose=False):
    p = Pcap()
    marks = []
    conv = {'n': 0}

    def mark(name):
        marks.append((len(p.frames) + 1, name))

    def new_conn(sport):
        t = Tcp(p, sport=sport, dport=5084)
        t.hs()
        return t

    names_ends_params = ['CLOSE_CONNECTION_RESPONSE', 'GET_READER_CAPABILITIES_RESPONSE', 'ADD_ROSPEC', 'ADD_ROSPEC_RESPONSE',
                         'DELETE_ROSPEC_RESPONSE', 'START_ROSPEC_RESPONSE', 'STOP_ROSPEC_RESPONSE', 'ENABLE_ROSPEC_RESPONSE',
                         'DISABLE_ROSPEC_RESPONSE', 'GET_ROSPECS_RESPONSE', 'ADD_ACCESSSPEC', 'ADD_ACCESSSPEC_RESPONSE',
                         'DELETE_ACCESSSPEC_RESPONSE', 'ENABLE_ACCESSSPEC_RESPONSE', 'DISABLE_ACCESSSPEC_RESPONSE',
                         'GET_ACCESSSPECS', 'CLIENT_REQUEST_OP', 'CLIENT_RESQUEST_OP_RESPONSE', 'RO_ACCESS_REPORT',
                         'READER_EVENT_NOTIFICATION', 'ERROR_MESSAGE', 'GET_READER_CONFIG_RESPONSE',
                         'SET_READER_CONFIG_RESPONSE', 'SET_PROTOCOL_VERSION_RESPONSE', 'GET_ACCESSSPECS_RESPONSE',
                         'GET_REPORT', 'ENABLE_EVENTS_AND_REPORTS']

    # ---- 1. messages of every type
    mark('Messages of every type (version 1 and 2), over TCP 5084')
    c = new_conn(50001)
    mid = [0]

    def send(m, fwd=True):
        mid[0] += 1
        c.seg(m, fwd)

    for n in ('KEEPALIVE', 'KEEPALIVE_ACK', 'CLOSE_CONNECTION', 'GET_ROSPECS', 'GET_SUPPORTED_VERSION'):
        send(msg(MSG[n], mid=mid[0] + 1))
    for n in ('START_ROSPEC', 'STOP_ROSPEC', 'ENABLE_ROSPEC', 'DISABLE_ROSPEC', 'DELETE_ROSPEC'):
        send(msg(MSG[n], struct.pack('>I', 0 if n == 'DELETE_ROSPEC' else 7), mid[0] + 1))
    for n in ('ENABLE_ACCESSSPEC', 'DELETE_ACCESSSPEC', 'DISABLE_ACCESSSPEC'):
        send(msg(MSG[n], struct.pack('>I', 0 if n == 'DELETE_ACCESSSPEC' else 9), mid[0] + 1))
    send(msg(MSG['GET_READER_CAPABILITIES'], bytes((3,)) + std_param('GENERAL_DEVICE_CAP'), mid[0] + 1))
    send(msg(MSG['GET_READER_CAPABILITIES'], bytes((0,)), mid[0] + 1, ver=2))
    for req in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11):
        send(msg(MSG['GET_READER_CONFIG'], struct.pack('>HBHH', 1, req, 2, 3), mid[0] + 1))
    send(msg(MSG['SET_READER_CONFIG'], bytes((0x80,)) + std_param('GPO_WRITE_DATA'), mid[0] + 1))
    send(msg(MSG['SET_READER_CONFIG'], bytes((0,)), mid[0] + 1))
    send(msg(MSG['GET_SUPPORTED_VERSION_RESPONSE'], bytes((2, 2)) + std_param('UTC_TIMESTAMP'), mid[0] + 1), False)
    send(msg(0x3FF - 1, b'unknown message type', mid[0] + 1))        # unknown message type (not dissected)
    # custom messages
    send(custom_msg(IMPMSG['ENABLE_EXTENSIONS'], bytes(4)))
    send(custom_msg(IMPMSG['ENABLE_EXTENSIONS_RESPONSE'], std_param('LLRP_STATUS') or b''), False)
    send(custom_msg(IMPMSG['SAVE_SETTINGS'], bytes((0x80,))))
    send(custom_msg(IMPMSG['SAVE_SETTINGS_RESPONSE'], b''), False)
    send(custom_msg(99, b''))                                           # unknown Impinj subtype
    send(msg(MSG['CUSTOM_MESSAGE'], struct.pack('>I', 12345), mid[0] + 1))   # unknown vendor

    # ---- 2. TLV and Impinj parameters, spread over the messages that end with parameters
    mark('Every TLV parameter, twice (fill 0x00 and 0x55), nested in messages that end with parameters')
    c = new_conn(50002)
    plist = []
    for name in sorted(TLV, key=lambda n: TLV[n][0]):
        for fill in (0x00, 0x55):
            pr = std_param(name, fill)
            if pr:
                plist.append(pr)
    # group parameters 4 per message, cycling through the message types
    i = 0
    for k in range(0, len(plist), 4):
        n = names_ends_params[i % len(names_ends_params)]
        i += 1
        c.seg(msg(MSG[n], b''.join(plist[k:k + 4]), 100 + k), k % 8 < 4)
    mark('TLV parameters with kids: parents holding a list of children')
    kidsets = [tv_by_name('ANTENNA_ID') + tv_by_name('PEAK_RSSI') + tv_by_name('EPC96', 0x33),
               tlv_param(TLV['UTC_TIMESTAMP'][0], bytes(8)) + tlv_param(TLV['UPTIME'][0], bytes(8))]
    for name, (t, lay) in sorted(TLV.items(), key=lambda kv: kv[1][0]):
        if ('kids',) in lay:
            for ks in kidsets:
                c.seg(msg(MSG['RO_ACCESS_REPORT'], tlv_param(t, body_for(lay, 0, ks)), 300 + t), True)
    # TV parameters
    mark('TV parameters (all 20) and an unknown TV type')
    tvs = b''.join(tv_by_name(n, 0x11) for n in TV) + tv_param(127, b'')
    c.seg(msg(MSG['RO_ACCESS_REPORT'], tlv_param(TLV['TAG_REPORT_DATA'][0], tvs), 400), False)
    # unknown TLV parameter (no body)
    c.seg(msg(MSG['RO_ACCESS_REPORT'], tlv_param(900, b'')), False)

    mark('Impinj custom parameters, every type, twice, and an unknown Impinj subtype and an unknown vendor')
    c = new_conn(50003)
    ip = []
    for name in sorted(IMP, key=lambda n: IMP[n][0]):
        for fill in (0x00, 0x55):
            ip.append(impinj_param(name, fill))
    for k in range(0, len(ip), 4):
        c.seg(msg(MSG['RO_ACCESS_REPORT'], b''.join(ip[k:k + 4]), 500 + k), True)
    # trailing custom parameter inside an Impinj parameter (nested), unknown subtype, unknown vendor
    inner = impinj_param('ENABLE_OPTIM_READ')
    c.seg(msg(MSG['RO_ACCESS_REPORT'], impinj_param('TAG_INFORMATION', 0, inner), 600), True)
    c.seg(msg(MSG['RO_ACCESS_REPORT'], impinj_param('LOW_DUTY_CYCLE', 1, inner), 601), True)
    c.seg(msg(MSG['RO_ACCESS_REPORT'], tlv_param(1023, struct.pack('>II', IMPINJ, 999)), 602), True)
    c.seg(msg(MSG['RO_ACCESS_REPORT'], tlv_param(1023, struct.pack('>I', 4242) + b'vendor specific data'), 603), True)
    c.seg(msg(MSG['RO_ACCESS_REPORT'], tlv_param(1023, struct.pack('>I', 4242)), 604), True)

    # ---- 3. reproducer: nested Impinj custom parameters (the depth bound)
    mark('Reproducer: 600 nested Impinj custom parameters (depth bound)')
    N = 600
    body = b''
    for _ in range(N):
        inner = struct.pack('>II', IMPINJ, IMP['TAG_INFORMATION'][0]) + body
        body = struct.pack('>HH', 1023, 4 + len(inner)) + inner
    c.seg(custom_msg(IMPMSG['ENABLE_EXTENSIONS_RESPONSE'], body, 700), False)

    # ---- 4. TCP framing
    mark('TCP framing: two messages in one segment, a message over three segments, a segment with a message and the start of the next')
    c = new_conn(50004)
    m1 = msg(MSG['KEEPALIVE'], mid=1)
    m2 = msg(MSG['GET_READER_CAPABILITIES_RESPONSE'], std_param('GENERAL_DEVICE_CAP') + std_param('LLRP_CAPABILITIES'), 2)
    c.seg(m1 + m1)
    c.seg(m2[:12])
    c.seg(m2[12:20])
    c.seg(m2[20:])
    c.seg(m1 + m2[:12])
    c.seg(m2[12:])

    p.write(os.path.join(out, 'llrp-coverage.pcap'))
    if verbose:
        for i, (n, name) in enumerate(marks):
            end = marks[i + 1][0] - 1 if i + 1 < len(marks) else len(p.frames)
            print('%d-%d: %s' % (n, end, name))
        print('total', len(p.frames))

    # ------------------------------------------------------------------ malformed
    m = Pcap()
    mc = Tcp(m, sport=51000, dport=5084)
    mc.hs()
    S = lambda d, fwd=True: mc.seg(d, fwd)
    S(msg(MSG['SET_PROTOCOL_VERSION'], bytes((2,))))                       # offset not advanced: "incorrect length" expert info
    S(struct.pack('>HII', (1 << 10) | MSG['KEEPALIVE'], 99, 1) + bytes(0)) # length field larger than the data
    S(msg(MSG['KEEPALIVE'], b'extra data'))                                # trailing data in a message without body
    S(msg(MSG['START_ROSPEC'], bytes(2)))                                  # ROSpec ID cut short
    S(msg(MSG['RO_ACCESS_REPORT'], struct.pack('>HH', TLV['UTC_TIMESTAMP'][0], 2)))   # TLV length below 4
    S(msg(MSG['RO_ACCESS_REPORT'], struct.pack('>HH', TLV['UTC_TIMESTAMP'][0], 400) + bytes(8)))   # length beyond the message
    S(msg(MSG['RO_ACCESS_REPORT'], tlv_param(TLV['UTC_TIMESTAMP'][0], bytes(3))))    # body cut short
    S(msg(MSG['RO_ACCESS_REPORT'], tlv_param(TLV['UTC_TIMESTAMP'][0], bytes(12))))   # body longer than the layout
    S(msg(MSG['GET_READER_CAPABILITIES_RESPONSE'], tlv_param(TLV['GENERAL_DEVICE_CAP'][0], bytes(12) + struct.pack('>H', 40) + b'ab')))   # string longer than the parameter
    S(msg(MSG['RO_ACCESS_REPORT'], tlv_param(TLV['ANTENNA_AIR_PROTO'][0], struct.pack('>HH', 1, 200) + bytes(2))))   # array longer than the message
    S(msg(MSG['RO_ACCESS_REPORT'], tlv_param(TLV['FREQ_HOP_TABLE'][0], bytes((1, 0)) + struct.pack('>H', 500))))
    S(msg(MSG['RO_ACCESS_REPORT'], tlv_param(TLV['IDENT'][0], b'\x01' + struct.pack('>H', 300) + b'ab')))   # reader ID longer than the parameter
    # parameters nested deeper than the bound of 16
    body = leaf_kids()
    for _ in range(20):
        body = tlv_param(TLV['TAG_REPORT_DATA'][0], body)
    S(msg(MSG['RO_ACCESS_REPORT'], body))
    S(msg(MSG['RO_ACCESS_REPORT'], tlv_param(1023, struct.pack('>II', IMPINJ, 99))))     # unknown subtype
    S(msg(MSG['RO_ACCESS_REPORT'], tlv_param(1023, struct.pack('>I', IMPINJ))))          # Impinj custom parameter without subtype
    S(msg(MSG['RO_ACCESS_REPORT'], struct.pack('>HHI', 1023, 6, 4242)[:6]))               # custom parameter length below the vendor ID
    S(msg(MSG['RO_ACCESS_REPORT'], struct.pack('>HHI', 1023, 4, 0) + b''))                # custom parameter length 4 (the old len-8 bug)
    S(msg(MSG['RO_ACCESS_REPORT'], impinj_param('DETAILED_VERSION')[:-6]))
    S(custom_msg(IMPMSG['ENABLE_EXTENSIONS'], bytes(2)))                                  # RFU cut short
    S(msg(MSG['GET_READER_CONFIG'], bytes(4)))
    S(msg(MSG['GET_READER_CONFIG'], struct.pack('>HBHH', 1, 99, 2, 3)))     # unknown configuration request
    S(bytes(5))                                                                          # shorter than a header
    m.write(os.path.join(out, 'llrp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
