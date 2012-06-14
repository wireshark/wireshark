/* packet-llrp.c
 * Routines for Low Level Reader Protocol dissection
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * http://www.gs1.org/gsmp/kc/epcglobal/llrp
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#define LLRP_PORT 5084

/* Initialize the protocol and registered fields */
static int proto_llrp         = -1;
static int hf_llrp_version    = -1;
static int hf_llrp_type       = -1;
static int hf_llrp_length     = -1;
static int hf_llrp_id         = -1;
static int hf_llrp_cur_ver    = -1;
static int hf_llrp_sup_ver    = -1;
static int hf_llrp_req_cap    = -1;
static int hf_llrp_req_conf   = -1;
static int hf_llrp_rospec     = -1;
static int hf_llrp_antenna_id = -1;
static int hf_llrp_gpi_port   = -1;
static int hf_llrp_gpo_port   = -1;
static int hf_llrp_rest_fact  = -1;
static int hf_llrp_accessspec = -1;
static int hf_llrp_vendor     = -1;
static int hf_llrp_tlv_type   = -1;
static int hf_llrp_tv_type    = -1;
static int hf_llrp_tlv_len    = -1;
static int hf_llrp_param      = -1;

/* Initialize the subtree pointers */
static gint ett_llrp = -1;
static gint ett_llrp_param = -1;

/* Message Types */
#define LLRP_TYPE_GET_READER_CAPABILITES            1
#define LLRP_TYPE_GET_READER_CONFIG                 2
#define LLRP_TYPE_SET_READER_CONFIG                 3
#define LLRP_TYPE_CLOSE_CONNECTION_RESPONSE         4
#define LLRP_TYPE_GET_READER_CAPABILITES_RESPONSE  11
#define LLRP_TYPE_GET_READER_CONFIG_RESPONSE       12
#define LLRP_TYPE_SET_READER_CONFIG_RESPONSE       13
#define LLRP_TYPE_CLOSE_CONNECTION                 14
#define LLRP_TYPE_ADD_ROSPEC                       20
#define LLRP_TYPE_DELETE_ROSPEC                    21
#define LLRP_TYPE_START_ROSPEC                     22
#define LLRP_TYPE_STOP_ROSPEC                      23
#define LLRP_TYPE_ENABLE_ROSPEC                    24
#define LLRP_TYPE_DISABLE_ROSPEC                   25
#define LLRP_TYPE_GET_ROSPECS                      26
#define LLRP_TYPE_ADD_ROSPEC_RESPONSE              30
#define LLRP_TYPE_DELETE_ROSPEC_RESPONSE           31
#define LLRP_TYPE_START_ROSPEC_RESPONSE            32
#define LLRP_TYPE_STOP_ROSPEC_RESPONSE             33
#define LLRP_TYPE_ENABLE_ROSPEC_RESPONSE           34
#define LLRP_TYPE_DISABLE_ROSPEC_RESPONSE          35
#define LLRP_TYPE_GET_ROSPECS_RESPONSE             36
#define LLRP_TYPE_ADD_ACCESSSPEC                   40
#define LLRP_TYPE_DELETE_ACCESSSPEC                41
#define LLRP_TYPE_ENABLE_ACCESSSPEC                42
#define LLRP_TYPE_DISABLE_ACCESSSPEC               43
#define LLRP_TYPE_GET_ACCESSSPECS                  44
#define LLRP_TYPE_CLIENT_REQUEST_OP                45
#define LLRP_TYPE_GET_SUPPORTED_VERSION            46
#define LLRP_TYPE_SET_PROTOCOL_VERSION             47
#define LLRP_TYPE_ADD_ACCESSSPEC_RESPONSE          50
#define LLRP_TYPE_DELETE_ACCESSSPEC_RESPONSE       51
#define LLRP_TYPE_ENABLE_ACCESSSPEC_RESPONSE       52
#define LLRP_TYPE_DISABLE_ACCESSSPEC_RESPONSE      53
#define LLRP_TYPE_GET_ACCESSSPECS_RESPONSE         54
#define LLRP_TYPE_CLIENT_RESQUEST_OP_RESPONSE      55
#define LLRP_TYPE_GET_SUPPORTED_VERSION_RESPONSE   56
#define LLRP_TYPE_SET_PROTOCOL_VERSION_RESPONSE    57
#define LLRP_TYPE_GET_REPORT                       60
#define LLRP_TYPE_RO_ACCESS_REPORT                 61
#define LLRP_TYPE_KEEPALIVE                        62
#define LLRP_TYPE_READER_EVENT_NOTIFICATION        63
#define LLRP_TYPE_ENABLE_EVENTS_AND_REPORTS        64
#define LLRP_TYPE_KEEPALIVE_ACK                    72
#define LLRP_TYPE_ERROR_MESSAGE                   100
#define LLRP_TYPE_CUSTOM_MESSAGE                 1023

static const value_string message_types[] = {
    { LLRP_TYPE_GET_READER_CAPABILITES,          "Get Reader Capabilites"          },
    { LLRP_TYPE_GET_READER_CONFIG,               "Get Reader Config"               },
    { LLRP_TYPE_SET_READER_CONFIG,               "Set Reader Config"               },
    { LLRP_TYPE_CLOSE_CONNECTION_RESPONSE,       "Close Connection Response"       },
    { LLRP_TYPE_GET_READER_CAPABILITES_RESPONSE, "Get Reader Capabilites Response" },
    { LLRP_TYPE_GET_READER_CONFIG_RESPONSE,      "Get Reader Config Response"      },
    { LLRP_TYPE_SET_READER_CONFIG_RESPONSE,      "Set Reader Config Response"      },
    { LLRP_TYPE_CLOSE_CONNECTION,                "Close Connection"                },
    { LLRP_TYPE_ADD_ROSPEC,                      "Add ROSpec"                      },
    { LLRP_TYPE_DELETE_ROSPEC,                   "Delete ROSpec"                   },
    { LLRP_TYPE_START_ROSPEC,                    "Start ROSpec"                    },
    { LLRP_TYPE_STOP_ROSPEC,                     "Stop ROSpec"                     },
    { LLRP_TYPE_ENABLE_ROSPEC,                   "Enable ROSpec"                   },
    { LLRP_TYPE_DISABLE_ROSPEC,                  "Disable ROSpec"                  },
    { LLRP_TYPE_GET_ROSPECS,                     "Get ROSpecs"                     },
    { LLRP_TYPE_ADD_ROSPEC_RESPONSE,             "Add ROSpec Response"             },
    { LLRP_TYPE_DELETE_ROSPEC_RESPONSE,          "Delete ROSpec Response"          },
    { LLRP_TYPE_START_ROSPEC_RESPONSE,           "Start ROSpec Response"           },
    { LLRP_TYPE_STOP_ROSPEC_RESPONSE,            "Stop ROSpec Response"            },
    { LLRP_TYPE_ENABLE_ROSPEC_RESPONSE,          "Enable ROSpec Response"          },
    { LLRP_TYPE_DISABLE_ROSPEC_RESPONSE,         "Disable ROSpec Response"         },
    { LLRP_TYPE_GET_ROSPECS_RESPONSE,            "Get ROSpecs Response"            },
    { LLRP_TYPE_ADD_ACCESSSPEC,                  "Add AccessSpec"                  },
    { LLRP_TYPE_DELETE_ACCESSSPEC,               "Delete AccessSpec"               },
    { LLRP_TYPE_ENABLE_ACCESSSPEC,               "Enable AccessSpec"               },
    { LLRP_TYPE_DISABLE_ACCESSSPEC,              "Disable AccessSpec"              },
    { LLRP_TYPE_GET_ACCESSSPECS,                 "Get AccessSpecs"                 },
    { LLRP_TYPE_CLIENT_REQUEST_OP,               "Client Request OP"               },
    { LLRP_TYPE_GET_SUPPORTED_VERSION,           "Get Supported Version"           },
    { LLRP_TYPE_SET_PROTOCOL_VERSION,            "Set Protocol Version"            },
    { LLRP_TYPE_ADD_ACCESSSPEC_RESPONSE,         "Add AccessSpec Response"         },
    { LLRP_TYPE_DELETE_ACCESSSPEC_RESPONSE,      "Delete AccessSpec Response"      },
    { LLRP_TYPE_ENABLE_ACCESSSPEC_RESPONSE,      "Enable AccessSpec Response"      },
    { LLRP_TYPE_DISABLE_ACCESSSPEC_RESPONSE,     "Disable AccessSpec Response"     },
    { LLRP_TYPE_GET_ACCESSSPECS_RESPONSE,        "Get AccessSpecs Response"        },
    { LLRP_TYPE_CLIENT_RESQUEST_OP_RESPONSE,     "Client Resquest OP Response"     },
    { LLRP_TYPE_GET_SUPPORTED_VERSION_RESPONSE,  "Get Supported Version Response"  },
    { LLRP_TYPE_SET_PROTOCOL_VERSION_RESPONSE,   "Set Protocol Version Response"   },
    { LLRP_TYPE_GET_REPORT,                      "Get Report"                      },
    { LLRP_TYPE_RO_ACCESS_REPORT,                "RO Access Report"                },
    { LLRP_TYPE_KEEPALIVE,                       "Keepalive"                       },
    { LLRP_TYPE_READER_EVENT_NOTIFICATION,       "Reader Event Notification"       },
    { LLRP_TYPE_ENABLE_EVENTS_AND_REPORTS,       "Enable Events And Reports"       },
    { LLRP_TYPE_KEEPALIVE_ACK,                   "Keepalive Ack"                   },
    { LLRP_TYPE_ERROR_MESSAGE,                   "Error Message"                   },
    { LLRP_TYPE_CUSTOM_MESSAGE,                  "Custom Message"                  },
    { 0,                                          NULL                             }
};

/* Versions */
#define LLRP_VERS_1_0_1 0x01
#define LLRP_VERS_1_1   0x02

static const value_string llrp_versions[] = {
    { LLRP_VERS_1_0_1, "1.0.1" },
    { LLRP_VERS_1_1,   "1.1"   },
    { 0,                NULL   }
};

/* Capabilities */
#define LLRP_CAP_ALL            0
#define LLRP_CAP_GENERAL_DEVICE 1
#define LLRP_CAP_LLRP           2
#define LLRP_CAP_REGULATORY     3
#define LLRP_CAP_AIR_PROTOCOL   4

static const value_string capabilities_request[] = {
    { LLRP_CAP_ALL,            "All"                            },
    { LLRP_CAP_GENERAL_DEVICE, "General Device Capabilities"    },
    { LLRP_CAP_LLRP,           "LLRP Capabilites"               },
    { LLRP_CAP_REGULATORY,     "Regulatory Capabilities"        },
    { LLRP_CAP_AIR_PROTOCOL,   "Air Protocol LLRP Capabilities" },
    { 0,                        NULL                            }
};

/* Configurations */
#define LLRP_CONF_ALL                             0
#define LLRP_CONF_IDENTIFICATION                  1
#define LLRP_CONF_ANTENNA_PROPERTIES              2
#define LLRP_CONF_ANTENNA_CONFIGURATION           3
#define LLRP_CONF_RO_REPORT_SPEC                  4
#define LLRP_CONF_READER_EVENT_NOTIFICATION_SPEC  5
#define LLRP_CONF_ACCESS_REPORT_SPEC              6
#define LLRP_CONF_LLRP_CONFIGURATION_STATE        7
#define LLRP_CONF_KEEPALIVE_SPEC                  8
#define LLRP_CONF_GPI_PORT_CURRENT_STATE          9
#define LLRP_CONF_GPO_WRITE_DATA                 10
#define LLRP_CONF_EVENTS_AND_REPORTS             11

static const value_string config_request[] = {
    { LLRP_CONF_ALL,                            "All"                            },
    { LLRP_CONF_IDENTIFICATION,                 "Identification"                 },
    { LLRP_CONF_ANTENNA_PROPERTIES,             "Antenna Properties"             },
    { LLRP_CONF_ANTENNA_CONFIGURATION,          "Antenna Configuration"          },
    { LLRP_CONF_RO_REPORT_SPEC,                 "RO Report Spec"                 },
    { LLRP_CONF_READER_EVENT_NOTIFICATION_SPEC, "Reader Event Notification Spec" },
    { LLRP_CONF_ACCESS_REPORT_SPEC,             "Access Report Spec"             },
    { LLRP_CONF_LLRP_CONFIGURATION_STATE,       "LLRP Configuration State"       },
    { LLRP_CONF_KEEPALIVE_SPEC,                 "Keepalive Spec"                 },
    { LLRP_CONF_GPI_PORT_CURRENT_STATE,         "GPI Port Current State"         },
    { LLRP_CONF_GPO_WRITE_DATA,                 "GPO Write Data"                 },
    { LLRP_CONF_EVENTS_AND_REPORTS,             "Events and Reports"             },
    { 0,                                         NULL                            }
};
   
/* TLV Parameter Types */
#define LLRP_TLV_UTC_TIMESTAMP           128
#define LLRP_TLV_UPTIME                  129
#define LLRP_TLV_GENERAL_DEVICE_CAP      137
#define LLRP_TLV_RECEIVE_SENSE_ENTRY     139
#define LLRP_TLV_ANTENNA_AIR_PROTO       140
#define LLRP_TLV_GPIO_CAPABILITIES       141
#define LLRP_TLV_LLRP_CAPABILITIES       142
#define LLRP_TLV_REGU_CAPABILITIES       143
#define LLRP_TLV_UHF_CAPABILITIES        144
#define LLRP_TLV_XMIT_POWER_LEVEL_ENTRY  145
#define LLRP_TLV_FREQ_INFORMATION        146
#define LLRP_TLV_FREQ_HOP_TABLE          147
#define LLRP_TLV_FIXED_FREQ_TABLE        148
#define LLRP_TLV_ANTENNA_RCV_SENSE_RANGE 149
#define LLRP_TLV_RO_SPEC                 177
#define LLRP_TLV_RO_BOUND_SPEC           178
#define LLRP_TLV_RO_SPEC_START_TRIGGER   179
#define LLRP_TLV_PER_TRIGGER_VAL         180
#define LLRP_TLV_GPI_TRIGGER_VAL         181
#define LLRP_TLV_RO_SPEC_STOP_TRIGGER    182
#define LLRP_TLV_AI_SPEC                 183
#define LLRP_TLV_AI_SPEC_STOP            184
#define LLRP_TLV_TAG_OBSERV_TRIGGER      185
#define LLRP_TLV_INVENTORY_PARAM_SPEC    186
#define LLRP_TLV_RF_SURVEY_SPEC          187
#define LLRP_TLV_RF_SURVEY_SPEC_STOP_TR  188
#define LLRP_TLV_ACCESS_SPEC             207
#define LLRP_TLV_ACCESS_SPEC_STOP_TRIG   208
#define LLRP_TLV_ACCESS_COMMAND          209
#define LLRP_TLV_CLIENT_REQ_OP_SPEC      210
#define LLRP_TLV_CLIENT_REQ_RESPONSE     211
#define LLRP_TLV_LLRP_CONF_STATE_VAL     217
#define LLRP_TLV_IDENT                   218
#define LLRP_TLV_GPO_WRITE_DATA          219
#define LLRP_TLV_KEEPALIVE_SPEC          220
#define LLRP_TLV_ANTENNA_PROPS           221
#define LLRP_TLV_ANTENNA_CONF            222
#define LLRP_TLV_RF_RECEIVER             223
#define LLRP_TLV_RF_TRANSMITTER          224
#define LLRP_TLV_GPI_PORT_CURRENT_STATE  225
#define LLRP_TLV_EVENTS_AND_REPORTS      226
#define LLRP_TLV_RO_REPORT_SPEC          237
#define LLRP_TLV_TAG_REPORT_CONTENT_SEL  238
#define LLRP_TLV_ACCESS_REPORT_SPEC      239
#define LLRP_TLV_TAG_REPORT_DATA         240
#define LLRP_TLV_EPC_DATA                241
#define LLRP_TLV_RF_SURVEY_REPORT_DATA   242
#define LLRP_TLV_FREQ_RSSI_LEVEL_ENTRY   243
#define LLRP_TLV_READER_EVENT_NOTI_SPEC  244
#define LLRP_TLV_EVENT_NOTIF_STATE       245
#define LLRP_TLV_READER_EVENT_NOTI_DATA  246
#define LLRP_TLV_HOPPING_EVENT           247
#define LLRP_TLV_GPI_EVENT               248
#define LLRP_TLV_RO_SPEC_EVENT           249
#define LLRP_TLV_REPORT_BUF_LEVEL_WARN   250
#define LLRP_TLV_REPORT_BUF_OVERFLOW_ERR 251
#define LLRP_TLV_READER_EXCEPTION_EVENT  252
#define LLRP_TLV_RF_SURVEY_EVENT         253
#define LLRP_TLV_AI_SPEC_EVENT           254
#define LLRP_TLV_ANTENNA_EVENT           255
#define LLRP_TLV_CONN_ATTEMPT_EVENT      256
#define LLRP_TLV_CONN_CLOSE_EVENT        257
#define LLRP_TLV_LLRP_STATUS             287
#define LLRP_TLV_FIELD_ERROR             288
#define LLRP_TLV_PARAM_ERROR             289
#define LLRP_TLV_C1G2_LLRP_CAP           327
#define LLRP_TLV_C1G2_UHF_RF_MD_TBL      328
#define LLRP_TLV_C1G2_UHF_RF_MD_TBL_ENT  329
#define LLRP_TLV_C1G2_INVENTORY_COMMAND  330
#define LLRP_TLV_C1G2_FILTER             331
#define LLRP_TLV_C1G2_TAG_INV_MASK       332
#define LLRP_TLV_C1G2_TAG_INV_AWARE_FLTR 333
#define LLRP_TLV_C1G2_TAG_INV_UNAWR_FLTR 334
#define LLRP_TLV_C1G2_RF_CONTROL         335
#define LLRP_TLV_C1G2_SINGULATION_CTRL   336
#define LLRP_TLV_C1G2_TAG_INV_AWARE_SING 337
#define LLRP_TLV_C1G2_TAG_SPEC           338
#define LLRP_TLV_C1G2_TARGET_TAG         339
#define LLRP_TLV_C1G2_READ               341
#define LLRP_TLV_C1G2_WRITE              342
#define LLRP_TLV_C1G2_KILL               343
#define LLRP_TLV_C1G2_LOCK               344
#define LLRP_TLV_C1G2_LOCK_PAYLOAD       345
#define LLRP_TLV_C1G2_BLK_ERASE          346
#define LLRP_TLV_C1G2_BLK_WRITE          347
#define LLRP_TLV_C1G2_EPC_MEMORY_SLCTOR  348
#define LLRP_TLV_C1G2_READ_OP_SPEC_RES   349
#define LLRP_TLV_C1G2_WRT_OP_SPEC_RES    350
#define LLRP_TLV_C1G2_KILL_OP_SPEC_RES   351
#define LLRP_TLV_C1G2_LOCK_OP_SPEC_RES   352
#define LLRP_TLV_C1G2_BLK_ERS_OP_SPC_RES 353
#define LLRP_TLV_C1G2_BLK_WRT_OP_SPC_RES 354
#define LLRP_TLV_LOOP_SPEC               355
#define LLRP_TLV_MAX_RECEIVE_SENSE       363
#define LLRP_TLV_RF_SURVEY_FREQ_CAP      365

static const value_string tlv_type[] = {
    { LLRP_TLV_UTC_TIMESTAMP,           "UTC Timestamp"                                  },
    { LLRP_TLV_UPTIME,                  "Uptime"                                         },
    { LLRP_TLV_GENERAL_DEVICE_CAP,      "General Device Capabilities"                    },
    { LLRP_TLV_RECEIVE_SENSE_ENTRY,     "Receive Sensitivity Entry"                      },
    { LLRP_TLV_ANTENNA_AIR_PROTO,       "Antenna Air Protocol"                           },
    { LLRP_TLV_GPIO_CAPABILITIES,       "GPIO Capabilities"                              },
    { LLRP_TLV_LLRP_CAPABILITIES,       "LLRP Capabilities"                              },
    { LLRP_TLV_REGU_CAPABILITIES,       "REGU Capabilities"                              },
    { LLRP_TLV_UHF_CAPABILITIES,        "UHF Capabilities"                               },
    { LLRP_TLV_XMIT_POWER_LEVEL_ENTRY,  "Transmit Power Level Entry"                     },
    { LLRP_TLV_FREQ_INFORMATION,        "Frequency Information"                          },
    { LLRP_TLV_FREQ_HOP_TABLE,          "Frequenct Hop Table"                            },
    { LLRP_TLV_FIXED_FREQ_TABLE,        "Fixed Frequency Table"                          },
    { LLRP_TLV_ANTENNA_RCV_SENSE_RANGE, "Antenna RCV Sensitivity Range"                  },
    { LLRP_TLV_RO_SPEC,                 "RO Spec"                                        },
    { LLRP_TLV_RO_BOUND_SPEC,           "RO Bound Spec"                                  },
    { LLRP_TLV_RO_SPEC_START_TRIGGER,   "RO Spec Start Trigger"                          },
    { LLRP_TLV_PER_TRIGGER_VAL,         "PER Trigger Value"                              },
    { LLRP_TLV_GPI_TRIGGER_VAL,         "GPI Trigger Value"                              },
    { LLRP_TLV_RO_SPEC_STOP_TRIGGER,    "RO Spec Stop Trigger"                           },
    { LLRP_TLV_AI_SPEC,                 "AI Spec"                                        },
    { LLRP_TLV_AI_SPEC_STOP,            "AI Spec Stop"                                   },
    { LLRP_TLV_TAG_OBSERV_TRIGGER,      "Tag Observation Trigger"                        },
    { LLRP_TLV_INVENTORY_PARAM_SPEC,    "Inventory Parameter Spec ID"                    },
    { LLRP_TLV_RF_SURVEY_SPEC,          "RF Survey Spec"                                 },
    { LLRP_TLV_RF_SURVEY_SPEC_STOP_TR,  "RF Survey Spec Stop Trigger"                    },
    { LLRP_TLV_ACCESS_SPEC,             "Access Spec"                                    },
    { LLRP_TLV_ACCESS_SPEC_STOP_TRIG,   "Access Spec Stop Trigger"                       },
    { LLRP_TLV_ACCESS_COMMAND,          "Access Command"                                 },
    { LLRP_TLV_CLIENT_REQ_OP_SPEC,      "Client Request Op Spec"                         },
    { LLRP_TLV_CLIENT_REQ_RESPONSE,     "Client Request Response"                        },
    { LLRP_TLV_LLRP_CONF_STATE_VAL,     "LLRP Configuration State Value"                 },
    { LLRP_TLV_IDENT,                   "Identification"                                 },
    { LLRP_TLV_GPO_WRITE_DATA,          "GPO Write Data"                                 },
    { LLRP_TLV_KEEPALIVE_SPEC,          "Keepalive Spec"                                 },
    { LLRP_TLV_ANTENNA_PROPS,           "Antenna Properties"                             },
    { LLRP_TLV_ANTENNA_CONF,            "Antenna Configuration"                          },
    { LLRP_TLV_RF_RECEIVER,             "RF Receiver"                                    },
    { LLRP_TLV_RF_TRANSMITTER,          "RF Transmitter"                                 },
    { LLRP_TLV_GPI_PORT_CURRENT_STATE,  "GPI Port Current State"                         },
    { LLRP_TLV_EVENTS_AND_REPORTS,      "Events And Reports"                             },
    { LLRP_TLV_RO_REPORT_SPEC,          "RO Report Spec"                                 },
    { LLRP_TLV_TAG_REPORT_CONTENT_SEL,  "Tag Report Content Selector"                    },
    { LLRP_TLV_ACCESS_REPORT_SPEC,      "Access Report Spec"                             },
    { LLRP_TLV_TAG_REPORT_DATA,         "Tag Report Data"                                },
    { LLRP_TLV_EPC_DATA,                "EPC Data"                                       },
    { LLRP_TLV_RF_SURVEY_REPORT_DATA,   "RF Survey Report Data"                          },
    { LLRP_TLV_FREQ_RSSI_LEVEL_ENTRY,   "Frequency RSSI Level Entry"                     },
    { LLRP_TLV_READER_EVENT_NOTI_SPEC,  "Reader Event Notification Spec"                 },
    { LLRP_TLV_EVENT_NOTIF_STATE,       "Event Notification State"                       },
    { LLRP_TLV_READER_EVENT_NOTI_DATA,  "Reader Event Notification Data"                 },
    { LLRP_TLV_HOPPING_EVENT,           "Hopping Event"                                  },
    { LLRP_TLV_GPI_EVENT,               "GPI Event"                                      },
    { LLRP_TLV_RO_SPEC_EVENT,           "RO Spec Event"                                  },
    { LLRP_TLV_REPORT_BUF_LEVEL_WARN,   "Report Buffer Level Warning Event"              },
    { LLRP_TLV_REPORT_BUF_OVERFLOW_ERR, "Report Buffer Overflow Error Event"             },
    { LLRP_TLV_READER_EXCEPTION_EVENT,  "Reader Exception Event"                         },
    { LLRP_TLV_RF_SURVEY_EVENT,         "RF Survey Event"                                },
    { LLRP_TLV_AI_SPEC_EVENT,           "AI Spec Event"                                  },
    { LLRP_TLV_ANTENNA_EVENT,           "ANTENNA Event"                                  },
    { LLRP_TLV_CONN_ATTEMPT_EVENT,      "CONN Attempt Event"                             },
    { LLRP_TLV_CONN_CLOSE_EVENT,        "CONN Close Event"                               },
    { LLRP_TLV_LLRP_STATUS,             "LLRP Status"                                    },
    { LLRP_TLV_FIELD_ERROR,             "Field Error"                                    },
    { LLRP_TLV_PARAM_ERROR,             "Param Error"                                    },
    { LLRP_TLV_C1G2_LLRP_CAP,           "C1G2 LLRP Capabilities"                         },
    { LLRP_TLV_C1G2_UHF_RF_MD_TBL,      "C1G2 UHF RF Mode Table"                         },
    { LLRP_TLV_C1G2_UHF_RF_MD_TBL_ENT,  "C1G2 UHF RF Mode Table Entry"                   },
    { LLRP_TLV_C1G2_INVENTORY_COMMAND,  "C1G2 Inventory Command"                         },
    { LLRP_TLV_C1G2_FILTER,             "C1G2 Filter"                                    },
    { LLRP_TLV_C1G2_TAG_INV_MASK,       "C1G2 Tag Inventory Mask"                        },
    { LLRP_TLV_C1G2_TAG_INV_AWARE_FLTR, "C1G2 Tag Inventory State-Aware Filtre Action"   },
    { LLRP_TLV_C1G2_TAG_INV_UNAWR_FLTR, "C1G2 Tag Inventory State-Unaware Filter Action" },
    { LLRP_TLV_C1G2_RF_CONTROL,         "C1G2 RF Control"                                },
    { LLRP_TLV_C1G2_SINGULATION_CTRL,   "C1G2 Singulation Control"                       },
    { LLRP_TLV_C1G2_TAG_INV_AWARE_SING, "C1G2 Tag Inventory State-Aware Singulation"     },
    { LLRP_TLV_C1G2_TAG_SPEC,           "C1G2 Tag Spec"                                  },
    { LLRP_TLV_C1G2_TARGET_TAG,         "C1G2 Target Tag"                                },
    { LLRP_TLV_C1G2_READ,               "C1G2 Read"                                      },
    { LLRP_TLV_C1G2_WRITE,              "C1G2 Write"                                     },
    { LLRP_TLV_C1G2_KILL,               "C1G2 Kill"                                      },
    { LLRP_TLV_C1G2_LOCK,               "C1G2 Lock"                                      },
    { LLRP_TLV_C1G2_LOCK_PAYLOAD,       "C1G2 Lock Payload"                              },
    { LLRP_TLV_C1G2_BLK_ERASE,          "C1G2 Block Erase"                               },
    { LLRP_TLV_C1G2_BLK_WRITE,          "C1G2 Block Write"                               },
    { LLRP_TLV_C1G2_EPC_MEMORY_SLCTOR,  "C1G2 EPC Memory Selector"                       },
    { LLRP_TLV_C1G2_READ_OP_SPEC_RES,   "C1G2 Read Op Spec Result"                       },
    { LLRP_TLV_C1G2_WRT_OP_SPEC_RES,    "C1G2 Write Op Spec Result"                      },
    { LLRP_TLV_C1G2_KILL_OP_SPEC_RES,   "C1G2 Kill Op Spec Result"                       },
    { LLRP_TLV_C1G2_LOCK_OP_SPEC_RES,   "C1G2 Lock Op Spec Result"                       },
    { LLRP_TLV_C1G2_BLK_ERS_OP_SPC_RES, "C1G2 Block Erase Op Spec Result"                },
    { LLRP_TLV_C1G2_BLK_WRT_OP_SPC_RES, "C1G2 Block Write Op Spec Result"                },
    { LLRP_TLV_LOOP_SPEC,               "Loop Spec"                                      },
    { LLRP_TLV_MAX_RECEIVE_SENSE,       "Maximum Receive Sensitivity"                    },
    { LLRP_TLV_RF_SURVEY_FREQ_CAP,      "RF Survey Frequency Capabilities"               },
    { 0,                                 NULL                                            }
};

/* TV Parameter Types */
#define LLRP_TV_ANTENNA_ID               1
#define LLRP_TV_FIRST_SEEN_TIME_UTC      2
#define LLRP_TV_FIRST_SEEN_TIME_UPTIME   3
#define LLRP_TV_LAST_SEEN_TIME_UTC       4
#define LLRP_TV_LAST_SEEN_TIME_UPTIME    5
#define LLRP_TV_PEAK_RSSI                6
#define LLRP_TV_CHANNEL_INDEX            7
#define LLRP_TV_TAG_SEEN_COUNT           8
#define LLRP_TV_RO_SPEC_ID               9
#define LLRP_TV_INVENTORY_PARAM_SPEC_ID 10
#define LLRP_TV_C1G2_CRC                11
#define LLRP_TV_C1G2_PC                 12
#define LLRP_TV_EPC96                   13
#define LLRP_TV_SPEC_INDEX              14
#define LLRP_TV_CLIENT_REQ_OP_SPEC_RES  15
#define LLRP_TV_ACCESS_SPEC_ID          16
#define LLRP_TV_OP_SPEC_ID              17
#define LLRP_TV_C1G2_SINGULATION_DET    18
#define LLRP_TV_C1G2_XPC_W1             19
#define LLRP_TV_C1G2_XPC_W2             20

/* Since TV's don't have a length field,
 * use these values instead */
#define LLRP_TV_LEN_ANTENNA_ID               2
#define LLRP_TV_LEN_FIRST_SEEN_TIME_UTC      8
#define LLRP_TV_LEN_FIRST_SEEN_TIME_UPTIME   8
#define LLRP_TV_LEN_LAST_SEEN_TIME_UTC       8
#define LLRP_TV_LEN_LAST_SEEN_TIME_UPTIME    8
#define LLRP_TV_LEN_PEAK_RSSI                1
#define LLRP_TV_LEN_CHANNEL_INDEX            2
#define LLRP_TV_LEN_TAG_SEEN_COUNT           2
#define LLRP_TV_LEN_RO_SPEC_ID               4
#define LLRP_TV_LEN_INVENTORY_PARAM_SPEC_ID  2
#define LLRP_TV_LEN_C1G2_CRC                 2
#define LLRP_TV_LEN_C1G2_PC                  2
#define LLRP_TV_LEN_EPC96                    2
#define LLRP_TV_LEN_SPEC_INDEX               2
#define LLRP_TV_LEN_CLIENT_REQ_OP_SPEC_RES   2
#define LLRP_TV_LEN_ACCESS_SPEC_ID           4
#define LLRP_TV_LEN_OP_SPEC_ID               2
#define LLRP_TV_LEN_C1G2_SINGULATION_DET     4
#define LLRP_TV_LEN_C1G2_XPC_W1              2
#define LLRP_TV_LEN_C1G2_XPC_W2              2

static const value_string tv_type[] = {
    { LLRP_TV_ANTENNA_ID,              "Antenna ID"                    },
    { LLRP_TV_FIRST_SEEN_TIME_UTC,     "First Seen Timestamp UTC"      },
    { LLRP_TV_FIRST_SEEN_TIME_UPTIME,  "First Seen Timestamp Uptime"   },
    { LLRP_TV_LAST_SEEN_TIME_UTC,      "Last Seen Timestamp UTC"       },
    { LLRP_TV_LAST_SEEN_TIME_UPTIME,   "Last Seen Timestamp Uptime"    },
    { LLRP_TV_PEAK_RSSI,               "Peak RSSI"                     },
    { LLRP_TV_CHANNEL_INDEX,           "Channel Index"                 },
    { LLRP_TV_TAG_SEEN_COUNT,          "Tag Seen Count"                },
    { LLRP_TV_RO_SPEC_ID,              "RO Spec ID"                    },
    { LLRP_TV_INVENTORY_PARAM_SPEC_ID, "Inventory Parameter Spec ID"   },
    { LLRP_TV_C1G2_CRC,                "C1G2 CRC"                      },
    { LLRP_TV_C1G2_PC,                 "C1G2 PC"                       },
    { LLRP_TV_EPC96,                   "EPC-96"                        },
    { LLRP_TV_SPEC_INDEX,              "Spec Index"                    },
    { LLRP_TV_CLIENT_REQ_OP_SPEC_RES,  "Client Request Op Spec Result" },
    { LLRP_TV_ACCESS_SPEC_ID,          "Access Spec ID"                },
    { LLRP_TV_OP_SPEC_ID,              "Op Spec ID"                    },
    { LLRP_TV_C1G2_SINGULATION_DET,    "C1G2 Singulation Details"      },
    { LLRP_TV_C1G2_XPC_W1,             "C1G2 XPC W1"                   },
    { LLRP_TV_C1G2_XPC_W2,             "C1G2 XPC W2"                   },
    { 0,                                NULL                           }
};

/* Misc */
#define LLRP_ROSPEC_ALL      0
#define LLRP_ANTENNA_ALL     0
#define LLRP_GPI_PORT_ALL    0
#define LLRP_GPO_PORT_ALL    0
#define LLRP_ACCESSSPEC_ALL  0
#define LLRP_TLV_LEN_MIN     4
#define LLRP_LEN_MIN        10

static void
dissect_llrp_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint offset)
{
    guint8 has_length;
    guint16 len, type;
    guint real_len;
    proto_item *ti;
    proto_tree *param_tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        has_length = !(tvb_get_guint8(tvb, offset) & 0x80);

        if (has_length)
        {
            len = tvb_get_ntohs(tvb, offset + 2);

            if (len < LLRP_TLV_LEN_MIN)
                real_len = LLRP_TLV_LEN_MIN;
            else if (len > tvb_reported_length_remaining(tvb, offset))
                real_len = tvb_reported_length_remaining(tvb, offset);
            else
                real_len = len;

            ti = proto_tree_add_none_format(tree, hf_llrp_param, tvb,
                    offset, real_len, "TLV Parameter");
            param_tree = proto_item_add_subtree(ti, ett_llrp_param);

            proto_tree_add_item(param_tree, hf_llrp_tlv_type, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            ti = proto_tree_add_item(param_tree, hf_llrp_tlv_len, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            if (len != real_len)
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                        "Invalid length field: claimed %u, should be %u.",
                        len, real_len);
            offset += 2;

            /* TODO: Decode actual TLV parameter fields */

            /* The len field includes the 4-byte parameter header that we've
             * already accounted for in offset */
            offset += real_len - 4;
        }
        else
        {
            type = tvb_get_guint8(tvb, offset) & 0x7F;

            /* TODO: Decode actual TV fields rather than just jumping
             * ahead the correct length */
            switch (type)
            {
                case LLRP_TV_ANTENNA_ID:
                    real_len = LLRP_TV_LEN_ANTENNA_ID; break;
                case LLRP_TV_FIRST_SEEN_TIME_UTC:
                    real_len = LLRP_TV_LEN_FIRST_SEEN_TIME_UTC; break;
                case LLRP_TV_FIRST_SEEN_TIME_UPTIME:
                    real_len = LLRP_TV_LEN_FIRST_SEEN_TIME_UPTIME; break;
                case LLRP_TV_LAST_SEEN_TIME_UTC:
                    real_len = LLRP_TV_LEN_LAST_SEEN_TIME_UTC; break;
                case LLRP_TV_LAST_SEEN_TIME_UPTIME:
                    real_len = LLRP_TV_LEN_LAST_SEEN_TIME_UPTIME; break;
                case LLRP_TV_PEAK_RSSI:
                    real_len = LLRP_TV_LEN_PEAK_RSSI; break;
                case LLRP_TV_CHANNEL_INDEX:
                    real_len = LLRP_TV_LEN_CHANNEL_INDEX; break;
                case LLRP_TV_TAG_SEEN_COUNT:
                    real_len = LLRP_TV_LEN_TAG_SEEN_COUNT; break;
                case LLRP_TV_RO_SPEC_ID:
                    real_len = LLRP_TV_LEN_RO_SPEC_ID; break;
                case LLRP_TV_INVENTORY_PARAM_SPEC_ID:
                    real_len = LLRP_TV_LEN_INVENTORY_PARAM_SPEC_ID; break;
                case LLRP_TV_C1G2_CRC:
                    real_len = LLRP_TV_LEN_C1G2_CRC; break;
                case LLRP_TV_C1G2_PC:
                    real_len = LLRP_TV_LEN_C1G2_PC; break;
                case LLRP_TV_EPC96:
                    real_len = LLRP_TV_LEN_EPC96; break;
                case LLRP_TV_SPEC_INDEX:
                    real_len = LLRP_TV_LEN_SPEC_INDEX; break;
                case LLRP_TV_CLIENT_REQ_OP_SPEC_RES:
                    real_len = LLRP_TV_LEN_CLIENT_REQ_OP_SPEC_RES; break;
                case LLRP_TV_ACCESS_SPEC_ID:
                    real_len = LLRP_TV_LEN_ACCESS_SPEC_ID; break;
                case LLRP_TV_OP_SPEC_ID:
                    real_len = LLRP_TV_LEN_OP_SPEC_ID; break;
                case LLRP_TV_C1G2_SINGULATION_DET:
                    real_len = LLRP_TV_LEN_C1G2_SINGULATION_DET; break;
                case LLRP_TV_C1G2_XPC_W1:
                    real_len = LLRP_TV_LEN_C1G2_XPC_W1; break;
                case LLRP_TV_C1G2_XPC_W2:
                    real_len = LLRP_TV_LEN_C1G2_XPC_W2; break;
                default:
                    /* ???
                     * No need to mark it, since the hf_llrp_tv_type field
                     * will already show up as 'unknown'. */
                    real_len = 0;
                    break;
            };

            ti = proto_tree_add_none_format(tree, hf_llrp_param, tvb,
                    offset, real_len + 1, "TV Parameter");
            param_tree = proto_item_add_subtree(ti, ett_llrp_param);

            proto_tree_add_item(param_tree, hf_llrp_tv_type, tvb,
                    offset, 1, ENC_NA);
            offset++;

            /* Unlike for TLV's, real_len for TV's doesn't include the standard
             * header length, so just add it straight to the offset. */
            offset += real_len;
        }
    }
}

static void
dissect_llrp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint16 type, guint offset)
{
    guint8  requested_data;
    guint16 antenna_id, gpi_port, gpo_port;
    guint32 spec_id;
    proto_item *ti;

    switch (type)
    {
        /* Simple cases just have normal TLV or TV parameters */
        case LLRP_TYPE_CLOSE_CONNECTION_RESPONSE:
        case LLRP_TYPE_GET_READER_CAPABILITES_RESPONSE:
        case LLRP_TYPE_ADD_ROSPEC:
        case LLRP_TYPE_ADD_ROSPEC_RESPONSE:
        case LLRP_TYPE_DELETE_ROSPEC_RESPONSE:
        case LLRP_TYPE_START_ROSPEC_RESPONSE:
        case LLRP_TYPE_STOP_ROSPEC_RESPONSE:
        case LLRP_TYPE_ENABLE_ROSPEC_RESPONSE:
        case LLRP_TYPE_DISABLE_ROSPEC_RESPONSE:
        case LLRP_TYPE_GET_ROSPECS_RESPONSE:
        case LLRP_TYPE_ADD_ACCESSSPEC:
        case LLRP_TYPE_ADD_ACCESSSPEC_RESPONSE:
        case LLRP_TYPE_DELETE_ACCESSSPEC_RESPONSE:
        case LLRP_TYPE_ENABLE_ACCESSSPEC_RESPONSE:
        case LLRP_TYPE_DISABLE_ACCESSSPEC_RESPONSE:
        case LLRP_TYPE_GET_ACCESSSPECS:
        case LLRP_TYPE_CLIENT_REQUEST_OP:
        case LLRP_TYPE_CLIENT_RESQUEST_OP_RESPONSE:
        case LLRP_TYPE_RO_ACCESS_REPORT:
        case LLRP_TYPE_READER_EVENT_NOTIFICATION:
        case LLRP_TYPE_ERROR_MESSAGE:
        case LLRP_TYPE_GET_READER_CONFIG_RESPONSE:
        case LLRP_TYPE_SET_READER_CONFIG_RESPONSE:
        case LLRP_TYPE_SET_PROTOCOL_VERSION_RESPONSE:
        case LLRP_TYPE_GET_ACCESSSPECS_RESPONSE:
        case LLRP_TYPE_GET_REPORT:
        case LLRP_TYPE_ENABLE_EVENTS_AND_REPORTS:
            dissect_llrp_parameters(tvb, pinfo, tree, offset);
            break;
        /* Some just have an ROSpec ID */
        case LLRP_TYPE_START_ROSPEC:
        case LLRP_TYPE_STOP_ROSPEC:
        case LLRP_TYPE_ENABLE_ROSPEC:
        case LLRP_TYPE_DISABLE_ROSPEC:
        case LLRP_TYPE_DELETE_ROSPEC:
            spec_id = tvb_get_ntohl(tvb, offset);
            if (spec_id == LLRP_ROSPEC_ALL)
                proto_tree_add_uint_format(tree, hf_llrp_rospec, tvb,
                        offset, 4, spec_id, "All ROSpecs (%u)", spec_id);
            else
                proto_tree_add_item(tree, hf_llrp_rospec, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
            break;
        /* Some just have an AccessSpec ID */
        case LLRP_TYPE_ENABLE_ACCESSSPEC:
        case LLRP_TYPE_DELETE_ACCESSSPEC:
        case LLRP_TYPE_DISABLE_ACCESSSPEC:
            spec_id = tvb_get_ntohl(tvb, offset);
            if (spec_id == LLRP_ACCESSSPEC_ALL)
                proto_tree_add_uint_format(tree, hf_llrp_accessspec, tvb,
                        offset, 4, spec_id, "All Access Specs (%u)", spec_id);
            else
                proto_tree_add_item(tree, hf_llrp_accessspec, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_llrp_accessspec, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        case LLRP_TYPE_GET_READER_CAPABILITES:
            proto_tree_add_item(tree, hf_llrp_req_cap, tvb, offset, 1, ENC_NA);
            offset++;
            dissect_llrp_parameters(tvb, pinfo, tree, offset);
            break;
        /* GET_READER_CONFIG is complicated */
        case LLRP_TYPE_GET_READER_CONFIG:
            requested_data = tvb_get_guint8(tvb, offset + 2);
            switch (requested_data)
            {
                case LLRP_CONF_ALL:
                    antenna_id = tvb_get_ntohs(tvb, offset);
                    if (antenna_id == LLRP_ANTENNA_ALL)
                        proto_tree_add_uint_format(tree, hf_llrp_antenna_id, tvb,
                                offset, 2, antenna_id, "All Antennas (%u)", antenna_id);
                    else
                        proto_tree_add_item(tree, hf_llrp_antenna_id, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(tree, hf_llrp_req_conf, tvb,
                            offset, 1, ENC_NA);
                    offset++;
                    gpi_port = tvb_get_ntohs(tvb, offset);
                    if (gpi_port == LLRP_GPI_PORT_ALL)
                        proto_tree_add_uint_format(tree, hf_llrp_gpi_port, tvb,
                                offset, 2, gpi_port, "All GPI Ports (%u)", gpi_port);
                    else
                        proto_tree_add_item(tree, hf_llrp_gpi_port, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    gpo_port = tvb_get_ntohs(tvb, offset);
                    if (gpo_port == LLRP_GPO_PORT_ALL)
                        proto_tree_add_uint_format(tree, hf_llrp_gpo_port, tvb,
                                offset, 2, gpo_port, "All GPO Ports (%u)", gpo_port);
                    else
                        proto_tree_add_item(tree, hf_llrp_gpo_port, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                case LLRP_CONF_ANTENNA_PROPERTIES:
                case LLRP_CONF_ANTENNA_CONFIGURATION:
                    antenna_id = tvb_get_ntohs(tvb, offset);
                    if (antenna_id == LLRP_ANTENNA_ALL)
                        proto_tree_add_uint_format(tree, hf_llrp_antenna_id, tvb,
                                offset, 2, antenna_id, "All Antennas (%u)", antenna_id);
                    else
                        proto_tree_add_item(tree, hf_llrp_antenna_id, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(tree, hf_llrp_req_conf, tvb,
                            offset, 1, ENC_NA);
                    offset++;
                    offset += 4; /* Skip both GPI and GPO ports */
                    break;
                case LLRP_CONF_IDENTIFICATION:
                case LLRP_CONF_RO_REPORT_SPEC:
                case LLRP_CONF_READER_EVENT_NOTIFICATION_SPEC:
                case LLRP_CONF_ACCESS_REPORT_SPEC:
                case LLRP_CONF_LLRP_CONFIGURATION_STATE:
                case LLRP_CONF_KEEPALIVE_SPEC:
                case LLRP_CONF_EVENTS_AND_REPORTS:
                    offset += 2; /* Skip antenna ID */
                    proto_tree_add_item(tree, hf_llrp_req_conf, tvb,
                            offset, 1, ENC_NA);
                    offset++;
                    offset += 4; /* Skip both GPI and GPO ports */
                    break;
                case LLRP_CONF_GPI_PORT_CURRENT_STATE:
                    offset += 2; /* Skip antenna ID */
                    proto_tree_add_item(tree, hf_llrp_req_conf, tvb,
                            offset, 1, ENC_NA);
                    offset++;
                    gpi_port = tvb_get_ntohs(tvb, offset);
                    if (gpi_port == LLRP_GPI_PORT_ALL)
                        proto_tree_add_uint_format(tree, hf_llrp_gpi_port, tvb,
                                offset, 2, gpi_port, "All GPI Ports (%u)", gpi_port);
                    else
                        proto_tree_add_item(tree, hf_llrp_gpi_port, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    offset += 2; /* Skip GPO Port */
                    break;
                case LLRP_CONF_GPO_WRITE_DATA:
                    offset += 2; /* Skip antenna ID */
                    proto_tree_add_item(tree, hf_llrp_req_conf, tvb,
                            offset, 1, ENC_NA);
                    offset++;
                    offset += 2; /* Skip GPI Port */
                    gpo_port = tvb_get_ntohs(tvb, offset);
                    if (gpo_port == LLRP_GPO_PORT_ALL)
                        proto_tree_add_uint_format(tree, hf_llrp_gpo_port, tvb,
                                offset, 2, gpo_port, "All GPO Ports (%u)", gpo_port);
                    else
                        proto_tree_add_item(tree, hf_llrp_gpo_port, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                default:
                    offset += 2; /* Skip antenna ID */
                    ti = proto_tree_add_item(tree, hf_llrp_req_conf, tvb,
                            offset, 1, ENC_NA);
                    expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                            "Unrecognized configuration request: %u",
                            requested_data);
                    offset++;
                    offset += 4; /* Skip both GPI and GPO ports */
                    break;
            };
            dissect_llrp_parameters(tvb, pinfo, tree, offset);
            break;
        /* END GET_READER_CONFIG */
        /* Misc */
        case LLRP_TYPE_SET_READER_CONFIG:
            proto_tree_add_item(tree, hf_llrp_rest_fact, tvb, offset, 1, ENC_NA);
            offset++;
            dissect_llrp_parameters(tvb, pinfo, tree, offset);
            break;
        case LLRP_TYPE_SET_PROTOCOL_VERSION:
            proto_tree_add_item(tree, hf_llrp_version, tvb, offset, 1, ENC_NA);
            break;
        case LLRP_TYPE_GET_SUPPORTED_VERSION_RESPONSE:
            proto_tree_add_item(tree, hf_llrp_cur_ver, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_llrp_sup_ver, tvb, offset, 1, ENC_NA);
            offset++;
            dissect_llrp_parameters(tvb, pinfo, tree, offset);
            break;
        case LLRP_TYPE_CUSTOM_MESSAGE:
            proto_tree_add_item(tree, hf_llrp_vendor, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        /* Some have no extra data expected */
        case LLRP_TYPE_KEEPALIVE:
        case LLRP_TYPE_KEEPALIVE_ACK:
        case LLRP_TYPE_CLOSE_CONNECTION:
        case LLRP_TYPE_GET_ROSPECS:
        case LLRP_TYPE_GET_SUPPORTED_VERSION:
            break;
        default:
            /* We shouldn't be called if we don't already recognize the value */
            DISSECTOR_ASSERT_NOT_REACHED();
    };
}

/* Code to actually dissect the packets */
static int
dissect_llrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *llrp_tree;
    guint16 type;
    guint32 len;
    guint offset = 0;

    /* Check that there's enough data */
    if (tvb_reported_length(tvb) < LLRP_LEN_MIN)
        return 0;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLRP");

    col_set_str(pinfo->cinfo, COL_INFO, "LLRP Message");

    type = tvb_get_ntohs(tvb, offset) & 0x03FF;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    val_to_str(type, message_types, "Unknown Type: %d"));

    ti = proto_tree_add_item(tree, proto_llrp, tvb, offset, -1, ENC_NA);
    llrp_tree = proto_item_add_subtree(ti, ett_llrp);

    proto_tree_add_item(llrp_tree, hf_llrp_version, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(llrp_tree, hf_llrp_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    ti = proto_tree_add_item(llrp_tree, hf_llrp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    len = tvb_get_ntohl(tvb, offset);
    if (len > tvb_reported_length(tvb))
    {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "Incorrect length field: claimed %u, but only have %u.",
                               len, tvb_reported_length(tvb));
    }
    offset += 4;

    proto_tree_add_item(llrp_tree, hf_llrp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (match_strval(type, message_types))
        dissect_llrp_message(tvb, pinfo, llrp_tree, type, offset);

    return tvb_length(tvb);
}

void
proto_register_llrp(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_llrp_version,
        { "Version", "llrp.version", FT_UINT8, BASE_DEC, VALS(llrp_versions), 0x1C,
          NULL, HFILL }},

        { &hf_llrp_type,
        { "Type", "llrp.type", FT_UINT16, BASE_DEC, VALS(message_types), 0x03FF,
          NULL, HFILL }},

        { &hf_llrp_length,
        { "Length", "llrp.length", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_id,
        { "ID", "llrp.id", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_cur_ver,
        { "Current Version", "llrp.cur_ver", FT_UINT8, BASE_DEC, VALS(llrp_versions), 0,
          NULL, HFILL }},

        { &hf_llrp_sup_ver,
        { "Supported Version", "llrp.sup_ver", FT_UINT8, BASE_DEC, VALS(llrp_versions), 0,
          "The max supported protocol version.", HFILL }},

        { &hf_llrp_req_cap,
        { "Requested Capabilities", "llrp.req_cap", FT_UINT8, BASE_DEC, VALS(capabilities_request), 0,
          NULL, HFILL }},

        { &hf_llrp_req_conf,
        { "Requested Configuration", "llrp.req_conf", FT_UINT8, BASE_DEC, VALS(config_request), 0,
          NULL, HFILL }},

        { &hf_llrp_rospec,
        { "ROSpec ID", "llrp.rospec", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_antenna_id,
        { "Antenna ID", "llrp.antenna_id", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_gpi_port,
        { "GPI Port Number", "llrp.gpi_port", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_gpo_port,
        { "GPO Port Number", "llrp.gpo_port", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_rest_fact,
        { "Restore Factory Settings", "llrp.rest_fact", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_accessspec,
        { "Access Spec ID", "llrp.accessspec", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_vendor,
        { "Vendor ID", "llrp.vendor", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_tlv_type,
        { "Type", "llrp.tlv_type", FT_UINT16, BASE_DEC, VALS(tlv_type), 0x03FF,
          "The type of TLV.", HFILL }},

        { &hf_llrp_tv_type,
        { "Type", "llrp.tv_type", FT_UINT8, BASE_DEC, VALS(tv_type), 0x7F,
          "The type of TV.", HFILL }},

        { &hf_llrp_tlv_len,
        { "Length", "llrp.tlv_len", FT_UINT16, BASE_DEC, NULL, 0,
          "The length of this TLV.", HFILL }},

        { &hf_llrp_param,
        { "Parameter", "llrp.param", FT_NONE, BASE_NONE, NULL, 0,
          NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_llrp,
        &ett_llrp_param
    };

    /* Register the protocol name and description */
    proto_llrp = proto_register_protocol("Low Level Reader Protocol",
            "LLRP", "llrp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_llrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_llrp(void)
{
    dissector_handle_t llrp_handle;

    llrp_handle = new_create_dissector_handle(dissect_llrp, proto_llrp);
    dissector_add_uint("tcp.port", LLRP_PORT, llrp_handle);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
