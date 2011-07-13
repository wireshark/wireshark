/* packet-edonkey.c
 * Routines for edonkey dissection
 * Copyright 2003, Xuan Zhang <xz@aemail4u.com>
 * Copyright 2007, Stefano Picerno <stefano.picerno@gmail.com>
 * Copyright 2008, Stefan Monhof <stefan.monhof@stud.uni-due.de>
 *
 * eDonkey dissector based on protocol descriptions from mldonkey:
 *  http://savannah.nongnu.org/download/mldonkey/docs/Edonkey-Overnet/edonkey-protocol.txt
 *  http://savannah.nongnu.org/download/mldonkey/docs/Edonkey-Overnet/overnet-protocol.txt
 *
 * Kademlia dissector based on source code inspection of aMule 2.1.3 and eMule 0.48a
 * Modified and added on the basis of information and names from the eMule 0.49a source code
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include "packet-edonkey.h"
#include "packet-tcp.h"

static int proto_edonkey = -1;

static int hf_edonkey_message  = -1;
static int hf_edonkey_protocol = -1;
static int hf_edonkey_message_length = -1;
static int hf_edonkey_message_type = -1;
static int hf_edonkey_client_hash = -1;
static int hf_edonkey_server_hash = -1;
static int hf_edonkey_file_hash = -1;
static int hf_edonkey_client_id = -1;
static int hf_edonkey_metatag_namesize = -1;
static int hf_edonkey_metatag_type = -1;
static int hf_edonkey_metatag = -1;
static int hf_edonkey_metatag_name = -1;
static int hf_edonkey_metatag_id = -1;
static int hf_edonkey_search = -1;
static int hf_edonkey_ip = -1;
static int hf_edonkey_port = -1;
static int hf_edonkey_hash = -1;
static int hf_edonkey_part_count = -1;
static int hf_edonkey_file_status = -1;
static int hf_edonkey_directory = -1;
static int hf_edonkey_string = -1;
static int hf_edonkey_string_length = -1;
static int hf_edonkey_fileinfo = -1;
static int hf_edonkey_clientinfo = -1;
static int hf_edonkey_serverinfo = -1;
static int hf_emule_aich_partnum = -1;
static int hf_emule_aich_root_hash = -1;
static int hf_emule_aich_hash_entry = -1;
static int hf_emule_aich_hash_id = -1;
static int hf_emule_aich_hash = -1;
static int hf_emule_multipacket_entry = -1;
static int hf_emule_multipacket_opcode = -1;
static int hf_emule_source_count = -1;
static int hf_emule_zlib = -1;
static int hf_emule_public_key = -1;
static int hf_emule_signature = -1;
static int hf_emule_sourceOBFU = -1;
static int hf_overnet_peer = -1;

static int hf_edonkey_unparsed_data_length = -1;
static int hf_kademlia = -1;
static int hf_kademlia_search_condition = -1;
static int hf_kademlia_search_condition_argument_uint32 = -1;
static int hf_kademlia_search_condition_argument_uint64 = -1;
static int hf_kademlia_unparsed_data_length = -1;
static int hf_kademlia_peer = -1;
static int hf_kademlia_peer_id = -1;
static int hf_kademlia_hash = -1;
static int hf_kademlia_file_id = -1;
static int hf_kademlia_keyword_hash = -1;
static int hf_kademlia_recipients_id = -1;
static int hf_kademlia_sender_id = -1;
static int hf_kademlia_target_id = -1;
static int hf_kademlia_distance = -1;
static int hf_kademlia_version = -1;
static int hf_kademlia_peertype = -1;
static int hf_kademlia_tag_float = -1;
static int hf_kademlia_tag_uint64 = -1;
static int hf_kademlia_tag_uint32 = -1;
static int hf_kademlia_tag_ipv4 = -1;
static int hf_kademlia_tag_uint16 = -1;
static int hf_kademlia_tag_uint8 = -1;
static int hf_kademlia_tag_hash = -1;
static int hf_kademlia_tag_bsob = -1;
static int hf_kademlia_tag_string = -1;
static int hf_kademlia_udp_port = -1;
static int hf_kademlia_tcp_port = -1;
static int hf_kademlia_ip = -1;
static int hf_kademlia_tag_name = -1;
static int hf_kademlia_tag_name_length = -1;
static int hf_kademlia_tag_type = -1;
static int hf_kademlia_request_type = -1;

static gint ett_kademlia_tag = -1;
static gint ett_edonkey_listitem = -1;
static gint ett_kademlia_search_expression = -1;
static gint ett_edonkey = -1;
static gint ett_edonkey_message = -1;
static gint ett_edonkey_metatag = -1;
static gint ett_edonkey_search = -1;
static gint ett_edonkey_fileinfo = -1;
static gint ett_edonkey_serverinfo = -1;
static gint ett_edonkey_clientinfo = -1;
static gint ett_emule_aichhash = -1;
static gint ett_emule_multipacket = -1;
static gint ett_emule_zlib = -1;
static gint ett_overnet_peer = -1;
static gint ett_emule_sourceOBFU = -1;

/* desegmentation of eDonkey over TCP */
static gboolean edonkey_desegment = TRUE;

static const value_string kademlia_msgs[] = {
    { KADEMLIA2_BOOTSTRAP_REQ        ,"KADEMLIA2_BOOTSTRAP_REQ"      },
    { KADEMLIA2_BOOTSTRAP_RES        ,"KADEMLIA2_BOOTSTRAP_RES"      },
    { KADEMLIA2_HELLO_REQ            ,"KADEMLIA2_HELLO_REQ"          },
    { KADEMLIA2_HELLO_RES            ,"KADEMLIA2_HELLO_RES"          },
    { KADEMLIA2_PUBLISH_KEY_REQ      ,"KADEMLIA2_PUBLISH_KEY_REQ"    },
    { KADEMLIA2_PUBLISH_NOTES_REQ    ,"KADEMLIA2_PUBLISH_NOTES_REQ"  },
    { KADEMLIA2_PUBLISH_RES          ,"KADEMLIA2_PUBLISH_RES"        },
    { KADEMLIA2_PUBLISH_SOURCE_REQ   ,"KADEMLIA2_PUBLISH_SOURCE_REQ" },
    { KADEMLIA2_REQ                  ,"KADEMLIA2_REQ"                },
    { KADEMLIA2_RES                  ,"KADEMLIA2_RES"                },
    { KADEMLIA2_SEARCH_KEY_REQ       ,"KADEMLIA2_SEARCH_KEY_REQ"     },
    { KADEMLIA2_SEARCH_NOTES_REQ     ,"KADEMLIA2_SEARCH_NOTES_REQ"   },
    { KADEMLIA2_SEARCH_RES           ,"KADEMLIA2_SEARCH_RES"         },
    { KADEMLIA2_SEARCH_SOURCE_REQ    ,"KADEMLIA2_SEARCH_SOURCE_REQ"  },
    { KADEMLIA_BOOTSTRAP_REQ         ,"KADEMLIA_BOOTSTRAP_REQ"       },
    { KADEMLIA_BOOTSTRAP_RES         ,"KADEMLIA_BOOTSTRAP_RES"       },
    { KADEMLIA_CALLBACK_REQ          ,"KADEMLIA_CALLBACK_REQ"        },
    { KADEMLIA_FINDBUDDY_REQ         ,"KADEMLIA_FINDBUDDY_REQ"       },
    { KADEMLIA_FINDBUDDY_RES         ,"KADEMLIA_FINDBUDDY_RES"       },
    { KADEMLIA_FIREWALLED_ACK_RES    ,"KADEMLIA_FIREWALLED_ACK_RES"  },
    { KADEMLIA_FIREWALLED_REQ        ,"KADEMLIA_FIREWALLED_REQ"      },
    { KADEMLIA_FIREWALLED_RES        ,"KADEMLIA_FIREWALLED_RES"      },
    { KADEMLIA_HELLO_REQ             ,"KADEMLIA_HELLO_REQ"           },
    { KADEMLIA_HELLO_RES             ,"KADEMLIA_HELLO_RES"           },
    { KADEMLIA_PUBLISH_NOTES_REQ     ,"KADEMLIA_PUBLISH_NOTES_REQ"   },
    { KADEMLIA_PUBLISH_NOTES_RES     ,"KADEMLIA_PUBLISH_NOTES_RES"   },
    { KADEMLIA_PUBLISH_REQ           ,"KADEMLIA_PUBLISH_REQ"         },
    { KADEMLIA_PUBLISH_RES           ,"KADEMLIA_PUBLISH_RES"         },
    { KADEMLIA_REQ                   ,"KADEMLIA_REQ"                 },
    { KADEMLIA_RES                   ,"KADEMLIA_RES"                 },
    { KADEMLIA_SEARCH_NOTES_REQ      ,"KADEMLIA_SEARCH_NOTES_REQ"    },
    { KADEMLIA_SEARCH_NOTES_RES      ,"KADEMLIA_SEARCH_NOTES_RES"    },
    { KADEMLIA_SEARCH_REQ            ,"KADEMLIA_SEARCH_REQ"          },
    { KADEMLIA_SEARCH_RES            ,"KADEMLIA_SEARCH_RES"          },
    { 0, NULL }
};

static const value_string kademlia_tag_types[] = {
    { KADEMLIA_TAGTYPE_HASH          ,"TAGTYPE_HASH"      },
    { KADEMLIA_TAGTYPE_STRING        ,"TAGTYPE_STRING"    },
    { KADEMLIA_TAGTYPE_UINT32        ,"TAGTYPE_UINT32"    },
    { KADEMLIA_TAGTYPE_FLOAT32       ,"TAGTYPE_FLOAT32"   },
    { KADEMLIA_TAGTYPE_BOOL          ,"TAGTYPE_BOOL"      },
    { KADEMLIA_TAGTYPE_BOOLARRAY     ,"TAGTYPE_BOOLARRAY" },
    { KADEMLIA_TAGTYPE_BLOB          ,"TAGTYPE_BLOB"      },
    { KADEMLIA_TAGTYPE_UINT16        ,"TAGTYPE_UINT16"    },
    { KADEMLIA_TAGTYPE_UINT8         ,"TAGTYPE_UINT8"     },
    { KADEMLIA_TAGTYPE_BSOB          ,"TAGTYPE_BSOB"      },
    { KADEMLIA_TAGTYPE_UINT64        ,"TAGTYPE_UINT64"    },

    { KADEMLIA_TAGTYPE_STR1          ,"TAGTYPE_STR1"      },
    { KADEMLIA_TAGTYPE_STR2          ,"TAGTYPE_STR2"      },
    { KADEMLIA_TAGTYPE_STR3          ,"TAGTYPE_STR3"      },
    { KADEMLIA_TAGTYPE_STR4          ,"TAGTYPE_STR4"      },
    { KADEMLIA_TAGTYPE_STR5          ,"TAGTYPE_STR5"      },
    { KADEMLIA_TAGTYPE_STR6          ,"TAGTYPE_STR6"      },
    { KADEMLIA_TAGTYPE_STR7          ,"TAGTYPE_STR7"      },
    { KADEMLIA_TAGTYPE_STR8          ,"TAGTYPE_STR8"      },
    { KADEMLIA_TAGTYPE_STR9          ,"TAGTYPE_STR9"      },
    { KADEMLIA_TAGTYPE_STR10         ,"TAGTYPE_STR10"     },
    { KADEMLIA_TAGTYPE_STR11         ,"TAGTYPE_STR11"     },
    { KADEMLIA_TAGTYPE_STR12         ,"TAGTYPE_STR12"     },
    { KADEMLIA_TAGTYPE_STR13         ,"TAGTYPE_STR13"     },
    { KADEMLIA_TAGTYPE_STR14         ,"TAGTYPE_STR14"     },
    { KADEMLIA_TAGTYPE_STR15         ,"TAGTYPE_STR15"     },
    { KADEMLIA_TAGTYPE_STR16         ,"TAGTYPE_STR16"     },
    { KADEMLIA_TAGTYPE_STR17         ,"TAGTYPE_STR17"     },
    { KADEMLIA_TAGTYPE_STR18         ,"TAGTYPE_STR18"     },
    { KADEMLIA_TAGTYPE_STR19         ,"TAGTYPE_STR19"     },
    { KADEMLIA_TAGTYPE_STR20         ,"TAGTYPE_STR20"     },
    { KADEMLIA_TAGTYPE_STR21         ,"TAGTYPE_STR21"     },
    { KADEMLIA_TAGTYPE_STR22         ,"TAGTYPE_STR22"     },
    { 0, NULL }
};

static const value_string kademlia_tags[] = {
    { KADEMLIA_TAG_BUDDYHASH         ,"TAG_BUDDYHASH"    },
    { KADEMLIA_TAG_CLIENTLOWID       ,"TAG_CLIENTLOWID"  },
    { KADEMLIA_TAG_COLLECTION        ,"TAG_COLLECTION"   },
    { KADEMLIA_TAG_COPIED            ,"TAG_COPIED"       },
    { KADEMLIA_TAG_DESCRIPTION       ,"TAG_DESCRIPTION"  },
    { KADEMLIA_TAG_ENCRYPTION        ,"TAG_ENCRYPTION"   },
    { KADEMLIA_TAG_FAIL              ,"TAG_FAIL"         },
    { KADEMLIA_TAG_FILECOMMENT       ,"TAG_FILECOMMENT"  },
    { KADEMLIA_TAG_FILE_COUNT        ,"TAG_FILE_COUNT"   },
    { KADEMLIA_TAG_FILEFORMAT        ,"TAG_FILEFORMAT"   },
    { KADEMLIA_TAG_FILENAME          ,"TAG_FILENAME"     },
    { KADEMLIA_TAG_FILERATING        ,"TAG_FILERATING"   },
    { KADEMLIA_TAG_FILESIZE_HI       ,"TAG_FILESIZE_HI"  },
    { KADEMLIA_TAG_FILESIZE          ,"TAG_FILESIZE"     },
    { KADEMLIA_TAG_FILETYPE          ,"TAG_FILETYPE"     },
    { KADEMLIA_TAG_GAP_END           ,"TAG_GAP_END"      },
    { KADEMLIA_TAG_GAP_START         ,"TAG_GAP_START"    },
    { KADEMLIA_TAG_IP_ADDRESS        ,"TAG_IP_ADDRESS"   },
    { KADEMLIA_TAG_MEDIA_ALBUM       ,"TAG_MEDIA_ALBUM"  },
    { KADEMLIA_TAG_MEDIA_ARTIST      ,"TAG_MEDIA_ARTIST" },
    { KADEMLIA_TAG_MEDIA_BITRATE     ,"TAG_MEDIA_BITRATE"},
    { KADEMLIA_TAG_MEDIA_CODEC       ,"TAG_MEDIA_CODEC"  },
    { KADEMLIA_TAG_MEDIA_LENGTH      ,"TAG_MEDIA_LENGTH" },
    { KADEMLIA_TAG_MEDIA_TITLE       ,"TAG_MEDIA_TITLE"  },
    { KADEMLIA_TAG_PART_HASH         ,"TAG_PART_HASH"    },
    { KADEMLIA_TAG_PART_PATH         ,"TAG_PART_PATH"    },
    { KADEMLIA_TAG_PARTS             ,"TAG_PARTS"        },
    { KADEMLIA_TAG_PERMISSIONS       ,"TAG_PERMISSIONS"  },
    { KADEMLIA_TAG_PING              ,"TAG_PING"         },
    { KADEMLIA_TAG_PORT              ,"TAG_PORT"         },
    { KADEMLIA_TAG_PREFERENCE        ,"TAG_PREFERENCE"   },
    { KADEMLIA_TAG_PRIORITY          ,"TAG_PRIORITY"     },
    { KADEMLIA_TAG_QTIME             ,"TAG_QTIME"        },
    { KADEMLIA_TAG_SERVERIP          ,"TAG_SERVERIP"     },
    { KADEMLIA_TAG_SERVERPORT        ,"TAG_SERVERPORT"   },
    { KADEMLIA_TAG_SOURCEIP          ,"TAG_SOURCEIP"     },
    { KADEMLIA_TAG_SOURCEPORT        ,"TAG_SOURCEPORT"   },
    { KADEMLIA_TAG_SOURCES           ,"TAG_SOURCES"      },
    { KADEMLIA_TAG_SOURCETYPE        ,"TAG_SOURCETYPE"   },
    { KADEMLIA_TAG_SOURCEUPORT       ,"TAG_SOURCEUPORT"  },
    { KADEMLIA_TAG_STATUS            ,"TAG_STATUS"       },
    { KADEMLIA_TAG_TEMPFILE          ,"TAG_TEMPFILE"     },
    { KADEMLIA_TAG_USER_COUNT        ,"TAG_USER_COUNT"   },
    { KADEMLIA_TAG_VERSION           ,"TAG_VERSION"      },

    { 0, NULL }
};

static const value_string edonkey_protocols[] = {
    { EDONKEY_PROTO_EDONKEY,             "eDonkey"                  },
    { EDONKEY_PROTO_EMULE_EXT,           "eMule Extensions"         },
    { EDONKEY_PROTO_EMULE_COMP,          "eMule Compressed"         },
    { EDONKEY_PROTO_KADEMLIA,            "Kademlia"                 },
    { EDONKEY_PROTO_KADEMLIA_COMP,       "Kademlia Compressed"      },
    { EDONKEY_PROTO_ADU_KADEMLIA,        "KAdu"                     },
    { EDONKEY_PROTO_ADU_KADEMLIA_COMP,   "KAdu Compressed"          },
    { 0,                                 NULL                       }
};

static const value_string edonkey_tcp_msgs[] = {
    { EDONKEY_MSG_HELLO,                 "Hello"                    },
    { EDONKEY_MSG_BAD_PROTO,             "Bad Proto"                },
    { EDONKEY_MSG_GET_SERVER_LIST,       "Get Server List"          },
    { EDONKEY_MSG_OFFER_FILES,           "Offer Files"              },
    { EDONKEY_MSG_SEARCH_FILES,          "Search Files"             },
    { EDONKEY_MSG_DISCONNECT,            "Disconnect"               },
    { EDONKEY_MSG_GET_SOURCES,           "Get Sources"              },
    { EDONKEY_MSG_GET_SOURCES_OBFU,      "Get Sources Obfuscation"  },
    { EDONKEY_MSG_SEARCH_USER,           "Search User"              },
    { EDONKEY_MSG_CLIENT_CB_REQ,         "Client Callback Request"  },
    { EDONKEY_MSG_MORE_RESULTS,          "More Results"             },
    { EDONKEY_MSG_SERVER_LIST,           "Server List"              },
    { EDONKEY_MSG_SEARCH_FILE_RESULTS,   "Search File Results"      },
    { EDONKEY_MSG_SERVER_STATUS,         "Server Status"            },
    { EDONKEY_MSG_SERVER_CB_REQ,         "Server Callback Request"  },
    { EDONKEY_MSG_CALLBACK_FAIL,         "Callback Fail"            },
    { EDONKEY_MSG_SERVER_MESSAGE,        "Server Message"           },
    { EDONKEY_MSG_ID_CHANGE,             "ID Change"                },
    { EDONKEY_MSG_SERVER_INFO_DATA,      "Server Info Data"         },
    { EDONKEY_MSG_FOUND_SOURCES,         "Found Sources"            },
    { EDONKEY_MSG_FOUND_SOURCES_OBFU,    "Found Sources Obfuscation"},
    { EDONKEY_MSG_SEARCH_USER_RESULTS,   "Search User Results"      },
    { EDONKEY_MSG_SENDING_PART,          "Sending Part"             },
    { EDONKEY_MSG_REQUEST_PARTS,         "Request Parts"            },
    { EDONKEY_MSG_NO_SUCH_FILE,          "No Such File"             },
    { EDONKEY_MSG_END_OF_DOWNLOAD,       "End of Download"          },
    { EDONKEY_MSG_VIEW_FILES,            "View Files"               },
    { EDONKEY_MSG_VIEW_FILES_ANSWER,     "View Files Answer"        },
    { EDONKEY_MSG_HELLO_ANSWER,          "Hello Answer"             },
    { EDONKEY_MSG_NEW_CLIENT_ID,         "New Client ID"            },
    { EDONKEY_MSG_CLIENT_MESSAGE,        "Client Message"           },
    { EDONKEY_MSG_FILE_STATUS_REQUEST,   "File Status Request"      },
    { EDONKEY_MSG_FILE_STATUS,           "File Status"              },
    { EDONKEY_MSG_HASHSET_REQUEST,       "Hashset Request"          },
    { EDONKEY_MSG_HASHSET_ANSWER,        "Hashset Answer"           },
    { EDONKEY_MSG_SLOT_REQUEST,          "Slot Request"             },
    { EDONKEY_MSG_SLOT_GIVEN,            "Slot Given"               },
    { EDONKEY_MSG_SLOT_RELEASE,          "Slot Release"             },
    { EDONKEY_MSG_SLOT_TAKEN,            "Slot Taken"               },
    { EDONKEY_MSG_FILE_REQUEST,          "File Request"             },
    { EDONKEY_MSG_FILE_REQUEST_ANSWER,   "File Request Answer"      },
    { EDONKEY_MSG_GET_SHARED_DIRS,       "Get Shared Directories"   },
    { EDONKEY_MSG_GET_SHARED_FILES,      "Get Shared Files"         },
    { EDONKEY_MSG_SHARED_DIRS,           "Shared Directories"       },
    { EDONKEY_MSG_SHARED_FILES,          "Shared Files"             },
    { EDONKEY_MSG_SHARED_DENIED,         "Shared Denied"            },
    { 0,                                 NULL                       }
};

static const value_string emule_tcp_msgs[] = {
    { EMULE_MSG_HELLO,                   "Hello"                    },
    { EMULE_MSG_HELLO_ANSWER,            "Hello Answer"             },
    { EMULE_MSG_DATA_COMPRESSED,         "Data Compressed"          },
    { EMULE_MSG_QUEUE_RANKING,           "Queue Ranking"            },
    { EMULE_MSG_FILE_DESC,               "File Description"         },
    { EMULE_MSG_SOURCES_REQUEST,         "Sources Request"          },
    { EMULE_MSG_SOURCES_ANSWER,          "Sources Answer"           },
    { EMULE_MSG_SIGNATURE,               "Signature"                },
    { EMULE_MSG_PUBLIC_KEY,              "Public Key"                  },
    { EMULE_MSG_SEC_IDENT_STATE,         "Second Identification State" },
    { EMULE_MSG_MULTIPACKET,             "MultiPacket"              },
    { EMULE_MSG_MULTIPACKET_EXT,         "MultiPacketExt"           },
    { EMULE_MSG_MULTIPACKET_ANSWER,      "MultiPacket Answer"       },
    { EMULE_MSG_CALLBACK,                "Callback"                 },
    { EMULE_MSG_AICH_REQUEST,            "AICH Hashset Request"     },
    { EMULE_MSG_AICH_ANSWER,             "AICH Hashset Answer"      },
    { EMULE_MSG_AICHFILEHASH_ANSWER,     "AICH Master Hash Request" },
    { EMULE_MSG_AICHFILEHASH_REQUEST,    "AICH Master Hash Answer"  },
    { EMULE_MSG_DATA_COMPRESSED_64,      "Data Compressed (64bit)"  },
    { EMULE_MSG_SENDING_PART_64,         "Sending Part (64bit)"     },
    { EMULE_MSG_REQUEST_PARTS_64,        "Request Parts (64bit)"    },
    { 0,                                 NULL                       }
};

static const value_string edonkey_udp_msgs[] = {
    { EDONKEY_MSG_UDP_SERVER_STATUS_REQUEST,    "Server Status Request"    },
    { EDONKEY_MSG_UDP_SERVER_STATUS,            "Server Status"            },
    { EDONKEY_MSG_UDP_SEARCH_FILE,              "Search File"              },
    { EDONKEY_MSG_UDP_SEARCH_FILE_RESULTS,      "Search File Results"      },
    { EDONKEY_MSG_UDP_GET_SOURCES,              "Get Sources"              },
    { EDONKEY_MSG_UDP_FOUND_SOURCES,            "Found Sources"            },
    { EDONKEY_MSG_UDP_CALLBACK_REQUEST,         "Callback Request"         },
    { EDONKEY_MSG_UDP_CALLBACK_FAIL,            "Callback Fail"            },
    { EDONKEY_MSG_UDP_SERVER_LIST,              "Server List"              },
    { EDONKEY_MSG_UDP_GET_SERVER_INFO,          "Get Server Info"          },
    { EDONKEY_MSG_UDP_SERVER_INFO,              "Server Info"              },
    { EDONKEY_MSG_UDP_GET_SERVER_LIST,          "Get Server List"          },

    /* eMule Extensions */
    { EMULE_MSG_UDP_REASKFILEPING,              "Reask File Ping"          },
    { EMULE_MSG_UDP_REASKACK,                   "Reask ACK"                },
    { EMULE_MSG_UDP_FILE_NOT_FOUND,             "File not found"           },
    { EMULE_MSG_UDP_QUEUE_FULL,                 "Queue Full"               },

    /* Overnet Extensions */
    { OVERNET_MSG_UDP_CONNECT,                  "Connect"                  },
    { OVERNET_MSG_UDP_CONNECT_REPLY,            "Connect Reply"            },
    { OVERNET_MSG_UDP_PUBLICIZE,                "Publicize"                },
    { OVERNET_MSG_UDP_PUBLICIZE_ACK,            "Publicize ACK"            },
    { OVERNET_MSG_UDP_SEARCH,                   "Search"                   },
    { OVERNET_MSG_UDP_SEARCH_NEXT,              "Search Next"              },
    { OVERNET_MSG_UDP_SEARCH_INFO,              "Search Info"              },
    { OVERNET_MSG_UDP_SEARCH_RESULT,            "Search Result"            },
    { OVERNET_MSG_UDP_SEARCH_END,               "Search End"               },
    { OVERNET_MSG_UDP_PUBLISH,                  "Publish"                  },
    { OVERNET_MSG_UDP_PUBLISH_ACK,              "Publish ACK"              },
    { OVERNET_MSG_UDP_IDENTIFY_REPLY,           "Identify Reply"           },
    { OVERNET_MSG_UDP_IDENTIFY_ACK,             "Identify ACK"             },
    { OVERNET_MSG_UDP_FIREWALL_CONNECTION,      "Firewall Connection"      },
    { OVERNET_MSG_UDP_FIREWALL_CONNECTION_ACK,  "Firewall Connection ACK"  },
    { OVERNET_MSG_UDP_FIREWALL_CONNECTION_NACK, "Firewall Connection NACK" },
    { OVERNET_MSG_UDP_IP_QUERY,                 "IP Query"                 },
    { OVERNET_MSG_UDP_IP_QUERY_ANSWER,          "IP Query Answer"          },
    { OVERNET_MSG_UDP_IP_QUERY_END,             "IP Query End"             },
    { OVERNET_MSG_UDP_IDENTIFY,                 "Identify"                 },
    { 0,                                        NULL                       }
};

static const value_string edonkey_special_tags[] = {
    { EDONKEY_STAG_NAME,                "Name"                      },
    { EDONKEY_STAG_SIZE,                "Size"                      },
    { EDONKEY_STAG_TYPE,                "Type"                      },
    { EDONKEY_STAG_FORMAT,              "Format"                    },
    { EDONKEY_STAG_COLLECTION,          "Collection"                },
    { EDONKEY_STAG_PART_PATH,           "Part Path"                 },
    { EDONKEY_STAG_PART_HASH,           "Part Hash"                 },
    { EDONKEY_STAG_COPIED,              "Copied"                    },
    { EDONKEY_STAG_GAP_START,           "Gap Start"                 },
    { EDONKEY_STAG_GAP_END,             "Gap End"                   },
    { EDONKEY_STAG_DESCRIPTION,         "Description"               },
    { EDONKEY_STAG_PING,                "Ping"                      },
    { EDONKEY_STAG_FAIL,                "Fail"                      },
    { EDONKEY_STAG_PREFERENCE,          "Preference"                },
    { EDONKEY_STAG_PORT,                "Port"                      },
    { EDONKEY_STAG_IP,                  "IP"                        },
    { EDONKEY_STAG_VERSION,             "Version"                   },
    { EDONKEY_STAG_TEMPFILE,            "Temporary File"            },
    { EDONKEY_STAG_PRIORITY,            "Priority"                  },
    { EDONKEY_STAG_STATUS,              "Status"                    },
    { EDONKEY_STAG_AVAILABILITY,        "Availability"              },
    { EDONKEY_STAG_QTIME,               "Queue Time"                },
    { EDONKEY_STAG_PARTS,               "Parts"                     },
    { EDONKEY_STAG_MOD_VERSION,         "Mod Version"               },
    { EMULE_STAG_COMPRESSION,           "Compression"               },
    { EMULE_STAG_UDP_CLIENT_PORT,       "UDP Client Port"           },
    { EMULE_STAG_UDP_VERSION,           "UDP Version"               },
    { EMULE_STAG_SOURCE_EXCHANGE,       "Source Exchange"           },
    { EMULE_STAG_COMMENTS,              "Comments"                  },
    { EMULE_STAG_EXTENDED_REQUEST,      "Extended Request"          },
    { EMULE_STAG_COMPATIBLE_CLIENT,     "Compatible Client"         },
    { EMULE_STAG_COMPLETE_SOURCES,      "Complete Sources"          },
    { EMULE_STAG_SIZE_HI,               "Size (High Byte)"          },
    { EMULE_STAG_SERVER_VERSION,        "Server Version"            },
    { EMULE_STAG_COMPAT_OPTIONS1,       "Compatible Options"        },
    { EMULE_STAG_UDPPORTS,              "UDP Ports"                 },
    { EMULE_STAG_MISCOPTIONS1,          "Misc Options 1"            },
    { EMULE_STAG_VERSION,               "eMule Version"             },
    { EMULE_STAG_BUDDYIP,               "Buddy IP"                  },
    { EMULE_STAG_BUDDYUDP,              "Buddy UDP"                 },
    { EMULE_STAG_MISCOPTIONS2,          "Misc Options 2"            },
    { 0,                                NULL                        }
};

static const value_string edonkey_search_ops[] = {
    { EDONKEY_SEARCH_AND,               "AND"                       },
    { EDONKEY_SEARCH_OR,                "OR"                        },
    { EDONKEY_SEARCH_ANDNOT,            "AND NOT"                   },
    { 0,                                NULL                        }
};

static const value_string edonkey_search_conds[] = {
    { EDONKEY_SEARCH_MIN,               "MIN"                       },
    { EDONKEY_SEARCH_MAX,               "MAX"                       },
    { 0,                                NULL                        }
};

static const value_string kademlia_search_conds[] = {
    { 0, "="  },
    { 1, ">"  },
    { 2, "<"  },
    { 3, ">=" },
    { 4, "<=" },
    { 5, "<>" },
    { 0, NULL }
};

static const value_string kademlia_versions[] = {
    { KADEMLIA_VERSION1_46c,     " (eMule <= 0.46c or compatibles)"   },
    { KADEMLIA_VERSION2_47a,     " (eMule 0.47a or compatibles)"      },
    { KADEMLIA_VERSION3_47b,     " (eMule 0.47b or compatibles)"      },
    { KADEMLIA_VERSION5_48a,     " (eMule 0.48a or compatibles)"      },
    { KADEMLIA_VERSION6_49aBETA, " (eMule 0.49aBETA1 or compatibles)" },
    { KADEMLIA_VERSION7_49a,     " (eMule 0.49a or compatibles)"      },
    { 0,                         NULL                                 }
};

static const value_string kademlia_parameter[] = {
    { KADEMLIA_FIND_VALUE,       " (Find Value)"   },
    { KADEMLIA_STORE,            " (Store)"        },
    { KADEMLIA_FIND_NODE,        " (Find Node)"    },
    { 0,                         NULL              }
};

static const value_string kademlia_tag_sourcetype[] = {
    { 1,                         "HighID Source"                                          },
    { 3,                         "Firewalled Kad Source"                                  },
    { 4,                         ">4GB file HighID Source"                                },
    { 5,                         ">4GB file Firewalled Kad Source"                        },
    { 6,                         "Firewalled Source with Direct Callback (supports >4GB)" },
    { 0,                         NULL                                                     }
};

static const value_string kademlia_tag_encryption[] = {
    { 1,                         "Supports Crypt Layer"                                              },
    { 2,                         "Requests Crypt Layer"                                              },
    { 3,                         "Supports & Requests Crypt Layer"                                   },
    { 4,                         "Requires Crypt Layer"                                              },
    { 5,                         "Supports & Requires Crypt Layer"                                   },
    { 6,                         "Requests & Requires Crypt Layer"                                   },
    { 7,                         "Supports, Requests & Requires Crypt Layer"                         },
    { 8,                         "Direct UDP Callback"                                               },
    { 9,                         "Supports Crypt Layer; Direct UDP Callback"                         },
    { 10,                        "Requests Crypt Layer; Direct UDP Callback"                         },
    { 11,                        "Supports & Requests Crypt Layer; Direct UDP Callback"              },
    { 12,                        "Requires Crypt Layer; Direct UDP Callback"                         },
    { 13,                        "Supports & Requires Crypt Layer; Direct UDP Callback"              },
    { 14,                        "Requests & Requires Crypt Layer; Direct UDP Callback"              },
    { 15,                        "Supports, Requests & Requires Crypt Layer; Direct UDP Callback"    },
    { 0,                         NULL                                                                }
};

/* Dissects a generic eDonkey list */
static int dissect_edonkey_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                int offset,  proto_tree *tree,
                                int listnum_length, const char* listdesc,
                                int  (*item_dissector)(tvbuff_t  *, packet_info *, int, proto_tree *))
{
    /* <List> ::= <List Size> <Item>* */
    guint32 listnum, i;
    proto_tree *subtree;
    proto_item* ti;
    proto_item* list_ti;
    int list_start_offset;

    list_start_offset = offset;

    switch (listnum_length) {
        case -1:
        case 1:
            listnum = tvb_get_guint8(tvb, offset);
            break;

        case -2:
            listnum = tvb_get_ntohs(tvb, offset);
            break;

        case 2:
            listnum = tvb_get_letohs(tvb, offset);
            break;

        case 4:
            listnum = tvb_get_letohl(tvb, offset);
            break;

        case -4:
            listnum = tvb_get_ntohl(tvb, offset);
            break;

        default:
            /* Not Supported */
            return offset;
    }
    if (listnum_length < 0)
        listnum_length = -listnum_length;

    /* keep the tree item object, its length will be set at the end of the function */
    list_ti = proto_tree_add_text(tree, tvb, offset, listnum_length, "%s List Size: %u", listdesc, listnum);

    offset+= listnum_length;

    for (i=0; i<listnum; i++)
    {
        int item_start_offset;

        item_start_offset = offset;
        ti = proto_tree_add_text( tree, tvb, item_start_offset, 1, "%s[%u/%u]", listdesc, i+1, listnum);

        subtree = proto_item_add_subtree(ti, ett_edonkey_listitem );

        /* dissect one list element */
        offset = (*item_dissector)(tvb, pinfo, offset, subtree);
        /* Set the container node length */
        proto_item_set_len( ti, offset - item_start_offset );
    }

    /* Set the container node length */
    proto_item_set_len(list_ti, offset - list_start_offset );
    return offset;
}

static gint lookup_str_index(gchar* str, gint length, const value_string *vs)
{
    gint i = 0;

    if (str == NULL) return -1;

    while (vs[i].strptr) {
        if (g_ascii_strncasecmp(str, vs[i].strptr, length) == 0)
            return i;
        i++;
    }

    return -1;
}

static guint8 edonkey_metatag_name_get_type(tvbuff_t *tvb, gint start, gint length, guint8 special_tagtype)
{
    guint8 *tag_name;

    if (match_strval(special_tagtype, edonkey_special_tags) == NULL) {
        gint idx;
        tag_name = tvb_get_ephemeral_string(tvb, start, length);
        idx = lookup_str_index(tag_name, length, edonkey_special_tags);
        if (idx < 0)
            return EDONKEY_STAG_UNKNOWN;
        else return edonkey_special_tags[idx].value;
    }
    else return special_tagtype;

}

static proto_item* edonkey_tree_add_metatag_name(proto_tree *tree, tvbuff_t *tvb,
                                                 gint start, gint length, guint8 special_tagtype)
{
    const gchar *tag_name;
    tag_name = match_strval(special_tagtype, edonkey_special_tags);
    if (tag_name == NULL) {
        return proto_tree_add_item(tree, hf_edonkey_metatag_name, tvb, start, length, FALSE);
    }
    else {
        return proto_tree_add_uint_format(tree, hf_edonkey_metatag_id, tvb, start, length,
                                          special_tagtype, "Meta Tag Name: %s (0x%02x)",
                                          tag_name, special_tagtype);
    }
}

static int dissect_kademlia_search_condition_argument_uint64(tvbuff_t *tvb, packet_info *pinfo _U_,
                                   int offset, proto_tree *tree)
{
    proto_tree_add_item( tree, hf_kademlia_search_condition_argument_uint64, tvb, offset, 8, TRUE );
    return offset + 8;
}

static int dissect_kademlia_search_condition_argument_uint32(tvbuff_t *tvb, packet_info *pinfo _U_,
                                   int offset, proto_tree *tree)
{
    proto_tree_add_item( tree, hf_kademlia_search_condition_argument_uint32, tvb, offset, 4, TRUE );
    return offset + 4;
}

static int dissect_kademlia_search_condition(tvbuff_t *tvb, packet_info *pinfo _U_,
                                   int offset, proto_tree *tree )
{
    proto_item * ti;
    guint16 value = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_item( tree, hf_kademlia_search_condition, tvb, offset, 1, FALSE );
    proto_item_append_text(ti, " [%s]", val_to_str( value, kademlia_search_conds, "Unknown") );

    return offset + 1;
}

/* Dissects the eDonkey meta tag */
static int dissect_edonkey_metatag(tvbuff_t *tvb, packet_info *pinfo _U_,
                                   int offset, proto_tree *tree)
{
    /* <Meta Tag> ::= <Tag Type (guint8)> <Tag Name> <Tag> */
    /* <Tag Name> ::= <Tag Name Size (guint16)> <Special Tag> || <String> */
    /* <Tag Name> ::= <Special Tag> iff Tag Type had the top bit set */
    proto_item *ti;
    proto_tree *metatag_tree;
    guint8 real_tag_type, tag_type, special_tagtype, trans_tagtype, tag_value_guint8;
    guint16 tag_name_size, string_length, array_length, tag_value_guint16;
    guint32 tag_length, blob_length, tag_value_guint32;
    int tag_offset;

    real_tag_type = tag_type = tvb_get_guint8(tvb, offset);
    if (tag_type & EDONKEY_MTAG_SHORTNAME) {
        real_tag_type &= ~EDONKEY_MTAG_SHORTNAME;
        tag_name_size = 1;
        special_tagtype = tvb_get_guint8(tvb, offset+1);
        tag_length = 2;
    } else {
        tag_name_size = tvb_get_letohs(tvb, offset+1);
        special_tagtype = tvb_get_guint8(tvb, offset+3);
        tag_length = 3 + tag_name_size;
    }

    tag_offset = offset + tag_length;

    switch (real_tag_type)
    {
        case EDONKEY_MTAG_HASH:
            /* <Tag> ::= HASH */
            tag_length += 16;
            ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
            metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
            proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
            if (tag_type==real_tag_type)
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
            edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            proto_tree_add_item(metatag_tree, hf_edonkey_hash, tvb, tag_offset, 16, FALSE);
            break;

        case EDONKEY_MTAG_STRING:
            /* <Tag> ::= <Length (guint16)> <String> */
            string_length = tvb_get_letohs(tvb, tag_offset);
            tag_length += 2+string_length;
            ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
            metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
            proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
            if (tag_type==real_tag_type)
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
            edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            proto_tree_add_uint(metatag_tree, hf_edonkey_string_length, tvb, tag_offset, 2, string_length);
            proto_tree_add_item(metatag_tree, hf_edonkey_string, tvb, tag_offset+2, string_length, FALSE);
            break;

        case EDONKEY_MTAG_DWORD:
            /* <Tag> ::= guint32 */
            tag_length += 4;
            ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
            metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
            proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
            if (tag_type==real_tag_type)
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
            edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            trans_tagtype = edonkey_metatag_name_get_type(tvb, offset+3, tag_name_size, special_tagtype);
            if (trans_tagtype == EDONKEY_STAG_IP) {
                proto_tree_add_item(metatag_tree, hf_edonkey_ip, tvb, tag_offset, 4, FALSE);
            }
            else if (trans_tagtype == EMULE_STAG_SERVER_VERSION) {
                guint16 maj, min;
                min = tvb_get_letohs(tvb, tag_offset);
                maj = tvb_get_letohs(tvb, tag_offset+2);
                proto_tree_add_text(metatag_tree, tvb, tag_offset, 4, "Meta Tag Value: %u.%u", maj, min);
            }
            else {
                tag_value_guint32 = tvb_get_letohl(tvb, tag_offset);
                proto_tree_add_text(metatag_tree, tvb, tag_offset, 4, "Meta Tag Value: %u", tag_value_guint32);
            }
            break;

        case EDONKEY_MTAG_FLOAT:
            /* <Tag> ::=  4 byte float */
            tag_length += 4;
            ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
            metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
            proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
            if (tag_type==real_tag_type)
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
            edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            break;

        case EDONKEY_MTAG_WORD:
            /* <Tag> ::= guint16 */
            tag_length += 2;
            ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
            metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
            proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
            if (tag_type==real_tag_type)
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
            edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            {
                tag_value_guint16 = tvb_get_letohs(tvb, tag_offset);
                proto_tree_add_text(metatag_tree, tvb, tag_offset, 2, "Meta Tag Value: %u", tag_value_guint16);
            }
            break;

        case EDONKEY_MTAG_BYTE:
            /* <Tag> ::= guint8 */
            tag_length += 1;
            ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
            metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
            proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
            if (tag_type==real_tag_type)
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
            edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            {
                tag_value_guint8 = tvb_get_guint8(tvb, tag_offset);
                proto_tree_add_text(metatag_tree, tvb, tag_offset, 1, "Meta Tag Value: %u", tag_value_guint8);
            }
            break;

        case EDONKEY_MTAG_BOOL:
            /* <Tag> ::= <Bool (guint8)> */
            tag_length += 1;
            ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
            metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
            proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
            if (tag_type==real_tag_type)
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
            edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            {
                tag_value_guint8 = tvb_get_guint8(tvb, tag_offset);
                proto_tree_add_text(metatag_tree, tvb, tag_offset, 1, "Meta Tag Value: %u", tag_value_guint8);
            }
            break;

        case EDONKEY_MTAG_BOOL_ARRAY:
            /* <Tag> ::= <Length (guint16)> <BoolArray> */
            array_length = tvb_get_letohs(tvb, tag_offset);
            /*
             * This is allegedly what the protocol uses, rather than the
             * correct value of (array_length+7)/8
             * Therefore an extra unused byte is transmitted if the array
             * is a multiple of 8 longs.
             */
            tag_length += 2+(array_length/8)+1;
            ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
            metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
            proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
            if (tag_type==real_tag_type)
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
            edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            proto_tree_add_text(metatag_tree, tvb, tag_offset, 2, "Boolean Array Length: %u", array_length);
            break;

        case EDONKEY_MTAG_BLOB:
            /* <Tag> ::= <Length (guint32)> <BLOB> */
            blob_length = tvb_get_letohl(tvb, tag_offset);
            tag_length += 4+blob_length;
            ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
            metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
            proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
            if (tag_type==real_tag_type)
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
            edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            proto_tree_add_text(metatag_tree, tvb, tag_offset, 2, "BLOB Length: %u", blob_length);
            break;

        case EDONKEY_MTAG_BSOB:
            /* This is possibly a Binary Small OBject, like a BLOB but with an 8 or 16-bit length field */
            /* That's a complete guess though, so don't handle it yet. */
        case EDONKEY_MTAG_UNKNOWN:
        default:
            if (real_tag_type>=EDONKEY_MTAG_STR1 && real_tag_type<=EDONKEY_MTAG_STR16) {
                /* <Tag> ::= <String> */
                string_length = real_tag_type-EDONKEY_MTAG_STR1+1;
                tag_length += string_length;
                ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
                metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
                proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_type, tvb, offset, 1, tag_type);
                if (real_tag_type==tag_type)
                    proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
                edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
                proto_tree_add_item(metatag_tree, hf_edonkey_string, tvb, tag_offset, string_length, FALSE);

            } else {
                /* Unknown tag type - actual tag length is also unknown */
                ti = proto_tree_add_item(tree, hf_edonkey_metatag, tvb, offset, tag_length, FALSE);
                metatag_tree = proto_item_add_subtree(ti, ett_edonkey_metatag);
                proto_tree_add_text(metatag_tree, tvb, offset, 1, "Unknown Meta Tag Type (0x%02x)", tag_type);
                if (real_tag_type==tag_type)
                    proto_tree_add_uint(metatag_tree, hf_edonkey_metatag_namesize, tvb, offset+1, 2, tag_name_size);
                edonkey_tree_add_metatag_name(metatag_tree, tvb, tag_offset-tag_name_size, tag_name_size, special_tagtype);
            }
            break;

    }

    return offset + tag_length;
}

/* Dissects the eDonkey address */
static int dissect_edonkey_address(tvbuff_t *tvb, packet_info *pinfo _U_,
                                   int offset, proto_tree *tree)
{
    /* <Address> ::= <IP> <Port> */
    /*    guint32 ip = tvb_get_letohl(tvb, offset);
          proto_tree_add_ipv4(tree, hf_edonkey_ip, tvb, offset, 4, ip); */
    proto_tree_add_item(tree, hf_edonkey_ip, tvb, offset, 4, FALSE);
    proto_tree_add_item(tree, hf_edonkey_port, tvb, offset+4, 2, TRUE);
    return offset+6;
}


static int dissect_kademlia_udp_port(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_kademlia_udp_port, tvb, offset, 2, TRUE);
    return offset +2;
}

static int dissect_kademlia_tcp_port(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_kademlia_tcp_port, tvb, offset, 2, TRUE);
    return offset +2;
}


static int dissect_kademlia_ip_address(tvbuff_t *tvb, packet_info *pinfo _U_,
                                       int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_kademlia_ip, tvb, offset, 4, TRUE);
    return offset + 4;
}


static int dissect_kademlia_address(tvbuff_t *tvb, packet_info *pinfo _U_,
                                    int offset, proto_tree *tree)
{
    /* <Address> ::= <IP> <Port> <Tcp Port>*/
    offset = dissect_kademlia_ip_address( tvb, pinfo, offset, tree );

    offset = dissect_kademlia_udp_port( tvb, pinfo, offset, tree );

    offset = dissect_kademlia_tcp_port( tvb, pinfo, offset, tree );

    return offset;
}

static int dissect_kademlia_tagname(tvbuff_t *tvb, packet_info *pinfo _U_,
                                    int offset, proto_tree *tree, const gchar** outputTagName, const gchar** outputExtendedTagName)
{
    /* <String> ::= <String length (guint16)> DATA */
    const gchar * tagname;
    const gchar * tag_full_name = NULL;
    guint8 tagname_value;
    proto_item *ti, *hidden_item;

    guint16 string_length = tvb_get_letohs(tvb, offset);

    proto_tree_add_uint(tree, hf_kademlia_tag_name_length, tvb, offset, 2, string_length);

    hidden_item = proto_tree_add_uint(tree, hf_edonkey_string_length, tvb, offset, 2, string_length);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    tagname = tvb_get_ephemeral_string( tvb, offset + 2, string_length );

    tag_full_name = "UnknownTagName";

    if ( tagname && string_length == 1 ) {
        tagname_value = *(guint8*)tagname;
        /* lookup tagname */
        tag_full_name = val_to_str( tagname_value, kademlia_tags, tag_full_name );
    }

    ti = proto_tree_add_item(tree, hf_kademlia_tag_name, tvb, offset+2, string_length, FALSE);
    proto_item_append_text(ti, " [%s]", tag_full_name);

    if (outputTagName)
        *outputTagName = tagname;

    if (outputExtendedTagName)
        *outputExtendedTagName = tag_full_name;

    return offset+2+string_length;
}

static int dissect_kademlia_string(tvbuff_t *tvb, packet_info *pinfo _U_,
                                    int offset, proto_tree *tree)
{
    /* <String> ::= <String length (guint16)> DATA */
    const gchar * string_value;
    guint16 string_length;
    string_length = tvb_get_letohs(tvb, offset);

    proto_tree_add_uint(tree, hf_edonkey_string_length, tvb, offset, 2, string_length);

    string_value = tvb_get_ephemeral_string( tvb, offset + 2, string_length );

    proto_tree_add_text(tree, tvb, offset+2, string_length, "String: %s", string_value);

    return offset+2+string_length;
}

/* Dissects the eDonkey address list */
static int dissect_edonkey_address_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset,  proto_tree *tree)
{
    /* <Address List> ::= <List Size (guint8)> <Address>* */
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 1, "Address", dissect_edonkey_address);
}

/* Dissects the eDonkey hash */
static int dissect_edonkey_hash(tvbuff_t *tvb, packet_info *pinfo _U_,
                                int offset, proto_tree *tree)
{
    /* <hash> ::= HASH (16 word MD4 digest) */
    proto_tree_add_item(tree, hf_edonkey_hash, tvb, offset, 16, FALSE);
    return offset+16;
}

/* Dissects the eDonkey file hash */
static int dissect_edonkey_file_hash(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset, proto_tree *tree)
{
    /* <File hash> ::= HASH (16 word MD4 digest) */
    proto_tree_add_item(tree, hf_edonkey_file_hash, tvb, offset, 16, FALSE);
    return offset+16;
}

/* Dissects the eMule public key */
static int dissect_edonkey_public_key(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset, proto_tree *tree)
{
    guint8 length = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "Public key length: %u", length);
    offset++;
    proto_tree_add_item(tree, hf_emule_public_key, tvb, offset, length, FALSE);
    return offset + length;
}

/* Dissects the eMule signature */
static int dissect_edonkey_signature(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset, proto_tree *tree)
{
    guint8 length = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "Signature length: %u", length);
    offset++;
    proto_tree_add_item(tree, hf_emule_signature, tvb, offset, length, FALSE);
    return offset + length;
}

static const char *kademlia_hash(tvbuff_t *tvb, int offset) {
    guint32 hash[4];
    int i;

    for (i = 0; i < 4; i++)
        hash[i] = tvb_get_letohl(tvb, offset + i*4);

    return ep_strdup_printf("%08X%08X%08X%08X", hash[0], hash[1], hash[2], hash[3]);
}

static int dissect_kademlia_hash_hidden(tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset, proto_tree *tree) {
    proto_item *hidden_item;
    const char *hash;

    hash = kademlia_hash(tvb, offset);

    /* <File hash> ::= HASH (16 word MD4 digest) */
    hidden_item = proto_tree_add_string_format_value(tree, hf_kademlia_hash, tvb, offset, 16, hash, "%s", hash);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    return offset+16;
}

/* Dissects the Kademlia hash*/
static int dissect_kademlia_hash(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, proto_tree *tree, int *value_ptr) {
    const char *hash;

    hash = kademlia_hash(tvb, offset);

    /* <File hash> ::= HASH (16 word MD4 digest) */
    proto_tree_add_string_format_value(tree, *value_ptr, tvb, offset, 16, hash, "%s", hash);

    return dissect_kademlia_hash_hidden(tvb, pinfo, offset, tree);
}

static int dissect_kademlia_tag_hash_hidden(tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset, proto_tree *tree) {
    proto_item *hidden_item;
    const char *hash;

    hash = kademlia_hash(tvb, offset);

    /* <File hash> ::= HASH (16 word MD4 digest) */
    hidden_item = proto_tree_add_string_format_value(tree, hf_kademlia_tag_hash, tvb, offset, 16, hash, "%s", hash);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    return offset+16;
}

static int dissect_kademlia_tag_hash(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, proto_tree *tree) {
    const char *hash;

    hash = kademlia_hash(tvb, offset);

    /* <File hash> ::= HASH (16 word MD4 digest) */
    proto_tree_add_string_format_value(tree, hf_kademlia_hash, tvb, offset, 16, hash, "%s", hash);
    return dissect_kademlia_tag_hash_hidden( tvb, pinfo, offset, tree );
}

static int dissect_kademlia_tag_bsob(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, proto_tree *tree, const gchar** string_value )
{
    guint16 bsob_length;

    bsob_length = tvb_get_guint8(tvb, offset);
    *string_value = tvb_bytes_to_str( tvb, offset + 1, bsob_length );

    proto_tree_add_item(tree, hf_kademlia_tag_bsob, tvb, offset + 1, bsob_length, FALSE);
    return offset + 1 + bsob_length;
}


static int dissect_kademlia_tag_string(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, proto_tree *tree, const gchar** string_value)
{
    proto_item *hidden_item;
    guint16 string_length = tvb_get_letohs(tvb, offset);

    hidden_item = proto_tree_add_uint(tree, hf_edonkey_string_length, tvb, offset, 2, string_length);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(tree, hf_edonkey_string, tvb, offset+2, string_length, FALSE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    *string_value = tvb_get_ephemeral_string(tvb, offset + 2, string_length);

    proto_tree_add_item(tree, hf_kademlia_tag_string, tvb, offset + 2, string_length, FALSE);
    return offset + 2 + string_length;
}

/* Dissects the eDonkey hash list */
static int dissect_edonkey_hash_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset,  proto_tree *tree)
{
    /* <Hash List> ::= <File Hash> <List Size (guint16)> <Hash>* */
    offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "Hash", dissect_edonkey_hash);
}

/* Dissects the eDonkey meta tag list */
static int dissect_edonkey_metatag_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset, proto_tree *tree)
{
    /* <Meta Tag List> ::= <List Size (guint32)> <Meta tag>* */
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 4, "Meta Tag", dissect_edonkey_metatag);
}

/* Dissects the eDonkey String */
static int dissect_edonkey_string(tvbuff_t *tvb, packet_info *pinfo _U_,
                                  int offset, proto_tree *tree)
{
    /* <String> ::= <String length (guint16)> DATA */
    guint16 string_length = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(tree, hf_edonkey_string_length, tvb, offset, 2, string_length);
    proto_tree_add_item(tree, hf_edonkey_string, tvb, offset+2, string_length, FALSE);
    return offset+2+string_length;
}

/* Dissects the eDonkey Directory */
static int dissect_edonkey_directory(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset, proto_tree *tree)
{
    /* <Directory> ::= <String> */
    guint16 string_length = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(tree, hf_edonkey_string_length, tvb, offset, 2, string_length);
    proto_tree_add_item(tree, hf_edonkey_directory, tvb, offset+2, string_length, FALSE);
    return offset+2+string_length;
}

/* Dissects the eDonkey Filename */
static int dissect_edonkey_file_name(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset, proto_tree *tree)
{
    /* <Filename> ::= <String> */
    return dissect_edonkey_string(tvb, pinfo, offset, tree);
}

/* Dissects the eDonkey File Status */
static int dissect_edonkey_file_status(tvbuff_t *tvb, packet_info *pinfo _U_,
                                       int offset, proto_tree *tree)
{
    guint16 partcount, arrlen;

    /* <File Status> ::= <Part Count> <Part Status> */
    partcount = tvb_get_letohs(tvb, offset);
    arrlen = (partcount+7)/8;

    proto_tree_add_uint(tree, hf_edonkey_part_count, tvb, offset, 2, partcount);
    if (partcount>0) {
        proto_tree_add_item(tree, hf_edonkey_file_status, tvb, offset+2, arrlen, FALSE);
    }
    return offset+2+arrlen;
}


/* Dissects the eDonkey directory list */
static int dissect_edonkey_directory_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                          int offset,  proto_tree *tree)
{
    /* <Directory List> ::= <List Size (guint32)> <Directory>* */
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 4, "Directory", dissect_edonkey_directory);
}

/* Dissects the eDonkey server hash */
static int dissect_edonkey_server_hash(tvbuff_t *tvb, packet_info *pinfo _U_,
                                       int offset, proto_tree *tree)
{
    /* <Server hash> ::= HASH (16 word MD4 digest) */
    proto_tree_add_item(tree, hf_edonkey_server_hash, tvb, offset, 16, FALSE);
    return offset+16;
}

/* Dissects the eDonkey client hash */
static int dissect_edonkey_client_hash(tvbuff_t *tvb, packet_info *pinfo _U_,
                                       int offset, proto_tree *tree)
{
    /* <Client hash> ::= HASH (16 word MD4 digest) */
    proto_tree_add_item(tree, hf_edonkey_client_hash, tvb, offset, 16, FALSE);
    return offset+16;
}

/* Dissects the eMule sourceOBFU */
static int dissect_emule_sourceOBFU(tvbuff_t *tvb, packet_info *pinfo _U_,
                                   int offset, proto_tree *tree)
{

    proto_item *ti;
    proto_tree *sourceOBFU_tree;
    guint8 settings = tvb_get_guint8(tvb, offset+6);
    /* Add subtree for client info */
    ti = proto_tree_add_item(tree, hf_emule_sourceOBFU, tvb, offset, 7 + ((settings & 0x80) ? 16 : 0), FALSE);
    sourceOBFU_tree = proto_item_add_subtree(ti, ett_emule_sourceOBFU);

    proto_tree_add_item(sourceOBFU_tree, hf_edonkey_ip, tvb, offset, 4, FALSE);
    proto_tree_add_item(sourceOBFU_tree, hf_edonkey_port, tvb, offset+4, 2, TRUE);
    proto_tree_add_text(sourceOBFU_tree, tvb, offset+6, 1, "Obfuscation Settings: %u", settings);
    offset += 7;
    if (settings & 0x80)
        offset = dissect_edonkey_client_hash(tvb, pinfo, offset, sourceOBFU_tree);
    return offset;
}


/* Dissects the eMule sourceOBFU list */
static int dissect_emule_sourceOBFU_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset,  proto_tree *tree)
{
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 1, "Sources Obfuscation", dissect_emule_sourceOBFU);
}


/* Dissects the eDonkey client ID */
static int dissect_edonkey_client_id(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset, proto_tree *tree, gboolean fileinfo)
{
    proto_item *ti;
    /* <Client ID> ::= guint32 */
    /*    guint32 ip = tvb_get_letohl(tvb, offset);
          proto_tree_add_ipv4(tree, hf_edonkey_client_id, tvb, offset, 4, ip); */
    ti = proto_tree_add_item(tree, hf_edonkey_client_id, tvb, offset, 4, FALSE);
    if (fileinfo) {
        guint32 ip = tvb_get_letohl(tvb, offset);
        guint16 port = tvb_get_letohs(tvb, offset+4);
        if (ip==0xfcfcfcfc && port==0xfcfc) {
            proto_item_append_text(ti, " (myself, incomplete file)");
        } else if (ip==0xfbfbfbfb && port==0xfbfb) {
            proto_item_append_text(ti, " (myself, complete file)");
        }
    }
    return offset+4;
}

/* Dissects the eDonkey port */
static int dissect_edonkey_port(tvbuff_t *tvb, packet_info *pinfo _U_,
                                int offset, proto_tree *tree)
{
    /* <Port> ::= guint16 */
    proto_tree_add_item(tree, hf_edonkey_port, tvb, offset, 2, TRUE);
    return offset+2;
}

/* Dissects the eDonkey start offset */
static int dissect_edonkey_start_offset(tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset, proto_tree *tree)
{
    /* <Start Offset> ::= guint32 */
    guint32 start = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "Start Offset: %u", start);
    return offset+4;
}

static int dissect_edonkey_start_offset_64(tvbuff_t *tvb, packet_info *pinfo _U_,
                                           int offset, proto_tree *tree)
{
    /* <Start Offset> ::= guint64 */
    guint64 start = tvb_get_letoh64(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 8, "Start Offset: %" G_GINT64_MODIFIER "u", start);
    return offset+8;
}

/* Dissects the eDonkey end offset */
static int dissect_edonkey_end_offset(tvbuff_t *tvb, packet_info *pinfo _U_,
                                      int offset, proto_tree *tree)
{
    /* <End Offset> ::= guint32 */
    guint32 end = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "End Offset: %u", end);
    return offset+4;
}

static int dissect_edonkey_end_offset_64(tvbuff_t *tvb, packet_info *pinfo _U_,
                                         int offset, proto_tree *tree)
{
    /* <End Offset> ::= guint64 */
    guint64 end = tvb_get_letoh64(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 8, "End Offset: %" G_GINT64_MODIFIER "u", end);
    return offset+8;
}

/* Dissects the eDonkey client info */
static int dissect_edonkey_client_info(tvbuff_t *tvb, packet_info *pinfo _U_,
                                       int offset,  proto_tree *tree)
{
    /* <Client info> ::= <Client hash> <Client ID> <Port> <Meta tag list> */
    proto_item *ti;
    proto_tree *clientinfo_tree;
    /* Add subtree for client info */
    ti = proto_tree_add_item(tree, hf_edonkey_clientinfo, tvb, offset, 0, FALSE);
    clientinfo_tree = proto_item_add_subtree(ti, ett_edonkey_clientinfo);
    offset = dissect_edonkey_client_hash(tvb, pinfo, offset, clientinfo_tree);
    offset = dissect_edonkey_client_id(tvb, pinfo, offset, clientinfo_tree, FALSE);
    offset = dissect_edonkey_port(tvb, pinfo, offset, clientinfo_tree);
    offset = dissect_edonkey_metatag_list(tvb, pinfo, offset, clientinfo_tree);
    return offset;
}

/* Dissects the eDonkey client info list */
static int dissect_edonkey_client_info_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                            int offset,  proto_tree *tree)
{
    /* <Client Info List> ::= <List Size (guint32)> <Client Info>* */
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 4, "Client Info", dissect_edonkey_client_info);
}

/* Dissects the eDonkey server info */
static int dissect_edonkey_server_info(tvbuff_t *tvb, packet_info *pinfo _U_,
                                       int offset,  proto_tree *tree)
{
    /* <Server info> ::= <Server hash> <Server Address> <Meta tag list> */
    proto_item *ti;
    proto_tree *serverinfo_tree;
    /* Add subtree for server info */
    ti = proto_tree_add_item(tree, hf_edonkey_serverinfo, tvb, offset, 0, FALSE);
    serverinfo_tree = proto_item_add_subtree(ti, ett_edonkey_serverinfo);
    offset = dissect_edonkey_server_hash(tvb, pinfo, offset, serverinfo_tree);
    offset = dissect_edonkey_address(tvb, pinfo, offset, serverinfo_tree);
    offset = dissect_edonkey_metatag_list(tvb, pinfo, offset, serverinfo_tree);
    return offset;
}

/* Dissects the eDonkey file info */
static int dissect_edonkey_file_info(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset,  proto_tree *tree)
{
    /* <File info> ::= <File hash> <Client ID> <Port> <Meta tag list> */
    proto_item *ti;
    proto_tree *fileinfo_tree;
    int startoff;
    /* Add subtree for file info */
    ti = proto_tree_add_item(tree, hf_edonkey_fileinfo, tvb, offset, 0, FALSE);
    startoff = offset;
    fileinfo_tree = proto_item_add_subtree(ti, ett_edonkey_fileinfo);
    offset = dissect_edonkey_file_hash(tvb, pinfo, offset, fileinfo_tree);
    offset = dissect_edonkey_client_id(tvb, pinfo, offset, fileinfo_tree, TRUE);
    offset = dissect_edonkey_port(tvb, pinfo, offset, fileinfo_tree);
    offset = dissect_edonkey_metatag_list(tvb, pinfo, offset, fileinfo_tree);
    proto_item_set_len(ti, offset-startoff);
    return offset;
}

/* Dissects the eDonkey file info list */
static int dissect_edonkey_file_info_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                          int offset,  proto_tree *tree)
{
    /* <File Info List> ::= <List Size (guint32)> <File Info>* */
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 4, "File Info", dissect_edonkey_file_info);
}


/* Dissects the eMule   address list */
static int dissect_emule_address_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                      int offset,  proto_tree *tree)
{
    /* <Address List> ::= <List Size (guint16)> <Address>* */
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "Address", dissect_edonkey_address);
}

static int dissect_emule_aich_root_hash(tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset, proto_tree *tree)
{
    /* <AICH Root Hash> ::= HASH (20 byte SHA1 digest) */
    proto_tree_add_item(tree, hf_emule_aich_root_hash, tvb, offset, 20, FALSE);
    return offset + 20;
}

static int dissect_emule_aich_hash_list_entry(tvbuff_t *tvb, packet_info *pinfo _U_,
                                              int offset, proto_tree *tree)
{
    guint16 hashid;
    proto_item *ti;
    proto_tree *aichhash_tree;
    /* <AICH Hash List Entry> ::= <AICH Hash ID> <AICH Hash> */
    ti = proto_tree_add_item(tree, hf_emule_aich_hash_entry, tvb, offset, 22, FALSE);
    aichhash_tree = proto_item_add_subtree(ti, ett_emule_aichhash);

    hashid = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(aichhash_tree, hf_emule_aich_hash_id, tvb, offset, 2, hashid);
    proto_tree_add_item(aichhash_tree, hf_emule_aich_hash, tvb, offset+2, 20, FALSE);
    return offset + 22;
}

static int dissect_emule_aich_hash_list(tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset, proto_tree *tree)
{
    /* <AICH Hash List> ::= <List Size (guint16)> < <AICH Hash ID> <AICH Hash> >* */
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "AICH Hash", dissect_emule_aich_hash_list_entry);
}

static int dissect_emule_multipacket(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset, int eoffset, proto_tree *tree, int isext)
{
    guint8 opcode, nextop;
    guint16 namelen, partcount, arrlen, oplen;
    guint32 sourcecount;
    proto_item *ti;
    proto_tree *mp_tree;

    /* <MultiPacket> ::= <File Hash> <Opcodes>* */
    /* <MultiPacketExt> ::= <File Hash> <FileLength> <Opcodes>* */
    offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);

    if (isext) {
        guint64 filelen = tvb_get_letoh64(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 8, "File Length: %" G_GINT64_MODIFIER "u", filelen);
        offset += 8;
    }

    while (offset<eoffset) {
        opcode = tvb_get_guint8(tvb, offset);

        switch (opcode) {
            case EDONKEY_MSG_FILE_STATUS_REQUEST:
                ti = proto_tree_add_item(tree, hf_emule_multipacket_entry, tvb, offset, 1, FALSE);
                mp_tree = proto_item_add_subtree(ti, ett_emule_multipacket);

                proto_tree_add_uint_format(mp_tree, hf_emule_multipacket_opcode, tvb, offset, 1,
                                           opcode, "File Status Request (0x%02x)", opcode);
                offset += 1;
                break;
            case EDONKEY_MSG_FILE_REQUEST:
                partcount = 443; /* Invalid */
                sourcecount = 65536; /* Out of range */
                arrlen = 0;
                oplen = 1;

                if (offset+2<eoffset) {
                    nextop = tvb_get_guint8(tvb, offset+1);
                    if (nextop!=EDONKEY_MSG_FILE_STATUS_REQUEST &&
                        nextop!=EMULE_MSG_SOURCES_REQUEST &&
                        nextop!=EMULE_MSG_AICHFILEHASH_REQUEST) {

                        partcount = tvb_get_letohs(tvb, offset+1);
                        if (partcount<=442) {
                            arrlen = (partcount+7)/8;
                            oplen += 2+arrlen;

                            if (offset+2+arrlen+2<eoffset) {
                                nextop = tvb_get_guint8(tvb, offset+2+arrlen+1);
                                if (nextop!=EDONKEY_MSG_FILE_STATUS_REQUEST &&
                                    nextop!=EMULE_MSG_SOURCES_REQUEST &&
                                    nextop!=EMULE_MSG_AICHFILEHASH_REQUEST) {

                                    sourcecount = tvb_get_letohs(tvb, offset+2+arrlen+1);
                                    oplen += 2;
                                }
                            }
                        }
                    }
                }

                ti = proto_tree_add_item(tree, hf_emule_multipacket_entry, tvb, offset, oplen, FALSE);
                mp_tree = proto_item_add_subtree(ti, ett_emule_multipacket);

                proto_tree_add_uint_format(mp_tree, hf_emule_multipacket_opcode, tvb, offset, 1,
                                           opcode, "File Name Request (0x%02x)", opcode);
                if (partcount<=442) {
                    dissect_edonkey_file_status(tvb, pinfo, offset+1, mp_tree);
                    if (sourcecount<65536) {
                        proto_tree_add_uint(mp_tree, hf_emule_source_count, tvb, offset+3+arrlen, 2, sourcecount);
                    }
                }
                offset += oplen;
                break;
            case EMULE_MSG_SOURCES_REQUEST:
                ti = proto_tree_add_item(tree, hf_emule_multipacket_entry, tvb, offset, 1, FALSE);
                mp_tree = proto_item_add_subtree(ti, ett_emule_multipacket);

                proto_tree_add_uint_format(mp_tree, hf_emule_multipacket_opcode, tvb, offset, 1,
                                           opcode, "Sources Request (0x%02x)", opcode);
                offset += 1;
                break;
            case EMULE_MSG_AICHFILEHASH_REQUEST:
                ti = proto_tree_add_item(tree, hf_emule_multipacket_entry, tvb, offset, 1, FALSE);
                mp_tree = proto_item_add_subtree(ti, ett_emule_multipacket);

                proto_tree_add_uint_format(mp_tree, hf_emule_multipacket_opcode, tvb, offset, 1,
                                           opcode, "AICH Root Hash Request (0x%02x)", opcode);
                offset += 1;
                break;

            case EDONKEY_MSG_FILE_STATUS:
                partcount = tvb_get_letohs(tvb, offset+1);
                arrlen = (partcount+7)/8;

                ti = proto_tree_add_item(tree, hf_emule_multipacket_entry, tvb, offset, 3+arrlen, FALSE);
                mp_tree = proto_item_add_subtree(ti, ett_emule_multipacket);

                proto_tree_add_uint_format(mp_tree, hf_emule_multipacket_opcode, tvb, offset, 1,
                                           opcode, "File Status (0x%02x)", opcode);
                offset = dissect_edonkey_file_status(tvb, pinfo, offset+1, mp_tree);
                break;
            case EDONKEY_MSG_FILE_REQUEST_ANSWER:
                namelen = tvb_get_letohs(tvb, offset+1);

                ti = proto_tree_add_item(tree, hf_emule_multipacket_entry, tvb, offset, 3+namelen, FALSE);
                mp_tree = proto_item_add_subtree(ti, ett_emule_multipacket);

                proto_tree_add_uint_format(mp_tree, hf_emule_multipacket_opcode, tvb, offset, 1,
                                           opcode, "File Name (0x%02x)", opcode);
                offset = dissect_edonkey_file_name(tvb, pinfo, offset+1, mp_tree);
                break;
            case EMULE_MSG_AICHFILEHASH_ANSWER:
                ti = proto_tree_add_item(tree, hf_emule_multipacket_entry, tvb, offset, 21, FALSE);
                mp_tree = proto_item_add_subtree(ti, ett_emule_multipacket);

                proto_tree_add_uint_format(mp_tree, hf_emule_multipacket_opcode, tvb, offset, 1,
                                           opcode, "AICH Root Hash (0x%02x)", opcode);
                proto_tree_add_item(mp_tree, hf_emule_aich_root_hash, tvb, offset+1, 20, FALSE);
                offset += 21;
                break;

            default:
                /* Unknown opcode means we can't continue parsing the stream */
                proto_tree_add_uint_format(tree, hf_emule_multipacket_opcode, tvb, offset, 1,
                                           opcode, "Unknown MultiPacket opcode (0x%02x)", opcode);
                return offset+1;
        }
    }

    return offset;
}

/* Dissects the Overnet peer type */
static int dissect_overnet_peertype(tvbuff_t *tvb, packet_info *pinfo _U_,
                                    int offset, proto_tree *tree)
{
    /* <Peer type> ::= guint8 */
    guint8 peertype = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "Peer Type: %u", peertype);
    return offset+1;
}

/* Dissects the Overnet peer */
static int dissect_overnet_peer(tvbuff_t *tvb, packet_info *pinfo _U_,
                                int offset, proto_tree *tree)
{
    /* <Peer> ::= <Hash> <Address> <Peer type> */
    proto_item *ti;
    proto_tree *peer_tree;
    ti = proto_tree_add_item(tree, hf_overnet_peer, tvb, offset, 16 + 6 + 1, FALSE);
    peer_tree = proto_item_add_subtree(ti, ett_overnet_peer);
    offset = dissect_edonkey_hash(tvb, pinfo, offset, peer_tree);
    offset = dissect_edonkey_address(tvb, pinfo, offset, peer_tree);
    offset = dissect_overnet_peertype(tvb, pinfo, offset, peer_tree);
    return offset;
}

static int dissect_kademlia_peertype(tvbuff_t *tvb, packet_info *pinfo _U_,
                                     int offset, proto_tree *tree)
{
    /* <Peer type> ::= 1bytes */
    proto_tree_add_item( tree, hf_kademlia_peertype, tvb, offset, 1, FALSE );
    return offset + 1;
}

/* Dissects the Kademlia peer */
static int dissect_kademlia_peer(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, proto_tree *tree)
{
    /* <Peer> ::= <Hash> <Address> <Peer type> */
    proto_item *ti;
    proto_tree *peer_tree;
    int kad_version;

    ti = proto_tree_add_item(tree, hf_kademlia_peer, tvb, offset, 16 + 4 + 4  + 1, FALSE);

    peer_tree = proto_item_add_subtree(ti, ett_overnet_peer);

    /* 16 */
    offset = dissect_kademlia_hash(tvb, pinfo, offset, peer_tree, &hf_kademlia_peer_id);

    /* 8 ( 4 ip + 2 tcp port + 2 udp port ) */
    offset = dissect_kademlia_address(tvb, pinfo, offset, peer_tree);

    /* 1 */
    /* offset = dissect_kademlia_peertype(tvb, pinfo, offset, peer_tree); */
    kad_version = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_item(peer_tree, hf_kademlia_version, tvb, offset, 1, FALSE);
    proto_item_append_text(ti, "%s", val_to_str(kad_version, kademlia_versions, " Unknown"));
    return offset + 1;
}

/* Dissects the Kademlia2 peer */
static int dissect_kademlia2_peer(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 int offset, proto_tree *tree)
{
    /* <Peer> ::= <Hash> <Address> <Peer type> */
    proto_item *ti;
    proto_tree *peer_tree;

    ti = proto_tree_add_item(tree, hf_kademlia_peer, tvb, offset, 16 + 4 + 4  + 1, FALSE);

    peer_tree = proto_item_add_subtree(ti, ett_overnet_peer);

    /* 16 */
    offset = dissect_kademlia_hash(tvb, pinfo, offset, peer_tree, &hf_kademlia_peer_id);

    /* 8 ( 4 ip + 2 tcp port + 2 udp port ) */
    offset = dissect_kademlia_address(tvb, pinfo, offset, peer_tree);

    /* 1 */
    offset = dissect_kademlia_peertype(tvb, pinfo, offset, peer_tree);
    return offset;
}


/* Dissects the eDonkey search query */
static int dissect_edonkey_search_query(tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset, proto_tree *tree)
{
    /* <Search Query> ::= <Search Type> <Search> */
    proto_item *ti;
    proto_tree *search_tree;
    guint8 search_type, operator, special_tagtype, limit_type;
    guint16 tag_name_size, string_length;
    guint32 search_length, limit;
    int string_offset, tag_name_offset;

    search_type = tvb_get_guint8(tvb, offset);
    search_length = 1;

    switch (search_type)
    {
        case EDONKEY_SEARCH_BOOL:
            /* <Search> ::=  <Operator> <Search Query> <Search Query> */
            search_length += 1;
            operator = tvb_get_guint8(tvb, offset+1);

            /* Add subtree for search entry */
            ti = proto_tree_add_item(tree, hf_edonkey_search, tvb, offset, search_length, FALSE);
            search_tree = proto_item_add_subtree(ti, ett_edonkey_search);

            /* Add query info */
            proto_tree_add_text(search_tree, tvb, offset, 2, "Boolean search (0x%02x): %s (0x%02x)",
                                search_type, val_to_str(operator, edonkey_search_ops, "Unknown"), operator);

            offset+=2;
            offset = dissect_edonkey_search_query(tvb, pinfo, offset, search_tree);
            offset = dissect_edonkey_search_query(tvb, pinfo, offset, search_tree);
            break;

        case EDONKEY_SEARCH_NAME:
            /* <Search> ::=  <String> */
            string_offset = offset + search_length;
            string_length = tvb_get_letohs(tvb, string_offset);
            search_length += 2+string_length;

            /* Add subtree for search entry */
            ti = proto_tree_add_item(tree, hf_edonkey_search, tvb, offset, search_length, FALSE);
            search_tree = proto_item_add_subtree(ti, ett_edonkey_search);

            /* Add query info */
            proto_tree_add_text(search_tree, tvb, offset, 1, "Search by name (0x%02x)", search_type);
            proto_tree_add_uint(search_tree, hf_edonkey_string_length, tvb, string_offset, 2, string_length);
            proto_tree_add_item(search_tree, hf_edonkey_string, tvb, string_offset+2, string_length, FALSE);
            offset += search_length;
            break;

        case EDONKEY_SEARCH_META:
            /* <Search> ::=  <String> <Meta tag Name> */
            string_offset = offset + search_length;
            string_length = tvb_get_letohs(tvb, offset+1);
            search_length += 2+string_length;

            tag_name_offset = offset + search_length;
            tag_name_size = tvb_get_letohs(tvb, tag_name_offset);
            special_tagtype = tvb_get_guint8(tvb, tag_name_offset+2);
            search_length += 2 + tag_name_size;

            /* Add subtree for search entry */
            ti = proto_tree_add_item(tree, hf_edonkey_search, tvb, offset, search_length, FALSE);
            search_tree = proto_item_add_subtree(ti, ett_edonkey_search);

            /* Add query info */
            proto_tree_add_text(search_tree, tvb, offset, 1, "Search by metadata (0x%02x)", search_type);
            proto_tree_add_uint(search_tree, hf_edonkey_string_length, tvb, string_offset, 2, string_length);
            proto_tree_add_item(search_tree, hf_edonkey_string, tvb, string_offset+2, string_length, FALSE);
            proto_tree_add_uint(search_tree, hf_edonkey_metatag_namesize, tvb, tag_name_offset, 2, tag_name_size);
            edonkey_tree_add_metatag_name(search_tree, tvb, tag_name_offset+2, tag_name_size, special_tagtype);
            offset += search_length;
            break;

        case EDONKEY_SEARCH_LIMIT:
            /* <Search> ::=  <Limit (guint32)> <Minmax> <Meta tag Name> */
            search_length += 5; /* 4 bytes for the limit, one for the minmax */
            limit = tvb_get_letohl(tvb, offset+1);
            limit_type = tvb_get_guint8(tvb, offset+5);

            tag_name_offset = offset + search_length;
            tag_name_size = tvb_get_letohs(tvb, tag_name_offset);
            special_tagtype = tvb_get_guint8(tvb, tag_name_offset+2);
            search_length += 2 + tag_name_size;

            /* Add subtree for search entry */
            ti = proto_tree_add_item(tree, hf_edonkey_search, tvb, offset, search_length, FALSE);
            search_tree = proto_item_add_subtree(ti, ett_edonkey_search);

            /* Add query info */
            proto_tree_add_text(search_tree, tvb, offset, 6, "Search by limit (0x%02x): %s %u",
                                search_type, val_to_str(limit_type, edonkey_search_conds, "Unknown"), limit);
            proto_tree_add_uint(search_tree, hf_edonkey_metatag_namesize, tvb, tag_name_offset, 2, tag_name_size);
            edonkey_tree_add_metatag_name(search_tree, tvb, tag_name_offset+2, tag_name_size, special_tagtype);
            offset += search_length;
            break;

        default:
            /* Unknown search type - actual search length is also unknown */
            ti = proto_tree_add_item(tree, hf_edonkey_search, tvb, offset, search_length, FALSE);
            search_tree = proto_item_add_subtree(ti, ett_edonkey_search);
            proto_tree_add_text(search_tree, tvb, offset, search_length, "Unknown Search (0x%02x)", search_type);
            offset += search_length;
            break;
    }

    return offset;
}

static void dissect_edonkey_tcp_message(guint8 msg_type,
                                        tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset, int length, proto_tree *tree)
{
    int msg_end, bytes_remaining;
    guint8  helloClient, more;
    guint32 nusers, nfiles;

    if (tree == NULL) return;

    bytes_remaining = tvb_reported_length_remaining(tvb, offset);
    if ((length < 0) || (length > bytes_remaining)) length = bytes_remaining;
    if (length <= 0) return;

    msg_end = offset + length;

    switch (msg_type) {
        case EDONKEY_MSG_HELLO:
            /* Client to Server: <Client Info> */
            /* Client to Client: 0x10 <Client Info> <Server address> */
            /* If Hello is sent to server 0x10 before UserHash is skipped,
               but UserHash might starts with 0x10. To decrease posibility
               of mistake, we check also 6th and 15h byte of UserHash -
               they have constant value. The best way would be to process
               whole packet to check it. */
            helloClient = (tvb_get_guint8(tvb, offset) == 0x10 && tvb_get_guint8(tvb, offset + 6) == 0x0E && tvb_get_guint8(tvb, offset + 15) == 0x6F);
            if (helloClient) {
                proto_tree_add_text(tree, tvb, offset, 1, "User hash length: 16");
                offset += 1;
            }
            offset = dissect_edonkey_client_info(tvb, pinfo, offset, tree);
            if (helloClient)  /* User's server ip is sent only to clients. */
                offset = dissect_edonkey_address(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_HELLO_ANSWER: /* Hello Answer: <Client Info> <Server address> */
            offset = dissect_edonkey_client_info(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_address(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_SERVER_CB_REQ: /* Server Callback Request: <Client address> */
            offset = dissect_edonkey_address(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_SERVER_INFO_DATA: /* Server Info Data: <Server Info> */
            offset = dissect_edonkey_server_info(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_SERVER_LIST: /* Server List: <Address List> */
            offset = dissect_edonkey_address_list(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_OFFER_FILES: /* Offer Files: <File info List> */
        case EDONKEY_MSG_VIEW_FILES_ANSWER: /* View Files Answer: <File info list> */
            offset = dissect_edonkey_file_info_list(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_SEARCH_FILE_RESULTS: /* Search File Results: <File Info list> <More> */
            offset = dissect_edonkey_file_info_list(tvb, pinfo, offset, tree);
            more = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 1, "More: %s (0x%02x)", (more) ? "TRUE" : "FALSE", more);
            break;

        case EDONKEY_MSG_SEARCH_FILES: /* Search File: <Search query> */
        case EDONKEY_MSG_SEARCH_USER:  /* Search User: <Search query> */
            offset = dissect_edonkey_search_query(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_GET_SOURCES:         /* Get Sources: <File Hash> <Size> <Size 64> */
        case EDONKEY_MSG_GET_SOURCES_OBFU:    /* Get Sources: <File Hash> <Size> <Size 64> */
            {
                guint32 fileSize;
                offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
                fileSize = tvb_get_letohl(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 4, "File size: %u %s", fileSize, (fileSize == 0) ? "(64bit file size used)" : "");
                offset += 4;
                /* if fileSize = 0 then 64bit file size comes next */
                if (fileSize == 0) {
                    guint64 fileSize64 = tvb_get_letoh64(tvb, offset);
                    proto_tree_add_text(tree, tvb, offset, 8, "Large file size : %" G_GINT64_MODIFIER "u", fileSize64);
                }
            }
            break;

        case EDONKEY_MSG_NO_SUCH_FILE:        /* No Such File: <File Hash> */
        case EDONKEY_MSG_END_OF_DOWNLOAD:     /* End of Download: <File Hash> */
        case EDONKEY_MSG_FILE_STATUS_REQUEST: /* File Status Request: <File Hash> */
        case EDONKEY_MSG_HASHSET_REQUEST:     /* Hashset Request: <File Hash> */
        case EDONKEY_MSG_SLOT_REQUEST:        /* Slot Request: <File Hash> */
        case EDONKEY_MSG_FILE_REQUEST:        /* File Request: <File Hash> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_FOUND_SOURCES_OBFU:   /* Found Sources: <File Hash> <SourceOBFU List> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_emule_sourceOBFU_list(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_FOUND_SOURCES: /* Found Sources: <File Hash> <Address List> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_address_list(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_CLIENT_CB_REQ:  /* Client Callback Request: <Client ID> */
        case EDONKEY_MSG_CALLBACK_FAIL:  /* Callback Fail:           <Client ID> */
        case EDONKEY_MSG_ID_CHANGE:      /* ID Change:               <Client ID> */
            offset = dissect_edonkey_client_id(tvb, pinfo, offset, tree, FALSE);
            break;

        case EDONKEY_MSG_NEW_CLIENT_ID:  /* New Client ID: <Client ID> <Client ID> */
            offset = dissect_edonkey_client_id(tvb, pinfo, offset, tree, FALSE);
            offset = dissect_edonkey_client_id(tvb, pinfo, offset, tree, FALSE);
            break;

        case EDONKEY_MSG_SERVER_MESSAGE: /* Server Message: <String> */
        case EDONKEY_MSG_CLIENT_MESSAGE: /* Client Message: <String> */
            offset = dissect_edonkey_string(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_SERVER_STATUS:  /* Server Status: <Nusers> <Nfiles> */
            nusers = tvb_get_letohl(tvb, offset);
            nfiles = tvb_get_letohl(tvb, offset+4);
            proto_tree_add_text(tree, tvb, offset, 4, "Number of Users: %u", nusers);
            proto_tree_add_text(tree, tvb, offset+4, 4, "Number of Files: %u", nfiles);
            break;

        case EDONKEY_MSG_FILE_STATUS: /* File Status: <File hash> <Part Count> <Part Status>? */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_file_status(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_FILE_REQUEST_ANSWER: /* File Request Answer: <File hash> <File name> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_file_name(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_REQUEST_PARTS:  /* Request Parts: <File hash> <Start offset>(3) <End offset>(3) */
            {
              int pairs, count;
              offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
              pairs = (msg_end - offset) / 8;

              for (count=0; count < pairs; count++)
              {
                offset = dissect_edonkey_start_offset(tvb, pinfo, offset, tree);
              }
              for (count=0; count < pairs; count++)
              {
                offset = dissect_edonkey_end_offset(tvb, pinfo, offset, tree);
              }
            }
            break;

        case EDONKEY_MSG_SENDING_PART:  /* Sending Part: <File hash> <Start offset> <End offset> DATA */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_start_offset(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_end_offset(tvb, pinfo, offset, tree);
            if (msg_end > offset) {
                bytes_remaining = msg_end - offset;
                proto_tree_add_text(tree, tvb, offset, bytes_remaining, "Message Data (%d bytes)", bytes_remaining);
            }
            break;


        case EDONKEY_MSG_SEARCH_USER_RESULTS: /* Search User Results: <Client info list> */
            offset = dissect_edonkey_client_info_list(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_GET_SHARED_FILES:    /* Get Shared Files: <Directory> */
            offset = dissect_edonkey_directory(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_SHARED_DIRS: /* Shared Dirs: <Directory List> */
            offset = dissect_edonkey_directory_list(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_SHARED_FILES: /* Shared Files: <Directory> <File info list> */
            offset = dissect_edonkey_directory(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_file_info_list(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_HASHSET_ANSWER:      /* Hashset Answer: <Hash List>  */
            offset = dissect_edonkey_hash_list(tvb, pinfo, offset, tree);
            break;

        default:
            proto_tree_add_text(tree, tvb, offset, length, "Message Data (%d bytes)", length);
            break;
    }

    if (offset < msg_end) {
        int extra_bytes = msg_end - offset;
        /* trailing garbage or broken packet */
        proto_tree_add_uint_format(tree, hf_edonkey_unparsed_data_length, tvb, offset, extra_bytes, extra_bytes,
                                   "Trailing/Undecoded data: %d bytes", extra_bytes );
    }
    return;
}

static void dissect_emule_tcp_message(guint8 msg_type,
                                      tvbuff_t *tvb, packet_info *pinfo _U_,
                                      int offset, int length, proto_tree *tree)
{
    int msg_end, bytes_remaining;
    guint32 packed_length;
    guint16 version, rank, partnum;

    if (tree == NULL) return;

    bytes_remaining = tvb_reported_length_remaining(tvb, offset);
    if ((length < 0) || (length > bytes_remaining)) length = bytes_remaining;
    if (length <= 0) return;

    msg_end = offset + length;

    switch (msg_type) {
        case EMULE_MSG_HELLO:  /* eMule Info: <eMule Version> <Meta tag list> */
        case EMULE_MSG_HELLO_ANSWER:  /* eMule Info Answer: <eMule Version> <Meta tag list> */
            version = tvb_get_letohs(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 2, "Version: %u", version);
            offset = dissect_edonkey_metatag_list(tvb, pinfo, offset+2, tree);
            break;

        case EMULE_MSG_QUEUE_RANKING: /* eMule Queue Ranking: <eMule Rank (guint16)> */
            rank = tvb_get_letohs(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 2, "Queue Ranking: %u", rank);
            break;

        case EMULE_MSG_SOURCES_REQUEST: /* Sources Request: <File Hash> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            break;

        case EMULE_MSG_SOURCES_ANSWER: /* Sources Answer: <File Hash> <Address List> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_emule_address_list(tvb, pinfo, offset, tree);
            break;

        case EMULE_MSG_SEC_IDENT_STATE: {
            guint32 rndchallenge;
            guint8 state = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 1, "State: %u (%s needed)", state, (state == 0) ? "nothing is" : (state == 1) ? "signature is" : "public key and signature are");
            offset++;
            rndchallenge = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 4, "Rndchallenge: %u", rndchallenge);
            offset += 4;
            break;
            }


        case EMULE_MSG_PUBLIC_KEY: /* Public Key: <1byte : len> <len bytes: pubkey> */
            offset = dissect_edonkey_public_key(tvb, pinfo, offset, tree);
            /* offset = dissect_emule_publickey(tvb, pinfo, offset, tree); */
            break;

        case EMULE_MSG_SIGNATURE:
            offset = dissect_edonkey_signature(tvb, pinfo, offset, tree);
            if (msg_end != offset) {
                guint8 sigIPused = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 1, "Sig IP Used: %u", sigIPused);
                offset++;
            }
            break;


        /* case EMULE_MSG_SIGNATURE: Public Key: <1byte : len> <len bytes: pubkey> */
            /* offset = dissect_emule_publickey(tvb, pinfo, offset, tree); */
            /* break; */

        /* case EMULE_MSG_SECIDENTSTATE: Public Key: <1byte : len> <len bytes: pubkey> */
            /* offset = dissect_emule_secstate(tvb, pinfo, offset, tree); */
            /* offset = dissect_emule_challenge(tvb, pinfo, offset, tree); */
            /* break; */

        case EMULE_MSG_DATA_COMPRESSED: /* Data Compressed: <File Hash> <Start Offset> <Length (guint32)> <DATA> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_start_offset(tvb, pinfo, offset, tree);
            packed_length = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 4, "Packed Length: %u", packed_length);
            offset += 4;
            if (msg_end > offset) {
                bytes_remaining = msg_end - offset;
                proto_tree_add_text(tree, tvb, offset, bytes_remaining,
                                    "Compressed Message Data (%d bytes)", bytes_remaining);
            }
            break;

        case EMULE_MSG_DATA_COMPRESSED_64: /* Data Compressed: <File Hash> <Start Offset (guint64)> <Length (guint32)> <DATA> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_start_offset_64(tvb, pinfo, offset, tree);
            packed_length = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 4, "Packed Length: %u", packed_length);
            offset += 4;
            if (msg_end > offset) {
                bytes_remaining = msg_end - offset;
                proto_tree_add_text(tree, tvb, offset, bytes_remaining,
                                    "Compressed Message Data (%d bytes)", bytes_remaining);
            }
            break;

        case EMULE_MSG_REQUEST_PARTS_64:  /* Request Parts: <File hash> <Start offset>(3) <End offset>(3) */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_start_offset_64(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_start_offset_64(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_start_offset_64(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_end_offset_64(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_end_offset_64(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_end_offset_64(tvb, pinfo, offset, tree);
            break;

        case EMULE_MSG_SENDING_PART_64:  /* Sending Part: <File hash> <Start offset> <End offset> DATA */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_start_offset_64(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_end_offset_64(tvb, pinfo, offset, tree);
            if (msg_end > offset) {
                bytes_remaining = msg_end - offset;
                proto_tree_add_text(tree, tvb, offset, bytes_remaining, "Message Data (%d bytes)", bytes_remaining);
            }
            break;

        case EMULE_MSG_CALLBACK:  /* Callback: < hash ><hash> <uint16> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            /* offset = dissect_edonkey_generic_uint16(tvb, pinfo, offset, tree, "uint16" ); */
            break;

        case EMULE_MSG_AICH_REQUEST: /* AICH Request: <File Hash> <PartNum> <AICH Hash> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            partnum = tvb_get_letohs(tvb, offset);
            proto_tree_add_uint(tree, hf_emule_aich_partnum, tvb, offset, 2, partnum);
            offset += 2;
            offset = dissect_emule_aich_root_hash(tvb, pinfo, offset, tree);
            break;

        case EMULE_MSG_AICH_ANSWER: /* AICH Answer: <File Hash> <PartNum> <AICH Hash> <AICH Hash List> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            partnum = tvb_get_letohs(tvb, offset);
            proto_tree_add_uint(tree, hf_emule_aich_partnum, tvb, offset, 2, partnum);
            offset += 2;
            offset = dissect_emule_aich_root_hash(tvb, pinfo, offset, tree);
            offset = dissect_emule_aich_hash_list(tvb, pinfo, offset, tree);
            break;

        case EMULE_MSG_MULTIPACKET: /* MultiPacket: <Hash> <Opcodes> */
        case EMULE_MSG_MULTIPACKET_ANSWER:
        case EMULE_MSG_MULTIPACKET_EXT: /* MultiPacketExt: <Hash> <FileLength> <Opcodes> */
            offset = dissect_emule_multipacket(tvb, pinfo, offset, offset+length, tree, msg_type==EMULE_MSG_MULTIPACKET_EXT);
            break;

        default:
            dissect_edonkey_tcp_message(msg_type, tvb, pinfo, offset, length, tree);
            break;
    }
    return;
}

static int dissect_edonkey_udp_message(guint8 msg_type,
                                        tvbuff_t *tvb, packet_info *pinfo _U_,
                                        int offset, int length, proto_tree *tree)
{
    int msg_end, bytes_remaining;
    guint8 type;
    guint16 min, max;
    guint16 ischal;
    guint32 chal;
    guint32 nusers, nfiles;

    if (tree == NULL) return offset;

    bytes_remaining = tvb_reported_length_remaining(tvb, offset);
    if ((length < 0) || (length > bytes_remaining)) length = bytes_remaining;
    if (length <= 0) return offset;

    msg_end = offset + length;

    switch (msg_type) {
        /* EDonkey UDP Messages */
        case EDONKEY_MSG_UDP_CALLBACK_REQUEST: /* Callback Request: <Address> <Client ID> */
            offset = dissect_edonkey_address(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_client_id(tvb, pinfo, offset, tree, FALSE);
            break;

        case EDONKEY_MSG_UDP_CALLBACK_FAIL: /* Callback Fail: <Client ID> */
            offset = dissect_edonkey_client_id(tvb, pinfo, offset, tree, FALSE);
            break;

        case EDONKEY_MSG_UDP_GET_SERVER_INFO: /* Get Server Info: <Challenge> */
            if (length>=2) {
                ischal = tvb_get_letohs(tvb, offset);
                if (ischal==0xf0ff) {
                    chal = tvb_get_letohl(tvb, offset);
                    proto_tree_add_text(tree, tvb, offset, 4, "Challenge: 0x%08x", chal);
                    offset += 4;
                } else {
                    offset = dissect_edonkey_string(tvb, pinfo, offset, tree);
                }
            }
            break;

        case EDONKEY_MSG_UDP_SERVER_INFO: /* Server Info: <String> <String>*/
            ischal = tvb_get_letohs(tvb, offset);
            if (ischal==0xf0ff) {
                chal = tvb_get_letohl(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 4, "Challenge: 0x%08x", chal);
                offset = dissect_edonkey_metatag_list(tvb, pinfo, offset+4, tree);
            } else {
                offset = dissect_edonkey_string(tvb, pinfo, offset, tree);
                offset = dissect_edonkey_string(tvb, pinfo, offset, tree);
            }
            break;

        case EDONKEY_MSG_UDP_SERVER_LIST: /* Server List: <Address List> */
            offset = dissect_edonkey_address_list(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_UDP_SEARCH_FILE_RESULTS: /* Search File Result: <File Info> */
            offset = dissect_edonkey_file_info(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_UDP_SEARCH_FILE: /* Search File: <Search query> */
            offset = dissect_edonkey_search_query(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_UDP_GET_SOURCES:     /* Get Sources: <File Hash> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_UDP_FOUND_SOURCES: /* Found Sources: <File Hash> <Address List> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_address_list(tvb, pinfo, offset, tree);
            break;

        case EDONKEY_MSG_UDP_SERVER_STATUS_REQUEST:  /* Server Status Request: <guint32> */
            chal = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 4, "Challenge: 0x%08x", chal);
            offset += 4;
            break;

        case EDONKEY_MSG_UDP_SERVER_STATUS:  /* Server Status: <guint32> <Nusers> <Nfiles> <Nusersmax> */
            chal = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 4, "Challenge: 0x%08x", chal);
            offset += 4;
            nusers = tvb_get_letohl(tvb, offset);
            nfiles = tvb_get_letohl(tvb, offset+4);
            proto_tree_add_text(tree, tvb, offset, 4, "Number of Users: %u", nusers);
            proto_tree_add_text(tree, tvb, offset+4, 4, "Number of Files: %u", nfiles);
            offset += 8;
            if (offset < msg_end) {
                nusers = tvb_get_letohl(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 4, "Max number of Users: %u", nusers);
                offset += 4;
            }
            break;

            /* Overnet UDP Messages */
        case OVERNET_MSG_UDP_CONNECT:    /* Connect:   <Peer (sender) > */
        case OVERNET_MSG_UDP_PUBLICIZE:  /* Publicize: <Peer (sender) > */
            offset = dissect_overnet_peer(tvb, pinfo, offset, tree);
            break;

        case OVERNET_MSG_UDP_CONNECT_REPLY:    /* Connect Reply: <guint16 Peer List> */
            offset = dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "Overnet Peer", dissect_overnet_peer);
            break;

        case OVERNET_MSG_UDP_SEARCH:    /* Search: <search type (guint8)> <Hash> */
            type = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 1, "Search Type: %u", type);
            offset = dissect_edonkey_hash(tvb, pinfo, offset+1, tree);
            break;

        case OVERNET_MSG_UDP_SEARCH_INFO:
            /* Search Info: <Hash> <search type (guint8)> <min (guint16)> <max (guint16)>*/
            offset = dissect_edonkey_hash(tvb, pinfo, offset, tree);
            type = tvb_get_guint8(tvb, offset);
            min = tvb_get_letohs(tvb, offset+1);
            max = tvb_get_letohs(tvb, offset+3);
            proto_tree_add_text(tree, tvb, offset, 1, "Search Type: %u", type);
            proto_tree_add_text(tree, tvb, offset+1, 4, "Search Range: Min=%u Max=%u", min, max);
            break;

        case OVERNET_MSG_UDP_SEARCH_NEXT:    /* Search Next: <Hash> <guint8 Peer List> */
            offset = dissect_edonkey_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_list(tvb, pinfo, offset, tree, 1, "Overnet Peer", dissect_overnet_peer);
            break;

        case OVERNET_MSG_UDP_SEARCH_RESULT:  /* Search Result: <Hash> <Hash> <Meta tag List> */
        case OVERNET_MSG_UDP_PUBLISH:        /* Publish: <Hash> <Hash> <Meta tag List> */
            offset = dissect_edonkey_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_metatag_list(tvb, pinfo, offset, tree);
            break;

        case OVERNET_MSG_UDP_SEARCH_END:  /* Search End: <Hash> */
            offset = dissect_edonkey_hash(tvb, pinfo, offset, tree);
            break;

        case OVERNET_MSG_UDP_PUBLISH_ACK:  /* Publish ACK: <File Hash> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            break;

        case OVERNET_MSG_UDP_IP_QUERY:  /* IP Query: <TCP Port> */
            proto_tree_add_item(tree, hf_edonkey_port, tvb, offset, 2, TRUE);
            break;

        case OVERNET_MSG_UDP_IP_QUERY_ANSWER:  /* IP Query Answer: <IP> */
            offset = dissect_edonkey_client_id(tvb, pinfo, offset, tree, FALSE);
            break;

        case OVERNET_MSG_UDP_IDENTIFY_REPLY:  /* Identify Reply: <Contact (sender)> */
            /* <Contact> ::= <Hash> <Address> */
            offset = dissect_edonkey_hash(tvb, pinfo, offset, tree);
            offset = dissect_edonkey_address(tvb, pinfo, offset, tree);
            break;

        case OVERNET_MSG_UDP_IDENTIFY_ACK:  /* Identify Reply: <TCP Port (sender)> */
            proto_tree_add_item(tree, hf_edonkey_port, tvb, offset, 2, TRUE);
            break;

        case OVERNET_MSG_UDP_FIREWALL_CONNECTION:      /* Firewall Connnection  Ack: <Hash> <TCP Port> */
            offset = dissect_edonkey_client_hash(tvb, pinfo, offset, tree);
            proto_tree_add_item(tree, hf_edonkey_port, tvb, offset, 2, TRUE);
            break;

        case OVERNET_MSG_UDP_FIREWALL_CONNECTION_ACK:  /* Firewall Connnection  Ack: <Hash> */
        case OVERNET_MSG_UDP_FIREWALL_CONNECTION_NACK: /* Firewall Connnection NAck: <Hash> */
            offset = dissect_edonkey_client_hash(tvb, pinfo, offset, tree);
            break;

        default:
            proto_tree_add_text(tree, tvb, offset, length, "Message Data (%d bytes)", length);
            offset+=length;
            break;
    }

    return offset;
}

static int dissect_emule_udp_message(guint8 msg_type,
                                      tvbuff_t *tvb, packet_info *pinfo _U_,
                                      int offset, int length, proto_tree *tree)
{
    int msg_end, bytes_remaining;
    guint16 rank;

    bytes_remaining = tvb_reported_length_remaining(tvb, offset);
    if ((length < 0) || (length > bytes_remaining)) length = bytes_remaining;
    if (length <= 0) return offset;

    msg_end = offset + length;

    switch (msg_type) {
        case EMULE_MSG_UDP_REASKFILEPING:     /* Reask File Ping: <File Hash> */
            offset = dissect_edonkey_file_hash(tvb, pinfo, offset, tree);
            if ( offset + 2 < msg_end ) {
                /* Udp version > 3 */
                offset = dissect_edonkey_file_status( tvb, pinfo, offset, tree );
            }

            if ( msg_end == offset + 2 ) {
                /* Udp version > 2 */
                proto_tree_add_item( tree, hf_emule_source_count, tvb, offset, 2, TRUE );
                offset += 2;
            }
            break;

        case EMULE_MSG_UDP_REASKACK:          /* Reask ACK:     <eMule Rank>  */
            if ( offset + 2 < msg_end ) {
                /* Udp version > 3 */
                offset = dissect_edonkey_file_status( tvb, pinfo, offset, tree );
            }

            rank = tvb_get_letohs(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 2, "Queue Ranking: %u", rank);
            offset += 2;
            break;

        default:
            offset = dissect_edonkey_udp_message(msg_type, tvb, pinfo, offset, length,tree);
            break;
    }
    return offset;
}

static int dissect_kademlia_peer_list_2byte(tvbuff_t *tvb, packet_info *pinfo _U_,
                                      int offset, proto_tree *tree)
{
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "Peer", dissect_kademlia_peer );
}


static int dissect_kademlia_peer_list_1byte(tvbuff_t *tvb, packet_info *pinfo _U_,
                                      int offset, proto_tree *tree)
{
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 1, "Peer", dissect_kademlia_peer );
}

static int dissect_kademlia2_peer_list_2byte(tvbuff_t *tvb, packet_info *pinfo _U_,
                                      int offset, proto_tree *tree)
{
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "Peer", dissect_kademlia2_peer );
}

static int dissect_kademlia2_peer_list_1byte(tvbuff_t *tvb, packet_info *pinfo _U_,
                                      int offset, proto_tree *tree)
{
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 1, "Peer", dissect_kademlia2_peer );
}

static int dissect_kademlia_tag(tvbuff_t *tvb, packet_info *pinfo _U_,
                                int offset, proto_tree *tree)
{
    guint8 type;
    guint8 tag_type;
    const gchar *str_type;
    proto_item *ti;
    proto_item* tag_node;
    proto_tree *subtree;
    int item_start_offset;

    item_start_offset = offset;
    /* tag_node length is adjusted at the end of this function */
    tag_node = proto_tree_add_text( tree, tvb, offset, 1, "Tag " );
    subtree = proto_item_add_subtree( tag_node, ett_kademlia_tag );

    type = tvb_get_guint8( tvb, offset );
    str_type = val_to_str(type, kademlia_tag_types, "Unknown" );

    {
        proto_item * ti_tagtype;
        ti_tagtype = proto_tree_add_item( subtree, hf_kademlia_tag_type, tvb, offset, 1, TRUE );
        proto_item_append_text( ti_tagtype, " [%s]", str_type );
    }

    offset += 1;

    {
        const gchar *tagname_string;
        const gchar *tagname_extended_string;

        /* Read tagname */
        tag_type = tvb_get_guint8( tvb, offset+2 );
        offset = dissect_kademlia_tagname( tvb, pinfo, offset, subtree, &tagname_string, &tagname_extended_string );
        if ( strlen( tagname_string ) == 1 ) {
            const guint8 tagname_guint = *(guint8*)tagname_string;

            proto_item_append_text( tag_node, " 0x%02X [%s] = ", tagname_guint, tagname_extended_string );
        }
        else
            proto_item_append_text( tag_node, " \"%s\" [%s] = ", tagname_string, tagname_extended_string );
    }

    /* Switch on type */
    switch( type )
    {
        case KADEMLIA_TAGTYPE_HASH:
            proto_item_append_text( tag_node, "%s", tvb_bytes_to_str( tvb, offset, 16 ));
            offset = dissect_kademlia_tag_hash( tvb, pinfo, offset, subtree );
            break;
        case KADEMLIA_TAGTYPE_STRING:
            {
                const gchar* value;
                offset = dissect_kademlia_tag_string( tvb, pinfo, offset, subtree, &value );

                proto_item_append_text( tag_node, "\"%s\"", value );
            }
            break;
        case KADEMLIA_TAGTYPE_UINT8:
            {
                guint8 value;
                ti = proto_tree_add_item( subtree, hf_kademlia_tag_uint8, tvb, offset, 1, TRUE);

                value = tvb_get_guint8( tvb, offset );
                proto_item_append_text( tag_node, "%u (0x%02X)", value, value );
                switch (tag_type) {
                    case KADEMLIA_TAG_SOURCETYPE:
                        {
                            proto_item_append_text(ti," (%s)", val_to_str(value, kademlia_tag_sourcetype, "Unknown"));
                        }
                        break;
                    case KADEMLIA_TAG_ENCRYPTION:
                        proto_item_append_text(ti, " (%s)", val_to_str(value, kademlia_tag_encryption, "Unknown"));
                        break;
                }
                offset += 1;
            }
            break;
        case KADEMLIA_TAGTYPE_UINT16:
            {
                guint16 value;
                proto_tree_add_item( subtree, hf_kademlia_tag_uint16, tvb, offset, 2, TRUE);

                value = tvb_get_letohs( tvb, offset );
                proto_item_append_text( tag_node, "%u (0x%04X)", value, value );

                offset += 2;
            }
            break;
        case KADEMLIA_TAGTYPE_UINT64:
            {
                guint64 value;
                proto_tree_add_item( subtree, hf_kademlia_tag_uint64, tvb, offset, 8, TRUE);

                value = tvb_get_letoh64( tvb, offset );
                proto_item_append_text( tag_node, "%" G_GINT64_MODIFIER "u (0x%08" G_GINT64_MODIFIER "X)", value, value );

                offset += 8;
            }
            break;
        case KADEMLIA_TAGTYPE_UINT32:
           {
                guint32 value;
                /* show ip as dotted decimal */
                switch( tag_type) {
                    case KADEMLIA_TAG_SERVERIP:
                    case KADEMLIA_TAG_SOURCEIP:
                    {
                        int ipa = 0, ipb = 0, ipc = 0, ipd = 0;
                        proto_tree_add_item( subtree, hf_kademlia_tag_ipv4, tvb, offset, 4, TRUE);
                        value = tvb_get_letohl( tvb, offset );
                        ipa = (value / (256*256*256)) % 256;
                        ipb = (value / (256*256)) % 256;
                        ipc = (value / 256) % 256;
                        ipd = value % 256;
                        proto_item_append_text( tag_node, "%u.%u.%u.%u (0x%02X) ", ipa, ipb, ipc, ipd, value );
                    }
                    break;
                    default:
                        proto_tree_add_item( subtree, hf_kademlia_tag_uint32, tvb, offset, 4, TRUE);
                        value = tvb_get_letohl( tvb, offset );
                        proto_item_append_text( tag_node, "%u (0x%02X) ", value, value );
                }

                offset += 4;
            }
            break;
        case KADEMLIA_TAGTYPE_FLOAT32:
            {
                float value;
                proto_tree_add_item( subtree, hf_kademlia_tag_float, tvb, offset, 4, TRUE);

                value = tvb_get_letohieee_float( tvb, offset );
                proto_item_append_text( tag_node, "%f", value );

                offset += 4;
            }
            break;
        case KADEMLIA_TAGTYPE_BSOB:
            {
                const gchar* value;
                offset = dissect_kademlia_tag_bsob( tvb, pinfo, offset, subtree, &value );
                proto_item_append_text( tag_node, "%s", value );
            }
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 1, "Tag value not decoded for type: 0x%02X", type );
    }

    proto_item_append_text( tag_node, " (Type: %s)", str_type );

    proto_item_set_len( tag_node, offset - item_start_offset );

    return offset;
}

static int dissect_kademlia_taglist(tvbuff_t *tvb, packet_info *pinfo _U_,
                                int offset, proto_tree *tree)
{
    return dissect_edonkey_list(tvb, pinfo, offset, tree, 1, "Tag", dissect_kademlia_tag );
}


static int dissect_kademlia_publish_req_entry_file(tvbuff_t *tvb, packet_info *pinfo _U_,
                                          int offset, proto_tree *tree)
{
    /* Get the hash */
    offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_file_id);
    /* Read all the kad tags */
    return dissect_kademlia_taglist( tvb, pinfo, offset, tree );
}

static int dissect_kademlia_publish_req_entry_peer(tvbuff_t *tvb, packet_info *pinfo _U_,
                                          int offset, proto_tree *tree)
{
    /* Get the hash */
    offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_peer_id);
    /* Read all the kad tags */
    return dissect_kademlia_taglist( tvb, pinfo, offset, tree );
}


static int dissect_kademlia_search_result(tvbuff_t *tvb, packet_info *pinfo _U_,
                                          int offset, proto_tree *tree)
{
    /* Get the hash */
    offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_hash);
    /* Read all the kad tags */
    return dissect_kademlia_taglist( tvb, pinfo, offset, tree );
}

static int dissect_kademlia_search_expression_tree(tvbuff_t *tvb, packet_info *pinfo _U_,
                                          int offset, proto_tree *tree)
{
    int op, item_start_offset;
    proto_item* ti;

    item_start_offset = offset;
    op = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_text(tree, tvb, offset, 1, "SearchExp type: %x ", op);
    ++offset;
    tree = proto_item_add_subtree( ti, ett_kademlia_search_expression );
    switch( op ) {
        case 0: /* Bool op */
            {
                int boolop;
                const char* bool_op_label;

                proto_item_append_text( ti, "[BoolOp]" );

                boolop = tvb_get_guint8(tvb, offset);

                switch( boolop ) {
                    case 0: /* AND */
                        bool_op_label = "AND";
                        break;
                    case 1: /* OR */
                        bool_op_label = "OR";
                        break;
                    case 2: /* NAND */
                        bool_op_label = "NAND";
                        break;
                    default:
                        bool_op_label = "Unknown";
                };
                proto_tree_add_text(tree, tvb, offset, 1, "Bool op: %x [%s]", boolop, bool_op_label );
                ++offset;

                /* Left */
                offset = dissect_kademlia_search_expression_tree( tvb, pinfo, offset, tree );
                /* Right */
                offset = dissect_kademlia_search_expression_tree( tvb, pinfo, offset, tree );

                break;
            }

        case 1: /* String */
            proto_item_append_text( ti, "[String]" );
            offset = dissect_kademlia_string( tvb, pinfo, offset, tree );
            break;
        case 2: /* Meta Tag */
            proto_item_append_text( ti, "[MetaTag]" );
            /* tag value */
            offset = dissect_edonkey_string( tvb, pinfo, offset, tree );
            /* tag name */
            offset = dissect_kademlia_tagname( tvb, pinfo, offset, tree, NULL, NULL );
            break;
        case 3: /* Min/Max - 32bit! */
            proto_item_append_text( ti, "[32bitOp]" );
            offset = dissect_kademlia_search_condition_argument_uint32( tvb, pinfo, offset, tree );
            offset = dissect_kademlia_search_condition( tvb, pinfo, offset, tree );
            /* tag name */
            offset = dissect_kademlia_tagname( tvb, pinfo, offset, tree, NULL, NULL );
            break;
        case 8: /* Min/Max - 64bit! */
            proto_item_append_text( ti, "[64bitOp]" );
            offset = dissect_kademlia_search_condition_argument_uint64( tvb, pinfo, offset, tree );
            offset = dissect_kademlia_search_condition( tvb, pinfo, offset, tree );
            /* tag name */
            offset = dissect_kademlia_tagname( tvb, pinfo, offset, tree, NULL, NULL );
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 1, "NOT DECODED op %x", op );
    }
    proto_item_set_len( ti, offset - item_start_offset );
    return offset;
}

static int dissect_kademlia2_prolog( tvbuff_t *tvb, packet_info *pinfo _U_,
                                         int offset, proto_tree *tree)
{
    int kad_version;
    proto_item* ti;

    offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_peer_id);
    offset = dissect_kademlia_tcp_port(tvb, pinfo, offset, tree);

    kad_version = tvb_get_guint8(tvb, offset);
    /* ti = proto_tree_add_text(tree, tvb, offset, 1, "Kad Version: %d", kad_version ); */
    ti = proto_tree_add_item(tree, hf_kademlia_version, tvb, offset, 1, FALSE);
    proto_item_append_text(ti, "%s", val_to_str(kad_version, kademlia_versions, " Unknown"));
    offset++;

    return offset;
}

static int dissect_kademlia_uload( tvbuff_t *tvb, packet_info *pinfo _U_,
                                         int offset, proto_tree *tree)
{
    int uLoad;
    uLoad = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "uLoad: %d", uLoad );
    return offset +1;

}
static int dissect_kademlia_udp_message(guint8 msg_type,
                                         tvbuff_t *tvb, packet_info *pinfo _U_,
                                         int offset, int length, proto_tree *tree)
{
    int msg_end, bytes_remaining;
    proto_item *hidden_item;

    bytes_remaining = tvb_reported_length_remaining(tvb, offset);
    if ((length < 0) || (length > bytes_remaining)) length = bytes_remaining;
    if (length <= 0) return offset;

    hidden_item = proto_tree_add_item(tree, hf_kademlia, tvb, offset, 1, FALSE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    msg_end = offset + length;

    switch (msg_type) {
        case KADEMLIA_BOOTSTRAP_REQ:/* <PEER [25]> */
        case KADEMLIA_HELLO_REQ:
        case KADEMLIA_HELLO_RES:
            offset = dissect_kademlia_peer(tvb, pinfo, offset, tree);
            break;
        case KADEMLIA2_BOOTSTRAP_REQ:
            offset = dissect_kademlia2_prolog( tvb, pinfo, offset, tree );
            break;

        case KADEMLIA2_HELLO_REQ:
        case KADEMLIA2_HELLO_RES:
            offset = dissect_kademlia2_prolog( tvb, pinfo, offset, tree );
            offset = dissect_kademlia_taglist( tvb, pinfo, offset, tree );
            break;
        case KADEMLIA_BOOTSTRAP_RES:  /* <CNT [2]> <PEER [25]>*(CNT) */
            offset = dissect_kademlia_peer_list_2byte( tvb, pinfo, offset, tree );
            break;
        case KADEMLIA2_BOOTSTRAP_RES:
            offset = dissect_kademlia2_prolog( tvb, pinfo, offset, tree );
            offset = dissect_kademlia2_peer_list_2byte( tvb, pinfo, offset, tree );
            break;

        case KADEMLIA2_SEARCH_SOURCE_REQ:
            {
                guint16 startPos;
                guint64 filesize;
                offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);
                /* start pos */
                startPos = tvb_get_letohs( tvb, offset );
                proto_tree_add_text(tree, tvb, offset, 2, "Start position: %d", startPos );
                offset +=2;
                /* filesize */
                filesize = tvb_get_letoh64( tvb, offset );
                proto_tree_add_text(tree, tvb, offset, 8, "Filesize: %" G_GINT64_MODIFIER "u", filesize );
                offset +=8;
            }
            break;

        case KADEMLIA_SEARCH_NOTES_REQ: /* <HASH (key) [16]> */
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_hash);
            break;

        case KADEMLIA2_SEARCH_KEY_REQ:
            {
              guint16 startPos;
              offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);
              /* start pos */
              startPos = tvb_get_letohs( tvb, offset );
              proto_tree_add_text(tree, tvb, offset, 2, "Start position: %d", startPos );
              offset += 2;
            }
            break;
        case KADEMLIA2_SEARCH_NOTES_REQ:

        case KADEMLIA_PUBLISH_RES:
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);
            if (offset<msg_end) {
                offset = dissect_kademlia_uload( tvb, pinfo, offset, tree );
            }
            break;
        case KADEMLIA2_PUBLISH_RES:
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);
            offset = dissect_kademlia_uload( tvb, pinfo, offset, tree );
            break;

        case KADEMLIA_REQ: /* <TYPE [1]> <HASH (target) [16]> <HASH (receiver) 16> */
        case KADEMLIA2_REQ:
            {
                int type;
                guint8 target_id[16];
                guint8 recipients_id[16];
                proto_item *ti;
                int i, j, k, l;
                char binarray[129];

                type = tvb_get_guint8(tvb, offset);
                ti = proto_tree_add_uint_format_value(tree, hf_kademlia_request_type, tvb, offset, 1, type, "0x%02x", type );
                proto_item_append_text(ti, "%s", val_to_str(type, kademlia_parameter, " Unknown"));
                offset +=1;

                /* get target id */
                for (i=0; i<4; i++) {
                  for (j=3; j>=0; j--) {
                    l = (j+4*i);
                    target_id[l] = tvb_get_guint8(tvb, offset + abs(8*i-(l-3)));
                  }
                }

                offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);

                /* get recipient's id */
                for (i=0; i<4; i++) {
                  for (j=3; j>=0; j--) {
                    l = (j+4*i);
                    recipients_id[l] = tvb_get_guint8(tvb, offset + abs(8*i-(l-3)));
                  }
                }

                offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_recipients_id);

                /* target_id XOR recipients_id */
                for (i=0; i<16; i++) {
                  k = 128;
                  l = target_id[i]^recipients_id[i];
                  for(j=8*i; j<8*i+8; j++) {
                    if (l >= k) {
                      binarray[j] = '1';
                      l = l-k;
                    }
                    else
                      binarray[j] = '0';
                    k = k/2;
                  }
                }
                binarray[128] = '\0';
                proto_tree_add_string_format_value(tree, hf_kademlia_distance, tvb, offset, 0, binarray, "%s", binarray);
            }
            break;

        case KADEMLIA_RES:     /* <HASH (target) [16]> <CNT> <PEER [25]>*(CNT) */
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);
            offset = dissect_kademlia_peer_list_1byte( tvb, pinfo, offset, tree );
            break;
        case KADEMLIA2_RES:
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);
            offset = dissect_kademlia2_peer_list_1byte( tvb, pinfo, offset, tree );
            break;

        case KADEMLIA_FIREWALLED_RES: /* <IP (sender) [4]> */
            offset = dissect_kademlia_ip_address( tvb, pinfo, offset, tree );
            break;

        case KADEMLIA_FIREWALLED_REQ: /* <TCPPORT (sender) [2]> */
            offset = dissect_kademlia_tcp_port( tvb, pinfo, offset, tree );
            break;
        case KADEMLIA_CALLBACK_REQ:
        case KADEMLIA_FINDBUDDY_REQ:
        case KADEMLIA_FINDBUDDY_RES:
            /* buddy id */
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_hash);
            /* userid */
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_hash);
            offset = dissect_kademlia_tcp_port( tvb, pinfo, offset, tree );
            break;
        case KADEMLIA2_PUBLISH_SOURCE_REQ:
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_file_id);
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_peer_id);
            offset = dissect_kademlia_taglist( tvb, pinfo, offset, tree );
            break;
        case KADEMLIA_SEARCH_REQ:
            {
                int restrictive;
                /* Target (16bytes) */
                offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);
                /* Restrictive (1 byte) 0/1 */
                restrictive = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 1, "Restrictive: %x", restrictive );
                offset +=1;

                if ( offset < msg_end && restrictive )
                    offset = dissect_kademlia_search_expression_tree( tvb, pinfo, offset, tree );
            }
            break;
        case KADEMLIA_SEARCH_RES:
            /* Target */
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);
            /* Results list */
            offset = dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "Result", dissect_kademlia_search_result );
            break;
        case KADEMLIA2_SEARCH_RES:
            /* Sender */
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_sender_id);
            /* Target */
            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_target_id);
            /* Results list */
            offset = dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "Result", dissect_kademlia_search_result );
            break;
        case KADEMLIA2_PUBLISH_KEY_REQ:
            {
                /* Keyword Hash */
                offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_keyword_hash);
                /* Results list */
                offset = dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "StuffToPublish", dissect_kademlia_publish_req_entry_file );
                break;
            }
        case KADEMLIA_PUBLISH_REQ: /*   0x40    // <HASH (key) [16]> <CNT1 [2]> (<HASH (target) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1) */
            {
                guint8 tagname_value=0, taglist_size, type;
                int i=1, j=34;

                /* check if TAG_SOURCETYPE is set */
                taglist_size = tvb_get_guint8(tvb, offset + j);
                j++;

                while(i <= taglist_size) {
                  type = tvb_get_guint8(tvb, offset + j);
                  j +=3;
                  tagname_value = tvb_get_guint8(tvb, offset + j);
                  if (tagname_value == 0xff)
                    i = taglist_size;
                  j++;
                  switch(type) {
                    case KADEMLIA_TAGTYPE_HASH:
                        j += 16;
                        break;
                    case KADEMLIA_TAGTYPE_STRING:
                    {
                        guint16 string_length = tvb_get_letohs(tvb, offset+j);
                        j += 2 + string_length;
                        break;
                    }
                    case KADEMLIA_TAGTYPE_UINT8:
                        j += 1;
                        break;
                    case KADEMLIA_TAGTYPE_UINT16:
                        j += 2;
                        break;
                    case KADEMLIA_TAGTYPE_UINT32:
                    case KADEMLIA_TAGTYPE_FLOAT32:
                        j += 4;
                        break;
                    case KADEMLIA_TAGTYPE_UINT64:
                        j += 8;
                        break;
                    case KADEMLIA_TAGTYPE_BSOB:
                    {
                      guint16 bsob_length = tvb_get_guint8(tvb, offset);
                      j += 1 + bsob_length;
                      break;
                    }
                  }
                  i++;
                }

                switch (tagname_value) {
                    case KADEMLIA_TAG_SOURCETYPE:
                        {
                            /* Target */
                            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_file_id);
                            /* Results list */
                            offset = dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "StuffToPublish", dissect_kademlia_publish_req_entry_peer);
                        }
                        break;
                    default:
                        {
                            /* Target */
                            offset = dissect_kademlia_hash(tvb, pinfo, offset, tree, &hf_kademlia_keyword_hash);
                            /* Results list */
                            offset = dissect_edonkey_list(tvb, pinfo, offset, tree, 2, "StuffToPublish", dissect_kademlia_publish_req_entry_file);
                        }
                }
            }
    }

    return offset;
}

static int dissect_kademlia_udp_compressed_message(guint8 msg_type,
                                                    tvbuff_t *tvb, packet_info *pinfo _U_,
                                                    int offset, int length, proto_tree *tree)
{
    tvbuff_t *tvbraw = NULL;


    tvbraw = tvb_child_uncompress(tvb, tvb, offset, length);

    if (tvbraw) {
        guint32 raw_length;

        raw_length = tvb_length( tvbraw );
        add_new_data_source(pinfo, tvbraw, "Decompressed Data");

        dissect_kademlia_udp_message( msg_type, tvbraw, pinfo, 0, raw_length, tree );
        offset += length;
    } else {
        proto_tree_add_text( tree, tvb, offset, length, "Broken Compressed data (%d bytes)", length);
    }
    return offset;
}


static guint get_edonkey_tcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    guint32 msg_len;

    /*
     * Get the length of the eDonkey packet.
     */
    msg_len = tvb_get_letohl(tvb, offset+1);

    /*
     * That length doesn't include the header; add that in.
     * XXX - what if it overflows?
     */
    return msg_len + EDONKEY_TCP_HEADER_LENGTH;
}

static void dissect_edonkey_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *edonkey_tree = NULL, *edonkey_msg_tree = NULL, *emule_zlib_tree = NULL;
    int offset, bytes;
    guint8 protocol, msg_type;
    guint32 msg_len;
    const gchar *protocol_name, *message_name;
    void  (*dissector)(guint8, tvbuff_t*, packet_info*, int, int, proto_tree*);
    tvbuff_t *tvbraw = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "eDonkey");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_edonkey, tvb, 0, -1, FALSE);
        edonkey_tree = proto_item_add_subtree(ti, ett_edonkey);
    }

    offset = 0;
    protocol = tvb_get_guint8(tvb, offset);
    msg_len = tvb_get_letohl(tvb, offset+1);

    protocol_name = match_strval(protocol, edonkey_protocols);
    if (protocol_name == NULL) {
        /* Not a recognized eDonkey protocol - probably a continuation */
        col_set_str(pinfo->cinfo, COL_INFO, "eDonkey Continuation");
        if (edonkey_tree) {
            bytes = tvb_length_remaining(tvb, offset);
            proto_tree_add_text(edonkey_tree, tvb, 0, -1, "Continuation data (%d bytes)", bytes);
        }
        return;
    }

    /* Add edonkey message tree */
    if (edonkey_tree) {
        ti = proto_tree_add_item(edonkey_tree, hf_edonkey_message, tvb,
                                 offset, EDONKEY_TCP_HEADER_LENGTH + msg_len, FALSE);
        edonkey_msg_tree = proto_item_add_subtree(ti, ett_edonkey_message);

        proto_tree_add_uint_format(edonkey_msg_tree, hf_edonkey_protocol, tvb, offset, 1, protocol,
                                   "Protocol: %s (0x%02x)", protocol_name, protocol);
        proto_tree_add_uint(edonkey_msg_tree, hf_edonkey_message_length, tvb, offset+1, 4, msg_len);
    }


    /* Skip past the EDONKEY Header */
    offset += EDONKEY_TCP_HEADER_LENGTH;

    if(tvb_reported_length_remaining(tvb, offset) <= 0) {
        /* There is not enough space for the msg_type - mark as fragment */
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s TCP Message Fragment", protocol_name);
        }
        return;
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s TCP", protocol_name);
    }

    msg_type = tvb_get_guint8(tvb, offset);
    switch (protocol) {
        case EDONKEY_PROTO_EDONKEY:
            message_name =  val_to_str(msg_type, edonkey_tcp_msgs, "Unknown");
            dissector = dissect_edonkey_tcp_message;
            break;

        case EDONKEY_PROTO_EMULE_EXT:
            message_name = val_to_str(msg_type, emule_tcp_msgs,
                                      val_to_str(msg_type, edonkey_tcp_msgs, "Unknown"));
            dissector = dissect_emule_tcp_message;
            break;

        case EDONKEY_PROTO_EMULE_COMP:
            /*
             * These ought to be exactly the same as standard eDonkey (0xe5) messages,
             * except that the payload (after the type byte) is a zlib compressed
             * stream.
             */
            message_name = val_to_str(msg_type, edonkey_tcp_msgs, "Unknown");
            tvbraw = tvb_child_uncompress(tvb, tvb, offset+1, msg_len-1);
            if (tvbraw) {
              dissector = dissect_edonkey_tcp_message;
              break;
            }

        default:
            message_name = "Unknown";
            dissector = NULL;
            break;
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", message_name);
    }


    if (edonkey_msg_tree) {
        proto_tree_add_uint_format(edonkey_msg_tree, hf_edonkey_message_type, tvb, offset, 1, msg_type,
                                   "Message Type: %s (0x%02x)", message_name, msg_type);
        if (dissector && (msg_len > 1)) {
          if (!tvbraw) {
            (*dissector)(msg_type, tvb, pinfo, offset+1, msg_len-1, edonkey_msg_tree);
          } else {
            ti = proto_tree_add_item(edonkey_msg_tree, hf_emule_zlib, tvb,
                                     offset+1, msg_len-1, FALSE);
            emule_zlib_tree = proto_item_add_subtree(ti, ett_emule_zlib);
            add_new_data_source(pinfo, tvbraw, "Decompressed Data");
            (*dissector)(msg_type, tvbraw, pinfo, 0, tvb_length(tvbraw), emule_zlib_tree);
          }
        }
    }
}

static void dissect_edonkey_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_clear(pinfo->cinfo, COL_INFO);

    tcp_dissect_pdus(tvb, pinfo, tree, edonkey_desegment,
                     EDONKEY_TCP_HEADER_LENGTH, get_edonkey_tcp_pdu_len,
                     dissect_edonkey_tcp_pdu);
}

static void dissect_edonkey_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *edonkey_tree = NULL, *edonkey_msg_tree = NULL;
    int offset;
    guint8 protocol, msg_type;
    const gchar *protocol_name, *message_name;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "eDonkey");

    col_set_str(pinfo->cinfo, COL_INFO, "eDonkey UDP Message");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_edonkey, tvb, 0, -1, FALSE);
        edonkey_tree = proto_item_add_subtree(ti, ett_edonkey);
    }

    offset = 0;
    /* eDonkey UDP message - Assume that there is one message per packet */
    if (tvb_length_remaining(tvb, offset) >= EDONKEY_UDP_HEADER_LENGTH) {
        protocol = tvb_get_guint8(tvb, offset);
        msg_type = tvb_get_guint8(tvb, offset+1);
        protocol_name = val_to_str(protocol, edonkey_protocols, "Unknown");

        if (protocol == EDONKEY_PROTO_KADEMLIA || protocol == EDONKEY_PROTO_KADEMLIA_COMP
            || protocol == EDONKEY_PROTO_ADU_KADEMLIA || protocol == EDONKEY_PROTO_ADU_KADEMLIA_COMP)
            message_name = val_to_str( msg_type, kademlia_msgs, "Unknown");
        else
            message_name = val_to_str(msg_type, edonkey_udp_msgs, "Unknown");

        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s UDP: %s", protocol_name, message_name);
        }

        if (edonkey_tree) {
            int remainingLength, extraBytes;

            ti = proto_tree_add_item(edonkey_tree, hf_edonkey_message, tvb, offset, -1, FALSE);
            edonkey_msg_tree = proto_item_add_subtree(ti, ett_edonkey_message);

            proto_tree_add_uint_format(edonkey_msg_tree, hf_edonkey_protocol, tvb, offset, 1, protocol,
                                       "Protocol: %s (0x%02x)", protocol_name, protocol);
            proto_tree_add_uint_format(edonkey_msg_tree, hf_edonkey_message_type, tvb, offset+1, 1, msg_type,
                                       "Message Type: %s (0x%02x)", message_name, msg_type);

            offset += EDONKEY_UDP_HEADER_LENGTH;
            remainingLength = tvb_length_remaining( tvb, offset );

            switch (protocol) {
                case EDONKEY_PROTO_EDONKEY:
                    offset = dissect_edonkey_udp_message(msg_type, tvb, pinfo, offset, remainingLength, edonkey_msg_tree);
                    break;

                case EDONKEY_PROTO_EMULE_EXT:
                    offset = dissect_emule_udp_message(msg_type, tvb, pinfo, offset, remainingLength, edonkey_msg_tree);
                    break;

                case EDONKEY_PROTO_ADU_KADEMLIA:
                case EDONKEY_PROTO_KADEMLIA:
                    offset = dissect_kademlia_udp_message(msg_type, tvb, pinfo, offset, remainingLength, edonkey_msg_tree);
                    break;

                case EDONKEY_PROTO_ADU_KADEMLIA_COMP:
                case EDONKEY_PROTO_KADEMLIA_COMP:
                    offset = dissect_kademlia_udp_compressed_message(msg_type, tvb, pinfo, offset, remainingLength, edonkey_msg_tree);
                    break;

                default:
                    break;
            }

            extraBytes = tvb_length_remaining( tvb, offset );

            if ( extraBytes > 0 ) {
                /* trailing garbage or broken packet */
                proto_tree_add_uint_format(tree, hf_edonkey_unparsed_data_length, tvb, offset, extraBytes, extraBytes,
                                           "Trailing/Undecoded data: %d bytes", extraBytes );
            }
        }
    }
}

void proto_register_edonkey(void) {

    static hf_register_info hf[] = {
        { &hf_edonkey_message,
            { "eDonkey Message", "edonkey.message",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_edonkey_protocol,
            { "Protocol", "edonkey.protocol",
                FT_UINT8, BASE_HEX, VALS(edonkey_protocols), 0, "eDonkey Protocol", HFILL } },
        { &hf_edonkey_message_length,
            { "Message Length", "edonkey.message.length",
                FT_UINT32, BASE_DEC, NULL, 0, "eDonkey Message Length", HFILL } },
        { &hf_edonkey_message_type,
            { "Message Type", "edonkey.message.type",
                FT_UINT8, BASE_HEX, NULL, 0, "eDonkey Message Type", HFILL } },
        { &hf_edonkey_client_hash,
            { "Client Hash", "edonkey.client_hash",
                FT_BYTES, BASE_NONE, NULL, 0, "eDonkey Client Hash", HFILL } },
        { &hf_edonkey_server_hash,
            { "Server Hash", "edonkey.server_hash",
                FT_BYTES, BASE_NONE, NULL, 0, "eDonkey Server Hash", HFILL } },
        { &hf_edonkey_file_hash,
            { "File Hash", "edonkey.file_hash",
                FT_BYTES, BASE_NONE, NULL, 0, "eDonkey File Hash", HFILL } },
        { &hf_edonkey_client_id,
            { "Client ID", "edonkey.clientid",
                FT_IPv4, BASE_NONE, NULL, 0, "eDonkey Client ID", HFILL } },
        { &hf_edonkey_ip,
            { "IP", "edonkey.ip",
                FT_IPv4, BASE_NONE, NULL, 0, "eDonkey IP", HFILL } },
        { &hf_edonkey_port,
            { "Port", "edonkey.port",
                FT_UINT16, BASE_DEC, NULL, 0, "eDonkey Port", HFILL } },
        { &hf_edonkey_metatag,
            { "eDonkey Meta Tag", "edonkey.metatag",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_edonkey_metatag_type,
            { "Meta Tag Type", "edonkey.metatag.type",
                FT_UINT8, BASE_HEX, NULL, 0, "eDonkey Meta Tag Type", HFILL } },
        { &hf_edonkey_metatag_id,
            { "Meta Tag ID", "edonkey.metatag.id",
                FT_UINT8, BASE_HEX, NULL, 0, "eDonkey Meta Tag ID", HFILL } },
        { &hf_edonkey_metatag_name,
            { "Meta Tag Name", "edonkey.metatag.name",
                FT_STRING, BASE_NONE, NULL, 0, "eDonkey Meta Tag Name", HFILL } },
        { &hf_edonkey_metatag_namesize,
            { "Meta Tag Name Size", "edonkey.metatag.namesize",
                FT_UINT16, BASE_DEC, NULL, 0, "eDonkey Meta Tag Name Size", HFILL } },
        { &hf_edonkey_search,
            { "eDonkey Search", "edonkey.search",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_edonkey_hash,
            { "Hash", "edonkey.hash",
                FT_BYTES, BASE_NONE, NULL, 0, "eDonkey Hash", HFILL } },
        { &hf_edonkey_string,
            { "String", "edonkey.string",
                FT_STRING, BASE_NONE, NULL, 0, "eDonkey String", HFILL } },
        { &hf_edonkey_string_length,
            { "String Length", "edonkey.string_length",
                FT_UINT16, BASE_DEC, NULL, 0, "eDonkey String Length", HFILL } },
        { &hf_edonkey_part_count,
            { "Part Count", "edonkey.part_count",
                FT_UINT16, BASE_DEC, NULL, 0, "eDonkey Part Count", HFILL } },
        { &hf_edonkey_file_status,
            { "File Status", "edonkey.file_status",
                FT_BYTES, BASE_NONE, NULL, 0, "eDonkey File Status", HFILL } },
        { &hf_edonkey_directory,
            { "Directory", "edonkey.directory",
                FT_STRING, BASE_NONE, NULL, 0, "eDonkey Directory", HFILL } },
        { &hf_edonkey_fileinfo,
            { "eDonkey File Info", "edonkey.fileinfo",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_edonkey_serverinfo,
            { "eDonkey Server Info", "edonkey.serverinfo",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_edonkey_clientinfo,
            { "eDonkey Client Info", "edonkey.clientinfo",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_emule_public_key,
            { "Public Key", "edonkey.emule.public_key",
                FT_BYTES, BASE_NONE, NULL, 0, "eMule Public Key", HFILL } },
        { &hf_emule_signature,
            { "Signature", "edonkey.emule.signature",
                FT_BYTES, BASE_NONE, NULL, 0, "eMule Signature", HFILL } },
        { &hf_emule_aich_partnum,
            { "Part Number", "edonkey.emule.aich_partnum",
                FT_UINT16, BASE_DEC, NULL, 0, "eMule AICH Part Number", HFILL } },
        { &hf_emule_aich_root_hash,
            { "AICH Root Hash", "edonkey.emule.aich_root_hash",
                FT_BYTES, BASE_NONE, NULL, 0, "eMule AICH Root Hash", HFILL } },
        { &hf_emule_aich_hash_entry,
            { "AICH Hash Entry", "edonkey.emule.aich_hash_entry",
                FT_NONE, BASE_NONE, NULL, 0, "eMule AICH Hash Entry", HFILL } },
        { &hf_emule_aich_hash_id,
            { "AICH Hash ID", "edonkey.emule.aich_hash_id",
                FT_UINT16, BASE_HEX, NULL, 0, "eMule AICH Hash ID", HFILL } },
        { &hf_emule_aich_hash,
            { "AICH Hash", "edonkey.emule.aich_hash",
                FT_BYTES, BASE_NONE, NULL, 0, "eMule AICH Hash", HFILL } },
        { &hf_emule_multipacket_entry,
            { "eMule MultiPacket Entry", "edonkey.emule.multipacket_entry",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_emule_multipacket_opcode,
            { "MultiPacket Opcode", "edonkey.emule.multipacket_opcode",
                FT_UINT8, BASE_HEX, NULL, 0, "eMule MultiPacket Opcode", HFILL } },
        { &hf_emule_sourceOBFU,
            {"Source", "edonkey.source",
                FT_NONE, BASE_NONE, NULL, 0, "eDonkey File Source", HFILL } },
        { &hf_emule_source_count,
            { "Completed Sources Count", "edonkey.emule.source_count",
                FT_UINT16, BASE_DEC, NULL, 0, "eMule Completed Sources Count", HFILL } },
        { &hf_emule_zlib,
            { "Compressed Data", "edonkey.emule.zlib",
                FT_NONE, BASE_NONE, NULL, 0, "eMule Compressed Data", HFILL } },
        { &hf_overnet_peer,
            { "Overnet Peer", "edonkey.overnet.peer",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_kademlia,
            { "Kademlia Packet", "edonkey.kademlia",
                FT_UINT8, BASE_HEX, NULL, 0, "Kademlia Packet Type", HFILL } },
        { &hf_kademlia_peertype,
            { "Peer Type", "edonkey.kademlia.peer.type",
                FT_UINT8, BASE_DEC_HEX, NULL, 0, "Kademlia Peer Type", HFILL } },
        { &hf_kademlia_peer,
            { "Kademlia Peer", "edonkey.kademlia.peer",
                FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_kademlia_peer_id,
            { "Peer ID", "edonkey.kademlia.peer.id",
                FT_STRING, BASE_NONE, NULL, 0, "Kademlia Peer ID", HFILL } },
        { &hf_kademlia_hash,
            { "Kademlia Hash", "edonkey.kademlia.hash",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_kademlia_file_id,
            { "File ID", "edonkey.kademlia.file.id",
                FT_STRING, BASE_NONE, NULL, 0, "Kademlia File ID", HFILL } },
        { &hf_kademlia_keyword_hash,
            { "Keyword Hash", "edonkey.kademlia.keyword.hash",
                FT_STRING, BASE_NONE, NULL, 0, "Kademlia Keyword Hash", HFILL } },
        { &hf_kademlia_recipients_id,
            { "Recipient's ID", "edonkey.kademlia.recipients.id",
                FT_STRING, BASE_NONE, NULL, 0, "Kademlia Recipient's ID", HFILL } },
        { &hf_kademlia_sender_id,
            { "Sender ID", "edonkey.kademlia.sender.id",
                FT_STRING, BASE_NONE, NULL, 0, "Kademlia Sender ID", HFILL } },
        { &hf_kademlia_target_id,
            { "Target ID", "edonkey.kademlia.target.id",
                FT_STRING, BASE_NONE, NULL, 0, "Kademlia Target ID", HFILL } },
        { &hf_kademlia_distance,
            { "XOR Distance", "edonkey.kademlia.distance",
                FT_STRING, BASE_NONE, NULL, 0, "Kademlia XOR Distance", HFILL } },
        { &hf_kademlia_version,
            { "Kad Version", "edonkey.kademlia.version",
                FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL } },
        { &hf_kademlia_tag_float,
            { "Tag Value (Float)", "edonkey.kademlia.tag.value.float",
                FT_FLOAT, BASE_NONE, NULL, 0, "Float Tag Value", HFILL } },
        { &hf_kademlia_tag_uint64,
            { "Tag Value (UINT64)", "edonkey.kademlia.tag.value.uint64",
                FT_UINT64, BASE_DEC_HEX, NULL, 0, "UINT64 Tag Value", HFILL } },
        { &hf_kademlia_tag_uint32,
            { "Tag Value (UINT32)", "edonkey.kademlia.tag.value.uint32",
                FT_UINT32, BASE_DEC_HEX, NULL, 0, "UINT32 Tag Value", HFILL } },
        { &hf_kademlia_tag_ipv4,
            { "Tag Value (IPv4)", "edonkey.kademlia.tag.value.ipv4",
                FT_IPv4, BASE_NONE, NULL, 0, "UINT32 Tag Value (IPv4)", HFILL } },
        { &hf_kademlia_tag_uint16,
            { "Tag Value (UINT16)", "edonkey.kademlia.tag.value.uint16",
                FT_UINT16, BASE_DEC_HEX, NULL, 0, "UINT16 Tag Value", HFILL } },
        { &hf_kademlia_tag_uint8,
            { "Tag Value (UINT8)", "edonkey.kademlia.tag.value.uint8",
                FT_UINT8, BASE_DEC_HEX, NULL, 0, "UINT8 Tag Value", HFILL } },
        { &hf_kademlia_tag_hash,
            { "Tag Value (HASH)", "edonkey.kademlia.tag.value.hash",
                FT_BYTES, BASE_NONE, NULL, 0, "HASH Tag Value", HFILL } },
        { &hf_kademlia_tag_string,
            { "Tag Value (String)", "edonkey.kademlia.tag.value.string",
                FT_STRING, BASE_NONE, NULL, 0, "String Tag Value", HFILL } },
        { &hf_kademlia_tag_bsob,
            { "Tag Value (BSOB)", "edonkey.kademlia.tag.value.bsob",
                FT_BYTES, BASE_NONE, NULL, 0, "BSOB Tag Value", HFILL } },
        { &hf_kademlia_udp_port,
            { "UDP Port", "edonkey.kademlia.udp_port",
                FT_UINT16, BASE_DEC, NULL, 0, "Kademlia UDP Port", HFILL } },
        { &hf_kademlia_ip,
            { "IP", "edonkey.kademlia.ip",
                FT_IPv4, BASE_NONE, NULL, 0, "eDonkey IP", HFILL } },
        { &hf_kademlia_tcp_port,
            { "TCP Port", "edonkey.kademlia.tcp_port",
                FT_UINT16, BASE_DEC, NULL, 0, "Kademlia TCP Port", HFILL } },
        { &hf_kademlia_unparsed_data_length,
            { "Kademlia unparsed data length", "edonkey.kademlia.unparsed",
                FT_UINT16, BASE_DEC, NULL, 0, "Kademlia trailing data length", HFILL } },
        { &hf_kademlia_tag_name,
            { "Tag Name", "edonkey.kademlia.tag.name",
                FT_UINT8, BASE_HEX, NULL, 0, "Kademlia Tag Name String", HFILL } },
        { &hf_kademlia_tag_name_length,
            { "Tag Name Length", "edonkey.kademlia.tag.name.length",
                FT_UINT16, BASE_DEC, NULL, 0, "Kademlia Tag Name String Length", HFILL } },
        { &hf_kademlia_tag_type,
            { "Tag Type", "edonkey.kademlia.tag.type",
                FT_UINT8, BASE_HEX, NULL, 0, "Kademlia Tag Type", HFILL } },
        { &hf_kademlia_request_type,
            { "Request Type", "edonkey.kademlia.request.type",
                FT_UINT8, BASE_HEX, NULL, 0, "Kademlia Request Type", HFILL } },
        { &hf_kademlia_search_condition,
            { "Search Condition", "edonkey.kademlia.search.condition",
                FT_UINT8, BASE_HEX, NULL, 0, "Kademlia Search Condition", HFILL } },
        { &hf_kademlia_search_condition_argument_uint32,
            { "32bit Argument", "edonkey.kademlia.search.condition.argument.uint32",
                FT_UINT32, BASE_DEC_HEX, NULL, 0, "Kademlia Search Condition Argument 32bit Value", HFILL } },
        { &hf_kademlia_search_condition_argument_uint64,
            { "64bit Argument", "edonkey.kademlia.search.condition.argument.uint64",
                FT_UINT64, BASE_DEC_HEX, NULL, 0, "Kademlia Search Condition Argument 64bit Value", HFILL } },
        { &hf_edonkey_unparsed_data_length,
            { "eDonkey unparsed data length", "edonkey.unparsed",
                FT_UINT32, BASE_DEC_HEX, NULL, 0, "eDonkey trailing or unparsed data length", HFILL } },
    };

    static gint *ett[] = {
        &ett_edonkey,
        &ett_edonkey_message,
        &ett_edonkey_metatag,
        &ett_edonkey_search,
        &ett_edonkey_fileinfo,
        &ett_edonkey_serverinfo,
        &ett_edonkey_clientinfo,
        &ett_emule_aichhash,
        &ett_emule_multipacket,
        &ett_emule_zlib,
        &ett_overnet_peer,
        &ett_emule_sourceOBFU,
        &ett_edonkey_listitem,
        &ett_kademlia_search_expression,
        &ett_kademlia_tag
    };
    module_t *edonkey_module;

    proto_edonkey = proto_register_protocol("eDonkey Protocol", "EDONKEY", "edonkey");

    proto_register_field_array(proto_edonkey, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("edonkey.tcp", dissect_edonkey_tcp, proto_edonkey);
    register_dissector("edonkey.udp", dissect_edonkey_udp, proto_edonkey);

    edonkey_module = prefs_register_protocol(proto_edonkey, NULL);
    prefs_register_bool_preference(edonkey_module, "desegment",
                                   "Reassemble eDonkey messages spanning multiple TCP segments",
                                   "Whether the eDonkey dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &edonkey_desegment);
}

void proto_reg_handoff_edonkey(void) {

    dissector_handle_t edonkey_tcp_handle;
    dissector_handle_t edonkey_udp_handle;

    edonkey_tcp_handle = find_dissector("edonkey.tcp");
    edonkey_udp_handle = find_dissector("edonkey.udp");

    dissector_add_uint("tcp.port", 4661, edonkey_tcp_handle);
    dissector_add_uint("tcp.port", 4662, edonkey_tcp_handle);
    dissector_add_uint("tcp.port", 4663, edonkey_tcp_handle);
    dissector_add_uint("udp.port", 4665, edonkey_udp_handle);
    dissector_add_uint("udp.port", 4672, edonkey_udp_handle);

}

/* vim:set expandtab ts=2 cino=(0 :*/
