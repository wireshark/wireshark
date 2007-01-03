/* packet-iuup.c
 * IuUP Protocol 3GPP TS 25.415 V6.2.0 (2005-03)
 *
 * (c) 2005 Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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
 */
 

/*
   Patch by Polystar (Peter Vestman, Petter Edblom):
	Corrected rfci handling in rate control messages
	Added crc6 and crc10 checks for header and payload
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/expert.h>


typedef struct _iuup_rfci_t {
    guint id;
    guint sum_len;
    guint num_of_subflows;
    struct {
        guint len;
    } subflow[8];
    struct _iuup_rfci_t* next;
} iuup_rfci_t;

typedef struct {
    guint32 id; 
    guint num_of_subflows;
    iuup_rfci_t* rfcis;
    iuup_rfci_t* last_rfci;
} iuup_circuit_t;

static int proto_iuup = -1;

static int hf_iuup_direction = -1;
static int hf_iuup_circuit_id = -1;
                    
static int hf_iuup_pdu_type = -1;
static int hf_iuup_frame_number = -1;
static int hf_iuup_fqc = -1;
static int hf_iuup_rfci = -1;
static int hf_iuup_hdr_crc = -1;
static int hf_iuup_hdr_crc_error = -1;
static int hf_iuup_payload_crc = -1;
static int hf_iuup_payload_crc_error = -1;

static int hf_iuup_ack_nack = -1;
static int hf_iuup_frame_number_t14 = -1;
static int hf_iuup_mode_version = -1;
static int hf_iuup_procedure_indicator = -1;
static int hf_iuup_error_cause_val = -1;

static int hf_iuup_init_ti = -1;
static int hf_iuup_init_subflows_per_rfci = -1;
static int hf_iuup_init_chain_ind = -1;

static int hf_iuup_error_distance = -1;
static int hf_iuup_errorevt_cause_val = -1;

static int hf_iuup_time_align = -1;
static int hf_iuup_spare_bytes = -1;
static int hf_iuup_spare_03 = -1;
static int hf_iuup_spare_0f = -1;
static int hf_iuup_spare_c0 = -1;
static int hf_iuup_spare_e0 = -1;
static int hf_iuup_spare_ff = -1;

static int hf_iuup_delay = -1;
static int hf_iuup_advance = -1;
static int hf_iuup_delta = -1;

static int hf_iuup_mode_versions = -1;
static int hf_iuup_mode_versions_a[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};


static int hf_iuup_data_pdu_type = -1;

static int hf_iuup_num_rfci_ind = -1;

static int hf_iuup_payload = -1;

static int hf_iuup_init_rfci_ind = -1;
static int hf_iuup_init_rfci[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};

static int hf_iuup_init_rfci_flow_len[64][8] = {
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1}    
};

static int hf_iuup_init_rfci_li[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
static int hf_iuup_init_rfci_lri[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
static int hf_iuup_init_ipti[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};

static int hf_iuup_rfci_subflow[64][8] = {
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1,-1,-1,-1,-1}    
};

static int hf_iuup_rfci_ratectl[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};


static gint ett_iuup = -1;
static gint ett_rfci = -1;
static gint ett_ipti = -1;
static gint ett_support = -1;
static gint ett_time = -1;
static gint ett_rfciinds = -1;
static gint ett_payload = -1;
static gint ett_payload_subflows = -1;

static GHashTable* circuits = NULL;

static dissector_handle_t data_handle = NULL;
static dissector_handle_t iuup_handle = NULL;
static gboolean dissect_fields = FALSE;
static gboolean two_byte_pseudoheader = FALSE;
static guint dynamic_payload_type = 0;
static guint temp_dynamic_payload_type = 0;
static gboolean iuup_prefs_initialized = FALSE;


#define PDUTYPE_DATA_WITH_CRC 0
#define PDUTYPE_DATA_NO_CRC 1
#define PDUTYPE_DATA_CONTROL_PROC 14

static const value_string iuup_pdu_types[] = {
    {PDUTYPE_DATA_WITH_CRC,"Data with CRC"},
    {PDUTYPE_DATA_NO_CRC,"Data without CRC"},
    {PDUTYPE_DATA_CONTROL_PROC,"Control Procedure"},
    {0,NULL}
};

static const value_string iuup_colinfo_pdu_types[] = {
    {PDUTYPE_DATA_WITH_CRC,"Data (CRC)"},
    {PDUTYPE_DATA_NO_CRC,"Data (no CRC)"},
    {PDUTYPE_DATA_CONTROL_PROC,""},
    {0,NULL}
};

#define ACKNACK_ACK 0x4
#define ACKNACK_NACK 0x8
#define ACKNACK_RESERVED 0xc
#define ACKNACK_PROC 0x0

static const value_string iuup_acknack_vals[] = {
    {ACKNACK_PROC >> 2,"Procedure"},
    {ACKNACK_ACK >> 2,"ACK"},
    {ACKNACK_NACK  >> 2,"NACK"},
    {ACKNACK_RESERVED  >> 2,"Reserved"},
    {0,NULL}
};

static const value_string iuup_colinfo_acknack_vals[] = {
    {ACKNACK_PROC,""},
    {ACKNACK_ACK,"ACK "},
    {ACKNACK_NACK,"NACK "},
    {ACKNACK_RESERVED,"Reserved "},
    {0,NULL}
};

#define PROC_INIT 0
#define PROC_RATE 1
#define PROC_TIME 2
#define PROC_ERROR 3

static const value_string iuup_procedures[] = {
    {PROC_INIT,"Initialization"},
    {PROC_RATE,"Rate Control"},
    {PROC_TIME,"Time Alignment"},
    {PROC_ERROR,"Error Event"},
    {4,"Reserved(4)"},
    {5,"Reserved(5)"},
    {6,"Reserved(6)"},
    {7,"Reserved(7)"},
    {8,"Reserved(8)"},
    {9,"Reserved(9)"},
    {10,"Reserved(10)"},
    {11,"Reserved(11)"},
    {12,"Reserved(12)"},
    {13,"Reserved(13)"},
    {14,"Reserved(14)"},
    {15,"Reserved(15)"},
    {0,NULL}
};

static const value_string iuup_colinfo_procedures[] = {
    {PROC_INIT,"Initialization "},
    {PROC_RATE,"Rate Control "},
    {PROC_TIME,"Time Alignment "},
    {PROC_ERROR,"Error Event "},
    {0,NULL}
};


static const value_string iuup_error_distances[] = {
    {0, "Reporting local error"},
    {1, "First forwarding of error event report"},
    {2, "Second forwarding of error event report"},
    {3, "Reserved"},
    {0,NULL}
};

static const value_string iuup_error_causes[] = {
    {0, "CRC error of frame header"},
    {1, "CRC error of frame payload"},
    {2, "Unexpected frame number"},
    {3, "Frame loss"},
    {4, "PDU type unknown"},
    {5, "Unknown procedure"},
    {6, "Unknown reserved value"},
    {7, "Unknown field"},
    {8, "Frame too short"},
    {9, "Missing fields"},
    {16, "Unexpected PDU type"},
    {18, "Unexpected procedure"},
    {19, "Unexpected RFCI"},
    {20, "Unexpected value"},
    {42, "Initialisation failure"},
    {43, "Initialisation failure (network error, timer expiry)"},
    {44, "Initialisation failure (Iu UP function error, repeated NACK)"},
    {45, "Rate control failure"},
    {46, "Error event failure"},
    {47, "Time Alignment not supported"},
    {48, "Requested Time Alignment not possible"},
    {49, "Iu UP Mode version not supported"},
    {0,NULL}
};

static const value_string iuup_rfci_indicator[] = {
    {0, "RFCI allowed"},
    {1, "RFCI barred"},
    {0,NULL}
};


static const value_string iuup_ti_vals[] = {
    {0, "IPTIs not present"},
    {1, "IPTIs present in frame"},
    {0,NULL}
};

static const value_string iuup_mode_version_support[] = {
    {0, "not supported"},
    {1, "supported"},
    {0,NULL}
};

static const value_string iuup_init_rfci_li_vals[] = {
    {0, "one octet used"},
    {1, "two octets used"},
    {0,NULL}
};

static const value_string iuup_init_chain_ind_vals[] = {
    {0, "this frame is the last frame for the procedure"},
    {1, "additional frames will be sent for the procedure"},
    {0,NULL}
};

static const value_string iuup_init_lri_vals[] = {
    {0, "Not last RFCI"},
    {1, "Last RFCI in current frame"},
    {0,NULL}
};

static const value_string iuup_payload_pdu_type[] = {
    {0, "PDU type 0"},
    {1, "PDU type 1"},
    {0,NULL}
};

static const value_string iuup_fqcs[] = {
    {0, "Frame Good"},
    {1, "Frame BAD"},
    {2, "Frame bad due to radio"},
    {3, "spare"},
    {0,NULL}
};
/*
 * Charles Michael Heard's CRC-10 code, from
 *
 *      http://cell-relay.indiana.edu/cell-relay/publications/software/CRC/crc10.html
 *
 * with the CRC table initialized with values computed by
 * his "gen_byte_crc10_table()" routine, rather than by calling that
 * routine at run time, and with various data type cleanups.
 */
static const guint16 byte_crc10_table[256] = {
        0x0000, 0x0233, 0x0255, 0x0066, 0x0299, 0x00aa, 0x00cc, 0x02ff,
        0x0301, 0x0132, 0x0154, 0x0367, 0x0198, 0x03ab, 0x03cd, 0x01fe,
        0x0031, 0x0202, 0x0264, 0x0057, 0x02a8, 0x009b, 0x00fd, 0x02ce,
        0x0330, 0x0103, 0x0165, 0x0356, 0x01a9, 0x039a, 0x03fc, 0x01cf,
        0x0062, 0x0251, 0x0237, 0x0004, 0x02fb, 0x00c8, 0x00ae, 0x029d,
        0x0363, 0x0150, 0x0136, 0x0305, 0x01fa, 0x03c9, 0x03af, 0x019c,
        0x0053, 0x0260, 0x0206, 0x0035, 0x02ca, 0x00f9, 0x009f, 0x02ac,
        0x0352, 0x0161, 0x0107, 0x0334, 0x01cb, 0x03f8, 0x039e, 0x01ad,
        0x00c4, 0x02f7, 0x0291, 0x00a2, 0x025d, 0x006e, 0x0008, 0x023b,
        0x03c5, 0x01f6, 0x0190, 0x03a3, 0x015c, 0x036f, 0x0309, 0x013a,
        0x00f5, 0x02c6, 0x02a0, 0x0093, 0x026c, 0x005f, 0x0039, 0x020a,
        0x03f4, 0x01c7, 0x01a1, 0x0392, 0x016d, 0x035e, 0x0338, 0x010b,
        0x00a6, 0x0295, 0x02f3, 0x00c0, 0x023f, 0x000c, 0x006a, 0x0259,
        0x03a7, 0x0194, 0x01f2, 0x03c1, 0x013e, 0x030d, 0x036b, 0x0158,
        0x0097, 0x02a4, 0x02c2, 0x00f1, 0x020e, 0x003d, 0x005b, 0x0268,
        0x0396, 0x01a5, 0x01c3, 0x03f0, 0x010f, 0x033c, 0x035a, 0x0169,
        0x0188, 0x03bb, 0x03dd, 0x01ee, 0x0311, 0x0122, 0x0144, 0x0377,
        0x0289, 0x00ba, 0x00dc, 0x02ef, 0x0010, 0x0223, 0x0245, 0x0076,
        0x01b9, 0x038a, 0x03ec, 0x01df, 0x0320, 0x0113, 0x0175, 0x0346,
        0x02b8, 0x008b, 0x00ed, 0x02de, 0x0021, 0x0212, 0x0274, 0x0047,
        0x01ea, 0x03d9, 0x03bf, 0x018c, 0x0373, 0x0140, 0x0126, 0x0315,
        0x02eb, 0x00d8, 0x00be, 0x028d, 0x0072, 0x0241, 0x0227, 0x0014,
        0x01db, 0x03e8, 0x038e, 0x01bd, 0x0342, 0x0171, 0x0117, 0x0324,
        0x02da, 0x00e9, 0x008f, 0x02bc, 0x0043, 0x0270, 0x0216, 0x0025,
        0x014c, 0x037f, 0x0319, 0x012a, 0x03d5, 0x01e6, 0x0180, 0x03b3,
        0x024d, 0x007e, 0x0018, 0x022b, 0x00d4, 0x02e7, 0x0281, 0x00b2,
        0x017d, 0x034e, 0x0328, 0x011b, 0x03e4, 0x01d7, 0x01b1, 0x0382,
        0x027c, 0x004f, 0x0029, 0x021a, 0x00e5, 0x02d6, 0x02b0, 0x0083,
        0x012e, 0x031d, 0x037b, 0x0148, 0x03b7, 0x0184, 0x01e2, 0x03d1,
        0x022f, 0x001c, 0x007a, 0x0249, 0x00b6, 0x0285, 0x02e3, 0x00d0,
        0x011f, 0x032c, 0x034a, 0x0179, 0x0386, 0x01b5, 0x01d3, 0x03e0,
        0x021e, 0x002d, 0x004b, 0x0278, 0x0087, 0x02b4, 0x02d2, 0x00e1
};

/* update the data block's CRC-10 remainder one byte at a time */
static guint16
update_crc10_by_bytes(guint16 crc10, const guint8 *data_blk_ptr,
    		      int data_blk_size)
{
    register int i;
    guint16 crc10_accum = 0;

    for (i = 0;  i < data_blk_size; i++) {
   	crc10_accum = ((crc10_accum << 8) & 0x3ff)
         	^ byte_crc10_table[( crc10_accum >> 2) & 0xff]
                ^ *data_blk_ptr++;
    }
    crc10_accum = ((crc10_accum << 8) & 0x3ff)
	            ^ byte_crc10_table[( crc10_accum >> 2) & 0xff]
                    ^ (crc10>>2);
    crc10_accum = ((crc10_accum << 8) & 0x3ff)
                    ^ byte_crc10_table[( crc10_accum >> 2) & 0xff]
	            ^ ((crc10<<6) & 0xFF);
    
    return crc10_accum;
}


static guint16
update_crc6_by_bytes(guint16 crc6, unsigned char byte1, unsigned char byte2)
{
    char bit;
    unsigned int remainder = 0;
    unsigned int polynomial = 0x6F << 15;

    unsigned int data = ( byte1<<8 | byte2 ) << 6;
    remainder = data;

    for (bit = 15; bit >= 0; --bit)
    {
        if (remainder & (0x40 << bit))
        {
            remainder ^= polynomial;
        }
        polynomial >>= 1;
    }

    return (remainder ^ crc6);
}


static proto_item*
proto_tree_add_bits(proto_tree* tree, int hf, tvbuff_t* tvb, int offset, int bit_offset, guint bits, gchar** buf) {
    static const guint8 masks[] = {0x00,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe};
    int len = (bits + bit_offset)/8 + ((bits + bit_offset)%8 ? 0 : 1);
    guint8* shifted_buffer;
    proto_item* pi;
    int i;

    DISSECTOR_ASSERT(bit_offset < 8);
    
    shifted_buffer = ep_tvb_memdup(tvb,offset,len+1);
    
    for(i = 0; i < len; i++) {
        shifted_buffer[i] <<= bit_offset;
        shifted_buffer[i] |= (shifted_buffer[i+1] & masks[bit_offset]) >> (8 - bit_offset); 
    }

    shifted_buffer[len] <<=  bit_offset;
    shifted_buffer[len] &= masks[(bits + bit_offset)%8];
    
    if (buf)
        *buf = (gchar*)shifted_buffer;
    
    pi = proto_tree_add_bytes(tree, hf, tvb, offset, len + ((bits + bit_offset) % 8 ? 1 : 0) , shifted_buffer);
    proto_item_append_text(pi, " (%i Bits)", bits);
    
    return pi;
}

static void dissect_iuup_payload(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, guint rfci_id _U_, int offset) {
    iuup_circuit_t* iuup_circuit;
    iuup_rfci_t *rfci;
    int last_offset = tvb_length(tvb) - 1;
    guint bit_offset = 0;
    proto_item* pi;
    
    pi = proto_tree_add_item(tree,hf_iuup_payload,tvb,offset,-1,FALSE);
    
    if ( ! dissect_fields ) {
        return;
    } else if ( ! pinfo->circuit_id
                || ! ( iuup_circuit  = g_hash_table_lookup(circuits,GUINT_TO_POINTER(pinfo->circuit_id)) ) ) {
        proto_item_set_expert_flags(pi, PI_UNDECODED, PI_WARN);
        return;
    }
    
    for(rfci = iuup_circuit->rfcis; rfci; rfci = rfci->next)
        if ( rfci->id == rfci_id )
            break;
    
    if (!rfci) {
        proto_item_set_expert_flags(pi, PI_UNDECODED, PI_WARN);
        return;
    }

    tree = proto_item_add_subtree(pi,ett_payload);


    do {
        guint i;
        guint subflows = rfci->num_of_subflows;
        proto_tree* flow_tree;
        
        pi = proto_tree_add_text(tree,tvb,offset,-1,"Payload Frame");
        flow_tree = proto_item_add_subtree(pi,ett_payload_subflows);

        bit_offset = 0;

        for(i = 0; i < subflows; i++) {
            
            if (! rfci->subflow[i].len)
                continue;
            
            proto_tree_add_bits(flow_tree, hf_iuup_rfci_subflow[rfci->id][i], tvb,
                                offset + (bit_offset/8),
                                bit_offset % 8,
                                rfci->subflow[i].len,
                                NULL);
            
            bit_offset += rfci->subflow[i].len;
        }
        
        offset += (bit_offset / 8) + (bit_offset % 8 ? 1 : 0);
        
    } while (offset <= last_offset);
}

static guint dissect_rfcis(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int* offset, iuup_circuit_t* iuup_circuit) {
    proto_item* pi;
    proto_tree* pt;
    guint8 oct;
    guint c = 0;
    guint i;

    do {
        iuup_rfci_t *rfci = se_alloc0(sizeof(iuup_rfci_t));
        guint len = 0;
        
        DISSECTOR_ASSERT(c < 64);

        pi = proto_tree_add_item(tree,hf_iuup_init_rfci_ind,tvb,*offset,-1,FALSE);
        pt = proto_item_add_subtree(pi,ett_rfci);
        
        proto_tree_add_item(pt,hf_iuup_init_rfci_lri[c],tvb,*offset,1,FALSE);
        proto_tree_add_item(pt,hf_iuup_init_rfci_li[c],tvb,*offset,1,FALSE);
        proto_tree_add_item(pt,hf_iuup_init_rfci[c],tvb,*offset,1,FALSE);
        
        oct = tvb_get_guint8(tvb,*offset);
        rfci->id = oct & 0x3f;
        rfci->num_of_subflows = iuup_circuit->num_of_subflows;
        
        len = (oct & 0x40) ? 2 : 1;
        proto_item_set_text(pi,"RFCI %i Initialization",rfci->id);
        proto_item_set_len(pi,(len*iuup_circuit->num_of_subflows)+1);
        
        (*offset)++;
        
        for(i = 0; i < iuup_circuit->num_of_subflows; i++) {
            guint subflow_len;
            
            if (len == 2) {
                subflow_len = tvb_get_ntohs(tvb,*offset);
            } else {
                subflow_len = tvb_get_guint8(tvb,*offset);
            }
            
            rfci->subflow[i].len = subflow_len;
            rfci->sum_len += subflow_len;
            
            proto_tree_add_uint(pt,hf_iuup_init_rfci_flow_len[c][i],tvb,*offset,len,subflow_len);

            (*offset) += len;
        }
        
        
        if (iuup_circuit->last_rfci) {
            iuup_circuit->last_rfci = iuup_circuit->last_rfci->next = rfci;
        } else {
            iuup_circuit->last_rfci = iuup_circuit->rfcis = rfci;
        }
        
        c++;
    } while ( ! (oct & 0x80) );
    
    return c - 1;
}

static void dissect_iuup_init(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {
    int offset = 4;
    guint8 oct = tvb_get_guint8(tvb,offset);
    guint n = (oct & 0x0e) >> 1;
    gboolean ti = oct & 0x10;
    guint i;
    guint rfcis;
    proto_item* pi;
    proto_tree* support_tree = NULL;
    proto_tree* iptis_tree;
    iuup_circuit_t* iuup_circuit = NULL;
    
    if (pinfo->circuit_id) {
        g_hash_table_lookup(circuits,GUINT_TO_POINTER(pinfo->circuit_id));
    
        if (iuup_circuit) {
            g_hash_table_remove(circuits,GUINT_TO_POINTER(pinfo->circuit_id));
        }
    
        iuup_circuit = se_alloc0(sizeof(iuup_circuit_t));
    } else {
        iuup_circuit = ep_alloc0(sizeof(iuup_circuit_t));
    }
    
    iuup_circuit->id = pinfo->circuit_id;
    iuup_circuit->num_of_subflows = n;
    iuup_circuit->rfcis = NULL;
    iuup_circuit->last_rfci = NULL;
    
    if (pinfo->circuit_id) {
        g_hash_table_insert(circuits,GUINT_TO_POINTER(iuup_circuit->id),iuup_circuit);
    }
    
    if (tree) {
        proto_tree_add_item(tree,hf_iuup_spare_e0,tvb,offset,1,FALSE);
        proto_tree_add_item(tree,hf_iuup_init_ti,tvb,offset,1,FALSE);
        proto_tree_add_item(tree,hf_iuup_init_subflows_per_rfci,tvb,offset,1,FALSE);
        proto_tree_add_item(tree,hf_iuup_init_chain_ind,tvb,offset,1,FALSE);
    }
    
    offset++;

    rfcis = dissect_rfcis(tvb, pinfo, tree, &offset, iuup_circuit);

    if (!tree) return;
    
    if (ti) {
        pi = proto_tree_add_text(tree,tvb,offset,(rfcis/2)+(rfcis%2),"IPTIs");
        iptis_tree = proto_item_add_subtree(pi,ett_ipti);
        
        for (i = 0; i <= rfcis; i++) {
            proto_tree_add_item(iptis_tree,hf_iuup_init_ipti[i],tvb,offset,1,FALSE);
            if ((i%2)) {
                offset++;
            }
        }
        
        if ((i%2)) {
            offset++;
        }
    }
    
    if (tree) {
        pi = proto_tree_add_item(tree,hf_iuup_mode_versions,tvb,offset,2,FALSE);
        support_tree = proto_item_add_subtree(pi,ett_support);
        
        for (i = 0; i < 16; i++) {
            proto_tree_add_item(support_tree,hf_iuup_mode_versions_a[i],tvb,offset,2,FALSE);
        }
        
    }
        
    offset += 2;
    
    proto_tree_add_item(tree,hf_iuup_data_pdu_type,tvb,offset,1,FALSE);
    
}

static void dissect_iuup_ratectl(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree) {
    guint num = tvb_get_guint8(tvb,4) & 0x3f;
    guint i;
    proto_item* pi;
    proto_tree* inds_tree;
    int offset = 4;
    
    pi = proto_tree_add_item(tree,hf_iuup_num_rfci_ind,tvb,4,1,FALSE);
    inds_tree = proto_item_add_subtree(pi,ett_rfciinds);
    
    for (i = 0; i < num; i++) {
        if (! (i % 8) ) offset++;
        proto_tree_add_item(inds_tree,hf_iuup_rfci_ratectl[i],tvb,offset,1,FALSE);
    }
    
}

proto_item *add_hdr_crc(tvbuff_t* tvb, packet_info* pinfo, proto_item* iuup_tree, guint16 crccheck)
{
   proto_item *crc_item;
   if (crccheck) {
      crc_item = proto_tree_add_item(iuup_tree,hf_iuup_hdr_crc_error,tvb,2,1,FALSE);
      expert_add_info_format(pinfo, crc_item, PI_CHECKSUM, PI_ERROR, "Bad checksum");
   } else {
      crc_item = proto_tree_add_item(iuup_tree,hf_iuup_hdr_crc,tvb,2,1,FALSE);
   }
   return crc_item;
}

proto_item *add_payload_crc(tvbuff_t* tvb, packet_info* pinfo, proto_item* iuup_tree)
{
   proto_item *crc_item;
   int length = tvb_length(tvb);
   guint16 crc10 = tvb_get_ntohs(tvb, 2) & 0x3FF;
   guint16 crccheck = update_crc10_by_bytes(crc10, tvb_get_ptr(tvb, 4, length - 4), length - 4);
   if (crccheck) {
      crc_item = proto_tree_add_item(iuup_tree,hf_iuup_payload_crc_error,tvb,2,2,FALSE);
      expert_add_info_format(pinfo, crc_item, PI_CHECKSUM, PI_ERROR, "Bad checksum");
   } else {
      crc_item = proto_tree_add_item(iuup_tree,hf_iuup_payload_crc,tvb,2,2,FALSE);
   }
   return crc_item;
}

#define ACKNACK_MASK  0x0c
#define PROCEDURE_MASK  0x0f
#define FQC_MASK 0xc0
#define PDUTYPE_MASK 0xf0
static void dissect_iuup(tvbuff_t* tvb_in, packet_info* pinfo, proto_tree* tree) {
    proto_item* pi;
    proto_item* iuup_item = NULL;
    proto_item* pdutype_item = NULL;
    proto_tree* iuup_tree = NULL;
    proto_item* proc_item = NULL;
    proto_item* ack_item = NULL;
    guint8 first_octet;
    guint8 second_octet;
    guint8 pdutype;
    guint phdr = 0;
    guint16  hdrcrc6;
    guint16  crccheck;
    tvbuff_t* tvb = tvb_in;
    
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IuUP");
    }

    if (two_byte_pseudoheader) {
        int len = tvb_length(tvb_in) - 2;
        
        phdr = tvb_get_ntohs(tvb,0);

        proto_tree_add_item(tree,hf_iuup_direction,tvb,0,2,FALSE);
        proto_tree_add_item(tree,hf_iuup_circuit_id,tvb,0,2,FALSE);
        
        phdr &= 0x7fff;
        
        pinfo->circuit_id = phdr;
        
        tvb = tvb_new_subset(tvb_in,2,len,len);
    }
    
    first_octet =  tvb_get_guint8(tvb,0);
    second_octet =  tvb_get_guint8(tvb,1);
    hdrcrc6 = tvb_get_guint8(tvb, 2) >> 2;
    crccheck = update_crc6_by_bytes(hdrcrc6, first_octet, second_octet);
    
    pdutype = ( first_octet & PDUTYPE_MASK ) >> 4;
    
    if (tree) {
        iuup_item = proto_tree_add_item(tree,proto_iuup,tvb,0,-1,FALSE);
        iuup_tree = proto_item_add_subtree(iuup_item,ett_iuup);
        
        pdutype_item = proto_tree_add_item(iuup_tree,hf_iuup_pdu_type,tvb,0,1,FALSE);
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str(pdutype, iuup_colinfo_pdu_types, "Unknown PDU Type(%u) "));
    }
    
    switch(pdutype) {
        case PDUTYPE_DATA_WITH_CRC:
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO,"FN: %x RFCI: %u", (guint)(first_octet & 0x0f) ,(guint)(second_octet & 0x3f));
            }
                
            if (!tree) return;
            proto_tree_add_item(iuup_tree,hf_iuup_frame_number,tvb,0,1,FALSE);
            pi = proto_tree_add_item(iuup_tree,hf_iuup_fqc,tvb,1,1,FALSE);
            
            if (first_octet & FQC_MASK) {
                proto_item_set_expert_flags(pi, PI_RESPONSE_CODE, PI_WARN);
                proto_item_set_expert_flags(iuup_item, PI_RESPONSE_CODE, PI_WARN);
            }
                
            proto_tree_add_item(iuup_tree,hf_iuup_rfci,tvb,1,1,FALSE);
	    add_hdr_crc(tvb, pinfo, iuup_tree, crccheck);
	    add_payload_crc(tvb, pinfo, iuup_tree);
            dissect_iuup_payload(tvb,pinfo,iuup_tree,second_octet & 0x3f,4);
            return;
        case PDUTYPE_DATA_NO_CRC:
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO," RFCI %u", (guint)(second_octet & 0x3f));
            }
            if (!tree) return;
            proto_tree_add_item(iuup_tree,hf_iuup_frame_number,tvb,0,1,FALSE);
            pi = proto_tree_add_item(iuup_tree,hf_iuup_fqc,tvb,1,1,FALSE);

            if (first_octet & FQC_MASK) {
                proto_item_set_expert_flags(pi, PI_RESPONSE_CODE, PI_WARN);
                proto_item_set_expert_flags(iuup_item, PI_RESPONSE_CODE, PI_WARN);
            }
                
            proto_tree_add_item(iuup_tree,hf_iuup_rfci,tvb,1,1,FALSE);
	    add_hdr_crc(tvb, pinfo, iuup_tree, crccheck);
            dissect_iuup_payload(tvb,pinfo,iuup_tree,second_octet & 0x3f,3);
            return;
        case PDUTYPE_DATA_CONTROL_PROC:
            if (tree) {
                ack_item = proto_tree_add_item(iuup_tree,hf_iuup_ack_nack,tvb,0,1,FALSE);
                proto_tree_add_item(iuup_tree,hf_iuup_frame_number_t14,tvb,0,1,FALSE);
                proto_tree_add_item(iuup_tree,hf_iuup_mode_version,tvb,1,1,FALSE);
                proc_item = proto_tree_add_item(iuup_tree,hf_iuup_procedure_indicator,tvb,1,1,FALSE);
	        add_hdr_crc(tvb, pinfo, iuup_tree, crccheck);
            }
            
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_str(pinfo->cinfo, COL_INFO,
                               val_to_str(first_octet & ACKNACK_MASK,
                                          iuup_colinfo_acknack_vals, "[action:%u] "));
                
                col_append_str(pinfo->cinfo, COL_INFO,
                               val_to_str(second_octet & PROCEDURE_MASK,
                                          iuup_colinfo_procedures, "[proc:%u] "));
            }
            
            switch ( first_octet & ACKNACK_MASK ) {
                case ACKNACK_ACK:
                    switch(second_octet & PROCEDURE_MASK) {
                        case PROC_INIT:
                            if (!tree) return;
                            proto_tree_add_item(iuup_tree,hf_iuup_spare_03,tvb,2,1,FALSE);
                            proto_tree_add_item(iuup_tree,hf_iuup_spare_ff,tvb,3,1,FALSE);
                            return;
                        case PROC_RATE:
                    	    if (!tree) return;
                    	    dissect_iuup_ratectl(tvb,pinfo,iuup_tree);
                    	    return;
                        case PROC_TIME:
                        case PROC_ERROR:
                            break;
                        default:
                            if (!tree) return;
                            proto_item_set_expert_flags(proc_item, PI_MALFORMED, PI_ERROR);
                            return;
                    }
                    break;
                case ACKNACK_NACK:
                    if (!tree) return;
                    pi = proto_tree_add_item(iuup_tree,hf_iuup_error_cause_val,tvb,4,1,FALSE);
                    proto_item_set_expert_flags(pi, PI_RESPONSE_CODE, PI_ERROR);
                    return;
                case ACKNACK_RESERVED:
                    if (!tree) return;
                    proto_item_set_expert_flags(ack_item, PI_MALFORMED, PI_ERROR);
                    return;
                case ACKNACK_PROC:
                    break;
            }
            
            switch( second_octet & PROCEDURE_MASK ) {
                case PROC_INIT:
                    if (tree) add_payload_crc(tvb, pinfo, iuup_tree);
                    dissect_iuup_init(tvb,pinfo,iuup_tree);
                    return;
                case PROC_RATE:
                    if (!tree) return;
                    add_payload_crc(tvb, pinfo, iuup_tree);
                    dissect_iuup_ratectl(tvb,pinfo,iuup_tree);
                    return;
                case PROC_TIME:
                {
                    proto_tree* time_tree;
                    guint ta;

                    if (!tree) return;

                    ta = tvb_get_guint8(tvb,4);
                    
                    pi = proto_tree_add_item(iuup_tree,hf_iuup_time_align,tvb,4,1,FALSE);
                    time_tree = proto_item_add_subtree(pi,ett_time);
                    
                    if (ta >= 1 && ta <= 80) {
                        pi = proto_tree_add_uint(time_tree,hf_iuup_delay,tvb,4,1,ta * 500);
                        PROTO_ITEM_SET_GENERATED(pi);
                        pi = proto_tree_add_float(time_tree,hf_iuup_delta,tvb,4,1,((gfloat)((gint)(ta) * 500))/1000000.0);
                        PROTO_ITEM_SET_GENERATED(pi);
                    } else if (ta >= 129 && ta <= 208) {
                        pi = proto_tree_add_uint(time_tree,hf_iuup_advance,tvb,4,1,(ta-128) * 500);
                        PROTO_ITEM_SET_GENERATED(pi);
                        pi = proto_tree_add_float(time_tree,hf_iuup_delta,tvb,4,1,((gfloat)((gint)(-(((gint)ta)-128))) * 500)/1000000.0);
                        PROTO_ITEM_SET_GENERATED(pi);
                    } else {
                        proto_item_set_expert_flags(pi, PI_MALFORMED, PI_ERROR);
                    }
                    
                    proto_tree_add_item(iuup_tree,hf_iuup_spare_bytes,tvb,5,-1,FALSE);
                    return;
                }
                case PROC_ERROR:
                    if (check_col(pinfo->cinfo, COL_INFO)) {
                        col_append_str(pinfo->cinfo, COL_INFO, val_to_str(tvb_get_guint8(tvb,4) & 0x3f,iuup_error_causes,"Unknown (%u)"));
                    }
                    if (!tree) return;
                    proto_tree_add_item(iuup_tree,hf_iuup_error_distance,tvb,4,1,FALSE);
                    pi = proto_tree_add_item(iuup_tree,hf_iuup_errorevt_cause_val,tvb,4,1,FALSE);
                    proto_item_set_expert_flags(pi, PI_RESPONSE_CODE, PI_ERROR);
                    proto_tree_add_item(iuup_tree,hf_iuup_spare_bytes,tvb,5,-1,FALSE);
                    return;
                default: /* bad */
                    if (!tree) return;
                    proto_item_set_expert_flags(proc_item, PI_MALFORMED, PI_ERROR);
                    return;
            }
        default:
            if (!tree) return;
            proto_item_set_expert_flags(pdutype_item, PI_MALFORMED, PI_ERROR);
            return;
    };
}

static void init_iuup(void) {
    if (circuits) g_hash_table_destroy(circuits);
    circuits = g_hash_table_new(g_direct_hash,g_direct_equal);

    if (!iuup_prefs_initialized) {
        iuup_prefs_initialized = TRUE;
    } else if ( dynamic_payload_type > 95 ) {
            dissector_delete("rtp.pt", dynamic_payload_type, iuup_handle);
    }
    
    dynamic_payload_type = temp_dynamic_payload_type;
    
    if ( dynamic_payload_type > 95 ) {
        dissector_add("rtp.pt", dynamic_payload_type, iuup_handle);
    }
    
    dissector_add_string("rtp_dyn_payload_type","VND.3GPP.IUFP", iuup_handle);

}


void proto_reg_handoff_iuup(void) {
    data_handle = find_dissector("data");
}


#define HFS_RFCI(i) \
{ &hf_iuup_rfci_ratectl[i], { "RFCI " #i, "iuup.rfci." #i, FT_UINT8, BASE_DEC, VALS(iuup_rfci_indicator),0x80>>(i%8),"",HFILL}}, \
{ &hf_iuup_init_rfci[i], { "RFCI " #i, "iuup.rfci." #i, FT_UINT8, BASE_DEC, NULL,0x3f,"",HFILL}}, \
{ &hf_iuup_init_rfci_flow_len[i][0], { "RFCI " #i " Flow 0 Len", "iuup.rfci."#i".flow.0.len", FT_UINT16, BASE_DEC, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_init_rfci_flow_len[i][1], { "RFCI " #i " Flow 1 Len", "iuup.rfci."#i".flow.1.len", FT_UINT16, BASE_DEC, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_init_rfci_flow_len[i][2], { "RFCI " #i " Flow 2 Len", "iuup.rfci."#i".flow.2.len", FT_UINT16, BASE_DEC, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_init_rfci_flow_len[i][3], { "RFCI " #i " Flow 3 Len", "iuup.rfci."#i".flow.3.len", FT_UINT16, BASE_DEC, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_init_rfci_flow_len[i][4], { "RFCI " #i " Flow 4 Len", "iuup.rfci."#i".flow.4.len", FT_UINT16, BASE_DEC, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_init_rfci_flow_len[i][5], { "RFCI " #i " Flow 5 Len", "iuup.rfci."#i".flow.5.len", FT_UINT16, BASE_DEC, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_init_rfci_flow_len[i][6], { "RFCI " #i " Flow 6 Len", "iuup.rfci."#i".flow.6.len", FT_UINT16, BASE_DEC, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_init_rfci_flow_len[i][7], { "RFCI " #i " Flow 7 Len", "iuup.rfci."#i".flow.7.len", FT_UINT16, BASE_DEC, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_init_rfci_li[i], { "RFCI " #i " LI", "iuup.rfci."#i".li", FT_UINT8, BASE_HEX, VALS(iuup_init_rfci_li_vals),0x40,"Length Indicator",HFILL}}, \
{ &hf_iuup_init_rfci_lri[i], { "RFCI " #i " LRI", "iuup.rfci."#i".lri", FT_UINT8, BASE_HEX, VALS(iuup_init_lri_vals),0x80,"Last Record Indicator",HFILL}}, \
{ &hf_iuup_rfci_subflow[i][0], { "RFCI " #i " Flow 0", "iuup.rfci."#i".flow.0", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_rfci_subflow[i][1], { "RFCI " #i " Flow 1", "iuup.rfci."#i".flow.1", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_rfci_subflow[i][2], { "RFCI " #i " Flow 2", "iuup.rfci."#i".flow.2", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_rfci_subflow[i][3], { "RFCI " #i " Flow 3 Len", "iuup.rfci."#i".flow.3", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_rfci_subflow[i][4], { "RFCI " #i " Flow 4 Len", "iuup.rfci."#i".flow.4", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_rfci_subflow[i][5], { "RFCI " #i " Flow 5 Len", "iuup.rfci."#i".flow.5", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_rfci_subflow[i][6], { "RFCI " #i " Flow 6 Len", "iuup.rfci."#i".flow.6", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_rfci_subflow[i][7], { "RFCI " #i " Flow 7 Len", "iuup.rfci."#i".flow.7", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}}, \
{ &hf_iuup_init_ipti[i], { "RFCI " #i " IPTI", "iuup.rfci."#i".ipti", FT_UINT8, BASE_HEX, NULL,i%2 ? 0x0F : 0xF0,"",HFILL}}



void proto_register_iuup(void) {
    static hf_register_info hf[] = {
        { &hf_iuup_direction, { "Frame Direction", "iuup.direction", FT_UINT16, BASE_DEC, NULL,0x8000,"",HFILL}},
        { &hf_iuup_circuit_id, { "Circuit ID", "iuup.circuit_id", FT_UINT16, BASE_DEC, NULL,0x7fff,"",HFILL}},
        { &hf_iuup_pdu_type, { "PDU Type", "iuup.pdu_type", FT_UINT8, BASE_DEC, VALS(iuup_pdu_types),0xf0,"",HFILL}},
        { &hf_iuup_frame_number, { "Frame Number", "iuup.framenum", FT_UINT8, BASE_DEC, NULL,0x0F,"",HFILL}},
        { &hf_iuup_fqc, { "FQC", "iuup.fqc", FT_UINT8, BASE_DEC, VALS(iuup_fqcs),0xc0,"Frame Quality Classification",HFILL}},
        { &hf_iuup_rfci, { "RFCI", "iuup.rfci", FT_UINT8, BASE_HEX, NULL, 0x3f, "RAB sub-Flow Combination Indicator",HFILL}},
        { &hf_iuup_hdr_crc, { "Header CRC", "iuup.header_crc", FT_UINT8, BASE_HEX, NULL,0xfc,"",HFILL}},        
        { &hf_iuup_hdr_crc_error, { "Header CRC [incorrect]", "iuup.header_crc", FT_UINT8, BASE_HEX, NULL,0xfc,"",HFILL}},        
        { &hf_iuup_payload_crc, { "Payload CRC", "iuup.payload_crc", FT_UINT16, BASE_HEX, NULL,0x03FF,"",HFILL}},
        { &hf_iuup_payload_crc_error, { "Payload CRC [incorrect]", "iuup.payload_crc", FT_UINT16, BASE_HEX, NULL,0x03FF,"",HFILL}},
        { &hf_iuup_ack_nack, { "Ack/Nack", "iuup.ack", FT_UINT8, BASE_DEC, VALS(iuup_acknack_vals),0x0c,"Ack/Nack",HFILL}},
        { &hf_iuup_frame_number_t14, { "Frame Number", "iuup.framenum", FT_UINT8, BASE_DEC, NULL,0x03,"",HFILL}},
        { &hf_iuup_mode_version, { "Mode Version", "iuup.mode", FT_UINT8, BASE_HEX, NULL,0xf0,"",HFILL}},
        { &hf_iuup_procedure_indicator, { "Procedure", "iuup.procedure", FT_UINT8, BASE_DEC, VALS(iuup_procedures),0x0f,"",HFILL}},
        { &hf_iuup_error_cause_val, { "Error Cause", "iuup.error_cause", FT_UINT8, BASE_DEC, VALS(iuup_error_causes),0xfc,"",HFILL}},
        { &hf_iuup_error_distance, { "Error DISTANCE", "iuup.error_distance", FT_UINT8, BASE_DEC, VALS(iuup_error_distances),0xc0,"",HFILL}},
        { &hf_iuup_errorevt_cause_val, { "Error Cause", "iuup.error_cause", FT_UINT8, BASE_DEC, NULL,0x3f,"",HFILL}},
        { &hf_iuup_time_align, { "Time Align", "iuup.time_align", FT_UINT8, BASE_HEX, NULL,0x0,"",HFILL}},
        { &hf_iuup_data_pdu_type, { "RFCI Data Pdu Type", "iuup.data_pdu_type", FT_UINT8, BASE_HEX, VALS(iuup_payload_pdu_type),0xF0,"",HFILL}},

        { &hf_iuup_spare_03, { "Spare", "iuup.spare", FT_UINT8, BASE_HEX, NULL,0x03,"",HFILL}},
        { &hf_iuup_spare_0f, { "Spare", "iuup.spare", FT_UINT8, BASE_HEX, NULL,0x0f,"",HFILL}},
        { &hf_iuup_spare_c0, { "Spare", "iuup.spare", FT_UINT8, BASE_HEX, NULL,0xc0,"",HFILL}},
        { &hf_iuup_spare_e0, { "Spare", "iuup.spare", FT_UINT8, BASE_HEX, NULL,0xe0,"",HFILL}},
        { &hf_iuup_spare_ff, { "Spare", "iuup.spare", FT_UINT8, BASE_HEX, NULL,0xff,"",HFILL}},
        { &hf_iuup_spare_bytes, { "Spare", "iuup.spare", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}},
        
        { &hf_iuup_delay, { "Delay", "iuup.delay", FT_UINT32, BASE_HEX, NULL,0x0,"",HFILL}},
        { &hf_iuup_advance, { "Advance", "iuup.advance", FT_UINT32, BASE_HEX, NULL,0x0,"",HFILL}},
        { &hf_iuup_delta, { "Delta Time", "iuup.delta", FT_FLOAT, BASE_DEC, NULL,0x0,"",HFILL}},

        { &hf_iuup_init_ti, { "TI", "iuup.ti", FT_UINT8, BASE_DEC, VALS(iuup_ti_vals),0x10,"Timing Information",HFILL}},
        { &hf_iuup_init_subflows_per_rfci, { "Subflows", "iuup.subflows", FT_UINT8, BASE_DEC, NULL,0x0e,"Number of Subflows",HFILL}},
        { &hf_iuup_init_chain_ind, { "Chain Indicator", "iuup.chain_ind", FT_UINT8, BASE_DEC, VALS(iuup_init_chain_ind_vals),0x01,"",HFILL}},
        { &hf_iuup_payload, { "Payload Data", "iuup.payload_data", FT_BYTES, BASE_HEX, NULL,0x00,"",HFILL}},


        { &hf_iuup_mode_versions, { "Iu UP Mode Versions Supported", "iuup.support_mode", FT_UINT16, BASE_HEX, NULL,0x0,"",HFILL}},
        
        { &hf_iuup_mode_versions_a[ 0], { "Version 16", "iuup.support_mode.version16", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x8000,"",HFILL}},
        { &hf_iuup_mode_versions_a[ 1], { "Version 15", "iuup.support_mode.version15", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x4000,"",HFILL}},
        { &hf_iuup_mode_versions_a[ 2], { "Version 14", "iuup.support_mode.version14", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x2000,"",HFILL}},
        { &hf_iuup_mode_versions_a[ 3], { "Version 13", "iuup.support_mode.version13", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x1000,"",HFILL}},
        { &hf_iuup_mode_versions_a[ 4], { "Version 12", "iuup.support_mode.version12", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0800,"",HFILL}},
        { &hf_iuup_mode_versions_a[ 5], { "Version 11", "iuup.support_mode.version11", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0400,"",HFILL}},
        { &hf_iuup_mode_versions_a[ 6], { "Version 10", "iuup.support_mode.version10", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0200,"",HFILL}},
        { &hf_iuup_mode_versions_a[ 7], { "Version  9", "iuup.support_mode.version9", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0100,"",HFILL}},
        { &hf_iuup_mode_versions_a[ 8], { "Version  8", "iuup.support_mode.version8", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0080,"",HFILL}},
        { &hf_iuup_mode_versions_a[ 9], { "Version  7", "iuup.support_mode.version7", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0040,"",HFILL}},
        { &hf_iuup_mode_versions_a[10], { "Version  6", "iuup.support_mode.version6", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0020,"",HFILL}},
        { &hf_iuup_mode_versions_a[11], { "Version  5", "iuup.support_mode.version5", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0010,"",HFILL}},
        { &hf_iuup_mode_versions_a[12], { "Version  4", "iuup.support_mode.version4", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0008,"",HFILL}},
        { &hf_iuup_mode_versions_a[13], { "Version  3", "iuup.support_mode.version3", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0004,"",HFILL}},
        { &hf_iuup_mode_versions_a[14], { "Version  2", "iuup.support_mode.version2", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0002,"",HFILL}},
        { &hf_iuup_mode_versions_a[15], { "Version  1", "iuup.support_mode.version1", FT_UINT16, BASE_HEX, VALS(iuup_mode_version_support),0x0001,"",HFILL}}, 

        { &hf_iuup_num_rfci_ind, { "Number of RFCI Indicators", "iuup.p", FT_UINT8, BASE_HEX, NULL,0x3f,"",HFILL}},
        { &hf_iuup_init_rfci_ind, { "RFCI Initialization", "iuup.rfci.init", FT_BYTES, BASE_HEX, NULL,0x0,"",HFILL}},

        HFS_RFCI(0),HFS_RFCI(1),HFS_RFCI(2),HFS_RFCI(3),HFS_RFCI(4),HFS_RFCI(5),HFS_RFCI(6),HFS_RFCI(7),
        HFS_RFCI(8),HFS_RFCI(9),HFS_RFCI(10),HFS_RFCI(11),HFS_RFCI(12),HFS_RFCI(13),HFS_RFCI(14),HFS_RFCI(15),
        HFS_RFCI(16),HFS_RFCI(17),HFS_RFCI(18),HFS_RFCI(19),HFS_RFCI(20),HFS_RFCI(21),HFS_RFCI(22),HFS_RFCI(23),
        HFS_RFCI(24),HFS_RFCI(25),HFS_RFCI(26),HFS_RFCI(27),HFS_RFCI(28),HFS_RFCI(29),HFS_RFCI(30),HFS_RFCI(31),
        HFS_RFCI(32),HFS_RFCI(33),HFS_RFCI(34),HFS_RFCI(35),HFS_RFCI(36),HFS_RFCI(37),HFS_RFCI(38),HFS_RFCI(39),
        HFS_RFCI(40),HFS_RFCI(41),HFS_RFCI(42),HFS_RFCI(43),HFS_RFCI(44),HFS_RFCI(45),HFS_RFCI(46),HFS_RFCI(47),
        HFS_RFCI(48),HFS_RFCI(49),HFS_RFCI(50),HFS_RFCI(51),HFS_RFCI(52),HFS_RFCI(53),HFS_RFCI(54),HFS_RFCI(55),
        HFS_RFCI(56),HFS_RFCI(57),HFS_RFCI(58),HFS_RFCI(59),HFS_RFCI(60),HFS_RFCI(61),HFS_RFCI(62),HFS_RFCI(63)
        
    };
    

    gint* ett[] = {
        &ett_iuup,
        &ett_rfci,
        &ett_ipti,
        &ett_support,
        &ett_time,
        &ett_rfciinds,
        &ett_payload,
        &ett_payload_subflows
    };

    module_t* iuup_module;

    
    proto_iuup = proto_register_protocol("IuUP", "IuUP", "iuup");
    proto_register_field_array(proto_iuup, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("iuup", dissect_iuup, proto_iuup);
    register_init_routine(&init_iuup);
    
    iuup_handle = create_dissector_handle(dissect_iuup, proto_iuup);

    iuup_module = prefs_register_protocol(proto_iuup, init_iuup);
    
    prefs_register_bool_preference(iuup_module, "dissect_payload",
                                   "Dissect IuUP Payload bits",
                                   "Whether IuUP Payload bits should be dissected",
                                   &dissect_fields);
    
    prefs_register_bool_preference(iuup_module, "two_byte_pseudoheader",
                                   "Two byte pseudoheader",
                                   "The payload contains a two byte pseudoheader indicating direction and circuit_id",
                                   &two_byte_pseudoheader);
    
    prefs_register_uint_preference(iuup_module, "dynamic.payload.type",
								   "IuUP dynamic payload type",
								   "The dynamic payload type which will be interpreted as IuUP",
								   10,
								   &temp_dynamic_payload_type);
    
    
}

