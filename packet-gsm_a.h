/* packet-gsm_a.h
 *
 * $Id: packet-gsm_a.h,v 1.1 2003/12/09 18:49:30 guy Exp $
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * this enum must be kept in-sync with 'gsm_a_pd_str'
 * it is used as an index into the array
 */
typedef enum
{
    PD_GCC = 0,
    PD_BCC,
    PD_RSVD_1,
    PD_CC,
    PD_GTTP,
    PD_MM,
    PD_RR,
    PD_UNK_1,
    PD_GMM,
    PD_SMS,
    PD_SM,
    PD_SS,
    PD_LCS,
    PD_UNK_2,
    PD_RSVD_EXT,
    PD_RSVD_TEST
}
gsm_a_pd_str_e;

typedef struct _gsm_a_tap_rec_t {
    /*
     * value from packet-bssap.h
     */
    guint8		pdu_type;
    guint8		message_type;
    gsm_a_pd_str_e	protocol_disc;
} gsm_a_tap_rec_t;


/*
 * the following allows TAP code access to the messages
 * without having to duplicate it
 */
extern const value_string gsm_a_bssmap_msg_strings[];
extern const value_string gsm_a_dtap_msg_mm_strings[];
extern const value_string gsm_a_dtap_msg_rr_strings[];
extern const value_string gsm_a_dtap_msg_cc_strings[];
extern const value_string gsm_a_dtap_msg_gmm_strings[];
extern const value_string gsm_a_dtap_msg_sms_strings[];
extern const value_string gsm_a_dtap_msg_sm_strings[];
extern const value_string gsm_a_dtap_msg_ss_strings[];

extern const gchar *gsm_a_pd_str[];
