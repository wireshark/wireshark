/* packet-sip-hdrs.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_SIP_HDRS_H__
#define __PACKET_SIP_HDRS_H__

/*
 * ########################### HOWTO ###########################
 * In order to add new header for sip do:
 *
 * 1/ add your-header, POS_FOO_BAR to packet-sip-hdrs.gperf
 * 2/ add below #define POS_FOO_BAR next_value
 * 3/ update hf_header_array[] in packet-sip.c
 * 4/ run gperf -m 500 -D packet-sip-hdrs.gperf > packet-sip-hdrs.c
 * #############################################################
 */

/* from RFC 3261
 * Updated with info from http://www.iana.org/assignments/sip-parameters
 * (last updated 2009-11-11)
 * Updated with: http://www.ietf.org/internet-drafts/draft-ietf-sip-resource-priority-05.txt
 */

#define POS_ACCEPT                       1
#define POS_ACCEPT_CONTACT               2 /* RFC3841  */
#define POS_ACCEPT_ENCODING              3
#define POS_ACCEPT_LANGUAGE              4
#define POS_ACCEPT_RESOURCE_PRIORITY     5 /* RFC4412 */
#define POS_ALERT_INFO                   6
#define POS_ALLOW                        7
#define POS_ALLOW_EVENTS                 8 /* RFC3265  */
#define POS_ANSWER_MODE                  9 /* RFC5373 */
#define POS_AUTHENTICATION_INFO         10
#define POS_AUTHORIZATION               11
#define POS_CALL_ID                     12
#define POS_CALL_INFO                   13
#define POS_CONTACT                     14
#define POS_CONTENT_DISPOSITION         15
#define POS_CONTENT_ENCODING            16
#define POS_CONTENT_LANGUAGE            17
#define POS_CONTENT_LENGTH              18
#define POS_CONTENT_TYPE                19
#define POS_CSEQ                        20
#define POS_DATE                        21
#define POS_ERROR_INFO                  22
#define POS_EVENT                       23
#define POS_EXPIRES                     24
#define POS_FEATURE_CAPS                25  /* [RFC6809 */
#define POS_FLOW_TIMER                  26  /* RFC5626  */
#define POS_FROM                        27
#define POS_GEOLOCATION                 28
#define POS_GEOLOCATION_ERROR           29
#define POS_GEOLOCATION_ROUTING         30
#define POS_HISTORY_INFO                31  /* RFC4244  */
#define POS_IDENTITY                    32  /* RFC4474  */
#define POS_IDENTITY_INFO               33  /* RFC4474  */
#define POS_INFO_PKG                    34  /* RFC-ietf-sipcore-info-events-10.txt  */
#define POS_IN_REPLY_TO                 35  /* RFC3261  */
#define POS_JOIN                        36  /* RFC3911  */
#define POS_MAX_BREADTH                 37  /* RFC5393*/
#define POS_MAX_FORWARDS                38
#define POS_MIME_VERSION                39
#define POS_MIN_EXPIRES                 40
#define POS_MIN_SE                      41  /* RFC4028  */
#define POS_ORGANIZATION                42  /* RFC3261  */
#define POS_P_ACCESS_NETWORK_INFO       43  /* RFC3455  */
#define POS_P_ANSWER_STATE              44  /* RFC4964  */
#define POS_P_ASSERTED_IDENTITY         45  /* RFC3325  */
#define POS_P_ASSERTED_SERV             46  /* RFC6050  */
#define POS_P_ASSOCIATED_URI            47  /* RFC3455  */
#define POS_P_CALLED_PARTY_ID           48  /* RFC3455  */
#define POS_P_CHARGING_FUNC_ADDRESSES   49  /* RFC3455  */
#define POS_P_CHARGING_VECTOR           50  /* RFC3455  */
#define POS_P_DCS_TRACE_PARTY_ID        51  /* RFC5503  */
#define POS_P_DCS_OSPS                  52  /* RFC5503  */
#define POS_P_DCS_BILLING_INFO          53  /* RFC5503  */
#define POS_P_DCS_LAES                  54  /* RFC5503  */
#define POS_P_DCS_REDIRECT              55  /* RFC5503  */
#define POS_P_EARLY_MEDIA               56  /* RFC5009  */
#define POS_P_MEDIA_AUTHORIZATION       57  /* RFC3313  */
#define POS_P_PREFERRED_IDENTITY        58  /* RFC3325  */
#define POS_P_PREFERRED_SERV            59  /* RFC6050  */
#define POS_P_PROFILE_KEY               60  /* RFC5002  */
#define POS_P_REFUSED_URI_LST           61  /* RFC5318  */
#define POS_P_SERVED_USER               62  /* RFC5502  */
#define POS_P_USER_DATABASE             63  /* RFC4457  */
#define POS_P_VISITED_NETWORK_ID        64  /* RFC3455  */
#define POS_PATH                        65  /* RFC3327  */
#define POS_PERMISSION_MISSING          66  /* RFC5360  */
#define POS_POLICY_CONTACT              67  /* RFC3261  */
#define POS_POLICY_ID                   68  /* RFC3261  */
#define POS_PRIORITY                    69  /* RFC3261  */
#define POS_PRIV_ANSWER_MODE            70  /* RFC5373  */
#define POS_PRIVACY                     71  /* RFC3323  */
#define POS_PROXY_AUTHENTICATE          72
#define POS_PROXY_AUTHORIZATION         73
#define POS_PROXY_REQUIRE               74
#define POS_RACK                        75  /* RFC3262  */
#define POS_REASON                      76  /* RFC3326  */
#define POS_REASON_PHRASE               77  /* RFC3326  */
#define POS_RECORD_ROUTE                78
#define POS_RECV_INFO                   79  /* RFC-ietf-sipcore-info-events-10.txt*/
#define POS_REFER_SUB                   80  /* RFC4488  */
#define POS_REFER_TO                    81  /* RFC3515  */
#define POS_REFERED_BY                  82  /* RFC3892  */
#define POS_REJECT_CONTACT              83  /* RFC3841  */
#define POS_REPLACES                    84  /* RFC3891  */
#define POS_REPLY_TO                    85  /* RFC3261  */
#define POS_REQUEST_DISPOSITION         86  /* RFC3841  */
#define POS_REQUIRE                     87  /* RFC3261  */
#define POS_RESOURCE_PRIORITY           88  /* RFC4412  */
#define POS_RETRY_AFTER                 89  /* RFC3261  */
#define POS_ROUTE                       90  /* RFC3261  */
#define POS_RSEQ                        91  /* RFC3262  */
#define POS_SECURITY_CLIENT             92  /* RFC3329  */
#define POS_SECURITY_SERVER             93  /* RFC3329  */
#define POS_SECURITY_VERIFY             94  /* RFC3329  */
#define POS_SERVER                      95  /* RFC3261  */
#define POS_SERVICE_ROUTE               96  /* RFC3608  */
#define POS_SESSION_EXPIRES             97  /* RFC4028  */
#define POS_SIP_ETAG                    98  /* RFC3903  */
#define POS_SIP_IF_MATCH                99  /* RFC3903  */
#define POS_SUBJECT                     100  /* RFC3261  */
#define POS_SUBSCRIPTION_STATE          101  /* RFC3265  */
#define POS_SUPPORTED                   102  /* RFC3261  */
#define POS_SUPPRESS_IF_MATCH           103  /* RFC5839  */
#define POS_TARGET_DIALOG               104  /* RFC4538  */
#define POS_TIMESTAMP                   105  /* RFC3261  */
#define POS_TO                          106  /* RFC3261  */
#define POS_TRIGGER_CONSENT             107  /* RFC5360  */
#define POS_UNSUPPORTED                 108  /* RFC3261  */
#define POS_USER_AGENT                  109  /* RFC3261  */
#define POS_VIA                         110  /* RFC3261  */
#define POS_WARNING                     111  /* RFC3261  */
#define POS_WWW_AUTHENTICATE            112  /* RFC3261  */
#define POS_DIVERSION                   113  /* RFC5806  */
#define POS_USER_TO_USER                114  /* draft-johnston-sipping-cc-uui-09  */

/* Encryption (Deprecated)       [RFC3261] */
/* Hide                          [RFC3261] (deprecated)*/
/* Response-Key (Deprecated)     [RFC3261] */

extern int sip_is_known_sip_header(const char *header_name, unsigned int header_len);

#endif /* __PACKET_SIP_HDRS_H__ */
