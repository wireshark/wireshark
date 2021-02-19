/* dccpservicecodes.h
 * Declarations of DCCP payload protocol IDs.
 *
 * Copyright 2021 by Thomas Dreibholz <dreibh [AT] simula.no>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __DCCPSERVICECODES_H__
#define __DCCPSERVICECODES_H__

/*
 * DCCP Service Codes.
 * From https://www.iana.org/assignments/service-codes/service-codes.xhtml
 * as of 2021-02-19
 *
 * Please do not put non-IANA-registered service codes here.  Put them in the
 * dissector using them instead (and consider registering them!).
 */
#define NOT_SPECIFIED_SERVICE_CODE            0
#define LTP_SERVICE_CODE                7107696
#define DISC_SERVICE_CODE            1145656131
#define RTCP_SERVICE_CODE            1381253968
#define RTPA_SERVICE_CODE            1381257281
#define RTPO_SERVICE_CODE            1381257295
#define RTPT_SERVICE_CODE            1381257300
#define RTPV_SERVICE_CODE            1381257302
#define SYLG_SERVICE_CODE            1398361159
#define BUNDLES_SERVICE_CODE         1685351985
#define NPMP_SERVICE_CODE            1852861808
#define RESERVED_SERVICE_CODE        4294967295

#endif /* dccpservicecodes.h */
