/* wireshark_flavor.c
 * Application flavor routines for Wireshark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL

#include <app/application_flavor.h>
#include <wsutil/path_config.h>

const char *application_flavor_name_proper(void)
{
    return "Wireshark";
}

const char *application_flavor_name_lower(void)
{
    return "wireshark";
}

const char* application_configuration_environment_prefix(void)
{
    return "WIRESHARK";
}

const char* application_extcap_dir(void)
{
    return EXTCAP_DIR;
}

/*
 * Return a version number string for Wireshark, including, for builds
 * from a tree checked out from Wireshark's version control system,
 * something identifying what version was checked out.
 */
const char*
application_get_vcs_version_info(void)
{
#ifdef WIRESHARK_VCS_VERSION
    return VERSION " (" WIRESHARK_VCS_VERSION ")";
#else
    return VERSION;
#endif
}

const char*
application_get_vcs_version_info_short(void)
{
#ifdef WIRESHARK_VCS_VERSION
    return WIRESHARK_VCS_VERSION;
#else
    return VERSION;
#endif
}

void application_file_extensions(const struct file_extension_info** file_extensions, unsigned* num_extensions)
{
    static const struct file_extension_info wireshark_file_type_extensions_base[] = {
            { "Wireshark/tcpdump/... - pcap", true, "pcap;cap;dmp" },
            { "Wireshark/... - pcapng", true, "pcapng;ntar" },
            { "Network Monitor, Surveyor, NetScaler", true, "cap" },
            { "Sun snoop", true, "snoop" },
            { "InfoVista 5View capture", true, "5vw" },
            { "Sniffer (DOS)", true, "cap;enc;trc;fdc;syc" },
            { "Cinco NetXRay, Sniffer (Windows)", true, "cap;caz" },
            { "Endace ERF capture", true, "erf" },
            { "EyeSDN USB S0/E1 ISDN trace format", true, "trc" },
            { "HP-UX nettl trace", true, "trc0;trc1" },
            { "Viavi Observer", true, "bfr" },
            { "Colasoft Capsa", true, "cscpkt" },
            { "Novell LANalyzer", true, "tr1" },
            { "Tektronix K12xx 32-bit .rf5 format", true, "rf5" },
            { "Savvius *Peek", true, "pkt;tpc;apc;wpz" },
            { "Catapult DCT2000 trace (.out format)", true, "out" },
            { "Micropross mplog", true, "mplog" },
            { "TamoSoft CommView NCF", true, "ncf" },
            { "TamoSoft CommView NCFX", true, "ncfx" },
            { "Symbian OS btsnoop", true, "log" },
            { "XML files (including Gammu DCT3 traces)", true, "xml" },
            { "macOS PacketLogger", true, "pklg" },
            { "Daintree SNA", true, "dcf" },
            { "IPFIX File Format", true, "pfx;ipfix" },
            { "Aethra .aps file", true, "aps" },
            { "MPEG2 transport stream", true, "mp2t;ts;m2ts;mpg" },
            { "Ixia IxVeriWave .vwr Raw 802.11 Capture", true, "vwr" },
            { "CAM Inspector file", true, "camins" },
            { "BLF file", true, "blf" },
            { "AUTOSAR DLT file", true, "dlt" },
            { "TTL file", true, "ttl" },
            { "MPEG files", false, "mpeg;mpg;mp3" },
            { "Transport-Neutral Encapsulation Format", false, "tnef" },
            { "JPEG/JFIF files", false, "jpg;jpeg;jfif" },
            { "NetLog file", true, "json" },
            { "JavaScript Object Notation file", false, "json" },
            { "JSON Log", true, "json;jsonl;log" },
            { "MP4 file", false, "mp4" },
            { "RTPDump file", false, "rtp;rtpdump" },
            { "EMS file", false, "ems" },
            { "ASN.1 Basic Encoding Rules", false, "cer;crl;csr;p10;p12;p772;p7c;p7s;p7m;p8;pfx;tsq;tsr" },
            { "RFC 7468 files", false, "crt;pem" },
            { "PEAK CAN TRC log", true, "trc" },
    };

    *file_extensions = wireshark_file_type_extensions_base;
    *num_extensions = array_length(wireshark_file_type_extensions_base);
}

const char** application_columns(void)
{
    static const char* col_fmt_packets[] = {
        "No.",         "%m",
        "Time",        "%t",
        "Source",      "%s",
        "Destination", "%d",
        "Protocol",    "%p",
        "Length",      "%L",
        "Info",        "%i"
    };

    return col_fmt_packets;
}

unsigned application_num_columns(void)
{
    return 7;
}

bool application_flavor_is_wireshark(void)
{
    return true;
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
