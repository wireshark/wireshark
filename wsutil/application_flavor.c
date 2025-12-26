/* application_flavor.c
 * Application flavor routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL

#include "application_flavor.h"
#include "path_config.h"

static enum application_flavor_e application_flavor = APPLICATION_FLAVOR_WIRESHARK;

void set_application_flavor(enum application_flavor_e flavor)
{
    application_flavor = flavor;
}

const char *application_flavor_name_proper(void) {
    switch (application_flavor) {
    case APPLICATION_FLAVOR_WIRESHARK:
        return "Wireshark";
    case APPLICATION_FLAVOR_STRATOSHARK:
        return "Stratoshark";
    default:
        ws_assert_not_reached();
    }
}

const char *application_flavor_name_lower(void) {
    switch (application_flavor) {
    case APPLICATION_FLAVOR_WIRESHARK:
        return "wireshark";
    case APPLICATION_FLAVOR_STRATOSHARK:
        return "stratoshark";
    default:
        ws_assert_not_reached();
    }
}

const char* application_configuration_environment_prefix(void)
{
    switch (application_flavor) {
    case APPLICATION_FLAVOR_WIRESHARK:
        return "WIRESHARK";
    case APPLICATION_FLAVOR_STRATOSHARK:
        return "STRATOSHARK";
    default:
        ws_assert_not_reached();
    }
}

/*
 * File types that can be identified by file extensions.
 *
 * These are used in file open dialogs to offer choices of extensions
 * for which to filter.  Note that the first field can list more than
 * one type of file, because, for example, ".cap" is a popular
 * extension used by a number of capture file types.
 *
 * File types that *don't* have a file extension used for them should
 * *not* be placed here; if there's nothing to put in the last field
 * of the structure, don't put an entry here, not even one with an
 * empty string for the extensions list.
 *
 * All added file types, regardless of extension or lack thereof,
 * must also be added open_info_base[] below.
 */
void application_file_extensions(const struct file_extension_info** file_extensions, unsigned* num_extensions)
{
    switch (application_flavor) {
    case APPLICATION_FLAVOR_WIRESHARK:
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
        break;
    }
    case APPLICATION_FLAVOR_STRATOSHARK:
    {
        static const struct file_extension_info stratoshark_file_type_extensions_base[] = {
                { "Stratoshark/... - scap", true, "scap"},
                { "JSON Log", true, "json;jsonl;log" },
                {"MS Procmon", true, "pml"},
        };

        *file_extensions = stratoshark_file_type_extensions_base;
        *num_extensions = array_length(stratoshark_file_type_extensions_base);
        break;
    }
    default:
        ws_assert_not_reached();
    }
}

const char** application_columns(void)
{
    switch (application_flavor) {
    case APPLICATION_FLAVOR_WIRESHARK:
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
    case APPLICATION_FLAVOR_STRATOSHARK:
    {
        static const char* col_fmt_logs[] = {
            "No.",              "%m",
            "Time",             "%t",
            "Event name",       "%Cus:sysdig.event_name:0:R",
            "Proc Name",        "%Cus:proc.name:0:R",
            "PID",              "%Cus:proc.pid:0:R",
            "TID",              "%Cus:thread.tid:0:R",
            "FD",               "%Cus:fd.num:0:R",
            "FD Name",          "%Cus:fd.name:0:R",
            "Container Name",   "%Cus:container.name:0:R",
            "Arguments",        "%Cus:evt.args:0:R",
            "Info",             "%i"
        };

        return col_fmt_logs;
    }
    default:
        ws_assert_not_reached();
    }
}

unsigned application_num_columns(void)
{
    switch (application_flavor) {
    case APPLICATION_FLAVOR_WIRESHARK:
        return 7;
    case APPLICATION_FLAVOR_STRATOSHARK:
        return 11;
    default:
        ws_assert_not_reached();
    }
}

bool application_flavor_is_wireshark(void)
{
    return (application_flavor == APPLICATION_FLAVOR_WIRESHARK);
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
