/* capture_wpcap_packet.c
 * WinPcap-specific interfaces for low-level information (packet.dll).
 * We load WinPcap at run
 * time, so that we only need one Wireshark binary and one TShark binary
 * for Windows, regardless of whether WinPcap is installed or not.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#if defined HAVE_LIBPCAP && defined _WIN32

#include <glib.h>
#include <gmodule.h>

#include <pcap.h>

/* XXX - yes, I know, I should move cppmagic.h to a generic location. */
#include "tools/lemon/cppmagic.h"

#include <epan/value_string.h>

#include <winsock2.h>    /* Needed here to force a definition of WINVER           */
                         /* for some (all ?) Microsoft compilers newer than vc6.  */
                         /* (If windows.h were used instead, there might be       */
                         /*  issues re winsock.h included before winsock2.h )     */
#include <windowsx.h>
#include <Ntddndis.h>

#include "capture_wpcap_packet.h"
#include <wsutil/file_util.h>

/* packet32.h requires sockaddr_storage
 * whether sockaddr_storage is defined or not depends on the Platform SDK
 * version installed. The only one not defining it is the SDK that comes
 * with MSVC 6.0 (WINVER 0x0400).
 *
 * copied from RFC2553 (and slightly modified because of datatypes) ...
 * XXX - defined more than once, move this to a header file */
#ifndef WINVER
#error WINVER not defined ....
#endif
#if (WINVER <= 0x0400) && defined(_MSC_VER)
typedef unsigned short eth_sa_family_t;

/*
 * Desired design of maximum size and alignment
 */
#define ETH_SS_MAXSIZE    128  /* Implementation specific max size */
#define ETH_SS_ALIGNSIZE  (sizeof (gint64 /*int64_t*/))
                         /* Implementation specific desired alignment */
/*
 * Definitions used for sockaddr_storage structure paddings design.
 */
#define ETH_SS_PAD1SIZE   (ETH_SS_ALIGNSIZE - sizeof (eth_sa_family_t))
#define ETH_SS_PAD2SIZE   (ETH_SS_MAXSIZE - (sizeof (eth_sa_family_t) + \
                              ETH_SS_PAD1SIZE + ETH_SS_ALIGNSIZE))

struct sockaddr_storage {
    eth_sa_family_t  __ss_family;     /* address family */
    /* Following fields are implementation specific */
    char      __ss_pad1[ETH_SS_PAD1SIZE];
              /* 6 byte pad, this is to make implementation */
              /* specific pad up to alignment field that */
              /* follows explicit in the data structure */
    gint64 /*int64_t*/   __ss_align;     /* field to force desired structure */
               /* storage alignment */
    char      __ss_pad2[ETH_SS_PAD2SIZE];
              /* 112 byte pad to achieve desired size, */
              /* _SS_MAXSIZE value minus size of ss_family */
              /* __ss_pad1, __ss_align fields is 112 */
};
/* ... copied from RFC2553 */
#endif /* WINVER */

#include <Packet32.h>

gboolean has_wpacket = FALSE;


/* This module will use the PacketRequest function in packet.dll (coming with WinPcap) to "directly" access
 * the Win32 NDIS network driver(s) and ask for various values (status, statistics, ...).
 *
 * Unfortunately, the definitions required for this are not available through the usual windows header files,
 * but require the Windows "Device Driver Kit" which is not available for free :-(
 *
 * Fortunately, the definitions needed to access the various NDIS values are available from various OSS projects:
 * - WinPcap in Ntddndis.h
 * - Ndiswrapper in driver/ndis.h and driver/iw_ndis.h
 * - cygwin (MingW?) in usr/include/w32api/ddk/ndis.h and ntddndis.h
 * - FreeBSD (netperf)
 */

/* The MSDN description of the NDIS driver API is available at:
/* MSDN Home >  MSDN Library >  Win32 and COM Development >  Driver Development Kit >  Network Devices and Protocols >  Reference */
/* "NDIS Objects" */
/* http://msdn.microsoft.com/library/default.asp?url=/library/en-us/network/hh/network/21oidovw_d55042e5-0b8a-4439-8ef2-be7331e98464.xml.asp */

/* Some more interesting links:
 * http://sourceforge.net/projects/ndiswrapper/
 * http://www.osronline.com/lists_archive/windbg/thread521.html
 * http://cvs.sourceforge.net/viewcvs.py/mingw/w32api/include/ddk/ndis.h?view=markup
 * http://cvs.sourceforge.net/viewcvs.py/mingw/w32api/include/ddk/ntddndis.h?view=markup
 */



/******************************************************************************************************************************/
/* stuff to load WinPcap's packet.dll and the functions required from it */

static PCHAR     (*p_PacketGetVersion) (void);
static LPADAPTER (*p_PacketOpenAdapter) (char *adaptername);
static void      (*p_PacketCloseAdapter) (LPADAPTER);
static int       (*p_PacketRequest) (LPADAPTER, int, void *);

typedef struct {
    const char  *name;
    gpointer    *ptr;
    gboolean    optional;
} symbol_table_t;

#define SYM(x, y)   { STRINGIFY(x) , (gpointer) &CONCAT(p_,x), y }

void
wpcap_packet_load(void)
{

    /* These are the symbols I need or want from packet.dll */
    static const symbol_table_t symbols[] = {
        SYM(PacketGetVersion, FALSE),
        SYM(PacketOpenAdapter, FALSE),
        SYM(PacketCloseAdapter, FALSE),
        SYM(PacketRequest, FALSE),
        { NULL, NULL, FALSE }
    };

    GModule     *wh; /* wpcap handle */
    const symbol_table_t    *sym;

    wh = ws_module_open("packet.dll", 0);

    if (!wh) {
        return;
    }

    sym = symbols;
    while (sym->name) {
        if (!g_module_symbol(wh, sym->name, sym->ptr)) {
            if (sym->optional) {
                /*
                 * We don't care if it's missing; we just
                 * don't use it.
                 */
                *sym->ptr = NULL;
            } else {
                /*
                 * We require this symbol.
                 */
                return;
            }
        }
        sym++;
    }

    has_wpacket = TRUE;
}



/******************************************************************************************************************************/
/* functions to access the NDIS driver values */


/* get dll version */
char *
wpcap_packet_get_version(void)
{
    if(!has_wpacket) {
        return NULL;
    }
    return p_PacketGetVersion();
}


/* open the interface */
void *
wpcap_packet_open(char *if_name)
{
    LPADAPTER   adapter;

    g_assert(has_wpacket);
    adapter = p_PacketOpenAdapter(if_name);

    return adapter;
}


/* close the interface */
void
wpcap_packet_close(void *adapter)
{

    g_assert(has_wpacket);
    p_PacketCloseAdapter(adapter);
}


/* do a packet request call */
int
wpcap_packet_request(void *adapter, ULONG Oid, int set, char *value, unsigned int *length)
{
    BOOLEAN    Status;
    ULONG      IoCtlBufferLength=(sizeof(PACKET_OID_DATA) + (*length) - 1);
    PPACKET_OID_DATA  OidData;


    g_assert(has_wpacket);

    if(p_PacketRequest == NULL) {
        g_warning("packet_request not available\n");
        return 0;
    }

    /* get a buffer suitable for PacketRequest() */
    OidData=GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,IoCtlBufferLength);
    if (OidData == NULL) {
        g_warning("GlobalAllocPtr failed for %u\n", IoCtlBufferLength);
        return 0;
    }

    OidData->Oid = Oid;
    OidData->Length = *length;
    memcpy(OidData->Data, value, *length);

    Status = p_PacketRequest(adapter, set, OidData);

    if(Status) {
        if(OidData->Length <= *length) {
            /* copy value from driver */
            memcpy(value, OidData->Data, OidData->Length);
            *length = OidData->Length;
        } else {
            /* the driver returned a value that is longer than expected (and longer than the given buffer) */
            g_warning("returned oid too long, Oid: 0x%x OidLen:%u MaxLen:%u", Oid, OidData->Length, *length);
            Status = FALSE;
        }
    }

    GlobalFreePtr (OidData);

    if(Status) {
        return 1;
    } else {
        return 0;
    }
}


/* get an UINT value using the packet request call */
int
wpcap_packet_request_uint(void *adapter, ULONG Oid, UINT *value)
{
    BOOLEAN     Status;
    int         length = sizeof(UINT);


    Status = wpcap_packet_request(adapter, Oid, FALSE /* !set */, (char *) value, &length);
    if(Status && length == sizeof(UINT)) {
        return 1;
    } else {
        return 0;
    }
}


/* get an ULONG value using the NDIS packet request call */
int
wpcap_packet_request_ulong(void *adapter, ULONG Oid, ULONG *value)
{
    BOOLEAN     Status;
    int         length = sizeof(ULONG);


    Status = wpcap_packet_request(adapter, Oid, FALSE /* !set */, (char *) value, &length);
    if(Status && length == sizeof(ULONG)) {
        return 1;
    } else {
        return 0;
    }
}


#else /* HAVE_LIBPCAP && _WIN32 */

void
wpcap_packet_load(void)
{
    return;
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
