/* etw_ndiscap.c
 *
  * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
* Reads IP packets from an Windows event trace logfile or an Windows event trace live session
* and write out a pcap file with LINKTYPE_ETHERNET, LINKTYPE_RAW or LINKTYPE_IEEE802_11.
* The major code of this file is from https://github.com/microsoft/etl2pcapng with some changes by Odysseus Yang.
* The changes mainly include but not limited
*   1. calling pcapng APIs instead of writing the data in the pcapng binary format by its own implementation in etl2pcapng.
*   2. Optimize the process of adding pcapng interfaces so it doesn't need process the same Windows event trace logfile twice,
       that not only impacts the performance, but also breaks Wireshark live capture function.
*/

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <strsafe.h>
#include <winsock2.h>
#include <netiodef.h>

// inet_ipv6.h and netiodef.h define exactly the same stuff, like _IPV6_ROUTING_HEADER and IP6F_OFF_MASK.
// So wiretap/wtap.h cannot be directly included in this file. Defines below three WTAP_ENCAP types with the value in wtap.h for compile
#define WTAP_ENCAP_ETHERNET                       1
#define WTAP_ENCAP_RAW_IP                         7
#define WTAP_ENCAP_IEEE_802_11                   20

#define MAX_PACKET_SIZE 0xFFFF

// From the ndiscap manifest
#define KW_MEDIA_WIRELESS_WAN         0x200
#define KW_MEDIA_NATIVE_802_11      0x10000
#define KW_PACKET_START          0x40000000
#define KW_PACKET_END            0x80000000
#define KW_SEND                 0x100000000
#define KW_RECEIVE              0x200000000

#define tidPacketFragment            1001
#define tidPacketMetadata            1002
#define tidVMSwitchPacketFragment    1003

// From: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/windot11/ns-windot11-dot11_extsta_recv_context
#pragma pack(push,8)
typedef struct _NDIS_OBJECT_HEADER {
    unsigned char  Type;
    unsigned char  Revision;
    unsigned short Size;
} NDIS_OBJECT_HEADER, * PNDIS_OBJECT_HEADER;

typedef struct DOT11_EXTSTA_RECV_CONTEXT {
    NDIS_OBJECT_HEADER Header;
    unsigned long      uReceiveFlags;
    unsigned long      uPhyId;
    unsigned long      uChCenterFrequency;
    unsigned short     usNumberOfMPDUsReceived;
    long               lRSSI;
    unsigned char      ucDataRate;
    unsigned long      uSizeMediaSpecificInfo;
    void               *pvMediaSpecificInfo;
    unsigned long long ullTimestamp;
} DOT11_EXTSTA_RECV_CONTEXT, * PDOT11_EXTSTA_RECV_CONTEXT;
#pragma pack(pop)

// From: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/windot11/ne-windot11-_dot11_phy_type
#define DOT11_PHY_TYPE_NAMES_MAX 10
static const char* DOT11_PHY_TYPE_NAMES[] = {
    "Unknown",        // dot11_phy_type_unknown = 0
    "Fhss",           // dot11_phy_type_fhss = 1
    "Dsss",           // dot11_phy_type_dsss = 2
    "IrBaseband",     // dot11_phy_type_irbaseband = 3
    "802.11a",        // dot11_phy_type_ofdm = 4
    "802.11b",        // dot11_phy_type_hrdsss = 5
    "802.11g",        // dot11_phy_type_erp = 6
    "802.11n",        // dot11_phy_type_ht = 7
    "802.11ac",       // dot11_phy_type_vht = 8
    "802.11ad",       // dot11_phy_type_dmg = 9
    "802.11ax"        // dot11_phy_type_he = 10
};

unsigned long long NumFramesConverted;
char AuxFragBuf[MAX_PACKET_SIZE] = {0};
unsigned long AuxFragBufOffset;

DOT11_EXTSTA_RECV_CONTEXT PacketMetadata;
BOOLEAN AddWlanMetadata;

typedef struct _NDIS_NET_BUFFER_LIST_8021Q_INFO {
    union {
        struct {
            UINT32 UserPriority : 3;             // 802.1p priority
            UINT32 CanonicalFormatId : 1;        // always 0
            UINT32 VlanId : 12;                  // VLAN Identification
            UINT32 Reserved : 16;                // set to 0 for ethernet
        } TagHeader;

        struct {
            UINT32 UserPriority : 3;             // 802.1p priority
            UINT32 CanonicalFormatId : 1;        // always 0
            UINT32 VlanId : 12;                  // VLAN Identification
            UINT32 WMMInfo : 4;
            UINT32 Reserved : 12;                // set to 0 for Wireless LAN
        } WLanTagHeader;

        PVOID Value;
    };
} NDIS_NET_BUFFER_LIST_8021Q_INFO, *PNDIS_NET_BUFFER_LIST_8021Q_INFO;

// The max OOB data size might increase in the future. If it becomes larger than MaxNetBufferListInfo,
// this tool will print a warning and the value of MaxNetBufferListInfo in the code should be increased.
// From: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/nblinfo/ne-nblinfo-ndis_net_buffer_list_info
#define MaxNetBufferListInfo 200
#define Ieee8021QNetBufferListInfo 4
PBYTE OobData[MaxNetBufferListInfo];

typedef struct _VMSWITCH_SOURCE_INFO {
    unsigned long SourcePortId;
    char* SourcePortName;
    char* SourceNicName;
    char* SourceNicType;
} VMSWITCH_SOURCE_INFO, *PVMSWITCH_SOURCE_INFO;

typedef struct _VMSWITCH_PACKET_FRAGMENT {
    unsigned long SourcePortId;
    unsigned long DestinationCount;
    short VlanId;
} VMSWITCH_PACKET_FRAGMENT, *PVMSWITCH_PACKET_FRAGMENT;

BOOLEAN CurrentPacketIsVMSwitchPacketFragment;
VMSWITCH_PACKET_FRAGMENT VMSwitchPacketFragment;

struct INTERFACE {
    struct INTERFACE* Next;
    unsigned long LowerIfIndex;
    unsigned long MiniportIfIndex;
    unsigned long PcapNgIfIndex;
    int PktEncapType;
    short VlanId;

    BOOLEAN IsVMNic;
    VMSWITCH_SOURCE_INFO VMNic;
};

#define IFACE_HT_SIZE 100
struct INTERFACE* InterfaceHashTable[IFACE_HT_SIZE];
unsigned long NumInterfaces;

void wtap_etl_rec_dump(char* etl_record, ULONG total_packet_length, ULONG original_packet_length, unsigned int interface_id, BOOLEAN is_inbound, ULARGE_INTEGER timestamp, int pkt_encap, char* comment, unsigned short comment_length);
void wtap_etl_add_interface(int pkt_encap, char* interface_name, unsigned short interface_name_length, char* interface_desc, unsigned short interface_desc_length);

extern char g_err_info[FILENAME_MAX];
extern int g_err;

unsigned long HashInterface(unsigned long LowerIfIndex)
{
    if (CurrentPacketIsVMSwitchPacketFragment) {
        return VMSwitchPacketFragment.SourcePortId * (VMSwitchPacketFragment.VlanId + 1);
    } else {
        return LowerIfIndex;
    }
}

struct INTERFACE* GetInterface(unsigned long LowerIfIndex)
{
    struct INTERFACE* Iface = InterfaceHashTable[HashInterface(LowerIfIndex) % IFACE_HT_SIZE];
    while (Iface != NULL) {
        if (CurrentPacketIsVMSwitchPacketFragment) {
            if (Iface->IsVMNic &&
                Iface->LowerIfIndex == LowerIfIndex &&
                Iface->VlanId == VMSwitchPacketFragment.VlanId &&
                Iface->VMNic.SourcePortId == VMSwitchPacketFragment.SourcePortId) {
                return Iface;
            }
        } else {
            if (!Iface->IsVMNic && Iface->LowerIfIndex == LowerIfIndex && Iface->VlanId == 0) {
                return Iface;
            }
        }
        Iface = Iface->Next;
    }
    return NULL;
}

struct INTERFACE* AddInterface(PEVENT_RECORD ev, unsigned long LowerIfIndex, unsigned long MiniportIfIndex, int Type)
{
    struct INTERFACE** Iface = &InterfaceHashTable[HashInterface(LowerIfIndex) % IFACE_HT_SIZE];
    struct INTERFACE* NewIface = malloc(sizeof(struct INTERFACE));

#define IF_STRING_MAX_SIZE 128
    char IfName[IF_STRING_MAX_SIZE];
    size_t IfNameLength = 0;
    char IfDesc[IF_STRING_MAX_SIZE];
    size_t IfDescLength = 0;
    //etw pcagng interface will be 0 always, network pcagng interface will start with 1
    static PcapNgIfIndex = 1;

    if (NewIface == NULL) {
        g_err = ERROR_OUTOFMEMORY;
        sprintf_s(g_err_info, sizeof(g_err_info), "malloc failed to allocate memory for NewIface");
        exit(1);
    }

    NewIface->LowerIfIndex = LowerIfIndex;
    NewIface->MiniportIfIndex = MiniportIfIndex;
    NewIface->PktEncapType = Type;
    NewIface->VlanId = 0;
    NewIface->IsVMNic = false;

    if (CurrentPacketIsVMSwitchPacketFragment) {

        NewIface->IsVMNic = true;

        wchar_t Buffer[8192];
        PROPERTY_DATA_DESCRIPTOR Desc;
        int Err;

        // SourceNicName
        Desc.PropertyName = (unsigned long long)(L"SourceNicName");
        Desc.ArrayIndex = ULONG_MAX;
        ULONG ParamNameSize = 0;
        (void)TdhGetPropertySize(ev, 0, NULL, 1, &Desc, &ParamNameSize);
        NewIface->VMNic.SourceNicName = malloc((ParamNameSize / sizeof(wchar_t)) + 1);
        if (NewIface->VMNic.SourceNicName == NULL) {
            g_err = ERROR_OUTOFMEMORY;
            sprintf_s(g_err_info, sizeof(g_err_info), "malloc failed to allocate memory for NewIface->VMNic.SourceNicName");
            exit(1);
        }
        Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(Buffer), (PBYTE)Buffer);
        if (Err != NO_ERROR) {
            Buffer[0] = L'\0';
        }
        Buffer[ParamNameSize / sizeof(wchar_t) + 1] = L'\0';
        WideCharToMultiByte(CP_ACP,
            0,
            Buffer,
            -1,
            NewIface->VMNic.SourceNicName,
            ParamNameSize / sizeof(wchar_t) + 1,
            NULL,
            NULL);
        NewIface->VMNic.SourceNicName[wcslen(Buffer)] = '\0';

        // SourcePortName
        Desc.PropertyName = (unsigned long long)(L"SourcePortName");
        Desc.ArrayIndex = ULONG_MAX;
        (void)TdhGetPropertySize(ev, 0, NULL, 1, &Desc, &ParamNameSize);
        NewIface->VMNic.SourcePortName = malloc((ParamNameSize / sizeof(wchar_t)) + 1);
        if (NewIface->VMNic.SourcePortName == NULL) {
            g_err = ERROR_OUTOFMEMORY;
            sprintf_s(g_err_info, sizeof(g_err_info), "malloc failed to allocate memory for NewIface->VMNic.SourcePortName");
            exit(1);
        }
        Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(Buffer), (PBYTE)Buffer);
        if (Err != NO_ERROR) {
            Buffer[0] = L'\0';
        }
        Buffer[ParamNameSize / sizeof(wchar_t) + 1] = L'\0';
        WideCharToMultiByte(CP_ACP,
            0,
            Buffer,
            -1,
            NewIface->VMNic.SourcePortName,
            ParamNameSize / sizeof(wchar_t) + 1,
            NULL,
            NULL);
        NewIface->VMNic.SourcePortName[wcslen(Buffer)] = '\0';

        // SourceNicType
        Desc.PropertyName = (unsigned long long)(L"SourceNicType");
        Desc.ArrayIndex = ULONG_MAX;
        (void)TdhGetPropertySize(ev, 0, NULL, 1, &Desc, &ParamNameSize);
        NewIface->VMNic.SourceNicType = malloc((ParamNameSize / sizeof(wchar_t)) + 1);
        if (NewIface->VMNic.SourceNicType == NULL) {
            g_err = ERROR_OUTOFMEMORY;
            sprintf_s(g_err_info, sizeof(g_err_info), "malloc failed to allocate memory for NewIface->VMNic.SourceNicType");
            exit(1);
        }
        Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(Buffer), (PBYTE)Buffer);
        if (Err != NO_ERROR) {
            Buffer[0] = L'\0';
        }
        Buffer[ParamNameSize / sizeof(wchar_t) + 1] = L'\0';
        WideCharToMultiByte(CP_ACP,
            0,
            Buffer,
            -1,
            NewIface->VMNic.SourceNicType,
            ParamNameSize / sizeof(wchar_t) + 1,
            NULL,
            NULL);
        NewIface->VMNic.SourceNicType[wcslen(Buffer)] = '\0';


        NewIface->VMNic.SourcePortId = VMSwitchPacketFragment.SourcePortId;
        NewIface->VlanId = VMSwitchPacketFragment.VlanId;
    }

    NewIface->Next = *Iface;

    *Iface = NewIface;
    NumInterfaces++;

    NewIface->PcapNgIfIndex = PcapNgIfIndex;
    PcapNgIfIndex++;
    memset(IfName, 0, sizeof(IfName));
    memset(IfDesc, 0, sizeof(IfDesc));
    switch (NewIface->PktEncapType) {
    case WTAP_ENCAP_ETHERNET:
        if (NewIface->IsVMNic) {
            printf("IF: medium=%s\tID=%lu\tIfIndex=%lu\tVlanID=%i",
                NewIface->VMNic.SourceNicType,
                NewIface->PcapNgIfIndex,
                NewIface->VMNic.SourcePortId,
                NewIface->VlanId
            );
            StringCchPrintfA(
                IfName,
                IF_STRING_MAX_SIZE,
                "%s:%s:%lu:%i",
                NewIface->VMNic.SourcePortName,
                NewIface->VMNic.SourceNicType,
                NewIface->VMNic.SourcePortId,
                NewIface->VlanId
            );
        }
        else {
            printf("IF: medium=eth\tID=%u\tIfIndex=%u\tVlanID=%i", NewIface->PcapNgIfIndex, NewIface->LowerIfIndex, NewIface->VlanId);
            StringCchPrintfA(IfName, IF_STRING_MAX_SIZE, "eth:%lu:%i", NewIface->LowerIfIndex, NewIface->VlanId);
        }
        break;
    case WTAP_ENCAP_IEEE_802_11:
        printf("IF: medium=wifi ID=%lu\tIfIndex=%lu", NewIface->PcapNgIfIndex, NewIface->LowerIfIndex);
        StringCchPrintfA(IfName, IF_STRING_MAX_SIZE, "wifi:%lu", NewIface->LowerIfIndex);
        break;
    case WTAP_ENCAP_RAW_IP:
        printf("IF: medium=mbb  ID=%lu\tIfIndex=%lu", NewIface->PcapNgIfIndex, NewIface->LowerIfIndex);
        StringCchPrintfA(IfName, IF_STRING_MAX_SIZE, "mbb:%lu", NewIface->LowerIfIndex);
        break;
    }
    StringCchLengthA(IfName, IF_STRING_MAX_SIZE, &IfNameLength);

    if (NewIface->LowerIfIndex != NewIface->MiniportIfIndex) {
        printf("\t(LWF over IfIndex %lu)", NewIface->MiniportIfIndex);
        StringCchPrintfA(IfDesc, IF_STRING_MAX_SIZE, "LWF over IfIndex %lu", NewIface->MiniportIfIndex);
        StringCchLengthA(IfDesc, IF_STRING_MAX_SIZE, &IfDescLength);
    }

    if (NewIface->VlanId != 0) {
        StringCchPrintfA(IfDesc + IfDescLength, IF_STRING_MAX_SIZE, " VlanID=%i ", NewIface->VlanId);
        StringCchLengthA(IfDesc, IF_STRING_MAX_SIZE, &IfDescLength);
    }

    printf("\n");

    wtap_etl_add_interface(NewIface->PktEncapType, IfName, (unsigned short)IfNameLength, IfDesc, (unsigned short)IfDescLength);
    return NewIface;
}

void ParseVmSwitchPacketFragment(PEVENT_RECORD ev)
{
    // Parse the current VMSwitch packet event for use elsewhere.
    // NB: Here we only do per-packet parsing. For any event fields that only need to be
    // parsed once and written into an INTERFACE, we do the parsing in AddInterface.

    PROPERTY_DATA_DESCRIPTOR Desc;
    int Err;
    PNDIS_NET_BUFFER_LIST_8021Q_INFO pNblVlanInfo;

    // Get VLAN from OOB
    unsigned long OobLength;
    Desc.PropertyName = (unsigned long long)L"OOBDataSize";
    Desc.ArrayIndex = ULONG_MAX;
    Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(OobLength), (PBYTE)&OobLength);
    if (Err != NO_ERROR) {
        g_err = Err;
        sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty OobLength failed, err is 0x%x", Err);
        return;
    }

    if (OobLength > sizeof(OobData)) {
        g_err = ERROR_INVALID_DATA;
        sprintf_s(g_err_info, sizeof(g_err_info), "OOB data of %lu bytes too large to fit in hardcoded buffer of size %lu", OobLength, (unsigned long)sizeof(OobData));
        return;
    }

    Desc.PropertyName = (unsigned long long)L"OOBData";
    Desc.ArrayIndex = ULONG_MAX;
    Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, OobLength, (PBYTE)&OobData);
    if (Err != NO_ERROR) {
        g_err = Err;
        sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty OobData failed, err is 0x%x", Err);
        return;
    }

    pNblVlanInfo = (PNDIS_NET_BUFFER_LIST_8021Q_INFO)&OobData[Ieee8021QNetBufferListInfo];
    VMSwitchPacketFragment.VlanId = pNblVlanInfo->TagHeader.VlanId;

    // SourcePortId
    Desc.PropertyName = (unsigned long long)L"SourcePortId";
    Desc.ArrayIndex = ULONG_MAX;
    Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(VMSwitchPacketFragment.SourcePortId), (PBYTE)&VMSwitchPacketFragment.SourcePortId);
    if (Err != NO_ERROR) {
        g_err = Err;
        sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty SourcePortId failed, err is 0x%x", Err);
        return;
    }

    // DestinationCount
    Desc.PropertyName = (unsigned long long)L"DestinationCount";
    Desc.ArrayIndex = ULONG_MAX;
    Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(VMSwitchPacketFragment.DestinationCount), (PBYTE)&VMSwitchPacketFragment.DestinationCount);
    if (Err != NO_ERROR) {
        g_err = Err;
        sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty DestinationCount failed, err is 0x%x", Err);
        return;
    }
}

void etw_dump_write_ndiscap_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    int Err;
    unsigned long LowerIfIndex;

    struct INTERFACE* Iface;
    unsigned long FragLength;
    PROPERTY_DATA_DESCRIPTOR Desc;
    int Type;
    unsigned long TotalFragmentLength;
    unsigned long InferredOriginalFragmentLength = 0;
    PETHERNET_HEADER EthHdr;
    PIPV4_HEADER Ipv4Hdr;
    PIPV6_HEADER Ipv6Hdr;

    if ((ev->EventHeader.EventDescriptor.Id != tidPacketFragment &&
         ev->EventHeader.EventDescriptor.Id != tidPacketMetadata &&
         ev->EventHeader.EventDescriptor.Id != tidVMSwitchPacketFragment)) {
        return;
    }

    CurrentPacketIsVMSwitchPacketFragment = (ev->EventHeader.EventDescriptor.Id == tidVMSwitchPacketFragment);
    if (CurrentPacketIsVMSwitchPacketFragment) {
        ParseVmSwitchPacketFragment(ev);
    }

    Desc.PropertyName = (unsigned long long)L"LowerIfIndex";
    Desc.ArrayIndex = ULONG_MAX;
    Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(LowerIfIndex), (PBYTE)&LowerIfIndex);
    if (Err != NO_ERROR) {
        g_err = Err;
        sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty LowerIfIndex failed, err is 0x%x", Err);
        return;
    }

    Iface = GetInterface(LowerIfIndex);

    if (!!(ev->EventHeader.EventDescriptor.Keyword & KW_MEDIA_NATIVE_802_11)) {
        Type = WTAP_ENCAP_IEEE_802_11;
    } else if (!!(ev->EventHeader.EventDescriptor.Keyword & KW_MEDIA_WIRELESS_WAN)) {
        Type = WTAP_ENCAP_RAW_IP;
    } else {
        Type = WTAP_ENCAP_ETHERNET;
    }

    // Record the IfIndex if it's a new one.
    if (Iface == NULL) {
        unsigned long MiniportIfIndex;
        Desc.PropertyName = (unsigned long long)L"MiniportIfIndex";
        Desc.ArrayIndex = ULONG_MAX;
        Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(MiniportIfIndex), (PBYTE)&MiniportIfIndex);
        if (Err != NO_ERROR) {
            g_err = Err;
            sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty MiniportIfIndex failed, err is 0x%x", Err);
            return;
        }
        Iface = AddInterface(
            ev,
            LowerIfIndex,
            MiniportIfIndex,
            Type
        );
    } else if (Iface->PktEncapType != Type) {
        printf("WARNING: inconsistent media type in packet events!\n");
    }

    if (Iface == NULL) {
        // We generated the list of interfaces directly from the
        // packet traces themselves, so there must be a bug.
        g_err = ERROR_INVALID_DATA;
        sprintf_s(g_err_info, sizeof(g_err_info), "Packet with unrecognized IfIndex");
        exit(1);
    }

    // Save off Ndis/Wlan metadata to be added to the next packet
    if (ev->EventHeader.EventDescriptor.Id == tidPacketMetadata) {
        unsigned long MetadataLength = 0;
        Desc.PropertyName = (unsigned long long)L"MetadataSize";
        Desc.ArrayIndex = ULONG_MAX;
        Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(MetadataLength), (PBYTE)&MetadataLength);
        if (Err != NO_ERROR) {
            g_err = Err;
            sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty MetadataSize failed, err is 0x%x", Err);
            return;
        }

        if (MetadataLength != sizeof(PacketMetadata)) {
            g_err = ERROR_INVALID_DATA;
            sprintf_s(g_err_info, sizeof(g_err_info), "Unknown Metadata length. Expected %lu, got %lu", (unsigned long)sizeof(DOT11_EXTSTA_RECV_CONTEXT), MetadataLength);
            return;
        }

        Desc.PropertyName = (unsigned long long)L"Metadata";
        Desc.ArrayIndex = ULONG_MAX;
        Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, MetadataLength, (PBYTE)&PacketMetadata);
        if (Err != NO_ERROR) {
            g_err = Err;
            sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty Metadata failed, err is 0x%x", Err);
            return;
        }

        AddWlanMetadata = true;
        return;
    }

    // N.B.: Here we are querying the FragmentSize property to get the
    // total size of the packet, and then reading that many bytes from
    // the Fragment property. This is unorthodox (normally you are
    // supposed to use TdhGetPropertySize to get the size of a property)
    // but required due to the way ndiscap puts packet contents in
    // multiple adjacent properties (which happen to be contiguous in
    // memory).

    Desc.PropertyName = (unsigned long long)L"FragmentSize";
    Desc.ArrayIndex = ULONG_MAX;
    Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, sizeof(FragLength), (PBYTE)&FragLength);
    if (Err != NO_ERROR) {
        g_err = Err;
        sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty FragmentSize failed, err is 0x%x", Err);
        return;
    }

    if (FragLength > RTL_NUMBER_OF(AuxFragBuf) - AuxFragBufOffset) {
        g_err = ERROR_INVALID_DATA;
        sprintf_s(g_err_info, sizeof(g_err_info), "Packet too large (size = %u) and skipped", AuxFragBufOffset + FragLength);
        return;
    }

    Desc.PropertyName = (unsigned long long)L"Fragment";
    Desc.ArrayIndex = ULONG_MAX;
    Err = TdhGetProperty(ev, 0, NULL, 1, &Desc, FragLength, (PBYTE)(AuxFragBuf + AuxFragBufOffset));
    if (Err != NO_ERROR) {
        g_err = Err;
        sprintf_s(g_err_info, sizeof(g_err_info), "TdhGetProperty Fragment failed, err is 0x%x", Err);
        return;
    }

    // The KW_PACKET_START and KW_PACKET_END keywords are used as follows:
    // -A single-event packet has both KW_PACKET_START and KW_PACKET_END.
    // -A multi-event packet consists of an event with KW_PACKET_START followed
    //  by an event with KW_PACKET_END, with zero or more events with neither
    //  keyword in between.
    //
    // So, we accumulate fragments in AuxFragBuf until KW_PACKET_END is
    // encountered, then call PcapNgWriteEnhancedPacket and start over. There's
    // no need for us to even look for KW_PACKET_START.
    //
    // NB: Starting with Windows 8.1, only single-event packets are traced.
    // This logic is here to support packet captures from older systems.

    if (!!(ev->EventHeader.EventDescriptor.Keyword & KW_PACKET_END)) {

        if (ev->EventHeader.EventDescriptor.Keyword & KW_MEDIA_NATIVE_802_11 &&
            AuxFragBuf[1] & 0x40) {
            // Clear Protected bit in the case of 802.11
            // Ndis captures will be decrypted in the etl file

            AuxFragBuf[1] = AuxFragBuf[1] & 0xBF; // _1011_1111_ - Clear "Protected Flag"
        }

        // COMMENT_MAX_SIZE must be multiple of 4
        #define COMMENT_MAX_SIZE 256
        char Comment[COMMENT_MAX_SIZE] = { 0 };
        size_t CommentLength = 0;

        if (AddWlanMetadata) {
            if (PacketMetadata.uPhyId > DOT11_PHY_TYPE_NAMES_MAX) {
                PacketMetadata.uPhyId = 0; // Set to unknown if outside known bounds.
            }

            Err = StringCchPrintfA(Comment, COMMENT_MAX_SIZE, "PID=%d ProcessorNumber=%d Packet Metadata: ReceiveFlags:0x%x, PhyType:%s, CenterCh:%u, NumMPDUsReceived:%u, RSSI:%d, DataRate:%u",
                ev->EventHeader.ProcessId,
                ev->BufferContext.ProcessorNumber,
                PacketMetadata.uReceiveFlags,
                DOT11_PHY_TYPE_NAMES[PacketMetadata.uPhyId],
                PacketMetadata.uChCenterFrequency,
                PacketMetadata.usNumberOfMPDUsReceived,
                PacketMetadata.lRSSI,
                PacketMetadata.ucDataRate);

            AddWlanMetadata = false;
            memset(&PacketMetadata, 0, sizeof(DOT11_EXTSTA_RECV_CONTEXT));
        } else if (CurrentPacketIsVMSwitchPacketFragment) {
            if (VMSwitchPacketFragment.DestinationCount > 0) {
                Err = StringCchPrintfA(Comment, COMMENT_MAX_SIZE, "PID=%d ProcessorNumber=%d VlanId=%d SrcPortId=%d SrcNicType=%s SrcNicName=%s SrcPortName=%s DstNicCount=%d",
                    ev->EventHeader.ProcessId,
                    ev->BufferContext.ProcessorNumber,
                    Iface->VlanId,
                    Iface->VMNic.SourcePortId,
                    Iface->VMNic.SourceNicType,
                    Iface->VMNic.SourceNicName,
                    Iface->VMNic.SourcePortName,
                    VMSwitchPacketFragment.DestinationCount
                );
            } else {
                Err = StringCchPrintfA(Comment, COMMENT_MAX_SIZE, "PID=%d ProcessorNumber=%d VlanId=%d SrcPortId=%d SrcNicType=%s SrcNicName=%s SrcPortName=%s",
                    ev->EventHeader.ProcessId,
                    ev->BufferContext.ProcessorNumber,
                    Iface->VlanId,
                    Iface->VMNic.SourcePortId,
                    Iface->VMNic.SourceNicType,
                    Iface->VMNic.SourceNicName,
                    Iface->VMNic.SourcePortName
                    );
            }
        } else {
            Err = StringCchPrintfA(Comment, COMMENT_MAX_SIZE, "PID=%d ProcessorNumber=%d", ev->EventHeader.ProcessId, ev->BufferContext.ProcessorNumber);
        }

        if (Err != NO_ERROR) {
            printf("Failed converting comment to string with error: %d\n", Err);
        } else {
            Err = StringCchLengthA(Comment, COMMENT_MAX_SIZE, &CommentLength);

            if (Err != NO_ERROR) {
                printf("Failed getting length of comment string with error: %d\n", Err);
                CommentLength = 0;
                memset(Comment, 0, COMMENT_MAX_SIZE);
            }
        }

        TotalFragmentLength = AuxFragBufOffset + FragLength;

        // Parse the packet to see if it's truncated. If so, try to recover the original length.
        if (Type == WTAP_ENCAP_ETHERNET) {
            if (TotalFragmentLength >= sizeof(ETHERNET_HEADER)) {
                EthHdr = (PETHERNET_HEADER)AuxFragBuf;
                if (ntohs(EthHdr->Type) == ETHERNET_TYPE_IPV4 &&
                    TotalFragmentLength >= sizeof(IPV4_HEADER) + sizeof(ETHERNET_HEADER)) {
                    Ipv4Hdr = (PIPV4_HEADER)(EthHdr + 1);
                    InferredOriginalFragmentLength = ntohs(Ipv4Hdr->TotalLength) + sizeof(ETHERNET_HEADER);
                } else if (ntohs(EthHdr->Type) == ETHERNET_TYPE_IPV6 &&
                           TotalFragmentLength >= sizeof(IPV6_HEADER) + sizeof(ETHERNET_HEADER)) {
                    Ipv6Hdr = (PIPV6_HEADER)(EthHdr + 1);
                    InferredOriginalFragmentLength = ntohs(Ipv6Hdr->PayloadLength) + sizeof(IPV6_HEADER) + sizeof(ETHERNET_HEADER);
                }
            }
        } else if (Type == WTAP_ENCAP_RAW_IP) {
            // Raw frames begins with an IPv4/6 header.
            if (TotalFragmentLength >= sizeof(IPV4_HEADER)) {
                Ipv4Hdr = (PIPV4_HEADER)AuxFragBuf;
                if (Ipv4Hdr->Version == 4) {
                    InferredOriginalFragmentLength = ntohs(Ipv4Hdr->TotalLength) + sizeof(ETHERNET_HEADER);
                } else if (Ipv4Hdr->Version == 6) {
                    Ipv6Hdr = (PIPV6_HEADER)(AuxFragBuf);
                    InferredOriginalFragmentLength = ntohs(Ipv6Hdr->PayloadLength) + sizeof(IPV6_HEADER) + sizeof(ETHERNET_HEADER);
                }
            }
        }

        wtap_etl_rec_dump(AuxFragBuf,
            TotalFragmentLength,
            // For LSO v2 packets, inferred original fragment length is ignored since length field in IP header is not filled.
            InferredOriginalFragmentLength <= TotalFragmentLength ? TotalFragmentLength : InferredOriginalFragmentLength,
            Iface->PcapNgIfIndex,
            !(ev->EventHeader.EventDescriptor.Keyword & KW_SEND),
            timestamp,
            Type,
            Comment,
            (unsigned short)CommentLength
            );

        AuxFragBufOffset = 0;
        NumFramesConverted++;
    } else {
        AuxFragBufOffset += FragLength;
    }
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
