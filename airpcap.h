/*
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#if !defined(AIRPCAP_H__EAE405F5_0171_9592_B3C2_C19EC426AD34__INCLUDED_)
#define AIRPCAP_H__EAE405F5_0171_9592_B3C2_C19EC426AD34__INCLUDED_

/* This disables a VS warning for zero-sized arrays. All the compilers we support have that feature */
#pragma warning( disable : 4200)

#ifdef __cplusplus
extern "C" {
#endif

/*!
	\mainpage AirPcap interface documentation

	\section Introduction

	This document describes the data structures and the functions exported by the CACE Technologies AirPcap library.
	The AirPcap library provides low-level access to the AirPcap driver including advanced capabilities such as channel setting,
	link type control and WEP configuration.<br>
	This manual includes the following sections:

	\note throughout this documentation, \i device refers to a physical USB AirPcap device, wile \i adapter is an open API
	instance. Most of the AirPcap API operations are adapter-specific but some of them, like setting the channel, are
	per-device and will be reflected on all the open adapters. These functions will have "Device" in their name, e.g.
	AirpcapSetDeviceChannel().

	\b Sections:

	- \ref airpcapfuncs
	- \ref airpcapdefs
	- \ref radiotap
*/

/** @defgroup airpcapdefs AirPcap definitions and data structures
 *  @{
 */

/*!
  \brief This string is the fixed prefix in the airpcap adapter name.
  It can be used to parse the name field in an AirpcapDeviceDescription structure.
*/
#define AIRPCAP_DEVICE_NAME_PREFIX "\\\\.\\airpcap"

/*!
  \brief This string is the scanf modifier to extract the adapter number from an adapter name.
  It can be used to parse the name field in an AirpcapDeviceDescription structure with scanf.
*/
#define AIRPCAP_DEVICE_NUMBER_EXTRACT_STRING "\\\\.\\airpcap%u"

/*!
  \brief This string is the scanf modifier to extract the adapter "Any" string from an adapter name.
  It can be used to parse the name field in an AirpcapDeviceDescription structure with scanf.
*/
#define AIRPCAP_DEVICE_ANY_EXTRACT_STRING "\\\\.\\airpcap_any"

/*!
  \brief Entry in the list returned by \ref AirpcapGetDeviceList();
*/
typedef struct _AirpcapDeviceDescription
{
	struct	_AirpcapDeviceDescription *next;			/* Next element in the list */
	PCHAR	Name;										/* Device name */
	PCHAR	Description;								/* Device description */
} AirpcapDeviceDescription, *PAirpcapDeviceDescription;


#ifndef __MINGW32__
#pragma pack(push)
#pragma pack(1)
#endif /* __MINGW32__ */


#define AIRPCAP_KEYTYPE_WEP		0	/* Key type: WEP. The key can have an arbitrary length smaller than 32 bytes. */
#define AIRPCAP_KEYTYPE_TKIP	1	/* Key type: TKIP (WPA_PWD). NOT SUPPORTED YET. */
#define AIRPCAP_KEYTYPE_CCMP	2	/* Key type: CCMP (WPA_BIN). NOT SUPPORTED YET. */

/*!
  \brief WEP key container
*/
typedef struct _AirpcapKey
{
	UINT KeyType;						/* Type of key, can be on of: \ref AIRPCAP_KEYTYPE_WEP, \ref AIRPCAP_KEYTYPE_TKIP, \ref AIRPCAP_KEYTYPE_CCMP. Only AIRPCAP_KEYTYPE_WEP is supported by the driver at the moment. */
	UINT KeyLen;						/* Length of the key, in bytes */
	BYTE KeyData[WEP_KEY_MAX_SIZE];		/* Key Data */
}
#ifdef __MINGW32__
__attribute__((__packed__))
#endif /* __MINGW32__ */
AirpcapKey, *PAirpcapKey;

/*!
  \brief Type of frame validation the adapter performs.
   An adapter can be instructed to accept different kind of frames: correct frames only, frames with wrong Frame Check Sequence (FCS) only, all frames.
*/
typedef enum _AirpcapValidationType
{
    AIRPCAP_VT_ACCEPT_EVERYTHING = 1,		/* Accept all the frames the device captures */
    AIRPCAP_VT_ACCEPT_CORRECT_FRAMES = 2,	/* Accept correct frames only, i.e. frames with correct Frame Check Sequence (FCS). */
    AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES = 3,	/* Accept corrupt frames only, i.e. frames with worng Frame Check Sequence (FCS). */
	AIRPCAP_VT_UNKNOWN = 4					/* Unknown validation type. You should see it only in case of error. */
}AirpcapValidationType, *PAirpcapValidationType;

/*!
  \brief Type of decryption the adapter performs.
   An adapter can be instructed to turn decryption (based on the device-configured keys configured
   with \ref AirpcapSetDeviceKeys()) on or off.
*/
typedef enum _AirpcapDecryptionState
{
    AIRPCAP_DECRYPTION_ON = 1,				/* This adapter performs decryption */
    AIRPCAP_DECRYPTION_OFF = 2				/* This adapter does not perform decryption */
}AirpcapDecryptionState, *PAirpcapDecryptionState;


/*!
  \brief Storage for a MAC address
*/
typedef struct _AirpcapMacAddress
{
	BYTE Address[6];		/* MAC address bytes */
}
#ifdef __MINGW32__
__attribute__((__packed__))
#endif /* __MINGW32__ */
AirpcapMacAddress, *PAirpcapMacAddress;

/*!
  \brief This structure is used to store a collection of WEP keys.
  Note that the definition of the structure doesn't contain any key, so be careful to allocate a buffer
  with the size of the key, like in the following example:

  \code
	PAirpcapKeysCollection KeysCollection;
	UINT KeysCollectionSize;

	KeysCollectionSize = sizeof(AirpcapKeysCollection) + NumKeys * sizeof(AirpcapKey);

	KeysCollection = (PAirpcapKeysCollection)g_malloc(KeysCollectionSize);
	if(!KeysCollection)
	{
		// Error
	}
  \endcode
*/
typedef struct _AirpcapKeysCollection
{
	UINT nKeys;												/* Number of keys in the collection */
	AirpcapKey Keys[0];										/* Array of nKeys keys.  */
} AirpcapKeysCollection, *PAirpcapKeysCollection;

/*!
  \brief Packet header.

  This structure defines the BPF that preceeds every packet delivered to the application.
*/
typedef struct _AirpcapBpfHeader
{
	UINT TsSec;			/* Timestamp associated with the captured packet. SECONDS. */
	UINT TsUsec;		/* Timestamp associated with the captured packet. MICROSECONDS. */
	UINT Caplen;		/* Length of captured portion. The captured portion <b>can be different</b> from the original packet, because it is possible (with a proper filter) to instruct the driver to capture only a portion of the packets. */
	UINT Originallen;	/* Original length of packet */
	USHORT	Hdrlen;		/* Length of bpf header (this struct plus alignment padding). In some cases, a padding could be added between the end of this structure and the packet data for performance reasons. This field can be used to retrieve the actual data of the packet. */
}
#ifdef __MINGW32__
__attribute__((__packed__))
#endif /* __MINGW32__ */
AirpcapBpfHeader, *PAirpcapBpfHeader;

/* Helper macros to extract packets coming from the driver. Rounds up to the next even multiple of AIRPCAP_ALIGNMENT.  */
#define AIRPCAP_ALIGNMENT sizeof(int)
#define AIRPCAP_WORDALIGN(x) (((x)+(AIRPCAP_ALIGNMENT-1))&~(AIRPCAP_ALIGNMENT-1))

#ifndef __MINGW32__
#pragma pack(pop)
#endif /* __MINGW32__ */

#define AIRPCAP_ERRBUF_SIZE 512		/* Size of the error buffer, in bytes */

#ifndef __AIRPCAP_DRIVER__

/*!
  \brief Link type.
   AirPcap supports two kind of 802.11 linktypes: plain 802.11 and radiotap.
*/
typedef enum _AirpcapLinkType
{
    AIRPCAP_LT_802_11 = 1,				/* plain 802.11 linktype. Every packet in the buffer contains the raw 802.11 frame, including MAC FCS. */
    AIRPCAP_LT_802_11_PLUS_RADIO = 2,	/* 802.11 plus radiotap linktype. Every packet in the buffer contains a radiotap header followed by the 802.11 frame. MAC FCS is included. */
	AIRPCAP_LT_UNKNOWN = 3				/* Unknown linktype. You should see it only in case of error. */
}AirpcapLinkType, *PAirpcapLinkType;

#if !defined(AIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_)
#define AIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_
/*!
  \brief Adapter handle.
*/
typedef struct _AirpcapHandle AirpcapHandle, *PAirpcapHandle;
#endif

/*!
  \brief Capture statistics.
   Returned by \ref AirpcapGetStats();
*/
typedef struct _AirpcapStats
{
	UINT Recvs;			/* Number of packets that the driver received by the adapter  */
						/* from the beginning of the current capture. This value includes the packets  */
						/* dropped because of buffer full. */
	UINT Drops;			/* number of packets that the driver dropped from the beginning of a capture.  */
						/* A packet is lost when the the buffer of the driver is full.  */
	UINT IfDrops;		/* Packets dropped by the card before going to the USB bus.  */
						/* Not supported at the moment. */
	UINT Capt;			/* number of packets that pass the BPF filter, find place in the kernel buffer and */
						/* therefore reach the application. */
}AirpcapStats, *PAirpcapStats;

/*@}*/

/** @defgroup airpcapfuncs AirPcap functions
 *  @{
 */

/*!
  \brief Return a string with the API version
  \param VersionMajor Pointer to a variable that will be filled with the major version number.
  \param VersionMinor Pointer to a variable that will be filled with the minor version number.
  \param VersionRev Pointer to a variable that will be filled with the revision number.
  \param VersionBuild Pointer to a variable that will be filled with the build number.
*/
void AirpcapGetVersion(PUINT VersionMajor, PUINT VersionMinor, PUINT VersionRev, PUINT VersionBuild);

/*!
  \brief Return the last error related to the specified handle
  \param AdapterHandle Handle to an open adapter.
  \return The string with the last error.
*/
PCHAR AirpcapGetLastError(PAirpcapHandle AdapterHandle);

/*!
  \brief Return the list of available devices
  \param PPAllDevs Address to a caller allocated pointer. On success this pointer will receive the head of a list of available devices.
  \param Ebuf String that will contain error information if FALSE is returned. The size of the string must be AIRPCAP_ERRBUF_SIZE bytes.
  \return TRUE on success. FALSE is returned on failure, in which case Ebuf is filled in with an appropriate error message.

	Here's a snppet of code that shows how to use AirpcapGetDeviceList():

	\code
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	AirpcapDeviceDescription *Desc, *tDesc;

	if(AirpcapGetDeviceList(&Desc, Ebuf) == -1)
	{
		printf("Unable to get the list of devices: %s\n", Ebuf);
		return -1;
	}

	for(tDesc = Desc; tDesc; tDesc = tDesc->next)
	{
		printf("%u) %s (%s)\n",
		++i,
		tDesc->Name,
		tDesc->Description);
	}
	\endcode
*/
BOOL AirpcapGetDeviceList(PAirpcapDeviceDescription *PPAllDevs, PCHAR Ebuf);

/*!
  \brief Free a list of devices returned by AirpcapGetDeviceList()
  \param PAllDevs Head of the list of devices returned by \ref AirpcapGetDeviceList().
*/
VOID AirpcapFreeDeviceList(PAirpcapDeviceDescription PAllDevs);

/*!
  \brief Open an adapter
  \param DeviceName Name of the device to open. Use \ref AirpcapGetDeviceList() to get the list of devices.
  \param Ebuf String that will contain error information in case of failure. The size of the string must be AIRPCAP_ERRBUF_SIZE bytes.
  \return A PAirpcapHandle handle on success. NULL is returned on failure, in which case Ebuf is filled in with an appropriate error message.
*/
PAirpcapHandle AirpcapOpen(PCHAR DeviceName, PCHAR Ebuf);

/*!
  \brief Close an adapter
  \param AdapterHandle Handle to the adapter to close.
*/
VOID AirpcapClose(PAirpcapHandle AdapterHandle);

/*!
  \brief Set the link type of an adapter
  \param AdapterHandle Handle to the adapter.
  \param NewLinkType the "link type", i.e. the format of the frames that will be received from the adapter.
  \return TRUE on success.

  the "link type" determines how the driver will encode the packets captured from the network.
  Aircap supports two link types:
  - AIRPCAP_LT_802_11, to capture 802.11 frames (including control frames) without any
   power information. Look at the Capture_no_radio example application in the developer's pack
   for a reference on how to decode 802.11 frames with this link type.
  - AIRPCAP_LT_802_11_PLUS_RADIO, to capture 802.11 frames (including control frames) with a radiotap header
  that contains power and channel information. More information about the radiotap header can be found int the
  \ref radiotap section. Moreover, the "Capture_radio" example application in
  the developer's pack can be used as a reference on how to decode 802.11 frames with radiotap headers.
*/
BOOL AirpcapSetLinkType(PAirpcapHandle AdapterHandle, AirpcapLinkType NewLinkType);

/*!
  \brief Get the link type of the specified adapter
  \param AdapterHandle Handle to the adapter.
  \param PLinkType Pointer to a caller allocated AirpcapLinkType variable that will contain the link type of the adapter.
  \return TRUE on success.

  the "link type" determines how the driver will encode the packets captured from the network.
  Aircap supports two link types:
  - AIRPCAP_LT_802_11, to capture 802.11 frames (including control frames) without any
   power information. Look at the Capture_no_radio example application in the developer's pack
   for a reference on how to decode 802.11 frames with this link type.
  - AIRPCAP_LT_802_11_PLUS_RADIO, to capture 802.11 frames (including control frames) with a radiotap header
  that contains power and channel information. More information about the radiotap header can be found int the
  \ref radiotap section. Moreover, the "Capture_radio" example application in
  the developer's pack can be used as a reference on how to decode 802.11 frames with radiotap headers.
*/
BOOL AirpcapGetLinkType(PAirpcapHandle AdapterHandle, PAirpcapLinkType PLinkType);

/*!
  \brief Configures the adapter on whether to include the MAC Frame Check Sequence in the captured packets.
  \param AdapterHandle Handle to the adapter.
  \param IsFcsPresent TRUE if the packets should include the FCS. FALSE otherwise
  \return TRUE on success.

  In the default configuration, the adapter includes the FCS in the captured packets. The MAC Frame Check Sequence
  is 4 bytes and is located at the end of the 802.11 packet, with both AIRPCAP_LT_802_11 and AIRPCAP_LT_802_11_PLUS_RADIO
  link types.
  When the FCS inclusion is turned on, and if the link type is AIRPCAP_LT_802_11_PLUS_RADIO, the radiotap header
  that precedes each frame has two additional fields at the end: Padding and FCS. These two fields are not present
  when FCS inclusion is off.
*/
BOOL AirpcapSetFcsPresence(PAirpcapHandle AdapterHandle, BOOL IsFcsPresent);

/*!
  \brief Returns TRUE if the specified adapter includes the MAC Frame Check Sequence in the captured packets
  \param AdapterHandle Handle to the adapter.
  \param PIsFcsPresent User-provided variable that will be set to true if the adapter is including the FCS.
  \return TRUE if the operation is successful. FALSE otherwise.

  In the default configuration, the adatper has FCS inclusion turned on. The MAC Frame Check Sequence is 4 bytes
  and is located at the end of the 802.11 packet, with both AIRPCAP_LT_802_11 and AIRPCAP_LT_802_11_PLUS_RADIO
  link types.
  When the FCS inclusion is turned on, and if the link type is AIRPCAP_LT_802_11_PLUS_RADIO, the radiotap header
  that precedes each frame has two additional fields at the end: Padding and FCS. These two fields are not present
  when FCS inclusion is off.
*/
BOOL AirpcapGetFcsPresence(PAirpcapHandle AdapterHandle, PBOOL PIsFcsPresent);

/*!
  \brief Configures the adapter to accept or drop frames with an incorrect Frame Check sequence (FCS).
  \param AdapterHandle Handle to the adapter.
  \param ValidationType The type of validation the driver will perform. See the documentation of \ref AirpcapValidationType for details.
  \return TRUE on success.

  \note By default, the driver is configured in \ref AIRPCAP_VT_ACCEPT_EVERYTHING mode.
*/
BOOL AirpcapSetFcsValidation(PAirpcapHandle AdapterHandle, AirpcapValidationType ValidationType);

/*!
  \brief Checks if the specified adapter is configured to capture frames with incorrect an incorrect Frame Check Sequence (FCS).
  \param AdapterHandle Handle to the adapter.
  \param ValidationType Pointer to a user supplied variable that will contain the type of validation the driver will perform. See the documentation of \ref AirpcapValidationType for details.
  \return TRUE if the operation is succesful. FALSE otherwise.

  \note By default, the driver is configured in \ref AIRPCAP_VT_ACCEPT_EVERYTHING mode.
*/
BOOL AirpcapGetFcsValidation(PAirpcapHandle AdapterHandle, PAirpcapValidationType ValidationType);

/*!
  \brief Set the list of decryption keys that the driver is going to use with the specified device.
  \param AdapterHandle Handle an open adapter instance.
  \param KeysCollection Pointer to a \ref PAirpcapKeysCollection structure that contains the keys to be set in the driver.
  \return TRUE if the operation is successful. FALSE otherwise.

  The AirPcap driver is able to use a set of decryption keys to decrypt the traffic transmitted on a specific SSID. If one of the
  keys corresponds to the one the frame has been encrypted with, the driver will perform decryption and return the cleartext frames
  to the application.
  The driver supports, for every device, multiple keys at the same time.

  At this time, the only supported decryption method is WEP.

  The configured decryption keys are device-specific: they will not be used by other airpcap devices besides the specified one.

  The keys are applied to the packets in the same order they appear in the KeysCollection structure until the packet is
  correctly decrypted, therefore putting frequently used keys at the beginning of the structure improves performance.

  \note: this is a Device-related function: when you change the channel from an open capture instance, the change will be
         immediately reflected on all the other capture instances.
*/
BOOL AirpcapSetDeviceKeys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);

/*!
  \brief Returns the list of decryption keys in the driver that are currently associated with the specified device
  \param AdapterHandle Handle to an open adapter instance.
  \param KeysCollection User-allocated PAirpcapKeysCollection structure that will be filled with the keys.
  \param PKeysCollectionSize \b IN: pointer to a user-allocated variable that contains the length of the KeysCollection structure, in bytes.
					        \b OUT: amount of data moved by the driver in the buffer pointed by KeysBuffer, in bytes.
  \return TRUE if the operation is succesful. If an error occurs, the return value is FALSE and KeysCollectionSize is zero.
  If the provided buffer is too small to contain the keys, the return value is FALSE and KeysCollectionSize contains the
  needed KeysCollection length, in bytes. If the device doesn't have any decryption key configured, the return value is TRUE, and
  KeysCollectionSize will be zero.

  This function returns the list of decryption keys in the driver that are associated with the specified device.
  The AirPcap driver is able to use a set of decryption keys to decrypt the traffic transmitted on a specific SSID. If one of the
  keys corresponds to the one the frame has been encrypted with, the driver will perform decryption and return the cleartext frames
  to the application.
  The driver supports, for every device, multiple keys at the same time.

  The configured decryption keys are device-specific, therefore AirpcapGetDeviceKeys() will return a different set of keys
  when called on different devices.

  At this time, the only supported decryption method is WEP.

  \note: this is a Device-related function: when you change the channel from an open capture instance, the change will be
         immediately reflected on all the other capture instances.
*/
BOOL AirpcapGetDeviceKeys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize);

/*!
  \brief Turns on or off the decryption of the incoming frames
  \param AdapterHandle Handle to the adapter.
  \param ValidationType Either \ref AIRPCAP_DECRYPTION_ON or \ref AIRPCAP_DECRYPTION_OFF
  \return TRUE on success.

  The decryption keys can be configured with the \ref AirpcapSetDeviceKeys() function.
  \note By default, the driver is configured with \ref AIRPCAP_DECRYPTION_ON.
*/
BOOL AirpcapSetDecryptionState(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);

/*!
  \brief Tells if this open instance is configured to perform the decryption of the incoming frames
  \param AdapterHandle Handle to the adapter.
  \param ValidationType Pointer to a user supplied variable that will contain the decryption configuration. See \ref PAirpcapDecryptionState for details.
  \return TRUE if the operation is succesful. FALSE otherwise.

  The decryption keys can be configured with the \ref AirpcapSetDeviceKeys() function.
  \note By default, the driver is configured with \ref AIRPCAP_DECRYPTION_ON.
*/
BOOL AirpcapGetDecryptionState(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);

/*!
  \brief Set the radio channel of a device
  \param AdapterHandle Handle to the adapter.
  \param Channel the new channel to set.
  \return TRUE on success.

  Valid channels are in the range 1-14. The default channel setting is 6.

  \note: this is a Device-related function: when you change the channel from an open capture instance, the change will be
         immediately reflected on all the other capture instances.
*/
BOOL AirpcapSetDeviceChannel(PAirpcapHandle AdapterHandle, UINT Channel);

/*!
  \brief Get the radio channel of a device
  \param AdapterHandle Handle to the adapter.
  \param PChannel Pointer to a user-supplied variable into which the function will copy the currently configured radio channel.
  \return TRUE on success.

  Valid channels are in the range 1-14. The default channel setting is 6.

  \note: this is a Device-related function: when you change the channel from an open capture instance, the change will be
         immediately reflected on all the other capture instances.
*/
BOOL AirpcapGetDeviceChannel(PAirpcapHandle AdapterHandle, PUINT PChannel);

/*!
  \brief Set the size of the kernel packet buffer for this adapter
  \param AdapterHandle Handle to the adapter.
  \param BufferSize New size, in bytes.
  \return TRUE on success.

  Every AirPcap open instance has an associated kernel buffer, whose default size is 1 Mbyte.
  This function can be used to change the size of this buffer, and can be called at any time.
  A bigger kernel buffer size decreases the risk of dropping packets during network bursts or when the
  application is busy, at the cost of higher kernel memory usage.

  \note: don't use this function unless you know what you are doing. Due to chaching issues and bigger non-paged
  memory consumption, Bigger buffer sizes can decrease the capture performace instead of improving it.
*/
BOOL AirpcapSetKernelBuffer(PAirpcapHandle AdapterHandle, UINT BufferSize);

/*!
  \brief Get the size of the kernel packet buffer for this adapter
  \param AdapterHandle Handle to the adapter.
  \param PSizeBytes User-allocated variable that will be filled with the size of the kernel buffer.
  \return TRUE on success.

  Every AirPcap open instance has an associated kernel buffer, whose default size is 1 Mbyte.
  This function can be used to get the size of this buffer.
*/
BOOL AirpcapGetKernelBufferSize(PAirpcapHandle AdapterHandle, PUINT PSizeBytes);

/*!
  \brief Saves the configuration of the specified adapter in the registry, so that it becomes the default for this adapter.
  \param AdapterHandle Handle to the adapter.
  \return TRUE on success. FALSE on failure.

  Almost all the AirPcap calls that modify the configuration (\ref AirpcapSetLinkType(), \ref AirpcapSetFcsPresence(),
  \ref AirpcapSetFcsValidation(), \ref AirpcapSetKernelBuffer(), \ref AirpcapSetMinToCopy())
  affect only the referenced AirPcap open instance. This means that if you do another \ref AirpcapOpen() on the same
  adapter, the configuration changes will not be remembered, and the new adapter handle will have default configuration
  settings.

  Exceptions to this rule are the \ref AirpcapSetDeviceChannel() and \ref AirpcapSetDeviceKeys() functions: a channel change is
  reflected on all the open instances, and remembered until the next call to \ref AirpcapSetDeviceChannel(), until the adapter
  is unplugged, or until the machine is powered off. Same thing for the configuration of the WEP keys.

  AirpcapStoreCurConfigAsAdapterDefault() stores the configuration of the give open instance as the default for the adapter:
  all the instances opened in the future will have the same configuration that this adapter currently has.
  The configuration is stored in the registry, therefore it is remembered even when the adapter is unplugged or the
  machine is turned off. However, an adapter doesn't bring its configuration with it from machine to machine.

  the configuration information saved in the registry includes the following parameters:
   - channel
   - kernel buffer size
   - mintocopy
   - link type
   - CRC presence
   - Encryption keys
   - Encryption Enabled/Disabled state

  The configuration is adapter-specific. This means that changing the configuration of an adapter
  doesn't modify the one of the other adapters that are currently used or that will be used in the future.

  \note AirpcapStoreCurConfigAsAdapterDefault() must have exclusive access to the adapter -- it
   will fail if more than one AirPcap handle is opened at the same time for this adapter.
   AirpcapStoreCurConfigAsAdapterDefault() needs administrator privileges. It will fail if the calling user
   is not a local machine administrator.
*/
BOOL AirpcapStoreCurConfigAsAdapterDefault(PAirpcapHandle AdapterHandle);

/*!
  \brief Set the BPF kernel filter for an adapter
  \param AdapterHandle Handle to the adapter.
  \param Instructions pointer to the first BPF instruction in the array. Corresponds to the  bf_insns
   in a bpf_program structure (see the WinPcap documentation at http://www.winpcap.org/devel.htm).
  \param Len Number of instructions in the array pointed by the previous field. Corresponds to the bf_len in
  a a bpf_program structure (see the WinPcap documentation at http://www.winpcap.org/devel.htm).
  \return TRUE on success.

  The AirPcap driver is able to perform kernel-level filtering using the standard BPF pseudo-machine format. You can read
  the WinPcap documentation at http://www.winpcap.org/devel.htm for more details on the BPF filtering mechaism.

  A filter can be automatically created by using the pcap_compile() function of the WinPcap API. This function
  converts a human readable text expression with the tcpdump/libpcap syntax into a BPF program.
  If your program doesn't link wpcap, but you need to generate the code for a particular filter, you can run WinDump
  with the -d or -dd or -ddd flags to obtain the pseudocode.

*/
BOOL AirpcapSetFilter(PAirpcapHandle AdapterHandle, PVOID Instructions, UINT Len);

/*!
  \brief Return the MAC address of an adapter.
  \param AdapterHandle Handle to the adapter.
  \param PMacAddress Pointer to a user allocated MAC address.
   The size of this buffer needs to be at least 6 bytes.
  \return TRUE on success.
*/
BOOL AirpcapGetMacAddress(PAirpcapHandle AdapterHandle, PAirpcapMacAddress PMacAddress);

/*!
  \brief Set the mintocopy parameter for an open adapter
  \param AdapterHandle Handle to the adapter.
  \param MinToCopy is the mintocopy size in bytes.
  \return TRUE on success.

  When the number of bytes in the kernel buffer changes from less than mintocopy bytes to greater than or equal to mintocopy bytes,
  the read event is signalled (see \ref AirpcapGetReadEvent()). A high value for mintocopy results in poor responsiveness since the
  driver may signal the application "long" after the arrival of the packet. And a high value results in low CPU loading
  by minimizing the number of user/kernel context switches.
  A low MinToCopy results in good responsiveness since the driver will signal the application close to the arrival time of
  the packet. This has higher CPU loading over the first approach.
*/
BOOL AirpcapSetMinToCopy(PAirpcapHandle AdapterHandle, UINT MinToCopy);

/*!
  \brief Gets an event that is signaled when that is signalled when packets are available in the kernel buffer (see \ref AirpcapSetMinToCopy()).
  \param AdapterHandle Handle to the adapter.
  \param PReadEvent Pointer to a user-supplied handle that in which the read event will be copied.
  \return TRUE on success.

  \note the event is signalled when at least mintocopy bytes are present in the kernel buffer (see \ref AirpcapSetMinToCopy()).
  This event can be used by WaitForSingleObject() and WaitForMultipleObjects() to create blocking behavior when reading
  packets from one or more adapters (see \ref AirpcapRead()).
*/
BOOL AirpcapGetReadEvent(PAirpcapHandle AdapterHandle, HANDLE* PReadEvent);

/*!
  \brief Fills a user-provided buffer with zero or more packets that have been captured on the referenced adapter.
  \param AdapterHandle Handle to the adapter.
  \param Buffer pointer to the buffer that will be filled with captured packets.
  \param BufSize size of the input buffer that will contain the packets, in bytes.
  \param PReceievedBytes Pointer to a user supplied variable that will receive the number of bytes copied by AirpcapRead.
  Can be smaller than BufSize.
  \return TRUE on success.

  802.11 frames are returned by the driver in buffers. Every 802.11 frame in the buffer is preceded by a \ref AirpcapBpfHeader structure.
  The suggested way to use an AirPcap adapter is through the pcap API exported by wpcap.dll. If this is not
  possible, the Capture_radio and Capture_no_radio examples in the AirPcap developer's pack show how to properly decode the
  packets in the read buffer returned by AirpcapRead().

  \note this function is NOT blocking. Blocking behavior can be obtained using the event returned
   by \ref AirpcapGetReadEvent(). See also \ref AirpcapSetMinToCopy().
*/
BOOL AirpcapRead(PAirpcapHandle AdapterHandle, PBYTE Buffer, UINT BufSize, PUINT PReceievedBytes);

/*!
  \brief Get per-adapter WinPcap-compatible capture statistics.
  \param AdapterHandle Handle to the adapter.
  \param PStats pointer to a user-allocated AirpcapStats structure that will be filled with statistical information.
  \return TRUE on success.
*/
BOOL AirpcapGetStats(PAirpcapHandle AdapterHandle, PAirpcapStats PStats);

/*!
  \brief Get the number of LEDs the referenced adapter has available.
  \param AdapterHandle Handle to the adapter.
  \param NumberOfLeds Number of LEDs available on this adapter.
  \return TRUE on success.
*/
BOOL AirpcapGetLedsNumber(PAirpcapHandle AdapterHandle, PUINT NumberOfLeds);

/*!
  \brief Turn on one of the adapter's LEDs.
  \param AdapterHandle Handle to the adapter.
  \param LedNumber zero-based identifier of the LED to turn on.
  \return TRUE on success.
*/
BOOL AirpcapTurnLedOn(PAirpcapHandle AdapterHandle, UINT LedNumber);

/*!
  \brief Turn off one of the adapter's LEDs.
  \param AdapterHandle Handle to the adapter.
  \param LedNumber zero-based identifier of the LED to turn off.
  \return TRUE on success.
*/
BOOL AirpcapTurnLedOff(PAirpcapHandle AdapterHandle, UINT LedNumber);

/*@}*/

#endif /* __AIRPCAP_DRIVER__ */

#ifdef __cplusplus
}
#endif

#endif /* !defined(AIRPCAP_H__EAE405F5_0171_9592_B3C2_C19EC426AD34__INCLUDED_) */
