#include "config.h"
#include <epan/packet.h>

#include <stdint.h>
#ifndef PACKET_PLDM_H
#define PACKET_PLDM_H

enum PLDMType {
  PLDM_DISCOVERY,
  PLDM_SMBIOS,
  PLDM_PLATFORM,
  PLDM_BIOS,
  PLDM_FRU,
  PLDM_FIRMWARE_UPDATE,
  PLDM_REDFISH,
  PLDM_OEM = 63
};

struct packet_data {
  guint8 direction;
  guint8 instance_id;
};

#endif
