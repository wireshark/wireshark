# - Find pcap
# Find the PCAP includes and library
#
#  PCAP_INCLUDE_DIR - where to find pcap.h, etc.
#  PCAP_LIBRARIES   - List of libraries when using pcap.
#  PCAP_FOUND       - True if pcap found.

FIND_PATH(PCAP_INCLUDE_DIR pcap.h
  /usr/local/include
  /usr/include
)

FIND_LIBRARY(PCAP_LIBRARIES
  NAMES pcap
  PATHS /usr/lib /usr/local/lib
)

IF(PCAP_INCLUDE_DIR)
  IF(PCAP_LIBRARIES)
    SET( PCAP_FOUND "YES" )
  ENDIF(PCAP_LIBRARIES)
ENDIF(PCAP_INCLUDE_DIR)

MARK_AS_ADVANCED(
  PCAP_LIBRARIES
  PCAP_INCLUDE_DIR
)
