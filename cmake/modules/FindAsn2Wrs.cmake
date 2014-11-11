#
# Look for the asn2wrs.py utility
#

find_program( ASN2WRS_EXECUTABLE
  NAMES
    asn2wrs.py
  HINTS
    # First try to find it in wireshark sources
    ${CMAKE_SOURCE_DIR}/tools
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( ASN2WRS DEFAULT_MSG ASN2WRS_EXECUTABLE )

mark_as_advanced( ASN2WRS_EXECUTABLE )
