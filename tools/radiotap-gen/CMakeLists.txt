
if(UNIX)

	add_executable( radiotap-gen radiotap-gen.c )

	target_link_libraries( radiotap-gen pcap ${GLIB2_LIBRARIES} )

endif()
