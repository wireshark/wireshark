# FileInstall - Install files and directories separately from the
# "install" command.
#
# Usage:
#   cmake -P /path/to/FileInstall.cmake [source ...] [destination]

# Params are
#   cmake -P /path/to/hhc.cmake "/path/to/hhc.exe" project.hhp
math(EXPR _dest_idx "${CMAKE_ARGC} - 1")
set(_destination ${CMAKE_ARGV${_dest_idx}})
set(_sources)

math(EXPR _last_src "${CMAKE_ARGC} - 2")
foreach(_src_idx RANGE 3 ${_last_src})
    set(_sources ${_sources} ${CMAKE_ARGV${_src_idx}})
endforeach(_src_idx)

if (_sources AND _destination)
    message (STATUS "Installing ${_sources} to ${_destination}")
    file (INSTALL ${_sources}
        DESTINATION ${_destination}
        FILE_PERMISSIONS
            OWNER_WRITE OWNER_READ
            GROUP_READ
            WORLD_READ
        DIRECTORY_PERMISSIONS
            OWNER_EXECUTE OWNER_WRITE OWNER_READ
            GROUP_EXECUTE GROUP_READ
            WORLD_EXECUTE WORLD_READ
    )
else()
    message (FATAL_ERROR "Missing arguments. Sources: ${_sources}. Destination: ${_destination}.")
endif()
