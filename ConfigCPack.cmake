############################
# CPack configuration file #
############################
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

## General ##

if(WIN32)
	set(CPACK_PACKAGE_NAME "Wireshark")
else()
	set(CPACK_PACKAGE_NAME "wireshark")
endif()
set(CPACK_PACKAGE_VENDOR "Wireshark Foundation")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_MAJOR_VERSION})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_MINOR_VERSION})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_PATCH_VERSION})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION
"Wireshark is the world’s most popular network protocol analyzer."
"It is used for troubleshooting, analysis, development and education."
)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Network protocol analyzer")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://www.wireshark.org/")
set(CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}/resources/icons/wireshark.ico")
set(CPACK_PACKAGE_CONTACT "Wireshark-Dev Mailing List <wireshark-dev@wireshark.org>")

set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_CHECKSUM "SHA256")

if(WIN32)
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "Wireshark")
    set(CPACK_STRIP_FILES FALSE)
else()
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "wireshark")
    set(CPACK_STRIP_FILES TRUE)
endif()

# This creates a screen in the windows installers asking users to "Agree" to the GPL which is incorrect.
# set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
# set( CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/README.md") # TODO: can we use this?

set(CPACK_WARN_ON_ABSOLUTE_INSTALL_DESTINATION TRUE)

# specific config for source packaging (note this is used by the 'dist' target)
set(CPACK_SOURCE_GENERATOR "TXZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PROJECT_VERSION})
set(CPACK_SOURCE_IGNORE_FILES "~$;[.]swp$;/[.]svn/;/[.]git/;.gitignore;/build/;/obj*/;cscope.*;.gitlab*;.coveragerc;*.md;")

set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)

## load cpack module (do this *after* all the CPACK_* variables have been set)
include(CPack)
