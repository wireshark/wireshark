# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

add_library(speexresampler STATIC resample.c)

set_target_properties(speexresampler PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "Libs"
)
