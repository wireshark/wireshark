# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

set(CODECS_FILES
  codecs.c
  G711a/G711adecode.c
  G711u/G711udecode.c
  # These are wrapped in "#ifdef HAVE_SPANDSP", which we don't currently
  # handle or define.
  # G722/G722decode.c
  # G726/G726decode.c
  speex/resample.c
)

# Enables visibility in IDEs
file(GLOB EXTRA_CODEC_HEADERS
  codecs.h
  G711a/G711adecode.h G711a/G711atable.h
  G711u/G711udecode.h G711u/G711utable.h
  speex/arch.h
  speex/speex_resampler.h
  speex/stack_alloc.h
)

if(SBC_FOUND)
  set(CODECS_FILES ${CODECS_FILES} sbc/sbc.c)
endif()

add_library(codecs STATIC
  ${CODECS_FILES}
)
set_target_properties(codecs PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "Libs")
