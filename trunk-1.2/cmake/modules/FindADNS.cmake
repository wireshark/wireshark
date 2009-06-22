###################################################################
#
#  Copyright (c) 2006 Frederic Heem, <frederic.heem@telsey.it>
#  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# * Neither the name of the Telsey nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
###################################################################
# - Find adns
# Find the gnu adns includes and library
# http://www.chiark.greenend.org.uk/~ian/adns/
#
#  ADNS_INCLUDE_DIRS - where to find adns.h, etc.
#  ADNS_LIBRARIES   - List of libraries when using adns.
#  ADNS_FOUND       - True if adns found.

#Includes
FIND_PATH(ADNS_INCLUDE_DIR adns.h
  /usr/local/include
  /usr/include
)

SET(ADNS_INCLUDE_DIRS ${ADNS_INCLUDE_DIR})

#Library
FIND_LIBRARY(ADNS_LIBRARY
  NAMES adns
  PATHS /usr/lib /usr/local/lib
)

SET(ADNS_LIBRARIES ${ADNS_LIBRARY})

#Is adns found ?
IF(ADNS_INCLUDE_DIR AND ADNS_LIBRARY)
  SET( ADNS_FOUND "YES" )
ENDIF(ADNS_INCLUDE_DIR AND ADNS_LIBRARY)


MARK_AS_ADVANCED(
  ADNS_LIBRARY
  ADNS_INCLUDE_DIR
)
