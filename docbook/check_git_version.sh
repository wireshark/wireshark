#!/bin/bash
#
# Check for Git version
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2005 Ulf Lamping
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

GIT_VERSION="unknown git version"
if [ -d ../.git ] ; then
    GIT_VERSION=`git describe --always --long`
fi
echo '<!ENTITY GitVersion "'${GIT_VERSION}'">' > git_version_tmp.xml

#echo -n '<!ENTITY GitVersion "' > git_version_tmp.xml
#[ -x svnversion ] && svnversion -n .                   >> git_version_tmp.xml
#echo '">'   >> git_version_tmp.xml

# /dev/null buries the output of the "cmp" command.
diff git_version.xml git_version_tmp.xml &> /dev/null

if [ $? -ne 0 ]
then
    cp git_version_tmp.xml git_version.xml
fi

rm git_version_tmp.xml

