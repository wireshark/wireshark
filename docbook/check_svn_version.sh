#!/bin/bash
#
# Check for SVN version
#
# $Id$
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# 

echo -n '<!ENTITY SvnVersion "' > svn_version_tmp.xml
[ -x svnversion ] && svnversion -n .                   >> svn_version_tmp.xml
echo '">'   >> svn_version_tmp.xml

# /dev/null buries the output of the "cmp" command.
diff svn_version.xml svn_version_tmp.xml &> /dev/null

if [ $? -ne 0 ]
then
  cp svn_version_tmp.xml svn_version.xml
fi

rm svn_version_tmp.xml

