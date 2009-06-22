#! @SHELL@
#
#  $Id$
#
#  File : idl2wrs          
#
#  Author : Frank Singleton (frank.singleton@ericsson.com)
#
#  Copyright (C) 2001 Frank Singleton, Ericsson Inc.
#
#  This file is a simple shell script wrapper for the IDL to 
#  Wireshark dissector code.
#
#  ie: wireshark_be.py and wireshark_gen.py
#
#  This file is used to generate "Wireshark" dissectors from IDL descriptions. 
#  The output language generated is "C". It will generate code to use the 
#  GIOP/IIOP get_CDR_XXX API.
#
#  Please see packet-giop.h in Wireshark distro for API description.
#  Wireshark is available at http://www.wireshark.org/
#
#  Omniidl is part of the OmniOrb distribution, and is available at
#  http://omniorb.sourceforge.net/
#
#  This program is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
#  02111-1307, USA.
#


#  Must at least supply an IDL file

if [ $# -lt 1 ]; then
    echo "idl2wrs Error: no IDL file specified."
    echo "Usage: idl2wrs idl_file_name"
    exit 1;
fi

#
# Run wireshark backend, looking for wireshark_be.py and wireshark_gen.py
# in pythons's "site-packages" directory. If cannot find that, then
# try looking in current directory. If still cannot, then exit with
# error.

if [ -f $PYTHONPATH/site-packages/wireshark_be.py ] && [ -f $PYTHONPATH/site-packages/wireshark_gen.py ]; then
    exec omniidl  -p $PYTHONPATH/site-packages -b wireshark_be $@
    /* not reached */
fi

# Try current directory.

if [ -f ./wireshark_be.py ] && [ -f ./wireshark_gen.py ]; then
    exec omniidl  -p ./ -b wireshark_be $@
    /* not reached */
fi

# Could not find both wireshark_be.py AND wireshark_gen.py
# So let's just try to run it without -p, hoping that the installation
# set up a valid path.

exec omniidl -b wireshark_be $@

old code: not reached

echo "idl2wrs Error: Could not find both wireshark_be.py AND wireshark_gen.py."
echo "Please ensure you have the PYTHONPATH variable set, or that wireshark_be.py "
echo "and wireshark_gen.py exist in the current directory. "
echo
echo "On this system, PYTHONPATH is : $PYTHONPATH"
echo

exit 2



