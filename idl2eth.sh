#! @SHELL@
#
#  $Id$
#
#  File : idl2eth          
#
#  Author : Frank Singleton (frank.singleton@ericsson.com)
#
#  Copyright (C) 2001 Frank Singleton, Ericsson Inc.
#
#  This file is a simple shell script wrapper for the IDL to 
#  Ethereal dissector code.
#
#  ie: ethereal_be.py and ethereal_gen.py
#
#  This file is used to generate "Ethereal" dissectors from IDL descriptions. 
#  The output language generated is "C". It will generate code to use the 
#  GIOP/IIOP get_CDR_XXX API.
#
#  Please see packet-giop.h in Ethereal distro for API description.
#  Ethereal is available at http://www.ethereal.com/
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
    echo "idl2eth Error: no IDL file specified."
    echo "Usage: idl2eth idl_file_name"
    exit 1;
fi

#
# Run ethereal backend, looking for ethereal_be.py and ethereal_gen.py
# in pythons's "site-packages" directory. If cannot find that, then
# try looking in current directory. If still cannot, then exit with
# error.

if [ -f $PYTHONPATH/site-packages/ethereal_be.py ] && [ -f $PYTHONPATH/site-packages/ethereal_gen.py ]; then
    exec omniidl  -p $PYTHONPATH/site-packages -b ethereal_be $1
    /* not reached */
fi

# Try current directory.

if [ -f ./ethereal_be.py ] && [ -f ./ethereal_gen.py ]; then
    exec omniidl  -p ./ -b ethereal_be $1
    /* not reached */
fi

# Could not find both ethereal_be.py AND ethereal_gen.py

echo "idl2eth Error: Could not find both ethereal_be.py AND ethereal_gen.py."
echo "Please ensure you have the PYTHONPATH variable set, or that ethereal_be.py "
echo "and ethereal_gen.py exist in the current directory. "
echo
echo "On this system, PYTHONPATH is : $PYTHONPATH"
echo

exit 2



