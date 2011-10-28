# wspy_libws.py
#
# $Id$
#
# Wireshark Protocol Python Binding
#
# Copyright (c) 2009 by Sebastien Tandel <sebastien [AT] tandel [dot] be>
# Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
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


from ctypes import cdll, c_void_p, c_int, POINTER
import platform

__libwireshark = None

# XXX - We should probably return a full path here, at least on Windows.
def get_libws_libname():
  system = platform.system()
  if system == "Darwin":
    return 'libwireshark.dylib'
  elif system == "Windows":
    return 'libwireshark.dll'
  else:
    return 'libwireshark.so'

def get_libws_handle():
  global __libwireshark
  try:
    if not __libwireshark:
      libname = get_libws_libname()
      __libwireshark = cdll.LoadLibrary(libname)
      __libwireshark.py_create_dissector_handle.restype = c_void_p
      __libwireshark.py_create_dissector_handle.argtypes = [c_int]
      __libwireshark.py_dissector_args.argtypes = [POINTER(c_void_p),POINTER(c_void_p),POINTER(c_void_p)]
      __libwireshark.proto_tree_add_item.argtypes = [c_void_p,
        c_int, c_void_p, c_int, c_int, c_int]

    return __libwireshark
  except Exception, e:
    print e
    return None
