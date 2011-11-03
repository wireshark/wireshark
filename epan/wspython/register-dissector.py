# register-dissector.py
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
import sys
import re
import os
import imp

#
# Build a list of files belonging to a directory and matching a regexp (f.e.
# '(?P<plugin>.*)\.py$' )
#
def get_plugin_list(dir, regexp):
  lDir = os.listdir(dir)

  lPlugins=[]
  for sDir in lDir:
    MatchedObject = re.match(regexp, sDir)
    if (MatchedObject != None):
      lPlugins.append(MatchedObject.group("plugin"))
  return lPlugins

#Import the module "name"
def plugin_import(name):
  #if the module was already loaded
  try:
    return sys.modules[name]
  except KeyError:
    pass

  r = __import__(name)
  return r

def register_dissectors(wspython_dir,  plugins_pers_dir=None):
  #append dir to be able to import py_lib
  sys.path.append(wspython_dir)
  from wspy_libws import get_libws_handle
  libws = get_libws_handle()

  dissectors_dirs = [
    os.path.join(wspython_dir, 'wspy_dissectors'),
    plugins_pers_dir
  ]

  registered_protocols = []
  for dissectors_dir in dissectors_dirs:
      #Check if we have the dissectors directory
      if not os.path.isdir(dissectors_dir):
        continue

      #append dir to be able to import python dissectors
      sys.path.append(dissectors_dir)

      #Read all python dissectors
      dissectors = get_plugin_list(dissectors_dir, "(?P<plugin>.*)\.py$")

      #For each dissector, register it and put it in the list of registered
      #protocols
      for dissector in dissectors:
          try:
              d = plugin_import(dissector)
              registered_protocol = d.register_protocol()
              if registered_protocol:
                registered_protocols.append(registered_protocol)
          except Exception, e:
              print 'register dissector %s exception %s' % (dissector, e)
  return registered_protocols

if False:
    import linecache

    # Start tracing when import has finished
    def tracer(frame, event, arg):
        if event == "line":
            lineno = frame.f_lineno
            filename = frame.f_globals["__file__"]
            if (filename.endswith(".pyc") or
                filename.endswith(".pyo")):
                filename = filename[:-1]
            name = frame.f_globals["__name__"]
            line = linecache.getline(filename, lineno)
            print "%s:%s: %s" % (name, lineno, line.rstrip())
        if event == "exception":
            print "exception", arg
        return tracer

    sys.settrace(tracer)

