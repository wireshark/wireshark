#! /usr/bin/python
# -*- python -*-
#
# mmelchior@xs4all.nl
#
# gererate files for the windows plugin interface from a file with declarations
#
# The input for this script is genereted by gcc using the following command:
#
# gcc -aux-info xyzzy $(pkg-config --cflags glib-2.0) -I ethereal-0.9.13 -c plugin_api_list.c
#
#   this gives one declaration per line, with consistent spacing.
#
#   with a much more elaborate parser than the one RE we have now, we could do without gcc.
#

"""Ethereal Windows interface generator."""

import sys, string, os, re
from string import strip, replace

pattFile = re.compile('.*plugin_api_list.* extern (.*)') # match filename and select declaration
pattName = re.compile('\w* .*?(\w*) \(.*') 		 # select function name

names = []
count = 0
if len(sys.argv) > 1:
    file = open(sys.argv[1], 'r')       # input name on command line
else:
    file = sys.stdin			# read from a stream
    
f1 = open("Xepan_plugins.c", 'w') 
f2 = open("Xplugin_api.h", 'w')
f3 = open("Xplugin_api.c", 'w')
f4 = open("Xplugin_api_decls.h", 'w')
f5 = open("Xplugin_table.h", 'w')

while 1:
    line = file.readline()
    if not line: break
    count += 1
    matchobj = pattFile.match(line)
    if matchobj:
        # print "+", count, " ", strip(line)
        decl = matchobj.group(1)
        # print "=      ", decl
        matchobj = pattName.match(decl)
        if matchobj:
            name = matchobj.group(1)
            # print "       ", name
            f1.write("patable.p_%s = %s;\n" % (name, name))
            f2.write("#define %s (*p_%s)\n" % (name, name))
            f3.write("p_%s = pat->p_%s;\n" % (name, name))
            f4.write("addr_%s p_%s;\n" % (name, name))
            f5.write(replace("typedef %s\n" % decl, name, "(*addr_%s)" % name))
            names.append(name)
        else:
            print '**** function name not fount in "%s"' % decl
            

f6 = open("Xass-list", 'w');
pos = 0
for i in names:
    f6.write(i)
    pos += len(i)
    if pos > 60:
        pos = 0
        f6.write(",\n")
    else:
        f6.write(", ")
f6.write('\n')
f6.close()

file.close()
f1.close()
f2.close()
f3.close()
f4.close()
f5.close()
