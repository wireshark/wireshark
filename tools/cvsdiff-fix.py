#!/usr/bin/python
#
# cvsdiff-fix
#
# Takes the output of "cvs diff", which produces a flattened
# recursive diff, and unflattens it so that it can be
# applied correctly with "patch".
#
# $Id: cvsdiff-fix.py,v 1.2 2001/11/13 23:55:41 gram Exp $
#
# Copyright (C) 2001 by Gilbert Ramirez <gram@alumni.rice.edu>
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
import string

# Open input stream
if len(sys.argv) == 1:
	input = sys.stdin
elif len(sys.argv) == 2:
	try:
		input = open(sys.argv[1])
	except IOError:
		(exc_type, exc_value, exc_traceback) = sys.exc_info()
		print "Cannot open %s for input: %s" % (sys.argv[1], exc_value)
		sys.exit(1)
else:
	print "Usage: %s [diff_file]" % (sys.argv[0])
	sys.exit(1)

# State	Meaning
# -----	-------
# 0	Looking for "^Index: "
# 1	Looking for "^diff "
# 2	Looking for "^---"
# 3	Looking for "^+++"

state = 0
pathname = None
basename = None

re_index = re.compile(r"^Index: (?P<pathname>\S+)")
re_diff = re.compile(r"^diff ")
re_diff_filename = re.compile(r"\S+$")
re_from = re.compile(r"^--- \S+(?P<after>.*)")
re_to = re.compile(r"^\+\+\+ \S+(?P<after>.*)")


for line in input.readlines():
	if line[-1] == "\n":
		line = line[:-1]

	if state == 0:
		match = re_index.search(line)
		if match:
			pathname = match.group("pathname")

			# Find basename
			i = string.rfind(pathname, "/")
			if i == -1:
				i = string.rfind(pathname, "\\")

			if i == -1:
				# if there's no dir info,
				# then there's no reason to
				# process this section
				pass
			else:
				basename = line[i+1:]
				state = 1

	elif state == 1:
		match = re_diff.search(line)
		if match:
			line = re_diff_filename.sub(pathname, line)
			state = 2
	
	elif state == 2:
		match = re_from.search(line)
		if match:
			new_line = "--- %s\\g<after>" % (pathname)
			line = re_from.sub(new_line, line)
			state = 3
		else:
			sys.stderr.write("Expected ^---, but found: %s\n" \
				% (line))

	elif state == 3:
		match = re_to.search(line)
		if match:
			new_line = "+++ %s\\g<after>" % (pathname)
			line = re_to.sub(new_line, line)
			state = 0
		else:
			sys.stderr.write("Expected ^+++, but found: %s\n" \
				% (line))

	print line
