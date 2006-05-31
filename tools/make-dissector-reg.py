#!/usr/bin/env python
#
# Looks for registration routines in the protocol dissectors,
# and assembles C code to call all the routines.
#
# This is a Python version of the make-reg-dotc shell script.
# Running the shell script on Win32 is very very slow because of
# all the process-launching that goes on --- multiple greps and
# seds for each input file.  I wrote this python version so that
# less processes would have to be started.
#
# $Id$

import os
import sys
import re

#
# The first argument is the directory in which the source files live.
#
srcdir = sys.argv[1]

#
# The second argument is either "plugin" or "dissectors"; if it's
# "plugin", we build a plugin.c for a plugin, and if it's
# "dissectors", we build a register.c for libwireshark.
#
registertype = sys.argv[2]
if registertype == "plugin":
	tmp_filename = "plugin.c-tmp"
	final_filename = "plugin.c"
elif registertype == "dissectors":
	tmp_filename = "register.c-tmp"
	final_filename = "register.c"
else:
	print "Unknown output type '%s'" % registertype
	sys.exit(1)
	

#
# All subsequent arguments are the files to scan.
#
files = sys.argv[3:]

# Create the proper list of filenames
filenames = []
for file in files:
	if os.path.isfile(file):
		filenames.append(file)
	else:
		filenames.append("%s/%s" % (srcdir, file))


# Look through all files, applying the regex to each line.
# If the pattern matches, save the "symbol" section to the
# appropriate array.
proto_reg = []
handoff_reg = []

# For those that don't know Python, r"" indicates a raw string,
# devoid of Python escapes.
proto_regex0 = r"^(?P<symbol>proto_register_[_A-Za-z0-9]+)\s*\([^;]+$"
proto_regex1 = r"void\s+(?P<symbol>proto_register_[_A-Za-z0-9]+)\s*\([^;]+$"

handoff_regex0 = r"^(?P<symbol>proto_reg_handoff_[_A-Za-z0-9]+)\s*\([^;]+$"
handoff_regex1 = r"void\s+(?P<symbol>proto_reg_handoff_[_A-Za-z0-9]+)\s*\([^;]+$"

# This table drives the pattern-matching and symbol-harvesting
patterns = [
	( proto_reg, re.compile(proto_regex0) ),
	( proto_reg, re.compile(proto_regex1) ),
	( handoff_reg, re.compile(handoff_regex0) ),
	( handoff_reg, re.compile(handoff_regex1) ),
	]

# Grep
for filename in filenames:
	file = open(filename)
#	print "Searching %s" % (filename)
	for line in file.readlines():
		for action in patterns:
			regex = action[1]
			match = regex.search(line)
			if match:
				symbol = match.group("symbol")
				list = action[0]
				list.append(symbol)
	file.close()

# Sort the lists to make them pretty
proto_reg.sort()
handoff_reg.sort()

reg_code = open(tmp_filename, "w")

reg_code.write("/* Do not modify this file.  */\n")
reg_code.write("/* It is created automatically by the Makefile.  */\n")

# Make the routine to register all protocols
if registertype == "plugin":
	reg_code.write("""
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>

#include "moduleinfo.h"

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

G_MODULE_EXPORT void
plugin_register (void)
{
""");
else:
	reg_code.write("""
#include "register.h"
void
register_all_protocols(void)
{
""");

for symbol in proto_reg:
	line = "  {extern void %s (void); %s ();}\n" % (symbol, symbol)
	reg_code.write(line)

reg_code.write("}\n")


# Make the routine to register all protocol handoffs
if registertype == "plugin":
	reg_code.write("""
G_MODULE_EXPORT void
plugin_reg_handoff(void)
{
""");
else:
	reg_code.write("""
void
register_all_protocol_handoffs(void)
{
""");

for symbol in handoff_reg:
	line = "  {extern void %s (void); %s ();}\n" % (symbol, symbol)
	reg_code.write(line)

reg_code.write("}\n")

if registertype == "plugin":
	reg_code.write("#endif\n");

# Close the file
reg_code.close()

# Remove the old final_file if it exists.
try:
	os.stat(final_filename)
	os.remove(final_filename)
except OSError:
	pass

# Move from tmp file to final file
os.rename(tmp_filename, final_filename)


