#!/bin/env python
#
# Xulender ('zoo-len-d&r) - XUL frontend generator.  Reads a XUL interface
# definition and generates an application frontend for a particular language
# and API.
#
# Mozilla XUL reference: http://www.mozilla.org/xpfe/xulref/
# XUL Planet XUL reference: http://www.xulplanet.com/references/elemref/
#
# Tabs: 8  Indent: 4

# Standard Python modules
import sys
import xml
from xml.dom.minidom import parse
import os
import getopt

# Local modules
import win32csdk
from frontendutil import id_to_name
import cssparser

frontend_list = []

def level_prefix(lvl):
    if lvl == 0: return ''
    return '--' * (lvl - 1) + '->'

def walk_tree(doc, lvl):
    for n in doc.childNodes:

	# To make things a little more clean (but a bit less obvious)
	# we borrow a trick from John Aycock's SPARK utility.  For each
	# frontend we have defined, we first see if a "gen" routine
	# exists for the nodename, e.g. win32_gen_button.  If it does,
	# we call it.  This avoids having a huge if/then/else clause in
	# each frontend module.
	if n.nodeType is n.ELEMENT_NODE:
	    # XXX - For now, we force external elements (e.g. ethereal:packetlist)
	    # into the local "namespace" by converting the colon to an underscore.
	    # We may at some point to put external element generators in their own
	    # modules.
	    element_name = id_to_name(n.nodeName)

	    for fe in frontend_list:
		pfx = fe.get_func_prefix()
		func_name = pfx + '_gen_' + element_name
		if hasattr(fe, func_name):
		    func = getattr(fe, func_name)
		    func(n)

#	    print level_prefix(lvl), element_name,
#	    if n.hasAttributes():
#		print '[',
#		for k in n.attributes.keys():
#		    print k + ': ' + n.attributes[k].value + ' ',
#		print ']'
#	    else:
#		print

	if n.hasChildNodes():
	    walk_tree(n, lvl + 1)

	# Once we've walked our child nodes, see if we have an _end routine
	# defined, and call it.
	if n.nodeType is n.ELEMENT_NODE:
	    for fe in frontend_list:
		pfx = fe.get_func_prefix()
		func_name = pfx + '_gen_' + element_name + '_end'
		if hasattr(fe, func_name):
		    func = getattr(fe, func_name)
		    func(n)

def main():
    path_prefix = ''
    opts, files = getopt.getopt(sys.argv[1:], 'f:I:C:')

    for flag, arg in opts:
    	if flag == '-f':
	    frontends = arg.split(',')
	    for fe in frontends:
		if fe == 'win32csdk':
		    if win32csdk not in frontend_list:
			frontend_list.append(win32csdk)
		else:
		    print 'Error: Unknown frontend "' + fe + '"'
	if flag == '-I':
	    path_prefix = arg

	if flag == '-C':
	    cssparser.parse_file(arg)

    print 'Path prefix: ' + path_prefix

    # XXX - Pass these as command-line arguments from the Makefile
    if (len(files) < 1):
	print "Error: No XUL source file specified."
	return 1

    for xul_file in files:
	ds = open(os.path.join(path_prefix, xul_file))
	try:
	    ui_doc = parse(ds)
	except xml.parsers.expat.ExpatError, err:
	    print 'Error in "%s", line %d, column %d\n' % (
		os.path.join(path_prefix, xul_file),
		err.lineno,
		err.offset + 1,
	    )
	    ds.seek(0)
	    for i in range(err.lineno):
		err_line = ds.readline()
	    print err_line.rstrip()
	    print ' ' * err.offset + '^'
	    print 'ExpatError: ' + \
		xml.parsers.expat.ErrorString(err.code) + '\n'
	    return 1

	walk_tree(ui_doc, 0)

	for fe in frontend_list:
	    fe.cleanup()

if __name__ == '__main__':
    sys.exit(main())
