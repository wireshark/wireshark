# cssparser.py - CSS parsing functions
# Tabs: 8  indent: 4

import re
from frontendutil import *

block_re = re.compile(r'(.*){(.*)}')

# The dict has the following structure:
# 'selector': {
#     'attribute1': value1,
#     'attribute2': value2,
# }
#
# Example:
#
# 'dialog': {
#     'padding-top': '5px',
#     'padding-left': '5px'
# }

# These should be split into -top, -left, -bottom, and -right attributes
tlbr_props = ['padding', 'margin']

css_dict = {}

class CSSParseError:
    pass

def parse_pvpairs(pvtext):
    '''Given some "property: value;" text, parse it out and return it as a dictionary'''

    if pvtext is None:
	return None

    pvdict = {}
    pvpairs = pvtext.split(';')

    lastpvp = pvpairs.pop().strip()
    if lastpvp != "":
	print 'Error parsing "' + pvtext + '"'
	raise CSSParseError

    for pvp in pvpairs:
	parts = pvp.split(':')
	if len(parts) != 2:
	    raise CSSParseError
	prop = parts[0].strip().lower()
	val = parts[1].strip()

	if prop in tlbr_props:
	    pvdict[prop + '-top']    = val
	    pvdict[prop + '-left']   = val
	    pvdict[prop + '-bottom'] = val
	    pvdict[prop + '-right']  = val
	else:
	    pvdict[prop] = val

    return pvdict


def parse_file(filename):
    '''Parse a CSS file, and use its contents to fill in css_dict{}.'''
    cssf = open(filename)

    expr = ''
    for line in cssf.readlines():
	expr += line.strip()
	match = block_re.match(expr)
	if match is not None:
	    expr = ''
	    selector = match.group(1).strip().lower()
	    pvdict = parse_pvpairs(match.group(2))

	    if selector not in css_dict:
		css_dict[selector] = {}

	    css_dict[selector].update(pvdict)

def get_css_attributes(node):
    '''Given an XML node, return its CSS attributes in the form of a dictionary.'''
    element_name = id_to_name(node.nodeName)
    style = get_attribute(node, 'style', None)
    classname = get_attribute(node, 'class', None)
    pvret = {}
    pvinline = parse_pvpairs(style)

    if css_dict.has_key(element_name):
	pvret.update(css_dict[element_name])

    if classname is not None:
	dotclass = '.' + classname.lower()
	if css_dict.has_key(dotclass):
	    pvret.update(css_dict[dotclass])

	# E.g., ".leftspacing button { ... }"
	dotclassel = dotclass + ' ' + element_name
	if css_dict.has_key(dotclassel):
	    pvret.update(css_dict[dotclassel])

    if pvinline is not None:
	pvret.update(pvinline)

    return pvret