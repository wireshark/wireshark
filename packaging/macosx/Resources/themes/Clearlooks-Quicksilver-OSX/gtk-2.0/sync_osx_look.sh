#!/bin/sh
#
#	Reads defaults from Apple preferences and modifies GTK accordingly
#
#	(c) 2007 JiHO <jo.irisson@gmail.com>
#	GNU General Public License http://www.gnu.org/copyleft/gpl.html
#

# Appearance setting
aquaStyle=`defaults read "Apple Global Domain" AppleAquaColorVariant`
# 1 for aqua, 6 for graphite, inexistant if the default color was never changed
if [[ "$aquaStyle" == "" ]]; then
	aquaStyle=1		# set aqua as default
fi

# Highlight Color setting
hiliColor=`defaults read "Apple Global Domain" AppleHighlightColor`
# a RGB value, with components between 0 and 1, also inexistant if it was not changed
if [[ "$hiliColor" == "" ]]; then
	hiliColor="0.709800 0.835300 1.000000"	# set blue as default
fi

# Menu items color
if [[ aquaStyle -eq 1 ]]; then
	menuColor="#4a76cd"	# blue
else
	menuColor="#7c8da4"	# graphite
fi
# Format highlight color as a GTK rgb value
hiliColorFormated=`echo $hiliColor | awk -F " " '{print "\\\{"$1","$2","$3"\\\}"}'`

# echo $menuColor
# echo $hiliColorFormated

# Modify the gtkrc
#	- with the correct colors
#	- to point to the correct scrollbars folder
sed 's/OSX_HILI_COLOR_PLACEHOLDER/'$hiliColorFormated'/g' pre_gtkrc | sed 's/OSX_MENU_COLOR_PLACEHOLDER/\"'$menuColor'\"/g' | sed 's/AQUASTYLE_PLACEHOLDER/'$aquaStyle'/g' > gtkrc
