#!/bin/sh

# Create any missing directories with mode 755, owned by root:wheel.
# Don't blindly clobber anything that's already there.
function build_path()
{
	echo "Checking $1"
	if [ ! -d "$1" ] ; then
		TRIMMED=`dirname "$1"`
		if [ ! -d "$TRIMMED" ] ; then
			build_path "$TRIMMED"
		fi
		install -v -o root -g wheel -m 0755 -d "$1"
	fi

}

build_path "$2"
