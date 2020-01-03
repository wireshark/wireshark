#!/bin/bash
#
# USAGE
# osx-extras
#
# This script preps the "Extras" packages prior to package creation.
#

set -e
shopt -s extglob

# Help message
#----------------------------------------------------------
help()
{
echo -e "
Prepare Wireshark's \"Extras\" packages.

USAGE
	$0

OPTIONS
	-h,--help
		Display this help message.
"
}


# Parse command line arguments
#----------------------------------------------------------
while [ "$1" != "" ]
do
	case $1 in
		-h|--help)
			help
			exit 0 ;;
		*)
			echo "Invalid command line option: $1"
			exit 2 ;;
	esac
	shift 1
done

script_dir=$( dirname "$0" )

codesign_file () {
	# https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html
	# https://developer.apple.com/library/archive/technotes/tn2206/_index.html
	# https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution/resolving_common_notarization_issues?language=objc
	#
	# XXX Do we need to add the com.apple.security.cs.allow-unsigned-executable-memory
	# entitlement for Lua?
	# https://developer.apple.com/documentation/security/hardened_runtime_entitlements?language=objc
	codesign \
		--sign "Developer ID Application: $CODE_SIGN_IDENTITY" \
		--force \
		--timestamp \
		--verbose \
		"$1"
}

if [ -n "$CODE_SIGN_IDENTITY" ] ; then
	security find-identity -v -s "$CODE_SIGN_IDENTITY" -p codesigning

	# According to
	# https://developer.apple.com/library/archive/technotes/tn2206/_index.html and
	# https://carlashley.com/2018/09/23/code-signing-scripts-for-pppc-whitelisting/
	# script signatures are stored in the file's extended attributes.
	#
	# In general, signing shell scripts probably isn't very useful.
	# In this specific case we should be able to ensure that
	# ChmodBPF's extended attributes are preserved from the build
	# system to the end user's machine.

	chmodbpf="$script_dir/ChmodBPF/root/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF"
	echo "Signing ChmodBPF"
	codesign_file "$chmodbpf"

	# Code Signing Guide, "Testing Conformance with Command Line Tools"
	codesign --verify --strict --verbose=2 "$chmodbpf" || exit 1
else
	echo "Extras code signing not performed (no identity)"
fi

exit 0
