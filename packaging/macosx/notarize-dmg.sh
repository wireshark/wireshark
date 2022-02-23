#!/bin/bash
#
# USAGE
# notarize-dmg -u <developer id> "/path/to/Wireshark x.y.z arch.dmg"

# https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution
# https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution/customizing_the_notarization_workflow

bundle_id="org.wireshark.dmg.$( printf "%04x" $RANDOM )"

# Parse command line arguments
while getopts u: OPTCHAR
do
	case $OPTCHAR in
	u)
		username="$OPTARG"
		shift 2
		;;
	*)
		echo "Invalid command line option"
		exit 2 ;;
	esac
done

dmg_file="$1"

if [[ "$username" != *?@*? ]] ; then
	echo "Username doesn't appear to be a valid Apple developer ID."
	exit 1
fi

if [ ! -r "$dmg_file" ] ; then
	echo "Can't find file: ${dmg_file:-No file specified}"
	exit 1
fi

# XXX Set account to $username instead?
generic_pw_service="WS_DMG_NOTARIZE"

if ! security find-generic-password -a "$username" -s "$generic_pw_service" > /dev/null 2>&1 ; then
	echo -e "No keychain credentials found. You can add them by running\\n"
	echo -e "    security add-generic-password -a $username -s $generic_pw_service -T altool -w\\n"
	exit 2
fi

echo -e "Notarizing $dmg_file\\n"
echo -e "SHA256 pre: $(shasum -a 256 "$dmg_file" | awk '{print $1}' )\\n"

if ! altool_out=$( mktemp /tmp/notarize-dmg.out.XXXXX ) ; then
	echo "Unable to create temp file"
	exit 1
fi
# trap 'rm -f "$altool_out"' EXIT

xcrun altool \
	--notarize-app \
	--type osx \
	--username "$username" \
	--password "@keychain:${generic_pw_service}" \
	--primary-bundle-id "$bundle_id" \
	--file "$dmg_file" \
	2>&1 | tee "$altool_out"

request_uuid=$( awk '/^RequestUUID/ { print $3 }' < "$altool_out")
if [[ "$request_uuid" != *-*-*-*-* ]] ; then
	echo "Unable to fetch request UUID"
	exit 1
fi

notarization_info_cmd=(xcrun altool \
	--notarization-info "$request_uuid" \
	--user "$username" \
	--password "@keychain:${generic_pw_service}" \
	)

start=$SECONDS

max_status_wait=$(( 20 * 60))
start=$SECONDS
while true ; do
	printf "\\nWaiting 15s \xe2\x80\xa6 "
	sleep 15
	elapsed=$(( SECONDS - start ))
	echo "done. Checking status after ${elapsed}s"
	"${notarization_info_cmd[@]}" 2>&1 | tee "$altool_out"
	grep "Status: in progress" "$altool_out" > /dev/null 2>&1 || break
	if [[ $elapsed -gt $max_status_wait ]] ; then break ; fi
done

staple_cmd=(xcrun stapler staple "$dmg_file")

if ! grep "Status: success" "$altool_out" > /dev/null 2>&1 ; then
	echo "Notarization failed or timed out:"
	cat "$altool_out"
	echo -e "\\nInfo command:"
	echo "${notarization_info_cmd[@]}"
	echo -e "\\nStaple command:"
	echo "${staple_cmd[@]}"
	echo "You can check the status of the Notary Service at https://developer.apple.com/system-status/."
	exit 1
fi

echo -e "\\nStapling $dmg_file"
"${staple_cmd[@]}"

echo -e "\\nSHA256 post: $(shasum -a 256 "$dmg_file" | awk '{print $1}' )"

# macOS 10.14.5+ requires notarization in order for this to pass?
# https://wiki.lazarus.freepascal.org/Notarization_for_macOS_10.14.5%2B
spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg_file" || exit 1
