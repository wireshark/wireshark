#!/usr/bin/gawk -f

function again(i)
{
 # shift remaining arguments up
 for (i = ARGC; i > ARGIND; i--)
     ARGV[i] = ARGV[i-1]

 # make sure gawk knows to keep going
 ARGC++

 # make current file next to get done
 ARGV[ARGIND+1] = FILENAME
}

BEGIN {
	while (getline x) {
		if (x ~ /^static\s*(int|gint)\s*hf_(.*)=\s*-1/) {
			hf = gensub(/^static\s*(int|gint)\s*(\S*).*/, "\\2", "g", x)

			HFS[hf] = ""
		}

		if (x ~ /\{\s*&hf_(.*)/) {
			hf = gensub(/\s*\{\s*\&(.*),(.*)/, "\\1", "g", x)

			if (hf in HFS) {
				hf_descr = gensub(/\s*\{\s*\&(.*),(.*)/, "\\2", "g", x)

				do { 
					getline x
					hf_descr = hf_descr "\n" x
					# XXX, below regex should check if we have { hf description }},
				} while (!(hf_descr ~ /[^{}]*}[^{}]*}[^{}]*,/))

				# get rid of one }
				hf_descr = gensub(/}\S*},/, "}", "g", hf_descr);

				HFS[hf] = hf_descr
			}
		}
	}

	print "#define NEW_PROTO_TREE_API"
	print "converted " length(HFS) > "/dev/stderr"

	again()
	TWOPASS = 1
}

TWOPASS {
	x = $0
	do {
		if (x ~ /^static\s*(int|gint)\s*hf_(.*)=\s*-1/) {
			hf = gensub(/^static\s*(int|gint)\s*(\S*).*/, "\\2", "g", x)
			## XXX, it can have some comment or smth, copy?

			if (hf in HFS && HFS[hf] != "") {
				print "static header_field_info " gensub("^hf_", "hfi_", "g", hf) " THIS_HF_INIT =" HFS[hf] ";"
				print ""
			} else
				print x
		}

		else if (x ~ /\{\s*&hf_(.*)/) {
			hf = gensub(/\s*\{\s*\&(.*),(.*)/, "\\1", "g", x)

			if (hf in HFS) {
				## keep indent
				new_x = gensub(/(\s*)\{\s*\&hf_(.*),(.*)/, "\\1\\&" "hfi_" "\\2" ",", "g", x)

				hf_descr = gensub(/\s*\{\s*\&(.*),(.*)/, "\\2", "g", x)

				do {
					getline x
					hf_descr = hf_descr "\n" x
				} while (!(hf_descr ~ /}/))

				print new_x

			} else
				print x
		} else
			print gensub("hf_", "\\&hfi_", "g", x)

	} while (getline x);
}
