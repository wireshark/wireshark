#!/bin/sh -e
# Patch lemon.c and lempar.c to silence static analyzer warnings.
# See also tools/lemon/README

# Strip trailing whitespace
sed -e 's/ \+$//' -i lemon.c lempar.c

# Other patches
if [ -d "patches" ]; then
    for i in patches/*.patch; do
        echo "Applying $i"
        patch --silent -p1 -i "$i"
    done
fi

echo DONE
