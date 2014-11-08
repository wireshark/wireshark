#!/bin/sh
# Copyright 2014, Alexis La Goutte (See AUTHORS file)
#
# For clang user: launch the script to add pragma for remove warning about -Wdocumentation
# (using on Petri Dish)


find . ! -name "*.sh" -type f -exec sed -i 's/#include <glib.h>/#pragma clang diagnostic push\n#pragma clang diagnostic ignored "-Wdocumentation"\n#include <glib.h>\n#pragma clang diagnostic pop/g'  {} \;

find . ! -name "*.sh" -type f -exec sed -i 's/#include <gtk\/gtk.h>/#pragma clang diagnostic push\n#pragma clang diagnostic ignored "-Wdocumentation"\n#include <gtk\/gtk.h>\n#pragma clang diagnostic pop/g'  {} \;

find . ! -name "*.sh" -type f -exec sed -i 's/#include <gmodule.h>/#pragma clang diagnostic push\n#pragma clang diagnostic ignored "-Wdocumentation"\n#include <gmodule.h>\n#pragma clang diagnostic pop/g'  {} \;
