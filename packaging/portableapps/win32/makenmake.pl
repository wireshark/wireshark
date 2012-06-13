#
# makenmake.pl - create a nmake file from a generic manifest file that will create the appropriate PortableApp structure
# $Id$
#

print q{
include ../../../config.nmake
include <win32.mak>

FILES 		= Files
APP 		= App
WIRESHARK 	= Wireshark

TOPDIR	= ..\..\..
STAGING_DIR = $(TOPDIR)\$(INSTALL_DIR)
COPY	= xcopy
MOVE    = mv
MKDIR	= mkdir
COPY_FLAGS	= /d /y 

distribution:
};

while($line = <>) {
    
    if($line =~ /^\#/) { # comment
	next;
    } elsif($line =~ /^\[(\S+)/) { # new directory
	if(defined $define) { # Clear out any leftover defines.
	    print "!ENDIF\n";
	    undef($define);
	}

	$dir = $1;

	$dir =~ s/\$INSTDIR?//; # remove $INSTDIR
	
	$dir =~ s/\{/\(/g; $dir =~ s/\}/\)/g; # convert curlies to round brackets

	if($dir ne '') { 
	    print "\tif not exist \$(FILES)\\\$(APP)\\\$(WIRESHARK)$dir \$(MKDIR) \$(FILES)\\\$(APP)\\\$(WIRESHARK)$dir\n"; 
	}
	
    } else { # this is a file

	$line =~ /^\s+(\S+)/;
	$file = $1;

	$file =~ s/\{/\(/g; $file =~ s/\}/\)/g; # convert curlies to round brackets

	if($file =~ /^[^\$]/) {
	    $file = "\$(TOPDIR)\\" . $file;
	}

	if($line =~ /ifdef=(\w+)/) { # dependency
	    if($define ne $1) {
		if(defined $define) {
		    print "!ENDIF\n";
		}
		$define = $1;
		print "!IF DEFINED($define)\n";
	    }
	} else {
	    
	    if(defined $define) {
		print "!ENDIF\n";
	    }
	    undef $define;
	}

	$oname = "";

	print "\t\$(COPY) \"$file\" \"\$(FILES)\\\$(APP)\\\$(WIRESHARK)$dir\" \$(COPY_FLAGS)\n";

	if($line =~ /oname=(\S+)/) { # override this filename
	    $oname = $1;
	    $file =~ /\\(.*)$/;
	    $name = $1;

	    print "\t\$(MOVE) \"\$(FILES)\\\$(APP)\\\$(WIRESHARK)\\$dir\\$name\" \"\$(FILES)\\\$(APP)\\\$(WIRESHARK)\\$dir\\$oname\"\n";

	}

    }
}
