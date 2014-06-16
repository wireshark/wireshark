This directory contains the source files needed to build the:

 - Wireshark User's guide
 - Wireshark Developer's Guide
 - Release notes (NEWS)
 - Lua Reference


To build everything, just do 'make' (for Win32: 'nmake -f Makefile.nmake')
but see the requirements below.

The guides are written in Docbook/XML (formerly Docbook/SGML). The release
notes are written in AsciiDoc (http://asciidoc.org/).

To get HTML, PDF or other output formats, conversions are done using XSL
stylesheets, which provides a flexible way for these conversions.

By default the Makefile generates HTML in single page and multiple (chunked)
formats and two PDF's.

Win32 only: The optional output format CHM has to be enabled by setting
HHC_EXE in ..\config.nmake. Microsoft has dropped support for HTML Help


Settings:
---------

Win32 only: ..\config.nmake
---------------------------
Settings moved to: ..\config.nmake.


Requirements:
-------------

DocBook XML DTD
---------------
DocBook "official" XML DTD V4.5:
http://www.oasis-open.org/docbook/xml/
(available as a package for Linux / Cygwin)

DocBook XSL
-----------
The "official" XSL stylesheets from Norman Walsh:
http://docbook.sourceforge.net/
(available as a package for Linux / Cygwin)

xsltproc
--------
The XSL processor xsltproc. Part of libxslt:
http://xmlsoft.org/xslt/
Available as a package for Linux / Cygwin.
Supplied with Mac OS X Panther and later.

xmllint
-------
Needed to validate if the .xml files conform to the Docbook/XML DTD.
Part of libxml2:
http://xmlsoft.org/
Available as a package for Linux / Cygwin.
Supplied with Mac OS X Panther and later.

FOP processor (for PDF generation only)
---------------------------------------
FOP processor from the apache project:
http://xml.apache.org/fop/

FOP is a Java program, so you need to have a Java environment installed.
The makefiles look for fop-1.0 in the docbook directory. You can change
this location by setting the FOP environment variable or by changing
config.nmake.

FOP might return an OutOfMemoryException. You can limit its memory usage
by adding " -Xmx256m" to the FOP_OPTS environment variable. The Windows
makefile does this by default.

Hyphenation Patterns
--------------------
Hyphenation patterns for FOP can be found at
http://offo.sourceforge.net/hyphenation/. Different pattern files have
different licenses. The English patterns may have restrictions on
commercial use.

JIMI (for PDF generation)
-------------------------
Jimi is a JAVA class library for managing images.
In addition to FOP, be sure to also have installed JAI and/or jimi to be able
to use/convert the PNG graphics files. The FOP release note webpage tells how
to do it:
download jimi from:
http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-java-client-419417.html
then extract the archive, then copy JimiProClasses.zip to FOP's lib dir and
rename it to jimi-1.0.jar.

AsciiDoc
--------
Text documentation format and conversion suite:
http://asciidoc.org/.  AsciiDoc can use either w3m (default) or Lynx
for plain text output.  We use AsciiDoc for the Developer's Guide and
for the release notes; Lynx as well is used for the official plaintext
release announcments.

Lynx
----
Text based web browser which can to convert HTML to plain text.
(Alternative [*nix]: elinks)

dblatex
-------
DocBook to LaTeX converter. Required for AsciiDoc PDF conversion on Win32.

Win32 only: HTML help compiler (for .chm generation only)
---------------------------------------------------------
HTML Help Compiler (hhc.exe) from Microsoft:
http://www.microsoft.com/en-us/download/details.aspx?id=21138

Packages for Win32
------------------
See ..\config.nmake for Win32 settings. You may need to run
"build-docbook-catalog" in order to register your catalog properly.

Tool/File           Cygwin Package          Opt./Mand.  Comments
---------           --------------          ----------  --------
xsltproc:           Doc/libxslt             M
xmllint:            Doc/libxml2             M
xsl stylesheets:    Doc/docbook-xsl         M           docbook.xsl, chunk.xsl and htmlhelp.xsl
docbookx.dtd:       Doc/docbook-xml42       M
lynx:               Web/lynx                M
asciidoc            Python/asciidoc         M           cygwin python is a dependency and will also be installed (if not installed)
dblatex             Text/dblatex            O           A number of dependencies will also be installed
fop:                -                       O           URL: http://xml.apache.org/fop/ - install it into docbook\fop-1.0 to keep defaults from config.nmake
jimi:               -                       O           URL: http://java.sun.com/products/jimi/ - see above
hhc:                -                       O           URL: http://msdn.microsoft.com/library/default.asp?url=/library/en-us/htmlhelp/html/hwMicrosoftHTMLHelpDownloads.asp
zip:                Archive/zip             O
getopt:             Utils/util-linux        O           Required to run "build-docbook-catalog"


Packages for Suse 9.3
---------------------
Tool/File           Package                 Opt./Mand.  Comments
---------           -------                 ----------  --------
xsltproc:           libxslt                 M
xmllint:            libxml2                 M
xsl stylesheets:    docbook-xsl-stylesheets M           docbook.xsl and chunk.xsl
docbookx.dtd:       docbook_4               M
fop:                fop                     O
jimi:               -                       O           get it from http://java.sun.com/products/jimi/ - see above


Packages for Gentoo
-------------------
Like with all packages do ...
Check dependencies: emerge -p <package>
Install it:         emerge <package>

Tool/File           Package                  Opt./Mand.   Comments
---------           -------                  ----------   --------
xsltproc:           libxslt                  M
xmllint:            libxml2                  M
xsl stylesheets:    docbook-xsl-stylesheets  M            docbook.xsl and chunk.xsl
                                                          Necessary docbook catalogs are built automatically by portage in /etc/xml and /etc/sgml
                                                            docbook.xsl and chunk.xsl using "/usr/bin/build-docbook-catalog".
                                                            So docbook runs out of the box on Gentoo.
docbookx.dtd:       docbook-xml-dtd          M
fop:                fop                      O            Has a lot of JAVA dependencies.
jimi:               sun-jimi                 O            Used by fop.
Quanta+             quanta or kdewebdev      O            Nice HTML/XML/SGML and Docbook editor with Syntaxhighlighting, Autocompletion, etc.

Tip: The actual DTD version of Gentoo is 4.4, but wireshark docs still use 4.2.
     To be able to generate the docs, change the version in the second line of
     developer-guide.xml or install an older version of the DTD.
     See into the Gentoo handbook howto unmask old versions.


Packages for Fedora
-------------------
Tool/File           Package                 Opt./Mand.  Comments
---------           -------                 ----------  --------
xsltproc:           libxslt                 M
xmllint:            libxml2                 M
xsl stylesheets:    docbook-style-xsl       M           docbook.xsl and chunk.xsl
docbookx.dtd:       docbook-dtds            M           provides v4.1, v4.2, v4.3, v4.4 DTDs
asciidoc:           ascidoc                 M

fop:                fop                     O           See above
jimi:               -                       O           get it from http://java.sun.com/products/jimi/ - see above

Note: There are required dependencies (such as xml-common and sgml-common);
      yum is your friend for doing package installs including required
      dependencies.


Packages for Debian
-------------------
Tool/File           Package                 Opt./Mand.  Comments
---------           -------                 ----------  --------
xsltproc:           libxslt                 M
xmllint:            libxml2-utils           M
xsl stylesheets:    docbook-xsl             M
chunk.xsl:          docbook-xsl             M
htmlhelp.xsl:       docbook-xsl             M
docbookx.dtd:       docbook-xml             M
fop:                fop                     O           See above
jimi:               -                       O           http://java.sun.com/products/jimi/ - see above



Makefile / Makefile.nmake:
--------------------------
There are several ways and tools to do these conversion, following is a short
description of the way the makefile targets are doing things and which output
files required for a release in that format.

all
Will generate both guide's in all available output formats (see below).

make wsug
Will generate Wireshark User's Guide in all available output formats.

make wsug_html
The HTML file is generated using xsltproc and the XSL stylesheets from
Norman Walsh. This is a conversion into a single HTML page.
output: wsug_html

make wsug_html_chunked
The HTML files are generated using xsltproc and the XSL stylesheets from
Norman Walsh. This is a conversion into chunked (multiple) HTML pages.
output: wsug_html_chunked

make wsug_pdf_us
make wsug_pdf_a4
The PDF is generated using an intermediate format named XSL-FO (XSL
formatting objects). xsltproc converts the XML to a FO file, and then FOP
(Apache's formatting object processor) is used to generate the PDF document,
in US letter or A4 paper format.
Tip: You will get lot's of INFO/WARNING/ERROR messages when generating PDF,
but the conversion works just fine.
output: user-guide-us.pdf user-guide-a4.pdf

make wsug_chm
On Win32 platforms, the "famous" HTML help format can be generated by using a
special HTML chunked conversion and then use the htmlhelp compiler from
Microsoft.
output: htmlhelp.chm

Using the prefix wsdg_ instead of wsug_ will build the same targets but for the
Wireshark Developer's Guide.

The makefile is written to be run with make on UNIX/Linux platforms.
Win32 platforms have to use nmake -f Makefile.nmake


Notes to authors
----------------
The docbook DTD provides you with all tags required to mark up a documents
structure. Please have a look at the existing XML files to see what these
structural tags are, and look at the DocBook web references below.
To maintain a consistent look and feel in the documents please use the
following tags for the indicated purposes.

Tag           Purpose
---           -------
<application> to mark application names, like Wireshark.
<filename>    to mark an individual file or path.
<command>     to mark a command, with parameters.
<prompt>      to mark a prompt before user input.
<userinput>   to mark an example of user input, like an actual command line.
<function>    to mark a function name, ending with parenthesis.
<parameter>   to mark (function) parameters.
<varname>     to mark (environment) variables.
<literal>     to mark some literal value.

These are all tags for inline text. Wrap literal text output in a CDATA block,
like so:

       <programlisting>
<![CDATA[#include <epan/tap.h>
...
]]>
       </programlisting>

Make sure the CDATA clause is at column 1, because prefixed whitespace will be
present in the verbatim output as well.


Docbook web references:
-----------------------
Some web references to further documentation about Docbook/XML and Docbook XSL
conversions:

DocBook: The Definitive Guide
by Norman Walsh and Leonard Muellner
http://www.docbook.org/tdg/en/html/docbook.html

DocBook XSL: The Complete Guide
by Bob Stayton
http://www.sagehill.net/docbookxsl/index.html

Documention with DocBook on Win32
by Jim Crafton
http://www.codeproject.com/KB/winhelp/docbook_howto.aspx

FO Parameter Reference
by Norman Walsh
http://docbook.sourceforge.net/release/xsl/current/doc/fo/

