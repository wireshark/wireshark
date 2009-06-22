$Id$

This directory contains the source files needed to build the:

 - Wireshark User's guide
 - Wireshark Developer's Guide
 - Release notes (NEWS)
 - Lua Reference


To build everything, just do 'make' (for Win32: 'nmake -f Makefile.nmake')
but see the requirements below.


The guides are written in Docbook/XML (formerly Docbook/SGML). This format is 
now used by many other documentation projects, e.g. "the linux documentation 
project" uses it too.

To get HTML, PDF or other output formats, conversions are done using XSL 
stylesheets, which provides a flexible way for these conversions.

By default the Makefile generates HTML in single page and multiple (chunked) 
formats and PDF.

Win32 only: The optional output format CHM has to be enabled by setting 
HHC_EXE in ..\config.nmake.


Settings:
---------

Unix only: Makefile and catalog.xml
-----------------------------------------------
You have to edit the settings in these files, to point to the DTD/XSL files 
and fop. (Makefile.auto.am is currently experimental and will probably NOT 
work - any progress on this would be appreciated!)

Win32 only: ..\config.nmake
---------------------------------------
Settings moved to: ..\config.nmake.


Requirements:
-------------

DocBook XML DTD
---------------
DocBook "official" XML DTD V4.2: 
http://www.oasis-open.org/docbook/xml/
(available as a package for Linux / cygwin)

DocBook XSL
-----------
The "official" XSL stylesheets from Norman Walsh: 
http://docbook.sourceforge.net/
(available as a package for Linux / cygwin)

xsltproc
--------
The XSL processor xsltproc. 
(available as a package for Linux / cygwin)

xmllint
-------
Needed to validate if the .xml files conform to the Docbook/XML DTD. 
(available as a package for Linux / cygwin)

FOP processor (for PDF generation only)
---------------------------------------
FOP processor from the apache project:
http://xml.apache.org/fop/
FOP is a JAVA program, so you need to have a JAVA environment installed.
I have put the fop-0.20.5 dir right into the docbook sources dir. If you have 
it somewhere else, you'll have to change the setting in the Makefile 
(or config.nmake for Win32).

As I got OutOfMemoryException when running fop, I had to insert -Xmx256m into 
the last line of the fop.bat file from:
java -cp "%LOCALCLASSPATH%" org.apache.fop.apps.Fop %1 %2 %3 %4 %5 %6 %7 %8
to:
java -Xmx256m -cp "%LOCALCLASSPATH%" org.apache.fop.apps.Fop %1 %2 %3 %4 %5 %6 %7 %8
This should be added automatically on unixish systems.

JIMI (for PDF generation only)
------------------------------
Jimi is a JAVA class library for managing images. 
In addition to FOP, be sure to also have installed JAI and/or jimi to be able 
to use/convert the png graphics files. The fop release note webpage tells how 
to do it: 
download jimi from: 
http://java.sun.com/products/jimi/
then extract the archive, then copy JimiProClasses.zip to FOP's lib dir and rename it to jimi-1.0.jar.

Win32 only: HTML help compiler (for .chm generation only)
---------------------------------------------------------
hhc compiler (hhc.exe) from Microsoft:
http://msdn.microsoft.com/library/default.asp?url=/library/en-us/htmlhelp/html/hwMicrosoftHTMLHelpDownloads.asp 

lynx
----
Text based web browser used to convert release_notes.html into plain text 
format.


Packages for Win32
------------------
See ..\config.nmake for Win32 settings.

Tool/File           Cygwin Package          Opt./Mand.  Comments
---------           --------------          ----------  --------
xsltproc:           Doc/libxslt             M
xmllint:            Doc/libxml2             M
xsl stylesheets:    Doc/docbook-xsl         M           docbook.xsl, chunk.xsl and htmlhelp.xsl
docbookx.dtd:       Doc/docbook_xml42       M
lynx:               Web/lynx                M
fop:                -                       O           URL: http://xml.apache.org/fop/ - install it into fop-0.20.5 to keep defaults from config.nmake
jimi:               -                       O           URL: http://java.sun.com/products/jimi/ - see above
hhc:                -                       O           URL: http://msdn.microsoft.com/library/default.asp?url=/library/en-us/htmlhelp/html/hwMicrosoftHTMLHelpDownloads.asp 
zip:                Archive/zip             O


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
     To be able to generate the docs, change the version in the second line of developer-guide.xml
     or install an older version of the DTD.
     See into the Gentoo handbook howto unmask old versions.


Packages for Fedora 7
---------------------
Tool/File           Package                 Opt./Mand.  Comments
---------           -------                 ----------  --------
xsltproc:           libxslt                 M
xmllint:            libxml2                 M
xsl stylesheets:    docbook-style-xsl       M           docbook.xsl and chunk.xsl
docbookx.dtd:       docbook-dtds            M           provides v4.1, v4.2, v4.3, v4.4 DTDs

fop:                fop                     O           See above
jimi:               -                       O           get it from http://java.sun.com/products/jimi/ - see above

Note: There are required dependencies (such as xml-common and sgml-common); 
      yum is your friend for doing package installs including required  dependencies.


Packages for Debian
-------------------
Tool/File           Package
---------           -------
xsltproc:           libxslt
xmllint:            libxml2-utils
xsl stylesheets:    docbook-xsl
chunk.xsl:          docbook-xsl
htmlhelp.xsl:       docbook-xsl
docbookx.dtd:       docbook-xml
fop:                fop
jimi:               http://java.sun.com/products/jimi/ - see above



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
formatting objects). xsltproc converts the XML to a FO file, and then fop 
(apache's formatting object processor) is used to generate the PDF document, 
in US letter or A4 paper format.
TIP: You will get lot's of INFO/WARNING/ERROR messages when generating pdf, 
but conversation works just fine.
output: user-guide-us.pdf user-guide-a4.pdf

make wsug_chm
On Win32 platforms, the "famous" HTML help format can be generated by using a 
special HTML chunked conversion and then use the htmlhelp compiler from 
Microsoft.
output: htmlhelp.chm

Using the prefix wsdg_ instead of wsug_ will build the same targets but for the 
Wireshark Developer's Guide.

The makefile is written to be run with gmake on UNIX/Linux platforms. Win32 
platforms have to use the cygwin environment (Microsoft nmake is not 
supported).


Docbook web references:
-----------------------
Some web references to further documentation about Docbook/XML and Docbook XSL conversions:

DocBook: The Definitive Guide
by Norman Walsh and Leonard Muellner
http://www.docbook.org/tdg/en/html/docbook.html

DocBook XSL: The Complete Guide
by Bob Stayton
http://www.sagehill.net/docbookxsl/index.html

Documention with DocBook on Win32
by Jim Crafton
http://www.codeproject.com/winhelp/docbook_howto.asp

FO Parameter Reference
by Norman Walsh
http://docbook.sourceforge.net/release/xsl/current/doc/fo/

