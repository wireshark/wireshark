#
# Make the "Ethereal User's Guide" in several formats.
# See the Readme.txt file for instructions.
#
# $Id$
#

# if you need to change this, don't forget to change it in catalog.xml too

# On suse 9.1, uncomment the following line:
#DOCBOOKXSL="/usr/share/xml/docbook/stylesheet/nwalsh/1.64.1"

DOCBOOKXSL="/usr/share/docbook-xsl"

# formatting objects processor
# (comment this out, if you don't want pdf or don't have fop installed)
# for win32 (cygwin) environments
FOP="fop-0.20.5/fop.bat"
# for unix like environments (if you have problems with fop, try to use an absolute path here)
#FOP="/usr/share/fop-0.20.5/fop.sh"

# html help compiler (Win32 only)
# (comment this out, if you don't want chm or don't have hhc installed)
#HHC="/cygdrive/c/Program Files/HTML Help Workshop/hhc.exe"

############### YOU SHOULDN'T HAVE TO EDIT ANYTHING BELOW THIS LINE! ################

# the XSL processor
XSLTPROC="xsltproc"

# the XML validator (from the xsltproc package)
XMLLINT="xmllint"

# as eug_chm will stop with an error, make sure it's the last in this dependency list
all: eug edg 

eug: eug_validate eug_pdf_a4 eug_html eug_html_chunked eug_chm 

clean:
	rm -f *.html
	rm -f htmlhelp.*
	rm -f *.hhc
	rm -f *.fo
	rm -f *.pdf
	rm -f *.chm
	rm -rf eug_html
	rm -rf eug_html_chunked
	rm -rf toc.hhc htmlhelp.hhp eug_chm


images:
	cp $(DOCBOOKXSL)/images/note.png ./graphics
	cp $(DOCBOOKXSL)/images/tip.png ./graphics
	cp $(DOCBOOKXSL)/images/warning.png ./graphics

# validate the content
eug_validate:
	@ echo --- VALIDATING XML ---
	$(XMLLINT) --valid --noout user-guide.xml

# create html single page file
eug_html:
	@ echo --- HTML SINGLE PAGE ---
	mkdir -p eug_html
	mkdir -p eug_html/graphics
	mkdir -p eug_html/graphics/toolbar
	cp ./graphics/*.* eug_html/graphics
	cp ./graphics/toolbar/*.* eug_html/graphics/toolbar
	$(XSLTPROC) --nonet $(DOCBOOKXSL)/html/docbook.xsl user-guide.xml > eug_html/user-guide.html
	
# create html chunked page files
eug_html_chunked: images
	@ echo --- HTML CHUNKED ---
	mkdir -p eug_html_chunked
	mkdir -p eug_html_chunked/graphics
	mkdir -p eug_html_chunked/graphics/toolbar
	cp ./graphics/*.* eug_html_chunked/graphics
	cp ./graphics/toolbar/*.* eug_html_chunked/graphics/toolbar
	$(XSLTPROC) --stringparam base.dir eug_html_chunked/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --nonet $(DOCBOOKXSL)/html/chunk.xsl user-guide.xml

# create pdf file (through XSL-FO), portrait pages on US letter paper (the default)
# you will get lot's of errors, but that's ok
eug_pdf_us: images
ifdef FOP
	@ echo --- PDF US PAPER ---
	$(XSLTPROC) --nonet custom_layer_pdf.xsl $(DOCBOOKXSL)/fo/docbook.xsl user-guide.xml > user-guide.fo
	$(FOP) user-guide.fo user-guide.pdf
endif

# create pdf file (through XSL-FO), portrait pages on A4 paper
# you will get lot's of errors, but that's ok
eug_pdf_a4: images
ifdef FOP
	@ echo --- PDF A4 PAPER ---
	$(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl user-guide.xml > user-guide.fo
	$(FOP) user-guide.fo user-guide.pdf
endif

# create MS html help file (through html chunked pages)
eug_chm: images
ifdef HHC
	@ echo --- MICROSOFT HTML HELP ---
	mkdir -p eug_chm
	mkdir -p eug_chm/graphics
	mkdir -p eug_chm/graphics/toolbar
	cp ./graphics/*.* eug_chm/graphics
	cp ./graphics/toolbar/*.* eug_chm/graphics/toolbar
	$(XSLTPROC) --stringparam base.dir eug_chm/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --nonet $(DOCBOOKXSL)/htmlhelp/htmlhelp.xsl user-guide.xml
	-$(HHC) htmlhelp.hhp
	mv htmlhelp.chm user-guide.chm
	rm -r htmlhelp.hhp
	rm -r toc.hhc
endif


edg: edg_validate edg_html_chunked 
#eug_pdf_a4 eug_html eug_chm 

# validate the content
edg_validate:
	@ echo --- VALIDATING XML ---
	$(XMLLINT) --valid --noout developer-guide.xml

# create html chunked page files
edg_html_chunked: images
	@ echo --- HTML CHUNKED ---
	mkdir -p edg_html_chunked
	mkdir -p edg_html_chunked/graphics
	mkdir -p edg_html_chunked/graphics/toolbar
	cp ./graphics/*.* edg_html_chunked/graphics
	cp ./graphics/toolbar/*.* edg_html_chunked/graphics/toolbar
	$(XSLTPROC) --stringparam base.dir edg_html_chunked/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --nonet $(DOCBOOKXSL)/html/chunk.xsl developer-guide.xml

