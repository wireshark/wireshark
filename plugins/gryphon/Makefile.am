# Makefile.am
# fichier Automake pour gryphon
#

ETHEREAL_DIR=../..

bin_PROGRAMS = gryphon

CLEANFILES = \
	packet-gryphon.o
	gryphon
	*~

gryphon_SOURCES = \
	packet-gryphon.c	\
	packet-gryphon.h

INCLUDES = -I$(ETHEREAL_DIR)

gryphon: packet-gryphon.o
	$(LD) -shared -o $@ $<
