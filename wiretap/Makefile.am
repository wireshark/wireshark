bin_PROGRAMS = wiretap filterc
noinst_LIBRARIES = @LIBWIRETAP_A@

EXTRA_LIBRARIES = libwiretap.a

CLEANFILES = \
	libwiretap.a		\
	filterc 		\
	*~ 			\
	ct-grammar.c		\
	ct-scanner.c		\
	ct-tokdefs.h		\
	rt-grammar.c		\
	rt-grammar.y		\
	rt-scanner.c		\
	rt-scanner.l		\
	rt-tokdefs.h

libwiretap_a_SOURCES = \
	bpf.c			\
	bpf-engine.c		\
	buffer.c		\
	buffer.h		\
	config.h		\
	file.c			\
	iptrace.c		\
	iptrace.h		\
	lanalyzer.c		\
	lanalyzer.h		\
	libpcap.c		\
	libpcap.h		\
	netmon.c		\
	netmon.h		\
	netxray.c		\
	netxray.h		\
	ngsniffer.c		\
	ngsniffer.h		\
	rt-compile.c		\
	rt-grammar.c		\
	rt-scanner.c		\
	snoop.c			\
	snoop.h			\
	wtap.c			\
	wtap.h

filterc_SOURCES = \
	ct-compile.c		\
	ct-grammar.c		\
	ct-main.c		\
	ct-scanner.c		\
	glib-new.c

FILTERS = \
	filter-eth		\
	filter-tr

CT_YACC=bison -y
CT_LEX=flex -i
RT_YACC=bison -y -p wtap_
RT_LEX=flex -i -Pwtap_

ct-grammar.c : ct-grammar.y
	@rm -f $@ ct-tokdefs.h
	$(CT_YACC) -d $<
	mv y.tab.c ct-grammar.c
	mv y.tab.h ct-tokdefs.h

ct-scanner.c : ct-scanner.l
	@rm -f $@
	$(CT_LEX) -t $< > $@

rt-scanner.l : rt-scanner-skel.l filterc
	cat $(FILTERS) | ./filterc > /dev/null

rt-scanner.c : rt-scanner.l rt-grammar.c
	@rm -f $@
	$(RT_LEX) -t $< > $@

rt-grammar.y : rt-grammar-skel.y filterc
	cat $(FILTERS) | ./filterc > /dev/null

rt-grammar.c : rt-grammar.y
	@rm -f $@ rt-tokdefs.h
	$(RT_YACC) -d $<
	mv y.tab.c rt-grammar.c
	mv y.tab.h rt-tokdefs.h

wiretap_SOURCES = \
	wiretap.c 		\
	glib-new.c

wiretap_LDADD = libwiretap.a
