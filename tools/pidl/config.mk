PIDL = $(PERL) $(pidldir)/pidl

$(pidldir)/Makefile: $(pidldir)/Makefile.PL
	@cd $(pidldir) && $(PERL) Makefile.PL PREFIX=$(prefix)

pidl-testcov: $(pidldir)/Makefile
	cd $(pidldir) && cover -test

installpidl:: $(pidldir)/Makefile
	@$(MAKE) -C $(pidldir) install_vendor VENDORPREFIX=$(prefix) \
		                           INSTALLVENDORLIB=$(datarootdir)/perl5 \
								   INSTALLVENDORBIN=$(bindir) \
								   INSTALLVENDORSCRIPT=$(bindir) \
								   INSTALLVENDORMAN1DIR=$(mandir)/man1 \
								   INSTALLVENDORMAN3DIR=$(mandir)/man3

ifeq ($(HAVE_PERL_EXTUTILS_MAKEMAKER),1)
install:: installpidl
endif

$(pidldir)/lib/Parse/Pidl/IDL.pm: $(pidldir)/idl.yp
	-$(YAPP) -m 'Parse::Pidl::IDL' -o $(pidldir)/lib/Parse/Pidl/IDL.pm $(pidldir)/idl.yp ||\
		touch $(pidldir)/lib/Parse/Pidl/IDL.pm 

$(pidldir)/lib/Parse/Pidl/Expr.pm: $(pidldir)/idl.yp
	-$(YAPP) -m 'Parse::Pidl::Expr' -o $(pidldir)/lib/Parse/Pidl/Expr.pm $(pidldir)/expr.yp ||\
		touch $(pidldir)/lib/Parse/Pidl/Expr.pm 

testcov-html:: pidl-testcov

pidl-clean:
	/bin/rm -f $(pidldir)/Makefile

clean:: pidl-clean
