
DIST_SUBDIRS = SPECS

EXTRA_DIST = wireshark.spec.in

clean-local:
	rm -rf BUILD RPMS SOURCES SRPMS

all-local:
	$(MKDIR_P) BUILD RPMS SOURCES SRPMS
	(cd SOURCES && $(LN_S) -f $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.xz .)
	$(RPMBUILD) --define "_topdir $(abs_builddir)" --define "_prefix $(prefix)" \
	    @RPMBUILD_WITH_ARGS@ --clean -ba SPECS/wireshark.spec
	@echo "Package successfully built in `pwd`/RPMS."
