../ethereal.1: ethereal.pod
	pod2man ethereal.pod                     \
	--center="The Ethereal Network Analyzer" \
	--release=$(VERSION)			 \
	> ../ethereal.1

ethereal.pod: ethereal.pod.template  ../ethereal
	rm -f ethereal-dump-fields
	ln ../ethereal ethereal-dump-fields
	./ethereal-dump-fields | ./dfilter2pod $(srcdir)/ethereal.pod.template > ethereal.pod
	rm -f ethereal-dump-fields

