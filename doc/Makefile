../ethereal.1: ethereal.pod
	pod2man ethereal.pod                     \
	--center="The Ethereal Network Analyzer" \
	--release=`cat ../VERSION`               \
	> ../ethereal.1

ethereal.pod: ethereal.pod.template 
	cat ../out | ./dfilter2pod ethereal.pod.template > ethereal.pod

