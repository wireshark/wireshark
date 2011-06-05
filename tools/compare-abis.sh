#!/bin/bash

# Compare ABIs of two Wireshark working copies
# $Id: $

function acc () {
	LIBNAME=$1
	DIR=$2
	# compare only dumped ABI descriptions first, then fall back to full comparison
	# if no difference is found
	if abi-compliance-checker -separately -l $LIBNAME \
		-d1 $V1_PATH/$DIR/.libs/$LIBNAME.abi.tar.gz \
		-d2 $V2_PATH/$DIR/.libs/$LIBNAME.abi.tar.gz ; then
		abi-compliance-checker -separately -l $LIBNAME \
			-d1 $V1_PATH/$DIR/abi-descriptor.xml -relpath1 $V1_PATH/$DIR \
			-v1 `ls  $V1_PATH/$DIR/.libs/$LIBNAME.so.?.?.?|sed 's/.*\.so\.//'` \
			-d2 $V2_PATH/$DIR/abi-descriptor.xml -relpath2 $V2_PATH/$DIR \
			-v2 `ls  $V2_PATH/$DIR/.libs/$LIBNAME.so.?.?.?|sed 's/.*\.so\.//'` \
			-check-implementation
	fi
}

V1_PATH=$1
V2_PATH=$2

# both working copies has to be build first
#make -C $V1_PATH all dumpabi
#make -C $V2_PATH all dumpabi

acc libwiretap wiretap $V1_PATH $V2_PATH
RET=$?
acc libwsutil wsutil $V1_PATH $V2_PATH 
RET=$(($RET + $?))
acc libwireshark epan $V1_PATH $V2_PATH 
exit $(($RET + $?))

