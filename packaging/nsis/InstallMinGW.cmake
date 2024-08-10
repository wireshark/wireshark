set(MINGW_SYSROOT "/usr/x86_64-w64-mingw32/sys-root/mingw" CACHE FILEPATH "Path to MinGW system root bindir")
set(MINGW_BINDIR ${MINGW_SYSROOT}/bin)

if(MINGW)
	# mingw-w64 dlls
	file(GLOB MINGW_DLLS
		${MINGW_BINDIR}/iconv.dll
		${MINGW_BINDIR}/icudata[1-9][0-9].dll
		${MINGW_BINDIR}/icui18n[1-9][0-9].dll
		${MINGW_BINDIR}/icuuc[1-9][0-9].dll
		${MINGW_BINDIR}/libbrotlicommon.dll
		${MINGW_BINDIR}/libbrotlidec.dll
		${MINGW_BINDIR}/libbrotlienc.dll
		${MINGW_BINDIR}/libbz2-1.dll
		${MINGW_BINDIR}/libcares-*.dll
		${MINGW_BINDIR}/libcrypto-3-x64.dll
		${MINGW_BINDIR}/libexpat-1.dll
		${MINGW_BINDIR}/libffi-8.dll
		${MINGW_BINDIR}/libfontconfig-1.dll
		${MINGW_BINDIR}/libfreetype-6.dll
		${MINGW_BINDIR}/libgcc_s_seh-1.dll
		${MINGW_BINDIR}/libgcrypt-20.dll
		${MINGW_BINDIR}/libglib-2.0-0.dll
		${MINGW_BINDIR}/libgmodule-2.0-0.dll
		${MINGW_BINDIR}/libgmp-10.dll
		${MINGW_BINDIR}/libgnutls-30.dll
		${MINGW_BINDIR}/libgpg-error-0.dll
		${MINGW_BINDIR}/libgraphite2.dll
		${MINGW_BINDIR}/libharfbuzz-0.dll
		${MINGW_BINDIR}/libhogweed-6.dll
		${MINGW_BINDIR}/libiconv-*.dll
		${MINGW_BINDIR}/libidn2-*.dll
		${MINGW_BINDIR}/libintl-8.dll
		${MINGW_BINDIR}/liblz4.dll
		${MINGW_BINDIR}/liblzma-5.dll
		${MINGW_BINDIR}/libminizip-*.dll
		${MINGW_BINDIR}/libnettle-8.dll
		${MINGW_BINDIR}/libnghttp2-*.dll
		${MINGW_BINDIR}/libopus-0.dll
		${MINGW_BINDIR}/libp11-kit-0.dll
		${MINGW_BINDIR}/libpcre2-16-0.dll
		${MINGW_BINDIR}/libpcre2-8-0.dll
		${MINGW_BINDIR}/libpng16-16.dll
		${MINGW_BINDIR}/libsnappy.dll
		${MINGW_BINDIR}/libspeexdsp-1.dll
		${MINGW_BINDIR}/libssp-0.dll
		${MINGW_BINDIR}/libstdc++-6.dll
		${MINGW_BINDIR}/libtasn1-6.dll
		${MINGW_BINDIR}/libunistring-*.dll
		${MINGW_BINDIR}/libwinpthread-1.dll
		${MINGW_BINDIR}/libxml2-2.dll
		${MINGW_BINDIR}/libzstd.dll
		${MINGW_BINDIR}/zlib1.dll
	)
endif()
