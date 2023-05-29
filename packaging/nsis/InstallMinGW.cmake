set(MINGW_BIN "/usr/x86_64-w64-mingw32/sys-root/mingw/bin")

if(MINGW AND NOT USE_MSYSTEM)
	# mingw-w64 dlls
	file(GLOB MINGW_DLLS
		${MINGW_BIN}/iconv.dll
		${MINGW_BIN}/icudata72.dll
		${MINGW_BIN}/icui18n72.dll
		${MINGW_BIN}/icuuc72.dll
		${MINGW_BIN}/libbrotlicommon.dll
		${MINGW_BIN}/libbrotlidec.dll
		${MINGW_BIN}/libbrotlienc.dll
		${MINGW_BIN}/libbz2-1.dll
		${MINGW_BIN}/libcares-2.dll
		${MINGW_BIN}/libcrypto-3-x64.dll
		${MINGW_BIN}/libexpat-1.dll
		${MINGW_BIN}/libffi-8.dll
		${MINGW_BIN}/libfontconfig-1.dll
		${MINGW_BIN}/libfreetype-6.dll
		${MINGW_BIN}/libgcc_s_seh-1.dll
		${MINGW_BIN}/libgcrypt-20.dll
		${MINGW_BIN}/libglib-2.0-0.dll
		${MINGW_BIN}/libgmodule-2.0-0.dll
		${MINGW_BIN}/libgmp-10.dll
		${MINGW_BIN}/libgnutls-30.dll
		${MINGW_BIN}/libgpg-error-0.dll
		${MINGW_BIN}/libharfbuzz-0.dll
		${MINGW_BIN}/libhogweed-6.dll
		${MINGW_BIN}/libintl-8.dll
		${MINGW_BIN}/liblzma-5.dll
		${MINGW_BIN}/libminizip-3.dll
		${MINGW_BIN}/libnettle-8.dll
		${MINGW_BIN}/libopus-0.dll
		${MINGW_BIN}/libp11-kit-0.dll
		${MINGW_BIN}/libpcre2-16-0.dll
		${MINGW_BIN}/libpcre2-8-0.dll
		${MINGW_BIN}/libpng16-16.dll
		${MINGW_BIN}/libspeexdsp-1.dll
		${MINGW_BIN}/libssp-0.dll
		${MINGW_BIN}/libstdc++-6.dll
		${MINGW_BIN}/libtasn1-6.dll
		${MINGW_BIN}/libwinpthread-1.dll
		${MINGW_BIN}/libxml2-2.dll
		${MINGW_BIN}/libzstd.dll
		${MINGW_BIN}/zlib1.dll
	)
endif()
