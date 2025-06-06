# Download prebuilt artifacts and extract them on systems that don't
# have a package manager. Track artifacts and versions we install, and
# re-extract them if we have an updates.

# To do:
# - Add support for Windows and migrate win-setup.ps1 here.

# It would be nice to be able to make this self-contained, e.g. by
# extracting artifacts somewhere under CMAKE_BINARY_DIR, but CMake
# doesn't allow source or build paths in INTERFACE_INCLUDE_DIRECTORIES.
#
if (NOT IS_DIRECTORY ${WIRESHARK_BASE_DIR})
# IS_WRITABLE requires CMake 3.29
# if (NOT IS_DIRECTORY ${WIRESHARK_BASE_DIR} OR NOT IS_WRITABLE ${WIRESHARK_BASE_DIR})
  message(FATAL_ERROR "Please make sure ${WIRESHARK_BASE_DIR} is a directory that is writable by you.")
endif()

set(DOWNLOAD_DIR ${CMAKE_SOURCE_DIR}/_download)
file(MAKE_DIRECTORY ${DOWNLOAD_DIR})
set(ARTIFACTS_DIR ${WIRESHARK_BASE_DIR}/macos-universal-master)
file(MAKE_DIRECTORY ${ARTIFACTS_DIR})
file(MAKE_DIRECTORY ${ARTIFACTS_DIR}/etc/xml)
list(APPEND CMAKE_PREFIX_PATH ${ARTIFACTS_DIR})
set(manifest_file ${ARTIFACTS_DIR}/manifest.txt)

# Make sure we look for our fetched artifacts first.
set(Asciidoctor_ROOT ${ARTIFACTS_DIR})
set(WIRESHARK_XML_CATALOG_PATH ${ARTIFACTS_DIR}/etc/xml/catalog.xml)

if(APPLE)
  set(download_prefix "https://dev-libs.wireshark.org/macos/packages")
  set(OSX_APP_LIBPREFIX ${ARTIFACTS_DIR})
else()
  message(FATAL_ERROR "No artifacts for this system")
endif()

set(artifacts)

function(add_artifact archive_path sha256_hash)
  # XXX Should this be a list of lists instead?
  list(APPEND artifacts "${download_prefix}/${archive_path}:${sha256_hash}:.")
  set(artifacts ${artifacts} PARENT_SCOPE)
endfunction()

function(add_external_artifact archive_url sha256_hash destination_subdir)
  # XXX Should this be a list of lists instead?
  list(APPEND artifacts "${archive_url}:${sha256_hash}:${destination_subdir}")
  set(artifacts ${artifacts} PARENT_SCOPE)
endfunction()

# ExternalProject_Add isn't a good choice here because it assumes that
# we want a build-time target that compiles something from source.
# FetchContent or CPM (https://github.com/cpm-cmake/CPM.cmake) might be
# good choices, but for now just using `file DOWNLOAD` and `file
# ARCHIVE_EXTRACT` seem to do the job.
function(download_artifacts download_ok)
  set(${download_ok} TRUE)
  foreach(artifact ${artifacts})
    string(REGEX MATCH "(https://[^:]+):([^:]+):([^:]+)" _ "${artifact}")
    set(archive_url ${CMAKE_MATCH_1})
    set(sha256_hash ${CMAKE_MATCH_2})
    set(destination_subdir ${CMAKE_MATCH_3})
    get_filename_component(archive_file ${archive_url} NAME)
    message(STATUS "Fetching ${archive_file}")
    file(DOWNLOAD
      ${archive_url}
      ${DOWNLOAD_DIR}/${archive_file}
      EXPECTED_HASH SHA256=${sha256_hash}
      STATUS download_status
      # SHOW_PROGRESS
    )
    list(POP_FRONT download_status retval)
    if (NOT ${retval} EQUAL 0)
      set(${download_ok} FALSE)
      message(FATAL_ERROR "Unable to download ${archive_file}")
      return()
    endif()
    file(ARCHIVE_EXTRACT
      INPUT ${DOWNLOAD_DIR}/${archive_file}
      DESTINATION ${ARTIFACTS_DIR}/${destination_subdir}
    )
  endforeach()
  set(download_ok ${download_ok} PARENT_SCOPE)
endfunction()

function(update_artifacts)
  list(JOIN artifacts "\n" list_manifest_contents)
  set(file_manifest_contents)
  if (EXISTS ${manifest_file})
# IS_READABLE requires CMake 3.29
# if (IS_READABLE ${manifest_file})
    file(READ ${manifest_file} file_manifest_contents)
  endif()
  if(list_manifest_contents STREQUAL file_manifest_contents)
    message(STATUS "Artifacts up to date. Skipping download.")
    return()
  endif()
  # Start with a clean slate.
  foreach(subdir IN ITEMS bin etc include lib libexec share)
    file(REMOVE_RECURSE "${ARTIFACTS_DIR}/${subdir}")
  endforeach()
  download_artifacts(download_ok)
  if(${download_ok})
    # XXX Should we generate the manifest file using configure_file?
    file(WRITE ${manifest_file} ${list_manifest_contents})
  endif()
endfunction()

if(APPLE)
  add_artifact(asciidoctor/asciidoctor-bundle-2.0.23-1-macos-x86_64.tar.xz c033d8873a1c9833fadf5ce97be5fc7321c4bef8485776a27cd6284233641301)
  add_artifact(bcg729/bcg729-1.1.1-1-macos-universal.tar.xz 0e302ac5816fbff353d33a428d25eeaad04d5e2ccd6df20a0003f14431aa63a4)
  add_artifact(brotli/brotli-1.1.0-1-macos-universal.tar.xz afb52675ff9d26a44776b1c53ddb03cf6079ee452ee12a6d2844a58256e7704b)
  add_artifact(c-ares/c-ares-1.34.5-1-macos-universal.tar.xz 158fc19f00529a568738cad60c47bc19374de18935fe12ac5f39364ba2cb0b90)
  add_artifact(glib/glib-bundle-2.84.1-2-macos-universal.tar.xz 4f0d13491cdb1ae1036db190fa9ea60c0781d53453925f727aec1a3b3b93abe7)
  add_artifact(gnutls/gnutls-bundle-3.8.9-1-macos-universal.tar.xz f713df06de9b077ba60d21fc1e0558382a76718fa2853f0e8155639e744f9e9b)
  add_artifact(libgcrypt/libgcrypt-bundle-1.11.0-1-macos-universal.tar.xz a93c989a18be505f78021be45abc1740b4a5cb55505a539fd0b4b1d970b6d183)
  add_artifact(libilbc/libilbc-2.0.2-1-macos-universal.tar.xz cf7c5f34c2101af1fe5b788cce6425b258cdaec03dc3301c4a8d2774a0c06801)
  add_artifact(libmaxminddb/libmaxminddb-1.12.2-1-macos-universal.tar.xz 722af5c180940cf0fcb7588ec2e824a56cc7dc6ed752c9ec263481c78345c187)
  add_artifact(libsmi/libsmi-0.4.8-1-macos-universal.tar.xz 3ebe3d5525bf356eafb1ed29cb9469f13a0b5b7cdae1e81f23da9b996e11a1cc)
  add_artifact(libssh/libssh-0.11.1-1-macos-universal.tar.xz c7c54b66c92f3197cfb7d5154eb6c279c7178ee0e120397aa5107db2118cb661)
  add_artifact(lua/lua-5.4.7-1-macos-universal.tar.xz 8027d98a0782b4ccb8b75fe99d1431bd57be9a0ab819d73cdf66e654cd31fae8)
  add_artifact(lz4/lz4-1.10.0-1-macos-universal.tar.xz f4bf1eb9a67f27afeb4f35d9ffc171493a34792b76c239581cdd2b58fec62711)
  add_artifact(minizip-ng/minizip-ng-4.0.10-1-macos-universal.tar.xz 8da7dc1f6bc97a0ad177a9753ee08353aac03a7d5ae736e49f1a3f5f921f4440)
  add_artifact(nghttp2/nghttp2-1.65.0-1-macos-universal.tar.xz 7851534e772be18c8f82125eaec1317a33647ca561b73986afcefc9ba8053f3a)
  add_artifact(nghttp3/nghttp3-1.9.0-1-macos-universal.tar.xz 44c7195ae41e77b2409283293d9639f427d9e6d05308e13061b6debd686d5870)
  add_artifact(opencore-amr/opencore-amr-0.1.6-1-macos-universal.tar.xz f0b5fc51b1591b187c1f6dc128c89cc9105931c26293e25255e179889d76d498)
  add_artifact(opus/opus-1.5.2-1-macos-universal.tar.xz 84f5430e703e72de7201be81ca7847b4eb69ceb44836210802f4321e6d72ade5)
  add_artifact(sbc/sbc-2.1-1-macos-universal.tar.xz 290621fdc6c840c0e06800d6be17a78fdd1be31fd8c71be62c39a393709141f9)
  add_artifact(snappy/snappy-1.2.2-1-macos-universal.tar.xz f68155652ba367f44ff66aacff88679d577e483a1a4bdc167799bd78951daf85)
  add_artifact(spandsp/spandsp-0.0.6-1-macos-universal.tar.xz 8d3371e79eeff754f93320080fb9efd4aa80ed2718411c98360a0c431ff88563)
  add_artifact(speexdsp/speexdsp-1.2.1-1-macos-universal.tar.xz 001933a7631fdafa0cca621891a8ad33ccc91fc33d756753a38a7d3f324ce397)
  add_artifact(zlib-ng/zlib-ng-2.2.4-1-macos-universal.tar.xz 52f1f054be4c97320b4417ebad5d4d8e278f615efac8fbec94abb4986100cbb0)
  add_artifact(zstd/zstd-1.5.7-1-macos-universal.tar.xz a7bfa6fdc228badbe30da5b89fc875e1c9bad52ee692df117aba9721798249d0)

  add_external_artifact(https://docbook.org/xml/5.0.1/docbook-5.0.1.zip 7af9df452410e035a3707883e43039b4062f09dc2f49f2e986da3e4c0386e3c7 etc/xml)
  add_external_artifact(https://github.com/docbook/xslt10-stylesheets/releases/download/release%2F1.79.2/docbook-xsl-1.79.2.zip 853dce096f5b32fe0b157d8018d8fecf92022e9c79b5947a98b365679c7e31d7 etc/xml)
  add_external_artifact(https://github.com/docbook/xslt10-stylesheets/releases/download/release%2F1.79.2/docbook-xsl-nons-1.79.2.zip ba41126fbf4021e38952f3074dc87cdf1e50f3981280c7a619f88acf31456822 etc/xml)

  if(BUILD_stratoshark OR BUILD_falcodump)
    add_artifact(falcosecurity-libs/falcosecurity-libs-bundle-0.21.0-1-macos-universal.tar.xz b0ac98e6f1906f891a8aa8c552639a1d6595aee26adfb730da9ff643d5e4bfaf)
    add_artifact(falcosecurity-libs/falcosecurity-plugins-2025-06-11-1-macos-universal.tar.xz e23c3b3c469f9cc84d509d7880653b8e0743d11a20105188402fec5cef0fde9d)
  endif()
endif()

update_artifacts()

unset(manifest_file)
unset(download_prefix)
unset(artifacts)
unset(external_artifacts)
