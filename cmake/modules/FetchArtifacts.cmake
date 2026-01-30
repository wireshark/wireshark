# Download prebuilt artifacts and extract them on systems that don't
# have a package manager. Track artifacts and versions we install, and
# re-extract them if we have an updates.

# It would be nice to be able to make this self-contained, e.g. by
# extracting artifacts somewhere under CMAKE_BINARY_DIR, but CMake
# doesn't allow source or build paths in INTERFACE_INCLUDE_DIRECTORIES.
#

if (APPLE)
  if (NOT IS_DIRECTORY ${WIRESHARK_BASE_DIR})
  # IS_WRITABLE requires CMake 3.29
  # if (NOT IS_DIRECTORY ${WIRESHARK_BASE_DIR} OR NOT IS_WRITABLE ${WIRESHARK_BASE_DIR})
    message(FATAL_ERROR "Please make sure ${WIRESHARK_BASE_DIR} is a directory that is writable by you.")
  endif()
  set(ARTIFACTS_DIR ${WIRESHARK_BASE_DIR}/macos-universal-4.6)
  set(download_prefix "https://dev-libs.wireshark.org/macos/packages")
  # Make sure we look for our fetched artifacts first.
  set(Asciidoctor_ROOT ${ARTIFACTS_DIR})
  file(MAKE_DIRECTORY ${ARTIFACTS_DIR}/etc/xml)
  set(WIRESHARK_XML_CATALOG_PATH ${ARTIFACTS_DIR}/etc/xml/catalog.xml)
  set(OSX_APP_LIBPREFIX ${ARTIFACTS_DIR})
elseif(WIN32)
  set(ARTIFACTS_DIR ${_PROJECT_LIB_DIR})
  set(download_prefix "https://dev-libs.wireshark.org/windows/packages")
  # Make sure we look for our fetched artifacts first.
  set(asciidoctor_version "2.0.23-1")
  set(Asciidoctor_ROOT ${ARTIFACTS_DIR}/asciidoctor-bundle-${asciidoctor_version}-x64-windows-ws)
  set(WIRESHARK_XML_CATALOG_PATH ${Asciidoctor_ROOT}/etc/xml/catalog.xml)
else()
  message(FATAL_ERROR "No artifacts for this system")
endif()

set(DOWNLOAD_DIR ${CMAKE_SOURCE_DIR}/_download)
file(MAKE_DIRECTORY ${DOWNLOAD_DIR})

file(MAKE_DIRECTORY ${ARTIFACTS_DIR})
list(APPEND CMAKE_PREFIX_PATH ${ARTIFACTS_DIR})
set(manifest_file ${ARTIFACTS_DIR}/manifest.txt)

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
  if(APPLE)
    foreach(subdir IN ITEMS bin etc include lib libexec share)
      file(REMOVE_RECURSE "${ARTIFACTS_DIR}/${subdir}")
    endforeach()
  elseif(WIN32)
    # XXX We need to do this more cleanly. We might want to install our Windows
    # libraries in a common root similar to what we do for macOS.
    file(GLOB artifact_dirs
      ${ARTIFACTS_DIR}/asciidoctor-bundle-*-windows-ws
      ${ARTIFACTS_DIR}/bcg729-*ws
      ${ARTIFACTS_DIR}/brotli-*ws
      ${ARTIFACTS_DIR}/c-ares-*-windows-ws
      ${ARTIFACTS_DIR}/falcosecurity-*-ws
      ${ARTIFACTS_DIR}/gnutls-*-ws
      ${ARTIFACTS_DIR}/krb5-*-windows-ws
      ${ARTIFACTS_DIR}/libgcrypt-bundle-*-ws
      ${ARTIFACTS_DIR}/libilbc-*-windows-ws
      ${ARTIFACTS_DIR}/libmaxminddb-*-windows-ws
      ${ARTIFACTS_DIR}/libsmi-*-windows-ws
      ${ARTIFACTS_DIR}/libssh-*-ws
      ${ARTIFACTS_DIR}/lua-*-win*64-*
      ${ARTIFACTS_DIR}/lz4-*-windows-ws
      ${ARTIFACTS_DIR}/minizip-*-windows-ws
      ${ARTIFACTS_DIR}/nghttp?-*-windows-ws
      ${ARTIFACTS_DIR}/opencore-amr-*-ws
      ${ARTIFACTS_DIR}/opus-*-windows-ws
      ${ARTIFACTS_DIR}/sbc-*-windows-ws
      ${ARTIFACTS_DIR}/snappy-*-windows-ws
      ${ARTIFACTS_DIR}/speexdsp-*-windows-ws
      ${ARTIFACTS_DIR}/vcpkg-export-*-windows-ws
      ${ARTIFACTS_DIR}/WinSparkle-*
      ${ARTIFACTS_DIR}/xxhash-*-windows-ws
      ${ARTIFACTS_DIR}/zlib-ng-*-windows-ws
      ${ARTIFACTS_DIR}/zstd-*-windows-ws
    )
    if (artifact_dirs)
      file(REMOVE_RECURSE ${artifact_dirs})
    endif()
  endif()
  download_artifacts(download_ok)
  if(${download_ok})
    # XXX Should we generate the manifest file using configure_file?
    file(WRITE ${manifest_file} ${list_manifest_contents})
  endif()
endfunction()

if(APPLE)
  add_artifact(asciidoctor/asciidoctor-bundle-2.0.23-1-macos-x86_64.tar.xz c033d8873a1c9833fadf5ce97be5fc7321c4bef8485776a27cd6284233641301)
  add_artifact(bcg729/bcg729-1.1.1-1-macos-universal.tar.xz 0e302ac5816fbff353d33a428d25eeaad04d5e2ccd6df20a0003f14431aa63a4)
  add_artifact(brotli/brotli-1.2.0-1-macos-universal.tar.xz 7f0ef38d880711ee99256bffd6c5952617ee9f0343f233b7c4243f49ccc2792b)
  add_artifact(c-ares/c-ares-1.34.6-1-macos-universal.tar.xz eb850d71fab4ed63bc2129aea84891b1dbb3af2bf22869d07cd2bf79493fdc18)
  add_artifact(glib/glib-bundle-2.84.1-2-macos-universal.tar.xz 4f0d13491cdb1ae1036db190fa9ea60c0781d53453925f727aec1a3b3b93abe7)
  add_artifact(gnutls/gnutls-bundle-3.8.11-1-macos-universal.tar.xz 93b021fff6bce58d9ccd7543b03bc86e3fce3fddc7a3566563f7a83f20efe455)
  add_artifact(libgcrypt/libgcrypt-bundle-1.11.2-1-macos-universal.tar.xz 27f26ce861fe67fca297ad47fc5da3ccc486af6658c91820c05e44331b69ef02)
  add_artifact(libilbc/libilbc-2.0.2-1-macos-universal.tar.xz cf7c5f34c2101af1fe5b788cce6425b258cdaec03dc3301c4a8d2774a0c06801)
  add_artifact(libmaxminddb/libmaxminddb-1.12.2-1-macos-universal.tar.xz 722af5c180940cf0fcb7588ec2e824a56cc7dc6ed752c9ec263481c78345c187)
  add_artifact(libsmi/libsmi-0.4.8-1-macos-universal.tar.xz 3ebe3d5525bf356eafb1ed29cb9469f13a0b5b7cdae1e81f23da9b996e11a1cc)
  add_artifact(libssh/libssh-0.11.3-1-macos-universal.tar.xz 8d48756d749a45678948b84fa9c4da5b596e88be3686eda54337d7202727e8d8)
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
  add_artifact(xxhash/xxhash-0.8.3-1-macos-universal.tar.xz ae61f3faffe5d17179b593891d4294908b4c4afa7be18823a4ff60e80c8ef70f)
  add_artifact(zlib-ng/zlib-ng-2.2.4-1-macos-universal.tar.xz 52f1f054be4c97320b4417ebad5d4d8e278f615efac8fbec94abb4986100cbb0)
  add_artifact(zstd/zstd-1.5.7-1-macos-universal.tar.xz a7bfa6fdc228badbe30da5b89fc875e1c9bad52ee692df117aba9721798249d0)

  add_external_artifact(https://archive.docbook.org/xml/5.0.1/docbook-5.0.1.zip 7af9df452410e035a3707883e43039b4062f09dc2f49f2e986da3e4c0386e3c7 etc/xml)
  add_external_artifact(https://github.com/docbook/xslt10-stylesheets/releases/download/release%2F1.79.2/docbook-xsl-1.79.2.zip 853dce096f5b32fe0b157d8018d8fecf92022e9c79b5947a98b365679c7e31d7 etc/xml)
  add_external_artifact(https://github.com/docbook/xslt10-stylesheets/releases/download/release%2F1.79.2/docbook-xsl-nons-1.79.2.zip ba41126fbf4021e38952f3074dc87cdf1e50f3981280c7a619f88acf31456822 etc/xml)

  file(MAKE_DIRECTORY ${ARTIFACTS_DIR}/sparkle)
  add_external_artifact(https://github.com/sparkle-project/Sparkle/releases/download/2.7.1/Sparkle-2.7.1.tar.xz f7385c3e8c70c37e5928939e6246ac9070757b4b37a5cb558afa1b0d5ef189de sparkle)

  if(BUILD_stratoshark OR BUILD_strato OR BUILD_falcodump)
    add_artifact(falcosecurity-libs/falcosecurity-libs-bundle-0.21.0-1-macos-universal.tar.xz b0ac98e6f1906f891a8aa8c552639a1d6595aee26adfb730da9ff643d5e4bfaf)
    add_artifact(falcosecurity-libs/falcosecurity-plugins-2025-08-20-1-macos-universal.tar.xz 7391aa5337914acaac1fd4756ec95c075ca1ece65c0fa6f60d3e34ba24844f4c)
  endif()
elseif(WIN32)
  if(WIRESHARK_TARGET_PLATFORM STREQUAL "x64")
    add_artifact(bcg729/bcg729-1.0.4-win64ws.zip 9a095fda4c39860d96f0c568830faa6651cd17635f68e27aa6de46c689aa0ee2)
    add_artifact(brotli/brotli-1.2.0-1-x64-windows-ws.7z 938114d56814dbfd028d7ff78c4936e0b305032ab153cd78a57b78d2b0accbbd)
    add_artifact(c-ares/c-ares-1.34.6-x64-windows-ws.7z 9505ae760e010b039caca49732c12a9d0c91bfe27b8599773463a9c9bd8e2f79)
    add_artifact(gnutls/gnutls-3.8.11-1-x64-mingw-dynamic-ws.7z abbbcaa38337fe487f33afa73e09244229519d0fed84e37e47d5830134dac6e4)
    add_artifact(krb5/krb5-1.22.1-1-x64-windows-ws.7z 087c0b2a0df3b8adcb0f3458b290df0adab3ce85b57a328501fe4206ef62915d)
    add_artifact(libgcrypt/libgcrypt-bundle-1.11.2-1-x64-mingw-dynamic-ws.zip 0f623b221e84817f68ed8c692a0722607cf52c2573691222b6c981d04fa9ee4c)
    add_artifact(libilbc/libilbc-2.0.2-4-x64-windows-ws.zip 4f35a1ffa03c89bf473f38249282a7867b203988d2b6d3d2f0924764619fd5f5)
    add_artifact(libmaxminddb/libmaxminddb-1.12.2-x64-windows-ws.zip 16c5f80c44a76355886ab1a53a01ae3c42eeafe486e6b2bb73ab7658324dce29)
    add_artifact(libsmi/libsmi-2021-01-15-2-x64-windows-ws.zip ee8e349427d2a4ee9c18fc6b5839bd6df41685ecba03506179c21425e04f3413)
    add_artifact(libssh/libssh-0.11.3-1-x64-mingw-dynamic-ws.7z 26324f2758ec4110d94f37e63f59c99619ac03eb0a37c4e818868ac6c061d241)
    add_artifact(lua/lua-5.4.6-unicode-win64-vc14.zip f0c6c7eb28733425b16717beb338d44c041dfbb5c6807e618d96bd754276aaff)
    add_artifact(lz4/lz4-1.10.0-1-x64-windows-ws.zip 8b838f68cc90efa2d7c37f2bc651d153487bc336525d67f9c224a3e4bccf3583)
    add_artifact(minizip-ng/minizip-ng-4.0.9-x64-windows-ws.zip 08ea4d0051a507afd5e0b3bda16bf7fe6da42932c3bb86052b3bdb114a945da1)
    add_artifact(nghttp2/nghttp2-1.65.0-x64-windows-ws.zip 3f1727c106e3a74b21361955215b5876cbb3e28f9d9658f7af1285417ed76083)
    add_artifact(nghttp3/nghttp3-1.8.0-x64-windows-ws.zip 31062662e8829243c951c4fc8b69f4a0eb4d38ca1141ad0d9fee35c549b117b6)
    add_artifact(opencore-amr/opencore-amr-0.1.6-1-x64-mingw-dynamic-ws.zip 013a7b29b62bec123482fed6acd8aed882be3478870c2ec8aec15b7cb81cda02)
    add_artifact(opus/opus-1.5.2-1-x64-windows-ws.7z 6765a2d2a5bb97751e463200f8cfec357be9d1d9f09ef61a9f021a5b9046dfc5)
    add_artifact(sbc/sbc-2.0-1-x64-windows-ws.zip d1a58f977dcffa168b11b280bd10228191582d263b7c901e50cde7c1c43d9c04)
    add_artifact(snappy/snappy-1.2.1-1-x64-windows-ws.zip e2ffccb26e91881b42d03061dcc728a98af9037705cb4595c8ccbe8d912b5d68)
    add_artifact(spandsp/spandsp-0.0.6-5-x64-windows-ws.zip cbb18310876ec6f081662253a2d37f5174ac60c58b0b7cd6759852fbcfaa7d7f)
    add_artifact(speexdsp/speexdsp-1.21.1-1-win64ws.zip d36db62e64ffaee38d9f607bef07d3778d8957ad29757f3eba169eb135f1a4e5)
    add_artifact(vcpkg-export/vcpkg-export-2025.07.25-x64-windows-ws.zip 5a9751b4406eeac1c7d46220077da530e584e8aed0ff6fab8dcc2903c6c4c686)
    add_artifact(WinSparkle/WinSparkle-0.9.2-1-x64-windows-ws.7z 293dfb2cb5b70398f0164e2f02bab906ec54589c84b0d5605d1344235c5d9d20)
    add_artifact(xxhash/xxhash-0.8.3-1-x64-windows-ws.zip 35e5adca66137150de17458c41f6b65fa8abb5a46cfb91deaaaa24df08121082)
    add_artifact(zlib-ng/zlib-ng-2.2.3-1-x64-windows-ws.zip 8b4e5ba1b61688eccb7e315c2f4ce1ef0c4301172f265bd41455e1df6a5a9522)
    add_artifact(zstd/zstd-1.5.7-x64-windows-ws.zip cdce6d578ece3a14873572b1bffd54b42443ddb97386df9e4552ab7c17b2097d)

    if(BUILD_stratoshark OR BUILD_strato OR BUILD_falcodump)
      add_artifact(falcosecurity-libs/falcosecurity-libs-0.21.0-1-x64-ws.7z 917eca3b676e1201d48acfbb72660fcd7af4ce40fe5112bb1ce689d957c18c4a)
      add_artifact(falcosecurity-libs/falcosecurity-plugins-2025-08-20-1-x64-ws.7z 1c1fc0f94767a79a7d12478b73a937fd363931ebcd457cd1fab437a11410e076)
    endif()
  else() # Arm64
    add_artifact(bcg729/bcg729-1.1.1-1-win64armws.zip f4d76b9acf0d0e12e87a020e9805d136a0e8775e061eeec23910a10828153625)
    add_artifact(brotli/brotli-1.2.0-1-arm64-windows-ws.7z 24fd2c27ea14b0732f6153aa048b15256d6369f854ac3bde7b93b12fd706a664)
    add_artifact(c-ares/c-ares-1.34.6-arm64-windows-ws.7z 9bd2937f82c2ee57232b1305de9f32f1de056b4e3047e952a38d157669d5c90c)
    add_artifact(gnutls/gnutls-3.8.11-1-arm64-mingw-dynamic-ws.7z 458b440acffc82e00bce61005d41ae3e1ce4d5a72789bc9fefaaac574cf3f0a7)
    add_artifact(krb5/krb5-1.22.1-1-arm64-windows-ws.7z 916d6a7a8063c00c4c586f338ec9d0b956f7acb50b93408500a7814fb1ebf851)
    add_artifact(libgcrypt/libgcrypt-bundle-1.11.2-1-arm64-mingw-dynamic-ws.zip 2919c991794e83d8ab3c90caa441889bf60e973ca464d483ccb06567ff3f0b34)
    add_artifact(libilbc/libilbc-2.0.2-4-arm64-windows-ws.zip 00a506cc1aac8a2e31856e463a555d899b5a6ccf376485a124104858ccf0be6d)
    add_artifact(libmaxminddb/libmaxminddb-1.12.2-arm64-windows-ws.zip c2cf5e3b1d875ef778df9448c172cdc7f7f3f3a15880ac173ec3df567465e67f)
    add_artifact(libsmi/libsmi-2021-01-15-2-arm64-windows-ws.zip 3f5b7507a19436bd6494e2cbc89856a5980950f931f7cf0d637a8e764914d015)
    add_artifact(libssh/libssh-0.11.3-1-arm64-mingw-dynamic-ws.7z 6ee3fba9ea3fb22b8f200f65c4ae49a8965efc31698dc8b92d5787c2b18226f5)
    add_artifact(lua/lua-5.4.6-unicode-arm64-windows-vc14.zip a28c38acde71de5c495420cd8bf480e2e41f1a14bac81503b700fc64a9679b95)
    add_artifact(lz4/lz4-1.10.0-1-arm64-windows-ws.zip ee51fbf87bf359fa7835be89797c3488daf502e36e26337b0e649030aab7a09b)
    add_artifact(minizip-ng/minizip-ng-4.0.9-arm64-windows-ws.zip c773532508dc6a5f528beb855c472cc343d9d3ace45adea4b0b48dad1ef85acd)
    add_artifact(nghttp2/nghttp2-1.65.0-arm64-windows-ws.zip 96f88a42f8a82e686de9ee04997ffd84d656bbd882afff890cde69de1bb306fb)
    add_artifact(nghttp3/nghttp3-1.8.0-arm64-windows-ws.zip 98acb5867bb3b68431d29cefa5356602350ce731105cb2b3ad23e54b1f413bca)
    add_artifact(opencore-amr/opencore-amr-0.1.6-1-arm64-mingw-dynamic-ws.zip 581ec9e8ee4dde2236b689eec4d39802e2f998baa8d1604a4e91c1da32556b57)
    add_artifact(opus/opus-1.5.2-1-arm64-windows-ws.7z 27afcdcc569830dfe1d2e8a3c6de059c50b11d9b7cf331d299076a861b7e553f)
    add_artifact(sbc/sbc-2.0-1-arm64-windows-ws.zip 83cfe4a8b6fa5bae253ecacc1c02e6e4c61b4ad9ad0e5e63f0f30422fb6eac96)
    add_artifact(snappy/snappy-1.2.1-1-arm64-windows-ws.zip 71d6987360eb1a10abd0d070768e6b7b250c6ea87feaee044ecbc8864c7e57f4)
    add_artifact(spandsp/spandsp-0.0.6-5-arm64-windows-ws.zip fdf01e3c33e739ff9399b7d42cd8230c97cb27ce51865a0f06285a8f68206b6c)
    add_artifact(speexdsp/speexdsp-1.2.1-1-win64armws.zip 1759a9193065f27e50dd79dbb1786d24031ac43ccc48c40dca46d8a48552e3bb)
    add_artifact(vcpkg-export/vcpkg-export-2025.07.25-arm64-windows-ws.zip 68571e46354416d54ec5a86bef10a73426a250f2b920827fa9d7071e2f063ce7)
    add_artifact(WinSparkle/WinSparkle-0.9.2-1-arm64-windows-ws.7z 39f61aff84e12d10b2b11abf9a2fad93206a4c9c33e6834b10551a2fcc4fb91f)
    add_artifact(xxhash/xxhash-0.8.3-1-arm64-windows-ws.zip d0fc3804b0c4d43ac09f80d9b0bab8d8b5550df282e56b44be3dd997ccc9eba2)
    add_artifact(zlib-ng/zlib-ng-2.2.3-1-arm64-windows-ws.zip bea4250059565c3cc49a382d8ec3f82b70c51c3ccca41c5d3daec6862d22d8f8)
    add_artifact(zstd/zstd-1.5.7-arm64-windows-ws.zip 5a066e38a0c7bbbae3955919107e099565aee0c6c6523c43c0c9a0e6982a6a0a)

    if(BUILD_stratoshark OR BUILD_strato OR BUILD_falcodump)
      add_artifact(falcosecurity-libs/falcosecurity-libs-0.21.0-1-arm64-ws.7z 222a691e704989144c91b08612ab7e0af1a6721a7f0bc3ac17452de3342a654e)
      add_artifact(falcosecurity-libs/falcosecurity-plugins-2025-08-20-1-arm64-ws.7z e2f36b0056139f51d11bbc1fc81a811809ddf54964508e45c62a96d74722c718)
    endif()
  endif()
  add_artifact(asciidoctor/asciidoctor-bundle-${asciidoctor_version}-x64-windows-ws.7z d1dae73dd61ded005b8f1f2d7d19bd08e6edbeed216428e8ab898267229d150b)
  add_external_artifact(https://archive.docbook.org/xml/5.0.1/docbook-5.0.1.zip 7af9df452410e035a3707883e43039b4062f09dc2f49f2e986da3e4c0386e3c7 asciidoctor-bundle-${asciidoctor_version}-x64-windows-ws/etc/xml)
  add_external_artifact(https://github.com/docbook/xslt10-stylesheets/releases/download/release%2F1.79.2/docbook-xsl-1.79.2.zip 853dce096f5b32fe0b157d8018d8fecf92022e9c79b5947a98b365679c7e31d7 asciidoctor-bundle-${asciidoctor_version}-x64-windows-ws/etc/xml)
  add_external_artifact(https://github.com/docbook/xslt10-stylesheets/releases/download/release%2F1.79.2/docbook-xsl-nons-1.79.2.zip ba41126fbf4021e38952f3074dc87cdf1e50f3981280c7a619f88acf31456822 asciidoctor-bundle-${asciidoctor_version}-x64-windows-ws/etc/xml)
endif()

update_artifacts()

unset(manifest_file)
unset(download_prefix)
unset(artifacts)
unset(external_artifacts)
unset(asciidoctor_version)
