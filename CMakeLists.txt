cmake_minimum_required(VERSION 3.22)
project(cryptopad VERSION 1.0.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Flat install layout on Windows: cryptopad.exe at prefix root
if(WIN32)
    set(CMAKE_INSTALL_BINDIR ".")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Concurrent)

# ── Arsenic FFI — téléchargé et compilé depuis cryptyrust ────────────────────
include(ExternalProject)

set(CRYPTYRUST_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/cryptyrust-src")

# Noms des artefacts selon la plateforme
if(WIN32)
    set(ARSENIC_FFI_SHARED "arsenic_ffi.dll")
    set(ARSENIC_FFI_STATIC "arsenic_ffi.lib")
elseif(APPLE)
    set(ARSENIC_FFI_SHARED "libarsenic_ffi.dylib")
    set(ARSENIC_FFI_STATIC "libarsenic_ffi.a")
else()
    set(ARSENIC_FFI_SHARED "libarsenic_ffi.so")
    set(ARSENIC_FFI_STATIC "libarsenic_ffi.a")
endif()

# Sur macOS, sélectionne la cible cargo en fonction de CMAKE_OSX_ARCHITECTURES
# pour que la bibliothèque produite corresponde à l'architecture demandée.
if(APPLE AND CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
    set(_CARGO_TARGET_ARGS --target aarch64-apple-darwin)
    set(_CARGO_TARGET_SUBDIR aarch64-apple-darwin/release)
elseif(APPLE AND CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
    set(_CARGO_TARGET_ARGS --target x86_64-apple-darwin)
    set(_CARGO_TARGET_SUBDIR x86_64-apple-darwin/release)
else()
    set(_CARGO_TARGET_ARGS "")
    set(_CARGO_TARGET_SUBDIR release)
endif()

set(ARSENIC_FFI_LIB_SHARED "${CRYPTYRUST_SOURCE_DIR}/target/${_CARGO_TARGET_SUBDIR}/${ARSENIC_FFI_SHARED}")
set(ARSENIC_FFI_LIB_STATIC "${CRYPTYRUST_SOURCE_DIR}/target/${_CARGO_TARGET_SUBDIR}/${ARSENIC_FFI_STATIC}")
set(ARSENIC_FFI_HDR_DIR    "${CRYPTYRUST_SOURCE_DIR}/ffi_test")

# Crée le répertoire d'en-têtes dès la configuration (peuplé au build par git clone)
file(MAKE_DIRECTORY "${ARSENIC_FFI_HDR_DIR}")

ExternalProject_Add(cryptyrust_ffi_build
    GIT_REPOSITORY      "https://github.com/Antidote1911/cryptyrust.git"
    GIT_TAG             "v1.3.2"
    GIT_SHALLOW         TRUE
    UPDATE_DISCONNECTED TRUE
    SOURCE_DIR          "${CRYPTYRUST_SOURCE_DIR}"
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       cargo build --release -p arsenic_ffi
                        --manifest-path "${CRYPTYRUST_SOURCE_DIR}/Cargo.toml"
                        ${_CARGO_TARGET_ARGS}
    INSTALL_COMMAND     ""
    BUILD_BYPRODUCTS    "${ARSENIC_FFI_LIB_SHARED}" "${ARSENIC_FFI_LIB_STATIC}"
)

# Sur macOS : édition statique pour éviter l'embarquement manuel du .dylib dans le .app
# Sur Linux/Windows : édition partagée
if(APPLE)
    add_library(arsenic_ffi STATIC IMPORTED GLOBAL)
    add_dependencies(arsenic_ffi cryptyrust_ffi_build)
    set_target_properties(arsenic_ffi PROPERTIES
        IMPORTED_LOCATION             "${ARSENIC_FFI_LIB_STATIC}"
        INTERFACE_INCLUDE_DIRECTORIES "${ARSENIC_FFI_HDR_DIR}"
        # Frameworks système requis par la stdlib Rust sur macOS
        INTERFACE_LINK_LIBRARIES      "-framework Security;-framework Foundation;-libc++"
    )
else()
    add_library(arsenic_ffi SHARED IMPORTED GLOBAL)
    add_dependencies(arsenic_ffi cryptyrust_ffi_build)
    set_target_properties(arsenic_ffi PROPERTIES
        IMPORTED_LOCATION             "${ARSENIC_FFI_LIB_SHARED}"
        INTERFACE_INCLUDE_DIRECTORIES "${ARSENIC_FFI_HDR_DIR}"
    )
endif()

# RPATH — le binaire trouvera libarsenic_ffi.so sans LD_LIBRARY_PATH
set(CMAKE_BUILD_RPATH "${CRYPTYRUST_SOURCE_DIR}/target/${_CARGO_TARGET_SUBDIR}")
if(APPLE)
    set(CMAKE_INSTALL_RPATH "@executable_path/../Frameworks")
elseif(UNIX)
    set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
endif()

# ── Application sources ──────────────────────────────────────────────────────
add_executable(cryptopad
    src/main.cpp
    src/mainwindow.cpp
    src/codeeditor.cpp
    src/syntaxhighlighter.cpp
    src/cryptomanager.cpp
    src/fileencryptor.cpp
    src/passworddialog.cpp
    src/filteredfontcombobox.cpp
    src/colorpickerpopup.cpp
    src/colorpickerdialog.cpp
)

# macOS: build as .app bundle
if(APPLE)
    set_target_properties(cryptopad PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME        "CryptoPad"
        MACOSX_BUNDLE_BUNDLE_VERSION     "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_GUI_IDENTIFIER     "io.github.antidote1911.cryptopad"
    )
endif()

# Windows: embed icon via resource file
if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/share/windows/cryptopad.ico")
    target_sources(cryptopad PRIVATE share/windows/icon.rc)
endif()

target_link_libraries(cryptopad PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Concurrent
    arsenic_ffi
)

target_compile_options(cryptopad PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall;-Wextra;-Wpedantic>
)
target_compile_definitions(cryptopad PRIVATE APP_VERSION="${PROJECT_VERSION}")

# ── Arch Linux PKGBUILDs (version injectée depuis PROJECT_VERSION) ────────────
configure_file(
    "${CMAKE_SOURCE_DIR}/share/archlinux_pkgbuild/PKGBUILD.in"
    "${CMAKE_SOURCE_DIR}/share/archlinux_pkgbuild/PKGBUILD"
    @ONLY
)
configure_file(
    "${CMAKE_SOURCE_DIR}/share/archlinux_pkgbuild/PKGBUILD-AppImage.in"
    "${CMAKE_SOURCE_DIR}/share/archlinux_pkgbuild/PKGBUILD-AppImage"
    @ONLY
)

# ── Install rules ─────────────────────────────────────────────────────────────
install(TARGETS cryptopad
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    BUNDLE  DESTINATION .
    COMPONENT cryptopad
)

if(UNIX AND NOT APPLE)
    install(FILES share/linux/cryptopad.desktop
            DESTINATION share/applications
            COMPONENT cryptopad)
    install(FILES share/linux/cryptopad.png
            DESTINATION share/icons/hicolor/256x256/apps
            COMPONENT cryptopad)
    install(FILES "${ARSENIC_FFI_LIB_SHARED}"
            DESTINATION lib
            COMPONENT cryptopad)
endif()

if(WIN32)
    install(FILES "${ARSENIC_FFI_LIB_SHARED}"
            DESTINATION ${CMAKE_INSTALL_BINDIR}
            COMPONENT cryptopad)
endif()

# ── Tests ────────────────────────────────────────────────────────────────────
enable_testing()
find_package(Qt6 REQUIRED COMPONENTS Test)

add_executable(test_cryptomanager
    tests/test_cryptomanager.cpp
    src/cryptomanager.cpp
)
target_include_directories(test_cryptomanager PRIVATE src)
target_link_libraries(test_cryptomanager PRIVATE
    Qt6::Core
    Qt6::Test
    arsenic_ffi
)
target_compile_options(test_cryptomanager PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall;-Wextra;-Wpedantic>
)
add_test(NAME CryptoManager COMMAND test_cryptomanager)

add_executable(test_fileencryptor
    tests/test_fileencryptor.cpp
    src/fileencryptor.cpp
)
target_include_directories(test_fileencryptor PRIVATE src)
target_link_libraries(test_fileencryptor PRIVATE
    Qt6::Core
    Qt6::Test
    arsenic_ffi
)
target_compile_options(test_fileencryptor PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall;-Wextra;-Wpedantic>
)
add_test(NAME FileEncryptor COMMAND test_fileencryptor)
