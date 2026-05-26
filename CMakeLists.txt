cmake_minimum_required(VERSION 3.22)
project(cryptopad VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Flat install layout on Windows: cryptopad.exe at prefix root
if(WIN32)
    set(CMAKE_INSTALL_BINDIR ".")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Concurrent)

# ── Botan-3 detection ────────────────────────────────────────────────────────
# Priority: (1) pkg-config  (2) build from source
find_package(PkgConfig QUIET)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(BOTAN QUIET botan-3)
endif()

if(BOTAN_FOUND)
    message(STATUS "Found system Botan-3 ${BOTAN_VERSION}")
    add_library(Botan::Botan INTERFACE IMPORTED)
    target_include_directories(Botan::Botan INTERFACE ${BOTAN_INCLUDE_DIRS})
    target_link_libraries(Botan::Botan INTERFACE ${BOTAN_LIBRARIES})
    target_compile_options(Botan::Botan INTERFACE ${BOTAN_CFLAGS_OTHER})
else()
    # Build Botan-3 from source using its own configure.py + make.
    # Requires Python 3 and a C++ compiler visible to the configure script.
    message(STATUS "Botan-3 not found on system — downloading and building from source")
    include(ExternalProject)

    set(BOTAN_INSTALL_DIR "${CMAKE_BINARY_DIR}/botan-install")

    ExternalProject_Add(botan_external
        URL      https://botan.randombit.net/releases/Botan-3.4.0.tar.xz
        # SHA256 intentionally omitted — verify manually for production builds.
        CONFIGURE_COMMAND
            python3 <SOURCE_DIR>/configure.py
                --prefix=${BOTAN_INSTALL_DIR}
                --minimized-build
                --enable-modules=serpent,gcm,aead,kdf,pbkdf,pbkdf2,sha2_32,sha2_64,hmac,auto_rng,system_rng,argon2,threefish_512,eax,siv,chacha20poly1305
        BUILD_COMMAND     make -j4
        INSTALL_COMMAND   make install
        BUILD_IN_SOURCE   0
        LOG_CONFIGURE ON
        LOG_BUILD     ON
        LOG_INSTALL   ON
    )

    set(BOTAN_INCLUDE_DIRS "${BOTAN_INSTALL_DIR}/include/botan-3")
    set(BOTAN_LIBRARY     "${BOTAN_INSTALL_DIR}/lib/libbotan-3.a")

    file(MAKE_DIRECTORY "${BOTAN_INCLUDE_DIRS}")

    add_library(Botan::Botan STATIC IMPORTED GLOBAL)
    set_target_properties(Botan::Botan PROPERTIES
        IMPORTED_LOCATION             "${BOTAN_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${BOTAN_INCLUDE_DIRS}"
    )
    add_dependencies(Botan::Botan botan_external)
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
set_target_properties(cryptopad PROPERTIES
    MACOSX_BUNDLE TRUE
    MACOSX_BUNDLE_BUNDLE_NAME        "CryptoPad"
    MACOSX_BUNDLE_BUNDLE_VERSION     "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    MACOSX_BUNDLE_GUI_IDENTIFIER     "io.github.antidote1911.cryptopad"
)

# Windows: embed icon via resource file
if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/share/windows/cryptopad.ico")
    target_sources(cryptopad PRIVATE share/windows/icon.rc)
endif()

target_link_libraries(cryptopad PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Concurrent
    Botan::Botan
)

target_compile_options(cryptopad PRIVATE -Wall -Wextra -Wpedantic)
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
    Botan::Botan
)
target_compile_options(test_cryptomanager PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME CryptoManager COMMAND test_cryptomanager)

add_executable(test_fileencryptor
    tests/test_fileencryptor.cpp
    src/fileencryptor.cpp
)
target_include_directories(test_fileencryptor PRIVATE src)
target_link_libraries(test_fileencryptor PRIVATE
    Qt6::Core
    Qt6::Test
    Botan::Botan
)
target_compile_options(test_fileencryptor PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME FileEncryptor COMMAND test_fileencryptor)
