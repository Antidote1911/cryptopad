cmake_minimum_required(VERSION 3.22)
project(cryptopad VERSION 1.0.1 LANGUAGES CXX)

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

# ── Botan-3 detection ────────────────────────────────────────────────────────
# Priority: (1) system Botan via CMake config  (2) amalgamation from source
find_package(Botan 3 REQUIRED)

botan_generate(cryptopad_botan
    aead
    auto_rng
    argon2
    chacha
    chacha20poly1305
    hmac
    sha2_32
    system_rng
    rng
)

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
    cryptopad_botan
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
endif()

if(WIN32 AND NOT BOTAN_USE_SYSTEM)
    install(TARGETS cryptopad_botan
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
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
    cryptopad_botan
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
    cryptopad_botan
)
target_compile_options(test_fileencryptor PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall;-Wextra;-Wpedantic>
)
add_test(NAME FileEncryptor COMMAND test_fileencryptor)
