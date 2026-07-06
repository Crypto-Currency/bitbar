TEMPLATE = app
TARGET = bitbar-qt
VERSION = 0.8.2.1

INCLUDEPATH += src src/json src/qt

DEFINES -= USE_UPNP
DEFINES += QT_GUI BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE
CONFIG += no_include_pwd
CONFIG += thread -w
QT += widgets network

OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build
CODECFORTR = UTF-8

# System Architecture Targeting & Static Toolchain Linkage
win32 {
    CONFIG += static
    CONFIG += no_plugin_manifest

    DEFINES += _WINDOWS WIN32 _MT
    DEFINES += BITCOIN_NEED_QT_PLUGINS

    QMAKE_LIBDIR += $$[QT_INSTALL_PLUGINS]/imageformats
    QTPLUGIN += qwebp

    # Enable modern ASLR and DEP security mitigation layouts
    QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat

    # Core Crypto Wallet Static Dependencies (Strict Link Ordering)
    LIBS += -ldb_cxx -lssl -lcrypto
    LIBS += -lboost_filesystem-mt-x64 -lboost_program_options-mt-x64 -lboost_thread-mt-x64 -lboost_chrono-mt-x64

    # Mandatory Windows Kernel Mappings (Required for Networking & OpenSSL 3.0)
    LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32 -luser32 -lcrypt32 -liphlpapi

    # Static compiler enforcement settings
    LIBS += -lmingwthrd -static-libgcc -static-libstdc++ -Wl,-Bstatic -lstdc++ -lpthread -Wl,--stack,16777216

    RC_FILE = src/qt/res/bitcoin-qt.rc
}

!win32 {
  # Linux and Unix Native Platform Enforcements
  DEFINES += BITCOIN_NEED_QT_PLUGINS 
  QTPLUGIN += qwebp
  
  QMAKE_CXXFLAGS *= -fstack-protector-all --param ssp-buffer-size=1 -DBOOST_BIND_GLOBAL_PLACEHOLDERS
  QMAKE_LFLAGS *= -rdynamic -fstack-protector-all --param ssp-buffer-size=1
  !macx {
    DEFINES += LINUX
        
    # Explicitly pull in your Ubuntu dynamic system libraries here:
    LIBS += -lboost_system -lboost_filesystem -lboost_thread -lboost_program_options -lboost_chrono
    LIBS += -ldb_cxx -lssl -lcrypto -lrt
    LIBS += -lwebp        
    QMAKE_LFLAGS *= -no-pie
  }
  contains(RELEASE, 1) {
    LIBS += -Wl,-Bstatic
  }
}

# Mac Build Framework Targets
macx {
    HEADERS += src/qt/macdockiconhandler.h
    OBJECTIVE_SOURCES += src/qt/macdockiconhandler.mm
    LIBS += -framework Foundation -framework ApplicationServices -framework AppKit
    DEFINES += MAC_OSX MSG_NOSIGNAL=0
    ICON = src/qt/res/icons/bitcoin.icns
    TARGET = "bitbar-qt"

    # =========================================================================
    # 1. STATIC BUILD SECTION (For your custom static Qt 5.15.16 engine)
    # =========================================================================
 CONFIG(static, static|shared) {
        message("Configuring a fully self-contained, leak-proof STATIC Mac build...")

        # 1. Point to your repository's local portable database folder
        INCLUDEPATH += $$PWD/src/qt/Static-Deps/include
        DEPENDPATH  += $$PWD/src/qt/Static-Deps/include
        LIBS        += $$PWD/src/qt/Static-Deps/lib/libdb_cxx.a

        # 2. Map standard include folders
        STATIC_PREFIX = /usr/local
        INCLUDEPATH  += $$STATIC_PREFIX/include

        # 3. FIXED HARDCODED FILE LINKERS
        # Passes the true Homebrew-installed static files by explicitly bypassing -mt tags
        LIBS += $$STATIC_PREFIX/lib/libboost_filesystem.a \
                $$STATIC_PREFIX/lib/libboost_program_options.a \
                $$STATIC_PREFIX/lib/libboost_thread.a \
                $$STATIC_PREFIX/opt/openssl@3/lib/libssl.a \
                $$STATIC_PREFIX/opt/openssl@3/lib/libcrypto.a

        # NOTE: WebP libraries are completely omitted here because they are
        # natively baked directly into your custom static /usr/local/qt5-static build!
    }

    
    # =========================================================================
    # 2. DYNAMIC BUILD SECTION (Fallback for Homebrew / MacPorts)
    # =========================================================================
    else {
        message("Configuring a DYNAMIC Package Manager Mac build...")

        # Tell the compiler to look inside your new relative repo folder for WebP & BDB headers
        INCLUDEPATH += $$PWD/src/qt/Static-Deps/include
        DEPENDPATH  += $$PWD/src/qt/Static-Deps/include

        # Link your local static WebP engine universal libraries natively out of the repository
        LIBS += $$PWD/src/qt/Static-Deps/lib/libwebp.a \
                $$PWD/src/qt/Static-Deps/lib/libsharpyuv.a

        # Define a default empty prefix variable
        DEP_PREFIX = ""

        # First Check: Detect MacPorts
        exists(/opt/local/bin/port) {
            message("MacPorts environment detected!")
            DEP_PREFIX = /opt/local
        } else {
            # Second Check: Fall back to Homebrew
            message("Homebrew environment or fallback detected!")
            DEP_PREFIX = $$system(brew --prefix)
        }

        # Dynamic Include Headers Path Mapping
        INCLUDEPATH += $$DEP_PREFIX/include
        INCLUDEPATH += $$DEP_PREFIX/opt/boost/include
        INCLUDEPATH += $$DEP_PREFIX/opt/openssl@3/include
        INCLUDEPATH += $$DEP_PREFIX/opt/berkeley-db@5/include

        # Dynamic Library Binary Path Mapping
        LIBS += -L$$DEP_PREFIX/lib
        LIBS += -L$$DEP_PREFIX/opt/boost/lib -lboost_filesystem -lboost_program_options -lboost_thread
        LIBS += -L$$DEP_PREFIX/opt/openssl@3/lib -lcrypto -lssl
        LIBS += -L$$DEP_PREFIX/opt/berkeley-db@5/lib -ldb_cxx
    }

    # =========================================================================
    # 3. GLOBAL MAC CONFIGURATION FLAGS
    # =========================================================================
    contains(RELEASE, 1) {
        QMAKE_CXXFLAGS += -arch x86_64
        QMAKE_LFLAGS += -arch x86_64
    }
    QMAKE_MACOSX_DEPLOYMENT_TARGET = 14.0
}

# Optional Feature: QRCode Support
contains(USE_QRCODE, 1) {
    message(Building with QRCode support)
    DEFINES += USE_QRCODE
    HEADERS += src/qt/qrcodedialog.h
    SOURCES += src/qt/qrcodedialog.cpp
    FORMS += src/qt/forms/qrcodedialog.ui
    LIBS += -lqrencode
}

## Optional Feature: UPNP Nat Traversal (Enabled by default)
#contains(USE_UPNP, -) {
#    message(Building without UPNP support)
#} else {
#    message(Building with UPNP support)
#    count(USE_UPNP, 0) {
#        USE_UPNP=1
#    }
#    DEFINES += USE_UPNP=$$USE_UPNP STATICLIB
#    INCLUDEPATH += $$MINIUPNPC_INCLUDE_PATH
#    LIBS += $$join(MINIUPNPC_LIB_PATH,,-L,) -lminiupnpc
#}

# Optional Feature: DBUS Desktop Notifications
contains(USE_DBUS, 1) {
    message(Building with DBUS support)
    DEFINES += USE_DBUS
    QT += dbus
}

# Optional Feature: First Class Messaging Layouts
contains(FIRST_CLASS_MESSAGING, 1) {
    message(Building with first-class messaging)
    DEFINES += FIRST_CLASS_MESSAGING
}


# Optional Unit Testing Mechanics
contains(BITCOIN_QT_TEST, 1) {
    SOURCES += src/qt/test/test_main.cpp \
        src/qt/test/uritests.cpp
    HEADERS += src/qt/test/uritests.h
    DEPENDPATH += src/qt/test
    QT += testlib
    TARGET = bitcoin-qt_test
    DEFINES += BITCOIN_QT_TEST
}

# Automated Translation File Generation Processing (lrelease engine setup)
TRANSLATIONS = $$files(src/qt/locale/bitcoin_*.ts)

isEmpty(QMAKE_LRELEASE) {
    win32:QMAKE_LRELEASE = lrelease
    else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}
isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale

TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# Git-Build Version Header Hook
!win32|contains(USE_BUILD_INFO, 1) {
    genbuild.depends = FORCE
    genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh $$OUT_PWD/build/build.h
    genbuild.target = $$OUT_PWD/build/build.h
    PRE_TARGETDEPS += $$OUT_PWD/build/build.h
    QMAKE_EXTRA_TARGETS += genbuild
    DEFINES += HAVE_BUILD_INFO
}

QMAKE_CXXFLAGS += -msse2 -w
QMAKE_CFLAGS += -msse2
QMAKE_CXXFLAGS_WARN_ON = -fdiagnostics-show-option -Wall -Wextra -Wformat -Wformat-security -Wno-unused-parameter -Wstack-protector

DEPENDPATH += src src/json src/qt

# Core Application File Tree Array Targets
HEADERS += src/qt/bitcoingui.h \
    src/qt/transactiontablemodel.h \
    src/qt/addresstablemodel.h \
    src/qt/optionsdialog.h \
    src/qt/sendcoinsdialog.h \
    src/qt/coincontroldialog.h \
    src/qt/coincontroltreewidget.h \
    src/qt/addressbookpage.h \
    src/qt/signverifymessagedialog.h \
    src/qt/aboutdialog.h \
    src/qt/splash.h \
    src/qt/editaddressdialog.h \
    src/qt/bitcoinaddressvalidator.h \
    src/alert.h \
    src/addrman.h \
    src/base58.h \
    src/bignum.h \
    src/checkpoints.h \
    src/coincontrol.h \
    src/compat.h \
    src/sync.h \
    src/util.h \
    src/uint256.h \
    src/kernel.h \
    src/scrypt_mine.h \
    src/pbkdf2.h \
    src/serialize.h \
    src/strlcpy.h \
    src/main.h \
    src/net.h \
    src/key.h \
    src/db.h \
    src/walletdb.h \
    src/script.h \
    src/init.h \
    src/qt/skinspage.h \
    src/mruset.h \
    src/json/json_spirit_writer_template.h \
    src/json/json_spirit_writer.h \
    src/json/json_spirit_value.h \
    src/json/json_spirit_utils.h \
    src/json/json_spirit_stream_reader.h \
    src/json/json_spirit_reader_template.h \
    src/json/json_spirit_reader.h \
    src/json/json_spirit_error_position.h \
    src/json/json_spirit.h \
    src/qt/clientmodel.h \
    src/qt/guiutil.h \
    src/qt/transactionrecord.h \
    src/qt/guiconstants.h \
    src/qt/optionsmodel.h \
    src/qt/monitoreddatamapper.h \
    src/qt/transactiondesc.h \
    src/qt/transactiondescdialog.h \
    src/qt/bitcoinamountfield.h \
    src/wallet.h \
    src/keystore.h \
    src/qt/transactionfilterproxy.h \
    src/qt/transactionview.h \
    src/qt/walletmodel.h \
    src/bitcoinrpc.h \
    src/qt/overviewpage.h \
    src/qt/csvmodelwriter.h \
    src/crypter.h \
    src/qt/sendcoinsentry.h \
    src/qt/qvalidatedlineedit.h \
    src/qt/bitcoinunits.h \
    src/qt/qvaluecombobox.h \
    src/qt/askpassphrasedialog.h \
    src/protocol.h \
    src/qt/notificator.h \
    src/qt/qtipcserver.h \
    src/allocators.h \
    src/ui_interface.h \
    src/qt/rpcconsole.h \
    src/version.h \
    src/netbase.h \
    src/clientversion.h \
#    src/qt/trafficgraphwidget.h \
#    src/qt/bantablemodel.h \
#    src/qt/peertablemodel.h \
#    src/qt/dustinggui.h \
#    src/qt/alertgui.h

SOURCES += src/qt/bitcoin.cpp src/qt/bitcoingui.cpp \
    src/qt/transactiontablemodel.cpp \
    src/qt/addresstablemodel.cpp \
    src/qt/optionsdialog.cpp \
    src/qt/sendcoinsdialog.cpp \
    src/qt/coincontroldialog.cpp \
    src/qt/coincontroltreewidget.cpp \
    src/qt/addressbookpage.cpp \
    src/qt/signverifymessagedialog.cpp \
    src/qt/aboutdialog.cpp \
    src/qt/splash.cpp \
    src/qt/editaddressdialog.cpp \
    src/qt/bitcoinaddressvalidator.cpp \
    src/alert.cpp \
    src/version.cpp \
    src/sync.cpp \
    src/util.cpp \
    src/netbase.cpp \
    src/key.cpp \
    src/script.cpp \
    src/main.cpp \
    src/init.cpp \
    src/net.cpp \
    src/qt/skinspage.cpp \
    src/checkpoints.cpp \
    src/addrman.cpp \
    src/db.cpp \
    src/walletdb.cpp \
    src/qt/clientmodel.cpp \
    src/qt/guiutil.cpp \
    src/qt/transactionrecord.cpp \
    src/qt/optionsmodel.cpp \
    src/qt/monitoreddatamapper.cpp \
    src/qt/transactiondesc.cpp \
    src/qt/transactiondescdialog.cpp \
    src/qt/bitcoinstrings.cpp \
    src/qt/bitcoinamountfield.cpp \
    src/wallet.cpp \
    src/keystore.cpp \
    src/qt/transactionfilterproxy.cpp \
    src/qt/transactionview.cpp \
    src/qt/walletmodel.cpp \
    src/bitcoinrpc.cpp \
    src/rpcdump.cpp \
    src/rpcnet.cpp \
    src/rpcmining.cpp \
    src/rpcwallet.cpp \
    src/rpcblockchain.cpp \
    src/rpcrawtransaction.cpp \
    src/qt/overviewpage.cpp \
    src/qt/csvmodelwriter.cpp \
    src/crypter.cpp \
    src/qt/sendcoinsentry.cpp \
    src/qt/qvalidatedlineedit.cpp \
    src/qt/bitcoinunits.cpp \
    src/qt/qvaluecombobox.cpp \
    src/qt/askpassphrasedialog.cpp \
    src/protocol.cpp \
    src/qt/notificator.cpp \
    src/qt/qtipcserver.cpp \
    src/qt/rpcconsole.cpp \
    src/noui.cpp \
    src/kernel.cpp \
    src/scrypt-x86.S \
    src/scrypt-x86_64.S \
#    src/scrypt-arm.S \
    src/scrypt_mine.cpp \
    src/pbkdf2.cpp \
#    src/qt/trafficgraphwidget.cpp \
#    src/qt/bantablemodel.cpp \
#    src/qt/peertablemodel.cpp \
#    src/qt/dustinggui.cpp \
#    src/qt/alertgui.cpp

RESOURCES += src/qt/bitcoin.qrc

FORMS += \
    src/qt/forms/sendcoinsdialog.ui \
    src/qt/forms/coincontroldialog.ui \
    src/qt/forms/addressbookpage.ui \
    src/qt/forms/signverifymessagedialog.ui \
    src/qt/forms/aboutdialog.ui \
    src/qt/forms/splash.ui \
    src/qt/forms/skinspage.ui \
#    src/qt/forms/dustinggui.ui \
#    src/qt/forms/alertgui.ui \
    src/qt/forms/editaddressdialog.ui \
    src/qt/forms/optionsdialog.ui \
    src/qt/forms/rpcconsole.ui \
    src/qt/forms/transactiondescdialog.ui \
    src/qt/forms/overviewpage.ui \
    src/qt/forms/sendcoinsentry.ui \
    src/qt/forms/askpassphrasedialog.ui



# "Other files" to show in Qt Creator
OTHER_FILES += \
    doc/*.rst doc/*.txt doc/README README.md res/bitcoin-qt.rc src/test/*.cpp src/test/*.h src/qt/test/*.cpp src/qt/test/*.h

contains(RELEASE, 1) {
    !windows:!macx {
        LIBS += -Wl,-Bdynamic
    }
}

system($$QMAKE_LRELEASE -silent $$_PRO_FILE_)
