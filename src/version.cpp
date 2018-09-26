// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <string>
#include <time.h>
#include "version.h"

// Name of client reported in the 'version' message. Report the same name
// for both bitcoind and bitcoin-qt, to make it harder for attackers to
// target servers or GUI users specifically.
const std::string CLIENT_NAME("BitBar");

// Client version number
#define CLIENT_VERSION_SUFFIX   "-beta"

#define BUILD_DESC_FROM_UNKNOWN(maj,min,rev,build) \
    "v" DO_STRINGIZE(maj) "." DO_STRINGIZE(min) "." DO_STRINGIZE(rev) "." DO_STRINGIZE(build) ""

#ifndef BUILD_DESC
#        define BUILD_DESC BUILD_DESC_FROM_UNKNOWN(DISPLAY_VERSION_MAJOR, DISPLAY_VERSION_MINOR, DISPLAY_VERSION_REVISION, DISPLAY_VERSION_BUILD)
#endif

#ifndef BUILD_DATE
#        define BUILD_DATE __DATE__ ", " __TIME__
#endif

const std::string CLIENT_BUILD(BUILD_DESC CLIENT_VERSION_SUFFIX);
const std::string CLIENT_DATE(BUILD_DATE);
