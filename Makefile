# ****************************************************************************
#    Ledger App for Bitcoin
#    (c) 2025 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifndef APPVERSION
    $(error "APPVERSION is not defined")
endif

ifndef APPNAME
    $(error "APPNAME is not defined")
endif

ifndef APP_DESCRIPTION
    $(error "APP_DESCRIPTION is not defined")
endif

ifeq ($(filter mainnet testnet,$(BITCOIN_NETWORK)),)
    $(error "BITCOIN_NETWORK must be either mainnet or testnet")
endif

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

########################################
#        Mandatory configuration       #
########################################

ifeq ($(APPVERSION_SUFFIX),)
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"
else
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)-$(strip $(APPVERSION_SUFFIX))"
endif

# Application source files
APP_SOURCE_PATH += src

# Application allowed derivation curves.
CURVE_APP_LOAD_PARAMS = secp256k1

# Coin-specific configuration
ifeq ($(BITCOIN_NETWORK),testnet)
    # Bitcoin testnet, no legacy support
    DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
    DEFINES   += BIP44_COIN_TYPE=1
    DEFINES   += COIN_P2PKH_VERSION=111
    DEFINES   += COIN_P2SH_VERSION=196
    DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"tb\"
    DEFINES   += COIN_COINID_SHORT=\"TEST\"
    # Application allowed derivation paths (testnet) + exception for Electrum + BIP-45 whole tree
    PATH_APP_LOAD_PARAMS = "*/1'" "4541509'" "45'"

else ifeq ($(BITCOIN_NETWORK),mainnet)
    # Bitcoin mainnet, no legacy support
    DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
    DEFINES   += BIP44_COIN_TYPE=0
    DEFINES   += COIN_P2PKH_VERSION=0
    DEFINES   += COIN_P2SH_VERSION=5
    DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"bc\"
    DEFINES   += COIN_COINID_SHORT=\"BTC\"
    # Application allowed derivation paths (mainnet) + exception for Electrum + BIP-45 whole tree
    PATH_APP_LOAD_PARAMS = "*/0'" "4541509'" "45'"

else
    ifeq ($(filter clean,$(MAKECMDGOALS)),)
        $(error Unsupported network)
    endif
endif

ifneq (,$(filter-out clean,$(MAKECMDGOALS)))
  ifeq ($(TARGET_NAME),TARGET_NANOS)
    $(error This app is not compatible with the Nano S device.)
  endif
endif

########################################
#     Application custom permissions   #
########################################
# See SDK `include/appflags.h` for the purpose of each permission
HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1
ENABLE_NBGL_FOR_NANO_DEVICES = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1

########################################
#       SWAP FEATURE FLAG      	       #
# This flag enables the swap feature   #
# in the Boilerplate application.      #
########################################
# Testing only SWAP flag
# ENABLE_TESTING_SWAP = 1
# Production enabled SWAP flag
#ENABLE_SWAP = 1

########################################
#          Features disablers          #
########################################
# Don't use standard app file to avoid conflicts for now
#DISABLE_STANDARD_APP_FILES = 1

# Don't use default IO_SEPROXY_BUFFER_SIZE to use another
# value for NANOS for an unknown reason.
#DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1

########################################
#        Application defines           #
########################################
DEFINES   += HAVE_BOLOS_APP_STACK_CANARY

# Estimated maximum stack usage.
# It acts as a build-time check to protect global variables.
# On the Nano X, the stack size is limited to 8K at the OS level.
ifeq ($(TARGET_NAME),TARGET_NANOX)
    APP_STACK_MIN_SIZE := 8192
else
    APP_STACK_MIN_SIZE := 16384
endif


# If set, the app will automatically approve all requests without user interaction. Useful for performance tests.
# It is critical that no such app is ever deployed in production.
AUTOAPPROVE_FOR_PERF_TESTS ?= 0
ifneq ($(AUTOAPPROVE_FOR_PERF_TESTS),0)
    DEFINES += HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    # the version for performance tests automatically approves all requests
    # there is no reason to ever compile the mainnet app with this flag
    ifeq ($(COIN),bitcoin)
        $(error Use testnet app for performance tests)
    endif
    ifeq ($(COIN),bitcoin_recovery)
        $(error Use testnet app for performance tests)
    endif
endif

# debugging helper functions and macros
CFLAGS    += -include debug-helpers/debug.h

# DEFINES   += HAVE_PRINT_STACK_POINTER

ifeq ($(DEBUG),10)
    $(warning Using semihosted PRINTF. Only run with speculos!)
    DEFINES   += HAVE_PRINTF HAVE_SEMIHOSTED_PRINTF PRINTF=semihosted_printf
endif

# Needed to be able to include the definition of G_cx
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

########################################
#          Features enablers           #
########################################
# Converting build warnings to errors
CFLAGS   += -Werror

include $(BOLOS_SDK)/Makefile.standard_app

# Makes a detailed report of code and data size in debug/size-report.txt
# More useful for production builds with DEBUG=0
size-report: bin/app.elf
	arm-none-eabi-nm --print-size --size-sort --radix=d bin/app.elf >debug/size-report.txt
