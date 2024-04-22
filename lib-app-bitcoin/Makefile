# ****************************************************************************
#    Ledger App Bitcoin
#    (c) 2023 Ledger SAS.
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

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

########################################
#        Mandatory configuration       #
########################################
# Name is defined later

ifeq ($(APPVERSION_M),)
$(error APPVERSION_M must be defined)
endif
ifeq ($(APPVERSION_N),)
$(error APPVERSION_N must be defined)
endif
ifeq ($(APPVERSION_P),)
$(error APPVERSION_P must be defined)
endif

APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

APP_SOURCE_PATH += lib-app-bitcoin/

ICON_NANOS = icons/nanos_app_$(COIN).gif
ICON_NANOX = icons/nanox_app_$(COIN).gif
ICON_NANOSP = icons/nanox_app_$(COIN).gif
ICON_STAX = icons/stax_app_$(COIN).gif

ifeq ($(TARGET_NAME),TARGET_STAX)
DEFINES += COIN_ICON=C_$(COIN)_64px
DEFINES += COIN_ICON_BITMAP=C_$(COIN)_64px_bitmap
endif

# Application allowed derivation curves.
CURVE_APP_LOAD_PARAMS ?= secp256k1

# Application allowed derivation paths.
# Currently there is no path restriction
PATH_APP_LOAD_PARAMS ?= ""

HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
HAVE_APPLICATION_FLAG_LIBRARY = 1

VARIANT_PARAM = COIN

ENABLE_BLUETOOTH = 1
ENABLE_NBGL_QRCODE = 1
ENABLE_SWAP = 1

ifndef BIP44_COIN_TYPE
$(error BIP44_COIN_TYPE must be defined)
endif

ifndef BIP44_COIN_TYPE_2
$(error BIP44_COIN_TYPE_2 must be defined)
endif

ifndef COIN_P2PKH_VERSION
$(error COIN_P2PKH_VERSION must be defined)
endif

ifndef COIN_P2SH_VERSION
$(error COIN_P2SH_VERSION must be defined)
endif

ifndef COIN_FAMILY
$(error COIN_FAMILY must be defined)
endif

ifndef COIN_COINID
$(error COIN_COINID must be defined)
endif

ifndef COIN_COINID_HEADER
$(error COIN_COINID_HEADER must be defined)
endif

ifndef COIN_COINID_NAME
$(error COIN_COINID_NAME must be defined)
endif

ifndef COIN_COINID_SHORT
$(error COIN_COINID_SHORT must be defined)
endif

ifndef COIN_NATIVE_SEGWIT_PREFIX
$(info COIN_NATIVE_SEGWIT_PREFIX automatically set to 0)
COIN_NATIVE_SEGWIT_PREFIX=0
endif

ifndef COIN_KIND
$(error COIN_KIND must be defined)
endif

ifndef COIN_FLAGS
$(info COIN_FLAGS automatically set to 0)
COIN_FLAGS=0
endif

ifndef COIN_FORKID
$(info COIN_FORKID automatically set to 0)
COIN_FORKID=0
endif

ifeq ($(APPNAME),)
$(error APPNAME must be defined)
endif

DEFINES +=BIP44_COIN_TYPE=$(BIP44_COIN_TYPE)
DEFINES +=BIP44_COIN_TYPE_2=$(BIP44_COIN_TYPE_2)
DEFINES +=COIN_P2PKH_VERSION=$(COIN_P2PKH_VERSION)
DEFINES +=COIN_P2SH_VERSION=$(COIN_P2SH_VERSION)
DEFINES +=COIN_FAMILY=$(COIN_FAMILY)
DEFINES +=COIN_COINID=$(COIN_COINID)
DEFINES +=COIN_COINID_HEADER=$(COIN_COINID_HEADER)
DEFINES +=COIN_COINID_SHORT=$(COIN_COINID_SHORT)
DEFINES +=COIN_NATIVE_SEGWIT_PREFIX=$(COIN_NATIVE_SEGWIT_PREFIX)
DEFINES +=COIN_KIND=$(COIN_KIND)
DEFINES +=COIN_FLAGS=$(COIN_FLAGS)
DEFINES +=COIN_FORKID=$(COIN_FORKID)

# COIN_COINID_NAME exposed to the app as a CFLAG because it might contain spaces
CFLAGS += -DCOIN_COINID_NAME=\"$(COIN_COINID_NAME)\"

include $(BOLOS_SDK)/Makefile.standard_app
