#*******************************************************************************
#   Ledger App
#   (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

APP_PATH = ""
# All but bitcoin app use dependency onto the bitcoin app/lib
DEFINES_LIB = USE_LIB_BITCOIN
APP_LOAD_PARAMS= --curve secp256k1 $(COMMON_LOAD_PARAMS)

APPVERSION_M=1
APPVERSION_N=3
APPVERSION_P=7
APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)
APP_LOAD_FLAGS=--appFlags 0x50 --dep Bitcoin:$(APPVERSION)

# simplify for tests
ifndef COIN
COIN=Ravencoin
endif

DEFINES += COIN_P2PKH_VERSION=60 COIN_P2SH_VERSION=122 COIN_FAMILY=1 COIN_COINID=\"Ravencoin\" COIN_COINID_HEADER=\"RAVENCOIN\" COIN_COLOR_HDR=0xEE5441 COIN_COLOR_DB=0xFFFFFF COIN_COINID_NAME=\"Ravencoin\" COIN_COINID_SHORT=\"RVN\" COIN_KIND=COIN_KIND_RVN
APPNAME ="Ravencoin"

APP_LOAD_PARAMS += $(APP_LOAD_FLAGS)
DEFINES += $(DEFINES_LIB)

ifeq ($(TARGET_NAME),TARGET_BLUE)
ICONNAME=blue_app_$(COIN).gif
else
ICONNAME=nanos_app_$(COIN).gif
endif

################
# Default rule #
################
all: default

############
# Platform #
############

DEFINES   += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES   += HAVE_BAGL HAVE_SPRINTF
#DEFINES   += HAVE_PRINTF PRINTF=screen_printf
DEFINES   += PRINTF\(...\)=
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += LEDGER_MAJOR_VERSION=$(APPVERSION_M) LEDGER_MINOR_VERSION=$(APPVERSION_N) LEDGER_PATCH_VERSION=$(APPVERSION_P) TCS_LOADER_PATCH_VERSION=0

# U2F
DEFINES   += HAVE_U2F HAVE_IO_U2F
DEFINES   += U2F_PROXY_MAGIC=\"BTC\"
DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += BLE_SEGMENT_SIZE=32 #max MTU, min 20

DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"

DEFINES += CX_COMPLIANCE_141
DEFINES += BLAKE_SDK

##############
# Compiler #
##############
ifneq ($(BOLOS_ENV),)
$(info BOLOS_ENV=$(BOLOS_ENV))
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
GCCPATH := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
else
$(info BOLOS_ENV is not set: falling back to CLANGPATH and GCCPATH)
endif
ifeq ($(CLANGPATH),)
$(info CLANGPATH is not set: clang will be used from PATH)
endif
ifeq ($(GCCPATH),)
$(info GCCPATH is not set: arm-none-eabi-* will be used from PATH)
endif

CC       := $(CLANGPATH)clang

#CFLAGS   += -O0
CFLAGS   += -O3 -Os

AS     := $(GCCPATH)arm-none-eabi-gcc

LD       := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS  += -O3 -Os
LDLIBS   += -lm -lgcc -lc

# import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

### variables processed by the common makefile.rules of the SDK to grab source files and include dirs
APP_SOURCE_PATH  += src
SDK_SOURCE_PATH  += lib_stusb lib_stusb_impl lib_u2f qrcode

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN bitcoin_testnet bitcoin bitcoin_cash bitcoin_gold litecoin dogecoin dash zcash horizen komodo stratis peercoin posw pivx viacoin vertcoin stealth digibyte qtum hcash bitcoin_private zcoin gamecredits zclassic xsn nix
