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

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "Zcash"

# Application version
APPVERSION_M=2
APPVERSION_N=2
APPVERSION_P=0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Application source files
APP_SOURCE_PATH += src

# Application icons
ICON_NANOS = icons/nanos_app_zcash.gif
ICON_NANOX = icons/nanox_app_zcash.gif
ICON_NANOSP = icons/nanox_app_zcash.gif
ICON_STAX = icons/stax_app_zcash.gif
ICON_FLEX = icons/flex_app_zcash.gif

# Application allowed derivation curves
CURVE_APP_LOAD_PARAMS = secp256k1

# Application allowed derivation paths.
PATH_APP_LOAD_PARAMS = "44'/133'"   # purpose=coin(44) / coin_type=ZCash(133)

# Setting to allow building variant applications
VARIANT_PARAM = COIN
VARIANT_VALUES = zcash

# Enabling DEBUG flag will enable PRINTF and disable optimizations
#DEBUG = 1

########################################
#     Application custom permissions   #
########################################
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_STAX TARGET_FLEX))
HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
endif

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1

########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
DISABLE_STANDARD_APP_FILES = 1

# Allow usage of function from lib_standard_app/crypto_helpers.c
APP_SOURCE_FILES += ${BOLOS_SDK}/lib_standard_app/format.c
APP_SOURCE_FILES += ${BOLOS_SDK}/lib_standard_app/crypto_helpers.c

DEFINES   += BIP44_COIN_TYPE=133 BIP44_COIN_TYPE_2=133 COIN_P2PKH_VERSION=7352 COIN_P2SH_VERSION=7357 COIN_FAMILY=1 COIN_COINID=\"Zcash\" COIN_COINID_HEADER=\"ZCASH\" COIN_COLOR_HDR=0x3790CA COIN_COLOR_DB=0x9BC8E5 COIN_COINID_NAME=\"Zcash\" COIN_COINID_SHORT=\"ZEC\" COIN_KIND=COIN_KIND_ZCASH
# Switch to NU5 over Canopy
DEFINES   += COIN_CONSENSUS_BRANCH_ID=0XC2D6D0B4
DEFINES   += TCS_LOADER_PATCH_VERSION=0

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_STAX TARGET_FLEX))
DEFINES += COIN_ICON=C_$(COIN)_64px
DEFINES += COIN_ICON_BITMAP=C_$(COIN)_64px_bitmap
endif

include $(BOLOS_SDK)/Makefile.standard_app
