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

########################################
#        Mandatory configuration       #
########################################

# Application version
APPVERSION_M = 2
APPVERSION_N = 1
APPVERSION_P = 8

VARIANT_VALUES = bitcoin_testnet_legacy bitcoin_legacy 

# Application source files
# There is no additional sources for bitcoin
#APP_SOURCE_PATH += src/

# simplify for tests
ifndef COIN
COIN=bitcoin_legacy
endif

# Enabling DEBUG flag will enable PRINTF and disable optimizations
#DEBUG = 1

ifeq ($(COIN),bitcoin_testnet_legacy)
BIP44_COIN_TYPE=1
BIP44_COIN_TYPE_2=1
COIN_P2PKH_VERSION=111
COIN_P2SH_VERSION=196
COIN_FAMILY=1
COIN_COINID=\"Bitcoin\"
COIN_COINID_HEADER=\"BITCOIN\" 
COIN_COINID_NAME=\"Bitcoin\" 
COIN_COINID_SHORT=\"TEST\" 
COIN_NATIVE_SEGWIT_PREFIX=\"tb\" 
COIN_KIND=COIN_KIND_BITCOIN_TESTNET 
COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="Bitcoin Test Legacy"

else ifeq ($(COIN),bitcoin_legacy)
# Horizen
BIP44_COIN_TYPE=0 
BIP44_COIN_TYPE_2=0 
COIN_P2PKH_VERSION=0 
COIN_P2SH_VERSION=5 
COIN_FAMILY=1 
COIN_COINID=\"Bitcoin\" 
COIN_COINID_HEADER=\"BITCOIN\" 
COIN_COINID_NAME=\"Bitcoin\" 
COIN_COINID_SHORT=\"BTC\" 
COIN_NATIVE_SEGWIT_PREFIX=\"bc\" 
COIN_KIND=COIN_KIND_BITCOIN 
COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="Bitcoin Legacy"
endif

include lib-app-bitcoin/Makefile
