#*******************************************************************************
#   Ledger Blue
#   (c) 2016 Ledger
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
#extract TARGET_ID from the SDK to allow for makefile choices
TARGET_ID := $(shell cat $(BOLOS_SDK)/include/bolos_target.h | grep 0x | cut -f3 -d' ')
$(info TARGET_ID=$(TARGET_ID))
APP_LOAD_PARAMS=--appFlags 0x50 --path "" --curve secp256k1

APPVERSION_M=1
APPVERSION_N=1
APPVERSION_P=5
APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

#prepare hsm generation
ifeq ($(TARGET_ID),0x31000002)
LOADFLAGS = --params --appVersion $(APPVERSION)
else
endif


################
# Default rule #
################

all: default

# consider every intermediate target as final to avoid deleting intermediate files
.SECONDARY:

# disable builtin rules that overload the build process (and the debug log !!)
.SUFFIXES:
MAKEFLAGS += -r

SHELL =       /bin/bash
#.ONESHELL:


############
# Platform #
############
PROG     := token

CONFIG_PRODUCTIONS := bin/$(PROG)

GLYPH_FILES := $(addprefix glyphs/,$(sort $(notdir $(shell find glyphs/))))
GLYPH_DESTC := src/glyphs.c
GLYPH_DESTH := src/glyphs.h
$(GLYPH_DESTC) $(GLYPH_DESTH): $(GLYPH_FILES) $(BOLOS_SDK)/icon.py
	-rm $@
	for gif in $(GLYPH_FILES) ; do python $(BOLOS_SDK)/icon.py $$gif glyphcheader ; done > $(GLYPH_DESTH)
	for gif in $(GLYPH_FILES) ; do python $(BOLOS_SDK)/icon.py $$gif glyphcfile ; done > $(GLYPH_DESTC)


SOURCE_PATH   := src $(BOLOS_SDK)/src $(dir $(shell find $(BOLOS_SDK)/lib_stusb* | grep "\.c$$"))
SOURCE_FILES  := $(foreach path, $(SOURCE_PATH),$(shell find $(path) | grep -E "\.c$$|\.s") ) $(GLYPH_DESTC)
INCLUDES_PATH := $(dir $(shell find $(BOLOS_SDK)/lib_stusb* | grep "\.h$$")) include src $(BOLOS_SDK)/include $(BOLOS_SDK)/include/arm


### platform definitions
DEFINES := ST31 gcc __IO=volatile

DEFINES   += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES   += HAVE_BAGL HAVE_SPRINTF
#DEFINES   += HAVE_PRINTF PRINTF=screen_printf
DEFINES   += PRINTF\(...\)=
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += LEDGER_MAJOR_VERSION=$(APPVERSION_M) LEDGER_MINOR_VERSION=$(APPVERSION_N) LEDGER_PATCH_VERSION=$(APPVERSION_P) TCS_LOADER_PATCH_VERSION=0 APPVERSION=\"$(APPVERSION)\"

# ifndef COIN
# COIN =bitcoin
# endif

ifeq ($(COIN),bitcoin_testnet)
# Bitcoin testnet
DEFINES  += BTCHIP_P2PKH_VERSION=111 BTCHIP_P2SH_VERSION=196 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Bitcoin\" COINID_UPCASE=\"BITCOIN\" COLOR_HDR=0xFCB653 COLOR_DB=0xFEDBA9 COINID_NAME=\"Bitcoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"TEST\" COIN_BITCOIN_TESTNET
APPNAME ="Bitcoin Test"
else ifeq ($(COIN),bitcoin)
# Bitcoin mainnet
DEFINES   += BTCHIP_P2PKH_VERSION=0 BTCHIP_P2SH_VERSION=5 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Bitcoin\" COINID_UPCASE=\"BITCOIN\" COLOR_HDR=0xFCB653 COLOR_DB=0xFEDBA9 COINID_NAME=\"Bitcoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"BTC\" COIN_BITCOIN
APPNAME ="Bitcoin"
else ifeq ($(COIN),litecoin)
# Litecoin
DEFINES   += BTCHIP_P2PKH_VERSION=48 BTCHIP_P2SH_VERSION=5 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Litecoin\" COINID_UPCASE=\"LITECOIN\" COLOR_HDR=0xCCCCCC COLOR_DB=0xE6E6E6 COINID_NAME=\"Litecoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"LTC\" COIN_LITECOIN
APPNAME ="Litecoin"
else ifeq ($(COIN),dogecoin)
# Doge
DEFINES   += BTCHIP_P2PKH_VERSION=30 BTCHIP_P2SH_VERSION=22 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Dogecoin\" COINID_UPCASE=\"DOGECOIN\" COLOR_HDR=0x65D196 COLOR_DB=0xB2E8CB COINID_NAME=\"Dogecoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"DOGE\" COIN_DOGE
APPNAME ="Dogecoin"
else ifeq ($(COIN),dash)
# Dash
DEFINES   += BTCHIP_P2PKH_VERSION=76 BTCHIP_P2SH_VERSION=16 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"DarkCoin\" COINID_UPCASE=\"DASH\" COLOR_HDR=0x0E76AA COLOR_DB=0x87BBD5 COINID_NAME=\"Dash\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"DASH\" COIN_DASH
APPNAME ="Dash"
else ifeq ($(COIN),zcash)
# Zcash
DEFINES   += BTCHIP_P2PKH_VERSION=7352 BTCHIP_P2SH_VERSION=7357 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Zcash\" COINID_UPCASE=\"ZCASH\" COLOR_HDR=0x3790CA COLOR_DB=0x9BC8E5 COINID_NAME=\"Zcash\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"ZEC\" COIN_ZCASH
APPNAME ="Zcash"
else ifeq ($(COIN),stratis)
# Stratis 
DEFINES   += BTCHIP_P2PKH_VERSION=63 BTCHIP_P2SH_VERSION=125 BTCHIP_COIN_FAMILY=2 BTCHIP_COINID=\"Stratis\" COINID_UPCASE=\"STRAT\" COLOR_HDR=0x3790CA COLOR_DB=0x9BC8E5 COINID_NAME=\"Strat\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"STRAT\" COIN_STRATIS HAVE_PEERCOIN_SUPPORT
APPNAME ="Stratis"
else ifeq ($(COIN),peercoin)
# Peercoin
DEFINES += BTCHIP_P2PKH_VERSION=55 BTCHIP_P2SH_VERSION=117 BTCHIP_COIN_FAMILY=2 BTCHIP_COINID=\"Peercoin\" COINID_UPCASE=\"PPC\" COLOR_HDR=0x3790CA COLOR_DB=0x9BC8E5 COINID_NAME=\"Peercoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"PPC\" COIN_PEERCOIN HAVE_PEERCOIN_SUPPORT
APPNAME ="Peercoin"
else
ifeq ($(filter clean,$(MAKECMDGOALS)),)
$(error Unsupported COIN - use bitcoin_testnet, bitcoin, litecoin, dogecoin, dash, zcash, stratis, peercoin) 
endif
endif

ifeq ($(TARGET_ID),0x31000002)
ICONNAME=icon_$(COIN)_blue.gif
else
ICONNAME=icon_$(COIN).gif
endif

# U2F
DEFINES   += HAVE_U2F
DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += BLE_SEGMENT_SIZE=32 #max MTU, min 20
#DEFINES   += U2F_MAX_MESSAGE_SIZE=264 #257+5+2
DEFINES    += U2F_MAX_MESSAGE_SIZE=200
DEFINES   += UNUSED\(x\)=\(void\)x

##############
# Compiler #
##############
GCCPATH   := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin
CC       := $(CLANGPATH)/clang 

CFLAGS_SHARED   := 
CFLAGS_SHARED   += -gdwarf-2  -gstrict-dwarf 
CFLAGS_SHARED   += -mcpu=cortex-m0 -mthumb 
CFLAGS_SHARED   += -fno-common -mtune=cortex-m0 -mlittle-endian 
CFLAGS_SHARED   += -std=gnu99 -Werror=int-to-pointer-cast -Wall -Wextra #-save-temps
CFLAGS_SHARED   += -fdata-sections -ffunction-sections -funsigned-char -fshort-enums 
CFLAGS_SHARED   += -mno-unaligned-access 
CFLAGS_SHARED   += -Wno-unused-parameter -Wno-duplicate-decl-specifier

#CFLAGS_SHARED   += --analyze
CFLAGS_SHARED   += -fropi --target=armv6m-none-eabi
#CFLAGS   += -finline-limit-0 -funsigned-bitfields 

CFLAGS += -O3 -Os $(CFLAGS_SHARED)

AS     := $(GCCPATH)/arm-none-eabi-gcc
AFLAGS += -ggdb2 -O3 -Os -mcpu=cortex-m0 -fno-common -mtune=cortex-m0

# NOT SUPPORTED BY STM3L152 CFLAGS   += -fpack-struct
#-pg --coverage
LD       := $(GCCPATH)/arm-none-eabi-gcc
LDFLAGS  := 
LDFLAGS  += -gdwarf-2  -gstrict-dwarf 
#LDFLAGS  += -O0 -g3
LDFLAGS  += -O3 -Os
#LDFLAGS  += -O0
LDFLAGS  += -Wall 
LDFLAGS  += -mcpu=cortex-m0 -mthumb 
LDFLAGS  += -fno-common -ffunction-sections -fdata-sections -fwhole-program -nostartfiles 
LDFLAGS  += -mno-unaligned-access
#LDFLAGS  += -nodefaultlibs
#LDFLAGS  += -nostdlib -nostdinc
LDFLAGS  += -T$(BOLOS_SDK)/script.ld  -Wl,--gc-sections -Wl,-Map,debug/$(PROG).map,--cref
LDLIBS   += -Wl,--library-path -Wl,$(GCCPATH)/../lib/armv6-m/
#LDLIBS   += -Wl,--start-group 
LDLIBS   += -lm -lgcc -lc 
#LDLIBS   += -Wl,--end-group
# -mno-unaligned-access 
#-pg --coverage

### computed variables
VPATH := $(dir $(SOURCE_FILES))
OBJECT_FILES := $(sort $(addprefix obj/, $(addsuffix .o, $(basename $(notdir $(SOURCE_FILES))))))
DEPEND_FILES := $(sort $(addprefix dep/, $(addsuffix .d, $(basename $(notdir $(SOURCE_FILES))))))

ifeq ($(filter clean,$(MAKECMDGOALS)),)
-include $(DEPEND_FILES)
endif

clean:
	rm -fr obj bin debug dep $(GLYPH_DESTC) $(GLYPH_DESTH)

prepare: $(GLYPH_DESTC)
	@mkdir -p bin obj debug dep

.SECONDEXPANSION:

# default is not to display make commands
log = $(if $(strip $(VERBOSE)),$1,@$1)

default: prepare bin/$(PROG)

reload: delete load

load: all
	python -m ledgerblue.loadApp --targetId $(TARGET_ID) --fileName bin/$(PROG).hex --appName $(APPNAME) --icon `python $(BOLOS_SDK)/icon.py $(ICONNAME) hexbitmaponly` $(LOADFLAGS) $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp --targetId $(TARGET_ID) --appName $(APPNAME)

bin/$(PROG): $(OBJECT_FILES) $(BOLOS_SDK)/script.ld
	@echo "[LINK] 	$@"
	$(call log,$(call link_cmdline,$(OBJECT_FILES) $(LDLIBS),$@))
	$(call log,$(GCCPATH)/arm-none-eabi-objcopy -O ihex -S bin/$(PROG) bin/$(PROG).hex)
	$(call log,mv bin/$(PROG) bin/$(PROG).elf)
	$(call log,cp bin/$(PROG).elf obj)
	$(call log,$(GCCPATH)/arm-none-eabi-objdump -S -d bin/$(PROG).elf > debug/$(PROG).asm)

dep/%.d: %.c Makefile
	@echo "[DEP]    $@"
	@mkdir -p dep
	$(call log,$(call dep_cmdline,$(INCLUDES_PATH), $(DEFINES),$<,$@))

obj/%.o: %.c dep/%.d
	@echo "[CC]	$@"
	$(call log,$(call cc_cmdline,$(INCLUDES_PATH), $(DEFINES),$<,$@))

obj/%.o: %.s
	@echo "[CC]	$@"
	$(call log,$(call as_cmdline,$(INCLUDES_PATH), $(DEFINES),$<,$@))

### BEGIN GCC COMPILER RULES

# link_cmdline(objects,dest)		Macro that is used to format arguments for the linker
link_cmdline = $(LD) $(LDFLAGS) -o $(2) $(1)

# dep_cmdline(include,defines,src($<),dest($@))	Macro that is used to format arguments for the dependency creator
dep_cmdline = $(CC) -M $(CFLAGS) $(addprefix -D,$(2)) $(addprefix -I,$(1)) $(3) | sed 's/\($*\)\.o[ :]*/obj\/\1.o: /g' | sed -e 's/[:\t ][^ ]\+\.c//g' > dep/$(basename $(notdir $(4))).d 2>/dev/null

# cc_cmdline(include,defines,src,dest)	Macro that is used to format arguments for the compiler
cc_cmdline = $(CC) -c $(CFLAGS) $(addprefix -D,$(2)) $(addprefix -I,$(1)) -o $(4) $(3)

as_cmdline = $(AS) -c $(AFLAGS) $(addprefix -D,$(2)) $(addprefix -I,$(1)) -o $(4) $(3)

### END GCC COMPILER RULES

