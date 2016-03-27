CPATH=

UNAME = $(shell uname)
ifeq ($(UNAME), Linux)
PREBUILT_PATH=linux-x86_64
endif
ifeq ($(UNAME), Darwin)
PREBUILT_PATH=darwin-x86_64
endif

NDKROOT64= /opt/android
SYSROOT64=$(NDKROOT64)/platforms/android-21/arch-arm64
TOOLCHAINPATH64=$(NDKROOT64)/toolchains/aarch64-linux-android-4.9/prebuilt/$(PREBUILT_PATH)/bin
TOOLCHAIN64=$(TOOLCHAINPATH64)/aarch64-linux-android-
CPP64     =$(TOOLCHAIN64)cpp
AR64      =$(TOOLCHAIN64)ar
LD64      =$(TOOLCHAIN64)ld
CC64      =$(TOOLCHAIN64)gcc
CXX64     =$(TOOLCHAIN64)g++
RANLIB64  =$(TOOLCHAIN64)ranlib
STRIP64   =$(TOOLCHAIN64)strip
NM64      =$(TOOLCHAIN64)nm
CFLAGS64=--sysroot=$(SYSROOT64) -fdiagnostics-color -fno-exceptions -O2
CXXFLAGS64=--sysroot=$(SYSROOT64) -fdiagnostics-color
CPPFLAGS64=--sysroot=$(SYSROOT64)

NDKROOT=$(NDKROOT64)
SYSROOT=$(NDKROOT)/platforms/android-21/arch-arm
TOOLCHAINPATH=$(NDKROOT)/toolchains/arm-linux-androideabi-4.9/prebuilt/$(PREBUILT_PATH)/bin
TOOLCHAIN=$(TOOLCHAINPATH)/arm-linux-androideabi-
CPP     =$(TOOLCHAIN)cpp
AR      =$(TOOLCHAIN)ar
LD      =$(TOOLCHAIN)ld
CC      =$(TOOLCHAIN)gcc
CXX     =$(TOOLCHAIN)g++
RANLIB  =$(TOOLCHAIN)ranlib
STRIP   =$(TOOLCHAIN)strip
NM      =$(TOOLCHAIN)nm
CFLAGS=--sysroot=$(SYSROOT) -fdiagnostics-color -fno-exceptions -O2
CXXFLAGS=--sysroot=$(SYSROOT) -fdiagnostics-color
CPPFLAGS=--sysroot=$(SYSROOT)

all:	test64 switch

clean:
	rm -rf test64 switch

test64: test64.c testasm64.S
	$(CC64) -pie $(CFLAGS64)  $^ -o $@
	python getgasbytes.py

switch: switch.c switchasm.S
	$(CC) -pie $(CFLAGS) $^ -o $@
