# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
CLANG_FORMAT_FILE := $(abspath ./.clang-format)
CFLAGS := -g -Wall -O3
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

APPS = proxy

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)

$(APPS): 
	gcc -o $@ net.c proxy.c -lelf -lz $(CFLAGS)

format:
	clang-format -style=file -i *.c *.h
	@grep -n "TODO" *.[ch] || true

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

