CC ?= cc

CPPFLAGS := -D_POSIX_C_SOURCE=200809L -Iinclude -I../rictus/include -I../ABI/includes
CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -fPIC
LDFLAGS := -shared
LDLIBS := -lcurl -lssl -lcrypto -pthread

BUILD_DIR := build/linux
TARGET := $(BUILD_DIR)/intelligence.so
PREFIX ?= /usr/local
MODULEDIR ?= $(PREFIX)/lib/rictus/modules/intelligence
DESTDIR ?=

SOURCES := \
	src/intelligence.c \
	src/collector_posix.c \
	src/doctrine.c \
	src/parser.c \
	src/record.c \
	src/relevance.c \
	src/seen.c \
	src/sources.c \
	src/sync.c \
	src/srt.c \
	src/warning.c \
	src/warning_exercise.c

HEADERS := $(wildcard include/*.h)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(SOURCES) $(LDLIBS) -o $@

install: all
	install -d "$(DESTDIR)$(MODULEDIR)"
	install -m 0755 "$(TARGET)" "$(DESTDIR)$(MODULEDIR)/intelligence.so"
	install -m 0644 module.conf "$(DESTDIR)$(MODULEDIR)/module.conf"

clean:
	rm -rf $(BUILD_DIR)
