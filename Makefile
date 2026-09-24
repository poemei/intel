CC ?= cc

CPPFLAGS := -D_POSIX_C_SOURCE=200809L -Iinclude -I../rictus/include -I../ABI/includes
CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -fPIC
LDFLAGS := -shared
LDLIBS := -lcurl -lssl -lcrypto -pthread

BUILD_DIR := build/linux
TARGET := $(BUILD_DIR)/intelligence.so

SOURCES := \
	src/intelligence.c \
	src/collector_posix.c \
	src/doctrine.c \
	src/parser.c \
	src/record.c \
	src/relevance.c \
	src/seen.c \
	src/sources.c \
	src/srt.c \
	src/warning.c \
	src/warning_exercise.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(SOURCES) $(LDLIBS) -o $@

clean:
	rm -rf $(BUILD_DIR)
