.DEFAULT_GOAL := all
TARGET := unipc

CC ?= gcc
# C compiler flags
CFLAGS ?= -Wall -Wextra -Werror -Wshadow -Wpedantic -pedantic-errors -g
# C preprocessor flags
CPPFLAGS ?= -D_GNU_SOURCE
# Linker flags
LDFLAGS ?=

PREFIX ?= /usr/local

SRCS := $(wildcard *.c)
OBJ_DIR := .build
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

# Include auto-generated header dependencies (ignore errors if missing)
-include $(DEPS)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
