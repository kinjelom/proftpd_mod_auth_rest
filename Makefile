
# Plain Makefile for building a ProFTPD contrib DSO (no autotools needed)

CC       ?= gcc
CFLAGS   ?=
CPPFLAGS ?=
LDFLAGS  ?=
LIBS     ?=

# Use the ProFTPD tree's libtool
LIBTOOL   = $(SHELL) ../../libtool
# Build a loadable ProFTPD module (.so) without libtool versioning
LTLDFLAGS = -module -avoid-version

# Where to install the module .so (BOSH or default to tree libexec)
ifdef BOSH_INSTALL_TARGET
  libexecdir = $(BOSH_INSTALL_TARGET)/libexec
else
  libexecdir ?= ../../libexec
endif

# ProFTPD top (for config.h) + headers under include/
PROFTPD_TOP := $(abspath ../..)
INCLUDES    = -I$(PROFTPD_TOP) -I$(PROFTPD_TOP)/include

SOURCES = mod_auth_rest.c
OBJECTS = mod_auth_rest.lo
TARGET  = mod_auth_rest.la

# -------- Test configuration --------
TEST_SOURCES = test_mod_auth_rest.c
TEST_BINARY  = test_mod_auth_rest
TEST_CFLAGS  = -Wall -Wextra -g -O0 $(INCLUDES) $(shell pkg-config --cflags check libcurl libmicrohttpd 2>/dev/null || echo "")
TEST_LDFLAGS = $(shell pkg-config --libs check libcurl libmicrohttpd 2>/dev/null || echo "-lcheck -lcurl -lmicrohttpd") -lpthread

.PHONY: all shared install clean distclean test check test-integration test-clean valgrind

all: shared
shared: $(TARGET)

$(TARGET): $(OBJECTS)
	$(LIBTOOL) --mode=link --tag=CC $(CC) -o $@ $(OBJECTS) \
		-rpath $(libexecdir) $(LTLDFLAGS) $(LDFLAGS) $(LIBS)

mod_auth_rest.lo: mod_auth_rest.c
	$(LIBTOOL) --mode=compile --tag=CC $(CC) $(INCLUDES) \
		$(CPPFLAGS) $(CFLAGS) -c $<

install: shared
	$(LIBTOOL) --mode=install /bin/install -c $(TARGET) $(libexecdir)

clean:
	-$(LIBTOOL) --mode=clean rm -f $(OBJECTS) $(TARGET)
	-rm -rf .libs

distclean: clean
	-true

# -------- Test targets --------

# Tests build
$(TEST_BINARY): $(TEST_SOURCES)
	@if ! pkg-config --exists check 2>/dev/null; then \
		echo "Error: libcheck not found. Install it with: sudo apt-get install check"; \
		exit 1; \
	fi
	$(CC) $(TEST_CFLAGS) -o $@ $< $(TEST_LDFLAGS)

# Unit Tests
test: $(TEST_BINARY)
	@echo "Running unit tests..."
	./$(TEST_BINARY)

check: test

# Valgrind Tests
valgrind: $(TEST_BINARY)
	@if ! command -v valgrind >/dev/null 2>&1; then \
		echo "Error: valgrind not found. Install it with: sudo apt-get install valgrind"; \
		exit 1; \
	fi
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TEST_BINARY)

# Integration Tests
test-integration: shared
	@if [ ! -f integration_test.sh ]; then \
		echo "Error: integration_test.sh not found"; \
		exit 1; \
	fi
	@if ! command -v python3 >/dev/null 2>&1; then \
		echo "Error: python3 not found"; \
		exit 1; \
	fi
	chmod +x integration_test.sh
	./integration_test.sh

test-clean:
	-rm -f $(TEST_BINARY)
	-rm -f /tmp/test_auth_rest.sock
	-rm -f test_proftpd.conf test_proftpd.pid
	-rm -f test_integration.log test_auth_rest.log
	-rm -f *.log

clean-all: clean test-clean

test-help:
	@echo "Available test targets:"
	@echo "  make test              - Run unit tests"
	@echo "  make check             - Alias for 'make test'"
	@echo "  make test-integration  - Run integration tests with ProFTPD"
	@echo "  make valgrind          - Run unit tests with Valgrind"
	@echo "  make test-clean        - Clean test artifacts"
	@echo "  make clean-all         - Clean everything (module + tests)"
	@echo ""
	@echo "Test requirements:"
	@echo "  Unit tests:        libcheck, libmicrohttpd, libcurl"
	@echo "  Integration tests: ProFTPD, Python 3 + Flask, netcat"
	@echo ""
	@echo "Install dependencies (Debian/Ubuntu):"
	@echo "  sudo apt-get install check libmicrohttpd-dev libcurl4-openssl-dev"
	@echo "  sudo apt-get install python3 python3-flask netcat"