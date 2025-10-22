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

.PHONY: all shared install clean distclean

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
