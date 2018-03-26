DESTDIR    =
PREFIX     = /usr/local
BINDIR     = $(PREFIX)/bin

CC ?= gcc
LD = $(CC)


ifeq ($(MODSEC_INC),)
MODSEC_INC := /usr/src/ModSecurity/standalone
endif

ifeq ($(MODSEC_APACHE2_INC),)
MODSEC_APACHE2_INC := /usr/src/ModSecurity/apache2
endif

ifeq ($(MODSEC_LIB),)
MODSEC_LIB := /usr/lib
endif

ifeq ($(APACHE2_INC),)
APACHE2_INC := /usr/include/httpd
endif

ifeq ($(APR_INC),)
APR_INC := /usr/include/apr-1
endif

ifeq ($(LIBXML_INC),)
LIBXML_INC := /usr/include/libxml2
endif

ifeq ($(EVENT_LIB),)
EVENT_LIB := -levent
endif

ifeq ($(EVENT_INC),)
EVENT_INC := /usr/include
endif

CFLAGS  += -g -Wall -pthread

INCS += -I/usr/src/haproxy/include -I/usr/src/haproxy/ebtree -I$(MODSEC_INC) -I$(MODSEC_APACHE2_INC) -I$(APACHE2_INC) -I$(APR_INC) -I$(LIBXML_INC) -I$(EVENT_INC)
LIBS += -lpthread -lm -ldl $(EVENT_LIB) -levent_pthreads -lcurl -lapr-1 -laprutil-1 -lxml2 -lpcre -lyajl -lfuzzy -llua
OBJS = spoa.o modsec_wrapper.o

modsecurity: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(MODSEC_LIB)/standalone.a $(LIBS)

install: modsecurity
	install modsecurity $(DESTDIR)$(BINDIR)

clean:
	rm -f modsecurity $(OBJS)

%.o:	%.c
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<
