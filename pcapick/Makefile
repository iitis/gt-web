FLAGS += -g -Wall -pedantic -fPIC $(FLAGS_ADD)
CFLAGS   += $(FLAGS) -std=gnu99 -Dinline='inline __attribute__ ((gnu_inline))' $(CFLAGS_ADD)

PREFIX ?= /usr
PKGDST = $(DESTDIR)$(PREFIX)

TARGETS = pcapick

default: all
all: $(TARGETS)

pcapick: pcapick.c
	gcc $(CFLAGS) -lflowcalc -lpjf pcapick.c -o pcapick

###

install:
	install -m 755 pcapick $(PKGDST)/bin

.PHONY: clean
clean:
	-rm -f *.o $(TARGETS)
