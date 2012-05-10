FLAGS += -g -Wall -pedantic -fPIC $(FLAGS_ADD)
CFLAGS   += $(FLAGS) -std=gnu99 -Dinline='inline __attribute__ ((gnu_inline))' $(CFLAGS_ADD)

PREFIX ?= /usr
PKGDST = $(DESTDIR)$(PREFIX)

TARGETS = pcapick pcapick-loose

default: all
all: $(TARGETS)

pcapick: pcapick.c
	gcc $(CFLAGS) -lflowcalc -lpjf -lm pcapick.c -o pcapick

pcapick-loose: pcapick-loose.c
	gcc $(CFLAGS) -lflowcalc -lpjf -lm pcapick-loose.c -o pcapick-loose

###

install:
	install -m 755 pcapick $(PKGDST)/bin

.PHONY: clean
clean:
	-rm -f *.o $(TARGETS)
