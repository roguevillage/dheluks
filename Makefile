# DHELUKS MAKEFILE

CFLAGS += -g -pedantic -std=c99
CFLAGS += $(shell pkg-config --cflags nettle hogweed)
LDFLAGS += $(shell pkg-config --libs nettle hogweed)
all: client askpass

check: drivers
	./drivers

DOCS = dheluks.html dheluks.pdf CONTRIBUTING.html CONTRIBUTING.pdf
docs: $(DOCS)
dheluks.html: README.md
	pandoc -o $@ -f markdown -t html $<
dheluks.pdf: README.md
	pandoc -o $@ -f markdown -t latex $<

%.html: %.md
	pandoc -o $@ -f markdown -t html $<
%.pdf: %.md
	pandoc -o $@ -f markdown -t latex $<


#compiler
%.o: %.c dheluks.h
	gcc -c -o $@ $(CFLAGS) $<


#linker
server: dheluks_server_request_pwd.o dheluks.o
	gcc -o $@ $(CFLAGS) $^ $(LDFLAGS)

client: client.o dheluks.o
	gcc -o $@ $(CFLAGS) $^ $(LDFLAGS)

askpass: askpass.o dheluks.o
	gcc -o $@ $(CFLAGS) $^ $(LDFLAGS)

drivers: drivers.o dheluks.o
	gcc -o $@ $(CFLAGS) $^ $(LDFLAGS)

clean:
	rm -f askpass *.o
	rm -f client *.o
	rm -f server *.o
	rm -f dheluks *.o
	rm -f $(DOCS)

.PHONY: all clean docs
