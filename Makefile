CFLAGS += -Ofast -I/usr/local/include
#CFLAGS += -g -I/usr/local/include
LDFLAGS += -L/usr/local/lib
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS += -lbsd
endif
DSTDIR = $$HOME/bin

all: atlas2dnst parse_dnst iter_dnsts

jsmn.o: jsmn.c
	$(CC) $(CFLAGS) -DJSMN_STRICT -c $<

rbtree.o: rbtree.c
	$(CC) $(CFLAGS) -c $<

atlas2dnst.o: atlas2dnst.c dnst.h
	$(CC) $(CFLAGS) -c $<

atlas2dnst: jsmn.o rbtree.o atlas2dnst.o
	$(CC) $(CFLAGS) -o $@ jsmn.o rbtree.o atlas2dnst.o $(LDFLAGS)

parse_dnst.o: parse_dnst.c dnst.h
	$(CC) $(CFLAGS) -c $<

parse_dnst: parse_dnst.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ parse_dnst.o $(LDFLAGS) -lgetdns

iter_dnsts.o: iter_dnsts.c dnst.h
	$(CC) $(CFLAGS) -c $<

iter_dnsts: iter_dnsts.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ iter_dnsts.o $(LDFLAGS) -lgetdns

clean:
	rm -f jsmn.o rbtree.o atlas2dnst.o atlas2dnst \
	      parse_dnst.o parse_dnst iter_dnsts.o iter_dnsts

$(DSTDIR)/atlas2dnst: atlas2dnst
	cp -p $< $@

$(DSTDIR)/parse_dnst: parse_dnst
	cp -p $< $@

$(DSTDIR)/iter_dnsts: iter_dnsts
	cp -p $< $@

$(DSTDIR)/get-daily-results.py: get-daily-results.py
	cp -p $< $@

$(DSTDIR)/fetch_and_process.sh: fetch_and_process.sh
	cp -p $< $@

$(DSTDIR)/fix_results.sh: fix_results.sh
	cp -p $< $@

install: $(DSTDIR)/atlas2dnst $(DSTDIR)/parse_dnst $(DSTDIR)/iter_dnsts $(DSTDIR)/get-daily-results.py $(DSTDIR)/fetch_and_process.sh $(DSTDIR)/fix_results.sh

