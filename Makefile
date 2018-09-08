CFLAGS += -Ofast -I/usr/local/include
LDFLAGS += -L/usr/local/lib
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS += -lbsd
endif

all: atlas2dnst parse_dnst

jsmn.o: jsmn.c
	$(CC) $(CFLAGS) -DJSMN_STRICT -c $<

rbtree.o: rbtree.c
	$(CC) $(CFLAGS) -c $<

atlas2dnst.o: atlas2dnst.c
	$(CC) $(CFLAGS) -c $<

atlas2dnst: jsmn.o rbtree.o atlas2dnst.o
	$(CC) $(CFLAGS) -o $@ jsmn.o rbtree.o atlas2dnst.o $(LDFLAGS)

parse_dnst.o: parse_dnst.c
	$(CC) $(CFLAGS) -c $<

parse_dnst: parse_dnst.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ parse_dnst.o $(LDFLAGS) -lgetdns

clean:
	rm -f jsmn.o rbtree.o atlas2dnst.o atlas2dnst parse_dnst.o parse_dnst
