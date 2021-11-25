BINS = serv

CFLAGS = -Ilibev-4.33 -Ilocal/include -pthread -Wall -fno-strict-aliasing
CFLAGS_DEBUG = -g -O0
CFLAGS_OPTIMIZE = -O3 -march=native -mtune=native -flto
LDFLAGS = -lrt -lm -Llocal/lib -lfmt -lev

STATIC_LIBEV = local/lib/libev.a
STATIC_FMT = local/lib/libfmt.a

CC = gcc
CXX = g++
RE2C = local/bin/re2c

#RE2COPTS = --conditions --computed-gotos --nested-ifs --case-ranges -W -Wno-nondeterministic-tags --storable-state
#RE2COPTS = --conditions --nested-ifs --case-ranges -W -Wno-nondeterministic-tags --storable-state
RE2COPTS = --conditions --case-ranges -W -Wno-nondeterministic-tags --storable-state

RE2C_SOURCE = serv.c http_headers.c

RE2C_OBJS = http_headers.o serv.o
C_OBJS = dlist.o mtag.o
CXX_OBJS = fmtshim.o

OBJS = $(RE2C_OBJS) $(C_OBJS) $(CXX_OBJS)


all: local/bin/re2c $(BINS) $(OBJS)


# dependencies
# re2c
local/bin/re2c:
	git submodule update --init --recommend-shallow --depth 1 deps/re2c
	mkdir -p build/re2c
	cd deps/re2c && ./autogen.sh
	cd build/re2c && ../../deps/re2c/configure --enable-docs --disable-golang --enable-libs --disable-shared --enable-static && make -j 4
	make -C build/re2c install-strip DESTDIR="`pwd`" prefix=/local

# fmt
$(STATIC_FMT):
	git submodule update --init --recommend-shallow --depth 1 deps/fmt
	cmake -g "Unix Makefiles" -S deps/fmt -B build/fmt  -DCMAKE_INSTALL_PREFIX=/local
	make -C build/fmt fmt/fast install/fast DESTDIR=../..

# libev
$(STATIC_LIBEV):
	mkdir -p deps/libev
	cd deps/libev && wget http://dist.schmorp.de/libev/libev-4.33.tar.gz -O - | tar xz --strip-components=1
	mkdir -p build/libev
	cd build/libev && ../../deps/libev/configure CFLAGS="$(CFLAGS_OPTIMIZE) -DEV_MULTIPLICITY=1" --enable-shared=no --enable-static=yes
	make -C build/libev install prefix=/local DESTDIR="`pwd`"


deps: local/bin/re2c local/lib/libev.a local/lib/libfmt.a
	test -e deps && git submodule foreach git checkout -f || echo -n ""
	test -e build && rm -r build || echo -n ""

deps-clean:
	test -e build && rm -r build || echo -n ""
	test -e deps && git submodule foreach git checkout -f || echo -n ""
	test -e deps && git submodule deinit deps/re2c || echo -n ""
	test -e deps && git submodule deinit deps/fmt || echo -n ""
	test -e deps && rm -r deps || echo -n ""


# .re -> .c
$(RE2C_SOURCE): %.c: %.re Makefile *.reh *.h $(RE2C)
	$(RE2C) $(RE2COPTS) $< -o $@


# .c, .cc -> .o
$(C_OBJS): %.o: %.c *.h Makefile
	$(CC) $(CFLAGS) $(CFLAGS_OPTIMIZE) -c $< -o $@

$(CXX_OBJS): %.o: %.cc *.h Makefile
	$(CXX) $(CFLAGS) $(CFLAGS_OPTIMIZE) -c $< -o $@

$(addprefix dbg_,$(C_OBJS)): dbg_%.o: %.c *.h Makefile
	$(CC) $(CFLAGS) $(CFLAGS_DEBUG) -c $< -o $@

$(addprefix dbg_,$(CXX_OBJS)): dbg_%.o: %.c *.h Makefile
	$(CC) $(CFLAGS) $(CFLAGS_DEBUG) -c $< -o $@


# bin targets
$(BINS): %: %.c Makefile *.h $(OBJS) deps
	$(CC) $(CFLAGS) $(CFLAGS_OPTIMIZE) -o $@ $< $(OBJS) $(LDFLAGS)

$(addprefix dbg_,$(BINS)): dbg_%: %.c Makefile *.h $(OBJS) deps
	$(CC) $(CFLAGS) $(CFLAGS_DEBUG) -o $@ $< $(OBJS) $(LDFLAGS)


$(addsuffix .dot,$(BINS)): %.dot: %.re Makefile *.h
	$(RE2C) $(RE2COPTS) --emit-dot $< -o $*.dot


vim-gdb: dbg_serv
	vim -c "set number" -c "set mouse=a" -c "set foldlevel=100" -c "Termdebug -ex set\ print\ pretty\ on --args ./dbg_serv" -c "1windo set nonumber" -c "2windo set nonumber" serv.re

tags: *.re
	ctags-exuberant --recurse=yes --langmap=c:+.re $(subst .c,.re,$(RE2C_SOURCE)) $(subst .o,.c,$(C_OBJS)) $(subst .o,.cc,$(CXX_OBJS)) *.reh *.h local/include/*.h

clean:
	-rm -rf core $(BINS) $(addprefix dbg_,$(BINS)) $(addsuffix .dot,$(BINS)) *.o tags $(RE2C_SOURCE) build

.PHONY: all clean vim-gdb deps

.SILENT: deps
