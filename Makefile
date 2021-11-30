BINS = serv fmttest

CFLAGS = -I. -Ilibev-4.33 -Ilocal/include -pthread -Wall -fno-strict-aliasing -std=gnu17
CXXFLAGS = -I. -Ilibev-4.33 -Ilocal/include -pthread -Wall -fno-strict-aliasing -std=gnu++17
CFLAGS_DEBUG = -ggdb3 -O0
CFLAGS_OPTIMIZE = -ggdb3 -O3 -march=native -mtune=native -flto -ffast-math
LDFLAGS = -lrt -lm -Llocal/lib -lfmt -lev

STATIC_LIBEV = local/lib/libev.a
STATIC_FMT = local/lib/libfmt.a

CC = gcc
CXX = g++
RE2C = local/bin/re2c
VALGRIND = valgrind

#RE2COPTS = --conditions --computed-gotos --nested-ifs --case-ranges -W -Wno-nondeterministic-tags --storable-state
#RE2COPTS = --conditions --nested-ifs --case-ranges -W -Wno-nondeterministic-tags --storable-state
RE2COPTS = --case-ranges -W -Wno-nondeterministic-tags

VALGRINDARGS	= --tool=memcheck --num-callers=8 --leak-resolution=high \
		  --leak-check=yes -v --suppressions=suppressions --keep-debuginfo=yes \
		  --trace-children=yes

RE2C_SOURCE_STORABLE = msg.c
RE2C_SOURCE_PLAIN = http_headers.c report.c
RE2C_SOURCE = $(RE2C_SOURCE_PLAIN) $(RE2C_SOURCE_STORABLE)

RE2C_HEADERS = msg.h report.h http_headers.h		# generated headers that the c files depend on

RE2C_OBJS = http_headers.o msg.o report.o
C_OBJS = dlist.o mtag.o utils.o obstack_pool.o
#CXX_OBJS = fmtshim.o MurmurHash3.o murmur3shim.o
CXX_OBJS = MurmurHash3.o murmur3shim.o

OBJS = $(RE2C_OBJS) $(C_OBJS) $(CXX_OBJS)


all: local/bin/re2c $(BINS) $(OBJS)


# dependencies
# re2c
local/bin/re2c:
	git submodule update --init --depth 1 deps/re2c
	mkdir -p build/re2c
	cd deps/re2c && ./autogen.sh
	cd build/re2c && ../../deps/re2c/configure CFLAGS="-O0 -g" CXXFLAGS="-g -O2" RE2C_FOR_BUILD="/home/cyan/git/tcl/reuri/tools/bin/re2c" --enable-lexers --enable-docs --disable-golang --enable-libs --disable-shared --enable-static && make -j 4
	#make -C build/re2c install-strip DESTDIR="`pwd`" prefix=/local
	make -C build/re2c install DESTDIR="`pwd`" prefix=/local

# fmt
$(STATIC_FMT):
	git submodule update --init --depth 1 deps/fmt
	cmake -g "Unix Makefiles" -S deps/fmt -B build/fmt  -DCMAKE_INSTALL_PREFIX=/local
	make -C build/fmt fmt/fast install/fast DESTDIR=../..

# libev
$(STATIC_LIBEV):
	mkdir -p deps/libev
	cd deps/libev && wget http://dist.schmorp.de/libev/libev-4.33.tar.gz -O - | tar xz --strip-components=1
	mkdir -p build/libev
	cd build/libev && ../../deps/libev/configure CFLAGS="$(CFLAGS_OPTIMIZE) -DEV_MULTIPLICITY=1" --enable-shared=no --enable-static=yes
	make -C build/libev install prefix=/local DESTDIR="`pwd`"

# murmur3:
MurmurHash3.cc:
	git submodule update --init --depth 1 deps/smhasher
	cp deps/smhasher/src/MurmurHash3.cpp MurmurHash3.cc
	cp deps/smhasher/src/MurmurHash3.h .

deps: local/bin/re2c local/lib/libev.a local/lib/libfmt.a
	test -e deps && git submodule foreach git checkout -f || echo -n ""
	test -e build && rm -r build || echo -n ""
	touch deps

deps-clean:
	test -e build && rm -r build || echo -n ""
	test -e deps && git submodule foreach git checkout -f || echo -n ""
	test -e deps && git submodule deinit deps/re2c || echo -n ""
	test -e deps && git submodule deinit deps/fmt || echo -n ""
	test -e deps && rm -r deps || echo -n ""


# .re -> .c
msg.c: msg.re Makefile common.re $(RE2C)
	$(RE2C) $(RE2COPTS) --storable-state --conditions --type-header msg.h $< -o $@

http_headers.c: http_headers.re Makefile common.re $(RE2C)
	$(RE2C) $(RE2COPTS) --type-header http_headers.h $< -o $@

report.c: report.re Makefile common.re $(RE2C)
	$(RE2C) $(RE2COPTS) --type-header report.h $< -o $@

re2c: $(RE2C_SOURCE)
	touch re2c

# .c, .cc -> .o
$(C_OBJS) $(RE2C_OBJS): %.o: %.c *.h Makefile re2c
	$(CC) $(CFLAGS) $(CFLAGS_OPTIMIZE) -c $< -o $@

$(CXX_OBJS): %.o: %.cc *.h Makefile re2c
	$(CXX) $(CXXFLAGS) $(CFLAGS_OPTIMIZE) -c $< -o $@

$(addprefix dbg_,$(C_OBJS)) $(addprefix dbg_,$(RE2C_OBJS)): dbg_%.o: %.c *.h common.re local/include/*.h Makefile re2c
	$(CC) $(CFLAGS) $(CFLAGS_DEBUG) -c $< -o $@

$(addprefix dbg_,$(CXX_OBJS)): dbg_%.o: %.cc *.h common.re local/include/*.h Makefile re2c
	$(CC) $(CXXFLAGS) $(CFLAGS_DEBUG) -c $< -o $@

$(addsuffix .o,$(BINS)): %.o: %.c *.h Makefile re2c
	$(CC) $(CFLAGS) $(CFLAGS_OPTIMIZE) -c $< -o $@

$(addprefix dbg_,$(addsuffix .o,$(BINS))): dbg_%.o: %.c *.h Makefile re2c
	$(CC) $(CFLAGS) $(CFLAGS_DEBUG) -c $< -o $@

# bin targets
$(BINS): %: %.o Makefile $(OBJS) deps
	$(CC) $(CFLAGS) $(CFLAGS_OPTIMIZE) -o $@ $< $(OBJS) $(LDFLAGS)

$(addprefix dbg_,$(BINS)): dbg_%: dbg_%.o Makefile $(addprefix dbg_,$(OBJS)) deps
	$(CC) $(CFLAGS) $(CFLAGS_DEBUG) -o $@ $< $(addprefix dbg_,$(OBJS)) $(LDFLAGS)


$(addsuffix .dot,$(BINS)): %.dot: %.re Makefile *.h common.re local/include/*.h
	$(RE2C) $(RE2COPTS) --emit-dot $< -o $*.dot


vim-gdb: dbg_serv tags
	vim -c "set number" -c "set mouse=a" -c "set foldlevel=100" -c "Termdebug -ex set\ print\ pretty\ on --args ./dbg_serv" -c "1windo set nonumber" -c "2windo set nonumber" serv.c

vim-gdb-optimized: serv tags
	vim -c "set number" -c "set mouse=a" -c "set foldlevel=100" -c "Termdebug -ex set\ print\ pretty\ on --args ./serv" -c "1windo set nonumber" -c "2windo set nonumber" serv.c

vim-gdb-re2c: local/bin/re2c
	vim -c "set number" -c "set mouse=a" -c "set foldlevel=100" -c "Termdebug -ex set\ print\ pretty\ on --args local/bin/re2c $(REURIARGS) includetest.re -o includetest.c" -c "1windo set nonumber" -c "2windo set nonumber" deps/re2c/src/parse/scanner.cc

valgrind: dbg_serv
	$(VALGRIND) $(VALGRINDARGS) ./$<

tags: $(addsuffix .c,$(BINS)) $(subst .c,.re,$(RE2C_SOURCE)) $(subst .o,.c,$(C_OBJS)) $(subst .o,.cc,$(CXX_OBJS)) common.re *.h local/include/*.h Makefile
	ctags-exuberant --recurse=yes --langmap=c:+.re $(addsuffix .c,$(BINS)) $(subst .c,.re,$(RE2C_SOURCE)) $(subst .o,.c,$(C_OBJS)) $(subst .o,.cc,$(CXX_OBJS)) *.h common.re local/include/*.h

clean:
	-rm -rf core $(BINS) $(addprefix dbg_,$(BINS)) $(addsuffix .dot,$(BINS)) *.o tags $(RE2C_SOURCE) $(RE2C_HEADERS) build

.PHONY: all clean vim-gdb vim-gdb-optimized valgrind

.SILENT: deps
