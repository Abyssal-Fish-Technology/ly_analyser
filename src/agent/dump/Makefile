CC = g++
CCDEPMODE = depmode=gcc3
CFLAGS = -g -O2 -Wall -Wmissing-declarations -Wmissing-noreturn -fno-strict-aliasing
CPP = g++ -E
DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES = -I. 
libnfdump_a_CFLAGS = -I.. -ggdb -fPIC
SHELL = /bin/sh
YACC = bison -y
YFLAGS =
YLWRAP = ./ylwrap
LEX_OUTPUT_ROOT = lex.yy
LEX = flex
LFLAGS = -i
BUILT_SOURCES = grammar.h
GENERATED_LIBS= libnfdump.a
AM_YFLAGS = -d
LEXCOMPILE = $(LEX) $(LFLAGS) $(AM_LFLAGS)
YACCCOMPILE = $(YACC) $(YFLAGS) $(AM_YFLAGS)

all: $(BUILT_SOURCES)
	$(MAKE) $(AM_MAKEFLAGS) all-am

LIBNFDUMP_OBJ = libnfdump.o nf_common.o nffile.o nflowcache.o nfstat.o nfexport.o nfx.o nfxstat.o nfprof.o util.o scanner.o exporter.o ipconv.o minilzo.o multi_nftree.o multi_grammar.o flist.o fts_compat.o

grammar.h: grammar.c
	@if test ! -f $@; then \
		rm -f grammar.c; \
		$(MAKE) $(AM_MAKEFLAGS) grammar.c; \
	else :; fi

multi_grammar.h: multi_grammar.c
	@if test ! -f $@; then \
		rm -f multi_grammar.c; \
		$(MAKE) $(AM_MAKEFLAGS) multi_grammar.c; \
	else :; fi

.c.o:
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(libnfdump_a_CFLAGS) $(CFLAGS) -c -o $@ $<

.l.c:
	$(SHELL) $(YLWRAP) $< $(LEX_OUTPUT_ROOT).c $@ -- $(LEXCOMPILE)
	
.y.c:
	$(SHELL) $(YLWRAP) $< y.tab.c $@ y.tab.h $*.h y.output $*.output -- $(YACCCOMPILE)

libnfdump.a:$(LIBNFDUMP_OBJ)
	ar cru $@ $^

CLEANFILES = lex.yy.c grammar.c grammar.h scanner.c scanner.h multi_grammar.c multi_grammar.h

all-am: Makefile $(GENERATED_LIBS)

clean:
	rm -f *.o a.out *~ core* $(GENERATED_LIBS) $(CLEANFILES)
	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

.MAKE: all 

.PHONY: all install clean  
