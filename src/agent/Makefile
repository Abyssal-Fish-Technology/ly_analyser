SUBDIRS=dump utils config model data flow indexing handlers
 

all:
	$(foreach c,$(SUBDIRS),$(MAKE) $@ -C $c &&) true

install:
	$(foreach c,$(SUBDIRS),$(MAKE) $@ -C $c &&) true

clean:
	$(foreach c,$(SUBDIRS),$(MAKE) $@ -C $c &&) true
	
.PHONY: all install clean
