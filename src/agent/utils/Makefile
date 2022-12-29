CXX=g++
INCS=-I. -I/usr/include -I/usr/local/include
CXXFLAGS=-Wall -fPIC -g -std=c++1y -DAGENT -O2
CXXFLAGS+=-I../../common
#CXXFLAGS+=-D_FILE_OFFSET_BITS=64
LIB_INSTALL_DIR=/Agent/lib
LDFLAGS+=-L/usr/lib64 -L/usr/lib -L/usr/local/lib -L. -L../../common
LDLIBS+=-Wl,--whole-archive -lprotobuf -Wl,--no-whole-archive
LDLIBS+=-lcommon

OBJS=time_util.o
SHARED_LIBS=../../common/libcommon.so
GENERATED_LIBS=utils.a

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<

all:$(GENERATED_LIBS)

utils.a:$(OBJS)
	ar rcs $@ $^

clean:
	# $(MAKE) -C $(SUBDIRS) clean
	rm -f *.o a.out *~ core* $(OBJS) $(EXES) $(GENERATED_LIBS) $(PB_SRCS) $(PB_HDRS) $(PB_OBJS)
	
.PHONY: all install clean $(SUBDIRS)
