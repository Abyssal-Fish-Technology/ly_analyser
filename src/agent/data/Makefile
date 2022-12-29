CXX=g++
INCS=-I. -I/usr/include -I/usr/local/include
CXXFLAGS=-Wall -fPIC -g -std=c++1y -DAGENT -O2 
CXXFLAGS+=-I../../common
#CXXFLAGS+=-D_FILE_OFFSET_BITS=64
LIB_INSTALL_DIR=/Agent/lib
LDFLAGS+=-L/usr/lib64 -L/usr/lib -L/usr/local/lib -L. -L../../common
LDLIBS+=-Wl,--whole-archive -lprotobuf -Wl,--no-whole-archive
LDLIBS+=-lcommon -lpthread

OBJS=unqlite_db.o dbctx.o tsdb.o unqlite.o web_cache.o
PBS=dbctx.proto
PB_SRCS=$(PBS:.proto=.pb.cc)
PB_HDRS=$(PBS:.proto=.pb.h)
PB_OBJS=$(PB_SRCS:.cc=.o)
GENERATED_LIBS=data.a

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<

all:$(GENERATED_LIBS)

data.a:$(OBJS) $(PB_OBJS)
	ar rcs $@ $^

$(OBJS):$(PB_OBJS)

$(PB_SRCS):$(PBS)
	protoc $^ --cpp_out=.

$(PB_OBJS):$(PB_SRCS)

clean:
	# $(MAKE) -C $(SUBDIRS) clean
	rm -f *.o a.out *~ core* $(OBJS) $(EXES) $(GENERATED_LIBS) $(PB_SRCS) $(PB_HDRS) $(PB_OBJS)
	
.PHONY: all install clean $(SUBDIRS)
