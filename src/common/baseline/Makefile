CXX=g++
CXXFLAGS=-Wall -g $(INCS) -std=c++0x
INCS=-I.
LDFLAGS=-L/usr/lib64 -L/usr/lib -L/usr/local/lib

# protobuf
LDLIBS +=-lprotobuf

# removed redis
# LDLIBS+=-lhiredis

# http
INCS+=-I/usr/include/cgicc
LDLIBS+=-lcgicc -lcurl 

# sql
#INCS+=-I/usr/include/mysql -I/usr/include/cppdb
#LDFLAGS+=-L/usr/lib64/mysql -L/usr/lib/mysql -L/usr/local/mysql/lib
#LDLIBS+=-lmysqlclient -lcppdb -ldb
#LDLIBS=-dynamiclib -install_name /usr/local/mysql/lib/libmysqlclient.dylib

-include ../../local_debug.mk
-include local_debug.mk

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<

SUBDIRS=
TARGETS=baseline
SRCS=slot_generator.cpp slot_manager.cpp
OBJS=$(SRCS:.cpp=.o)
HDRS=$(SRCS:.cpp=.h)
COMMON_LIBS=../libcommon.a
LIBS+=$(COMMON_LIBS)
PBS=baseline.proto
PB_SRCS=$(PBS:.proto=.pb.cc) $(PBS:.proto=.pb.h)
PB_OBJS=$(PB_SRCS:.cc=.o)

all:$(TARGETS)
baseline:$(PB_SRCS) $(PB_OBJS) $(SRCS) $(OBJS) $(HDRS) $(LIBS)
#	$(CXX) $^ $(CXXFLAGS) $(LDFLAGS) $(LDLIBS) $(LIBS) -o $@
$(PB_SRCS):$(PBS)
	protoc $^ --cpp_out=.

install:all
clean:
	rm -f *.o a.out *~ core* $(TARGETS) $(OBJS) $(PB_SRCS) $(PB_OBJS)
	rm -rf *.dSYM
.PHONY: all install clean $(SUBDIRS)
