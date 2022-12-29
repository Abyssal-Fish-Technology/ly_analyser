CXX=g++
INCS=-I. -I/usr/include -I/usr/local/include -I/usr/local/include/tf/ -I/usr/local/include/tf/bazel-genfiles -I/usr/local/include/tf/tensorflow -I/usr/local/include/tf/tensorflow/third-party -I/usr/local/include/tf/tensorflow/contrib/makefile/downloads/eigen -I/usr/local/include/tf/tensorflow/contrib/makefile/downloads/absl -I/usr/local/include/tf/tensorflow/contrib/makefile/gen/protobuf/include -I/usr/local/include/tf/tensorflow/contrib/makefile/gen/proto
CXXFLAGS=-Wall -fPIC -g -std=c++1y -DAGENT -O2
CXXFLAGS+=-I../../common
#CXXFLAGS+=-D_FILE_OFFSET_BITS=64
LDFLAGS+=-L/usr/lib64 -L/usr/lib -L/usr/local/lib -L. -L../../common -L../flow
LDLIBS+=-Wl,--whole-archive -lprotobuf -Wl,--no-whole-archive -lcommon -lboost_regex -lpthread
LDLIBS+=-ltensorflow_cc -ltensorflow_framework

CMD_INSTALL_DIR=/Agent/cmd
BIN_INSTALL_DIR=/Agent/bin
LIB_INSTALL_DIR=/Agent/lib
PAT_INSTALL_DIR=/Agent/data

FILTER=indexer_process

LIBS=../dump/libnfdump.a ../flow/flow_filter.a ../model/model.a ../data/data.a ../config/config.a
BIN_EXES=indexer
EXES=$(BIN_EXES)
SCRIPTS=launch_indexer.sh

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<

all:$(EXES)

indexer:indexer.o flow_indexer.o cache_generator.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

install:all
	cp $(FILTER) $(PAT_INSTALL_DIR) 
	cp $(BIN_EXES) $(BIN_INSTALL_DIR)
	cp $(SCRIPTS) $(BIN_INSTALL_DIR)

clean:
	# $(MAKE) -C $(SUBDIRS) clean
	rm -f *.o a.out *~ core* $(OBJS) $(EXES) $(GENERATED_LIBS) $(PB_SRCS) $(PB_HDRS) $(PB_OBJS)
	
.PHONY: all install clean $(SUBDIRS)
