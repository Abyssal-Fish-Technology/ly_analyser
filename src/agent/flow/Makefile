CXX=g++
INCS=-I. -I/usr/include -I/usr/local/include -I/usr/local/include/tf/ -I/usr/local/include/tf/bazel-genfiles -I/usr/local/include/tf/tensorflow -I/usr/local/include/tf/tensorflow/third-party -I/usr/local/include/tf/tensorflow/contrib/makefile/downloads/eigen -I/usr/local/include/tf/tensorflow/contrib/makefile/downloads/absl -I/usr/local/include/tf/tensorflow/contrib/makefile/gen/protobuf/include -I/usr/local/include/tf/tensorflow/contrib/makefile/gen/proto
CXXFLAGS=-Wall -fPIC -g -std=c++11 -DAGENT -O2
CXXFLAGS+=-I../../common
#CXXFLAGS+=-D_FILE_OFFSET_BITS=64
LDFLAGS+=-L/usr/lib64 -L/usr/lib -L/usr/local/lib -L. -L../../common
LDLIBS+=-Wl,--whole-archive -lprotobuf -Wl,--no-whole-archive -lcommon
LDLIBS+=-lboost_regex
LDLIBS+=-ltensorflow_cc -ltensorflow_framework
# SUBDIRS=db
CMD_INSTALL_DIR=/Agent/cmd
BIN_INSTALL_DIR=/Agent/bin
LIB_INSTALL_DIR=/Agent/lib
PAT_INSTALL_DIR=/Agent/data

PAT=indexer_feature
CACHE=indexer_cache
DOMAINS=domains

FLOW_FILTER_OBJS=$(CONFIG_OBJS) flow_filter.o mo_filter.o ip_scan_filter.o ip_set_filter.o threshold_filter.o bw_filter.o nf_scanner.o flow_file_util.o tcpinit_filter.o service_filter.o assetsrv_filter.o dns_filter.o dns_tunnel.o port_scan_filter.o url_content_filter.o frn_trip_filter.o icmp_tunnel.o dga_filter.o threat_filter.o dnstun_ai_filter.o mining_filter.o
FLOW_CAPD_LAUNCHER_OBJS=flow_capd_launcher.o

LIBS=../dump/libnfdump.a ../model/model.a ../data/data.a ../config/config.a
BIN_EXES=flow_capd_launcher
EXES=$(BIN_EXES)

GENERATED_LIBS=libflow_filter.so flow_filter.a
SHARED_LIBS=libflow_filter.so

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<

all:$(EXES) $(GENERATED_LIBS)

libflow_filter.so:$(FLOW_FILTER_OBJS) $(LIBS)
	$(CXX) $^ -shared -o $@ $(LDFLAGS)

flow_filter.a:$(FLOW_FILTER_OBJS)
	ar rcs $@ $^

flow_capd_launcher:$(FLOW_CAPD_LAUNCHER_OBJS) $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

install:
	mkdir -p $(LIB_INSTALL_DIR)
	mkdir -p $(BIN_INSTALL_DIR)
	mkdir -p $(PAT_INSTALL_DIR)
	cp $(CACHE) $(PAT_INSTALL_DIR)
	cp $(PAT) $(PAT_INSTALL_DIR)
	cp $(DOMAINS) $(PAT_INSTALL_DIR)
	cp $(BIN_EXES) $(BIN_INSTALL_DIR)
	$(foreach c,$(SHARED_LIBS),sudo cp -a $(c) $(LIB_INSTALL_DIR) && ) true
	cp libflow_filter.so /lib64	
	sudo ldconfig

clean:
	# $(MAKE) -C $(SUBDIRS) clean
	rm -f *.o a.out *~ core* $(OBJS) $(EXES) $(GENERATED_LIBS) $(PB_SRCS) $(PB_HDRS) $(PB_OBJS)
	
.PHONY: all install clean $(SUBDIRS)
