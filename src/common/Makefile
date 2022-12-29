CXX=g++
INCS=-I/usr/include/cppdb -I/usr/include/cgicc -I. -I/usr/local/include
CXXFLAGS=-Wall -g -fPIC -std=c++1y -O2
LDFLAGS=-shared -Wl,--whole-archive -lprotobuf -lcppdb -lcgicc -lcurl -lboost_regex -Wl,--no-whole-archive

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<
.cc.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<

SUBDIRS=baseline
TARGETS=common libcommon.so
SRCS=strings.cpp log.cpp ip.cpp datetime.cpp topn_req.cpp sha256.cpp http.cpp file.cpp ini.cpp config.cpp mo_req.cpp md5.cpp cJSON.cpp slice.cpp stringutil.cpp scoped_mmap.cpp mmapped_file.cpp event_req.cpp feature_req.cpp topn_param.cpp CMyINI.cpp asset.cpp ctl_req.cpp event_feature_req.cpp
SRCS+=tic.cpp
SRCS+=evidence_req.cpp 
HDRS=$(SRCS:.cpp=.h)
OBJS=$(SRCS:.cpp=.o)
PBS=cache.proto topn.proto config.proto mo.proto event.proto policy.proto feature.proto ctl.proto event_feature.proto
PBS+=domaininfo.proto
PBS+=evidence.proto
PB_SRCS=$(PBS:.proto=.pb.cc)
PB_HDRS=$(PBS:.proto=.pb.h)
PB_OBJS=$(PB_SRCS:.cc=.o)

SERVER_INSTALL_DIR=/Server/lib
AGENT_INSTALL_DIR=/Agent/lib

-include ../local_debug.mk
-include local_debug.mk

all:$(TARGETS)
	$(foreach c,$(SUBDIRS),$(MAKE) -C $(c) && ) true
common:$(PBS) $(PB_OBJS) $(SRCS) $(OBJS) $(HDRS)
	ar rcs libcommon.a $(OBJS) $(PB_OBJS)
libcommon.so: $(PBS) $(PB_OBJS) $(SRCS) $(OBJS) $(HDRS)
	$(CXX) -o $@ $(LDFLAGS) $(OBJS) $(PB_OBJS)
$(PB_SRCS):$(PBS)
	protoc $^ --cpp_out=.

install:
	mkdir -p $(SERVER_INSTALL_DIR)
	mkdir -p $(AGENT_INSTALL_DIR)
	cp libcommon.so $(SERVER_INSTALL_DIR)
	cp libcommon.so $(AGENT_INSTALL_DIR)
	cp libcommon.so /lib64

clean:
	$(foreach c,$(SUBDIRS),$(MAKE) -C $(c) clean && ) true
	rm -f *.o a.out *~ core* $(TARGETS) $(OBJS) $(PB_SRCS) $(PB_HDRS) $(PB_OBJS) libcommon.a 
	rm -rf *.dSYM

