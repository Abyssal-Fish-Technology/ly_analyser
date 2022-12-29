CXX=g++
INCS=-I. -I/usr/include -I/usr/local/include -I/usr/include/cgicc -I../../common -I/usr/local/include/tf/ -I/usr/local/include/tf/bazel-genfiles -I/usr/local/include/tf/tensorflow -I/usr/local/include/tf/tensorflow/third-party -I/usr/local/include/tf/tensorflow/contrib/makefile/downloads/eigen -I/usr/local/include/tf/tensorflow/contrib/makefile/downloads/absl -I/usr/local/include/tf/tensorflow/contrib/makefile/gen/protobuf/include -I/usr/local/include/tf/tensorflow/contrib/makefile/gen/proto
CXXFLAGS=-Wall -fPIC -g -std=c++1y -DAGENT -O2
#CXXFLAGS+=-D_FILE_OFFSET_BITS=64
LDFLAGS+=-L/usr/lib64 -L/usr/lib -L/usr/local/lib -L. -L../../common -L../flow -L../data
LDLIBS+=-Wl,--whole-archive -lprotobuf -Wl,--no-whole-archive -lcommon -lcgicc -lboost_regex -lpthread
LDLIBS+=-ltensorflow_cc -ltensorflow_framework

CMD_INSTALL_DIR=/Agent/cmd
BIN_INSTALL_DIR=/Agent/bin
LIB_INSTALL_DIR=/Agent/lib

PBS=event.proto
PB_SRCS=$(PBS:.proto=.pb.cc)
PB_HDRS=$(PBS:.proto=.pb.h)
PB_OBJS=$(PB_SRCS:.cc=.o)

LIBS=../config/config.a ../model/model.a ../utils/utils.a ../flow/flow_filter.a ../dump/libnfdump.a ../data/data.a 
CMD_EXES=config_updater extract_event flow_scan extract_feature output_unqlite actl extract_event_feature extract_pcap
BIN_EXES=extractor fsd

EXES=$(CMD_EXES) $(BIN_EXES)


all:$(EXES)

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<

$(PB_SRCS):$(PBS)
	protoc $^ --cpp_out=.

config_updater:config_updater.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

extractor:extractor.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

extract_feature:extract_feature.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

extract_event_feature:extract_event_feature.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

output_unqlite:output_unqlite.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

extract_event:event_extractor.o event_filter.o extract_event.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

extract_pcap:extract_pcap.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS) -lpcap

flow_scan:flow_scan.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

actl:actl.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

fsd:fsd.o $(LIBS)
	$(CXX) $^ -o $@ $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

install:all
	mkdir -p $(CMD_INSTALL_DIR)
	cp $(BIN_EXES) $(BIN_INSTALL_DIR)
	cp $(CMD_EXES) $(CMD_INSTALL_DIR)

clean:
	# $(MAKE) -C $(SUBDIRS) clean
	rm -f *.o a.out *~ core* $(OBJS) $(EXES) $(GENERATED_LIBS) $(PB_SRCS) $(PB_HDRS) $(PB_OBJS)
	
.PHONY: all install clean $(SUBDIRS)
