#ifndef __AGENT_FLOW_FILTER_H__
#define __AGENT_FLOW_FILTER_H__

#include <string>

using namespace std;

class FlowFilter {
 public:
  virtual ~FlowFilter() {}

  typedef void* FlowPtr;
  virtual bool CheckFlow(FlowPtr flow) = 0;
//  virtual bool UpdateByFlow(FlowPtr flow) = 0;

 protected:
  FlowFilter() {}
};

class FlowFilters {
 public:
  static FlowFilters* Create();
  virtual ~FlowFilters();
  virtual bool ParseOptArg(const std::string& optarg) = 0;
  virtual bool CheckFlow(FlowFilter::FlowPtr flow) = 0;

 protected:
  FlowFilters();
};
#endif // __AGENT_FLOW_FILTER_H__
