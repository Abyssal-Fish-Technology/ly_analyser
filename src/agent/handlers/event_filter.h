#ifndef __AGENT_EVENT_FILTER_H__
#define __AGENT_EVENT_FILTER_H__

#include <memory>
#include <string>
#include "../../common/common.h"
#include "../../common/event.pb.h"

////////////////////////////////////////////////////////////////////////////
class EventFilter {
 public:
  enum FilterResult {
    UNKNOWN = 0,
    POSITIVE = 1,
    NEGATIVE = 2,
    IRRELEVANT = 3,
  };
    
  EventFilter() {}
  virtual ~EventFilter() {}
  virtual FilterResult CheckEvent(const event::GenEventRecord& event) {
    return FilterResult::IRRELEVANT;
  }
};

////////////////////////////////////////////////////////////////////////////
class EventFilterFactory {
 public:
  virtual EventFilter* CreateEventFilter() = 0;

 protected:
  EventFilterFactory() {}
};

////////////////////////////////////////////////////////////////////////////
class EventFilterReqFactory : public EventFilterFactory {
 public:
  explicit EventFilterReqFactory(const event::GenEventReq& req) : req_(req) {}
  EventFilter* CreateEventFilter() override;

 private:
  const event::GenEventReq& req_;
};

#endif // __AGENT_EVENT_FILTER_H__
