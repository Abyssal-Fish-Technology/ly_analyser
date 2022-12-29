#ifndef __AGENT_EVENT_EXTRACTOR__
#define __AGENT_EVENT_EXTRACTOR__

#include <memory>
#include <string>
#include "../../common/common.h"
#include "../../common/event.pb.h"
#include "../define.h"
#include "event_filter.h"

class EventExtractor {
 public:
  explicit EventExtractor(std::unique_ptr<EventFilter> filter);
  const event::GenEventRes& FilterEvents();
  
 private:
  void LoadAndFilter();
  bool LoadEventsFromFile();

  bool filtered_;
  std::unique_ptr<EventFilter> filter_;
  event::GenEventRes events_;
};

#endif  // __AGENT_EVENT_EXTRACTOR__
