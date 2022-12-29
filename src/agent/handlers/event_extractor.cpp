#include "event_extractor.h"

#include <memory>
#include <iostream>
#include <sstream>
#include <string>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include "../../common/common.h"
#include "../../common/event.pb.h"
#include "../../common/log.h"
#include "../../common/strings.h"

using namespace std;
using google::protobuf::io::IstreamInputStream;
using google::protobuf::io::OstreamOutputStream;

////////////////////////////////////////////////////////////////////////////
EventExtractor::EventExtractor(std::unique_ptr<EventFilter> filter)
  : filtered_(false), filter_(std::move(filter)) {}

////////////////////////////////////////////////////////////////////////////
bool EventExtractor::LoadEventsFromFile() {
  ifstream ifs(AGENT_EVENT_FILE, ios_base::in);
  IstreamInputStream is(&ifs);
  if (google::protobuf::TextFormat::Parse(&is, &events_)) {
    return true;
  }
  return false;
}

////////////////////////////////////////////////////////////////////////////
void EventExtractor::LoadAndFilter() {
  if (!LoadEventsFromFile()) return;
  event::GenEventRes events;
  events.Swap(&events_);
  for (auto it = events.records().begin(); it != events.records().end(); ++it) {
    if (filter_->CheckEvent(*it) == EventFilter::FilterResult::POSITIVE) {
      if (DEBUG) log_info("Add event to records:%s \n", it->DebugString().c_str());
      auto record = events_.add_records();
      *record = *it;
    } else {
      if (DEBUG) log_info("Skip event %s\n", it->DebugString().c_str());
    }
  }
  filtered_ = true;
}

////////////////////////////////////////////////////////////////////////////
const event::GenEventRes& EventExtractor::FilterEvents() {
  if (!filtered_) LoadAndFilter();
  return events_;
}
