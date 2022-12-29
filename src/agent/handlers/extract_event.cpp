#include <memory>
#include <iostream>
#include <sstream>
#include <string>
#include <Cgicc.h>
#include <google/protobuf/text_format.h>

#include "../../common/common.h"
#include "../../common/event.pb.h"
#include "../../common/datetime.h"
#include "../../common/file.h"
#include "../../common/http.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../define.h"
#include "event_filter.h"
#include "event_extractor.h"

using namespace std;

class HTTPProcessor {
 public:
  HTTPProcessor() : filtered_events_(nullptr) {}
  void Process();

 private:
  void ExtractEvents();

  event::GenEventReq req_;
  event::GenEventRes events_;
  std::unique_ptr<EventFilterFactory> event_filter_factory_;
  std::unique_ptr<EventFilter> event_filter_;
  std::unique_ptr<EventExtractor> event_extractor_;
  const event::GenEventRes* filtered_events_;
};

////////////////////////////////////////////////////////////////////////////
void HTTPProcessor::ExtractEvents() {
  event_filter_factory_.reset(new EventFilterReqFactory(req_));
  event_filter_.reset(event_filter_factory_->CreateEventFilter());
  if (!event_filter_) {
    log_err("Can't create EventFilter\n");
    return;
  }
  event_extractor_.reset(new EventExtractor(std::move(event_filter_)));
  filtered_events_ = &event_extractor_->FilterEvents();
}

////////////////////////////////////////////////////////////////////////////
void HTTPProcessor::Process() {
  bool is_http = getenv("REMOTE_ADDR") != NULL;
  if (is_http) std::cout << "Content-Type: application/protobuf; charset=UTF-8\r\n\r\n";

  bool parsed = false;
  cgicc::Cgicc cgi;
  if (!cgi("dbg").empty()) {
    setenv("DEBUG", "ALL", 1);
    if (DEBUG) log_info("debug mode is on\n");
  }

  const cgicc::CgiEnvironment& cgienv = cgi.getEnvironment();
  const std::string& method = cgienv.getRequestMethod();
  if (method == "POST" || method == "PUT") {
    parsed = google::protobuf::TextFormat::ParseFromString(cgienv.getPostData(), &req_);
  } else if (method == "GET") {
    //parsed = ParseGenEventReqFromUrlParams(cgi, &req_);
  }
  if (!parsed) {
    std::cout << "HTTP/1.1 400 Invalid Request\r\n\r\n";
  }

  try {
    if (DEBUG) log_info("GenEventReq: %s\n", req_.DebugString().c_str());
    ExtractEvents();
    if (filtered_events_) {
      log_info("Extracted %d events.\n", filtered_events_->records().size());
    } else {
      log_info("Can't extract events.\n");
    }

    if (filtered_events_) {
      std::ostringstream out;
      if (!filtered_events_->SerializeToOstream(&out)) {
        log_err("failed to serialize GenEventRes\n");
      }
      std::cout << out.str();
    }
  } catch (std::exception const& e) {
    log_err(__FILE__":%s\n", e.what());
  }
}

////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[]) {
  setvbuf(stdout, NULL, _IOFBF, 81920);
  HTTPProcessor processor;
  processor.Process();
  return 0;
}
