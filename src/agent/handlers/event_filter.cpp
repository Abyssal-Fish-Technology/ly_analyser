#include "event_filter.h"

#include <memory>
#include <string>
#include "../../common/common.h"
#include "../../common/event.pb.h"
#include "../../common/log.h"
#include "../define.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////
class TimeRangeEventFilter : public EventFilter {
 public:
  TimeRangeEventFilter(u32 starttime, u32 endtime) : starttime_(starttime), endtime_(endtime) {}
  virtual FilterResult CheckEvent(const event::GenEventRecord& event) {
    if (event.time() >= starttime_ && event.time() < endtime_) {
      if (DEBUG) log_info("TimeRangeEventFilter votes POSITIVE.\n");
      return FilterResult::POSITIVE;
    } else {
      // if (DEBUG) log_info("TimeRangeEventFilter votes NEGATIVE.\n");
      return FilterResult::NEGATIVE;
    }
  }

 private:
  u32 starttime_;
  u32 endtime_;
};

////////////////////////////////////////////////////////////////////////////
class TypeIdEventFilter : public EventFilter {
 public:
  explicit TypeIdEventFilter(u32 type_id) : type_id_(type_id) {}
  virtual FilterResult CheckEvent(const event::GenEventRecord& event) {
    if (event.type_id() == type_id_) {
      if (DEBUG) log_info("TypeIdEventFilter votes POSITIVE.\n");
      return FilterResult::POSITIVE;
    } else {
      if (DEBUG) log_info("TypeIdEventFilter votes NEGATIVE.\n");
      return FilterResult::NEGATIVE;
    }
  }

 private:
  u32 type_id_;
};

////////////////////////////////////////////////////////////////////////////
class ConfigIdEventFilter : public EventFilter {
 public:
  explicit ConfigIdEventFilter(u32 config_id) : config_id_(config_id) {}
  virtual FilterResult CheckEvent(const event::GenEventRecord& event) {
    if (event.config_id() == config_id_) {
      if (DEBUG) log_info("ConfigIdEventFilter votes POSITIVE.\n");
      return FilterResult::POSITIVE;
    } else {
      if (DEBUG) log_info("ConfigIdEventFilter votes NEGATIVE.\n");
      return FilterResult::NEGATIVE;
    }
  }

 private:
  u32 config_id_;
};

////////////////////////////////////////////////////////////////////////////
class AndEventFilter : public EventFilter {
 public:
  explicit AndEventFilter(bool strong) : strong_(strong) {}
  virtual ~AndEventFilter() {
    for (auto it = sub_filters_.begin(); it != sub_filters_.end(); ++it) {
      delete *it;
    }
  }
  virtual FilterResult CheckEvent(const event::GenEventRecord& event) {
    for (auto it = sub_filters_.begin(); it != sub_filters_.end(); ++it) {
      auto result = (*it)->CheckEvent(event);
      if (result == FilterResult::NEGATIVE) return result;
      if (result == FilterResult::IRRELEVANT && strong_) return FilterResult::NEGATIVE;
    }
    if ((sub_filters_.size() == 0) && strong_) {
      return FilterResult::NEGATIVE;
    } else {
      return FilterResult::POSITIVE;
    }
  }

  void AddSubFilter(EventFilter* sub_filter) {
    sub_filters_.push_back(sub_filter);
  }

  int size() { return sub_filters_.size(); }

 private:
  // If true, all sub filter have to vote POSITIVE to return POSITIVE.
  bool strong_;
  std::vector<EventFilter*> sub_filters_;
};

////////////////////////////////////////////////////////////////////////////
class OrEventFilter : public EventFilter {
 public:
  OrEventFilter() {}
  virtual ~OrEventFilter() {
    for (auto it = sub_filters_.begin(); it != sub_filters_.end(); ++it) {
      delete *it;
    }
  }
  virtual FilterResult CheckEvent(const event::GenEventRecord& event) {
    for (auto it = sub_filters_.begin(); it != sub_filters_.end(); ++it) {
      auto result = (*it)->CheckEvent(event);
      if (result == FilterResult::POSITIVE) return result;
    }
    return FilterResult::NEGATIVE;
  }

  void AddSubFilter(EventFilter* sub_filter) {
    sub_filters_.push_back(sub_filter);
  }

 private:
  std::vector<EventFilter*> sub_filters_;
};

////////////////////////////////////////////////////////////////////////////
EventFilter* EventFilterReqFactory::CreateEventFilter() {
  std::unique_ptr<AndEventFilter> and_filter(
    new AndEventFilter(false /* strong */));

  if (req_.has_type_id()) {
    and_filter->AddSubFilter(new TypeIdEventFilter(req_.type_id()));
  }

  if (req_.has_starttime() && req_.has_endtime()) {
    and_filter->AddSubFilter(
        new TimeRangeEventFilter(req_.starttime(), req_.endtime()));
  }

  if (req_.config_id_size() > 0) {
    std::unique_ptr<OrEventFilter> or_filter(new OrEventFilter());
    for (int i = 0; i < req_.config_id_size(); ++i) {
      or_filter->AddSubFilter(new ConfigIdEventFilter(req_.config_id(i)));
    }
    and_filter->AddSubFilter(or_filter.release());
  }
  return and_filter.release();    
};
