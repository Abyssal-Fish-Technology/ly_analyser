#include "flow.h"
#include "define.h"
#include "../common/common.h"
#include "../common/datetime.h"

using namespace std;

string latest_flow_files(u32 devid, u32 time_range) {
  time_range -= time_range % 300;
  auto endtime = datetime::latest_flow_time();
  auto starttime = endtime - time_range;
  auto endtime_str = datetime::format_timestamp(endtime);
  auto starttime_str = datetime::format_timestamp(starttime);

  ostringstream s;
  s << AGENT_FLOW_DIR"/" << devid << "/nfcapd." << starttime_str << ":nfcapd." << endtime_str;
  return s.str();
}
