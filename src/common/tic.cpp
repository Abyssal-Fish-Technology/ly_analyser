#include <string>
#include "md5.h"
#include "define.h"
#include "tic.h"

using namespace std;

namespace tic {

string generate_token_from_key(const string& key, long ts_now, long start_time, long valid_time) {
	if ( key.empty() )
		return string();

	if (ts_now==0)
		ts_now = time(NULL);

	string interval_start = to_string(ts_now - (ts_now - start_time) % valid_time);
	return MD5( key + interval_start + to_string(valid_time) ).toString();
}

} // namespace std
