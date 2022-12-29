#ifndef TIC_H
#define TIC_H

#include "define.h"

namespace tic {
// return empty string on failure
std::string generate_token_from_key(const std::string& key, long ts_now = 0, long start_time = AUTH_START_TIME, long valid_time = AUTH_VALID_TIME);

}

#endif