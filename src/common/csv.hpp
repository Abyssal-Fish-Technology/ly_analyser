#ifndef _CSV_H_
#define _CSV_H_

#include <vector>
#include <string>
#include <boost/tokenizer.hpp>

namespace csv {

typedef boost::tokenizer< boost::escaped_list_separator<char> > Tokenizer;

static inline void fill_vector_from_line(std::vector<std::string>& vec, const std::string& line) {
	Tokenizer tok(line);
	vec.assign(tok.begin(),tok.end());

	return;
}

static inline void fill_vector_from_line(std::vector<std::string>& vec, const std::string& line, char delim) {
	boost::escaped_list_separator<char> sep('\\',delim,'\"');
	Tokenizer tok(line, sep);
	vec.assign(tok.begin(),tok.end());

	return;
}

} // namespace csv

#endif