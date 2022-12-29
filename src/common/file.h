#ifndef __COMMON_FILE_H__
#define __COMMON_FILE_H__

#include "common.h"
#include <unordered_set>

std::string get_base_path(const std::string& path);
bool make_dirs(const std::string& path);
void read_file_to_cout(const char * path);
bool write_file_contents(
    const std::string& file_name, const std::string& contents,
    bool lock=true, bool use_dummy_byte = true);
bool read_file_contents(
  const std::string& file_name, std::string* contents, bool lock=true);
bool file_exists(const std::string& file_name);
void set_max_open_files(u32 num_of_files);
void LoadLineFromFile(const std::string& file_name, std::unordered_set<std::string>& lines); // read to set

#endif // __COMMON_FILE_H__
