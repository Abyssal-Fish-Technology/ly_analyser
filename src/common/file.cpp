#include "file.h"
#include "log.h"
#include "strings.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////
// For: /some/path/to/file, return /some/path/to
// For: /some/path/to/dir, return /some/path/to
// For: /some/path/to/dir/, return /some/path/to/dir
// For: file, return ''
// For: dir, return ''
string get_base_path(const string& path) {
  auto i = path.find_last_of('/');
  if (i == string::npos) { return ""; }
  return path.substr(0, i);
}

////////////////////////////////////////////////////////////////////////////
bool make_dirs(const string& path) {
  int pos = 0;
  while (true) {
    auto i = path.find_first_of('/', pos);
    if (i == string::npos) break;
    if (i && -1 == mkdir(path.substr(0, i).c_str(), 0777) && errno != EEXIST) {
      log_err("Could not create dir %s, err:%s\n", path.substr(0, i).c_str(), 
              strerror(errno));
      return false;
    }
    pos = i + 1;
  }
  return true;
}

////////////////////////////////////////////////////////////////////////////
time_t get_file_mtime(const char *path)
{
  struct stat st;
  if (stat(path, &st) < 0) 
    return 0;
  else
    return st.st_mtime;
}

////////////////////////////////////////////////////////////////////////////
void read_file_to_cout(const char * path)
{
  cout << ifstream(path, ifstream::in).rdbuf();
}

////////////////////////////////////////////////////////////////////////////
bool file_exists(const string& file_name) {
  return ifstream(file_name.c_str()).good();
}

////////////////////////////////////////////////////////////////////////////
bool write_file_contents(
    const string& file_name, const string& contents,
    bool lock, bool use_dummy_byte) {
  u64 len = contents.size();

  int fd = open(file_name.c_str(), O_CREAT|O_RDWR|O_TRUNC, 00600);
  if (fd == -1) {
    log_err("Cound not create file: %s\n", file_name.c_str());
    return false;
  }
  if (lock && -1 == flock(fd, LOCK_EX)) {
    log_err("Could not lock file for writing: %s\n", file_name.c_str());
    close(fd);
    return false;
  }

  if (-1 == ftruncate(fd, len)) {
    perror("ftruncate");
    close(fd);
  }

  /* go to the location corresponding to the last byte */
  if (use_dummy_byte && lseek(fd, len, SEEK_SET) == -1) {
    log_err("Could not seek to last byte: %s\n", file_name.c_str());
    close(fd);
    return false;
  }
  /* write a dummy byte at the last location */
  if (use_dummy_byte && write(fd, "", 1) != 1) {
    log_err("Could not write to file: %s\n", file_name.c_str());
    close(fd);
    return false;
  }

  /* mmap the output file */
  void* dst;
  if ((dst = mmap (0, len, PROT_WRITE, MAP_SHARED, fd, 0)) == (caddr_t) -1) {
    log_err("Could not mmap file for writing: %s\n", file_name.c_str());
    perror("mmap");
    close(fd);
    return false;
  }

  memcpy(dst, contents.c_str(), len);
  munmap(dst, len);
  close(fd);
  return true;
}

////////////////////////////////////////////////////////////////////////////
bool read_file_contents(
  const string& file_name, string* contents, bool lock) {
  if (!contents) return false;
  int fd = open(file_name.c_str(), O_RDONLY);
  if (fd == -1) {
    log_err("Cound not open file for reading: %s\n", file_name.c_str());
    return false;
  }
  struct stat stat;
  if (-1 == fstat(fd, &stat)) {
    log_err("Could not fstat file: %s\n", file_name.c_str());
    return false;
  }
  u64 len = stat.st_size;

  if (lock && (-1 == flock(fd, LOCK_SH))) {
    log_err("Could not lock file for reading: %s\n", file_name.c_str());
    close(fd);
    return false;
  }
 
  void *src;
  if ((src = mmap(0, len, PROT_READ, MAP_SHARED, fd, 0)) == (caddr_t) -1) {
    log_err("Could not mmap file for reading: %s\n", file_name.c_str());
    close(fd);
    return false;
  }

  contents->append((const char*)src, len);
  munmap(src, len);
  close(fd);
  return true;
}

////////////////////////////////////////////////////////////////////////////
void set_max_open_files(u32 num_of_files) {
  struct rlimit rlp;
  getrlimit(RLIMIT_NOFILE, &rlp);
  rlp.rlim_cur = MAX(rlp.rlim_cur, num_of_files);
  setrlimit(RLIMIT_NOFILE, &rlp);
  getrlimit(RLIMIT_NOFILE, &rlp);
  std::cerr << "current open file limit is " << rlp.rlim_cur << std::endl;
}

////////////////////////////////////////////////////////////////////////////
void LoadLineFromFile(const std::string& file_name, std::unordered_set<string>& lines) {
  try {
    ifstream ifs(file_name);
    std::string line;
    while (getline(ifs, line)) {
      trim(line);
      if (line.empty() || line[0] == '#') continue;
      lines.insert(line);
    }
  } catch (...) {
     log_warning("Could not load domain from file %s\n", file_name.c_str());
  }
}
