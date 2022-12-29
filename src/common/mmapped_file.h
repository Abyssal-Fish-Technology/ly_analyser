#ifndef _COMMON_MMAPPED_FILE_H_
#define _COMMON_MMAPPED_FILE_H_

#include <memory>
#include "common.h"
#include "scoped_mmap.h"

class MmappedFile {
 public:
  ~MmappedFile();

  static MmappedFile* create(const std::string& file_name, bool read_only,
                             bool create_if_not_existed, std::string* error);

  class ScopedLock {
   public:
    ScopedLock(MmappedFile* file, bool shared);
    ~ScopedLock();

   private:
    MmappedFile* file_;
  };
    
  u64 FileSize();
  bool FileSize(u64* size);
  void* MapWholeFile();
  void* Map(u64 map_size);
  // Must remap after truncating.
  bool TruncateAt(u64 length);
  void Flush();

  int fd() const {return fd_;}
  
 private:
  MmappedFile(int fd, bool read_only);

  int fd_;
  bool read_only_;
  std::string last_error_;
  std::unique_ptr<ScopedMmap> map_;
};
#endif // _COMMON_MMAPPED_FILE_H_
