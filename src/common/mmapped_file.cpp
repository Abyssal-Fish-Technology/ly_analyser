#include "mmapped_file.h"

#include "log.h"

static u32 kMinAlignmentSize = 1024*1024; // 1MB

// MmappedFile -------------------------------------------------------
MmappedFile::MmappedFile(int fd, bool read_only)
    : fd_(fd), read_only_(read_only) {}

MmappedFile::~MmappedFile() {
  map_.reset(NULL);
  close(fd_);
}

MmappedFile* MmappedFile::create(const std::string& file_name,
                                 bool read_only,
                                 bool create_if_not_exists,
                                 std::string* error) {
  int flags = (create_if_not_exists ? O_CREAT : 0) |
              (read_only ? O_RDONLY : O_RDWR);
  mode_t mode = 00664;
  int fd = open(file_name.c_str(), flags, mode);
  if (fd < 0) {
    if (error) *error = strerror(errno);
    return NULL;
  }
  
  return new MmappedFile(fd, read_only);
}

u64 MmappedFile::FileSize() {
  u64 size;
  if (FileSize(&size)) return size;
  return 0;
}

bool MmappedFile::FileSize(u64* size) {
  struct stat stat;
  if (-1 == fstat(fd_, &stat)) {
    last_error_ = strerror(errno);
    return false;
  }
  *size = stat.st_size;
  last_error_.clear();
  return true;
}

void* MmappedFile::MapWholeFile() {
  u64 file_size;
  if (!FileSize(&file_size)) {
    log_err("Could not get file size. error:%s\n", last_error_.c_str());
    return NULL;
  }
  return Map(file_size);
}

void* MmappedFile::Map(u64 map_size) {
  map_.reset(new ScopedMmap());
  int prot = read_only_ ? PROT_READ : PROT_WRITE;
  void* address = map_->Map(fd_, 0, map_size, kMinAlignmentSize, prot,
                            MAP_SHARED);
  if (!address) last_error_ = strerror(errno);
  return address;
}

bool MmappedFile::TruncateAt(u64 length) {
  map_.reset(NULL);
  if (ftruncate(fd_, length) < 0) {
    last_error_ = strerror(errno);
    return false;
  }
  return true;
}

void MmappedFile::Flush() {
  fsync(fd_);
}

// ScopedLock ------------------------------------------------------

MmappedFile::ScopedLock::ScopedLock(MmappedFile* file, bool shared)
    : file_(file) {
  if (0 < flock(file_->fd_, shared ? LOCK_SH : LOCK_EX)) {
    log_err("Could not lock file, error:%s\n", strerror(errno));
  }
}

MmappedFile::ScopedLock::~ScopedLock() {
  if (0 < flock(file_->fd_, LOCK_UN)) {
   log_err("Could not unlock file, error:%s\n", strerror(errno));
  } 
}

