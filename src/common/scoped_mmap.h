#ifndef _COMMON_SCOPED_MMAP_H_
#define _COMMON_SCOPED_MMAP_H_

#include <stddef.h>

class ScopedMmap {
 public:
  ScopedMmap();
  ~ScopedMmap();
  void* Map(int fd, size_t offset, size_t size, size_t alignment,
            int mmap_prot, int mmap_flags);
  void Unmap();
  bool IsMapped() const;

 private:
  ScopedMmap(const ScopedMmap&) = delete;
  void operator=(const ScopedMmap&) = delete;

  void* mapped_address_;
  size_t aligned_size_;
};

#endif // _COMMON_SCOPED_MMAP_H_

