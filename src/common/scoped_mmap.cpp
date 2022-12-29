#include "scoped_mmap.h"

#include "common.h"
#include "log.h"

ScopedMmap::ScopedMmap() : mapped_address_(NULL), aligned_size_(0) {}

ScopedMmap::~ScopedMmap() {
  if (IsMapped()) Unmap();
}

void* ScopedMmap::Map(int fd, size_t offset, size_t size, size_t alignment, 
                      int mmap_prot, int mmap_flags) {
  if (fd < 0) {
    log_err("fd should be greater or equal than 0\n");
    return NULL;
  }
  
  // allign address.
  size_t aligned_offset = offset - offset % alignment;
  aligned_size_ = size + offset % alignment;
  mapped_address_ = mmap(
      0, aligned_size_, mmap_prot, mmap_flags, fd, aligned_offset);
  if (MAP_FAILED == mapped_address_) {
    log_warning("Failed to map file at %zd length %zd\n", offset, size);
    mapped_address_ = NULL;
    aligned_size_ = 0;
    return NULL;
  }
  return static_cast<u8*>(mapped_address_) + offset % alignment;
}

void ScopedMmap::Unmap() {
  if (!mapped_address_) return;
  if (munmap(mapped_address_, aligned_size_) < 0) {
    log_warning("Failed to unmap address %p size %zd, errno:%d\n",
                mapped_address_, aligned_size_, errno);
  }
  mapped_address_ = NULL;
  aligned_size_ = 0;
}

bool ScopedMmap::IsMapped() const {
  return mapped_address_;
}

