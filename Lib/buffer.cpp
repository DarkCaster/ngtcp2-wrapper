#include "buffer.h"

Buffer::Buffer(const uint8_t *data, size_t datalen)
  : buf{data, data + datalen},
    begin(buf.data()),
    head(begin),
    tail(begin + datalen)
{}

Buffer::Buffer(uint8_t *begin, uint8_t *end)
  : begin(begin), head(begin), tail(end)
{}

Buffer::Buffer(size_t datalen)
  : buf(datalen), begin(buf.data()), head(begin), tail(begin)
{}

Buffer::Buffer() : begin(buf.data()), head(begin), tail(begin)
{}
