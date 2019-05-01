#ifndef BUFFER_H
#define BUFFER_H

#include "config.h"
#ifdef HAVE_INTTYPES_H
#include <cinttypes>
#else
#include <cstdint>
#endif

#include <cstddef>
#include <vector>

struct Buffer {
		Buffer(const uint8_t *data, size_t datalen);
		Buffer(uint8_t *begin, uint8_t *end);
		explicit Buffer(size_t datalen);
		Buffer();

		size_t size() const { return static_cast<size_t>(tail - head); }
		size_t left() const { return static_cast<size_t>(buf.data() + buf.size() - tail); }
		uint8_t *wpos() { return tail; }
		const uint8_t *rpos() const { return head; }
		void seek(size_t len) { head += len; }
		void push(size_t len) { tail += len; }
		void reset() { head = tail = begin; }
		size_t bufsize() const { return static_cast<size_t>(tail - begin); }

		std::vector<uint8_t> buf;
		// begin points to the beginning of the buffer.  This might point to
		// buf.data() if a buffer space is allocated by this object.  It is
		// also allowed to point to the external shared buffer.
		uint8_t *begin;
		// head points to the position of the buffer where read should
		// occur.
		uint8_t *head;
		// tail points to the position of the buffer where write should
		// occur.
		uint8_t *tail;
};

#endif
