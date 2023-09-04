#ifndef UTILS_HPP
#define UTILS_HPP

#include <cstdbool>
#include <cstdint>
#include <vector>

#include "log.hpp"

/**
 * Gets a value of type T from data at a given byte offset. This must be implemented in the header.
 *
 * @data: Data containing the value.
 * @offset: Offset into the data where value T starts.
 * @out: Stores the output value.
 * @return: true on success, otherwise false
 */
template <class T>
bool get_value(std::vector<uint8_t>& data, uint32_t offset, T& out)
{
	if (data.size() <= offset) {
		log_error("Attempted to get value from vector at offset 0x%x from a vector of size 0x%x", offset,
		          data.size());
		return false;
	}

	out = *(T*)&data.data()[offset];

	return true;
}

/**
 * Gets a long value, based on the kernel bitness, from data at a given byte offset.
 *
 * @data: Data containing the value.
 * @offset: Offset into the data where value T starts.
 * @out: Stores the output value.
 * @return: true on success, otherwise false
 */
bool get_kern_ulong(std::vector<uint8_t>& data, uint32_t offset, uint64_t& out);

/**
 * Gets a kernel pointer sized value from data at a given byte offset.
 *
 * @data: Data containing the value.
 * @offset: Offset into the data where value T starts.
 * @out: Stores the output value.
 * @return: true on success, otherwise false
 */
bool get_kern_ptr(std::vector<uint8_t>& data, uint32_t offset, uint64_t& out);

uint32_t get_kern_ptr_size();

bool is_vmalloc_address(uint64_t addr);

bool is_kernel_address(uint64_t addr);

#endif  // UTILS_HPP
