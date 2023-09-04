#include "utils.hpp"

bool get_kern_ulong(std::vector<uint8_t>& data, uint32_t offset, uint64_t& out)
{
	uint32_t kern_ptr = 0;
	auto success = get_value<uint32_t>(data, offset, kern_ptr);
	out = (uint64_t)kern_ptr;
	return success;
}

bool get_kern_ptr(std::vector<uint8_t>& data, uint32_t offset, uint64_t& out)
{
	return get_kern_ulong(data, offset, out);
}

uint32_t get_kern_ptr_size()
{
	return 4;
}

bool is_vmalloc_address(uint64_t addr)
{
	const uint64_t kernel_start_va_addr_32 = 0xc0000000ul;
	const uint64_t vmalloc_end_va_addr_32 = 0xff800000ul;
	return kernel_start_va_addr_32 <= addr && addr <= vmalloc_end_va_addr_32;
}

bool is_kernel_address(uint64_t addr)
{
	// The PAGE_OFFSET value from arch/arm/Kconfig determines the kernel start VA
	const uint64_t kernel_start_va_addr_32 = 0xc0000000ul;
	const uint64_t kernel_end_va_addr_32 = 0xd0000000ul;
	return kernel_start_va_addr_32 <= addr && addr <= kernel_end_va_addr_32;
}
