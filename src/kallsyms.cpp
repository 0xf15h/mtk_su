#include <inttypes.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <map>
#include <memory>

#include "kallsyms.hpp"
#include "log.hpp"
#include "utils.hpp"

#define STR_CMP_EQ 0

/**
 * Gets the kernel symbol table alignment based on kernel bitness.
 */
static uint32_t _get_table_alignment()
{
	// 0x100 for 64-bit kernel
	return 0x10;
}

/**
 * Calculates the address of the next table given the end address of the previous table.
 *
 * @param end_of_table_addr: The address of the last entry of the previous table
 * @param start_of_next_table_addr: The calculated address of the first entry in the next table
 *
 */
static void _get_start_addr_of_next_table(uint64_t end_of_table_addr, uint64_t& start_addr_of_next_table)
{
	log_info("Previous kernel symbol table end 0x%" PRIx64, end_of_table_addr);
	auto align = _get_table_alignment();
	auto align_mask = ~(align - 1);
	if (end_of_table_addr & (align - 1)) {
		start_addr_of_next_table = (end_of_table_addr + align) & align_mask;
	} else {
		start_addr_of_next_table = end_of_table_addr;
	}
	log_info("Start of next kernel symbol table 0x%" PRIx64, start_addr_of_next_table);
}

static bool _find_kernel_start_addr(MTKSu& kern_rw, uint64_t& start_addr_out)
{
	// 32-bit kernels only
	const uint64_t scan_start = 0xc0828000ul;
	const uint64_t scan_stop = 0xc2008000ul;
	const uint64_t scan_step = 0x20000;

	// Search through kernel memory in search of three contiguous kernel pointers
	const uint32_t num_kern_ptrs = 3;
	const uint32_t kern_ptr_size = get_kern_ptr_size();
	const uint32_t read_size = num_kern_ptrs * kern_ptr_size;
	auto read_buf = std::make_unique<std::vector<uint8_t>>();

	for (uint64_t addr_itr = scan_start; addr_itr < scan_stop; addr_itr += scan_step) {
		read_buf->clear();
		auto success = kern_rw.read(addr_itr, read_size, read_buf);
		if (!success) {
			log_error("Failed to read 0x%x bytes at address 0x%" PRIx64, read_size, addr_itr);
			return false;
		}

		uint64_t maybe_kern_ptr = 0;
		success = get_kern_ptr(*read_buf.get(), 0, maybe_kern_ptr);
		if (!success) {
			return false;
		}
		if (!is_kernel_address(maybe_kern_ptr)) {
			continue;
		}

		success = get_kern_ptr(*read_buf.get(), 1 * kern_ptr_size, maybe_kern_ptr);
		if (!success) {
			return false;
		}
		if (!is_kernel_address(maybe_kern_ptr)) {
			continue;
		}

		success = get_kern_ptr(*read_buf.get(), 2 * kern_ptr_size, maybe_kern_ptr);
		if (!success) {
			return false;
		}
		if (!is_kernel_address(maybe_kern_ptr)) {
			continue;
		}

		log_info("Found three kernel pointers at 0x%" PRIx64, addr_itr);

		// Now that we're finding kernel addresses, go back a step and start scanning for the beginning
		start_addr_out = addr_itr - scan_step;

		// Stop when the first set of kernel pointers are found
		break;
	}

	if (start_addr_out == 0ull) {
		log_error("Could not find the kernel start address");
		return false;
	}

	log_info("Kernel starts at 0x%" PRIx64, start_addr_out);

	return true;
}

static bool _find_addresses_table_start(MTKSu& kern_rw, uint64_t kern_start_addr, uint64_t& addr_table_start_out)
{
	log_info("Starting kernel symbol address table scan at 0x%" PRIx64, kern_start_addr);

	// The number of contiguous kernel pointers needed to determine if memory is the start of the address table
	const int ptr_threshold = 3;
	uint32_t kern_ptr_size = get_kern_ptr_size();
	auto read_buf_size = ptr_threshold * kern_ptr_size;
	auto read_buf = std::make_unique<std::vector<uint8_t>>();

	// The max offset within a given kernel start address that the kernel addresses table will start
	const uint64_t max_offset = 0x20000;
	for (uint64_t offset_itr = 0; offset_itr < max_offset; offset_itr += kern_ptr_size) {
		read_buf->clear();
		auto success = kern_rw.read(kern_start_addr + offset_itr, read_buf_size, read_buf);
		if (!success) {
			log_error("Failed to read possible kernel address table memory");
			return false;
		}

		// Iterate through the read buffer to determine if it contains entries that match the start of an
		// address table
		bool found_possible_start = false;
		uint64_t last_kern_ptr = std::numeric_limits<uint64_t>::max();
		for (uint32_t kern_ptr_itr = 0; kern_ptr_itr < ptr_threshold; kern_ptr_itr += 1) {
			uint64_t addr_table_candidate = 0;
			success = get_kern_ptr(*read_buf.get(), kern_ptr_itr * kern_ptr_size, addr_table_candidate);
			if (!success) {
				log_error("Failed to get kernel pointer from read buffer");
				return false;
			}

			if (!is_kernel_address(addr_table_candidate)) {
				break;
			}

			if (kern_ptr_itr == 0) {
				if (!(addr_table_candidate == 0xc0100000ul || addr_table_candidate == 0xc0008180ul ||
				      addr_table_candidate == 0xc0200000ul)) {
					break;
				}

				// Skip the max difference check because it's the first entry
				last_kern_ptr = addr_table_candidate;
				continue;
			}

			// The kernel pointers in the address table should be increasing i.e. pointing to high addresses
			if (last_kern_ptr > addr_table_candidate) {
				break;
			}

			// The address table entries should not be too far apart
			const uint64_t max_diff = 0x1000;
			if (addr_table_candidate - last_kern_ptr > max_diff) {
				break;
			}

			last_kern_ptr = addr_table_candidate;

			// Reached the max threshold. This must be the start of the address table!
			if (kern_ptr_itr + 1 == ptr_threshold) {
				addr_table_start_out = kern_start_addr + offset_itr;
				log_info("Found address table start address 0x%" PRIx64, addr_table_start_out);
				return true;
			}
		}
	}

	return false;
}

static bool _build_address_table(MTKSu& kern_rw,
                                 uint64_t kern_start_addr,
                                 std::vector<uint64_t>& table,
                                 uint64_t& addr_table_end_addr)
{
	uint64_t addr_table_start = 0;
	auto success = _find_addresses_table_start(kern_rw, kern_start_addr, addr_table_start);
	if (!success) {
		log_error("Could not find the address table start address");
		return false;
	}

	// This may need to be adjusted in the future
	const uint64_t addr_table_max_size = 0x10000 * get_kern_ptr_size();
	auto addr_table_bytes = std::make_unique<std::vector<uint8_t>>();
	success = kern_rw.read(addr_table_start, addr_table_max_size, addr_table_bytes);
	if (!success) {
		log_error("Failed to read kernel memory");
		return false;
	}

	auto kern_ptr_size = get_kern_ptr_size();
	uint32_t itr = 0;
	for (auto end_of_addr_table = false; !end_of_addr_table; itr += kern_ptr_size) {
		uint64_t addr_table_entry = 0;
		success = get_kern_ptr(*addr_table_bytes.get(), itr, addr_table_entry);
		if (!success) {
			log_error("Could not get kernel pointer from address table bytes");
			return false;
		}
		if (!is_kernel_address(addr_table_entry)) {
			end_of_addr_table = true;
			continue;
		}
		table.push_back(addr_table_entry);
	}

	addr_table_end_addr = addr_table_start + table.size() * kern_ptr_size;

	log_info("Found %d entries in the address table", table.size());

	return true;
}

static bool _build_symbol_names_table(MTKSu& kern_rw,
                                      uint64_t name_table_start_addr,
                                      uint64_t num_symbols,
                                      std::vector<std::vector<uint8_t>>& table_out,
                                      uint64_t& name_table_end_addr)
{
	// This may need to be adjusted in the future
	auto name_table_max_size = 0x100000;
	auto name_table_bytes = std::make_unique<std::vector<uint8_t>>();
	auto success = kern_rw.read(name_table_start_addr, name_table_max_size, name_table_bytes);
	if (!success) {
		log_error("Could not read the name table");
		return false;
	}

	auto num_names_found = 0ul;
	auto name_table_idx = 0ul;
	while (true) {
		auto name_len = name_table_bytes->at(name_table_idx++);
		if (name_len == 0) {
			break;
		}

		std::vector<uint8_t> name_entry{};
		for (auto name_itr = 0; name_itr < name_len; name_itr++) {
			name_entry.push_back(name_table_bytes->at(name_table_idx++));
		}
		table_out.push_back(name_entry);

		num_names_found++;
	}

	if (table_out.size() != num_symbols) {
		log_error("Expected %d names but found %d", num_symbols, table_out.size());
		return false;
	}

	name_table_end_addr = name_table_start_addr + name_table_idx;

	return true;
}

/**
 * This is a really bad implementation that looks for the null bytes at the end of the section. If the markers table
 * is already aligned, we'll never find the end of the table.
 */
static bool _skip_markers_table(MTKSu& kern_rw, uint64_t markers_table_start_addr, uint64_t& markers_table_end_addr)
{
	// This may need to be adjusted in the future
	auto markers_table_max_size = 0x400;
	auto markers_table_bytes = std::make_unique<std::vector<uint8_t>>();
	auto success = kern_rw.read(markers_table_start_addr, markers_table_max_size, markers_table_bytes);
	if (!success) {
		log_error("Could not read the markers table");
		return false;
	}

	// Skip the first entry in the markers table because it's zero
	auto kern_ptr_size = get_kern_ptr_size();
	for (uint32_t table_idx = kern_ptr_size; table_idx < markers_table_max_size; table_idx += kern_ptr_size) {
		auto entry = 0ull;
		success = get_kern_ulong(*markers_table_bytes.get(), table_idx, entry);
		if (!success) {
			log_error("Could not get ulong value from markers table");
			return false;
		}

		if (entry == 0ull) {
			markers_table_end_addr = markers_table_start_addr + table_idx;
			break;
		}
	}

	log_info("Markers table start 0x%" PRIx64 " end 0x%" PRIx64, markers_table_start_addr, markers_table_end_addr);

	return true;
}

static bool _build_token_table(MTKSu& kern_rw,
                               uint64_t token_table_start_addr,
                               std::vector<std::string>& table,
                               uint64_t& token_table_end_addr)
{
	// This may need to be adjusted in the future
	auto token_table_max_size = 0x400ull;
	auto token_table_bytes = std::make_unique<std::vector<uint8_t>>();
	auto success = kern_rw.read(token_table_start_addr, token_table_max_size, token_table_bytes);
	if (!success) {
		log_error("Could not read token table");
		return false;
	}

	uint8_t last_value = 0;
	std::string entry{};
	token_table_end_addr = token_table_start_addr;
	for (auto value : *token_table_bytes.get()) {
		if (value == 0) {
			if (last_value == 0) {
				// End of token table
				break;
			}
			table.push_back(entry);
			entry.clear();
			last_value = value;
			token_table_end_addr++;
			continue;
		}

		entry.push_back(value);
		last_value = value;
		token_table_end_addr++;
	}

	return true;
}

static bool _build_token_index_table(MTKSu& kern_rw,
                                     uint64_t token_index_table_start_addr,
                                     std::vector<uint16_t>& table)
{
	auto token_index_table_max_size = 0x800ull;
	auto token_index_table_bytes = std::make_unique<std::vector<uint8_t>>();
	auto success = kern_rw.read(token_index_table_start_addr, token_index_table_max_size, token_index_table_bytes);
	if (!success) {
		log_error("Could not read the token index table");
		return false;
	}

	// The max step from one token index table entry to the next
	const uint16_t max_step = 0x1000;
	uint16_t prev_value = 0;
	for (uint32_t table_idx = 0; table_idx < token_index_table_bytes->size(); table_idx += sizeof(uint16_t)) {
		uint16_t token_index = 0;
		success = get_value<uint16_t>(*token_index_table_bytes.get(), table_idx, token_index);
		if (!success) {
			log_error("Could not get value from token index table bytes");
			return false;
		}
		if (token_index - prev_value > max_step) {
			log_info("Found the end of the token index table at %" PRIx64,
			         token_index_table_start_addr + table_idx - sizeof(uint16_t));
			return true;
		}
		prev_value = token_index;
		table.push_back(token_index);
	}

	return true;
}

static bool _get_string_from_token_table(std::vector<std::string>& token_table,
                                         uint16_t token_index,
                                         std::string& token_out)
{
	uint32_t token_table_itr = 0;
	for (auto token : token_table) {
		if (token_table_itr + token.length() >= token_index) {
			// Found the token we're interested in
			uint16_t index_into_token = token_index - token_table_itr;
			token_out = token.substr(index_into_token);
			return true;
		}
		token_table_itr += token.length() + 1;
	}

	return false;
}

static bool _build_symbol_strings(std::vector<std::string>& symbol_strings,
                                  std::vector<std::vector<uint8_t>>& names_table,
                                  std::vector<uint16_t>& token_index_table,
                                  std::vector<std::string>& token_table)
{
	for (auto name : names_table) {
		std::string symbol_str{};
		for (auto name_idx : name) {
			uint16_t token_index = token_index_table.at(name_idx);
			std::string token_str{};
			auto success = _get_string_from_token_table(token_table, token_index, token_str);
			if (!success) {
				log_error("Could not find string in token table");
				return false;
			}

			symbol_str.append(token_str);
		}
		symbol_strings.push_back(symbol_str);
	}

	return true;
}

static bool _get_number_of_symbols(MTKSu& kern_rw,
                                   uint64_t num_symbols_start_addr,
                                   uint64_t& num_symbols_out,
                                   uint64_t& num_symbols_end_addr)
{
	auto num_symbols_bytes = std::make_unique<std::vector<uint8_t>>();
	auto num_symbols_size = 4;  // It's an unsigned long
	auto success = kern_rw.read(num_symbols_start_addr, num_symbols_size, num_symbols_bytes);
	if (!success) {
		log_error("Could not read the number of symbols");
		return false;
	}
	num_symbols_end_addr = num_symbols_start_addr + num_symbols_size;

	uint32_t num_symbols = 0;
	success = get_value<uint32_t>(*num_symbols_bytes.get(), 0, num_symbols);
	if (!success) {
		log_info("Could not get number of symbols from bytes");
		return false;
	}
	num_symbols_out = (uint64_t)num_symbols;

	log_info("Number of symbols %" PRIu64, num_symbols_out);

	return true;
}

bool _build_all_symbol_strings(MTKSu& kern_rw,
                               uint64_t name_table_start_addr,
                               uint32_t num_symbols,
                               std::vector<std::string>& symbol_list_out)
{
	auto names_table = std::make_unique<std::vector<std::vector<uint8_t>>>();
	auto name_table_end_addr = 0ull;
	auto success = _build_symbol_names_table(kern_rw, name_table_start_addr, num_symbols, *names_table.get(),
	                                         name_table_end_addr);
	if (!success) {
		log_error("Could not build the names table");
		return false;
	}

	// Get the start address of the markers table
	auto markers_table_start_addr = 0ull;
	_get_start_addr_of_next_table(name_table_end_addr, markers_table_start_addr);

	auto markers_table_end_addr = 0ull;
	success = _skip_markers_table(kern_rw, markers_table_start_addr, markers_table_end_addr);
	if (!success) {
		log_error("Could not skip the markers table");
		return false;
	}

	// Get the start address of the token table
	auto token_table_start_addr = 0ull;
	_get_start_addr_of_next_table(markers_table_end_addr, token_table_start_addr);

	auto token_table = std::make_unique<std::vector<std::string>>();
	auto token_table_end_addr = 0ull;
	success = _build_token_table(kern_rw, token_table_start_addr, *token_table.get(), token_table_end_addr);
	if (!success) {
		log_error("Could not build the tokens table");
		return false;
	}

	// Get the start address of the token index table
	auto token_index_table_start_addr = 0ull;
	_get_start_addr_of_next_table(token_table_end_addr, token_index_table_start_addr);

	auto token_index_table = std::make_unique<std::vector<uint16_t>>();
	success = _build_token_index_table(kern_rw, token_index_table_start_addr, *token_index_table.get());
	if (!success) {
		log_error("Could not build the tokens index table");
		return false;
	}

	success =
	    _build_symbol_strings(symbol_list_out, *names_table.get(), *token_index_table.get(), *token_table.get());
	if (!success) {
		log_error("Could not build the kernel symbol table from the names, token index, and token tables");
		return false;
	}

	return true;
}

/**
 * The kallsyms table should be in the following order:
 *
 * - addresses table
 * - number of symbols
 * - symbol names
 * - symbol markers
 * - token table
 * - token index table
 *
 * The algorithm is:
 * - jump through large chunks of memory looking for kernel pointers in the kernel symbol addresses table
 * - once we find some, we're probably in the middle of the table so go back one jump
 * - precisely scan through the jump to find the start of the kernel symbol addresses table
 * - once we have the addresses table, scan until you find null bytes from the number of symbols padding
 * - now that we have the number of symbols, read the number of symbols from the symbol names table
 * - verify that we found the correct number of symbols
 */
bool build_kernel_symbol_table(MTKSu& kern_rw, std::map<std::string, uint64_t>& symbol_table_out)
{
	// Find the start of the kernel by scanning for kernel pointers
	auto kernel_start_addr = 0ull;
	auto success = _find_kernel_start_addr(kern_rw, kernel_start_addr);
	if (!success) {
		log_error("Could not find the kernel start address");
		return false;
	}

	// Find a build the kernel address table
	auto addr_table = std::make_unique<std::vector<uint64_t>>();
	auto addr_table_end_addr = 0ull;
	success = _build_address_table(kern_rw, kernel_start_addr, *addr_table.get(), addr_table_end_addr);
	if (!success) {
		log_error("Could not build the kernel addresses table");
		return false;
	}

	// Get the start address of the number of symbols section
	auto num_symbols_start_addr = 0ull;
	_get_start_addr_of_next_table(addr_table_end_addr, num_symbols_start_addr);

	// Get the number of symbols and verify that it matches the number of addresses in the address table
	auto num_symbols = 0ull;
	auto num_symbols_end_addr = 0ull;
	success = _get_number_of_symbols(kern_rw, num_symbols_start_addr, num_symbols, num_symbols_end_addr);
	if (!success) {
		log_error("Could not get the number of symbols");
		return false;
	}
	if (addr_table->size() != num_symbols) {
		log_error("Expected %" PRIu64 " symbols but found %" PRIu64 " in the address table", num_symbols,
		          addr_table->size());
		return false;
	}

	// Get the start address of the name table
	auto name_table_start_addr = 0ull;
	_get_start_addr_of_next_table(num_symbols_end_addr, name_table_start_addr);

	// Build a list of kernel symbol strings
	auto symbol_strings = std::make_unique<std::vector<std::string>>();
	success = _build_all_symbol_strings(kern_rw, name_table_start_addr, num_symbols, *symbol_strings.get());
	if (!success) {
		log_error("Could not build the kernel name table");
		return false;
	}

	for (auto symbol_itr = 0; symbol_itr < num_symbols; symbol_itr++) {
		auto new_entry =
		    std::pair<std::string, uint64_t>{symbol_strings->at(symbol_itr), addr_table->at(symbol_itr)};
		symbol_table_out.insert(new_entry);
	}

	return true;
}
