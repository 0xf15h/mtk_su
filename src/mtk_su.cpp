#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "log.hpp"
#include "mtk_su.hpp"

// 32-bit kernels only (arch/arm/include/asm/memory.h)
#define PAGE_OFFSET 0xc0000000ul
#define PHYS_OFFSET 0x40000000ul
#define VIRT_TO_PHYS(virt_addr) (virt_addr - PAGE_OFFSET + PHYS_OFFSET)

/**
 * Initializes a MediaTek cmdq DMA buffer.
 */
bool MTKSu::init_dma_buf()
{
	// g_ctx->dma_buf->count = CMDQ_MAX_WRITE_ADDR_COUNT;
	// Number of available uint32_t to fit in DMA buffer
	ctx.dma_buf.count = 0x400;

	// Request a DMA buffer from the kernel
	int ret = ioctl(ctx.cmdq_fd, CMDQ_IOCTL_ALLOC_WRITE_ADDRESS, &ctx.dma_buf);
	if (ret != 0) {
		log_error("ioctl returned %d: %s", ret, strerror(errno));
		return false;
	}

	// This is the start address of the newly created DMA buffer. This buffer cannot be accessed from user space,
	// but there's an exec command ioctl that'll copy it to userland.
	log_info("startPA %x", ctx.dma_buf.startPA);

	return true;
}

/**
 * Destroys an allocated MediaTek DMA buffer.
 */
bool MTKSu::cleanup_dma_buf()
{
	int ret = ioctl(ctx.cmdq_fd, CMDQ_IOCTL_FREE_WRITE_ADDRESS, &ctx.dma_buf);
	if (ret != 0) {
		log_error("ioctl returned %d", ret);
		return false;
	}

	return true;
}

/**
 * Appends an instruction to a DMA controller command. This is very similar to the cmdq_core_append_command found in:
 *
 * drivers/misc/mediatek/cmdq/v3/cmdq_core.c
 *
 * @param command The command that the new instruction will get added to
 * @param arg_a   The bit vector containing the command code et al.
 * @param arg_b   The value for the instruction
 */
void MTKSu::append_instruction(struct cmdqCommandStruct* command, uint64_t arg_a, uint64_t arg_b)
{
	auto new_instr = (uint64_t*)(command->pVABase + command->blockSize);
	*new_instr = (arg_a << 32ul) | (arg_b & 0xffffffff);

	// Increment the size of the instruction buffer
	command->blockSize += CMDQ_INST_SIZE;
}

bool MTKSu::read_phys_addr(uint64_t phys_addr, uint32_t num_bytes, std::unique_ptr<std::vector<uint8_t>>& out)
{
	int ret = 0;
	struct cmdqCommandStruct command = {0};
	// It's technically CMDQ_MAX_COMMAND_SIZE (or 0x80000000), but we don't need that much.
	const int max_buf_size = 0x3000;

	// Reuse pre-allocated buffers
	command.pVABase = ctx.pVABase;
	command.readAddress.dmaAddresses = ctx.readAddressDMAAddresses;
	command.readAddress.values = ctx.readAddressValues;

	// Wipe pre-allocated buffers before use to remove any lingering instructions
	memset((void*)command.pVABase, 0, CMDQ_INST_SIZE * (max_buf_size + 8));
	memset((void*)command.readAddress.dmaAddresses, 0, max_buf_size);
	memset((void*)command.readAddress.values, 0, max_buf_size);

	// Reset the size of the instruction buffer in bytes
	command.blockSize = 0;

	// Rest the number of entries in the result
	command.readAddress.count = 0;

	// The following read instructions are copied from the cmdq_op_read_mem_to_reg function in:
	//
	// drivers/misc/mediatek/cmdq/v2/cmdq_record.c

	// The "wait for event and clear" command blocks the usage of some registers. In our scenario, we're going to
	// block the usage of CMDQ_DATA_REG_DEBUG and CMDQ_DATA_REQ_DEBUG_DST during the execution of our command. A
	// legit invocation of this command can be seen in:
	//
	// drivers/misc/mediatek/cmdq/v3/cmdq_core.c
	//
	// The next line sets the "wait for event and clear" instruction.
	uint64_t arg_a = CMDQ_CODE_WFE << 24;
	arg_a |= CMDQ_SYNC_TOKEN_GPR_SET_4;

	// The arg_b for CMDQ_CODE_WFE is calculated in cmdq_append_command function in:
	//
	// drivers/misc/mediatek/cmdq/v2/cmdq_record.c
	//
	// The next line sets the to_update value of the SYNC TOKEN to true
	uint64_t arg_b = 1 << 31;
	// Sets the to_wait value of the SYNC TOKEN to true
	arg_b |= 1 << 15;
	// Sets the wait_value to one
	arg_b |= 1;
	// Leaving the update_value as zero

	// Append the "wait for event and clear" instruction
	append_instruction(&command, arg_a, arg_b);

	uint32_t count = 0;
	uint32_t offset = 0;
	uint32_t num_addr = 0x400 / 4;
	while (count < num_addr) {
		// We're using two registers here:
		// 1) CMDQ_DATA_REG_DEBUG which is a 32-bit value register
		// 2) CMDQ_DATA_REG_DEBUG_DST which is a 64-bit address register

		// Move the physical address to read into the CMDQ_DATA_REG_DEBUG_DST address register
		// move phys_addr + offset into CMDQ_DATA_REG_DEBUG_DST
		arg_a = CMDQ_CODE_MOVE << 24 | 1 << 23 | CMDQ_DATA_REG_DEBUG_DST << 16 | (phys_addr + offset) >> 0x20;
		arg_b = phys_addr + offset;
		append_instruction(&command, arg_a, arg_b);

		// Read the data at the physical memory address stored in CMDQ_DATA_REG_DEBUG_DST address register into
		// the CMDQ_DATA_REG_DEBUG value register.
		arg_a = CMDQ_CODE_READ << 24 | 3 << 22 | CMDQ_DATA_REG_DEBUG_DST << 16;
		arg_b = CMDQ_DATA_REG_DEBUG;
		append_instruction(&command, arg_a, arg_b);

		// Move the address to our DMA buffer into the CMDQ_DATA_REG_DEBUG_DST address register.
		arg_a = CMDQ_CODE_MOVE << 24 | 1 << 23 | CMDQ_DATA_REG_DEBUG_DST << 16 | (phys_addr + offset) >> 0x20;
		arg_b = ctx.dma_buf.startPA + offset;
		append_instruction(&command, arg_a, arg_b);

		// Move the read value in CMDQ_DATA_REG_DEBUG value register into the DMA buffer address in
		// CMDQ_DATA_REG_DEBUG_DST address register.
		arg_a = CMDQ_CODE_WRITE << 24 | 3 << 22 | CMDQ_DATA_REG_DEBUG_DST << 16;
		arg_b = CMDQ_DATA_REG_DEBUG;
		append_instruction(&command, arg_a, arg_b);

		// Add the read request to our list of addresses to read from the DMA buffer.
		*(uint32_t*)((uint32_t)command.readAddress.dmaAddresses + offset) =
		    (uint32_t)ctx.dma_buf.startPA + offset;

		count++;
		offset += 4;
	}

	// Set the number of read addresses that we expect.
	command.readAddress.count = offset;

	// Disable the "wait for event and clear" lock on the debug registers
	arg_a = 0 << 15 | 0 /* the disable bit */ | 1 << 31 | 1 << 16;
	arg_b = CMDQ_CODE_WFE << 24 | CMDQ_SYNC_TOKEN_GPR_SET_4;
	append_instruction(&command, arg_a, arg_b);

	// The "end of command" indicates the end of a command list. It has many flags, but we only need the IRQ flag
	// to be set.
	arg_a = CMDQ_CODE_EOC << 24;
	arg_b = 1;
	append_instruction(&command, arg_a, arg_b);

	// The jump command jumps into a command buffer by using an offset. This command is used at the very end of each
	// command buffer after the "end of command" command to jump to the previous command. This is to take in the DMA
	// controller's prefetch mechanism (similar to MIPS).
	arg_a = CMDQ_CODE_JUMP << 24;
	arg_b = 8;
	append_instruction(&command, arg_a, arg_b);

	ret = ioctl(ctx.cmdq_fd, CMDQ_IOCTL_EXEC_COMMAND, &command);
	if (ret != 0) {
		log_error("Command queue execute command ioctl returned %d: errno(%d) %s", ret, errno, strerror(errno));
		return false;
	}

	uint8_t* data = (uint8_t*)command.readAddress.values;
	for (uint32_t itr = 0; itr < num_bytes; itr++) {
		out->push_back(*(data + itr));
	}

	return true;
}

bool MTKSu::write_phys_addr(uint64_t phys_addr, std::unique_ptr<std::vector<uint8_t>>& data)
{
	int ret = 0;
	struct cmdqCommandStruct command = {0};
	// It's technically CMDQ_MAX_COMMAND_SIZE (or 0x80000000), but we don't need that much.
	const int max_buf_size = 0x3000;

	// Reuse pre-allocated buffers
	command.pVABase = ctx.pVABase;

	// Wipe pre-allocated buffers before use to remove any lingering instructions
	memset((void*)command.pVABase, 0, CMDQ_INST_SIZE * (max_buf_size + 8));

	// Reset the size of the instruction buffer in bytes
	command.blockSize = 0;

	// The following read instructions are copied from the cmdq_op_read_mem_to_reg function in:
	//
	// drivers/misc/mediatek/cmdq/v2/cmdq_record.c

	// The "wait for event and clear" command blocks the usage of some registers. In our scenario, we're going to
	// block the usage of CMDQ_DATA_REG_DEBUG and CMDQ_DATA_REQ_DEBUG_DST during the execution of our command. A
	// legit invocation of this command can be seen in:
	//
	// drivers/misc/mediatek/cmdq/v3/cmdq_core.c
	//
	// The next line sets the "wait for event and clear" instruction.
	uint64_t arg_a = CMDQ_CODE_WFE << 24;
	arg_a |= CMDQ_SYNC_TOKEN_GPR_SET_4;

	// The arg_b for CMDQ_CODE_WFE is calculated in cmdq_append_command function in:
	//
	// drivers/misc/mediatek/cmdq/v2/cmdq_record.c
	//
	// The next line sets the to_update value of the SYNC TOKEN to true
	uint64_t arg_b = 1 << 31;
	// Sets the to_wait value of the SYNC TOKEN to true
	arg_b |= 1 << 15;
	// Sets the wait_value to one
	arg_b |= 1;
	// Leaving the update_value as zero

	// Append the "wait for event and clear" instruction
	append_instruction(&command, arg_a, arg_b);

	uint32_t offset = 0;
	while (offset < data->size()) {
		// We're using two registers here:
		// 1) CMDQ_DATA_REG_DEBUG which is a 32-bit value register
		// 2) CMDQ_DATA_REG_DEBUG_DST which is a 64-bit address register

		// Move the value of our write into the debug value register
		uint64_t write_val =
		    (uint64_t) * (uint32_t*)(((uint8_t*)data->data()) + offset);  // value that we want to write
		log_info("writing 0x%x to 0x%llx", (uint32_t)write_val, phys_addr + offset);
		arg_a = CMDQ_CODE_MOVE << 24 | 1 << 23 | CMDQ_DATA_REG_DEBUG << 16 | (phys_addr + offset) >> 0x20;
		arg_b = write_val;
		append_instruction(&command, arg_a, arg_b);

		// Move the physical address to write to into the CMDQ_DATA_REG_DEBUG_DST address register
		// move phys_addr + offset into CMDQ_DATA_REG_DEBUG_DST
		arg_a = CMDQ_CODE_MOVE << 24 | 1 << 23 | CMDQ_DATA_REG_DEBUG_DST << 16 | (phys_addr + offset) >> 0x20;
		arg_b = phys_addr + offset;  // physical address that we want to write to
		append_instruction(&command, arg_a, arg_b);

		// Write the value in CMDQ_DATA_REG_DEBUG into the physical address specified by
		// CMDQ_DATA_REG_DEBUG_DST
		arg_a = CMDQ_CODE_WRITE << 24 | 3 << 22 | CMDQ_DATA_REG_DEBUG_DST << 16;
		arg_b = CMDQ_DATA_REG_DEBUG;
		append_instruction(&command, arg_a, arg_b);

		offset += 4;
	}

	// Disable the "wait for event and clear" lock on the debug registers
	arg_a = 0 << 15 | 0 /* the disable bit */ | 1 << 31 | 1 << 16;
	arg_b = CMDQ_CODE_WFE << 24 | CMDQ_SYNC_TOKEN_GPR_SET_4;
	append_instruction(&command, arg_a, arg_b);

	// The "end of command" indicates the end of a command list. It has many flags, but we only need the IRQ flag
	// to be set.
	arg_a = CMDQ_CODE_EOC << 24;
	arg_b = 1;
	append_instruction(&command, arg_a, arg_b);

	// The jump command jumps into a command buffer by using an offset. This command is used at the very end of each
	// command buffer after the "end of command" command to jump to the previous command. This is to take in the DMA
	// controller's prefetch mechanism (similar to MIPS).
	arg_a = CMDQ_CODE_JUMP << 24;
	arg_b = 8;
	append_instruction(&command, arg_a, arg_b);

	ret = ioctl(ctx.cmdq_fd, CMDQ_IOCTL_EXEC_COMMAND, &command);
	if (ret != 0) {
		log_error("Command queue execute command ioctl returned %d: errno(%d) %s", ret, errno, strerror(errno));
		return false;
	}

	return true;
}

bool MTKSu::initialize()
{
	const int max_buf_size = 0x3000;
	const std::string cmdq_path = "/dev/mtk_cmdq";
	ctx.cmdq_fd = open(cmdq_path.c_str(), O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);
	if (ctx.cmdq_fd == 0) {
		log_error("Failed to open cmdq file");
		return false;
	}

	auto success = init_dma_buf();
	if (!success) {
		log_error("Failed to initialize the DMA buffer");
		return false;
	}

	// This is the instruction buffer that will be sent to the DMA controller. It must be 64-bit aligned.
	//
	// The pVABase field is the userland instruction buffer. It's copied into the command queue in the
	// cmdq_pkt_copy_cmd as the src parameter. The mailbox then parses the commands and executes the instructions.
	//
	// The following stacktrace shows where the value is copied:
	//
	// ```
	// cmdq_pkt_copy_cmd
	// cmdq_mdp_copy_cmd_to_task
	// cmdq_mdp_flush_async
	// cmdq_mdp_flush
	// cmdq_driver_process_command_request
	// cmdq_driver_ioctl_exec_command
	// cmdq_ioctl
	// ```
	ctx.pVABase = (cmdqU32Ptr_t)calloc(1, CMDQ_INST_SIZE * (max_buf_size + 8));
	if (ctx.pVABase == 0ul) {
		log_error("Failed to allocate command queue user land instruction buffer");
		return false;
	}

	// This is the array of physical addresses to read. These values must be allocated by the
	// CMDQ_IOCTL_ALLOC_WRITE_ADDRESS ioctl command.
	ctx.readAddressDMAAddresses = (uint64_t)calloc(1, max_buf_size);
	if (ctx.readAddressDMAAddresses == 0ul) {
		log_error("Failed to allocate command queue's read address DMA address buffer");
		return false;
	}

	// This is the user space buffer that will contain the results of the DMA controller's reads. Note that the DMA
	// controller does not directly write to this buffer, the kernel copies it over.
	ctx.readAddressValues = (uint64_t)calloc(1, max_buf_size);
	if (ctx.readAddressValues == 0ul) {
		log_error("Failed to allocate command queue's read address values buffer");
		return false;
	}

	max_read_bytes = 0x400;
	max_write_bytes = 0x400;

	return true;
}

bool MTKSu::read(uint64_t virt_addr, uint32_t num_bytes, std::unique_ptr<std::vector<uint8_t>>& out)
{
	// Determine the number of reads required to service the request
	uint32_t num_reads = num_bytes / max_read_bytes;

	// Handle the remaining bytes for read requests that are not aligned with max_read_bytes
	uint32_t read_remainder = num_bytes % max_read_bytes;
	if (read_remainder > 0) {
		num_reads++;
	}

	for (uint32_t read_itr = 0; read_itr < num_reads; read_itr++) {
		uint32_t read_len = max_read_bytes;

		// The last read of a read request that's not max_read_bytes aligned is shorter
		bool last_read = read_itr + 1 == num_reads;
		if (last_read && read_remainder > 0) {
			read_len = read_remainder;
		}

		uint64_t phys_addr = VIRT_TO_PHYS(virt_addr + read_itr * max_read_bytes);
		auto success = read_phys_addr(phys_addr, read_len, out);
		if (!success) {
			log_error("Read failed on address 0x%" PRIx64 " offset 0x%lx", virt_addr,
			          read_itr * max_read_bytes);
			return false;
		}
	}

	return true;
}

bool MTKSu::write(uint64_t virt_addr, std::unique_ptr<std::vector<uint8_t>>& data)
{
	uint64_t phys_addr = VIRT_TO_PHYS(virt_addr);

	// Since the vector holds uint8_t, the size is equivalent to the number of bytes to write
	uint32_t num_bytes = data->size();

	// Determine the number of writes required to service the request
	uint32_t num_writes = num_bytes / max_write_bytes;

	// Handle the remaining bytes for write requests that are not aligned with max_write_bytes
	uint32_t write_remainder = num_bytes % max_write_bytes;
	if (write_remainder > 0) {
		num_writes++;
	}

	for (uint32_t write_itr = 0; write_itr < num_writes; write_itr++) {
		uint32_t write_offset = write_itr * max_write_bytes;
		uint32_t write_len = max_write_bytes;

		// The last write of a write request that's not max_write_bytes aligned is shorter
		bool last_write = write_itr + 1 == num_writes;
		if (last_write && write_remainder > 0) {
			write_len = write_remainder;
		}

		auto single_write = std::make_unique<std::vector<uint8_t>>(
		    &data.get()->begin()[write_offset], &data.get()->begin()[write_offset + write_len]);
		uint32_t attempt = 0;
		const uint32_t max_attempts = 5;
		for (attempt = 0; attempt < max_attempts; attempt++) {
			auto success = write_phys_addr(phys_addr, data);
			if (success) {
				break;
			}
			log_error("Failed to write physical address. Retrying...");
			sleep(1);
		}
		if (attempt == max_attempts) {
			log_error("Write failed on address 0x%" PRIx64 " offset 0x%lx", virt_addr, write_offset);
			return false;
		}
	}

	return true;
}

bool MTKSu::cleanup()
{
	cleanup_dma_buf();
	free((void*)ctx.pVABase);
	free((void*)ctx.readAddressDMAAddresses);
	free((void*)ctx.readAddressValues);
	close(ctx.cmdq_fd);

	return true;
}
