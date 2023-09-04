#ifndef MTK_SU_HPP
#define MTK_SU_HPP

#include <inttypes.h>
#include <stdbool.h>

#include <memory>
#include <vector>

#include "mtk.hpp"

typedef struct mtk_su_ctx {
	int cmdq_fd;
	struct cmdqWriteAddressStruct dma_buf;
	cmdqU32Ptr_t pVABase;
	cmdqU32Ptr_t readAddressDMAAddresses;
	cmdqU32Ptr_t readAddressValues;
} mtk_su_ctx_t;

class MTKSu
{
       public:
	bool initialize();
	bool read(uint64_t addr, uint32_t num_bytes, std::unique_ptr<std::vector<uint8_t>>& out);
	bool write(uint64_t addr, std::unique_ptr<std::vector<uint8_t>>& data);
	bool cleanup();
	virtual ~MTKSu() {}

       private:
	mtk_su_ctx_t ctx = {};
	uint32_t max_read_bytes;
	uint32_t max_write_bytes;
	bool init_dma_buf();
	bool cleanup_dma_buf();
	void append_instruction(struct cmdqCommandStruct* command, uint64_t arg_a, uint64_t arg_b);
	bool read_phys_addr(uint64_t addr, uint32_t num_bytes, std::unique_ptr<std::vector<uint8_t>>& out);
	bool write_phys_addr(uint64_t addr, std::unique_ptr<std::vector<uint8_t>>& data);
};

#endif  // MTK_SU_HPP