#ifndef MTK_HPP
#define MTK_HPP

#include <inttypes.h>

#define cmdqU32Ptr_t unsigned long long
#define CMDQ_MAX_SRAM_OWNER_NAME 32
#define CMDQ_MAX_PROFILE_MARKER_IN_TASK 5
#define CMDQ_INST_SIZE 8

typedef int32_t s32;
typedef uint32_t u32;
typedef uint64_t u64;

struct cmdqReadRegStruct {
	u32 count;
	cmdqU32Ptr_t regAddresses;
};

struct cmdqRegValueStruct {
	u32 count;
	cmdqU32Ptr_t regValues;
};

struct cmdqReadAddressStruct {
	u32 count;
	cmdqU32Ptr_t dmaAddresses;
	cmdqU32Ptr_t values;
};

struct cmdqSecDataStruct {
	bool is_secure;
	u32 addrMetadataCount;
	cmdqU32Ptr_t addrMetadatas;
	u32 addrMetadataMaxCount;
	u64 enginesNeedDAPC;
	u64 enginesNeedPortSecurity;
	s32 waitCookie;
	bool resetExecCnt;
};

struct cmdq_v3_replace_struct {
	u32 number;
	cmdqU32Ptr_t position;
};

struct cmdqProfileMarkerStruct {
	u32 count;
	long long hSlot;
	cmdqU32Ptr_t tag[CMDQ_MAX_PROFILE_MARKER_IN_TASK];
};

struct cmdqCommandStruct {
	u32 scenario;
	u32 priority;
	u64 engineFlag;
	cmdqU32Ptr_t pVABase;
	u32 blockSize;
	struct cmdqReadRegStruct regRequest;
	struct cmdqRegValueStruct regValue;
	struct cmdqReadAddressStruct readAddress;
	struct cmdqSecDataStruct secData;
	struct cmdq_v3_replace_struct replace_instr;
	bool use_sram_buffer;
	char sram_owner_name[CMDQ_MAX_SRAM_OWNER_NAME];
	u32 debugRegDump;
	cmdqU32Ptr_t privateData;
	u32 prop_size;
	cmdqU32Ptr_t prop_addr;
	struct cmdqProfileMarkerStruct profileMarker;
	cmdqU32Ptr_t userDebugStr;
	u32 userDebugStrLen;
};

enum CMDQ_CODE_ENUM {
	CMDQ_CODE_READ = 0x01,
	CMDQ_CODE_MOVE = 0x02,
	CMDQ_CODE_WRITE = 0x04,
	CMDQ_CODE_JUMP = 0x10,
	CMDQ_CODE_WFE = 0x20,
	CMDQ_CODE_EOC = 0x40,
};

struct cmdqWriteAddressStruct {
	u32 count;
	u32 startPA;
};

enum cmdq_gpr_reg {
	CMDQ_DATA_REG_DEBUG = 0x0b,
	CMDQ_DATA_REG_DEBUG_DST = 0x17,
};

enum CMDQ_EVENT_ENUM {
	CMDQ_SYNC_TOKEN_GPR_SET_4 = 474,
};

#define CMDQ_IOCTL_MAGIC_NUMBER 'x'
#define CMDQ_IOCTL_EXEC_COMMAND _IOW(CMDQ_IOCTL_MAGIC_NUMBER, 3, struct cmdqCommandStruct)
#define CMDQ_IOCTL_ALLOC_WRITE_ADDRESS _IOW(CMDQ_IOCTL_MAGIC_NUMBER, 7, struct cmdqWriteAddressStruct)
#define CMDQ_IOCTL_FREE_WRITE_ADDRESS _IOW(CMDQ_IOCTL_MAGIC_NUMBER, 8, struct cmdqWriteAddressStruct)

#endif  // MTK_HPP