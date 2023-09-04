#ifndef DISASM_HPP
#define DISASM_HPP

#include <stdint.h>

enum DataProcInstrOpCodeArm32 : uint32_t {
	AND = 0,
	EOR = 1,
	SUB = 2,
	RSB = 3,
	ADD = 4,
	ADC = 5,
	SBC = 6,
	RSC = 7,
	TST = 8,
	TEQ = 9,
	CMP = 10,
	CMN = 11,
	ORR = 12,
	MOV = 13,
	BIC = 14,
	MVN = 15,
};

class DataProcessingInstructionArm32
{
       public:
	DataProcessingInstructionArm32();
	uint32_t get_cond();
	uint32_t get_immediate_operand();
	uint32_t get_op_code();
	uint32_t get_operand_1();
	uint32_t get_operand_2();
	uint32_t get_dst_reg();
	uint32_t get_immediate_value();
	void set_instruction(uint32_t instruction);

       private:
	uint32_t instruction;
	uint32_t get_set_cond_codes();
	uint32_t get_instruction_field(uint32_t mask, uint32_t shift);
};

#endif  // DISASM_HPP
