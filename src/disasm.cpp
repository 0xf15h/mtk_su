#include "disasm.hpp"

uint64_t rotate_right(uint64_t input, uint32_t num_bits, bool is_32_bit)
{
	uint64_t total_bits = 0;
	if (is_32_bit) {
		total_bits = 32;
	} else {
		total_bits = 64;
	}
	uint32_t left_shift = total_bits - num_bits;
	uint32_t input_left = input << left_shift;
	uint32_t input_right = input >> num_bits;
	return input_left | input_right;
}

DataProcessingInstructionArm32::DataProcessingInstructionArm32() {}

void DataProcessingInstructionArm32::set_instruction(uint32_t instruction)
{
	this->instruction = instruction;
}

uint32_t DataProcessingInstructionArm32::get_instruction_field(uint32_t mask, uint32_t shift)
{
	return (instruction & (mask << shift)) >> shift;
}

uint32_t DataProcessingInstructionArm32::get_cond()
{
	const uint32_t mask = 0b1111;
	const uint32_t shift = 28;
	return get_instruction_field(mask, shift);
}

uint32_t DataProcessingInstructionArm32::get_immediate_operand()
{
	const uint32_t mask = 0b1;
	const uint32_t shift = 25;
	return get_instruction_field(mask, shift);
}

uint32_t DataProcessingInstructionArm32::get_op_code()
{
	const uint32_t mask = 0b1111;
	const uint32_t shift = 21;
	return get_instruction_field(mask, shift);
}

uint32_t DataProcessingInstructionArm32::get_operand_1()
{
	const uint32_t mask = 0b1111;
	const uint32_t shift = 16;
	return get_instruction_field(mask, shift);
}

uint32_t DataProcessingInstructionArm32::get_operand_2()
{
	const uint32_t mask = 0b111111111111;
	const uint32_t shift = 0;
	return get_instruction_field(mask, shift);
}

uint32_t DataProcessingInstructionArm32::get_dst_reg()
{
	const uint32_t mask = 0b1111;
	const uint32_t shift = 12;
	return get_instruction_field(mask, shift);
}

uint32_t DataProcessingInstructionArm32::get_immediate_value()
{
	const uint32_t operand_2_immediate = 1;
	if (get_immediate_operand() != operand_2_immediate) {
		// Operand 2 is register based
		return 0;
	}

	uint32_t operand_2 = get_operand_2();

	// Relative to operand 2
	const uint32_t rotate_mask = 0b1111;
	const uint32_t rotate_shift = 8;
	uint32_t num_bits_to_rotate = (operand_2 & (rotate_mask << rotate_shift)) >> rotate_shift;

	uint32_t immediate = operand_2 & 0xff;
	immediate = rotate_right(immediate, num_bits_to_rotate * 2, true);
	return immediate;
}

uint32_t DataProcessingInstructionArm32::get_set_cond_codes()
{
	const uint32_t mask = 0b1;
	const uint32_t shift = 20;
	return get_instruction_field(mask, shift);
}
