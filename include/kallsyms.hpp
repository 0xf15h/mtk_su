#ifndef KALLSYMS_HPP
#define KALLSYMS_HPP

#include <map>
#include <memory>
#include <vector>

#include "mtk_su.hpp"

/**
 * Builds the kernel symbol table by scanning kernel memory.
 *
 * @param kern_rw: The kernel read/write primitive used to read kernel memory
 * @param symbol_table_out: The symbol name to symbol address map used to store the kernel symbol table
 * @return true if the symbol table was built successfully, otherwise false
 */
bool build_kernel_symbol_table(MTKSu& kern_rw, std::map<std::string, uint64_t>& symbol_table_out);

#endif  // KALLSYMS_HPP