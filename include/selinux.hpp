#ifndef SELINUX_HPP
#define SELINUX_HPP

#include <map>
#include <memory>
#include <vector>

#include "mtk_su.hpp"

/**
 * Determines if SELinux status is set to enforcing. If not, it's permissive.
 *
 * @param is_enforcing: True if SELinux is enforcing, otherwise false for permissive
 * @return true if the SELinux status was successfully resolved, otherwise false on error
 */
bool is_selinux_enforcing(bool& is_enforcing);

bool set_selinux_permissive(MTKSu& kern_rw, std::map<std::string, uint64_t>& symbol_table);

#endif  // SELINUX_HPP
