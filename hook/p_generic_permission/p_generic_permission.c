#include "p_generic_permission.h"

#include "../../p_config.h"
#include "../../p_lkrg_main.h"

int p_generic_permission_entry(void *, int);

static struct p_hook_struct p_generic_permission_hook = {
    .entry_fn = p_generic_permission_entry,
    .name = "generic_permission",
};

int p_generic_permission_entry(void *node, const int mask) {
  p_print_log("generic_permission node:%llx mask:%d\n", (uint64_t) node, mask);
  return ((typeof(p_generic_permission_entry) *)
              p_generic_permission_hook.stub->trampoline)(node, mask);
}
