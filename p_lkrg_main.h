#ifndef P_LKRG_MAIN_H
#define P_LKRG_MAIN_H

#include <linux/module.h>

#if !defined(CONFIG_KALLSYMS)
#  error INLINE_HOOK_ENGINE NEED CONFIG_KALLSYMS
#endif

typedef struct {
#pragma pack(push, 1)
  atomic_t count;
  uint8_t backup[0x30];
  uint8_t trampoline[0x30];
#pragma pack(pop)
  uint32_t nbytes;
} hook_stub;

struct p_hook_struct {
#pragma pack(push, 1)
  void *entry_fn;
  const char *name;
  uint8_t *addr;
  hook_stub *stub;
  int trampoline_mode;
#pragma pack(pop)
};

bool p_install_hook(struct p_hook_struct *p_current_hook_struct);

bool p_uninstall_hook(struct p_hook_struct *p_current_hook_struct);

#endif