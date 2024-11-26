#include "p_lkrg_main.h"

#include <asm/page.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "p_config.h"
#include "p_hook_target.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#  define stop_machine stop_machine
#else
#  define stop_machine stop_machine_run
#endif

#if defined(CONFIG_X86_64)
#  include "x86/p_x86_hook.h"
#elif defined(CONFIG_ARM64)
#  include "arm64/p_arm64_hook.h"
#endif


#if defined(CONFIG_ARM64)
bool check_function_length_enough(void *target) {
  unsigned long symbolsize, offset;
  unsigned long pos;

  pos = p_global_symbols.p_get_symbol_pos((unsigned long) target, &symbolsize,
                                          &offset);
  if (pos && !offset && symbolsize >= ARM64_HOOK_SIZE) {
    return true;
  } else {
    return false;
  }
}
#endif

static void wakeup_process(void) {
  struct task_struct *p;
  rcu_read_lock();
  for_each_process(p) {
    wake_up_process(p);
  }
  rcu_read_unlock();
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0))
static int p_lookup_syms_hack(void *unused, const char *name,
                              struct module *mod, unsigned long addr) {

  if (strcmp("kallsyms_lookup_name", name) == 0) {
    p_global_symbols.p_kallsyms_lookup_name = (void *(*) (const char *) ) addr;
    return 1;
  }

  return 0;
}
#endif

static int kallsyms_lookup_name_entry(struct kprobe *p, struct pt_regs *regs) {
#if defined(CONFIG_X86_64)
  p_global_symbols.p_kallsyms_lookup_name =
      (void *(*) (const char *) )(regs->ip - 1);
#endif
  return 0;
}

static inline int get_kallsyms_address(void) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
  struct kprobe first = {
      .symbol_name = "kallsyms_lookup_name",
      .pre_handler = kallsyms_lookup_name_entry,
  };
  if (register_kprobe(&first) != 0) {
    p_print_log("kprobe hook kallsyms_lookup_name failed\n");
    return -1;
  }

  struct kprobe trigger = {
      .symbol_name = "unknown",
  };
  register_kprobe(&trigger);
  unregister_kprobe(&first);
#else
  kallsyms_on_each_symbol(p_lookup_syms_hack, NULL);
#endif
  if (p_global_symbols.p_kallsyms_lookup_name == NULL) {
    return -1;
  }

  p_print_log("kallsyms_lookup_name:%lx\n",
              (uintptr_t) p_global_symbols.p_kallsyms_lookup_name);
  return 0;
}

static inline int inline_hook_init(void) {
#if defined(CONFIG_X86_64)
  p_global_symbols.p_insn_init =
      (typeof(insn_init) *) p_global_symbols.p_kallsyms_lookup_name(
          "insn_init");
  if (p_global_symbols.p_insn_init == NULL) {
    p_print_log("insn_init addr get failed\n");
    return -1;
  }

  p_global_symbols.p_insn_get_length =
      p_global_symbols.p_kallsyms_lookup_name("insn_get_length");
  if (p_global_symbols.p_insn_get_length == NULL) {
    p_print_log("insn_get_length get failed\n");
    return -1;
  }

  p_global_symbols.p_flush_tlb_all =
      p_global_symbols.p_kallsyms_lookup_name("flush_tlb_all");
  if (p_global_symbols.p_flush_tlb_all == NULL) {
    p_print_log("flush_tlb_all addr get failed\n");
    return -1;
  }
#endif

#if defined(CONFIG_ARM64)
  p_global_symbols.p_get_symbol_pos =
      (unsigned long (*)(unsigned long, unsigned long *, unsigned long *))
          p_global_symbols.p_kallsyms_lookup_name("get_symbol_pos");
  if (p_global_symbols.p_get_symbol_pos == NULL) {
    p_print_log("p_get_symbol_pos get failed\n");
    return -1;
  }

  p_global_symbols.p_stext = p_global_symbols.p_kallsyms_lookup_name("_stext");
  if (p_global_symbols.p_stext == NULL) {
    p_print_log("p_stext get failed\n");
    return -1;
  }

  p_global_symbols.p_etext = p_global_symbols.p_kallsyms_lookup_name("_etext");
  if (p_global_symbols.p_etext == NULL) {
    p_print_log("p_etext get failed\n");
    return -1;
  }

  p_global_symbols.p_sinittext =
      p_global_symbols.p_kallsyms_lookup_name("_sinittext");
  if (p_global_symbols.p_sinittext == NULL) {
    p_print_log("p_sinittext get failed (skipping it)\n");
  }

  p_global_symbols.p_einittext =
      p_global_symbols.p_kallsyms_lookup_name("_einittext");
  if (p_global_symbols.p_einittext == NULL) {
    p_print_log("p_einittext get failed (skipping it)\n");
  }

  p_global_symbols.p_init_mm =
      (struct mm_struct *) p_global_symbols.p_kallsyms_lookup_name("init_mm");
  if (p_global_symbols.p_init_mm == NULL) {
    p_global_symbols.p_init_mm = (struct mm_struct *) get_init_mm_address();
    if (p_global_symbols.p_init_mm == NULL) {
      p_print_log("init_mm get failed\n");
      return -1;
    }
  }

#  if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  p_global_symbols.p_sync_icache_dcache = (void (*)(
      pte_t)) p_global_symbols.p_kallsyms_lookup_name("__sync_icache_dcache");
  if (p_global_symbols.p_sync_icache_dcache == NULL) {
    p_print_log("p_sync_icache_dcache get failed\n");
    return -1;
  }
#  endif
#endif
  p_global_symbols.p_module_alloc =
      p_global_symbols.p_kallsyms_lookup_name("module_alloc");
  if (p_global_symbols.p_module_alloc == NULL) {
    p_print_log("module_alloc addr get failed\n");
    return -1;
  }

  p_global_symbols.p_set_memory_x =
      p_global_symbols.p_kallsyms_lookup_name("set_memory_x");
  if (p_global_symbols.p_set_memory_x == NULL) {
#if defined(CONFIG_X86_64)
    p_print_log("get set_memory_x addr failed\n");
    return -1;
#elif defined(CONFIG_ARM64)
    p_print_log("get set_memory_x addr (skipping it)\n");
#endif
  }
  return 0;
}

bool p_install_hook(struct p_hook_struct *p_current_hook_struct) {
  if (strlen(p_current_hook_struct->name) == 0) {
    return false;
  }

  void *func =
      p_global_symbols.p_kallsyms_lookup_name(p_current_hook_struct->name);
  if (func == NULL) {
    p_print_log("%s hook failed\n", p_current_hook_struct->name);
    return false;
  }
  if (!can_hook_point(func)) {
    p_print_log("%s already hooked\n", p_current_hook_struct->name);
    return false;
  }

  p_current_hook_struct->addr = (uint8_t *) func;

#if defined(CONFIG_ARM64)
  if (!check_function_length_enough(p_current_hook_struct->addr) ||
      !check_target_can_hook(p_current_hook_struct->addr)) {
    p_print_log("[%s] can not hook\n", p_current_hook_struct->name);
    return -1;
  }
#endif
  hook_stub *stub = p_global_symbols.p_module_alloc(sizeof(hook_stub));
  if (stub == NULL) {
    p_print_log("%s module_alloc failed\n", p_current_hook_struct->name);
    return -1;
  }

  memset(stub, 0, sizeof(hook_stub));
  const int num_pages = round_up(sizeof(hook_stub), PAGE_SIZE) / PAGE_SIZE;
#if defined(CONFIG_ARM64)
  if (p_global_symbols.p_set_memory_x) {
    p_global_symbols.p_set_memory_x((unsigned long) stub, numpages);
  } else {
    set_allocate_memory_x((unsigned long) stub, numpages);
  }
#elif defined(CONFIG_X86_64)
  p_global_symbols.p_set_memory_x((unsigned long) stub, num_pages);
#endif

#if defined(CONFIG_X86_64)
  if (p_global_symbols.p_flush_tlb_all != NULL) {
    p_global_symbols.p_flush_tlb_all();
  }
#endif
  p_current_hook_struct->stub = stub;
  const int p_ret =
      stop_machine(inline_hook_install, p_current_hook_struct, NULL);
  if (p_ret == 0) {
    p_print_log("%s addr:%p hook addr:%p\n", p_current_hook_struct->name,
                p_current_hook_struct->addr, stub);
    p_print_log("%s hook success\n", p_current_hook_struct->name);
  }

  return p_ret == 0;
}

bool p_uninstall_hook(struct p_hook_struct *p_current_hook_struct) {
  const hook_stub *stub = p_current_hook_struct->stub;
  if (stub == NULL) {
    return false;
  }

  stop_machine(inline_hook_uninstall, p_current_hook_struct, NULL);

  while (atomic_read(&stub->count) > 0) {
    wakeup_process();
    msleep_interruptible(500);
    p_print_log("waiting for %s...\n", p_current_hook_struct->name);
  }

  msleep_interruptible(300);
  vfree(stub);
  p_print_log("uninstall %s success\n", p_current_hook_struct->name);
  return true;
}

static int __init p_lkrg_register(void) {
  if (get_kallsyms_address() != 0) {
    p_print_log("kallsyms_lookup_name get failed\n");
    return -1;
  }

  if (inline_hook_init() != 0) {
    p_print_log("init failed\n");
    return -1;
  }

  hook_target_init();

  p_print_log("load success\n");
  return 0;
}

static void __exit p_lkrg_unregister(void) {
  hook_target_exit();
  p_print_log("unload success\n");
}

module_init(p_lkrg_register);
module_exit(p_lkrg_unregister);

MODULE_LICENSE("GPL");
