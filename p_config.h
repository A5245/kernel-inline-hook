//
// Created by kand on 2024/11/26.
//

#ifndef P_CONFIG_PRIV_H
#define P_CONFIG_PRIV_H

#if defined(CONFIG_X86_64)
#  include <asm/insn.h>
#endif

typedef struct _p_lkrg_global_symbols_structure {
  void *(*p_kallsyms_lookup_name)(const char *);

  void *(*p_module_alloc)(unsigned long);

  int (*p_set_memory_x)(unsigned long, int);
#if defined(CONFIG_X86_64)
  typeof(insn_init) *p_insn_init;
  typeof(insn_get_length) *p_insn_get_length;

  void (*p_flush_tlb_all)(void);
#endif

#if defined(CONFIG_ARM64)
  unsigned long (*p_get_symbol_pos)(unsigned long, unsigned long *,
                                    unsigned long *);
  void (*p_flush_tlb_kernel_range)(unsigned long, unsigned long);
  int (*p_apply_to_page_range)(struct mm_struct *, unsigned long, unsigned long,
                               pte_fn_t, void *);
  void (*p_sync_icache_dcache)(pte_t);

  void *p_stext;
  void *p_etext;
  void *p_sinittext;
  void *p_einittext;
  struct mm_struct *p_init_mm;
#endif
} p_lkrg_global_symbols;

extern p_lkrg_global_symbols p_global_symbols;
#define P_SYM(p_field) p_global_symbols.p_field

#define P_LKRG_SIGNATURE "[INLINE_HOOK_ENGINE] "

#define p_print_log(p_fmt, p_args...) \
  ({ printk(KERN_INFO P_LKRG_SIGNATURE p_fmt, ##p_args); })

#endif  //P_CONFIG_PRIV_H
