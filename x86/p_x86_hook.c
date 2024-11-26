#if defined(CONFIG_X86_64)
#  include "p_x86_hook.h"

#  include <asm/insn.h>
#  include <linux/vmalloc.h>

#  include "../p_config.h"
#  include "../p_hook_target.h"
#  include "../p_lkrg_main.h"
#  include "../p_memory.h"

#  define TINY_SIZE 5
#  define FULL_SIZE 12

#  define MODE_TINY 0
#  define MODE_FULL 1

static inline int get_insn_length(struct insn *insn, const void *p) {
  int x86_64 = 0;
#  ifdef CONFIG_X86_64
  x86_64 = 1;
#  endif
#  if defined MAX_INSN_SIZE && (MAX_INSN_SIZE == 15) /* 3.19.7+ */
  p_global_symbols.p_insn_init(insn, p, MAX_INSN_SIZE, x86_64);
#  else
  p_global_symbols.p_insn_init(&insn, p, x86_64);
#  endif
  p_global_symbols.p_insn_get_length(insn);
  return insn->length;
}

// static inline void build_trampoline(void *a, const void *from, const void *to,
//                                     const size_t size) {
//   if (size < FULL_SIZE) {
//     uint8_t *ptr = a;
//     ptr[0] = 0xE9;
//     ((uint32_t *) (ptr + 1))[0] = to - (from + 5);
//   } else {
//   }
// }

static void set_trampoline(uint8_t *ptr, const int mode, const void *from,
                           const void *to) {
  if (mode == MODE_TINY) {
    // jmp 0x0
    ptr[0] = 0xE9;
    ((uint32_t *) (ptr + 1))[0] = to - (from + 5);
  } else {

    // mov rax, 0x0
    ((uint16_t *) ptr)[0] = 0xB848;
    ((uint64_t *) (ptr + 2))[0] = (uint64_t) to;
    // jmp rax
    ((uint16_t *) (ptr + 10))[0] = 0xE0FF;
  }
}

static inline void build_trampoline(struct p_hook_struct *hook_struct) {
  hook_stub *stub = hook_struct->stub;
  set_trampoline(stub->trampoline + stub->nbytes, hook_struct->trampoline_mode,
                 stub->trampoline + stub->nbytes,
                 hook_struct->addr + stub->nbytes);
}

static inline int is_fix_offset(const uint8_t *opcode) {
  if (opcode[0] == 0xE8 || opcode[0] == 0xE9) {
    return 1;
  }
#  ifdef CONFIG_X86_64
  //jmp [addr]
  if (opcode[0] == 0xFF && opcode[1] == 0x25) {
    return 2;
  }
  //mov reg,[addr]
  //mov [addr],reg
  //lea reg,[addr]
  if ((opcode[0] == 0x48 || opcode[0] == 0x4C) &&
      (opcode[1] == 0x8B || opcode[1] == 0x8D) && (opcode[2] & 0x5) == 0x5) {
    return 3;
  }
#  endif
  return -1;
}

static inline void fix_hook_offset(const uint8_t *func_addr, uint8_t *new_addr,
                                   const int offset, const int insn_length,
                                   const int pos) {
  const uint8_t *target_addr = func_addr + offset + insn_length;
  const size_t new_offset = target_addr - (new_addr + insn_length);
  ((int *) (new_addr + pos))[0] = (int) new_offset;
}

static inline void find_offset_code(const struct p_hook_struct *hook_struct,
                                    const uint8_t *func_addr,
                                    const unsigned long hook_length) {
  struct insn insn;
  int index = 0;
  int pos = 0;

  while (index < hook_length) {
    const uint8_t *opcode = func_addr + index;
    const int size = get_insn_length(&insn, opcode);
    if ((pos = is_fix_offset(opcode)) != -1) {
      fix_hook_offset(opcode, hook_struct->stub->trampoline + index,
                      ((int *) (opcode + pos))[0], size, pos);
    }
    index += size;
  }
}

static void set_trampoline_size(struct p_hook_struct *hook_struct) {
  hook_stub *stub = hook_struct->stub;

  // jmp 0xFFFFFFFF (5)
  size_t size = 5;
  hook_struct->trampoline_mode = MODE_TINY;
  const int64_t offset = stub->trampoline - hook_struct->addr;
  if (offset < S32_MIN || offset > S32_MAX) {
    // mov rax, 0xFFFFFFFFFFFFFFFF (10)
    // jmp rax (2)
    size = 12;
    hook_struct->trampoline_mode = MODE_FULL;
  }

  struct insn insn;
  while (stub->nbytes < size) {
    stub->nbytes += get_insn_length(&insn, hook_struct->addr + stub->nbytes);
  }
}

int inline_hook_install(void *arg) {
  struct p_hook_struct *hook_struct = arg;
  hook_stub *stub = hook_struct->stub;

  set_trampoline_size(hook_struct);

  memcpy(stub->backup, hook_struct->addr, stub->nbytes);
  memcpy(stub->trampoline, hook_struct->addr, stub->nbytes);
  build_trampoline(hook_struct);

  find_offset_code(hook_struct, hook_struct->addr, stub->nbytes);
  kernel_write_enter();
  set_trampoline(hook_struct->addr, hook_struct->trampoline_mode,
                 hook_struct->addr, hook_struct->entry_fn);
  kernel_write_leave();

  return add_hook_point(hook_struct->addr, hook_struct);
}

int inline_hook_uninstall(void *arg) {
  struct p_hook_struct *hook_struct = arg;
  hook_stub *stub = hook_struct->stub;

  kernel_write_enter();
  memcpy(hook_struct->addr, stub->backup, stub->nbytes);
  vfree(stub);
  hook_struct->stub = NULL;
  kernel_write_leave();
  return 0;
}

#endif
