# kernel-inline-hook

## Introduction

This kernel module is a linux kernel inline hook module that supports different architectures. Used to inline hook linux kernel functions. This engine can be mainly used to insert custom code before or after calling a certain kernel function for functions similar to function monitoring.

## Support Situation

1. Callback before calling -> call the original function -> callback after calling
2. Callback before calling -> call the original function
3. Callback before calling -> return calling function

## Limits

Currently the module supports the following architectures:

1. x86_64 (test passed)

## Extra Features

1. You can modify the parameters that call the original function in the previous callback
2. You can get the parameter content of the original function in the previous callback function, verify it, etc.
3. You can check the return value of the original function in the post callback function, and you can also modify the return value of the original function
4. You can directly return not call the original function

## Build

1. Normal build first make and then insmod to load the module
2. If you want to build a kernel module under arm architecture on a machine with x86 architecture: make ARCH=arm64 or arm CROSS_COMPILE=cross toolchain address
3. If you want to add a hook function, you need to add the corresponding .o file path in the Makefile, add the corresponding header file in install/p_install, and add the corresponding file in the hook folder and add the added function information in the global array.

## Notice

1. If the kernel version is greater than 5.7.0, you need to pass in parameters when loading the module. For example: insmod hook_engine.ko kallsyms_lookup_name_address=0xffffffc0100d4dc8
2. If there are many hook functions, the system will freeze for a while when unloading, and the unloading will be successful because it is waiting for the memory to be released.

## Example

Example of hook function structure

```c
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
```

Example of install hook

```c
p_install_hook(&p_generic_permission_hook);
```

## References

1. https://github.com/milabs/khook
2. https://github.com/zhuotong/Android_InlineHook
3. https://github.com/WeiJiLab/kernel-hook-framework

