MODULE := hook_engine
obj-m += $(MODULE).o
$(MODULE)-objs += p_lkrg_main.o p_memory.o p_hook_target.o p_config.o
$(MODULE)-objs += x86/p_x86_hook.o
$(MODULE)-objs += arm64/p_arm64_check.o arm64/p_arm64_hook.o
$(MODULE)-objs += hook/p_generic_permission/p_generic_permission.o

# specify flags for the module compilation
EXTRA_CFLAGS = -g -O0

all: hook_engine.ko

hook_engine.ko:
	$(MAKE) -C '/lib/modules/$(shell uname -r)/build' M='$(PWD)' modules
clean:
	$(MAKE) -C '/lib/modules/$(shell uname -r)/build' M='$(PWD)' clean