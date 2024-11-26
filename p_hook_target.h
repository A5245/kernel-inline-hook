//
// Created by kand on 2024/11/26.
//

#ifndef HOOK_P_TARGET_H
#define HOOK_P_TARGET_H

#include <linux/types.h>

void hook_target_init(void);
void hook_target_exit(void);

bool add_hook_point(const void *key, void *value);
void remove_hook_point(const void *key);

bool can_hook_point(const void *key);

#endif  //HOOK_P_TARGET_H
