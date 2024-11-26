//
// Created by kand on 24-11-26.
//
#include "p_hook_target.h"

#include <linux/hashtable.h>
#include <linux/vmalloc.h>

#include "p_config.h"
#include "p_lkrg_main.h"

struct hook_node {
  const void *func;
  struct p_hook_struct *value;
  struct hlist_node node;
  struct rcu_head rcu;
};

DEFINE_HASHTABLE(hook_target_table, 16);

static void free_data(struct rcu_head *head) {
  const struct hook_node *data = container_of(head, struct hook_node, rcu);
  if (!p_uninstall_hook(data->value)) {
    p_print_log("%s called uninstall hook failed\n", data->value->name);
  }
}

static inline struct p_hook_struct *find_data(const void *key) {
  struct hook_node *data;
  hash_for_each_possible(hook_target_table, data, node, (uint64_t) key) {
    if (data->func == key) {
      return data->value;
    }
  }
  return NULL;
}

void hook_target_init(void) {}
void hook_target_exit(void) {
  struct hook_node *data;
  struct hlist_node *tmp;
  int bkt;

  hash_for_each_safe(hook_target_table, bkt, tmp, data, node) {
    hash_del(&data->node);
    call_rcu(&data->rcu, free_data);
  }
}

bool add_hook_point(const void *key, void *value) {
  struct hook_node *data =
      p_global_symbols.p_module_alloc(sizeof(struct hook_node));
  if (data == NULL) {
    p_print_log("%s called allocating memory failed\n", __FUNCTION__);
    return false;
  }
  data->func = key;
  data->value = value;

  hash_add_rcu(hook_target_table, &data->node, (uint64_t) key);
  return true;
}

void remove_hook_point(const void *key) {
  struct hook_node *data;
  hash_for_each_possible(hook_target_table, data, node, (uint64_t) key) {
    if (data->func == key) {
      call_rcu(&data->rcu, free_data);
      return;
    }
  }
}

bool can_hook_point(const void *key) {
  return find_data(key) == NULL;
}
