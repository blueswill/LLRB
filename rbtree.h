#ifndef RBTREE_H
#define RBTREE_H

#include<stddef.h>

#define TRUE 1
#define FALSE 0

typedef struct _rb_tree rb_tree;
typedef unsigned char boolean;

typedef int (*key_compare_func)(const void *key1, const void *key2);

#define KEY_COMP_FUNC(f) ((key_compare_func)(void (*)(void *))f)

rb_tree *rb_tree_new(key_compare_func func);
size_t rb_tree_size(rb_tree *tree);
boolean rb_tree_insert(rb_tree *tree, const void *key, const void *val, boolean overwrite);
const void *rb_tree_lookup(rb_tree *tree, const void *key);
const void *rb_tree_del_min(rb_tree *tree);
const void *rb_tree_del_max(rb_tree *tree);
boolean rb_tree_del(rb_tree *tree, const void *key, const void **data);
void rb_tree_check(rb_tree *tree);

#endif
