#include"rbtree.h"
#include<stdlib.h>
#include<assert.h>

typedef enum { RED = 0, BLACK = 1} RBTREE_COLOR;

#define __alloc(type, n) ((type *)malloc(sizeof(type) * (n)))
#define __alloc0(type) __alloc(type, 1)
#define BUG(expression) assert(expression)

#define UNUSED_RESULT __attribute__((warn_unused_result))
#define ALIGNED __attribute__((aligned))

#define IS_BLACK(node) (!(node) || (node)->_color == BLACK)
#define IS_RED(node) ((node) && (node)->_color == RED)
#define TO_RED(node) ((node)->_color = RED)
#define TO_BLACK(node) ((node)->_color = BLACK)
#define TRANSFER_COLOR(prev, now) ((now)->_color = (prev)->_color)

struct _rb_tree_node {
    const void *_key;
    const void *_data;
    RBTREE_COLOR _color;
    struct _rb_tree_node *_parent, *_left, *_right;
} ALIGNED;

struct _rb_tree {
    struct _rb_tree_node *_root;
    key_compare_func _func;
    size_t _size;
};

struct _rb_tree_node *__correct_tree(struct _rb_tree_node *node) UNUSED_RESULT;

rb_tree *rb_tree_new(key_compare_func func) {
    if (!func)
        return NULL;
    rb_tree *tree = __alloc0(rb_tree);
    tree->_func = func;
    tree->_root = NULL;
    tree->_size = 0;
    return tree;
}

size_t rb_tree_size(rb_tree *tree) {
    return tree->_size;
}

struct _rb_tree_node *__get_min(struct _rb_tree_node *node) {
    while (node->_left) {
        node = node->_left;
    }
    return node;
}

void __rotate_right(struct _rb_tree_node *node, struct _rb_tree_node *parent) {
    struct _rb_tree_node *right = node->_right, *p = parent->_parent;
    node->_right = parent;
    parent->_parent = node;
    parent->_left = right;
    node->_parent = p;
    if (right)
        right->_parent = parent;
    if (p && p->_left == parent)
        p->_left = node;
    else if (p)
        p->_right = node;
}

void __rotate_left(struct _rb_tree_node *node, struct _rb_tree_node *parent) {
    struct _rb_tree_node *left = node->_left, *p = parent->_parent;
    node->_left = parent;
    parent->_parent = node;
    parent->_right = left;
    node->_parent = p;
    if (left)
        left->_parent = parent;
    if (p && p->_left == parent)
        p->_left = node;
    else if (p)
        p->_right = node;
}

struct _rb_tree_node *__correct_tree(struct _rb_tree_node *node) {
    struct _rb_tree_node *prev = NULL;
    while (node) {
        if (IS_RED(node->_right) && IS_BLACK(node->_left)) {
            TRANSFER_COLOR(node, node->_right);
            TO_RED(node);
            __rotate_left(node->_right, node);
            node = node->_parent;
        }
        if (IS_RED(node->_left) && IS_RED(node->_left->_left)) {
            TRANSFER_COLOR(node, node->_left);
            TO_RED(node);
            __rotate_right(node->_left, node);
            node = node->_parent;
        }
        if (IS_RED(node->_left) && IS_RED(node->_right)) {
            TO_BLACK(node->_left);
            TO_BLACK(node->_right);
            TO_RED(node);
        }
        prev = node;
        node = node->_parent;
    }
    if (IS_RED(prev))
        TO_BLACK(prev);
    return prev;
}

boolean __do_insert(rb_tree *tree, const void *key, const void *val,
        boolean overwrite) {
    struct _rb_tree_node **ptr = &tree->_root, *parent = NULL;
    key_compare_func func = tree->_func;
    while (*ptr) {
        struct _rb_tree_node *node = *ptr;
        parent = node;
        int comp = func(key, node->_key);
        if (comp < 0)
            ptr = &node->_left;
        else if (comp > 0)
            ptr = &node->_right;
        else {
            if (overwrite) {
                node->_data = val;
                return TRUE;
            }
            return FALSE;
        }
    }
    struct _rb_tree_node *tmp = __alloc0(struct _rb_tree_node);
    tmp->_key = key;
    tmp->_data = val;
    TO_RED(tmp);
    tmp->_left = tmp->_right = NULL;
    tmp->_parent = parent;
    *ptr = tmp;
    ++tree->_size;
    tree->_root = __correct_tree(*ptr);
    return TRUE;
}

boolean rb_tree_insert(rb_tree *tree, const void *key, const void *val,
        boolean overwrite) {
    if (!tree)
        return FALSE;
    return __do_insert(tree, key, val, !!overwrite);
}

const void *__do_lookup(rb_tree *tree, const void *key) {
    struct _rb_tree_node *node = tree->_root;
    key_compare_func f = tree->_func;
    while (node) {
        int c = f(key, node->_data);
        if (c < 0)
            node = node->_left;
        else if (c > 0)
            node = node->_right;
        else
            return node->_data;
    }
    return NULL;
}

const void *rb_tree_lookup(rb_tree *tree, const void *key) {
    if (!tree || tree->_root == NULL)
        return NULL;
    return __do_lookup(tree, key);
}

int __do_check(struct _rb_tree_node *node) {
    int left_depth, right_depth;
    if (!node)
        return 0;
    if (IS_BLACK(node)) {
        BUG(IS_BLACK(node->_right));
    }
    else
        BUG(IS_BLACK(node->_left) && IS_BLACK(node->_right));
    left_depth = __do_check(node->_left);
    right_depth = __do_check(node->_right);
    BUG(left_depth == right_depth);
    return left_depth + !!IS_BLACK(node);
}

void rb_tree_check(rb_tree *tree) {
    if (!tree->_root)
        return;
    struct _rb_tree_node *node = tree->_root;
    BUG(IS_BLACK(node));
    __do_check(node);
}

#define IS_NODE_2(node) (IS_BLACK(node) && IS_BLACK((node)->_left))
#define IS_NODE_3(node) (IS_BLACK(node) && IS_RED((node)->_left))

struct _rb_tree_node *__combine_left(struct _rb_tree_node *node) {
    if (IS_NODE_3(node->_left))
        return node->_left;
    if (IS_NODE_2(node->_right)) {
        __rotate_left(node->_right, node);
        TO_RED(node);
        TO_RED(node->_left);
        node = node->_parent;
    }
    else {
        BUG(IS_NODE_3(node->_right));
        TRANSFER_COLOR(node, node->_right->_left);
        TO_BLACK(node);
        TO_RED(node->_left);
        __rotate_right(node->_right->_left, node->_right);
        __rotate_left(node->_right, node);
    }
    return node;
}

const void *__do_del_min(struct _rb_tree_node *node, struct _rb_tree_node *wait, struct _rb_tree_node **root) {
    struct _rb_tree_node *ptr = node;
    const void *ret = NULL;
    while (ptr) {
        if (!ptr->_left) {
            ret = ptr->_data;
            if (wait) {
                ret = wait->_data;
                wait->_key = ptr->_key;
                wait->_data = ptr->_data;
            }
            break;
        }
        if (IS_RED(ptr->_left))
            ptr = ptr->_left;
        else
            ptr = __combine_left(ptr);
    }
    if (ptr->_parent)
        ptr->_parent->_left = NULL;
    struct _rb_tree_node *new_root = __correct_tree(ptr->_parent);
    if (root)
        *root = new_root;
    free(ptr);
    return ret;
}

const void *rb_tree_del_min(rb_tree *tree) {
    if (!tree->_root)
        return NULL;
    --tree->_size;
    return __do_del_min(tree->_root, NULL, &tree->_root);
}

struct _rb_tree_node *__combine_right(struct _rb_tree_node *node) {
    if (IS_NODE_3(node->_right))
        return node->_right;
    if (IS_RED(node->_left)) {
        struct _rb_tree_node *left = node->_left;
        if (IS_NODE_2(left->_right)) {
            TRANSFER_COLOR(node, left);
            TO_RED(left->_right);
            __rotate_right(node->_left, node);
            __rotate_left(node->_right, node);
        }
        else {
            TRANSFER_COLOR(node, left->_right);
            TO_BLACK(left->_right->_left);
            __rotate_left(left->_right, left);
            __rotate_right(node->_left, node);
            __rotate_left(node->_right, node);
        }
    }
    else if (IS_NODE_2(node->_left)) {
        TO_RED(node->_left);
        __rotate_left(node->_right, node);
    }
    else {
        TO_BLACK(node->_left->_left);
        TRANSFER_COLOR(node, node->_left);
        __rotate_right(node->_left, node);
        __rotate_left(node->_right, node);
    }
    TO_RED(node);
    return node->_parent;
}

const void *__do_del_max(struct _rb_tree_node *node, struct _rb_tree_node *wait, struct _rb_tree_node **root) {
    struct _rb_tree_node *ptr = node;
    const void *ret = NULL;
    while (ptr) {
        if (!ptr->_right) {
            ret = ptr->_data;
            if (wait) {
                ret = wait->_data;
                wait->_data = ptr->_data;
                wait->_key = ptr->_key;
            }
            TO_BLACK(ptr->_left);
            __rotate_right(ptr->_left, ptr);
            ptr->_parent->_right = NULL;
            break;
        }
        ptr = __combine_right(ptr);
        BUG(IS_NODE_3(ptr));
    }
    struct _rb_tree_node *new_root = __correct_tree(ptr->_parent);
    if (root)
        *root = new_root;
    free(ptr);
    return ret;
}

const void *rb_tree_del_max(rb_tree *tree) {
    if (!tree || !tree->_root)
        return NULL;
    --tree->_size;
    if (!tree->_root->_right) {
        struct _rb_tree_node *old = tree->_root;
        const void *data = old->_data;
        tree->_root = tree->_root->_left;
        if (tree->_root)
            TO_BLACK(tree->_root);
        free(old);
        return data;
    }
    return __do_del_max(tree->_root, NULL, &tree->_root);
}

boolean rb_tree_del(rb_tree *tree, const void *k, const void **data) {
    if (!tree || !tree->_root)
        return FALSE;
    struct _rb_tree_node *node = tree->_root, *wait = NULL;
    key_compare_func func = tree->_func;
    const void *key = k;
    while (TRUE) {
        int c = func(key, node->_key);
        if (c < 0) {
            if (!node->_left) {
                tree->_root = __correct_tree(node);
                return FALSE;
            }
            if (IS_RED(node->_left))
                node = node->_left;
            else
                node = __combine_left(node);
        }
        else if (c == 0) {
            if (!node->_right) {
                if (node->_left) {
                    BUG(IS_RED(node->_left));
                    TRANSFER_COLOR(node, node->_left);
                    __rotate_right(node->_left, node);
                }
                if (node->_parent && node->_parent->_left == node)
                    node->_parent->_left = NULL;
                else if (node->_parent)
                    node->_parent->_right = NULL;
                break;
            }
            BUG(!wait);
            struct _rb_tree_node *min = __get_min(node->_right);
            key = min->_key;
            wait = node;
            node = __combine_right(node);
        }
        else {
            if (!node->_right) {
                tree->_root = __correct_tree(node);
                return FALSE;
            }
            node = __combine_right(node);
        }
    }
    --tree->_size;
    const void *d = node->_data;
    if (wait) {
        wait->_key = node->_key;
        d = wait->_data;
        wait->_data = node->_data;
    }
    if (data)
        *data = d;
    tree->_root = __correct_tree(node->_parent);
    free(node);
    return TRUE;
}
