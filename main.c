#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<assert.h>
#include"rbtree.h"

#define PTR_TO_INT(ptr) ((int)(long)(ptr))
#define INT_TO_PTR(i) ((void *)(long)(i))

int _random(int min, int max); //[min, max)
void shuffle(int *buf, size_t size);

int comp(const void *p1, const void *p2) {
    int a = PTR_TO_INT(p1);
    int b = PTR_TO_INT(p2);
    return a - b;
}

int main(void) {
    rb_tree *tree = rb_tree_new(comp);
    const int  MAX = 1000;
    for (int a = 1; a < MAX + 1; ++a) {
        int i = a;
        rb_tree_insert(tree, INT_TO_PTR(i), INT_TO_PTR(i), TRUE);
        rb_tree_check(tree);
    }
    srand(time(NULL));
    int *seq = (int *)malloc(sizeof(int) * MAX);
    for (int i = 0; i < MAX; ++i)
        seq[i] = i + 1;
    shuffle(seq, MAX);
    for (int i = 0; i < MAX; ++i) {
        const void *data = NULL;
        if (rb_tree_del(tree, INT_TO_PTR(seq[i]), &data)) {
            printf("%d\n", PTR_TO_INT(data));
            assert(data == INT_TO_PTR(seq[i]));
        }
        else
            printf("delete %d failed\n", seq[i]);
        rb_tree_check(tree);
    }
    free(seq);
    return 0;
    /*
    size_t size = rb_tree_size(tree);
    for (size_t a = 0; a < size; ++a) {
        int num = PTR_TO_INT(rb_tree_del_max(tree));
        rb_tree_check(tree);
        printf("%d\n", num);
    }
    */
}

int _random(int min, int max) {
    int n = max - min;
    int m = RAND_MAX - RAND_MAX % n, s;
    do {
        s = rand();
    } while (s >= m);
    return s % n + min;
}

void shuffle(int *buf, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        size_t r = _random(i, size);
        int s = buf[r];
        buf[r] = buf[i];
        buf[i] = s;
    }
}

