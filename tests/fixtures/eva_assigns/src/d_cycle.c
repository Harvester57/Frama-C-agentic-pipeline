/* A recursion cycle through a callback: walk -> visit (via function pointer) -> walk. */
struct node {
    int value;
    struct node *child;
};

typedef int (*visitor)(struct node *);

static int walk(struct node *n, visitor v);

static int visit(struct node *n)
{
    return walk(n->child, visit);
}

static int walk(struct node *n, visitor v)
{
    if (!n)
        return 0;
    return n->value + v(n);
}

int eva_main(void)
{
    struct node leaf = {1, 0};
    struct node root = {2, &leaf};
    return walk(&root, visit);
}
