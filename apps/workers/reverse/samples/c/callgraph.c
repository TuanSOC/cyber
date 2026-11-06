/* CyberLab RE fixture: parsed only, never run.
 *
 * A known call tree for call-edge recall (M10 phase 4): direct calls, mutual recursion, self
 * recursion, a tail call (a `jmp` at -O2), a function-pointer table (indirect calls, not
 * edges) and a `static` helper that -O2 inlines (its edges then disappear from the build, and
 * the truth drops them because objdump no longer shows them).
 *
 * Every function carries an `re:` annotation block (samples/truth.py): `fn=` names it,
 * `calls=` lists its direct callees in this file, `indirect=` the targets it reaches only
 * through the table. Calls into the C runtime are not annotated (library edges).
 * Benign: prints a few numbers. Compiled at test time, never executed.
 */
#include <stdio.h>
#include <stdlib.h>

#define CL_NOINLINE __attribute__((noinline, noclone))

typedef int (*op_fn)(int);

/* re: fn=clamp_value */
static inline int clamp_value(int x) {
    return x < 0 ? 0 : (x > 100000 ? 100000 : x);
}

/* re: fn=leaf_add */
CL_NOINLINE int leaf_add(int x) {
    return x + 3;
}

/* re: fn=leaf_mul */
CL_NOINLINE int leaf_mul(int x) {
    return x * 7 - 1;
}

/* re: fn=combine
 * re: calls=leaf_add, leaf_mul, clamp_value
 */
CL_NOINLINE int combine(int a, int b) {
    return clamp_value(leaf_add(a) + leaf_mul(b));
}

/* re: fn=is_odd
 * re: calls=is_even
 */
CL_NOINLINE int is_odd(unsigned n);

/* re: fn=is_even
 * re: calls=is_odd
 */
CL_NOINLINE int is_even(unsigned n) {
    return n == 0 ? 1 : is_odd(n - 1);
}

CL_NOINLINE int is_odd(unsigned n) {
    return n == 0 ? 0 : is_even(n - 1);
}

/* re: fn=op_double */
CL_NOINLINE int op_double(int x) {
    return x * 2;
}

/* re: fn=op_negate */
CL_NOINLINE int op_negate(int x) {
    return -x + 11;
}

/* re: fn=op_square */
CL_NOINLINE int op_square(int x) {
    return x * x - 5;
}

static op_fn const OPS[] = {op_double, op_negate, op_square};

/* re: fn=apply_ops
 * re: calls=clamp_value
 * re: indirect=op_double, op_negate, op_square
 */
CL_NOINLINE int apply_ops(int x) {
    int acc = x;
    for (size_t i = 0; i < sizeof OPS / sizeof OPS[0]; i++) {
        acc = clamp_value(OPS[i](acc));
    }
    return acc;
}

/* re: fn=log_value */
CL_NOINLINE int log_value(const char *label, int value) {
    return printf("%s=%d\n", label, value);
}

/* re: fn=finish
 * re: calls=log_value
 */
CL_NOINLINE int finish(int value) {
    return log_value("result", value); /* a tail call at -O2 */
}

/* re: fn=walk_tree
 * re: calls=walk_tree, combine
 */
CL_NOINLINE int walk_tree(int depth) {
    if (depth <= 0) {
        return 1;
    }
    return combine(depth, walk_tree(depth - 1)) + walk_tree(depth - 2);
}

/* re: fn=helper_static
 * re: calls=leaf_add
 */
CL_NOINLINE static int helper_static(int x) {
    return leaf_add(x) ^ 0x5a;
}

/* re: fn=pipeline
 * re: calls=combine, apply_ops, walk_tree, finish
 */
CL_NOINLINE int pipeline(int seed) {
    int value = combine(seed, seed + 1);
    value = apply_ops(value);
    value += walk_tree(seed % 6);
    return finish(value);
}

/* re: fn=main
 * re: calls=pipeline, is_even, helper_static, log_value
 */
int main(int argc, char **argv) {
    int seed = argc > 1 ? atoi(argv[1]) : 4;
    log_value("even", is_even((unsigned)seed));
    log_value("helper", helper_static(seed));
    return pipeline(seed) > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
