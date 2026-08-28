#define main diskplan_fs_helper_program_main
#include "diskplan-fs-helper.c"
#undef main

static void test_fail(const char *message) {
    fprintf(stderr, "diskplan-fs-helper-tests: %s\n", message);
    exit(1);
}

static void join_test_path(char output[PATH_MAX], const char *root, const char *suffix) {
    int length = snprintf(output, PATH_MAX, "%s/%s", root, suffix);
    if (length < 0 || length >= PATH_MAX) test_fail("test path exceeds PATH_MAX");
}

static void make_test_directory(const char *path) {
    if (mkdir(path, 0700) != 0) {
        perror("diskplan-fs-helper-tests: mkdir");
        exit(1);
    }
}

static struct path_binding make_bound_fixture(const char *root, const char *case_name,
                                              char case_root[PATH_MAX],
                                              char parent[PATH_MAX],
                                              char leaf[PATH_MAX]) {
    join_test_path(case_root, root, case_name);
    join_test_path(parent, case_root, "parent");
    join_test_path(leaf, parent, "leaf");
    make_test_directory(case_root);
    make_test_directory(parent);
    make_test_directory(leaf);
    return bind_absolute_directory(leaf, false);
}

static void test_ancestor_replacement(const char *root) {
    char case_root[PATH_MAX], parent[PATH_MAX], leaf[PATH_MAX], retired[PATH_MAX];
    struct path_binding binding =
        make_bound_fixture(root, "ancestor-replacement", case_root, parent, leaf);
    join_test_path(retired, case_root, "retired-parent");
    if (rename(parent, retired) != 0) test_fail("cannot retire bound ancestor");
    make_test_directory(parent);
    make_test_directory(leaf);
    if (check_path_binding(&binding) == PATH_BINDING_MATCHES)
        test_fail("replacement ancestor retained a valid prefix binding");
    close_path_binding(&binding);
}

static void test_ancestor_access_policy_change(const char *root) {
    char case_root[PATH_MAX], parent[PATH_MAX], leaf[PATH_MAX];
    struct path_binding binding =
        make_bound_fixture(root, "ancestor-access", case_root, parent, leaf);
    if (chmod(parent, 0755) != 0) test_fail("cannot change ancestor mode");
    if (check_path_binding(&binding) == PATH_BINDING_MATCHES)
        test_fail("ancestor access-policy change retained a valid prefix binding");
    close_path_binding(&binding);
}

static void test_mount_boundary_change(const char *root) {
    char case_root[PATH_MAX], parent[PATH_MAX], leaf[PATH_MAX];
    struct path_binding binding =
        make_bound_fixture(root, "mount-boundary", case_root, parent, leaf);
    struct directory_binding *entry = &binding.entries[binding.count - 1];
    entry->crosses_mount = !entry->crosses_mount;
    if (check_path_binding(&binding) == PATH_BINDING_MATCHES)
        test_fail("mount-boundary mismatch retained a valid prefix binding");
    close_path_binding(&binding);
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: diskplan-fs-helper-tests /absolute/test/root\n");
        return 64;
    }
    test_ancestor_replacement(argv[1]);
    test_ancestor_access_policy_change(argv[1]);
    test_mount_boundary_change(argv[1]);
    puts("fs-helper ancestor and mount binding tests passed");
    return 0;
}
