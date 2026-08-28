#define DISKPLAN_FS_HELPER_TESTING 1
#define main diskplan_fs_helper_program_main
#include "diskplan-fs-helper.c"
#undef main

static bool copy_touch_enabled = false;

void diskplan_copy_test_hook(int source_fd) {
    if (!copy_touch_enabled) return;
    struct stat metadata;
    if (fstat(source_fd, &metadata) != 0) abort();
    struct timespec times[2] = {metadata.st_atimespec, metadata.st_mtimespec};
    times[1].tv_sec += 1;
    if (futimens(source_fd, times) != 0) abort();
    copy_touch_enabled = false;
}

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

static void close_managed_without_revalidation(struct managed *managed) {
    close_child_directory_binding(&managed->root_slot);
    close_child_directory_binding(&managed->libexec_slot);
    close_child_directory_binding(&managed->bin_slot);
    close_path_binding(&managed->prefix_path);
}

static void test_managed_child_slot_replacement(const char *root, const char *case_name,
                                                const char *child_name) {
    char prefix[PATH_MAX];
    join_test_path(prefix, root, case_name);
    make_test_directory(prefix);
    struct managed managed = open_managed(prefix, NULL, true);
    struct child_directory_binding *slot;
    int parent;
    mode_t mode;
    if (strcmp(child_name, "bin") == 0) {
        slot = &managed.bin_slot;
        parent = managed.prefix;
        mode = 0755;
    } else if (strcmp(child_name, "libexec") == 0) {
        slot = &managed.libexec_slot;
        parent = managed.prefix;
        mode = 0755;
    } else {
        slot = &managed.root_slot;
        parent = managed.libexec;
        mode = 0700;
    }
    char retired[NAME_MAX + 1];
    snprintf(retired, sizeof(retired), "%s-retired", child_name);
    if (renameat(parent, child_name, parent, retired) != 0)
        test_fail("cannot retire managed child slot fixture");
    if (mkdirat(parent, child_name, mode) != 0)
        test_fail("cannot create managed child replacement fixture");
    if (check_child_directory_binding(slot) == PATH_BINDING_MATCHES)
        test_fail("managed child replacement retained a valid slot binding");
    close_managed_without_revalidation(&managed);
}

static void test_managed_child_access_policy_change(const char *root) {
    char prefix[PATH_MAX];
    join_test_path(prefix, root, "managed-bin-access");
    make_test_directory(prefix);
    struct managed managed = open_managed(prefix, NULL, true);
    if (fchmod(managed.bin, 0777) != 0)
        test_fail("cannot mutate managed child access-policy fixture");
    if (check_child_directory_binding(&managed.bin_slot) == PATH_BINDING_MATCHES)
        test_fail("managed child access-policy drift retained a valid slot binding");
    if (fchmod(managed.bin, 0755) != 0)
        test_fail("cannot restore managed child access-policy fixture");
    close_managed(&managed);
}

static void test_removed_managed_slot_repopulation(const char *root) {
    char prefix[PATH_MAX];
    join_test_path(prefix, root, "managed-removed-slot");
    make_test_directory(prefix);
    struct managed managed = open_managed(prefix, NULL, true);
    prune_empty_managed_directories(&managed);
    if (managed.bin_slot.active || managed.libexec_slot.active || managed.root_slot.active)
        test_fail("empty managed directories were not marked absent");
    if (mkdirat(managed.prefix, "bin", 0755) != 0)
        test_fail("cannot create removed-slot replacement fixture");
    if (check_child_directory_binding(&managed.bin_slot) == PATH_BINDING_MATCHES)
        test_fail("removed managed slot accepted a replacement object");
    if (unlinkat(managed.prefix, "bin", AT_REMOVEDIR) != 0)
        test_fail("cannot remove removed-slot replacement fixture");
    close_managed(&managed);
}

static void test_selected_access_flags(void) {
    struct stat baseline = {0};
    baseline.st_dev = 1;
    baseline.st_ino = 2;
    baseline.st_gen = 3;
    baseline.st_mode = S_IFDIR | 0700;
    baseline.st_uid = geteuid();
    baseline.st_gid = getegid();
    struct stat changed = baseline;
    changed.st_flags = UF_HIDDEN | UF_NODUMP;
    if (!same_directory_access(&baseline, &changed))
        test_fail("benign hidden/nodump flags changed directory access proof");
    changed.st_flags |= UF_IMMUTABLE;
    if (same_directory_access(&baseline, &changed))
        test_fail("immutable flag drift retained directory access proof");
}

static void test_copy_time_touch(const char *root) {
    char case_root[PATH_MAX], source_path[PATH_MAX], destination_path[PATH_MAX];
    join_test_path(case_root, root, "copy-time-touch");
    join_test_path(source_path, case_root, "source");
    join_test_path(destination_path, case_root, "destination");
    make_test_directory(case_root);
    make_test_directory(source_path);
    make_test_directory(destination_path);
    int source = open(source_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int destination = open(destination_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (source < 0 || destination < 0) test_fail("cannot bind copy-time-touch fixture");
    size_t index = (size_t)artifact_index("VERSION");
    int fixture = openat(source, k_artifacts[index].name,
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         k_artifacts[index].mode);
    static const char bytes[] = "0.1.0\n";
    if (fixture < 0 ||
        write(fixture, bytes, sizeof(bytes) - 1) != (ssize_t)(sizeof(bytes) - 1) ||
        fchmod(fixture, k_artifacts[index].mode) != 0 || fsync(fixture) != 0 ||
        close(fixture) != 0)
        test_fail("cannot create copy-time-touch artifact");
    copy_touch_enabled = true;
    copy_file_stable(source, destination, index);
    if (copy_touch_enabled) test_fail("copy-time-touch hook was not invoked");
    int copied = open_artifact(destination, index, O_RDONLY);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    unsigned char expected_digest[CC_SHA256_DIGEST_LENGTH];
    off_t size = 0;
    digest_artifact_fd(copied, k_artifacts[index].maximum_size, digest, &size);
    if (CC_SHA256(bytes, (CC_LONG)(sizeof(bytes) - 1), expected_digest) == NULL)
        test_fail("cannot hash expected copy-time-touch content");
    close(copied);
    close(destination);
    close(source);
    if (size != (off_t)(sizeof(bytes) - 1) ||
        memcmp(digest, expected_digest, sizeof(digest)) != 0)
        test_fail("copy-time-touch changed copied content");
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: diskplan-fs-helper-tests /absolute/test/root\n");
        return 64;
    }
    test_ancestor_replacement(argv[1]);
    test_ancestor_access_policy_change(argv[1]);
    test_mount_boundary_change(argv[1]);
    test_managed_child_slot_replacement(argv[1], "managed-bin-slot", "bin");
    test_managed_child_slot_replacement(argv[1], "managed-libexec-slot", "libexec");
    test_managed_child_slot_replacement(argv[1], "managed-root-slot", "diskplan");
    test_managed_child_access_policy_change(argv[1]);
    test_removed_managed_slot_repopulation(argv[1]);
    test_selected_access_flags();
    test_copy_time_touch(argv[1]);
    puts("fs-helper ancestor, child-slot, mount, flags, and copy tests passed");
    return 0;
}
