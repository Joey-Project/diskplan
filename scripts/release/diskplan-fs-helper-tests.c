#define DISKPLAN_FS_HELPER_TESTING 1
#include <sys/wait.h>
#define main diskplan_fs_helper_program_main
#include "diskplan-fs-helper.c"
#undef main

static bool copy_touch_enabled = false;
static bool remove_replace_enabled = false;
static bool delete_receipt_replace_enabled = false;

void diskplan_copy_test_hook(int source_fd) {
    if (!copy_touch_enabled) return;
    struct stat metadata;
    if (fstat(source_fd, &metadata) != 0) abort();
    struct timespec times[2] = {metadata.st_atimespec, metadata.st_mtimespec};
    times[1].tv_sec += 1;
    if (futimens(source_fd, times) != 0) abort();
    copy_touch_enabled = false;
}

void diskplan_remove_test_hook(int parent_fd, const char *quarantine,
                               const char *original) {
    (void)original;
    if (!remove_replace_enabled) return;
    if (renameat(parent_fd, quarantine, parent_fd, ".retained-owned-artifact") != 0)
        abort();
    int replacement = openat(parent_fd, quarantine,
                             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                             0644);
    static const char bytes[] = "replacement\n";
    if (replacement < 0 ||
        write(replacement, bytes, sizeof(bytes) - 1) !=
            (ssize_t)(sizeof(bytes) - 1) ||
        close(replacement) != 0)
        abort();
    remove_replace_enabled = false;
}

void diskplan_delete_receipt_test_hook(int directory_fd) {
    if (!delete_receipt_replace_enabled) return;
    if (renameat(directory_fd, "VERSION", directory_fd, ".receipt-owned-version") != 0)
        abort();
    int replacement = openat(directory_fd, "VERSION",
                             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                             0644);
    static const char bytes[] = "replacement\n";
    if (replacement < 0 ||
        write(replacement, bytes, sizeof(bytes) - 1) !=
            (ssize_t)(sizeof(bytes) - 1) ||
        close(replacement) != 0)
        abort();
    delete_receipt_replace_enabled = false;
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

static void add_test_acl(const char *path) {
    pid_t child = fork();
    if (child < 0) test_fail("cannot fork ACL fixture helper");
    if (child == 0) {
        execl("/bin/chmod", "chmod", "+a", "everyone allow read", path, NULL);
        _exit(127);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        test_fail("cannot add ACL fixture");
}

static void test_acl_contract(const char *root) {
    char case_root[PATH_MAX], file_path[PATH_MAX];
    join_test_path(case_root, root, "acl-contract");
    join_test_path(file_path, case_root, "record");
    make_test_directory(case_root);
    int file = open(file_path, O_RDONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    int directory = open(case_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (file < 0 || directory < 0) test_fail("cannot create ACL contract fixture");
    if (probe_fd_acl(file) != ACL_PROBE_FREE ||
        probe_fd_acl(directory) != ACL_PROBE_FREE)
        test_fail("ACL-free fixture did not report free");
    if (probe_fd_acl(-1) != ACL_PROBE_ERROR)
        test_fail("ACL API failure did not remain distinct");
    add_test_acl(file_path);
    add_test_acl(case_root);
    if (probe_fd_acl(file) != ACL_PROBE_PRESENT ||
        probe_fd_acl(directory) != ACL_PROBE_PRESENT || !fd_has_acl(file) ||
        cleanup_acl_free(directory))
        test_fail("extended ACL fixture was not rejected");
    close(file);
    close(directory);
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
    int fixture = openat(source, k_artifacts[index].path,
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

static void test_nested_artifact_copy(const char *root) {
    char case_root[PATH_MAX], source_path[PATH_MAX], destination_path[PATH_MAX];
    join_test_path(case_root, root, "nested-artifact-copy");
    join_test_path(source_path, case_root, "source");
    join_test_path(destination_path, case_root, "destination");
    make_test_directory(case_root);
    make_test_directory(source_path);
    make_test_directory(destination_path);
    int source = open(source_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int destination =
        open(destination_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (source < 0 || destination < 0) test_fail("cannot bind nested-copy fixture");
    create_nested_bundle_directories(source);
    create_nested_bundle_directories(destination);
    size_t index = (size_t)artifact_index("rules/builtin-v1.json");
    char artifact_path[PATH_MAX];
    char *leaf = NULL;
    int parent = open_artifact_parent(source, index, false, artifact_path, &leaf);
    int fixture = openat(parent, leaf,
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         k_artifacts[index].mode);
    static const char bytes[] = "{\"rules\":[]}\n";
    if (fixture < 0 ||
        write(fixture, bytes, sizeof(bytes) - 1) != (ssize_t)(sizeof(bytes) - 1) ||
        fchmod(fixture, k_artifacts[index].mode) != 0 || fsync(fixture) != 0 ||
        close(fixture) != 0) {
        close(parent);
        test_fail("cannot create nested-copy source artifact");
    }
    close(parent);
    copy_file_stable(source, destination, index);
    int copied = open_artifact(destination, index, O_RDONLY);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    unsigned char expected_digest[CC_SHA256_DIGEST_LENGTH];
    off_t size = 0;
    digest_artifact_fd(copied, k_artifacts[index].maximum_size, digest, &size);
    if (CC_SHA256(bytes, (CC_LONG)(sizeof(bytes) - 1), expected_digest) == NULL)
        test_fail("cannot hash expected nested-copy content");
    close(copied);
    close(destination);
    close(source);
    if (size != (off_t)(sizeof(bytes) - 1) ||
        memcmp(digest, expected_digest, sizeof(digest)) != 0)
        test_fail("nested-copy changed copied content");
}

static void populate_exact_bundle(int directory) {
    create_nested_bundle_directories(directory);
    for (size_t index = 0; index < k_artifact_count; ++index) {
        char path[PATH_MAX];
        char *leaf = NULL;
        int parent = open_artifact_parent(directory, index, false, path, &leaf);
        int file = openat(parent, leaf,
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          k_artifacts[index].mode);
        static const char bytes[] = "fixture\n";
        if (file < 0 || write(file, bytes, sizeof(bytes) - 1) != (ssize_t)(sizeof(bytes) - 1) ||
            fchmod(file, k_artifacts[index].mode) != 0 || fsync(file) != 0 ||
            close(file) != 0) {
            close(parent);
            test_fail("cannot populate exact bundle fixture");
        }
        close(parent);
    }
}

static void test_exact_nested_bundle_lifecycle(const char *root) {
    char case_root[PATH_MAX], source_path[PATH_MAX], destination_path[PATH_MAX];
    join_test_path(case_root, root, "exact-nested-lifecycle");
    join_test_path(source_path, case_root, "source");
    join_test_path(destination_path, case_root, "0.1.0");
    make_test_directory(case_root);
    make_test_directory(source_path);
    make_test_directory(destination_path);
    int parent = open(case_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int source = open(source_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int destination =
        open(destination_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0 || source < 0 || destination < 0)
        test_fail("cannot bind exact nested lifecycle fixture");
    populate_exact_bundle(source);
    create_nested_bundle_directories(destination);
    require_exact_bundle_entries(source, false, true);
    char source_proof[256];
    bundle_proof(source, false, true, source_proof);
    for (size_t index = 0; index < k_artifact_count; ++index)
        copy_file_stable(source, destination, index);
    require_exact_bundle_entries(destination, false, false);
    char destination_proof[256];
    bundle_proof(destination, true, false, destination_proof);

    int extra = openat(destination, "unexpected",
                       O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (extra < 0 || close(extra) != 0) test_fail("cannot create unexpected-entry fixture");
    pid_t child = fork();
    if (child < 0) test_fail("cannot fork unexpected-entry probe");
    if (child == 0) {
        int sink = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (sink >= 0) {
            (void)dup2(sink, STDERR_FILENO);
            close(sink);
        }
        require_exact_bundle_entries(destination, false, false);
        _exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) == 0)
        test_fail("unexpected or case-fold-colliding entry was accepted");
    if (unlinkat(destination, "unexpected", 0) != 0)
        test_fail("cannot remove unexpected-entry fixture");
    require_exact_bundle_entries(destination, false, false);

    delete_exact_bundle(parent, destination, "0.1.0", destination_proof);
    struct stat removed;
    if (fstatat(parent, "0.1.0", &removed, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
        test_fail("exact nested bundle was not fully removed");
    close(destination);
    close(source);
    close(parent);
}

static void test_partial_nested_cleanup(const char *root) {
    char case_root[PATH_MAX], stage_path[PATH_MAX], sentinel_path[PATH_MAX];
    join_test_path(case_root, root, "partial-nested-cleanup");
    join_test_path(stage_path, case_root, ".install-stage-00000000000000000000000000000000");
    join_test_path(sentinel_path, case_root, "sentinel");
    make_test_directory(case_root);
    make_test_directory(stage_path);
    int parent = open(case_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int stage = open(stage_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0 || stage < 0) test_fail("cannot bind partial-cleanup fixture");
    create_nested_bundle_directories(stage);
    size_t index = (size_t)artifact_index("rules/builtin-v1.json");
    char artifact_path[PATH_MAX];
    char *leaf = NULL;
    int artifact_parent = open_artifact_parent(stage, index, false, artifact_path, &leaf);
    int sentinel = open(sentinel_path,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    static const char bytes[] = "sentinel\n";
    if (sentinel < 0 ||
        write(sentinel, bytes, sizeof(bytes) - 1) != (ssize_t)(sizeof(bytes) - 1) ||
        close(sentinel) != 0 || symlinkat(sentinel_path, artifact_parent, leaf) != 0) {
        close(artifact_parent);
        test_fail("cannot create partial-cleanup symlink fixture");
    }
    close(artifact_parent);
    cleanup_root_fd = parent;
    cleanup_stage_fd = stage;
    strcpy(cleanup_stage_name, ".install-stage-00000000000000000000000000000000");
    cleanup_partial_stage();
    int retained = open(stage_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (retained < 0) test_fail("uncertain partial cleanup removed a retained stage");
    close(retained);
    int target = open(sentinel_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char observed[sizeof(bytes)] = {0};
    if (target < 0 || read(target, observed, sizeof(bytes) - 1) != (ssize_t)(sizeof(bytes) - 1) ||
        close(target) != 0 || memcmp(observed, bytes, sizeof(bytes) - 1) != 0)
        test_fail("partial cleanup followed a hostile symlink");
}

static void test_artifact_delete_replacement_is_retained(const char *root) {
    char case_root[PATH_MAX];
    join_test_path(case_root, root, "artifact-delete-replacement");
    make_test_directory(case_root);
    int directory = open(case_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) test_fail("cannot bind artifact-delete replacement fixture");
    size_t index = (size_t)artifact_index("VERSION");
    int fixture = openat(directory, "VERSION",
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         k_artifacts[index].mode);
    static const char owned[] = "owned\n";
    if (fixture < 0 ||
        write(fixture, owned, sizeof(owned) - 1) != (ssize_t)(sizeof(owned) - 1) ||
        close(fixture) != 0)
        test_fail("cannot create artifact-delete replacement fixture");
    int held = open_artifact(directory, index, O_RDONLY);
    struct artifact_proof receipt;
    capture_held_artifact_receipt(held, index, &receipt);
    pid_t child = fork();
    if (child < 0) test_fail("cannot fork artifact-delete replacement probe");
    if (child == 0) {
        int sink = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (sink >= 0) {
            (void)dup2(sink, STDERR_FILENO);
            close(sink);
        }
        remove_replace_enabled = true;
        remove_artifact_relative(directory, index, held, &receipt);
        _exit(0);
    }
    close(held);
    int child_status = 0;
    if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) == 0)
        test_fail("artifact replacement during deletion was accepted");
    int retained = openat(directory, ".retained-owned-artifact",
                          O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char observed[sizeof(owned)] = {0};
    if (retained < 0 ||
        read(retained, observed, sizeof(owned) - 1) != (ssize_t)(sizeof(owned) - 1) ||
        close(retained) != 0 || memcmp(observed, owned, sizeof(owned) - 1) != 0)
        test_fail("owned artifact was deleted after quarantine replacement");
    struct stat original_slot;
    if (fstatat(directory, "VERSION", &original_slot, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT)
        test_fail("replacement race unexpectedly repopulated the original artifact slot");
    close(directory);
}

static void test_exact_delete_uses_preproof_receipts(const char *root) {
    char case_root[PATH_MAX], bundle_path[PATH_MAX];
    join_test_path(case_root, root, "exact-delete-receipts");
    join_test_path(bundle_path, case_root, "0.1.0");
    make_test_directory(case_root);
    make_test_directory(bundle_path);
    int parent = open(case_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int bundle = open(bundle_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0 || bundle < 0) test_fail("cannot bind exact-delete receipt fixture");
    populate_exact_bundle(bundle);
    char proof[256];
    bundle_proof(bundle, true, false, proof);
    pid_t child = fork();
    if (child < 0) test_fail("cannot fork exact-delete receipt probe");
    if (child == 0) {
        int sink = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (sink >= 0) {
            (void)dup2(sink, STDERR_FILENO);
            close(sink);
        }
        delete_receipt_replace_enabled = true;
        delete_exact_bundle(parent, bundle, "0.1.0", proof);
        _exit(0);
    }
    int child_status = 0;
    if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) == 0)
        test_fail("exact deletion accepted a post-proof replacement");
    int replacement = openat(bundle, "VERSION", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int owned = openat(bundle, ".receipt-owned-version",
                       O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (replacement < 0 || owned < 0)
        test_fail("exact deletion removed a replacement or its receipt-bound object");
    close(replacement);
    close(owned);
    close(bundle);
    close(parent);
}

static void test_partial_cleanup_requires_creation_receipt(const char *root) {
    char case_root[PATH_MAX];
    join_test_path(case_root, root, "partial-cleanup-receipts");
    make_test_directory(case_root);
    int directory = open(case_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) test_fail("cannot bind partial receipt fixture");
    size_t index = (size_t)artifact_index("VERSION");
    int file = openat(directory, "VERSION",
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (file < 0 || write(file, "owned\n", 6) != 6 || close(file) != 0)
        test_fail("cannot create partial receipt artifact");
    initialize_cleanup_receipts();
    cleanup_artifact_receipts[index] = open_artifact(directory, index, O_RDONLY);
    if (renameat(directory, "VERSION", directory, ".partial-owned-version") != 0)
        test_fail("cannot retire partial receipt artifact");
    int replacement = openat(directory, "VERSION",
                             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (replacement < 0 || write(replacement, "replacement\n", 12) != 12 ||
        close(replacement) != 0)
        test_fail("cannot create partial receipt replacement");
    cleanup_partial_artifacts(directory);
    int current = openat(directory, "VERSION", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int owned = openat(directory, ".partial-owned-version",
                       O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (current < 0 || owned < 0)
        test_fail("partial cleanup deleted an object without its creation receipt");
    close(current);
    close(owned);
    close_cleanup_receipts();
    close(directory);
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
    test_acl_contract(argv[1]);
    test_copy_time_touch(argv[1]);
    test_nested_artifact_copy(argv[1]);
    test_exact_nested_bundle_lifecycle(argv[1]);
    test_partial_nested_cleanup(argv[1]);
    test_artifact_delete_replacement_is_retained(argv[1]);
    test_exact_delete_uses_preproof_receipts(argv[1]);
    test_partial_cleanup_requires_creation_receipt(argv[1]);
    puts("fs-helper ancestor, child-slot, mount, ACL, flags, and nested lifecycle tests passed");
    return 0;
}
