#define _DARWIN_C_SOURCE 1

#include <CommonCrypto/CommonDigest.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#ifndef RENAME_EXCL
#define RENAME_EXCL 0x00000004
#endif
#ifndef RENAME_SWAP
#define RENAME_SWAP 0x00000002
#endif

#ifndef DISKPLAN_PRODUCT_VERSION
#define DISKPLAN_PRODUCT_VERSION "0.1.0"
#endif
#ifndef DISKPLAN_PROTOCOL_MAJOR
#define DISKPLAN_PROTOCOL_MAJOR 1
#endif
#ifndef DISKPLAN_PROTOCOL_MINOR
#define DISKPLAN_PROTOCOL_MINOR 3
#endif
#define DISKPLAN_FS_HELPER_ABI 1

/*
 * Protected properties and their signals:
 *
 * - Object identity is st_dev + st_ino + st_gen from descriptors opened with
 *   O_NOFOLLOW, or from fstatat(AT_SYMLINK_NOFOLLOW) for a symlink leaf.
 * - Content stability is an exact SHA-256 tree proof plus stable size. Mtime
 *   and ctime only trigger one bounded reopen and rehash; they are not proof.
 * - Access policy is the effective-UID owner, exact managed modes, one link for
 *   regular files, no extended ACL, no immutable/append/restricted/data-vault/
 *   no-unlink flags, and stable mount access flags. Managed-prefix traversal
 *   retains every ancestor and revalidates each child slot, filesystem identity,
 *   and mount boundary. Hidden/nodump flags are deliberately not access proof.
 *
 * Directory child churn is not itself treated as content mutation. Exact entry
 * enumeration and the per-leaf signals above establish the selected property.
 * Any unreadable or failed revalidation is reported as an operation failure,
 * separately from a missing object or an identity/content mismatch.
 */

struct artifact {
    const char *path;
    mode_t mode;
    off_t maximum_size;
    const char *role;
    const char *compatibility_version;
};

#define MAX_BINARY_BYTES ((off_t)512 * 1024 * 1024)
#define MAX_METADATA_BYTES ((off_t)64 * 1024)

#include "bundle-contract.generated.h"

static const size_t k_artifact_count = sizeof(k_artifacts) / sizeof(k_artifacts[0]);
static const size_t k_bundle_directory_count =
    sizeof(k_bundle_directories) / sizeof(k_bundle_directories[0]);
#define ARTIFACT_COUNT (sizeof(k_artifacts) / sizeof(k_artifacts[0]))
#define BUNDLE_DIRECTORY_COUNT \
    (sizeof(k_bundle_directories) / sizeof(k_bundle_directories[0]))
static const char *k_lock_name = ".diskplan-install.lock";

static int cleanup_root_fd = -1;
static int cleanup_stage_fd = -1;
static char cleanup_stage_name[NAME_MAX + 1];
static int cleanup_artifact_receipts[ARTIFACT_COUNT];
static int cleanup_directory_receipts[BUNDLE_DIRECTORY_COUNT];
static bool cleanup_receipts_initialized = false;
#ifdef DISKPLAN_FS_HELPER_TESTING
extern void diskplan_copy_test_hook(int source_fd);
extern void diskplan_remove_test_hook(int parent_fd, const char *quarantine,
                                      const char *original);
extern void diskplan_delete_receipt_test_hook(int directory_fd);
#endif
static int emergency_prefix_fd = -1;
static int emergency_lock_fd = -1;
static bool emergency_lock_armed = false;
static char emergency_lock_identity[128];

static void cleanup_partial_stage(void);
static void emergency_release_lock(void);

static void fatal_errno(const char *message) {
    int saved = errno;
    cleanup_partial_stage();
    emergency_release_lock();
    errno = saved;
    fprintf(stderr, "diskplan-fs-helper: %s: %s\n", message, strerror(saved));
    exit(EX_OSERR);
}

static void fatal(const char *message) {
    cleanup_partial_stage();
    emergency_release_lock();
    fprintf(stderr, "diskplan-fs-helper: %s\n", message);
    exit(EX_DATAERR);
}

static void usage(void) {
    fprintf(stderr,
            "usage: diskplan-fs-helper COMMAND ARGS...\n"
            "commands: prepare-prefix, acquire-lock, release-lock, stage-bundle, "
            "bundle-proof, publish-version, cleanup-stage, activate, uninstall\n");
    exit(EX_USAGE);
}

static bool valid_hex(const char *value, size_t length) {
    if (strlen(value) != length) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        char byte = value[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool valid_semver_identifier(const unsigned char *start, size_t length,
                                    bool prerelease) {
    if (length == 0) return false;
    bool numeric = true;
    for (size_t index = 0; index < length; ++index) {
        unsigned char byte = start[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
              (byte >= 'a' && byte <= 'z') || byte == '-')) {
            return false;
        }
        if (byte < '0' || byte > '9') numeric = false;
    }
    return !(prerelease && numeric && length > 1 && start[0] == '0');
}

static bool valid_semver(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    for (int component = 0; component < 3; ++component) {
        if (*cursor == '0') {
            ++cursor;
            if (*cursor >= '0' && *cursor <= '9') return false;
        } else if (*cursor >= '1' && *cursor <= '9') {
            do {
                ++cursor;
            } while (*cursor >= '0' && *cursor <= '9');
        } else {
            return false;
        }
        if (component < 2 && *cursor++ != '.') return false;
    }

    if (*cursor == '-') {
        ++cursor;
        for (;;) {
            const unsigned char *start = cursor;
            while (*cursor != '\0' && *cursor != '.' && *cursor != '+') ++cursor;
            if (!valid_semver_identifier(start, (size_t)(cursor - start), true)) return false;
            if (*cursor != '.') break;
            ++cursor;
        }
    }
    if (*cursor == '+') {
        ++cursor;
        for (;;) {
            const unsigned char *start = cursor;
            while (*cursor != '\0' && *cursor != '.') ++cursor;
            if (!valid_semver_identifier(start, (size_t)(cursor - start), false)) return false;
            if (*cursor == '\0') break;
            ++cursor;
        }
    }
    return *cursor == '\0';
}

static void random_hex(char output[33]) {
    unsigned char bytes[16];
    arc4random_buf(bytes, sizeof(bytes));
    for (size_t index = 0; index < sizeof(bytes); ++index) {
        snprintf(output + index * 2, 3, "%02x", bytes[index]);
    }
    output[32] = '\0';
}

static bool timespec_equal(struct timespec left, struct timespec right) {
    return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}

static uint32_t selected_access_flags(uint32_t flags) {
    uint32_t mask = UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND;
#ifdef UF_RESTRICTED
    mask |= UF_RESTRICTED;
#endif
#ifdef UF_DATAVAULT
    mask |= UF_DATAVAULT;
#endif
#ifdef SF_RESTRICTED
    mask |= SF_RESTRICTED;
#endif
#ifdef SF_NOUNLINK
    mask |= SF_NOUNLINK;
#endif
    return flags & mask;
}

static bool same_object(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_gen == right->st_gen;
}

static bool same_content_signals(const struct stat *left, const struct stat *right) {
    return same_object(left, right) && left->st_size == right->st_size &&
           left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid && left->st_nlink == right->st_nlink &&
           selected_access_flags(left->st_flags) == selected_access_flags(right->st_flags) &&
           timespec_equal(left->st_mtimespec, right->st_mtimespec) &&
           timespec_equal(left->st_ctimespec, right->st_ctimespec);
}

static bool safe_symlink_metadata(const struct stat *metadata) {
    return S_ISLNK(metadata->st_mode) && metadata->st_uid == geteuid() &&
           metadata->st_gid == getegid() &&
           selected_access_flags(metadata->st_flags) == 0;
}

static bool same_symlink_signals(const struct stat *left, const struct stat *right) {
    return same_object(left, right) && left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
           selected_access_flags(left->st_flags) == selected_access_flags(right->st_flags);
}

static void identity_string(const struct stat *metadata, char output[128]) {
    snprintf(output, 128, "%llu:%llu:%u", (unsigned long long)metadata->st_dev,
             (unsigned long long)metadata->st_ino, metadata->st_gen);
}

static void disarm_emergency_lock(void) {
    if (emergency_lock_fd >= 0) close(emergency_lock_fd);
    if (emergency_prefix_fd >= 0) close(emergency_prefix_fd);
    emergency_lock_fd = emergency_prefix_fd = -1;
    emergency_lock_armed = false;
    emergency_lock_identity[0] = '\0';
}

static void emergency_release_lock(void) {
    if (!emergency_lock_armed || emergency_prefix_fd < 0 || emergency_lock_fd < 0) return;
    char nonce[33];
    random_hex(nonce);
    char retired[NAME_MAX + 1];
    snprintf(retired, sizeof(retired), ".diskplan-lock-emergency-%s", nonce);
    if (renameatx_np(emergency_prefix_fd, k_lock_name, emergency_prefix_fd, retired,
                     RENAME_EXCL) != 0) {
        disarm_emergency_lock();
        return;
    }
    int bound = openat(emergency_prefix_fd, retired,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat metadata;
    char actual[128] = {0};
    if (bound >= 0 && fstat(bound, &metadata) == 0) identity_string(&metadata, actual);
    if (bound < 0 || strcmp(actual, emergency_lock_identity) != 0) {
        if (bound >= 0) close(bound);
        (void)renameatx_np(emergency_prefix_fd, retired, emergency_prefix_fd, k_lock_name,
                           RENAME_EXCL);
        disarm_emergency_lock();
        return;
    }
    (void)unlinkat(emergency_lock_fd, "owner", 0);
    (void)fsync(emergency_lock_fd);
    close(bound);
    close(emergency_lock_fd);
    emergency_lock_fd = -1;
    (void)unlinkat(emergency_prefix_fd, retired, AT_REMOVEDIR);
    (void)fsync(emergency_prefix_fd);
    disarm_emergency_lock();
}

static void access_identity_string(int fd, char output[192]) {
    struct stat metadata;
    if (fstat(fd, &metadata) != 0) fatal_errno("cannot stat bound descriptor");
    snprintf(output, 192, "%llu:%llu:%u:%04o:%u:%u:%x",
             (unsigned long long)metadata.st_dev, (unsigned long long)metadata.st_ino,
             metadata.st_gen, metadata.st_mode & 07777, metadata.st_uid, metadata.st_gid,
             selected_access_flags(metadata.st_flags));
}

static void require_identity(const struct stat *metadata, const char *expected) {
    char actual[128];
    identity_string(metadata, actual);
    if (strcmp(actual, expected) != 0) {
        fatal("object identity changed");
    }
}

static bool fd_has_acl(int fd) {
    errno = 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        if (errno == ENOENT || errno == ENOTSUP) {
            return false;
        }
        fatal_errno("cannot read access-control list");
    }
    acl_entry_t entry;
    int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    if (result < 0) {
        acl_free(acl);
        fatal_errno("cannot inspect access-control list");
    }
    acl_free(acl);
    return result == 1;
}

static void require_directory_policy(int fd, mode_t exact_mode, bool exact) {
    struct stat metadata;
    if (fstat(fd, &metadata) != 0) {
        fatal_errno("cannot stat directory descriptor");
    }
    mode_t mode = metadata.st_mode & 07777;
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid() ||
        metadata.st_gid != getegid() || fd_has_acl(fd) ||
        selected_access_flags(metadata.st_flags) != 0) {
        fatal("directory owner or access policy is unsafe");
    }
    if ((exact && mode != exact_mode) || (!exact && (mode & 0022) != 0)) {
        fatal("directory mode is unsafe");
    }
}

static void require_regular_policy(int fd, mode_t expected_mode) {
    struct stat metadata;
    if (fstat(fd, &metadata) != 0) {
        fatal_errno("cannot stat file descriptor");
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
        metadata.st_gid != getegid() || metadata.st_nlink != 1 ||
        (metadata.st_mode & 07777) != expected_mode || fd_has_acl(fd) ||
        selected_access_flags(metadata.st_flags) != 0) {
        fatal("file type, owner, mode, link count, or access policy is unsafe");
    }
}

static void require_archive_directory_policy(int fd) {
    struct stat metadata;
    if (fstat(fd, &metadata) != 0) {
        fatal_errno("cannot stat archive source directory descriptor");
    }
    mode_t mode = metadata.st_mode & 07777;
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_gid != 0 && metadata.st_gid != getegid()) || fd_has_acl(fd) ||
        selected_access_flags(metadata.st_flags) != 0 ||
        (mode & 0022) != 0) {
        fatal("archive source directory owner or access policy is unsafe");
    }
}

static void require_archive_regular_policy(int fd, mode_t expected_mode, const char *name) {
    struct stat metadata;
    if (fstat(fd, &metadata) != 0) {
        fatal_errno("cannot stat archive source file descriptor");
    }
    if (!S_ISREG(metadata.st_mode)) fatal("archive source artifact is not a regular file");
    if (metadata.st_uid != geteuid()) fatal("archive source artifact owner is unsafe");
    if (metadata.st_gid != 0 && metadata.st_gid != getegid())
        fatal("archive source artifact group is unsafe");
    if (metadata.st_nlink != 1) fatal("archive source artifact link count is unsafe");
    mode_t actual_mode = metadata.st_mode & 07777;
    if ((actual_mode & 0700) != (expected_mode & 0700) ||
        (actual_mode & (mode_t)~expected_mode) != 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "archive source artifact mode is unsafe: %s maximum=%04o actual=%04o", name,
                 expected_mode, actual_mode);
        fatal(message);
    }
    if (fd_has_acl(fd)) fatal("archive source artifact access-control list is unsafe");
    if (selected_access_flags(metadata.st_flags) != 0)
        fatal("archive source artifact flags are unsafe");
}

static void validate_absolute_path(const char *path) {
    size_t length = strlen(path);
    if (length < 2 || length >= PATH_MAX || path[0] != '/' || path[length - 1] == '/' ||
        strchr(path, '\n') != NULL || strstr(path, "//") != NULL) {
        fatal("path must be a normalized single-line absolute path other than /");
    }
    const char *cursor = path + 1;
    while (*cursor != '\0') {
        const char *slash = strchr(cursor, '/');
        size_t component_length = slash == NULL ? strlen(cursor) : (size_t)(slash - cursor);
        if ((component_length == 1 && cursor[0] == '.') ||
            (component_length == 2 && cursor[0] == '.' && cursor[1] == '.')) {
            fatal("path contains a dot component");
        }
        cursor = slash == NULL ? cursor + component_length : slash + 1;
    }
}

struct directory_binding {
    int fd;
    char *name;
    struct stat metadata;
    fsid_t filesystem_id;
    fsid_t parent_filesystem_id;
    unsigned long mount_access_flags;
    char *acl_text;
    dev_t parent_device;
    bool crosses_device;
    bool crosses_mount;
};

struct path_binding {
    struct directory_binding *entries;
    size_t count;
    size_t capacity;
};

struct child_directory_binding {
    int parent_fd;
    struct directory_binding entry;
    bool active;
};

static char *directory_acl_text(int fd) {
    errno = 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        if (errno == ENOENT || errno == ENOTSUP) {
            char *empty = strdup("");
            if (empty == NULL) fatal_errno("cannot allocate empty ACL binding");
            return empty;
        }
        fatal_errno("cannot read directory access-control list");
    }
    ssize_t length = 0;
    char *text = acl_to_text(acl, &length);
    if (text == NULL || length < 0) {
        if (text != NULL) acl_free(text);
        acl_free(acl);
        fatal_errno("cannot serialize directory access-control list");
    }
    char *copy = strndup(text, (size_t)length);
    acl_free(text);
    acl_free(acl);
    if (copy == NULL) fatal_errno("cannot allocate directory ACL binding");
    return copy;
}

static bool same_directory_access(const struct stat *left, const struct stat *right) {
    return same_object(left, right) && S_ISDIR(right->st_mode) &&
           left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid &&
           selected_access_flags(left->st_flags) == selected_access_flags(right->st_flags);
}

static bool same_filesystem_id(fsid_t left, fsid_t right) {
    return memcmp(&left, &right, sizeof(left)) == 0;
}

static unsigned long selected_mount_access_flags(const struct statfs *metadata) {
    return (unsigned long)metadata->f_flags &
           (MNT_RDONLY | MNT_NOEXEC | MNT_NOSUID | MNT_NODEV);
}

static void capture_directory_binding(struct directory_binding *entry, int fd, const char *name,
                                      dev_t parent_device, fsid_t parent_filesystem_id) {
    memset(entry, 0, sizeof(*entry));
    if (fstat(fd, &entry->metadata) != 0 || !S_ISDIR(entry->metadata.st_mode))
        fatal_errno("cannot bind directory component metadata");
    struct statfs filesystem;
    if (fstatfs(fd, &filesystem) != 0)
        fatal_errno("cannot bind directory component filesystem");
    entry->fd = fd;
    entry->name = name == NULL ? NULL : strdup(name);
    if (name != NULL && entry->name == NULL)
        fatal_errno("cannot allocate directory component binding");
    entry->acl_text = directory_acl_text(fd);
    entry->filesystem_id = filesystem.f_fsid;
    entry->parent_filesystem_id = parent_filesystem_id;
    entry->mount_access_flags = selected_mount_access_flags(&filesystem);
    entry->parent_device = parent_device;
    entry->crosses_device = entry->metadata.st_dev != parent_device;
    entry->crosses_mount = !same_filesystem_id(entry->filesystem_id, parent_filesystem_id);
}

static void append_directory_binding(struct path_binding *binding, int fd, const char *name,
                                     dev_t parent_device, fsid_t parent_filesystem_id) {
    if (binding->count >= binding->capacity)
        fatal("absolute path contains too many components");
    struct directory_binding *entry = &binding->entries[binding->count];
    capture_directory_binding(entry, fd, name, parent_device, parent_filesystem_id);
    binding->count += 1;
}

enum path_binding_result {
    PATH_BINDING_MATCHES,
    PATH_BINDING_MISSING,
    PATH_BINDING_MISMATCH,
    PATH_BINDING_FAILED,
};

static enum path_binding_result path_binding_failure(int saved_errno) {
    errno = saved_errno;
    return PATH_BINDING_FAILED;
}

static enum path_binding_result check_directory_binding(
    const struct directory_binding *entry, int parent_fd) {
    struct stat current;
    struct statfs current_filesystem;
    if (fstat(entry->fd, &current) != 0) return path_binding_failure(errno);
    if (!same_directory_access(&entry->metadata, &current)) return PATH_BINDING_MISMATCH;
    if (fstatfs(entry->fd, &current_filesystem) != 0) return path_binding_failure(errno);
    if (!same_filesystem_id(entry->filesystem_id, current_filesystem.f_fsid) ||
        entry->mount_access_flags != selected_mount_access_flags(&current_filesystem))
        return PATH_BINDING_MISMATCH;
    char *acl_text = directory_acl_text(entry->fd);
    bool acl_matches = strcmp(entry->acl_text, acl_text) == 0;
    free(acl_text);
    if (!acl_matches) return PATH_BINDING_MISMATCH;

    struct stat parent_metadata;
    struct statfs parent_filesystem;
    int reopened;
    struct stat slot_metadata = {0};
    if (parent_fd < 0) {
        parent_metadata = current;
        parent_filesystem = current_filesystem;
        reopened = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } else {
        if (fstat(parent_fd, &parent_metadata) != 0 ||
            fstatfs(parent_fd, &parent_filesystem) != 0)
            return path_binding_failure(errno);
        if (fstatat(parent_fd, entry->name, &slot_metadata, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) return PATH_BINDING_MISSING;
            return path_binding_failure(errno);
        }
        if (!same_directory_access(&entry->metadata, &slot_metadata))
            return PATH_BINDING_MISMATCH;
        reopened = openat(parent_fd, entry->name,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    if (reopened < 0) {
        if (errno == ENOENT) return PATH_BINDING_MISSING;
        if (errno == ELOOP || errno == ENOTDIR) return PATH_BINDING_MISMATCH;
        return path_binding_failure(errno);
    }
    struct stat reopened_metadata;
    struct statfs reopened_filesystem;
    if (fstat(reopened, &reopened_metadata) != 0 ||
        fstatfs(reopened, &reopened_filesystem) != 0) {
        int saved = errno;
        close(reopened);
        return path_binding_failure(saved);
    }
    bool matches = same_directory_access(&entry->metadata, &reopened_metadata) &&
                   (parent_fd < 0 || same_object(&slot_metadata, &reopened_metadata)) &&
                   same_filesystem_id(entry->filesystem_id, reopened_filesystem.f_fsid) &&
                   entry->mount_access_flags == selected_mount_access_flags(&reopened_filesystem);
    if (matches) {
        char *reopened_acl = directory_acl_text(reopened);
        matches = strcmp(entry->acl_text, reopened_acl) == 0;
        free(reopened_acl);
    }
    int close_result = close(reopened);
    if (!matches) return PATH_BINDING_MISMATCH;
    if (close_result != 0) return path_binding_failure(errno);

    if (entry->parent_device != parent_metadata.st_dev ||
        entry->crosses_device != (current.st_dev != parent_metadata.st_dev) ||
        !same_filesystem_id(entry->parent_filesystem_id, parent_filesystem.f_fsid) ||
        entry->crosses_mount !=
            !same_filesystem_id(current_filesystem.f_fsid, parent_filesystem.f_fsid))
        return PATH_BINDING_MISMATCH;
    return PATH_BINDING_MATCHES;
}

static enum path_binding_result check_path_binding(const struct path_binding *binding) {
    if (binding->count == 0) return PATH_BINDING_MISMATCH;
    for (size_t index = 0; index < binding->count; ++index) {
        const struct directory_binding *entry = &binding->entries[index];
        enum path_binding_result result =
            check_directory_binding(entry, index == 0 ? -1 : binding->entries[index - 1].fd);
        if (result != PATH_BINDING_MATCHES) return result;
    }
    return PATH_BINDING_MATCHES;
}

static struct child_directory_binding bind_child_directory(int parent_fd, int fd,
                                                           const char *name) {
    struct stat parent_metadata;
    struct statfs parent_filesystem;
    if (fstat(parent_fd, &parent_metadata) != 0 ||
        fstatfs(parent_fd, &parent_filesystem) != 0)
        fatal_errno("cannot bind managed child parent");
    int retained_parent = dup(parent_fd);
    if (retained_parent < 0) fatal_errno("cannot retain managed child parent");
    struct child_directory_binding binding = {
        .parent_fd = retained_parent,
        .active = true,
    };
    capture_directory_binding(&binding.entry, fd, name, parent_metadata.st_dev,
                              parent_filesystem.f_fsid);
    if (check_directory_binding(&binding.entry, binding.parent_fd) != PATH_BINDING_MATCHES)
        fatal("managed child slot changed while binding");
    return binding;
}

static enum path_binding_result check_child_directory_binding(
    const struct child_directory_binding *binding) {
    if (!binding->active) {
        if (binding->parent_fd < 0 || binding->entry.name == NULL) {
            errno = EBADF;
            return PATH_BINDING_FAILED;
        }
        struct stat metadata;
        if (fstatat(binding->parent_fd, binding->entry.name, &metadata,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) return PATH_BINDING_MATCHES;
            return path_binding_failure(errno);
        }
        return PATH_BINDING_MISMATCH;
    }
    return check_directory_binding(&binding->entry, binding->parent_fd);
}

static void mark_child_directory_removed(struct child_directory_binding *binding) {
    if (!binding->active) fatal("managed child slot was already marked absent");
    if (binding->entry.fd >= 0 && close(binding->entry.fd) != 0)
        fatal_errno("cannot close removed managed child descriptor");
    binding->entry.fd = -1;
    binding->active = false;
    enum path_binding_result result = check_child_directory_binding(binding);
    if (result == PATH_BINDING_MISMATCH)
        fatal("removed managed child slot was unexpectedly repopulated");
    if (result == PATH_BINDING_MISSING)
        fatal("removed managed child slot reported an inconsistent missing state");
    if (result == PATH_BINDING_FAILED)
        fatal_errno("cannot prove removed managed child slot is absent");
}

static void close_child_directory_binding(struct child_directory_binding *binding) {
    if (binding->active && binding->entry.fd >= 0) close(binding->entry.fd);
    if (binding->parent_fd >= 0) close(binding->parent_fd);
    free(binding->entry.name);
    free(binding->entry.acl_text);
    memset(&binding->entry, 0, sizeof(binding->entry));
    binding->entry.fd = -1;
    binding->parent_fd = -1;
    binding->active = false;
}

static void require_current_path_binding(const struct path_binding *binding) {
    switch (check_path_binding(binding)) {
        case PATH_BINDING_MATCHES:
            return;
        case PATH_BINDING_MISSING:
            fatal("managed prefix ancestor or child slot is missing");
            return;
        case PATH_BINDING_MISMATCH:
            fatal("managed prefix ancestor identity, access policy, or mount boundary changed");
            return;
        case PATH_BINDING_FAILED:
            fatal_errno("cannot revalidate managed prefix ancestor chain");
            return;
    }
}

static void close_path_binding(struct path_binding *binding) {
    for (size_t index = binding->count; index > 0; --index) {
        struct directory_binding *entry = &binding->entries[index - 1];
        if (entry->fd >= 0) close(entry->fd);
        free(entry->name);
        free(entry->acl_text);
    }
    free(binding->entries);
    binding->entries = NULL;
    binding->count = binding->capacity = 0;
}

static struct path_binding bind_absolute_directory(const char *path, bool create) {
    validate_absolute_path(path);
    struct path_binding binding = {0};
    binding.capacity = strlen(path) + 1;
    binding.entries = calloc(binding.capacity, sizeof(*binding.entries));
    if (binding.entries == NULL) fatal_errno("cannot allocate absolute path binding");
    int current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (current < 0) fatal_errno("cannot open filesystem root");
    struct stat root_metadata;
    struct statfs root_filesystem;
    if (fstat(current, &root_metadata) != 0) fatal_errno("cannot stat filesystem root");
    if (fstatfs(current, &root_filesystem) != 0)
        fatal_errno("cannot stat filesystem root mount");
    append_directory_binding(&binding, current, NULL, root_metadata.st_dev,
                             root_filesystem.f_fsid);

    char *copy = strdup(path + 1);
    if (copy == NULL) fatal_errno("cannot allocate path buffer");
    char *state = NULL;
    for (char *component = strtok_r(copy, "/", &state); component != NULL;
         component = strtok_r(NULL, "/", &state)) {
        int next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && errno == ENOENT && create) {
            bool created = mkdirat(current, component, 0755) == 0;
            if (!created && errno != EEXIST) fatal_errno("cannot create path component");
            next = openat(current, component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (created && next >= 0 && fchmod(next, 0755) != 0)
                fatal_errno("cannot set path component mode");
            if (fsync(current) != 0) fatal_errno("cannot sync created path component");
        }
        if (next < 0) fatal_errno("cannot open path component without following links");
        struct stat slot, child;
        if (fstatat(current, component, &slot, AT_SYMLINK_NOFOLLOW) != 0 ||
            fstat(next, &child) != 0 || !same_object(&slot, &child) ||
            !S_ISDIR(slot.st_mode))
            fatal("directory child slot identity changed while binding");
        append_directory_binding(&binding, next, component,
                                 binding.entries[binding.count - 1].metadata.st_dev,
                                 binding.entries[binding.count - 1].filesystem_id);
        current = next;
    }
    free(copy);
    require_current_path_binding(&binding);
    return binding;
}

static int open_absolute_directory(const char *path, bool create) {
    validate_absolute_path(path);
    int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) {
        fatal_errno("cannot open filesystem root");
    }
    char *copy = strdup(path + 1);
    if (copy == NULL) {
        close(current);
        fatal_errno("cannot allocate path buffer");
    }
    char *state = NULL;
    for (char *component = strtok_r(copy, "/", &state); component != NULL;
         component = strtok_r(NULL, "/", &state)) {
        int next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && errno == ENOENT && create) {
            bool created = mkdirat(current, component, 0755) == 0;
            if (!created && errno != EEXIST) {
                free(copy);
                close(current);
                fatal_errno("cannot create path component");
            }
            next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (created && next >= 0 && fchmod(next, 0755) != 0) {
                free(copy);
                close(next);
                close(current);
                fatal_errno("cannot set path component mode");
            }
            if (fsync(current) != 0) {
                free(copy);
                close(next);
                close(current);
                fatal_errno("cannot sync created path component");
            }
        }
        if (next < 0) {
            free(copy);
            close(current);
            fatal_errno("cannot open path component without following links");
        }
        close(current);
        current = next;
    }
    free(copy);
    return current;
}

static int ensure_directory_at(int parent, const char *name, mode_t mode, bool shared, bool create) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && create) {
        if (mkdirat(parent, name, mode) != 0) {
            fatal_errno("cannot create managed directory");
        }
        fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 || fchmod(fd, mode) != 0 || fsync(parent) != 0) {
            fatal_errno("cannot bind created managed directory");
        }
    } else if (fd < 0) {
        fatal_errno("cannot open managed directory without following links");
    }
    require_directory_policy(fd, mode, !shared);
    return fd;
}

struct managed {
    struct path_binding prefix_path;
    int prefix;
    int bin;
    int libexec;
    int root;
    struct child_directory_binding bin_slot;
    struct child_directory_binding libexec_slot;
    struct child_directory_binding root_slot;
};

static void close_managed(struct managed *managed);

static void require_child_binding(const struct child_directory_binding *binding,
                                  const char *label) {
    switch (check_child_directory_binding(binding)) {
        case PATH_BINDING_MATCHES:
            return;
        case PATH_BINDING_MISSING: {
            char message[192];
            snprintf(message, sizeof(message), "managed %s child slot is missing", label);
            fatal(message);
        }
        case PATH_BINDING_MISMATCH: {
            char message[256];
            snprintf(message, sizeof(message),
                     "managed %s child identity, access policy, or mount boundary changed",
                     label);
            fatal(message);
        }
        case PATH_BINDING_FAILED: {
            char message[192];
            snprintf(message, sizeof(message), "cannot revalidate managed %s child slot", label);
            fatal_errno(message);
        }
    }
}

static void require_current_managed(const struct managed *managed) {
    require_current_path_binding(&managed->prefix_path);
    require_directory_policy(managed->prefix, 0, false);
    require_child_binding(&managed->bin_slot, "bin");
    require_child_binding(&managed->libexec_slot, "libexec");
    require_child_binding(&managed->root_slot, "libexec/diskplan");
    if (managed->bin_slot.active) require_directory_policy(managed->bin, 0755, false);
    if (managed->libexec_slot.active)
        require_directory_policy(managed->libexec, 0755, false);
    if (managed->root_slot.active) require_directory_policy(managed->root, 0700, true);
}

static void managed_identity_string(const struct managed *managed, char output[1024]) {
    require_current_managed(managed);
    char prefix[192], bin[192], libexec[192], root[192];
    access_identity_string(managed->prefix, prefix);
    access_identity_string(managed->bin, bin);
    access_identity_string(managed->libexec, libexec);
    access_identity_string(managed->root, root);
    require_current_managed(managed);
    snprintf(output, 1024, "v1|%s|%s|%s|%s", prefix, bin, libexec, root);
}

static struct managed open_managed(const char *path, const char *prefix_identity, bool create) {
    struct managed result = {.prefix_path = {0},
                             .prefix = -1,
                             .bin = -1,
                             .libexec = -1,
                             .root = -1,
                             .bin_slot = {.parent_fd = -1, .entry = {.fd = -1}},
                             .libexec_slot = {.parent_fd = -1, .entry = {.fd = -1}},
                             .root_slot = {.parent_fd = -1, .entry = {.fd = -1}}};
    result.prefix_path = bind_absolute_directory(path, create);
    result.prefix = result.prefix_path.entries[result.prefix_path.count - 1].fd;
    require_directory_policy(result.prefix, 0, false);
    result.bin = ensure_directory_at(result.prefix, "bin", 0755, true, create);
    result.bin_slot = bind_child_directory(result.prefix, result.bin, "bin");
    result.libexec = ensure_directory_at(result.prefix, "libexec", 0755, true, create);
    result.libexec_slot = bind_child_directory(result.prefix, result.libexec, "libexec");
    result.root = ensure_directory_at(result.libexec, "diskplan", 0700, false, create);
    result.root_slot = bind_child_directory(result.libexec, result.root, "diskplan");
    require_current_managed(&result);
    if (prefix_identity != NULL) {
        char actual[1024];
        managed_identity_string(&result, actual);
        if (strcmp(actual, prefix_identity) != 0) {
            close_managed(&result);
            fatal("managed prefix or ancestor identity/access policy changed");
        }
    }
    return result;
}

static void close_managed(struct managed *managed) {
    require_current_managed(managed);
    close_child_directory_binding(&managed->root_slot);
    close_child_directory_binding(&managed->libexec_slot);
    close_child_directory_binding(&managed->bin_slot);
    close_path_binding(&managed->prefix_path);
    managed->root = managed->libexec = managed->bin = managed->prefix = -1;
}

static int artifact_index(const char *path) {
    for (size_t index = 0; index < k_artifact_count; ++index) {
        if (strcmp(path, k_artifacts[index].path) == 0) {
            return (int)index;
        }
    }
    return -1;
}

static int bundle_directory_index(const char *path) {
    for (size_t index = 0; index < k_bundle_directory_count; ++index) {
        if (strcmp(path, k_bundle_directories[index]) == 0) return (int)index;
    }
    return -1;
}

static bool descriptor_within_bundle_boundary(int root, int candidate) {
    struct stat root_metadata, candidate_metadata;
    struct statfs root_filesystem, candidate_filesystem;
    return fstat(root, &root_metadata) == 0 &&
           fstat(candidate, &candidate_metadata) == 0 &&
           fstatfs(root, &root_filesystem) == 0 &&
           fstatfs(candidate, &candidate_filesystem) == 0 &&
           root_metadata.st_dev == candidate_metadata.st_dev &&
           same_filesystem_id(root_filesystem.f_fsid, candidate_filesystem.f_fsid) &&
           selected_mount_access_flags(&root_filesystem) ==
               selected_mount_access_flags(&candidate_filesystem);
}

static void require_bundle_boundary(int root, int candidate) {
    if (!descriptor_within_bundle_boundary(root, candidate))
        fatal("bundle descendant crosses its root device, mount, or mount access policy");
}

static int open_bundle_directory(int root, const char *path, bool archive_source) {
    int current = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (current < 0) fatal_errno("cannot reopen bundle root descriptor");
    struct stat original, reopened;
    if (fstat(root, &original) != 0 || fstat(current, &reopened) != 0) {
        close(current);
        fatal_errno("cannot bind reopened bundle root descriptor");
    }
    if (!same_object(&original, &reopened)) {
        close(current);
        fatal("reopened bundle root identity changed");
    }
    require_bundle_boundary(root, current);
    if (archive_source)
        require_archive_directory_policy(current);
    else
        require_directory_policy(current, 0700, true);
    if (*path == '\0') return current;
    char copy[PATH_MAX];
    if (strlen(path) >= sizeof(copy)) {
        close(current);
        fatal("bundle directory path exceeds PATH_MAX");
    }
    strcpy(copy, path);
    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL) *slash = '\0';
        int next = openat(current, cursor,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            close(current);
            fatal_errno("cannot open nested bundle directory without following links");
        }
        require_bundle_boundary(root, next);
        if (archive_source)
            require_archive_directory_policy(next);
        else
            require_directory_policy(next, 0700, true);
        close(current);
        current = next;
        if (slash == NULL) return current;
        cursor = slash + 1;
    }
}

static int open_artifact_parent(int directory, size_t index, bool archive_source,
                                char path[PATH_MAX], char **leaf) {
    if (strlen(k_artifacts[index].path) >= PATH_MAX)
        fatal("bundle artifact path exceeds PATH_MAX");
    strcpy(path, k_artifacts[index].path);
    *leaf = strrchr(path, '/');
    int parent = -1;
    if (*leaf == NULL) {
        *leaf = path;
        parent = dup(directory);
    } else {
        **leaf = '\0';
        *leaf += 1;
        parent = open_bundle_directory(directory, path, archive_source);
    }
    if (parent < 0) fatal_errno("cannot bind bundle artifact parent");
    return parent;
}

static int open_artifact_kind(int directory, size_t index, int flags,
                              bool archive_source) {
    char path[PATH_MAX];
    char *leaf = NULL;
    int parent = open_artifact_parent(directory, index, archive_source, path, &leaf);
    int fd = openat(parent, leaf, flags | O_NOFOLLOW | O_CLOEXEC);
    require_bundle_boundary(directory, parent);
    close(parent);
    if (fd < 0) {
        fatal_errno("cannot open bundle artifact without following links");
    }
    if (archive_source)
        require_archive_regular_policy(fd, k_artifacts[index].mode,
                                       k_artifacts[index].path);
    else
        require_regular_policy(fd, k_artifacts[index].mode);
    require_bundle_boundary(directory, fd);
    struct stat metadata;
    if (fstat(fd, &metadata) != 0) {
        close(fd);
        fatal_errno("cannot stat bounded bundle artifact");
    }
    if (metadata.st_size < 0 || metadata.st_size > k_artifacts[index].maximum_size) {
        close(fd);
        fatal("bundle artifact exceeds its packaged size limit");
    }
    return fd;
}

static int open_artifact(int directory, size_t index, int flags) {
    return open_artifact_kind(directory, index, flags, false);
}

static int open_archive_artifact(int directory, size_t index, int flags) {
    return open_artifact_kind(directory, index, flags, true);
}

static void require_exact_bundle_entries(int directory, bool allow_partial,
                                         bool archive_source) {
    bool seen[sizeof(k_artifacts) / sizeof(k_artifacts[0])] = {false};
    bool seen_directories[sizeof(k_bundle_directories) /
                          sizeof(k_bundle_directories[0])] = {false};
    for (size_t pass = 0; pass <= k_bundle_directory_count; ++pass) {
        const char *relative = pass == 0 ? "" : k_bundle_directories[pass - 1];
        int bound = pass == 0 ? open_bundle_directory(directory, "", archive_source)
                              : open_bundle_directory(directory, relative, archive_source);
        DIR *stream = fdopendir(bound);
        if (stream == NULL) {
            close(bound);
            fatal_errno("cannot enumerate bundle directory");
        }
        for (;;) {
            errno = 0;
            struct dirent *entry = readdir(stream);
            if (entry == NULL) {
                if (errno != 0) {
                    int saved = errno;
                    closedir(stream);
                    errno = saved;
                    fatal_errno("cannot complete bundle enumeration");
                }
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            if (strchr(entry->d_name, '/') != NULL || entry->d_name[0] == '\0') {
                closedir(stream);
                fatal("bundle entry name is not canonical");
            }
            char child[PATH_MAX];
            int length = relative[0] == '\0'
                             ? snprintf(child, sizeof(child), "%s", entry->d_name)
                             : snprintf(child, sizeof(child), "%s/%s", relative,
                                        entry->d_name);
            if (length < 0 || (size_t)length >= sizeof(child)) {
                closedir(stream);
                fatal("bundle entry path exceeds PATH_MAX");
            }
            int artifact = artifact_index(child);
            int nested = bundle_directory_index(child);
            if (artifact >= 0) {
                if (seen[artifact]) {
                    closedir(stream);
                    fatal("bundle directory repeats an artifact");
                }
                int fd = archive_source
                             ? open_archive_artifact(directory, (size_t)artifact, O_RDONLY)
                             : open_artifact(directory, (size_t)artifact, O_RDONLY);
                close(fd);
                seen[artifact] = true;
            } else if (nested >= 0) {
                if (seen_directories[nested]) {
                    closedir(stream);
                    fatal("bundle directory repeats a nested directory");
                }
                int fd = open_bundle_directory(directory, child, archive_source);
                close(fd);
                seen_directories[nested] = true;
            } else {
                closedir(stream);
                fatal("bundle directory contains an unexpected entry");
            }
        }
        closedir(stream);
    }
    if (!allow_partial) {
        for (size_t index = 0; index < k_artifact_count; ++index) {
            if (!seen[index]) {
                char message[256];
                snprintf(message, sizeof(message), "%s bundle is missing artifact: %s",
                         archive_source ? "archive source" : "managed",
                         k_artifacts[index].path);
                fatal(message);
            }
        }
        for (size_t index = 0; index < k_bundle_directory_count; ++index) {
            if (!seen_directories[index]) fatal("bundle is missing a nested directory");
        }
    }
}

static void hash_bytes(CC_SHA256_CTX *context, const void *bytes, size_t length) {
    while (length > 0) {
        CC_LONG chunk = length > UINT32_MAX ? UINT32_MAX : (CC_LONG)length;
        if (CC_SHA256_Update(context, bytes, chunk) != 1) {
            fatal("cannot update bundle digest");
        }
        bytes = (const unsigned char *)bytes + chunk;
        length -= chunk;
    }
}

static void hash_u64(CC_SHA256_CTX *context, uint64_t value) {
    unsigned char encoded[8];
    for (size_t index = 0; index < sizeof(encoded); ++index) {
        encoded[sizeof(encoded) - index - 1] = (unsigned char)(value >> (index * 8));
    }
    hash_bytes(context, encoded, sizeof(encoded));
}

static bool same_artifact_protected_properties(const struct stat *left,
                                               const struct stat *right) {
    return same_object(left, right) && left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
           left->st_nlink == right->st_nlink &&
           selected_access_flags(left->st_flags) == selected_access_flags(right->st_flags);
}

static bool same_artifact_timestamps(const struct stat *left, const struct stat *right) {
    return timespec_equal(left->st_mtimespec, right->st_mtimespec) &&
           timespec_equal(left->st_ctimespec, right->st_ctimespec);
}

static void digest_artifact_fd(int fd, off_t maximum_size,
                               unsigned char output[CC_SHA256_DIGEST_LENGTH], off_t *size) {
    CC_SHA256_CTX digest;
    if (CC_SHA256_Init(&digest) != 1) fatal("cannot initialize artifact digest");
    unsigned char buffer[64 * 1024];
    ssize_t count;
    off_t consumed = 0;
    while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
        consumed += count;
        if (consumed > maximum_size) fatal("bundle artifact grew beyond its packaged size limit");
        hash_bytes(&digest, buffer, (size_t)count);
    }
    if (count < 0) fatal_errno("cannot read bundle artifact");
    if (CC_SHA256_Final(output, &digest) != 1) fatal("cannot finalize artifact digest");
    *size = consumed;
}

struct artifact_proof {
    struct stat metadata;
    off_t content_size;
    unsigned char sha256[CC_SHA256_DIGEST_LENGTH];
};

static void capture_artifact_proof(int directory, size_t index, bool archive_source,
                                   struct artifact_proof *proof) {
    struct stat first_before = {0};
    unsigned char first_digest[CC_SHA256_DIGEST_LENGTH] = {0};
    for (int attempt = 0; attempt < 2; ++attempt) {
        int fd = archive_source ? open_archive_artifact(directory, index, O_RDONLY)
                                : open_artifact(directory, index, O_RDONLY);
        struct stat before;
        if (fstat(fd, &before) != 0) {
            close(fd);
            fatal_errno("cannot stat bundle artifact");
        }
        if (attempt == 0)
            first_before = before;
        else if (!same_artifact_protected_properties(&first_before, &before)) {
            close(fd);
            fatal("bundle artifact identity or access policy changed before bounded rehash");
        }

        off_t content_size = 0;
        unsigned char content_digest[CC_SHA256_DIGEST_LENGTH];
        digest_artifact_fd(fd, k_artifacts[index].maximum_size, content_digest, &content_size);
        struct stat after;
        if (fstat(fd, &after) != 0) {
            close(fd);
            fatal_errno("cannot restat bundle artifact");
        }
        if (archive_source)
            require_archive_regular_policy(fd, k_artifacts[index].mode, k_artifacts[index].path);
        else
            require_regular_policy(fd, k_artifacts[index].mode);
        close(fd);
        if (!same_artifact_protected_properties(&before, &after))
            fatal("bundle artifact identity or access policy changed while hashing");
        bool stable_observation = before.st_size == after.st_size &&
                                  after.st_size == content_size &&
                                  same_artifact_timestamps(&before, &after);
        if (attempt == 0) {
            memcpy(first_digest, content_digest, sizeof(first_digest));
            if (!stable_observation) continue;
        } else {
            if (memcmp(first_digest, content_digest, sizeof(first_digest)) != 0)
                fatal("bundle artifact content changed during bounded rehash");
            if (!stable_observation)
                fatal("bundle artifact timestamps did not stabilize during bounded rehash");
        }
        proof->metadata = after;
        proof->content_size = content_size;
        memcpy(proof->sha256, content_digest, sizeof(proof->sha256));
        return;
    }
    fatal("bundle artifact could not be proven stable");
}

static void capture_held_artifact_receipt(int fd, size_t index,
                                          struct artifact_proof *proof) {
    struct stat before, after;
    if (fstat(fd, &before) != 0 || lseek(fd, 0, SEEK_SET) < 0)
        fatal_errno("cannot begin held artifact receipt");
    digest_artifact_fd(fd, k_artifacts[index].maximum_size, proof->sha256,
                       &proof->content_size);
    if (fstat(fd, &after) != 0 || lseek(fd, 0, SEEK_SET) < 0)
        fatal_errno("cannot finish held artifact receipt");
    require_regular_policy(fd, k_artifacts[index].mode);
    if (!same_artifact_protected_properties(&before, &after) ||
        !same_artifact_timestamps(&before, &after) ||
        after.st_size != proof->content_size)
        fatal("held artifact changed while its deletion receipt was captured");
    proof->metadata = after;
}

static void bundle_proof(int directory, bool managed_exact, bool archive_source,
                         char output[256]) {
    if (archive_source)
        require_archive_directory_policy(directory);
    else
        require_directory_policy(directory, 0700, managed_exact);
    require_exact_bundle_entries(directory, false, archive_source);
    struct stat directory_before;
    if (fstat(directory, &directory_before) != 0) {
        fatal_errno("cannot stat bundle directory");
    }
    CC_SHA256_CTX digest;
    if (CC_SHA256_Init(&digest) != 1) {
        fatal("cannot initialize bundle digest");
    }
    struct stat nested_before[sizeof(k_bundle_directories) /
                              sizeof(k_bundle_directories[0])];
    for (size_t index = 0; index < k_bundle_directory_count; ++index) {
        int nested = open_bundle_directory(directory, k_bundle_directories[index],
                                           archive_source);
        if (fstat(nested, &nested_before[index]) != 0) {
            close(nested);
            fatal_errno("cannot stat nested bundle directory");
        }
        close(nested);
        hash_bytes(&digest, k_bundle_directories[index],
                   strlen(k_bundle_directories[index]) + 1);
        hash_u64(&digest, (uint64_t)nested_before[index].st_dev);
        hash_u64(&digest, nested_before[index].st_ino);
        hash_u64(&digest, nested_before[index].st_gen);
        hash_u64(&digest, (uint64_t)nested_before[index].st_mode);
        hash_u64(&digest, nested_before[index].st_uid);
        hash_u64(&digest, nested_before[index].st_gid);
        hash_u64(&digest, selected_access_flags(nested_before[index].st_flags));
    }
    for (size_t index = 0; index < k_artifact_count; ++index) {
        struct artifact_proof proof;
        capture_artifact_proof(directory, index, archive_source, &proof);
        hash_bytes(&digest, k_artifacts[index].path, strlen(k_artifacts[index].path) + 1);
        hash_u64(&digest, (uint64_t)proof.metadata.st_dev);
        hash_u64(&digest, proof.metadata.st_ino);
        hash_u64(&digest, proof.metadata.st_gen);
        hash_u64(&digest, (uint64_t)proof.metadata.st_mode);
        hash_u64(&digest, proof.metadata.st_uid);
        hash_u64(&digest, proof.metadata.st_gid);
        hash_u64(&digest, proof.metadata.st_nlink);
        hash_u64(&digest, selected_access_flags(proof.metadata.st_flags));
        hash_u64(&digest, (uint64_t)proof.content_size);
        hash_bytes(&digest, proof.sha256, sizeof(proof.sha256));
    }
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    if (CC_SHA256_Final(result, &digest) != 1) {
        fatal("cannot finalize bundle digest");
    }
    struct stat directory_after;
    require_exact_bundle_entries(directory, false, archive_source);
    if (archive_source)
        require_archive_directory_policy(directory);
    else
        require_directory_policy(directory, 0700, managed_exact);
    if (fstat(directory, &directory_after) != 0) {
        fatal_errno("cannot restat bundle directory");
    }
    if (!same_object(&directory_before, &directory_after) ||
        directory_before.st_mode != directory_after.st_mode ||
        directory_before.st_uid != directory_after.st_uid ||
        directory_before.st_gid != directory_after.st_gid ||
        selected_access_flags(directory_before.st_flags) !=
            selected_access_flags(directory_after.st_flags)) {
        fatal("bundle directory identity or access policy changed");
    }
    for (size_t index = 0; index < k_bundle_directory_count; ++index) {
        int nested = open_bundle_directory(directory, k_bundle_directories[index],
                                           archive_source);
        struct stat nested_after;
        if (fstat(nested, &nested_after) != 0) {
            close(nested);
            fatal_errno("cannot restat nested bundle directory");
        }
        close(nested);
        if (!same_directory_access(&nested_before[index], &nested_after))
            fatal("nested bundle directory identity or access policy changed");
    }
    char identity[192];
    access_identity_string(directory, identity);
    size_t offset = (size_t)snprintf(output, 256, "%s:", identity);
    for (size_t index = 0; index < sizeof(result); ++index) {
        offset += (size_t)snprintf(output + offset, 256 - offset, "%02x", result[index]);
    }
}

static bool valid_bundle_name(const char *name) {
    return valid_semver(name) ||
           (strncmp(name, ".install-stage-", 15) == 0 && valid_hex(name + 15, 32));
}

static int open_named_bundle(int root, const char *name) {
    if (!valid_bundle_name(name)) {
        fatal("managed bundle name is invalid");
    }
    int fd = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        fatal_errno("cannot open managed bundle without following links");
    }
    require_directory_policy(fd, 0700, true);
    return fd;
}

static bool process_info(pid_t pid, struct kinfo_proc *process) {
    int selectors[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    size_t length = sizeof(*process);
    memset(process, 0, sizeof(*process));
    return sysctl(selectors, 4, process, &length, NULL, 0) == 0 && length != 0;
}

static bool process_start(pid_t pid, struct timeval *start) {
    struct kinfo_proc process;
    if (!process_info(pid, &process)) return false;
    *start = process.kp_proc.p_starttime;
    return true;
}

static bool process_is_ancestor(pid_t expected) {
    pid_t cursor = getppid();
    for (int depth = 0; depth < 64 && cursor > 1; ++depth) {
        if (cursor == expected) return true;
        struct kinfo_proc process;
        if (!process_info(cursor, &process)) return false;
        pid_t parent = process.kp_eproc.e_ppid;
        if (parent == cursor) return false;
        cursor = parent;
    }
    return cursor == expected;
}

struct lock_token {
    uid_t uid;
    pid_t pid;
    long long seconds;
    int microseconds;
    char nonce[33];
    char identity[128];
};

static bool parse_lock_text(const char *text, struct lock_token *token) {
    unsigned long uid_value;
    long pid_value;
    char trailing;
    int matched = sscanf(text, "v1 %lu %ld %lld %d %32[a-f0-9] %127s %c", &uid_value,
                         &pid_value, &token->seconds, &token->microseconds, token->nonce,
                         token->identity, &trailing);
    if (matched != 6 || uid_value > UINT_MAX || pid_value <= 1 || pid_value > INT_MAX ||
        !valid_hex(token->nonce, 32)) {
        return false;
    }
    token->uid = (uid_t)uid_value;
    token->pid = (pid_t)pid_value;
    return true;
}

static void read_small_file(int fd, char *output, size_t capacity) {
    ssize_t count = pread(fd, output, capacity - 1, 0);
    if (count < 0) {
        fatal_errno("cannot read lock owner record");
    }
    if ((size_t)count == capacity - 1) {
        fatal("lock owner record is too large");
    }
    output[count] = '\0';
}

static bool lock_owner_is_alive(const struct lock_token *token) {
    struct timeval start;
    return token->uid == geteuid() && process_start(token->pid, &start) &&
           start.tv_sec == token->seconds && start.tv_usec == token->microseconds;
}

static int open_lock_directory(int root, struct lock_token *record) {
    int lock = openat(root, k_lock_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (lock < 0) {
        fatal_errno("cannot open install lock without following links");
    }
    require_directory_policy(lock, 0700, true);
    struct stat metadata;
    if (fstat(lock, &metadata) != 0) {
        close(lock);
        fatal_errno("cannot stat install lock");
    }
    int owner = openat(lock, "owner", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (owner < 0) {
        close(lock);
        fatal_errno("cannot open lock owner record");
    }
    require_regular_policy(owner, 0600);
    struct stat owner_before;
    if (fstat(owner, &owner_before) != 0) {
        close(owner);
        close(lock);
        fatal_errno("cannot stat lock owner record");
    }
    char text[512];
    read_small_file(owner, text, sizeof(text));
    struct stat owner_after;
    if (fstat(owner, &owner_after) != 0) {
        close(owner);
        close(lock);
        fatal_errno("cannot restat lock owner record");
    }
    require_regular_policy(owner, 0600);
    close(owner);
    if (!same_content_signals(&owner_before, &owner_after)) {
        close(lock);
        fatal("lock owner record changed while it was read");
    }
    if (!parse_lock_text(text, record)) {
        close(lock);
        fatal("lock owner record is malformed");
    }
    char actual[128];
    identity_string(&metadata, actual);
    if (strcmp(record->identity, actual) != 0) {
        close(lock);
        fatal("lock identity record is inconsistent");
    }
    return lock;
}

static void format_lock_token(const struct lock_token *token, char output[512]) {
    snprintf(output, 512, "v1 %u %d %lld %d %s %s", token->uid, token->pid,
             token->seconds, token->microseconds, token->nonce, token->identity);
}

static int require_lock(int root, const char *expected) {
    struct lock_token actual;
    int lock = open_lock_directory(root, &actual);
    char text[512];
    format_lock_token(&actual, text);
    if (strcmp(text, expected) != 0 || !lock_owner_is_alive(&actual) ||
        !process_is_ancestor(actual.pid)) {
        close(lock);
        fatal("install lock is not owned by the calling process");
    }
    return lock;
}

static void remove_named_lock(int root, const char *name, const char *expected_identity) {
    int lock = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (lock < 0) {
        fatal_errno("cannot bind renamed lock directory");
    }
    require_directory_policy(lock, 0700, true);
    struct stat metadata;
    if (fstat(lock, &metadata) != 0) {
        close(lock);
        fatal_errno("cannot stat renamed lock directory");
    }
    require_identity(&metadata, expected_identity);
    int owner = openat(lock, "owner", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (owner < 0) {
        close(lock);
        fatal_errno("cannot bind renamed lock owner record");
    }
    require_regular_policy(owner, 0600);
    close(owner);
    if (unlinkat(lock, "owner", 0) != 0 || fsync(lock) != 0) {
        close(lock);
        fatal_errno("cannot remove renamed lock owner record");
    }
    close(lock);
    if (unlinkat(root, name, AT_REMOVEDIR) != 0 || fsync(root) != 0) {
        fatal_errno("cannot remove renamed lock directory");
    }
}

static void recover_stale_lock(int root) {
    struct lock_token record;
    int lock = open_lock_directory(root, &record);
    if (lock_owner_is_alive(&record)) {
        close(lock);
        fatal("another Diskplan install operation is active");
    }
    struct stat metadata;
    if (fstat(lock, &metadata) != 0) {
        close(lock);
        fatal_errno("cannot stat stale install lock");
    }
    close(lock);
    char stale[NAME_MAX + 1];
    char nonce[33];
    random_hex(nonce);
    snprintf(stale, sizeof(stale), ".install-lock-stale-%s", nonce);
    if (renameatx_np(root, k_lock_name, root, stale, RENAME_EXCL) != 0) {
        if (errno == ENOENT) {
            return;
        }
        fatal_errno("cannot quarantine stale install lock");
    }
    remove_named_lock(root, stale, record.identity);
}

static bool directory_is_empty(int directory) {
    int duplicate = dup(directory);
    if (duplicate < 0) fatal_errno("cannot duplicate directory for empty check");
    DIR *stream = fdopendir(duplicate);
    if (stream == NULL) {
        close(duplicate);
        fatal_errno("cannot enumerate directory for empty check");
    }
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) {
                int saved = errno;
                closedir(stream);
                errno = saved;
                fatal_errno("cannot complete empty-directory check");
            }
            closedir(stream);
            return true;
        }
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            closedir(stream);
            return false;
        }
    }
}

static bool remove_empty_bound_directory(int parent, int *directory,
                                         struct child_directory_binding *slot, const char *name,
                                         const char *temporary_prefix, mode_t mode,
                                         bool shared) {
    require_child_binding(slot, name);
    require_directory_policy(*directory, mode, !shared);
    if (!directory_is_empty(*directory)) return false;
    struct stat before;
    if (fstat(*directory, &before) != 0) fatal_errno("cannot stat empty directory");
    char before_access[192];
    access_identity_string(*directory, before_access);
    char nonce[33];
    random_hex(nonce);
    char temporary[NAME_MAX + 1];
    snprintf(temporary, sizeof(temporary), ".%s-prune-%s", temporary_prefix, nonce);
    if (renameatx_np(parent, name, parent, temporary, RENAME_EXCL) != 0)
        fatal_errno("cannot conditionally quarantine empty directory");
    int quarantined = openat(parent, temporary,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (quarantined < 0) fatal_errno("cannot bind quarantined empty directory");
    require_directory_policy(quarantined, mode, !shared);
    struct stat after;
    if (fstat(quarantined, &after) != 0) fatal_errno("cannot stat quarantined directory");
    char after_access[192];
    access_identity_string(quarantined, after_access);
    if (!same_object(&before, &after) || strcmp(before_access, after_access) != 0 ||
        !directory_is_empty(quarantined)) {
        close(quarantined);
        if (renameatx_np(parent, temporary, parent, name, RENAME_EXCL) != 0)
            fatal_errno("cannot restore directory after conditional cleanup lost identity");
        require_child_binding(slot, name);
        return false;
    }
    close(quarantined);
    if (unlinkat(parent, temporary, AT_REMOVEDIR) != 0 || fsync(parent) != 0)
        fatal_errno("cannot remove identity-proven empty directory");
    mark_child_directory_removed(slot);
    *directory = -1;
    return true;
}

static void prune_empty_managed_directories(struct managed *managed) {
    bool removed_root = remove_empty_bound_directory(
        managed->libexec, &managed->root, &managed->root_slot, "diskplan", "diskplan-root",
        0700, false);
    if (!removed_root) return;
    (void)remove_empty_bound_directory(
        managed->prefix, &managed->libexec, &managed->libexec_slot, "libexec",
        "diskplan-libexec", 0755, true);
    (void)remove_empty_bound_directory(
        managed->prefix, &managed->bin, &managed->bin_slot, "bin", "diskplan-bin", 0755,
        true);
    require_current_managed(managed);
}

static void retire_owned_lock(struct managed *managed, const struct stat *metadata) {
    char released[NAME_MAX + 1];
    char nonce[33];
    random_hex(nonce);
    snprintf(released, sizeof(released), ".diskplan-lock-released-%s", nonce);
    if (renameatx_np(managed->prefix, k_lock_name, managed->prefix, released,
                     RENAME_EXCL) != 0)
        fatal_errno("cannot retire install lock");
    char identity[128];
    identity_string(metadata, identity);
    remove_named_lock(managed->prefix, released, identity);
    disarm_emergency_lock();
}

static void split_relative_path(const char *relative, char parent[PATH_MAX],
                                const char **leaf) {
    if (strlen(relative) >= PATH_MAX) fatal("bundle relative path exceeds PATH_MAX");
    strcpy(parent, relative);
    char *separator = strrchr(parent, '/');
    if (separator == NULL) {
        *leaf = relative;
        parent[0] = '\0';
        return;
    }
    *separator = '\0';
    *leaf = relative + (separator - parent) + 1;
}

static void create_nested_bundle_directories(int root) {
    for (size_t index = 0; index < k_bundle_directory_count; ++index) {
        char parent_path[PATH_MAX];
        const char *leaf = NULL;
        split_relative_path(k_bundle_directories[index], parent_path, &leaf);
        int parent = open_bundle_directory(root, parent_path, false);
        if (mkdirat(parent, leaf, 0700) != 0) {
            close(parent);
            fatal_errno("cannot create nested staged bundle directory");
        }
        int child = openat(parent, leaf,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0 || fchown(child, geteuid(), getegid()) != 0 ||
            fchmod(child, 0700) != 0 || fsync(child) != 0 || fsync(parent) != 0) {
            if (child >= 0) close(child);
            close(parent);
            fatal_errno("cannot bind nested staged bundle directory");
        }
        require_directory_policy(child, 0700, true);
        close(child);
        close(parent);
    }
}

static void fatal_retained_quarantine(const char *quarantine, const char *reason) {
    char message[512];
    snprintf(message, sizeof(message),
             "%s; retained the unverified object as %s",
             reason, quarantine);
    fatal(message);
}

static void remove_artifact_relative(int root, size_t index, int held,
                                     const struct artifact_proof *receipt) {
    char path[PATH_MAX];
    char *leaf = NULL;
    int parent = open_artifact_parent(root, index, false, path, &leaf);
    require_regular_policy(held, k_artifacts[index].mode);
    require_bundle_boundary(root, held);
    struct stat before;
    if (fstat(held, &before) != 0) fatal_errno("cannot stat bundle artifact before deletion");
    unsigned char current_digest[CC_SHA256_DIGEST_LENGTH];
    off_t current_size = 0;
    if (lseek(held, 0, SEEK_SET) < 0) fatal_errno("cannot rewind artifact before deletion");
    digest_artifact_fd(held, k_artifacts[index].maximum_size, current_digest,
                       &current_size);
    if (lseek(held, 0, SEEK_SET) < 0) fatal_errno("cannot restore artifact descriptor offset");
    if (!same_artifact_protected_properties(&receipt->metadata, &before) ||
        current_size != receipt->content_size ||
        memcmp(current_digest, receipt->sha256, sizeof(current_digest)) != 0)
        fatal("bundle artifact identity, access policy, or content changed after proof");
    struct stat slot;
    if (fstatat(parent, leaf, &slot, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_artifact_protected_properties(&before, &slot)) {
        close(parent);
        fatal("bundle artifact slot changed before deletion quarantine");
    }

    char nonce[33];
    random_hex(nonce);
    char quarantine[NAME_MAX + 1];
    snprintf(quarantine, sizeof(quarantine), ".diskplan-artifact-remove-%s", nonce);
    if (renameatx_np(parent, leaf, parent, quarantine, RENAME_EXCL) != 0) {
        close(parent);
        fatal_errno("cannot quarantine bundle artifact before deletion");
    }
#ifdef DISKPLAN_FS_HELPER_TESTING
    diskplan_remove_test_hook(parent, quarantine, leaf);
#endif
    int rebound = openat(parent, quarantine,
                         O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    struct stat after;
    bool exact = rebound >= 0 && fstat(rebound, &after) == 0 &&
                 same_artifact_protected_properties(&before, &after) &&
                 descriptor_within_bundle_boundary(root, rebound);
    if (!exact) {
        if (rebound >= 0) close(rebound);
        fatal_retained_quarantine(
            quarantine,
            "bundle artifact identity or access policy changed during deletion");
    }
    if (unlinkat(parent, quarantine, 0) != 0 || fsync(parent) != 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "cannot remove quarantined bundle artifact %s", quarantine);
        close(parent);
        fatal_errno(message);
    }
    close(rebound);
    close(parent);
}

static void remove_nested_bundle_directories(
    int root, int receipts[BUNDLE_DIRECTORY_COUNT]) {
    for (size_t offset = k_bundle_directory_count; offset > 0; --offset) {
        const char *relative = k_bundle_directories[offset - 1];
        char parent_path[PATH_MAX];
        const char *leaf = NULL;
        split_relative_path(relative, parent_path, &leaf);
        int parent = open_bundle_directory(root, parent_path, false);
        int current = openat(parent, leaf,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int child = receipts[offset - 1];
        if (current < 0 || child < 0) {
            if (current >= 0) close(current);
            close(parent);
            fatal_errno("cannot bind nested bundle directory before deletion");
        }
        require_directory_policy(child, 0700, true);
        require_bundle_boundary(root, child);
        struct stat before, current_metadata;
        if (fstat(child, &before) != 0 || fstat(current, &current_metadata) != 0)
            fatal_errno("cannot stat nested bundle directory");
        char before_access[192];
        access_identity_string(child, before_access);
        char current_access[192];
        access_identity_string(current, current_access);
        close(current);
        if (!same_object(&before, &current_metadata) ||
            strcmp(before_access, current_access) != 0) {
            close(parent);
            fatal("nested bundle directory changed after its proof receipt");
        }
        char nonce[33];
        random_hex(nonce);
        char quarantine[NAME_MAX + 1];
        snprintf(quarantine, sizeof(quarantine), ".diskplan-directory-remove-%s", nonce);
        if (renameatx_np(parent, leaf, parent, quarantine, RENAME_EXCL) != 0) {
            close(child);
            close(parent);
            fatal_errno("cannot quarantine nested bundle directory before deletion");
        }
        int rebound = openat(parent, quarantine,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat after;
        char after_access[192] = {0};
        bool exact = rebound >= 0 && fstat(rebound, &after) == 0 &&
                     descriptor_within_bundle_boundary(root, rebound);
        if (exact) access_identity_string(rebound, after_access);
        exact = exact && same_object(&before, &after) &&
                strcmp(before_access, after_access) == 0 && directory_is_empty(rebound);
        if (!exact) {
            if (rebound >= 0) close(rebound);
            close(child);
            fatal_retained_quarantine(
                quarantine,
                "nested bundle directory identity or access policy changed during deletion");
        }
        if (unlinkat(parent, quarantine, AT_REMOVEDIR) != 0 || fsync(parent) != 0) {
            char message[256];
            snprintf(message, sizeof(message),
                     "cannot remove quarantined nested directory %s", quarantine);
            close(parent);
            fatal_errno(message);
        }
        close(rebound);
        close(child);
        receipts[offset - 1] = -1;
        close(parent);
    }
}

static bool cleanup_acl_free(int fd) {
    errno = 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (acl == NULL) return errno == ENOENT || errno == ENOTSUP;
    acl_entry_t entry;
    int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    acl_free(acl);
    return result == 0;
}

static bool cleanup_safe_directory(int fd) {
    struct stat metadata;
    return fstat(fd, &metadata) == 0 && S_ISDIR(metadata.st_mode) &&
           metadata.st_uid == geteuid() && metadata.st_gid == getegid() &&
           (metadata.st_mode & 07777) == 0700 &&
           selected_access_flags(metadata.st_flags) == 0 && cleanup_acl_free(fd);
}

static int try_open_cleanup_directory(int root, const char *path) {
    int current = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat root_metadata, reopened_metadata;
    if (current < 0 || fstat(root, &root_metadata) != 0 ||
        fstat(current, &reopened_metadata) != 0 ||
        !same_object(&root_metadata, &reopened_metadata) ||
        !cleanup_safe_directory(current) ||
        !descriptor_within_bundle_boundary(root, current)) {
        if (current >= 0) close(current);
        return -1;
    }
    if (*path == '\0') return current;
    char copy[PATH_MAX];
    if (strlen(path) >= sizeof(copy)) {
        close(current);
        return -1;
    }
    strcpy(copy, path);
    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL) *slash = '\0';
        int next = openat(current, cursor,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(current);
        if (next < 0 || !cleanup_safe_directory(next) ||
            !descriptor_within_bundle_boundary(root, next)) {
            if (next >= 0) close(next);
            return -1;
        }
        current = next;
        if (slash == NULL) return current;
        cursor = slash + 1;
    }
}

static bool cleanup_directory_empty(int directory);

static void initialize_cleanup_receipts(void) {
    for (size_t index = 0; index < ARTIFACT_COUNT; ++index)
        cleanup_artifact_receipts[index] = -1;
    for (size_t index = 0; index < BUNDLE_DIRECTORY_COUNT; ++index)
        cleanup_directory_receipts[index] = -1;
    cleanup_receipts_initialized = true;
}

static void close_cleanup_receipts(void) {
    if (!cleanup_receipts_initialized) return;
    for (size_t index = 0; index < ARTIFACT_COUNT; ++index) {
        if (cleanup_artifact_receipts[index] >= 0)
            close(cleanup_artifact_receipts[index]);
        cleanup_artifact_receipts[index] = -1;
    }
    for (size_t index = 0; index < BUNDLE_DIRECTORY_COUNT; ++index) {
        if (cleanup_directory_receipts[index] >= 0)
            close(cleanup_directory_receipts[index]);
        cleanup_directory_receipts[index] = -1;
    }
    cleanup_receipts_initialized = false;
}

static void cleanup_remove_safe_file(int root, int parent, const char *leaf,
                                     const struct stat *before) {
    char nonce[33];
    random_hex(nonce);
    char quarantine[NAME_MAX + 1];
    snprintf(quarantine, sizeof(quarantine), ".partial-artifact-cleanup-%s", nonce);
    if (renameatx_np(parent, leaf, parent, quarantine, RENAME_EXCL) != 0) return;
    int rebound = openat(parent, quarantine,
                         O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    struct stat after;
    bool exact = rebound >= 0 && fstat(rebound, &after) == 0 &&
                 same_artifact_protected_properties(before, &after) &&
                 descriptor_within_bundle_boundary(root, rebound);
    if (exact) {
        (void)unlinkat(parent, quarantine, 0);
    }
    if (rebound >= 0) close(rebound);
}

static void cleanup_remove_safe_directory(int root, int parent, const char *leaf,
                                          const struct stat *before) {
    char nonce[33];
    random_hex(nonce);
    char quarantine[NAME_MAX + 1];
    snprintf(quarantine, sizeof(quarantine), ".partial-directory-cleanup-%s", nonce);
    if (renameatx_np(parent, leaf, parent, quarantine, RENAME_EXCL) != 0) return;
    int rebound = openat(parent, quarantine,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat after;
    bool exact = rebound >= 0 && fstat(rebound, &after) == 0 &&
                 same_directory_access(before, &after) && cleanup_safe_directory(rebound) &&
                 descriptor_within_bundle_boundary(root, rebound) &&
                 cleanup_directory_empty(rebound);
    if (exact) {
        (void)unlinkat(parent, quarantine, AT_REMOVEDIR);
    }
    if (rebound >= 0) close(rebound);
}

static void cleanup_partial_artifacts(int root) {
    if (!cleanup_receipts_initialized) return;
    for (size_t index = 0; index < k_artifact_count; ++index) {
        if (cleanup_artifact_receipts[index] < 0) continue;
        char parent_path[PATH_MAX];
        const char *leaf = NULL;
        split_relative_path(k_artifacts[index].path, parent_path, &leaf);
        int parent = try_open_cleanup_directory(root, parent_path);
        if (parent < 0) continue;
        int file = openat(parent, leaf, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        struct stat metadata, receipt;
        bool safe = file >= 0 && fstat(file, &metadata) == 0 &&
                    fstat(cleanup_artifact_receipts[index], &receipt) == 0 &&
                    same_artifact_protected_properties(&receipt, &metadata) &&
                    S_ISREG(metadata.st_mode) && metadata.st_uid == geteuid() &&
                    metadata.st_gid == getegid() && metadata.st_nlink == 1 &&
                    (metadata.st_mode & 07777) == k_artifacts[index].mode &&
                    selected_access_flags(metadata.st_flags) == 0 &&
                    cleanup_acl_free(file) &&
                    descriptor_within_bundle_boundary(root, file);
        if (safe) cleanup_remove_safe_file(root, parent, leaf, &metadata);
        if (file >= 0) close(file);
        (void)fsync(parent);
        close(parent);
    }
    for (size_t offset = k_bundle_directory_count; offset > 0; --offset) {
        if (cleanup_directory_receipts[offset - 1] < 0) continue;
        char parent_path[PATH_MAX];
        const char *leaf = NULL;
        split_relative_path(k_bundle_directories[offset - 1], parent_path, &leaf);
        int parent = try_open_cleanup_directory(root, parent_path);
        if (parent < 0) continue;
        int child = openat(parent, leaf,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat metadata, receipt;
        bool safe = child >= 0 && cleanup_safe_directory(child) &&
                    fstat(child, &metadata) == 0 &&
                    fstat(cleanup_directory_receipts[offset - 1], &receipt) == 0 &&
                    same_directory_access(&receipt, &metadata) &&
                    descriptor_within_bundle_boundary(root, child) &&
                    cleanup_directory_empty(child);
        if (safe) cleanup_remove_safe_directory(root, parent, leaf, &metadata);
        if (child >= 0) close(child);
        (void)fsync(parent);
        close(parent);
    }
}

static bool cleanup_directory_empty(int directory) {
    int reopened = openat(directory, ".",
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (reopened < 0) return false;
    DIR *stream = fdopendir(reopened);
    if (stream == NULL) {
        close(reopened);
        return false;
    }
    bool empty = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) empty = false;
            break;
        }
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            empty = false;
            break;
        }
    }
    closedir(stream);
    return empty;
}

static void cleanup_partial_stage(void) {
    if (cleanup_root_fd < 0 || cleanup_stage_name[0] == '\0') {
        return;
    }
    if (cleanup_stage_fd < 0) {
        close_cleanup_receipts();
        close(cleanup_root_fd);
        cleanup_root_fd = -1;
        cleanup_stage_name[0] = '\0';
        return;
    }
    cleanup_partial_artifacts(cleanup_stage_fd);
    close_cleanup_receipts();
    (void)fsync(cleanup_stage_fd);
    struct stat held, slot;
    bool exact = cleanup_safe_directory(cleanup_stage_fd) &&
                 cleanup_directory_empty(cleanup_stage_fd) &&
                 fstat(cleanup_stage_fd, &held) == 0 &&
                 fstatat(cleanup_root_fd, cleanup_stage_name, &slot,
                         AT_SYMLINK_NOFOLLOW) == 0 &&
                 same_object(&held, &slot) && same_directory_access(&held, &slot) &&
                 descriptor_within_bundle_boundary(cleanup_root_fd, cleanup_stage_fd);
    char retired[NAME_MAX + 1] = {0};
    if (exact) {
        char nonce[33];
        random_hex(nonce);
        snprintf(retired, sizeof(retired), ".partial-stage-cleanup-%s", nonce);
        if (renameatx_np(cleanup_root_fd, cleanup_stage_name, cleanup_root_fd, retired,
                         RENAME_EXCL) == 0) {
            int rebound = openat(cleanup_root_fd, retired,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            struct stat after;
            bool committed = rebound >= 0 && cleanup_safe_directory(rebound) &&
                             cleanup_directory_empty(rebound) &&
                             fstat(rebound, &after) == 0 && same_object(&held, &after) &&
                             same_directory_access(&held, &after);
            if (committed)
                (void)unlinkat(cleanup_root_fd, retired, AT_REMOVEDIR);
            if (rebound >= 0) close(rebound);
        }
    }
    close(cleanup_stage_fd);
    cleanup_stage_fd = -1;
    (void)fsync(cleanup_root_fd);
    cleanup_root_fd = -1;
    cleanup_stage_name[0] = '\0';
}

static void copy_file_stable(int source_directory, int destination_directory, size_t index) {
    int source = open_archive_artifact(source_directory, index, O_RDONLY);
    struct stat before;
    if (fstat(source, &before) != 0) {
        close(source);
        fatal_errno("cannot stat source artifact");
    }
    char destination_path[PATH_MAX];
    char *destination_leaf = NULL;
    int destination_parent = open_artifact_parent(
        destination_directory, index, false, destination_path, &destination_leaf);
    int destination = openat(destination_parent, destination_leaf,
                             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                             k_artifacts[index].mode);
    close(destination_parent);
    if (destination < 0) {
        close(source);
        fatal_errno("cannot create staged artifact");
    }
    unsigned char buffer[64 * 1024];
    ssize_t count;
    off_t consumed = 0;
    CC_SHA256_CTX copied_digest_context;
    if (CC_SHA256_Init(&copied_digest_context) != 1)
        fatal("cannot initialize copied artifact digest");
    while ((count = read(source, buffer, sizeof(buffer))) > 0) {
        consumed += count;
        if (consumed > k_artifacts[index].maximum_size) {
            close(destination);
            close(source);
            fatal("source artifact grew beyond its packaged size limit");
        }
        ssize_t written = 0;
        while (written < count) {
            ssize_t result = write(destination, buffer + written, (size_t)(count - written));
            if (result < 0) {
                close(destination);
                close(source);
                fatal_errno("cannot write staged artifact");
            }
            written += result;
        }
        hash_bytes(&copied_digest_context, buffer, (size_t)count);
    }
    unsigned char copied_digest[CC_SHA256_DIGEST_LENGTH];
    if (CC_SHA256_Final(copied_digest, &copied_digest_context) != 1)
        fatal("cannot finalize copied artifact digest");
    if (count < 0 || fchown(destination, geteuid(), getegid()) != 0 ||
        fchmod(destination, k_artifacts[index].mode) != 0 || fsync(destination) != 0) {
        close(destination);
        close(source);
        fatal_errno("cannot finish staged artifact");
    }
    require_regular_policy(destination, k_artifacts[index].mode);
#ifdef DISKPLAN_FS_HELPER_TESTING
    diskplan_copy_test_hook(source);
#endif
    struct stat after;
    if (fstat(source, &after) != 0) {
        close(destination);
        close(source);
        fatal_errno("cannot restat source artifact");
    }
    require_archive_regular_policy(source, k_artifacts[index].mode, k_artifacts[index].path);
    close(destination);
    close(source);
    if (!same_artifact_protected_properties(&before, &after) || before.st_size != consumed ||
        after.st_size != consumed) {
        fatal("source artifact identity, access policy, or size changed while it was copied");
    }
    if (!same_artifact_timestamps(&before, &after)) {
        struct artifact_proof proof;
        capture_artifact_proof(source_directory, index, true, &proof);
        if (!same_artifact_protected_properties(&before, &proof.metadata) ||
            proof.content_size != consumed ||
            memcmp(proof.sha256, copied_digest, sizeof(copied_digest)) != 0) {
            fatal("source artifact content changed during bounded post-copy rehash");
        }
    }
}

static void delete_exact_bundle(int root, int directory, const char *name, const char *proof) {
    int artifact_receipts[ARTIFACT_COUNT];
    int directory_receipts[BUNDLE_DIRECTORY_COUNT];
    struct artifact_proof artifact_proofs[ARTIFACT_COUNT];
    for (size_t index = 0; index < k_artifact_count; ++index)
        artifact_receipts[index] = open_artifact(directory, index, O_RDONLY);
    for (size_t index = 0; index < k_bundle_directory_count; ++index)
        directory_receipts[index] = open_bundle_directory(
            directory, k_bundle_directories[index], false);
    char actual[256];
    bundle_proof(directory, true, false, actual);
    if (strcmp(actual, proof) != 0) {
        fatal("bundle proof changed before deletion");
    }
    for (size_t index = 0; index < k_artifact_count; ++index)
        capture_held_artifact_receipt(artifact_receipts[index], index,
                                      &artifact_proofs[index]);
    char confirmed[256];
    bundle_proof(directory, true, false, confirmed);
    if (strcmp(actual, confirmed) != 0)
        fatal("bundle changed while deletion receipts were captured");
#ifdef DISKPLAN_FS_HELPER_TESTING
    diskplan_delete_receipt_test_hook(directory);
#endif
    require_bundle_boundary(root, directory);
    struct stat directory_before;
    if (fstat(directory, &directory_before) != 0)
        fatal_errno("cannot stat bundle directory before deletion quarantine");
    char before_access[192];
    access_identity_string(directory, before_access);
    char nonce[33];
    random_hex(nonce);
    char quarantine[NAME_MAX + 1];
    snprintf(quarantine, sizeof(quarantine), ".diskplan-bundle-remove-%s", nonce);
    if (renameatx_np(root, name, root, quarantine, RENAME_EXCL) != 0)
        fatal_errno("cannot quarantine bundle directory before deletion");
    int rebound = openat(root, quarantine,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat directory_after;
    char after_access[192] = {0};
    bool exact = rebound >= 0 && fstat(rebound, &directory_after) == 0 &&
                 descriptor_within_bundle_boundary(root, rebound);
    if (exact) access_identity_string(rebound, after_access);
    exact = exact && same_object(&directory_before, &directory_after) &&
            strcmp(before_access, after_access) == 0;
    if (rebound >= 0) close(rebound);
    if (!exact) {
        fatal_retained_quarantine(
            quarantine,
            "bundle directory identity or access policy changed during deletion quarantine");
    }
    size_t helper_index = (size_t)artifact_index("diskplan-fs-helper");
    for (size_t index = 0; index < k_artifact_count; ++index) {
        if (index == helper_index) continue;
        remove_artifact_relative(directory, index, artifact_receipts[index],
                                 &artifact_proofs[index]);
        close(artifact_receipts[index]);
        artifact_receipts[index] = -1;
    }
    if (emergency_prefix_fd >= 0 && emergency_lock_fd >= 0)
        emergency_lock_armed = true;
    remove_artifact_relative(directory, helper_index, artifact_receipts[helper_index],
                             &artifact_proofs[helper_index]);
    close(artifact_receipts[helper_index]);
    artifact_receipts[helper_index] = -1;
    remove_nested_bundle_directories(directory, directory_receipts);
    if (fsync(directory) != 0) {
        fatal_errno("cannot sync emptied bundle directory");
    }
    struct stat metadata;
    if (fstat(directory, &metadata) != 0) {
        fatal_errno("cannot restat emptied bundle directory");
    }
    const char *separator = strchr(proof, ':');
    if (separator == NULL) {
        fatal("bundle proof is malformed");
    }
    char identity[192];
    access_identity_string(directory, identity);
    size_t identity_length = strrchr(proof, ':') - proof;
    if (strlen(identity) != identity_length || strncmp(identity, proof, identity_length) != 0) {
        fatal("bundle directory identity changed before removal");
    }
    int final_rebound = openat(root, quarantine,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat final_metadata;
    char final_access[192] = {0};
    bool final_exact = final_rebound >= 0 &&
                       fstat(final_rebound, &final_metadata) == 0 &&
                       descriptor_within_bundle_boundary(root, final_rebound) &&
                       directory_is_empty(final_rebound);
    if (final_exact) access_identity_string(final_rebound, final_access);
    final_exact = final_exact && same_object(&directory_before, &final_metadata) &&
                  strcmp(before_access, final_access) == 0;
    if (!final_exact) {
        if (final_rebound >= 0) close(final_rebound);
        fatal_retained_quarantine(
            quarantine,
            "bundle root identity or access policy changed before final removal");
    }
    if (unlinkat(root, quarantine, AT_REMOVEDIR) != 0 || fsync(root) != 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "cannot remove quarantined empty bundle directory %s", quarantine);
        close(final_rebound);
        fatal_errno(message);
    }
    close(final_rebound);
}

static void cmd_prepare_prefix(int argc, char **argv) {
    if (argc != 3) usage();
    struct managed managed = open_managed(argv[2], NULL, true);
    char identity[1024];
    managed_identity_string(&managed, identity);
    printf("%s\n", identity);
    close_managed(&managed);
}

static void cmd_bind_prefix(int argc, char **argv) {
    if (argc != 3) usage();
    struct managed managed = open_managed(argv[2], NULL, false);
    char identity[1024];
    managed_identity_string(&managed, identity);
    printf("%s\n", identity);
    close_managed(&managed);
}

static void cmd_acquire_lock(int argc, char **argv) {
    if (argc != 5) usage();
    char *end = NULL;
    long requested_pid = strtol(argv[4], &end, 10);
    if (*argv[4] == '\0' || *end != '\0' || requested_pid <= 1 || requested_pid > INT_MAX ||
        !process_is_ancestor((pid_t)requested_pid)) {
        fatal("lock owner PID must be an ancestor of the helper process");
    }
    struct managed managed = open_managed(argv[2], argv[3], false);
    for (int attempt = 0; attempt < 2; ++attempt) {
        char nonce[33];
        random_hex(nonce);
        char pending[NAME_MAX + 1];
        snprintf(pending, sizeof(pending), ".diskplan-lock-pending-%s", nonce);
        if (mkdirat(managed.prefix, pending, 0700) != 0) fatal_errno("cannot create pending lock");
        int lock = openat(managed.prefix, pending,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (lock < 0 || fchmod(lock, 0700) != 0) fatal_errno("cannot bind pending lock");
        struct stat lock_metadata;
        if (fstat(lock, &lock_metadata) != 0) fatal_errno("cannot stat pending lock");
        struct timeval start;
        if (!process_start((pid_t)requested_pid, &start)) fatal("cannot identify lock owner process");
        struct lock_token token = {.uid = geteuid(),
                                   .pid = (pid_t)requested_pid,
                                   .seconds = start.tv_sec,
                                   .microseconds = start.tv_usec};
        memcpy(token.nonce, nonce, sizeof(token.nonce));
        identity_string(&lock_metadata, token.identity);
        char text[512];
        format_lock_token(&token, text);
        int owner = openat(lock, "owner", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                           0600);
        if (owner < 0 || fchmod(owner, 0600) != 0 ||
            write(owner, text, strlen(text)) != (ssize_t)strlen(text) || fsync(owner) != 0 ||
            fsync(lock) != 0) {
            fatal_errno("cannot write pending lock owner record");
        }
        close(owner);
        close(lock);
        if (renameatx_np(managed.prefix, pending, managed.prefix, k_lock_name, RENAME_EXCL) == 0) {
            if (fsync(managed.prefix) != 0) fatal_errno("cannot sync acquired install lock");
            printf("%s\n", text);
            close_managed(&managed);
            return;
        }
        int rename_error = errno;
        remove_named_lock(managed.prefix, pending, token.identity);
        if (rename_error != EEXIST) {
            errno = rename_error;
            fatal_errno("cannot publish install lock");
        }
        recover_stale_lock(managed.prefix);
    }
    fatal("cannot acquire install lock after stale-lock recovery");
}

static void cmd_release_lock(int argc, char **argv) {
    if (argc != 5) usage();
    struct managed managed = open_managed(argv[2], argv[3], false);
    int lock = require_lock(managed.prefix, argv[4]);
    struct stat metadata;
    if (fstat(lock, &metadata) != 0) fatal_errno("cannot stat owned install lock");
    close(lock);
    prune_empty_managed_directories(&managed);
    retire_owned_lock(&managed, &metadata);
    close_managed(&managed);
}

static void cmd_stage_bundle(int argc, char **argv) {
    if (argc != 6) usage();
    struct managed managed = open_managed(argv[2], argv[3], false);
    int lock = require_lock(managed.prefix, argv[4]);
    close(lock);
    int source = open_absolute_directory(argv[5], false);
    require_archive_directory_policy(source);
    require_exact_bundle_entries(source, false, true);
    char source_before[256];
    bundle_proof(source, false, true, source_before);
    require_current_managed(&managed);
    char nonce[33];
    random_hex(nonce);
    snprintf(cleanup_stage_name, sizeof(cleanup_stage_name), ".install-stage-%s", nonce);
    cleanup_root_fd = dup(managed.root);
    if (cleanup_root_fd < 0) fatal_errno("cannot retain managed staging root descriptor");
    if (mkdirat(cleanup_root_fd, cleanup_stage_name, 0700) != 0)
        fatal_errno("cannot create staging directory");
    cleanup_stage_fd = openat(cleanup_root_fd, cleanup_stage_name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cleanup_stage_fd < 0 || fchmod(cleanup_stage_fd, 0700) != 0)
        fatal_errno("cannot bind staging directory");
    initialize_cleanup_receipts();
    create_nested_bundle_directories(cleanup_stage_fd);
    for (size_t index = 0; index < k_bundle_directory_count; ++index) {
        cleanup_directory_receipts[index] = open_bundle_directory(
            cleanup_stage_fd, k_bundle_directories[index], false);
    }
    for (size_t index = 0; index < k_artifact_count; ++index) {
        copy_file_stable(source, cleanup_stage_fd, index);
        cleanup_artifact_receipts[index] = open_artifact(
            cleanup_stage_fd, index, O_RDONLY);
    }
    if (fsync(cleanup_stage_fd) != 0) fatal_errno("cannot sync staged bundle");
    char source_after[256];
    bundle_proof(source, false, true, source_after);
    if (strcmp(source_before, source_after) != 0)
        fatal("source bundle changed while staging");
    char staged_proof[256];
    bundle_proof(cleanup_stage_fd, true, false, staged_proof);
    printf("%s\t%s\n", cleanup_stage_name, staged_proof);
    close(source);
    close_cleanup_receipts();
    close(cleanup_stage_fd);
    cleanup_stage_fd = -1;
    close(cleanup_root_fd);
    cleanup_root_fd = -1;
    cleanup_stage_name[0] = '\0';
    require_current_managed(&managed);
    close_managed(&managed);
}

static void cmd_bundle_proof(int argc, char **argv) {
    if (argc != 7) usage();
    struct managed managed = open_managed(argv[2], argv[3], false);
    int lock = require_lock(managed.prefix, argv[4]);
    close(lock);
    int bundle = open_named_bundle(managed.root, argv[5]);
    char proof[256];
    bundle_proof(bundle, true, false, proof);
    if (strcmp(argv[6], "-") != 0 && strcmp(argv[6], proof) != 0)
        fatal("bundle proof does not match expected identity and content");
    printf("%s\n", proof);
    close(bundle);
    close_managed(&managed);
}

static void cmd_publish_version(int argc, char **argv) {
    if (argc != 8) usage();
    if (strncmp(argv[5], ".install-stage-", 15) != 0 || !valid_hex(argv[5] + 15, 32) ||
        !valid_semver(argv[7])) fatal("publish names are invalid");
    struct managed managed = open_managed(argv[2], argv[3], false);
    int lock = require_lock(managed.prefix, argv[4]);
    close(lock);
    int stage = open_named_bundle(managed.root, argv[5]);
    char proof[256];
    bundle_proof(stage, true, false, proof);
    if (strcmp(proof, argv[6]) != 0) fatal("staged bundle proof changed before publication");
    require_current_managed(&managed);
    if (renameatx_np(managed.root, argv[5], managed.root, argv[7], RENAME_EXCL) != 0) {
        if (errno == EEXIST) {
            close(stage);
            close_managed(&managed);
            exit(17);
        }
        fatal_errno("cannot publish version directory exclusively");
    }
    if (fsync(managed.root) != 0) fatal_errno("cannot sync published version directory");
    int published = open_named_bundle(managed.root, argv[7]);
    char published_proof[256];
    bundle_proof(published, true, false, published_proof);
    if (strcmp(proof, published_proof) != 0) fatal("published bundle identity proof changed");
    require_current_managed(&managed);
    printf("%s\n", published_proof);
    close(published);
    close(stage);
    close_managed(&managed);
}

static void cmd_cleanup_stage(int argc, char **argv) {
    if (argc != 7) usage();
    if (strncmp(argv[5], ".install-stage-", 15) != 0 || !valid_hex(argv[5] + 15, 32))
        fatal("staging name is invalid");
    struct managed managed = open_managed(argv[2], argv[3], false);
    int lock = require_lock(managed.prefix, argv[4]);
    close(lock);
    int stage = open_named_bundle(managed.root, argv[5]);
    require_current_managed(&managed);
    delete_exact_bundle(managed.root, stage, argv[5], argv[6]);
    require_current_managed(&managed);
    close(stage);
    close_managed(&managed);
}

static void read_symlink_at(int directory, const char *name, char output[PATH_MAX]) {
    ssize_t count = readlinkat(directory, name, output, PATH_MAX - 1);
    if (count < 0) fatal_errno("cannot read launcher symbolic link");
    output[count] = '\0';
}

static void cmd_activate(int argc, char **argv) {
    if (argc != 7) usage();
    if (!valid_semver(argv[5])) fatal("activation version is invalid");
    struct managed managed = open_managed(argv[2], argv[3], false);
    int lock = require_lock(managed.prefix, argv[4]);
    close(lock);
    int bundle = open_named_bundle(managed.root, argv[5]);
    char proof[256];
    bundle_proof(bundle, true, false, proof);
    if (strcmp(proof, argv[6]) != 0) fatal("bundle proof changed before activation");
    close(bundle);
    require_current_managed(&managed);
    char target[PATH_MAX];
    snprintf(target, sizeof(target), "../libexec/diskplan/%s/diskplan", argv[5]);
    struct stat old_metadata;
    bool had_old = fstatat(managed.bin, "diskplan", &old_metadata, AT_SYMLINK_NOFOLLOW) == 0;
    char old_target[PATH_MAX] = {0};
    if (had_old) {
        if (!safe_symlink_metadata(&old_metadata))
            fatal("refusing to replace a launcher with unsafe type, owner, or flags");
        read_symlink_at(managed.bin, "diskplan", old_target);
        if (strcmp(old_target, target) == 0) {
            close_managed(&managed);
            return;
        }
    } else if (errno != ENOENT) {
        fatal_errno("cannot inspect launcher without following it");
    }
    char nonce[33];
    random_hex(nonce);
    char temporary[NAME_MAX + 1];
    snprintf(temporary, sizeof(temporary), ".diskplan-link-%s", nonce);
    if (symlinkat(target, managed.bin, temporary) != 0) fatal_errno("cannot create launcher link");
    if (!had_old) {
        if (renameatx_np(managed.bin, temporary, managed.bin, "diskplan", RENAME_EXCL) != 0) {
            int saved = errno;
            unlinkat(managed.bin, temporary, 0);
            errno = saved;
            fatal_errno("cannot publish launcher exclusively");
        }
    } else {
        struct stat current;
        if (fstatat(managed.bin, "diskplan", &current, AT_SYMLINK_NOFOLLOW) != 0 ||
            !safe_symlink_metadata(&current) || !same_symlink_signals(&old_metadata, &current)) {
            unlinkat(managed.bin, temporary, 0);
            fatal("launcher identity changed before replacement");
        }
        char current_target[PATH_MAX];
        read_symlink_at(managed.bin, "diskplan", current_target);
        if (strcmp(current_target, old_target) != 0) {
            unlinkat(managed.bin, temporary, 0);
            fatal("launcher target changed before replacement");
        }
        if (renameatx_np(managed.bin, temporary, managed.bin, "diskplan", RENAME_SWAP) != 0)
            fatal_errno("cannot atomically exchange launcher");
        struct stat displaced;
        char displaced_target[PATH_MAX];
        bool displaced_matches =
            fstatat(managed.bin, temporary, &displaced, AT_SYMLINK_NOFOLLOW) == 0 &&
            safe_symlink_metadata(&displaced) && same_symlink_signals(&old_metadata, &displaced);
        if (displaced_matches) {
            read_symlink_at(managed.bin, temporary, displaced_target);
            displaced_matches = strcmp(displaced_target, old_target) == 0;
        }
        if (!displaced_matches) {
            (void)renameatx_np(managed.bin, temporary, managed.bin, "diskplan", RENAME_SWAP);
            fatal("launcher replacement lost its conditional identity proof");
        }
        if (unlinkat(managed.bin, temporary, 0) != 0)
            fatal_errno("cannot remove displaced launcher");
    }
    if (fsync(managed.bin) != 0) fatal_errno("cannot sync activated launcher");
    require_current_managed(&managed);
    close_managed(&managed);
}

static void remove_matching_launcher(int bin, const char *expected_target) {
    struct stat metadata;
    if (fstatat(bin, "diskplan", &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return;
        fatal_errno("cannot inspect launcher during uninstall");
    }
    if (!safe_symlink_metadata(&metadata))
        fatal("refusing to remove a launcher with unsafe type, owner, or flags");
    char target[PATH_MAX];
    read_symlink_at(bin, "diskplan", target);
    if (strcmp(target, expected_target) != 0) return;
    char nonce[33];
    random_hex(nonce);
    char retired[NAME_MAX + 1];
    snprintf(retired, sizeof(retired), ".diskplan-retired-%s", nonce);
    if (renameatx_np(bin, "diskplan", bin, retired, RENAME_EXCL) != 0)
        fatal_errno("cannot conditionally retire launcher");
    struct stat retired_metadata;
    char retired_target[PATH_MAX];
    bool matches = fstatat(bin, retired, &retired_metadata, AT_SYMLINK_NOFOLLOW) == 0 &&
                   safe_symlink_metadata(&retired_metadata) &&
                   same_symlink_signals(&metadata, &retired_metadata);
    if (matches) {
        read_symlink_at(bin, retired, retired_target);
        matches = strcmp(retired_target, expected_target) == 0;
    }
    if (!matches) {
        (void)renameatx_np(bin, retired, bin, "diskplan", RENAME_EXCL);
        fatal("retired launcher did not match the selected version");
    }
    if (unlinkat(bin, retired, 0) != 0 || fsync(bin) != 0)
        fatal_errno("cannot remove retired launcher");
}

static void cmd_uninstall(int argc, char **argv) {
    if (argc != 7) usage();
    if (!valid_semver(argv[5])) fatal("uninstall version is invalid");
    struct managed managed = open_managed(argv[2], argv[3], false);
    int lock = require_lock(managed.prefix, argv[4]);
    struct stat lock_metadata;
    if (fstat(lock, &lock_metadata) != 0) {
        close(lock);
        fatal_errno("cannot stat uninstall lock");
    }
    emergency_prefix_fd = dup(managed.prefix);
    emergency_lock_fd = dup(lock);
    if (emergency_prefix_fd < 0 || emergency_lock_fd < 0) {
        close(lock);
        fatal_errno("cannot retain uninstall lock descriptors");
    }
    identity_string(&lock_metadata, emergency_lock_identity);
    close(lock);
    int bundle = open_named_bundle(managed.root, argv[5]);
    char target[PATH_MAX];
    snprintf(target, sizeof(target), "../libexec/diskplan/%s/diskplan", argv[5]);
    require_current_managed(&managed);
    remove_matching_launcher(managed.bin, target);
    delete_exact_bundle(managed.root, bundle, argv[5], argv[6]);
    require_current_managed(&managed);
    close(bundle);
    prune_empty_managed_directories(&managed);
    retire_owned_lock(&managed, &lock_metadata);
    close_managed(&managed);
}

int main(int argc, char **argv) {
    if (argc < 2) usage();
    if (strcmp(argv[1], "--version-json") == 0) {
        if (argc != 2) usage();
        printf("{\"component\":\"diskplan-fs-helper\",\"product_version\":\"%s\","
               "\"protocol_major\":%d,\"protocol_minor\":%d,\"helper_abi\":%d}\n",
               DISKPLAN_PRODUCT_VERSION, DISKPLAN_PROTOCOL_MAJOR, DISKPLAN_PROTOCOL_MINOR,
               DISKPLAN_FS_HELPER_ABI);
    } else if (strcmp(argv[1], "prepare-prefix") == 0) cmd_prepare_prefix(argc, argv);
    else if (strcmp(argv[1], "bind-prefix") == 0) cmd_bind_prefix(argc, argv);
    else if (strcmp(argv[1], "acquire-lock") == 0) cmd_acquire_lock(argc, argv);
    else if (strcmp(argv[1], "release-lock") == 0) cmd_release_lock(argc, argv);
    else if (strcmp(argv[1], "stage-bundle") == 0) cmd_stage_bundle(argc, argv);
    else if (strcmp(argv[1], "bundle-proof") == 0) cmd_bundle_proof(argc, argv);
    else if (strcmp(argv[1], "publish-version") == 0) cmd_publish_version(argc, argv);
    else if (strcmp(argv[1], "cleanup-stage") == 0) cmd_cleanup_stage(argc, argv);
    else if (strcmp(argv[1], "activate") == 0) cmd_activate(argc, argv);
    else if (strcmp(argv[1], "uninstall") == 0) cmd_uninstall(argc, argv);
    else usage();
    return 0;
}
