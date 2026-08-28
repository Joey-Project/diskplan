#include "diskplan_macos.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <unistd.h>

typedef struct __attribute__((packed, aligned(4))) {
    uint32_t length;
    attribute_set_t returned;
    dev_t device;
    fsobj_type_t object_type;
    uint32_t flags;
    uint64_t file_id;
    uint32_t link_count;
    off_t total_size;
    off_t allocated_size;
    off_t private_size;
    uint64_t clone_id;
    uint64_t extended_flags;
    uint32_t clone_refcount;
} dp_kernel_item_buffer;

typedef struct __attribute__((packed, aligned(4))) {
    uint32_t length;
    attribute_set_t returned;
    dev_t device;
    fsobj_type_t object_type;
    uint64_t file_id;
} dp_kernel_fd_identity_buffer;

typedef struct __attribute__((packed, aligned(4))) {
    uint32_t length;
    attribute_set_t returned;
    vol_capabilities_attr_t capabilities;
    vol_attributes_attr_t attributes;
} dp_kernel_volume_buffer;

static void dp_store_u32(uint8_t *wire, size_t offset, uint32_t value) {
    memcpy(wire + offset, &value, sizeof(value));
}

static void dp_store_u64(uint8_t *wire, size_t offset, uint64_t value) {
    memcpy(wire + offset, &value, sizeof(value));
}

static int dp_read_claimed_field(const uint8_t *raw, size_t raw_length,
                                 size_t offset, void *value, size_t value_size,
                                 int claimed) {
    if (!claimed) {
        return 0;
    }
    if (offset > raw_length || value_size > raw_length - offset) {
        errno = EPROTO;
        return -1;
    }
    memcpy(value, raw + offset, value_size);
    return 0;
}

int dp_set_materialization_off(void) {
    return setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
                          IOPOL_SCOPE_PROCESS,
                          IOPOL_MATERIALIZE_DATALESS_FILES_OFF);
}

int dp_get_materialization_policy(void) {
    return getiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
                          IOPOL_SCOPE_PROCESS);
}

uint64_t dp_item_probe_options(void) {
    return FSOPT_NOFOLLOW | FSOPT_RESOLVE_BENEATH | FSOPT_REPORT_FULLSIZE |
           FSOPT_PACK_INVAL_ATTRS | FSOPT_ATTR_CMN_EXTENDED |
           FSOPT_RETURN_REALDEV;
}

int dp_parse_item_buffer(const uint8_t *raw, size_t raw_capacity,
                         uint8_t *wire, size_t wire_capacity,
                         size_t *wire_length) {
    const size_t returned_end = offsetof(dp_kernel_item_buffer, device);
    if (raw == NULL || wire == NULL || wire_length == NULL ||
        raw_capacity < returned_end || wire_capacity < DP_ITEM_WIRE_V1_SIZE) {
        errno = EINVAL;
        return -1;
    }

    uint32_t raw_length = 0;
    memcpy(&raw_length, raw, sizeof(raw_length));
    if (raw_length < returned_end || raw_length > raw_capacity) {
        errno = EPROTO;
        return -1;
    }

    attribute_set_t returned = {0};
    memcpy(&returned, raw + offsetof(dp_kernel_item_buffer, returned),
           sizeof(returned));
    const uint32_t requested_common =
        ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_DEVID | ATTR_CMN_OBJTYPE |
        ATTR_CMN_FLAGS | ATTR_CMN_FILEID;
    const uint32_t requested_file =
        ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE;
    const uint32_t requested_extended =
        ATTR_CMNEXT_PRIVATESIZE | ATTR_CMNEXT_CLONEID |
        ATTR_CMNEXT_EXT_FLAGS | ATTR_CMNEXT_CLONE_REFCNT;
    if ((returned.commonattr & ATTR_CMN_RETURNED_ATTRS) == 0 ||
        (returned.commonattr & ~requested_common) != 0 ||
        returned.volattr != 0 || returned.dirattr != 0 ||
        (returned.fileattr & ~requested_file) != 0 ||
        (returned.forkattr & ~requested_extended) != 0) {
        errno = EPROTO;
        return -1;
    }

    dev_t device = 0;
    fsobj_type_t object_type = 0;
    uint32_t flags = 0;
    uint64_t file_id = 0;
    uint32_t link_count = 0;
    off_t total_size = 0;
    off_t allocated_size = 0;
    off_t private_size = 0;
    uint64_t clone_id = 0;
    uint64_t extended_flags = 0;
    uint32_t clone_refcount = 0;

#define DP_READ_FIELD(group, bit, field, value)                                  \
    do {                                                                          \
        if (dp_read_claimed_field(raw, raw_length,                                \
                                  offsetof(dp_kernel_item_buffer, field),         \
                                  &(value), sizeof(value),                         \
                                  (returned.group & (bit)) != 0) != 0) {           \
            return -1;                                                            \
        }                                                                         \
    } while (0)

    DP_READ_FIELD(commonattr, ATTR_CMN_DEVID, device, device);
    DP_READ_FIELD(commonattr, ATTR_CMN_OBJTYPE, object_type, object_type);
    DP_READ_FIELD(commonattr, ATTR_CMN_FLAGS, flags, flags);
    DP_READ_FIELD(commonattr, ATTR_CMN_FILEID, file_id, file_id);
    DP_READ_FIELD(fileattr, ATTR_FILE_LINKCOUNT, link_count, link_count);
    DP_READ_FIELD(fileattr, ATTR_FILE_TOTALSIZE, total_size, total_size);
    DP_READ_FIELD(fileattr, ATTR_FILE_ALLOCSIZE, allocated_size, allocated_size);
    DP_READ_FIELD(forkattr, ATTR_CMNEXT_PRIVATESIZE, private_size, private_size);
    DP_READ_FIELD(forkattr, ATTR_CMNEXT_CLONEID, clone_id, clone_id);
    DP_READ_FIELD(forkattr, ATTR_CMNEXT_EXT_FLAGS, extended_flags, extended_flags);
    DP_READ_FIELD(forkattr, ATTR_CMNEXT_CLONE_REFCNT, clone_refcount, clone_refcount);

#undef DP_READ_FIELD

    memset(wire, 0, DP_ITEM_WIRE_V1_SIZE);
    dp_store_u32(wire, 0, DP_ITEM_WIRE_V1_SIZE);
    dp_store_u32(wire, 4, returned.commonattr);
    dp_store_u32(wire, 8, returned.volattr);
    dp_store_u32(wire, 12, returned.dirattr);
    dp_store_u32(wire, 16, returned.fileattr);
    dp_store_u32(wire, 20, returned.forkattr);
    if ((returned.commonattr & ATTR_CMN_DEVID) != 0) {
        dp_store_u64(wire, 24, (uint64_t)(int64_t)device);
    }
    if ((returned.commonattr & ATTR_CMN_OBJTYPE) != 0) {
        dp_store_u32(wire, 32, (uint32_t)object_type);
    }
    if ((returned.commonattr & ATTR_CMN_FLAGS) != 0) {
        dp_store_u32(wire, 36, flags);
    }
    if ((returned.commonattr & ATTR_CMN_FILEID) != 0) {
        dp_store_u64(wire, 40, file_id);
    }
    if ((returned.fileattr & ATTR_FILE_LINKCOUNT) != 0) {
        dp_store_u32(wire, 48, link_count);
    }
    if ((returned.fileattr & ATTR_FILE_TOTALSIZE) != 0) {
        dp_store_u64(wire, 52, (uint64_t)total_size);
    }
    if ((returned.fileattr & ATTR_FILE_ALLOCSIZE) != 0) {
        dp_store_u64(wire, 60, (uint64_t)allocated_size);
    }
    if ((returned.forkattr & ATTR_CMNEXT_PRIVATESIZE) != 0) {
        dp_store_u64(wire, 68, (uint64_t)private_size);
    }
    if ((returned.forkattr & ATTR_CMNEXT_CLONEID) != 0) {
        dp_store_u64(wire, 76, clone_id);
    }
    if ((returned.forkattr & ATTR_CMNEXT_EXT_FLAGS) != 0) {
        dp_store_u64(wire, 84, extended_flags);
    }
    if ((returned.forkattr & ATTR_CMNEXT_CLONE_REFCNT) != 0) {
        dp_store_u32(wire, 92, clone_refcount);
    }
    *wire_length = DP_ITEM_WIRE_V1_SIZE;
    return 0;
}

int dp_probe_item_at(int parent_fd, const uint8_t *name, size_t name_length,
                     uint8_t *wire, size_t wire_capacity, size_t *wire_length) {
    if (parent_fd < 0 || name == NULL || wire == NULL || wire_length == NULL ||
        name_length == 0 || name_length > NAME_MAX || wire_capacity < DP_ITEM_WIRE_V1_SIZE ||
        memchr(name, '\0', name_length) != NULL || memchr(name, '/', name_length) != NULL ||
        (name_length == 1 && name[0] == '.') ||
        (name_length == 2 && name[0] == '.' && name[1] == '.')) {
        errno = EINVAL;
        return -1;
    }

    char component[NAME_MAX + 1];
    memcpy(component, name, name_length);
    component[name_length] = '\0';

    struct attrlist attributes = {0};
    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_DEVID |
                            ATTR_CMN_OBJTYPE | ATTR_CMN_FLAGS | ATTR_CMN_FILEID;
    attributes.fileattr = ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE;
    attributes.forkattr = ATTR_CMNEXT_PRIVATESIZE | ATTR_CMNEXT_CLONEID |
                          ATTR_CMNEXT_EXT_FLAGS | ATTR_CMNEXT_CLONE_REFCNT;

    uint8_t raw[sizeof(dp_kernel_item_buffer)] = {0};
    unsigned long options = (unsigned long)dp_item_probe_options();
    if (getattrlistat(parent_fd, component, &attributes, &raw, sizeof(raw), options) != 0) {
        return -1;
    }
    return dp_parse_item_buffer(raw, sizeof(raw), wire, wire_capacity, wire_length);
}

int dp_probe_fd_identity(int fd, dp_fd_identity_v1 *result) {
    if (fd < 0 || result == NULL) {
        errno = EINVAL;
        return -1;
    }

    struct attrlist attributes = {0};
    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_DEVID |
                            ATTR_CMN_OBJTYPE | ATTR_CMN_FILEID;

    uint8_t raw[sizeof(dp_kernel_fd_identity_buffer)] = {0};
    unsigned long options = FSOPT_REPORT_FULLSIZE | FSOPT_PACK_INVAL_ATTRS |
                            FSOPT_RETURN_REALDEV;
    if (fgetattrlist(fd, &attributes, raw, sizeof(raw), options) != 0) {
        return -1;
    }

    const size_t returned_end = offsetof(dp_kernel_fd_identity_buffer, device);
    uint32_t raw_length = 0;
    memcpy(&raw_length, raw, sizeof(raw_length));
    if (raw_length < returned_end || raw_length > sizeof(raw)) {
        errno = EPROTO;
        return -1;
    }
    attribute_set_t returned = {0};
    memcpy(&returned, raw + offsetof(dp_kernel_fd_identity_buffer, returned),
           sizeof(returned));
    const uint32_t requested_common =
        ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_DEVID | ATTR_CMN_OBJTYPE |
        ATTR_CMN_FILEID;
    if ((returned.commonattr & ATTR_CMN_RETURNED_ATTRS) == 0 ||
        (returned.commonattr & ~requested_common) != 0 ||
        returned.volattr != 0 || returned.dirattr != 0 ||
        returned.fileattr != 0 || returned.forkattr != 0) {
        errno = EPROTO;
        return -1;
    }

    dev_t device = 0;
    fsobj_type_t object_type = 0;
    uint64_t file_id = 0;
    if (dp_read_claimed_field(raw, raw_length,
                              offsetof(dp_kernel_fd_identity_buffer, device),
                              &device, sizeof(device),
                              (returned.commonattr & ATTR_CMN_DEVID) != 0) != 0 ||
        dp_read_claimed_field(raw, raw_length,
                              offsetof(dp_kernel_fd_identity_buffer, object_type),
                              &object_type, sizeof(object_type),
                              (returned.commonattr & ATTR_CMN_OBJTYPE) != 0) != 0 ||
        dp_read_claimed_field(raw, raw_length,
                              offsetof(dp_kernel_fd_identity_buffer, file_id),
                              &file_id, sizeof(file_id),
                              (returned.commonattr & ATTR_CMN_FILEID) != 0) != 0) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->returned_common = returned.commonattr;
    if ((returned.commonattr & ATTR_CMN_DEVID) != 0) {
        result->real_device = (int64_t)device;
    }
    if ((returned.commonattr & ATTR_CMN_FILEID) != 0) {
        result->file_id = file_id;
    }
    if ((returned.commonattr & ATTR_CMN_OBJTYPE) != 0) {
        result->object_type = (uint32_t)object_type;
    }
    return 0;
}

int dp_probe_volume_fd(int fd, dp_volume_evidence_v1 *result) {
    if (fd < 0 || result == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct attrlist attributes = {0};
    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.commonattr = ATTR_CMN_RETURNED_ATTRS;
    attributes.volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES;

    dp_kernel_volume_buffer raw = {0};
    if (fgetattrlist(fd, &attributes, &raw, sizeof(raw),
                     FSOPT_REPORT_FULLSIZE | FSOPT_PACK_INVAL_ATTRS) != 0) {
        return -1;
    }
    if (raw.length != sizeof(raw)) {
        errno = EPROTO;
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->returned_common = raw.returned.commonattr;
    result->returned_volume = raw.returned.volattr;
    result->returned_directory = raw.returned.dirattr;
    result->returned_file = raw.returned.fileattr;
    result->returned_extended = raw.returned.forkattr;
    memcpy(result->valid_capabilities, raw.capabilities.valid,
           sizeof(result->valid_capabilities));
    memcpy(result->capabilities, raw.capabilities.capabilities,
           sizeof(result->capabilities));
    memcpy(result->valid_attributes, &raw.attributes.validattr,
           sizeof(result->valid_attributes));
    memcpy(result->native_attributes, &raw.attributes.nativeattr,
           sizeof(result->native_attributes));

    struct statfs filesystem = {0};
    if (fstatfs(fd, &filesystem) != 0) {
        return -1;
    }
    strlcpy(result->filesystem_type, filesystem.f_fstypename,
            sizeof(result->filesystem_type));
    return 0;
}

uint32_t dp_attr_common_device(void) { return ATTR_CMN_DEVID; }
uint32_t dp_attr_common_object_type(void) { return ATTR_CMN_OBJTYPE; }
uint32_t dp_attr_common_flags(void) { return ATTR_CMN_FLAGS; }
uint32_t dp_attr_common_file_id(void) { return ATTR_CMN_FILEID; }
uint32_t dp_attr_file_link_count(void) { return ATTR_FILE_LINKCOUNT; }
uint32_t dp_attr_file_total_size(void) { return ATTR_FILE_TOTALSIZE; }
uint32_t dp_attr_file_allocated_size(void) { return ATTR_FILE_ALLOCSIZE; }
uint32_t dp_attr_extended_private_size(void) { return ATTR_CMNEXT_PRIVATESIZE; }
uint32_t dp_attr_extended_clone_id(void) { return ATTR_CMNEXT_CLONEID; }
uint32_t dp_attr_extended_flags(void) { return ATTR_CMNEXT_EXT_FLAGS; }
uint32_t dp_attr_extended_clone_refcount(void) { return ATTR_CMNEXT_CLONE_REFCNT; }
uint32_t dp_flag_dataless(void) { return SF_DATALESS; }
uint64_t dp_flag_sync_root(void) { return EF_IS_SYNC_ROOT; }
uint64_t dp_flag_may_share_blocks(void) { return EF_MAY_SHARE_BLOCKS; }
uint64_t dp_flag_shares_all_blocks(void) { return EF_SHARES_ALL_BLOCKS; }
uint32_t dp_volume_clone_interface(void) { return VOL_CAP_INT_CLONE; }
uint32_t dp_volume_snapshot_interface(void) { return VOL_CAP_INT_SNAPSHOT; }
uint32_t dp_volume_clone_mapping_format(void) { return VOL_CAP_FMT_CLONE_MAPPING; }
