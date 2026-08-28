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
    vol_capabilities_attr_t capabilities;
    vol_attributes_attr_t attributes;
} dp_kernel_volume_buffer;

static void dp_store_u32(uint8_t *wire, size_t offset, uint32_t value) {
    memcpy(wire + offset, &value, sizeof(value));
}

static void dp_store_u64(uint8_t *wire, size_t offset, uint64_t value) {
    memcpy(wire + offset, &value, sizeof(value));
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

    dp_kernel_item_buffer raw = {0};
    unsigned long options = FSOPT_NOFOLLOW | FSOPT_RESOLVE_BENEATH |
                            FSOPT_REPORT_FULLSIZE | FSOPT_PACK_INVAL_ATTRS |
                            FSOPT_ATTR_CMN_EXTENDED;
    if (getattrlistat(parent_fd, component, &attributes, &raw, sizeof(raw), options) != 0) {
        return -1;
    }
    if (raw.length < sizeof(raw) || raw.length > sizeof(raw)) {
        errno = EPROTO;
        return -1;
    }

    memset(wire, 0, DP_ITEM_WIRE_V1_SIZE);
    dp_store_u32(wire, 0, DP_ITEM_WIRE_V1_SIZE);
    dp_store_u32(wire, 4, raw.returned.commonattr);
    dp_store_u32(wire, 8, raw.returned.volattr);
    dp_store_u32(wire, 12, raw.returned.dirattr);
    dp_store_u32(wire, 16, raw.returned.fileattr);
    dp_store_u32(wire, 20, raw.returned.forkattr);
    dp_store_u64(wire, 24, (uint64_t)(int64_t)raw.device);
    dp_store_u32(wire, 32, (uint32_t)raw.object_type);
    dp_store_u32(wire, 36, raw.flags);
    dp_store_u64(wire, 40, raw.file_id);
    dp_store_u32(wire, 48, raw.link_count);
    dp_store_u64(wire, 52, (uint64_t)raw.total_size);
    dp_store_u64(wire, 60, (uint64_t)raw.allocated_size);
    dp_store_u64(wire, 68, (uint64_t)raw.private_size);
    dp_store_u64(wire, 76, raw.clone_id);
    dp_store_u64(wire, 84, raw.extended_flags);
    dp_store_u32(wire, 92, raw.clone_refcount);
    dp_store_u32(wire, 96, 0);
    dp_store_u32(wire, 100, 0);
    *wire_length = DP_ITEM_WIRE_V1_SIZE;
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
