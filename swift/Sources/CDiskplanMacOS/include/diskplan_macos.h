#ifndef DISKPLAN_MACOS_H
#define DISKPLAN_MACOS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    DP_ITEM_WIRE_V1_SIZE = 104,
    DP_VOLUME_MASK_WORDS = 5,
};

typedef struct {
    uint32_t returned_common;
    uint32_t returned_volume;
    uint32_t returned_directory;
    uint32_t returned_file;
    uint32_t returned_extended;
    uint32_t valid_capabilities[4];
    uint32_t capabilities[4];
    uint32_t valid_attributes[DP_VOLUME_MASK_WORDS];
    uint32_t native_attributes[DP_VOLUME_MASK_WORDS];
    char filesystem_type[16];
} dp_volume_evidence_v1;

int dp_set_materialization_off(void);
int dp_get_materialization_policy(void);
int dp_probe_item_at(int parent_fd, const uint8_t *name, size_t name_length,
                     uint8_t *wire, size_t wire_capacity, size_t *wire_length);
int dp_probe_volume_fd(int fd, dp_volume_evidence_v1 *result);

uint32_t dp_attr_common_device(void);
uint32_t dp_attr_common_object_type(void);
uint32_t dp_attr_common_flags(void);
uint32_t dp_attr_common_file_id(void);
uint32_t dp_attr_file_link_count(void);
uint32_t dp_attr_file_total_size(void);
uint32_t dp_attr_file_allocated_size(void);
uint32_t dp_attr_extended_private_size(void);
uint32_t dp_attr_extended_clone_id(void);
uint32_t dp_attr_extended_flags(void);
uint32_t dp_attr_extended_clone_refcount(void);
uint32_t dp_flag_dataless(void);
uint64_t dp_flag_sync_root(void);
uint64_t dp_flag_may_share_blocks(void);
uint64_t dp_flag_shares_all_blocks(void);
uint32_t dp_volume_clone_interface(void);
uint32_t dp_volume_snapshot_interface(void);
uint32_t dp_volume_clone_mapping_format(void);

#ifdef __cplusplus
}
#endif

#endif
