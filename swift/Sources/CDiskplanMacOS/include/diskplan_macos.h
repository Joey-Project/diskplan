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

typedef struct {
    uint32_t returned_common;
    int64_t real_device;
    uint64_t file_id;
    uint32_t object_type;
    uint32_t reserved;
} dp_fd_identity_v1;

typedef struct {
    int32_t process_id;
    int32_t standard_output_fd;
    int32_t standard_error_fd;
} dp_spawned_process_group_v1;

int dp_set_materialization_off(void);
int dp_get_materialization_policy(void);
uint64_t dp_item_probe_options(void);
int dp_parse_item_buffer(const uint8_t *raw, size_t raw_capacity,
                         uint8_t *wire, size_t wire_capacity,
                         size_t *wire_length);
int dp_probe_item_at(int parent_fd, const uint8_t *name, size_t name_length,
                     uint8_t *wire, size_t wire_capacity, size_t *wire_length);
int dp_probe_fd_identity(int fd, dp_fd_identity_v1 *result);
int dp_probe_volume_fd(int fd, dp_volume_evidence_v1 *result);
int dp_list_snapshot_attributes(int fd, uint8_t *buffer, size_t buffer_size);
int dp_spawn_process_group(const char *executable,
                           const uint8_t *arguments,
                           size_t arguments_size,
                           size_t argument_count,
                           const uint8_t *environment,
                           size_t environment_size,
                           size_t environment_count,
                           dp_spawned_process_group_v1 *result);

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
