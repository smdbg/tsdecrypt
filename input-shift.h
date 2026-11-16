/* Bounded, monotonic, whole-input delay. GPL-2.0-only. */
#ifndef INPUT_SHIFT_H
#define INPUT_SHIFT_H

#include <stddef.h>
#include <stdint.h>

#define INPUT_SHIFT_BLOCK_SIZE 1316
#define INPUT_SHIFT_MAX_MS 10000

struct input_shift_block {
	uint64_t due_ns;
	uint32_t length;
	uint8_t data[INPUT_SHIFT_BLOCK_SIZE];
};

/* Header and every slot live in the same capped anonymous mapping. */
struct input_shift {
	size_t capacity_bytes, allocated_bytes, capacity_blocks;
	size_t head, count, queued_bytes, peak_bytes;
	uint64_t delay_ns, received_blocks, released_blocks, overflows, max_late_ns;
	struct input_shift_block blocks[];
};

uint64_t input_shift_now(void);
struct input_shift *input_shift_create(size_t budget, unsigned int delay_ms);
void input_shift_destroy(struct input_shift *shift);
int input_shift_push(struct input_shift *shift, const uint8_t *data, size_t length, uint64_t now);
struct input_shift_block *input_shift_ready(struct input_shift *shift, uint64_t now);
void input_shift_release(struct input_shift *shift, uint64_t now);
int input_shift_wait_ms(const struct input_shift *shift, uint64_t now, int maximum);
size_t input_shift_used(const struct input_shift *shift);

#endif
