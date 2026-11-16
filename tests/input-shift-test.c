/* SPDX-License-Identifier: GPL-2.0-only */
#include "input-shift.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(void) {
	uint8_t a[INPUT_SHIFT_BLOCK_SIZE], b[188];
	struct input_shift *queue;
	struct input_shift_block *block;
	uint64_t now = 1000000000;
	size_t i, capacity;
	memset(a, 0xa1, sizeof(a));
	memset(b, 0xb2, sizeof(b));
	assert(input_shift_create(1, 10) == NULL);
	assert(input_shift_create(4096, INPUT_SHIFT_MAX_MS + 1) == NULL);
	queue = input_shift_create(8191, 250);
	assert(queue && queue->allocated_bytes <= 8191);
	assert(sizeof(*queue) + queue->capacity_blocks * sizeof(*block) <= queue->allocated_bytes);
	assert(input_shift_push(queue, a, sizeof(a), now) == 0);
	assert(input_shift_push(queue, b, sizeof(b), now + 20000000) == 0);
	assert(input_shift_ready(queue, now + 249999999) == NULL);
	assert(input_shift_wait_ms(queue, now + 249999999, 100) == 1);
	assert(input_shift_wait_ms(queue, now + 250000000, 100) == 0);
	block = input_shift_ready(queue, now + 250000000);
	assert(block && block->length == sizeof(a) && memcmp(block->data, a, sizeof(a)) == 0);
	input_shift_release(queue, now + 250000000);
	assert(input_shift_ready(queue, now + 269999999) == NULL);
	block = input_shift_ready(queue, now + 270000000);
	assert(block && block->length == sizeof(b) && memcmp(block->data, b, sizeof(b)) == 0);
	input_shift_release(queue, now + 271000000);
	assert(queue->max_late_ns == 1000000);
	assert(queue->count == 0 && queue->queued_bytes == 0);
	assert(input_shift_wait_ms(queue, now, 100) == 100);
	capacity = queue->capacity_blocks;
	for (i = 0; i < capacity; ++i)
		assert(input_shift_push(queue, a, sizeof(a), now) == 0);
	assert(input_shift_used(queue) <= queue->allocated_bytes);
	assert(input_shift_push(queue, b, sizeof(b), now) == -1 && errno == ENOBUFS);
	assert(queue->count == capacity && queue->overflows == 1);
	for (i = 0; i < capacity; ++i) {
		block = input_shift_ready(queue, now + 250000000);
		assert(block && block->data[0] == 0xa1); /* No overwrite at overflow. */
		input_shift_release(queue, now + 250000000);
	}
	for (i = 0; i < capacity * 20; ++i) {
		b[0] = (uint8_t)i;
		assert(input_shift_push(queue, b, sizeof(b), now) == 0);
		block = input_shift_ready(queue, now + 250000000);
		assert(block && block->data[0] == (uint8_t)i);
		input_shift_release(queue, now + 250000000);
	}
	assert(input_shift_push(queue, b, 1, now) == -1 && errno == EINVAL);
	assert(input_shift_push(queue, a, sizeof(a) + 188, now) == -1 && errno == EINVAL);
	assert(queue->released_blocks + queue->count == queue->received_blocks);
	input_shift_destroy(queue);
	puts("PASS RAM shift cap, due times, spacing, FIFO wrap, overflow without overwrite, partial lengths");
	return 0;
}
