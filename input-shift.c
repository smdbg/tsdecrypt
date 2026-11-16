/* Bounded, monotonic, whole-input delay. GPL-2.0-only. */
#include "input-shift.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

uint64_t input_shift_now(void) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

struct input_shift *input_shift_create(size_t budget, unsigned int delay_ms) {
	long page = sysconf(_SC_PAGESIZE);
	size_t bytes;
	struct input_shift *shift;
	if (page <= 0 || delay_ms > INPUT_SHIFT_MAX_MS) {
		errno = EINVAL;
		return NULL;
	}
	bytes = budget / (size_t)page * (size_t)page;
	if (bytes < sizeof(*shift) + sizeof(struct input_shift_block)) {
		errno = EINVAL;
		return NULL;
	}
	shift = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (shift == MAP_FAILED)
		return NULL;
	shift->capacity_bytes = budget;
	shift->allocated_bytes = bytes;
	shift->capacity_blocks = (bytes - sizeof(*shift)) / sizeof(struct input_shift_block);
	shift->delay_ns = (uint64_t)delay_ms * 1000000;
	shift->peak_bytes = sizeof(*shift);
	return shift;
}

void input_shift_destroy(struct input_shift *shift) {
	if (shift)
		munmap(shift, shift->allocated_bytes);
}

size_t input_shift_used(const struct input_shift *shift) {
	return sizeof(*shift) + shift->count * sizeof(struct input_shift_block);
}

int input_shift_push(struct input_shift *shift, const uint8_t *data, size_t length, uint64_t now) {
	struct input_shift_block *block;
	size_t used;
	if (!length || length > INPUT_SHIFT_BLOCK_SIZE || length % 188) {
		errno = EINVAL;
		return -1;
	}
	if (shift->count == shift->capacity_blocks) {
		shift->overflows++;
		errno = ENOBUFS;
		return -1;
	}
	block = &shift->blocks[(shift->head + shift->count) % shift->capacity_blocks];
	block->due_ns = now + shift->delay_ns;
	block->length = length;
	memcpy(block->data, data, length);
	shift->count++;
	shift->received_blocks++;
	shift->queued_bytes += length;
	used = input_shift_used(shift);
	if (used > shift->peak_bytes)
		shift->peak_bytes = used;
	return 0;
}

struct input_shift_block *input_shift_ready(struct input_shift *shift, uint64_t now) {
	if (shift->count && shift->blocks[shift->head].due_ns <= now)
		return &shift->blocks[shift->head];
	return NULL;
}

void input_shift_release(struct input_shift *shift, uint64_t now) {
	struct input_shift_block *block = &shift->blocks[shift->head];
	if (!shift->count)
		return;
	if (now >= block->due_ns && now - block->due_ns > shift->max_late_ns)
		shift->max_late_ns = now - block->due_ns;
	shift->queued_bytes -= block->length;
	shift->head = (shift->head + 1) % shift->capacity_blocks;
	shift->count--;
	shift->released_blocks++;
}

int input_shift_wait_ms(const struct input_shift *shift, uint64_t now, int maximum) {
	uint64_t wait;
	if (!shift->count)
		return maximum;
	if (shift->blocks[shift->head].due_ns <= now)
		return 0;
	/* Round upward: never release early, never spin for a submillisecond wait. */
	wait = (shift->blocks[shift->head].due_ns - now + 999999) / 1000000;
	return wait < (uint64_t)maximum ? (int)wait : maximum;
}
