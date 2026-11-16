/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Synthetic wire-level regression test; no network server or real keys. */
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>

/* Include the production receiver so its private functions are exercised. */
#ifndef CS378X_SOURCE
#define CS378X_SOURCE "../camd-cs378x.c"
#endif
#include CS378X_SOURCE

static const uint8_t test_aes_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint32_t test_auth = 0x12345678;

static void fatal(const char *what)
{
    perror(what);
    exit(2);
}

/* Encode the actual cs378x framing: 4-byte auth token, then AES blocks. */
static void send_frame(int fd, const AES_KEY *key, uint8_t command,
                       uint16_t index, const uint8_t *cw)
{
    uint8_t wire[4 + 48] = {0};
    uint8_t payload[48] = {0};
    const unsigned payload_size = cw ? 16 : 1;
    const unsigned encrypted_size = ((20 + payload_size + 15) / 16) * 16;

    payload[0] = command;
    payload[1] = payload_size;
    payload[10] = 0x09;
    payload[11] = 0xbd;
    payload[16] = index >> 8;
    payload[17] = index & 0xff;
    if (cw)
        memcpy(payload + 20, cw, 16);
    init_4b(crc32(0, payload + 20, payload_size), payload + 4);
    init_4b(test_auth, wire);
    for (unsigned offset = 0; offset < encrypted_size; offset += 16)
        AES_encrypt(payload + offset, wire + 4 + offset, key);
    if (fdwrite(fd, (char *)wire, encrypted_size + 4) != (ssize_t)encrypted_size + 4)
        fatal("write synthetic frame");
}

static int check_replies(const char *name, int emm, int extended)
{
    int sockets[2];
    struct camd client = {0};
    AES_KEY encryption_key;
    uint8_t expected[2][16];
    int failed = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
        fatal("socketpair");
    client.server_fd = sockets[0];
    client.ops.ident = "cs378x-test";
    client.cs378x.auth_token = test_auth;
    if (AES_set_encrypt_key(test_aes_key, 128, &encryption_key) != 0 ||
        AES_set_decrypt_key(test_aes_key, 128, &client.cs378x.aes_decrypt_key) != 0) {
        fprintf(stderr, "FAIL: initialize synthetic AES key\n");
        exit(2);
    }
    for (unsigned i = 0; i < 16; ++i) {
        expected[0][i] = (uint8_t)(i + 1);
        expected[1][i] = (uint8_t)(0xf0 - i);
    }

    if (emm)
        send_frame(sockets[1], &encryption_key, 0x05, 0, NULL);
    if (extended)
        send_frame(sockets[1], &encryption_key, 0x50, 0, NULL);
    send_frame(sockets[1], &encryption_key, 0x01, 0x1234, expected[0]);
    send_frame(sockets[1], &encryption_key, 0x01, 0x1235, expected[1]);

    for (unsigned reply = 0; reply < 2; ++reply) {
        uint16_t caid = 0, index = 0;
        uint8_t cw[16] = {0};
        int result = cs378x_get_cw(&client, &caid, &index, cw);
        if (result != 1 || caid != 0x09bd || index != 0x1234 + reply ||
            memcmp(cw, expected[reply], sizeof(cw)) != 0) {
            fprintf(stderr, "FAIL %s: reply %u returned %d, CAID=%04x, index=%04x\n",
                    name, reply + 1, result, caid, index);
            failed = 1;
            break;
        }
    }
    if (!failed) {
        uint8_t remaining;
        ssize_t result = recv(sockets[0], &remaining, 1, MSG_DONTWAIT);
        if (result != -1 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            fprintf(stderr, "FAIL %s: a response was left queued\n", name);
            failed = 1;
        }
    }
    close(sockets[0]);
    close(sockets[1]);
    if (!failed)
        printf("PASS %s: both CW replies remain aligned\n", name);
    return failed;
}

int main(void)
{
    /* Bound a regression that accidentally waits past the available frames. */
    alarm(5);
    int failed = 0;
    failed |= check_replies("ordinary", 0, 0);
    failed |= check_replies("EMM notification", 1, 0);
    failed |= check_replies("extended announcement", 0, 1);
    failed |= check_replies("EMM and extended announcement", 1, 1);
    return failed ? 1 : 0;
}
