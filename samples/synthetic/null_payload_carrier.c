/*
 * Harmless binary fixture for defensive content-signature demonstrations.
 *
 * The table resembles callback metadata so the compiled file has realistic structure,
 * but every slot is NULL. This program does not hook APIs, open sockets, modify files,
 * load payloads, or invoke any callback.
 */
#include <stddef.h>
#include <stdint.h>

typedef void (*carrier_callback)(const void *, size_t);

struct carrier_fixture {
    uint32_t version;
    uint32_t slot_count;
    carrier_callback slots[16];
    unsigned char marker[32];
    unsigned char payload[16];
};

const struct carrier_fixture daybreak_null_carrier = {
    .version = 1,
    .slot_count = 16,
    .slots = {0},
    .marker = "MALWARE PAYLOAD CARRIER HERE",
    .payload = "NULL PAYLOAD",
};

int main(void) {
    /* Reference the fixture so the linker must retain its bytes. */
    return daybreak_null_carrier.slots[0] != (carrier_callback)0 ||
           daybreak_null_carrier.marker[0] != (unsigned char)'M';
}
