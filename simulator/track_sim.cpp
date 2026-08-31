// track_sim.cpp
//
// Simulated track-management PLC exposed over Modbus TCP.
// Stands in for a PLC bridging a radar/sensor feed to an HMI in a
// simplified air-defense-style track-management architecture.
//
// This is a teaching/testbed target only. It implements the register map
// documented in docs/register-map.md, with NO Modbus-layer authentication —
// intentionally, since that is the real-world default posture of Modbus TCP
// and the exposure this toolkit is built to demonstrate.
//
// Build: see CMakeLists.txt (links against libmodbus)

#include <modbus/modbus.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cstdarg>
#include <cerrno>
#include <ctime>
#include <atomic>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace {

constexpr int NUM_COILS = 32;
constexpr int NUM_HOLDING_REGS = 128;
constexpr int NUM_INPUT_REGS = 16;

constexpr int COIL_TRACK_ACTIVE_BASE = 0;   // 0..3
constexpr int COIL_IFF_FRIEND_BASE   = 8;   // 8..11
constexpr int COIL_OPERATOR_LOCKOUT  = 16;
constexpr int COIL_ALARM_SILENCED    = 17;

constexpr int HR_TRACK_BASE     = 0;    // 4 regs/track * 4 tracks = 0..15
constexpr int HR_SYSTEM_MODE    = 100;
constexpr int HR_WATCHDOG       = 101;

constexpr int IR_SENSOR_HEALTH  = 0;
constexpr int IR_SCAN_RATE      = 1;

std::atomic<bool> g_running{true};

void handle_sigint(int) { g_running = false; }

void log_event(const char *fmt, ...) {
    char timebuf[32];
    time_t t = time(nullptr);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tmv);
    printf("[%s] ", timebuf);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

void seed_initial_state(modbus_mapping_t *mb) {
    // Track 1: active, friendly, plausible bearing/range/alt/speed
    mb->tab_bits[COIL_TRACK_ACTIVE_BASE + 0] = 1;
    mb->tab_bits[COIL_IFF_FRIEND_BASE + 0] = 1;
    mb->tab_registers[HR_TRACK_BASE + 0] = 045;  // bearing
    mb->tab_registers[HR_TRACK_BASE + 1] = 120;  // range x10 nm -> 12.0nm
    mb->tab_registers[HR_TRACK_BASE + 2] = 350;  // altitude/10 -> 3500ft
    mb->tab_registers[HR_TRACK_BASE + 3] = 210;  // speed kts

    // Track 2: active, unresolved/hostile
    mb->tab_bits[COIL_TRACK_ACTIVE_BASE + 1] = 1;
    mb->tab_bits[COIL_IFF_FRIEND_BASE + 1] = 0;
    mb->tab_registers[HR_TRACK_BASE + 4] = 270;
    mb->tab_registers[HR_TRACK_BASE + 5] = 340;
    mb->tab_registers[HR_TRACK_BASE + 6] = 410;
    mb->tab_registers[HR_TRACK_BASE + 7] = 480;

    mb->tab_registers[HR_SYSTEM_MODE] = 1; // track mode
    mb->tab_registers[HR_WATCHDOG] = 0;

    mb->tab_input_registers[IR_SENSOR_HEALTH] = 0b11; // radar OK, IFF interrogator OK
    mb->tab_input_registers[IR_SCAN_RATE] = 12;
}

// Diff-log any coil/register writes a client makes, so the simulator's
// console output doubles as an attack log when used with the toolkit.
struct PriorState {
    uint8_t coils[NUM_COILS];
    uint16_t hregs[NUM_HOLDING_REGS];
};

void snapshot(modbus_mapping_t *mb, PriorState &s) {
    memcpy(s.coils, mb->tab_bits, NUM_COILS);
    memcpy(s.hregs, mb->tab_registers, NUM_HOLDING_REGS * sizeof(uint16_t));
}

void diff_and_log(modbus_mapping_t *mb, PriorState &prev, const char *peer) {
    for (int i = 0; i < NUM_COILS; i++) {
        if (mb->tab_bits[i] != prev.coils[i]) {
            log_event("WRITE from %s: coil[%d] %d -> %d", peer, i, prev.coils[i], mb->tab_bits[i]);
        }
    }
    for (int i = 0; i < NUM_HOLDING_REGS; i++) {
        if (mb->tab_registers[i] != prev.hregs[i]) {
            log_event("WRITE from %s: holding_reg[%d] %u -> %u", peer, i, prev.hregs[i], mb->tab_registers[i]);
        }
    }
    snapshot(mb, prev);
}

} // namespace

int main(int argc, char **argv) {
    const char *bind_addr = "127.0.0.1";
    int port = 15020; // non-privileged port for the sim, distinct from standard 502

    if (argc >= 2) bind_addr = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    modbus_t *ctx = modbus_new_tcp(bind_addr, port);
    if (!ctx) {
        fprintf(stderr, "Failed to create Modbus TCP context\n");
        return 1;
    }

    modbus_mapping_t *mb = modbus_mapping_new(NUM_COILS, 0, NUM_HOLDING_REGS, NUM_INPUT_REGS);
    if (!mb) {
        fprintf(stderr, "Failed to allocate Modbus mapping: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return 1;
    }

    seed_initial_state(mb);

    int server_socket = modbus_tcp_listen(ctx, 1);
    if (server_socket == -1) {
        fprintf(stderr, "modbus_tcp_listen failed: %s\n", modbus_strerror(errno));
        modbus_mapping_free(mb);
        modbus_free(ctx);
        return 1;
    }

    log_event("track-sim listening on %s:%d (Modbus TCP, unauthenticated)", bind_addr, port);
    log_event("Register map: docs/register-map.md");

    PriorState prev;
    snapshot(mb, prev);

    uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];

    while (g_running) {
        int master_socket = modbus_tcp_accept(ctx, &server_socket);
        if (master_socket == -1) {
            if (!g_running) break;
            continue;
        }

        struct sockaddr_in addr{};
        socklen_t addrlen = sizeof(addr);
        getpeername(master_socket, (struct sockaddr *)&addr, &addrlen);
        char peer[64];
        snprintf(peer, sizeof(peer), "%s", inet_ntoa(addr.sin_addr));
        log_event("Connection from %s", peer);

        modbus_set_socket(ctx, master_socket);

        for (;;) {
            int rc = modbus_receive(ctx, query);
            if (rc == -1) {
                break; // client disconnected or error
            }
            modbus_reply(ctx, query, rc, mb);
            diff_and_log(mb, prev, peer);
            mb->tab_registers[HR_WATCHDOG]++;
        }

        log_event("Connection from %s closed", peer);
        close(master_socket);
    }

    modbus_mapping_free(mb);
    modbus_close(ctx);
    modbus_free(ctx);
    return 0;
}
