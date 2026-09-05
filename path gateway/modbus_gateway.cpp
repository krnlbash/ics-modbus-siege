// modbus_gateway.cpp — Level 2: Access Control Layer
//
// A Modbus TCP proxy that sits between clients (modbus_toolkit or a real
// operator) and the backend PLC (track_sim). It parses each request at the
// wire-protocol level and enforces a whitelist:
//
//   1. Reads (function codes 1-4) are allowed from anyone.
//   2. Writes (function codes 5,6,15,16) are allowed ONLY from a trusted
//      source IP.
//   3. Even the trusted IP may only write within specific register/coil
//      ranges — SYSTEM_MODE, WATCHDOG, OPERATOR_LOCKOUT, and ALARM_SILENCED
//      stay protected regardless of who's asking.
//
// Denied requests get a real Modbus exception response (not a silent
// drop), so a client-side tool like modbus_toolkit can distinguish
// "rejected by policy" from "server is down" — using the same wire format
// production Modbus gateways use.
//
// This gateway does NOT use libmodbus for the proxy path — it reads and
// writes raw Modbus TCP frames directly, because the whole point is
// selectively forwarding or rejecting individual requests based on their
// contents, which requires seeing the wire format directly rather than
// letting a library fully decode/re-encode it.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstdarg>
#include <cerrno>
#include <ctime>
#include <string>
#include <vector>
#include <set>
#include <utility>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace {

// ---- Modbus exception codes (standard, per the Modbus spec) ----
constexpr uint8_t EXC_ILLEGAL_FUNCTION      = 0x01;
constexpr uint8_t EXC_ILLEGAL_DATA_ADDRESS  = 0x02;

// ---- Policy ----
const std::set<std::string> TRUSTED_WRITE_IPS = {"127.0.0.2"};

const std::set<uint8_t> READ_FUNCTION_CODES  = {1, 2, 3, 4};
const std::set<uint8_t> WRITE_FUNCTION_CODES = {5, 6, 15, 16};

// Inclusive [min,max] address ranges writable by a trusted client.
const std::vector<std::pair<uint16_t,uint16_t>> ALLOWED_WRITE_REG_RANGES  = {{0, 15}};
const std::vector<std::pair<uint16_t,uint16_t>> ALLOWED_WRITE_COIL_RANGES = {{0, 3}, {8, 11}};

enum class Decision { ALLOW, DENY_UNTRUSTED_IP, DENY_ADDRESS, DENY_UNKNOWN_FUNCTION };

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

bool in_any_range(uint16_t addr, uint16_t qty, const std::vector<std::pair<uint16_t,uint16_t>> &ranges) {
    uint16_t last = addr + (qty > 0 ? qty - 1 : 0);
    for (const auto &r : ranges) {
        if (addr >= r.first && last <= r.second) return true;
    }
    return false;
}

// Reads exactly `want` bytes into buf, looping over short reads. Returns
// false on disconnect/error.
bool recv_full(int sock, uint8_t *buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        ssize_t n = recv(sock, buf + got, want - got, 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

bool send_full(int sock, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

// Reads one full Modbus TCP frame (MBAP header + PDU) from `sock` into
// `frame`. Returns false on disconnect/error.
bool read_modbus_frame(int sock, std::vector<uint8_t> &frame) {
    uint8_t head[6];
    if (!recv_full(sock, head, 6)) return false; // txid(2) + protocol(2) + length(2)

    uint16_t length = (static_cast<uint16_t>(head[4]) << 8) | head[5];
    frame.assign(head, head + 6);
    frame.resize(6 + length);
    if (length > 0) {
        if (!recv_full(sock, frame.data() + 6, length)) return false;
    }
    return true;
}

// Builds a Modbus exception response mirroring the request's transaction
// id and unit id, per the Modbus spec's error-response format.
std::vector<uint8_t> build_exception(const std::vector<uint8_t> &req, uint8_t exception_code) {
    std::vector<uint8_t> resp(9);
    resp[0] = req[0]; resp[1] = req[1];       // transaction id, copied
    resp[2] = 0x00;   resp[3] = 0x00;         // protocol id, always 0
    resp[4] = 0x00;   resp[5] = 0x03;         // length: unit id + func + exc code
    resp[6] = req[6];                          // unit id, copied
    resp[7] = req[7] | 0x80;                   // function code with error bit set
    resp[8] = exception_code;
    return resp;
}

Decision evaluate(uint8_t func, uint16_t addr, uint16_t qty, const std::string &peer_ip) {
    if (READ_FUNCTION_CODES.count(func)) {
        return Decision::ALLOW; // reads are open in this policy
    }
    if (!WRITE_FUNCTION_CODES.count(func)) {
        return Decision::DENY_UNKNOWN_FUNCTION;
    }
    if (!TRUSTED_WRITE_IPS.count(peer_ip)) {
        return Decision::DENY_UNTRUSTED_IP;
    }
    bool in_range = (func == 5 || func == 15)
        ? in_any_range(addr, qty, ALLOWED_WRITE_COIL_RANGES)
        : in_any_range(addr, qty, ALLOWED_WRITE_REG_RANGES);
    return in_range ? Decision::ALLOW : Decision::DENY_ADDRESS;
}

// Extracts (function code, starting address, quantity) from a request PDU.
// qty is 1 for single-item writes (FC 5, 6).
void parse_request(const std::vector<uint8_t> &req, uint8_t &func, uint16_t &addr, uint16_t &qty) {
    func = req[7];
    addr = (static_cast<uint16_t>(req[8]) << 8) | req[9];
    if (func == 5 || func == 6) {
        qty = 1;
    } else {
        qty = (static_cast<uint16_t>(req[10]) << 8) | req[11];
    }
}

int connect_backend(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

void handle_client(int client_sock, const std::string &peer_ip, const char *backend_host, int backend_port) {
    int backend_sock = connect_backend(backend_host, backend_port);
    if (backend_sock < 0) {
        log_event("Failed to reach backend %s:%d", backend_host, backend_port);
        close(client_sock);
        return;
    }

    std::vector<uint8_t> req;
    while (read_modbus_frame(client_sock, req)) {
        if (req.size() < 8) continue; // malformed/short frame, ignore

        uint8_t func; uint16_t addr, qty;
        parse_request(req, func, addr, qty);
        Decision d = evaluate(func, addr, qty, peer_ip);

        switch (d) {
            case Decision::ALLOW: {
                log_event("ALLOW  %-15s FC=%-2u addr=%-5u qty=%-3u", peer_ip.c_str(), func, addr, qty);
                if (!send_full(backend_sock, req.data(), req.size())) goto done;
                std::vector<uint8_t> resp;
                if (!read_modbus_frame(backend_sock, resp)) goto done;
                send_full(client_sock, resp.data(), resp.size());
                break;
            }
            case Decision::DENY_UNTRUSTED_IP: {
                log_event("DENY   %-15s FC=%-2u addr=%-5u qty=%-3u reason=untrusted-ip", peer_ip.c_str(), func, addr, qty);
                auto resp = build_exception(req, EXC_ILLEGAL_FUNCTION);
                send_full(client_sock, resp.data(), resp.size());
                break;
            }
            case Decision::DENY_ADDRESS: {
                log_event("DENY   %-15s FC=%-2u addr=%-5u qty=%-3u reason=out-of-range", peer_ip.c_str(), func, addr, qty);
                auto resp = build_exception(req, EXC_ILLEGAL_DATA_ADDRESS);
                send_full(client_sock, resp.data(), resp.size());
                break;
            }
            case Decision::DENY_UNKNOWN_FUNCTION: {
                log_event("DENY   %-15s FC=%-2u reason=unknown-function", peer_ip.c_str(), func);
                auto resp = build_exception(req, EXC_ILLEGAL_FUNCTION);
                send_full(client_sock, resp.data(), resp.size());
                break;
            }
        }
    }

done:
    close(backend_sock);
    close(client_sock);
    log_event("Connection from %s closed", peer_ip.c_str());
}

} // namespace

int main(int argc, char **argv) {
    const char *listen_addr = "127.0.0.1";
    int listen_port = 15021;
    const char *backend_host = "127.0.0.1";
    int backend_port = 15020;

    if (argc >= 2) listen_addr = argv[1];
    if (argc >= 3) listen_port = atoi(argv[2]);
    if (argc >= 4) backend_host = argv[3];
    if (argc >= 5) backend_port = atoi(argv[4]);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    inet_pton(AF_INET, listen_addr, &addr.sin_addr);

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind failed: %s\n", strerror(errno));
        return 1;
    }
    listen(server_sock, 1);

    log_event("modbus_gateway listening on %s:%d -> backend %s:%d",
               listen_addr, listen_port, backend_host, backend_port);
    log_event("Policy: reads open to all; writes require trusted IP + in-range address");

    for (;;) {
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) continue;

        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ipbuf, sizeof(ipbuf));
        log_event("Connection from %s", ipbuf);

        handle_client(client_sock, std::string(ipbuf), backend_host, backend_port);
    }

    return 0;
}
