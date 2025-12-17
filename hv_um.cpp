#include <windows.h>
#include <iostream>
#include <intrin.h>
#include <iomanip>
#include <chrono>
#include <vector>
#include <algorithm>
#include <cmath>
#include <numeric>
#include <thread>
#include <mutex>

void Log(const char* label, const char* msg, bool detected) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    std::cout << "[";
    if (detected) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "failed";
    }
    else {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "pass";
    }
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "] " << std::left << std::setw(25) << label << ": " << msg << std::endl;
}

// if eax >= 0x40000000, a hypervisor interface is exposed.
// check for a few common vendors (Hyper‑V, VMware, KVM, Xen).
// note: can spoof or hide this leaf
void CheckSyntheticCPUID() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x40000000);

    char vendor[13] = { 0 };
    memcpy(vendor, &cpuInfo[1], 4); // EBX
    memcpy(vendor + 4, &cpuInfo[2], 4); // ECX
    memcpy(vendor + 8, &cpuInfo[3], 4); // EDX

    bool isHypervisor =
        (cpuInfo[0] >= 0x40000000) && (
            strcmp(vendor, "Microsoft Hv") == 0 ||
            strcmp(vendor, "VMwareVMware") == 0 ||
            strcmp(vendor, "KVMKVMKVM") == 0 ||
            strcmp(vendor, "XenVMMXenVMM") == 0
            );

    char msg[128];
    sprintf_s(msg, "eax=0x%08X vendor=%s", cpuInfo[0], vendor);
    Log("synthetic CPUID", msg, isHypervisor);
}

// measured TSC via rdtsc calibrated over wall clock QPC time
// mismatch >5%: treated as suspicious (heuristic threshold)
void CheckCrystalClock() {
    int leaf15[4] = { 0 };
    int leaf16[4] = { 0 };

    __cpuid(leaf15, 0x15);
    __cpuid(leaf16, 0x16);

    bool has15 = (leaf15[2] != 0);      // ecx = crystal frequency if non‑zero
    bool has16 = (leaf16[0] != 0);      // eax = base MHz if non‑zero

    double official_hz = 0.0;

    if (has15) {
        // TSC frequency from ratio + crystal clock
        unsigned int denom = leaf15[0] ? leaf15[0] : 1;
        unsigned int numer = leaf15[1] ? leaf15[1] : 1;
        double crystal = (double)leaf15[2]; // Hz
        official_hz = crystal * ((double)numer / (double)denom);
    }
    else if (has16) {
        unsigned int base_mhz = (unsigned int)leaf16[0];
        official_hz = (double)base_mhz * 1.0e6;
    }

    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);

    unsigned __int64 rdtsc1 = __rdtsc();
    Sleep(100);
    unsigned __int64 rdtsc2 = __rdtsc();
    QueryPerformanceCounter(&t2);

    double wallSecs = (double)(t2.QuadPart - t1.QuadPart) / (double)freq.QuadPart;
    double measured_hz = (double)(rdtsc2 - rdtsc1) / wallSecs;

    char msg[128];

    if (official_hz > 0.0) {
        double pctDiff = fabs(official_hz - measured_hz) / official_hz;
        bool mismatch = (pctDiff > 0.05); // heuristic 5% tolerance

        sprintf_s(msg, "official: %.0f MHz | measured: %.0f MHz | %.1f%% diff",
            official_hz / 1e6, measured_hz / 1e6, pctDiff * 100.0);

        Log("CPUID.0x15/0x16", msg, mismatch);
    }
    else {
        sprintf_s(msg, "measured: %.0f MHz (no CPUID freq info)", measured_hz / 1e6);
        Log("TSC (measured only)", msg, false);
    }
}

// KUSER_SHARED_DATA.InterruptTime at 0x7FFE0008/0x7FFE000C
// kernel provided shared memory counter, updates at 10 MHz (100ns per tick)
// hypervisors may inject skew or artificial stepping on this counter
// detect delta outside [9M, 11M] over ~1 second (+=10% tolerance)
void CheckKUserSharedData() {
    volatile DWORD* low = (DWORD*)0x7FFE0008;
    volatile DWORD* high = (DWORD*)0x7FFE000C;

    ULONGLONG tsc1 = __rdtsc();
    (void)tsc1; // not used directly, but read is cheap
    ULONGLONG k1 = ((ULONGLONG)*high << 32) | *low;

    Sleep(1000);

    ULONGLONG tsc2 = __rdtsc();
    (void)tsc2;
    ULONGLONG k2 = ((ULONGLONG)*high << 32) | *low;

    ULONGLONG kDelta = k2 - k1;
    bool skew = (kDelta < 9000000ULL || kDelta > 11000000ULL); // ±10% heuristic

    char msg[64];
    sprintf_s(msg, "delta: %llu (10M expected)", kDelta);
    Log("KUSER_SHARED_DATA", msg, skew);
}

// baremetal: executes directly, ~8k-10k cycles (varies by CPU generation)
// UMIP enabled: kernel #GP trap emulation, ~5-15k cycles
// hypervisor: may use fast path or synthetic timing, <1000 cycles (anomalous)
// note: threshold varies significantly; not reliable across CPU generations
void CheckUMIP_SGDT() {
    unsigned char gdtr[10] = { 0 };
    ULONGLONG t1 = __rdtsc();
    _sgdt(gdtr);
    ULONGLONG t2 = __rdtsc();

    ULONGLONG cycles = t2 - t1;
    ULONGLONG base = *(ULONGLONG*)(gdtr + 2);

    // Treat extremely low latency as suspicious (e.g. hypervisor fast‑path)
    bool suspicious = (cycles < 1000);

    char msg[64];
    sprintf_s(msg, "cycles: %llu | base: 0x%llx", cycles, base);
    Log("SGDT/UMIP", msg, suspicious);
}

// baremetal: 0.1-10us typical (workload dependent, highly variable)
// hypervisor: may show >1000us overhead or suspiciously consistent timing
// detect mean >1000us (arbitrary heuristic, unreliable)
void CheckSchedulerSignature() {
    int num_cores = (int)std::thread::hardware_concurrency();
    if (num_cores < 2) return;

    std::vector<double> wakeup_deltas;
    std::mutex m;

    auto worker = [&](int core_id) {
        SetThreadAffinityMask(GetCurrentThread(), 1ULL << (core_id % num_cores));

        LARGE_INTEGER qpf, qpc1, qpc2;
        QueryPerformanceFrequency(&qpf);

        for (int i = 0; i < 20; i++) {
            QueryPerformanceCounter(&qpc1);
            Sleep(0);
            QueryPerformanceCounter(&qpc2);

            double delta_us =
                ((double)(qpc2.QuadPart - qpc1.QuadPart) * 1e6) / (double)qpf.QuadPart;

            {
                std::lock_guard<std::mutex> lock(m);
                wakeup_deltas.push_back(delta_us);
            }
        }
        };

    std::thread t0(worker, 0);
    std::thread t1(worker, 1);
    t0.join();
    t1.join();

    if (!wakeup_deltas.empty()) {
        double mean = std::accumulate(wakeup_deltas.begin(), wakeup_deltas.end(), 0.0) /
            wakeup_deltas.size();
        double sq_sum = 0.0;
        for (auto d : wakeup_deltas) sq_sum += (d - mean) * (d - mean);
        double variance = sq_sum / wakeup_deltas.size();

        bool anomaly = (mean > 1000.0); // >1 ms mean wake latency -> suspicious

        char msg[128];
        sprintf_s(msg, "slice: %.2f us | variance: %.2f | anomaly: %s",
            mean, variance, anomaly ? "yes" : "no");
        Log("SchedulerSignature", msg, anomaly);
    }
}

// baremetal: ratio ~3-5x (page_walk / hit latency)
// nested paging (EPT/SLAT): ratio >>10x due to 2 level page table walk
// detect ratio >10 indicates hypervisor nested paging overhead
void CheckTLBEPTPressure() {
    const size_t alloc_size = 64 * 1024 * 1024;
    void* region = VirtualAlloc(nullptr, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!region) {
        std::cout << "[skip] CheckTLBEPTPressure: VirtualAlloc failed\n";
        return;
    }

    std::vector<unsigned __int64> hit_latencies;
    std::vector<unsigned __int64> walk_latencies;

    // TLB friendly: sequential low‑offset access
    for (size_t i = 0; i < 10000; i += 64) {
        unsigned char* p = (unsigned char*)region + i;
        unsigned __int64 t1 = __rdtsc();
        *p = 0x42;
        unsigned __int64 t2 = __rdtsc();
        hit_latencies.push_back(t2 - t1);
    }

    // TLB unfriendly: sparse 16‑page strides (64KB) across the region
    for (size_t i = 0; i < alloc_size; i += 4096 * 16) {
        unsigned char* p = (unsigned char*)region + i;
        unsigned __int64 t1 = __rdtsc();
        *p = 0x42;
        unsigned __int64 t2 = __rdtsc();
        walk_latencies.push_back(t2 - t1);
    }

    VirtualFree(region, 0, MEM_RELEASE);

    if (!hit_latencies.empty() && !walk_latencies.empty()) {
        double mean_hit =
            std::accumulate(hit_latencies.begin(), hit_latencies.end(), 0.0) / hit_latencies.size();
        double mean_walk =
            std::accumulate(walk_latencies.begin(), walk_latencies.end(), 0.0) / walk_latencies.size();

        double ratio = mean_walk / (mean_hit > 0 ? mean_hit : 1.0);
        bool anomaly = (ratio > 10.0);

        char msg[128];
        sprintf_s(msg, "hit: %.0f cyc | walk: %.0f cyc | ratio: %.1f",
            mean_hit, mean_walk, ratio);
        Log("TLB/EPT pressure", msg, anomaly);
    }
}

double calculate_stddev(const std::vector<unsigned __int64>& data, double mean) {
    double sq_sum = 0.0;
    for (auto v : data) {
        sq_sum += (v - mean) * (v - mean);
    }
    return std::sqrt(sq_sum / data.size());
}

// baremetal: ~10% peaks (SMT interference, interrupts, freq scaling expected)
// vCPU: <10% peaks possible (isolated synthetic timing)
// detect >10% of samples are peaks (interfered timing)
void CheckTSCNoiseFloor() {
    std::vector<unsigned __int64> deltas;
    deltas.reserve(100000);

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    SetThreadAffinityMask(GetCurrentThread(), 1ULL); // core 0

    unsigned __int64 prev_tsc = __rdtsc();

    for (int i = 0; i < 100000; i++) {
        unsigned __int64 curr_tsc = __rdtsc();
        unsigned __int64 delta = curr_tsc - prev_tsc;

        if (delta > 0 && delta < 10000) {
            deltas.push_back(delta);
        }

        prev_tsc = curr_tsc;
    }

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

    if (deltas.size() > 1) {
        double mean = std::accumulate(deltas.begin(), deltas.end(), 0.0) / deltas.size();
        double sq_sum = 0.0;
        for (auto d : deltas) sq_sum += (d - mean) * (d - mean);
        double stddev = std::sqrt(sq_sum / deltas.size());

        int count_high = 0;
        for (auto d : deltas) {
            if (d > mean * 1.5) count_high++;
        }

        bool peaks = (count_high > (int)(deltas.size() * 0.1)); // >10% peaks

        char msg[128];
        sprintf_s(msg, "mean: %.0f | stddev: %.0f | peaks>1.5x: %s",
            mean, stddev, peaks ? "yes" : "no");
        Log("TSCNoiseFloor", msg, peaks);
    }
}

static int g_ermsb_trap_detected = 0;

static LONG WINAPI ErmsbExceptionHandler(PEXCEPTION_POINTERS ctx)
{
    if (ctx->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        g_ermsb_trap_detected = 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

//baremetal: debug breakpoints fire reliably during rep movsb
//hypervisor w/ EPT hooks: breakpoint may not fire (EPT intercepts before debug logic)
void CheckERMSBEPT()
{
    void* src_page = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    void* dst_page = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);

    if (!src_page || !dst_page)
        return;

    memset(src_page, 0xAB, 0x2000);

    uint64_t breakpoint_addr = (uint64_t)src_page + 0x1000;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    ctx.Dr0 = breakpoint_addr;

    // Dr7 = 0x30001
    //   bit 0   = 1: enable local breakpoint for Dr0
    //   bits 17:16 = 11b: Dr0 break on instruction execution
    //   bits 19:18 = 00b: length = 1 byte
    ctx.Dr7 = 0x30001;

    PVOID veh = AddVectoredExceptionHandler(1, ErmsbExceptionHandler);
    SetThreadContext(GetCurrentThread(), &ctx);

    g_ermsb_trap_detected = 0;

    __try
    {
        __movsb((PBYTE)dst_page, (PBYTE)src_page, 0x2000);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // any exception during the copy is swallowed here;
        // the VEH will already have set g_ermsb_trap_detected if Dr0 fired.
    }

    RemoveVectoredExceptionHandler(veh);

    ctx.Dr7 = 0;
    SetThreadContext(GetCurrentThread(), &ctx);

    VirtualFree(src_page, 0, MEM_RELEASE);
    VirtualFree(dst_page, 0, MEM_RELEASE);

    bool anomaly = (g_ermsb_trap_detected == 0);

    char msg[128];
    sprintf_s(msg, "trap triggered: %s | EPT hook detected: %s",
        g_ermsb_trap_detected ? "yes" : "no",
        anomaly ? "yes" : "no");

    Log("ERMSB", msg, anomaly);
}

int main() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    
    CheckSyntheticCPUID();
    CheckCrystalClock();
    CheckERMSBEPT();

    CheckUMIP_SGDT();
    CheckSchedulerSignature();
    CheckTLBEPTPressure();
    CheckTSCNoiseFloor();

    CheckKUserSharedData();

    printf("\nPress any key to exit.\n");
    getchar();
    return 0;
}
