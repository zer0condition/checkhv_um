#include <windows.h>
#include <iostream>
#include <intrin.h>
#include <iomanip>
#include <chrono>

void Log(const char* label, const char* msg, bool detected) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    std::cout << "[";
    if (detected) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "failed";
    }
    else {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "success";
    }
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "] " << std::left << std::setw(25) << label << ": " << msg << std::endl;
}

void CheckSyntheticCPUID() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x40000000);

    // only flag if it returns a valid hypervisor vendor string
    char vendor[13] = { 0 };
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);

    bool isHypervisor = (cpuInfo[0] >= 0x40000000) &&
        (strcmp(vendor, "Microsoft Hv") == 0 ||
            strcmp(vendor, "VMwareVMware") == 0 ||
            strcmp(vendor, "KVMKVMKVM") == 0 ||
            strcmp(vendor, "XenVMMXenVMM") == 0);

    char msg[128];
    sprintf_s(msg, "eax=0x%08X vendor=%s", cpuInfo[0], vendor);
    Log("synthetic CPUID", msg, isHypervisor);
}

void CheckCrystalClock() {
    int leaf15[4] = { 0 };
    int leaf16[4] = { 0 };

    __cpuid(leaf15, 0x15);
    __cpuid(leaf16, 0x16);

    bool has15 = (leaf15[2] != 0); // ECX = crystal freq if supported 
    bool has16 = (leaf16[0] != 0); // EAX = base freq MHz if supported 

    double official_hz = 0.0;

    if (has15) {
        // TSC freq = ECX * EBX / EAX
        unsigned long long denom = leaf15[0] ? leaf15[0] : 1;
        official_hz = (double)leaf15[2] * (double)leaf15[1] / (double)denom;
    }
    else if (has16) {
        // leaf 0x16: base frequency in MHz, not guaranteed == TSC
        // but often very close on modern Intel, good enough as "nominal"
        unsigned int base_mhz = (unsigned int)leaf16[0];
        official_hz = (double)base_mhz * 1.0e6;
    }
    else {
        // no CPUID based freq info at all fall back to consistency only mode
        // we still measure TSC vs QPC but dont label it against an official value
    }

    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);

    unsigned __int64 rdtsc1 = __rdtsc();
    Sleep(100);  // short interval reduces noise
    unsigned __int64 rdtsc2 = __rdtsc();
    QueryPerformanceCounter(&t2);

    double wallSecs = (double)(t2.QuadPart - t1.QuadPart) / (double)freq.QuadPart;
    double measured_hz = (double)(rdtsc2 - rdtsc1) / wallSecs;

    char msg[128];

    if (official_hz > 0.0) {
        double pctDiff = fabs(official_hz - measured_hz) / official_hz;
        bool mismatch = (pctDiff > 0.05); // 5% tolerance

        sprintf_s(msg, "official: %.0f | measured: %.0f | %.1f%% diff",
            official_hz / 1e6, measured_hz / 1e6, pctDiff * 100.0);

        Log("CPUID.0x15/0x16", msg, mismatch);
    }
    else {
        // no official reference; just print measured TSC freq and mark as success
        sprintf_s(msg, "measured: %.0f MHz (no CPUID freq info)", measured_hz / 1e6);
        Log("TSC (measured only)", msg, false);
    }
}

void CheckKUserSharedData() {
    volatile DWORD* low = (DWORD*)0x7FFE0008;
    volatile DWORD* high = (DWORD*)0x7FFE000C;

    ULONGLONG tsc1 = __rdtsc();
    ULONGLONG k1 = ((ULONGLONG)*high << 32) | *low;

    Sleep(1000);

    ULONGLONG tsc2 = __rdtsc();
    ULONGLONG k2 = ((ULONGLONG)*high << 32) | *low;

    ULONGLONG kDelta = k2 - k1;  // should be ~10M for 1s
    bool skew = (kDelta < 9000000LL || kDelta > 11000000LL);

    char msg[64];
    sprintf_s(msg, "delta: %llu (10M expected)", kDelta);
    Log("KUSER_SHARED_DATA", msg, skew);
}

void CheckUMIP_SGDT() {
    // 8829 cycles = normal windows emulation 
    // baremetal w/ UMIP ON: kernel emulates -> 5k-15k cycles typical
    unsigned char gdtr[10] = { 0 };
    ULONGLONG t1 = __rdtsc();
    _sgdt(gdtr);
    ULONGLONG t2 = __rdtsc();

    ULONGLONG cycles = t2 - t1;
    ULONGLONG base = *(ULONGLONG*)(gdtr + 2);

    bool suspicious = (cycles < 1000);  // only flag raw hardware execution

    char msg[64];
    sprintf_s(msg, "cycles: %llu | base: 0x%llx", cycles, base);
    Log("SGDT/UMIP", msg, suspicious);
}

void CheckTSX() {
    int info[4];
    __cpuidex(info, 7, 0);

    if (!(info[1] & (1 << 11))) {
        Log("TSX/RTM", "disabled by Intel microcode (normal post-2021)", false);
        return;
    }

    // mhm
    Log("TSX/RTM", "RTM supported", false);
}

int main() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    CheckSyntheticCPUID();
    CheckCrystalClock();
    CheckKUserSharedData();
    CheckUMIP_SGDT();
    CheckTSX();

    std::cout << "\press any key to exit.\n";
    std::cin.get();
    return 0;
}
