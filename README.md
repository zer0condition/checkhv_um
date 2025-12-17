## CheckSyntheticCPUID
CPUID leaf is explicitly defined for hypervisors to expose their presence and vendor ID; any honest vm stack should set this up
***

## CheckCrystalClock
compare freq from crystal clock or base MHz to measured TSC freq via RDTSC againsst QueryPerformanceCounter; large mismatch suggests TSC scaling/offsetting or lazy CPUID emulation
***

## CheckKUserSharedData
calculate the delta between the shared page time and RDTSC;  large deviation suggests the OS timer and TSC/time virtualization are out of sync
***

## CheckUMIP_SGDT
modern CPUs support UMIP (User Mode Instruction Prevention), executing instructions like SGDT, SIDT and SLDT should throw a #GP exception and be emulated by the OS; should be slower and return dummy-ish values; very fast SGDT suggests UMIP is off or badly emulated; keep in mind this doesnt apply for old CPUs
***

---

## Disclaimer

For educational and authorized security research only. Don't use on systems you don't own or have explicit permission to test. I'm not responsible for misuse. Use at your own risk.
