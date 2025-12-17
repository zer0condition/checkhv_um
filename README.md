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

## CheckERMSBEPT
hardware debug breakpoint (Dr0) set on EXECUTE during rep movsb copy; baremetal fires breakpoint reliably; sloppy EPT hypervisors may suppress/intercept before debug logic triggers; trap not firing == possible EPT hook detected
***

## CheckSchedulerSignature
Sleep(0) thread yield wakeup latency via QPC; bare metal <10us typical; sloppy vCPU schedulers could show >1000us switching overhead from poor thread migration or time slice emulation
***

## CheckTLBEPTPressure
TLB hit (dense 64B strides) vs page walk (sparse 64KB strides) latency ratio; baremetal ~3-5x; nested paging (EPT/SLAT) >>10x due to 2 level table walks; sloppy hypervisors could leak this overhead
***

## CheckTSCNoiseFloor
consecutive rdtsc() deltas on isolated core; count peaks >1.5x mean; baremetal ~10% peaks from SMT/interrupts; possible sloppy vCPU timing may show unnatural consistency (<10% peaks) or jitter spikes
***
