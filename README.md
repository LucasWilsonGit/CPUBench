# CPUBench
A Windows 8+ Microbenchmarking library that does not require test signed drivers. Somewhat restricted by the Windows Kernel Logger, but sufficient for most use cases.
 
## Requirements
Windows 10 SDK

## Compilation flags
Make sure to enable full compiler optimizations, such as /O2 on MSVC or -O3 on gcc

## Example Usage
```C++

CPUBench::BenchmarkProperties props{};
props.profiling_flags = ETWUtils::ProfilerFlags::BranchMispredictions
		| ETWUtils::ProfilerFlags::BranchInstructions
		| ETWUtils::ProfilerFlags::UnhaltedCoreCycles;
props.repetitions = 10'000'000;
props.name = "MispredictionBenchmark";
props.warmup_cache = true;
props.user_context = 30;

CPUBench::Benchmark benchmark(benchmark_mispredicts, props);

CPUBench::run_benchmarks();

//load the result, set the logger to a custom logger that has the default behavior but also times the function and outputs the misprediction rate (%)
auto& result = CPUBench::get_result("MispredictionBenchmark");
result.set_logger([](CPUBench::BenchmarkResult& res) {
 CPUBench::default_logger(res); //start with default logger behavior 
 
 //add extra output based on counters we want to get
 unsigned int branches = 0;
 unsigned int mispredicts = 0;
 unsigned int core_cycles = 0; //will read unhalted core cycles
 
 for (auto& counter : res.m_counters) {
  if (counter.name == L"BranchInstructions")
   branches = counter.value;
  else if (counter.name == L"BranchMispredictions")
   mispredicts = counter.value;
  else if (counter.name == L"UnhaltedCoreCycles")
   core_cycles = counter.value;
 }
  
 //float precis is fine, we are close to 1.0f
 std::cout << "Branch miss rate: " << mispredicts * 100.f / branches << "%\n";
 std::cout << "Unhalted core time: " << static_cast<double>(core_cycles) / (CPUBench::get_baseclock_mhz() * 1'000'000) << "s\n";
});
result.log();
```
