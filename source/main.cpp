#include "ETWUtils.hpp"
#include <iostream>
#include <map>
#include <algorithm>

#include <random>

#include "Benchmark.h"

//set the condition to true to suppress the warning 
//static_assert(false, "WARNING: CPUBench must be used in Administrator Mode for Real Time Event Consumption. This is a constraint of ETW.\n");

void benchmark_mispredicts(CPUBench::BenchmarkContext& context) {
	volatile const char c{ 0 };
	std::minstd_rand simple_random;
	simple_random.seed(0xF00D);

	auto val = 50;
	try {
		val = std::any_cast<int>(context.m_user_context);
	}
	catch (std::bad_any_cast& e) {
		std::cout << e.what() << std::endl;
	}

	for (auto _ : context) {
		if (simple_random() % 100 > val) {
			(void)c;
		}
	}
}

int main() {
	CPUBench::BenchmarkProperties props{};
	props.profiling_flags = ETWUtils::ProfilerFlags::BranchMispredictions
		| ETWUtils::ProfilerFlags::BranchInstructions
		| ETWUtils::ProfilerFlags::UnhaltedCoreCycles;
	props.repetitions = 10'000'000;
	props.name = "MispredictionBenchmark";
	props.warmup_cache = true;
	props.user_context = 30;

	CPUBench::Benchmark benchmark(benchmark_mispredicts, props);

	//BenchmarkProperties are taken by value, so we can reuse a single BenchmarkProperties struct
	//to vary a user_context i.e miss rate in this case, and observe how the program execution changes
	props.user_context = 40;
	benchmark = CPUBench::Benchmark(benchmark_mispredicts, props);
	

	CPUBench::run_benchmarks();

	auto mispredict_logger = [](CPUBench::BenchmarkResult& res) {
		CPUBench::default_logger(res);

		unsigned int branches = 0;
		unsigned int mispredicts = 0;
		unsigned int core_cycles = 0;

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
	};

	auto& result = CPUBench::get_result("MispredictionBenchmark");
	result.set_logger(mispredict_logger);
	result.log();

	std::cout << "\n";

	auto& result2 = CPUBench::get_result("MispredictionBenchmark", 1);
	result2.set_logger(mispredict_logger);
	result2.log();

	//std::cout << CPUBench::get_baseclock_mhz() << "\n";
	//std::cout << CPUBench::get_GP_PMU_count() << "\n";

	getchar();

	return 0;
}