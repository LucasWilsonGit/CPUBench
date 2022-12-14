#ifndef CPUBENCH_SOURCE_HEADERS_BENCHMARK_H
#define CPUBENCH_SOURCE_HEADERS_BENCHMARK_H 1

#include <memory>
#include <mutex>
#include <any>
#include <vector>
#include <functional>

#include "ETWUtils.hpp"
#include <variant>

namespace CPUBench {
	extern uint32_t get_baseclock_mhz();
	//number of General Purpose Performance Monitoring Units available
	extern uint16_t get_GP_PMU_count();
	//number of Fixed Function Performance Monitoring Units available
	extern uint16_t get_FF_PMU_count();

	//coupled to BenchmarkContext, adding any property means adding to the 
	//constructor for BenchmarkContext(BenchmarkProperties props_copy)
	//TODO: refactor to remove coupling
	struct BenchmarkProperties
	{ 
		//leave zero for automatic repetition count 
		uint64_t repetitions = 0;

		//mutable custom context to pass custom state to the benchmarked function
		mutable std::any user_context;

		//set false to disable prewarming the cache
		bool warmup_cache = true;
		
		//default InstructionsRetired+UnhaltedCoreCycles (base clk) 
		ETWUtils::ProfilerFlags profiling_flags = 
			ETWUtils::ProfilerFlags::InstructionsRetiredFixed |
			ETWUtils::ProfilerFlags::UnhaltedCoreCyclesFixed;

		//mutable name
		mutable std::string name;
	};
	class BenchmarkContext;

	class BenchmarkContextIterand
	{
	private:
		const BenchmarkContext& m_context;
	public:
		BenchmarkContextIterand(const BenchmarkContext& context);
		~BenchmarkContextIterand();
	};

	class BenchmarkContextIterator
	{
	private:
		BenchmarkContext const& m_context;

	public:
		BenchmarkContextIterator(const BenchmarkContext&);
		BenchmarkContextIterand operator*();
		bool operator!=(const BenchmarkContextIterator& other);
		void operator++();
	};

	class BenchmarkContext
	{
		//private members are read in the implementation of operator!=
		friend class BenchmarkContextIterator;
		friend class Benchmark;
	private:
		
		mutable uint64_t m_current_iteration = 0;
		uint64_t m_target_iteration = std::numeric_limits<uint64_t>::max();
		bool m_auto_iterate = true;
		bool m_warmup_cache = true;
		ETWUtils::ProfilerFlags m_profiling_flags =
			ETWUtils::ProfilerFlags::InstructionsRetiredFixed |
			ETWUtils::ProfilerFlags::UnhaltedCoreCyclesFixed;
		std::string m_name;

	public:
		std::any m_user_context;

		BenchmarkContext();
		BenchmarkContext(BenchmarkProperties props_copy);

		void resume() const noexcept;
		void pause() const noexcept;

		BenchmarkContextIterator begin();
		BenchmarkContextIterator end();

		std::string const& get_name() const;
		uint64_t get_current_iteration() const;
	};

	class Benchmark
	{

	private:
		std::function<void(BenchmarkContext&)> m_fn;
		BenchmarkContext m_context;
		
	protected:

	public:
		using benchmark_func = std::function<void(BenchmarkContext&)>;
		Benchmark(const benchmark_func& fn);
		Benchmark(const benchmark_func& fn, const BenchmarkProperties& p);

		void run() noexcept;
		BenchmarkContext const& get_context() const;
	};

	class BenchmarkResult
	{
		using logger_func = std::function<void(BenchmarkResult&)>;
	private:
		logger_func m_logger_fn;
		const Benchmark& m_benchmark;
	public:
		std::vector<ETWUtils::PMCCounter> m_counters;
		double m_duration_s;

		BenchmarkResult(const Benchmark& benchmark, double duration_s);

		void log();
		void set_logger(const logger_func& fn);
		Benchmark const& get_benchmark() const;
	};

	extern std::vector<Benchmark> benchmarks;
	extern std::map<std::string, std::vector<BenchmarkResult>> results;
	void default_logger(BenchmarkResult& res);

	void run_benchmarks();
	BenchmarkResult& get_result(const std::string& s);
	BenchmarkResult& get_result(const std::string& s, int idx);
}

#endif
