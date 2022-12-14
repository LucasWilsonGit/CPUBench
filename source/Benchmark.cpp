

#include "Benchmark.h"
#include <algorithm>
#include <intrin.h>
#include <chrono>

typedef struct _PROCESSOR_POWER_INFORMATION {
	ULONG Number;
	ULONG MaxMhz;
	ULONG CurrentMhz;
	ULONG MhzLimit;
	ULONG MaxIdleState;
	ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION, * PPROCESSOR_POWER_INFORMATION;

constexpr uint32_t STATUS_BUFFER_TOO_SMALL{ 0xc0000023 };
constexpr uint32_t STATUS_SUCCESS{ 0 };

uint32_t physical_core_count{ 0 };

//may throw exceptions from std::vector::resize, such as bad_alloc
//I leave this to you to handle (i.e you might want to close orders or somth before terminating)
uint32_t get_physical_core_count() {
	//reuse the result of previous calls
	if (physical_core_count != 0) {
		return physical_core_count;
	}

	std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> lpi_buf{};
	DWORD return_size{ 0 };
	bool res = GetLogicalProcessorInformation(
		lpi_buf.data(),
		&return_size
	);
	DWORD last_err = GetLastError();
	while (last_err == ERROR_INSUFFICIENT_BUFFER) {
		lpi_buf.resize(return_size / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));

		res = GetLogicalProcessorInformation(
			lpi_buf.data(),
			&return_size
		);

		SetLastError(0);
		last_err = GetLastError();
	}
	if (!res) {
		std::cerr << "GetLogicalProcessorInformation failed: reason " << last_err << "\n";
		return 0;
	}

	for (auto& lpi : lpi_buf) {
		switch (lpi.Relationship) {
		case RelationProcessorCore: {
			physical_core_count++; //counts core units (i.e physical cores)
			break;
		}
		default:
			break;
		}
	}
	return physical_core_count;
}

//may throw executions from std::vector::resize
std::vector<PROCESSOR_POWER_INFORMATION> get_processor_power_info() {
	std::vector<PROCESSOR_POWER_INFORMATION> buffer{};
	buffer.resize(get_physical_core_count()); //zero-initialize the buffer memory

	NTSTATUS status = CallNtPowerInformation(
		POWER_INFORMATION_LEVEL::ProcessorInformation,
		nullptr,
		0,
		buffer.data(),
		sizeof(PROCESSOR_POWER_INFORMATION) * buffer.capacity()
	);
	//just keep retrying with a larger buffer until it works or a different problem occurs
	while (status == STATUS_BUFFER_TOO_SMALL) {
		buffer.resize(buffer.capacity() + 1);
		status = CallNtPowerInformation(
			POWER_INFORMATION_LEVEL::ProcessorInformation,
			nullptr,
			0,
			buffer.data(),
			sizeof(PROCESSOR_POWER_INFORMATION) * buffer.capacity()
		);
		//std::cout << buffer.capacity() << std::endl;
	}
	
	//STATUS_BUFFER_TOO_SMALL is checked and handled by resizing the buffer vector
	//STATUS_ACCUSS_DENIED will not happen because the project file requires admin mode execution
	return buffer;
}

struct EAX_CPUID10 {
	UINT version_id : 8;
	UINT GP_counters : 8;
	UINT GP_counter_width : 8;
	UINT EBX_vector_length : 8;
};
//EBX just tells us what counters are unavailable, we don't care, Windows already checks that =)
struct EDX_CPUID10 {
	UINT fixed_counters : 5;
	UINT FP_counter_width : 8;
	UINT reserves : 19;
};

bool loaded_cpuid = false;
uint16_t GP_PMU_count = 0;
uint16_t FF_PMU_count = 0;

void load_cpuid() {
	uint32_t registers[4];
	uint32_t& eax = registers[0];
	uint32_t& ebx = registers[1];
	uint32_t& ecx = registers[2];
	uint32_t& edx = registers[3];
	__cpuid(reinterpret_cast<int*>(registers), 10);

	EAX_CPUID10* eax_bitfield = reinterpret_cast<EAX_CPUID10*>(&eax);
	EDX_CPUID10* edx_bitfield = reinterpret_cast<EDX_CPUID10*>(&edx);

	GP_PMU_count = eax_bitfield->GP_counters;
	FF_PMU_count = edx_bitfield->fixed_counters;
	loaded_cpuid = true;
}

namespace CPUBench {
	uint32_t baseclock_mhz = 0;
	//exceptions may come from std::vector::resize() such as std::bad_alloc
	uint32_t get_baseclock_mhz() {
		if (baseclock_mhz != 0) {
			return baseclock_mhz;
		}
		else
		{
			std::vector<PROCESSOR_POWER_INFORMATION> buffer{ get_processor_power_info() };
			//Compiler RVO... should move from xvalue return of get_processor_power_info()

			for (PROCESSOR_POWER_INFORMATION& info : buffer) {
				baseclock_mhz = std::max(baseclock_mhz, (uint32_t)info.MaxMhz);
			}
			return baseclock_mhz;
		}
	}

	uint16_t get_GP_PMU_count() {
		if (!loaded_cpuid) {
			load_cpuid();
		}
		return GP_PMU_count;
	}

	uint16_t get_FF_PMU_count() {
		if (!loaded_cpuid) {
			load_cpuid();
		}
		return FF_PMU_count;
	}

	std::vector<Benchmark> benchmarks{};
	std::map<std::string, std::vector<BenchmarkResult>> results{};

	BenchmarkContextIterand::BenchmarkContextIterand(const BenchmarkContext& context) : m_context(context)
	{
		m_context.resume();
	}
	BenchmarkContextIterand::~BenchmarkContextIterand() {
		m_context.pause();
	}

	BenchmarkContextIterator::BenchmarkContextIterator(const BenchmarkContext& context)
		: m_context(context)
	{}
	BenchmarkContextIterand BenchmarkContextIterator::operator*() {
		return BenchmarkContextIterand(m_context);
	}
	bool BenchmarkContextIterator::operator!=(const BenchmarkContextIterator& other)
	{
		return m_context.m_current_iteration != m_context.m_target_iteration;
	}
	void BenchmarkContextIterator::operator++()
	{
		m_context.m_current_iteration++;
	}

	auto default_props = BenchmarkProperties();

	BenchmarkContext::BenchmarkContext() : BenchmarkContext(default_props) {}
	BenchmarkContext::BenchmarkContext(BenchmarkProperties props_copy) {
		m_warmup_cache = props_copy.warmup_cache;
		m_profiling_flags = props_copy.profiling_flags;
		if (props_copy.repetitions != 0) {
			m_auto_iterate = false;
			m_target_iteration = props_copy.repetitions;
		}

		//try to avoid multiple expensive copies by moving them instead from the copy
		m_user_context = std::move(props_copy.user_context);
		m_name = std::move(props_copy.name);
	}



	//disabled resume/pause because unless I can sample the hardware PMUs
	//and store their values out into my software and reset them to 0 on the hardware
	//the pause can mean overflow events get discarded that had branch counts from 
	//unpaused execution

	void BenchmarkContext::resume() const noexcept {
		//ETWUtils::pause = false;
		//std::cout << "resume\n";
	}
	void BenchmarkContext::pause() const noexcept {
		//ETWUtils::pause = true;
		//std::cout << "pause\n";
	}
	BenchmarkContextIterator BenchmarkContext::begin() {
		return BenchmarkContextIterator(*this);
	}
	BenchmarkContextIterator BenchmarkContext::end() {
		return BenchmarkContextIterator(*this);
	}
	std::string const& BenchmarkContext::get_name() const {
		return m_name;
	}
	uint64_t BenchmarkContext::get_current_iteration() const {
		return m_current_iteration;
	}

	
	//using benchmark_func = std::function<void(BenchmarkContext&)>;
	Benchmark::Benchmark(const benchmark_func& fn) :
		m_fn(fn),
		m_context(BenchmarkContext())
	{
		benchmarks.push_back(*this);
	}
	Benchmark::Benchmark(const benchmark_func& fn, const BenchmarkProperties& props) :
		m_fn(fn),
		m_context(BenchmarkContext(props))
	{
		benchmarks.push_back(*this);
	}
	void Benchmark::run() noexcept {
		//std::cout << std::hex << (uint32_t)m_context.m_profiling_flags << std::dec << "\n";
		auto start = std::chrono::high_resolution_clock::now();

		bool res = ETWUtils::start(m_context.m_profiling_flags);
		if (res) {
			m_context.resume();

			m_fn(m_context);

			ETWUtils::stop();

			auto end = std::chrono::high_resolution_clock::now();
			std::chrono::duration<double> duration = end - start;
			duration -= std::chrono::duration<double>(0.5);

			//pause + resume on BenchmarkContextIterand lifetime
			//means the all of the overflow events get discarded
			//because I can't stop the collection while paused in the kernel logger
			//unless I completely stop it, which wipes the counters
			//and I can't sample them :((
			//instead I will manually remove the iteration count number of branches from the branch count
			//it only gets mispredicted a handful of times so it shouldn't 
			//significantly affect the results
			ETWUtils::ProfilerFlags flags = m_context.m_profiling_flags;
			auto masked = flags & (ETWUtils::ProfilerFlags::BranchInstructions | ETWUtils::ProfilerFlags::BranchInstructionsRetired);
			if (masked != ETWUtils::ProfilerFlags::None) {
				for (auto& pair : ETWUtils::active_profile_sources) {
					if (pair.second.name == std::wstring(L"BranchInstructions")) {
						pair.second.value -= m_context.m_current_iteration;
					}
					else if (pair.second.name == std::wstring(L"BranchInstructionsRetired")) {
						pair.second.value -= m_context.m_current_iteration;
					}
				}
			}

			auto it = results.find(m_context.m_name);
			if (it != results.end()) {
				it->second.push_back(BenchmarkResult(*this, duration.count()));
			}
			else
			{
				results.emplace(
					std::pair<std::string, std::vector<BenchmarkResult>>(
						m_context.m_name, { BenchmarkResult(*this, duration.count()) }
					)
				);
			}

		}
		else
		{
			std::cerr << "Failed to run benchmark " << m_context.m_name << "\n";
		}
	}
	BenchmarkContext const& Benchmark::get_context() const {
		return m_context;
	}

	void default_logger(BenchmarkResult& result) {
		auto& context = result.get_benchmark().get_context();

		std::cout << context.get_name() << ":\n"
			<< context.get_current_iteration() << " iterations\n"
			<< "lasted: " << result.m_duration_s << "s\n";
		for (auto& counter : result.m_counters) {
			std::wcout << counter.name << ": " << counter.value << "\n";
		}
	}

	BenchmarkResult::BenchmarkResult(const Benchmark& benchmark, double duration_s) :
		m_benchmark(benchmark),
		m_logger_fn(default_logger),
		m_duration_s(duration_s)
	{
		//copy the active counters into the BenchmarkResult m_counters
		for (auto& pair : ETWUtils::active_profile_sources) {
			m_counters.push_back(pair.second);
		}
	}
	void BenchmarkResult::log() {
		m_logger_fn(*this);
	}
	void BenchmarkResult::set_logger(const BenchmarkResult::logger_func& fn)
	{
		m_logger_fn = fn;
	}
	Benchmark const& BenchmarkResult::get_benchmark() const {
		return m_benchmark;
	}

	void run_benchmarks() {
		ETWUtils::init();

		for (auto& benchmark : benchmarks) {
			benchmark.run();
		}
	}

	BenchmarkResult& get_result(const std::string& s)
	{
		// TODO: insert return statement here
		return get_result(s, 0);
	}

	//can throw std::excecption if there is no result found for the passed benchmark name
	//can throw out of bounds from the index into the vector
	BenchmarkResult& get_result(const std::string& name, int idx=0) {
		const auto& it = results.find(name);
		if (it != results.cend()) {
			return it->second[idx];
		}
		else
		{
			throw std::exception("Attempt to get result from unknown name");
		}
	}

}