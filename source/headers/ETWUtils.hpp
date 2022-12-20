#ifndef SRC_HEADERS_ETWUTILS_HPP
#define SRC_HEADERS_ETWUTILS_HPP

#define ETWU_WCONV2(x) L##x
#define ETWU_WCONV(x) ETWU_WCONV2(x)
#define FNSIGW ETWU_WCONV(__FUNCSIG__)
#define FNSIG __FUNCSIG__
//TODO: other compilers support than just MSVC 

#define NOMINMAX
#include <Windows.h>
#include <powerbase.h>
extern "C" {
	#include <powrprof.h>
}
#pragma comment(lib, "Powrprof.lib")

#include <wmistr.h>
#include <evntrace.h>
//LINK AGAINST tdh.lib
#pragma comment(lib, "tdh.lib")
#include <tdh.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <string>
#include <functional>
#include <map>
#include <array>
#include <thread>
#include <winternl.h>
#include <iostream>
#include <mutex>



#define MAX_GUID_SIZE 39 //taken from https://learn.microsoft.com/en-us/windows/win32/etw/enumerating-providers

//https://github.com/processhacker/phnt/blob/master/ntexapi.h#L2155
//alternative: https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/um/minwin/ntwmi.h#L626
#define PERF_MEMORY             0x20000001
#define PERF_PROFILE            0x20000002  // equivalent to EVENT_TRACE_FLAG_PROFILE
#define PERF_CONTEXT_SWITCH     0x20000004  // equivalent to EVENT_TRACE_FLAG_CSWITCH
#define PERF_FOOTPRINT          0x20000008
#define PERF_DRIVERS            0x20000010  // equivalent to EVENT_TRACE_FLAG_DRIVER
#define PERF_REFSET             0x20000020
#define PERF_POOL               0x20000040
#define PERF_POOLTRACE          0x20000041
#define PERF_DPC                0x20000080  // equivalent to EVENT_TRACE_FLAG_DPC
#define PERF_COMPACT_CSWITCH    0x20000100
#define PERF_DISPATCHER         0x20000200  // equivalent to EVENT_TRACE_FLAG_DISPATCHER
#define PERF_PMC_PROFILE        0x20000400
#define PERF_PROFILING          0x20000402
#define PERF_PROCESS_INSWAP     0x20000800
#define PERF_AFFINITY           0x20001000
#define PERF_PRIORITY           0x20002000
#define PERF_INTERRUPT          0x20004000  // equivalent to EVENT_TRACE_FLAG_INTERRUPT
#define PERF_VIRTUAL_ALLOC      0x20008000  // equivalent to EVENT_TRACE_FLAG_VIRTUAL_ALLOC
#define PERF_SPINLOCK           0x20010000
#define PERF_SYNC_OBJECTS       0x20020000
#define PERF_DPC_QUEUE          0x20040000
#define PERF_MEMINFO            0x20080000
#define PERF_CONTMEM_GEN        0x20100000
#define PERF_SPINLOCK_CNTRS     0x20200000
#define PERF_SPININSTR          0x20210000
#define PERF_SESSION            0x20400000
#define PERF_PFSECTION          0x20400000
#define PERF_MEMINFO_WS         0x20800000
#define PERF_KERNEL_QUEUE       0x21000000
#define PERF_INTERRUPT_STEER    0x22000000
#define PERF_SHOULD_YIELD       0x24000000
#define PERF_WS                 0x28000000

constexpr const auto& min(const int& a, const int& b) {
	return (b < a) ? b : a;
}

namespace ETWUtils {

	//PMUs not found here may exist but not be supported, or I simply may not have those PMUs on my CPU so cannot develop for them. :(
	enum class ProfilerFlags : uint32_t {
		None = 0,
		TotalIssues = 1,
		BranchInstructions = 2,

		//I can't find if there is any tracing of whether this is L1, L2 or L3 cache. Really, there is NO documentation on this. On the entire internet.
		//TODO: use the TdhGetProperty to just dump the entire event and see if there is anything relevant to whether it is L1/L2/L3 Cache
		//note: LLCMisses can be subtracted and that leaves us with L1/L2 cache misses
		CacheMisses = 4,

		BranchMispredictions = 8,
		TotalCycles = 16,

		//Possible to filter for which thread was active when this overflows the interval, idk if the value is reset when a different thread is switched into the core
		//
		UnhaltedCoreCycles = 32,

		InstructionsRetired = 64,

		//Reference-Cycles uses base clock speed cycles, so you can convert to wall time
		//NOTE: Prefer the UnhaltedReferenceCyclesFixed, so that you don't consume one of 4 available programmable counter slots
		//This limitation is kernel based, if you write your own kernel mode driver you can consume as many programmable counters as your chip supports
		UnhaltedReferenceCycles = 128,

		//Something to do with LAST LEVEL CACHE (L3 on most desktops) 
		//Probably any access(read/write) to the LLC 
		LLCReferences = 256,

		//Identical to CacheMisses, PREFER CacheMisses for portability
		LLCMisses = 512,
		BranchInstructionsRetired = 1024,
		BranchMispredictsRetired = 2048,

		//record inserted into branch table
		//TODO: Use TdhGetProperty to dump the event and see if there is any useful data
		LbrInserts = 4096,

		//Fixed counters are separate from Programmable counters, You can have 3 Fixed and 4 Programmable simultaneously.
		//RAII implementation ontop of the Utils may internally hog all 3 Fixed counters for e.g. InstructionsRetired 
		
		InstructionsRetiredFixed = 8192,
		UnhaltedCoreCyclesFixed = 16384,
		UnhaltedReferenceCyclesFixed = 32768,
		TimerFixed = 65536
	};
	inline constexpr bool operator==(const ProfilerFlags& a, const ProfilerFlags& b) {
		return static_cast<uint32_t>(a) == static_cast<uint32_t>(b);
	}
	inline constexpr ProfilerFlags operator&(const ProfilerFlags& a, const ProfilerFlags& b)
	{
		return static_cast<ProfilerFlags>(
			static_cast<uint32_t>(a) & static_cast<uint32_t>(b)
		);
	}
	inline constexpr ProfilerFlags operator|(const ProfilerFlags& a, const ProfilerFlags& b)
	{
		return static_cast<ProfilerFlags>(
			static_cast<uint32_t>(a) | static_cast<uint32_t>(b)
		);
	}
	inline constexpr ProfilerFlags operator~(const ProfilerFlags& a)
	{
		return static_cast<ProfilerFlags>(
			~static_cast<uint32_t>(a)
		);
	}
	inline constexpr ProfilerFlags operator^(const ProfilerFlags& a, const ProfilerFlags& b)
	{
		return static_cast<ProfilerFlags>(
			static_cast<uint32_t>(a) ^ static_cast<uint32_t>(b)
		);
	}
	inline constexpr ProfilerFlags operator>>(const ProfilerFlags& a, const int b)
	{
		return static_cast<ProfilerFlags>(
			static_cast<uint32_t>(a) >> b
		);
	}
	inline constexpr ProfilerFlags operator<<(const ProfilerFlags& a, const int b)
	{
		return static_cast<ProfilerFlags>(
			static_cast<uint32_t>(a) << b
		);
	}
	inline constexpr ProfilerFlags operator&=(const ProfilerFlags& a, const ProfilerFlags& b)
	{
		return a & b;
	}
	inline constexpr ProfilerFlags operator|=(const ProfilerFlags& a, const ProfilerFlags& b)
	{
		return a | b;
	}
	inline constexpr ProfilerFlags operator^=(const ProfilerFlags& a, const ProfilerFlags& b)
	{
		return a ^ b;
	}

	//maximum session name length
	constexpr uint16_t session_name_max = 1024;
	//maximum logfile path length
	constexpr uint16_t logfile_path_max = 1024;

	struct ProviderInfo {
		GUID m_guid;
		bool m_is_MOF;
		std::wstring m_name;
		std::wstring m_guid_str;
	};

	struct TracePropertiesBuffer {
		EVENT_TRACE_PROPERTIES m_properties;
		WCHAR m_log_file_name[logfile_path_max];
		WCHAR m_logger_name[session_name_max];
	};
	constexpr size_t _tpb_path_offset = offsetof(TracePropertiesBuffer, m_log_file_name);
	constexpr size_t _tpb_name_offset = offsetof(TracePropertiesBuffer, m_logger_name);

	struct PMCCounter {
		std::wstring name;
		uint64_t interval;
		uint32_t source;  
		uint64_t value;
		uint64_t min_interval;
	};

	//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracesup/class.htm
	enum EVENT_TRACE_INFORMATION_CLASS {
		EventTraceKernelVersionInformation = 0,
		EventTraceGroupMaskInformation = 1,
		EventTracePerformanceInformation = 2,
		EventTraceTimeProfileInformation = 3,
		EventTraceSessionSecurityInformation = 4,
		EventTraceSpinlockInformation = 5,
		EventTraceStackTracingINformation = 6,
		EventTraceExecutiveResourceInformation = 7,
		EventTraceHeapTracingInformation = 8,
		EventTraceHeapSummaryTracingInformation = 9,
		EventTracePoolTagFilterInformation = 10,
		EventTracePebsTracingInformation = 11,
		EventTraceProfileConfigInformation = 12,
		EventTraceProfileSourceListInformation = 13,
		EventTraceProfileEventListInformation = 14,
		EventTraceProfileCounterListInformation = 15,
		EventTraceStackCachingInformation = 16,
		EventTraceObjectTypeFilterInformation = 17,
		MaxEventTraceInfoClass
	};

	//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntwmi/perfinfo_groupmask.htm
	struct PERFINFO_GROUPMASK {
		ULONG Masks[8];
		DWORD Reserved;
	};

	//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntetw/event_trace_groupmask_information.htm
	struct EVENT_TRACE_GROUPMASK_INFORMATION {
		EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
		TRACEHANDLE TraceHandle;
		PERFINFO_GROUPMASK EventTraceGroupMasks;
	};

	struct TraceException : public std::exception {
		const char* what();
	};

	struct TraceBadResultException : public std::exception {
		TraceBadResultException(ULONG res);

		const char* what();
		const wchar_t* w_what();
	private:
		ULONG m_res;
	};

	extern std::vector<PMCCounter> supported_profile_sources;
	extern std::unordered_map<uint32_t, PMCCounter> active_profile_sources;
	extern std::wstring last_error;
	extern TRACEHANDLE kernel_handle;
	extern TRACEHANDLE session_handle;
	extern std::thread session_thread;
	extern bool session_running;
	extern bool pause;

	extern std::mutex tracing_mutex;

	extern DWORD process_id;
	//extern uint64_t interval;//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/profile/setinterval.htm

	void enumerate_providers(std::function<void(const ProviderInfo&)> callback);
	void enumerate_sessions(std::function<void(const TracePropertiesBuffer&)> callback);
	
	const std::vector<PMCCounter>& query_performance_counters();
	
	template <class T> 
	//returns an xvalue T 
	T read_property(PEVENT_RECORD p_event_record, const wchar_t* property_name) {
		PROPERTY_DATA_DESCRIPTOR desc{};
		desc.PropertyName = reinterpret_cast<ULONGLONG>(property_name);
		desc.ArrayIndex = 0;

		ULONG property_size;
		TDHSTATUS res = TdhGetPropertySize(p_event_record, 0, nullptr, 1, &desc, &property_size);
		if (res != ERROR_SUCCESS) {
			std::cout << "read_property err(" << res << ")\n";
			//return 0;
			throw TraceBadResultException(res);
		}

		constexpr uint8_t size = min(64, sizeof(T)); //align to at most 64 byte boundary
		std::vector<std::byte> buffer(size);
		//uintptr_t addr = reinterpret_cast<uintptr_t>(buffer.data())+ size - (reinterpret_cast<uintptr_t>(buffer.data()) % size);//ensure alignment, this is pedantic but good practice 
		
		
		res = TdhGetProperty(p_event_record, 0, nullptr, 1, &desc, property_size, 
			reinterpret_cast<BYTE*>(buffer.data()));
		if (res != ERROR_SUCCESS) {
			std::cout << "read_property err2\n";
			return 0;
			//throw TraceBadResultException(res);
		}

		//Not UB because TdhGetProperty is a C API and returns primitive types, object alignment rules don't apply
		return *reinterpret_cast<T*>(buffer.data());
	}

	bool init();
	void toggle_system_profiling(bool t);
	void enable_profilers(ProfilerFlags flags);
	void create_trace_session();
	void enable_kernel_trace_flags(std::initializer_list<ULONG> flags);
	//starts tracing without clearing the previous trace counters
	//bool _start(ProfilerFlags flags) noexcept;
	bool start(ProfilerFlags flags) noexcept;
	void stop() noexcept;
	double get_last_trace_duration() noexcept;
}


#endif