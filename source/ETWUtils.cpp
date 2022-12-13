
#define INITGUID
#include "ETWUtils.hpp"
#include <vector>
#include <iostream>

//compilation unit locals
std::unordered_map<DWORD, std::string> err_str_map( {
	{0, "NO_ERROR(0)"} 
});
std::unordered_map<DWORD, std::wstring> err_wstr_map({
	{0, L"NO_ERROR(0)"}
});
std::vector<std::byte> kernel_properties_buffer{};

//namespace member globals
std::unordered_map<uint32_t, ETWUtils::PMCCounter> ETWUtils::active_profile_sources{};
std::vector<ETWUtils::PMCCounter> ETWUtils::supported_profile_sources{};
std::wstring ETWUtils::last_error{};
TRACEHANDLE ETWUtils::kernel_handle{ INVALID_PROCESSTRACE_HANDLE };
TRACEHANDLE ETWUtils::session_handle{ INVALID_PROCESSTRACE_HANDLE };
std::thread ETWUtils::session_thread{ std::thread() }; //empty thread
bool ETWUtils::session_running = false;
bool ETWUtils::pause = false;

const std::string& _get_last_err_string() {
	//Get the error message ID, if any.
	DWORD errorMessageID = GetLastError();
	if (errorMessageID == 0) {
		return ""; //No error message has been recorded
	}

	if (err_str_map.find(errorMessageID) == err_str_map.end()) {
		//key not found, get the formatted message and emplace it

		LPSTR messageBuffer = nullptr;

		//Ask Win32 to give us the string version of that message ID.
		//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
		size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

		//Copy the error message into a std::string.
		std::string message(messageBuffer, size);

		//Free the Win32's string's buffer.
		LocalFree(messageBuffer);

		err_str_map.emplace(errorMessageID, message);
	}
	
	return err_str_map.at(errorMessageID);
}

const std::wstring& _get_last_err_wstring() {
	//Get the error message ID, if any.
	DWORD errorMessageID = GetLastError();
	if (errorMessageID == 0) {
		return std::wstring(); //No error message has been recorded
	}

	if (err_wstr_map.find(errorMessageID) == err_wstr_map.end()) {
		LPWSTR messageBuffer = nullptr;

		//Ask Win32 to give us the string version of that message ID.
		//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
		size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

		//Copy the error message into a std::string.
		std::wstring message(messageBuffer, size);

		//Free the Win32's string's buffer.
		LocalFree(messageBuffer);

		err_wstr_map.emplace(errorMessageID, message);
	}

	return err_wstr_map.at(errorMessageID);
}

const char* ETWUtils::TraceException::what() {
	return "ETWUtils TraceException Occurred. Error Message can be found by reading ETWUtils::last_error.";
}

ETWUtils::TraceBadResultException::TraceBadResultException(ULONG res) : std::exception(), m_res(res) {

}

const char* ETWUtils::TraceBadResultException::what() {
	try {
		return _get_last_err_string().c_str(); //no lifetime issues since its a const ref to a string with a lifetime that lasts the duration of the program
	}
	catch (...) {
		//Oops, something went wrong!
		return "ETWUtils TraceBadResultException: failed to format win32 error DWORD";
	}
}

const wchar_t* ETWUtils::TraceBadResultException::w_what() {
	try {
		return _get_last_err_wstring().c_str();
	}
	catch (...) {
		return L"ETWUtils TraceBadResultException: failed to format win32 error DWORD";
	}
}

//https://docs.microsoft.com/en-us/windows/win32/etw/perfinfo
//typedef struct _GUID {
//    unsigned long  Data1;
//    unsigned short Data2;
//    unsigned short Data3;
//    unsigned char  Data4[ 8 ];
//} GUID;
constexpr GUID perfinfo_guid = {
	0xce1dbfb4, 0x137e, 0x4da6, {0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc}
};

auto process_id = GetCurrentProcessId();
DWORD benchmark_thread_id{ 0 };

bool is_null_thread(const std::thread& t) {
	return t.get_id() == std::thread::id();
}

int interrupts = 0;

void WINAPI record_event_callback(PEVENT_RECORD pEvent) noexcept {
	//I only check GUID equals once so we can use the inline version to avoid some call overhead
	if (!InlineIsEqualGUID(pEvent->EventHeader.ProviderId, perfinfo_guid)) {
		return;
	}

	if (ETWUtils::pause) {
		return;
	}

	switch (pEvent->EventHeader.EventDescriptor.Opcode) {
		//https://github.com/microsoftarchive/bcl/blob/master/Tools/ETW/traceEvent/KernelTraceEventParser.cs
		//you can find the relevent opcodes here
		//they are also the low order word of the dwords here, so 71 is "NMI" which for me means "Never (gonna) Make It" cos I'm never gonna make it sadpepe
		//https://github.com/processhacker/phnt/blob/master/ntexapi.h

		//pEvent->EventHeader.ThreadId is the thread that generated the event
		//this will be some kernel mode thread for the interrupts, so we have to read the ThreadId property from the event data 

		//PMCCounterProf 
		case 47: {
			auto tid = ETWUtils::read_property<uint32_t>(pEvent, L"ThreadId");
			if (tid != benchmark_thread_id) {
				return;
			}

			auto source = ETWUtils::read_property<uint32_t>(pEvent, L"ProfileSource");
			auto& ref = ETWUtils::active_profile_sources.at(source);

			ref.value += ref.interval;
			
			break;
		}
		case 72://SetInterval

			break;

		case 73://CollectionStart
		{
			uint32_t source = ETWUtils::read_property<uint32_t>(pEvent, L"Source");
			if (source == 0) {
				//Something went wrong.
				return;
			}

			uint32_t interval = ETWUtils::read_property<uint32_t>(pEvent, L"NewInterval");

			try {
				auto& PMC = ETWUtils::active_profile_sources.at(source);
				PMC.interval = interval;
			}
			catch (std::out_of_range e)
			{
				std::cout << "OUT_OF_RANGE EXCEPTION ON CollectionStart for Source_ID " << source << std::endl;
			}

			break;
		}
		case 74://CollectionEnd
			break;

		default:
			break;
	}


}

#pragma warning( push )
#pragma warning( disable: 4100)
bool WINAPI buffer_event_callback(PEVENT_TRACE_LOGFILE pBuf) {
	return true;
}
#pragma warning( pop )

void ETWUtils::enumerate_providers(std::function<void(const ETWUtils::ProviderInfo&)> callback) {
	std::unique_ptr<PROVIDER_ENUMERATION_INFO> p_enuminfo_buffer;
	DWORD buffer_size{ 0 };
	HRESULT hr{ S_OK };
	WCHAR str_guid[MAX_GUID_SIZE]{ 0 };
	DWORD RegisteredMOFCount = 0;
	DWORD RegisteredManifestCount = 0;
	DWORD status{ 0 };

	//TdhEnumerateProviders will resize the buffer to the needed size when it returns ERROR_INSUFFICIENT_BUFFER
	while (status = TdhEnumerateProviders(p_enuminfo_buffer.get(), &buffer_size) == ERROR_INSUFFICIENT_BUFFER) {
		p_enuminfo_buffer.reset(static_cast<PROVIDER_ENUMERATION_INFO*>(static_cast<void*>(new uint8_t[buffer_size])));
		if (p_enuminfo_buffer.get() == nullptr) {
			last_error = FNSIGW + (L": TdhEnumerateProviders:\nFailed allocation: " + _get_last_err_wstring());
			throw ETWUtils::TraceException();
		}
	}

	if (status != ERROR_INVALID_PARAMETER) {

		for (DWORD i = 0; i < p_enuminfo_buffer->NumberOfProviders; i++) {
			auto& provider_info = p_enuminfo_buffer->TraceProviderInfoArray[i];

			hr = StringFromGUID2(
				provider_info.ProviderGuid,
				str_guid,
				MAX_GUID_SIZE
			);

			if (hr == 0) {
				last_error = FNSIGW + std::wstring(L": StringFromGUID2:\nInsufficient string buffer size.");
				throw ETWUtils::TraceException();
			}
			else
			{
				WCHAR* p_provider_name = reinterpret_cast<WCHAR*>(
					reinterpret_cast<uintptr_t>(p_enuminfo_buffer.get()) + provider_info.ProviderNameOffset
				);

				callback({ provider_info.ProviderGuid, provider_info.ProviderNameOffset == 1, p_provider_name, str_guid });
			}
		}

	}
	else
	{
		last_error = FNSIGW + (L": TdhEnumerateProviders:\nInvalid Parameter: " + _get_last_err_wstring());
		throw ETWUtils::TraceException();
	}
}

void reconstruct_tracepropertiesbuffers(
	std::vector<ETWUtils::TracePropertiesBuffer>& properties_buffer_array, 
	std::vector<ETWUtils::TracePropertiesBuffer*>& microsoft_braindamage_pointer_array,
	ULONG count
) 
{
	properties_buffer_array.clear();
	microsoft_braindamage_pointer_array.clear();

	properties_buffer_array.reserve(count);
	for (ULONG i = 0; i < count; i++) {
		properties_buffer_array.emplace_back();
		auto& new_buffer = properties_buffer_array.back();

		new_buffer.m_properties.Wnode.BufferSize = sizeof(ETWUtils::TracePropertiesBuffer);
		new_buffer.m_properties.LogFileNameOffset = ETWUtils::_tpb_path_offset;
		new_buffer.m_properties.LoggerNameOffset = ETWUtils::_tpb_name_offset;

		microsoft_braindamage_pointer_array.emplace_back(&new_buffer);
	}
}

void ETWUtils::enumerate_sessions(std::function<void(const ETWUtils::TracePropertiesBuffer&)> callback) {
	ULONG logger_count{ 8 };

	std::vector<ETWUtils::TracePropertiesBuffer> properties_buffers{};
	std::vector<ETWUtils::TracePropertiesBuffer*> properties_buffers_pointers{};
	reconstruct_tracepropertiesbuffers(properties_buffers, properties_buffers_pointers, logger_count);

	ULONG status = ERROR_SUCCESS;
	//loop until all sessions loaded into TracePropertiesBuffer vector
	while (status = QueryAllTracesW((PEVENT_TRACE_PROPERTIES*)&properties_buffers_pointers[0], logger_count, &logger_count) == ERROR_MORE_DATA) {
		reconstruct_tracepropertiesbuffers(properties_buffers, properties_buffers_pointers, logger_count);
	}

	if (status == ERROR_INVALID_PARAMETER) {

		last_error = FNSIGW + (L": QueryAllTracesW:\nInvalid Parameter: " + _get_last_err_wstring());
		throw ETWUtils::TraceException();
	}

	//apply the callback
	for (auto& properties_buffer : properties_buffers) {
		callback(properties_buffer);
		//we dont need the properties_buffer anymore
	}
}

void _test_TraceQueryInformation_result(ULONG res) {
	using namespace ETWUtils;

	if (res != ERROR_SUCCESS) {
		last_error = L"query_performance_counters.TraceQueryInformation.";

		switch (res) {
		case ERROR_BAD_LENGTH:
			last_error += L"ERROR_BAD_LENGTH";
			break;
		case ERROR_INVALID_PARAMETER:
			last_error += L"ERROR_INVALID_PARAMETER";
			break;
		case ERROR_NOT_SUPPORTED:
			last_error += L"ERROR_NOT_SUPPORTED";
			break;
		default:
			last_error += L"OTHER(ERRCODE: " + std::to_wstring(GetLastError()) + L")";
		}

		last_error += _get_last_err_wstring();

		throw TraceException();
	}
}

std::vector<ETWUtils::PMCCounter> requery_performance_counters() {
	//required reading: https://www.geoffchappell.com/studies/windows/win32/advapi32/api/etw/logapi/query.htm
	std::vector<ETWUtils::PMCCounter> counters{};

	ULONG buffer_length{ 0 };
	ULONG res = TraceQueryInformation(0, TraceProfileSourceListInfo, nullptr, 0, &buffer_length);
	//_test_TraceQueryInformation_result(res);
	//I shit you not, the ETW MSDN DOCUMENTED METHOD TO TraceQueryInformation
	//returns BAD_LENGTH
	//FOR VALID USE CASES WHERE YOU WANT TO GET THE LENGTH

	std::vector<uint8_t> buffer(buffer_length);

	res = TraceQueryInformation(
		0,
		_TRACE_QUERY_INFO_CLASS::TraceProfileSourceListInfo,
		buffer.data(),
		static_cast<ULONG>(buffer.size()),
		&buffer_length
	);
	_test_TraceQueryInformation_result(res);

	TRACE_PROFILE_INTERVAL interval;
	PROFILE_SOURCE_INFO* p_head = reinterpret_cast<PROFILE_SOURCE_INFO*>(buffer.data()); //reader "head"
	while (p_head != nullptr) {
		ETWUtils::PMCCounter counter{};

		counter.name = p_head->Description;
		counter.source = p_head->Source;
		interval.Source = p_head->Source;
		

		ULONG interval_length;
		res = TraceQueryInformation(
			0,
			TraceSampledProfileIntervalInfo,
			&interval,
			sizeof(interval),
			&interval_length
		);
		_test_TraceQueryInformation_result(res);

		counter.interval = interval.Interval;
		counter.value = 0;
		counter.min_interval = p_head->MinInterval;
		counters.push_back(std::move(counter));

		if (p_head->NextEntryOffset == 0) {
			p_head = nullptr;
		}
		else
		{
			//ptr math is undefined behavior so cast to uint64_t 
			p_head = reinterpret_cast<PROFILE_SOURCE_INFO*>(reinterpret_cast<uintptr_t>(p_head) + p_head->NextEntryOffset);

		}
	}

	return counters;
}

const std::vector<ETWUtils::PMCCounter>& ETWUtils::query_performance_counters() {
	//if supported profile sources haven't already been queried
	if (supported_profile_sources.empty()) {
		//load the supported sources
		supported_profile_sources = requery_performance_counters();
	}

	return supported_profile_sources;
}

bool ETWUtils::init() {
	//side-effect is loading the supported profile sources into ETWUtils::supported_profile_sources
	query_performance_counters();
	toggle_system_profiling(true);

	return true;
}

//adds system profiling privileges to the process privilege token
void ETWUtils::toggle_system_profiling(bool t) {
	LUID Privilege;
	if (!LookupPrivilegeValueW(0, SE_SYSTEM_PROFILE_NAME, &Privilege)) {
		last_error = FNSIGW + (L": LookupPrivilegeValueW\nFailed to find PrivilegeValueW associated with SE_SYSTEM_PROFILE_NAME: " + _get_last_err_wstring());
		throw TraceException();
	}
	//query for the local machine what the SE_SYSTEM_PROFILE_PRIVILEGE constant is

	HANDLE TokenHandle;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_READ, &TokenHandle)) {
		last_error = FNSIGW + (L": OpenProcessToken: \n" + _get_last_err_wstring());
		throw TraceException();
	}
	//get a token for the process with privileges to adjust the token

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Privilege;
	tp.Privileges[0].Attributes = t ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(TokenHandle, false, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		last_error = FNSIGW + (L": AdjustTokenPrivileges:\n" + _get_last_err_wstring());
		throw TraceException();
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		last_error = FNSIGW + (L": AdjustTokenPrivileges:\n" + _get_last_err_wstring());
		throw TraceException();
	}
}

//throws TraceException if PMC is not found
ETWUtils::PMCCounter& find_supported_PMC(const std::wstring& s) {
	for (auto& c : ETWUtils::supported_profile_sources) {
		if (c.name == s) {
			return c;
		}
	}
	ETWUtils::last_error = L"Failed to locate a supported PMC" + s;
	throw ETWUtils::TraceException();
}

void _enable_profilers(std::vector<ETWUtils::PMCCounter>& counters) {
	using namespace ETWUtils;
	//was originally written as a ETWUtils:: member, but then moved out to be an internal method, so I could simplify the interface

	if (counters.size() == 0) {
		last_error = L"bad call to _enable_profilers, minimum at least one counter required";
		throw TraceException();
	}
	else if(counters.size() > 4) {
		last_error = L"Windows Kernel behavior is undefined for any number of counters beyond 4 "
			L"Windows does not differentiate between Programmable and Fixed Counters";
		while (counters.size() > 4) {
			counters.pop_back();
		}
	}

	size_t alloc_size = counters.size() * sizeof(uint32_t);
	int* sources_arr = static_cast<int*>(malloc(alloc_size));
	ZeroMemory(sources_arr, alloc_size);

	uint8_t idx = 0;
	for (auto& counter : counters) {
		TRACE_PROFILE_INTERVAL interval;
		interval.Source = counter.source;
		interval.Interval = 100;
		//will just default to the MinInterval of the KE_PROFILESOURCE 
		//usually 4096

		ULONG res = TraceSetInformation(
			0,
			TraceSampledProfileIntervalInfo,
			&interval,
			sizeof(TRACE_PROFILE_INTERVAL)
		);
		if (res != ERROR_SUCCESS) {
			throw TraceBadResultException(res);
		}

		counter.interval = interval.Interval;
		counter.value = 0;
		sources_arr[idx] = counter.source;
		idx++;
		active_profile_sources[counter.source] = counter;
	}

	ULONG result = TraceSetInformation(
		0,
		TraceProfileSourceConfigInfo,
		sources_arr,
		alloc_size
	);
	if (result != ERROR_SUCCESS) {
		throw TraceBadResultException(result);
	}
}

void ETWUtils::enable_profilers(ProfilerFlags flags) {
	std::vector<PMCCounter> counters{};
	uint8_t ProgrammableCount{ 0 };
	uint8_t FixedCount{ 0 };

	const auto addp = [&](const wchar_t* w) {
		const auto& pmc = find_supported_PMC(w);

		if (ProgrammableCount++ > 4) {
			last_error = L"Attempt to set over 4 simultaneous programmable counters";
			throw TraceException();
		}
		else
		{
			counters.push_back(pmc);
		}
	};

	const auto addf = [&](const wchar_t* w) {
		const auto& pmc = find_supported_PMC(w);

		if (FixedCount++ > 3) {
			last_error = L"Attempt to set over 3 simultaneous fixed counters";
			throw TraceException();
		}
		else
		{
			counters.push_back(pmc);
		}
	};

	if ((flags & ProfilerFlags::TotalIssues) != ProfilerFlags::None) {
		addp(L"TotalIssues");
	}
	if ((flags & ProfilerFlags::BranchInstructions) != ProfilerFlags::None) {
		addp(L"BranchInstructions");
	}
	if ((flags & ProfilerFlags::CacheMisses) != ProfilerFlags::None) {
		addp(L"CacheMisses");
	}
	if ((flags & ProfilerFlags::BranchMispredictions) != ProfilerFlags::None) {
		addp(L"BranchMispredictions");
	}
	if ((flags & ProfilerFlags::TotalCycles) != ProfilerFlags::None) {
		addp(L"TotalCycles");
	}
	if ((flags & ProfilerFlags::UnhaltedCoreCycles) != ProfilerFlags::None) {
		addp(L"UnhaltedCoreCycles");
	}
	if ((flags & ProfilerFlags::InstructionsRetired) != ProfilerFlags::None) {
		addp(L"InstructionRetired");
	}
	if ((flags & ProfilerFlags::UnhaltedReferenceCycles) != ProfilerFlags::None) {
		addp(L"UnhaltedReferenceCycles");
	}
	if ((flags & ProfilerFlags::LLCReferences) != ProfilerFlags::None) {
		addp(L"LLCReference");
	}
	if ((flags & ProfilerFlags::LLCMisses) != ProfilerFlags::None) {
		addp(L"LLCMisses");
	}
	if ((flags & ProfilerFlags::BranchInstructionsRetired) != ProfilerFlags::None) {
		addp(L"BranchInstructionRetired");
	}
	if ((flags & ProfilerFlags::BranchMispredictsRetired) != ProfilerFlags::None) {
		addp(L"BranchMispredictsRetired");
	}
	if ((flags & ProfilerFlags::LbrInserts) != ProfilerFlags::None) {
		addp(L"LbrInserts");
	}
	if ((flags & ProfilerFlags::InstructionsRetiredFixed) != ProfilerFlags::None) {
		addf(L"InstructionsRetiredFixed");
	}
	if ((flags & ProfilerFlags::UnhaltedCoreCyclesFixed) != ProfilerFlags::None) {
		addf(L"UnhaltedCoreCyclesFixed");
	}
	if ((flags & ProfilerFlags::UnhaltedReferenceCyclesFixed) != ProfilerFlags::None) {
		addf(L"UnhaltedReferenceCyclesFixed");
	}
	if ((flags & ProfilerFlags::TimerFixed) != ProfilerFlags::None) {
		
		addf(L"TimerFixed");
	}

	if (counters.size() > 4) {
		std::cerr << "Cannot set more than 4 simultaneous counters\n";
		last_error = L"Cannot set more t han 4 simultaneous counters\n";
		throw TraceException();
	}

	_enable_profilers(counters);
}

void open_kernel_logger_session_handle()
{
	EVENT_TRACE_LOGFILEW logfile{};
	logfile.LoggerName = const_cast<LPWSTR>(KERNEL_LOGGER_NAMEW);
	logfile.EventRecordCallback = reinterpret_cast<PEVENT_RECORD_CALLBACK>(record_event_callback);
	logfile.BufferCallback = reinterpret_cast<PEVENT_TRACE_BUFFER_CALLBACKW>(buffer_event_callback);
	logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	logfile.Context = nullptr;

	ETWUtils::session_handle = OpenTraceW(&logfile);
}

void ETWUtils::create_trace_session() {

	if (session_handle != INVALID_PROCESSTRACE_HANDLE) { 
		last_error = FNSIGW + std::wstring(L": session already exists and/or was not properly stopped.");
		throw TraceException(); 
	}

	open_kernel_logger_session_handle();

	if (session_handle == INVALID_PROCESSTRACE_HANDLE) {
		throw TraceBadResultException(GetLastError());
	}

	session_thread = std::thread([&] {
		ULONG res = ProcessTrace(&session_handle, 1, nullptr, nullptr);
		if (res != ERROR_SUCCESS) {
			std::cout << "ProcessTrace failed reason: " << res << std::endl;
			return;
			//throw TraceBadResultException(res); //intentionally cause a crash so I can figure out what went wrong
		}
	});
	//block the calling thread for a while, because otherwise the session can be stopped before the logger has started
	//and this causes an error inside the ProcessTrace function (invalid handle) because the trace gets closed too quickly
	Sleep(500);


	//do not detach
	//ETWUtils::stop() will join the session_thread
	//program termination without ending profiling (stopping the trace) will be bad
	//implementing ETWUtils should use RAII for microbenchmarks and the objects should be in heap memory (NOT ON THE STACK!)
	//this way exit() etc will still call destructors 
}

PEVENT_TRACE_PROPERTIES init_kernel_properties() noexcept {
	//set up the kernel trace
	size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES_V2) + sizeof(KERNEL_LOGGER_NAME) + 1;

	kernel_properties_buffer.clear();
	kernel_properties_buffer.resize(bufferSize); //num_elements is equiv to size in a vector of <byte> (cos size is measured in bytes)

	PEVENT_TRACE_PROPERTIES properties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(kernel_properties_buffer.data());
	properties->EnableFlags = EVENT_TRACE_FLAG_PROFILE; //gets perf events, maybe I will add interrupts later
	properties->Wnode.Guid = SystemTraceControlGuid;
	properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES;
	properties->Wnode.BufferSize = static_cast<ULONG>(bufferSize);
	properties->Wnode.ClientContext = 1; //uses the QPC clock (100ns)
	properties->LogFileMode = EVENT_TRACE_INDEPENDENT_SESSION_MODE | EVENT_TRACE_REAL_TIME_MODE;
	properties->FlushTimer = 1; //defaults to 1
	properties->LogFileNameOffset = 0;
	properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	return properties;
}

void load_kernel_handle(PEVENT_TRACE_PROPERTIES properties) {
	ULONG res = ControlTrace(0, KERNEL_LOGGER_NAME, properties, EVENT_TRACE_CONTROL_STOP);
	if (res != ERROR_SUCCESS) {
		if (res != ERROR_WMI_INSTANCE_NOT_FOUND) {
			std::cerr << "Attempted to Control a Trace Session that is not running" << std::endl;
			throw ETWUtils::TraceBadResultException(res);	
		}
		else
		{
			SetLastError(0);
		}
	}
}

void ETWUtils::enable_kernel_trace_flags(std::initializer_list<ULONG> flags) {
	//required reading
	//https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-the-nt-kernel-logger-session
	//https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/trace-flags
	// 
	// 
	//call StartTrace to get the KERNEL_LOGGER_NAME kernel logger handle
	//use bitwise OR to add the specified flags into the existing flag mask
	//use TraceSetInformation to update the flags

	PEVENT_TRACE_PROPERTIES properties = init_kernel_properties();
	load_kernel_handle(properties);

	ULONG res = StartTraceW(&kernel_handle, KERNEL_LOGGER_NAMEW, properties);
	if (res != ERROR_SUCCESS) {
		std::cout << FNSIG << ":StartTraceW\n" << _get_last_err_string() << std::endl;
		throw TraceBadResultException(res);
	}

	EVENT_TRACE_GROUPMASK_INFORMATION groupmaskinfo{};
	groupmaskinfo.EventTraceInformationClass = EventTraceGroupMaskInformation;
	groupmaskinfo.TraceHandle = kernel_handle;

	//query SystemPerformanceTraceInformation to get EVENT_TRACE_INFORMATION_CLASS
											//SystemPerformanceTraceInformation
	res = TraceQueryInformation(kernel_handle, TraceSystemTraceEnableFlagsInfo, &groupmaskinfo.EventTraceGroupMasks, sizeof(PERFINFO_GROUPMASK), nullptr);
	if (res != ERROR_SUCCESS) {
		throw TraceBadResultException(res);
	}
	//load the kernel logger session group mask into our groupmaskinfo struct 

	//there are 8 potential groups that the mask info can go into, but the group it's in is held in the first nibble (single hex digit) of the mask
	//https://github.com/processhacker/phnt/blob/master/ntexapi.h
	//above has all the definitions, the stuff we care about can be found below:
	//https://github.com/processhacker/phnt/blob/master/ntexapi.h#L2155

	ULONG PERF_GROUP_IDX_MASK = 0xe0000000;


	for (ULONG flag : flags) {
		//we can bitwise AND the PERF_GROUP to our mask and then bitwise shift it so all we have is the top 3 bits (>> 29) to get which mask index it goes into
		uint8_t mask_idx = (PERF_GROUP_IDX_MASK & flag) >> 29;

		groupmaskinfo.EventTraceGroupMasks.Masks[mask_idx] |= (flag & (~PERF_GROUP_IDX_MASK));
		//bitwise OR our mask bits into the correct mask
	}

	//submit the masks to enable the various desired kernel logger events
	res = TraceSetInformation(kernel_handle, TraceSystemTraceEnableFlagsInfo, &groupmaskinfo.EventTraceGroupMasks, sizeof(ULONG) * 8);
	if (res != ERROR_SUCCESS) {
		throw TraceBadResultException(res);
	}
}

//returns false if the trace failed to start
//cleans up in the case of any internal exceptions
bool ETWUtils::start(ProfilerFlags flags) noexcept {
	benchmark_thread_id = GetCurrentThreadId();
	//native thread ID because those are what we get given by the EVENTRECORD struct in the event record callback

	try {
		toggle_system_profiling(true);
	}
	catch (std::exception& e) //ref so no slicing
	{
		std::cerr << "Failed to enable system profiling privileges\n" << e.what();
		return false;
	}

	try {
		stop();
	}
	catch (TraceException e) {
		//thrown by no session running
		//continue
	}

	//active_profile_sources.clear();
	try {
		enable_profilers(flags);
	}
	catch (TraceException e)
	{
		std::wcerr << L"TraceException: " << last_error << L"\n";
	}
	catch (std::exception& e) {
		std::cerr << "Unknown exception attempting to enable_profilers\n";
		std::cerr << e.what() << "\n";
	}

	try {
		if (kernel_handle == INVALID_PROCESSTRACE_HANDLE) {
			enable_kernel_trace_flags({ PERF_PMC_PROFILE });
		}

		create_trace_session();

		session_running = true;
		return true;
	}
	catch (TraceException e) {
		std::wcerr << L"TraceException: " << last_error << L"\n";

		stop();
	}

	return false;
}

//strong guarantee to stop the kernel logger
void ETWUtils::stop() noexcept {
	if (!session_running) { 
		//std::cout << "close existing kernel session" << std::endl;
		try {
			load_kernel_handle(init_kernel_properties()); //stops the kernel logger if it's already running so it can be reconfig'd
		}
		catch (TraceBadResultException e) {
			//the session is already stopped
			//the exception is caused by ERROR_WMI_INSTANCE_NOT_FOUND
		}
	}
	else
	{
		ULONG res = CloseTrace(session_handle);
		if (res != ERROR_CTX_CLOSE_PENDING && res != ERROR_SUCCESS) {
			std::cout << "FAILED TO STOP KE SESSION: " << res << std::endl;
			//throw TraceBadResultException(res);
			//error would be ERROR_INVALID_HANDLE but I think my handle is always valid in this branch
			//for all possible valid state permutations i.e all deterministic control flow paths of execution
			//session_running is true IF AND ONLY IF session_handle is set 

			//in the impossible scenario that we do reach this path of execution
			//invalidate whatever garbage value was in our session_handle variable
			session_handle = INVALID_PROCESSTRACE_HANDLE;

			//try to load up the kernel session (make sure it's running)
			load_kernel_handle(init_kernel_properties());

			//load the kernel logger handle
			open_kernel_logger_session_handle();

			//retry the stop operation now that we should be in a valid state
			stop();
		}

		session_thread.join();
		session_running = false;
		session_handle = INVALID_PROCESSTRACE_HANDLE;
		kernel_handle = INVALID_PROCESSTRACE_HANDLE;

		//load_kernel_handle(init_kernel_properties()); //stops the kernel logger if it's already running so it can be reconfig'd
	}
}
