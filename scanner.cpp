#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <exception>
#include <cstdint>
#include <vector>
#include <sstream>
#include <fstream>

template <typename T>
void print_hex(std::ostream &stream, T x, int width = 8){
	stream << std::hex << std::setw(width) << std::setfill('0') << x << std::dec;
}

template <typename T>
void print_address(std::ostream &stream, T x){
	if (x < 0x100)
		print_hex(stream, x, 2);
	else if (x < 0x10000)
		print_hex(stream, x, 4);
	else if (x < 0x100000000ULL)
		print_hex(stream, x, 8);
	else
		print_hex(stream, x, 16);
}

class DebugProcess{
	DWORD pid;
public:
	DebugProcess(DWORD pid): pid(pid){
		if (!DebugActiveProcess(pid)){
			auto error = GetLastError();
			std::cerr << "DebugActiveProcess() failed with error " << error << " (0x";
			print_hex(std::cerr, error);
			std::cerr << ")\n";
			throw std::exception();
		}
	}
	~DebugProcess(){
		if (!DebugActiveProcessStop(this->pid)){
			auto error = GetLastError();
			std::cerr << "DebugActiveProcessStop() failed with error " << error << " (0x";
			print_hex(std::cerr, error);
			std::cerr << ")\n";
		}
	}
};

bool is_handle_valid(HANDLE handle){
	return handle && handle != INVALID_HANDLE_VALUE;
}

class AutoHandle{
	HANDLE handle;
public:
	AutoHandle(HANDLE handle): handle(handle){}
	~AutoHandle(){
		if (is_handle_valid(this->handle))
			CloseHandle(this->handle);
	}
};

template <typename T>
void zero_struct(T &mem){
	memset(&mem, 0, sizeof(mem));
}

struct memory_region{
	std::uint64_t start,
		size;
	MEMORY_BASIC_INFORMATION info;
};

void dump_process_memory(DWORD pid){
	DebugProcess dp(pid);

	auto proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!is_handle_valid(proc)){
		auto error = GetLastError();
		std::cerr << "OpenProcess() failed with error " << error << " (0x";
		print_hex(std::cerr, error);
		std::cerr << ")\n";
		return;
	}
	AutoHandle autoproc(proc);

	std::vector<memory_region> regions;
	for (std::uint64_t address = 0; address < 0x10000000ULL;){
		MEMORY_BASIC_INFORMATION mbi;
		zero_struct(mbi);
		auto bytes = VirtualQueryEx(proc, (LPCVOID)address, &mbi, sizeof(mbi));
		if (!bytes){
			address += 4096;
			continue;
		}
		if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) != PAGE_GUARD)
			regions.push_back(memory_region{ (std::uint64_t)mbi.BaseAddress, mbi.RegionSize, mbi });

		address += mbi.RegionSize;
	}

	if (regions.size()){
		std::cout << "Flat size:   " << regions.back().start + regions.back().size << std::endl;
		std::uint64_t sum = 0;
		for (auto &region : regions)
			sum += region.size;
		std::cout << "Packed size: " << sum << std::endl;
	}

	std::ofstream file("dump.bin", std::ios::binary);
	std::uint64_t current_size = 0;
	for (auto &region : regions){
		std::vector<char> buffer(region.size);
		size_t read;
		if (!ReadProcessMemory(proc, (LPCVOID)region.start, &buffer[0], buffer.size(), &read)){
			auto error = GetLastError();
			if (error != ERROR_PARTIAL_COPY){
				std::cerr << "ReadProcessMemory() failed with error " << error << " (0x";
				print_hex(std::cerr, error);
				std::cerr << ")\n";
				return;
			}
		}

		if (read < region.size){
#if 1
			std::cerr << "Warning: region starting at 0x";
			print_address(std::cerr, region.start);
			std::cerr << " has size " << region.size << ", but only " << read
				<< " bytes could be read by ReadProcessMemory().\n";
#endif
			memset(&buffer[read], 0, buffer.size() - read);
		}

		file.seekp(region.start);

		file.write(&buffer[0], buffer.size());
	}
}

int main(int argc, char **argv){
	if (argc < 2)
		return 0;
	DWORD pid;
	{
		std::stringstream stream(argv[1]);
		if (!(stream >> pid))
			return 0;
	}

	try{
		dump_process_memory(pid);
	}catch (std::exception &){
		std::cerr << "Exception caught.\n";
	}

	return 0;
}
