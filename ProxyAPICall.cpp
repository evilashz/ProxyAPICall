#include <windows.h>
#include <tuple>
#include <map>
#include <stdio.h>
#include "stub.h"


char* WorkCallbackArgAddr = NULL;
int offset = 0;

template<class Tuple, std::size_t N>
struct TuplePrinter {
    static void operate(const Tuple& t)
    {
        TuplePrinter<Tuple, N - 1>::operate(t);
        memcpy(WorkCallbackArgAddr + offset, &std::get<N - 1>(t), sizeof(char*));
        offset += sizeof(char*);
    }
};

template<class Tuple>
struct TuplePrinter<Tuple, 1> {
    static void operate(const Tuple& t)
    {
        memcpy(WorkCallbackArgAddr + offset, &std::get<0>(t), sizeof(char*));
        offset += sizeof(char*);
    }
};

template<class... Args>
void OperateTuple(const std::tuple<Args...>& t){
    TuplePrinter<decltype(t), sizeof...(Args)>::operate(t);
}


template<typename... ServiceArgs>
uint32_t ProxyCall(ServiceArgs... args) {

    //Init
    FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpAllocWork");
    FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpPostWork");
    FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpReleaseWork");

    //Init Call Stub Map
    std::map<int, unsigned char*> stub_map;
    stub_map.insert(std::make_pair(1, WorkCallback_stub_arg_1));
    stub_map.insert(std::make_pair(2, WorkCallback_stub_arg_2));
    stub_map.insert(std::make_pair(3, WorkCallback_stub_arg_3));
    stub_map.insert(std::make_pair(4, WorkCallback_stub_arg_4));
    stub_map.insert(std::make_pair(5, WorkCallback_stub_arg_5));
    stub_map.insert(std::make_pair(6, WorkCallback_stub_arg_6));
    stub_map.insert(std::make_pair(7, WorkCallback_stub_arg_7));
    stub_map.insert(std::make_pair(8, WorkCallback_stub_arg_8));
    stub_map.insert(std::make_pair(9, WorkCallback_stub_arg_9));
    stub_map.insert(std::make_pair(10, WorkCallback_stub_arg_10));
    stub_map.insert(std::make_pair(11, WorkCallback_stub_arg_11));


    std::size_t argsize = sizeof...(ServiceArgs);
    auto data = std::make_tuple(std::forward<ServiceArgs>(args)...);
   
    std::size_t argBufferSize = argsize * sizeof(char*);
    WorkCallbackArgAddr = (char*)malloc(argBufferSize);
    memset(WorkCallbackArgAddr, 0x00, argBufferSize);

    //operate args
    OperateTuple(data);

    //locate args num
    auto maplocation = stub_map.find(argsize);
    unsigned char* WorkCallback_stub = maplocation->second;

    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback_stub, WorkCallbackArgAddr, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

    WaitForSingleObject((HANDLE)-1, 0x1000);

    free(WorkCallbackArgAddr);

    return 0;

}

int main()
{   
    void* allocation = nullptr;
    SIZE_T size = 0x1000;
    
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");

    ProxyCall(pNtAllocateVirtualMemory,
        (ULONG_PTR) -1,
        &allocation,
        (ULONG_PTR) 0,
        &size,
        (ULONG_PTR)MEM_RESERVE | MEM_COMMIT,
        (ULONG_PTR)PAGE_READWRITE);

    printf("allocatedAddress: %p\n", allocation);
}

