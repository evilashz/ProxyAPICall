#pragma once
#include <windows.h>

//stub in .text section
#define ALLOC_ON_CODE \
_Pragma("section(\".text\")") \
__declspec(allocate(".text"))


typedef NTSTATUS(NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID(NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID(NTAPI* TPRELEASEWORK)(PTP_WORK);

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_1[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_2[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_3[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR[rbx + 0x18]

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_4[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR[rbx + 0x18]
    0x4c, 0x8b, 0x4b, 0x20,                                 // mov r9,  QWORD PTR[rbx + 0x20]

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_5[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR[rbx + 0x18]
    0x4c, 0x8b, 0x4b, 0x20,                                 // mov r9,  QWORD PTR[rbx + 0x20]

    0x4c, 0x8b, 0x53, 0x28,                                 // mov r10, QWORD PTR[rbx+0x28]
    0x4c, 0x89, 0x54, 0x24, 0x28,                           // mov QWORD PTR[rsp + 0x28], r10

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_6[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR[rbx + 0x18]
    0x4c, 0x8b, 0x4b, 0x20,                                 // mov r9,  QWORD PTR[rbx + 0x20]

    0x4c, 0x8b, 0x53, 0x30,                                 // mov r10, QWORD PTR[rbx + 0x30]
    0x4c, 0x89, 0x54, 0x24, 0x30,                           // mov QWORD PTR[rsp + 0x30], r10
    0x4c, 0x8b, 0x53, 0x28,                                 // mov r10, QWORD PTR[rbx + 0x28]
    0x4c, 0x89, 0x54, 0x24, 0x28,                           // mov QWORD PTR[rsp + 0x28], r10

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_7[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR[rbx+0x18]
    0x4c, 0x8b, 0x4b, 0x20,                                 // mov r9,  QWORD PTR[rbx + 0x20]

    0x4c, 0x8b, 0x53, 0x38,                                 // mov r10, QWORD PTR[rbx + 0x38]
    0x4c, 0x89, 0x54, 0x24, 0x38,                           // mov QWORD PTR[rsp + 0x38], r10
    0x4c, 0x8b, 0x53, 0x30,                                 // mov r10, QWORD PTR[rbx + 0x30]
    0x4c, 0x89, 0x54, 0x24, 0x30,                           // mov QWORD PTR[rsp + 0x30], r10
    0x4c, 0x8b, 0x53, 0x28,                                 // mov r10, QWORD PTR[rbx + 0x28]
    0x4c, 0x89, 0x54, 0x24, 0x28,                           // mov QWORD PTR[rsp + 0x28], r10

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_8[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR[rbx+0x18]
    0x4c, 0x8b, 0x4b, 0x20,                                 // mov r9,  QWORD PTR[rbx + 0x20]

    0x4c, 0x8b, 0x53, 0x40,                                 // mov r10, QWORD PTR[rbx + 0x40]
    0x4c, 0x89, 0x54, 0x24, 0x40,                           // mov QWORD PTR[rsp + 0x40], r10
    0x4c, 0x8b, 0x53, 0x38,                                 // mov r10, QWORD PTR[rbx + 0x38]
    0x4c, 0x89, 0x54, 0x24, 0x38,                           // mov QWORD PTR[rsp + 0x38], r10
    0x4c, 0x8b, 0x53, 0x30,                                 // mov r10, QWORD PTR[rbx + 0x30]
    0x4c, 0x89, 0x54, 0x24, 0x30,                           // mov QWORD PTR[rsp + 0x30], r10
    0x4c, 0x8b, 0x53, 0x28,                                 // mov r10, QWORD PTR[rbx + 0x28]
    0x4c, 0x89, 0x54, 0x24, 0x28,                           // mov QWORD PTR[rsp + 0x28], r10

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_9[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR[rbx+0x18]
    0x4c, 0x8b, 0x4b, 0x20,                                 // mov r9,  QWORD PTR[rbx + 0x20]

    0x4c, 0x8b, 0x53, 0x48,                                 // mov r10, QWORD PTR[rbx + 0x48]
    0x4c, 0x89, 0x54, 0x24, 0x48,                           // mov QWORD PTR[rsp + 0x48], r10
    0x4c, 0x8b, 0x53, 0x40,                                 // mov r10, QWORD PTR[rbx + 0x40]
    0x4c, 0x89, 0x54, 0x24, 0x40,                           // mov QWORD PTR[rsp + 0x40], r10
    0x4c, 0x8b, 0x53, 0x38,                                 // mov r10, QWORD PTR[rbx + 0x38]
    0x4c, 0x89, 0x54, 0x24, 0x38,                           // mov QWORD PTR[rsp + 0x38], r10
    0x4c, 0x8b, 0x53, 0x30,                                 // mov r10, QWORD PTR[rbx + 0x30]
    0x4c, 0x89, 0x54, 0x24, 0x30,                           // mov QWORD PTR[rsp + 0x30], r10
    0x4c, 0x8b, 0x53, 0x28,                                 // mov r10, QWORD PTR[rbx + 0x28]
    0x4c, 0x89, 0x54, 0x24, 0x28,                           // mov QWORD PTR[rsp + 0x28], r10

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_10[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR[rbx+0x18]
    0x4c, 0x8b, 0x4b, 0x20,                                 // mov r9,  QWORD PTR[rbx + 0x20]

    0x4c, 0x8b, 0x53, 0x50,                                 // mov r10, QWORD PTR[rbx + 0x50]
    0x4c, 0x89, 0x54, 0x24, 0x50,                           // mov QWORD PTR[rsp + 0x50], r10
    0x4c, 0x8b, 0x53, 0x48,                                 // mov r10, QWORD PTR[rbx + 0x48]
    0x4c, 0x89, 0x54, 0x24, 0x48,                           // mov QWORD PTR[rsp + 0x48], r10
    0x4c, 0x8b, 0x53, 0x40,                                 // mov r10, QWORD PTR[rbx + 0x40]
    0x4c, 0x89, 0x54, 0x24, 0x40,                           // mov QWORD PTR[rsp + 0x40], r10
    0x4c, 0x8b, 0x53, 0x38,                                 // mov r10, QWORD PTR[rbx + 0x38]
    0x4c, 0x89, 0x54, 0x24, 0x38,                           // mov QWORD PTR[rsp + 0x38], r10
    0x4c, 0x8b, 0x53, 0x30,                                 // mov r10, QWORD PTR[rbx + 0x30]
    0x4c, 0x89, 0x54, 0x24, 0x30,                           // mov QWORD PTR[rsp + 0x30], r10
    0x4c, 0x8b, 0x53, 0x28,                                 // mov r10, QWORD PTR[rbx + 0x28]
    0x4c, 0x89, 0x54, 0x24, 0x28,                           // mov QWORD PTR[rsp + 0x28], r10

    0xff, 0xe0                                              // jmp rax

};

ALLOC_ON_CODE unsigned char WorkCallback_stub_arg_11[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR[rbx+0x18]
    0x4c, 0x8b, 0x4b, 0x20,                                 // mov r9,  QWORD PTR[rbx + 0x20]

    0x4c, 0x8b, 0x53, 0x58,                                 // mov r10, QWORD PTR[rbx + 0x58]
    0x4c, 0x89, 0x54, 0x24, 0x58,                           // mov QWORD PTR[rsp + 0x58], r10
    0x4c, 0x8b, 0x53, 0x48,                                 // mov r10, QWORD PTR[rbx + 0x48]
    0x4c, 0x89, 0x54, 0x24, 0x48,                           // mov QWORD PTR[rsp + 0x48], r10
    0x4c, 0x8b, 0x53, 0x40,                                 // mov r10, QWORD PTR[rbx + 0x40]
    0x4c, 0x89, 0x54, 0x24, 0x40,                           // mov QWORD PTR[rsp + 0x40], r10
    0x4c, 0x8b, 0x53, 0x38,                                 // mov r10, QWORD PTR[rbx + 0x38]
    0x4c, 0x89, 0x54, 0x24, 0x38,                           // mov QWORD PTR[rsp + 0x38], r10
    0x4c, 0x8b, 0x53, 0x30,                                 // mov r10, QWORD PTR[rbx + 0x30]
    0x4c, 0x89, 0x54, 0x24, 0x30,                           // mov QWORD PTR[rsp + 0x30], r10
    0x4c, 0x8b, 0x53, 0x28,                                 // mov r10, QWORD PTR[rbx + 0x28]
    0x4c, 0x89, 0x54, 0x24, 0x28,                           // mov QWORD PTR[rsp + 0x28], r10

    0xff, 0xe0                                              // jmp rax

};