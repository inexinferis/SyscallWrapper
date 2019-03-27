/*++ NDK Version: 0098
Copyright (c) Alex Ionescu.  All rights reserved.
Header Name:
    pstypes.h
Abstract:
    Type definitions for the Process Manager
Author:
    Alex Ionescu (alexi@tinykrnl.org) - Updated - 27-Feb-2006
--*/

#ifndef _PSTYPES_H
#define _PSTYPES_H

#ifndef STATUS_ASSERTION_FAILURE
#define STATUS_ASSERTION_FAILURE  0xC0000420
#endif

#ifndef STATUS_FAILURE
#define STATUS_FAILURE   0x80000000
#endif

#define ROUND_UP(VALUE,ROUND) ((ULONG)(((ULONG)VALUE + ((ULONG)ROUND - 1L)) & (~((ULONG)ROUND - 1L))))
#define ROUND_SIZE  ROUND_UP

#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#define RtlGetProcessHeap() (NtCurrentPeb()->ProcessHeap)

//#define WH_MIN -1
#define WH_MAX 14
#define WH_MINHOOK WH_MIN
#define WH_MAXHOOK WH_MAX
#define NB_HOOKS (WH_MAXHOOK-WH_MINHOOK+1)

#define RPL_MASK                                0x0003
#define MODE_MASK                               0x0001
#define KGDT_R0_CODE                            (0x8)
#define KGDT_R0_DATA                            (0x10)
#define KGDT_R3_CODE                            (0x18)
#define KGDT_R3_DATA                            (0x20)
#define KGDT_TSS                                (0x28)
#define KGDT_R0_PCR                             (0x30)
#define KGDT_R3_TEB                             (0x38)
#define KGDT_LDT                                (0x48)
#define KGDT_DF_TSS                             (0x50)
#define KGDT_NMI_TSS                            (0x58)

//
// KV86M_REGISTERS Offsets
//
#define KV86M_REGISTERS_EBP                     0x0
#define KV86M_REGISTERS_EDI                     0x4
#define KV86M_REGISTERS_ESI                     0x8
#define KV86M_REGISTERS_EDX                     0xC
#define KV86M_REGISTERS_ECX                     0x10
#define KV86M_REGISTERS_EBX                     0x14
#define KV86M_REGISTERS_EAX                     0x18
#define KV86M_REGISTERS_DS                      0x1C
#define KV86M_REGISTERS_ES                      0x20
#define KV86M_REGISTERS_FS                      0x24
#define KV86M_REGISTERS_GS                      0x28
#define KV86M_REGISTERS_EIP                     0x2C
#define KV86M_REGISTERS_CS                      0x30
#define KV86M_REGISTERS_EFLAGS                  0x34
#define KV86M_REGISTERS_ESP                     0x38
#define KV86M_REGISTERS_SS                      0x3C
#define TF_SAVED_EXCEPTION_STACK                0x8C
#define TF_REGS                                 0x90
#define TF_ORIG_EBP                             0x94

//
// TSS Offsets
//
#define KTSS_ESP0                               0x4
#define KTSS_CR3                                0x1C
#define KTSS_EFLAGS                             0x24
#define KTSS_IOMAPBASE                          0x66
#define KTSS_IO_MAPS                            0x68

//
// KTHREAD Offsets
//
#define KTHREAD_DEBUG_ACTIVE                    0x03
#define KTHREAD_INITIAL_STACK                   0x18
#define KTHREAD_STACK_LIMIT                     0x1C
#define KTHREAD_TEB                             0x74
#define KTHREAD_KERNEL_STACK                    0x20
#define KTHREAD_NPX_STATE                       0x4D
#define KTHREAD_STATE                           0x4C
#define KTHREAD_ALERTED                         0x5E
#define KTHREAD_APCSTATE_PROCESS                0x28 + 0x10
#define KTHREAD_PENDING_USER_APC                0x28 + 0x16
#define KTHREAD_PENDING_KERNEL_APC              0x28 + 0x15
#define KTHREAD_CONTEXT_SWITCHES                0x48
#define KTHREAD_WAIT_IRQL                       0x4E
#define KTHREAD_SERVICE_TABLE                   0x118
#define KTHREAD_PREVIOUS_MODE                   0xD7
#define KTHREAD_COMBINED_APC_DISABLE            0x70
#define KTHREAD_LARGE_STACK                     0x107
#define KTHREAD_TRAP_FRAME                      0x110
#define KTHREAD_CALLBACK_STACK                  0x114
#define KTHREAD_APC_STATE_INDEX                 0x11C
#define KTHREAD_STACK_BASE                      0x158

//
// KPROCESS Offsets
//
#define KPROCESS_DIRECTORY_TABLE_BASE           0x18
#define KPROCESS_LDT_DESCRIPTOR0                0x20
#define KPROCESS_LDT_DESCRIPTOR1                0x24
#define KPROCESS_IOPM_OFFSET                    0x30

//
// KPCR Offsets
//
#define KPCR_EXCEPTION_LIST                     0x0
#define KPCR_INITIAL_STACK                      0x4
#define KPCR_STACK_LIMIT                        0x8
#define KPCR_SET_MEMBER_COPY                    0x14
#define KPCR_TEB                                0x18
#define KPCR_SELF                               0x1C
#define KPCR_PRCB                               0x20
#define KPCR_IRQL                               0x24
#define KPCR_KD_VERSION_BLOCK                   0x34
#define KPCR_GDT                                0x3C
#define KPCR_TSS                                0x40
#define KPCR_SET_MEMBER                         0x48
#define KPCR_NUMBER                             0x51
#define KPCR_CURRENT_THREAD                     0x124
#define KPCR_PROCESSOR_NUMBER                   0x130
#define KPCR_PRCB_SET_MEMBER                    0x134
#define KPCR_NPX_THREAD                         0x2F4
#define KPCR_DR6                                0x428
#define KPCR_DR7                                0x42C
#define KPCR_SYSTEM_CALLS                       0x6B8

//
// KGDTENTRY Offsets
//
#define KGDT_BASE_LOW                           0x2
#define KGDT_BASE_MID                           0x4
#define KGDT_BASE_HI                            0x7
#define KGDT_LIMIT_HI                           0x6
#define KGDT_LIMIT_LOW                          0x0

//
// FPU Save Area Offsets
//
#define FN_CONTROL_WORD                         0x0
#define FN_STATUS_WORD                          0x4
#define FN_TAG_WORD                             0x8
#define FN_DATA_SELECTOR                        0x18
#define FN_CR0_NPX_STATE                        0x20C
#define SIZEOF_FX_SAVE_AREA                     528
#define NPX_FRAME_LENGTH                        0x210

//
// NPX States
//
#define NPX_STATE_NOT_LOADED                    0xA
#define NPX_STATE_LOADED                        0x0

//
// Trap Frame Offsets
//
#define KTRAP_FRAME_DEBUGEBP                    0x0
#define KTRAP_FRAME_DEBUGEIP                    0x4
#define KTRAP_FRAME_DEBUGARGMARK                0x8
#define KTRAP_FRAME_DEBUGPOINTER                0xC
#define KTRAP_FRAME_TEMPCS                      0x10
#define KTRAP_FRAME_TEMPESP                     0x14
#define KTRAP_FRAME_DR0                         0x18
#define KTRAP_FRAME_DR1                         0x1C
#define KTRAP_FRAME_DR2                         0x20
#define KTRAP_FRAME_DR3                         0x24
#define KTRAP_FRAME_DR6                         0x28
#define KTRAP_FRAME_DR7                         0x2C
#define KTRAP_FRAME_GS                          0x30
#define KTRAP_FRAME_RESERVED1                   0x32
#define KTRAP_FRAME_ES                          0x34
#define KTRAP_FRAME_RESERVED2                   0x36
#define KTRAP_FRAME_DS                          0x38
#define KTRAP_FRAME_RESERVED3                   0x3A
#define KTRAP_FRAME_EDX                         0x3C
#define KTRAP_FRAME_ECX                         0x40
#define KTRAP_FRAME_EAX                         0x44
#define KTRAP_FRAME_PREVIOUS_MODE               0x48
#define KTRAP_FRAME_EXCEPTION_LIST              0x4C
#define KTRAP_FRAME_FS                          0x50
#define KTRAP_FRAME_RESERVED4                   0x52
#define KTRAP_FRAME_EDI                         0x54
#define KTRAP_FRAME_ESI                         0x58
#define KTRAP_FRAME_EBX                         0x5C
#define KTRAP_FRAME_EBP                         0x60
#define KTRAP_FRAME_ERROR_CODE                  0x64
#define KTRAP_FRAME_EIP                         0x68
#define KTRAP_FRAME_CS                          0x6C
#define KTRAP_FRAME_EFLAGS                      0x70
#define KTRAP_FRAME_ESP                         0x74
#define KTRAP_FRAME_SS                          0x78
#define KTRAP_FRAME_RESERVED5                   0x7A
#define KTRAP_FRAME_V86_ES                      0x7C
#define KTRAP_FRAME_RESERVED6                   0x7E
#define KTRAP_FRAME_V86_DS                      0x80
#define KTRAP_FRAME_RESERVED7                   0x82
#define KTRAP_FRAME_V86_FS                      0x84
#define KTRAP_FRAME_RESERVED8                   0x86
#define KTRAP_FRAME_V86_GS                      0x88
#define KTRAP_FRAME_RESERVED9                   0x8A
#define KTRAP_FRAME_SIZE                        0x8C
#define KTRAP_FRAME_LENGTH                      0x8C
#define KTRAP_FRAME_ALIGN                       0x04
#define FRAME_EDITED                            0xFFF8

//
// KUSER_SHARED_DATA Offsets
//
#define KERNEL_USER_SHARED_DATA                 0x7FFE0000
#define KUSER_SHARED_PROCESSOR_FEATURES         KERNEL_USER_SHARED_DATA + 0x274
#define KUSER_SHARED_SYSCALL                    KERNEL_USER_SHARED_DATA + 0x300
#define KUSER_SHARED_SYSCALL_RET                KERNEL_USER_SHARED_DATA + 0x304
#define PROCESSOR_FEATURE_FXSR                  KUSER_SHARED_PROCESSOR_FEATURES + 0x4

//
// CONTEXT Offsets
//
#define CONTEXT_FLAGS                           0x0
#define CONTEXT_DR6                             0x14
#define CONTEXT_FLOAT_SAVE                      0x1C
#define CONTEXT_SEGGS                           0x8C
#define CONTEXT_SEGFS                           0x90
#define CONTEXT_SEGES                           0x94
#define CONTEXT_SEGDS                           0x98
#define CONTEXT_EDI                             0x9C
#define CONTEXT_ESI                             0xA0
#define CONTEXT_EBX                             0xA4
#define CONTEXT_EDX                             0xA8
#define CONTEXT_ECX                             0xAC
#define CONTEXT_EAX                             0xB0
#define CONTEXT_EBP                             0xB4
#define CONTEXT_EIP                             0xB8
#define CONTEXT_SEGCS                           0xBC
#define CONTEXT_EFLAGS                          0xC0
#define CONTEXT_ESP                             0xC4
#define CONTEXT_SEGSS                           0xC8
#define CONTEXT_FLOAT_SAVE_CONTROL_WORD         CONTEXT_FLOAT_SAVE + FN_CONTROL_WORD
#define CONTEXT_FLOAT_SAVE_STATUS_WORD          CONTEXT_FLOAT_SAVE + FN_STATUS_WORD
#define CONTEXT_FLOAT_SAVE_TAG_WORD             CONTEXT_FLOAT_SAVE + FN_TAG_WORD

//
// EXCEPTION_RECORD Offsets
//
#define EXCEPTION_RECORD_EXCEPTION_CODE         0x0
#define EXCEPTION_RECORD_EXCEPTION_FLAGS        0x4
#define EXCEPTION_RECORD_EXCEPTION_RECORD       0x8
#define EXCEPTION_RECORD_EXCEPTION_ADDRESS      0xC
#define EXCEPTION_RECORD_NUMBER_PARAMETERS      0x10
#define SIZEOF_EXCEPTION_RECORD                 0x14

//
// TEB Offsets
//
#define TEB_EXCEPTION_LIST                      0x0
#define TEB_STACK_BASE                          0x4
#define TEB_STACK_LIMIT                         0x8
#define TEB_FIBER_DATA                          0x10
#define TEB_PEB                                 0x30
#define TEB_EXCEPTION_CODE                      0x1A4
#define TEB_ACTIVATION_CONTEXT_STACK_POINTER    0x1A8
#define TEB_DEALLOCATION_STACK                  0xE0C
#define TEB_GUARANTEED_STACK_BYTES              0xF78
#define TEB_FLS_DATA                            0xFB4

//
// PEB Offsets
//
#define PEB_KERNEL_CALLBACK_TABLE               0x2C

//
// FIBER Offsets
//
#define FIBER_PARAMETER                         0x0
#define FIBER_EXCEPTION_LIST                    0x4
#define FIBER_STACK_BASE                        0x8
#define FIBER_STACK_LIMIT                       0xC
#define FIBER_DEALLOCATION_STACK                0x10
#define FIBER_CONTEXT                           0x14
#define FIBER_GUARANTEED_STACK_BYTES            0x2E0
#define FIBER_FLS_DATA                          0x2E4
#define FIBER_ACTIVATION_CONTEXT_STACK          0x2E8
#define FIBER_CONTEXT_FLAGS                     FIBER_CONTEXT + CONTEXT_FLAGS
#define FIBER_CONTEXT_EAX                       FIBER_CONTEXT + CONTEXT_EAX
#define FIBER_CONTEXT_EBX                       FIBER_CONTEXT + CONTEXT_EBX
#define FIBER_CONTEXT_ECX                       FIBER_CONTEXT + CONTEXT_ECX
#define FIBER_CONTEXT_EDX                       FIBER_CONTEXT + CONTEXT_EDX
#define FIBER_CONTEXT_ESI                       FIBER_CONTEXT + CONTEXT_ESI
#define FIBER_CONTEXT_EDI                       FIBER_CONTEXT + CONTEXT_EDI
#define FIBER_CONTEXT_EBP                       FIBER_CONTEXT + CONTEXT_EBP
#define FIBER_CONTEXT_ESP                       FIBER_CONTEXT + CONTEXT_ESP
#define FIBER_CONTEXT_DR6                       FIBER_CONTEXT + CONTEXT_DR6
#define FIBER_CONTEXT_FLOAT_SAVE_STATUS_WORD    FIBER_CONTEXT + CONTEXT_FLOAT_SAVE_STATUS_WORD
#define FIBER_CONTEXT_FLOAT_SAVE_CONTROL_WORD   FIBER_CONTEXT + CONTEXT_FLOAT_SAVE_CONTROL_WORD
#define FIBER_CONTEXT_FLOAT_SAVE_TAG_WORD       FIBER_CONTEXT + CONTEXT_FLOAT_SAVE_TAG_WORD

//
// EFLAGS
//
#define EFLAGS_TF                               0x100
#define EFLAGS_INTERRUPT_MASK                   0x200
#define EFLAGS_NESTED_TASK                      0x4000
#define EFLAGS_V86_MASK                         0x20000
#define EFLAGS_ALIGN_CHECK                      0x40000
#define EFLAGS_VIF                              0x80000
#define EFLAGS_VIP                              0x100000
#define EFLAG_SIGN                              0x8000
#define EFLAG_ZERO                              0x4000
#ifndef EFLAG_SELECT
#define EFLAG_SELECT                            (EFLAG_SIGN + EFLAG_ZERO)
#endif

//
// CR0
//
#define CR0_PE                                  0x1
#define CR0_MP                                  0x2
#define CR0_EM                                  0x4
#define CR0_TS                                  0x8
#define CR0_ET                                  0x10
#define CR0_NE                                  0x20
#define CR0_WP                                  0x10000
#define CR0_AM                                  0x40000
#define CR0_NW                                  0x20000000
#define CR0_CD                                  0x40000000
#define CR0_PG                                  0x80000000

//
// CR4
//
#define CR4_VME                                 0x1
#define CR4_PVI                                 0x2
#define CR4_TSD                                 0x4
#define CR4_DE                                  0x8
#define CR4_PSE                                 0x10
#define CR4_PAE                                 0x20
#define CR4_MCE                                 0x40
#define CR4_PGE                                 0x80
#define CR4_FXSR                                0x200
#define CR4_XMMEXCPT                            0x400

//
// Usermode callout frame definitions
//
#define CBSTACK_STACK                           0x0
#define CBSTACK_TRAP_FRAME                      0x4
#define CBSTACK_CALLBACK_STACK                  0x8
#define CBSTACK_RESULT                          0x20
#define CBSTACK_RESULT_LENGTH                   0x24

//
// NTSTATUS and Bugcheck Codes
//
#ifdef __ASM__
#define STATUS_ACCESS_VIOLATION                 0xC0000005
#define STATUS_INVALID_SYSTEM_SERVICE           0xC000001C
#define STATUS_NO_CALLBACK_ACTIVE               0xC0000258
#define APC_INDEX_MISMATCH                      0x01
#define IRQL_GT_ZERO_AT_SYSTEM_SERVICE          0x4A
#define UNEXPECTED_KERNEL_MODE_TRAP             0x7F
#endif

//
// System Call Table definitions
//
#define NUMBER_SERVICE_TABLES                   0x0002
#define SERVICE_NUMBER_MASK                     0x0FFF
#define SERVICE_TABLE_SHIFT                     0x0008
#define SERVICE_TABLE_MASK                      0x0010
#define SERVICE_TABLE_TEST                      0x0010
#define SERVICE_DESCRIPTOR_BASE                 0x0000
#define SERVICE_DESCRIPTOR_COUNT                0x0004
#define SERVICE_DESCRIPTOR_LIMIT                0x0008
#define SERVICE_DESCRIPTOR_NUMBER               0x000C
#define SERVICE_DESCRIPTOR_LENGTH               0x0010

//
// Generic Definitions
//
#define MAXIMUM_IDTVECTOR                       0xFF

//
// KUSER_SHARED_DATA location in User Mode
//
//#define USER_SHARED_DATA                        (0x7FFE0000)
#define MM_SHARED_USER_DATA_VA   0x7FFE0000
#define USER_SHARED_DATA   ((KUSER_SHARED_DATA * const)MM_SHARED_USER_DATA_VA)

//
// Global Flags
//
#define FLG_STOP_ON_EXCEPTION                   0x00000001
#define FLG_SHOW_LDR_SNAPS                      0x00000002
#define FLG_DEBUG_INITIAL_COMMAND               0x00000004
#define FLG_STOP_ON_HUNG_GUI                    0x00000008
#define FLG_HEAP_ENABLE_TAIL_CHECK              0x00000010
#define FLG_HEAP_ENABLE_FREE_CHECK              0x00000020
#define FLG_HEAP_VALIDATE_PARAMETERS            0x00000040
#define FLG_HEAP_VALIDATE_ALL                   0x00000080
#define FLG_POOL_ENABLE_TAIL_CHECK              0x00000100
#define FLG_POOL_ENABLE_FREE_CHECK              0x00000200
#define FLG_POOL_ENABLE_TAGGING                 0x00000400
#define FLG_HEAP_ENABLE_TAGGING                 0x00000800
#define FLG_USER_STACK_TRACE_DB                 0x00001000
#define FLG_KERNEL_STACK_TRACE_DB               0x00002000
#define FLG_MAINTAIN_OBJECT_TYPELIST            0x00004000
#define FLG_HEAP_ENABLE_TAG_BY_DLL              0x00008000
#define FLG_IGNORE_DEBUG_PRIV                   0x00010000
#define FLG_ENABLE_CSRDEBUG                     0x00020000
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD           0x00040000
#define FLG_DISABLE_PAGE_KERNEL_STACKS          0x00080000
#define FLG_HEAP_ENABLE_CALL_TRACING            0x00100000
#define FLG_HEAP_DISABLE_COALESCING             0x00200000
#define FLG_ENABLE_CLOSE_EXCEPTIONS             0x00400000
#define FLG_ENABLE_EXCEPTION_LOGGING            0x00800000
#define FLG_ENABLE_HANDLE_TYPE_TAGGING          0x01000000
#define FLG_HEAP_PAGE_ALLOCS                    0x02000000
#define FLG_DEBUG_INITIAL_COMMAND_EX            0x04000000
#define FLG_VALID_BITS                          0x07FFFFFF

//
// Process priority classes
//
#define PROCESS_PRIORITY_CLASS_INVALID          0
#define PROCESS_PRIORITY_CLASS_IDLE             1
#define PROCESS_PRIORITY_CLASS_NORMAL           2
#define PROCESS_PRIORITY_CLASS_HIGH             3
#define PROCESS_PRIORITY_CLASS_REALTIME         4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL     5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL     6

//
// NtCreateProcessEx flags
//
#define PS_REQUEST_BREAKAWAY                    1
#define PS_NO_DEBUG_INHERIT                     2
#define PS_INHERIT_HANDLES                      4
#define PS_LARGE_PAGES                          8
#define PS_ALL_FLAGS                            (PS_REQUEST_BREAKAWAY | \
                                                 PS_NO_DEBUG_INHERIT  | \
                                                 PS_INHERIT_HANDLES   | \
                                                 PS_LARGE_PAGES)

//
// Process base priorities
//
#define PROCESS_PRIORITY_IDLE                   3
#define PROCESS_PRIORITY_NORMAL                 8
#define PROCESS_PRIORITY_NORMAL_FOREGROUND      9

//
// Process memory priorities
//
#define MEMORY_PRIORITY_BACKGROUND             0
#define MEMORY_PRIORITY_UNKNOWN                1
#define MEMORY_PRIORITY_FOREGROUND             2

//
// Process Priority Separation Values (OR)
//
#define PSP_VARIABLE_QUANTUMS                   4
#define PSP_LONG_QUANTUMS                       16

#ifndef NTOS_MODE_USER

//
// Process Access Types
//
#define PROCESS_SUSPEND_RESUME                  0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION       0x1000
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
#define _PROCESS_ALL_ACCESS                      (STANDARD_RIGHTS_REQUIRED | \
                                                 SYNCHRONIZE | \
                                                 0xFFFF)
#else
#define _PROCESS_ALL_ACCESS                      (STANDARD_RIGHTS_REQUIRED | \
                                                 SYNCHRONIZE | \
                                                 0xFFF)

//
// Thread Base Priorities
//
#define THREAD_BASE_PRIORITY_LOWRT              15
#define THREAD_BASE_PRIORITY_MAX                2
#define THREAD_BASE_PRIORITY_MIN                -2
#define THREAD_BASE_PRIORITY_IDLE               -15

//
// TLS Slots
//
#define TLS_MINIMUM_AVAILABLE                   64
#endif

//
// Job Access Types
//
#define JOB_OBJECT_ASSIGN_PROCESS               0x1
#define JOB_OBJECT_SET_ATTRIBUTES               0x2
#define JOB_OBJECT_QUERY                        0x4
#define JOB_OBJECT_TERMINATE                    0x8
#define JOB_OBJECT_SET_SECURITY_ATTRIBUTES      0x10
#define JOB_OBJECT_ALL_ACCESS                   (STANDARD_RIGHTS_REQUIRED | \
                                                 SYNCHRONIZE | \
                                                 31)

//
// Cross Thread Flags
//
#define CT_TERMINATED_BIT                       0x1
#define CT_DEAD_THREAD_BIT                      0x2
#define CT_HIDE_FROM_DEBUGGER_BIT               0x4
#define CT_ACTIVE_IMPERSONATION_INFO_BIT        0x8
#define CT_SYSTEM_THREAD_BIT                    0x10
#define CT_HARD_ERRORS_ARE_DISABLED_BIT         0x20
#define CT_BREAK_ON_TERMINATION_BIT             0x40
#define CT_SKIP_CREATION_MSG_BIT                0x80
#define CT_SKIP_TERMINATION_MSG_BIT             0x100

//
// Same Thread Passive Flags
//
#define STP_ACTIVE_EX_WORKER_BIT                0x1
#define STP_EX_WORKER_CAN_WAIT_USER_BIT         0x2
#define STP_MEMORY_MAKER_BIT                    0x4
#define STP_KEYED_EVENT_IN_USE_BIT              0x8

//
// Same Thread APC Flags
//
#define STA_LPC_RECEIVED_MSG_ID_VALID_BIT       0x1
#define STA_LPC_EXIT_THREAD_CALLED_BIT          0x2
#define STA_ADDRESS_SPACE_OWNER_BIT             0x4
#define STA_OWNS_WORKING_SET_BITS               0x1F8
#endif

#define TLS_EXPANSION_SLOTS                     1024
//
// Process Flags
//
#define PSF_CREATE_REPORTED_BIT                 0x1
#define PSF_NO_DEBUG_INHERIT_BIT                0x2
#define PSF_PROCESS_EXITING_BIT                 0x4
#define PSF_PROCESS_DELETE_BIT                  0x8
#define PSF_WOW64_SPLIT_PAGES_BIT               0x10
#define PSF_VM_DELETED_BIT                      0x20
#define PSF_OUTSWAP_ENABLED_BIT                 0x40
#define PSF_OUTSWAPPED_BIT                      0x80
#define PSF_FORK_FAILED_BIT                     0x100
#define PSF_WOW64_VA_SPACE_4GB_BIT              0x200
#define PSF_ADDRESS_SPACE_INITIALIZED_BIT       0x400
#define PSF_SET_TIMER_RESOLUTION_BIT            0x1000
#define PSF_BREAK_ON_TERMINATION_BIT            0x2000
#define PSF_SESSION_CREATION_UNDERWAY_BIT       0x4000
#define PSF_WRITE_WATCH_BIT                     0x8000
#define PSF_PROCESS_IN_SESSION_BIT              0x10000
#define PSF_OVERRIDE_ADDRESS_SPACE_BIT          0x20000
#define PSF_HAS_ADDRESS_SPACE_BIT               0x40000
#define PSF_LAUNCH_PREFETCHED_BIT               0x80000
#define PSF_INJECT_INPAGE_ERRORS_BIT            0x100000
#define PSF_VM_TOP_DOWN_BIT                     0x200000
#define PSF_IMAGE_NOTIFY_DONE_BIT               0x400000
#define PSF_PDE_UPDATE_NEEDED_BIT               0x800000
#define PSF_VDM_ALLOWED_BIT                     0x1000000
#define PSF_SWAP_ALLOWED_BIT                    0x2000000
#define PSF_CREATE_FAILED_BIT                   0x4000000
#define PSF_DEFAULT_IO_PRIORITY_BIT             0x8000000

//
// Vista Process Flags
//
#define PSF2_PROTECTED_BIT                      0x800

//
// Current Process/Thread built-in 'special' handles
//
#define NtCurrentProcess()                      ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()                       ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentProcess()                      NtCurrentProcess()
#define ZwCurrentThread()                       NtCurrentThread()
#define GetCurrentProcess()                     NtCurrentProcess()
#define GetCurrentThread()                      NtCurrentThread()

#define RVA(m,b)  ((PVOID)((ULONG_PTR)(b)+(ULONG_PTR)(m)))
#define RVAPTR(c,m,b) ((c)((ULONG_PTR)(b)+(ULONG_PTR)(m)))

#define BYTEn(x, n)   (*((BYTE*)&(x)+n))
#define BYTE1(x)   BYTEn(x,  1)
#define BYTE2(x)   BYTEn(x,  2)
#define BYTE3(x)   BYTEn(x,  3)
#define BYTE4(x)   BYTEn(x,  4)

//
// Loader Data Table Entry Flags
//
#define LDRP_STATIC_LINK                        0x00000002
#define LDRP_IMAGE_DLL                          0x00000004
#define LDRP_LOAD_IN_PROGRESS                   0x00001000
#define LDRP_UNLOAD_IN_PROGRESS                 0x00002000
#define LDRP_ENTRY_PROCESSED                    0x00004000
#define LDRP_ENTRY_INSERTED                     0x00008000
#define LDRP_CURRENT_LOAD                       0x00010000
#define LDRP_FAILED_BUILTIN_LOAD                0x00020000
#define LDRP_DONT_CALL_FOR_THREADS              0x00040000
#define LDRP_PROCESS_ATTACH_CALLED              0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED               0x00100000
#define LDRP_IMAGE_NOT_AT_BASE                  0x00200000
#define LDRP_COR_IMAGE                          0x00400000
#define LDR_COR_OWNS_UNMAP                      0x00800000
#define LDRP_SYSTEM_MAPPED                      0x01000000
#define LDRP_IMAGE_VERIFYING                    0x02000000
#define LDRP_DRIVER_DEPENDENT_DLL               0x04000000
#define LDRP_ENTRY_NATIVE                       0x08000000
#define LDRP_REDIRECTED                         0x10000000
#define LDRP_NON_PAGED_DEBUG_INFO               0x20000000
#define LDRP_MM_LOADED                          0x40000000
#define LDRP_COMPAT_DATABASE_PROCESSED          0x80000000

#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED              0x01
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_USER            0x02
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL          0x04
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER          0x08
#define RTL_USER_PROCESS_PARAMETERS_UNKNOWN                 0x10
#define RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB             0x20
#define RTL_USER_PROCESS_PARAMETERS_RESERVE_16MB            0x40
#define RTL_USER_PROCESS_PARAMETERS_CASE_SENSITIVE          0x80
#define RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_CHECKS     0x100
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_1            0x200
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_2            0x400
#define RTL_USER_PROCESS_PARAMETERS_PRIVATE_DLL_PATH        0x1000
#define RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH          0x2000
#define RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING       0x4000
#define RTL_USER_PROCESS_PARAMETERS_NX                      0x20000

#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED   0x01
#define DENORMALIZE(x,addr) {if(x) x=(PWSTR)((ULONG_PTR)(x)-(ULONG_PTR)(addr));}
#define ALIGN(x,align) (((ULONG)(x)+(align)-1UL)&(~((align)-1UL)))

#define HANDLE_DETACHED_PROCESS     (HANDLE)-1
#define HANDLE_CREATE_NEW_CONSOLE   (HANDLE)-2
#define HANDLE_CREATE_NO_WINDOW     (HANDLE)-3

#ifdef NTOS_MODE_USER

//
// Process/Thread/Job Information Classes for NtQueryInformationProcess/Thread/Job
//
typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    MaxThreadInfoClass
} THREADINFOCLASS;

#else

typedef enum _PSPROCESSPRIORITYMODE
{
    PsProcessPriorityForeground,
    PsProcessPriorityBackground,
    PsProcessPrioritySpinning
} PSPROCESSPRIORITYMODE;

//
// Power Event Events for Win32K Power Event Callback
//
typedef enum _PSPOWEREVENTTYPE
{
    PsW32FullWake = 0,
    PsW32EventCode = 1,
    PsW32PowerPolicyChanged = 2,
    PsW32SystemPowerState = 3,
    PsW32SystemTime = 4,
    PsW32DisplayState = 5,
    PsW32CapabilitiesChanged = 6,
    PsW32SetStateFailed = 7,
    PsW32GdiOff = 8,
    PsW32GdiOn = 9,
    PsW32GdiPrepareResumeUI = 10,
    PsW32GdiOffRequest = 11,
    PsW32MonitorOff = 12,
} PSPOWEREVENTTYPE;

//
// Power State Tasks for Win32K Power State Callback
//
typedef enum _POWERSTATETASK
{
    PowerState_BlockSessionSwitch = 0,
    PowerState_Init = 1,
    PowerState_QueryApps = 2,
    PowerState_QueryServices = 3,
    PowerState_QueryAppsFailed = 4,
    PowerState_QueryServicesFailed = 5,
    PowerState_SuspendApps = 6,
    PowerState_SuspendServices = 7,
    PowerState_ShowUI = 8,
    PowerState_NotifyWL = 9,
    PowerState_ResumeApps = 10,
    PowerState_ResumeServices = 11,
    PowerState_UnBlockSessionSwitch = 12,
    PowerState_End = 13,
    PowerState_BlockInput = 14,
    PowerState_UnblockInput = 15,
} POWERSTATETASK;

//
// Win32K Job Callback Types
//
typedef enum _PSW32JOBCALLOUTTYPE
{
   PsW32JobCalloutSetInformation = 0,
   PsW32JobCalloutAddProcess = 1,
   PsW32JobCalloutTerminate = 2,
} PSW32JOBCALLOUTTYPE;

//
// Win32K Thread Callback Types
//
typedef enum _PSW32THREADCALLOUTTYPE
{
    PsW32ThreadCalloutInitialize,
    PsW32ThreadCalloutExit,
} PSW32THREADCALLOUTTYPE;

//
// Declare empty structure definitions so that they may be referenced by
// routines before they are defined
//
struct _W32THREAD;
struct _W32PROCESS;
struct _ETHREAD;
struct _WIN32_POWEREVENT_PARAMETERS;
struct _WIN32_POWERSTATE_PARAMETERS;
struct _WIN32_JOBCALLOUT_PARAMETERS;
struct _WIN32_OPENMETHOD_PARAMETERS;
struct _WIN32_OKAYTOCLOSEMETHOD_PARAMETERS;
struct _WIN32_CLOSEMETHOD_PARAMETERS;
struct _WIN32_DELETEMETHOD_PARAMETERS;
struct _WIN32_PARSEMETHOD_PARAMETERS;

//
// Win32K Process and Thread Callbacks
//
typedef
NTSTATUS
(NTAPI *PKWIN32_PROCESS_CALLOUT)(
    struct _EPROCESS *Process,
    BOOLEAN Create
);

typedef
NTSTATUS
(NTAPI *PKWIN32_THREAD_CALLOUT)(
    struct _ETHREAD *Thread,
    PSW32THREADCALLOUTTYPE Type
);

typedef
NTSTATUS
(NTAPI *PKWIN32_GLOBALATOMTABLE_CALLOUT)(
    VOID
);

typedef
NTSTATUS
(NTAPI *PKWIN32_POWEREVENT_CALLOUT)(
    struct _WIN32_POWEREVENT_PARAMETERS *Parameters
);

typedef
NTSTATUS
(NTAPI *PKWIN32_POWERSTATE_CALLOUT)(
    struct _WIN32_POWERSTATE_PARAMETERS *Parameters
);

typedef
NTSTATUS
(NTAPI *PKWIN32_JOB_CALLOUT)(
    struct _WIN32_JOBCALLOUT_PARAMETERS *Parameters
);

typedef
NTSTATUS
(NTAPI *PGDI_BATCHFLUSH_ROUTINE)(
    VOID
);

typedef
NTSTATUS
(NTAPI *PKWIN32_OPENMETHOD_CALLOUT)(
    struct _WIN32_OPENMETHOD_PARAMETERS *Parameters
);

typedef
NTSTATUS
(NTAPI *PKWIN32_OKTOCLOSEMETHOD_CALLOUT)(
    struct _WIN32_OKAYTOCLOSEMETHOD_PARAMETERS *Parameters
);

typedef
NTSTATUS
(NTAPI *PKWIN32_CLOSEMETHOD_CALLOUT)(
    struct _WIN32_CLOSEMETHOD_PARAMETERS *Parameters
);

typedef
VOID
(NTAPI *PKWIN32_DELETEMETHOD_CALLOUT)(
    struct _WIN32_DELETEMETHOD_PARAMETERS *Parameters
);

typedef
NTSTATUS
(NTAPI *PKWIN32_PARSEMETHOD_CALLOUT)(
    struct _WIN32_PARSEMETHOD_PARAMETERS *Parameters
);

typedef
NTSTATUS
(NTAPI *PKWIN32_WIN32DATACOLLECTION_CALLOUT)(
    struct _EPROCESS *Process,
    PVOID Callback,
    PVOID Context
);

//
// Lego Callback
//
typedef
VOID
(NTAPI *PLEGO_NOTIFY_ROUTINE)(
    IN PKTHREAD Thread
);

#endif

typedef NTSTATUS
(NTAPI *PPOST_PROCESS_INIT_ROUTINE)(
    VOID
);

//
// Descriptor Table Entry Definition
//
#define _DESCRIPTOR_TABLE_ENTRY_DEFINED
typedef struct _DESCRIPTOR_TABLE_ENTRY
{
    ULONG Selector;
    LDT_ENTRY Descriptor;
} DESCRIPTOR_TABLE_ENTRY, *PDESCRIPTOR_TABLE_ENTRY;

//
// PEB Lock Routine
//
typedef VOID
(NTAPI *PPEBLOCKROUTINE)(
    PVOID PebLock
);

//
// PEB Free Block Descriptor
//
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* Next;
    ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _PEB_LDR_DATA
{
     ULONG Length;
     UCHAR Initialized;
     PVOID SsHandle;
     LIST_ENTRY InLoadOrderModuleList;
     LIST_ENTRY InMemoryOrderModuleList;
     LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     WORD LoadCount;
     WORD TlsIndex;
     union{
          LIST_ENTRY HashLinks;
          struct{
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     }U1;
     union{
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     }U2;
     struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

//
// Current Directory Structures
//
typedef struct _CURDIR{
  UNICODE_STRING DosPath;
  HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR{
  USHORT Flags;
  USHORT Length;
  ULONG TimeStamp;
  UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

//
// Structures for RtlCreateUserProcess
//
typedef struct _RTL_USER_PROCESS_PARAMETERS{
  ULONG MaximumLength;
  ULONG Length;
  ULONG Flags;
  ULONG DebugFlags;
  HANDLE ConsoleHandle;
  ULONG ConsoleFlags;
  HANDLE StandardInput;
  HANDLE StandardOutput;
  HANDLE StandardError;
  CURDIR CurrentDirectory;
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
  PWSTR Environment;
  ULONG StartingX;
  ULONG StartingY;
  ULONG CountX;
  ULONG CountY;
  ULONG CountCharsX;
  ULONG CountCharsY;
  ULONG FillAttribute;
  ULONG WindowFlags;
  ULONG ShowWindowFlags;
  UNICODE_STRING WindowTitle;
  UNICODE_STRING DesktopInfo;
  UNICODE_STRING ShellInfo;
  UNICODE_STRING RuntimeData;
  RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT Reserved;
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
  LARGE_INTEGER BootTime;
  LARGE_INTEGER CurrentTime;
  LARGE_INTEGER TimeZoneBias;
  ULONG TimeZoneId;
  ULONG Reserved;
#if (NTDDI_VERSION >= NTDDI_WIN2K)
  ULONGLONG BootTimeBias;
  ULONGLONG SleepTimeBias;
#endif
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation, /// Obsolete: Use KUSER_SHARED_DATA
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowerInformationNative,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation,
    SystemLoadGdiDriverInSystemSpaceInformation,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHanfleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchDogTimerHandler,
    SystemWatchDogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWo64SharedInformationObosolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPathInformation,
    SystemVerifierFaultsInformation,
    MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS;

typedef struct _NLS_USER_INFO
{
  WCHAR iCountry[80];
  WCHAR sCountry[80];
  WCHAR sList[80];
  WCHAR iMeasure[80];
  WCHAR iPaperSize[80];
  WCHAR sDecimal[80];
  WCHAR sThousand[80];
  WCHAR sGrouping[80];
  WCHAR iDigits[80];
  WCHAR iLZero[80];
  WCHAR iNegNumber[80];
  WCHAR sNativeDigits[80];
  WCHAR iDigitSubstitution[80];
  WCHAR sCurrency[80];
  WCHAR sMonDecSep[80];
  WCHAR sMonThouSep[80];
  WCHAR sMonGrouping[80];
  WCHAR iCurrDigits[80];
  WCHAR iCurrency[80];
  WCHAR iNegCurr[80];
  WCHAR sPosSign[80];
  WCHAR sNegSign[80];
  WCHAR sTimeFormat[80];
  WCHAR s1159[80];
  WCHAR s2359[80];
  WCHAR sShortDate[80];
  WCHAR sYearMonth[80];
  WCHAR sLongDate[80];
  WCHAR iCalType[80];
  WCHAR iFirstDay[80];
  WCHAR iFirstWeek[80];
  WCHAR sLocale[80];
  WCHAR sLocaleName[85];
  LCID UserLocaleId;
  LUID InteractiveUserLuid;
  CHAR InteractiveUserSid[68]; // SECURITY_MAX_SID_SIZE to make ros happy
  ULONG ulCacheUpdateCount;
} NLS_USER_INFO, *PNLS_USER_INFO;

typedef struct _KSYSTEM_TIME {
  ULONG LowPart;
  LONG High1Time;
  LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef struct _BASE_STATIC_SERVER_DATA
{
  UNICODE_STRING WindowsDirectory;
  UNICODE_STRING WindowsSystemDirectory;
  UNICODE_STRING NamedObjectDirectory;
  USHORT WindowsMajorVersion;
  USHORT WindowsMinorVersion;
  USHORT BuildNumber;
  USHORT CSDNumber;
  USHORT RCNumber;
  WCHAR CSDVersion[128];
  SYSTEM_BASIC_INFORMATION SysInfo;
  SYSTEM_TIMEOFDAY_INFORMATION TimeOfDay;
  PVOID IniFileMapping;
  NLS_USER_INFO NlsUserInfo;
  BOOLEAN DefaultSeparateVDM;
  BOOLEAN IsWowTaskReady;
  UNICODE_STRING WindowsSys32x86Directory;
  BOOLEAN fTermsrvAppInstallMode;
  TIME_ZONE_INFORMATION tziTermsrvClientTimeZone;
  KSYSTEM_TIME ktTermsrvClientBias;
  ULONG TermsrvClientTimeZoneId;
  BOOLEAN LUIDDeviceMapsEnabled;
  ULONG TermsrvClientTimeZoneChangeNum;
} BASE_STATIC_SERVER_DATA, *PBASE_STATIC_SERVER_DATA;

typedef struct _STATIC_SERVER_DATA//cambia en 64 bits
{
  PVOID Unknown;
  PBASE_STATIC_SERVER_DATA BaseStaticServerData;
  PVOID MultipleUnknown[4];//ni idea...
} STATIC_SERVER_DATA, *PSTATIC_SERVER_DATA;
//
// Process Environment Block (PEB)
//
typedef struct _PEB
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    union
    {
        struct
        {
            UCHAR ImageUsesLargePages:1;
            UCHAR IsProtectedProcess:1;
            UCHAR IsLegacyProcess:1;
            UCHAR IsImageDynamicallyRelocated:1;
            UCHAR SkipPatchingUser32Forwarders:1;
            UCHAR SpareBits:3;
        };
        UCHAR BitField;
    };
#else
    BOOLEAN SpareBool;
#endif
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    struct _RTL_CRITICAL_SECTION *FastPebLock;
    PVOID AltThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        struct
        {
            ULONG ProcessInJob:1;
            ULONG ProcessInitializing:1;
            ULONG ProcessUsingVEH:1;
            ULONG ProcessUsingVCH:1;
            ULONG ReservedBits0:28;
        };
        ULONG CrossProcessFlags;
    };
    union
    {
        PVOID* KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG SpareUlong;
    ULONG SparePebPtr0;
#else
    PVOID FastPebLock;
    PPEBLOCKROUTINE FastPebLockRoutine;
    PPEBLOCKROUTINE FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID EventLogSection;
    PVOID EventLog;
    PPEB_FREE_BLOCK FreeList;
#endif
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[0x2];
    PVOID ReadOnlySharedMemoryBase;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID HotpatchInformation;
#else
    PVOID ReadOnlySharedMemoryHeap;
#endif
    PSTATIC_SERVER_DATA ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    struct _RTL_CRITICAL_SECTION *LoaderLock;
#else
    PVOID LoaderLock;
#endif
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubSystem;
    ULONG ImageSubSystemMajorVersion;
    ULONG ImageSubSystemMinorVersion;
    ULONG ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[0x22];
    PPOST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    struct _RTL_BITMAP *TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[0x20];
    ULONG SessionId;
#if (NTDDI_VERSION >= NTDDI_WINXP)
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    struct _ACTIVATION_CONTEXT_DATA *ActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP *ProcessAssemblyStorageMap;
    struct _ACTIVATION_CONTEXT_DATA *SystemDefaultActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP *SystemAssemblyStorageMap;
    ULONG MinimumStackCommit;
#endif
#if (NTDDI_VERSION >= NTDDI_WS03)
    PVOID *FlsCallback;
    LIST_ENTRY FlsListHead;
    struct _RTL_BITMAP *FlsBitmap;
    ULONG FlsBitmapBits[4];
    ULONG FlsHighIndex;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
#endif
} PEB, *PPEB;

//
// GDI Batch Descriptor
//
typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    HANDLE HDC;
    ULONG Buffer[0x136];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

//
// Initial TEB
//
typedef struct _INITIAL_TEB{
   ULONG StackCommit;
   ULONG StackReserve;
   PVOID StackBase;
   PVOID StackLimit;
   PVOID StackAllocate;
} INITIAL_TEB, *PINITIAL_TEB;

//
// TEB Active Frame Structures
//
typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    LPSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef LRESULT(CALLBACK * 	HOOKPROC )(int, WPARAM, LPARAM);
//typedef LRESULT (*WNDPROC)(HWND, long, WPARAM, LPARAM);

typedef struct tagWnd{
  WNDPROC  lpfnWndProc;
  int      style;
  long     backGround;
  long     titleMsg;
  long     extra;
} WND, *PWND;

typedef struct _HOOK *PHOOK;

typedef struct _DESKTOPINFO
{
/* 000 */ PVOID        pvDesktopBase;
/* 004 */ PVOID        pvDesktopLimit;
/* 008 */ PWND         spwnd;
/* 00c */ DWORD        fsHooks;
/* 010 */ PHOOK        aphkStart[NB_HOOKS];
/* 050 */ PWND         spwndShell;
/* 054 */ PVOID ppiShellProcess;
/* 058 */ PWND         spwndBkGnd;
/* 05c */ PWND         spwndTaskman;
/* 060 */ PWND         spwndProgman;
/* 064 */ PVOID        pvwplShellHook;
/* 068 */ INT          cntMBox;
} DESKTOPINFO, *PDESKTOPINFO;

typedef struct _DESKTOP  // Size: 0x88
{                                          // XP
#if (_WIN32_WINNT >= 0x0501)
  DWORD              dwSessionId;          // 000
#endif
  PDESKTOPINFO       pDeskInfo;            // 004
  PVOID       pDispInfo;            // 008
  struct _DESKTOP   *rpdeskNext;           // 00c
  PVOID     rpwinstaParent;       // 010
  DWORD              dwDTFlage;            // 014
  DWORD              dwDesktopId;          // 018
  PWND               spwndMenu;            // 01c
  PVOID              spmenuSys;            // 020
  PVOID              spmenuDialogSys;      // 024
  PVOID              spmenuHScroll;        // 028
  PVOID              spmenuVScroll;        // 02c
  PWND               spwndForeground;      // 030
  PWND               spwndTray;            // 034
  PWND               spwndMessage;         // 038
  PWND               spwndTooltip;         // 03c
  HANDLE             hsectionDesktop;      // 040
  PVOID         pheapDesktop;         // 044
  DWORD              dwConsoleThreadId;    // 048
  DWORD              dwConsoleIMEThreadId; // 04c
  PVOID cciConsole;           // 050 Size is 20 bytes
  LIST_ENTRY         PtiList;              // 064
  PWND               spwndTrack;           // 06c
  DWORD              htEx;                 // 070
  RECT               rcMouseHover;         // 074
  DWORD              dwMouseHoverTime;     // 084
#if (_WIN32_WINNT <= 0x0500)
  DWORD              dwSessionId; // W2k
#endif
} DESKTOP, *PDESKTOP;

typedef struct _THREADINFO *PTHREADINFO;

typedef struct _HOOK {
  ULONG hHook;
  ULONG cLockObj;
  PTHREADINFO *pti;
  ULONG rpdesk;
  ULONG pSelf;
  struct _HOOK *phkNext;
  int iHook;
  HOOKPROC offPfn;
  unsigned int flags;
  int ihmod;
  PTHREADINFO *ptiHooked;
  PDESKTOP rpdesk2;
} HOOK;

typedef struct tagHOOKTABLE
{
  LIST_ENTRY Hooks[NB_HOOKS];
  UINT       Counts[NB_HOOKS];
} HOOKTABLE, *PHOOKTABLE;

typedef struct _USER_MESSAGE
{
  LIST_ENTRY ListEntry;
  BOOLEAN FreeLParam;
  MSG Msg;
} USER_MESSAGE, *PUSER_MESSAGE;

struct _USER_MESSAGE_QUEUE;
//typedef FARPROC SENDASYNCPROC;

typedef struct _USER_SENT_MESSAGE
{
  LIST_ENTRY ListEntry;
  MSG Msg;
  PKEVENT CompletionEvent;
  LRESULT* Result;
  struct _USER_MESSAGE_QUEUE* SenderQueue;
  SENDASYNCPROC CompletionCallback;
  ULONG_PTR CompletionCallbackContext;
  LIST_ENTRY DispatchingListEntry;
  INT HookMessage;
} USER_SENT_MESSAGE, *PUSER_SENT_MESSAGE;

typedef struct _THRDCARETINFO
{
    HWND hWnd;
    HBITMAP Bitmap;
    POINT Pos;
    SIZE Size;
    BYTE Visible;
    BYTE Showing;
} THRDCARETINFO, *PTHRDCARETINFO;

typedef struct _USER_MESSAGE_QUEUE
{
  LONG References;
  struct _ETHREAD *Thread;
  LIST_ENTRY SentMessagesListHead;
  LIST_ENTRY PostedMessagesListHead;
  LIST_ENTRY NotifyMessagesListHead;
  LIST_ENTRY HardwareMessagesListHead;
  LIST_ENTRY TimerListHead;
  KMUTEX HardwareLock;
  PUSER_MESSAGE MouseMoveMsg;
  BOOLEAN QuitPosted;
  ULONG QuitExitCode;
  PKEVENT NewMessages;
  HANDLE NewMessagesHandle;
  ULONG LastMsgRead;
  HWND FocusWindow;
  ULONG PaintCount;
  HWND ActiveWindow;
  HWND CaptureWindow;
  HWND MoveSize;
  HWND MenuOwner;
  BYTE MenuState;
  PTHRDCARETINFO CaretInfo;
  PHOOKTABLE Hooks;
  WORD WakeMask;
  WORD QueueBits;
  WORD ChangedBits;
  LPARAM ExtraInfo;
  LIST_ENTRY DispatchingMessagesHead;
  LIST_ENTRY LocalDispatchingMessagesHead;
  struct _DESKTOP_OBJECT *Desktop;
} USER_MESSAGE_QUEUE, *PUSER_MESSAGE_QUEUE;

typedef struct _TL
{
    struct _TL* next;
    PVOID pobj;
    PVOID pfnFree;
} TL, *PTL;

typedef struct _W32THREAD
{
    PETHREAD pEThread;
    ULONG RefCount;
    PTL ptlW32;
    PVOID pgdiDcattr;
    PVOID pgdiBrushAttr;
    PVOID pUMPDObjs;
    PVOID pUMPDHeap;
    DWORD dwEngAcquireCount;
    PVOID pSemTable;
    PVOID pUMPDObj;
} W32THREAD, *PW32THREAD;

typedef struct _W32PROCESSINFO
{
    PVOID UserHandleTable;
    HANDLE hUserHeap;
    PVOID UserHeapDelta;
    PVOID hModUser;
    PVOID LocalClassList;
    PVOID GlobalClassList;
    PVOID SystemClassList;
    PVOID psi;
} W32PROCESSINFO, *PW32PROCESSINFO;


typedef struct _W32THREADINFO
{
    W32PROCESSINFO pi; /* [USER] */
    W32PROCESSINFO kpi; /* [KERNEL] */
    PDESKTOPINFO pDeskInfo;
    ULONG Hooks;
    PVOID ClientThreadInfo;
} W32THREADINFO, *PW32THREADINFO;

typedef struct _CALLBACKWND{
  HWND hWnd;
  struct _WND *pWnd;
  PVOID pActCtx;
} CALLBACKWND, *PCALLBACKWND;

typedef struct _CLIENTINFO{
  ULONG_PTR CI_flags;
  ULONG_PTR cSpins;
  DWORD dwExpWinVer;
  DWORD dwCompatFlags;
  DWORD dwCompatFlags2;
  DWORD dwTIFlags;
  PDESKTOPINFO pDeskInfo;
  ULONG_PTR ulClientDelta;
  PHOOK phkCurrent;
  DWORD fsHooks;
  CALLBACKWND CallbackWnd;
  DWORD dwHookCurrent;
  INT cInDDEMLCallback;
  PVOID pClientThreadInfo;
  ULONG_PTR dwHookData;
  DWORD dwKeyCache;
  BYTE afKeyState[8];
  DWORD dwAsyncKeyCache;
  BYTE afAsyncKeyState[8];
  BYTE afAsyncKeyStateRecentDow[8];
  HKL hKL;
  WORD CodePage;
  BYTE achDbcsCF[2];
  MSG msgDbcsCB;
}CLIENTINFO,*PCLIENTINFO;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME{
  struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
  struct _ACTIVATION_CONTEXT *ActivationContext;
  ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK{
  ULONG Flags;
  ULONG NextCookieSequenceNumber;
  RTL_ACTIVATION_CONTEXT_STACK_FRAME *ActiveFrame;
  LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

//
// Thread Environment Block (TEB)
//
typedef struct _TEB
{
    NT_TIB Tib;                           //0x000
    PVOID EnvironmentPointer;             //0x01c
    CLIENT_ID ClientId;                   //0x020
    PVOID ActiveRpcHandle;                //0x028
    PVOID ThreadLocalStoragePointer;      //0x02C
    struct _PEB *ProcessEnvironmentBlock; //0x030
    ULONG LastErrorValue;                 //0x034
    ULONG CountOfOwnedCriticalSections;   //0x038
    PVOID CsrClientThread;                //0x03C
    PW32THREADINFO Win32ThreadInfo;   //0x040
    ULONG User32Reserved[0x1A];           //0x044
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[0x36];
    LONG ExceptionCode;
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
#ifdef _WIN64
    UCHAR SpareBytes1[24];
#else
    UCHAR SpareBytes1[0x24];
#endif
    ULONG TxFsContext;
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    PVOID GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    SIZE_T Win32ClientInfo[62];
    PVOID glDispatchTable[0xE9];
    SIZE_T glReserved1[0x1D];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[0x105];
    PVOID DeallocationStack;
    PVOID TlsSlots[0x40];
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[0x2];
    ULONG HardErrorDisabled;
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;
    PVOID SubProcessTag;
    PVOID EtwTraceData;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID EtwLocalData;
#endif
    PVOID WinSockData;
    ULONG GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    BOOLEAN SpareBool0;
    BOOLEAN SpareBool1;
    BOOLEAN SpareBool2;
#else
    BOOLEAN InDbgPrint;
    BOOLEAN FreeStackOnTermination;
    BOOLEAN HasFiberData;
#endif
    UCHAR IdealProcessor;
    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID SavedPriorityState;
#else
    ULONG SparePointer1;
#endif
    ULONG SoftPatchPtr1;
    ULONG SoftPatchPtr2;
    PVOID *TlsExpansionSlots;
    ULONG ImpersonationLocale;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirualAffinity;
    PVOID CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
    PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID PreferredLangauges;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        struct
        {
            USHORT SpareCrossTebFlags:16;
        };
        USHORT CrossTebFlags;
    };
    union
    {
        struct
        {
            USHORT DbgSafeThunkCall:1;
            USHORT DbgInDebugPrint:1;
            USHORT DbgHasFiberData:1;
            USHORT DbgSkipThreadAttach:1;
            USHORT DbgWerInShipAssertCode:1;
            USHORT DbgIssuedInitialBp:1;
            USHORT DbgClonedThread:1;
            USHORT SpareSameTebBits:9;
        };
        USHORT SameTebFlags;
    };
    PVOID TxnScopeEntercallback;
    PVOID TxnScopeExitCAllback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG ProcessRundown;
    ULONGLONG LastSwitchTime;
    ULONGLONG TotalSwitchOutTime;
    LARGE_INTEGER WaitReasonBitMap;
#else
    UCHAR SafeThunkCall;
    UCHAR BooleanSpare[3];
#endif
} TEB, *PTEB;

#ifdef NTOS_MODE_USER

//
// Process Information Structures for NtQueryProcessInformation
//
typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_ACCESS_TOKEN
{
    HANDLE Token;
    HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef struct _PROCESS_DEVICEMAP_INFORMATION
{
    union
    {
        struct
        {
            HANDLE DirectoryHandle;
        } Set;
        struct
        {
            ULONG DriveMap;
            UCHAR DriveType[32];
        } Query;
    };
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

typedef struct _KERNEL_USER_TIMES
{
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef struct _PROCESS_SESSION_INFORMATION
{
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

#endif

#ifndef NTOS_MODE_USER

//
// Job Set Array
//
typedef struct _JOB_SET_ARRAY
{
    HANDLE JobHandle;
    ULONG MemberLevel;
    ULONG Flags;
} JOB_SET_ARRAY, *PJOB_SET_ARRAY;


//
// Per-Process APC Rate Limiting
//
typedef struct _PSP_RATE_APC
{
    union
    {
        SINGLE_LIST_ENTRY NextApc;
        ULONGLONG ExcessCycles;
    };
    ULONGLONG TargetGEneration;
    KAPC RateApc;
} PSP_RATE_APC, *PPSP_RATE_APC;

typedef struct _PP_LOOKASIDE_LIST
{
     PGENERAL_LOOKASIDE P;
     PGENERAL_LOOKASIDE L;
} PP_LOOKASIDE_LIST, *PPP_LOOKASIDE_LIST;

typedef struct _GENERAL_LOOKASIDE_POOL
{
     union
     {
          SLIST_HEADER ListHead;
          SINGLE_LIST_ENTRY SingleListHead;
     };
     WORD Depth;
     WORD MaximumDepth;
     ULONG TotalAllocates;
     union
     {
          ULONG AllocateMisses;
          ULONG AllocateHits;
     };
     ULONG TotalFrees;
     union
     {
          ULONG FreeMisses;
          ULONG FreeHits;
     };
     POOL_TYPE Type;
     ULONG Tag;
     ULONG Size;
     union
     {
          PVOID * AllocateEx;
          PVOID * Allocate;
     };
     union
     {
          PVOID FreeEx;
          PVOID Free;
     };
     LIST_ENTRY ListEntry;
     ULONG LastTotalAllocates;
     union
     {
          ULONG LastAllocateMisses;
          ULONG LastAllocateHits;
     };
     ULONG Future[2];
} GENERAL_LOOKASIDE_POOL, *PGENERAL_LOOKASIDE_POOL;

typedef struct _DESCRIPTOR
{
     WORD Pad;
     WORD Limit;
     ULONG Base;
} DESCRIPTOR, *PDESCRIPTOR;

typedef struct _KSPECIAL_REGISTERS
{
     ULONG Cr0;
     ULONG Cr2;
     ULONG Cr3;
     ULONG Cr4;
     ULONG KernelDr0;
     ULONG KernelDr1;
     ULONG KernelDr2;
     ULONG KernelDr3;
     ULONG KernelDr6;
     ULONG KernelDr7;
     DESCRIPTOR Gdtr;
     DESCRIPTOR Idtr;
     WORD Tr;
     WORD Ldtr;
     ULONG Reserved[6];
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE
{
     CONTEXT ContextFrame;
     KSPECIAL_REGISTERS SpecialRegisters;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;

typedef struct _CACHED_KSTACK_LIST
{
     SLIST_HEADER SListHead;
     LONG MinimumFree;
     ULONG Misses;
     ULONG MissesLast;
} CACHED_KSTACK_LIST, *PCACHED_KSTACK_LIST;

typedef struct _KNODE
{
     SLIST_HEADER PagedPoolSListHead;
     SLIST_HEADER NonPagedPoolSListHead[3];
     SLIST_HEADER PfnDereferenceSListHead;
     ULONG ProcessorMask;
     UCHAR Color;
     UCHAR Seed;
     UCHAR NodeNumber;
     DWORD Flags;
     ULONG MmShiftedColor;
     ULONG FreeCount[2];
     PSINGLE_LIST_ENTRY PfnDeferredList;
     CACHED_KSTACK_LIST CachedKernelStacks;
} KNODE, *PKNODE;

typedef struct _KDPC_DATA
{
     LIST_ENTRY DpcListHead;
     ULONG DpcLock;
     LONG DpcQueueDepth;
     ULONG DpcCount;
} KDPC_DATA, *PKDPC_DATA;

typedef struct _FX_SAVE_AREA
{
     BYTE U[520];
     ULONG NpxSavedCpu;
     ULONG Cr0NpxState;
} FX_SAVE_AREA, *PFX_SAVE_AREA;

typedef struct
{
     LONG * IdleHandler;
     ULONG Context;
     ULONG Latency;
     ULONG Power;
     ULONG TimeCheck;
     ULONG StateFlags;
     UCHAR PromotePercent;
     UCHAR DemotePercent;
     UCHAR PromotePercentBase;
     UCHAR DemotePercentBase;
     UCHAR StateType;
} PPM_IDLE_STATE, *PPPM_IDLE_STATE;

typedef struct _PPM_IDLE_STATES
{
     ULONG Type;
     ULONG Count;
     ULONG Flags;
     ULONG TargetState;
     ULONG ActualState;
     ULONG OldState;
     ULONG TargetProcessors;
     PPM_IDLE_STATE State[1];
} PPM_IDLE_STATES, *PPPM_IDLE_STATES;

typedef struct
{
     ULONG IdleTransitions;
     ULONG FailedTransitions;
     ULONG InvalidBucketIndex;
     UINT64 TotalTime;
     ULONG IdleTimeBuckets[6];
} PPM_IDLE_STATE_ACCOUNTING, *PPPM_IDLE_STATE_ACCOUNTING;

typedef struct
{
     ULONG StateCount;
     ULONG TotalTransitions;
     ULONG ResetCount;
     UINT64 StartTime;
     PPM_IDLE_STATE_ACCOUNTING State[1];
} PPM_IDLE_ACCOUNTING, *PPPM_IDLE_ACCOUNTING;

typedef struct
{
     ULONG Frequency;
     ULONG Power;
     UCHAR PercentFrequency;
     UCHAR IncreaseLevel;
     UCHAR DecreaseLevel;
     UCHAR Type;
     UINT64 Control;
     UINT64 Status;
     ULONG TotalHitCount;
     ULONG DesiredCount;
} PPM_PERF_STATE, *PPPM_PERF_STATE;

typedef struct
{
     ULONG Count;
     ULONG MaxFrequency;
     ULONG MaxPerfState;
     ULONG MinPerfState;
     ULONG LowestPState;
     ULONG IncreaseTime;
     ULONG DecreaseTime;
     UCHAR BusyAdjThreshold;
     UCHAR Reserved;
     UCHAR ThrottleStatesOnly;
     UCHAR PolicyType;
     ULONG TimerInterval;
     ULONG Flags;
     ULONG TargetProcessors;
     LONG * PStateHandler;
     ULONG PStateContext;
     LONG * TStateHandler;
     ULONG TStateContext;
     LONG * FeedbackHandler;
     PPM_PERF_STATE State[1];
} PPM_PERF_STATES, *PPPM_PERF_STATES;

typedef struct _KPRCB *PKPRCB;

//
// Job Token Filter Data
//
#include <pshpack1.h>
typedef struct _PS_JOB_TOKEN_FILTER
{
    ULONG CapturedSidCount;
    PSID_AND_ATTRIBUTES CapturedSids;
    ULONG CapturedSidsLength;
    ULONG CapturedGroupCount;
    PSID_AND_ATTRIBUTES CapturedGroups;
    ULONG CapturedGroupsLength;
    ULONG CapturedPrivilegeCount;
    PLUID_AND_ATTRIBUTES CapturedPrivileges;
    ULONG CapturedPrivilegesLength;
} PS_JOB_TOKEN_FILTER, *PPS_JOB_TOKEN_FILTER;

//
// Executive Job (EJOB)
//
typedef struct _EJOB
{
    KEVENT Event;
    LIST_ENTRY JobLinks;
    LIST_ENTRY ProcessListHead;
    ERESOURCE JobLock;
    LARGE_INTEGER TotalUserTime;
    LARGE_INTEGER TotalKernelTime;
    LARGE_INTEGER ThisPeriodTotalUserTime;
    LARGE_INTEGER ThisPeriodTotalKernelTime;
    ULONG TotalPageFaultCount;
    ULONG TotalProcesses;
    ULONG ActiveProcesses;
    ULONG TotalTerminatedProcesses;
    LARGE_INTEGER PerProcessUserTimeLimit;
    LARGE_INTEGER PerJobUserTimeLimit;
    ULONG LimitFlags;
    ULONG MinimumWorkingSetSize;
    ULONG MaximumWorkingSetSize;
    ULONG ActiveProcessLimit;
    ULONG Affinity;
    UCHAR PriorityClass;
    ULONG UIRestrictionsClass;
    ULONG SecurityLimitFlags;
    PVOID Token;
    PPS_JOB_TOKEN_FILTER Filter;
    ULONG EndOfJobTimeAction;
    PVOID CompletionPort;
    PVOID CompletionKey;
    ULONG SessionId;
    ULONG SchedulingClass;
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
    IO_COUNTERS IoInfo;
    ULONG ProcessMemoryLimit;
    ULONG JobMemoryLimit;
    ULONG PeakProcessMemoryUsed;
    ULONG PeakJobMemoryUsed;
    ULONG CurrentJobMemoryUsed;
#if (NTDDI_VERSION == NTDDI_WINXP)
    FAST_MUTEX MemoryLimitsLock;
#elif (NTDDI_VERSION == NTDDI_WS03)
    KGUARDED_MUTEX MemoryLimitsLock;
#elif (NTDDI_VERSION >= NTDDI_LONGHORN)
    EX_PUSH_LOCK MemoryLimitsLock;
#endif
    LIST_ENTRY JobSetLinks;
    ULONG MemberLevel;
    ULONG JobFlags;
} EJOB, *PEJOB;
#include <poppack.h>

//
// Win32K Callback Registration Data
//
typedef struct _WIN32_POWEREVENT_PARAMETERS
{
    PSPOWEREVENTTYPE EventNumber;
    ULONG Code;
} WIN32_POWEREVENT_PARAMETERS, *PWIN32_POWEREVENT_PARAMETERS;

typedef struct _WIN32_POWERSTATE_PARAMETERS
{
    UCHAR Promotion;
    POWER_ACTION SystemAction;
    SYSTEM_POWER_STATE MinSystemState;
    ULONG Flags;
    POWERSTATETASK PowerStateTask;
} WIN32_POWERSTATE_PARAMETERS, *PWIN32_POWERSTATE_PARAMETERS;

typedef struct _WIN32_JOBCALLOUT_PARAMETERS
{
    PVOID Job;
    PSW32JOBCALLOUTTYPE CalloutType;
    PVOID Data;
} WIN32_JOBCALLOUT_PARAMETERS, *PWIN32_JOBCALLOUT_PARAMETERS;

typedef enum _OB_OPEN_REASON
{
         ObCreateHandle = 0,
         ObOpenHandle = 1,
         ObDuplicateHandle = 2,
         ObInheritHandle = 3,
         ObMaxOpenReason = 4
} OB_OPEN_REASON;

typedef struct _WIN32_OPENMETHOD_PARAMETERS
{
    OB_OPEN_REASON OpenReason;
    PEPROCESS Process;
    PVOID Object;
    ULONG GrantedAccess;
    ULONG HandleCount;
} WIN32_OPENMETHOD_PARAMETERS, *PWIN32_OPENMETHOD_PARAMETERS;

typedef struct _WIN32_OKAYTOCLOSEMETHOD_PARAMETERS
{
    PEPROCESS Process;
    PVOID Object;
    HANDLE Handle;
    KPROCESSOR_MODE PreviousMode;
} WIN32_OKAYTOCLOSEMETHOD_PARAMETERS, *PWIN32_OKAYTOCLOSEMETHOD_PARAMETERS;

typedef struct _WIN32_CLOSEMETHOD_PARAMETERS
{
    PEPROCESS Process;
    PVOID Object;
    ACCESS_MASK AccessMask;
    ULONG ProcessHandleCount;
    ULONG SystemHandleCount;
} WIN32_CLOSEMETHOD_PARAMETERS, *PWIN32_CLOSEMETHOD_PARAMETERS;

typedef struct _WIN32_DELETEMETHOD_PARAMETERS
{
    PVOID Object;
} WIN32_DELETEMETHOD_PARAMETERS, *PWIN32_DELETEMETHOD_PARAMETERS;

typedef struct _WIN32_PARSEMETHOD_PARAMETERS
{
    PVOID ParseObject;
    PVOID ObjectType;
    PACCESS_STATE AccessState;
    KPROCESSOR_MODE AccessMode;
    ULONG Attributes;
    OUT PUNICODE_STRING CompleteName;
    PUNICODE_STRING RemainingName;
    PVOID Context;
    PSECURITY_QUALITY_OF_SERVICE SecurityQos;
    PVOID *Object;
} WIN32_PARSEMETHOD_PARAMETERS, *PWIN32_PARSEMETHOD_PARAMETERS;

typedef struct _WIN32_CALLOUTS_FPNS
{
    PKWIN32_PROCESS_CALLOUT ProcessCallout;
    PKWIN32_THREAD_CALLOUT ThreadCallout;
    PKWIN32_GLOBALATOMTABLE_CALLOUT GlobalAtomTableCallout;
    PKWIN32_POWEREVENT_CALLOUT PowerEventCallout;
    PKWIN32_POWERSTATE_CALLOUT PowerStateCallout;
    PKWIN32_JOB_CALLOUT JobCallout;
    PGDI_BATCHFLUSH_ROUTINE BatchFlushRoutine;
    PKWIN32_OPENMETHOD_CALLOUT DesktopOpenProcedure;
    PKWIN32_OKTOCLOSEMETHOD_CALLOUT DesktopOkToCloseProcedure;
    PKWIN32_CLOSEMETHOD_CALLOUT DesktopCloseProcedure;
    PKWIN32_DELETEMETHOD_CALLOUT DesktopDeleteProcedure;
    PKWIN32_OKTOCLOSEMETHOD_CALLOUT WindowStationOkToCloseProcedure;
    PKWIN32_CLOSEMETHOD_CALLOUT WindowStationCloseProcedure;
    PKWIN32_DELETEMETHOD_CALLOUT WindowStationDeleteProcedure;
    PKWIN32_PARSEMETHOD_CALLOUT WindowStationParseProcedure;
    PKWIN32_OPENMETHOD_CALLOUT WindowStationOpenProcedure;
    PKWIN32_WIN32DATACOLLECTION_CALLOUT Win32DataCollectionProcedure;
} WIN32_CALLOUTS_FPNS, *PWIN32_CALLOUTS_FPNS;

#endif // !NTOS_MODE_USER

#define PROCESSOR_FEATURE_MAX   64
#define MAX_WOW64_SHARED_ENTRIES   16

typedef struct _KUSER_SHARED_DATA {
  ULONG TickCountLow;
  ULONG TickCountMultiplier;
  volatile KSYSTEM_TIME InterruptTime;
  volatile KSYSTEM_TIME SystemTime;
  volatile KSYSTEM_TIME TimeZoneBias;
  USHORT ImageNumberLow;
  USHORT ImageNumberHigh;
  WCHAR NtSystemRoot[260];
  ULONG MaxStackTraceDepth;
  ULONG CryptoExponent;
  ULONG TimeZoneId;
  ULONG LargePageMinimum;
  ULONG Reserved2[7];
  ULONG NtProductType;
  BOOLEAN ProductTypeIsValid;
  ULONG NtMajorVersion;
  ULONG NtMinorVersion;
  BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
  ULONG Reserved1;
  ULONG Reserved3;
  volatile ULONG TimeSlip;
  ULONG AlternativeArchitecture;
  ULONG AltArchitecturePad[1];
  LARGE_INTEGER SystemExpirationDate;
  ULONG SuiteMask;
  BOOLEAN KdDebuggerEnabled;
#if (NTDDI_VERSION >= NTDDI_WINXPSP2)
  UCHAR NXSupportPolicy;
#endif
  volatile ULONG ActiveConsoleId;
  volatile ULONG DismountCount;
  ULONG ComPlusPackage;
  ULONG LastSystemRITEventTickCount;
  ULONG NumberOfPhysicalPages;
  BOOLEAN SafeBootMode;
#if (NTDDI_VERSION >= NTDDI_WIN7)
  _ANONYMOUS_UNION union {
    UCHAR TscQpcData;
    _ANONYMOUS_STRUCT struct {
      UCHAR TscQpcEnabled:1;
      UCHAR TscQpcSpareFlag:1;
      UCHAR TscQpcShift:6;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
  UCHAR TscQpcPad[2];
#endif
#if (NTDDI_VERSION >= NTDDI_VISTA)
  _ANONYMOUS_UNION union {
    ULONG SharedDataFlags;
    _ANONYMOUS_STRUCT struct {
      ULONG DbgErrorPortPresent:1;
      ULONG DbgElevationEnabled:1;
      ULONG DbgVirtEnabled:1;
      ULONG DbgInstallerDetectEnabled:1;
      ULONG DbgSystemDllRelocated:1;
      ULONG DbgDynProcessorEnabled:1;
      ULONG DbgSEHValidationEnabled:1;
      ULONG SpareBits:25;
    } DUMMYSTRUCTNAME2;
  } DUMMYUNIONNAME2;
#else
  ULONG TraceLogging;
#endif
  ULONG DataFlagsPad[1];
  ULONGLONG TestRetInstruction;
  ULONG SystemCall;
  ULONG SystemCallReturn;
  ULONGLONG SystemCallPad[3];
  _ANONYMOUS_UNION union {
    volatile KSYSTEM_TIME TickCount;
    volatile ULONG64 TickCountQuad;
    _ANONYMOUS_STRUCT struct {
      ULONG ReservedTickCountOverlay[3];
      ULONG TickCountPad[1];
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME3;
  ULONG Cookie;
  ULONG CookiePad[1];
#if (NTDDI_VERSION >= NTDDI_WS03)
   LONGLONG ConsoleSessionForegroundProcessId;
   ULONG Wow64SharedInformation[MAX_WOW64_SHARED_ENTRIES];
#endif
#if (NTDDI_VERSION >= NTDDI_VISTA)
#if (NTDDI_VERSION >= NTDDI_WIN7)
  USHORT UserModeGlobalLogger[16];
#else
  USHORT UserModeGlobalLogger[8];
  ULONG HeapTracingPid[2];
  ULONG CritSecTracingPid[2];
#endif
  ULONG ImageFileExecutionOptions;
#if (NTDDI_VERSION >= NTDDI_VISTASP1)
  ULONG LangGenerationCount;
#else
  /* 4 bytes padding */
#endif
  ULONGLONG Reserved5;
  volatile ULONG64 InterruptTimeBias;
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
  volatile ULONG64 TscQpcBias;
  volatile ULONG ActiveProcessorCount;
  volatile USHORT ActiveGroupCount;
  USHORT Reserved4;
  volatile ULONG AitSamplingValue;
  volatile ULONG AppCompatFlag;
  ULONGLONG SystemDllNativeRelocation;
  ULONG SystemDllWowRelocation;
  ULONG XStatePad[1];
  ULONG XState[132];
#endif
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

//
// Memory Information Classes for NtQueryVirtualMemory
//

#define PTR_ADD_OFFSET(Pointer,Offset) ((PVOID)((ULONG_PTR)(Pointer)+(ULONG_PTR)(Offset)))

typedef enum _MEMORY_INFORMATION_CLASS{
  MemoryBasicInformation,
  MemoryWorkingSetList,
  MemorySectionName,
  MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _SECTION_IMAGE_INFORMATION{
  VOID*        EntryPoint;
  ULONG32      StackZeroBits;
  ULONG32      StackReserved;
  ULONG32      StackCommit;
  ULONG32      ImageSubsystem;
  union{
    struct{
      UINT16       SubSystemMinorVersion;
      UINT16       SubSystemMajorVersion;
    };
    ULONG32      SubSystemVersion;
  };
  ULONG32      GpValue;
  UINT16       ImageCharacteristics;
  UINT16       DllCharacteristics;
  UINT16       Machine;
  UINT8        ImageContainsCode;
  union{
    UINT8        ImageFlags;
    struct{
      UINT8        ComPlusNativeReady : 1;        // 0 BitPosition
      UINT8        ComPlusILOnly : 1;             // 1 BitPosition
      UINT8        ImageDynamicallyRelocated : 1; // 2 BitPosition
      UINT8        ImageMappedFlat : 1;           // 3 BitPosition
      UINT8        Reserved : 4;                  // 4 BitPosition
    };
  };
  ULONG32      LoaderFlags;
  ULONG32      ImageFileSize;
  ULONG32      CheckSum;
}SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _PROCESS_PRIORITY_CLASS
{
    BOOLEAN Foreground;
    UCHAR PriorityClass;
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

typedef enum _SECTION_INFORMATION_CLASS
{
  SectionBasicInformation,
  SectionImageInformation,
} SECTION_INFORMATION_CLASS;

typedef enum _BASE_CONTEXT_TYPE {
  BaseContextTypeProcess,
  BaseContextTypeThread,
  BaseContextTypeFiber
} BASE_CONTEXT_TYPE, *PBASE_CONTEXT_TYPE;

typedef struct _PROCESS_BASIC_INFORMATION {
  NTSTATUS ExitStatus;
  struct _PEB *PebBaseAddress;
  ULONG_PTR AffinityMask;
  KPRIORITY BasePriority;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;

typedef struct _VM_COUNTERS {
  ULONG PeakVirtualSize;
  ULONG VirtualSize;
  ULONG PageFaultCount;
  ULONG PeakWorkingSetSize;
  ULONG WorkingSetSize;
  ULONG QuotaPeakPagedPoolUsage;
  ULONG QuotaPagedPoolUsage;
  ULONG QuotaPeakNonPagedPoolUsage;
  ULONG QuotaNonPagedPoolUsage;
  ULONG PagefileUsage;
  ULONG PeakPagefileUsage;
} VM_COUNTERS;
//
// Process session information
//
typedef struct _PROCESS_SESSION_INFORMATION {
    ULONG   SessionId;
} PROCESS_SESSION_INFORMATION,*PPROCESS_SESSION_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
  NTSTATUS ExitStatus;
  PNT_TIB TebBaseAddress;
  CLIENT_ID ClientId;
  KAFFINITY AffinityMask;
  KPRIORITY Priority;
  KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef enum _THREAD_STATE{
  Initialized,
  Ready,
  Running,
  Standby,
  Terminated,
  Waiting,
  Transition,
  DeferredReady,
  GateWait,
  MaximumThreadState
} THREAD_STATE, *PTHREAD_STATE;

typedef struct _SYSTEM_THREAD_INFORMATION{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitchCount;
    ULONG State;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION,*PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; //VISTA
    ULONG HardFaultCount; //WIN7
    ULONG NumberOfThreadsHighWatermark; //WIN7
    ULONGLONG CycleTime; //WIN7
    ULONGLONG CreateTime;
    ULONGLONG UserTime;
    ULONGLONG KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    ULONG PrivatePageCount;  // Garbage
    VM_COUNTERS VirtualMemoryCounters;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD_INFORMATION Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _PROCESS_DEVICEMAP_INFORMATION {
  _ANONYMOUS_UNION union {
    struct {
      HANDLE DirectoryHandle;
    } Set;
    struct {
      ULONG DriveMap;
      UCHAR DriveType[32];
    } Query;
  } DUMMYUNIONNAME;
}PROCESS_DEVICEMAP_INFORMATION,*PPROCESS_DEVICEMAP_INFORMATION;

#define MAX_DOS_DRIVES   26
#define IS_SEPARATOR(ch)  ((ch)==L'\\'||(ch)==L'/')
#define RTL_CONSTANT_STRING(s) {sizeof(s)-sizeof((s)[0]),sizeof(s),s}
#define UNICODE_STRING_MAX_BYTES   ((USHORT) 65534)

typedef BOOLEAN(WINAPI * PDLL_INIT_ROUTINE)(PVOID DllHandle,ULONG Reason,PCONTEXT Context);

typedef enum _RTL_PATH_TYPE{
  RTL_INVALID_PATH=0,
  RTL_UNC_PATH,               // "\\" or "\\foo"
  RTL_ABSOLUTE_DRIVE_PATH,    // "c:\foo"
  RTL_RELATIVE_DRIVE_PATH,    // "c:foo"
  RTL_ABSOLUTE_PATH,          // "\" or "\foo"
  RTL_RELATIVE_PATH,          // "f" or "foo"
  RTL_DEVICE_PATH,            // "\\.\foo" or "\\?\foo"
  RTL_UNC_DOT_PATH            // "\\." or "\\?"
} DOS_PATH_TYPE;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  CHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _HARDERROR_RESPONSE{
  ResponseReturnToCaller,
  ResponseNotHandled,
  ResponseAbort,
  ResponseCancel,
  ResponseIgnore,
  ResponseNo,
  ResponseOk,
  ResponseRetry,
  ResponseYes
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

typedef enum _HARDERROR_RESPONSE_OPTION{
  OptionAbortRetryIgnore,
  OptionOk,
  OptionOkCancel,
  OptionRetryCancel,
  OptionYesNo,
  OptionYesNoCancel,
  OptionShutdownSystem,
  OptionOkNoWait,
  OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

//drivers...

#define SE_MIN_WELL_KNOWN_PRIVILEGE         2
#define SE_CREATE_TOKEN_PRIVILEGE           2
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     3
#define SE_LOCK_MEMORY_PRIVILEGE            4
#define SE_INCREASE_QUOTA_PRIVILEGE         5
#define SE_MACHINE_ACCOUNT_PRIVILEGE        6
#define SE_TCB_PRIVILEGE                    7
#define SE_SECURITY_PRIVILEGE               8
#define SE_TAKE_OWNERSHIP_PRIVILEGE         9
#define SE_LOAD_DRIVER_PRIVILEGE            10
#define SE_SYSTEM_PROFILE_PRIVILEGE         11
#define SE_SYSTEMTIME_PRIVILEGE             12
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    13
#define SE_INC_BASE_PRIORITY_PRIVILEGE      14
#define SE_CREATE_PAGEFILE_PRIVILEGE        15
#define SE_CREATE_PERMANENT_PRIVILEGE       16
#define SE_BACKUP_PRIVILEGE                 17
#define SE_RESTORE_PRIVILEGE                18
#define SE_SHUTDOWN_PRIVILEGE               19
#define SE_DEBUG_PRIVILEGE                  20
#define SE_AUDIT_PRIVILEGE                  21
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     22
#define SE_CHANGE_NOTIFY_PRIVILEGE          23
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        24
#define SE_UNDOCK_PRIVILEGE                 25
#define SE_SYNC_AGENT_PRIVILEGE             26
#define SE_ENABLE_DELEGATION_PRIVILEGE      27
#define SE_MANAGE_VOLUME_PRIVILEGE          28
#define SE_IMPERSONATE_PRIVILEGE            29
#define SE_CREATE_GLOBAL_PRIVILEGE          30
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE 31
#define SE_RELABEL_PRIVILEGE                32
#define SE_INC_WORKING_SET_PRIVILEGE        33
#define SE_TIME_ZONE_PRIVILEGE              34
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   35
#define SE_MAX_WELL_KNOWN_PRIVILEGE         SE_CREATE_SYMBOLIC_LINK_PRIVILEGE

#define MANAGER_TAG 0x72674D68  /* 'hMgr' */
#define SERVICE_TAG 0x63765368  /* 'hSvc' */

#define SC_MANAGER_READ \
  (STANDARD_RIGHTS_READ | \
   SC_MANAGER_QUERY_LOCK_STATUS | \
   SC_MANAGER_ENUMERATE_SERVICE)

#define SC_MANAGER_WRITE \
  (STANDARD_RIGHTS_WRITE | \
   SC_MANAGER_MODIFY_BOOT_CONFIG | \
   SC_MANAGER_CREATE_SERVICE)

#define SC_MANAGER_EXECUTE \
  (STANDARD_RIGHTS_EXECUTE | \
   SC_MANAGER_LOCK | \
   SC_MANAGER_ENUMERATE_SERVICE | \
   SC_MANAGER_CONNECT | \
   SC_MANAGER_CREATE_SERVICE)

#define SERVICE_READ \
  (STANDARD_RIGHTS_READ | \
   SERVICE_INTERROGATE | \
   SERVICE_ENUMERATE_DEPENDENTS | \
   SERVICE_QUERY_STATUS | \
   SERVICE_QUERY_CONFIG)

#define SERVICE_WRITE \
  (STANDARD_RIGHTS_WRITE | \
   SERVICE_CHANGE_CONFIG)

#define SERVICE_EXECUTE \
  (STANDARD_RIGHTS_EXECUTE | \
   SERVICE_USER_DEFINED_CONTROL | \
   SERVICE_PAUSE_CONTINUE | \
   SERVICE_STOP | \
   SERVICE_START)

typedef struct _SERVICE_GROUP{
  LIST_ENTRY GroupListEntry;
  LPWSTR lpGroupName;
  DWORD dwRefCount;
  BOOLEAN ServicesRunning;
  ULONG TagCount;
  PULONG TagArray;
  WCHAR szGroupName[1];
} SERVICE_GROUP, *PSERVICE_GROUP;

typedef struct _SERVICE_IMAGE{
  LIST_ENTRY ImageListEntry;
  DWORD dwImageRunCount;
  HANDLE hControlPipe;
  HANDLE hProcess;
  DWORD dwProcessId;
  WCHAR szImagePath[1];
} SERVICE_IMAGE, *PSERVICE_IMAGE;

typedef struct _SERVICE{
  LIST_ENTRY ServiceListEntry;
  LPWSTR lpServiceName;
  LPWSTR lpDisplayName;
  PSERVICE_GROUP lpGroup;
  PSERVICE_IMAGE lpImage;
  BOOL bDeleted;
  DWORD dwResumeCount;
  DWORD dwRefCount;
  SERVICE_STATUS Status;
  DWORD dwStartType;
  DWORD dwErrorControl;
  DWORD dwTag;
  ULONG Flags;
  PSECURITY_DESCRIPTOR lpSecurityDescriptor;
  BOOLEAN ServiceVisited;
  WCHAR szServiceName[1];
} SERVICE, *PSERVICE;

typedef struct _SCMGR_HANDLE{
  DWORD Tag;
  DWORD DesiredAccess;
} SCMGR_HANDLE;

typedef struct _MANAGER_HANDLE{
  SCMGR_HANDLE Handle;
  WCHAR DatabaseName[1];
} MANAGER_HANDLE, *PMANAGER_HANDLE;

typedef struct _SERVICE_HANDLE{
  SCMGR_HANDLE Handle;
  PSERVICE ServiceEntry;
} SERVICE_HANDLE, *PSERVICE_HANDLE;

typedef struct _OBJECT_DIRECTORY_INFORMATION{
  UNICODE_STRING Name;
  UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

#endif // _PSTYPES_H
