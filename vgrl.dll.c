typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    ImageBaseOffset32 EndAddress;
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef ushort WORD;

typedef ulong DWORD;

typedef longlong INT_PTR;

typedef INT_PTR (*FARPROC)(void);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef DWORD *LPDWORD;

typedef void *HANDLE;

typedef HANDLE HLOCAL;

typedef struct HWINSTA__ HWINSTA__, *PHWINSTA__;

struct HWINSTA__ {
    int unused;
};

typedef struct HWINSTA__ *HWINSTA;

typedef int BOOL;

typedef uchar BYTE;

typedef BYTE *LPBYTE;

typedef uint UINT;

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    ImageBaseOffset32 Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    ImageBaseOffset32 AddressOfFunctions;
    ImageBaseOffset32 AddressOfNames;
    ImageBaseOffset32 AddressOfNameOrdinals;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer64 GuardAddressTakenIatEntryTable;
    qword GuardAddressTakenIatEntryCount;
    pointer64 GuardLongJumpTargetTable;
    qword GuardLongJumpTargetCount;
    pointer64 DynamicValueRelocTable;
    pointer64 CHPEMetadataPointer;
    pointer64 GuardRFFailureRoutine;
    pointer64 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer64 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    qword Reserved3;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOW *LPSTARTUPINFOW;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef void *PVOID;

typedef WCHAR *LPCWSTR;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ulonglong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR *PDWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[27];
};




void FUN_1801bcb41(void)

{
  code *in_RAX;
  
  (*in_RAX)();
  FUN_180367892();
  return;
}



void FUN_1801d2115(void)

{
  code *in_RAX;
  
  (*in_RAX)();
  FUN_180367878();
  return;
}



// WARNING: Control flow encountered bad instruction data

void entry(void)

{
  FUN_180404dd9();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



longlong FUN_1803673bb(short *param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  byte bVar5;
  uint uVar6;
  longlong lVar7;
  char *pcVar8;
  char cVar9;
  uint uVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  byte bVar13;
  int iVar14;
  char *pcVar15;
  ulonglong uVar16;
  byte *pbVar17;
  int iVar18;
  uint unaff_R14D;
  uint local_res8;
  char local_138 [280];
  
  if ((((param_1 == (short *)0x0) || (param_2 == 0)) || (*param_1 != 0x5a4d)) ||
     ((lVar7 = (longlong)*(int *)(param_1 + 0x1e), *(int *)(lVar7 + (longlong)param_1) != 0x4550 ||
      (uVar3 = *(uint *)(lVar7 + 0x88 + (longlong)param_1), uVar3 == 0)))) {
    return 0;
  }
  uVar11 = 0xffffffff;
  uVar12 = 0;
  local_res8 = 0xffffffff;
  if (param_2 < 0x10000) {
    uVar10 = (int)param_2 - *(int *)((longlong)param_1 + (ulonglong)uVar3 + 0x10);
    if (*(uint *)((longlong)param_1 + (ulonglong)uVar3 + 0x14) <= uVar10) {
      return 0;
    }
    uVar10 = *(uint *)((longlong)param_1 +
                      (ulonglong)uVar10 * 4 +
                      (ulonglong)*(uint *)((longlong)param_1 + (ulonglong)uVar3 + 0x1c));
  }
  else {
    iVar18 = *(int *)((longlong)param_1 + (ulonglong)uVar3 + 0x18);
    if (iVar18 != 0) {
      uVar10 = *(uint *)((longlong)param_1 + (ulonglong)uVar3 + 0x20);
      iVar18 = iVar18 + -1;
      iVar14 = 0;
      if (-1 < iVar18) {
        do {
          uVar6 = iVar18 + iVar14 >> 1;
          uVar11 = (ulonglong)uVar6;
          iVar4 = 0;
          if (unaff_R14D != 0) {
            for (; (unaff_R14D >> iVar4 & 1) == 0; iVar4 = iVar4 + 1) {
            }
          }
          pbVar17 = (byte *)((ulonglong)
                             *(uint *)((longlong)param_1 + uVar11 * 4 + (ulonglong)uVar10) +
                            (longlong)param_1);
          uVar16 = uVar12;
          do {
            bVar13 = pbVar17[(param_2 -
                             *(uint *)((longlong)param_1 + uVar11 * 4 + (ulonglong)uVar10)) -
                             (longlong)param_1];
            bVar1 = *pbVar17;
            pbVar17 = pbVar17 + 1;
            if (param_3 != '\0') {
              bVar5 = (byte)uVar16 & 0x1f;
              bVar13 = bVar13 ^ ((byte)(0x530f2b2f << bVar5) | (byte)(0x530f2b2f >> 0x20 - bVar5)) +
                                (byte)uVar16;
              uVar16 = uVar16 + 1;
            }
          } while ((bVar13 != 0) && (bVar13 == bVar1));
          if (bVar13 < bVar1) {
            uVar11 = (ulonglong)local_res8;
            iVar18 = uVar6 - 1;
          }
          else if (bVar1 < bVar13) {
            uVar11 = (ulonglong)local_res8;
            iVar14 = uVar6 + 1;
          }
          else {
            iVar14 = iVar18 + 1;
            uVar2 = *(ushort *)
                     ((longlong)param_1 +
                     uVar11 * 2 + (ulonglong)*(uint *)((longlong)param_1 + (ulonglong)uVar3 + 0x24))
            ;
            uVar11 = (ulonglong)uVar2;
            local_res8 = (uint)uVar2;
          }
        } while (iVar14 <= iVar18);
      }
    }
    if (*(uint *)((longlong)param_1 + (ulonglong)uVar3 + 0x14) <= (uint)uVar11) {
      return 0;
    }
    uVar10 = *(uint *)((longlong)param_1 +
                      uVar11 * 4 + (ulonglong)*(uint *)((longlong)param_1 + (ulonglong)uVar3 + 0x1c)
                      );
  }
  if (uVar10 != 0) {
    if ((uVar10 < uVar3) || (*(int *)(lVar7 + 0x8c + (longlong)param_1) + uVar3 <= uVar10)) {
      return (ulonglong)uVar10 + (longlong)param_1;
    }
    pcVar8 = (char *)((ulonglong)uVar10 + (longlong)param_1);
    cVar9 = *pcVar8;
    pcVar15 = pcVar8;
    if (cVar9 != '\0') {
      while (cVar9 != '.') {
        cVar9 = pcVar15[1];
        pcVar15 = pcVar15 + 1;
        if (cVar9 == '\0') {
          return 0;
        }
      }
      uVar11 = (longlong)pcVar15 - (longlong)pcVar8;
      if (uVar11 < 0x104) {
        if (pcVar15 != pcVar8) {
          lVar7 = -(longlong)pcVar8;
          do {
            if (*pcVar8 == '\0') break;
            uVar12 = uVar12 + 1;
            pcVar8[(longlong)(local_138 + lVar7)] = *pcVar8;
            pcVar8 = pcVar8 + 1;
          } while (uVar12 < uVar11);
        }
        local_138[uVar12] = '\0';
        lVar7 = FUN_1801d2115(local_138);
        return lVar7;
      }
    }
  }
  return 0;
}



void FUN_180367878(void)

{
  char cVar1;
  byte bVar2;
  longlong in_RAX;
  longlong unaff_RBX;
  char *pcVar3;
  LPCSTR unaff_RBP;
  HMODULE unaff_RSI;
  ulonglong unaff_RDI;
  undefined4 in_R11D;
  undefined4 in_register_0000009c;
  char in_stack_000001a0;
  
  if (in_RAX == 0) {
    FUN_1801bcb41(&stack0x00000050);
    return;
  }
  if ((HMODULE)CONCAT44(in_register_0000009c,in_R11D) == unaff_RSI) {
    if (in_stack_000001a0 != (char)unaff_RDI) {
      do {
        bVar2 = (byte)unaff_RDI & 0x1f;
        bVar2 = ((byte)(0x530f2b2f << bVar2) | (byte)(0x530f2b2f >> 0x20 - bVar2)) + (byte)unaff_RDI
                ^ (&stack0x00000050 + unaff_RDI)[(longlong)unaff_RBP - (longlong)&stack0x00000050];
        (&stack0x00000050)[unaff_RDI] = bVar2;
        if (bVar2 == 0) break;
        unaff_RDI = unaff_RDI + 1;
      } while (unaff_RDI < 0x104);
      unaff_RBP = &stack0x00000050;
    }
    GetProcAddress(unaff_RSI,unaff_RBP);
  }
  else {
    if (*(char *)(unaff_RBX + 1) == '#') {
      pcVar3 = (char *)(unaff_RBX + 2);
      cVar1 = *(char *)(unaff_RBX + 2);
      while ((cVar1 != '\0' && (pcVar3 = pcVar3 + 1, (byte)(cVar1 - 0x30U) < 10))) {
        cVar1 = *pcVar3;
      }
    }
    FUN_1803673bb();
  }
  return;
}



FARPROC FUN_180367892(void)

{
  char cVar1;
  byte bVar2;
  FARPROC pFVar3;
  longlong unaff_RBX;
  char *pcVar4;
  LPCSTR unaff_RBP;
  HMODULE unaff_RSI;
  ulonglong unaff_RDI;
  undefined4 in_R11D;
  undefined4 in_register_0000009c;
  bool in_ZF;
  char param_13;
  
  if (in_ZF) {
    pFVar3 = (FARPROC)0x0;
  }
  else if ((HMODULE)CONCAT44(in_register_0000009c,in_R11D) == unaff_RSI) {
    if (param_13 != (char)unaff_RDI) {
      do {
        bVar2 = (byte)unaff_RDI & 0x1f;
        bVar2 = ((byte)(0x530f2b2f << bVar2) | (byte)(0x530f2b2f >> 0x20 - bVar2)) + (byte)unaff_RDI
                ^ (&stack0x00000050 + unaff_RDI)[(longlong)unaff_RBP - (longlong)&stack0x00000050];
        (&stack0x00000050)[unaff_RDI] = bVar2;
        if (bVar2 == 0) break;
        unaff_RDI = unaff_RDI + 1;
      } while (unaff_RDI < 0x104);
      unaff_RBP = &stack0x00000050;
    }
    pFVar3 = GetProcAddress(unaff_RSI,unaff_RBP);
  }
  else {
    if (*(char *)(unaff_RBX + 1) == '#') {
      pcVar4 = (char *)(unaff_RBX + 2);
      cVar1 = *(char *)(unaff_RBX + 2);
      while ((cVar1 != '\0' && (pcVar4 = pcVar4 + 1, (byte)(cVar1 - 0x30U) < 10))) {
        cVar1 = *pcVar4;
      }
    }
    pFVar3 = (FARPROC)FUN_1803673bb();
  }
  return pFVar3;
}



void FUN_18036f160(void)

{
  FUN_1803d2f81();
  return;
}



void FUN_1803d1222(undefined8 param_1,undefined8 param_2,ushort param_3)

{
  short sVar1;
  undefined2 unaff_DI;
  ushort uVar2;
  
  uVar2 = (ushort)CONCAT31((int3)(char)((ushort)unaff_DI >> 8),0xdf) & ~(1 << (param_3 & 0xf));
  sVar1 = 0xf;
  if (uVar2 != 0) {
    for (; uVar2 >> sVar1 == 0; sVar1 = sVar1 + -1) {
    }
  }
  FUN_18036f160();
  return;
}



void FUN_1803d2f81(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x0001803d2f81. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_1803fa2b6(void)

{
  FUN_1803d1222();
  return;
}



void FUN_180404dd9(void)

{
  FUN_1803fa2b6();
  return;
}



void FUN_18049503f(void)

{
  return;
}


