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


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

typedef ulong DWORD;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef longlong INT_PTR;

typedef INT_PTR (*FARPROC)(void);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_16 IMAGE_RESOURCE_DIR_STRING_U_16, *PIMAGE_RESOURCE_DIR_STRING_U_16;

struct IMAGE_RESOURCE_DIR_STRING_U_16 {
    word Length;
    wchar16 NameString[8];
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

typedef struct IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

struct IMAGE_THUNK_DATA64 {
    qword StartAddressOfRawData;
    qword EndAddressOfRawData;
    qword AddressOfIndex;
    qword AddressOfCallBacks;
    dword SizeOfZeroFill;
    dword Characteristics;
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

typedef struct GuardCfgTableEntry GuardCfgTableEntry, *PGuardCfgTableEntry;

struct GuardCfgTableEntry {
    ImageBaseOffset32 Offset;
    byte Pad[1];
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulonglong ULONG_PTR;

typedef union _union_540 _union_540, *P_union_540;

typedef struct _struct_541 _struct_541, *P_struct_541;

typedef void *PVOID;

struct _struct_541 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_540 {
    struct _struct_541 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_540 u;
    HANDLE hEvent;
};

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef wchar_t WCHAR;

typedef long HRESULT;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef BYTE BOOLEAN;

typedef WCHAR *LPCWSTR;

typedef WCHAR *LPWSTR;

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _RUNTIME_FUNCTION *PRUNTIME_FUNCTION;

typedef long LONG;

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

typedef void *HCRYPTMSG;

typedef ULONG_PTR HCRYPTKEY;

typedef void *HCERTSTORE;

typedef ULONG_PTR HCRYPTHASH;

typedef ulonglong UINT_PTR;

typedef UINT_PTR SOCKET;

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




void FUN_140a40ad2(void)

{
  code *in_RAX;
  
  (*in_RAX)();
  FUN_1411d4cf8();
  return;
}



void FUN_140a4dc63(void)

{
  code *in_RAX;
  
  (*in_RAX)();
  return;
}



void FUN_140ba508f(void)

{
  undefined4 in_EAX;
  undefined4 in_register_00000004;
  
  (*(code *)CONCAT44(in_register_00000004,in_EAX))();
  return;
}



// WARNING: Control flow encountered bad instruction data

void tls_callback_0(void)

{
  longlong unaff_RBX;
  byte in_R9B;
  
  FUN_1411f79ed();
  *(byte *)(unaff_RBX + -0x2d) = *(byte *)(unaff_RBX + -0x2d) ^ in_R9B;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void entry(void)

{
  FUN_14129bbd9();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



longlong FUN_1411d4820(HMODULE param_1,byte *param_2,char param_3)

{
  byte bVar1;
  ushort uVar2;
  uint uVar3;
  uint uVar4;
  short sVar5;
  byte bVar6;
  byte bVar7;
  uint uVar8;
  longlong lVar9;
  char *pcVar10;
  HMODULE pHVar11;
  char cVar12;
  uint uVar13;
  ulonglong uVar14;
  ulonglong uVar15;
  char *pcVar16;
  uint uVar17;
  ulonglong uVar18;
  byte *pbVar19;
  int iVar20;
  ushort unaff_R13W;
  uint local_res8;
  byte local_138 [280];
  
  if ((((param_1 == (HMODULE)0x0) || (param_2 == (byte *)0x0)) ||
      (*(short *)&param_1->unused != 0x5a4d)) ||
     ((lVar9 = (longlong)param_1[0xf].unused, *(int *)((longlong)&param_1->unused + lVar9) != 0x4550
      || (uVar3 = *(uint *)((longlong)&param_1[0x22].unused + lVar9), uVar3 == 0)))) {
    return 0;
  }
  uVar14 = 0xffffffff;
  uVar18 = 0;
  uVar17 = 0;
  local_res8 = 0xffffffff;
  if (param_2 < (byte *)0x10000) {
    uVar13 = (int)param_2 - *(int *)((longlong)&param_1[4].unused + (ulonglong)uVar3);
    if (*(uint *)((longlong)&param_1[5].unused + (ulonglong)uVar3) <= uVar13) {
      return 0;
    }
    uVar13 = *(uint *)((longlong)&param_1[uVar13].unused +
                      (ulonglong)*(uint *)((longlong)&param_1[7].unused + (ulonglong)uVar3));
  }
  else {
    iVar20 = *(int *)((longlong)&param_1[6].unused + (ulonglong)uVar3);
    if (iVar20 != 0) {
      uVar4 = *(uint *)((longlong)&param_1[8].unused + (ulonglong)uVar3);
      iVar20 = iVar20 + -1;
      uVar13 = uVar17;
      if (-1 < iVar20) {
        do {
          uVar8 = (int)(iVar20 + uVar13) >> 1;
          uVar15 = (ulonglong)uVar8;
          pbVar19 = (byte *)((longlong)&param_1->unused +
                            (ulonglong)
                            *(uint *)((longlong)&param_1[uVar15].unused + (ulonglong)uVar4));
          uVar14 = uVar18;
          do {
            bVar7 = pbVar19[(longlong)
                            (param_2 +
                            (-(longlong)param_1 -
                            (ulonglong)
                            *(uint *)((longlong)&param_1[uVar15].unused + (ulonglong)uVar4)))];
            bVar1 = *pbVar19;
            pbVar19 = pbVar19 + 1;
            if (param_3 != '\0') {
              bVar6 = (byte)uVar14 & 0x1f;
              bVar7 = bVar7 ^ ((byte)(0x332f42ef << bVar6) | (byte)(0x332f42ef >> 0x20 - bVar6)) +
                              (byte)uVar14;
              uVar14 = uVar14 + 1;
            }
          } while ((bVar7 != 0) && (bVar7 == bVar1));
          if (bVar7 < bVar1) {
            uVar14 = (ulonglong)local_res8;
            iVar20 = uVar8 - 1;
          }
          else if (bVar1 < bVar7) {
            uVar14 = (ulonglong)local_res8;
            uVar13 = uVar8 + 1;
          }
          else {
            uVar13 = iVar20 + 1;
            uVar2 = *(ushort *)
                     ((longlong)&param_1->unused +
                     uVar15 * 2 +
                     (ulonglong)*(uint *)((longlong)&param_1[9].unused + (ulonglong)uVar3));
            uVar14 = (ulonglong)uVar2;
            local_res8 = (uint)uVar2;
          }
        } while ((int)uVar13 <= iVar20);
      }
    }
    if (*(uint *)((longlong)&param_1[5].unused + (ulonglong)uVar3) <= (uint)uVar14) {
      return 0;
    }
    uVar13 = *(uint *)((longlong)&param_1[uVar14].unused +
                      (ulonglong)*(uint *)((longlong)&param_1[7].unused + (ulonglong)uVar3));
  }
  if (uVar13 != 0) {
    if ((uVar13 < uVar3) || (*(int *)((longlong)&param_1[0x23].unused + lVar9) + uVar3 <= uVar13)) {
      return (longlong)&param_1->unused + (ulonglong)uVar13;
    }
    pcVar10 = (char *)((longlong)&param_1->unused + (ulonglong)uVar13);
    cVar12 = *pcVar10;
    pcVar16 = pcVar10;
    if (cVar12 != '\0') {
      while (cVar12 != '.') {
        cVar12 = pcVar16[1];
        pcVar16 = pcVar16 + 1;
        if (cVar12 == '\0') {
          return 0;
        }
      }
      uVar14 = (longlong)pcVar16 - (longlong)pcVar10;
      if (uVar14 < 0x104) {
        uVar15 = uVar18;
        if (pcVar16 != pcVar10) {
          sVar5 = 0xf;
          if (unaff_R13W != 0) {
            for (; unaff_R13W >> sVar5 == 0; sVar5 = sVar5 + -1) {
            }
          }
          lVar9 = -(longlong)pcVar10;
          do {
            if (*pcVar10 == '\0') break;
            uVar15 = uVar15 + 1;
            pcVar10[(longlong)(local_138 + lVar9)] = *pcVar10;
            pcVar10 = pcVar10 + 1;
          } while (uVar15 < uVar14);
        }
        local_138[uVar15] = 0;
        pHVar11 = GetModuleHandleA((LPCSTR)local_138);
        if (pHVar11 == (HMODULE)0x0) {
          lVar9 = FUN_140a40ad2(local_138);
          return lVar9;
        }
        if (pHVar11 != param_1) {
          pcVar10 = pcVar16 + 1;
          if (pcVar16[1] == '#') {
            pcVar10 = pcVar16 + 2;
            cVar12 = pcVar16[2];
            while (cVar12 != '\0') {
              uVar17 = (uint)uVar18;
              pcVar10 = pcVar10 + 1;
              if (9 < (byte)(cVar12 - 0x30U)) break;
              uVar17 = cVar12 + -0x30 + uVar17 * 10;
              uVar18 = (ulonglong)uVar17;
              cVar12 = *pcVar10;
            }
            pcVar10 = (char *)(longlong)(int)uVar17;
          }
          lVar9 = FUN_1411d4820(pHVar11,pcVar10,0);
          return lVar9;
        }
        if (param_3 != '\0') {
          rdtsc();
          do {
            bVar7 = (byte)uVar18 & 0x1f;
            bVar7 = ((byte)(0x332f42ef << bVar7) | (byte)(0x332f42ef >> 0x20 - bVar7)) +
                    (byte)uVar18 ^ (local_138 + uVar18)[(longlong)param_2 - (longlong)local_138];
            local_138[uVar18] = bVar7;
            if (bVar7 == 0) break;
            uVar18 = uVar18 + 1;
          } while (uVar18 < 0x104);
          param_2 = local_138;
        }
        lVar9 = FUN_140ba508f(param_1,param_2);
        return lVar9;
      }
    }
  }
  return 0;
}



undefined8 FUN_1411d4cf8(void)

{
  char cVar1;
  byte bVar2;
  undefined8 uVar3;
  longlong unaff_RBX;
  char *pcVar4;
  longlong unaff_RBP;
  longlong unaff_RSI;
  ulonglong unaff_RDI;
  undefined2 in_R11W;
  undefined6 in_register_0000009a;
  bool in_ZF;
  char param_13;
  
  if (in_ZF) {
    uVar3 = 0;
  }
  else {
    if (CONCAT62(in_register_0000009a,in_R11W) == unaff_RSI) {
      if (param_13 != (char)unaff_RDI) {
        rdtsc();
        do {
          bVar2 = (byte)unaff_RDI & 0x1f;
          bVar2 = ((byte)(0x332f42ef << bVar2) | (byte)(0x332f42ef >> 0x20 - bVar2)) +
                  (byte)unaff_RDI ^
                  (&stack0x00000050 + unaff_RDI)[unaff_RBP - (longlong)&stack0x00000050];
          (&stack0x00000050)[unaff_RDI] = bVar2;
          if (bVar2 == 0) break;
          unaff_RDI = unaff_RDI + 1;
        } while (unaff_RDI < 0x104);
      }
      uVar3 = FUN_140ba508f();
      return uVar3;
    }
    if (*(char *)(unaff_RBX + 1) == '#') {
      pcVar4 = (char *)(unaff_RBX + 2);
      cVar1 = *(char *)(unaff_RBX + 2);
      while ((cVar1 != '\0' && (pcVar4 = pcVar4 + 1, (byte)(cVar1 - 0x30U) < 10))) {
        cVar1 = *pcVar4;
      }
    }
    uVar3 = FUN_1411d4820();
  }
  return uVar3;
}



void FUN_1411ddea3(void)

{
  FUN_141311f03();
  return;
}



void FUN_1411f1d6d(void)

{
  FUN_1412ec053();
  return;
}



void FUN_1411f2812(void)

{
  undefined *unaff_RDI;
  
  if (unaff_RDI <= &stack0x00000140) {
    FUN_14128283c(0x100);
    return;
  }
  return;
}



void FUN_1411f64e4(longlong param_1)

{
  undefined *unaff_RSI;
  undefined *unaff_RDI;
  
  for (; param_1 != 0; param_1 = param_1 + -1) {
    *unaff_RDI = *unaff_RSI;
    unaff_RSI = unaff_RSI + 1;
    unaff_RDI = unaff_RDI + 1;
  }
  FUN_1412e2386();
  return;
}



void FUN_1411f79ed(void)

{
  FUN_141262066();
  return;
}



void FUN_141206820(undefined8 param_1,undefined8 param_2,int param_3)

{
  FUN_14128fb45((longlong)param_3,param_2,param_3,(longlong)(short)&stack0xffffffffffffffb8);
  return;
}



void FUN_14121a02c(void)

{
  FUN_1412ebbbd();
  return;
}



// WARNING: Removing unreachable block (ram,0x0001412211c3)

void FUN_1412210cc(undefined param_1,undefined8 param_2,undefined param_3)

{
  FUN_141314899(param_1,0x100000000,param_3,0x141221213);
  return;
}



void FUN_141224f9b(void)

{
  FUN_1412b3aa4();
  return;
}



void FUN_141228ab4(void)

{
  FUN_14126e259();
  return;
}



void FUN_14122ff6d(ushort param_1,undefined8 param_2,undefined8 param_3)

{
  FUN_141304df2(param_1,0x100000000,
                ~((int)CONCAT62((int6)((ulonglong)param_3 >> 0x10),
                                (short)param_3 << 1 | param_1 >> 0xf) - 1U),0);
  return;
}



void FUN_1412410fa(void)

{
  FUN_1411f1d6d();
  return;
}



void FUN_14126020d(void)

{
  FUN_14126d14f();
  return;
}



void FUN_141262066(void)

{
  FUN_1412958d8();
  return;
}



void FUN_14126d14f(void)

{
  FUN_141318610();
  return;
}



void FUN_14126e259(void)

{
  FUN_1412fface();
  return;
}



void FUN_141277da1(void)

{
  FUN_1412987d8();
  return;
}



void FUN_141278358(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4)

{
  FUN_14121a02c(param_1,param_2,CONCAT71((uint7)(uint3)(int3)(char)((ushort)param_4 >> 8),0xc3));
  return;
}



void FUN_141280d18(int param_1,undefined8 param_2,undefined4 param_3,uint param_4)

{
  uint uVar1;
  
  uVar1 = (((uint)-param_1 >> 1 | (uint)((-param_1 & 1U) != 0) << 0x1f) ^ 0x1b583b8a) + 0xf7a38894 ^
          0x277774b7;
  FUN_141292ecb((longlong)(int)uVar1,param_2,param_3,param_4 ^ uVar1);
  return;
}



void FUN_14128283c(void)

{
  FUN_1411ddea3();
  return;
}



void FUN_1412840d5(void)

{
  FUN_141277da1();
  return;
}



void FUN_14128fb45(undefined8 param_1,undefined8 param_2,undefined2 param_3)

{
  uint uVar1;
  char unaff_R13B;
  char unaff_R14B;
  uint param_11;
  
  uVar1 = (param_11 >> 0x18 | (param_11 & 0xff0000) >> 8 | (param_11 & 0xff00) << 8 |
          param_11 << 0x18) + 1;
  FUN_1412ad617(-(ulonglong)CONCAT22((short)unaff_R14B >> 0xf,(short)unaff_R13B),param_2,param_3,
                (ulonglong)
                -(uVar1 >> 0x18 | (uVar1 & 0xff0000) >> 8 | (uVar1 & 0xff00) << 8 |
                 uVar1 * 0x1000000) + 0x100000000);
  return;
}



void FUN_141292ecb(void)

{
  return;
}



void FUN_1412958d8(void)

{
  FUN_1412410fa();
  return;
}



void FUN_1412987d8(void)

{
  return;
}



void FUN_14129bbd9(void)

{
  FUN_141206820();
  return;
}



// WARNING: Removing unreachable block (ram,0x0001412ad62b)

void FUN_1412ad617(void)

{
  longlong unaff_RBP;
  uint in_R9D;
  
  FUN_141280d18(*(uint *)(unaff_RBP + -4) ^ in_R9D);
  return;
}



void FUN_1412b3aa4(void)

{
  FUN_1412c734f();
  return;
}



void FUN_1412bd27d(void)

{
  FUN_141228ab4();
  return;
}



void FUN_1412c14ff(void)

{
  FUN_1412210cc();
  return;
}



void FUN_1412c734f(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x0001412c734f. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_1412d0b68(void)

{
  FUN_1413029fc();
  return;
}



void FUN_1412dcaf3(void)

{
  FUN_1412f6d17();
  return;
}



void FUN_1412e2386(void)

{
  return;
}



void FUN_1412ebbbd(void)

{
  return;
}



void FUN_1412ec053(void)

{
  FUN_1412840d5();
  return;
}



void FUN_1412f6d17(undefined param_1,undefined8 param_2,uint param_3)

{
  int in_R11D;
  
  FUN_14126020d(param_1,param_2,param_3 ^ ~((~(in_R11D - 1U) >> 2 | ~(in_R11D - 1U) << 0x1e) - 1));
  return;
}



void FUN_1412fface(undefined param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  uint unaff_EDI;
  
  FUN_14122ff6d(param_1,(int)(short)CONCAT71((int7)((ulonglong)param_4 >> 8),
                                             (char)param_4 + -0xc + ((unaff_EDI >> 0x13 & 1) != 0))
                        | 0x17c62ce4);
  return;
}



void FUN_1413029fc(void)

{
  FUN_1412dcaf3();
  return;
}



void FUN_141304df2(undefined param_1,undefined8 param_2)

{
  undefined8 unaff_RBX;
  
  FUN_1412d0b68(param_1,param_2,unaff_RBX,0x141304e25);
  return;
}



void FUN_141311f03(void)

{
  FUN_1411f64e4();
  return;
}



void FUN_141314899(void)

{
  FUN_141224f9b();
  return;
}



void FUN_141318610(void)

{
  return;
}


