#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

enum class Family
{
    BaseBacking,
    FileIdentity,
    HeaderAgreement,
    CodeContent,
    EntryLocality,
    LoaderState
};

enum class Tier
{
    Strong,
    Moderate,
    Weak
};

struct Evidence
{
    Family       family;
    Tier         tier;
    std::wstring text;
};

struct Section
{
    char     name[9];
    uint32_t rva;
    uint32_t vsize;
    uint32_t rawptr;
    uint32_t rawsize;
    uint32_t chars;
};

struct PeInfo
{
    bool      valid = false;
    bool      pe64 = false;
    uint64_t  preferred_base = 0;
    uint32_t  size_of_image = 0;
    uint32_t  size_of_headers = 0;
    uint32_t  entry_rva = 0;
    uint32_t  reloc_rva = 0;
    uint32_t  reloc_size = 0;
    std::vector<Section> sections;
};

struct DiskLoad
{
    bool     ok = false;
    bool     absent = false;
    bool     denied = false;
    bool     stale = false;
    uint64_t write_time = 0;
    PeInfo   pe;
    std::vector<uint8_t> view;
};

struct DiffStats
{
    size_t compared = 0;
    size_t differing = 0;
    size_t clusters = 0;
    size_t hooklike = 0;
    size_t bulk = 0;
    size_t largest = 0;
};

struct Finding
{
    DWORD        pid = 0;
    std::wstring path;
    uintptr_t    base = 0;
    uint32_t     disk_entry_rva = 0;
    uint32_t     mem_entry_rva = 0;
    bool         disk_valid = false;
    std::vector<Evidence>     evidence;
    std::vector<std::wstring> coverage;

    void add(Family fam, Tier t, const wchar_t* text)
    {
        evidence.push_back({ fam, t, text });
    }

    void addf(Family fam, Tier t, const wchar_t* fmt, ...)
    {
        wchar_t buf[256];
        va_list ap;
        va_start(ap, fmt);
        _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
        va_end(ap);
        evidence.push_back({ fam, t, buf });
    }

    void note(const wchar_t* text)
    {
        coverage.push_back(text);
    }
};

static const size_t kClusterGap      = 8;
static const size_t kHookMaxLen      = 24;
static const size_t kBulkStrong      = 4096;
static const size_t kRunStrong       = 1024;
static const double kRatioStrong     = 0.02;
static const size_t kBulkModerate    = 256;
static const uint64_t kMtimeSlack    = 20ull * 1000 * 1000 * 10;

static bool EnableDebugPriv()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tok))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(tok);
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(tok);
    return err == ERROR_SUCCESS;
}

static std::wstring LowerOf(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static uint64_t ToU64(const FILETIME& ft)
{
    ULARGE_INTEGER u;
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

static std::wstring DeviceToDos(const std::wstring& nt)
{
    if (nt.empty())
        return nt;

    wchar_t drives[512] = {};
    DWORD len = GetLogicalDriveStringsW(_countof(drives), drives);
    if (!len || len > _countof(drives))
        return nt;

    for (wchar_t* d = drives; *d; d += wcslen(d) + 1)
    {
        wchar_t letter[3] = { d[0], L':', 0 };
        wchar_t target[MAX_PATH] = {};

        if (!QueryDosDeviceW(letter, target, MAX_PATH))
            continue;

        size_t tl = wcslen(target);
        if (nt.size() > tl && _wcsnicmp(nt.c_str(), target, tl) == 0 && nt[tl] == L'\\')
            return std::wstring(letter) + nt.substr(tl);
    }
    return nt;
}

static bool ParseHeaders(const uint8_t* buf, size_t len, PeInfo& out, bool raw_layout)
{
    if (len < sizeof(IMAGE_DOS_HEADER))
        return false;

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > len)
        return false;

    auto nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buf + dos->e_lfanew);
    if (nt32->Signature != IMAGE_NT_SIGNATURE)
        return false;

    WORD magic = nt32->OptionalHeader.Magic;
    const IMAGE_DATA_DIRECTORY* dirs = nullptr;
    DWORD numdirs = 0;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        out.pe64 = false;
        out.preferred_base   = nt32->OptionalHeader.ImageBase;
        out.size_of_image    = nt32->OptionalHeader.SizeOfImage;
        out.size_of_headers  = nt32->OptionalHeader.SizeOfHeaders;
        out.entry_rva        = nt32->OptionalHeader.AddressOfEntryPoint;
        dirs                 = nt32->OptionalHeader.DataDirectory;
        numdirs              = nt32->OptionalHeader.NumberOfRvaAndSizes;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > len)
            return false;

        auto nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf + dos->e_lfanew);
        out.pe64 = true;
        out.preferred_base   = nt64->OptionalHeader.ImageBase;
        out.size_of_image    = nt64->OptionalHeader.SizeOfImage;
        out.size_of_headers  = nt64->OptionalHeader.SizeOfHeaders;
        out.entry_rva        = nt64->OptionalHeader.AddressOfEntryPoint;
        dirs                 = nt64->OptionalHeader.DataDirectory;
        numdirs              = nt64->OptionalHeader.NumberOfRvaAndSizes;
    }
    else
    {
        return false;
    }

    if (dirs && numdirs > IMAGE_DIRECTORY_ENTRY_BASERELOC)
    {
        out.reloc_rva  = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        out.reloc_size = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }

    WORD nsec = nt32->FileHeader.NumberOfSections;
    if (nsec == 0 || nsec > 96)
        return false;

    size_t secoff = dos->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)
                  + nt32->FileHeader.SizeOfOptionalHeader;

    if (secoff + nsec * sizeof(IMAGE_SECTION_HEADER) > len)
        return false;

    auto sh = reinterpret_cast<const IMAGE_SECTION_HEADER*>(buf + secoff);
    for (WORD i = 0; i < nsec; ++i)
    {
        Section s = {};
        memcpy(s.name, sh[i].Name, 8);
        s.name[8]  = 0;
        s.rva      = sh[i].VirtualAddress;
        s.vsize    = sh[i].Misc.VirtualSize;
        s.rawptr   = sh[i].PointerToRawData;
        s.rawsize  = sh[i].SizeOfRawData;
        s.chars    = sh[i].Characteristics;

        if (raw_layout && ((size_t)s.rawptr + s.rawsize > len))
            s.rawsize = (s.rawptr < len) ? (uint32_t)(len - s.rawptr) : 0;

        out.sections.push_back(s);
    }

    out.valid = true;
    return true;
}

static void LoadDiskImage(const std::wstring& path, uint64_t proc_start, DiskLoad& out)
{
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE)
    {
        DWORD e = GetLastError();
        out.absent = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND);
        out.denied = !out.absent;
        return;
    }

    FILETIME wt = {};
    if (GetFileTime(f, nullptr, nullptr, &wt))
    {
        out.write_time = ToU64(wt);
        if (proc_start && out.write_time > proc_start + kMtimeSlack)
            out.stale = true;
    }

    LARGE_INTEGER sz = {};
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (128ll << 20))
    {
        CloseHandle(f);
        out.denied = true;
        return;
    }

    std::vector<uint8_t> raw((size_t)sz.QuadPart);
    DWORD got = 0;
    BOOL rok = ReadFile(f, raw.data(), (DWORD)raw.size(), &got, nullptr);
    CloseHandle(f);

    if (!rok || got != raw.size())
    {
        out.denied = true;
        return;
    }

    if (!ParseHeaders(raw.data(), raw.size(), out.pe, true))
    {
        out.denied = true;
        return;
    }

    if (out.pe.size_of_image < 0x1000 || out.pe.size_of_image > (512u << 20))
    {
        out.denied = true;
        return;
    }

    out.view.assign(out.pe.size_of_image, 0);

    size_t hdr = (std::min)((size_t)out.pe.size_of_headers, raw.size());
    memcpy(out.view.data(), raw.data(), hdr);

    for (const auto& s : out.pe.sections)
    {
        if (!s.rawsize || s.rva >= out.view.size())
            continue;

        size_t n = (std::min)((size_t)s.rawsize, out.view.size() - s.rva);
        if (s.vsize && n > s.vsize)
            n = s.vsize;
        if ((size_t)s.rawptr + n > raw.size())
            continue;

        memcpy(out.view.data() + s.rva, raw.data() + s.rawptr, n);
    }

    out.ok = true;
}

static void Relocate(std::vector<uint8_t>& view, const PeInfo& info, uint64_t actual_base)
{
    int64_t delta = (int64_t)(actual_base - info.preferred_base);
    if (!delta || !info.reloc_rva || !info.reloc_size)
        return;

    size_t off = info.reloc_rva;
    size_t end = (std::min)((size_t)info.reloc_rva + info.reloc_size, view.size());

    while (off + sizeof(IMAGE_BASE_RELOCATION) <= end)
    {
        auto blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(view.data() + off);
        if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || off + blk->SizeOfBlock > end)
            break;

        DWORD count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto ent = reinterpret_cast<WORD*>(blk + 1);

        for (DWORD i = 0; i < count; ++i)
        {
            WORD type = ent[i] >> 12;
            DWORD rva = blk->VirtualAddress + (ent[i] & 0xfff);

            if (type == IMAGE_REL_BASED_DIR64 && rva + 8 <= view.size())
            {
                uint64_t v;
                memcpy(&v, view.data() + rva, 8);
                v += delta;
                memcpy(view.data() + rva, &v, 8);
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW && rva + 4 <= view.size())
            {
                uint32_t v;
                memcpy(&v, view.data() + rva, 4);
                v += (uint32_t)delta;
                memcpy(view.data() + rva, &v, 4);
            }
        }
        off += blk->SizeOfBlock;
    }
}

static bool ReadPtr(HANDLE proc, uintptr_t at, uintptr_t& out)
{
    SIZE_T rd = 0;
    return ReadProcessMemory(proc, (LPCVOID)at, &out, sizeof(out), &rd) && rd == sizeof(out);
}

static uintptr_t PebOf(HANDLE proc)
{
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG ret = 0;

    if (NtQueryInformationProcess(proc, ProcessBasicInformation, &pbi, sizeof(pbi), &ret) < 0)
        return 0;

    return (uintptr_t)pbi.PebBaseAddress;
}

static uintptr_t LdrFirstModuleBase(HANDLE proc, uintptr_t peb)
{
    uintptr_t ldr = 0;
    if (!peb || !ReadPtr(proc, peb + 0x18, ldr) || !ldr)
        return 0;

    uintptr_t first = 0;
    if (!ReadPtr(proc, ldr + 0x10, first) || !first)
        return 0;

    uintptr_t dllbase = 0;
    if (!ReadPtr(proc, first + 0x30, dllbase))
        return 0;

    return dllbase;
}

static bool ReadHeadersFromMem(HANDLE proc, uintptr_t base, PeInfo& out)
{
    std::vector<uint8_t> hdr(0x1000, 0);
    SIZE_T rd = 0;

    if (!ReadProcessMemory(proc, (LPCVOID)base, hdr.data(), hdr.size(), &rd) || rd < 0x200)
        return false;

    hdr.resize(rd);
    return ParseHeaders(hdr.data(), hdr.size(), out, false);
}

static void DiffRegion(HANDLE proc, uintptr_t addr, const uint8_t* want, size_t len, DiffStats& st)
{
    const size_t page = 0x1000;
    std::vector<uint8_t> got(want, want + len);
    std::vector<uint8_t> readable((len + page - 1) / page, 0);

    for (size_t off = 0, pi = 0; off < len; off += page, ++pi)
    {
        size_t n = (std::min)(page, len - off);
        SIZE_T rd = 0;

        if (ReadProcessMemory(proc, (LPCVOID)(addr + off), got.data() + off, n, &rd) && rd == n)
        {
            readable[pi] = 1;
            st.compared += n;
        }
    }

    size_t i = 0;
    while (i < len)
    {
        if (!readable[i / page] || got[i] == want[i])
        {
            ++i;
            continue;
        }

        size_t start = i;
        size_t last  = i;
        size_t gap   = 0;

        while (i < len && gap <= kClusterGap)
        {
            if (readable[i / page] && got[i] != want[i])
            {
                last = i;
                gap = 0;
            }
            else
            {
                ++gap;
            }
            ++i;
        }

        size_t runlen = last - start + 1;
        ++st.clusters;
        st.differing += runlen;

        if (runlen > st.largest)
            st.largest = runlen;

        if (runlen <= kHookMaxLen)
            st.hooklike += runlen;
        else
            st.bulk += runlen;
    }
}

static bool RangeHasPrivateHole(HANDLE proc, uintptr_t base, size_t size, uintptr_t& where)
{
    uintptr_t cur = base;
    uintptr_t end = base + size;

    while (cur < end)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(proc, (LPCVOID)cur, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;

        uintptr_t rb = (uintptr_t)mbi.BaseAddress;

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && rb > base)
        {
            where = rb;
            return true;
        }

        uintptr_t next = rb + mbi.RegionSize;
        if (next <= cur)
            break;
        cur = next;
    }
    return false;
}

static std::wstring MappedNameAt(HANDLE proc, uintptr_t addr)
{
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD n = GetMappedFileNameW(proc, (LPVOID)addr, buf, _countof(buf));
    if (!n)
        return L"";
    return DeviceToDos(std::wstring(buf, n));
}

static const Section* SectionForRva(const PeInfo& pe, uint32_t rva)
{
    for (const auto& s : pe.sections)
    {
        uint32_t span = s.vsize ? s.vsize : s.rawsize;
        if (rva >= s.rva && rva < s.rva + span)
            return &s;
    }
    return nullptr;
}

static bool Inspect(DWORD pid, HANDLE proc, Finding& f)
{
    wchar_t pathbuf[MAX_PATH * 2] = {};
    DWORD plen = _countof(pathbuf);

    if (!QueryFullProcessImageNameW(proc, 0, pathbuf, &plen))
        return false;

    f.pid = pid;
    f.path.assign(pathbuf, plen);

    FILETIME ct = {}, et = {}, kt = {}, ut = {};
    uint64_t started = 0;
    if (GetProcessTimes(proc, &ct, &et, &kt, &ut))
        started = ToU64(ct);

    uintptr_t peb = PebOf(proc);
    uintptr_t base = 0;

    if (!peb || !ReadPtr(proc, peb + 0x10, base) || !base)
        return false;

    f.base = base;

    uintptr_t ldrbase = LdrFirstModuleBase(proc, peb);
    if (ldrbase && ldrbase != base)
    {
        f.addf(Family::LoaderState, Tier::Moderate,
               L"loader list head reports base %p, PEB reports %p",
               (void*)ldrbase, (void*)base);
    }

    MEMORY_BASIC_INFORMATION bmbi = {};
    bool have_bmbi = VirtualQueryEx(proc, (LPCVOID)base, &bmbi, sizeof(bmbi)) == sizeof(bmbi);

    if (have_bmbi && bmbi.State == MEM_COMMIT && bmbi.Type == MEM_PRIVATE)
    {
        f.add(Family::BaseBacking, Tier::Strong,
              L"image base is private committed memory, not a mapped image");
    }
    else if (have_bmbi && bmbi.State == MEM_COMMIT && bmbi.Type == MEM_MAPPED)
    {
        f.add(Family::BaseBacking, Tier::Strong,
              L"image base is a data mapping rather than an image mapping");
    }

    if (have_bmbi && bmbi.Type == MEM_IMAGE)
    {
        std::wstring mapped = MappedNameAt(proc, base);
        if (mapped.empty())
        {
            f.add(Family::FileIdentity, Tier::Moderate,
                  L"image mapping at base has no resolvable backing file");
        }
        else if (LowerOf(mapped) != LowerOf(f.path))
        {
            f.addf(Family::FileIdentity, Tier::Strong,
                   L"base maps %s but process path is %s",
                   mapped.c_str(), f.path.c_str());
        }
    }

    PeInfo mem;
    if (!ReadHeadersFromMem(proc, base, mem))
    {
        f.add(Family::HeaderAgreement, Tier::Moderate,
              L"no parsable PE header at the image base");
        mem.valid = false;
    }
    else
    {
        f.mem_entry_rva = mem.entry_rva;

        uintptr_t hole = 0;
        if (RangeHasPrivateHole(proc, base, mem.size_of_image, hole))
        {
            f.addf(Family::BaseBacking, Tier::Strong,
                   L"private committed region at %p inside the image range",
                   (void*)hole);
        }

        if (mem.entry_rva == 0 || mem.entry_rva >= mem.size_of_image)
        {
            f.add(Family::EntryLocality, Tier::Moderate,
                  L"entry point RVA falls outside the image");
        }
        else
        {
            MEMORY_BASIC_INFORMATION emb = {};
            if (VirtualQueryEx(proc, (LPCVOID)(base + mem.entry_rva), &emb, sizeof(emb)) == sizeof(emb))
            {
                if (emb.State == MEM_COMMIT && emb.Type == MEM_PRIVATE)
                {
                    f.add(Family::EntryLocality, Tier::Strong,
                          L"entry point sits in private committed memory");
                }
                else if (emb.State == MEM_COMMIT && emb.Protect == PAGE_EXECUTE_READWRITE)
                {
                    f.add(Family::EntryLocality, Tier::Moderate,
                          L"entry point page is RWX");
                }
            }

            const Section* es = SectionForRva(mem, mem.entry_rva);
            if (!es)
            {
                f.add(Family::EntryLocality, Tier::Moderate,
                      L"entry point does not land in any declared section");
            }
            else if (!(es->chars & IMAGE_SCN_MEM_EXECUTE))
            {
                f.addf(Family::EntryLocality, Tier::Moderate,
                       L"entry point lands in non-executable section %hs", es->name);
            }
        }
    }

    DiskLoad disk;
    LoadDiskImage(f.path, started, disk);

    if (disk.absent)
    {
        f.add(Family::FileIdentity, Tier::Weak,
              L"backing file no longer exists on disk");
    }
    if (disk.denied)
    {
        f.note(L"backing file unreadable, disk comparison skipped");
    }
    if (disk.stale)
    {
        f.note(L"backing file modified after process start, disk comparison skipped");
    }

    if (!disk.ok || disk.stale || !mem.valid)
        return false;

    f.disk_valid = true;
    f.disk_entry_rva = disk.pe.entry_rva;

    if (disk.pe.entry_rva != mem.entry_rva)
    {
        f.addf(Family::HeaderAgreement, Tier::Strong,
               L"entry RVA disk 0x%08X vs memory 0x%08X",
               disk.pe.entry_rva, mem.entry_rva);
    }

    if (disk.pe.size_of_image != mem.size_of_image)
    {
        f.add(Family::HeaderAgreement, Tier::Moderate,
              L"SizeOfImage differs from the file");
    }

    if (disk.pe.sections.size() != mem.sections.size())
    {
        f.add(Family::HeaderAgreement, Tier::Moderate,
              L"section count differs from the file");
    }
    else
    {
        for (size_t i = 0; i < disk.pe.sections.size(); ++i)
        {
            if (disk.pe.sections[i].rva != mem.sections[i].rva ||
                strcmp(disk.pe.sections[i].name, mem.sections[i].name) != 0)
            {
                f.add(Family::HeaderAgreement, Tier::Moderate,
                      L"section table layout differs from the file");
                break;
            }
        }
    }

    Relocate(disk.view, disk.pe, base);

    DiffStats worst = {};
    const Section* worst_sec = nullptr;

    for (const auto& s : disk.pe.sections)
    {
        if (!(s.chars & IMAGE_SCN_MEM_EXECUTE))
            continue;
        if (s.chars & IMAGE_SCN_MEM_WRITE)
            continue;
        if (!s.rawsize || s.rva >= disk.view.size())
            continue;

        size_t span = s.vsize ? s.vsize : s.rawsize;
        size_t len  = (std::min)(span, disk.view.size() - s.rva);
        if (len < 0x200)
            continue;

        DiffStats st = {};
        DiffRegion(proc, base + s.rva, disk.view.data() + s.rva, len, st);

        if (st.bulk > worst.bulk)
        {
            worst = st;
            worst_sec = &s;
        }
    }

    if (worst_sec && worst.compared)
    {
        double ratio = (double)worst.bulk / (double)worst.compared;

        if (worst.bulk >= kBulkStrong || worst.largest >= kRunStrong || ratio > kRatioStrong)
        {
            f.addf(Family::CodeContent, Tier::Strong,
                   L"%hs diverges from the file: %zu bulk bytes, longest run %zu, %zu clusters",
                   worst_sec->name, worst.bulk, worst.largest, worst.clusters);
        }
        else if (worst.bulk >= kBulkModerate)
        {
            f.addf(Family::CodeContent, Tier::Moderate,
                   L"%hs diverges from the file: %zu bulk bytes in %zu clusters",
                   worst_sec->name, worst.bulk, worst.clusters);
        }
        else if (worst.hooklike)
        {
            wchar_t buf[160];
            _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                         L"%hs has %zu hook-shaped bytes across %zu clusters",
                         worst_sec->name, worst.hooklike, worst.clusters);
            f.note(buf);
        }
    }

    if (mem.entry_rva && mem.entry_rva + 32 <= disk.view.size() &&
        mem.entry_rva == disk.pe.entry_rva)
    {
        DiffStats est = {};
        DiffRegion(proc, base + mem.entry_rva, disk.view.data() + mem.entry_rva, 32, est);

        if (est.compared && est.differing)
        {
            f.addf(Family::CodeContent, Tier::Strong,
                   L"%zu of the first 32 bytes at the entry point differ from the file",
                   est.differing);
        }
    }

    return true;
}

static bool Verdict(const Finding& f, Family& primary)
{
    for (const auto& e : f.evidence)
    {
        if (e.tier != Tier::Strong)
            continue;

        for (const auto& o : f.evidence)
        {
            if (o.family != e.family && o.tier != Tier::Weak)
            {
                primary = e.family;
                return true;
            }
        }
    }
    return false;
}

static const wchar_t* FamilyName(Family f)
{
    switch (f)
    {
    case Family::BaseBacking:     return L"base-backing";
    case Family::FileIdentity:    return L"file-identity";
    case Family::HeaderAgreement: return L"header-agreement";
    case Family::CodeContent:     return L"code-content";
    case Family::EntryLocality:   return L"entry-locality";
    case Family::LoaderState:     return L"loader-state";
    }
    return L"?";
}

static const wchar_t* TierName(Tier t)
{
    switch (t)
    {
    case Tier::Strong:   return L"STRONG";
    case Tier::Moderate: return L"MODERATE";
    case Tier::Weak:     return L"WEAK";
    }
    return L"?";
}

static void Report(const Finding& f, Family primary)
{
    wprintf(L"\n[%u] %s\n", f.pid, f.path.c_str());
    wprintf(L"    base %p  entry disk=0x%08X mem=0x%08X  primary=%s\n",
            (void*)f.base, f.disk_entry_rva, f.mem_entry_rva, FamilyName(primary));

    for (const auto& e : f.evidence)
        wprintf(L"    %-8s [%s] %s\n", TierName(e.tier), FamilyName(e.family), e.text.c_str());

    for (const auto& c : f.coverage)
        wprintf(L"    ....     %s\n", c.c_str());
}

int wmain(int argc, wchar_t** argv)
{
    bool verbose = (argc > 1 && _wcsicmp(argv[1], L"-v") == 0);

    if (!EnableDebugPriv())
        wprintf(L"[!] no SeDebugPrivilege, coverage will be incomplete\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        wprintf(L"snapshot failed: %lu\n", GetLastError());
        return 1;
    }

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    int flagged = 0, looked = 0, skipped = 0;

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (pe.th32ProcessID <= 4)
                continue;

            HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                      FALSE, pe.th32ProcessID);
            if (!proc)
            {
                ++skipped;
                continue;
            }

            ++looked;

            Finding f;
            Inspect(pe.th32ProcessID, proc, f);

            Family primary = Family::BaseBacking;
            if (Verdict(f, primary))
            {
                ++flagged;
                Report(f, primary);
            }
            else if (verbose && (!f.evidence.empty() || !f.coverage.empty()))
            {
                Report(f, primary);
            }

            CloseHandle(proc);

        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

    wprintf(L"\n%d inspected, %d unreachable, %d flagged\n", looked, skipped, flagged);
    return 0;
}
