#include <windows.h>

typedef struct _VEH_ENTRY
{
    LIST_ENTRY list;
    ULONG_PTR* refcnt;
    DWORD unk;
    DWORD pad;
    PVOID enc_handler;
} VEH_ENTRY, * PVEH_ENTRY;

typedef PVOID(WINAPI* fnRtlEncodePointer)(PVOID);
typedef PVOID(WINAPI* fnRtlDecodePointer)(PVOID);
typedef VOID(*fnLdrProtectMrdata)(BOOL);

static ULONG_PTR g_list = 0;
static ULONG_PTR g_rtlp = 0;
static ULONG_PTR g_prot = 0;

__forceinline BOOL chk
(
    PVOID p,
    SIZE_T sz
)
{
    __try
    {
        volatile char c = *(char*)p;
        if (sz > 1) c = *((char*)p + sz - 1);
        return 1;
    }
    __except (1)
    {
        return 0;
    }
}

VOID dbg
(
    const CHAR* s
)
{
    HANDLE h;
    DWORD w;

    h = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteConsoleA(h, s, lstrlenA(s), &w, 0);
}

BOOL find_prot
(
    VOID
)
{
    BYTE* code;
    int i, rel;
    ULONG_PTR tgt;
    BYTE* fn;

    if (!g_rtlp) return 0;

    dbg("[*]  scanning for LdrProtectMrdata...\n");

    code = (BYTE*)g_rtlp;

    for (i = 0; i < 0x400; i++)
    {
        if (!chk(&code[i], 5)) continue;
        if (code[i] != 0xE8) continue;
        if (!chk(&code[i + 1], 4)) continue;

        rel = *(int*)&code[i + 1];
        tgt = (ULONG_PTR)(&code[i + 5]) + rel;

        if (tgt < 0x10000 || tgt > 0x7FFFFFFFFFFF) continue;
        if (!chk((PVOID)tgt, 15)) continue;

        fn = (BYTE*)tgt;

        if (fn[0] == 0x48 && fn[1] == 0x89 && fn[2] == 0x5C && fn[3] == 0x24 && fn[4] == 0x08 &&
            fn[5] == 0x48 && fn[6] == 0x89 && fn[7] == 0x74 && fn[8] == 0x24 && fn[9] == 0x10 &&
            fn[10] == 0x57 && fn[11] == 0x48 && fn[12] == 0x83 && fn[13] == 0xEC && fn[14] == 0x20)
        {
            g_prot = tgt;
            dbg("[+]  found!\n");
            return 1;
        }
    }

    dbg("[-]  not found\n");
    return 0;
}

BOOL find_list
(
    VOID
)
{
    HMODULE ntdll;
    ULONG_PTR rtladd;
    BYTE* code;
    int rel;
    ULONG_PTR rtlp;
    BYTE* fn;
    int i, rel2;
    ULONG_PTR tgt;

    dbg("\n===  GhostVEH  ===\n\n");

    ntdll = GetModuleHandleA("ntdll");
    if (!ntdll) goto fail;

    rtladd = (ULONG_PTR)GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler");
    if (!rtladd) goto fail;

    dbg("[*]  locating internals...\n");

    code = (BYTE*)rtladd;

    if (code[0] != 0x41 && code[0] != 0x45) goto fail;
    if (code[3] != 0xE9) goto fail;

    rel = *(int*)&code[4];
    rtlp = (ULONG_PTR)(&code[8]) + rel;

    g_rtlp = rtlp;

    dbg("[+]  RtlpAddVectoredHandler\n");

    fn = (BYTE*)rtlp;

    for (i = 0; i < 0x400; i++)
    {
        if (fn[i] != 0x48 || fn[i + 1] != 0x8D || fn[i + 2] != 0x3D) continue;

        rel2 = *(int*)&fn[i + 3];
        tgt = (ULONG_PTR)(&fn[i + 7]) + rel2;

        if (fn[i + 7] == 0x48 && fn[i + 8] == 0x8D && fn[i + 9] == 0x7F && fn[i + 10] == 0x08)
        {
            g_list = tgt;
            dbg("[+]  LdrpVectorHandlerList\n");
            if (!find_prot()) goto fail;
            dbg("\n");
            return 1;
        }
    }

fail:
    dbg("[-]  failed to locate\n");
    return 0;
}

LONG CALLBACK veh_handler
(
    EXCEPTION_POINTERS* ep
)
{
    dbg("[!]  stealth veh triggered\n");
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL add_veh
(
    PVECTORED_EXCEPTION_HANDLER h,
    BOOL first
)
{
    HMODULE ntdll;
    fnRtlEncodePointer enc;
    fnLdrProtectMrdata prot;
    PVEH_ENTRY ent;
    PVOID* base;
    PSRWLOCK lock;
    PLIST_ENTRY head;

    if (!g_list || !g_prot) return 0;

    dbg("[*]  installing GhostVEH...\n");

    ntdll = GetModuleHandleA("ntdll");
    enc = (fnRtlEncodePointer)GetProcAddress(ntdll, "RtlEncodePointer");
    if (!enc) return 0;

    prot = (fnLdrProtectMrdata)g_prot;

    ent = (PVEH_ENTRY)HeapAlloc(GetProcessHeap(), 8, sizeof(VEH_ENTRY));
    if (!ent) return 0;

    ent->refcnt = (ULONG_PTR*)HeapAlloc(GetProcessHeap(), 8, sizeof(ULONG_PTR));
    if (!ent->refcnt)
    {
        HeapFree(GetProcessHeap(), 0, ent);
        return 0;
    }

    *ent->refcnt = 1;
    ent->unk = 0;
    ent->pad = 0;
    ent->enc_handler = enc(h);

    base = (PVOID*)g_list;
    lock = (PSRWLOCK)&base[0];
    head = (PLIST_ENTRY)&base[1];

    if (!head->Flink || !head->Blink) goto cleanup;

    dbg("    unlocking .mrdata\n");
    prot(0);
    AcquireSRWLockExclusive(lock);

    if (first)
    {
        ent->list.Flink = head->Flink;
        ent->list.Blink = head;
        head->Flink->Blink = &ent->list;
        head->Flink = &ent->list;
    }
    else
    {
        ent->list.Flink = head;
        ent->list.Blink = head->Blink;
        head->Blink->Flink = &ent->list;
        head->Blink = &ent->list;
    }

    ReleaseSRWLockExclusive(lock);
    dbg("    locking .mrdata\n");
    prot(1);

    dbg("[+]  handler installed\n\n");
    return 1;

cleanup:
    HeapFree(GetProcessHeap(), 0, ent->refcnt);
    HeapFree(GetProcessHeap(), 0, ent);
    return 0;
}

VOID enum_veh
(
    VOID
)
{
    HMODULE ntdll;
    fnRtlDecodePointer dec;
    PVOID* base;
    PLIST_ENTRY head;
    PLIST_ENTRY cur;
    int idx;
    PVEH_ENTRY ent;
    PVOID decoded;
    CHAR buf[64];

    if (!g_list) return;

    ntdll = GetModuleHandleA("ntdll");
    dec = (fnRtlDecodePointer)GetProcAddress(ntdll, "RtlDecodePointer");

    base = (PVOID*)g_list;
    head = (PLIST_ENTRY)&base[1];

    dbg("---  veh chain  ---\n");

    if (head->Flink == head)
    {
        dbg("    empty\n");
        dbg("---  end  ---\n\n");
        return;
    }

    cur = head->Flink;
    idx = 0;

    while (cur != head && idx < 100)
    {
        if ((ULONG_PTR)cur < 0x10000) break;

        ent = CONTAINING_RECORD(cur, VEH_ENTRY, list);

        if (dec && ent->enc_handler)
        {
            decoded = dec(ent->enc_handler);
            wsprintfA(buf, "    [%d]  handler @ %p\n", idx, decoded);
            dbg(buf);
        }

        cur = cur->Flink;
        idx++;
    }

    dbg("---  end  ---\n\n");
}

LONG CALLBACK normal_veh
(
    EXCEPTION_POINTERS* p
)
{
    dbg("[!]  normal veh triggered\n");
    return EXCEPTION_CONTINUE_SEARCH;
}

int main
(
    VOID
)
{
    int x, y;

    if (!find_list()) return 1;

    enum_veh();

    dbg("[*]  adding normal veh via api...\n");
    AddVectoredExceptionHandler(1, normal_veh);
    dbg("[+]  normal veh added\n\n");

    enum_veh();

    if (add_veh(veh_handler, 1))
    {
        enum_veh();

        dbg("[*]  triggering exception...\n");
        __try
        {
            x = 0;
            y = 5 / x;
            (void)y;
        }
        __except (1)
        {
            dbg("[+]  exception handled\n");
        }
    }

    dbg("\n");
    Sleep(2000);
    return 0;
}