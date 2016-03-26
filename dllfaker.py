#coding=utf-8
#
# Dll Faker
#
# platform: Python 2.x @ Windows 
#
# author:Rozbo

import os,sys,time
import pefile


def main():
    try:
        pe = pefile.PE(sys.argv[1])
        exportTable = pe.DIRECTORY_ENTRY_EXPORT.symbols
        print "[!]Find export function :[ %d ]\r\n" % len(exportTable)
        for exptab in exportTable: 
            print "%3s %10s" % (exptab.ordinal, exptab.name)
        print "\r\n[+] generating DLL Faker cpp file ..."
        
        generate(exportTable)
        
        print "\r\n[+] generating DLL Faker cpp file has finished!"
    except Exception, e:
        print e

def generate(exportTable):
    segments = r"//Generate by FakerDll.py\
\
#include \"stdafx.h\"\
#include <Windows.h>\
\
DEFINE_DLL_EXPORT_FUNC\
\
\
DEFINE_OLD_FUNC_ADDR\
\
\
#define EXTERNC extern \"C\"\
#define NAKED __declspec(naked)\
#define EXPORT __declspec(dllexport)\
#define ALCPP EXPORT NAKED\
#define ALSTD EXTERNC EXPORT NAKED void __stdcall\
#define ALCFAST EXTERNC EXPORT NAKED void __fastcall\
#define ALCDECL EXTERNC NAKED void __cdecl\
\
namespace FakerDll\
{\
    HMODULE m_hModule = NULL;\
    FARPROC WINAPI GetAddress(PCSTR pszProcName)\
    {\
        FARPROC fpAddress;\
        CHAR szProcName[16];\
        fpAddress = GetProcAddress(m_hModule, pszProcName);\
        if (fpAddress == NULL)\
        {\
            if (HIWORD(pszProcName) == 0)\
            {\
                wsprintfA(szProcName, \"%d\", pszProcName);\
                pszProcName = szProcName;\
            }\
            ExitProcess(-2);\
        }\
        return fpAddress;\
    }\
    inline VOID WINAPI InitializeAddresses()\
    {SET_OLD_FUNC_ADDR\
    }\
    inline BOOL WINAPI Load()\
    {\
        TCHAR tzPath[MAX_PATH];\
        GetSystemDirectoryW(tzPath, MAX_PATH);\
        wcscat_s(tzPath, MAX_PATH, L\"/_/_/_/DLL_FILENAME.dll\");\
        m_hModule = LoadLibrary(tzPath);\
        if (m_hModule == NULL)\
            return FALSE;\
        InitializeAddresses();\
        return (m_hModule != NULL);\
    }\
    inline VOID WINAPI Free()\
    {\
        if (m_hModule)\
            FreeLibrary(m_hModule);\
    }\
}\
using namespace FakerDll;\
\
VOID SmallEntry()\
{\
    //code ur codes here pls.\
}\
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)\
{\
    if (dwReason == DLL_PROCESS_ATTACH)\
    {\
        DisableThreadLibraryCalls(hModule);\
        if(Load())\
            SmallEntry();\
    }\
    else if (dwReason == DLL_PROCESS_DETACH)\
    {\
        Free();\
    }\
    return TRUE;\
}\
"
    filename = sys.argv[1][sys.argv[1].rindex('\\')+1:sys.argv[1].rindex('.')]
    fp = open(filename + ".cpp", "w+")
    define_dll_exp_func = ""
    for exptable in exportTable:
        define_dll_exp_func += r"#pragma comment(linker, \"/EXPORT:" + str(exptable.name) +\
                            "=_FakerDll_" + str(exptable.name) + ",@"+ str(exptable.ordinal) +"\")\n"
    segments = segments.replace('DLL_FILENAME', filename)
    segments = segments.replace("DEFINE_DLL_EXPORT_FUNC", define_dll_exp_func).replace('\\','').replace("/_/_/_/",'\\\\')
    #定义全局变量.
    pfn=""
    #初始化函数源地址
    old_funcaddr_set=""
    for exptable in exportTable:
        pfn += r"PVOID pfn"+ str(exptable.name) +";\n"
        old_funcaddr_set+=  "\n        pfn" + str(exptable.name) +"= GetAddress(\""+str(exptable.name)+ "\");"
    segments = segments.replace('DEFINE_OLD_FUNC_ADDR', pfn)
    segments = segments.replace('SET_OLD_FUNC_ADDR', old_funcaddr_set)
    fp.writelines(segments)

    forward_dll_exp_func = ""
    for exptable in exportTable:
        forward_dll_exp_func += "ALCDECL FakerDll_"+ str(exptable.name) +"(void)\n{" + \
                            "\n    __asm JMP pfn"+str(exptable.name)+";\n}\r\n"
    fp.writelines(forward_dll_exp_func)
    fp.close()

def usage():
    print "Usage:"
    print "    %s c:\\windows\\system32\\msimg32.dll" % sys.argv[0]

if __name__ == "__main__":
    if(len(sys.argv) <2):
        usage()
    else:
        main()