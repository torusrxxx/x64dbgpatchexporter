/******************************************************************************
patch exporter plugin
Copyright(c) 2016, torusrxxx
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met :

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and / or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#include <Windows.h>
#include "_plugins.h"
#include "capstone_wrapper.h"
#include "Commdlg.h"
#include "utf8.h"
#include "resource.h"
#include <ctime>
#include <memory>
#include <sstream>
#include <iomanip>
#include <map>
#include <Psapi.h>

int pluginHandle = 0;
HWND hwndDlg;
int hMenu;
HMODULE hModule;
wchar_t templatename[512];
wchar_t exportedname[512];

bool command(int argc, char* argv[]);
void menu(CBTYPE cbType, void* arg1);

std::string LoadUTF8String(int index)
{
    wchar_t p[512];
    int len;
    memset(p, 0, sizeof(p));
    if((len = LoadString(hModule, index, (LPWSTR)p, 512)) == 0)
    {
        return "";
    }
    else
    {
        std::wstring utf16line(p, len);
        std::string utf8line;
        utf8::utf16to8(utf16line.begin(), utf16line.end(), std::back_inserter(utf8line));
        return utf8line;
    }
}

std::wstring LoadWideString(int index)
{
    wchar_t p[512];
    int len;
    memset(p, 0, sizeof(p));
    if((len = LoadString(hModule, index, (LPWSTR)p, 512)) == 0)
    {
        return L"";
    }
    else
    {
        std::wstring utf16line(p, len);
        return utf16line;
    }
}

std::string Utf16ToUtf8(const std::wstring & a)
{
    std::string utf8;
    utf8::utf16to8(a.begin(), a.end(), std::back_inserter(utf8));
    return utf8;
}

std::wstring Utf8ToUtf16(const std::string & a)
{
    std::wstring utf16;
    utf8::utf8to16(a.begin(), a.end(), std::back_inserter(utf16));
    return utf16;
}

void ReplaceWString(std::wstring & str, const std::wstring & find, const std::wstring & replace)
{
    for(auto i = str.find(find); i != std::wstring::npos ;i = str.find(find))
    {
        str.replace(i, find.size(), replace);
    }
}

std::wstring LoadFile(const wchar_t* filename)
{
    HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
        return L"";
    ULARGE_INTEGER size;
    DWORD BOM = 0;
    size.LowPart = GetFileSize(hFile, &size.HighPart);
    DWORD bytesread;
    ReadFile(hFile, &BOM, 3, &bytesread, NULL);
    if((BOM & 0xffff) == 0xfeff) //UTF-16
    {
        std::wstring result;
        result.resize(size.QuadPart / 2 - 1);
        SetFilePointer(hFile, 2, NULL, FILE_BEGIN);
        ReadFile(hFile, (LPVOID)result.data(), size.QuadPart - 2, &bytesread, NULL);
        CloseHandle(hFile);
        return result;
    }
    else if(BOM == 0xbfbbef) //UTF-8
    {
        std::string utf8line;
        utf8line.resize(size.QuadPart - 3);
        SetFilePointer(hFile, 3, NULL, FILE_BEGIN);
        ReadFile(hFile, (LPVOID)utf8line.data(), size.QuadPart - 3, &bytesread, NULL);
        CloseHandle(hFile);
        std::wstring result;
        utf8::utf8to16(utf8line.begin(), utf8line.end(), std::back_inserter(result));
        return result;
    }
    else //ASCII
    {
        std::string ascii;
        ascii.resize(size.QuadPart);
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        ReadFile(hFile, (LPVOID)ascii.data(), size.QuadPart, &bytesread, NULL);
        CloseHandle(hFile);
        std::wstring result;
        result.resize(size.QuadPart);
        MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, ascii.data(), ascii.size(), (LPWSTR)result.data(), result.size());
        return result;
    }
}

bool SaveFile(const wchar_t* filename, const std::wstring & text)
{
    HANDLE hFile = CreateFile(filename, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
        return false;
    unsigned short BOM = 0xfeff;
    DWORD written = 0;
    WriteFile(hFile, &BOM, 2, &written, NULL);
    WriteFile(hFile, text.c_str(), text.size() * sizeof(wchar_t), &written, NULL);
    CloseHandle(hFile);
    return true;
}

int APIENTRY DllMain(HMODULE hModule1, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if(ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        hModule = hModule1;
        DisableThreadLibraryCalls(hModule1);
    }
    return 1;
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = 3;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, LoadUTF8String(IDS_PLUGNAME).c_str());
    pluginHandle = initStruct->pluginHandle;
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    _plugin_menuaddentry(hMenu, 1, LoadUTF8String(IDS_PLUGMENUENTRY).c_str());
    _plugin_menuaddentry(hMenu, 2, LoadUTF8String(IDS_PLUGMENUENTRY2).c_str());
    _plugin_menuaddentry(hMenu, 3, LoadUTF8String(IDS_PLUGMENUENTRYABOUT).c_str());
    _plugin_menuaddentry(setupStruct->hMenuDisasm, 4, LoadUTF8String(IDS_COPYASM).c_str());
    _plugin_registercallback(pluginHandle, CB_MENUENTRY, menu);
    _plugin_registercommand(pluginHandle, "ExportPatch", command, true);
    _plugin_registercommand(pluginHandle, "ExportPatchWithLastTemplate", command, true);
}

bool command(int argc, char* argv[])
{
    if(argc != 1)
        return false;
    PLUG_CB_MENUENTRY arg1;
    arg1.hEntry = 1;
    if(_stricmp(argv[0], "ExportPatch") == 0)
        arg1.hEntry = 1;
    else if(_stricmp(argv[0], "ExportPatchWithLastTemplate") == 0)
        arg1.hEntry = 2;
    menu(CB_MENUENTRY, &arg1);
    return true;
}

std::wstring getTemplateFilter(const std::wstring & templateContent)
{
    size_t idx_template = templateContent.find(L"$TEMPLATE_FILEFILTER:");
    std::wstring line;
    if(idx_template != std::wstring::npos)
    {
        idx_template += wcslen(L"$TEMPLATE_FILEFILTER:");
        size_t EOL = templateContent.find(L"\n", idx_template);
        if(EOL == std::wstring::npos)
            EOL = templateContent.size() - idx_template - 1;
        if(templateContent.at(EOL - 1) == L'\r')
            EOL--;
        if(EOL < idx_template)
            EOL = idx_template;
        line = templateContent.substr(idx_template, EOL - idx_template);
    }
    else
    {
        line = LoadWideString(IDS_FILTER);
    }
    for(size_t i = 0; i < line.size(); i++)
        if(line[i] == L'|')
            line[i] = L'\0';
    line.push_back(L'\0');
    return line;
}

template<class T> std::wstring printInto(T text)
{
    std::wstringstream stream;
    stream << text;
    return stream.str();
}

std::wstring printByte(unsigned char b)
{
    wchar_t text[4];
    swprintf_s(text, 4, L"%.2X", b);
    return std::wstring(text);
}

std::wstring printHex(duint p)
{
#ifdef _WIN64
    wchar_t text[18];
    swprintf_s(text, L"%.16X", p);
#else //x86
    wchar_t text[10];
    swprintf_s(text, L"%.8X", p);
#endif //_WIN64
    return std::wstring(text);
}

std::wstring printTime()
{
    std::time_t t = std::time(nullptr);
    std::wstringstream result;
    result << std::put_time(std::localtime(&t), L"%Y-%m-%d %H:%M:%S");
    return result.str();
}

void printFileName()
{
    std::wstring logtext = LoadWideString(IDS_LOGTEXT1) + L"\r\n";
    ReplaceWString(logtext, L"%template", templatename);
    ReplaceWString(logtext, L"%file", exportedname);
    std::string outputtext;
    utf8::utf16to8(logtext.begin(), logtext.end(), std::back_inserter(outputtext));
    _plugin_logputs(outputtext.c_str());
}

std::unique_ptr<DBGPATCHINFO> EnumPatches(size_t & buffersize, size_t & numPatches)
{
    if(!DbgIsDebugging())
        return nullptr;
    DbgFunctions()->PatchEnum(0, &buffersize);
    if(buffersize % sizeof(DBGPATCHINFO) != 0)
    {
        MessageBox(hwndDlg, LoadWideString(IDS_OUTDATED).c_str(), LoadWideString(IDS_PLUGNAME).c_str(), MB_ICONERROR);
        return nullptr;
    }
    if(buffersize == 0)
    {
        MessageBox(hwndDlg, LoadWideString(IDS_EMPTYPATCH).c_str(), LoadWideString(IDS_PLUGNAME).c_str(), MB_ICONERROR);
        return nullptr;
    }
    numPatches = buffersize / sizeof(DBGPATCHINFO);
    std::unique_ptr<DBGPATCHINFO> patchList(new DBGPATCHINFO[numPatches]);
    memset(patchList.get(), 0, numPatches * sizeof(DBGPATCHINFO));
    DbgFunctions()->PatchEnum(patchList.get(), &buffersize);
    std::qsort(patchList.get(), numPatches, sizeof(DBGPATCHINFO), [](const void* a, const void* b)
    {
        const DBGPATCHINFO* A = (const DBGPATCHINFO*)a;
        const DBGPATCHINFO* B = (const DBGPATCHINFO*)b;
        if(A->addr > B->addr)
            return 1;
        else if(A->addr < B->addr)
            return -1;
        else
            return 0;
    });
    return patchList;
}

void ExportPatch(const std::wstring & templateContent, DBGPATCHINFO* patchList, size_t numPatches)
{
    printFileName();
    size_t idx_template = templateContent.find(L"$TEMPLATE_PREFIX:");
    size_t idx_module = templateContent.find(L"$MODULE_PREFIX:");
    size_t idx_patch = templateContent.find(L"$PATCH:");
    size_t idx_module_suffix = templateContent.find(L"$MODULE_SUFFIX:");
    size_t idx_template_suffix = templateContent.find(L"$TEMPLATE_SUFFIX:");
    if(idx_template == std::wstring::npos || idx_module == std::wstring::npos || idx_patch == std::wstring::npos || idx_module_suffix == std::wstring::npos || idx_template_suffix == std::wstring::npos)
    {
        MessageBox(hwndDlg, LoadWideString(IDS_INVALID_PATCH).c_str(), LoadWideString(IDS_PLUGNAME).c_str(), MB_ICONERROR);
        return;
    }

    HANDLE hProcess;
    wchar_t ProcessName[1024];
    memset(ProcessName, 0, sizeof(ProcessName));
    hProcess = (HANDLE)DbgValFromString("$hProcess");
    if(GetModuleBaseNameW(hProcess, 0, ProcessName, sizeof(ProcessName) / sizeof(wchar_t)) == 0)
    {
        MessageBox(hwndDlg, LoadWideString(IDS_HPROCESSFAIL).c_str(), LoadWideString(IDS_PLUGNAME).c_str(), MB_ICONERROR);
        return;
    }
    std::wstring text = templateContent.substr(idx_template + int(wcslen(L"$TEMPLATE_PREFIX:")), idx_module - idx_template - int(wcslen(L"$TEMPLATE_PREFIX:")));
    std::wstring modulePrefix = templateContent.substr(idx_module + int(wcslen(L"$MODULE_PREFIX:")), idx_patch - idx_module - int(wcslen(L"$MODULE_PREFIX:")));
    std::wstring patchText = templateContent.substr(idx_patch + int(wcslen(L"$PATCH:")), idx_module_suffix - idx_patch - int(wcslen(L"$PATCH:")));
    std::wstring moduleSuffix = templateContent.substr(idx_module_suffix + int(wcslen(L"$MODULE_SUFFIX:")), idx_template_suffix - idx_module_suffix - int(wcslen(L"$MODULE_SUFFIX:")));
    std::wstring templateSuffix = templateContent.substr(idx_template_suffix + int(wcslen(L"$TEMPLATE_SUFFIX:")));
    std::vector<std::pair<std::wstring, unsigned int>> modules;
    std::string firstModuleUTF8(patchList[0].mod);
    std::wstring firstModuleUTF16;
    unsigned int currentModuleCount = 1;
    utf8::utf8to16(firstModuleUTF8.begin(), firstModuleUTF8.end(), std::back_inserter(firstModuleUTF16));
    modules.push_back(std::make_pair(firstModuleUTF16, 1));
    for(duint i = 1; i < numPatches; i++)
    {
        firstModuleUTF8 = std::string(patchList[i].mod);
        firstModuleUTF16.clear();
        utf8::utf8to16(firstModuleUTF8.begin(), firstModuleUTF8.end(), std::back_inserter(firstModuleUTF16));
        if(firstModuleUTF16.compare(modules.back().first) != 0)
        {
            modules.back().second = currentModuleCount;
            currentModuleCount = 1;
            modules.push_back(std::make_pair(firstModuleUTF16, 1));
        }
        else
            currentModuleCount++;
    }
    modules.back().second = currentModuleCount;
    currentModuleCount = 0;
    duint patches = 0;
    duint modbase;
    unsigned int currentModule = 0;
    std::wstring moduleText;

    for(duint i = 0; i < numPatches; i++)
    {
        if(currentModuleCount == 0)
        {
            moduleText += modulePrefix + L"\r\n";
            modbase = DbgFunctions()->ModBaseFromName(patchList[i].mod);
        }
        std::wstring patchText2(patchText);
        std::wstring newByteText(printByte(patchList[i].newbyte));
        ReplaceWString(patchText2, L"$rva", printHex(patchList[i].addr - modbase));
        ReplaceWString(patchText2, L"$newByte", newByteText);
        ReplaceWString(patchText2, L"$patchIndex", printInto(++patches));
        moduleText += patchText2 + L"\r\n";
        if(currentModuleCount == modules.at(currentModule).second - 1)
        {
            moduleText += moduleSuffix + L"\r\n";
            ReplaceWString(moduleText, L"$moduleName", modules.at(currentModule).first);
            ReplaceWString(moduleText, L"$numPatches", printInto(modules.at(currentModule).second));
            text += moduleText;
            moduleText.clear();
            currentModuleCount = 0;
            patches = 0;
            currentModule++;
        }
        else
            currentModuleCount++;
    }

    text.append(templateSuffix);
    ReplaceWString(text, L"$numPatches", printInto(numPatches));
    ReplaceWString(text, L"$exeName", std::wstring(ProcessName));
    ReplaceWString(text, L"$date", printTime());
    std::wstring compiledate;
    std::string compiledateASCII(__DATE__);
    utf8::utf8to16(compiledateASCII.begin(), compiledateASCII.end(), std::back_inserter(compiledate));
    ReplaceWString(text, L"$compiledate", compiledate);
    
    // save
    if(SaveFile(exportedname, text))
        _plugin_logputs(LoadUTF8String(IDS_SAVESUCCESS).c_str());
    else
        _plugin_logputs(LoadUTF8String(IDS_SAVEFAIL).c_str());
}

void copyAsm()
{
    SELECTIONDATA section;
    duint addr;
    unsigned char* buffer;
    std::wstring value;
    std::map<duint, std::wstring> labels;
    duint newdisp;
    wchar_t data[60];
    char label[max(MAX_LABEL_SIZE, MAX_COMMENT_SIZE)];
    HANDLE hClipboard;

    if(!GuiSelectionGet(GUI_DISASSEMBLY, &section))
        return;
    addr = section.start;
    buffer = new unsigned char[section.end - section.start + 16];
    if(!DbgMemRead(section.start, buffer, section.end - section.start + 16))
    {
        delete buffer;
        return;
    }
    if(!OpenClipboard(GuiGetWindowHandle()))
    {
        delete buffer;
        return;
    }
    if(!EmptyClipboard())
    {
        delete buffer;
        return;
    }
    Capstone::GlobalInitialize();
    addr = section.start;
    while(addr <= section.end)
    {
        Capstone c;
        c.Disassemble(addr, buffer + addr - section.start);
        if(DbgGetLabelAt(addr, SEG_DEFAULT, label))
        {
            if(label[0] != '&')
                labels[addr] = Utf8ToUtf16(label);
            else
                labels[addr] = Utf8ToUtf16(label + 1);
        }
        addr += c.Size();
        if(!c.Success())
            continue;
        for(int i = 0; i < c.OpCount(); i++)
        {
            switch(c[i].type)
            {
            case X86_OP_IMM:
                if(c[i].imm >= section.start && c[i].imm <= section.end)
                {
                    if(labels.find(c[i].imm) == labels.end())
                    {
                        swprintf_s(data, L"addr_%p", c[i].imm);
                        labels.insert(std::make_pair(c[i].imm, std::wstring(data)));
                    }
                }
                else if(DbgGetLabelAt(c[i].imm, SEG_DEFAULT, label))
                {
                    if(label[0] != '&')
                        labels.insert(std::make_pair(c[i].imm, Utf8ToUtf16(label)));
                    else
                        labels.insert(std::make_pair(c[i].imm, Utf8ToUtf16(label + 1)));
                }
                break;
            case X86_OP_MEM:
                newdisp = c[i].mem.disp;
                if(c[i].mem.base == X86_REG_RIP)
                    newdisp += addr;
                if(newdisp >= section.start && newdisp <= section.end)
                {
                    if(labels.find(newdisp) == labels.end())
                    {
                        swprintf_s(data, L"addr_%p", newdisp);
                        labels.insert(std::make_pair(newdisp, std::wstring(data)));
                    }
                }
                else if(DbgGetLabelAt(newdisp, SEG_DEFAULT, label))
                {
                    if(label[0] != '&')
                        labels.insert(std::make_pair(newdisp, Utf8ToUtf16(label)));
                    else
                        labels.insert(std::make_pair(newdisp, Utf8ToUtf16(label + 1)));
                }
                break;
            }
        }
    }
    addr = section.start;
    swprintf_s(data, L"; %p", addr);
    value += data;
    value += L"\r\n";
    while(addr <= section.end)
    {
        Capstone c;
        c.Disassemble(addr, buffer + addr - section.start);
        const auto & l = labels.find(addr);
        if(l != labels.cend())
        {
            value += l->second;
            value += L":\r\n";
        }
        if(!c.Success())
        {
            value += L"; ???";
            if(DbgGetCommentAt(addr, label))
            {
                value += L' ';
                value += Utf8ToUtf16(label);
            }
            value += L"\r\n";
            addr += c.Size();
            continue;
        }
        value += Utf8ToUtf16(c.Mnemonic());
        if(c.OpCount() > 0)
        {
            value += L' ';
            for(int i = 0; i < c.OpCount(); i++)
            {
                std::wstring value2;
                if(i != 0)
                    value += L',';
                value += L' ';
                const auto & mem = c[i].mem;
                switch(c[i].type)
                {
                case X86_OP_IMM:
					if((labels.find(c[i].imm) != labels.cend()) && (labels.at(c[i].imm)).find(L"addr_") != std::string::npos)
						value += labels.at(c[i].imm);
					else
                        value += Utf8ToUtf16(c.OperandText(i));
                    break;
                case X86_OP_MEM:
                    newdisp = mem.disp;
                    if(c[0].mem.base == X86_REG_RIP)
                        newdisp += addr + c.Size();
                    if(labels.find(newdisp) != labels.cend())
                    {
                        if(mem.base == X86_REG_RIP) //rip-relative
                            value2 = labels.at(newdisp);
                        else //normal
                        {
                            bool prependPlus = false;
                            if(mem.base)
                            {
                                value2 += Utf8ToUtf16(c.RegName(mem.base));
                                prependPlus = true;
                            }
                            if(mem.index)
                            {
                                if(prependPlus)
                                    value2 += L"+";
                                value2 += Utf8ToUtf16(c.RegName(mem.index));
                                if(mem.scale != 1)
                                {
                                    swprintf_s(data, L"*%X", mem.scale);
                                    value2 += data;
                                }
                                prependPlus = true;
                            }
                            if(mem.disp)
                            {
                                if(prependPlus)
                                    value2 += L'+';
                                value2 += labels.at(mem.disp);
                            }
                        }
                    }
                    else
                        value2 = Utf8ToUtf16(c.OperandText(i));
                    if(mem.segment != X86_REG_INVALID)
                        value += Utf8ToUtf16(c.MemSizeName(c[i].size)) + L" ptr " + Utf8ToUtf16(c.RegName(mem.segment)) + L":[" + value2 + L"]";
                    else
                        value += Utf8ToUtf16(c.MemSizeName(c[i].size)) + L" ptr [" + value2 + L"]";
                    break;
                default:
                    value += Utf8ToUtf16(c.OperandText(i));
                }
            }
        }
        if(DbgGetCommentAt(addr, label))
        {
            value += L"  ;";
            if(label[0] != 1)
                value += Utf8ToUtf16(label);
            else
                value += Utf8ToUtf16(label + 1);
        }
        addr += c.Size();
        if(addr <= section.end)
            value += L"\r\n";
    }
    Capstone::GlobalFinalize();
    delete buffer;
    hClipboard = GlobalAlloc(GMEM_MOVEABLE, value.size() * sizeof(wchar_t) + sizeof(wchar_t));
    if(hClipboard != NULL)
    {
        void* clipboardData = GlobalLock(hClipboard);
        if(clipboardData != NULL)
        {
            memcpy(clipboardData, value.c_str(), value.size() * sizeof(wchar_t));
            ((wchar_t*)clipboardData)[value.size()] = 0;
            GlobalUnlock(hClipboard);
            clipboardData = NULL;
            SetClipboardData(CF_UNICODETEXT, hClipboard);
        }
    }
    CloseClipboard();
    GuiAddStatusBarMessage(LoadUTF8String(IDS_DATACOPIED).c_str());
}

void menu(CBTYPE cbType, void* arg1)
{
    PLUG_CB_MENUENTRY* info = (PLUG_CB_MENUENTRY*)arg1;
    if(info->hEntry == 1)
    {
        // get patch information
        size_t buffersize;
        size_t numPatches;
        std::unique_ptr<DBGPATCHINFO> patchList(nullptr);
        if(!(patchList = EnumPatches(buffersize, numPatches)))
            return;
        // browse
        OPENFILENAME browse;
        memset(&browse, 0, sizeof(browse));
        browse.lStructSize = sizeof(browse);
        browse.hwndOwner = hwndDlg;
        browse.hInstance = hModule;
        wchar_t filter[512];
        memset(filter, 0, sizeof(filter));
        memset(templatename, 0, sizeof(templatename));
        memset(exportedname, 0, sizeof(exportedname));
        LoadString(hModule, IDS_FILTER, filter, 512);
        for(size_t i = 0; i < _countof(filter); i++)
        {
            if(filter[i] == '|')
                filter[i] = '\0';
        }
        browse.lpstrFilter = filter;
        browse.nFilterIndex = 1;
        browse.lpstrFile = templatename;
        browse.lpstrFileTitle = nullptr;
        browse.nMaxFile = 512;
        browse.Flags = OFN_FILEMUSTEXIST;
        std::wstring browseDialogTitle(LoadWideString(IDS_BROWSETEMPLATE));
        browse.lpstrTitle = browseDialogTitle.c_str();
        if(GetOpenFileName(&browse) == 0)
            return;
        std::wstring templateContent = LoadFile(templatename);
        std::wstring filterString = getTemplateFilter(templateContent);
        browse.lpstrFile = exportedname;
        browse.lpstrFilter = filterString.c_str();
        std::wstring saveDialogTitle(LoadWideString(IDS_PLUGMENUENTRY));
        browse.lpstrTitle = saveDialogTitle.c_str();
        browse.Flags = OFN_OVERWRITEPROMPT;
        if(GetSaveFileName(&browse) == 0)
            return;
        // export patches
        ExportPatch(templateContent, patchList.get(), numPatches);
    }
    else if(info->hEntry == 2)
    {
        // get patch information
        size_t buffersize;
        size_t numPatches;
        std::unique_ptr<DBGPATCHINFO> patchList(nullptr);
        if(!(patchList = EnumPatches(buffersize, numPatches)))
            return;
        // check last template
        if(wcslen(templatename) == 0)
        {
            MessageBox(hwndDlg, LoadWideString(IDS_NOLASTTEMPLATE).c_str(), LoadWideString(IDS_PLUGNAME).c_str(), MB_ICONERROR);
            return;
        }
        std::wstring templateContent = LoadFile(templatename);
        // browse
        OPENFILENAME browse;
        memset(&browse, 0, sizeof(browse));
        browse.lStructSize = sizeof(browse);
        browse.hwndOwner = hwndDlg;
        browse.hInstance = hModule;
        wchar_t filter[512];
        memset(filter, 0, sizeof(filter));
        memset(exportedname, 0, sizeof(exportedname));
        LoadString(hModule, IDS_FILTER, filter, 512);
        for(size_t i = 0; i < _countof(filter); i++)
        {
            if(filter[i] == '|')
                filter[i] = '\0';
        }
        std::wstring filterString = getTemplateFilter(templateContent);
        browse.lpstrFile = exportedname;
        browse.lpstrFilter = filterString.c_str();
        browse.nFilterIndex = 1;
        browse.lpstrFileTitle = nullptr;
        browse.nMaxFile = 512;
        browse.lpstrFile = exportedname;
        browse.Flags = OFN_OVERWRITEPROMPT;
        std::wstring saveDialogTitle(LoadWideString(IDS_PLUGMENUENTRY));
        browse.lpstrTitle = saveDialogTitle.c_str();
        if(GetSaveFileName(&browse) == 0)
            return;
        // export patches
        ExportPatch(templateContent, patchList.get(), numPatches);
    }
    else if(info->hEntry == 3)
    {
        std::wstring text = LoadWideString(IDS_ABOUT);
        std::wstring compiledate;
        std::string compiledateASCII(__DATE__);
        utf8::utf8to16(compiledateASCII.begin(), compiledateASCII.end(), std::back_inserter(compiledate));
        ReplaceWString(text, L"$compiledate", compiledate);
        MessageBox(hwndDlg, text.c_str(), LoadWideString(IDS_PLUGNAME).c_str(), MB_OK);
    }
    else if(info->hEntry == 4)
    {
        copyAsm();
    }
    else
    {
        __debugbreak();
    }
}
