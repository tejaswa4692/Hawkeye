#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <time.h>

#define MAX_PROCESSES 1000
#define MAX_NAME_LEN 256
#define CHECK_INTERVAL 2000  // milliseconds
#define LOOP_THRESHOLD 3
#define OUTPUT_FILE_NAME "looping_programs.txt"

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

char output_file_path[MAX_PATH];
char drive_letter;  // Store the drive letter where program is running

// List of Windows system processes and services to ignore
const char *ignored_processes[] = {
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "winlogon.exe", "explorer.exe", "taskhost.exe",
    "taskhostw.exe", "dwm.exe", "conhost.exe", "fontdrvhost.exe", "WmiPrvSE.exe",
    "spoolsv.exe", "SearchIndexer.exe", "RuntimeBroker.exe", "sihost.exe",
    "ctfmon.exe", "TextInputHost.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
    "dllhost.exe", "audiodg.exe", "SearchProtocolHost.exe", "SearchFilterHost.exe",
    "SecurityHealthSystray.exe", "SecurityHealthService.exe", "MsMpEng.exe",
    "NisSrv.exe", "SgrmBroker.exe", "dasHost.exe", "LockApp.exe", "SystemSettings.exe",
    "ApplicationFrameHost.exe", "backgroundTaskHost.exe", "wudfhost.exe",
    "unsecapp.exe", "WUDFHost.exe", "MemCompression", "Idle", "System Idle Process",
    "csrss.exe", "LogonUI.exe", "userinit.exe", "rdpclip.exe", "rdpinput.exe",
    "smartscreen.exe", "CompPkgSrv.exe", "CompatTelRunner.exe", "TiWorker.exe",
    NULL
};

// Check if a process should be ignored
int should_ignore_process(const char *process_name) {
    // Ignore system idle process
    if (strcmp(process_name, "[System Process]") == 0 || 
        strcmp(process_name, "System") == 0) {
        return 1;
    }
    
    // Check against ignored list
    for (int i = 0; ignored_processes[i] != NULL; i++) {
        if (_stricmp(process_name, ignored_processes[i]) == 0) {
            return 1;
        }
    }
    
    return 0;
}

typedef struct {
    char name[MAX_NAME_LEN];
    int count;
    time_t last_seen;
} ProcessInfo;

ProcessInfo processes[MAX_PROCESSES];
int process_count = 0;

// Get the directory where the executable is located
void get_executable_directory(char *path, size_t size) {
    GetModuleFileName(NULL, path, size);
    
    // Find the last backslash to get directory
    char *last_slash = strrchr(path, '\\');
    if (last_slash) {
        *(last_slash + 1) = '\0';  // Keep the trailing backslash
    }
}

// Check if the drive is still accessible
int is_drive_accessible(char drive) {
    char root_path[4];
    snprintf(root_path, sizeof(root_path), "%c:\\", drive);
    
    UINT drive_type = GetDriveType(root_path);
    
    // If drive doesn't exist or is not ready, return 0
    if (drive_type == DRIVE_NO_ROOT_DIR || drive_type == DRIVE_UNKNOWN) {
        return 0;
    }
    
    // Try to access the drive
    DWORD sectors_per_cluster, bytes_per_sector, free_clusters, total_clusters;
    if (!GetDiskFreeSpace(root_path, &sectors_per_cluster, &bytes_per_sector, 
                          &free_clusters, &total_clusters)) {
        return 0;  // Drive not accessible
    }
    
    return 1;  // Drive is accessible
}

// Get all running processes using Windows API
void scan_processes(char running[][MAX_NAME_LEN], int *count) {
    HANDLE snapshot;
    PROCESSENTRY32 pe32;
    
    *count = 0;
    
    // Take a snapshot of all processes
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Error: CreateToolhelp32Snapshot failed\n");
        return;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    // Get first process
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return;
    }
    
    // Walk through all processes
    do {
        if (*count < MAX_PROCESSES) {
            char process_name[MAX_NAME_LEN];
            
            // Convert wide string to regular string if needed
            #ifdef UNICODE
            wcstombs(process_name, pe32.szExeFile, MAX_NAME_LEN);
            #else
            strncpy(process_name, pe32.szExeFile, MAX_NAME_LEN - 1);
            process_name[MAX_NAME_LEN - 1] = '\0';
            #endif
            
            // Only add if not in ignore list
            if (!should_ignore_process(process_name)) {
                strcpy(running[*count], process_name);
                (*count)++;
            }
        }
    } while (Process32Next(snapshot, &pe32));
    
    CloseHandle(snapshot);
}

// Update process tracking and detect loops
void update_tracking(char running[][MAX_NAME_LEN], int count) {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < count; i++) {
        int found = 0;
        
        // Check if process already tracked
        for (int j = 0; j < process_count; j++) {
            if (strcmp(processes[j].name, running[i]) == 0) {
                // Check if it's a new instance (appeared again quickly)
                if (current_time - processes[j].last_seen <= (CHECK_INTERVAL / 1000) + 1) {
                    processes[j].count++;
                    processes[j].last_seen = current_time;
                }
                found = 1;
                break;
            }
        }
        
        // New process
        if (!found && process_count < MAX_PROCESSES) {
            strcpy(processes[process_count].name, running[i]);
            processes[process_count].count = 1;
            processes[process_count].last_seen = current_time;
            process_count++;
        }
    }
}

// Save looping programs to file after each scan
void save_looping_programs(int scan_number) {
    FILE *fp = fopen(output_file_path, "w");
    if (!fp) {
        return;  // Silently fail if can't open file
    }
    
    time_t current_time = time(NULL);
    
    fprintf(fp, "Process Monitor - Real-time Results\n");
    fprintf(fp, "====================================\n");
    fprintf(fp, "Last updated: %s", ctime(&current_time));
    fprintf(fp, "Scan number: %d\n", scan_number);
    fprintf(fp, "Drive: %c:\n", drive_letter);
    fprintf(fp, "(Windows system processes and services are excluded)\n\n");
    
    fprintf(fp, "Programs detected running in a loop:\n");
    fprintf(fp, "-------------------------------------\n");
    
    int found_any = 0;
    for (int i = 0; i < process_count; i++) {
        if (processes[i].count >= LOOP_THRESHOLD) {
            fprintf(fp, "Program: %s (detected %d times)\n", 
                    processes[i].name, processes[i].count);
            found_any = 1;
        }
    }
    
    if (!found_any) {
        fprintf(fp, "No programs detected running in a loop yet.\n");
    }
    
    fprintf(fp, "\n\nAll tracked processes:\n");
    fprintf(fp, "----------------------\n");
    for (int i = 0; i < process_count; i++) {
        fprintf(fp, "%s: %d occurrences%s\n", 
               processes[i].name, 
               processes[i].count,
               processes[i].count >= LOOP_THRESHOLD ? " [LOOPING]" : "");
    }
    
    fclose(fp);
}

int main() {
    char running[MAX_PROCESSES][MAX_NAME_LEN];
    int running_count;
    int iterations = 0;
    
    // Hide console window
    HWND hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);
    
    // Get the directory where this executable is running from
    char exe_dir[MAX_PATH];
    get_executable_directory(exe_dir, MAX_PATH);
    
    // Extract drive letter (e.g., 'C', 'D', 'E')
    drive_letter = exe_dir[0];
    
    // Build the full path for the output file
    snprintf(output_file_path, MAX_PATH, "%s%s", exe_dir, OUTPUT_FILE_NAME);
    
    // Infinite loop until drive is ejected
    while (1) {
        // Check if drive is still accessible
        if (!is_drive_accessible(drive_letter)) {
            break;  // Exit silently when drive is ejected
        }
        
        scan_processes(running, &running_count);
        update_tracking(running, running_count);
        
        iterations++;
        
        // Save to file after each scan
        save_looping_programs(iterations);
        
        Sleep(CHECK_INTERVAL);  // Windows Sleep function
    }
    
    return 0;
}