#include <typeinfo>
#include <string>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include "stdio.h"
#include <tchar.h>
#include <map>
#include "psapi.h"
#include "tlhelp32.h"
#include <string>

using std::string;
using namespace std;

unsigned long usage;

BOOL ListProcessThreads( DWORD dwOwnerPID );
LPVOID get_entry_point(HANDLE processHandle);
void print_process_info(map<int, PROCESSENTRY32> processesList, int counterNum);
map<int, MEMORY_BASIC_INFORMATION> show_modules(HANDLE process);

int main( ) {
    SetConsoleTitle("Memory Class Test");

    HANDLE hProcessSnap;
    HANDLE hProcess;
    HANDLE processHandle;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;
    int counter = 1;
    int counterNum;
    int processId;
    int pageNum;
	float value = 9999;
	SIZE_T lpNumberOfBytesRead;
	BOOL success;
    map<int, PROCESSENTRY32> processesList;
    map<int, MEMORY_BASIC_INFORMATION> MBIPagesList;


    // Take a snapshot of all processesList in the system.
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    //check if hProcessSnap works
    if( hProcessSnap == INVALID_HANDLE_VALUE ){
    	printf( TEXT("CreateToolhelp32Snapshot (of processesList)") );
        return 1;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof( PROCESSENTRY32 );

    //get info on the first process
    Process32First( hProcessSnap, &pe32 );

    //populate processesList map
    do{
    	//PROCESS NAME
		printf("\n %d. %s", counter, pe32.szExeFile);

		processesList.insert(pair<int, PROCESSENTRY32>(counter, pe32));

		counter++;
    } while( Process32Next( hProcessSnap, &pe32 ) );

    //user chooses the process to examine
    printf("\n Enter the process number (1-%d):", counter);
    cin >> counterNum;

    //print basic info for process
    print_process_info(processesList, counterNum);
    //list all thread for process
    ListProcessThreads( processesList.at(counterNum).th32ProcessID );

    processId = processesList.at(counterNum).th32ProcessID;
    //get process handle
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);

    //get virtual memory information
    //map for pages in virual address
    MBIPagesList = show_modules(processHandle);

    //user chooses the address to examine
    printf("\n Enter the address number (1-%d):", MBIPagesList.size());
    cin >> pageNum;
    cout << "====================================" << endl;
    printf("Virtual Memory address: %#10.10x \n", MBIPagesList.at(pageNum).BaseAddress);
    cout << "====================================" << endl;

	success = ReadProcessMemory(processHandle, MBIPagesList.at(pageNum).BaseAddress, &value, sizeof(value), &lpNumberOfBytesRead);

	if (success){

		cout << "Data read : " << value << endl;

	} else {
		printf("\n failed to read process memory");
	}

	return 0;
}

BOOL ListProcessThreads( DWORD dwOwnerPID ){

  HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
  THREADENTRY32 te32;

  // Take a snapshot of all running threads
  hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
  if( hThreadSnap == INVALID_HANDLE_VALUE )
    return( FALSE );

  // Fill in the size of the structure before using it.
  te32.dwSize = sizeof(THREADENTRY32);

  // Retrieve information about the first thread,
  // and exit if unsuccessful
  if( !Thread32First( hThreadSnap, &te32 ) ){
	  printf( TEXT("Thread32First") ); // show cause of failure
    CloseHandle( hThreadSnap );          // clean the snapshot object
    return( FALSE );
  }

  // Now walk the thread list of the system,
  // and display information about each thread
  // associated with the specified process
  do{
    if( te32.th32OwnerProcessID == dwOwnerPID ){
    	printf( TEXT("\n\n     th32OwnerProcessID      = 0x%08X"), te32.th32OwnerProcessID );
    	printf( TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID );
    	printf( TEXT("\n     Base priority  = %d"), te32.tpBasePri );
    	printf( TEXT("\n     Delta priority = %d"), te32.tpDeltaPri );
    	printf( TEXT("\n"));
    }
  } while( Thread32Next(hThreadSnap, &te32 ) );

  CloseHandle( hThreadSnap );
  return( TRUE );
}


LPVOID get_entry_point(HANDLE processHandle){

	HMODULE *hModules = NULL;
	DWORD cModules;
	char szBuf[50];
	LPVOID EntryPoint;
	int i;

	hModules = new HMODULE[cModules/sizeof(HMODULE)];

	EnumProcessModules(processHandle, hModules, cModules/sizeof(HMODULE), &cModules);


	for (i = 0; i < sizeof(hModules); i ++){

		if(GetModuleFileNameExA(processHandle, hModules[i], szBuf, sizeof(szBuf))){

			MODULEINFO mi;
			GetModuleInformation(processHandle, hModules[i], &mi, sizeof(mi));

			EntryPoint =  mi.EntryPoint;
			break;

		}

	}

	return EntryPoint;
}

void print_process_info(map<int, PROCESSENTRY32> processesList, int counterNum){

	printf("\n=====================================================\n");
	printf(processesList.at(counterNum).szExeFile);
	printf("\n=====================================================" );

	printf( "\n  Process ID        = 0x%08X", processesList.at(counterNum).th32ProcessID );
	printf( "\n  Thread count      = %d",   processesList.at(counterNum).cntThreads );
	printf( "\n  Parent process ID = 0x%08X", processesList.at(counterNum).th32ParentProcessID );
	printf( "\n  Priority base     = %d", processesList.at(counterNum).pcPriClassBase );
	printf(" \n-------------------------------------------------------" );
}

map<int, MEMORY_BASIC_INFORMATION> show_modules(HANDLE process) {

    unsigned char *p = NULL;
    MEMORY_BASIC_INFORMATION info;
    int counter = 1;
    map<int, MEMORY_BASIC_INFORMATION> MBIPagesList;

    cout << "====================================" << endl;
    cout << "memory allocated for process" <<  endl;
    cout << "====================================" << endl;

    for ( p = NULL; VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info); p += info.RegionSize ) {

        	MBIPagesList.insert(pair<int, MEMORY_BASIC_INFORMATION>(counter, info));
        	printf("%d. %#10.10x (%6uK)\t", counter, info.BaseAddress, info.RegionSize/1024);

        	switch (info.State) {
				case MEM_COMMIT:
					printf("Committed");
					break;
				case MEM_RESERVE:
					printf("Reserved");
					break;
				case MEM_FREE:
					printf("Free");
					break;
        	}

			printf("\t");
			switch (info.Type) {
				case MEM_IMAGE:
					printf("Code Module");
					break;
				case MEM_MAPPED:
					printf("Mapped     ");
					break;
				case MEM_PRIVATE:
					printf("Private    ");
			}
			printf("\t");

			if ((info.State == MEM_COMMIT) && (info.Type == MEM_PRIVATE))
				usage +=info.RegionSize;

			int guard = 0, nocache = 0;

			if ( info.AllocationProtect & PAGE_NOCACHE)
				nocache = 1;
			if ( info.AllocationProtect & PAGE_GUARD )
				guard = 1;

			info.AllocationProtect &= ~(PAGE_GUARD | PAGE_NOCACHE);

			switch (info.AllocationProtect) {
				case PAGE_READONLY:
					printf("Read Only");
					break;
				case PAGE_READWRITE:
					printf("Read/Write");
					break;
				case PAGE_WRITECOPY:
					printf("Copy on Write");
					break;
				case PAGE_EXECUTE:
					printf("Execute only");
					break;
				case PAGE_EXECUTE_READ:
					printf("Execute/Read");
					break;
				case PAGE_EXECUTE_READWRITE:
					printf("Execute/Read/Write");
					break;
				case PAGE_EXECUTE_WRITECOPY:
					printf("COW Executable");
					break;
			}

			if (guard)
				printf("\tguard page");
			if (nocache)
				printf("\tnon-cachable");
			printf("\n");

			counter++;
    }

  return MBIPagesList;
}
