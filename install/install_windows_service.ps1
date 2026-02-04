# Windows Service Installer for Faramesh Guard
# Run as Administrator: .\install_windows_service.ps1

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Status,
    [string]$ServiceName = "FarameshGuard",
    [string]$DisplayName = "Faramesh Guard - AI Safety Daemon",
    [string]$Description = "Human-in-the-loop safety layer for AI agents"
)

$ErrorActionPreference = "Stop"

# Service configuration
$ServiceUser = "LocalSystem"
$InstallDir = "$env:ProgramFiles\FarameshGuard"
$PythonPath = "$InstallDir\venv\Scripts\python.exe"
$ServiceScript = "$InstallDir\daemon\service\main.py"
$LogDir = "$InstallDir\logs"
$ConfigDir = "$InstallDir\config"

function Write-ColorMessage {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Prerequisites {
    Write-ColorMessage "Checking prerequisites..." "Cyan"

    # Check Python
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-ColorMessage "Error: Python is not installed or not in PATH" "Red"
        Write-ColorMessage "Please install Python 3.11+ from https://python.org" "Yellow"
        exit 1
    }
    Write-ColorMessage "Found: $pythonVersion" "Green"

    # Check pywin32 for service support
    $pywin32Check = python -c "import win32serviceutil" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-ColorMessage "Installing pywin32 for Windows service support..." "Yellow"
        pip install pywin32
    }
}

function Create-ServiceWrapper {
    # Create Windows service wrapper using pywin32
    $wrapperContent = @'
"""
Faramesh Guard Windows Service Wrapper

Uses pywin32 to run the Guard daemon as a Windows service.
"""

import os
import sys
import time
import socket
import subprocess
import win32serviceutil
import win32service
import win32event
import servicemanager


class FarameshGuardService(win32serviceutil.ServiceFramework):
    """Windows Service for Faramesh Guard daemon."""

    _svc_name_ = "FarameshGuard"
    _svc_display_name_ = "Faramesh Guard - AI Safety Daemon"
    _svc_description_ = "Human-in-the-loop safety layer for AI agents"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.process = None
        self.running = False

        # Configuration
        self.install_dir = os.environ.get(
            "FARAMESH_INSTALL_DIR",
            r"C:\Program Files\FarameshGuard"
        )
        self.python_path = os.path.join(self.install_dir, "venv", "Scripts", "python.exe")
        self.service_script = os.path.join(self.install_dir, "daemon", "service", "main.py")
        self.log_dir = os.path.join(self.install_dir, "logs")

    def SvcStop(self):
        """Stop the service."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.running = False

        if self.process:
            try:
                # Try graceful shutdown first
                self.process.terminate()
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Force kill if graceful fails
                self.process.kill()
            except Exception as e:
                servicemanager.LogErrorMsg(f"Error stopping Guard process: {e}")

    def SvcDoRun(self):
        """Run the service."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )

        self.running = True
        self.main()

    def main(self):
        """Main service loop."""
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)

        # Log file paths
        stdout_log = os.path.join(self.log_dir, "guard_stdout.log")
        stderr_log = os.path.join(self.log_dir, "guard_stderr.log")

        while self.running:
            try:
                # Check if port is available
                if self._is_port_in_use(8765):
                    servicemanager.LogWarningMsg("Port 8765 already in use, waiting...")
                    time.sleep(5)
                    continue

                # Start the daemon process
                with open(stdout_log, "a") as stdout_f, open(stderr_log, "a") as stderr_f:
                    self.process = subprocess.Popen(
                        [self.python_path, self.service_script],
                        stdout=stdout_f,
                        stderr=stderr_f,
                        cwd=self.install_dir,
                        env={**os.environ, "GUARD_SERVICE_MODE": "1"},
                    )

                servicemanager.LogInfoMsg(f"Guard daemon started (PID: {self.process.pid})")

                # Monitor the process
                while self.running:
                    result = win32event.WaitForSingleObject(self.hWaitStop, 1000)

                    if result == win32event.WAIT_OBJECT_0:
                        # Stop requested
                        break

                    # Check if process is still running
                    if self.process.poll() is not None:
                        exit_code = self.process.returncode
                        servicemanager.LogWarningMsg(
                            f"Guard daemon exited with code {exit_code}, restarting..."
                        )
                        time.sleep(5)  # Brief delay before restart
                        break

            except Exception as e:
                servicemanager.LogErrorMsg(f"Service error: {e}")
                time.sleep(10)  # Wait before retry on error

        servicemanager.LogInfoMsg("Guard service stopped")

    def _is_port_in_use(self, port: int) -> bool:
        """Check if a port is in use."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return False
            except OSError:
                return True


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Running as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(FarameshGuardService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Command line (install, remove, etc.)
        win32serviceutil.HandleCommandLine(FarameshGuardService)
'@

    $wrapperPath = "$InstallDir\guard_service.py"
    $wrapperContent | Out-File -FilePath $wrapperPath -Encoding UTF8
    Write-ColorMessage "Created service wrapper: $wrapperPath" "Green"
}

function Install-Service {
    Write-ColorMessage "`n=== Installing Faramesh Guard Service ===" "Cyan"

    if (-not (Test-Administrator)) {
        Write-ColorMessage "Error: Administrator privileges required" "Red"
        Write-ColorMessage "Please run this script as Administrator" "Yellow"
        exit 1
    }

    Install-Prerequisites

    # Create installation directory
    Write-ColorMessage "Creating installation directory..." "Cyan"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

    # Copy files
    Write-ColorMessage "Copying daemon files..." "Cyan"
    $sourceDir = Split-Path -Parent $PSScriptRoot
    Copy-Item -Path "$sourceDir\daemon" -Destination $InstallDir -Recurse -Force

    # Create virtual environment
    Write-ColorMessage "Creating Python virtual environment..." "Cyan"
    python -m venv "$InstallDir\venv"

    # Install dependencies
    Write-ColorMessage "Installing dependencies..." "Cyan"
    & "$InstallDir\venv\Scripts\pip.exe" install -r "$InstallDir\daemon\requirements.txt"
    & "$InstallDir\venv\Scripts\pip.exe" install pywin32

    # Create service wrapper
    Create-ServiceWrapper

    # Install the service
    Write-ColorMessage "Installing Windows service..." "Cyan"
    & "$InstallDir\venv\Scripts\python.exe" "$InstallDir\guard_service.py" install

    if ($LASTEXITCODE -eq 0) {
        Write-ColorMessage "`n✅ Service installed successfully!" "Green"
        Write-ColorMessage "Service Name: $ServiceName" "White"
        Write-ColorMessage "Display Name: $DisplayName" "White"
        Write-ColorMessage "Install Dir: $InstallDir" "White"
        Write-ColorMessage "Log Dir: $LogDir" "White"
        Write-ColorMessage "`nTo start the service: .\install_windows_service.ps1 -Start" "Yellow"
    } else {
        Write-ColorMessage "❌ Service installation failed" "Red"
        exit 1
    }
}

function Uninstall-Service {
    Write-ColorMessage "`n=== Uninstalling Faramesh Guard Service ===" "Cyan"

    if (-not (Test-Administrator)) {
        Write-ColorMessage "Error: Administrator privileges required" "Red"
        exit 1
    }

    # Stop service if running
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-ColorMessage "Stopping service..." "Yellow"
        Stop-Service -Name $ServiceName -Force
    }

    # Remove service
    Write-ColorMessage "Removing service..." "Cyan"
    & "$InstallDir\venv\Scripts\python.exe" "$InstallDir\guard_service.py" remove

    # Ask about removing files
    $removeFiles = Read-Host "Remove installation directory? (y/N)"
    if ($removeFiles -eq "y" -or $removeFiles -eq "Y") {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-ColorMessage "Installation directory removed" "Green"
    }

    Write-ColorMessage "`n✅ Service uninstalled successfully!" "Green"
}

function Start-ServiceCmd {
    Write-ColorMessage "Starting $ServiceName..." "Cyan"

    try {
        Start-Service -Name $ServiceName
        Write-ColorMessage "✅ Service started successfully!" "Green"
    } catch {
        Write-ColorMessage "❌ Failed to start service: $_" "Red"
        exit 1
    }
}

function Stop-ServiceCmd {
    Write-ColorMessage "Stopping $ServiceName..." "Cyan"

    try {
        Stop-Service -Name $ServiceName -Force
        Write-ColorMessage "✅ Service stopped successfully!" "Green"
    } catch {
        Write-ColorMessage "❌ Failed to stop service: $_" "Red"
        exit 1
    }
}

function Get-ServiceStatus {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if (-not $service) {
        Write-ColorMessage "Service '$ServiceName' is not installed" "Yellow"
        return
    }

    Write-ColorMessage "`n=== Faramesh Guard Service Status ===" "Cyan"
    Write-ColorMessage "Name:         $($service.Name)" "White"
    Write-ColorMessage "Display Name: $($service.DisplayName)" "White"
    Write-ColorMessage "Status:       $($service.Status)" $(if ($service.Status -eq "Running") { "Green" } else { "Yellow" })
    Write-ColorMessage "Start Type:   $($service.StartType)" "White"

    # Check if Guard is responding
    if ($service.Status -eq "Running") {
        Write-ColorMessage "`nChecking Guard health..." "Cyan"
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:8765/health" -TimeoutSec 5
            Write-ColorMessage "Guard Health: OK" "Green"
            Write-ColorMessage "Version:      $($response.version)" "White"
        } catch {
            Write-ColorMessage "Guard not responding on port 8765" "Yellow"
        }
    }

    # Show recent log entries
    $logFile = "$LogDir\guard_stderr.log"
    if (Test-Path $logFile) {
        Write-ColorMessage "`nRecent log entries:" "Cyan"
        Get-Content $logFile -Tail 5 | ForEach-Object { Write-ColorMessage "  $_" "DarkGray" }
    }
}

# Main execution
if ($Install) {
    Install-Service
} elseif ($Uninstall) {
    Uninstall-Service
} elseif ($Start) {
    Start-ServiceCmd
} elseif ($Stop) {
    Stop-ServiceCmd
} elseif ($Status) {
    Get-ServiceStatus
} else {
    Write-ColorMessage "Faramesh Guard - Windows Service Installer" "Cyan"
    Write-ColorMessage ""
    Write-ColorMessage "Usage:" "White"
    Write-ColorMessage "  .\install_windows_service.ps1 -Install    Install the service" "Gray"
    Write-ColorMessage "  .\install_windows_service.ps1 -Uninstall  Remove the service" "Gray"
    Write-ColorMessage "  .\install_windows_service.ps1 -Start      Start the service" "Gray"
    Write-ColorMessage "  .\install_windows_service.ps1 -Stop       Stop the service" "Gray"
    Write-ColorMessage "  .\install_windows_service.ps1 -Status     Check service status" "Gray"
    Write-ColorMessage ""
    Write-ColorMessage "Run as Administrator for install/uninstall operations." "Yellow"
}
