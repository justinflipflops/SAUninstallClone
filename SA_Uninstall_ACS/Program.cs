using Microsoft.Win32;
using ProcessPrivileges;
using System;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace SA_Uninstall_ACS
{
    class Program
    {
        [DllImport("libc")]
        public static extern uint getuid();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 DllRegUnRegAPI();

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPWStr)]string strLibraryName);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        static extern Int32 FreeLibrary(IntPtr hModule);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPWStr)] string lpProcName);
        static void Main(string[] args)
        {
            string _hklm_services = @"SYSTEM\CurrentControlSet\Services";
            string[] _hklms = { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OfficeScan Monitor", @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\OfficeScan Monitor", @"Software\Microsoft\windows\currentversion\uninstall\Wofie", @"Software\Microsoft\windows\currentversion\uninstall\{BED0B8A2-2986-49F8-90D6-FA008D37A3D2}", @"Software\Microsoft\windows\currentversion\uninstall\{C1F6E833-B25E-4C39-A026-D3253958B0D0}", @"Software\Microsoft\windows\currentversion\uninstall\{A38F51ED-D01A-4CE4-91EB-B824A00A8BDF}", @"Software\Microsoft\windows\currentversion\uninstall\{19D84BB4-35C9-4125-90AB-C2ADD0F9A8EC}", @"Software\Microsoft\windows\currentversion\uninstall\{8456195C-3BA3-45A4-A6A7-30AE7A62EADB}", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\2A8B0DEB68928F94096DAF00D8733A2D", @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{BED0B8A2-2986-49F8-90D6-FA008D37A3D2}", @"SOFTWARE\TrendMicro\AEGIS", @"SOFTWARE\TrendMicro\AMSP", @"SOFTWARE\TrendMicro\ClientStatus", @"SOFTWARE\TrendMicro\NSC", @"SOFTWARE\TrendMicro\Osprey", @"SOFTWARE\TrendMicro\Pc-cillinNTCorp", @"SOFTWARE\TrendMicro\Wolfie", @"SOFTWARE\TrendMicro\iACAgent", @"SOFTWARE\TrendMicro", @"SOFTWARE\TrendMicro_Volatile", @"SOFTWARE\Wow6432Node\TrendMicro\AEGIS", @"SOFTWARE\Wow6432Node\TrendMicro\AMSP", @"SOFTWARE\Wow6432Node\TrendMicro\NSC", @"SOFTWARE\Wow6432Node\TrendMicro\Osprey", @"SOFTWARE\Wow6432Node\TrendMicro\Wolfie", @"SOFTWARE\Wow6432Node\TrendMicro\iACAgent", @"SOFTWARE\Wow6432Node\TrendMicro", @"SOFTWARE\Wow6432Node\TrendMicro_Volatile" };
            string[] _hkcrs = { @"Installer\Features\338E6F1CE52B93C40A623D5293850B0D", @"Installer\Products\2A8B0DEB68928F94096DAF00D8733A2D", @"Installer\Products\338E6F1CE52B93C40A623D5293850B0D", @"Installer\Upgradecodes\8A88AE84D667B304CB368C99791A74A6", @"Installer\Features\DE15F83AA10D4EC419BE8B420AA0B8FD", @"Installer\Products\DE15F83AA10D4EC419BE8B420AA0B8FD", @"Installer\Upgradecodes\8A88AE84D667B304CB368C99791A74A6", @"TypeLib\{A00B957E-3315-46CB-B090-9EF2187641E2}" };
            string[] _unregister = { @"\program files\trend micro\Security Agent\tmdshell.dll", @"\program files (x86)\trend micro\Security Agent\tmdshell_64x.dll" };
            string[] _delete = { @"\Program Files (x86)\Trend Micro\Security Agent", @"\Program Files\Trend Micro\Security Agent" };
            string[] _process_list = { "ntrtscan", "pccntmon", "tmbmsrv", "tmccsf", "tmlisten", "tmproxy", "pccntupd", "xpupg", "wfbssupdater" };
            string[] _svc_list = { "svcgenerichost","ntrtscan", "tmactmon", "tmbmserver", "tmccsf", "tmcfw", "tmcomm", "tmebc", "tmeevw", "tmevtmgr", "tmfilter", "tmlisten", "tmlwf", "tmpfw", "tmprefilter", "tmproxy", "tmtdi", "tmusa", "tmwfp", "vsapint" };
            try
            {
                RequireAdministrator();
            }
            catch (Exception _ex)
            {
                Console.WriteLine("This application requires administrative rights!", _ex);
                return;
            }
            using (new ProcessPrivileges.PrivilegeEnabler(Process.GetCurrentProcess(), Privilege.TakeOwnership))
            {
                string _drive = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).Substring(0, 2);
                for (int i = 0; i < _unregister.Count(); i++)
                {
                    _unregister[i] = $"{_drive}{_unregister[i]}";
                }
                for (int i = 0; i < _delete.Count(); i++)
                {
                    _delete[i] = $"{_drive}{_delete[i]}";
                }
                Console.WriteLine("Analyzing Services");
                foreach (var _svc in ServiceController.GetServices())
                {
                    if (_svc_list.Contains(_svc.ServiceName.ToLower()))
                    {
                        Console.WriteLine($"Found {_svc.ServiceName}");
                        try
                        {
                            _svc.Stop();
                            Console.WriteLine($"Stopped {_svc.ServiceName}");
                        }
                        catch (Exception _ex)
                        {
                            Console.WriteLine($"Failed to stop {_svc.ServiceName}");
                        }
                        try
                        {
                            ServiceInstaller _tmp_installer = new ServiceInstaller();
                            _tmp_installer.Context = new InstallContext();
                            _tmp_installer.ServiceName = _svc.ServiceName;
                            _tmp_installer.Uninstall(null);
                            Console.WriteLine($"Uninstalled {_svc.ServiceName}");
                        }
                        catch (Exception _ex)
                        {
                            Console.WriteLine($"Failed to uninstall {_svc.ServiceName}");
                        }
                    }
                }
                Console.WriteLine("Analyzing Processes");
                foreach (var _process in Process.GetProcesses())
                {
                    try
                    {
                        if (_process_list.Contains(_process.ProcessName.ToLower()))
                        {
                            Console.WriteLine($"Found {_process.ProcessName}");
                            _process.Kill();
                            Console.WriteLine($"Killed {_process.ProcessName}");
                        }
                    }
                    catch
                    {
                        Console.WriteLine($"Failed to kill {_process.ProcessName}");
                    }
                }
                Console.WriteLine("Unregistering DLLs");
                bool _unregistered = false;
                foreach (var _unreg in _unregister)
                {
                    if (File.Exists(_unreg))
                    {
                        Console.WriteLine($"Found {_unreg}");
                        try
                        {
                            IntPtr hModuleDLL = LoadLibrary(_unreg);
                            if (hModuleDLL != IntPtr.Zero)
                            {

                                // Obtain the required exported API.
                                IntPtr pExportedFunction = IntPtr.Zero;

                                pExportedFunction = GetProcAddress(hModuleDLL, "DllUnregisterServer");
                                if (pExportedFunction != IntPtr.Zero)
                                {
                                    DllRegUnRegAPI pDelegateRegUnReg = (DllRegUnRegAPI)(Marshal.GetDelegateForFunctionPointer(pExportedFunction, typeof(DllRegUnRegAPI))) as DllRegUnRegAPI;

                                    UInt32 hResult = pDelegateRegUnReg();

                                    if (hResult == 0)
                                    {
                                        _unregistered = true;
                                        Console.WriteLine($"Unregistered {_unreg}");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"Failed to unregister {_unreg}");
                                    }
                                    FreeLibrary(hModuleDLL);
                                    hModuleDLL = IntPtr.Zero;
                                }
                            }
                        }
                        catch
                        {
                            Console.WriteLine($"Unregistered {_unreg}");
                        }
                    }
                }
                if (_unregistered) // only restart explorer if we unregistered something!
                {
                    bool _terminated = false;
                    Console.WriteLine("Terminating Explorer");
                    foreach (var _explorer in Process.GetProcessesByName("explorer"))
                    {
                        try
                        {
                            _explorer.Kill();
                            _terminated = true;
                            Console.WriteLine($"Terminated Explorer.exe({_explorer.Id.ToString()})");
                        }
                        catch
                        {
                            Console.WriteLine($"Failed terminating Explorer.exe({_explorer.Id.ToString()})");
                        }
                    }
                    if (_terminated)
                    {
                        Console.WriteLine("Restarting Explorer");
                        try
                        {
                            Process _started = Process.Start($"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\\explorer.exe");
                            Console.WriteLine($"Restarted Explorer({_started.Id.ToString()})");
                        }
                        catch
                        {
                            Console.WriteLine($"Failed to restart explorer");
                        }
                    }
                }
                Console.WriteLine("Cleaning Up Registry");
                using (WindowsIdentity _currentUser = WindowsIdentity.GetCurrent())
                { 
                    Console.WriteLine("[REGISTRY] Services");
                    using (RegistryKey _keyServices = Registry.LocalMachine.OpenSubKey(_hklm_services, true))
                    {
                        string[] _subKeyNames = _keyServices.GetSubKeyNames();
                        foreach (string _svc in _svc_list)
                        {
                            if (_subKeyNames.Contains(_svc))
                            {
                                bool blnFound = false;
                                using (RegistryKey _subKey = _keyServices.OpenSubKey(_svc,true))
                                {
                                    if (_subKey != null)
                                    {
                                        Console.WriteLine($"[REGISTRY] Found {_svc}");
                                        RegistrySecurity ownerSecurity = new RegistrySecurity();
                                        ownerSecurity.SetOwner(_currentUser.User);
                                        RegistrySecurity accessSecurity = new RegistrySecurity();
                                        accessSecurity.AddAccessRule(new RegistryAccessRule(_currentUser.User, RegistryRights.FullControl, AccessControlType.Allow));
                                        _subKey.SetAccessControl(ownerSecurity);
                                        _subKey.SetAccessControl(accessSecurity);
                                        _subKey.Close();
                                        blnFound = true;
                                    }
                                }
                                if (blnFound)
                                {
                                    try
                                    {
                                        _keyServices.DeleteSubKeyTree(_svc);
                                        Console.WriteLine($"[REGISTRY] Removed {_svc}");
                                    }
                                    catch (Exception _ex)
                                    {
                                        Console.WriteLine($"[REGISTRY] Failed to remove {_svc} : {_ex.Message}");
                                    }
                                }
                            }
                        }
                        _keyServices.Close();
                    }

                    Console.WriteLine("[REGISTRY] HKLM");
                    Registry.LocalMachine.GetSubKeyNames();
                    foreach (var _hklm in _hklms)
                    {
                        RegistrySecurity ownerSecurity = new RegistrySecurity();
                        ownerSecurity.SetOwner(_currentUser.User);
                        RegistrySecurity accessSecurity = new RegistrySecurity();
                        accessSecurity.AddAccessRule(new RegistryAccessRule(_currentUser.User, RegistryRights.FullControl, AccessControlType.Allow));

                        string _current_key = _hklm;
                        bool blnFound = false;
                        using (var _key = Registry.LocalMachine.OpenSubKey(_current_key, true))
                        {
                            if (_key != null)
                            {
                                Console.WriteLine($"[REGISTRY] Found {_hklm}");
                                _key.SetAccessControl(ownerSecurity);
                                Console.WriteLine($"[REGISTRY] Set Owner {_hklm}");
                                _key.SetAccessControl(accessSecurity);
                                Console.WriteLine($"[REGISTRY] Set Full Access {_hklm}");
                                _key.Close();
                                blnFound = true;
                            }
                        }
                        if (blnFound)
                        {
                            try
                            {
                                Registry.LocalMachine.DeleteSubKeyTree(_hklm);
                                Console.WriteLine($"[REGISTRY] Removed {_hklm}");
                            }
                            catch
                            {
                                Console.WriteLine($"[REGISTRY] Failed to remove {_hklm}");
                            }
                        }
                    }
                    Console.WriteLine("[REGISTRY] HKCR");
                    foreach (var _hkcr in _hkcrs)
                    {
                        RegistrySecurity ownerSecurity = new RegistrySecurity();
                        ownerSecurity.SetOwner(_currentUser.User);
                        RegistrySecurity accessSecurity = new RegistrySecurity();
                        accessSecurity.AddAccessRule(new RegistryAccessRule(_currentUser.User, RegistryRights.FullControl, AccessControlType.Allow));
                        bool blnFound = false;
                        string szKeyName = String.Empty;
                        using (var _key = Registry.ClassesRoot.OpenSubKey(_hkcr, true))
                        {
                            if (_key != null)
                            {
                                Console.WriteLine($"[REGISTRY] Found {_hkcr}");
                                _key.SetAccessControl(ownerSecurity);
                                _key.SetAccessControl(accessSecurity);
                                _key.Close();
                                blnFound = true;
                            }
                        }
                        if (blnFound)
                        {
                            try
                            {

                                Registry.ClassesRoot.DeleteSubKeyTree(_hkcr);
                                Console.WriteLine($"[REGISTRY] Removed {_hkcr}");
                            }
                            catch
                            {
                                Console.WriteLine($"[REGISTRY] Failed to remove {_hkcr}");
                            }
                        }
                    }
                }
                Console.WriteLine("[FILES] Cleanup");
                foreach (var _dir in _delete)
                {
                    if (Directory.Exists(_dir))
                    {
                        Console.WriteLine("[FILES] found {_dir}");
                        try
                        {
                            TakeOwnership(_dir);
                            Directory.Delete(_dir, true);
                            Console.WriteLine("[FILES] removed {_dir}");
                        }
                        catch
                        {
                            Console.WriteLine("[FILES] failed to remove {_dir}");
                        }
                    }
                }
            }
            Console.WriteLine("Done");
            Console.ReadLine();
        }

        private static bool TakeOwnership(string Path)
        {
            // get the file attributes for file or directory
            if (!String.IsNullOrWhiteSpace(Path))
            {
                try
                {

                    FileAttributes attr = File.GetAttributes(Path);
                    using (WindowsIdentity _currentUser = WindowsIdentity.GetCurrent())
                    {
                        if (!attr.HasFlag(FileAttributes.Directory))
                        {
                            FileSecurity ownerSecurity = new FileSecurity();
                            ownerSecurity.SetOwner(_currentUser.User);
                            File.SetAccessControl(Path, ownerSecurity);

                            FileSecurity accessSecurity = new FileSecurity();
                            accessSecurity.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow));
                            File.SetAccessControl(Path, accessSecurity);
                        }
                        else
                        {
                            DirectorySecurity ownerSecurity = new DirectorySecurity();
                            ownerSecurity.SetOwner(_currentUser.User);
                            Directory.SetAccessControl(Path, ownerSecurity);

                            DirectorySecurity accessSecurity = new DirectorySecurity();
                            accessSecurity.AddAccessRule(new FileSystemAccessRule(_currentUser.User, FileSystemRights.FullControl, AccessControlType.Allow));
                            Directory.SetAccessControl(Path, accessSecurity);
                        }
                    }
                    return true;
                }
                catch {
                    return false;
                }
            }
            return false;
        }
        public static void RequireAdministrator()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                    {
                        WindowsPrincipal principal = new WindowsPrincipal(identity);
                        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                        {
                            throw new InvalidOperationException("Application must be run as administrator");
                        }
                    }
                }
                else if (getuid() != 0)
                {
                    throw new InvalidOperationException("Application must be run as root");
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Unable to determine administrator or root status", ex);
            }
        }
    }
}
