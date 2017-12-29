using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Forms;

namespace MemoryClass
{
    public class Memory
    {
        public IntPtr pHandle;

        public Process process;
        public ProcessModule mainModule;
        public Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();

        #region DllImports
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, Int32 dwProcessId);
        #endregion

        /// <summary>
        /// Open the PC game process with all security and access rights.
        /// </summary>
        /// <param name="process"></param>
        /// <returns></returns>
        public bool OpenProcess(Process process)
        {
            if(IsAdmin() == false)
            {
                Debug.Write("WARNING: You are NOT running this program as admin!! Visit https://github.com/erfg12/memory.dll/wiki/Administrative-Privileges");
                MessageBox.Show("WARNING: You are NOT running this program as admin!!");
            } else
            {
                Debug.Write("Program is operating at Administrative level. Now opening process id #" + process.Id + "." + Environment.NewLine);
            }

            try
            {
                Process.EnterDebugMode();
                if(process.Id == 0)
                    return false;

                if (process.Responding == false)
                    return false;

                pHandle = OpenProcess(0x1F0FFF, true, process.Id);
                if (pHandle == IntPtr.Zero)
                    return false;

                Debug.Write("Now storing module addresses for process id #" + process.Id + "." + Environment.NewLine);
                this.process = process;
                mainModule = process.MainModule;
                GetModules(process);
                return true;
            } catch { return false; }
        }

        /// <summary>
        /// Check if program is running with administrative privileges. Read about it here: https://github.com/erfg12/memory.dll/wiki/Administrative-Privileges
        /// </summary>
        /// <returns></returns>
        public bool IsAdmin()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        /// <summary>
        /// Builds the process modules dictionary (names with addresses).
        /// </summary>
        public void GetModules(Process process)
        {
            if (process == null)
                return;
            modules.Clear();

            foreach (ProcessModule module in process.Modules)
            {
                if (module.ModuleName != null && module.ModuleName != "" && !modules.ContainsKey(module.ModuleName))
                    modules.Add(module.ModuleName, module.BaseAddress);
            }
        }

        /// <summary>
        /// Get a process from his name.
        /// </summary>
        /// <param name="name">Example: "eqgame". Use task manager to find the name. Do not include .exe</param>
        /// <returns></returns>
        public Process GetProcessFromName(string name)
        {
            Process[] processList = Process.GetProcesses();
            if (name.Contains(".exe"))
                name.Replace(".exe", string.Empty);

            foreach(Process process in processList)
            {
                if (process.ProcessName.Equals(name))
                    return process;
            }
            return null;
        }
    }
}