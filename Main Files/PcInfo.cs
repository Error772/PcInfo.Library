using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Management;
using System.Text;
using System.IO;

namespace PcInfo
{
    public class ComputerSerials
	{

        //Dev => T.me/Ali_Cod7
		
		//Returns { CpuSerial , HardDriveSerial , MotherBoardSerial , DiskID , WindowsID }

		public string GetCpu()
		{
			var Sn = new byte[8];

			return !Execute(ref Sn) ? "ND" : string.Format("{0:X8}{1:X8}", BitConverter.ToUInt32(Sn, 4), BitConverter.ToUInt32(Sn, 0));
		}

		public string GetHardDrive()
		{
			string Result = string.Empty;
			ManagementObjectSearcher Searcher = new ManagementObjectSearcher("Select * From win32_PhysicalMedia");
			foreach (ManagementBaseObject ManageBO in Searcher.Get())
			{
				ManagementObject MBO = (ManagementObject)ManageBO;
				bool Flag = MBO["SerialNumber"] != null;
				if (Flag)
				{
					Result = MBO["SerialNumber"].ToString();
				}
			}
			return Result.Remove(0, 5);
		}

		public string GetMotherBoard()
		{
			string Text = "";
			string Result;
			try
			{
				ManagementObjectSearcher MOS = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard");
				ManagementObjectCollection MOC = MOS.Get();
				foreach (ManagementBaseObject MBO in MOC)
				{
					ManagementObject MO = (ManagementObject)MBO;
					Text = MO["SerialNumber"].ToString();
				}
				Result = Text;
			}
			catch (Exception)
			{
				Result = Text;
			}
			return Result;
		}

		public string GetDiskID(string DiskLetter = "C")
		{
			if (string.IsNullOrEmpty(DiskLetter))
			{
				foreach (var CDrive in DriveInfo.GetDrives())
				{
					if (CDrive.IsReady)
					{
						DiskLetter = CDrive.RootDirectory.ToString();
						break;
					}
				}
			}
			if (!string.IsNullOrEmpty(DiskLetter) && DiskLetter.EndsWith(":\\"))
			{
				DiskLetter = DiskLetter.Substring(0, DiskLetter.Length - 2);
			}
			var Disk = new ManagementObject(@"win32_logicaldisk.deviceid=""" + DiskLetter + @":""");
			Disk.Get();
			var volumeSerial = Disk["VolumeSerialNumber"].ToString();
			Disk.Dispose();

			return volumeSerial;
		}

		public string GetWindowsID()
		{
			var WinInf = "";
			var ManageC = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_OperatingSystem");
			var ManageCol = ManageC.Get();
			var Is64 = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432"));

			foreach (var Ob in ManageCol)
			{
				var ManageOb = (ManagementObject)Ob;
				WinInf = ManageOb.Properties["Caption"].Value + Environment.UserName + (string)ManageOb.Properties["Version"].Value;
				break;
			}

			WinInf = WinInf.Replace(" ", "");
			WinInf = WinInf.Replace("Windows", "");
			WinInf = WinInf.Replace("windows", "");
			WinInf += Is64 ? " 64bit" : " 32bit";
			var Hash = MD5.Create();
			var WI = Hash.ComputeHash(Encoding.Default.GetBytes(WinInf));
			var WIHex = BitConverter.ToString(WI).Replace("-", "");
			return WIHex;
		}

		//=================================[Public]================================\\

		[DllImport("user32", EntryPoint = "CallWindowProcW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
		private static extern IntPtr WindowProcess([In] byte[] Bytes, IntPtr HWND, int Message, [In, Out] byte[] WP, IntPtr LP);

		[return: MarshalAs(UnmanagedType.Bool)]
		[DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
		private static extern bool VirtualProtect([In] byte[] bytes, IntPtr size, int newProtect, out int oldProtect);
		
		private static bool Execute(ref byte[] Result)
		{
			var ISsX64Process = IntPtr.Size == 8;
			byte[] Code;

			if (ISsX64Process)
			{
				Code = new byte[] {0x53, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0x41, 0x89, 0x00, 0x41, 0x89, 0x50, 0x04, 0x5b, 0xc3};
			}
			else
			{
				Code = new byte[] {0x55, 0x89, 0xe5, 0x57, 0x8b, 0x7d, 0x10, 0x6a, 0x01, 0x58, 0x53, 0x0f, 0xa2, 0x89, 0x07, 0x89, 0x57, 0x04, 0x5b, 0x5f, 0x89, 0xec, 0x5d, 0xc2, 0x10, 0x00};
			}

			var Ptr = new IntPtr(Code.Length);

			if (!VirtualProtect(Code, Ptr, 0x40, out _))
			{
				Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
			}

			Ptr = new IntPtr(Result.Length);
			return WindowProcess(Code, IntPtr.Zero, 0, Result, Ptr) != IntPtr.Zero;

		}

		//=================================[Privates]================================\\
	}
}
