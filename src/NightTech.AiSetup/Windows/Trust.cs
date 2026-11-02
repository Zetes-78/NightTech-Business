using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace NightTech.AiSetup.Windows;

/// <summary>
/// Checks a downloaded installer's digital signature with Windows (WinVerifyTrust) and who signed it, before it is run
/// as administrator. A file that isn't validly signed by the expected publisher is never run.
/// </summary>
public static class Trust
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WintrustFileInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WintrustData data);

    /// <summary>True when Windows trusts the file's signature and the signing certificate's subject contains the expected name.</summary>
    public static bool IsSignedBy(string path, string expectedSubject, out string signer)
    {
        signer = "";
        var info = new WintrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WintrustFileInfo>(), pcwszFilePath = path };
        IntPtr pInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(info, pInfo, false);
            var data = new WintrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WintrustData>(),
                dwUIChoice = 2,          // no UI
                fdwRevocationChecks = 0, // revocation checks need the internet; the signature chain is still checked
                dwUnionChoice = 1,       // a file
                pFile = pInfo,
                dwStateAction = 1,       // verify
            };
            var action = GenericVerifyV2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = 2;      // release
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            if (result != 0)
            {
                signer = $"signature not trusted (0x{result:X8})";
                return false;
            }
        }
        finally
        {
            Marshal.DestroyStructure<WintrustFileInfo>(pInfo);
            Marshal.FreeHGlobal(pInfo);
        }

        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            signer = cert.GetNameInfo(X509NameType.SimpleName, false);
            return cert.Subject.Contains(expectedSubject, StringComparison.OrdinalIgnoreCase);
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            signer = "unreadable signature: " + ex.Message;
            return false;
        }
    }
}
