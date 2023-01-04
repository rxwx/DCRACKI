using CommandLine;
using SharpDPAPI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Linq;
using System.Security.Principal;

namespace DCRACKI
{
    internal class Program
    {
        static readonly string masterKeyRegex = @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}";

        class GlobalOptions
        {
            [Option('m', "masterkey", Required = true, HelpText = "Path to masterkey file.")]
            public string MasterKeyPath { get; set; }

            [Option('s', "sid", Required = false, HelpText = "SID of user. If no value is given, we will attempt to recover it from the folder name.")]
            public string Sid { get; set; }
        }

        [Verb("test", HelpText = "Test a single password or NTLM hash against a masterkey file.")]
        class TestOptions: GlobalOptions
        {
            [Option('p', "password", Required = false, HelpText = "Password or NTLM hash for user.")]
            public string Password { get; set; }

            [Option('l', "local", Required = false, Default = false, HelpText = "Masterkey is from non Domain Joined machine.")]
            public bool Local { get; set; }
        }

        [Verb("preferred", HelpText = "Parse a DPAPI Preferrred file to extract the preferred masterkey GUID.")]
        class PreferredOptions
        {
            [Option('f', "file", Required = true, HelpText = "Path to Peferred file.")]
            public string PreferredFile { get; set; }
        }

        [Verb("hash", HelpText = "Dump masterkey hash in john/hashcat format.")]
        class HashOptions : GlobalOptions
        {
            [Option('c', "context", Required = false, Default = 3, 
                HelpText = "Context. Default is 3 for Domain Joined machines above Windows 10 1607. " +
                "Use context 2 for older systems (pre-1607)." +
                "If the machine is non Domain Joined, set the context to 1.")]
            public int Context { get; set; }
        }

        [Verb("crack", HelpText = "Attempt to crack a masterkey using a dictionary of passwords or NTLM/SHA1 hashes.")]
        class CrackOptions: GlobalOptions
        {
            [Option('d', "dictionary", Required = true, HelpText = "Dictionary of passwords or NTLM/SHA1 hashes.")]
            public string Dictionary { get; set; }

            [Option('l', "local", Required = false, Default = false, HelpText = "Masterkey is from non Domain Joined machine.")]
            public bool Local { get; set; }

            [Option('n', "ntlm", Required = false, Default = false, HelpText = "Dictionary is NTLM hashes (skip hashing).")]
            public bool IsNtlm { get; set; }

            [Option("sha1", Required = false, Default = false, HelpText = "Dictionary is SHA1 hashes (skip hashing).")]
            public bool IsSha1 { get; set; }
        }

        private static Type[] LoadVerbs()
        {
            return Assembly.GetExecutingAssembly().GetTypes()
                .Where(t => t.GetCustomAttribute<VerbAttribute>() != null).ToArray();
        }

        public static void HandleErrors(object obj)
        {
        }

        private static void Run(object obj)
        {
            Console.WriteLine();
            switch (obj)
            {
                case TestOptions opt:
                    TestSingle(opt);
                    break;
                case CrackOptions opt:
                    DictionaryAttack(opt);
                    break;
                case PreferredOptions opt:
                    GetPreferredKey(opt);
                    break;
                case HashOptions opt:
                    DumpHash(opt);
                    break;
                default:
                    break;
            }
        }

        private static void GetPreferredKey(PreferredOptions opt)
        {
            if (!File.Exists(opt.PreferredFile) || !(new FileInfo(opt.PreferredFile).Length == 24))
                throw new ArgumentException("input file is not valid");

            byte[] guidBytes = new byte[16];
            using (BinaryReader reader = new BinaryReader(new FileStream(opt.PreferredFile, FileMode.Open)))
            {
                reader.Read(guidBytes, 0, 16);
            }
            var guid = new Guid(guidBytes).ToString();
            Console.WriteLine($"[+] Preferred: {guid}");
        }

        public static string GetSidFromBKFile(string bkFile)
        {
            string sid = string.Empty;
            byte[] bkBytes = File.ReadAllBytes(bkFile);

            if (bkBytes.Length > 28)
            {
                try
                {
                    SecurityIdentifier sidObj = new SecurityIdentifier(bkBytes, 0x3c);
                    sid = sidObj.Value;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to parse BK file: {ex.Message}");
                }
            }
            return sid;
        }

        private static string TryGetSid(string masterKeyPath)
        {
            string sid = string.Empty;

            // First check if there is a BK file we can get the SID from
            foreach (string file in Directory.GetFiles(Path.GetDirectoryName(masterKeyPath), "*", SearchOption.AllDirectories))
            {
                if (Path.GetFileName(file).StartsWith("BK-"))
                {
                    sid = GetSidFromBKFile(file);
                    if (!string.IsNullOrEmpty(sid))
                    {
                        Console.WriteLine($"[*] Found SID from BK file: {sid}");
                        break;
                    }
                }
            }

            // Fall back to directory name
            if (string.IsNullOrEmpty(sid) && Regex.IsMatch(Path.GetDirectoryName(masterKeyPath), 
                @"^S-\d-\d+-(\d+-){1,14}\d+$", RegexOptions.IgnoreCase))
            {
                sid = Path.GetDirectoryName(masterKeyPath);
                Console.WriteLine($"[*] Found SID from directory: {sid}");
            }
            else if (string.IsNullOrEmpty(sid))
            {
                Console.WriteLine("Could not determine users's SID. " +
                    "Ensure that DPAPI Masterkey directory name contains the user SID, " +
                    "OR that the BK-<NETBIOSDOMAINNAME> file is present");
            }
            return sid;
        }

        private static void TestSingle(TestOptions opt)
        {
            if (!Regex.IsMatch(Path.GetFileName(opt.MasterKeyPath), masterKeyRegex) 
                || !File.Exists(opt.MasterKeyPath))
            {
                Console.WriteLine("[!] Provided file does not appear to be a DPAPI Master Key file");
                return;
            }

            string sid = opt.Sid;
            if (string.IsNullOrEmpty(sid))
                sid = TryGetSid(opt.MasterKeyPath);
            if (string.IsNullOrEmpty(sid))
                return;

            bool isNtlm = Regex.IsMatch(opt.Password, "^[a-f0-9]{32}$", RegexOptions.IgnoreCase);
            bool isSha1 = Regex.IsMatch(opt.Password, "^[a-f0-9]{40}$", RegexOptions.IgnoreCase);

            if (opt.Local && isNtlm && !isSha1)
            {
                Console.WriteLine("[!] NTLM Hash provided, but the Masterkey is from a non Domain Joined Machine");
                Console.WriteLine("[!] This will not work, since SHA1 is used instead of RC4. Use a password or SHA1 instead.");
                return;
            }

            if (IsValidKey(opt.MasterKeyPath, sid, opt.Password, isNtlm || isSha1, !opt.Local))
                Console.WriteLine("[+] {0} is VALID", isNtlm ? "NTLM" : "Password");
            else
                Console.WriteLine("[!] {0} is NOT valid", isNtlm ? "NTLM" : "Password");
        }

        private static void DictionaryAttack(CrackOptions opt)
        {
            if (!Regex.IsMatch(Path.GetFileName(opt.MasterKeyPath), masterKeyRegex) || !File.Exists(opt.MasterKeyPath))
            {
                Console.WriteLine("[!] Provided file does not appear to be a DPAPI Master Key file");
                return;
            }

            string sid = opt.Sid;
            if (string.IsNullOrEmpty(sid))
                sid = TryGetSid(opt.MasterKeyPath);
            if (string.IsNullOrEmpty(sid))
                return;

            if (opt.IsNtlm && opt.Local)
            {
                Console.WriteLine("[!] You have specified that the MasterKey file is from a non Domain Joined machine");
                Console.WriteLine("[!] Providing NTLM hashes will not work. Provide a list of passwords or SHA1 instead.");
                return;
            }

            Console.WriteLine("[*] Running with {0} dictionary", opt.IsNtlm ? "NTLM" : "password");
            Console.WriteLine("[*] Started at {0}", DateTime.Now);

            foreach (string line in File.ReadLines(opt.Dictionary))
            {
                if (IsValidKey(opt.MasterKeyPath, sid, line, opt.IsNtlm || opt.IsSha1, !opt.Local))
                {
                    Console.WriteLine("[+] Success! Found {0}: {1}", (opt.IsNtlm || opt.IsSha1) ? "Hash" : "Password", line);
                    break;
                }
            }
            Console.WriteLine("[*] Finished at {0}", DateTime.Now);
        }

        private static bool IsValidKey(string masterKeyPath, string sid, string password, 
            bool pth, bool domain = true)
        {

            byte[] masterKeyBytes = File.ReadAllBytes(masterKeyPath);
            byte[] hmacBytes = Dpapi.CalculateKeys(password, sid, pth, domain);

            try
            {
                // Try and decrypt masterKey
                KeyValuePair<string, string> plaintextMasterKey = Dpapi.DecryptMasterKeyWithSha(masterKeyBytes, hmacBytes);
                Console.WriteLine($"[+] Decrypted: {plaintextMasterKey.Key}:{plaintextMasterKey.Value}");
                return true;
            }
            catch {}
            return false;
        }
        private static void DumpHash(HashOptions opt)
        {
            if (!Regex.IsMatch(Path.GetFileName(opt.MasterKeyPath), masterKeyRegex)
                || !File.Exists(opt.MasterKeyPath))
            {
                Console.WriteLine("[!] Provided file does not appear to be a DPAPI Master Key file");
                return;
            }

            string sid = opt.Sid;
            if (string.IsNullOrEmpty(sid))
                sid = TryGetSid(opt.MasterKeyPath);
            if (string.IsNullOrEmpty(sid))
                return;

            string hash = Dpapi.FormatHash(File.ReadAllBytes(opt.MasterKeyPath), sid, opt.Context);
            Console.WriteLine($"[+] Hash: \n{hash}");
        }

        static void Main(string[] args)
        {
            var types = LoadVerbs();

            try
            {
                Parser.Default.ParseArguments(args, types)
                .WithParsed(Run)
                .WithNotParsed(HandleErrors);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }
    }
}
