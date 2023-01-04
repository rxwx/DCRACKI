using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using PBKDF2;

namespace SharpDPAPI
{
    public class Dpapi
    {
        public static byte[] CalculateKeys(string password, string userSID, 
            bool pth = false, bool domain = true)
        {
            var utf16pass = Encoding.Unicode.GetBytes(password);
            var utf16sid = Encoding.Unicode.GetBytes(userSID);

            var utf16sidfinal = new byte[utf16sid.Length + 2];
            utf16sid.CopyTo(utf16sidfinal, 0);
            utf16sidfinal[utf16sidfinal.Length - 2] = 0x00;

            byte[] derived = null;
            byte[] finalKey = null;

            if (!domain)
            {
                if (pth)
                {
                    // Pass-the-hash (skip initial SHA1 phase)
                    // Note: SHA1 hash must be in format: SHA1(UTF16LE(password))
                    // e.g. from mimikatz' sekurlsa::msv
                    derived = Helpers.ConvertHexStringToByteArray(password);
                }
                else
                {
                    //Calculate SHA1 from user password
                    using (var sha1 = new SHA1Managed())
                    {
                        derived = sha1.ComputeHash(utf16pass);
                    }
                }
            }
            else
            {
                //Calculate NTLM from user password. Kerberos's RC4_HMAC key is the NTLM hash
                string rc4Hash = pth ? password : Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, password);

                var ntlm = Helpers.ConvertHexStringToByteArray(rc4Hash);

                //Calculate SHA1 of NTLM from user password
                byte[] tmpbytes1;

                using (var hMACSHA256 = new HMACSHA256())
                {
                    var deriveBytes = new Pbkdf2(hMACSHA256, ntlm, utf16sid, 10000);
                    tmpbytes1 = deriveBytes.GetBytes(32, "sha256");
                }

                using (var hMACSHA256 = new HMACSHA256())
                {
                    var deriveBytes = new Pbkdf2(hMACSHA256, tmpbytes1, utf16sid, 1);
                    derived = deriveBytes.GetBytes(16, "sha256");
                }
            }

            using (var hmac = new HMACSHA1(derived))
            {
                finalKey = hmac.ComputeHash(utf16sidfinal);
            }
            return finalKey;
        }

        private static byte[] DerivePreKey(byte[] shaBytes, int algHash, byte[] salt, int rounds)
        {
            byte[] derivedPreKey;

            switch (algHash)
            {
                // CALG_SHA_512 == 32782
                case 32782:
                    {
                        // derive the "Pbkdf2/SHA512" key for the masterkey, using MS' silliness
                        using (var hmac = new HMACSHA512())
                        {
                            var df = new Pbkdf2(hmac, shaBytes, salt, rounds);
                            derivedPreKey = df.GetBytes(48);
                        }

                        break;
                    }

                case 32777:
                    {
                        // derive the "Pbkdf2/SHA1" key for the masterkey, using MS' silliness
                        using (var hmac = new HMACSHA1())
                        {
                            var df = new Pbkdf2(hmac, shaBytes, salt, rounds);
                            derivedPreKey = df.GetBytes(32);
                        }

                        break;
                    }

                default:
                    throw new Exception($"alg hash  '{algHash} / 0x{algHash:X8}' not currently supported!");
            }

            return derivedPreKey;
        }

        private static bool IsValidHMAC(byte[] plaintextBytes, byte[] masterKeyFull, byte[] shaBytes, Type HMACType)
        {
            var obj = (HMAC)Activator.CreateInstance(HMACType);
            var HMACLen = obj.HashSize / 8;

            // we're HMAC'ing the first 16 bytes of the decrypted buffer with the shaBytes as the key
            var hmacSalt = new byte[16];
            Array.Copy(plaintextBytes, hmacSalt, 16);

            var hmac = new byte[HMACLen];
            Array.Copy(plaintextBytes, 16, hmac, 0, hmac.Length);

            var hmac1 = (HMAC)Activator.CreateInstance(HMACType, shaBytes);
            var round1Hmac = hmac1.ComputeHash(hmacSalt);

            // round 2
            var hmac2 = (HMAC)Activator.CreateInstance(HMACType, round1Hmac);
            var round2Hmac = hmac2.ComputeHash(masterKeyFull);

            // compare the second HMAC value to the original plaintextBytes, starting at index 16
            if (hmac.SequenceEqual(round2Hmac))
            {
                return true;
            }
            return false;
        }

        private static byte[] DecryptTripleDESHmac(byte[] shaBytes, byte[] final, byte[] encData)
        {
            var desCryptoProvider = new TripleDESCryptoServiceProvider();

            var ivBytes = new byte[8];
            var key = new byte[24];

            Array.Copy(final, 24, ivBytes, 0, 8);
            Array.Copy(final, 0, key, 0, 24);

            desCryptoProvider.Key = key;
            desCryptoProvider.IV = ivBytes;
            desCryptoProvider.Mode = CipherMode.CBC;
            desCryptoProvider.Padding = PaddingMode.Zeros;

            var plaintextBytes = desCryptoProvider.CreateDecryptor().TransformFinalBlock(encData, 0, encData.Length);
            var masterKeyFull = new byte[64];
            Array.Copy(plaintextBytes, plaintextBytes.Length - masterKeyFull.Length, masterKeyFull, 0, masterKeyFull.Length);

            using (var sha1 = new SHA1Managed())
            {
                var masterKeySha1 = sha1.ComputeHash(masterKeyFull);

                if (!IsValidHMAC(plaintextBytes, masterKeyFull, shaBytes, typeof(HMACSHA1)))
                    throw new Exception("HMAC integrity check failed!");

                return masterKeySha1;
            }
        }

        private static byte[] DecryptAes256HmacSha512(byte[] shaBytes, byte[] final, byte[] encData)
        {
            var aesCryptoProvider = new AesManaged();

            var ivBytes = new byte[16];
            Array.Copy(final, 32, ivBytes, 0, 16);

            var key = new byte[32];
            Array.Copy(final, 0, key, 0, 32);

            aesCryptoProvider.Key = key;
            aesCryptoProvider.IV = ivBytes;
            aesCryptoProvider.Mode = CipherMode.CBC;
            aesCryptoProvider.Padding = PaddingMode.Zeros;

            // decrypt the encrypted data using the Pbkdf2-derived key
            var plaintextBytes = aesCryptoProvider.CreateDecryptor().TransformFinalBlock(encData, 0, encData.Length);
            var masterKeyFull = new byte[64];
            Array.Copy(plaintextBytes, plaintextBytes.Length - masterKeyFull.Length, masterKeyFull, 0, masterKeyFull.Length);

            using (var sha1 = new SHA1Managed())
            {
                var masterKeySha1 = sha1.ComputeHash(masterKeyFull);

                if (!IsValidHMAC(plaintextBytes, masterKeyFull, shaBytes, typeof(HMACSHA512)))
                    throw new Exception("HMAC integrity check failed!");

                return masterKeySha1;
            }
        }

        public static byte[] GetMasterKey(byte[] masterKeyBytes)
        {
            // helper to extract domain masterkey subbytes from a master key blob

            var offset = 96;

            var masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 4 * 8; // skip the key length headers

            var masterKeySubBytes = new byte[masterKeyLen];
            Array.Copy(masterKeyBytes, offset, masterKeySubBytes, 0, masterKeyLen);

            return masterKeySubBytes;
        }

        public static string FormatHash(byte[] masterKeyBytes, string sid, int context = 3)
        {
            var mkBytes = GetMasterKey(masterKeyBytes);

            var offset = 4;
            var salt = new byte[16];
            Array.Copy(mkBytes, 4, salt, 0, 16);
            offset += 16;

            var rounds = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algHash = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algCrypt = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var encData = new byte[mkBytes.Length - offset];
            Array.Copy(mkBytes, offset, encData, 0, encData.Length);

            int version = 0;
            string cipherAlgo;
            string hmacAlgo;

            switch (algCrypt)
            {
                case 26128 when (algHash == 32782 || algHash == 32772):
                    version = 2;
                    cipherAlgo = "aes256";
                    hmacAlgo = "sha512";
                    break;
                case 26115 when (algHash == 32777):
                    version = 1;
                    cipherAlgo = "des3";
                    hmacAlgo = "sha1";
                    break;
                default:
                    throw new Exception($"Alg crypt '{algCrypt} / 0x{algCrypt:X8}' not currently supported!");
            }

            string hash = string.Format(
                "$DPAPImk${0}*{1}*{2}*{3}*{4}*{5}*{6}*{7}*{8}",
                version,
                context,
                sid,
                cipherAlgo,
                hmacAlgo,
                rounds,
                Helpers.ByteArrayToString(salt),
                encData.Length * 2,
                Helpers.ByteArrayToString(encData)
                );
            return hash;
        }


        public static KeyValuePair<string, string> DecryptMasterKeyWithSha(byte[] masterKeyBytes, byte[] shaBytes)
        {
            // takes masterkey bytes and SYSTEM_DPAPI masterkey sha bytes, returns a dictionary of guid:sha1 masterkey mappings
            var guidMasterKey = $"{{{Encoding.Unicode.GetString(masterKeyBytes, 12, 72)}}}";

            var mkBytes = GetMasterKey(masterKeyBytes);

            var offset = 4;
            var salt = new byte[16];
            Array.Copy(mkBytes, 4, salt, 0, 16);
            offset += 16;

            var rounds = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algHash = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algCrypt = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var encData = new byte[mkBytes.Length - offset];
            Array.Copy(mkBytes, offset, encData, 0, encData.Length);

            var derivedPreKey = DerivePreKey(shaBytes, algHash, salt, rounds);

            switch (algCrypt)
            {
                // CALG_AES_256 == 26128 , CALG_SHA_512 == 32782
                case 26128 when (algHash == 32782|| algHash == 32772):
                    {
                        var masterKeySha1 = DecryptAes256HmacSha512(shaBytes, derivedPreKey, encData);
                        var masterKeyStr = BitConverter.ToString(masterKeySha1).Replace("-", "");

                        return new KeyValuePair<string, string>(guidMasterKey, masterKeyStr);
                    }

                // Support for 32777(CALG_HMAC) / 26115(CALG_3DES)
                case 26115 when (algHash == 32777):
                    {
                        var masterKeySha1 = DecryptTripleDESHmac(shaBytes, derivedPreKey, encData);
                        var masterKeyStr = BitConverter.ToString(masterKeySha1).Replace("-", "");

                        return new KeyValuePair<string, string>(guidMasterKey, masterKeyStr);
                    }

                default:
                    throw new Exception($"Alg crypt '{algCrypt} / 0x{algCrypt:X8}' not currently supported!");
            }

        }
    }
}
