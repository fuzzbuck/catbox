using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace catbox.Utils
{
    public static class Parsers
    {
        private static readonly uint[] _lookup32Unsafe = CreateLookup32Unsafe();
        private static readonly unsafe uint* _lookup32UnsafeP = (uint*)GCHandle.Alloc(_lookup32Unsafe,GCHandleType.Pinned).AddrOfPinnedObject();

        private static uint[] CreateLookup32Unsafe()
        {
            var result = new uint[256];
            for (int i = 0; i < 256; i++)
            {
                string s=i.ToString("X2");
                if(BitConverter.IsLittleEndian)
                    result[i] = s[0] + ((uint)s[1] << 16);
                else
                    result[i] = s[1] + ((uint)s[0] << 16);
            }
            return result;
        }

        public static unsafe string ByteArrayToHexViaLookup32Unsafe(byte[] bytes)
        {
            var lookupP = _lookup32UnsafeP;
            var result = new char[bytes.Length * 2];
            fixed(byte* bytesP = bytes)
            fixed (char* resultP = result)
            {
                uint* resultP2 = (uint*)resultP;
                for (int i = 0; i < bytes.Length; i++)
                {
                    resultP2[i] = lookupP[bytesP[i]];
                }
            }
            return new string(result).ToLower();
        }
    }
    
    public class Crypto
    {
        public class CryptoJSFormat
        {
            public string ct = "";
            public string iv = "";
            public string s = "";
        }
        private static byte[] parseHex(string hex) {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((getHexVal(hex[i << 1]) << 4) + getHexVal(hex[(i << 1) + 1]));
            }

            return arr;
        }

        private static int getHexVal(char hex) {
            int val = hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        public static string Decrypt(string json_string, string password)
        {
            CryptoJSFormat json = JsonConvert.DeserializeObject<CryptoJSFormat>(json_string);
            if (json.s == null || json.s.Length < 1)
                return null;

            try
            {
                var hashKey = new OpenSslCompatDeriveBytes(password,
                    parseHex(json.s));

                byte[] key = hashKey.GetBytes(32);

                return DecryptDirect(json.ct, key, parseHex(json.iv));
            }catch(Exception)
            {
                return null;
            }
        }
        
        private static string DecryptDirect(string cipherData, byte[] key, byte[] iv)
        {

            try
            {
                using (var rijndaelManaged =
                    new RijndaelManaged {Key = key, IV = iv, Mode = CipherMode.CBC, BlockSize = 128})
                using (var memoryStream = 
                    new MemoryStream(Convert.FromBase64String(cipherData)))
                using (var cryptoStream =
                    new CryptoStream(memoryStream,
                        rijndaelManaged.CreateDecryptor(key, iv),
                        CryptoStreamMode.Read))
                {

                    byte[] bytes;
                    using (var output = new MemoryStream())
                    {
                        cryptoStream.CopyTo(output);
                        bytes = output.ToArray();

                        return Convert.ToBase64String(bytes);
                    }
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                Console.WriteLine(e.StackTrace);
                return null;
            }
        }
        
        public static string Encrypt(string plainText, string password = "BadgersAreAwesome")
    {
        if (plainText == null)
            throw new ArgumentNullException("plainText");
        if (password == null)
            throw new ArgumentNullException("password");
        
        // Will return this
        var CryptoJSFormat = new CryptoJSFormat();

        // Generate random 8 byte salt
        Random rnd = new Random();
        
        byte[] salt = new byte[8];
        rnd.NextBytes(salt);
        
        CryptoJSFormat.s = Parsers.ByteArrayToHexViaLookup32Unsafe(salt);
        // Convert plain text to bytes
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        
        // create new password derived bytes using password/salt
        using (OpenSslCompatDeriveBytes pdb = new OpenSslCompatDeriveBytes(password, salt))
        {
            using (Rijndael aes = RijndaelManaged.Create())
            {
                // Generate key and iv from password/salt and pass to aes
                aes.Key = pdb.GetBytes(aes.KeySize / 8);
                aes.IV = pdb.GetBytes(aes.BlockSize / 8);
                aes.Mode = CipherMode.CBC;
                aes.BlockSize = 128;
                
                CryptoJSFormat.iv = Parsers.ByteArrayToHexViaLookup32Unsafe(aes.IV);

                // Open a new memory stream to write the encrypted data to
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create a crypto stream to perform encryption
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        // write encrypted bytes to memory
                        cs.Write(plainBytes, 0, plainBytes.Length);
                    }
                    // get the cipher bytes from memory
                    byte[] cipherBytes = ms.ToArray();
                    
                    // convert cipher array to base 64 string
                    CryptoJSFormat.ct = Convert.ToBase64String(cipherBytes);
                }
                aes.Clear();
            }
        }

        return JsonConvert.SerializeObject(CryptoJSFormat);
    }
        
    }
    
    /// <summary>
    /// Derives a key from a password using an OpenSSL-compatible version of the PBKDF1 algorithm.
    /// </summary>
    /// <remarks>
    /// based on the OpenSSL EVP_BytesToKey method for generating key and iv
    /// http://www.openssl.org/docs/crypto/EVP_BytesToKey.html
    /// </remarks>
    public class OpenSslCompatDeriveBytes : DeriveBytes
    {
        private readonly byte[] _data;
        private readonly HashAlgorithm _hash;
        private readonly int _iterations;
        private readonly byte[] _salt;
        private byte[] _currentHash;
        private int _hashListReadIndex;
        private List<byte> _hashList;

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSslCompatDeriveBytes"/> class specifying the password, key salt, hash name, and iterations to use to derive the key.
        /// </summary>
        /// <param name="password">The password for which to derive the key.</param>
        /// <param name="salt">The key salt to use to derive the key.</param>
        /// <param name="hashName">The name of the hash algorithm for the operation. (e.g. MD5 or SHA1)</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        public OpenSslCompatDeriveBytes(string password, byte[] salt, string hashName="MD5", int iterations=1) : this(new UTF8Encoding(false).GetBytes(password), salt, hashName, iterations)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSslCompatDeriveBytes"/> class specifying the password, key salt, hash name, and iterations to use to derive the key.
        /// </summary>
        /// <param name="password">The password for which to derive the key.</param>
        /// <param name="salt">The key salt to use to derive the key.</param>
        /// <param name="hashName">The name of the hash algorithm for the operation. (e.g. MD5 or SHA1)</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        public OpenSslCompatDeriveBytes(byte[] password, byte[] salt, string hashName, int iterations)
        {
            if (iterations <= 0)
                throw new ArgumentOutOfRangeException("iterations", iterations, "iterations is out of range. Positive number required");

            _data = password;
            _salt = salt;
            _hash = HashAlgorithm.Create(hashName);
            _iterations = iterations;
        }

        /// <summary>
        /// Returns a pseudo-random key from a password, salt and iteration count.
        /// </summary>
        /// <param name="cb">The number of pseudo-random key bytes to generate.</param>
        /// <returns>A byte array filled with pseudo-random key bytes.</returns>
        public override byte[] GetBytes(int cb)
        {
            if (cb <= 0)
                throw new ArgumentOutOfRangeException("cb", cb, "cb is out of range. Positive number required.");

            if (_currentHash == null)
            {
                _hashList = new List<byte>();
                _currentHash = new byte[0];
                _hashListReadIndex = 0;

                int preHashLength = _data.Length + ((_salt != null) ? _salt.Length : 0);
                var preHash = new byte[preHashLength];

                Buffer.BlockCopy(_data, 0, preHash, 0, _data.Length);
                if (_salt != null)
                    Buffer.BlockCopy(_salt, 0, preHash, _data.Length, _salt.Length);

                _currentHash = _hash.ComputeHash(preHash);

                for (int i = 1; i < _iterations; i++)
                {
                    _currentHash = _hash.ComputeHash(_currentHash);
                }

                _hashList.AddRange(_currentHash);
            }

            while (_hashList.Count < (cb + _hashListReadIndex))
            {
                int preHashLength = _currentHash.Length + _data.Length + ((_salt != null) ? _salt.Length : 0);
                var preHash = new byte[preHashLength];

                Buffer.BlockCopy(_currentHash, 0, preHash, 0, _currentHash.Length);
                Buffer.BlockCopy(_data, 0, preHash, _currentHash.Length, _data.Length);
                if (_salt != null)
                    Buffer.BlockCopy(_salt, 0, preHash, _currentHash.Length + _data.Length, _salt.Length);

                _currentHash = _hash.ComputeHash(preHash);

                for (int i = 1; i < _iterations; i++)
                {
                    _currentHash = _hash.ComputeHash(_currentHash);
                }

                _hashList.AddRange(_currentHash);
            }

            byte[] dst = new byte[cb];
            _hashList.CopyTo(_hashListReadIndex, dst, 0, cb);
            _hashListReadIndex += cb;

            return dst;
        }

        /// <summary>
        /// Resets the state of the operation.
        /// </summary>
        public override void Reset()
        {
            _hashListReadIndex = 0;
            _currentHash = null;
            _hashList = null;
        }
    }
}