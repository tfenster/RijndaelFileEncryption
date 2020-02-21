using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace RijndaelFileEncryption
{
    class Program
    {
        const string ENCRYPT = "encrypt";
        const string DECRYPT = "decrypt";

        static void Main(string[] args)
        {
            var builder = new ConfigurationBuilder().AddCommandLine(args);
            var config = builder.Build();

            var action = config["action"];
            if (action == null) {
                Console.WriteLine($"Don't know whether to encrypt or decrypt, please provide --action {ENCRYPT} or --action {DECRYPT}");
                Environment.Exit(1);
            }

            var file = config["file"];
            if (file == null) {
                Console.WriteLine("Don't know which file to handle, please provide --file <path>");
                Environment.Exit(1);
            }
            if (! File.Exists(file)) {
                Console.WriteLine($"File {file} doesn't exist");
                Environment.Exit(1);
            }

            var pwd = config["password"];
            if (pwd == null) {
                Console.WriteLine("Please provide a password using --password <password>");
                Environment.Exit(1);
            }

            if (action == ENCRYPT) 
                Encrypt(action, file, pwd);
            else if (action == DECRYPT)
                Decrypt(action, file, pwd);
            else {
                Console.WriteLine($"Unknown action {action}, use {ENCRYPT} or {DECRYPT}");
                Environment.Exit(1);
            }
        }

        static void Encrypt(string action, string file, string pwd) 
        {
            var input = File.ReadAllBytes(file);
            var rijn = Rijndael.Create();
            var keyGenerator = new Rfc2898DeriveBytes(pwd, 8);
            rijn.IV = keyGenerator.GetBytes( rijn.BlockSize / 8 );
            rijn.Key = keyGenerator.GetBytes( rijn.KeySize / 8 );
            
            using (var fileStream = new FileStream(file + ".enc", FileMode.OpenOrCreate)) 
            {
                fileStream.Write(keyGenerator.Salt, 0, 8);
                using (var cryptStream = new CryptoStream(fileStream, rijn.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptStream.Write(input);
                }
            }
        }

        static void Decrypt(string action, string file, string pwd) 
        {
            var fileInStream = new FileStream(file, FileMode.Open);
            var salt = new byte[8];
            fileInStream.Read(salt, 0, 8);
            var keyGenerator = new Rfc2898DeriveBytes(pwd, salt);
            var rijn = Rijndael.Create();
            rijn.IV = keyGenerator.GetBytes( rijn.BlockSize / 8 );
            rijn.Key = keyGenerator.GetBytes( rijn.KeySize / 8 );

            using (var cryptStream = new CryptoStream(fileInStream, rijn.CreateDecryptor(), CryptoStreamMode.Read))
            using (var streamReader = new StreamReader(cryptStream))
            {
                File.WriteAllText(file.Substring(0, file.Length-4), streamReader.ReadToEnd());
            }
        }
    }
}
