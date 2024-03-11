using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class AesAlgorithm
{
    static void Main()
    {
        Console.WriteLine("Iveskite teksta kuri norite sifruoti arba desifruoti:");
        string inputText = Console.ReadLine();

        Console.WriteLine("Iveskite rakta:");
        string keyInput = Console.ReadLine();
        byte[] key = Encoding.UTF8.GetBytes(keyInput.PadRight(32, ' ').Substring(0, 32));

        Console.WriteLine("Pasirinkite:\n1. Sifruoti\n2. Desifruoti");
        int choice = Convert.ToInt32(Console.ReadLine());

        Console.WriteLine("Pasirinkite moda(1-ECB, 2-CBC, 3-CFB):");
        int modeInput = int.Parse(Console.ReadLine());
        CipherMode mode = CipherMode.CBC;
        switch (modeInput)
        {
            case 1:
                mode = CipherMode.ECB;
                break;
            case 2:
                mode = CipherMode.CBC;
                break;
            case 3:
                mode = CipherMode.CFB;
                break;
          
        }

        string outputText = "";
        switch (choice)
        {
            case 1: // Sifruoti
                outputText = EncryptText(inputText, key, mode);
                Console.WriteLine("Sifruotas tekstas:");
                Console.WriteLine(outputText);
                Console.WriteLine("Iveskite failo pavadinima kur norite saugoti sifruota teksta:");
                string encryptFilename = Console.ReadLine();
                File.WriteAllText(encryptFilename, outputText);
                Console.WriteLine("Sifruotas tekstas issaugotas i faila: " + encryptFilename);
                break;
            case 2: // Desifruoti
                string decryptText = DecryptText(inputText, key, mode);
                Console.WriteLine("Desifruotas tekstas:");
                Console.WriteLine(decryptText);
                Console.WriteLine("Iveskite failo pavadinima is kurio skaitysite sifruota teksta:");
                string decryptFilename = Console.ReadLine();
                string encryptedTextFromFile = File.ReadAllText(decryptFilename);
                outputText = DecryptText(encryptedTextFromFile, key, mode);
                Console.WriteLine("Desifruotas tekstas:");
                Console.WriteLine(outputText);
                break;
        }

        Console.ReadKey();
    }

    public static string EncryptText(string input, byte[] key, CipherMode mode)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Mode = mode;
            aesAlg.Key = key;
            aesAlg.Padding = PaddingMode.PKCS7;

            aesAlg.GenerateIV();
            byte[] iv = aesAlg.IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, iv);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(input);
                    }
                }

                byte[] encrypted = msEncrypt.ToArray();
                byte[] result = new byte[iv.Length + encrypted.Length];
                Array.Copy(iv, 0, result, 0, iv.Length);
                Array.Copy(encrypted, 0, result, iv.Length, encrypted.Length);

                return Convert.ToBase64String(result);
            }
        }
    }

    public static string DecryptText(string input, byte[] key, CipherMode mode)
    {
        byte[] fullCipher = Convert.FromBase64String(input);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Mode = mode;
            aesAlg.Key = key;
            aesAlg.Padding = PaddingMode.PKCS7;

            byte[] iv = new byte[aesAlg.BlockSize / 8];
            Array.Copy(fullCipher, 0, iv, 0, iv.Length);
            byte[] cipherText = new byte[fullCipher.Length - iv.Length];
            Array.Copy(fullCipher, iv.Length, cipherText, 0, cipherText.Length);

            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, iv);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
}