using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    // ==== SETTINGS ====
    static string P12_PATH = "yourfile.p12"; // PKCS#12 file path
    static int MAX_LENGTH = 4;
    static string CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Custom passwords to try before brute force
    static List<string> CUSTOM_PASSWORDS = new List<string>
    {
        "skibidi", "password123", "letmein", "admin"
    };

    // Discord webhook URL (leave empty "" to disable)
    static string DISCORD_WEBHOOK = "https://discord.com/api/webhooks/XXXX/XXXX";
    // ==================

    static byte[] P12_DATA;
    static long guesses = 0;
    static Stopwatch stopwatch = new Stopwatch();
    static volatile bool found = false;
    static string foundPassword = null;

    static void Main()
    {
        P12_DATA = File.ReadAllBytes(P12_PATH);
        stopwatch.Start();

        Console.WriteLine($"[+] Trying {CUSTOM_PASSWORDS.Count} custom passwords first...");
        foreach (var pwd in CUSTOM_PASSWORDS)
        {
            if (TryPassword(pwd))
            {
                ReportSuccess(pwd);
                return;
            }
        }

        for (int length = 1; length <= MAX_LENGTH; length++)
        {
            Console.WriteLine($"\n[+] Trying length {length}...");
            BruteForceLength(length);
            if (found) break;
        }

        if (!found)
            Console.WriteLine("\n[-] Password not found within given length limit.");
    }

    static void BruteForceLength(int length)
    {
        var charsetArray = CHARSET.ToCharArray();
        double total = Math.Pow(charsetArray.Length, length);
        var partitioner = Partitioner.Create(0L, (long)total);

        Parallel.ForEach(partitioner, (range, state) =>
        {
            char[] buffer = new char[length];
            for (long index = range.Item1; index < range.Item2; index++)
            {
                if (found) { state.Stop(); return; }
                IndexToPassword(index, charsetArray, buffer);
                string guess = new string(buffer);
                if (TryPassword(guess))
                {
                    found = true;
                    foundPassword = guess;
                    state.Stop();
                    return;
                }
                UpdateCounter();
            }
        });

        if (found)
            ReportSuccess(foundPassword);
    }

    static void IndexToPassword(long index, char[] charset, char[] buffer)
    {
        int baseN = charset.Length;
        for (int i = buffer.Length - 1; i >= 0; i--)
        {
            buffer[i] = charset[(int)(index % baseN)];
            index /= baseN;
        }
    }

    static bool TryPassword(string password)
    {
        try
        {
            var cert = new X509Certificate2(P12_DATA, password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
            return cert.HasPrivateKey;
        }
        catch
        {
            return false;
        }
    }

    static void UpdateCounter()
    {
        long count = Interlocked.Increment(ref guesses);
        if (count % 1000 == 0)
        {
            double speed = count / stopwatch.Elapsed.TotalSeconds;
            Console.Write($"\r{count} passwords guessed | {speed:F2} guesses/sec");
        }
    }

    static void ReportSuccess(string password)
    {
        stopwatch.Stop();
        Console.WriteLine($"\n[✓] Password found: {password}");
        Console.WriteLine($"Total guesses: {guesses}");
        Console.WriteLine($"Elapsed time: {stopwatch.Elapsed.TotalSeconds:F2} sec");
        Console.WriteLine($"Average speed: {guesses / stopwatch.Elapsed.TotalSeconds:F2} guesses/sec");

        // Send Discord notification
        if (!string.IsNullOrEmpty(DISCORD_WEBHOOK))
        {
            SendDiscordMessage($"✅ PKCS#12 password found: `{password}`\nTried {guesses} guesses in {stopwatch.Elapsed.TotalSeconds:F2} sec").Wait();
        }
    }

    static async Task SendDiscordMessage(string message)
    {
        try
        {
            using (var client = new HttpClient())
            {
                var content = new StringContent("{\"content\":\"" + message + "\"}", Encoding.UTF8, "application/json");
                await client.PostAsync(DISCORD_WEBHOOK, content);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Failed to send Discord notification: {ex.Message}");
        }
    }
}
