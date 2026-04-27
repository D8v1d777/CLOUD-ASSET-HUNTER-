using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Net.Security;

namespace CloudHunter;

class Program
{
    private static readonly string[] UserAgents = new[]
    {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    };

    static async Task Main(string[] args)
    {
        Console.WriteLine("Initializing CloudHunter Phase 3...");

        var targetsFile = "targets.txt";
        var wordsFile = "words.txt";

        if (!File.Exists(targetsFile) || !File.Exists(wordsFile))
        {
            Console.WriteLine("Missing targets.txt or words.txt. Exiting.");
            return;
        }

        var targets = await File.ReadAllLinesAsync(targetsFile);
        var words = await File.ReadAllLinesAsync(wordsFile);

        var finalTargets = new List<string>();
        foreach (var t in targets)
        {
            if (string.IsNullOrWhiteSpace(t)) continue;
            if (t.StartsWith("seed:"))
            {
                var domain = t.Replace("seed:", "").Trim();
                var subdomains = await ReconEngine.AutoSeedAsync(domain);
                finalTargets.AddRange(subdomains);
            }
            else
            {
                finalTargets.Add(t.Trim());
            }
        }
        
        // Deduplicate final targets
        finalTargets = finalTargets.Distinct().ToList();
        
        var channel = Channel.CreateBounded<(string url, string cloud)>(new BoundedChannelOptions(1000)
        {
            FullMode = BoundedChannelFullMode.Wait
        });
        
        var semaphore = new SemaphoreSlim(100);
        var tracker = new Tracker();
        
        var proxiesFile = "proxies.txt";
        var clients = new List<HttpClient>();
        
        if (File.Exists(proxiesFile))
        {
            var proxyLines = await File.ReadAllLinesAsync(proxiesFile);
            foreach (var p in proxyLines)
            {
                if (!string.IsNullOrWhiteSpace(p))
                    clients.Add(CreateConfiguredClient(p.Trim()));
            }
        }
        
        if (clients.Count == 0)
        {
            clients.Add(CreateConfiguredClient(null));
        }

        // Permutation generator
        var generatorTask = Task.Run(async () =>
        {
            foreach (var t in finalTargets)
            {
                if (string.IsNullOrWhiteSpace(t)) continue;
                foreach (var w in words)
                {
                    if (string.IsNullOrWhiteSpace(w)) continue;
                    
                    // AWS S3
                    await channel.Writer.WriteAsync(($"https://{w}.{t}.s3.amazonaws.com", "AWS_S3"));
                    
                    // Azure Blob
                    var cleanTarget = t.Replace(".", "");
                    if (cleanTarget.Length >= 3 && cleanTarget.Length <= 24) // Azure storage account naming rules
                    {
                        await channel.Writer.WriteAsync(($"https://{cleanTarget}.blob.core.windows.net/{w}?restype=container&comp=list", "AZURE_BLOB"));
                    }
                    
                    // GCP GCS
                    await channel.Writer.WriteAsync(($"https://storage.googleapis.com/storage/v1/b/{w}-{t}/o", "GCP_GCS"));
                    await channel.Writer.WriteAsync(($"https://storage.googleapis.com/storage/v1/b/{t}-{w}/o", "GCP_GCS"));
                }
                
                // Rate control between domain batches
                await Task.Delay(200);
            }
            channel.Writer.Complete();
        });

        // Async dispatcher
        var results = new List<ValidationResult>();
        var resultsLock = new object();

        var consumerTask = Task.Run(async () =>
        {
            var tasks = new List<Task>();
            await foreach (var item in channel.Reader.ReadAllAsync())
            {
                await semaphore.WaitAsync();
                
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var rand = new Random();
                        var client = clients[rand.Next(clients.Count)];
                        
                        using var req = new HttpRequestMessage(HttpMethod.Get, item.url);
                        req.Headers.TryAddWithoutValidation("User-Agent", UserAgents[rand.Next(UserAgents.Length)]);
                        req.Headers.TryAddWithoutValidation("Accept", "*/*");
                        req.Headers.TryAddWithoutValidation("Accept-Language", "en-US,en;q=0.9");
                        
                        var res = await client.SendAsync(req);
                        var status = (int)res.StatusCode;
                        
                        if (status == 200 || status == 403)
                        {
                            var validation = await CloudValidator.ValidateAsync(res, item.url, item.cloud, client);
                            if (validation.Confidence >= 0.50)
                            {
                                lock(resultsLock)
                                {
                                    results.Add(validation);
                                    tracker.UpsertAsset(validation, "OPEN");
                                }
                            }
                        }
                    }
                    catch (Exception)
                    {
                        // timeout/dns fail
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }
            await Task.WhenAll(tasks);
        });

        await Task.WhenAll(generatorTask, consumerTask);

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        var jsonOutput = JsonSerializer.Serialize(results, jsonOptions);
        
        await File.WriteAllTextAsync("validated_results.json", jsonOutput);
        
        // Output Diffs & Alert
        var diffs = tracker.GetDiff();
        if (diffs.Count > 0)
        {
            var jsonDiff = JsonSerializer.Serialize(diffs, jsonOptions);
            await File.WriteAllTextAsync("new_exposed.json", jsonDiff);
            Console.WriteLine($"Found {diffs.Count} NEW or upgraded exposures. Firing alerts...");
            await AlertEngine.FireAlertAsync(diffs);
        }

        Console.WriteLine($"Scan complete. {results.Count} validated endpoints discovered. Results saved to validated_results.json.");
        
        foreach (var c in clients) c.Dispose();
    }

    static HttpClient CreateConfiguredClient(string proxyStr)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            MaxConnectionsPerServer = 100,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
            }
        };

        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            try
            {
                handler.SslOptions.CipherSuitesPolicy = new CipherSuitesPolicy(new[]
                {
                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                });
            }
            catch { }
        }

        if (!string.IsNullOrEmpty(proxyStr))
        {
            handler.UseProxy = true;
            handler.Proxy = new System.Net.WebProxy(proxyStr);
        }

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
    }
}
