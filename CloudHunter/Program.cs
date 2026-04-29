using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Security;
using System.Collections.Concurrent;

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

        var targets = (await File.ReadAllLinesAsync(targetsFile)).ToList();
        var words = await File.ReadAllLinesAsync(wordsFile);
        var tracker = new Tracker();
        var planner = new ScanPlanner();
        var concurrencyManager = new AdaptiveConcurrencyManager(initial: 50, min: 10, max: 200);
        var correctionEngine = new SelfCorrectionEngine(planner, concurrencyManager);

        // Task 4: Historical prioritization & Tiering
        var topDomains = tracker.GetHistoricalTopDomains(50);
        var highSuccessDomains = topDomains.Where(x => x.HitRate > 0.05).Select(x => x.Domain).ToHashSet();

        // Permutation generator integrated with ScanPlanner
        var generatorTask = Task.Run(async () =>
        {
            foreach (var t in targets)
            {
                if (string.IsNullOrWhiteSpace(t)) continue;
                
                List<string> subTargets = new();
                ScanTier tier = ScanTier.Tier2_HighRelevance;

                if (t.StartsWith("seed:"))
                {
                    var domain = t.Replace("seed:", "").Trim();
                    subTargets = await ReconEngine.AutoSeedAsync(domain);
                    tier = ScanTier.Tier3_AutoSeed;
                }
                else
                {
                    var domain = t.Trim();
                    subTargets.Add(domain);
                    if (highSuccessDomains.Contains(domain))
                    {
                        tier = ScanTier.Tier1_HighHistorical;
                    }
                }

                foreach (var st in subTargets)
                {
                    foreach (var w in words)
                    {
                        if (string.IsNullOrWhiteSpace(w)) continue;
                        
                        await planner.EnqueueAsync(new ScanTarget($"https://{w}.{st}.s3.amazonaws.com", "AWS_S3", tier, DateTime.UtcNow), concurrencyManager.PressureRatio);
                        
                        var cleanTarget = st.Replace(".", "");
                        if (cleanTarget.Length >= 3 && cleanTarget.Length <= 24)
                        {
                            await planner.EnqueueAsync(new ScanTarget($"https://{cleanTarget}.blob.core.windows.net/{w}?restype=container&comp=list", "AZURE_BLOB", tier, DateTime.UtcNow), concurrencyManager.PressureRatio);
                        }
                        
                        await planner.EnqueueAsync(new ScanTarget($"https://storage.googleapis.com/storage/v1/b/{w}-{st}/o", "GCP_GCS", tier, DateTime.UtcNow), concurrencyManager.PressureRatio);
                    }
                }
            }
        });

        // Task 1 & 2: Adaptive Concurrency and Domain Throttling
        var domainThrottle = new DomainThrottle(maxPerDomain: 5);
        var metrics = new SystemMetrics();
        var signalMetrics = tracker.GetSignalMetrics(); // Task 5: Pre-fetch signal metrics for feedback loop
        
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

        // Dispatcher using ScanPlanner
        var results = new List<ValidationResult>();
        var resultsLock = new object();
        var cts = new CancellationTokenSource();

        // Dispatcher using a fixed worker pool for performance and memory stability.
        // This avoids spawning millions of tasks and prevents the memory leak in the 'tasks' list.
        var workerCount = 200; // Aligned with AdaptiveConcurrencyManager max
        var workers = Enumerable.Range(0, workerCount).Select(_ => Task.Run(async () =>
        {
            var rand = new Random();
            while (!cts.IsCancellationRequested)
            {
                var item = await planner.GetNextAsync(cts.Token);
                if (item == null) break;

                await concurrencyManager.WaitAsync();
                await domainThrottle.WaitAsync(item.Url);

                var sw = System.Diagnostics.Stopwatch.StartNew();
                bool success = false;
                try
                {
                    var client = clients[rand.Next(clients.Count)];
                    using var req = new HttpRequestMessage(HttpMethod.Get, item.Url);
                    req.Headers.TryAddWithoutValidation("User-Agent", UserAgents[rand.Next(UserAgents.Length)]);
                    req.Headers.TryAddWithoutValidation("Accept", "*/*");

                    var res = await client.SendAsync(req, cts.Token);
                    success = true;

                    if ((int)res.StatusCode is 200 or 403)
                    {
                        var validation = await CloudValidator.ValidateAsync(res, item.Url, item.Cloud, client, signalMetrics);
                        if (validation.Confidence >= 0.50)
                        {
                            lock (resultsLock)
                            {
                                results.Add(validation);
                                tracker.UpsertAsset(validation, "OPEN");
                            }
                        }
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    var failureType = FailureClassifier.Classify(ex);
                    metrics.RecordRequest(sw.ElapsedMilliseconds, false, failureType);
                    concurrencyManager.RecordResult(false, failureType);
                    tracker.LogFailure(domainThrottle.GetDomain(item.Url), failureType);
                }
                finally
                {
                    sw.Stop();
                    if (success)
                    {
                        metrics.RecordRequest(sw.ElapsedMilliseconds, true);
                        concurrencyManager.RecordResult(true);
                        tracker.UpdateDomainStats(domainThrottle.GetDomain(item.Url), true);
                    }
                    else
                    {
                        tracker.UpdateDomainStats(domainThrottle.GetDomain(item.Url), false);
                    }

                    planner.RecordResult(item.Tier, success);
                    metrics.UpdateConcurrency(concurrencyManager.CurrentLimit);
                    domainThrottle.Release(item.Url);
                    concurrencyManager.Release();

                    if (metrics.TotalRequests % 1000 == 0 && metrics.TotalRequests > 0)
                    {
                        var health = SystemHealthAnalyzer.Analyze(metrics, results.Count, signalMetrics);
                        correctionEngine.ApplyCorrections(health);
                    }
                }
            }
        })).ToArray();

        var consumerTask = Task.WhenAll(workers);

        await Task.WhenAll(generatorTask, consumerTask);

        // Print observability metrics (Task 3)
        metrics.PrintSummary();

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
        
        // Task: System Health Diagnostics
        var healthReport = SystemHealthAnalyzer.Analyze(metrics, results.Count, signalMetrics);
        SystemHealthAnalyzer.PrintHealthReport(healthReport);
        
        // Task 5: Structured Export
        var report = tracker.ExportStructuredReport("csv");
        await File.WriteAllTextAsync("exposure_report.csv", report);
        Console.WriteLine("Structured report exported to exposure_report.csv");

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

public class SystemMetrics
{
    private long _totalRequests = 0;
    private long _successfulRequests = 0;
    private long _failedRequests = 0;
    private long _totalLatencyMs = 0;
    private int _activeConcurrency = 0;
    private readonly ConcurrentDictionary<string, long> _failureCounts = new();

    public long TotalRequests => Interlocked.Read(ref _totalRequests);
    public long SuccessfulRequests => Interlocked.Read(ref _successfulRequests);
    public long TotalLatencyMs => Interlocked.Read(ref _totalLatencyMs);
    
    public IReadOnlyDictionary<string, long> FailureCounts => _failureCounts;

    public void RecordRequest(long latencyMs, bool success, string errorType = "None")
    {
        Interlocked.Increment(ref _totalRequests);
        if (success) Interlocked.Increment(ref _successfulRequests);
        else 
        {
            Interlocked.Increment(ref _failedRequests);
            _failureCounts.AddOrUpdate(errorType, 1, (_, count) => count + 1);
        }
        Interlocked.Add(ref _totalLatencyMs, latencyMs);
    }

    public void UpdateConcurrency(int count) => _activeConcurrency = count;

    public void PrintSummary()
    {
        var total = Interlocked.Read(ref _totalRequests);
        if (total == 0) return;

        var success = Interlocked.Read(ref _successfulRequests);
        var failed = Interlocked.Read(ref _failedRequests);
        var latency = Interlocked.Read(ref _totalLatencyMs);

        Console.WriteLine("\n--- System Metrics Summary ---");
        Console.WriteLine($"Total Requests: {total}");
        Console.WriteLine($"Success Rate: {(double)success / total:P2}");
        Console.WriteLine($"Average Latency: {latency / total}ms");
        Console.WriteLine($"Active Concurrency: {_activeConcurrency}");
        
        if (_failureCounts.Count > 0)
        {
            Console.WriteLine("Failure Classification:");
            foreach (var f in _failureCounts.OrderByDescending(x => x.Value))
                Console.WriteLine($"  - {f.Key}: {f.Value}");
        }
        Console.WriteLine("------------------------------\n");
    }
}

public static class FailureClassifier
{
    public static string Classify(Exception ex)
    {
        return ex switch
        {
            TaskCanceledException => "Timeout",
            HttpRequestException h when h.Message.Contains("connection") => "ConnRefused",
            HttpRequestException h when h.Message.Contains("DNS") => "DNSError",
            HttpRequestException h when h.StatusCode == System.Net.HttpStatusCode.TooManyRequests => "RateLimited",
            _ => "Other"
        };
    }
}

public class AdaptiveConcurrencyManager
{
    private int _currentLimit;
    private readonly int _minLimit;
    private readonly int _maxLimit;
    private readonly SemaphoreSlim _semaphore;
    private int _consecutiveSuccesses = 0;
    private int _reductionDeficit = 0;
    private readonly object _lock = new();
    private DateTime _lastLimitUpdate = DateTime.MinValue;
    private double _correctionThrottle = 1.0;

    private readonly Queue<bool> _failureWindow = new(100);

    public AdaptiveConcurrencyManager(int initial, int min, int max)
    {
        _currentLimit = initial;
        _minLimit = min;
        _maxLimit = max;
        _semaphore = new SemaphoreSlim(initial, max);
    }

    public void ApplyGlobalThrottle(double multiplier)
    {
        lock (_lock)
        {
            _correctionThrottle = Math.Clamp(multiplier, 0.1, 1.0);
        }
    }

    public async Task WaitAsync() => await _semaphore.WaitAsync();
    
    public void Release()
    {
        lock (_lock)
        {
            if (_reductionDeficit > 0)
            {
                _reductionDeficit--;
                return; // Do not release, effectively shrinking the pool
            }
        }
        _semaphore.Release();
    }

    public void RecordResult(bool success, string failureType = "None")
    {
        lock (_lock)
        {
            _failureWindow.Enqueue(success);
            if (_failureWindow.Count > 100) _failureWindow.Dequeue();

            double failureRate = (double)_failureWindow.Count(x => !x) / _failureWindow.Count;

            // Progressive Failure Response System
            if (failureRate > 0.15 || !success) // Start reacting if window > 15% or immediate failure
            {
                _consecutiveSuccesses = 0;
                
                // Exponential reduction based on failure severity
                double pressure = failureType switch {
                    "RateLimited" => 0.20, // 20% drop
                    "DNSError" => 0.10,    // 10% drop
                    _ => 0.05              // 5% drop
                };

                int reduction = (int)Math.Max(1, _currentLimit * pressure);
                
                if (_currentLimit > _minLimit && (DateTime.UtcNow - _lastLimitUpdate).TotalMilliseconds > 200)
                {
                    int newLimit = Math.Max(_minLimit, _currentLimit - reduction);
                    // Efficiently shrink capacity by tracking deficit for the Release() method
                    _reductionDeficit += (_currentLimit - newLimit);
                    _currentLimit = newLimit;
                    _lastLimitUpdate = DateTime.UtcNow;
                }
            }
            else if (success && failureRate < 0.05)
            {
                // Smooth Recovery
                _consecutiveSuccesses++;
                if (_consecutiveSuccesses >= 15 && _currentLimit < (_maxLimit * _correctionThrottle))
                {
                    _currentLimit++;
                    _semaphore.Release();
                    _consecutiveSuccesses = 0;
                    _lastLimitUpdate = DateTime.UtcNow;
                }
            }
        }
    }

    public double PressureRatio => 1.0 - (double)(_currentLimit - _minLimit) / (_maxLimit - _minLimit);
}

public class DomainThrottle
{
    private readonly Dictionary<string, SemaphoreSlim> _domainSemaphores = new();
    private readonly int _maxPerDomain;
    private readonly object _lock = new();

    public DomainThrottle(int maxPerDomain)
    {
        _maxPerDomain = maxPerDomain;
    }

    public async Task WaitAsync(string url)
    {
        var domain = GetDomain(url);
        SemaphoreSlim sem;
        lock (_lock)
        {
            if (!_domainSemaphores.TryGetValue(domain, out sem))
            {
                sem = new SemaphoreSlim(_maxPerDomain);
                _domainSemaphores[domain] = sem;
            }
        }
        await sem.WaitAsync();
    }

    public void Release(string url)
    {
        var domain = GetDomain(url);
        lock (_lock)
        {
            if (_domainSemaphores.TryGetValue(domain, out var sem))
            {
                sem.Release();
            }
        }
    }

    public string GetDomain(string url)
    {
        try
        {
            var uri = new Uri(url);
            return uri.Host;
        }
        catch { return "unknown"; }
    }
}
