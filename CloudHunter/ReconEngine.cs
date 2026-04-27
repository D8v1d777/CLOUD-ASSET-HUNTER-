using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Linq;

namespace CloudHunter;

public class ReconEngine
{
    private static readonly HttpClient _client = new HttpClient();

    public static async Task<List<string>> AutoSeedAsync(string domain, int topN = 100)
    {
        Console.WriteLine($"[*] Auto-Seeding: Fetching subdomains for {domain} via CRT.sh...");
        var rawSubdomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var noisePatterns = new[] { "mta-sts", "autodiscover", "_tcp", "_udp", "smtp", "pop", "imap", "direct-connect" };

        try
        {
            var url = $"https://crt.sh/?q=%25.{domain}&output=json";
            _client.DefaultRequestHeaders.Clear();
            _client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) CloudHunter/1.0");
            
            var response = await _client.GetStringAsync(url);
            using var doc = JsonDocument.Parse(response);
            
            foreach (var element in doc.RootElement.EnumerateArray())
            {
                if (element.TryGetProperty("name_value", out var nameValue))
                {
                    var names = nameValue.GetString()?.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    if (names != null)
                    {
                        foreach (var name in names)
                        {
                            var cleanName = name.Trim().ToLower().Replace("*.", "");
                            if (!cleanName.EndsWith(domain) || cleanName == domain) continue;
                            if (noisePatterns.Any(p => cleanName.StartsWith(p + "."))) continue;
                            rawSubdomains.Add(cleanName);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Auto-Seed failed for {domain}: {ex.Message}");
            return new List<string>();
        }

        // Task 1: Recon Target Relevance Scoring
        var scoredTargets = rawSubdomains.Select(s => new 
        {
            Target = s,
            Score = CalculateRelevanceScore(s, domain)
        })
        .OrderByDescending(x => x.Score)
        .Take(topN)
        .ToList();

        Console.WriteLine($"[+] Auto-Seed prioritized top {scoredTargets.Count} targets for {domain}.");
        return scoredTargets.Select(x => x.Target).ToList();
    }

    private static double CalculateRelevanceScore(string subdomain, string rootDomain)
    {
        double score = 0.5; // Base score
        var parts = subdomain.Split('.');
        int depth = parts.Length - rootDomain.Split('.').Length;

        // 1. Keyword Presence
        var highValue = new[] { "dev", "prod", "backup", "assets", "storage", "api", "internal", "stg", "test", "cloud", "bucket", "s3", "blob", "data", "sql", "db" };
        foreach (var word in highValue)
        {
            if (subdomain.Contains(word)) score += 0.15;
        }

        // 2. Subdomain Depth (Prefer shallower subdomains as they are often more significant)
        score -= (depth * 0.05);

        // 3. Cloud-Related Patterns
        if (subdomain.Contains("s3") || subdomain.Contains("blob") || subdomain.Contains("storage") || subdomain.Contains("aws") || subdomain.Contains("azure") || subdomain.Contains("gcp"))
            score += 0.2;

        return Math.Clamp(score, 0, 1.0);
    }
}
