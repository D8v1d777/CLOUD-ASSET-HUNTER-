using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace CloudHunter;

public class CloudValidator
{
    public static async Task<ValidationResult> ValidateAsync(HttpResponseMessage resp, string url, string cloud, HttpClient client)
    {
        var body = await resp.Content.ReadAsStringAsync();
        double confidence = 0;
        var interestingFiles = new List<string>();
        var headers = resp.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value));

        // False Positive Elimination (Extended)
        var fpPatterns = new[] { "CloudFront", "cloudflare", "Please verify you are a human", "404 Not Found", "Access Denied", "NoSuchKey" };
        if (fpPatterns.Any(p => body.Contains(p)) && resp.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return new ValidationResult { Url = url, Confidence = 0, Evidence = new Evidence { Summary = "False Positive (Static Error Page)" } };
        }

        if (cloud == "AWS_S3")
        {
            if (body.Contains("<ListBucketResult>"))
            {
                confidence = 0.98;
                ExtractS3Files(body, interestingFiles);
            }
            else if (body.Contains("AccessDenied") || body.Contains("AllAccessDisabled"))
            {
                confidence = 0.60;
            }
        }
        else if (cloud == "AZURE_BLOB")
        {
            if (headers.TryGetValue("x-ms-blob-public-access", out var access) && access == "container")
            {
                confidence = 0.98;
                ExtractAzureFiles(body, interestingFiles);
            }
            else if (body.Contains("<EnumerationResults"))
            {
                confidence = 0.90;
                ExtractAzureFiles(body, interestingFiles);
            }
        }
        else if (cloud == "GCP_GCS")
        {
            if (body.Contains("\"items\":"))
            {
                confidence = 0.95;
                ExtractGCPFiles(body, interestingFiles);
            }
        }
        else // Generic Cloud API / K8s
        {
            if (body.Contains("\"kind\":") && body.Contains("\"items\":"))
            {
                confidence = 0.85;
            }
        }

        // Task 2: Normalize Multi-Signal Impact Scoring
        var signalScores = CalculateSignalScores(interestingFiles, headers, body);
        var impact = (signalScores["keyword"] * 0.4) + (signalScores["entropy"] * 0.2) + (signalScores["volume"] * 0.2) + (signalScores["header"] * 0.2);
        impact = Math.Clamp(impact, 0, 1.0);

        // Task 3: Improve Priority Scoring with Confidence Gating
        double priority = impact * confidence;
        if (confidence < 0.5) priority *= 0.1; // Aggressive gating for low confidence

        string priorityLabel = priority >= 0.75 ? "HIGH" : (priority >= 0.40 ? "MEDIUM" : "LOW");

        // Task 4: Structured Evidence Object
        var evidence = await BuildStructuredEvidence(url, interestingFiles, headers, body, client);

        return new ValidationResult 
        { 
            Url = url, 
            Cloud = cloud, 
            Confidence = confidence, 
            ImpactScore = impact,
            PriorityScore = priority,
            PriorityLabel = priorityLabel,
            Evidence = evidence,
            SignalScores = signalScores
        };
    }

    private static Dictionary<string, double> CalculateSignalScores(List<string> files, Dictionary<string, string> headers, string body)
    {
        var scores = new Dictionary<string, double>();

        // 1. Keyword Score (Normalized 0-1)
        double keywordScore = 0;
        var highValue = new[] { ".env", ".sql", "config", "secret", "id_rsa", "backup", "credential", "password", "shadow", "master", "key.json", "vault" };
        var piValue = new[] { "user", "client", "customer", "employee", "salary", "invoice", "passport", "identity", "ssn", "kyc" };
        
        var filesLower = files.Select(f => f.ToLower()).ToList();
        if (filesLower.Any(f => highValue.Any(p => f.Contains(p)))) keywordScore = 1.0;
        else if (filesLower.Any(f => piValue.Any(p => f.Contains(p)))) keywordScore = 0.6;
        else if (filesLower.Any()) keywordScore = 0.2;
        scores["keyword"] = keywordScore;

        // 2. Volume Score (Logarithmic Scaling)
        scores["volume"] = files.Count > 0 ? Math.Clamp(Math.Log10(files.Count) / 3.0, 0, 1.0) : 0;

        // 3. Header Score (Normalized)
        double headerScore = 0;
        if (!headers.ContainsKey("Content-Security-Policy")) headerScore += 0.4;
        if (headers.ContainsKey("X-Internal-ID") || headers.ContainsKey("X-Powered-By") || headers.ContainsKey("Server")) headerScore += 0.6;
        scores["header"] = Math.Clamp(headerScore, 0, 1.0);

        // 4. Entropy Score (Simple length-based proxy for data density if no files listable)
        scores["entropy"] = files.Count == 0 ? Math.Clamp(body.Length / 10000.0, 0, 1.0) : 0;

        return scores;
    }

    private static async Task<Evidence> BuildStructuredEvidence(string url, List<string> files, Dictionary<string, string> headers, string body, HttpClient client)
    {
        var evidence = new Evidence();
        var highValuePatterns = new[] { ".env", ".sql", "config", "secret", "id_rsa", "key.json" };
        
        evidence.Filenames = files.Take(100).ToList();
        evidence.Headers = headers;
        evidence.SensitiveFiles = files.Where(f => highValuePatterns.Any(p => f.ToLower().Contains(p))).Take(10).ToList();

        // Capture snippets for up to 3 high-value files
        foreach (var sensitiveFile in evidence.SensitiveFiles.Take(3))
        {
            try
            {
                // Simple heuristic to build file URL - might need provider-specific logic
                var fileUrl = url.TrimEnd('/') + "/" + sensitiveFile.TrimStart('/');
                var resp = await client.GetAsync(fileUrl);
                if (resp.IsSuccessStatusCode)
                {
                    var content = await resp.Content.ReadAsByteArrayAsync();
                    var snippet = System.Text.Encoding.UTF8.GetString(content.Take(256).ToArray());
                    evidence.Snippets.Add(new Snippet { Filename = sensitiveFile, Content = snippet });
                }
            }
            catch { }
        }

        // Reasons & Summary
        if (evidence.SensitiveFiles.Any())
        {
            evidence.Reasons.Add("Exposure of highly sensitive credential or configuration files.");
            evidence.Reasons.Add("Direct path to system compromise or data exfiltration.");
        }
        if (files.Count > 50)
        {
            evidence.Reasons.Add($"Large volume of internal assets ({files.Count} files) exposed.");
        }
        
        evidence.Summary = evidence.Reasons.Any() 
            ? $"Critical exposure found at {url}. " + string.Join(" ", evidence.Reasons)
            : $"Unauthenticated access discovered at {url} with moderate impact signals.";

        return evidence;
    }

    private static void ExtractS3Files(string xml, List<string> files)
    {
        try
        {
            var doc = System.Xml.Linq.XDocument.Parse(xml);
            var ns = doc.Root?.Name.Namespace;
            var keys = doc.Descendants(ns + "Key").Select(x => x.Value).Distinct().Take(100);
            files.AddRange(keys);
        }
        catch { }
    }

    private static void ExtractAzureFiles(string xml, List<string> files)
    {
        try
        {
            var doc = System.Xml.Linq.XDocument.Parse(xml);
            var keys = doc.Descendants("Name").Select(x => x.Value).Distinct().Take(100);
            files.AddRange(keys);
        }
        catch { }
    }

    private static void ExtractGCPFiles(string json, List<string> files)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("items", out var items))
            {
                foreach (var item in items.EnumerateArray().Take(100))
                {
                    if (item.TryGetProperty("name", out var name))
                        files.Add(name.GetString() ?? "");
                }
            }
        }
        catch { }
    }
}

public record ValidationResult
{
    public string Url { get; init; } = "";
    public string Cloud { get; init; } = "";
    public double Confidence { get; init; }
    public double ImpactScore { get; init; }
    public double PriorityScore { get; init; }
    public string PriorityLabel { get; init; } = "LOW";
    public Evidence Evidence { get; init; } = new();
    public Dictionary<string, double> SignalScores { get; init; } = new();
}

public class Evidence
{
    public List<string> Filenames { get; set; } = new();
    public List<string> SensitiveFiles { get; set; } = new();
    public List<Snippet> Snippets { get; set; } = new();
    public Dictionary<string, string> Headers { get; set; } = new();
    public string Summary { get; set; } = "";
    public List<string> Reasons { get; set; } = new();
}

public class Snippet
{
    public string Filename { get; set; } = "";
    public string Content { get; set; } = "";
}
