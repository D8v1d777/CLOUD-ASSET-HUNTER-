using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace CloudHunter;

public class CloudValidator
{
    private static readonly Dictionary<string, double> _signalDampeners = new();
    private static readonly object _dampenerLock = new();

    public static void ApplySignalDampener(string signalName, double dampener)
    {
        lock (_dampenerLock)
        {
            _signalDampeners[signalName] = Math.Clamp(dampener, 0.1, 1.0);
        }
    }

    public static async Task<ValidationResult> ValidateAsync(HttpResponseMessage resp, string url, string cloud, HttpClient client, Dictionary<string, (int FP, int Total)>? metrics = null)
    {
        var headers = resp.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value));
        
        // Stage 1: Quick Header/Status Validation (Performance Task 5)
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound || resp.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            // Even 403 can be interesting, but 404 is usually a dead end unless it's a specific cloud error
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound && !headers.ContainsKey("x-ms-error-code") && !headers.ContainsKey("x-amz-request-id"))
            {
                 return new ValidationResult { Url = url, Confidence = 0, Evidence = new Evidence { Summary = "Not Found" } };
            }
        }

        // Stage 2: Body Parsing
        var body = await resp.Content.ReadAsStringAsync();
        double confidence = 0;
        var interestingFiles = new List<string>();

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

        // Task 3: Normalize Multi-Signal Impact Scoring with Bounded Weights (Task 1)
        var signalScores = CalculateSignalScores(interestingFiles, headers, body);
        
        // Apply Self-Correction Dampeners
        lock (_dampenerLock)
        {
            foreach (var kvp in _signalDampeners)
            {
                if (signalScores.ContainsKey(kvp.Key))
                {
                    signalScores[kvp.Key] *= kvp.Value;
                }
            }
        }

        // Task 5: Feedback Loop - Adjust signal influence based on historical FP rate
        if (metrics != null)
        {
            foreach (var signal in signalScores.Keys.ToList())
            {
                if (metrics.TryGetValue(signal, out var m) && m.Total > 20)
                {
                    double fpRate = (double)m.FP / m.Total;
                    // Dampen the signal score if it has a high FP rate
                    // Influence = (1 - FP_Rate)^2
                    double influence = Math.Pow(1.0 - fpRate, 2);
                    signalScores[signal] *= influence;
                }
            }
        }

        // Task 1: Prevent scoring drift with bounded weights
        // Weights are hardcoded to fixed values that sum to 1.0, ensuring stability
        const double keywordWeight = 0.4;
        const double entropyWeight = 0.2;
        const double volumeWeight = 0.2;
        const double headerWeight = 0.2;

        var baseImpact = (signalScores["keyword"] * keywordWeight) + 
                         (signalScores["entropy"] * entropyWeight) + 
                         (signalScores["volume"] * volumeWeight) + 
                         (signalScores["header"] * headerWeight);

        // Task: Signal Correlation Logic
        double correlationBoost = 0;
        var filesLower = interestingFiles.Select(f => f.ToLower()).ToList();

        // Rule 1: .env + high entropy → critical
        if (filesLower.Any(f => f.Contains(".env")) && signalScores["entropy"] > 0.5)
            correlationBoost += 0.20;

        // Rule 2: backup.sql + large volume → critical
        if (filesLower.Any(f => f.Contains("backup.sql")) && signalScores["volume"] > 0.5)
            correlationBoost += 0.20;

        // Rule 3: public access (high confidence) + sensitive filenames → critical
        if (confidence > 0.9 && signalScores["keyword"] > 0.8)
            correlationBoost += 0.15;

        // Rule 4: keyword reinforcement
        if (signalScores["keyword"] > 0.7 && signalScores["entropy"] > 0.6)
            correlationBoost += 0.10;

        var impact = baseImpact + correlationBoost;

        // Prevent false positives: If only one weak signal → reduce influence
        int activeSignals = signalScores.Values.Count(v => v > 0.25);
        if (activeSignals <= 1 && impact < 0.5)
        {
            impact *= 0.5; // Dampen isolated signals that aren't inherently strong
        }
        
        impact = Math.Clamp(impact, 0, 1.0);

        // Task 3: Improve Priority Scoring with Confidence Gating
        double priority = impact * confidence;
        if (confidence < 0.5) priority *= 0.1;

        string priorityLabel = priority >= 0.75 ? "HIGH" : (priority >= 0.40 ? "MEDIUM" : "LOW");

        // Task 6: Decision/Action Layer
        string decision = priority >= 0.75 ? "IMMEDIATE_TRIAGE" : (priority >= 0.40 ? "REVIEW_REQUIRED" : "MONITOR");
        string recommendedAction = decision switch
        {
            "IMMEDIATE_TRIAGE" => "CRITICAL: Secure bucket/container immediately. Review sensitive snippets for credentials or keys.",
            "REVIEW_REQUIRED" => "WARNING: Verify if exposure is intentional. Check for internal non-sensitive data exposure.",
            "MONITOR" => "INFO: No immediate action required. Asset added to baseline monitoring list.",
            _ => "UNKNOWN: Requires manual investigation."
        };

        // Stage 3: Expensive Evidence Building (Only if priority > 0.1)
        Evidence evidence;
        if (priority > 0.1)
        {
            evidence = await BuildStructuredEvidence(url, interestingFiles, headers, body, client);
        }
        else
        {
            evidence = new Evidence { Summary = "Low priority asset, detailed evidence skipped.", Filenames = interestingFiles.Take(10).ToList() };
        }

        return new ValidationResult 
        { 
            Url = url, 
            Cloud = cloud, 
            Confidence = confidence, 
            ImpactScore = impact,
            PriorityScore = priority,
            PriorityLabel = priorityLabel,
            Evidence = evidence,
            SignalScores = signalScores,
            Decision = decision,
            RecommendedAction = recommendedAction
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

        // 4. Entropy Score (Task: Correlation support)
        // Always calculate entropy proxy from body or filenames to support correlation logic
        double entropyProxy = files.Count > 0 
            ? Math.Clamp(string.Join("", files).Length / 5000.0, 0, 1.0) 
            : Math.Clamp(body.Length / 10000.0, 0, 1.0);
        scores["entropy"] = entropyProxy;

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
                    // Task 3: Sanitize and optimize evidence storage
                    // Limit snippet size to 512 bytes and sanitize common secrets
                    var snippetRaw = System.Text.Encoding.UTF8.GetString(content.Take(512).ToArray());
                    var sanitizedSnippet = SanitizeSnippet(snippetRaw);
                    evidence.Snippets.Add(new Snippet { Filename = sensitiveFile, Content = sanitizedSnippet });
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

    private static string SanitizeSnippet(string content)
    {
        if (string.IsNullOrEmpty(content)) return "";
        
        // Simple sanitization for common secret patterns to prevent sensitive data leakage in storage/alerts
        var sanitized = content;
        var patterns = new[] 
        { 
            @"(?i)password\s*[:=]\s*[^\s,;]+",
            @"(?i)secret\s*[:=]\s*[^\s,;]+",
            @"(?i)key\s*[:=]\s*[^\s,;]+",
            @"(?i)token\s*[:=]\s*[^\s,;]+",
            @"(?i)api_key\s*[:=]\s*[^\s,;]+"
        };

        foreach (var p in patterns)
        {
            sanitized = System.Text.RegularExpressions.Regex.Replace(sanitized, p, m => m.Value.Split(new[] { ':', '=' }, 2)[0] + ": [REDACTED]");
        }

        return sanitized;
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
    public string Decision { get; init; } = "MONITOR";
    public string RecommendedAction { get; init; } = "";
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
