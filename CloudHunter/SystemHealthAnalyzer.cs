using System;
using System.Collections.Generic;
using System.Linq;

namespace CloudHunter;

public class SystemHealthAnalyzer
{
    public class HealthReport
    {
        public string HealthStatus { get; set; } = "OPTIMAL";
        public List<string> Issues { get; set; } = new();
        public List<string> Recommendations { get; set; } = new();
        public Dictionary<string, object> MetricsSummary { get; set; } = new();
    }

    public static HealthReport Analyze(SystemMetrics metrics, int validatedResultsCount, Dictionary<string, (int FP, int Total)> signalMetrics)
    {
        var report = new HealthReport();
        var totalRequests = metrics.TotalRequests;
        if (totalRequests == 0) return report;

        var successRate = (double)metrics.SuccessfulRequests / totalRequests;
        var avgLatency = totalRequests > 0 ? metrics.TotalLatencyMs / totalRequests : 0;
        var failures = metrics.FailureCounts;

        // 1. Success Rate Analysis
        if (successRate < 0.50)
        {
            report.HealthStatus = "CRITICAL";
            report.Issues.Add($"Extremely low success rate: {successRate:P2}");
            report.Recommendations.Add("Check proxy health and target validity.");
        }
        else if (successRate < 0.85)
        {
            if (report.HealthStatus != "CRITICAL") report.HealthStatus = "DEGRADED";
            report.Issues.Add($"Suboptimal success rate: {successRate:P2}");
        }

        // 2. Failure Distribution Analysis
        int dnsErrors = failures.GetValueOrDefault("DNSError");
        int timeouts = failures.GetValueOrDefault("Timeout");
        int rateLimits = failures.GetValueOrDefault("RateLimited");

        if (dnsErrors > totalRequests * 0.2)
        {
            report.Issues.Add("High DNS failure rate detected.");
            report.Recommendations.Add("DNS resolution issues: Consider verifying recon quality or using more reliable DNS servers.");
            if (report.HealthStatus == "OPTIMAL") report.HealthStatus = "DEGRADED";
        }

        if (timeouts > totalRequests * 0.15)
        {
            report.Issues.Add("High timeout rate detected.");
            report.Recommendations.Add("Latency/Network issues: Reduce global concurrency or increase client timeout.");
            if (report.HealthStatus == "OPTIMAL") report.HealthStatus = "DEGRADED";
        }

        if (rateLimits > totalRequests * 0.05)
        {
            report.Issues.Add("System is being rate-limited by providers.");
            report.Recommendations.Add("Rate limiting detected: Add more rotating proxies or increase domain throttling.");
        }

        // 3. Scoring & Value Analysis
        double highPriorityRatio = totalRequests > 0 ? (double)validatedResultsCount / totalRequests : 0;
        if (validatedResultsCount > 0 && highPriorityRatio < 0.0001) // 1 in 10,000
        {
            report.Issues.Add("Extremely low yield of high-priority findings.");
            report.Recommendations.Add("Scoring problem: Verify if CloudValidator signal weights are too restrictive for current targets.");
        }

        // 4. False Positive Analysis
        double totalFpRate = 0;
        int signalsWithData = 0;
        foreach (var signal in signalMetrics)
        {
            if (signal.Value.Total > 20)
            {
                double fpRate = (double)signal.Value.FP / signal.Value.Total;
                totalFpRate += fpRate;
                signalsWithData++;
                if (fpRate > 0.4)
                {
                    report.Issues.Add($"High FP rate for signal '{signal.Key}': {fpRate:P2}");
                }
            }
        }
        
        if (signalsWithData > 0 && (totalFpRate / signalsWithData) > 0.3)
        {
            report.Recommendations.Add("High overall FP rate: Consider refining signal correlation logic or keyword lists.");
            if (report.HealthStatus == "OPTIMAL") report.HealthStatus = "DEGRADED";
        }

        // Final Latency Trend
        if (avgLatency > 2000)
        {
            report.Issues.Add($"High average latency: {avgLatency}ms");
            report.Recommendations.Add("Improve performance by using geographically closer proxies or reducing payload sizes.");
        }

        report.MetricsSummary = new Dictionary<string, object>
        {
            { "SuccessRate", successRate },
            { "AvgLatency", avgLatency },
            { "TotalRequests", totalRequests },
            { "ValidatedFindings", validatedResultsCount }
        };

        return report;
    }

    public static void PrintHealthReport(HealthReport report)
    {
        Console.WriteLine("\n=== SYSTEM HEALTH REPORT ===");
        var color = report.HealthStatus switch
        {
            "OPTIMAL" => ConsoleColor.Green,
            "DEGRADED" => ConsoleColor.Yellow,
            "CRITICAL" => ConsoleColor.Red,
            _ => ConsoleColor.White
        };

        var originalColor = Console.ForegroundColor;
        Console.Write("Status: ");
        Console.ForegroundColor = color;
        Console.WriteLine(report.HealthStatus);
        Console.ForegroundColor = originalColor;

        if (report.Issues.Any())
        {
            Console.WriteLine("\nDetected Issues:");
            foreach (var issue in report.Issues) Console.WriteLine($"- {issue}");
        }

        if (report.Recommendations.Any())
        {
            Console.WriteLine("\nRecommendations:");
            foreach (var rec in report.Recommendations) Console.WriteLine($"- {rec}");
        }
        Console.WriteLine("============================\n");
    }
}
