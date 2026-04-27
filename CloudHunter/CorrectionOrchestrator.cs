using System;
using System.Collections.Generic;
using System.Linq;

namespace CloudHunter;

public enum CorrectionPriority
{
    MEDIUM = 1,    // Yield optimization
    HIGH = 2,      // False positives
    CRITICAL = 3   // Network stability (Latency, DNS)
}

public class CorrectionDecision
{
    public double? ConcurrencyThrottle { get; set; }
    public Dictionary<ScanTier, double> WeightOverrides { get; set; } = new();
    public Dictionary<string, double> SignalDampeners { get; set; } = new();
}

public class CorrectionOrchestrator
{
    public static CorrectionDecision Orchestrate(SystemHealthAnalyzer.HealthReport report, Dictionary<string, double> currentDampeners)
    {
        var decision = new CorrectionDecision();
        var activeSignals = new List<(CorrectionPriority Priority, Action Apply)>();

        // 1. Identify CRITICAL signals (Network/Stability)
        bool hasCriticalNetworkIssue = report.Issues.Any(i => i.Contains("DNS failure") || i.Contains("timeout") || i.Contains("latency"));
        if (hasCriticalNetworkIssue)
        {
            activeSignals.Add((CorrectionPriority.CRITICAL, () => {
                // Network stability overrides yield and FP adjustments for resource allocation
                if (report.Issues.Any(i => i.Contains("timeout") || i.Contains("latency")))
                {
                    decision.ConcurrencyThrottle = -0.15; // Aggressive reduction
                }
                
                if (report.Issues.Any(i => i.Contains("DNS failure")))
                {
                    decision.WeightOverrides[ScanTier.Tier3_AutoSeed] = 0.10; // Drastic reduction of exploratory
                    decision.WeightOverrides[ScanTier.Tier1_HighHistorical] = 0.60; // Focus on known good
                }
            }));
        }

        // 2. Identify HIGH signals (False Positives)
        var fpIssues = report.Issues.Where(i => i.Contains("High FP rate for signal")).ToList();
        if (fpIssues.Any())
        {
            activeSignals.Add((CorrectionPriority.HIGH, () => {
                foreach (var issue in fpIssues)
                {
                    var signalName = issue.Split('\'')[1];
                    var current = currentDampeners.GetValueOrDefault(signalName, 1.0);
                    decision.SignalDampeners[signalName] = Math.Max(0.1, current - 0.1);
                }
                
                // HIGH priority also influences yield optimization: 
                // if signals are noisy, reduce exploratory depth even if no network issue
                if (!decision.WeightOverrides.ContainsKey(ScanTier.Tier3_AutoSeed))
                {
                    decision.WeightOverrides[ScanTier.Tier3_AutoSeed] = 0.15;
                }
            }));
        }

        // 3. Identify MEDIUM signals (Yield Optimization)
        if (report.Issues.Any(i => i.Contains("low yield")))
        {
            activeSignals.Add((CorrectionPriority.MEDIUM, () => {
                // MEDIUM yield optimization only applies if no CRITICAL stability issues
                if (!hasCriticalNetworkIssue)
                {
                    decision.WeightOverrides[ScanTier.Tier2_HighRelevance] = 0.45;
                    if (!decision.WeightOverrides.ContainsKey(ScanTier.Tier3_AutoSeed))
                    {
                        decision.WeightOverrides[ScanTier.Tier3_AutoSeed] = 0.10;
                    }
                }
            }));
        }

        // Resolve conflicts by processing based on priority
        foreach (var signal in activeSignals.OrderByDescending(s => s.Priority))
        {
            signal.Apply();
        }

        // Handle recovery if no active signals for specific areas
        if (!hasCriticalNetworkIssue)
        {
            decision.ConcurrencyThrottle = 0.05; // Gradual recovery
            
            // Weight recovery: Return towards baseline (50/30/20)
            decision.WeightOverrides[ScanTier.Tier1_HighHistorical] = 0.50;
            decision.WeightOverrides[ScanTier.Tier2_HighRelevance] = 0.30;
            decision.WeightOverrides[ScanTier.Tier3_AutoSeed] = 0.20;
        }

        // Signal dampener decay: Gradually return towards 1.0 if not re-triggered
        foreach (var kvp in currentDampeners)
        {
            if (!decision.SignalDampeners.ContainsKey(kvp.Key) && kvp.Value < 1.0)
            {
                decision.SignalDampeners[kvp.Key] = Math.Min(1.0, kvp.Value + 0.02);
            }
        }

        return decision;
    }
}
