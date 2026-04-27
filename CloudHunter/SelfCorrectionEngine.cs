using System;
using System.Collections.Generic;
using System.Linq;

namespace CloudHunter;

public class SelfCorrectionEngine
{
    private readonly ScanPlanner _planner;
    private readonly AdaptiveConcurrencyManager _concurrencyManager;
    private readonly object _lock = new();
    
    // Internal state to track corrections applied
    private double _tier3Dampener = 1.0;
    private double _concurrencyMultiplier = 1.0;
    private readonly Dictionary<string, double> _signalDampeners = new();
    
    // Task: Correction History & Damping
    private record CorrectionRecord(string Type, double Magnitude, DateTime Timestamp);
    private readonly List<CorrectionRecord> _history = new();
    private const int HistoryLimit = 50;
    private readonly TimeSpan _dampingWindow = TimeSpan.FromSeconds(30);

    public SelfCorrectionEngine(ScanPlanner planner, AdaptiveConcurrencyManager concurrencyManager)
    {
        _planner = planner;
        _concurrencyManager = concurrencyManager;
    }

    public void ApplyCorrections(SystemHealthAnalyzer.HealthReport report)
    {
        lock (_lock)
        {
            // Clean old history
            _history.RemoveAll(h => DateTime.UtcNow - h.Timestamp > TimeSpan.FromMinutes(5));

            var decision = CorrectionOrchestrator.Orchestrate(report, _signalDampeners);

            // 1. Apply Concurrency Adjustments (Damped)
            if (decision.ConcurrencyThrottle.HasValue)
            {
                double magnitude = decision.ConcurrencyThrottle.Value;
                magnitude = ApplyDamping("concurrency", magnitude);

                if (magnitude < 0)
                    _concurrencyMultiplier = Math.Max(0.3, _concurrencyMultiplier + magnitude);
                else
                    _concurrencyMultiplier = Math.Min(1.0, _concurrencyMultiplier + magnitude);
                
                _concurrencyManager.ApplyGlobalThrottle(_concurrencyMultiplier);
                RecordCorrection("concurrency", magnitude);
            }

            // 2. Apply Weight Adjustments (Damped)
            foreach (var kvp in decision.WeightOverrides)
            {
                // Simple damping for weights: only apply if significant change or first time
                RecordCorrection($"weight_{kvp.Key}", kvp.Value);
                _planner.ApplyWeightOverride(kvp.Key, kvp.Value);
            }

            // 3. Apply Signal Dampening (Damped)
            foreach (var kvp in decision.SignalDampeners)
            {
                double current = _signalDampeners.GetValueOrDefault(kvp.Key, 1.0);
                double delta = kvp.Value - current;
                
                if (Math.Abs(delta) > 0.01)
                {
                    delta = ApplyDamping($"signal_{kvp.Key}", delta);
                    _signalDampeners[kvp.Key] = Math.Clamp(current + delta, 0.1, 1.0);
                    CloudValidator.ApplySignalDampener(kvp.Key, _signalDampeners[kvp.Key]);
                    RecordCorrection($"signal_{kvp.Key}", delta);
                }
            }
        }
    }

    private double ApplyDamping(string type, double magnitude)
    {
        // If we applied the same correction type recently, reduce strength
        var recent = _history.Where(h => h.Type == type && DateTime.UtcNow - h.Timestamp < _dampingWindow).ToList();
        
        if (recent.Count > 0)
        {
            // Dampen magnitude by 50% for each recent repeated correction
            double factor = Math.Pow(0.5, recent.Count);
            return magnitude * factor;
        }
        return magnitude;
    }

    private void RecordCorrection(string type, double magnitude)
    {
        _history.Add(new CorrectionRecord(type, magnitude, DateTime.UtcNow));
        if (_history.Count > HistoryLimit) _history.RemoveAt(0);
    }
}
