using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CloudHunter
{
    public enum ScanTier
    {
        Tier1_HighHistorical, // 50%
        Tier2_HighRelevance,  // 30%
        Tier3_AutoSeed        // 20%
    }

    public record ScanTarget(string Url, string Cloud, ScanTier Tier);

    public class ScanPlanner
    {
        private readonly ConcurrentQueue<ScanTarget> _tier1Queue = new();
        private readonly ConcurrentQueue<ScanTarget> _tier2Queue = new();
        private readonly ConcurrentQueue<ScanTarget> _tier3Queue = new();

        private readonly Dictionary<ScanTier, double> _weights = new()
        {
            { ScanTier.Tier1_HighHistorical, 0.50 },
            { ScanTier.Tier2_HighRelevance, 0.30 },
            { ScanTier.Tier3_AutoSeed, 0.20 }
        };

        private readonly Dictionary<ScanTier, int> _activeCounts = new()
        {
            { ScanTier.Tier1_HighHistorical, 0 },
            { ScanTier.Tier2_HighRelevance, 0 },
            { ScanTier.Tier3_AutoSeed, 0 }
        };

        private readonly Dictionary<ScanTier, (int success, int total)> _stats = new()
        {
            { ScanTier.Tier1_HighHistorical, (0, 0) },
            { ScanTier.Tier2_HighRelevance, (0, 0) },
            { ScanTier.Tier3_AutoSeed, (0, 0) }
        };

        private readonly object _lock = new();
        private readonly SemaphoreSlim _availableSignal = new(0);
        private int _totalQueued = 0;

        public int TotalQueued => _totalQueued;

        public void Enqueue(ScanTarget target)
        {
            switch (target.Tier)
            {
                case ScanTier.Tier1_HighHistorical: _tier1Queue.Enqueue(target); break;
                case ScanTier.Tier2_HighRelevance: _tier2Queue.Enqueue(target); break;
                case ScanTier.Tier3_AutoSeed: _tier3Queue.Enqueue(target); break;
            }
            Interlocked.Increment(ref _totalQueued);
            _availableSignal.Release();
        }

        public void ApplyWeightOverride(ScanTier tier, double weight)
        {
            lock (_lock)
            {
                _weights[tier] = Math.Clamp(weight, 0.01, 0.90);
                // Re-normalize other weights if needed (simplified here)
            }
        }

        public async Task<ScanTarget?> GetNextAsync(int globalLimit, CancellationToken ct = default)
        {
            while (!ct.IsCancellationRequested)
            {
                await _availableSignal.WaitAsync(ct);

                lock (_lock)
                {
                    var tier = SelectTier(globalLimit);
                    if (tier == null)
                    {
                        // No tier is suitable or queues are empty
                        // Note: availableSignal might have been released but queues are empty due to race conditions
                        continue;
                    }

                    ScanTarget? target = null;
                    bool dequeued = tier switch
                    {
                        ScanTier.Tier1_HighHistorical => _tier1Queue.TryDequeue(out target),
                        ScanTier.Tier2_HighRelevance => _tier2Queue.TryDequeue(out target),
                        ScanTier.Tier3_AutoSeed => _tier3Queue.TryDequeue(out target),
                        _ => false
                    };

                    if (dequeued && target != null)
                    {
                        _activeCounts[tier.Value]++;
                        Interlocked.Decrement(ref _totalQueued);
                        return target;
                    }
                }
            }
            return null;
        }

        private ScanTier? SelectTier(int globalLimit)
        {
            // Calculate target counts based on weights
            var tierTargets = _weights.ToDictionary(
                kvp => kvp.Key,
                kvp => (int)Math.Max(1, globalLimit * kvp.Value)
            );

            // Priority 1: Pick from tiers that are under their allocated target
            var candidates = _weights.Keys
                .Where(t => IsTierAvailable(t))
                .OrderByDescending(t => (double)(tierTargets[t] - _activeCounts[t]) / tierTargets[t])
                .ToList();

            if (candidates.Any())
            {
                // Return the tier that is most "hungry" (furthest from its target percentage)
                return candidates.First();
            }

            // Priority 2: If all are over target (e.g. some tiers are empty), just pick by priority
            if (!_tier1Queue.IsEmpty) return ScanTier.Tier1_HighHistorical;
            if (!_tier2Queue.IsEmpty) return ScanTier.Tier2_HighRelevance;
            if (!_tier3Queue.IsEmpty) return ScanTier.Tier3_AutoSeed;

            return null;
        }

        private bool IsTierAvailable(ScanTier tier)
        {
            return tier switch
            {
                ScanTier.Tier1_HighHistorical => !_tier1Queue.IsEmpty,
                ScanTier.Tier2_HighRelevance => !_tier2Queue.IsEmpty,
                ScanTier.Tier3_AutoSeed => !_tier3Queue.IsEmpty,
                _ => false
            };
        }

        public void RecordResult(ScanTier tier, bool success)
        {
            lock (_lock)
            {
                _activeCounts[tier]--;
                var current = _stats[tier];
                _stats[tier] = (current.success + (success ? 1 : 0), current.total + 1);

                AdaptWeights();
            }
        }

        private void AdaptWeights()
        {
            // Task 3: Real-time adaptation
            // Only adapt after a reasonable sample size per tier (e.g., 20)
            foreach (var tier in _stats.Keys.ToList())
            {
                if (_stats[tier].total < 20) continue;

                double hitRate = (double)_stats[tier].success / _stats[tier].total;

                if (tier == ScanTier.Tier1_HighHistorical && hitRate < 0.02)
                {
                    // Tier 1 failing -> shift 5% to Tier 2
                    if (_weights[ScanTier.Tier1_HighHistorical] > 0.20)
                    {
                        _weights[ScanTier.Tier1_HighHistorical] -= 0.05;
                        _weights[ScanTier.Tier2_HighRelevance] += 0.05;
                        ResetStats(tier);
                    }
                }
                else if (tier == ScanTier.Tier3_AutoSeed && hitRate > 0.10)
                {
                    // Tier 3 spiking -> shift 5% from Tier 2 to Tier 3
                    if (_weights[ScanTier.Tier2_HighRelevance] > 0.10)
                    {
                        _weights[ScanTier.Tier2_HighRelevance] -= 0.05;
                        _weights[ScanTier.Tier3_AutoSeed] += 0.05;
                        ResetStats(tier);
                    }
                }
            }
        }

        private void ResetStats(ScanTier tier)
        {
            _stats[tier] = (0, 0);
        }
    }
}
