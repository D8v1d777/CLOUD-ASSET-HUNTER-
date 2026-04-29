using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading;
using System.Threading.Tasks;

namespace CloudHunter
{
    public enum ScanTier
    {
        Tier1_HighHistorical = 0,
        Tier2_HighRelevance = 1,
        Tier3_AutoSeed = 2
    }

    public record ScanTarget(string Url, string Cloud, ScanTier Tier, DateTime QueuedAt);

    public class TierMetrics
    {
        public long ProcessedCount;
        public long SuccessCount;
        public long FailureCount;
        public long TotalWaitMs;
    }

    public class ScanPlanner
    {
        // Memory Safety: Hard bounds for 175k total in-flight targets
        private const int CapT1 = 100_000;
        private const int CapT2 = 50_000;
        private const int CapT3 = 25_000;

        private readonly Channel<ScanTarget>[] _channels;
        private readonly TierMetrics[] _metrics;
        
        private volatile ScanTier[] _strideTable;
        private long _globalSequenceIndex = 0;
        private long _droppedTier3Count = 0;
        private double _lastPressure = -1.0;
        private long _totalQueued = 0;

        public int TotalQueued => (int)Interlocked.Read(ref _totalQueued);

        public ScanPlanner()
        {
            _channels = new[]
            {
                Channel.CreateBounded<ScanTarget>(new BoundedChannelOptions(CapT1) { SingleReader = false, FullMode = BoundedChannelFullMode.Wait }),
                Channel.CreateBounded<ScanTarget>(new BoundedChannelOptions(CapT2) { SingleReader = false, FullMode = BoundedChannelFullMode.Wait }),
                Channel.CreateBounded<ScanTarget>(new BoundedChannelOptions(CapT3) { SingleReader = false, FullMode = BoundedChannelFullMode.DropWrite })
            };

            _metrics = new[] { new TierMetrics(), new TierMetrics(), new TierMetrics() };
            _strideTable = GenerateStrideTable(0.0);
        }

        public async ValueTask EnqueueAsync(ScanTarget target, double pressure, CancellationToken ct = default)
        {
            // 1. Dynamic Weight Shifting based on System Pressure
            if (Math.Abs(_lastPressure - pressure) > 0.05)
            {
                _strideTable = GenerateStrideTable(pressure);
                _lastPressure = pressure;
            }

            // 2. Stable Backpressure: Prune exploratory data when system is under high stress
            if (target.Tier == ScanTier.Tier3_AutoSeed && pressure > 0.75)
            {
                Interlocked.Increment(ref _droppedTier3Count);
                return;
            }

            var channel = _channels[(int)target.Tier];
            if (!channel.Writer.TryWrite(target))
            {
                await channel.Writer.WriteAsync(target, ct);
            }

            Interlocked.Increment(ref _totalQueued);
        }

        public async Task<ScanTarget?> GetNextAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                if (Interlocked.Read(ref _totalQueued) == 0)
                {
                    await Task.WhenAny(_channels.Select(c => c.Reader.WaitToReadAsync(ct).AsTask()));
                }

                var sequence = Interlocked.Increment(ref _globalSequenceIndex);
                var preferredTier = (int)_strideTable[sequence % 100];

                // Final Scheduling Model: Deterministic Stride with Fair Sequential Fallback
                for (int i = 0; i < 3; i++)
                {
                    int currentTier = (preferredTier + i) % 3;
                    if (_channels[currentTier].Reader.TryRead(out var target))
                    {
                        Interlocked.Decrement(ref _totalQueued);
                        UpdateMetrics(target);
                        return target;
                    }
                }
            }
            return null;
        }

        private void UpdateMetrics(ScanTarget target)
        {
            var m = _metrics[(int)target.Tier];
            Interlocked.Increment(ref m.ProcessedCount);
            Interlocked.Add(ref m.TotalWaitMs, (long)(DateTime.UtcNow - target.QueuedAt).TotalMilliseconds);
        }

        public void RecordResult(ScanTier tier, bool success)
        {
            var m = _metrics[(int)tier];
            if (success) Interlocked.Increment(ref m.SuccessCount);
            else Interlocked.Increment(ref m.FailureCount);
        }

        private ScanTier[] GenerateStrideTable(double pressure)
        {
            // Adjust weights based on system pressure: shift exploratory bandwidth to historical success
            int t1Count = (int)(50 + (35 * pressure)); // 50% -> 85%
            int t2Count = (int)(30 - (15 * pressure)); // 30% -> 15%
            int t3Count = 100 - t1Count - t2Count;

            var table = new ScanTier[100];
            for (int i = 0; i < 100; i++)
            {
                if (i < t1Count) table[i] = ScanTier.Tier1_HighHistorical;
                else if (i < t1Count + t2Count) table[i] = ScanTier.Tier2_HighRelevance;
                else table[i] = ScanTier.Tier3_AutoSeed;
            }

            // Use Fisher-Yates shuffle for O(n) deterministic distribution
            var rng = new Random(42);
            for (int i = table.Length - 1; i > 0; i--)
            {
                int k = rng.Next(i + 1);
                var temp = table[k];
                table[k] = table[i];
                table[i] = temp;
            }

            return table;
        }

        public Dictionary<string, long> GetObservabilityMetrics() => new() {
            { "T1_Depth", _channels[0].Reader.Count },
            { "T2_Depth", _channels[1].Reader.Count },
            { "T3_Depth", _channels[2].Reader.Count },
            { "Dropped_T3", Interlocked.Read(ref _droppedTier3Count) },
            { "AvgWait_T1_Ms", GetAvgWait(0) }
        };

        private long GetAvgWait(int tierIdx)
        {
            var m = _metrics[tierIdx];
            var processed = Interlocked.Read(ref m.ProcessedCount);
            return processed == 0 ? 0 : Interlocked.Read(ref m.TotalWaitMs) / processed;
        }
    }
}
