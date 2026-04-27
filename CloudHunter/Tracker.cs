using System;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;

namespace CloudHunter;

public interface ITracker
{
    void UpsertAsset(ValidationResult result, string state);
    List<ValidationResult> GetDiff();
    void MarkValidationStatus(string url, string status);
    Dictionary<string, (int FP, int Total)> GetSignalMetrics();
    void LogFailure(string domain, string errorType);
    void UpdateDomainStats(string domain, bool foundExposure);
    List<DomainStat> GetHistoricalTopDomains(int limit);
    string ExportStructuredReport(string format);
}

public record DomainStat(string Domain, int SuccessCount, int TotalScans, double HitRate);

public class Tracker : ITracker
{
    private readonly string _dbPath;

    public Tracker(string dbPath = "assets.db")
    {
        _dbPath = dbPath;
        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                cloud TEXT,
                state TEXT,
                confidence REAL,
                impact_score REAL,
                priority_score REAL,
                priority_label TEXT,
                evidence_json TEXT,
                signal_scores_json TEXT,
                validation_status TEXT DEFAULT 'unknown',
                first_seen TEXT,
                last_seen TEXT,
                changed INTEGER
            );

            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signal_name TEXT UNIQUE,
                false_positive_count INTEGER DEFAULT 0,
                total_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS domain_stats (
                domain TEXT PRIMARY KEY,
                success_count INTEGER DEFAULT 0,
                total_scans INTEGER DEFAULT 0,
                last_scan TEXT
            );

            CREATE TABLE IF NOT EXISTS failure_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                error_type TEXT,
                count INTEGER DEFAULT 1,
                last_seen TEXT,
                UNIQUE(domain, error_type)
            );
        ";
        command.ExecuteNonQuery();

        // Migration: Add signal_scores_json if it doesn't exist
        var migrateCmd = connection.CreateCommand();
        migrateCmd.CommandText = "PRAGMA table_info(assets)";
        var columns = new List<string>();
        using (var reader = migrateCmd.ExecuteReader())
        {
            while (reader.Read()) columns.Add(reader.GetString(1));
        }
        if (!columns.Contains("signal_scores_json"))
        {
            var addColCmd = connection.CreateCommand();
            addColCmd.CommandText = "ALTER TABLE assets ADD COLUMN signal_scores_json TEXT";
            addColCmd.ExecuteNonQuery();
        }
        if (!columns.Contains("validation_status"))
        {
            var addColCmd = connection.CreateCommand();
            addColCmd.CommandText = "ALTER TABLE assets ADD COLUMN validation_status TEXT DEFAULT 'unknown'";
            addColCmd.ExecuteNonQuery();
        }

        // Baseline metrics for cold start (Task 2)
        // These ensure signals have a baseline denominator to prevent initial volatility
        var baselineCmd = connection.CreateCommand();
        baselineCmd.CommandText = @"
            INSERT OR IGNORE INTO metrics (signal_name, false_positive_count, total_count) VALUES ('keyword', 0, 10);
            INSERT OR IGNORE INTO metrics (signal_name, false_positive_count, total_count) VALUES ('volume', 0, 10);
            INSERT OR IGNORE INTO metrics (signal_name, false_positive_count, total_count) VALUES ('header', 0, 10);
            INSERT OR IGNORE INTO metrics (signal_name, false_positive_count, total_count) VALUES ('entropy', 0, 10);
        ";
        baselineCmd.ExecuteNonQuery();
    }

    public void LogFailure(string domain, string errorType)
    {
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();
        var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO failure_logs (domain, error_type, last_seen) 
            VALUES (@domain, @type, @now) 
            ON CONFLICT(domain, error_type) DO UPDATE SET count = count + 1, last_seen = @now";
        cmd.Parameters.AddWithValue("@domain", domain);
        cmd.Parameters.AddWithValue("@type", errorType);
        cmd.Parameters.AddWithValue("@now", DateTime.UtcNow.ToString("O"));
        cmd.ExecuteNonQuery();
    }

    public void UpdateDomainStats(string domain, bool foundExposure)
    {
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();
        var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO domain_stats (domain, success_count, total_scans, last_scan) 
            VALUES (@domain, @s, 1, @now) 
            ON CONFLICT(domain) DO UPDATE SET 
                success_count = success_count + @s, 
                total_scans = total_scans + 1, 
                last_scan = @now";
        cmd.Parameters.AddWithValue("@domain", domain);
        cmd.Parameters.AddWithValue("@s", foundExposure ? 1 : 0);
        cmd.Parameters.AddWithValue("@now", DateTime.UtcNow.ToString("O"));
        cmd.ExecuteNonQuery();
    }

    public List<DomainStat> GetHistoricalTopDomains(int limit)
    {
        var stats = new List<DomainStat>();
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();
        var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT domain, success_count, total_scans FROM domain_stats ORDER BY success_count DESC LIMIT @limit";
        cmd.Parameters.AddWithValue("@limit", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            int s = reader.GetInt32(1);
            int t = reader.GetInt32(2);
            stats.Add(new DomainStat(reader.GetString(0), s, t, (double)s / t));
        }
        return stats;
    }

    public string ExportStructuredReport(string format)
    {
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();

        // Fetch all relevant findings sorted by priority
        var findings = new List<dynamic>();
        var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT url, cloud, priority_score, impact_score, confidence, validation_status, last_seen, evidence_json FROM assets WHERE priority_score > 0.1 ORDER BY priority_score DESC";
        
        using (var reader = cmd.ExecuteReader())
        {
            while (reader.Read())
            {
                findings.Add(new {
                    Url = reader.GetString(0),
                    Cloud = reader.GetString(1),
                    Priority = reader.GetDouble(2),
                    Impact = reader.GetDouble(3),
                    Confidence = reader.GetDouble(4),
                    Status = reader.GetString(5),
                    LastSeen = reader.GetString(6),
                    EvidenceJson = reader.GetString(7)
                });
            }
        }

        if (format.ToLower() == "csv")
        {
            var sb = new System.Text.StringBuilder();
            
            // 1. Executive Summary
            var criticalCount = findings.Count(f => f.Priority >= 0.85);
            var highCount = findings.Count(f => f.Priority >= 0.7 && f.Priority < 0.85);
            var mediumCount = findings.Count(f => f.Priority >= 0.5 && f.Priority < 0.7);
            
            sb.AppendLine("=== EXECUTIVE EXPOSURE SUMMARY ===");
            sb.AppendLine($"Total Findings: {findings.Count}");
            sb.AppendLine($"Critical Priority (0.85+): {criticalCount}");
            sb.AppendLine($"High Priority (0.7-0.85): {highCount}");
            sb.AppendLine($"Medium Priority (0.5-0.7): {mediumCount}");
            
            // Top affected domains logic
            var domains = findings.GroupBy(f => {
                try { return new Uri(f.Url).Host; } catch { return "unknown"; }
            }).OrderByDescending(g => g.Count()).Take(3);
            
            sb.AppendLine("Top Affected Domains:");
            foreach (var d in domains) sb.AppendLine($"- {d.Key} ({d.Count()} findings)");
            sb.AppendLine("==================================");
            sb.AppendLine();

            // 2. CSV Header
            sb.AppendLine("Classification,URL,Priority,Confidence,Impact,Risk Explanation,Recommended Action,Evidence Summary,Cloud,LastSeen");

            // 3. Findings
            foreach (var f in findings)
            {
                string classification = f.Priority >= 0.85 ? "CRITICAL" : (f.Priority >= 0.7 ? "HIGH" : (f.Priority >= 0.5 ? "MEDIUM" : "LOW"));
                
                // Human-readable risk explanation
                string riskExplanation = classification switch {
                    "CRITICAL" => "Immediate risk of full compromise. Highly sensitive data or credentials are listable and accessible.",
                    "HIGH" => "Significant risk. Internal files or configuration data are exposed without authentication.",
                    "MEDIUM" => "Moderate risk. Asset is unauthenticated and contains potentially internal information.",
                    _ => "Low risk. Monitor for changes in access level or content."
                };

                // Recommended Action (simulating logic from CloudValidator for reporting)
                string action = classification switch {
                    "CRITICAL" => "ACTION REQUIRED: Secure bucket/container immediately and rotate any exposed keys.",
                    "HIGH" => "ACTION REQUIRED: Restrict public access and verify intentionality of exposure.",
                    "MEDIUM" => "RECOMMENDED: Review access policies and data sensitivity.",
                    _ => "MONITOR: Periodically audit for sensitive content."
                };

                // Extract summary from EvidenceJson if possible
                string summary = "Exposure detected.";
                try {
                    var evidence = System.Text.Json.JsonDocument.Parse(f.EvidenceJson);
                    if (evidence.RootElement.TryGetProperty("Summary", out var s)) summary = s.GetString().Replace(",", ";");
                } catch { }

                sb.AppendLine($"{classification},{f.Url},{f.Priority:F4},{f.Confidence:F4},{f.Impact:F4},\"{riskExplanation}\",\"{action}\",\"{summary}\",{f.Cloud},{f.LastSeen}");
            }
            return sb.ToString();
        }
        else if (format.ToLower() == "json")
        {
            var report = new {
                GeneratedAt = DateTime.UtcNow,
                Summary = new {
                    TotalExposures = findings.Count,
                    Critical = findings.Count(f => f.Priority >= 0.85),
                    High = findings.Count(f => f.Priority >= 0.7 && f.Priority < 0.85),
                    Medium = findings.Count(f => f.Priority >= 0.5 && f.Priority < 0.7)
                },
                Findings = findings.Select(f => {
                    string classification = f.Priority >= 0.85 ? "CRITICAL" : (f.Priority >= 0.7 ? "HIGH" : (f.Priority >= 0.5 ? "MEDIUM" : "LOW"));
                    return new {
                        Classification = classification,
                        Url = f.Url,
                        Priority = f.Priority,
                        Confidence = f.Confidence,
                        Impact = f.Impact,
                        Risk = classification switch {
                            "CRITICAL" => "Immediate risk of full compromise.",
                            "HIGH" => "Significant risk of internal data exposure.",
                            "MEDIUM" => "Moderate risk of information leakage.",
                            _ => "Low risk baseline exposure."
                        },
                        Action = classification switch {
                            "CRITICAL" => "Secure immediately, rotate keys.",
                            "HIGH" => "Restrict access, verify content.",
                            "MEDIUM" => "Review sensitivity.",
                            _ => "Monitor."
                        },
                        Cloud = f.Cloud,
                        LastSeen = f.LastSeen
                    };
                })
            };
            return System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        }
        return "Unsupported format";
    }

    public void UpsertAsset(ValidationResult result, string state)
    {
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();

        var now = DateTime.UtcNow.ToString("O");
        var evidenceJson = System.Text.Json.JsonSerializer.Serialize(result.Evidence);
        var signalScoresJson = System.Text.Json.JsonSerializer.Serialize(result.SignalScores);

        // Check if exists
        var checkCmd = connection.CreateCommand();
        checkCmd.CommandText = "SELECT confidence FROM assets WHERE url = @url";
        checkCmd.Parameters.AddWithValue("@url", result.Url);
        
        var existingConfidence = checkCmd.ExecuteScalar();

        var upsertCmd = connection.CreateCommand();
        if (existingConfidence == null)
        {
            // Insert new
            upsertCmd.CommandText = @"
                INSERT INTO assets (url, cloud, state, confidence, impact_score, priority_score, priority_label, evidence_json, signal_scores_json, first_seen, last_seen, changed)
                VALUES (@url, @cloud, @state, @confidence, @impact_score, @priority_score, @priority_label, @evidence_json, @signal_scores_json, @now, @now, 1)
            ";
        }
        else
        {
            // Update existing
            double oldConf = Convert.ToDouble(existingConfidence);
            int changed = (Math.Abs(oldConf - result.Confidence) > 0.01) ? 1 : 0;
            
            upsertCmd.CommandText = @"
                UPDATE assets 
                SET state = @state, 
                    confidence = @confidence, 
                    impact_score = @impact_score,
                    priority_score = @priority_score,
                    priority_label = @priority_label,
                    evidence_json = @evidence_json,
                    signal_scores_json = @signal_scores_json,
                    last_seen = @now, 
                    changed = @changed
                WHERE url = @url
            ";
            upsertCmd.Parameters.AddWithValue("@changed", changed);
        }

        upsertCmd.Parameters.AddWithValue("@url", result.Url);
        upsertCmd.Parameters.AddWithValue("@cloud", result.Cloud);
        upsertCmd.Parameters.AddWithValue("@state", state);
        upsertCmd.Parameters.AddWithValue("@confidence", result.Confidence);
        upsertCmd.Parameters.AddWithValue("@impact_score", result.ImpactScore);
        upsertCmd.Parameters.AddWithValue("@priority_score", result.PriorityScore);
        upsertCmd.Parameters.AddWithValue("@priority_label", result.PriorityLabel);
        upsertCmd.Parameters.AddWithValue("@evidence_json", evidenceJson);
        upsertCmd.Parameters.AddWithValue("@signal_scores_json", signalScoresJson);
        upsertCmd.Parameters.AddWithValue("@now", now);

        upsertCmd.ExecuteNonQuery();

        // Update metrics: increment total_count for signals that fired
        foreach (var signal in result.SignalScores)
        {
            if (signal.Value > 0)
            {
                var metricCmd = connection.CreateCommand();
                metricCmd.CommandText = "INSERT INTO metrics (signal_name, total_count) VALUES (@name, 1) ON CONFLICT(signal_name) DO UPDATE SET total_count = total_count + 1";
                metricCmd.Parameters.AddWithValue("@name", signal.Key);
                metricCmd.ExecuteNonQuery();
            }
        }
    }

    public List<ValidationResult> GetDiff()
    {
        var diffs = new List<ValidationResult>();
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();

        var command = connection.CreateCommand();
        // Task 5: Return assets that are newly exposed or upgraded with high priority (> 0.75)
        command.CommandText = "SELECT url, cloud, confidence, impact_score, priority_score, priority_label, evidence_json, signal_scores_json FROM assets WHERE changed = 1 AND priority_score >= 0.75";
        
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var evidenceJson = reader.GetString(6);
            var evidence = System.Text.Json.JsonSerializer.Deserialize<Evidence>(evidenceJson) ?? new Evidence();

            var signalScoresJson = reader.IsDBNull(7) ? "{}" : reader.GetString(7);
            var signalScores = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, double>>(signalScoresJson) ?? new();

            // Task 6: Populate Decision/Action for alerts
            double priority = reader.GetDouble(4);
            string decision = priority >= 0.75 ? "IMMEDIATE_TRIAGE" : (priority >= 0.40 ? "REVIEW_REQUIRED" : "MONITOR");
            string recommendedAction = decision switch
            {
                "IMMEDIATE_TRIAGE" => "CRITICAL: Secure bucket/container immediately. Review sensitive snippets for credentials or keys.",
                "REVIEW_REQUIRED" => "WARNING: Verify if exposure is intentional. Check for internal non-sensitive data exposure.",
                "MONITOR" => "INFO: No immediate action required. Asset added to baseline monitoring list.",
                _ => "UNKNOWN: Requires manual investigation."
            };

            diffs.Add(new ValidationResult
            {
                Url = reader.GetString(0),
                Cloud = reader.GetString(1),
                Confidence = reader.GetDouble(2),
                ImpactScore = reader.GetDouble(3),
                PriorityScore = priority,
                PriorityLabel = reader.GetString(5),
                Evidence = evidence,
                SignalScores = signalScores,
                Decision = decision,
                RecommendedAction = recommendedAction
            });
        }

        var resetCmd = connection.CreateCommand();
        resetCmd.CommandText = "UPDATE assets SET changed = 0 WHERE changed = 1";
        resetCmd.ExecuteNonQuery();

        return diffs;
    }

    public void MarkValidationStatus(string url, string status)
    {
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();

        // Fetch signal scores to update metrics if false positive
        var fetchCmd = connection.CreateCommand();
        fetchCmd.CommandText = "SELECT signal_scores_json FROM assets WHERE url = @url";
        fetchCmd.Parameters.AddWithValue("@url", url);
        var signalScoresJson = fetchCmd.ExecuteScalar()?.ToString();
        var signalScores = string.IsNullOrEmpty(signalScoresJson) 
            ? new Dictionary<string, double>() 
            : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, double>>(signalScoresJson) ?? new();

        var command = connection.CreateCommand();
        command.CommandText = "UPDATE assets SET validation_status = @status WHERE url = @url";
        command.Parameters.AddWithValue("@status", status);
        command.Parameters.AddWithValue("@url", url);
        command.ExecuteNonQuery();
        
        // Task 6: Feedback loop - increment false positive metrics per signal
        if (status == "false_positive")
        {
            foreach (var signal in signalScores)
            {
                if (signal.Value > 0)
                {
                    var metricCmd = connection.CreateCommand();
                    metricCmd.CommandText = "INSERT INTO metrics (signal_name, false_positive_count) VALUES (@name, 1) ON CONFLICT(signal_name) DO UPDATE SET false_positive_count = false_positive_count + 1";
                    metricCmd.Parameters.AddWithValue("@name", signal.Key);
                    metricCmd.ExecuteNonQuery();
                }
            }
        }
    }

    public Dictionary<string, (int FP, int Total)> GetSignalMetrics()
    {
        var metrics = new Dictionary<string, (int FP, int Total)>();
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = "SELECT signal_name, false_positive_count, total_count FROM metrics";
        
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            metrics[reader.GetString(0)] = (reader.GetInt32(1), reader.GetInt32(2));
        }
        return metrics;
    }
}
