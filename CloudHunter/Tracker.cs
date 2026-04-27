using System;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;

namespace CloudHunter;

public class Tracker
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

            diffs.Add(new ValidationResult
            {
                Url = reader.GetString(0),
                Cloud = reader.GetString(1),
                Confidence = reader.GetDouble(2),
                ImpactScore = reader.GetDouble(3),
                PriorityScore = reader.GetDouble(4),
                PriorityLabel = reader.GetString(5),
                Evidence = evidence,
                SignalScores = signalScores
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
}
