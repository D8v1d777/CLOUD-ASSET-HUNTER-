using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace CloudHunter;

public class AlertEngine
{
    private static readonly HttpClient _client = new HttpClient();
    private static readonly Dictionary<string, DateTime> _lastAlertTime = new();
    private static readonly object _lock = new();

    public static async Task FireAlertAsync(List<ValidationResult> diffs)
    {
        var webhookUrl = Environment.GetEnvironmentVariable("WEBHOOK_URL");
        if (string.IsNullOrEmpty(webhookUrl))
        {
            Console.WriteLine("WEBHOOK_URL not set. Skipping alerts.");
            return;
        }

        if (diffs.Count == 0) return;

        // Task 5: Group alerts by root domain
        var groupedByDomain = diffs.GroupBy(d => {
            var uri = new Uri(d.Url);
            var hostParts = uri.Host.Split('.');
            return hostParts.Length >= 2 ? string.Join(".", hostParts.TakeLast(2)) : uri.Host;
        });

        foreach (var group in groupedByDomain)
        {
            // Task 4: Rate limiting per domain (e.g., max 1 alert per 5 minutes per domain)
            lock (_lock)
            {
                if (_lastAlertTime.TryGetValue(group.Key, out var lastTime))
                {
                    if (DateTime.UtcNow - lastTime < TimeSpan.FromMinutes(5))
                    {
                        Console.WriteLine($"[!] Rate limiting alert for domain {group.Key}. Last alert was {lastTime}.");
                        continue;
                    }
                }
                _lastAlertTime[group.Key] = DateTime.UtcNow;
            }

            var messageBuilder = new StringBuilder();
            messageBuilder.AppendLine($"🚀 **Domain Intelligence Report: {group.Key}** 🚀");
            messageBuilder.AppendLine("---");

            // Batch alerts: limit to top 10 findings per domain alert to avoid payload size issues (Task 4)
            var topFindings = group.OrderByDescending(d => d.PriorityScore).Take(10);

            foreach (var d in topFindings)
            {
                var priorityEmoji = d.PriorityLabel switch {
                    "HIGH" => "🔥",
                    "MEDIUM" => "⚠️",
                    _ => "⚪"
                };

                messageBuilder.AppendLine($"{priorityEmoji} **{d.PriorityLabel}** | {d.Cloud} | {d.Decision}");
                messageBuilder.AppendLine($"> **URL:** {d.Url}");
                messageBuilder.AppendLine($"> **Score:** `{d.PriorityScore:P0}` | **Action:** {d.RecommendedAction}");
                
                if (d.PriorityScore >= 0.75)
                {
                    messageBuilder.AppendLine($"> **Summary:** {d.Evidence.Summary}");
                    if (d.Evidence.SensitiveFiles.Any())
                    {
                        messageBuilder.AppendLine("> **Sensitive Files Found:**");
                        foreach (var file in d.Evidence.SensitiveFiles.Take(3))
                            messageBuilder.AppendLine($">   - `{file}`");
                    }
                }
                
                messageBuilder.AppendLine("---");
            }

            if (group.Count() > 10)
            {
                messageBuilder.AppendLine($"*Note: {group.Count() - 10} additional findings for this domain were batched and saved to DB.*");
            }

            var payload = new { content = messageBuilder.ToString() };
            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            try
            {
                var response = await _client.PostAsync(webhookUrl, content);
                if (response.IsSuccessStatusCode)
                    Console.WriteLine($"Alert fired for domain {group.Key}.");
                else
                    Console.WriteLine($"Failed to fire alert for {group.Key}. Status: {response.StatusCode}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending alert for {group.Key}: {ex.Message}");
            }
        }
    }
}
