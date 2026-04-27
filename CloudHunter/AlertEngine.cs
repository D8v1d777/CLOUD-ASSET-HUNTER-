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
            var messageBuilder = new StringBuilder();
            messageBuilder.AppendLine($"🚀 **Domain Intelligence Report: {group.Key}** 🚀");
            messageBuilder.AppendLine("---");

            foreach (var d in group)
            {
                var priorityEmoji = d.PriorityLabel switch {
                    "HIGH" => "🔥",
                    "MEDIUM" => "⚠️",
                    _ => "⚪"
                };

                messageBuilder.AppendLine($"{priorityEmoji} **{d.PriorityLabel} PRIORITY** | {d.Cloud}");
                messageBuilder.AppendLine($"> **URL:** {d.Url}");
                messageBuilder.AppendLine($"> **Score:** `{d.PriorityScore:P0}` | **Confidence:** `{d.Confidence:P0}` | **Impact:** `{d.ImpactScore:P0}`");
                
                messageBuilder.AppendLine($"> **Summary:** {d.Evidence.Summary}");

                if (d.Evidence.SensitiveFiles.Any())
                {
                    messageBuilder.AppendLine("> **Sensitive Files Found:**");
                    foreach (var file in d.Evidence.SensitiveFiles.Take(5))
                        messageBuilder.AppendLine($">   - `{file}`");
                }

                if (d.Evidence.Snippets.Any())
                {
                    messageBuilder.AppendLine("> **Data Snippets:**");
                    foreach (var snippet in d.Evidence.Snippets)
                    {
                        var cleanSnippet = snippet.Content.Replace("`", "'").Replace("\n", " ").Replace("\r", "");
                        messageBuilder.AppendLine($">   - `{snippet.Filename}`: ```{cleanSnippet}```");
                    }
                }
                
                messageBuilder.AppendLine("---");
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
