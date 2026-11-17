using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Schiza.Application;
using Schiza.Application.Legacy;
using Schiza.LogEngine.Parsing;

namespace Schiza.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton<IApacheLogParser, ApacheLogParser>();
        services.AddSingleton<SqliteFlaggedEventRepository>();
        services.AddSingleton<IFlaggedEventRepository>(services => services.GetRequiredService<SqliteFlaggedEventRepository>());
        services.AddSingleton<LogEventProcessor>();
        services.AddSingleton<FlaggedEventQueries>();
        services.AddSingleton<IAuthenticationService, ConfigurationAuthenticationService>();
        services.AddSingleton<IRuleStore, InMemoryRuleStore>();
        services.AddSingleton<IEventStore, InMemoryEventStore>();
        services.AddSingleton<IRequestClassifier, StaticRuleClassifier>();
        services.AddHostedService<ApacheLogWorker>();
        services.AddHostedService<FlaggedEventRetentionWorker>();
        services.AddHttpClient<IAnomalyDetector, PythonAnomalyDetector>(client =>
        {
            string url = configuration["PythonDetection:BaseUrl"] ?? "http://127.0.0.1:8000/";
            client.BaseAddress = new Uri(url, UriKind.Absolute);
            client.Timeout = TimeSpan.FromSeconds(30);
        });
        return services;
    }
}
