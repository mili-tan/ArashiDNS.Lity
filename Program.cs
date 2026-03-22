using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Caching;
using Arashi;
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using MaxMind.GeoIP2;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

namespace ArashiDNS.Lity
{
    internal class Program
    {
        public static IPEndPoint ListenEndpoint = new(IPAddress.Any, 5380);
        public static int QueryTimeoutMs = 500;
        public static string QueryPath = "dns-query";
        public static string QueryParamKey = "dns";
        public static bool EnableResponseValidation = false;
        public static bool EnableRequestDeduplication = true;
        public static bool EnableEcsEcho = true;
        public static bool EnableCache = false;
        public static bool EnableGeoCache = false;
        public static bool EnableOptimisticCache = false;
        public static bool MonitorUpstreamPort = true;
        public static bool UseHardDeduplication = false;
        public static bool UseDictionaryCache = false;
        public static int DeduplicationWaitMs = 100;
        public static IPEndPoint UpstreamEndpoint = new(IPAddress.Parse("8.8.8.8"), 53);
        public static Dictionary<string, IPEndPoint> CustomPathUpstreamMappings = new();

        private static readonly ConcurrentDictionary<string, SemaphoreSlim> RequestSemaphores = new();

        public static DatabaseReader? AsnReader;
        public static DatabaseReader? CityReader;

        public static int MinTtlSeconds = 60;
        public static int MaxTtlSeconds = 86400;
        public static int OptimisticTtlSeconds = 30;

        public static ConcurrentDictionary<(DnsQuestion, string), CacheEntry> CacheEntries = new();

        public record CacheEntry(DnsMessage ResponseData, DateTimeOffset ExpiryTime);

        public static Timer? CleanupTimer;
        public static TimeSpan CleanupInterval = TimeSpan.FromHours(1);
        public static TimeSpan StaleDataThreshold = TimeSpan.FromHours(12);

        public static ObjectPool<RecursiveDnsResolver> RecursiveResolverPool = new(() =>
            new RecursiveDnsResolver
            {
                Is0x20ValidationEnabled = EnableResponseValidation,
                IsResponseValidationEnabled = EnableResponseValidation,
                QueryTimeout = QueryTimeoutMs
            });

        static void Main(string[] args)
        {
            var cmd = new CommandLineApplication
            {
                Name = "ArashiDNS.Lity",
                Description =
                    $"ArashiDNS.Lity - Minimal DNS over HTTPS server with Recursive Resolver{Environment.NewLine}" +
                    $"Copyright (c) {DateTime.Now.Year} Milkey Tan. Code released under the MIT License"
            };

            cmd.HelpOption("-?|-he|--help");
            var isZh = Thread.CurrentThread.CurrentCulture.Name.Contains("zh");

            var timeoutOption = cmd.Option<int>("-w <TimeOut>",
                isZh ? "等待回复的超时时间（毫秒）。[3000]" : "Timeout for waiting response (ms). [3000]",
                CommandOptionType.SingleValue);
            var listenOption = cmd.Option<string>("-l <IPEndPoint>",
                isZh ? "设置监听地址和端口。[8.8.8.8:5380]" : "Set listen address and port. [8.8.8.8:5380]",
                CommandOptionType.SingleValue);
            var upstreamOption = cmd.Option<string>("-s <IPEndPoint>",
                isZh
                    ? "设置上游地址，为 0.0.0.0 时使用递归。[8.8.8.8:53]"
                    : "Set upstream address, use recursion if 0.0.0.0. [8.8.8.8:53]", CommandOptionType.SingleValue);
            var pathOption = cmd.Option<string>("-p <Path>", isZh ? "查询路径。[/dns-query]" : "Query path. [/dns-query]",
                CommandOptionType.SingleValue);
            var keyOption = cmd.Option<string>("-k <Key>", isZh ? "查询参数。[dns]" : "Query parameter. [dns]",
                CommandOptionType.SingleValue);
            var validationOption = cmd.Option<bool>("-v",
                isZh
                    ? "启用 DNS 响应验证（0x20 和 RRSIG，对于递归）。"
                    : "Enable DNS response validation (0x20 and RRSIG, for recursion).", CommandOptionType.NoValue);
            var noDeduplicationOption = cmd.Option<bool>("-nrw",
                isZh ? "不启用重复查询等待以防止缓存穿透。" : "Disabled repeated query wait to prevent cache penetration.",
                CommandOptionType.NoValue);
            var deduplicationWaitTimeOption = cmd.Option<int>("-rwt <Seconds>",
                isZh ? "重复查询等待的最大时间（毫秒）。[100]" : "Maximum time for repeated query wait (ms). [100]",
                CommandOptionType.SingleValue);
            var cacheOption = cmd.Option<bool>("-c", isZh ? "启用缓存。" : "Enable caching.", CommandOptionType.NoValue);
            var optimisticCacheOption = cmd.Option<bool>("-oc",
                isZh
                    ? "启用乐观缓存（可能返回过期数据，但能减少上游查询）。"
                    : "Enable optimistic cache (may return stale data but reduces upstream queries).",
                CommandOptionType.NoValue);
            var geoCacheOption = cmd.Option<bool>("-geoc",
                isZh
                    ? "启用基于地理位置的缓存（需要 GeoLite2 ASN&City 数据库）。"
                    : "Enable geo-location based cache (requires GeoLite2 databases).", CommandOptionType.NoValue);
            var staleThresholdOption = cmd.Option<int>("-st <Hours>",
                isZh ? "乐观缓存的过期数据阈值（小时）。[12]" : "Stale data threshold for optimistic cache (Hours). [12]",
                CommandOptionType.SingleValue);
            var maxTtlOption = cmd.Option<int>("-max-t <Seconds>",
                isZh ? "缓存的最大TTL（秒）。[86400]" : "Maximum TTL for cache (Seconds). [86400]",
                CommandOptionType.SingleValue);
            var minTtlOption = cmd.Option<int>("-min-t <Seconds>",
                isZh ? "缓存的最小TTL（秒）。[60]" : "Minimum TTL for cache (Seconds). [60]", CommandOptionType.SingleValue);

            cmd.OnExecute(() =>
            {
                if (timeoutOption.HasValue()) QueryTimeoutMs = timeoutOption.ParsedValue;
                if (listenOption.HasValue()) ListenEndpoint = IPEndPoint.Parse(listenOption.ParsedValue);
                if (upstreamOption.HasValue()) UpstreamEndpoint = IPEndPoint.Parse(upstreamOption.ParsedValue);
                if (pathOption.HasValue()) QueryPath = pathOption.ParsedValue;
                if (keyOption.HasValue()) QueryParamKey = keyOption.ParsedValue;
                if (validationOption.HasValue()) EnableResponseValidation = validationOption.ParsedValue;
                if (cacheOption.HasValue()) EnableCache = cacheOption.ParsedValue;
                if (optimisticCacheOption.HasValue()) EnableOptimisticCache = optimisticCacheOption.ParsedValue;
                if (maxTtlOption.HasValue()) MaxTtlSeconds = maxTtlOption.ParsedValue;
                if (minTtlOption.HasValue()) MinTtlSeconds = minTtlOption.ParsedValue;
                if (staleThresholdOption.HasValue())
                    StaleDataThreshold = TimeSpan.FromHours(staleThresholdOption.ParsedValue);
                if (geoCacheOption.HasValue()) EnableGeoCache = geoCacheOption.ParsedValue;

                if (UpstreamEndpoint.Port == 0) UpstreamEndpoint.Port = 53;
                if (ListenEndpoint.Port == 0) ListenEndpoint.Port = 8053;
                if (noDeduplicationOption.HasValue()) EnableRequestDeduplication = !noDeduplicationOption.ParsedValue;
                if (DeduplicationWaitMs == 0) DeduplicationWaitMs = 1;
                if (deduplicationWaitTimeOption.HasValue())
                    DeduplicationWaitMs = deduplicationWaitTimeOption.ParsedValue / 25;

                if (Equals(UpstreamEndpoint.Address, IPAddress.Broadcast))
                    CometLite.InitCleanupCacheTask();

                if (Equals(UpstreamEndpoint.Address, IPAddress.Broadcast) && !File.Exists("./public_suffix_list.dat"))
                {
                    Console.WriteLine("Downloading public_suffix_list.dat...");
                    File.WriteAllBytes("./public_suffix_list.dat",
                        new HttpClient().GetByteArrayAsync("https://publicsuffix.org/list/public_suffix_list.dat")
                            .Result);
                }

                if (File.Exists("pathup.txt"))
                    foreach (var line in File.ReadAllLines("pathup.txt").Where(l => !string.IsNullOrWhiteSpace(l)))
                        try
                        {
                            var parts = line.Split(' ', ',');
                            CustomPathUpstreamMappings[parts[0]] = IPEndPoint.Parse(parts[1]);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                        }

                if (EnableGeoCache)
                {
                    Console.WriteLine(
                        "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com");
                    Parallel.Invoke(
                        () => DownloadGeoDatabase("GeoLite2-ASN.mmdb",
                            "https://github.com/mili-tan/maxmind-geoip/releases/latest/download/GeoLite2-Asn.mmdb"),
                        () => DownloadGeoDatabase("GeoLite2-City.mmdb",
                            "https://github.com/mili-tan/maxmind-geoip/releases/latest/download/GeoLite2-City.mmdb"));
                }

                if (UseDictionaryCache)
                    CleanupTimer = new Timer(_ => CleanupCache(), null, CleanupInterval, CleanupInterval);

                if (MonitorUpstreamPort)
                {
                    var timer = new System.Timers.Timer(60000);
                    timer.Elapsed += (_, _) =>
                    {
                        try
                        {
                            if (!Equals(UpstreamEndpoint.Address, IPAddress.Loopback) ||
                                IsPortInUse(UpstreamEndpoint.Port)) return;
                            Console.WriteLine($"Upstream {UpstreamEndpoint} is unreachable. Exiting...");
                            Environment.Exit(1);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error checking upstream {UpstreamEndpoint}: {ex.Message}. Exiting...");
                        }
                    };
                    timer.Start();
                }

                RecursiveResolverPool = new(() => new RecursiveDnsResolver
                {
                    Is0x20ValidationEnabled = EnableResponseValidation,
                    IsResponseValidationEnabled = EnableResponseValidation,
                    QueryTimeout = QueryTimeoutMs
                });

                var host = new WebHostBuilder()
                    .UseKestrel()
                    .UseContentRoot(AppDomain.CurrentDomain.SetupInformation.ApplicationBase)
                    .ConfigureServices(services => services.AddRouting())
                    .ConfigureKestrel(options =>
                        options.Listen(ListenEndpoint, lo => lo.Protocols = HttpProtocols.Http1AndHttp2))
                    .Configure(app =>
                    {
                        app.Map(string.Empty, svr =>
                        {
                            app.UseRouting().UseEndpoints(endpoint =>
                            {
                                endpoint.Map("/", async ctx => await ctx.Response.WriteAsync("200 OK"));
                                endpoint.Map($"/{QueryPath.Trim('/')}",
                                    async ctx => await HandleDnsRequest(ctx, UpstreamEndpoint));
                                endpoint.Map($"/{QueryPath.Trim('/')}/json",
                                    async ctx => await HandleDnsRequest(ctx, UpstreamEndpoint, isJson: true));

                                foreach (var (path, upstream) in CustomPathUpstreamMappings)
                                {
                                    endpoint.Map($"/{path.Trim('/')}",
                                        async ctx => await HandleDnsRequest(ctx, upstream));
                                    endpoint.Map($"/{path.Trim('/')}/json",
                                        async ctx => await HandleDnsRequest(ctx, upstream, isJson: true));
                                }
                            });
                        });
                    }).Build();

                host.Run();
            });

            cmd.Execute(args);
        }

        public static bool IsPortInUse(int port)
        {
            try
            {
                var ipProps = IPGlobalProperties.GetIPGlobalProperties();
                return ipProps.GetActiveTcpListeners().Any(ep => ep.Port == port) ||
                       ipProps.GetActiveUdpListeners().Any(ep => ep.Port == port);
            }
            catch
            {
                return true;
            }
        }

        private static async Task HandleDnsRequest(HttpContext context, IPEndPoint upstreamEndpoint,
            bool isJson = false)
        {
            var query = await ParseDnsQuery(context);
            var result = query.CreateResponseInstance();

            if (!query.Questions.Any())
            {
                await SendResponse(context, result, query, isJson);
                return;
            }

            var question = query.Questions.First();
            var clientSubnet = ExtractClientSubnet(query, context);
            var cacheKeySuffix = EnableGeoCache ? GetGeoLocationKey(clientSubnet) : clientSubnet.ToString();

            if (TryGetFromCache(question, cacheKeySuffix, out var cachedEntry))
            {
                result = ApplyCacheToResponse(result, cachedEntry);
                if (EnableOptimisticCache && DateTime.UtcNow > cachedEntry.ExpiryTime)
                    _ = Task.Run(() => RefreshCacheAsync(query, upstreamEndpoint));
            }
            else
            {
                result = await QueryUpstreamWithDeduplication(query, upstreamEndpoint, question, clientSubnet);
                if (EnableCache && result.ReturnCode is ReturnCode.NoError or ReturnCode.NxDomain)
                    CacheResponse(question, cacheKeySuffix, result);
            }

            await SendResponse(context, result, query, isJson);
        }

        private static async Task<DnsMessage> ParseDnsQuery(HttpContext context)
        {
            if (context.Request.Query.TryGetValue("name", out var nameStr))
            {
                var typeStr = context.Request.Query["type"].ToString();
                var recordType = Enum.TryParse<RecordType>(typeStr, ignoreCase: true, out var type)
                    ? type
                    : RecordType.A;

                return new DnsMessage
                {
                    Questions = {new DnsQuestion(DomainName.Parse(nameStr.ToString()), recordType, RecordClass.INet)}
                };
            }

            return context.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                ? await DNSParser.FromPostByteAsync(context)
                : DNSParser.FromWebBase64(context, QueryParamKey);
        }

        private static IPAddress ExtractClientSubnet(DnsMessage query, HttpContext context)
        {
            try
            {
                if (context.Request.Query.TryGetValue("ecs", out var ecsStr))
                {
                    var clientSubnet = IPAddress.Parse(ecsStr.ToString().Split('/')[0]);
                    query.IsEDnsEnabled = true;
                    query.EDnsOptions?.Options.RemoveAll(x => x.Type == EDnsOptionType.ClientSubnet);
                    query.EDnsOptions?.Options.Add(new ClientSubnetOption(24, clientSubnet));
                    return clientSubnet;
                }

                return query.EDnsOptions?.Options
                    .OfType<ClientSubnetOption>()
                    .FirstOrDefault()?.Address ?? IPAddress.Any;
            }
            catch
            {
                return IPAddress.Any;
            }
        }

        private static bool TryGetFromCache(DnsQuestion question, string cacheKeySuffix, out CacheEntry entry)
        {
            entry = null;
            if (!EnableCache) return false;

            if (UseDictionaryCache)
                return CacheEntries.TryGetValue((question, cacheKeySuffix), out entry);

            var memoryCacheKey = $"C:{question}{cacheKeySuffix}";
            if (!MemoryCache.Default.Contains(memoryCacheKey)) return false;

            entry = (CacheEntry) MemoryCache.Default.Get(memoryCacheKey);
            return true;
        }

        private static DnsMessage ApplyCacheToResponse(DnsMessage result, CacheEntry cacheEntry)
        {
            result.ReturnCode = cacheEntry.ResponseData.ReturnCode;
            var ttl = Math.Max(OptimisticTtlSeconds, (int) (cacheEntry.ExpiryTime - DateTime.UtcNow).TotalSeconds);

            foreach (var record in cacheEntry.ResponseData.AnswerRecords)
            {
                result.AnswerRecords.Add(record switch
                {
                    ARecord a => new ARecord(a.Name, ttl, a.Address),
                    AaaaRecord aaaa => new AaaaRecord(aaaa.Name, ttl, aaaa.Address),
                    _ => record
                });
            }

            return result;
        }

        private static async Task<DnsMessage> QueryUpstreamWithDeduplication(DnsMessage query, IPEndPoint upstream,
            DnsQuestion question, IPAddress clientSubnet)
        {
            SemaphoreSlim semaphore = null;

            if (EnableRequestDeduplication)
            {
                if (UseHardDeduplication)
                {
                    if (MemoryCache.Default.Contains($"W:{question}{clientSubnet}"))
                        await Task.Delay(100);
                }
                else
                {
                    semaphore = RequestSemaphores.GetOrAdd($"{question}{clientSubnet}", _ => new SemaphoreSlim(1, 1));
                    try
                    {
                        await semaphore.WaitAsync(DeduplicationWaitMs);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
            }

            try
            {
                if (UseHardDeduplication && EnableRequestDeduplication)
                    MemoryCache.Default.Add($"W:{question}{clientSubnet}", true, DateTimeOffset.Now.AddSeconds(1));

                return await QueryUpstreamAsync(query, upstream);
            }
            finally
            {
                if (EnableRequestDeduplication)
                {
                    if (UseHardDeduplication)
                        MemoryCache.Default.Remove($"{question}{clientSubnet}");
                    else if (semaphore != null)
                    {
                        semaphore.Release();
                        if (semaphore.CurrentCount == 1)
                            RequestSemaphores.TryRemove($"{question}{clientSubnet}", out _);
                    }
                }
            }
        }

        private static async Task<DnsMessage> QueryUpstreamAsync(DnsMessage query, IPEndPoint upstream)
        {
            if (Equals(upstream.Address, IPAddress.Broadcast))
                return await CometLite.DoQuery(query);

            if (Equals(upstream.Address, IPAddress.Any))
            {
                var resolver = RecursiveResolverPool.Get();
                try
                {
                    var question = query.Questions.First();
                    var records =
                        resolver.Resolve<DnsRecordBase>(question.Name, question.RecordType, question.RecordClass);

                    var result = query.CreateResponseInstance();
                    if (records.Any())
                        result.AnswerRecords.AddRange(records);
                    else
                        result.ReturnCode = ReturnCode.NxDomain;

                    return result;
                }
                finally
                {
                    RecursiveResolverPool.Return(resolver);
                }
            }

            var client = new DnsClient(
                [upstream.Address],
                [new UdpClientTransport(upstream.Port), new TcpClientTransport(upstream.Port)],
                queryTimeout: QueryTimeoutMs);

            return await client.SendMessageAsync(query) ?? new DnsMessage()
                {ReturnCode = ReturnCode.ServerFailure, Questions = query.Questions, IsQuery = false};
        }

        private static void CacheResponse(DnsQuestion question, string cacheKeySuffix, DnsMessage response)
        {
            var ttl = GetTtlFromResponse(response);
            var cacheEntry = new CacheEntry(response, DateTimeOffset.UtcNow.AddSeconds(ttl));

            if (UseDictionaryCache)
            {
                CacheEntries[(question, cacheKeySuffix)] = cacheEntry;
            }
            else
            {
                var expiration = EnableOptimisticCache
                    ? DateTimeOffset.UtcNow.AddSeconds(ttl).Add(StaleDataThreshold)
                    : DateTimeOffset.UtcNow.AddSeconds(ttl);

                MemoryCache.Default.Set($"C:{question}{cacheKeySuffix}", cacheEntry, expiration);
            }
        }

        private static int GetTtlFromResponse(DnsMessage response)
        {
            if (!response.AnswerRecords.Any()) return MinTtlSeconds;
            return Math.Clamp(response.AnswerRecords.Min(r => r.TimeToLive), MinTtlSeconds, MaxTtlSeconds);
        }

        private static string GetGeoLocationKey(IPAddress ipAddress)
        {
            AsnReader ??= new DatabaseReader("./GeoLite2-ASN.mmdb");
            CityReader ??= new DatabaseReader("./GeoLite2-City.mmdb");

            var asn = AsnReader.Asn(ipAddress);
            var city = CityReader.City(ipAddress);

            var key = $"{asn.AutonomousSystemNumber}{asn.AutonomousSystemOrganization}{city.Country.IsoCode}";
            if (city.Country.IsoCode?.Equals("CN", StringComparison.OrdinalIgnoreCase) == true)
                key += city.MostSpecificSubdivision.IsoCode;

            return key;
        }

        private static async Task RefreshCacheAsync(DnsMessage originalQuery, IPEndPoint upstream)
        {
            try
            {
                var newResponse = await QueryUpstreamAsync(originalQuery, upstream);
                if (newResponse.ReturnCode is not (ReturnCode.NoError or ReturnCode.NxDomain)) return;

                var question = originalQuery.Questions[0];
                var clientSubnet = ExtractClientSubnetFromDnsMessage(originalQuery);
                var cacheKeySuffix = EnableGeoCache ? GetGeoLocationKey(clientSubnet) : clientSubnet.ToString();
                var ttl = GetTtlFromResponse(newResponse);
                var cacheEntry = new CacheEntry(newResponse, DateTimeOffset.UtcNow.AddSeconds(ttl));

                if (UseDictionaryCache)
                    CacheEntries[(question, cacheKeySuffix)] = cacheEntry;
                else
                    MemoryCache.Default.Set($"C:{question}{cacheKeySuffix}", cacheEntry,
                        DateTimeOffset.UtcNow.AddSeconds(ttl).Add(StaleDataThreshold));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error refreshing cache: {ex.Message}");
            }
        }

        private static IPAddress ExtractClientSubnetFromDnsMessage(DnsMessage dnsMsg)
        {
            try
            {
                return dnsMsg.EDnsOptions?.Options
                    .OfType<ClientSubnetOption>()
                    .FirstOrDefault()?.Address ?? IPAddress.Any;
            }
            catch
            {
                return IPAddress.Any;
            }
        }

        private static async Task SendResponse(HttpContext context, DnsMessage response, DnsMessage originalQuery,
            bool isJson)
        {
            if (EnableEcsEcho && originalQuery.EDnsOptions?.Options.Any(x => x.Type == EDnsOptionType.ClientSubnet) ==
                true)
            {
                var clientSubnet =
                    (ClientSubnetOption) originalQuery.EDnsOptions.Options.First(x =>
                        x.Type == EDnsOptionType.ClientSubnet);
                response.EDnsOptions?.Options.Clear();
                response.EDnsOptions?.Options.Add(new ClientSubnetOption(24, 24, clientSubnet.Address));
            }

            context.Response.StatusCode = 200;
            context.Response.Headers.Server = "ArashiDNSP/Lity";

            if (isJson)
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(DnsJsonEncoder.Encode(response, true).ToString());
            }
            else
            {
                context.Response.ContentType = "application/dns-message";
                var bytes = DnsEncoder.Encode(response, transIdEnable: false, id: originalQuery.TransactionID);
                context.Response.ContentLength = bytes.Length;
                await context.Response.BodyWriter.WriteAsync(bytes);
            }
        }

        private static void CleanupCache()
        {
            var threshold = EnableOptimisticCache ? DateTime.UtcNow : DateTime.UtcNow.Add(-StaleDataThreshold);
            var expiredKeys = CacheEntries
                .Where(kvp => kvp.Value.ExpiryTime < threshold)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in expiredKeys)
                CacheEntries.TryRemove(key, out _);

            Console.WriteLine($"C：{expiredKeys.Count} / {CacheEntries.Count}");
        }

        public static void DownloadGeoDatabase(string fileName, string downloadUrl)
        {
            var basePath = AppDomain.CurrentDomain.SetupInformation.ApplicationBase;
            var fullPath = Path.Combine(basePath, fileName);

            if (File.Exists(fullPath))
            {
                var lastWrite = new FileInfo(fullPath).LastWriteTimeUtc;
                var daysOld = (DateTime.UtcNow - lastWrite).TotalDays;

                Console.Write($"{fileName} Last updated: {lastWrite}");
                if (daysOld > 7)
                {
                    Console.WriteLine($" : Expired {daysOld:0} days");
                    File.Delete(fullPath);
                }
                else
                {
                    Console.WriteLine();
                    return;
                }
            }
            else
            {
                Console.Write($"{fileName} Not Exist or being Updating");
            }

            Console.WriteLine($"Downloading {fileName}...");
            File.WriteAllBytes(fullPath, new HttpClient().GetByteArrayAsync(downloadUrl).Result);
            Console.WriteLine($"{fileName} Download Done");
        }

        public class ObjectPool<T>
        {
            private readonly ConcurrentBag<T> _objects = new();
            private readonly Func<T> _generator;
            private readonly int _maxSize;

            public ObjectPool(Func<T> generator, int maxSize = 10)
            {
                _generator = generator ?? throw new ArgumentNullException(nameof(generator));
                _maxSize = maxSize;
            }

            public T Get() => _objects.TryTake(out var item) ? item : _generator();

            public void Return(T item)
            {
                if (_objects.Count < _maxSize)
                    _objects.Add(item);
            }
        }
    }
}
