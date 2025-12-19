//This class from ArashiDNS.Comet and
//Released under the FSL-1.1-ALv2 License.
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using DeepCloner.Core;
using NStack;
using System.Collections.Concurrent;
using IPAddress = System.Net.IPAddress;

namespace ArashiDNS
{
    public class CometLite
    {
        public static IPAddress[] Servers =
        [
            IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1"), IPAddress.Parse("8.8.8.8"),
            IPAddress.Parse("9.9.9.9")
        ];
        public static TldExtract TldExtractor = new("./public_suffix_list.dat");

        public static int Timeout = 1250;
        public static int MaxCnameDepth = 10;
        public static int MinNsTTL = 3600;
        public static int MinTTL = 60;

        public static bool UseLog = false;
        public static bool UseV6Ns = false;
        public static bool UseResponseCache = true;
        public static bool UseCnameFoldingCache = true;
        public static bool UseEcsCache = true;
        public static bool UseLessEDns = true;

        public static Timer CacheCleanupTimer;
        public class CacheItem<T>
        {
            public T Value { get; set; }
            public DateTime ExpiryTime { get; set; }
            public bool IsExpired => DateTime.UtcNow >= ExpiryTime;
        }

        public static ConcurrentDictionary<string, CacheItem<DnsMessage>> DnsResponseCache = new();
        public static ConcurrentDictionary<string, CacheItem<DnsMessage>> NsQueryCache = new();

        public static void InitCleanupCacheTask()
        {
            CacheCleanupTimer = new Timer(_ =>
            {
                try
                {
                    var expiredDnsKeys = DnsResponseCache.Where(kv => kv.Value.IsExpired)
                        .Select(kv => kv.Key).ToList();
                    foreach (var key in expiredDnsKeys) DnsResponseCache.TryRemove(key, out var _);

                    var expiredNsKeys = NsQueryCache.Where(kv => kv.Value.IsExpired)
                        .Select(kv => kv.Key).ToList();
                    foreach (var key in expiredNsKeys) NsQueryCache.TryRemove(key, out var _);

                    if (expiredDnsKeys.Any() || expiredNsKeys.Any())
                        if (UseLog) Console.WriteLine($"Cache cleanup: {expiredDnsKeys.Count} DNS entries, " +
                                                      $"{expiredNsKeys.Count} NS entries removed.");
                }
                catch (Exception ex)
                {
                    if (UseLog) Console.WriteLine($"Cache cleanup error: {ex.Message}");
                }
            }, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5));
        }

        public static async Task<DnsMessage> DoQuery(DnsMessage query)
        {
            var response = new DnsMessage();
            if (query.Questions.Count == 0) return response;

            var quest = query.Questions.First();
            var cacheKey = UseEcsCache ? BuildCacheKey(query) : BuildCacheKey(quest);
            if (UseResponseCache && DnsResponseCache.TryGetValue(cacheKey, out var cacheItem) && !cacheItem.IsExpired)
            {
                var cachedResponse = cacheItem.Value.DeepClone();
                cachedResponse.TransactionID = query.TransactionID;
                response = cachedResponse;
                if (UseLog) Task.Run(() => Console.WriteLine($"Cache hit for: {quest.Name}"));
                return response;
            }

            var answer = await ResolveAsync(query);

            if (answer == null)
            {
                response = query.CreateResponseInstance();
                response.ReturnCode = ReturnCode.ServerFailure;
            }
            else
            {
                response = query.CreateResponseInstance();
                response.ReturnCode = answer.ReturnCode;
                response.IsRecursionAllowed = true;
                response.IsRecursionDesired = true;
                response.AnswerRecords.AddRange(answer.AnswerRecords);

                if (UseResponseCache && answer.ReturnCode is ReturnCode.NoError or ReturnCode.NxDomain)
                    CacheResponse(cacheKey, response);
            }

            return response;
        }

        private static string BuildCacheKey(DnsQuestion question) =>
            $"{question.Name}:{question.RecordType}:{question.RecordClass}";

        private static string BuildCacheKey(DnsMessage message)
        {
            var quest = message.Questions.First();
            return $"{quest.Name}:{quest.RecordType}:{quest.RecordClass}:{GetClientIpBase64(message)}";
        }

        private static string BuildNsCacheKey(DomainName domain, RecordType recordType) =>
            $"{domain}:{recordType}";

        private static void CacheResponse(string key, DnsMessage response)
        {
            var ttl = Math.Max(response.AnswerRecords.Count > 0
                ? response.AnswerRecords.Min(r => r.TimeToLive)
                : (response.AuthorityRecords.Count > 0
                    ? response.AuthorityRecords.Min(r => r.TimeToLive)
                    : 300), MinTTL);

            DnsResponseCache[key] = new CacheItem<DnsMessage>
            {
                Value = response.DeepClone(),
                ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
            };
            if (UseLog) Task.Run(() => Console.WriteLine($"Cached response for: {key} (TTL: {ttl}s)"));
        }

        public static DnsMessage CloneQuery(DnsMessage qMessage, DnsQuestion question)
        {
            var newQuery = qMessage.DeepClone();
            newQuery.Questions.Clear();
            newQuery.Questions.Add(question);
            return newQuery;
        }

        private static async Task<DnsMessage?> ResolveAsync(DnsMessage query, int cnameDepth = 0)
        {
            if (cnameDepth >= MaxCnameDepth + 1) return null;
            var answer = query.CreateResponseInstance();
            var quest = query.Questions.First();
            var cnameFoldCacheKey = $"{quest.Name}:CNAME-FOLD:{quest.RecordClass}";
            if (UseEcsCache) cnameFoldCacheKey += $":{GetClientIpBase64(query)}";

            if (quest.RecordType == RecordType.Any)
            {
                answer.ReturnCode = ReturnCode.Refused;
                return answer;
            }

            if (UseCnameFoldingCache && DnsResponseCache.TryGetValue(cnameFoldCacheKey, out var nsRootCacheItem) &&
                !nsRootCacheItem.IsExpired)
            {
                var cNameRecord = (nsRootCacheItem.Value.AnswerRecords
                    .Last(x => x.RecordType == RecordType.CName) as CNameRecord);
                if (UseLog) Task.Run(() => Console.WriteLine($"CNAME cache hit for: {cNameRecord.CanonicalName}"));
                answer.AnswerRecords.Add(new CNameRecord(quest.Name, cNameRecord.TimeToLive,
                    cNameRecord.CanonicalName));
                var cnameAnswer = await ResolveAsync(CloneQuery(query, new DnsQuestion(cNameRecord.CanonicalName,
                    quest.RecordType,
                    quest.RecordClass)), cnameDepth + 1);
                //Console.WriteLine(cnameAnswer.ReturnCode);
                if (cnameAnswer is { AnswerRecords.Count: > 0 })
                {
                    answer.AnswerRecords.AddRange(cnameAnswer.AnswerRecords);
                    return answer;
                }
            }

            var nsServers = await GetAuthorityServers(quest);
            if (nsServers.Count == 0)
            {
                answer.ReturnCode = ReturnCode.NxDomain;
                return answer;
            }

            var nsIps = await GetAuthorityServerIps(nsServers.Order().Take(2).ToList());
            if (nsIps.Count == 0)
            {
                answer.ReturnCode = ReturnCode.NxDomain;
                return answer;
            }

            answer = await ResolveFromAuthority(nsIps, query);

            if (answer != null && answer.AnswerRecords.Count != 0 &&
                answer.AnswerRecords.All(x => x.RecordType == RecordType.CName) && cnameDepth <= MaxCnameDepth)
            {
                var cnameAnswer = await ResolveAsync(CloneQuery(query, new DnsQuestion(
                    ((CNameRecord)answer.AnswerRecords.LastOrDefault(x => x.RecordType == RecordType.CName)!)
                    .CanonicalName,
                    quest.RecordType,
                    quest.RecordClass)), cnameDepth + 1);
                //Console.WriteLine(cnameAnswer.ReturnCode);

                if (cnameAnswer is { AnswerRecords.Count: > 0 })
                {
                    answer.AnswerRecords.AddRange(cnameAnswer.AnswerRecords);
                    if (UseCnameFoldingCache && cnameAnswer.AnswerRecords.Any(x => x.RecordType == RecordType.CName))
                    {
                        var cnameRecord = cnameAnswer.AnswerRecords
                            .Last(x => x.RecordType == RecordType.CName);
                        var ttl = Math.Max(cnameAnswer.AnswerRecords.Count > 0
                            ? cnameAnswer.AnswerRecords.Max(r => r.TimeToLive)
                            : 60, MinTTL);
                        DnsResponseCache[cnameFoldCacheKey] =
                            new CacheItem<DnsMessage>
                            {
                                Value = cnameAnswer,
                                ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                            };
                        if (UseLog) Task.Run(() =>
                            Console.WriteLine($"Cached CNAME records for: {cnameRecord.Name} (TTL: {ttl}s)"));
                    }
                }
            }

            return answer;
        }

        private static async Task<List<DomainName>> GetAuthorityServers(DnsQuestion query)
        {
            var name = query.Name;
            if (NsQueryCache.TryGetValue(BuildNsCacheKey(name, RecordType.Ns), out var nsMainCacheItem) &&
                !nsMainCacheItem.IsExpired)
            {
                if (UseLog) Task.Run(() => Console.WriteLine($"NS cache hit for: {name}"));
                return nsMainCacheItem.Value.AnswerRecords
                    .Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer)
                    .ToList();
            }

            var tld = TldExtractor.Extract(name.ToString().Trim('.'));
            var rootName = name.LabelCount == 2
                ? name
                : string.IsNullOrWhiteSpace(tld.tld)
                    ? DomainName.Parse(string.Join('.', name.Labels.TakeLast(2)))
                    : DomainName.Parse(tld.root + "." + tld.tld);

            if (!name.GetParentName().Equals(rootName) &&
                NsQueryCache.TryGetValue(BuildNsCacheKey(name.GetParentName(), RecordType.Ns),
                    out var nsParentCacheItem) &&
                !nsParentCacheItem.IsExpired)
            {
                if (UseLog) Task.Run(() => Console.WriteLine($"NS cache hit for: {name.GetParentName()}"));
                return nsParentCacheItem.Value.AnswerRecords
                    .Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer)
                    .ToList();
            }

            var nsRootCacheKey = BuildNsCacheKey(rootName, RecordType.Ns);
            if (NsQueryCache.TryGetValue(nsRootCacheKey, out var nsRootCacheItem) && !nsRootCacheItem.IsExpired)
            {
                if (UseLog) Task.Run(() => Console.WriteLine($"NS cache hit for: {rootName}"));
                return nsRootCacheItem.Value.AnswerRecords
                    .Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer)
                    .ToList();
            }

            var nsAnswer = await new DnsClient(Servers, Timeout).ResolveAsync(rootName, RecordType.Ns);

            if (nsAnswer is { AnswerRecords.Count: 0 })
                nsAnswer = await new DnsClient(Servers, Timeout).ResolveAsync(rootName.GetParentName(), RecordType.Ns);

            if (nsAnswer != null)
            {
                var ttl = Math.Min(nsAnswer.AnswerRecords.Count > 0
                    ? nsAnswer.AnswerRecords.Min(r => r.TimeToLive)
                    : (nsAnswer.AuthorityRecords.Count > 0
                        ? nsAnswer.AuthorityRecords.Min(r => r.TimeToLive)
                        : 300), MinNsTTL);

                NsQueryCache[nsRootCacheKey] = new CacheItem<DnsMessage>
                {
                    Value = nsAnswer.DeepClone(),
                    ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                };
                if (UseLog) Task.Run(() => Console.WriteLine($"Cached NS records for: {rootName} (TTL: {ttl}s)"));
            }

            return nsAnswer?.AnswerRecords.Where(x => x.RecordType == RecordType.Ns)
                .Select(x => ((NsRecord)x).NameServer).ToList() ?? [];
        }

        private static async Task<List<IPAddress>> GetAuthorityServerIps(List<DomainName> nsServers)
        {
            var nsIps = new List<IPAddress>();

            await Parallel.ForEachAsync(nsServers, async (item, c) =>
            {
                var aCacheKey = BuildNsCacheKey(item, RecordType.A);
                var aaaaCacheKey = BuildNsCacheKey(item, RecordType.Aaaa);
                if (NsQueryCache.TryGetValue(aCacheKey, out var aCacheItem) && !aCacheItem.IsExpired)
                {
                    var cachedIps = aCacheItem.Value.AnswerRecords
                        .Where(x => x.RecordType == RecordType.A)
                        .Select(x => ((ARecord)x).Address)
                        .ToList();

                    lock (nsIps) nsIps.AddRange(cachedIps);
                    if (UseLog) Task.Run(() => Console.WriteLine($"A record cache hit for: {item}"));
                    return;
                }
                if (UseV6Ns && NsQueryCache.TryGetValue(aaaaCacheKey, out var aaaaCacheItem) && !aaaaCacheItem.IsExpired)
                {
                    var cachedIps = aaaaCacheItem.Value.AnswerRecords
                        .Where(x => x.RecordType == RecordType.A)
                        .Select(x => ((ARecord)x).Address)
                        .ToList();

                    lock (nsIps) nsIps.AddRange(cachedIps);
                    if (UseLog) Task.Run(() => Console.WriteLine($"AAAA record cache hit for: {item}"));
                    return;
                }

                var nsARecords = (await new DnsClient(Servers, Timeout).ResolveAsync(item, token: c))?.AnswerRecords ?? [];
                if (nsARecords.Any(x => x.RecordType == RecordType.A))
                {
                    var addresses = nsARecords.Where(x => x.RecordType == RecordType.A)
                        .Select(x => ((ARecord)x).Address)
                        .ToList();

                    lock (nsIps) nsIps.AddRange(addresses);

                    if (nsARecords.Any())
                    {
                        var response = new DnsMessage();
                        response.AnswerRecords.AddRange(nsARecords);
                        var ttl = Math.Max(nsARecords.Min(r => r.TimeToLive), MinTTL);

                        NsQueryCache[aCacheKey] = new CacheItem<DnsMessage>
                        {
                            Value = response,
                            ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                        };
                        if (UseLog) Task.Run(() => Console.WriteLine($"Cached A records for: {item} (TTL: {ttl}s)"));
                    }
                }
                else if (UseV6Ns)
                {
                    var nsAaaaRecords =
                        (await new DnsClient(Servers, Timeout).ResolveAsync(item, RecordType.Aaaa, token: c))
                        ?.AnswerRecords ?? [];
                    if (nsAaaaRecords.Any(x => x.RecordType == RecordType.A))
                    {
                        var addresses = nsAaaaRecords.Where(x => x.RecordType == RecordType.Aaaa)
                            .Select(x => ((AaaaRecord)x).Address)
                            .ToList();

                        lock (nsIps) nsIps.AddRange(addresses);

                        if (nsAaaaRecords.Any())
                        {
                            var response = new DnsMessage();
                            response.AnswerRecords.AddRange(nsAaaaRecords);
                            var ttl = Math.Max(nsAaaaRecords.Min(r => r.TimeToLive), MinTTL);

                            NsQueryCache[aaaaCacheKey] = new CacheItem<DnsMessage>
                            {
                                Value = response,
                                ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                            };
                            if (UseLog)
                                Task.Run(() => Console.WriteLine($"Cached AAAA records for: {item} (TTL: {ttl}s)"));
                        }
                    }
                }
            });

            return nsIps.Distinct().ToList();
        }

        private static async Task<DnsMessage?> ResolveFromAuthority(List<IPAddress> nsAddresses, DnsMessage query, int depth = 0)
        {
            if (depth >= MaxCnameDepth + 1) return null;
            try
            {
                if (UseLessEDns && query.EDnsOptions != null && query.EDnsOptions.Options.Any())
                    query.EDnsOptions.Options.RemoveAll(x => x.Type != EDnsOptionType.ClientSubnet);

                var quest = query.Questions.First();
                var client = new DnsClient(nsAddresses,
                    [new TcpClientTransport(), new UdpClientTransport()],
                    queryTimeout: Timeout);

                var answer = await client.ResolveAsync(quest.Name, quest.RecordType,
                    options: new DnsQueryOptions
                    {
                        EDnsOptions = query.EDnsOptions,
                        IsEDnsEnabled = query.IsEDnsEnabled,
                        IsRecursionDesired = true
                    });

                if (answer is { AnswerRecords.Count: 0 } &&
                    answer.AuthorityRecords.Any(x => x.RecordType == RecordType.Ns) &&
                    answer.AuthorityRecords.FirstOrDefault(x => x.RecordType == RecordType.Ns)!.Name.LabelCount > 1)
                {
                    var nsCacheMsg = query.CreateResponseInstance();
                    var ttl = DateTime.UtcNow.AddSeconds(Math.Min(answer.AuthorityRecords.Count > 0
                        ? answer.AuthorityRecords.Min(r => r.TimeToLive)
                        : 300, MinNsTTL));
                    nsCacheMsg.AnswerRecords.AddRange(
                        answer.AuthorityRecords.Where(x => x.RecordType == RecordType.Ns));

                    NsQueryCache[BuildNsCacheKey(quest.Name, RecordType.Ns)] = new CacheItem<DnsMessage>
                    {
                        Value = nsCacheMsg,
                        ExpiryTime = ttl
                    };
                    NsQueryCache[
                        BuildNsCacheKey(answer.AuthorityRecords.First(x => x.RecordType == RecordType.Ns).Name,
                            RecordType.Ns)] = new CacheItem<DnsMessage>
                            {
                                Value = nsCacheMsg,
                                ExpiryTime = ttl
                            };

                    return await ResolveFromAuthority(
                        await GetAuthorityServerIps(answer.AuthorityRecords.Where(x => x.RecordType == RecordType.Ns)
                            .Select(x => ((NsRecord)x).NameServer).Order().Take(2).ToList()),
                        query, depth + 1);
                }

                if (answer == null ||
                    (answer.ReturnCode != ReturnCode.NoError && answer.ReturnCode != ReturnCode.NxDomain))
                    answer = await client.ResolveAsync(quest.Name, quest.RecordType) ?? answer;

                return answer;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        public static IPAddress GetClientIp(DnsMessage dnsMsg)
        {
            try
            {
                if (dnsMsg is { IsEDnsEnabled: false }) return IPAddress.Any;
                foreach (var eDnsOptionBase in dnsMsg.EDnsOptions.Options.ToList())
                {
                    if (eDnsOptionBase is ClientSubnetOption option)
                        return option.Address;
                }

                return IPAddress.Any;
            }
            catch (Exception)
            {
                return IPAddress.Any;
            }
        }

        public static string GetClientIpBase64(DnsMessage dnsMsg)
        {
            return Convert.ToBase64String(GetClientIp(dnsMsg).GetAddressBytes());
        }
    }
}