using Arashi;
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Caching;

namespace ArashiDNS.Lity
{
    internal class Program
    {
        public static IPEndPoint Listen = new IPEndPoint(IPAddress.Any, 5380);
        public static int TimeOut = 500;
        public static string Path = "dns-query";
        public static string Key = "dns";
        public static bool Validation = false;
        public static bool RepeatedWait = true;
        public static bool RepeatedWaitHard = false;
        public static bool UseEcsEcho = true;
        public static int RepeatedWaitTime = 100;
        public static IPEndPoint Up = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53);
        public static Dictionary<string, IPEndPoint> PathUpDictionary = new Dictionary<string, IPEndPoint>();
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> RequestSemaphores = new ConcurrentDictionary<string, SemaphoreSlim>();

        public static ObjectPool<RecursiveDnsResolver> RecursiveResolverPool = new(() =>
            new RecursiveDnsResolver()
            {
                Is0x20ValidationEnabled = Validation, IsResponseValidationEnabled = Validation, QueryTimeout = TimeOut
            });

        static void Main(string[] args)
        {
            var cmd = new CommandLineApplication
            {
                Name = "ArashiDNS.Lity",
                Description = "ArashiDNS.Lity - Minimal DNS over HTTPS server with Recursive Resolver" +
                              Environment.NewLine +
                              $"Copyright (c) {DateTime.Now.Year} Milkey Tan. Code released under the MIT License"
            };
            cmd.HelpOption("-?|-he|--help");
            var isZh = Thread.CurrentThread.CurrentCulture.Name.Contains("zh");
            var wOption = cmd.Option<int>("-w <TimeOut>",
                isZh ? "等待回复的超时时间（毫秒）。[3000]" : "Timeout for waiting response (ms). [3000]",
                CommandOptionType.SingleValue);
            var lOption = cmd.Option<string>("-l <IPEndPoint>",
                isZh ? "设置监听地址和端口。[8.8.8.8:5380]" : "Set listen address and port. [8.8.8.8:5380]",
                CommandOptionType.SingleValue);
            var sOption = cmd.Option<string>("-s <IPEndPoint>",
                isZh
                    ? "设置上游地址，为 0.0.0.0 时使用递归。[8.8.8.8:53]"
                    : "Set upstream address, use recursion if 0.0.0.0. [8.8.8.8:53]", CommandOptionType.SingleValue);
            var pOption = cmd.Option<string>("-p <Path>", isZh ? "查询路径。[/dns-query]" : "Query path. [/dns-query]",
                CommandOptionType.SingleValue);
            var kOption = cmd.Option<string>("-k <Key>", isZh ? "查询参数。[dns]" : "Query parameter. [dns]",
                CommandOptionType.SingleValue);
            var vOption = cmd.Option<bool>("-v",
                isZh
                    ? "启用 DNS 响应验证（0x20 和 RRSIG，对于递归）。"
                    : "Enable DNS response validation (0x20 and RRSIG, for recursion).", CommandOptionType.NoValue);

            var noRepeatedWaitOption = cmd.Option<bool>("-nrw",
                isZh
                    ? "不启用重复查询等待以防止缓存穿透。"
                    : "Disabled repeated query wait to prevent cache penetration.",
                CommandOptionType.NoValue);
            var repeatedWaitTimeOption = cmd.Option<int>("-rwt <Seconds>",
                isZh
                    ? "重复查询等待的最大时间（毫秒）。[100]"
                    : "Maximum time for repeated query wait (ms). [100]",
                CommandOptionType.SingleValue);

            cmd.OnExecute(() =>
            {
                if (wOption.HasValue()) TimeOut = wOption.ParsedValue;
                if (lOption.HasValue()) Listen = IPEndPoint.Parse(lOption.ParsedValue);
                if (sOption.HasValue()) Up = IPEndPoint.Parse(sOption.ParsedValue);
                if (pOption.HasValue()) Path = pOption.ParsedValue;
                if (kOption.HasValue()) Key = kOption.ParsedValue;
                if (vOption.HasValue()) Validation = vOption.ParsedValue;
                if (Up.Port == 0) Up.Port = 53;
                if (Listen.Port == 0) Listen.Port = 8053;

                if (noRepeatedWaitOption.HasValue()) RepeatedWait = !noRepeatedWaitOption.ParsedValue;
                if (repeatedWaitTimeOption.HasValue()) RepeatedWaitTime = repeatedWaitTimeOption.ParsedValue / 25;
                if (RepeatedWaitTime == 0) RepeatedWaitTime = 1;

                if (Equals(Up.Address, IPAddress.Broadcast))
                    CometLite.InitCleanupCacheTask();

                if (Equals(Up.Address, IPAddress.Broadcast) && !File.Exists("./public_suffix_list.dat"))
                {
                    Console.WriteLine("Downloading public_suffix_list.dat...");
                    File.WriteAllBytes("./public_suffix_list.dat",
                        new HttpClient()
                            .GetByteArrayAsync(
                                "https://publicsuffix.org/list/public_suffix_list.dat")
                            .Result);
                }

                if (File.Exists("pathup.txt"))
                    foreach (var item in File.ReadAllLines("pathup.txt"))
                        if (!string.IsNullOrWhiteSpace(item))
                            try
                            {
                                var sp = item.Split(' ', ',');
                                PathUpDictionary.Add(sp[0], IPEndPoint.Parse(sp[1]));
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e);
                            }

                var timer = new System.Timers.Timer(1000);
                timer.Elapsed += (sender, e) =>
                {
                    try
                    {
                        if (!Equals(Up.Address, IPAddress.Loopback) || PortIsUse(Up.Port)) return;
                        Console.WriteLine($"Up {Up} is unreachable. Exiting...");
                        Environment.Exit(1);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error checking Up {Up}: {ex.Message}. Exiting...");
                    }
                };
                timer.Start();

                RecursiveResolverPool = new(() =>
                    new RecursiveDnsResolver()
                    {
                        Is0x20ValidationEnabled = Validation,
                        IsResponseValidationEnabled = Validation,
                        QueryTimeout = TimeOut
                    });

                var host = new WebHostBuilder()
                    .UseKestrel()
                    .UseContentRoot(AppDomain.CurrentDomain.SetupInformation.ApplicationBase)
                    .ConfigureServices(services => { services.AddRouting(); })
                    .ConfigureKestrel(options =>
                    {
                        options.Listen(Listen,
                            listenOptions => { listenOptions.Protocols = HttpProtocols.Http1AndHttp2; });
                    })
                    .Configure(app =>
                    {
                        app.Map(string.Empty, svr =>
                        {
                            app.UseRouting().UseEndpoints(endpoint =>
                            {
                                endpoint.Map(
                                    "/", async context => { await context.Response.WriteAsync("200 OK"); });
                                endpoint.Map(
                                    "/" + Path.Trim('/'),
                                    async context => await DnsRequest(context, Up));
                                endpoint.Map(
                                    "/" + Path.Trim('/') + "/json",
                                    async context =>
                                        await DnsRequest(context, Up, isJson: true));

                                if (PathUpDictionary.Any())
                                {
                                    foreach (var item in PathUpDictionary)
                                    {
                                        endpoint.Map(
                                            "/" + item.Key.Trim('/'),
                                            async context => await DnsRequest(context, item.Value));
                                        endpoint.Map(
                                            "/" + item.Key.Trim('/') + "/json",
                                            async context =>
                                                await DnsRequest(context, item.Value, isJson: true));
                                    }
                                }
                            });
                        });
                    }).Build();

                host.Run();
            });
            cmd.Execute(args);
        }

        public static bool PortIsUse(int port)
        {
            try
            {
                var ipEndPointsTcp = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
                var ipEndPointsUdp = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();

                return ipEndPointsTcp.Any(endPoint => endPoint.Port == port)
                       || ipEndPointsUdp.Any(endPoint => endPoint.Port == port);
            }
            catch (Exception)
            {
                return true;
            }
        }


        private static async Task DnsRequest(HttpContext context, IPEndPoint up, bool isJson = false)
        {
            var query = context.Request.Query.TryGetValue("name", out var nameStr)
                ? new DnsMessage()
                {
                    Questions =
                    [
                        new DnsQuestion(DomainName.Parse(nameStr.ToString()),
                            context.Request.Query.TryGetValue("type", out var typeStr)
                                ? Enum.TryParse(typeStr.ToString(), ignoreCase: true, out RecordType typeVal)
                                    ? typeVal
                                    : RecordType.A
                                : RecordType.A, RecordClass.INet)
                    ]
                }
                : context.Request.Method.ToUpper() == "POST"
                    ? await DNSParser.FromPostByteAsync(context)
                    : DNSParser.FromWebBase64(context, Key);
            var result = query.CreateResponseInstance();
            var ecs = IPAddress.Any;

            if (query.Questions.Any())
            {
                var quest = query.Questions.First();
                if (context.Request.Query.TryGetValue("ecs", out var ecsStr))
                {
                    ecs = IPAddress.Parse(ecsStr.ToString().Split('/').First());
                    query.IsEDnsEnabled = true;
                    query.EDnsOptions?.Options.RemoveAll(x => x.Type == EDnsOptionType.ClientSubnet);
                    query.EDnsOptions?.Options.Add(new ClientSubnetOption(24, ecs));
                }

                SemaphoreSlim? semaphore = null;
                if (RepeatedWait)
                {
                    if (RepeatedWaitHard)
                    {
                        if (MemoryCache.Default.Contains(quest + ecs.ToString())) await Task.Delay(100);
                    }
                    else
                    {
                        try
                        {
                            semaphore = RequestSemaphores.GetOrAdd(quest + ecs.ToString(), new SemaphoreSlim(1, 1));
                            await semaphore.WaitAsync(RepeatedWaitTime);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                        }
                    }
                }

                try
                {
                    if (RepeatedWaitHard && RepeatedWait)
                        try
                        {
                            MemoryCache.Default.Add(quest + ecs.ToString(), true, DateTimeOffset.Now.AddSeconds(1));
                        }
                        catch (Exception e)
                        {
                            // ignored
                        }

                    if (Equals(up.Address, IPAddress.Broadcast))
                        result = await CometLite.DoQuery(query);
                    else if (Equals(up.Address, IPAddress.Any))
                    {
                        var resolver = RecursiveResolverPool.Get();
                        var record = resolver.Resolve<DnsRecordBase>(quest.Name, quest.RecordType, quest.RecordClass);

                        if (record.Any())
                            result.AnswerRecords.AddRange(record);
                        else
                            result.ReturnCode = ReturnCode.NxDomain;

                        RecursiveResolverPool.Return(resolver);
                    }
                    else
                    {
                        var res = await new DnsClient([up.Address],
                                [new UdpClientTransport(up.Port), new TcpClientTransport(up.Port)], queryTimeout: TimeOut)
                            .SendMessageAsync(query);

                        if (res != null)
                            result = res;
                        else
                            result.ReturnCode = ReturnCode.ServerFailure;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                try
                {
                    if (RepeatedWait)
                        if (RepeatedWaitHard)
                            MemoryCache.Default.Remove(quest + ecs.ToString());
                        else if (semaphore != null)
                        {
                            semaphore.Release(1);
                            if (semaphore.CurrentCount == 0) RequestSemaphores.TryRemove(quest + ecs.ToString(), out _);
                        }
                }
                catch (Exception)
                {
                    // ignored
                }
            }

            if (isJson)
            {
                var responseJson = DnsJsonEncoder.Encode(result, true).ToString();

                context.Response.ContentType = "application/json";
                context.Response.StatusCode = 200;
                context.Response.Headers.Server = "ArashiDNSP/Lity";

                await context.Response.WriteAsync(responseJson);
            }
            else
            {
                try
                {

                    if(UseEcsEcho)
                        if (query.EDnsOptions != null &&
                            query.EDnsOptions.Options.Any(x => x.Type == EDnsOptionType.ClientSubnet))
                        {
                            var clientSubnet = (ClientSubnetOption) query.EDnsOptions.Options.First(x => x.Type == EDnsOptionType.ClientSubnet);
                            result.EDnsOptions?.Options.Clear();
                            result.EDnsOptions?.Options.Add(new ClientSubnetOption(24, 24, clientSubnet.Address));
                        }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                var responseBytes = DnsEncoder.Encode(result, transIdEnable: false, id: query.TransactionID);

                context.Response.ContentType = "application/dns-message";
                context.Response.StatusCode = 200;
                context.Response.ContentLength = responseBytes.Length;
                context.Response.Headers.Server = "ArashiDNSP/Lity";

                await context.Response.BodyWriter.WriteAsync(responseBytes);
            }
        }

        public class ObjectPool<T>
        {
            private readonly ConcurrentBag<T> _objects;
            private readonly Func<T> _objectGenerator;

            public ObjectPool(Func<T> objectGenerator)
            {
                _objectGenerator = objectGenerator ?? throw new ArgumentNullException(nameof(objectGenerator));
                _objects = new ConcurrentBag<T>();
            }

            public T Get() => _objects.TryTake(out T item) ? item : _objectGenerator();

            public void Return(T item)
            {
                if (_objects.Count <= 10) _objects.Add(item);
            }
        }
    }
}
