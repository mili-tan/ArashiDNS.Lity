using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using Arashi;
using ARSoft.Tools.Net.Dns;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.AspNetCore.Builder;

namespace ArashiDNS.Lity
{
    internal class Program
    {
        public static IPEndPoint Listen = new IPEndPoint(IPAddress.Any, 5380);
        public static IPEndPoint Up = new IPEndPoint(IPAddress.Any, 53);
        public static int TimeOut = 3000;
        public static string Path = "/dns-query";
        public static string Key = "dns";
        public static bool Validation = false;

        public static RecursiveDnsResolver RecursiveResolver = new()
            {Is0x20ValidationEnabled = Validation, IsResponseValidationEnabled = Validation, QueryTimeout = TimeOut};

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
            var wOption = cmd.Option<int>("-w <TimeOut>", isZh ? "等待回复的超时时间（毫秒）。[3000]" : "Timeout for waiting response (ms). [3000]", CommandOptionType.SingleValue);
            var lOption = cmd.Option<string>("-l <IPEndPoint>", isZh ? "设置监听地址和端口。[8.8.8.8:5380]" : "Set listen address and port. [8.8.8.8:5380]", CommandOptionType.SingleValue);
            var sOption = cmd.Option<string>("-s <IPEndPoint>", isZh ? "设置上游地址，为 0.0.0.0 时使用递归。[8.8.8.8:53]" : "Set upstream address, use recursion if 0.0.0.0. [8.8.8.8:53]", CommandOptionType.SingleValue);
            var pOption = cmd.Option<string>("-p <Path>", isZh ? "查询路径。[/dns-query]" : "Query path. [/dns-query]", CommandOptionType.SingleValue);
            var kOption = cmd.Option<string>("-k <Key>", isZh ? "查询参数。[dns]" : "Query parameter. [dns]", CommandOptionType.SingleValue);
            var vOption = cmd.Option<bool>("-v", isZh ? "启用 DNS 响应验证（0x20 和 RRSIG，对于递归）。" : "Enable DNS response validation (0x20 and RRSIG, for recursion).", CommandOptionType.NoValue);
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

                RecursiveResolver = new RecursiveDnsResolver()
                    {Is0x20ValidationEnabled = Validation, IsResponseValidationEnabled = Validation, QueryTimeout = TimeOut};

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
                                    Path, async context =>
                                    {
                                        var query = context.Request.Method.ToUpper() == "POST"
                                            ? await DNSParser.FromPostByteAsync(context)
                                            : DNSParser.FromWebBase64(context, Key);
                                        var result = query.CreateResponseInstance();

                                        if (query.Questions.Any())
                                        {
                                            var quest = query.Questions.First();

                                            if (Equals(Up.Address, IPAddress.Any))
                                            {
                                                var record = RecursiveResolver.Resolve<DnsRecordBase>(quest.Name,
                                                    quest.RecordType,
                                                    quest.RecordClass);

                                                if (record.Any()) result.AnswerRecords.AddRange(record);
                                                else result.ReturnCode = ReturnCode.NxDomain;
                                            }
                                            else
                                            {
                                                var res = await new DnsClient([Up.Address],
                                                    [new UdpClientTransport(Up.Port), new TcpClientTransport(Up.Port)],
                                                    queryTimeout: TimeOut).SendMessageAsync(query);
                                                
                                                if (res != null) result = res;
                                                else result.ReturnCode = ReturnCode.ServerFailure;
                                            }
                                        }

                                        context.Response.ContentType = "application/dns-message";
                                        await context.Response.BodyWriter.WriteAsync(DnsEncoder.Encode(result));
                                    });
                            });
                        });
                    }).Build();

                host.Run();
            });
            cmd.Execute(args);
        }
    }
}
