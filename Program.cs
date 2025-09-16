using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using Arashi;
using ARSoft.Tools.Net.Dns;
using Microsoft.AspNetCore.Builder;

namespace ArashiDNS.Lity
{
    internal class Program
    {
        public static IPEndPoint Listen = new IPEndPoint(IPAddress.Any, 5380);
        public static IPEndPoint Up = new IPEndPoint(IPAddress.Any, 53);
        public static int TimeOut = 3000;
        public static string Path = "dns-query";
        public static string Key = "dns";

        public static RecursiveDnsResolver RecursiveResolver = new()
            {Is0x20ValidationEnabled = false, IsResponseValidationEnabled = false, QueryTimeout = TimeOut};

        static void Main(string[] args)
        {
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
                                    var dnsMsg = context.Request.Method.ToUpper() == "POST"
                                        ? await DNSParser.FromPostByteAsync(context)
                                        : DNSParser.FromWebBase64(context, Key);
                                    var quest = dnsMsg.Questions.FirstOrDefault();
                                    var result = dnsMsg.CreateResponseInstance();

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
                                            queryTimeout: TimeOut).SendMessageAsync(dnsMsg);
                                        if (res != null) result = res;
                                    }

                                    context.Response.ContentType = "application/dns-message";
                                    await context.Response.BodyWriter.WriteAsync(DnsEncoder.Encode(result));
                                });
                        });
                    });
                }).Build();

            host.Run();
        }
    }
}
