using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using Microsoft.AspNetCore.Builder;

namespace ArashiDNS.Lity
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var listen = new IPEndPoint(IPAddress.Any, 5380);
            var host = new WebHostBuilder()
                .UseKestrel()
                .UseContentRoot(AppDomain.CurrentDomain.SetupInformation.ApplicationBase)
                .ConfigureServices(services => { services.AddRouting(); })
                .ConfigureKestrel(options =>
                {
                    options.Listen(listen,
                        listenOptions => { listenOptions.Protocols = HttpProtocols.Http1AndHttp2; });
                })

                .Configure(app =>
                {
                    app.Map(string.Empty, svr =>
                    {
                        app.UseRouting().UseEndpoints(endpoint =>
                        {
                            endpoint.Map(
                                "/", async context => { await context.Response.WriteAsync("Arashi Lity"); });
                        });
                    });
                }).Build();

            host.Run();
        }
    }
}
