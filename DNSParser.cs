using System.Buffers;
using System.Net;
using System.Net.Sockets;
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using Microsoft.AspNetCore.Http;

namespace Arashi
{
    class DNSParser
    {
        public static DnsMessage FromDnsJson(HttpContext context, byte EcsDefaultMask = 24)
        {
            var queryDictionary = context.Request.Query;
            var dnsQuestion = new DnsQuestion(DomainName.Parse(queryDictionary["name"]),
                context.Connection.RemoteIpAddress!.AddressFamily == AddressFamily.InterNetworkV6 ? RecordType.Aaaa : RecordType.A,
                RecordClass.INet);
            if (queryDictionary.ContainsKey("type"))
                if (Enum.TryParse(queryDictionary["type"], true, out RecordType rType))
                    dnsQuestion = new DnsQuestion(DomainName.Parse(queryDictionary["name"]), rType,
                        RecordClass.INet);

            var dnsQMsg = new DnsMessage
            {
                IsEDnsEnabled = true,
                IsQuery = true,
                IsRecursionAllowed = true,
                IsRecursionDesired = true,
                TransactionID = Convert.ToUInt16(new Random(DateTime.Now.Millisecond).Next(1, 99))
            };
            dnsQMsg.Questions.Add(dnsQuestion);

            if (queryDictionary.ContainsKey("edns_client_subnet"))
            {
                var ipStr = queryDictionary["edns_client_subnet"].ToString();
                var ipNetwork = ipStr.Contains("/")
                    ? IPNetwork2.Parse(ipStr)
                    : IPNetwork2.Parse(ipStr, EcsDefaultMask);
                dnsQMsg.EDnsOptions.Options.Add(new ClientSubnetOption(
                    Equals(ipNetwork.Network, IPAddress.Any) ? (byte)0 : ipNetwork.Cidr, ipNetwork.Network));
            }

            return dnsQMsg;
        }

        public static DnsMessage FromWebBase64(string base64) => DnsMessage.Parse(DecodeWebBase64(base64));

        public static DnsMessage FromWebBase64(HttpContext context, string key = "dns")
        {
            return FromWebBase64(context.Request.Query[key].ToString());
        }

        public static async Task<DnsMessage> FromPostByteAsync(HttpContext context)
        {
            var msg = DnsMessage.Parse((await context.Request.BodyReader.ReadAsync()).Buffer.ToArray());
            return msg;
        }

        public static bool IsEcsEnable(DnsMessage msg)
        {
            return msg.IsEDnsEnabled && msg.EDnsOptions.Options.ToArray().OfType<ClientSubnetOption>().Any();
        }

        public static byte[] DecodeWebBase64(string base64)
        {
            if (base64.Length % 4 > 0) base64 = base64.PadRight(base64.Length + 4 - base64.Length % 4, '=');
            return Convert.FromBase64String(base64.Replace("-", "+").Replace("_", "/"));
        }
    }
}
