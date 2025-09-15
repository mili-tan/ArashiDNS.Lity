﻿using System;
using System.Linq;
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;

namespace Arashi
{
    public static class DnsEncoder {

        public static byte[] Encode(DnsMessage dnsMsg, bool transIdEnable = false, bool trimEnable = false,
            ushort id = 0)
        {
            dnsMsg.IsRecursionAllowed = true;
            dnsMsg.IsRecursionDesired = true;
            dnsMsg.IsQuery = false;
            dnsMsg.IsEDnsEnabled = false;
            dnsMsg.EDnsOptions?.Options?.Clear();
            dnsMsg.AdditionalRecords?.Clear();

            if (id != 0) dnsMsg.TransactionID = id;
            if (!transIdEnable) dnsMsg.TransactionID = 0;

            dnsMsg.AuthorityRecords.RemoveAll(item =>
                item.Name.IsSubDomainOf(DomainName.Parse("arashi-msg")) ||
                item.Name.IsSubDomainOf(DomainName.Parse("nova-msg")));

            var dnsBytes = dnsMsg.Encode().ToArraySegment(false).ToArray();
            return trimEnable ? bytesTrimEnd(dnsBytes) : dnsBytes;
        }

        private static byte[] bytesTrimEnd(byte[] bytes, bool appendZero = false)
        {
            var list = bytes.ToList();
            var count = 0;
            for (var i = bytes.Length - 1; i >= 0; i--)
            {
                if (bytes[i] == 0x00)
                {
                    list.RemoveAt(i);
                    count++;
                }
                else
                    break;
            }

            if (count % 2 == 1 && appendZero) list.AddRange(new byte[] {0x00});
            return list.ToArray();
        }

        public static byte[] EncodeQuery(DnsMessage dnsQMsg)
        {
            dnsQMsg.IsRecursionAllowed = true;
            dnsQMsg.IsRecursionDesired = true;
            dnsQMsg.TransactionID = Convert.ToUInt16(new Random(DateTime.Now.Millisecond).Next(1, 10));
            var dnsBytes = dnsQMsg.Encode().ToArraySegment(false).ToArray();
            return dnsBytes;
        }
    }
}
