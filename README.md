<p align="center">
  <img src='https://github.com/user-attachments/assets/b60400b9-4d8b-43c1-8552-0f0b026afc7c' width="70%" height="70%"/>
</p>

----------

> Please make sure you have installed the [.NET SDK](https://learn.microsoft.com/zh-cn/dotnet/core/install/linux).
> 
> 请确保已经 [安装 .NET SDK](https://learn.microsoft.com/zh-cn/dotnet/core/install/linux) 运行环境

```
git clone https://github.com/mili-tan/ArashiDNS.Lity
cd ArashiDNS.Lity
dotnet run
```
----------

```
ArashiDNS.Lity - Minimal DNS over HTTPS  server with recursive
Copyright (c) 2025 Milkey Tan. Code released under the MIT License

Usage: ArashiDNS.Lity [options]

Options:
  -?|-he|--help    Show help information.
  -w <TimeOut>     Timeout for waiting response (ms). / 等待回复的超时时间（毫秒）。[3000]
  -l <IPEndPoint>  Set listen address and port. / 设置监听地址和端口。[8.8.8.8:5380]
  -s <IPEndPoint>  Set upstream address, use recursion if 0.0.0.0. / 设置上游地址，为 0.0.0.0 时使用递归。[8.8.8.8:53]
  -p <Path>        Query path. / 查询路径。[/dns-query]
  -k <Key>         Query parameter. / 查询参数。[dns]
  -v               Enable DNS response validation (0x20 and RRSIG, for recursion). / 启用 DNS 响应验证（0x20 和 RRSIG，对于递归）。
```

## License

Copyright (c) 2025 Milkey Tan. Code released under the [MIT License](https://github.com/mili-tan/ArashiDNS.Aha/blob/main/LICENSE). 

<sup>ArashiDNS™ is a trademark of Milkey Tan.</sup>
