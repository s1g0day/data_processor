# 简介

这是一个用于域名和IP地址处理的Python工具库，名为 DomainIPProcessor。它提供了一系列功能来解析、排序和处理包含域名和IP地址的数据。此工具非常适用于网络分析、安全审核以及任何需要精确管理和解析网络地址数据的场合。

## 主要特点

- 国际化域名处理：支持将中文域名转换为ASCII，适用于国际化域名（IDN）。
- IP地址排序与分析：对IP地址进行提取和排序，支持CIDR格式的IP段提取。
- URL和IP的高级处理：分类处理含IP和域名的URL，支持带协议和不带协议的URL格式。
- 数据去重与整合：从文件中读取URL数据，自动去重并分类整理。
- 结果输出：处理结果以文件形式保存，并在控制台输出详细的日志信息，便于追踪处理过程。
- 易于集成和使用：可以作为命令行工具直接使用，方便集成到其他Python项目或脚本中。

这个工具非常适合开发人员和网络管理员使用，它可以帮助快速分析和处理网络数据，提高工作效率和数据管理的准确性。这个库也适合进行网络研究和教育用途，因为它涵盖了域名解析、IP处理等基础而关键的网络操作。

## 使用场景

- 网络安全：分析和审计来自各种源的IP地址和域名，识别潜在的安全威胁。
- 数据清洗：在大数据项目中，清洗和准备来自网络日志的数据。
- 教育和研究：教授学生关于网络地址解析的基础知识，以及如何在Python中处理这些数据。
- API开发：为网络服务开发背景任务，例如自动更新DNS记录或验证网络配置。

# 安装

```
pip install DomainIPProcessor

# 使用示例
python3 data_processor.py url.txt
```
导入模式
```
# 使用示例
from DomainIPProcessor import DomainIPProcessor

# 创建实例
processor = DomainIPProcessor()

# 处理特定文件中的URL和IP
processor.process_file('path_to_your_file.txt')
```
# 输出

数据源详情可以查看`demo.txt`, 项目会输出14个各类样式的文件
```
demo--All_Data_Quchong.txt                                # 去重后的所有数据。保留原格式
demo--All_Domains_No_Schemes.txt                # 提取所有不带协议头的数据
demo--All_Domains_Schemes.txt                        # 提取所有带协议头的数据
demo--All_Err.txt                                                # 所有无法处理或数据源异常的数据
demo--Domains_Chinese_Ascii.txt                        # 提取中文域名
demo--Domains_Chinese_Ascii.txt                        # 中文域名转为asscii后的数据
demo--Domains_No_Schemes.txt                        # 提取不带协议头的数据。域名数据
demo--Domains_Root.txt                                        # 提取根域名。域名数据
demo--Domains_Schemes.txt                                # 提取带协议头的数据。域名数据
demo--IPs.txt                                                        # 提取排序去重后的IP数据。IP数据
demo--IP_Domains_No_Schemes.txt                        # 提取不带协议头的数据。IP数据
demo--IP_Domains_Schemes.txt                        # 提取带协议头的数据。IP数据
demo--IP_Ports_Sorted_List.txt                        # 提取排序IP:PORT数据。IP数据，原意是整理fscan错乱的的IP:port数据
demo--IP_Segment.txt                                        # 提取IP段。仅提取了C段
```

# 贡献与支持

如果本项目对你有用，还请star鼓励一下。

无论是添加新功能、改进代码、修复BUG或提供文档。请通过GitHub的Issue和Pull Request提交您的贡献，我会尽快给予帮助及更新。
