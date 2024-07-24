'''
Author     : S1g0day
Version    : 0.3.7
Creat time : 2024/2/10 18:00
Modification time: 2024/7/24 10:00
Introduce  : 域名数据处理，结果导出到excel
'''

import re
import os
import time
import idna
import socket
import argparse
import tldextract
from tabulate import tabulate

class DomainIPProcessor:
    def __init__(self):
        pass
    
    # 中文域名转ASCII
    def convert_to_ascii(self, domain_name):
        if "://" in domain_name:
            domains = domain_name.split("://")
            domain = domains[1]
        else:
            domain = domain_name
        try:
            Ascii_Domain = idna.encode(domain).decode('ascii')
            return Ascii_Domain
        except Exception as e:
            print("转换失败:", e)
            return None

    def is_chinese_domain(self, domain):
        # 如果字符的 ASCII 编码大于 127，则说明是非 ASCII 字符，可能是中文字符
        return any(ord(char) > 127 for char in domain)

    def parse_ip_port(self, s):
        ip, _, port = s.partition(':')
        return (ip, int(port) if port else 0)

    # IP排序
    def sort_IPs(self, ip_addresses):
        # 使用set()函数进行去重
        unique_IPs = set(ip_addresses)

        # 使用socket库中的inet_aton函数将IP地址转换为32位二进制数，然后再将其转换为整数
        ip_integers = [socket.inet_aton(ip) for ip in unique_IPs]
        ip_integers.sort()

        # 使用socket库中的inet_ntoa函数将整数转换回IP地址格式
        sorted_IPs = [socket.inet_ntoa(ip) for ip in ip_integers]
        return sorted_IPs

    # url ip 排序
    def ip_url_output(self, IPs_list, IP_valid):
        ip_domains = []
        Schemes_IP_Domains = []
        NO_Schemes_IP_Domains = []
        ip_ports = []

        for i in IPs_list:
            for j in IP_valid:
                ipList = re.findall(r'[0-9]+(?:\.[0-9]+){3}', j)
                if i == ipList[0]:
                    if j and j not in ip_domains:
                        ip_domains.append(j)

                        # 分离协议头
                        if "://" in j:
                            Schemes_IP_Domains.append(j)
                        else:
                            NO_Schemes_IP_Domains.append(j)
        # 提取出IP:PORT
        for IP_PORT in NO_Schemes_IP_Domains:
            pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)'
            match = re.search(pattern, IP_PORT)
            if match:
                IP_PORT = f"{match.group(1)}:{match.group(2)}"
                if IP_PORT and IP_PORT not in ip_ports:
                    ip_ports.append(IP_PORT)
        IP_Ports_Sorted_List = sorted(ip_ports, key=self.parse_ip_port)
        return ip_domains, Schemes_IP_Domains, NO_Schemes_IP_Domains, IP_Ports_Sorted_List

    # 提取IP段
    def extract_ip_segment(self, ip):
        parts = ip.split('.')
        if len(parts) == 4:
            return '.'.join(parts[:3]) + '.0/24'
        return None

    # 提取纯粹的IP地址
    def process_ips(self, ip_list):
        pure_ips = set()
        ip_segments = set()
        ips_err = []
        p = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        for ip in ip_list:
            ip_match = re.findall(r'[0-9]+(?:\.[0-9]+){3}', ip)
            if ip_match and p.match(ip_match[0]):
                pure_ip = ip_match[0]
                pure_ips.add(pure_ip)
                ip_segments.add(self.extract_ip_segment(pure_ip))
            else:
                ips_err.append(ip)

        sorted_ips = self.sort_IPs(list(pure_ips))
        sorted_segments = sorted(list(ip_segments))
        return sorted_ips, sorted_segments, ips_err
        
    def handle_Domain_Valid(self, Domain_Valid):
        '''
        处理 Domain_Valid 数据
        '''
        Root_Domains = []
        Schemes_Domains = []
        NO_Schemes_Domains= []
        for url in Domain_Valid:
            # 提取根域名
            extracted = tldextract.extract(url)
            root_domain = extracted.domain + '.' + extracted.suffix
            if root_domain and root_domain not in Root_Domains:
                Root_Domains.append(root_domain)
            # 分离协议头
            if "://" in url:
                Schemes_Domains.append(url)
            else:
                NO_Schemes_Domains.append(url)
        return Root_Domains, Schemes_Domains, NO_Schemes_Domains

    # 区分IP和域名
    def classify_urls(self, urls):
        IP_valid = []
        Domain_Valid = []
        Root_Domains = []
        Chinese_Domain = []
        Ascii_Domain = []
        Url_Err = []

        ip_pattern = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        domain_pattern = re.compile(r'([a-zA-Z0-9.-]+?\.[a-zA-Z]{2,6})')
        for url in urls:
            # 检查是否包含IP地址
            ip_match = ip_pattern.search(url)
            # 检查是否包含域名
            domain_match = domain_pattern.search(url)
            if ip_match and domain_match:
                Url_Err.append(url)
            elif ip_match:
                IP_valid.append(url)
            elif domain_match:
                Domain_Valid.append(url)
            # 判断是否是中文域名
            elif self.is_chinese_domain(url):
                # 转换为 ASCII 格式
                domain_ascii = self.convert_to_ascii(url)
                if domain_ascii:
                    Chinese_Domain.append(url)
                    Ascii_Domain.append(domain_ascii)
            else:
                Url_Err.append(url)

        Root_Domains, Schemes_Domains, NO_Schemes_Domains= self.handle_Domain_Valid(Domain_Valid)
        return IP_valid, Domain_Valid, Chinese_Domain, Ascii_Domain, Root_Domains, Schemes_Domains, NO_Schemes_Domains, Url_Err

    # url去重
    def deduplicate_urls(self, file_name):
        non_scheme_parts = []
        texts = []
        with open(file_name, 'r', encoding='utf-8') as files:
            filelist = files.readlines()
            for fileurl in filelist:
                url = fileurl.strip()
                if url:
                    if "://" in url:
                        url_parts = url.split("://")
                        non_scheme_part = re.sub(r'/+', '/', url_parts[1])
                        if non_scheme_part and non_scheme_part not in non_scheme_parts:
                            non_scheme_parts.append(non_scheme_part)
                            texts.append(f"{url_parts[0]}://{non_scheme_part}")
                    else:
                        url = re.sub(r'/+', '/', url)
                        if url and url not in non_scheme_parts:
                            non_scheme_parts.append(url)
                            texts.append(url)
        return texts

    def save_results(self, output, data):
        savedata = []
        with open(output, 'w', encoding='utf-8') as fs:
            for i in data:
                if i and i not in savedata:
                    fs.write(i + '\n')

    def save_and_print_results(self, files, Root_Domains, Schemes_Domains, NO_Schemes_Domains, IPs, IP_Segment, 
                               Schemes_IP_Domains, NO_Schemes_IP_Domains, IP_Ports_Sorted_List, Chinese_Domain, 
                               Ascii_Domain, All_Schemes_Domains, All_No_Schemes_Domains, All_Data, All_Err):

        # 生成文件名
        str(time.time()).split(".")[0]
        filename = ''.join(files.split('/')[-1].split('.')[:-1])
        timenow = str(time.time()).split(".")[0]
        # outfilename = f'{filename}-'
        outfilename = f'{filename}-{timenow}'

        # 获取脚本所在目录
        script_dir = os.path.dirname(__file__)

        # 创建日志目录
        log_dir = os.path.join(script_dir, 'log')
        os.makedirs(log_dir, exist_ok=True)
        import pandas as pd
        outputs = {
            'Domains_Root': Root_Domains,
            'Domains_Schemes': Schemes_Domains,
            'Domains_No_Schemes': NO_Schemes_Domains,
            'Domains_Chinese': Chinese_Domain,
            'Domains_Chinese_Ascii': Ascii_Domain,
            'IPs': IPs,
            'IP_Segment': IP_Segment,
            'IP_Domains_Schemes': Schemes_IP_Domains,
            'IP_Domains_No_Schemes': NO_Schemes_IP_Domains,
            'IP_Ports_Sorted_List': IP_Ports_Sorted_List,
            'All_Domains_Schemes': All_Schemes_Domains,
            'All_Domains_No_Schemes': All_No_Schemes_Domains,
            'All_Err': All_Err,
            'All_Data_Quchong': All_Data
        }

        output_file = f'log/{outfilename}.xlsx'
        writer = pd.ExcelWriter(output_file)

        # 倒序处理outputs字典
        for key, data in reversed(list(outputs.items())):
            df = pd.DataFrame(data)
            df.to_excel(writer, sheet_name=key, index=False, header=False)

        writer.close()
        print(f"输出到：{output_file}")

    def process_file(self, files):
        # 去重
        texts = self.deduplicate_urls(files)

        # 提取域名和IP
        IP_valid, Domain_Valid, Chinese_Domain, Ascii_Domain, Root_Domains, Schemes_Domains, NO_Schemes_Domains, Url_Err = self.classify_urls(texts)
        
        # 提取纯粹IP和IP段, 并排序
        IPs, IP_Segment, IPs_Err = self.process_ips(IP_valid)
        # 处理IP url
        ip_domains, Schemes_IP_Domains, NO_Schemes_IP_Domains, IP_Ports_Sorted_List = self.ip_url_output(IPs, IP_valid)
        #合并
        All_Schemes_Domains = Schemes_Domains + Schemes_IP_Domains
        All_No_Schemes_Domains = NO_Schemes_Domains+ NO_Schemes_IP_Domains
        All_Err = Url_Err + IPs_Err
        All_Data = Domain_Valid + ip_domains
        # 调用函数并传入所需参数
        self.save_and_print_results(files, Root_Domains, Schemes_Domains, NO_Schemes_Domains, IPs, IP_Segment, 
                                    Schemes_IP_Domains, NO_Schemes_IP_Domains, IP_Ports_Sorted_List, Chinese_Domain, 
                                    Ascii_Domain, All_Schemes_Domains, All_No_Schemes_Domains, All_Data, All_Err)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Process URLs and IPs from a file.")
    parser.add_argument('file', type=str, help='The path to the file containing URLs and IPs.')
    args = parser.parse_args()

    processor = DomainIPProcessor()
    processor.process_file(args.file)
