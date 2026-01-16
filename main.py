import requests
import os
import socket
import re
from datetime import datetime, timezone
import pytz
from ipaddress import ip_address
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing
from multiprocessing import Manager
import threading
from tqdm import tqdm


def extract_domain_from_rule(rule):
    """
    从广告规则中提取域名
    支持多种规则格式：
    - ||domain.com^
    - ||sub.domain.com^
    - domain.com
    - *.domain.com
    - www.domain.com
    - ||domain.com/path
    - ||domain.com^path
    - ||domain.com^$third-party
    - ||domain.com^$important
    """
    # 移除规则选项部分 (以$开头的部分)
    base_rule = rule.split('$')[0]
    
    # 正则表达式匹配各种域名格式
    patterns = [
        # 匹配 ||domain.com^ 格式
        r'\|\|([a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]*\.[a-zA-Z]{2,})(?:\^|$)',
        # 匹配 ||sub.domain.com/path 格式
        r'\|\|([a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]*\.[a-zA-Z]{2,})(?:/|$|\^)',
        # 匹配普通的域名格式
        r'([a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]*\.)+[a-zA-Z]{2,}',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, base_rule)
        if match:
            domain = match.group(1)
            if domain:
                # 移除可能的路径部分
                domain = domain.split('/')[0].split('^')[0]
                # 清理域名字符串
                domain = domain.strip().rstrip('^')
                if domain.startswith('*.'):
                    domain = domain[2:]
                elif domain.startswith('.'):
                    domain = domain[1:]
                
                if is_valid_domain(domain):
                    return domain
    
    # 如果正则都没匹配上，尝试更简单的提取方法
    # 查找可能的域名部分
    parts = re.split(r'[\/\^\$\?=#]', base_rule)
    for part in parts:
        # 尝试移除前缀
        if part.startswith('||'):
            part = part[2:]
        elif part.startswith('*'):
            part = part[1:]
        elif part.startswith('.'):
            part = part[1:]
        
        # 检查是否是有效的域名
        if is_valid_domain(part):
            return part
            
    return None


def is_valid_domain(domain):
    """检查域名是否有效"""
    if not domain or len(domain) > 253:
        return False
    
    # 基本的域名格式验证
    pattern = re.compile(
        r'^([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.)+[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(domain))


def get_ip_location(ip_str):
    """
    判断IP地址是否属于中国
    返回: 'CN' 表示中国, 'Foreign' 表示国外, 'Unknown' 表示未知
    """
    # 检查缓存中是否存在该IP
    with IP_LOCATION_CACHE_LOCK:
        if ip_str in IP_LOCATION_CACHE:
            return IP_LOCATION_CACHE[ip_str]
    
    try:
        # 这里我们使用简化的逻辑来判断IP位置
        # 实际应用中可能需要调用IP地理位置API
        ip_obj = ip_address(ip_str)
        
        # 处理私有IP地址
        if ip_obj.is_private:
            result = 'Private'
        
        # 一些常见的中国IP段（示例，实际应使用IP地理位置数据库）
        else:
            cn_ranges = [
                # 中国主要IP段（示例范围，不是完整列表）
                ('1.0.0.0', '1.255.255.255'),      # APNIC (China Telecom)
                ('36.25.0.0', '36.25.255.255'),    # China Unicom
                ('42.0.0.0', '42.255.255.255'),    # China Mobile
                ('49.0.0.0', '49.255.255.255'),    # Some China IPs
                ('58.0.0.0', '58.255.255.255'),    # China Education Network
                ('59.0.0.0', '59.255.255.255'),    # China Public Computer Internet
                ('110.0.0.0', '110.255.255.255'),  # China Telecom
                ('111.0.0.0', '111.255.255.255'),  # China Telecom
                ('112.0.0.0', '112.255.255.255'),  # China Telecom
                ('113.0.0.0', '113.255.255.255'),  # China Unicom
                ('114.0.0.0', '114.255.255.255'),  # China Telecom
                ('115.0.0.0', '115.255.255.255'),  # China Telecom
                ('116.0.0.0', '116.255.255.255'),  # China Telecom
                ('117.0.0.0', '117.255.255.255'),  # China Telecom
                ('118.0.0.0', '118.255.255.255'),  # China Unicom
                ('119.0.0.0', '119.255.255.255'),  # China Unicom
                ('120.0.0.0', '120.255.255.255'),  # China Telecom
                ('121.0.0.0', '121.255.255.255'),  # China Telecom
                ('122.0.0.0', '122.255.255.255'),  # China Unicom
                ('123.0.0.0', '123.255.255.255'),  # China Unicom
                ('124.0.0.0', '124.255.255.255'),  # China Telecom
                ('125.0.0.0', '125.255.255.255'),  # China Telecom
                ('14.0.0.0', '14.255.255.255'),    # China Telecom
                ('27.0.0.0', '27.255.255.255'),    # China Mobile
                ('36.0.0.0', '36.255.255.255'),    # China Mobile
                ('39.0.0.0', '39.255.255.255'),    # China Education Network
                ('42.4.0.0', '42.7.255.255'),      # China Mobile
                ('42.8.0.0', '42.15.255.255'),     # China Mobile
                ('42.16.0.0', '42.63.255.255'),    # China Mobile
                ('42.64.0.0', '42.127.255.255'),   # China Mobile
                ('42.128.0.0', '42.191.255.255'),  # China Mobile
                ('42.192.0.0', '42.255.255.255'),  # China Mobile
                ('43.224.0.0', '43.255.255.255'),  # Hong Kong (APNIC)
                ('45.64.0.0', '45.127.255.255'),   # Hong Kong (APNIC)
                ('47.92.0.0', '47.95.255.255'),    # Alibaba Cloud (China)
                ('47.96.0.0', '47.111.255.255'),   # Alibaba Cloud (China)
                ('47.104.0.0', '47.119.255.255'),  # Alibaba Cloud (China)
                ('47.240.0.0', '47.255.255.255'),  # Alibaba Cloud (China)
                ('47.252.0.0', '47.255.255.255'),  # Alibaba Cloud (China)
                ('101.0.0.0', '101.255.255.255'),  # APNIC (China)
                ('103.0.0.0', '103.255.255.255'),  # APNIC (Various Asian countries)
                ('106.0.0.0', '106.255.255.255'),  # APNIC (China)
                ('110.34.0.0', '110.35.255.255'),  # APNIC (China)
                ('110.44.0.0', '110.47.255.255'),  # APNIC (China)
                ('110.172.0.0', '110.175.255.255'), # APNIC (China)
                ('111.0.0.0', '111.255.255.255'),  # APNIC (China)
                ('112.0.0.0', '112.255.255.255'),  # APNIC (China)
                ('113.0.0.0', '113.255.255.255'),  # APNIC (China)
                ('114.0.0.0', '114.255.255.255'),  # China Telecom
                ('115.0.0.0', '115.255.255.255'),  # China Telecom
                ('116.0.0.0', '116.255.255.255'),  # China Telecom
                ('117.0.0.0', '117.255.255.255'),  # China Telecom
                ('118.0.0.0', '118.255.255.255'),  # China Unicom
                ('119.0.0.0', '119.255.255.255'),  # China Unicom
                ('120.0.0.0', '120.255.255.255'),  # China Telecom
                ('121.0.0.0', '121.255.255.255'),  # China Telecom
                ('122.0.0.0', '122.255.255.255'),  # China Unicom
                ('123.0.0.0', '123.255.255.255'),  # China Unicom
                ('124.0.0.0', '124.255.255.255'),  # China Telecom
                ('125.0.0.0', '125.255.255.255'),  # China Telecom
                ('129.226.0.0', '129.226.255.255'), # Tencent Cloud (China)
                ('139.9.0.0', '139.9.255.255'),    # Huawei Cloud (China)
                ('140.205.0.0', '140.205.255.255'), # Alibaba Cloud (China)
                ('146.196.0.0', '146.199.255.255'), # Alibaba Cloud (China)
                ('149.129.0.0', '149.129.255.255'), # Alibaba Cloud (China)
                ('155.102.0.0', '155.102.255.255'), # Alibaba Cloud (China)
                ('161.117.0.0', '161.117.255.255'), # Alibaba Cloud (China)
                ('175.0.0.0', '175.255.255.255'),  # APNIC (China)
                ('180.0.0.0', '180.255.255.255'),  # APNIC (China)
                ('182.0.0.0', '182.255.255.255'),  # APNIC (China)
                ('183.0.0.0', '183.255.255.255'),  # APNIC (China)
                ('202.0.0.0', '202.255.255.255'),  # APNIC (China and others)
                ('203.0.0.0', '203.255.255.255'),  # APNIC (China and others)
                ('210.0.0.0', '210.255.255.255'),  # APNIC (China and others)
                ('211.0.0.0', '211.255.255.255'),  # APNIC (China and others)
                ('218.0.0.0', '218.255.255.255'),  # APNIC (China and others)
                ('219.0.0.0', '219.255.255.255'),  # APNIC (China and others)
                ('220.0.0.0', '220.255.255.255'),  # APNIC (China and others)
                ('221.0.0.0', '221.255.255.255'),  # APNIC (China and others)
                ('222.0.0.0', '222.255.255.255'),  # APNIC (China and others)
                ('223.0.0.0', '223.255.255.255'),  # APNIC (China and others)
            ]
            
            ip_int = int(ip_obj)
            for start_ip, end_ip in cn_ranges:
                start_int = int(ip_address(start_ip))
                end_int = int(ip_address(end_ip))
                if start_int <= ip_int <= end_int:
                    result = 'CN'
                    break
            else:
                result = 'Foreign'
        
        # 将结果存入缓存
        with IP_LOCATION_CACHE_LOCK:
            IP_LOCATION_CACHE[ip_str] = result
        return result
    except ValueError:
        result = 'Unknown'
        # 将无效IP的结果也缓存起来
        with IP_LOCATION_CACHE_LOCK:
            IP_LOCATION_CACHE[ip_str] = result
        return result


def get_domain_ips(domain):
    """获取域名的所有IP地址，使用缓存机制"""
    # 检查缓存中是否存在该域名
    with DNS_CACHE_LOCK:
        if domain in DNS_CACHE:
            return DNS_CACHE[domain]
    
    try:
        # 设置socket超时
        socket.setdefaulttimeout(3)  # 3秒超时
        # 获取域名的所有IP地址
        result = socket.getaddrinfo(domain, None, socket.AF_INET)  # 仅IPv4
        ips = list(set([res[4][0] for res in result]))  # 去重
        
        # 将结果存入缓存
        with DNS_CACHE_LOCK:
            DNS_CACHE[domain] = ips
        return ips
    except socket.gaierror:
        # 如果无法解析域名，则返回空列表
        ips = []
        # 将无法解析的结果也缓存起来，避免重复查询
        with DNS_CACHE_LOCK:
            DNS_CACHE[domain] = ips
        # 将无法解析的域名添加到未解析域名集合
        with UNRESOLVED_DOMAINS_LOCK:
            UNRESOLVED_DOMAINS_SET.add(domain)
        return ips
    except socket.timeout:
        # 如果超时，则返回空列表
        ips = []
        # 将超时的结果也缓存起来，避免重复查询
        with DNS_CACHE_LOCK:
            DNS_CACHE[domain] = ips
        # 将无法解析的域名添加到未解析域名集合
        with UNRESOLVED_DOMAINS_LOCK:
            UNRESOLVED_DOMAINS_SET.add(domain)
        return ips
    finally:
        # 重置超时设置
        socket.setdefaulttimeout(None)


def classify_rule_by_location(rule, processed_domains_cache):
    """
    根据域名的IP位置对规则进行分类
    返回: 'CN' (中国), 'Foreign' (国外), 'Mixed' (混合), 'Unknown' (未知)
    """
    domain = extract_domain_from_rule(rule)
    if not domain:
        # 如果无法提取域名，可能是IP规则或其他类型，暂时归类为Unknown
        if re.match(r'^\d+\.\d+\.\d+\.\d+', rule):
            # 如果是以IP开头的规则，直接判断IP位置
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', rule)
            if ip_match:
                ip = ip_match.group(1)
                location = get_ip_location(ip)
                return location if location != 'Private' else 'Unknown'
        return 'Unknown'

    # 检查是否是已知的未解析域名
    with UNRESOLVED_DOMAINS_LOCK:
        if domain in UNRESOLVED_DOMAINS_SET:
            return 'Unknown'
    
    # 检查是否已经处理过这个域名
    if domain in processed_domains_cache:
        # 使用之前缓存的位置信息
        return processed_domains_cache[domain]
    
    # 获取域名的IP地址
    ips = get_domain_ips(domain)
    if not ips:
        processed_domains_cache[domain] = 'Unknown'
        return 'Unknown'
    
    # 统计IP位置
    cn_count = 0
    foreign_count = 0
    unknown_count = 0
    
    for ip in ips:
        location = get_ip_location(ip)
        if location == 'CN':
            cn_count += 1
        elif location == 'Foreign':
            foreign_count += 1
        else:
            unknown_count += 1
    
    # 根据IP位置决定规则分类
    if cn_count > 0 and foreign_count == 0 and unknown_count == 0:
        result = 'CN'
    elif foreign_count > 0 and cn_count == 0 and unknown_count == 0:
        result = 'Foreign'
    elif cn_count > 0 and foreign_count > 0:
        # 有中国和国外IP，可以根据数量判断主要位置
        result = 'CN' if cn_count >= foreign_count else 'Foreign'
    else:
        result = 'Unknown'
    
    # 缓存结果
    processed_domains_cache[domain] = result
    return result


def classify_single_rule(line, processed_domains_cache):
    """
    对单条规则进行分类
    """
    # 去重处理
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#'):
        return None, None  # 表示跳过该行

    # 分类规则
    classification = classify_rule_by_location(line, processed_domains_cache)

    return line, classification


def classify_single_rule_optimized(rule_data):
    """
    对单条规则进行分类的优化版本
    """
    rule, processed_domains_cache = rule_data
    domain = extract_domain_from_rule(rule)
    if not domain:
        # 如果无法提取域名，可能是IP规则或其他类型，暂时归类为Unknown
        if re.match(r'^\d+\.\d+\.\d+\.\d+', rule):
            # 如果是以IP开头的规则，直接判断IP位置
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', rule)
            if ip_match:
                ip = ip_match.group(1)
                location = get_ip_location(ip)
                return rule, location if location != 'Private' else 'Unknown'
        return rule, 'Unknown'

    # 检查是否是已知的未解析域名
    with UNRESOLVED_DOMAINS_LOCK:
        if domain in UNRESOLVED_DOMAINS_SET:
            return rule, 'Unknown'
    
    # 检查是否已经处理过这个域名
    if domain in processed_domains_cache:
        # 使用之前缓存的位置信息
        return rule, processed_domains_cache[domain]
    
    # 获取域名的IP地址
    ips = get_domain_ips(domain)
    if not ips:
        processed_domains_cache[domain] = 'Unknown'
        return rule, 'Unknown'
    
    # 统计IP位置
    cn_count = 0
    foreign_count = 0
    unknown_count = 0
    
    for ip in ips:
        location = get_ip_location(ip)
        if location == 'CN':
            cn_count += 1
        elif location == 'Foreign':
            foreign_count += 1
        else:
            unknown_count += 1
    
    # 根据IP位置决定规则分类
    if cn_count > 0 and foreign_count == 0 and unknown_count == 0:
        result = 'CN'
    elif foreign_count > 0 and cn_count == 0 and unknown_count == 0:
        result = 'Foreign'
    elif cn_count > 0 and foreign_count > 0:
        # 有中国和国外IP，可以根据数量判断主要位置
        result = 'CN' if cn_count >= foreign_count else 'Foreign'
    else:
        result = 'Unknown'
    
    # 缓存结果
    processed_domains_cache[domain] = result
    return rule, result


def classify_rules_batch(rules_batch, progress_dict=None, batch_id=None):
    """对一批规则进行分类，返回分类结果"""
    cn_rules = []
    foreign_rules = []
    unknown_rules = []
    processed_domains_cache = {}  # 记录已处理的域名及其位置，避免重复查询
    
    # 尝试加载未解析域名列表
    unresolved_domains = set()
    try:
        with open('unresolved_domains.txt', 'r', encoding='utf-8') as f:
            for line in f:
                domain = line.strip()
                if domain:
                    unresolved_domains.add(domain)
    except FileNotFoundError:
        pass  # 如果文件不存在，继续执行

    # 将未解析域名添加到全局集合
    with UNRESOLVED_DOMAINS_LOCK:
        UNRESOLVED_DOMAINS_SET.update(unresolved_domains)

    # 使用线程池处理这一批规则
    rules_with_cache = [(rule, processed_domains_cache) for rule in rules_batch]
    total_rules = len(rules_batch)
    
    # 创建内部进度条
    with tqdm(total=total_rules, desc=f"Batch {batch_id+1} progress", leave=False) as batch_pbar:
        with ThreadPoolExecutor(max_workers=min(len(rules_batch), 5)) as executor:
            # 提交所有任务
            futures = [executor.submit(classify_single_rule_optimized, rule_data) for rule_data in rules_with_cache]
            
            # 收集结果
            completed_count = 0
            for idx, future in enumerate(as_completed(futures)):
                rule, classification = future.result()
                
                if classification == 'CN':
                    cn_rules.append(rule)
                elif classification == 'Foreign':
                    foreign_rules.append(rule)
                else:
                    unknown_rules.append(rule)
                
                completed_count += 1
                
                # 更新进度字典
                if progress_dict is not None and batch_id is not None:
                    progress_dict[batch_id] = completed_count
                
                # 更新进度条
                batch_pbar.update(1)
                if completed_count % 1000 == 0:  # 每处理1000条规则更新一次附加信息
                    batch_pbar.set_postfix({'CN': len(cn_rules), 'Foreign': len(foreign_rules), 'Unknown': len(unknown_rules)})

    return cn_rules, foreign_rules, unknown_rules


def classify_rules_by_location(rules, max_workers=None, use_multiprocess=False):
    """对规则列表进行分类，可以选择使用多线程或多重进程优化"""
    print("Step 2: Classifying rules by location...")
    total_rules = len(rules)
    
    # 如果使用多进程模式
    if use_multiprocess and len(rules) > 10000:
        print(f"Using multiprocess mode for {len(rules)} rules")
        
        # 每10万条规则创建一个进程
        batch_size = 100000
        num_batches = (len(rules) + batch_size - 1) // batch_size  # 向上取整
        
        # 确定进程数
        if max_workers is None:
            max_workers = min(num_batches, multiprocessing.cpu_count())
        
        print(f"Splitting rules into {num_batches} batches with {max_workers} processes")
        
        # 分割规则列表为批次
        rule_batches = [rules[i:i + batch_size] for i in range(0, len(rules), batch_size)]
        
        # 使用进程池处理批次
        cn_rules = []
        foreign_rules = []
        unknown_rules = []
        
        # 创建进度条
        with tqdm(total=len(rule_batches), desc="Processing batches") as pbar:
            # 提交任务并跟踪进度
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                # 提交所有批次任务
                future_to_batch = {executor.submit(classify_rules_batch, batch, None, i): i for i, batch in enumerate(rule_batches)}
                
                completed_count = 0
                total_batches = len(rule_batches)
                
                # 收集结果
                for future in as_completed(future_to_batch):
                    batch_id = future_to_batch[future]
                    try:
                        batch_cn, batch_foreign, batch_unknown = future.result()
                        cn_rules.extend(batch_cn)
                        foreign_rules.extend(batch_foreign)
                        unknown_rules.extend(batch_unknown)
                        
                        completed_count += 1
                        batch_size_actual = len(rule_batches[batch_id])
                        pbar.set_postfix({'Batch size': batch_size_actual, 'Completed': f'{completed_count}/{total_batches}'})
                        pbar.update(1)
                    except Exception as exc:
                        print(f"  Batch {batch_id+1} generated an exception: {exc}")
                        pbar.update(1)
        
        return cn_rules, foreign_rules, unknown_rules
    else:
        # 如果未启用多进程或规则较少，使用原来的多线程方式
        if max_workers is None:
            max_workers = min(len(rules), multiprocessing.cpu_count() * 2)
            # 确保至少有1个线程，最多不超过20个线程
            max_workers = max(1, min(max_workers, 20))
        
        print(f"Using {max_workers} threads for classification")
        
        cn_rules = []
        foreign_rules = []
        unknown_rules = []
        processed_domains_cache = {}  # 记录已处理的域名及其位置，避免重复查询
        
        # 尝试加载未解析域名列表
        unresolved_domains = set()
        try:
            with open('unresolved_domains.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        unresolved_domains.add(domain)
        except FileNotFoundError:
            pass  # 如果文件不存在，继续执行

        # 将未解析域名添加到全局集合
        with UNRESOLVED_DOMAINS_LOCK:
            UNRESOLVED_DOMAINS_SET.update(unresolved_domains)

        # 使用线程池并行处理规则
        rules_with_cache = [(rule, processed_domains_cache) for rule in rules]
        
        # 创建进度条
        with tqdm(total=len(rules), desc="Classifying rules") as pbar:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # 提交所有任务
                futures = [executor.submit(classify_single_rule_optimized, rule_data) for rule_data in rules_with_cache]
                
                # 收集结果
                completed_count = 0
                for idx, future in enumerate(as_completed(futures)):
                    rule, classification = future.result()
                    
                    if classification == 'CN':
                        cn_rules.append(rule)
                    elif classification == 'Foreign':
                        foreign_rules.append(rule)
                    else:
                        unknown_rules.append(rule)
                    
                    completed_count += 1
                    pbar.update(1)
                    if completed_count % 5000 == 0:  # 每处理5000条规则更新一次附加信息
                        pbar.set_postfix({'CN': len(cn_rules), 'Foreign': len(foreign_rules), 'Unknown': len(unknown_rules)})

        return cn_rules, foreign_rules, unknown_rules


def load_existing_rules():
    """加载现有的规则文件，用于增量更新"""
    existing_rules = set()
    
    # 尝试加载所有现有的规则文件
    output_files = [
        'output/all_rules.txt',
        'domestic/cn_rules.txt',
        'foreign/foreign_rules.txt',
        'unknown_rules.txt'
    ]
    
    for file_path in output_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # 跳过以!开头的注释行（如 "! Generated on" 或 "! Update on"）
                    # 但保留实际的规则内容
                    if line and line.startswith('!'):
                        continue  # 跳过注释行
                    elif line and line.startswith('#'):
                        continue  # 跳过其他注释行
                    elif not line:
                        continue  # 跳过空行
                    else:
                        # 只添加实际的规则行
                        existing_rules.add(line)
        except FileNotFoundError:
            # 如果文件不存在，继续处理下一个
            continue
    
    print(f"Loaded {len(existing_rules)} existing rules for incremental update")
    return existing_rules


def collect_and_deduplicate_new_rules(urls, existing_rules):
    """收集新规则并去除已存在的规则"""
    print("Step 1: Collecting new rules and removing existing ones...")
    new_rules = set()
    
    for url_idx, url in enumerate(urls):
        print(f"Fetching rules from: {url} ({url_idx+1}/{len(urls)})")
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            lines = response.text.splitlines()

            for line_idx, line in enumerate(lines):
                if line_idx % 5000 == 0:
                    print(f"  Processed {line_idx}/{len(lines)} lines...")
                    
                line = line.strip()

                # 跳过注释行
                if line.startswith('!') or line.startswith('#'):
                    continue

                if not line:
                    continue

                # 只添加不在现有规则中的新规则
                if line not in existing_rules:
                    new_rules.add(line)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching URL ({url}): {e}")
    
    print(f"Collected {len(new_rules)} new unique rules")
    return list(new_rules)


def filter_and_classify_rules(urls):
    # 加载已存在的规则
    existing_rules = load_existing_rules()
    
    # 收集新规则
    new_rules = collect_and_deduplicate_new_rules(urls, existing_rules)
    
    if not new_rules:
        print("No new rules found. Nothing to process.")
        # 即使没有新规则，也需要加载现有的分类结果
        old_cn_rules = []
        old_foreign_rules = []
        old_unknown_rules = []
        
        try:
            with open('domestic/cn_rules.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('!') and not line.startswith('#'):
                        old_cn_rules.append(line)
        except FileNotFoundError:
            pass
        
        try:
            with open('foreign/foreign_rules.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('!') and not line.startswith('#'):
                        old_foreign_rules.append(line)
        except FileNotFoundError:
            pass
        
        try:
            with open('unknown_rules.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('!') and not line.startswith('#'):
                        old_unknown_rules.append(line)
        except FileNotFoundError:
            pass
        
        # 返回现有的规则，确保时间戳被更新
        all_unique_rules = existing_rules
        return old_cn_rules, old_foreign_rules, old_unknown_rules, 0, all_unique_rules
    
    # 对新规则进行分类
    new_cn_rules, new_foreign_rules, new_unknown_rules = classify_rules_by_location(new_rules, max_workers=None, use_multiprocess=True)
    
    # 加载旧的规则分类（如果文件存在）
    all_cn_rules = []
    all_foreign_rules = []
    all_unknown_rules = []
    
    # 加载之前分类的规则（排除注释行）
    try:
        with open('domestic/cn_rules.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('!') and not line.startswith('#'):
                    all_cn_rules.append(line)
    except FileNotFoundError:
        pass
    
    try:
        with open('foreign/foreign_rules.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('!') and not line.startswith('#'):
                    all_foreign_rules.append(line)
    except FileNotFoundError:
        pass
    
    try:
        with open('unknown_rules.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('!') and not line.startswith('#'):
                    all_unknown_rules.append(line)
    except FileNotFoundError:
        pass
    
    # 将新规则添加到相应的分类中
    all_cn_rules.extend(new_cn_rules)
    all_foreign_rules.extend(new_foreign_rules)
    all_unknown_rules.extend(new_unknown_rules)
    
    # 计算统计信息
    total_original_count = 0
    for url in urls:
        try:
            response = requests.get(url, timeout=30)
            lines = response.text.splitlines()
            actual_lines = len(lines)
            total_original_count += actual_lines
        except requests.exceptions.RequestException:
            continue
    
    duplicate_count = total_original_count - len(new_rules)  # 这里是新规则中的重复数量
    
    # 合并所有规则
    all_unique_rules = existing_rules.union(set(new_rules))
    
    return all_cn_rules, all_foreign_rules, all_unknown_rules, duplicate_count, all_unique_rules


def save_all_rules_to_output(all_rules):
    """将所有去重后的规则保存到output目录"""
    beijing_tz = pytz.timezone('Asia/Shanghai')
    beijing_time = datetime.now(beijing_tz)
    timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
    
    # 确保output目录存在
    os.makedirs('output', exist_ok=True)
    
    header_info = f"! Update on {timestamp} (Beijing Time)\n"
    header_info += f"! Generated on {timestamp} (Beijing Time)\n"
    header_info += f"! All deduplicated rules\n"
    header_info += f"! Total rules: {len(all_rules)}\n\n"
    
    with open('output/all_rules.txt', 'w', encoding='utf-8') as f:
        f.write(header_info)
        for rule in all_rules:
            if rule:
                f.write(rule + "\n")
    print(f"All deduplicated rules saved to output/all_rules.txt ({len(all_rules)} rules)")


def save_classified_rules(cn_rules, foreign_rules, unknown_rules, dup_count):
    """保存分类后的规则到不同目录"""
    beijing_tz = pytz.timezone('Asia/Shanghai')
    beijing_time = datetime.now(beijing_tz)
    timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')

    # 确保目录存在
    os.makedirs('domestic', exist_ok=True)
    os.makedirs('foreign', exist_ok=True)

    # 创建国内规则文件
    if cn_rules:
        header_info = f"! Update on {timestamp} (Beijing Time)\n"
        header_info += f"! Generated on {timestamp} (Beijing Time)\n"
        header_info += f"! Domestic rules (China IP location)\n"
        header_info += f"! Total domestic rules: {len(cn_rules)}\n\n"
        with open('domestic/cn_rules.txt', 'w', encoding='utf-8') as f:
            f.write(header_info)
            for line in cn_rules:
                if line:
                    f.write(line + "\n")
        print(f"Domestic rules saved to domestic/cn_rules.txt ({len(cn_rules)} rules)")
    else:
        # 即使没有规则也要创建文件，包含更新时间
        header_info = f"! Update on {timestamp} (Beijing Time)\n"
        header_info += f"! Generated on {timestamp} (Beijing Time)\n"
        header_info += f"! Domestic rules (China IP location)\n"
        header_info += f"! Total domestic rules: {len(cn_rules)}\n\n"
        with open('domestic/cn_rules.txt', 'w', encoding='utf-8') as f:
            f.write(header_info)

    # 创建国外规则文件
    if foreign_rules:
        header_info = f"! Update on {timestamp} (Beijing Time)\n"
        header_info += f"! Generated on {timestamp} (Beijing Time)\n"
        header_info += f"! Foreign rules (Non-China IP location)\n"
        header_info += f"! Total foreign rules: {len(foreign_rules)}\n\n"
        with open('foreign/foreign_rules.txt', 'w', encoding='utf-8') as f:
            f.write(header_info)
            for line in foreign_rules:
                if line:
                    f.write(line + "\n")
        print(f"Foreign rules saved to foreign/foreign_rules.txt ({len(foreign_rules)} rules)")
    else:
        # 即使没有规则也要创建文件，包含更新时间
        header_info = f"! Update on {timestamp} (Beijing Time)\n"
        header_info += f"! Generated on {timestamp} (Beijing Time)\n"
        header_info += f"! Foreign rules (Non-China IP location)\n"
        header_info += f"! Total foreign rules: {len(foreign_rules)}\n\n"
        with open('foreign/foreign_rules.txt', 'w', encoding='utf-8') as f:
            f.write(header_info)

    # 创建未知规则文件
    if unknown_rules:
        header_info = f"! Update on {timestamp} (Beijing Time)\n"
        header_info += f"! Generated on {timestamp} (Beijing Time)\n"
        header_info += f"! Unknown location rules (Could not determine IP location)\n"
        header_info += f"! Total unknown rules: {len(unknown_rules)}\n\n"
        with open('unknown_rules.txt', 'w', encoding='utf-8') as f:
            f.write(header_info)
            for line in unknown_rules:
                if line:
                    f.write(line + "\n")
        print(f"Unknown location rules saved to unknown_rules.txt ({len(unknown_rules)} rules)")
    else:
        # 即使没有规则也要创建文件，包含更新时间
        header_info = f"! Update on {timestamp} (Beijing Time)\n"
        header_info += f"! Generated on {timestamp} (Beijing Time)\n"
        header_info += f"! Unknown location rules (Could not determine IP location)\n"
        header_info += f"! Total unknown rules: {len(unknown_rules)}\n\n"
        with open('unknown_rules.txt', 'w', encoding='utf-8') as f:
            f.write(header_info)

    print("\nSummary:")
    print(f"  Domestic rules: {len(cn_rules)}")
    print(f"  Foreign rules: {len(foreign_rules)}")
    print(f"  Unknown rules: {len(unknown_rules)}")
    print(f"  Duplicates removed: {dup_count}")


def save_unresolved_domains():
    """保存无法解析的域名到文件"""
    beijing_tz = pytz.timezone('Asia/Shanghai')
    beijing_time = datetime.now(beijing_tz)
    timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
    
    with UNRESOLVED_DOMAINS_LOCK:
        unresolved_list = sorted(list(UNRESOLVED_DOMAINS_SET))
    
    header_info = f"! Update on {timestamp} (Beijing Time)\n"
    header_info += f"! Generated on {timestamp} (Beijing Time)\n"
    header_info += f"! Unresolved domains that could not be resolved to IP addresses\n"
    header_info += f"! Total unresolved domains: {len(unresolved_list)}\n\n"
    
    with open('unresolved_domains.txt', 'w', encoding='utf-8') as f:
        f.write(header_info)
        for domain in unresolved_list:
            f.write(domain + "\n")
    print(f"Unresolved domains saved to unresolved_domains.txt ({len(unresolved_list)} domains)")


# 全局DNS缓存和IP位置缓存
DNS_CACHE = {}
IP_LOCATION_CACHE = {}
UNRESOLVED_DOMAINS_SET = set()  # 存储无法解析的域名
DNS_CACHE_LOCK = threading.Lock()
IP_LOCATION_CACHE_LOCK = threading.Lock()
UNRESOLVED_DOMAINS_LOCK = threading.Lock()


def main():
    # 从urls.txt文件中读取URL列表
    urls = []
    try:
        with open('urls.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # 忽略空行和注释行
                    urls.append(line)
    except FileNotFoundError:
        print("错误: 找不到 urls.txt 文件")
        exit(1)
    
    print(f"Found {len(urls)} URLs to process")
    
    # 调用函数处理并分类规则
    cn_rules, foreign_rules, unknown_rules, dup_count, all_unique_rules = filter_and_classify_rules(urls)
    
    # 保存所有去重后的规则到output目录
    save_all_rules_to_output(all_unique_rules)
    
    # 保存分类后的规则
    save_classified_rules(cn_rules, foreign_rules, unknown_rules, dup_count)
    
    # 保存无法解析的域名
    save_unresolved_domains()
    
    print("\nProcessing complete! Rules have been classified and saved to respective directories.")


if __name__ == '__main__':
    # Windows平台需要添加此保护，以避免递归创建子进程
    import multiprocessing
    multiprocessing.freeze_support()  # 可选，用于可执行文件冻结支持
    main()