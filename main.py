import requests
import os
from datetime import datetime, timezone
import pytz


def filter_and_log_duplicates(urls, output_file):
    unique_rules = set()  # 用于存储第一次匹配的规则
    duplicates = set()  # 用于存储出现重复的规则
    output_lines = []  # 用于保持所有行（保留顺序，包括注释和规则）

    for url in urls:
        print(f"Fetching rules from: {url}")
        try:
            # 从指定网址获取内容（下载）
            response = requests.get(url, timeout=30)
            response.raise_for_status()  # 检查请求是否成功
            lines = response.text.splitlines()  # 逐行拆分内容

            # 开始处理规则文件内容
            for line_number, line in enumerate(lines, start=1):
                line = line.strip()  # 去掉空格和换行符

                # 把注释行（以 `!` 或 `#` 开头）直接删除
                if line.startswith('!') or line.startswith('#'):
                    continue

                # 从第1行开始去重处理
                if line_number >= 2:
                    # 如果当前行已存在于集合中，记录为重复
                    if line in unique_rules:
                        duplicates.add(line)
                    else:
                        # 如果当前行是新规则，存储到集合并加入输出行
                        unique_rules.add(line)
                        output_lines.append(line)
                else:
                    # 对第13行之前的非注释内容直接保留
                    output_lines.append(line)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching URL ({url}): {e}")

    # 添加更新时间戳和其他元数据到输出文件的最上方
    beijing_tz = pytz.timezone('Asia/Shanghai')
    beijing_time = datetime.now(beijing_tz)
    header_info = f"! Generated on {beijing_time.strftime('%Y-%m-%d %H:%M:%S')} (Beijing Time)\n"
    header_info += f"! Total rules: {len(unique_rules)}\n"
    header_info += f"! Duplicates removed: {len(duplicates)}\n\n"

    # 将处理后的规则保存到输出文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(header_info)  # 首先写入头部信息
        for line in output_lines:
            if line:  # 只写入非空行
                f.write(line + "\n")  # 把输出内容逐行写入

    # 提示任务完成
    print("Processing complete!")
    print(f"Processed content saved to {output_file}")
    print(f"Total unique rules: {len(unique_rules)}")
    print(f"Duplicates found: {len(duplicates)}")


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

output_file_path = os.getenv('OUTPUT_FILE', 'output.txt')  # 可通过环境变量自定义输出文件名

# 调用函数处理
filter_and_log_duplicates(urls, output_file_path)