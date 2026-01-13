import requests
from sqlalchemy import null


def filter_and_log_duplicates(urls, output_file):
    unique_rules = set()  # 用于存储第一次匹配的规则
    duplicates = set()  # 用于存储出现重复的规则
    output_lines = []  # 用于保持所有行（保留顺序，包括注释和规则）

    for url in urls:
        print(f"Fetching rules from: {url}")
        try:
            # 从指定网址获取内容（下载）
            response = requests.get(url)
            response.raise_for_status()  # 检查请求是否成功
            lines = response.text.splitlines()  # 逐行拆分内容

            # 开始处理规则文件内容
            for line_number, line in enumerate(lines, start=1):
                line = line.strip()  # 去掉空格和换行符

                # 把注释行（以 `!---` 开头）直接保留
                if line.startswith('!---'):
                    output_lines.append(line)
                    continue

                # 从第13行开始去重处理
                if line_number >= 1:
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

    # 将处理后的规则保存到输出文件
    with open(output_file, 'w', encoding='utf-8') as f:
        for line in output_lines:
            f.write(line + "\n")  # 把输出内容逐行写入

    # 将重复的规则写入到日志文件
    # with open(log_file, 'w', encoding='utf-8') as log:
    #     total_duplicates = len(duplicates)  # 统计总计重复的规则数量
    #     log.write("Duplicate Rules (ignored occurrences after the first):\n")
    #     for rule in sorted(duplicates):  # 重复规则按字典序保存
    #         log.write(f"{rule}\n")
    #     log.write(f"\nTotal distinct duplicates: {total_duplicates}\n")

    # 提示任务完成
    print("Processing complete!")
    print(f"Processed content saved to {output_file}")


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

output_file_path = 'output.txt'  # 最终去重后保存的输出文件

# 调用函数处理
filter_and_log_duplicates(urls, output_file_path)
