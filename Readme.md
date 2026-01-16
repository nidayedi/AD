# 广告规则地理分类工具

一个高效的大规模广告规则处理工具，能够从多个来源收集广告过滤规则，并根据IP地理位置将其分类为国内和国外规则。

## 功能特点

- **多源规则收集**：从多个URL源收集广告过滤规则
- **智能去重**：自动识别和去除重复规则
- **地理位置分类**：根据IP地理位置将规则分为国内、国外和未知三类
- **增量更新**：只处理新增规则，提高处理效率
- **多线程处理**：使用多线程加速规则分类
- **缓存机制**：DNS和IP位置缓存，避免重复查询
- **未解析域名追踪**：记录无法解析的域名供后续处理

## 文件结构

```
AD/
├── main.py                 # 主程序入口
├── urls.txt               # 规则源URL列表
├── domestic/              # 国内规则目录
│   └── cn_rules.txt       # 国内规则文件
├── foreign/               # 国外规则目录
│   └── foreign_rules.txt  # 国外规则文件
├── output/                # 所有去重后规则目录
│   └── all_rules.txt      # 所有去重后的规则
├── unknown_rules.txt      # 无法确定位置的规则
└── unresolved_domains.txt # 无法解析的域名列表
```

## 使用方法

### 1. 配置规则源

编辑 `urls.txt` 文件，添加广告规则源URL，每行一个URL，支持注释（以#开头）：

```
# AdGuard Home 规则
https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/all.txt
# EasyList China
https://easylist-downloads.adblockplus.org/easylistchina.txt
```

### 2. 运行程序

```bash
python main.py
```

## 输出文件说明

- `output/all_rules.txt`：所有去重后的规则
- `domestic/cn_rules.txt`：位于中国的域名/IP规则
- `foreign/foreign_rules.txt`：位于海外的域名/IP规则
- `unknown_rules.txt`：无法确定地理位置的规则
- `unresolved_domains.txt`：无法解析的域名列表

## 分类逻辑

1. **域名规则**：提取域名，通过DNS解析获取IP，根据IP地理位置判断
2. **IP规则**：直接根据IP地址判断地理位置
3. **分类标准**：
   - `CN`：中国IP段的规则
   - `Foreign`：海外IP段的规则
   - `Unknown`：无法解析或无法确定位置的规则

## 技术特点

- **高性能**：使用多线程处理和缓存机制，可高效处理数十万条规则
- **增量更新**：自动识别新增规则，避免重复处理
- **容错机制**：处理网络异常、DNS解析失败等情况
- **进度提示**：实时显示处理进度

## 依赖

- Python 3.x
- requests
- pytz

## 应用场景

- 广告过滤规则的地理区域分类
- 网络安全策略的地域化配置
- CDN资源的地域化管理
- 数据合规性的地域划分
- 跨境业务的数据隔离处理