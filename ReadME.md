# S7 变量解析工具

## 简介
这是一个用于解析 S7 通信协议的工具，能够从 `.pcap` 或 `.pcapng`文件中提取 S7 变量信息，并将其导出为 `.csv` 文件。该工具支持多进程处理，可以高效地处理大型 pcap 文件。

## 命令行参数
运行该工具时，需要通过命令行参数指定输入文件、输出文件以及可选的分片大小。以下是参数说明：

| 参数 | 简写 | 描述 | 是否必选 | 默认值 |
|------|------|------|----------|--------|
| `--input` | `-i` | 输入的 `.pcap` 文件路径 | 是 | 无 |
| `--output` | `-o` | 输出的 `.csv` 文件路径 | 是 | 无 |
| `--slice` | `-s` | 每片报文的数量（用于分片处理） | 否 | 10000 |

## 示例用法
以下是一个使用示例：
```bash
python S7Analyzer.py -i input.pcap -o output.csv -s 5000
```
或者：
```bash
S7Analyzer.exe -i input.pcap -o output.csv -s 5000
```

## 输出文件
该工具将解析的 S7 变量信息导出为一个 `.csv` 文件，包含以下字段：
- `source_ip`：源 IP 地址
- `destination_ip`：目标 IP 地址
- `operation`：操作类型（读或写）
- `memory_type`：内存类型（如 `P`、`I`、`Q` 等）
- `data_type`：数据类型（如 `BOOL`、`BYTE`、`INT` 等）
- `data_size`：数据大小（字节）
- `number_of_data`：数据元素数量
- `block_num`：块编号
- `offset`：偏移量（字节）
- `byte_length`：总字节长度

## 注意事项
- 确保输入的 `.pcap` 文件存在且路径正确。
- 如果需要处理的 `.pcap` 文件非常大，建议适当调整分片大小（`--slice` 参数）以优化性能。
- 该工具依赖于 `editcap` 工具（包含在 Wireshark 中），请确保其已安装并可用。

---
