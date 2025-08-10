import pyshark
import csv

# Wireshark 文件路径
pcap_file = r'c:\temp\1.pcap'
# 输出 CSV 文件路径
csv_file = 's7_variables.csv'

def get_tcp_payload(packet):
    # 检查是否有 TCP 层
    if 'TCP' in packet:
        tcp_layer = packet['TCP']
        # 检查是否有 payload 属性
        if hasattr(tcp_layer, 'payload'):
            # payload = bytes.fromhex(tcp_layer.payload.replace(":", ""))
            return tcp_layer.payload.binary_value

def is_S7Job(payload):
    # 检查 payload 长度并判断第9个字节是否为1
    if payload and len(payload) >= 9:
        return payload[8] == 1
    return False

def bytes_to_int(data, start, length):
    # data: bytes对象
    # start: 起始索引（从0开始）
    # length: 字节数（2或4）
    if data and len(data) >= start + length:
        return int.from_bytes(data[start:start+length], byteorder='big')
    return None

def parse_item(item):
    """
    Parses a binary item and extracts information about its data type, size, memory type, and other attributes.
    Args:
        item (bytes): A binary sequence representing the item to be parsed. 
                      Must be at least 10 bytes long.
    Returns:
        dict or None: A dictionary containing the parsed information if the input is valid, 
                      otherwise None. The dictionary contains the following keys:
            - 'data_type' (str): The name of the data type (e.g., 'BOOL', 'BYTE', etc.).
            - 'data_size' (int): The size of the data type in bytes.
            - 'byte_length' (int): The total byte length of the data.
            - 'number_of_data' (int): The number of data elements.
            - 'block_num' (int): The block number associated with the data.
            - 'memory_type' (str): The memory type (e.g., 'P', 'I', 'Q', etc.).
            - 'offset' (int): The offset in memory, in bytes.
    Notes:
        - The function uses predefined mappings for data types and memory types.
        - If the data type or memory type is not recognized, it defaults to 'unknown'.
        - For 'bit' data types, the length is calculated in bits and converted to bytes.
    Raises:
        None: The function does not raise exceptions but returns None for invalid input.
    """
    if not item or len(item) < 10:
        return None

    # 类型映射：类型名和长度
    type_map = {
        0x01: ('BOOL', 0),
        0x02: ('BYTE', 1),
        0x03: ('CHAR', 2),
        0x04: ('WORD', 2),
        0x05: ('INT', 2),
        0x06: ('DWORD', 4),
        0x07: ('DINT', 4),
        0x08: ('REAL', 4),
        0x09: ('DATE', 2),
        0x0A: ('TOD', 4),
        0x0B: ('TIME', 4),
        0x0C: ('S5TIME', 2),
        0x0E: ('DT', 8),
        # 可继续扩展
    }
    # 存储类型映射
    memory_type_map = {
        0x80: 'P',
        0x81: 'I',
        0x82: 'Q',
        0x83: 'M',
        0x84: 'DB',
        0x85: 'DI',
        0x86: 'L',
        0x87: 'V',
        # 可继续扩展
    }
    b2 = item[1]
    # print(f"b2: {b2:#x}")
    type_name, type_len = type_map.get(b2, ('unknown', 0))

    int_34 = int.from_bytes(item[2:4], byteorder='big')
    if type_name == 'bit':
        length = int_34  # bit类型，length为bit数
        byte_length = (length + 7) // 8  # 实际占用字节数
    else:
        length = type_len * int_34
        byte_length = length

    block_num = int.from_bytes(item[4:6], byteorder='big')

    memory_type_code = item[6]
    # print(f"memory_type_code: {memory_type_code:#x}")
    memory_type = memory_type_map.get(memory_type_code, f'unknown({memory_type_code:#x})')

    offset = int.from_bytes(item[7:10], byteorder='big') // 8

    return {
        'data_type': type_name,
        'data_size': type_len,
        'byte_length': byte_length,
        'number_of_data': int_34,
        'block_num': block_num,
        'memory_type': memory_type,
        'offset': offset
    }

def extract_s7_variables(packet):
    """
    Extracts S7 communication variables from a given network packet.
    This function analyzes the payload of a TCP packet to determine if it contains
    S7 communication data. If the payload corresponds to an S7 Job, it extracts
    variable information such as operation type (read or write), source IP, and
    destination IP.
    Args:
        packet: A network packet object containing TCP payload and IP information.
                It is expected to have attributes like `ip.src` and `ip.dst`.
    Returns:
        list: A list of dictionaries, where each dictionary contains the following keys:
            - 'operation': A string indicating the operation type ('read' or 'write').
            - Additional keys parsed from the S7 variable item (e.g., address, length).
            - 'source_ip': The source IP address of the packet.
            - 'destination_ip': The destination IP address of the packet.
        If the packet does not contain S7 communication data, an empty list is returned.
    Notes:
        - The function assumes that the payload structure adheres to the S7 protocol.
        - The `get_tcp_payload` and `is_S7Job` helper functions are used to extract
          and validate the payload.
        - The `parse_item` function is used to parse individual S7 variable items.
    """
    # 检查是否为 S7 通信报文
    payload = get_tcp_payload(packet)
    # for byte in payload:
    #     print(f"{byte:02x}", end=" ")
    # print()
    if is_S7Job(payload):
        # 提取 S7 变量信息
        func = payload[17]
        # 操作类型: 读或写
        item_count_index = 18
        items = []
        if func in [0x04, 0x05]:
            count = payload[item_count_index]  # 第19个字节是项数
            item_start = item_count_index + 1  # 项数据起始位置
            for _ in range(count):
                item = payload[item_start + 2:item_start + 12]
                item_start += 12
                # print(f"item: {item.hex()}")
                parsed = parse_item(item)
                if parsed is not None:
                    items.append({
                        **parsed,
                        'operation': 'read' if func == 0x04 else 'write',
                        'source_ip': packet.ip.src,
                        'destination_ip': packet.ip.dst
                    })
            return items
    return []

def main():
    seen_items = set()
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['source_ip','destination_ip','operation', 'memory_type','data_type','data_size','number_of_data','block_num','offset','byte_length'])
        writer.writeheader()
        cap = pyshark.FileCapture(pcap_file, display_filter='s7comm', keep_packets=False)
        for packet in cap:
            items = extract_s7_variables(packet)
            for item in items:
                key_fields = (
                    item.get('source_ip'),
                    item.get('destination_ip'),
                    item.get('operation'),
                    item.get('memory_type'),
                    item.get('data_type'),
                    item.get('offset')
                )
                if key_fields not in seen_items:
                    seen_items.add(key_fields)
                    writer.writerow(item)
        cap.close()

if __name__ == '__main__':
    # Run the main function to process the pcap file and export S7 variables to CSV
    main()
    print(f"Processing complete. The results have been saved to the CSV file: {csv_file}")
