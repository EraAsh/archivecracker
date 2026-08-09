#!/usr/bin/env python3
"""
sevenzip2john.py - 纯 Python 版 7z 哈希提取器
替代 Perl 版 7z2john.pl（Windows 无 Perl 解释器导致 GPU 模式失败）
输出 hashcat mode 11600 兼容的 $7z$ hash 行。
"""
import struct
import sys

SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
SEVEN_ZIP_AES = b"\x06\xf1\x07\x01"
SEVEN_ZIP_LZMA1 = b"\x03\x01\x01"
SEVEN_ZIP_HEADER = b"\x01"
SEVEN_ZIP_ENCODED_HEADER = b"\x17"
SEVEN_ZIP_END = b"\x00"
SEVEN_ZIP_SIZE = b"\x09"
SEVEN_ZIP_CRC = b"\x0a"
SEVEN_ZIP_DEFAULT_POWER = 19
SEVEN_ZIP_DEFAULT_IV = b"\x00" * 16


class Reader:
    """带位置跟踪的二进制读取器"""

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def read(self, n: int) -> bytes:
        end = self.pos + n
        if end > len(self.data):
            raise EOFError(f"读取越界: pos={self.pos} n={n} len={len(self.data)}")
        b = self.data[self.pos:end]
        self.pos = end
        return b

    def tell(self) -> int:
        return self.pos

    def seek(self, pos: int):
        self.pos = pos

    def read_number(self) -> int:
        """7z 变长整数编码"""
        b = self.read(1)[0]
        if (b & 0x80) == 0:
            return b
        value = self.read(1)[0]
        for i in range(1, 8):
            mask = 0x80 >> i
            if (b & mask) == 0:
                high = b & (mask - 1)
                value |= (high << (i * 8))
                return value
            value |= (self.read(1)[0] << (i * 8))
        return value

    def read_id(self) -> bytes:
        """读属性 ID（number 转字节序列）"""
        num = self.read_number()
        if num == 0:
            return b"\x00"
        out = bytearray()
        while num > 0:
            out.insert(0, num & 0xFF)
            num >>= 8
        return bytes(out)

    def skip_data(self):
        """跳过属性数据段"""
        n = self.read(1)[0]
        self.read(n)


def get_decoder_properties(attributes: bytes):
    """从 AES coder 属性提取 salt/iv/cycles power（对齐 7z2john.pl get_decoder_properties）"""
    salt_len = 0
    salt_buf = b""
    iv_len = len(SEVEN_ZIP_DEFAULT_IV)
    iv_buf = SEVEN_ZIP_DEFAULT_IV
    number_cycles_power = SEVEN_ZIP_DEFAULT_POWER

    if len(attributes) == 0:
        return salt_len, salt_buf, iv_len, iv_buf, number_cycles_power

    offset = 0
    first_byte = attributes[offset]
    offset += 1
    number_cycles_power = first_byte & 0x3F

    if (first_byte & 0xC0) == 0:
        return salt_len, salt_buf, iv_len, iv_buf, number_cycles_power

    salt_len = (first_byte >> 7) & 1
    iv_len = (first_byte >> 6) & 1

    second_byte = attributes[offset]
    offset += 1

    salt_len += (second_byte >> 4)
    iv_len += (second_byte & 0x0F)

    salt_buf = attributes[offset:offset + salt_len]
    offset += salt_len

    iv_buf = attributes[offset:offset + iv_len]

    # pad iv 到 16 字节
    iv_buf = (iv_buf + b"\x00" * 16)[:16]

    return salt_len, salt_buf, iv_len, iv_buf, number_cycles_power


def get_boolean_vector(r: Reader, number_items: int) -> list:
    """读取布尔向量（位打包）"""
    booleans = []
    v = 0
    mask = 0
    for _ in range(number_items):
        if mask == 0:
            v = r.read(1)[0]
            mask = 0x80
        booleans.append(bool(v & mask))
        mask >>= 1
    return booleans


SEVEN_ZIP_ALL_DEFINED = b"\xff"


def read_digests(r: Reader, number_items: int) -> list:
    """读取 digest 数组（CRC），defined 向量支持 ALL_DEFINED(0xFF) 捷径"""
    digests = []
    first = r.read(1)
    if first == SEVEN_ZIP_ALL_DEFINED:
        defined = [True] * number_items
    else:
        # 把已读的首字节拼回 bit 流再解析
        bits = []
        v = first[0]
        mask = 0x80
        for _ in range(number_items):
            if mask == 0:
                v = r.read(1)[0]
                mask = 0x80
            bits.append(bool(v & mask))
            mask >>= 1
        defined = bits

    for i in range(number_items):
        crc = 0
        if defined[i]:
            for j in range(4):
                crc |= (r.read(1)[0] << (8 * j))
        digests.append({"crc": crc, "defined": defined[i]})
    return digests


def read_pack_info(r: Reader) -> dict:
    """解析 PackInfo: PackPos, NumPackStreams, PackSizes"""
    pack_pos = r.read_number()
    num_pack_streams = r.read_number()

    # 找 Size 属性
    while True:
        pid = r.read_id()
        if pid == SEVEN_ZIP_END:
            break
        if pid == SEVEN_ZIP_SIZE:
            pack_sizes = [r.read_number() for _ in range(num_pack_streams)]
            break
        r.skip_data()
    else:
        pack_sizes = []

    # 跳过剩余属性直到 END
    while True:
        pid = r.read_id()
        if pid == SEVEN_ZIP_END:
            break
        if pid == SEVEN_ZIP_CRC:
            read_digests(r, num_pack_streams)
        else:
            r.skip_data()

    return {
        "pack_pos": pack_pos,
        "num_pack_streams": num_pack_streams,
        "pack_sizes": pack_sizes,
    }


def read_folder(r: Reader) -> dict:
    """解析一个 Folder：coders 列表"""
    num_coders = r.read_number()
    coders = []
    sum_in = 0
    sum_out = 0

    for _ in range(num_coders):
        main_byte = r.read(1)[0]
        if main_byte & 0xC0:
            raise ValueError("不支持的 coder flag")
        codec_id_size = main_byte & 0x0F
        codec_id = r.read(codec_id_size)

        num_in = 1
        num_out = 1
        if main_byte & 0x10:
            num_in = r.read_number()
            num_out = r.read_number()

        sum_in += num_in
        sum_out += num_out

        attributes = b""
        if main_byte & 0x20:
            prop_size = r.read_number()
            attributes = r.read(prop_size)

        coders.append({
            "codec_id": codec_id,
            "num_in": num_in,
            "num_out": num_out,
            "attributes": attributes,
        })

    # bindpairs（对齐 7z2john: number_bindpairs = sum_output - 1）
    num_bind_pairs = 0
    sum_packed = 1
    if sum_in != 1 or sum_out != 1:
        num_bind_pairs = sum_out - 1
        for _ in range(num_bind_pairs):
            r.read_number()  # InIndex
            r.read_number()  # OutIndex
        sum_packed = sum_in - num_bind_pairs
        if sum_packed != 1:
            for _ in range(sum_packed):
                r.read_number()  # PackedStreamIndex

    return {
        "num_coders": num_coders,
        "coders": coders,
        "num_bind_pairs": num_bind_pairs,
    }


def read_unpack_info(r: Reader) -> dict:
    """解析 UnpackInfo: folders + unpack sizes + digests"""
    # 找 Folder 属性 (0x0e)
    pid = r.read_id()
    if pid != b"\x0b":
        raise ValueError(f"期望 Folder 属性, 得到 {pid.hex()}")

    num_folders = r.read_number()
    external = r.read_number()

    folders = []
    for _ in range(num_folders):
        folders.append(read_folder(r))

    if external:
        r.read_number()  # data stream index (不处理)

    # 找 CodersUnpackSize 属性 (0x0f)
    pid = r.read_id()
    if pid != b"\x0c":
        raise ValueError(f"期望 CodersUnpackSize 属性, 得到 {pid.hex()}")

    unpack_sizes = []
    for folder in folders:
        for _ in range(folder["num_coders"]):
            unpack_sizes.append(r.read_number())

    # digests (0x0a, 可选)
    digests = []
    pid = r.read_id()
    if pid == SEVEN_ZIP_CRC:
        num_digests = r.read_number()
        digests = read_digests(r, num_digests)
        pid = r.read_id()

    if pid != SEVEN_ZIP_END:
        raise ValueError(f"UnpackInfo 尾部异常: {pid.hex()}")

    return {
        "folders": folders,
        "unpack_sizes": unpack_sizes,
        "digests": digests,
    }


def read_streams_info(r: Reader) -> dict:
    """解析 StreamsInfo: PackInfo + UnpackInfo + SubstreamsInfo"""
    pack_info = None
    unpack_info = None
    substreams_info = None

    while True:
        pid = r.read_id()
        if pid == SEVEN_ZIP_END:
            break
        if pid == b"\x06":  # kPackInfo
            pack_info = read_pack_info(r)
        elif pid == b"\x07":  # kUnpackInfo
            unpack_info = read_unpack_info(r)
        elif pid == b"\x08":  # kSubStreamsInfo
            # 简化：解析后跳到 END
            substreams_info = {}
            while True:
                pid2 = r.read_id()
                if pid2 == SEVEN_ZIP_END:
                    break
                elif pid2 == b"\x0a":  # Digests
                    num = r.read_number()
                    read_digests(r, num)
                else:
                    r.skip_data()
        else:
            r.skip_data()

    return {"pack_info": pack_info, "unpack_info": unpack_info,
            "substreams_info": substreams_info}


def parse_signature_header(data: bytes):
    """解析 32 字节签名头"""
    if len(data) < 32:
        raise ValueError("文件过短")
    if data[0:6] != SEVEN_ZIP_MAGIC:
        raise ValueError("不是有效的 7z 文件")
    next_offset = struct.unpack("<Q", data[12:20])[0]
    next_size = struct.unpack("<Q", data[20:28])[0]
    return next_offset, next_size


def has_encrypted_header(folder: dict) -> bool:
    """判断 folder 是否加密 header"""
    if folder["num_coders"] != 1:
        return False
    coder = folder["coders"][0]
    return coder["codec_id"] == SEVEN_ZIP_AES


def extract_hash(data: bytes) -> str:
    """
    从 7z 文件字节提取 $7z$ hash（hashcat mode 11600 格式）。
    返回 hash 字符串；失败抛 ValueError。
    """
    next_offset, next_size = parse_signature_header(data)

    # next header 从签名头之后偏移 next_offset
    header_start = 32 + next_offset
    if header_start + next_size > len(data):
        raise ValueError("next header 越界")

    r = Reader(data, header_start)
    pid = r.read_id()

    if pid == SEVEN_ZIP_HEADER:
        raise ValueError("7z 未加密 header（无密码保护或非传统加密）")
    if pid != SEVEN_ZIP_ENCODED_HEADER:
        raise ValueError(f"未知 header 类型: {pid.hex()}")

    # EncodedHeader 后直接是 StreamsInfo（无 NumFolders 前缀）
    streams_info = read_streams_info(r)

    # 从 unpack_info 取 folders
    unpack_info = streams_info["unpack_info"]
    if not unpack_info:
        raise ValueError("缺少 unpack_info")
    folders = unpack_info["folders"]

    pack_info = streams_info["pack_info"]
    unpack_info = streams_info["unpack_info"]
    if not pack_info or not unpack_info:
        raise ValueError("缺少 pack/unpack 信息")

    # 找第一个 AES coder
    aes_coder = None
    aes_folder = None
    for folder in folders:
        for coder in folder["coders"]:
            if coder["codec_id"] == SEVEN_ZIP_AES:
                aes_coder = coder
                aes_folder = folder
                break
        if aes_coder:
            break

    if aes_coder is None:
        raise ValueError("未找到 AES coder")

    # 定位加密数据位置：position_after_header(32) + pack_pos
    pack_pos = pack_info["pack_pos"]
    pack_sizes = pack_info["pack_sizes"]
    data_start = 32 + pack_pos
    data_len = pack_sizes[0] if pack_sizes else 0

    if data_start + data_len > len(data):
        raise ValueError("加密数据越界")

    encrypted_data = data[data_start:data_start + data_len]

    # unpack size
    unpack_sizes = unpack_info["unpack_sizes"]
    unpack_size = unpack_sizes[0] if unpack_sizes else data_len

    # digests: 从 unpack_info 找 CRC；没有则用签名头 next_header_crc
    # （7z 加密 header 的校验值，hashcat 用它验证解密结果）
    crc = 0
    for d in unpack_info.get("digests", []):
        if d["defined"]:
            crc = d["crc"]
            break
    if crc == 0:
        crc = struct.unpack("<I", data[28:32])[0]

    # AES 属性
    salt_len, salt_buf, iv_len, iv_buf, cycles = get_decoder_properties(aes_coder["attributes"])

    # 组装 hash: $7z$type$cycles$saltlen$salt$ivlen$iv$crc$datalen$unpacks$data
    # 注意: "$7z$" 已带结尾 $，后续字段用 $ 连接
    hash_parts = [
        "0", str(cycles), str(salt_len), salt_buf.hex(),
        str(iv_len), iv_buf.hex(), str(crc),
        str(data_len), str(unpack_size), encrypted_data.hex(),
    ]
    return "$7z$" + "$".join(hash_parts)


def sevenzip2john_file(path: str) -> str:
    """从文件提取 7z hash"""
    with open(path, "rb") as f:
        data = f.read()
    return extract_hash(data)


def main():
    if len(sys.argv) < 2:
        print("用法: python sevenzip2john.py <file.7z>", file=sys.stderr)
        sys.exit(1)
    try:
        h = sevenzip2john_file(sys.argv[1])
        print(h)
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
