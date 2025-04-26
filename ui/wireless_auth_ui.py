"""
区块链无线网络身份验证系统 - 图形用户界面
CSEC5615 云安全项目

这个程序提供了一个图形化界面，用于管理基于区块链的无线网络身份验证系统。
用户可以通过此界面创建网络、注册设备、管理权限，以及执行认证等操作。
"""

import os
import sys
import time
import uuid
import threading
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from tkinter.font import Font
import json
import traceback
from python.test_identity import IdentityChainClient

# 全局变量
client = None
devices = {}  # 存储设备信息
networks = {}  # 存储网络信息

# 颜色主题
COLORS = {
    "bg": "#f0f0f0",
    "primary": "#3498db",
    "secondary": "#2ecc71",
    "warning": "#e74c3c",
    "text": "#2c3e50",
    "light_text": "#7f8c8d",
    "card": "#ffffff"
}


class ScrollableFrame(ttk.Frame):
    """创建可滚动的框架"""

    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")


class LogConsole:
    """日志控制台组件"""

    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="操作日志", padding=10)
        self.text_area = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, width=50, height=10)
        self.text_area.pack(fill=tk.BOTH, expand=True)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def log(self, message, level="INFO"):
        """添加日志消息"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}\n"

        # 根据级别设置颜色
        tag = f"tag_{level.lower()}"
        self.text_area.tag_configure("tag_info", foreground="black")
        self.text_area.tag_configure("tag_success", foreground="green")
        self.text_area.tag_configure("tag_error", foreground="red")
        self.text_area.tag_configure("tag_warning", foreground="orange")

        self.text_area.insert(tk.END, formatted_message, tag)
        self.text_area.see(tk.END)  # 自动滚动到底部

    def info(self, message):
        self.log(message, "INFO")

    def success(self, message):
        self.log(message, "SUCCESS")

    def error(self, message):
        self.log(message, "ERROR")

    def warning(self, message):
        self.log(message, "WARNING")

    def clear(self):
        """清空日志"""
        self.text_area.delete(1.0, tk.END)


class BlockchainAuthApp:
    """区块链无线网络身份验证系统主应用"""

    def __init__(self, root):
        self.root = root
        self.root.title("区块链无线网络身份验证系统")
        self.root.geometry("1200x800")
        self.root.configure(bg=COLORS["bg"])

        self.setup_styles()
        self.create_widgets()
        self.load_saved_data()

    def setup_styles(self):
        """设置控件样式"""
        style = ttk.Style()
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"])
        style.configure("TButton", background=COLORS["primary"], foreground="black")
        style.configure("Secondary.TButton", background=COLORS["secondary"])
        style.configure("Warning.TButton", background=COLORS["warning"])

    # 在wireless_auth_ui.py中的BlockchainAuthApp类的create_widgets方法中添加用户标签页

    # 在此处修改原来的create_widgets方法，添加用户管理标签页
    def create_widgets(self):
        """创建界面控件"""
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建上方连接区域
        self.connection_frame = ttk.LabelFrame(self.main_frame, text="区块链连接", padding=10)
        self.connection_frame.pack(fill=tk.X, pady=10)

        # 网络选择
        ttk.Label(self.connection_frame, text="网络:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.network_var = tk.StringVar(value="localhost")
        network_combo = ttk.Combobox(self.connection_frame, textvariable=self.network_var,
                                     values=["localhost", "sepolia"])
        network_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # 连接按钮
        self.connect_btn = ttk.Button(self.connection_frame, text="连接", command=self.connect_blockchain)
        self.connect_btn.grid(row=0, column=2, padx=5, pady=5)

        # 状态显示
        ttk.Label(self.connection_frame, text="状态:").grid(row=0, column=3, padx=5, pady=5)
        self.status_var = tk.StringVar(value="未连接")
        ttk.Label(self.connection_frame, textvariable=self.status_var).grid(row=0, column=4, padx=5, pady=5)

        # 当前账户
        ttk.Label(self.connection_frame, text="当前账户:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.account_var = tk.StringVar(value="无")
        ttk.Label(self.connection_frame, textvariable=self.account_var).grid(row=1, column=1, columnspan=4, padx=5,
                                                                             pady=5, sticky=tk.W)

        # 创建标签页控件
        self.tab_control = ttk.Notebook(self.main_frame)

        # 创建各个标签页
        self.tab_users = ttk.Frame(self.tab_control)  # 新增用户管理标签页
        self.tab_networks = ttk.Frame(self.tab_control)
        self.tab_devices = ttk.Frame(self.tab_control)
        self.tab_auth = ttk.Frame(self.tab_control)
        self.tab_logs = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_users, text="用户管理")  # 添加用户管理标签页
        self.tab_control.add(self.tab_networks, text="网络管理")
        self.tab_control.add(self.tab_devices, text="设备管理")
        self.tab_control.add(self.tab_auth, text="认证管理")
        self.tab_control.add(self.tab_logs, text="审计日志")

        self.tab_control.pack(expand=1, fill="both")

        # 创建各标签页内容
        self.create_users_tab()  # 创建用户管理标签页
        self.create_networks_tab()
        self.create_devices_tab()
        self.create_auth_tab()
        self.create_logs_tab()

        # 创建日志控制台
        self.console = LogConsole(self.main_frame)
        self.console.info("应用已启动，请连接区块链网络")

    # 添加创建用户管理标签页的方法
    def create_users_tab(self):
        """创建用户管理标签页"""
        # 导入用户管理模块
        from ui.user_management_ui import UserManagementTab

        # 创建用户管理标签页
        self.user_mgmt_tab = UserManagementTab(
            self.tab_users,
            self.client,
            self.console,
            self.refresh_all  # 传入刷新所有数据的回调函数
        )

    # 添加一个刷新所有数据的方法
    def refresh_all(self):
        """刷新所有数据"""
        self.refresh_networks()
        self.refresh_devices()

        # 如果有用户管理标签页，也刷新它
        if hasattr(self, 'user_mgmt_tab'):
            self.user_mgmt_tab.refresh_user_info()
            self.user_mgmt_tab.refresh_user_devices()
            self.user_mgmt_tab.refresh_users_list()

    # 修改connect_blockchain方法，添加用户管理标签页的初始化
    def update_connection_status(self, success, message):
        """更新连接状态"""
        if success:
            self.status_var.set("已连接")
            self.account_var.set(message)
            self.console.success(f"成功连接到区块链网络，账户: {message}")

            # 更新认证标签页的下拉菜单
            self.update_device_network_dropdowns()

            # 初始化用户管理标签页
            if hasattr(self, 'user_mgmt_tab'):
                self.user_mgmt_tab.client = self.client
                self.user_mgmt_tab.refresh_user_info()
                self.user_mgmt_tab.refresh_users_list()
        else:
            self.status_var.set("连接失败")
            self.console.error(f"连接失败: {message}")

        # 重新启用连接按钮
        self.connect_btn.configure(state="normal")

    def create_networks_tab(self):
        """创建网络管理标签页"""
        # 左侧 - 网络列表
        left_frame = ttk.Frame(self.tab_networks, padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 网络列表标题
        ttk.Label(left_frame, text="我的网络", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)

        # 网络列表框架
        self.networks_list_frame = ScrollableFrame(left_frame)
        self.networks_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 刷新按钮
        refresh_btn = ttk.Button(left_frame, text="刷新网络列表", command=self.refresh_networks)
        refresh_btn.pack(fill=tk.X, pady=5)

        # 右侧 - 创建网络
        right_frame = ttk.LabelFrame(self.tab_networks, text="创建新网络", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10)

        # 网络名称
        ttk.Label(right_frame, text="网络名称:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.network_name_var = tk.StringVar()
        ttk.Entry(right_frame, textvariable=self.network_name_var, width=25).grid(row=0, column=1, padx=5, pady=5)

        # 创建网络按钮
        create_net_btn = ttk.Button(right_frame, text="创建网络", command=self.create_network)
        create_net_btn.grid(row=1, column=0, columnspan=2, padx=5, pady=10, sticky=tk.E)

    def create_devices_tab(self):
        """创建设备管理标签页"""
        # 左侧 - 设备列表
        left_frame = ttk.Frame(self.tab_devices, padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 设备列表标题
        ttk.Label(left_frame, text="我的设备", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)

        # 设备列表框架
        self.devices_list_frame = ScrollableFrame(left_frame)
        self.devices_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 刷新按钮
        refresh_btn = ttk.Button(left_frame, text="刷新设备列表", command=self.refresh_devices)
        refresh_btn.pack(fill=tk.X, pady=5)

        # 右侧 - 注册设备
        right_frame = ttk.LabelFrame(self.tab_devices, text="注册新设备", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10)

        # 设备名称
        ttk.Label(right_frame, text="设备名称:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.device_name_var = tk.StringVar()
        ttk.Entry(right_frame, textvariable=self.device_name_var, width=25).grid(row=0, column=1, padx=5, pady=5)

        # 设备类型
        ttk.Label(right_frame, text="设备类型:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.device_type_var = tk.StringVar(value="smartphone")
        device_types = ttk.Combobox(right_frame, textvariable=self.device_type_var,
                                    values=["smartphone", "laptop", "tablet", "iot_device", "smart_tv"])
        device_types.grid(row=1, column=1, padx=5, pady=5)

        # 元数据标签
        ttk.Label(right_frame, text="设备元数据:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.device_metadata_var = tk.StringVar()
        ttk.Entry(right_frame, textvariable=self.device_metadata_var, width=25).grid(row=2, column=1, padx=5, pady=5)

        # 注册设备按钮
        register_btn = ttk.Button(right_frame, text="注册设备", command=self.register_device)
        register_btn.grid(row=3, column=0, columnspan=2, padx=5, pady=10, sticky=tk.E)

    def create_auth_tab(self):
        """创建认证管理标签页"""
        # 左侧 - 选择设备和网络
        left_frame = ttk.Frame(self.tab_auth, padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 选择设备
        device_frame = ttk.LabelFrame(left_frame, text="选择设备", padding=10)
        device_frame.pack(fill=tk.X, pady=5)

        self.auth_device_var = tk.StringVar()
        self.auth_device_combo = ttk.Combobox(device_frame, textvariable=self.auth_device_var, width=40)
        self.auth_device_combo.pack(fill=tk.X, pady=5)

        # 选择网络
        network_frame = ttk.LabelFrame(left_frame, text="选择网络", padding=10)
        network_frame.pack(fill=tk.X, pady=5)

        self.auth_network_var = tk.StringVar()
        self.auth_network_combo = ttk.Combobox(network_frame, textvariable=self.auth_network_var, width=40)
        self.auth_network_combo.pack(fill=tk.X, pady=5)

        # 授权管理
        auth_frame = ttk.LabelFrame(left_frame, text="授权管理", padding=10)
        auth_frame.pack(fill=tk.X, pady=5)

        ttk.Button(auth_frame, text="授予访问权限", command=self.grant_access).pack(fill=tk.X, pady=2)
        ttk.Button(auth_frame, text="撤销访问权限", command=self.revoke_access).pack(fill=tk.X, pady=2)
        ttk.Button(auth_frame, text="检查访问权限", command=self.check_access).pack(fill=tk.X, pady=2)

        # 右侧 - 模拟认证
        right_frame = ttk.LabelFrame(self.tab_auth, text="模拟设备认证", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10)

        # 认证步骤框架
        self.auth_steps_frame = ScrollableFrame(right_frame)
        self.auth_steps_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 认证步骤标签
        ttk.Label(self.auth_steps_frame.scrollable_frame, text="认证步骤", font=("Arial", 12, "bold")).pack(anchor=tk.W,
                                                                                                            pady=5)

        # 步骤1: 生成挑战
        step1_frame = ttk.Frame(self.auth_steps_frame.scrollable_frame)
        step1_frame.pack(fill=tk.X, pady=5)
        ttk.Label(step1_frame, text="步骤1: 生成挑战").pack(side=tk.LEFT)
        ttk.Button(step1_frame, text="生成挑战", command=self.generate_challenge).pack(side=tk.RIGHT)

        # 挑战显示
        self.challenge_var = tk.StringVar()
        challenge_entry = ttk.Entry(self.auth_steps_frame.scrollable_frame, textvariable=self.challenge_var, width=50,
                                    state="readonly")
        challenge_entry.pack(fill=tk.X, pady=2)

        # 步骤2: 签名挑战
        step2_frame = ttk.Frame(self.auth_steps_frame.scrollable_frame)
        step2_frame.pack(fill=tk.X, pady=5)
        ttk.Label(step2_frame, text="步骤2: 设备签名挑战").pack(side=tk.LEFT)
        ttk.Button(step2_frame, text="模拟签名", command=self.sign_challenge).pack(side=tk.RIGHT)

        # 签名显示
        self.signature_var = tk.StringVar()
        signature_entry = ttk.Entry(self.auth_steps_frame.scrollable_frame, textvariable=self.signature_var, width=50,
                                    state="readonly")
        signature_entry.pack(fill=tk.X, pady=2)

        # 步骤3: 验证签名
        step3_frame = ttk.Frame(self.auth_steps_frame.scrollable_frame)
        step3_frame.pack(fill=tk.X, pady=5)
        ttk.Label(step3_frame, text="步骤3: 验证签名并颁发令牌").pack(side=tk.LEFT)
        ttk.Button(step3_frame, text="验证认证", command=self.verify_authentication).pack(side=tk.RIGHT)

        # 令牌显示
        ttk.Label(self.auth_steps_frame.scrollable_frame, text="访问令牌:").pack(anchor=tk.W, pady=2)
        self.token_var = tk.StringVar()
        token_entry = ttk.Entry(self.auth_steps_frame.scrollable_frame, textvariable=self.token_var, width=50,
                                state="readonly")
        token_entry.pack(fill=tk.X, pady=2)

        # 令牌验证
        token_frame = ttk.Frame(self.auth_steps_frame.scrollable_frame)
        token_frame.pack(fill=tk.X, pady=5)
        ttk.Label(token_frame, text="验证令牌有效性").pack(side=tk.LEFT)
        ttk.Button(token_frame, text="验证令牌", command=self.validate_token).pack(side=tk.RIGHT)

        # 令牌撤销
        revoke_frame = ttk.Frame(self.auth_steps_frame.scrollable_frame)
        revoke_frame.pack(fill=tk.X, pady=5)
        ttk.Label(revoke_frame, text="撤销令牌").pack(side=tk.LEFT)
        ttk.Button(revoke_frame, text="撤销令牌", command=self.revoke_token).pack(side=tk.RIGHT)

    def create_logs_tab(self):
        """创建审计日志标签页"""
        # 设备选择框架
        select_frame = ttk.Frame(self.tab_logs, padding=10)
        select_frame.pack(fill=tk.X)

        ttk.Label(select_frame, text="选择设备:").pack(side=tk.LEFT)
        self.log_device_var = tk.StringVar()
        self.log_device_combo = ttk.Combobox(select_frame, textvariable=self.log_device_var, width=40)
        self.log_device_combo.pack(side=tk.LEFT, padx=5)

        ttk.Button(select_frame, text="查询日志", command=self.fetch_auth_logs).pack(side=tk.LEFT, padx=5)

        # 日志列表框架
        log_frame = ttk.LabelFrame(self.tab_logs, text="认证日志记录", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建表格视图
        columns = ("序号", "时间", "验证者", "结果")
        self.log_table = ttk.Treeview(log_frame, columns=columns, show="headings")

        # 定义列标题
        for col in columns:
            self.log_table.heading(col, text=col)
            if col == "序号":
                self.log_table.column(col, width=50)
            elif col == "结果":
                self.log_table.column(col, width=80)
            else:
                self.log_table.column(col, width=150)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_table.yview)
        self.log_table.configure(yscroll=scrollbar.set)

        # 布局
        self.log_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def load_saved_data(self):
        """加载保存的数据"""
        # 尝试加载设备和网络数据
        try:
            if os.path.exists("blockchain_auth_data.json"):
                with open("blockchain_auth_data.json", "r") as f:
                    data = json.load(f)
                    if "devices" in data:
                        global devices
                        devices = data["devices"]
                    if "networks" in data:
                        global networks
                        networks = data["networks"]
                self.console.info("已加载保存的数据")
        except Exception as e:
            self.console.error(f"加载数据失败: {str(e)}")

    def save_data(self):
        """保存数据到本地文件"""
        try:
            data = {
                "devices": devices,
                "networks": networks
            }
            with open("blockchain_auth_data.json", "w") as f:
                json.dump(data, f, indent=2)
            self.console.info("数据已保存到本地")
        except Exception as e:
            self.console.error(f"保存数据失败: {str(e)}")

    def connect_blockchain(self):
        """连接到区块链网络"""
        try:
            network = self.network_var.get()
            self.console.info(f"正在连接到 {network} 网络...")

            # 禁用连接按钮防止重复点击
            self.connect_btn.configure(state="disabled")
            self.status_var.set("连接中...")

            # 在单独线程中执行连接操作，避免UI冻结
            def connect_thread():
                global client
                try:
                    client = IdentityChainClient(network=network)
                    self.root.after(0, self.update_connection_status, True, client.account.address)
                    self.root.after(0, self.refresh_devices)
                    self.root.after(0, self.refresh_networks)
                except Exception as e:
                    self.root.after(0, self.update_connection_status, False, str(e))

            threading.Thread(target=connect_thread).start()
        except Exception as e:
            self.console.error(f"连接失败: {str(e)}")
            self.update_connection_status(False, str(e))

    def update_connection_status(self, success, message):
        """更新连接状态"""
        if success:
            self.status_var.set("已连接")
            self.account_var.set(message)
            self.console.success(f"成功连接到区块链网络，账户: {message}")

            # 更新认证标签页的下拉菜单
            self.update_device_network_dropdowns()
        else:
            self.status_var.set("连接失败")
            self.console.error(f"连接失败: {message}")

        # 重新启用连接按钮
        self.connect_btn.configure(state="normal")

    def update_device_network_dropdowns(self):
        """更新设备和网络下拉菜单"""
        if not client:
            return

        # 更新设备下拉菜单
        device_list = []
        for did, device in devices.items():
            device_list.append(f"{device['name']} ({did[:10]}...)")

        self.auth_device_combo['values'] = device_list
        self.log_device_combo['values'] = device_list

        # 更新网络下拉菜单
        network_list = []
        for nid, network in networks.items():
            network_list.append(f"{network['name']} ({nid[:10]}...)")

        self.auth_network_combo['values'] = network_list

    def refresh_networks(self):
        """刷新网络列表"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        try:
            # 清空现有网络列表
            for widget in self.networks_list_frame.scrollable_frame.winfo_children():
                widget.destroy()

            self.console.info("正在获取网络列表...")

            # 获取用户的网络
            result = client.get_owner_networks()

            if result['success']:
                self.console.success(f"找到 {result['network_count']} 个网络")

                global networks
                networks = {}

                if result['network_count'] == 0:
                    ttk.Label(self.networks_list_frame.scrollable_frame,
                              text="没有找到网络，请创建一个新网络").pack(pady=10)
                    return

                # 创建网络卡片
                for i, network_id in enumerate(result['networks']):
                    network_frame = ttk.Frame(self.networks_list_frame.scrollable_frame, style="Card.TFrame")
                    network_frame.pack(fill=tk.X, pady=5)

                    # 获取网络详情（如果合约有相应方法）
                    network_name = f"网络 #{i + 1}"
                    try:
                        # 此处应有获取网络详情的方法，暂时使用ID代替
                        network_name = f"网络 #{i + 1} ({network_id[:10]}...)"
                    except:
                        pass

                    # 存储网络信息
                    networks[network_id] = {
                        "id": network_id,
                        "name": network_name
                    }

                    # 网络标题
                    ttk.Label(network_frame, text=network_name, font=("Arial", 11, "bold")).pack(anchor=tk.W)

                    # 网络ID
                    ttk.Label(network_frame, text=f"ID: {network_id}").pack(anchor=tk.W)

                    # 分隔线
                    ttk.Separator(network_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)

                # 更新认证标签页的网络下拉菜单
                self.update_device_network_dropdowns()

                # 保存数据
                self.save_data()
            else:
                self.console.error(f"获取网络列表失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"刷新网络列表时出错: {str(e)}")
            traceback.print_exc()

    def create_network(self):
        """创建新网络"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        network_name = self.network_name_var.get()
        if not network_name:
            messagebox.showwarning("警告", "请输入网络名称")
            return

        try:
            self.console.info(f"正在创建网络: {network_name}...")

            # 创建网络
            result = client.create_network(network_name)

            if result['success']:
                network_id = result['network_id_bytes32']
                self.console.success(f"网络创建成功: {network_name}")

                # 添加到网络字典
                global networks
                networks[network_id] = {
                    "id": network_id,
                    "name": network_name
                }

                # 刷新网络列表
                self.refresh_networks()

                # 清空输入框
                self.network_name_var.set("")

                # 保存数据
                self.save_data()
            else:
                self.console.error(f"创建网络失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"创建网络失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"创建网络时出错: {str(e)}")
            messagebox.showerror("错误", f"创建网络时出错: {str(e)}")
            traceback.print_exc()

    def refresh_devices(self):
        """刷新设备列表"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        try:
            # 清空现有设备列表
            for widget in self.devices_list_frame.scrollable_frame.winfo_children():
                widget.destroy()

            self.console.info("正在获取设备列表...")

            # 获取用户的设备
            result = client.get_owner_devices()

            if result['success']:
                self.console.success(f"找到 {result['device_count']} 个设备")

                global devices
                devices = {}

                if result['device_count'] == 0:
                    ttk.Label(self.devices_list_frame.scrollable_frame,
                              text="没有找到设备，请注册一个新设备").pack(pady=10)
                    return

                # 创建设备卡片
                for i, device_id in enumerate(result['devices']):
                    device_frame = ttk.Frame(self.devices_list_frame.scrollable_frame, style="Card.TFrame")
                    device_frame.pack(fill=tk.X, pady=5)

                    # 获取设备详情
                    device_info = client.get_device_info(device_id)

                    if device_info['success']:
                        # 存储设备信息
                        devices[device_id] = {
                            "id": device_id,
                            "name": device_info['name'],
                            "device_type": device_info['device_type'],
                            "public_key": device_info['public_key'],
                            "is_active": device_info['is_active'],
                            "registered_at": device_info['registered_at'],
                            "metadata": device_info['metadata']
                        }

                        # 显示设备信息
                        self.create_device_card(device_frame, device_info, device_id)
                    else:
                        ttk.Label(device_frame, text=f"设备 #{i + 1} ({device_id[:10]}...)").pack(anchor=tk.W)
                        ttk.Label(device_frame, text="无法获取设备详情").pack(anchor=tk.W)

                # 更新认证标签页的设备下拉菜单
                self.update_device_network_dropdowns()

                # 保存数据
                self.save_data()
            else:
                self.console.error(f"获取设备列表失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"刷新设备列表时出错: {str(e)}")
            traceback.print_exc()

    def create_device_card(self, parent_frame, device_info, device_id):
        """创建设备信息卡片"""
        # 设备标题
        header_frame = ttk.Frame(parent_frame)
        header_frame.pack(fill=tk.X)

        ttk.Label(header_frame, text=device_info['name'], font=("Arial", 11, "bold")).pack(side=tk.LEFT)

        # 设备状态标签
        status_text = "活跃" if device_info['is_active'] else "已停用"
        status_label = ttk.Label(header_frame, text=status_text)
        status_label.pack(side=tk.RIGHT)

        # 设备类型和ID
        ttk.Label(parent_frame, text=f"类型: {device_info['device_type']}").pack(anchor=tk.W)
        ttk.Label(parent_frame, text=f"ID: {device_id}").pack(anchor=tk.W)

        # 注册时间
        reg_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(device_info['registered_at']))
        ttk.Label(parent_frame, text=f"注册时间: {reg_time}").pack(anchor=tk.W)

        # 操作按钮框架
        btn_frame = ttk.Frame(parent_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        # 更新信息按钮
        update_btn = ttk.Button(
            btn_frame,
            text="更新信息",
            command=lambda did=device_id: self.show_update_device_dialog(did)
        )
        update_btn.pack(side=tk.LEFT, padx=2)

        # 停用/激活按钮
        if device_info['is_active']:
            deactivate_btn = ttk.Button(
                btn_frame,
                text="停用设备",
                command=lambda did=device_id: self.deactivate_device(did)
            )
            deactivate_btn.pack(side=tk.LEFT, padx=2)

        # 分隔线
        ttk.Separator(parent_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)

    def show_update_device_dialog(self, device_id):
        """显示更新设备信息对话框"""
        if device_id not in devices:
            messagebox.showwarning("警告", "找不到设备信息")
            return

        device = devices[device_id]

        # 创建对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("更新设备信息")
        dialog.geometry("400x200")
        dialog.transient(self.root)  # 设置为主窗口的子窗口
        dialog.grab_set()  # 模态窗口

        # 设备名称
        ttk.Label(dialog, text="设备名称:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        name_var = tk.StringVar(value=device['name'])
        ttk.Entry(dialog, textvariable=name_var, width=30).grid(row=0, column=1, padx=10, pady=10)

        # 元数据
        ttk.Label(dialog, text="设备元数据:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        metadata_var = tk.StringVar(value=device['metadata'])
        ttk.Entry(dialog, textvariable=metadata_var, width=30).grid(row=1, column=1, padx=10, pady=10)

        # 按钮框架
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=20)

        # 取消按钮
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)

        # 确认按钮
        ttk.Button(
            btn_frame,
            text="更新",
            command=lambda: self.update_device_info(device_id, name_var.get(), metadata_var.get(), dialog)
        ).pack(side=tk.RIGHT, padx=10)

    def update_device_info(self, device_id, name, metadata, dialog):
        """更新设备信息"""
        if not client:
            messagebox.showwarning("警告", "区块链连接已断开")
            return

        try:
            self.console.info(f"正在更新设备信息: {name}...")

            # 调用合约更新设备信息
            result = client.update_device_info(device_id, name, metadata)

            if result['success']:
                self.console.success(f"设备信息更新成功: {name}")

                # 更新本地设备信息
                devices[device_id]['name'] = name
                devices[device_id]['metadata'] = metadata

                # 刷新设备列表
                self.refresh_devices()

                # 关闭对话框
                dialog.destroy()

                # 保存数据
                self.save_data()
            else:
                self.console.error(f"更新设备信息失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"更新设备信息失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"更新设备信息时出错: {str(e)}")
            messagebox.showerror("错误", f"更新设备信息时出错: {str(e)}")
            traceback.print_exc()

    def deactivate_device(self, device_id):
        """停用设备"""
        if not client:
            messagebox.showwarning("警告", "区块链连接已断开")
            return

        if messagebox.askyesno("确认", "确定要停用此设备吗？停用后将无法使用此设备进行认证。"):
            try:
                self.console.info(f"正在停用设备: {devices[device_id]['name']}...")

                # 调用合约停用设备
                result = client.deactivate_device(device_id)

                if result['success']:
                    self.console.success(f"设备已停用: {devices[device_id]['name']}")

                    # 更新本地设备信息
                    devices[device_id]['is_active'] = False

                    # 刷新设备列表
                    self.refresh_devices()

                    # 保存数据
                    self.save_data()
                else:
                    self.console.error(f"停用设备失败: {result.get('error', '未知错误')}")
                    messagebox.showerror("错误", f"停用设备失败: {result.get('error', '未知错误')}")
            except Exception as e:
                self.console.error(f"停用设备时出错: {str(e)}")
                messagebox.showerror("错误", f"停用设备时出错: {str(e)}")
                traceback.print_exc()

    def register_device(self):
        """注册新设备"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        device_name = self.device_name_var.get()
        device_type = self.device_type_var.get()
        metadata = self.device_metadata_var.get()

        if not device_name:
            messagebox.showwarning("警告", "请输入设备名称")
            return

        try:
            self.console.info(f"正在注册设备: {device_name}...")

            # 创建设备标识
            did_info = client.create_did(device_type)

            # 生成密钥对
            keys = client.generate_keys()

            # 注册设备
            result = client.register_device(
                device_type,
                did_info,
                keys,
                device_name,
                metadata
            )

            if result['success']:
                self.console.success(f"设备注册成功: {device_name}")

                # 清空输入框
                self.device_name_var.set("")
                self.device_metadata_var.set("")

                # 刷新设备列表
                self.refresh_devices()

                # 保存密钥信息
                did_bytes32 = did_info['did_bytes32']
                if did_bytes32 in devices:
                    devices[did_bytes32]['private_key'] = keys['private_key']
                    devices[did_bytes32]['public_key'] = keys['public_key']

                # 保存数据
                self.save_data()
            else:
                self.console.error(f"注册设备失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"注册设备失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"注册设备时出错: {str(e)}")
            messagebox.showerror("错误", f"注册设备时出错: {str(e)}")
            traceback.print_exc()

    def get_selected_device_id(self):
        """获取选中的设备ID"""
        device_str = self.auth_device_var.get()
        if not device_str:
            return None

        # 从字符串中提取设备ID
        for did, device in devices.items():
            if device_str.startswith(device['name']):
                return did

        return None

    def get_selected_network_id(self):
        """获取选中的网络ID"""
        network_str = self.auth_network_var.get()
        if not network_str:
            return None

        # 从字符串中提取网络ID
        for nid, network in networks.items():
            if network_str.startswith(network['name']):
                return nid

        return None

    def grant_access(self):
        """授予设备访问网络的权限"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        device_id = self.get_selected_device_id()
        network_id = self.get_selected_network_id()

        if not device_id:
            messagebox.showwarning("警告", "请选择设备")
            return

        if not network_id:
            messagebox.showwarning("警告", "请选择网络")
            return

        try:
            device_name = devices[device_id]['name']
            network_name = networks[network_id]['name']

            self.console.info(f"正在授予设备 {device_name} 访问网络 {network_name} 的权限...")

            # 授予权限
            result = client.grant_access(device_id, network_id)

            if result['success']:
                self.console.success(f"已授予设备 {device_name} 访问网络 {network_name} 的权限")
                messagebox.showinfo("成功", f"已授予设备访问权限")
            else:
                self.console.error(f"授予权限失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"授予权限失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"授予权限时出错: {str(e)}")
            messagebox.showerror("错误", f"授予权限时出错: {str(e)}")
            traceback.print_exc()

    def revoke_access(self):
        """撤销设备访问网络的权限"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        device_id = self.get_selected_device_id()
        network_id = self.get_selected_network_id()

        if not device_id:
            messagebox.showwarning("警告", "请选择设备")
            return

        if not network_id:
            messagebox.showwarning("警告", "请选择网络")
            return

        try:
            device_name = devices[device_id]['name']
            network_name = networks[network_id]['name']

            self.console.info(f"正在撤销设备 {device_name} 访问网络 {network_name} 的权限...")

            # 撤销权限
            result = client.revoke_access(device_id, network_id)

            if result['success']:
                self.console.success(f"已撤销设备 {device_name} 访问网络 {network_name} 的权限")
                messagebox.showinfo("成功", f"已撤销设备访问权限")
            else:
                self.console.error(f"撤销权限失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"撤销权限失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"撤销权限时出错: {str(e)}")
            messagebox.showerror("错误", f"撤销权限时出错: {str(e)}")
            traceback.print_exc()

    def check_access(self):
        """检查设备是否有权访问网络"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        device_id = self.get_selected_device_id()
        network_id = self.get_selected_network_id()

        if not device_id:
            messagebox.showwarning("警告", "请选择设备")
            return

        if not network_id:
            messagebox.showwarning("警告", "请选择网络")
            return

        try:
            device_name = devices[device_id]['name']
            network_name = networks[network_id]['name']

            self.console.info(f"正在检查设备 {device_name} 访问网络 {network_name} 的权限...")

            # 检查权限
            result = client.check_access(device_id, network_id)

            if result['success']:
                if result['has_access']:
                    self.console.success(f"设备 {device_name} 有权访问网络 {network_name}")
                    messagebox.showinfo("访问权限", f"设备 {device_name} 有权访问网络 {network_name}")
                else:
                    self.console.warning(f"设备 {device_name} 没有权限访问网络 {network_name}")
                    messagebox.showwarning("访问权限", f"设备 {device_name} 没有权限访问网络 {network_name}")
            else:
                self.console.error(f"检查权限失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"检查权限失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"检查权限时出错: {str(e)}")
            messagebox.showerror("错误", f"检查权限时出错: {str(e)}")
            traceback.print_exc()

    def generate_challenge(self):
        """生成认证挑战"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        device_id = self.get_selected_device_id()
        network_id = self.get_selected_network_id()

        if not device_id:
            messagebox.showwarning("警告", "请选择设备")
            return

        if not network_id:
            messagebox.showwarning("警告", "请选择网络")
            return

        try:
            device_name = devices[device_id]['name']
            network_name = networks[network_id]['name']

            self.console.info(f"正在为设备 {device_name} 和网络 {network_name} 生成认证挑战...")

            # 生成挑战
            result = client.generate_auth_challenge(device_id, network_id)

            if result['success']:
                challenge = result['challenge']
                self.challenge_var.set(challenge)
                self.console.success(f"挑战生成成功")

                # 清空之前的签名和令牌
                self.signature_var.set("")
                self.token_var.set("")
            else:
                self.console.error(f"生成挑战失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"生成挑战失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"生成挑战时出错: {str(e)}")
            messagebox.showerror("错误", f"生成挑战时出错: {str(e)}")
            traceback.print_exc()

    def sign_challenge(self):
        """模拟设备签名挑战"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        device_id = self.get_selected_device_id()
        challenge = self.challenge_var.get()

        if not device_id:
            messagebox.showwarning("警告", "请选择设备")
            return

        if not challenge:
            messagebox.showwarning("警告", "请先生成挑战")
            return

        try:
            device_name = devices[device_id]['name']

            # 检查是否有私钥
            if 'private_key' not in devices[device_id]:
                self.console.error(f"找不到设备 {device_name} 的私钥")
                messagebox.showerror("错误", f"找不到设备的私钥，请重新注册设备")
                return

            private_key = devices[device_id]['private_key']

            self.console.info(f"正在使用设备 {device_name} 的私钥签名挑战...")

            # 签名挑战
            signature = client.sign_challenge(private_key, device_id, challenge)

            if signature:
                self.signature_var.set(signature)
                self.console.success(f"挑战签名成功")
            else:
                self.console.error("签名失败")
                messagebox.showerror("错误", "签名失败")
        except Exception as e:
            self.console.error(f"签名挑战时出错: {str(e)}")
            messagebox.showerror("错误", f"签名挑战时出错: {str(e)}")
            traceback.print_exc()

    def verify_authentication(self):
        """验证设备并获取访问令牌"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        device_id = self.get_selected_device_id()
        network_id = self.get_selected_network_id()
        challenge = self.challenge_var.get()
        signature = self.signature_var.get()

        if not device_id or not network_id:
            messagebox.showwarning("警告", "请选择设备和网络")
            return

        if not challenge:
            messagebox.showwarning("警告", "请先生成挑战")
            return

        if not signature:
            messagebox.showwarning("警告", "请先签名挑战")
            return

        try:
            device_name = devices[device_id]['name']
            network_name = networks[network_id]['name']

            self.console.info(f"正在验证设备 {device_name} 对网络 {network_name} 的认证...")

            # 验证认证
            result = client.authenticate(device_id, network_id, challenge, signature)

            if result['success']:
                token_id = result['token_id']
                self.token_var.set(token_id)
                self.console.success(f"认证成功，获得访问令牌: {token_id[:20]}...")
                messagebox.showinfo("认证成功", "设备认证成功，已获得访问令牌")
            else:
                self.console.error(f"认证失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"认证失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"认证时出错: {str(e)}")
            messagebox.showerror("错误", f"认证时出错: {str(e)}")
            traceback.print_exc()

    def validate_token(self):
        """验证令牌是否有效"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        token_id = self.token_var.get()

        if not token_id:
            messagebox.showwarning("警告", "请先获取访问令牌")
            return

        try:
            self.console.info(f"正在验证令牌: {token_id[:20]}...")

            # 验证令牌
            result = client.validate_token(token_id)

            if result['valid']:
                self.console.success("令牌有效")
                messagebox.showinfo("令牌状态", "令牌有效")
            else:
                self.console.warning("令牌无效")
                messagebox.showwarning("令牌状态", "令牌无效")
        except Exception as e:
            self.console.error(f"验证令牌时出错: {str(e)}")
            messagebox.showerror("错误", f"验证令牌时出错: {str(e)}")
            traceback.print_exc()

    def revoke_token(self):
        """撤销访问令牌"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        token_id = self.token_var.get()

        if not token_id:
            messagebox.showwarning("警告", "请先获取访问令牌")
            return

        if messagebox.askyesno("确认", "确定要撤销此令牌吗？撤销后将无法使用此令牌进行认证。"):
            try:
                self.console.info(f"正在撤销令牌: {token_id[:20]}...")

                # 撤销令牌
                result = client.revoke_token(token_id)

                if result['success']:
                    self.console.success("令牌已撤销")
                    messagebox.showinfo("成功", "令牌已成功撤销")

                    # 清空令牌显示
                    self.token_var.set("")
                else:
                    self.console.error(f"撤销令牌失败: {result.get('error', '未知错误')}")
                    messagebox.showerror("错误", f"撤销令牌失败: {result.get('error', '未知错误')}")
            except Exception as e:
                self.console.error(f"撤销令牌时出错: {str(e)}")
                messagebox.showerror("错误", f"撤销令牌时出错: {str(e)}")
                traceback.print_exc()

    def fetch_auth_logs(self):
        """获取设备的认证日志"""
        if not client:
            self.console.warning("请先连接到区块链网络")
            return

        # 获取选中的设备
        device_str = self.log_device_var.get()
        device_id = None

        # 从字符串中提取设备ID
        for did, device in devices.items():
            if device_str.startswith(device['name']):
                device_id = did
                break

        if not device_id:
            messagebox.showwarning("警告", "请选择设备")
            return

        try:
            device_name = devices[device_id]['name']

            self.console.info(f"正在获取设备 {device_name} 的认证日志...")

            # 清空现有日志
            for item in self.log_table.get_children():
                self.log_table.delete(item)

            # 获取认证日志
            result = client.get_auth_logs(device_id)

            if result['success']:
                log_count = result['log_count']
                logs = result['logs']

                self.console.success(f"找到 {log_count} 条认证日志")

                if log_count == 0:
                    messagebox.showinfo("信息", "没有找到认证日志")
                    return

                # 添加日志到表格
                for i, log in enumerate(logs):
                    # 格式化时间
                    log_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(log['timestamp']))

                    # 格式化结果
                    result_text = "成功" if log['success'] else "失败"

                    # 添加到表格
                    self.log_table.insert("", "end",
                                          values=(i + 1, log_time, log['verifier'][:15] + "...", result_text))
            else:
                self.console.error(f"获取认证日志失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"获取认证日志失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"获取认证日志时出错: {str(e)}")
            messagebox.showerror("错误", f"获取认证日志时出错: {str(e)}")
            traceback.print_exc()


def main():
    """主函数"""
    root = tk.Tk()
    app = BlockchainAuthApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()