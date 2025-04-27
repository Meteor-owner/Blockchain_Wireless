"""
区块链无线网络身份验证系统 - 主界面
"""

import os
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import threading
import hashlib

# 设置样式颜色
COLORS = {
    "primary": "#3498db",  # 主色调 - 蓝色
    "secondary": "#2ecc71",  # 次要色调 - 绿色
    "accent": "#e74c3c",  # 强调色 - 红色
    "bg_light": "#f8f9fa",  # 浅色背景
    "bg_dark": "#343a40",  # 深色背景
    "text_light": "#f8f9fa",  # 浅色文字
    "text_dark": "#343a40",  # 深色文字
    "border": "#dee2e6"  # 边框颜色
}


class MainWindow(tk.Tk):
    """主界面窗口"""

    def __init__(self, user_address, user_role, client=None):
        super().__init__()

        # 用户信息
        self.user_address = user_address
        self.user_role = user_role  # SYSTEM_ADMIN, NETWORK_ADMIN, USER
        self.client = client

        # 用户数据
        self.user_name = "Unknown User"
        self.user_devices = []
        self.user_networks = []

        # 窗口设置
        self.title("区块链无线网络身份验证系统")
        self.geometry("1200x800")
        self.minsize(1000, 700)

        # 创建样式
        self.create_styles()

        # 创建主布局
        self.create_layout()

        # 加载用户数据
        self.load_user_data()

    def create_styles(self):
        """创建自定义样式"""
        style = ttk.Style()

        # 配置主题颜色
        style.configure("TFrame", background=COLORS["bg_light"])
        style.configure("TLabel", background=COLORS["bg_light"], foreground=COLORS["text_dark"])
        style.configure("TButton", background=COLORS["primary"], foreground=COLORS["text_light"])

        # 侧边栏样式
        style.configure("Sidebar.TFrame", background=COLORS["bg_dark"])
        style.configure("Sidebar.TLabel", background=COLORS["bg_dark"], foreground=COLORS["text_light"])
        style.configure("Sidebar.TButton", background=COLORS["bg_dark"], foreground=COLORS["text_light"])

        # 内容区样式
        style.configure("Content.TFrame", background=COLORS["bg_light"])

        # 卡片样式
        style.configure("Card.TFrame", background="white", relief="raised", borderwidth=1)

        # 标题样式
        style.configure("Title.TLabel", font=("Arial", 18, "bold"), background=COLORS["bg_light"],
                        foreground=COLORS["primary"])
        style.configure("Subtitle.TLabel", font=("Arial", 14), background=COLORS["bg_light"],
                        foreground=COLORS["text_dark"])

        # 状态栏样式
        style.configure("Statusbar.TFrame", background=COLORS["bg_dark"])
        style.configure("Statusbar.TLabel", background=COLORS["bg_dark"], foreground=COLORS["text_light"])

        # 表格样式
        style.configure("Treeview", font=("Arial", 10))
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))

    def create_layout(self):
        """创建主界面布局"""
        # 创建主容器
        self.main_container = ttk.Frame(self)
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # 创建顶部导航栏
        self.create_topbar()

        # 创建中间内容区域
        self.create_content_area()

        # 创建底部状态栏
        self.create_statusbar()

        # 默认显示控制面板
        self.show_dashboard()

    def create_topbar(self):
        """创建顶部导航栏"""
        # 顶部导航栏框架
        self.topbar = ttk.Frame(self.main_container, style="Sidebar.TFrame", height=50)
        self.topbar.pack(fill=tk.X, side=tk.TOP)

        # 系统标题
        title_label = ttk.Label(self.topbar, text="区块链无线网络身份验证系统", style="Sidebar.TLabel",
                                font=("Arial", 14, "bold"))
        title_label.pack(side=tk.LEFT, padx=20, pady=10)

        # 用户信息显示
        self.user_info_var = tk.StringVar(value=f"用户: {self.user_address[:10]}... | 角色: {self.user_role}")
        user_info_label = ttk.Label(self.topbar, textvariable=self.user_info_var, style="Sidebar.TLabel")
        user_info_label.pack(side=tk.RIGHT, padx=20, pady=10)

        # 区块链连接状态
        self.connection_var = tk.StringVar(value="已连接")
        connection_label = ttk.Label(self.topbar, textvariable=self.connection_var, style="Sidebar.TLabel")
        connection_label.pack(side=tk.RIGHT, padx=20, pady=10)

        # 登出按钮
        logout_btn = ttk.Button(self.topbar, text="登出", command=self.logout)
        logout_btn.pack(side=tk.RIGHT, padx=10, pady=10)

    def create_content_area(self):
        """创建内容区域"""
        # 内容区容器
        self.content_container = ttk.Frame(self.main_container, style="TFrame")
        self.content_container.pack(fill=tk.BOTH, expand=True)

        # 侧边导航栏
        self.sidebar = ttk.Frame(self.content_container, style="Sidebar.TFrame", width=200)
        self.sidebar.pack(fill=tk.Y, side=tk.LEFT)

        # 固定侧边栏宽度
        self.sidebar.pack_propagate(False)

        # 主内容区域
        self.main_content = ttk.Frame(self.content_container, style="Content.TFrame")
        self.main_content.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)

        # 创建侧边栏菜单
        self.create_sidebar_menu()

    def create_statusbar(self):
        """创建底部状态栏"""
        self.statusbar = ttk.Frame(self.main_container, style="Statusbar.TFrame", height=25)
        self.statusbar.pack(fill=tk.X, side=tk.BOTTOM)

        # 版本信息
        version_label = ttk.Label(self.statusbar, text="版本: 1.0.0", style="Statusbar.TLabel")
        version_label.pack(side=tk.LEFT, padx=10)

        # 区块信息
        self.block_info_var = tk.StringVar(value="区块高度: 未知")
        block_info_label = ttk.Label(self.statusbar, textvariable=self.block_info_var, style="Statusbar.TLabel")
        block_info_label.pack(side=tk.RIGHT, padx=10)

        # 时间信息
        self.time_var = tk.StringVar(value=time.strftime("%Y-%m-%d %H:%M:%S"))
        time_label = ttk.Label(self.statusbar, textvariable=self.time_var, style="Statusbar.TLabel")
        time_label.pack(side=tk.RIGHT, padx=10)

        # 启动时钟更新
        self.update_clock()

    def update_clock(self):
        """更新时钟"""
        self.time_var.set(time.strftime("%Y-%m-%d %H:%M:%S"))
        self.after(1000, self.update_clock)

    def create_sidebar_menu(self):
        """创建侧边栏菜单"""
        # 创建菜单项容器
        menu_frame = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        menu_frame.pack(fill=tk.X, padx=10, pady=20)

        # 控制面板按钮
        dashboard_btn = ttk.Button(
            menu_frame,
            text="控制面板",
            command=self.show_dashboard,
            style="Sidebar.TButton"
        )
        dashboard_btn.pack(fill=tk.X, pady=5)

        # 用户管理按钮 (仅管理员可见)
        if self.user_role in ["SYSTEM_ADMIN", "NETWORK_ADMIN"]:
            user_mgmt_btn = ttk.Button(
                menu_frame,
                text="用户管理",
                command=self.show_user_management,
                style="Sidebar.TButton"
            )
            user_mgmt_btn.pack(fill=tk.X, pady=5)

        # 设备管理按钮
        device_mgmt_btn = ttk.Button(
            menu_frame,
            text="设备管理",
            command=self.show_device_management,
            style="Sidebar.TButton"
        )
        device_mgmt_btn.pack(fill=tk.X, pady=5)

        # 网络管理按钮
        network_mgmt_btn = ttk.Button(
            menu_frame,
            text="网络管理",
            command=self.show_network_management,
            style="Sidebar.TButton"
        )
        network_mgmt_btn.pack(fill=tk.X, pady=5)

        # 认证管理按钮
        auth_mgmt_btn = ttk.Button(
            menu_frame,
            text="认证管理",
            command=self.show_auth_management,
            style="Sidebar.TButton"
        )
        auth_mgmt_btn.pack(fill=tk.X, pady=5)

        # 审计日志按钮
        audit_log_btn = ttk.Button(
            menu_frame,
            text="审计日志",
            command=self.show_audit_logs,
            style="Sidebar.TButton"
        )
        audit_log_btn.pack(fill=tk.X, pady=5)

        # 设置按钮
        settings_btn = ttk.Button(
            menu_frame,
            text="设置",
            command=self.show_settings,
            style="Sidebar.TButton"
        )
        settings_btn.pack(fill=tk.X, pady=5)

    def load_user_data(self):
        """加载用户数据"""

        #TODO 实际应用中应从区块链获取数据
        # 这里使用模拟数据

        # 模拟获取用户信息
        def simulate_data_loading():
            # 模拟加载延迟
            time.sleep(1.5)

            # 模拟用户数据
            user_data = {
                "name": "Test User",
                "email": "test@example.com",
                "registered_at": time.time() - 3600 * 24 * 7,  # 7天前
                "device_count": 3,
                "network_count": 2
            }

            # 模拟设备数据
            devices_data = [
                {
                    "did": f"did:identity-chain:{hashlib.sha256(f'device1{self.user_address}'.encode()).hexdigest()}",
                    "name": "我的笔记本电脑",
                    "device_type": "laptop",
                    "registered_at": time.time() - 3600 * 24 * 5,
                    "is_active": True
                },
                {
                    "did": f"did:identity-chain:{hashlib.sha256(f'device2{self.user_address}'.encode()).hexdigest()}",
                    "name": "我的智能手机",
                    "device_type": "smartphone",
                    "registered_at": time.time() - 3600 * 24 * 3,
                    "is_active": True
                },
                {
                    "did": f"did:identity-chain:{hashlib.sha256(f'device3{self.user_address}'.encode()).hexdigest()}",
                    "name": "办公室平板",
                    "device_type": "tablet",
                    "registered_at": time.time() - 3600 * 24,
                    "is_active": False
                }
            ]

            # 模拟网络数据
            networks_data = [
                {
                    "networkId": f"net:{hashlib.sha256(f'network1{self.user_address}'.encode()).hexdigest()}",
                    "name": "家庭网络",
                    "created_at": time.time() - 3600 * 24 * 6,
                    "is_active": True,
                    "device_count": 2
                },
                {
                    "networkId": f"net:{hashlib.sha256(f'network2{self.user_address}'.encode()).hexdigest()}",
                    "name": "办公室网络",
                    "created_at": time.time() - 3600 * 24 * 2,
                    "is_active": True,
                    "device_count": 1
                }
            ]

            # 更新UI (在主线程中)
            self.after(0, lambda: self._update_user_data(user_data, devices_data, networks_data))

        # 启动数据加载线程
        threading.Thread(target=simulate_data_loading).start()

    def _update_user_data(self, user_data, devices_data, networks_data):
        """更新用户数据（在主线程中调用）"""
        self.user_name = user_data["name"]
        self.user_info_var.set(f"用户: {self.user_name} | 角色: {self.user_role}")

        self.user_devices = devices_data
        self.user_networks = networks_data

        # 刷新当前显示的页面
        current_page = self.main_content.winfo_children()
        if current_page and hasattr(current_page[0], "refresh"):
            current_page[0].refresh()

    def clear_main_content(self):
        """清空主内容区域"""
        for widget in self.main_content.winfo_children():
            widget.destroy()

    def show_dashboard(self):
        """显示控制面板"""
        self.clear_main_content()

        # 创建仪表板面板
        dashboard = DashboardPanel(self.main_content, self)
        dashboard.pack(fill=tk.BOTH, expand=True)

    def show_user_management(self):
        """显示用户管理面板"""
        self.clear_main_content()

        # 创建用户管理面板
        user_mgmt = UserManagementPanel(self.main_content, self)
        user_mgmt.pack(fill=tk.BOTH, expand=True)

    def show_device_management(self):
        """显示设备管理面板"""
        self.clear_main_content()

        # 创建设备管理面板
        device_mgmt = DeviceManagementPanel(self.main_content, self)
        device_mgmt.pack(fill=tk.BOTH, expand=True)

    def show_network_management(self):
        """显示网络管理面板"""
        self.clear_main_content()

        # 创建网络管理面板
        network_mgmt = NetworkManagementPanel(self.main_content, self)
        network_mgmt.pack(fill=tk.BOTH, expand=True)

    def show_auth_management(self):
        """显示认证管理面板"""
        self.clear_main_content()

        # 创建认证管理面板
        auth_mgmt = AuthManagementPanel(self.main_content, self)
        auth_mgmt.pack(fill=tk.BOTH, expand=True)

    def show_audit_logs(self):
        """显示审计日志面板"""
        self.clear_main_content()

        # 创建审计日志面板
        audit_logs = AuditLogsPanel(self.main_content, self)
        audit_logs.pack(fill=tk.BOTH, expand=True)

    def show_settings(self):
        """显示设置面板"""
        self.clear_main_content()

        # 创建设置面板
        settings = SettingsPanel(self.main_content, self)
        settings.pack(fill=tk.BOTH, expand=True)

    def logout(self):
        """注销登录"""
        if messagebox.askyesno("确认登出", "您确定要退出登录吗?"):
            # 清除会话
            try:
                if os.path.exists("session.json"):
                    os.remove("session.json")
            except:
                pass

            # 关闭当前窗口
            self.destroy()

            # 启动登录界面
            # 在实际项目中，应该导入登录界面模块并启动
            # 这里仅作为示例
            messagebox.showinfo("已登出", "您已成功登出系统。请重新启动应用程序以登录。")


class BasePanel(ttk.Frame):
    """基础面板类"""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.parent = parent
        self.controller = controller

        # 创建基本布局
        self.create_base_layout()

        # 创建内容
        self.create_widgets()

    def create_base_layout(self):
        """创建基本布局"""
        # 标题区域
        self.title_frame = ttk.Frame(self)
        self.title_frame.pack(fill=tk.X, padx=20, pady=10)

        # 内容区域
        self.content_frame = ttk.Frame(self)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    def create_widgets(self):
        """创建具体内容，子类需重写此方法"""
        pass

    def refresh(self):
        """刷新数据，子类可重写此方法"""
        pass


class DashboardPanel(BasePanel):
    """控制面板"""

    def create_widgets(self):
        # 设置标题
        ttk.Label(self.title_frame, text="控制面板", style="Title.TLabel").pack(anchor=tk.W)

        # 创建卡片网格
        self.cards_frame = ttk.Frame(self.content_frame)
        self.cards_frame.pack(fill=tk.BOTH, expand=True)

        # 配置网格
        self.cards_frame.columnconfigure(0, weight=1)
        self.cards_frame.columnconfigure(1, weight=1)
        self.cards_frame.rowconfigure(0, weight=1)
        self.cards_frame.rowconfigure(1, weight=1)

        # 创建用户信息卡片
        self.create_user_info_card()

        # 创建设备概览卡片
        self.create_device_overview_card()

        # 创建网络概览卡片
        self.create_network_overview_card()

        # 创建最近活动卡片
        self.create_recent_activity_card()

    def create_user_info_card(self):
        """创建用户信息卡片"""
        user_card = ttk.Frame(self.cards_frame, style="Card.TFrame", padding=15)
        user_card.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # 卡片标题
        ttk.Label(user_card, text="用户信息", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # 用户信息
        ttk.Label(user_card, text=f"用户名: {self.controller.user_name}").pack(anchor=tk.W, pady=3)
        ttk.Label(user_card,
                  text=f"地址: {self.controller.user_address[:10]}...{self.controller.user_address[-8:]}").pack(
            anchor=tk.W, pady=3)
        ttk.Label(user_card, text=f"角色: {self.controller.user_role}").pack(anchor=tk.W, pady=3)

        # 注册时间
        reg_time = "未知"
        if hasattr(self.controller, "user_data") and "registered_at" in self.controller.user_data:
            reg_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.controller.user_data["registered_at"]))
        ttk.Label(user_card, text=f"注册时间: {reg_time}").pack(anchor=tk.W, pady=3)

        # 修改用户信息按钮
        ttk.Button(user_card, text="修改用户信息", command=self.edit_user_info).pack(anchor=tk.W, pady=(10, 0))

    def create_device_overview_card(self):
        """创建设备概览卡片"""
        device_card = ttk.Frame(self.cards_frame, style="Card.TFrame", padding=15)
        device_card.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # 卡片标题
        ttk.Label(device_card, text="设备概览", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # 设备数量
        device_count = len(self.controller.user_devices)
        ttk.Label(device_card, text=f"总设备数: {device_count}").pack(anchor=tk.W, pady=3)

        # 活跃设备数
        active_devices = sum(1 for d in self.controller.user_devices if d.get("is_active", False))
        ttk.Label(device_card, text=f"活跃设备: {active_devices}").pack(anchor=tk.W, pady=3)

        # 设备类型分布
        device_types = {}
        for device in self.controller.user_devices:
            device_type = device.get("device_type", "未知")
            device_types[device_type] = device_types.get(device_type, 0) + 1

        ttk.Label(device_card, text="设备类型分布:").pack(anchor=tk.W, pady=3)
        for dtype, count in device_types.items():
            ttk.Label(device_card, text=f"   - {dtype}: {count}").pack(anchor=tk.W, pady=1)

        # 设备管理按钮
        ttk.Button(device_card, text="管理设备", command=self.controller.show_device_management).pack(anchor=tk.W,
                                                                                                      pady=(10, 0))

    def create_network_overview_card(self):
        """创建网络概览卡片"""
        network_card = ttk.Frame(self.cards_frame, style="Card.TFrame", padding=15)
        network_card.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        # 卡片标题
        ttk.Label(network_card, text="网络概览", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # 网络数量
        network_count = len(self.controller.user_networks)
        ttk.Label(network_card, text=f"总网络数: {network_count}").pack(anchor=tk.W, pady=3)

        # 活跃网络
        active_networks = sum(1 for n in self.controller.user_networks if n.get("is_active", False))
        ttk.Label(network_card, text=f"活跃网络: {active_networks}").pack(anchor=tk.W, pady=3)

        # 网络列表
        if network_count > 0:
            ttk.Label(network_card, text="我的网络:").pack(anchor=tk.W, pady=3)
            for network in self.controller.user_networks[:3]:  # 只显示前3个
                status = "活跃" if network.get("is_active", False) else "未活跃"
                ttk.Label(network_card, text=f"   - {network.get('name', '未命名')}: {status}").pack(anchor=tk.W,
                                                                                                     pady=1)

        # 网络管理按钮
        ttk.Button(network_card, text="管理网络", command=self.controller.show_network_management).pack(anchor=tk.W,
                                                                                                        pady=(10, 0))

    def create_recent_activity_card(self):
        """创建最近活动卡片"""
        activity_card = ttk.Frame(self.cards_frame, style="Card.TFrame", padding=15)
        activity_card.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")

        # 卡片标题
        ttk.Label(activity_card, text="最近活动", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # 创建活动列表框架
        activities_frame = ttk.Frame(activity_card)
        activities_frame.pack(fill=tk.BOTH, expand=True)

        # 模拟一些活动数据
        activities = [
            {"time": time.time() - 3600, "type": "认证", "description": "设备 '我的笔记本电脑' 成功认证"},
            {"time": time.time() - 3600 * 3, "type": "注册", "description": "新设备 '办公室平板' 已注册"},
            {"time": time.time() - 3600 * 10, "type": "创建", "description": "创建新网络 '办公室网络'"},
            {"time": time.time() - 3600 * 24, "type": "认证", "description": "设备 '我的智能手机' 成功认证"},
            {"time": time.time() - 3600 * 48, "type": "撤销", "description": "撤销了令牌 #token-123"}
        ]

        # 显示活动列表
        for i, activity in enumerate(activities):
            activity_time = time.strftime("%m-%d %H:%M", time.localtime(activity["time"]))
            activity_row = ttk.Frame(activities_frame)
            activity_row.pack(fill=tk.X, pady=(0, 5))

            ttk.Label(activity_row, text=activity_time, width=12).pack(side=tk.LEFT)

            # 根据类型设置标签样式
            type_text = f"[{activity['type']}]"
            type_label = ttk.Label(activity_row, text=type_text, width=10)
            type_label.pack(side=tk.LEFT, padx=5)

            ttk.Label(activity_row, text=activity["description"]).pack(side=tk.LEFT, padx=5)

        # 查看全部按钮
        ttk.Button(activity_card, text="查看全部活动", command=self.controller.show_audit_logs).pack(anchor=tk.W,
                                                                                                     pady=(10, 0))

    def edit_user_info(self):
        """编辑用户信息"""
        # 创建编辑对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title("编辑用户信息")
        dialog.geometry("400x250")
        dialog.transient(self.controller)
        dialog.grab_set()

        # 对话框内容
        content_frame = ttk.Frame(dialog, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 用户名
        ttk.Label(content_frame, text="用户名:").grid(row=0, column=0, sticky=tk.W, pady=10)
        username_var = tk.StringVar(value=self.controller.user_name)
        username_entry = ttk.Entry(content_frame, textvariable=username_var, width=30)
        username_entry.grid(row=0, column=1, sticky=tk.W, pady=10)

        # 邮箱
        ttk.Label(content_frame, text="邮箱:").grid(row=1, column=0, sticky=tk.W, pady=10)
        email_var = tk.StringVar(value="user@example.com")  # 假设值
        email_entry = ttk.Entry(content_frame, textvariable=email_var, width=30)
        email_entry.grid(row=1, column=1, sticky=tk.W, pady=10)

        # 公钥更新
        ttk.Label(content_frame, text="更新公钥:").grid(row=2, column=0, sticky=tk.W, pady=10)
        update_pubkey_var = tk.BooleanVar(value=False)
        update_pubkey_check = ttk.Checkbutton(content_frame, variable=update_pubkey_var)
        update_pubkey_check.grid(row=2, column=1, sticky=tk.W, pady=10)

        # 按钮区域
        btn_frame = ttk.Frame(content_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)

        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="保存",
                   command=lambda: self._save_user_info(username_var.get(), email_var.get(), update_pubkey_var.get(),
                                                        dialog)).pack(side=tk.LEFT, padx=10)

    def _save_user_info(self, username, email, update_pubkey, dialog):
        """保存用户信息"""
        # 模拟保存操作
        if update_pubkey:
            # 如果需要更新公钥，应该打开新的对话框处理
            messagebox.showinfo("更新公钥", "公钥更新功能将在完整版中提供")

        # 更新用户名
        self.controller.user_name = username
        self.controller.user_info_var.set(f"用户: {username} | 角色: {self.controller.user_role}")

        messagebox.showinfo("成功", "用户信息已更新")
        dialog.destroy()

        # 刷新界面
        self.refresh()

    def refresh(self):
        """刷新面板数据"""
        # 重新加载面板
        self.cards_frame.destroy()

        # 创建卡片网格
        self.cards_frame = ttk.Frame(self.content_frame)
        self.cards_frame.pack(fill=tk.BOTH, expand=True)

        # 配置网格
        self.cards_frame.columnconfigure(0, weight=1)
        self.cards_frame.columnconfigure(1, weight=1)
        self.cards_frame.rowconfigure(0, weight=1)
        self.cards_frame.rowconfigure(1, weight=1)

        # 重新创建所有卡片
        self.create_user_info_card()
        self.create_device_overview_card()
        self.create_network_overview_card()
        self.create_recent_activity_card()


class UserManagementPanel(BasePanel):
    """用户管理面板"""

    def create_widgets(self):
        # 设置标题
        ttk.Label(self.title_frame, text="用户管理", style="Title.TLabel").pack(anchor=tk.W)

        # 工具栏
        toolbar = ttk.Frame(self.content_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        # 搜索框
        ttk.Label(toolbar, text="搜索:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)

        # 搜索按钮
        ttk.Button(toolbar, text="搜索", command=self.search_users).pack(side=tk.LEFT, padx=5)

        # 添加用户按钮
        ttk.Button(toolbar, text="添加用户", command=self.add_user).pack(side=tk.RIGHT, padx=5)

        # 用户表格
        self.create_users_table()

        # 待处理请求标签页
        self.create_pending_requests_tab()

    def create_users_table(self):
        """创建用户表格"""
        # 表格容器
        table_frame = ttk.LabelFrame(self.content_frame, text="用户列表")
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # 创建表格
        columns = ("用户名", "角色", "设备数", "状态", "注册时间", "操作")
        self.users_table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        # 设置列
        for col in columns:
            self.users_table.heading(col, text=col)
            if col in ("设备数", "状态"):
                self.users_table.column(col, width=80, anchor=tk.CENTER)
            elif col == "角色":
                self.users_table.column(col, width=120, anchor=tk.CENTER)
            elif col == "注册时间":
                self.users_table.column(col, width=150, anchor=tk.CENTER)
            elif col == "操作":
                self.users_table.column(col, width=150, anchor=tk.CENTER)
            else:
                self.users_table.column(col, width=150)

        # 添加垂直滚动条
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.users_table.yview)
        self.users_table.configure(yscroll=scrollbar.set)

        # 布局
        self.users_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定点击事件
        self.users_table.bind("<Double-1>", self.on_user_double_click)

        # 加载用户数据
        self.load_users_data()

    def create_pending_requests_tab(self):
        """创建待处理请求标签页"""
        # 请求容器
        requests_frame = ttk.LabelFrame(self.content_frame, text="待处理注册请求")
        requests_frame.pack(fill=tk.BOTH, expand=True)

        # 创建表格
        columns = ("请求ID", "用户名", "请求时间", "状态", "操作")
        self.requests_table = ttk.Treeview(requests_frame, columns=columns, show="headings", selectmode="browse")

        # 设置列
        for col in columns:
            self.requests_table.heading(col, text=col)
            if col in ("状态"):
                self.requests_table.column(col, width=100, anchor=tk.CENTER)
            elif col == "请求时间":
                self.requests_table.column(col, width=150, anchor=tk.CENTER)
            elif col == "操作":
                self.requests_table.column(col, width=150, anchor=tk.CENTER)
            elif col == "请求ID":
                self.requests_table.column(col, width=200)
            else:
                self.requests_table.column(col, width=150)

        # 添加垂直滚动条
        scrollbar = ttk.Scrollbar(requests_frame, orient=tk.VERTICAL, command=self.requests_table.yview)
        self.requests_table.configure(yscroll=scrollbar.set)

        # 布局
        self.requests_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定点击事件
        self.requests_table.bind("<Double-1>", self.on_request_double_click)

        # 加载请求数据
        self.load_requests_data()

    def load_users_data(self):
        """加载用户数据"""
        # 清空表格
        for item in self.users_table.get_children():
            self.users_table.delete(item)

        # 模拟用户数据
        users_data = [
            {"id": "0x123...", "username": "Alice", "role": "SYSTEM_ADMIN", "device_count": 5, "is_active": True,
             "registered_at": time.time() - 3600 * 24 * 30},
            {"id": "0x456...", "username": "Bob", "role": "NETWORK_ADMIN", "device_count": 3, "is_active": True,
             "registered_at": time.time() - 3600 * 24 * 20},
            {"id": "0x789...", "username": "Charlie", "role": "USER", "device_count": 2, "is_active": True,
             "registered_at": time.time() - 3600 * 24 * 10},
            {"id": "0xabc...", "username": "David", "role": "USER", "device_count": 1, "is_active": False,
             "registered_at": time.time() - 3600 * 24 * 5},
            {"id": "0xdef...", "username": "Eve", "role": "USER", "device_count": 4, "is_active": True,
             "registered_at": time.time() - 3600 * 24 * 2}
        ]

        # 填充表格
        for user in users_data:
            status = "活跃" if user["is_active"] else "已停用"
            reg_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(user["registered_at"]))

            # 插入数据
            self.users_table.insert("", tk.END, values=(
                user["username"],
                user["role"],
                user["device_count"],
                status,
                reg_time,
                "查看/编辑"
            ), tags=(user["id"],))

    def load_requests_data(self):
        """加载请求数据"""
        # 清空表格
        for item in self.requests_table.get_children():
            self.requests_table.delete(item)

        # 模拟请求数据
        requests_data = [
            {"id": "req_001", "username": "Frank", "requested_at": time.time() - 3600 * 5, "status": "待处理"},
            {"id": "req_002", "username": "Grace", "requested_at": time.time() - 3600 * 3, "status": "待处理"},
            {"id": "req_003", "username": "Heidi", "requested_at": time.time() - 3600, "status": "待处理"}
        ]

        # 填充表格
        for req in requests_data:
            req_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(req["requested_at"]))

            # 插入数据
            self.requests_table.insert("", tk.END, values=(
                req["id"],
                req["username"],
                req_time,
                req["status"],
                "批准/拒绝"
            ), tags=(req["id"],))

    def search_users(self):
        """搜索用户"""
        search_text = self.search_var.get().strip().lower()
        if not search_text:
            # 如果搜索框为空，重新加载所有数据
            self.load_users_data()
            return

        # 清空表格
        for item in self.users_table.get_children():
            self.users_table.delete(item)

        # 模拟搜索结果
        #TODO 实际应用中应该从区块链或数据库筛选
        users_data = [
            {"id": "0x123...", "username": "Alice", "role": "SYSTEM_ADMIN", "device_count": 5, "is_active": True,
             "registered_at": time.time() - 3600 * 24 * 30}
        ]

        # 填充表格
        for user in users_data:
            status = "活跃" if user["is_active"] else "已停用"
            reg_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(user["registered_at"]))

            # 插入数据
            self.users_table.insert("", tk.END, values=(
                user["username"],
                user["role"],
                user["device_count"],
                status,
                reg_time,
                "查看/编辑"
            ), tags=(user["id"],))

    def add_user(self):
        """添加用户"""
        # 创建对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title("添加用户")
        dialog.geometry("500x400")
        dialog.transient(self.controller)
        dialog.grab_set()

        # 对话框内容
        content_frame = ttk.Frame(dialog, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 用户名
        ttk.Label(content_frame, text="用户名:").grid(row=0, column=0, sticky=tk.W, pady=10)
        username_var = tk.StringVar()
        username_entry = ttk.Entry(content_frame, textvariable=username_var, width=30)
        username_entry.grid(row=0, column=1, sticky=tk.W, pady=10)

        # 邮箱
        ttk.Label(content_frame, text="邮箱:").grid(row=1, column=0, sticky=tk.W, pady=10)
        email_var = tk.StringVar()
        email_entry = ttk.Entry(content_frame, textvariable=email_var, width=30)
        email_entry.grid(row=1, column=1, sticky=tk.W, pady=10)

        # 角色
        ttk.Label(content_frame, text="角色:").grid(row=2, column=0, sticky=tk.W, pady=10)
        role_var = tk.StringVar(value="USER")
        role_combo = ttk.Combobox(content_frame, textvariable=role_var, width=15, state="readonly")
        role_combo['values'] = ["USER", "NETWORK_ADMIN", "SYSTEM_ADMIN"]
        role_combo.grid(row=2, column=1, sticky=tk.W, pady=10)

        # 密钥管理
        key_frame = ttk.LabelFrame(content_frame, text="密钥管理")
        key_frame.grid(row=3, column=0, columnspan=2, sticky=tk.EW, pady=10)

        # 生成密钥按钮
        generate_btn = ttk.Button(key_frame, text="生成新密钥对",
                                  command=lambda: self._generate_key_for_new_user(pubkey_var))
        generate_btn.pack(fill=tk.X, pady=5)

        # 公钥显示
        ttk.Label(key_frame, text="公钥:").pack(anchor=tk.W, pady=5)
        pubkey_var = tk.StringVar()
        pubkey_entry = ttk.Entry(key_frame, textvariable=pubkey_var, width=40)
        pubkey_entry.pack(fill=tk.X, pady=2)

        # 按钮区域
        btn_frame = ttk.Frame(content_frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=20)

        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="创建用户", command=lambda: self._create_user(
            username_var.get(), email_var.get(), role_var.get(), pubkey_var.get(), dialog)).pack(side=tk.LEFT, padx=10)

    def _generate_key_for_new_user(self, pubkey_var):
        """为新用户生成密钥对"""
        # 生成密钥对
        # 模拟生成过程
        private_key = f"0x{os.urandom(32).hex()}"
        public_key = f"0x{hashlib.sha256(private_key.encode()).hexdigest()}"

        # 设置公钥值
        pubkey_var.set(public_key)

        # 显示私钥给管理员（实际应用中应更安全地处理）
        messagebox.showinfo(
            "私钥信息 - 重要",
            f"请安全地传递此私钥给新用户:\n\n{private_key}\n\n此私钥只显示一次，请立即保存！"
        )

    def _create_user(self, username, email, role, pubkey, dialog):
        """创建新用户"""
        if not username or not pubkey:
            messagebox.showerror("错误", "用户名和公钥不能为空")
            return

        #TODO 实际应用中应调用智能合约
        # 模拟创建用户过程
        messagebox.showinfo("成功", f"用户 {username} 已创建，角色: {role}")
        dialog.destroy()

        # 刷新用户列表
        self.load_users_data()

    def on_user_double_click(self, event):
        """处理用户表格行双击事件"""
        region = self.users_table.identify("region", event.x, event.y)
        if region == "cell":
            # 获取选中的行
            selected_items = self.users_table.selection()
            if selected_items:
                item = selected_items[0]
                # 获取用户ID
                user_id = self.users_table.item(item, "tags")[0]
                # 获取列索引
                column = self.users_table.identify_column(event.x)
                column_index = int(column.replace('#', '')) - 1

                # 如果点击的是操作列
                if column_index == 5:  # "操作"列
                    # 获取用户基本信息
                    values = self.users_table.item(item, "values")
                    user_name = values[0]

                    # 显示编辑对话框
                    self.edit_user(user_id, user_name)

    def on_request_double_click(self, event):
        """处理请求表格行双击事件"""
        region = self.requests_table.identify("region", event.x, event.y)
        if region == "cell":
            # 获取选中的行
            selected_items = self.requests_table.selection()
            if selected_items:
                item = selected_items[0]
                # 获取请求ID
                request_id = self.requests_table.item(item, "tags")[0]
                # 获取列索引
                column = self.requests_table.identify_column(event.x)
                column_index = int(column.replace('#', '')) - 1

                # 如果点击的是操作列
                if column_index == 4:  # "操作"列
                    # 获取请求基本信息
                    values = self.requests_table.item(item, "values")
                    request_user = values[1]

                    # 显示请求处理对话框
                    self.process_request(request_id, request_user)

    def edit_user(self, user_id, user_name):
        """编辑用户"""
        # 创建编辑对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title(f"编辑用户 - {user_name}")
        dialog.geometry("500x400")
        dialog.transient(self.controller)
        dialog.grab_set()
        # 对话框内容
        content_frame = ttk.Frame(dialog, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 用户ID显示
        ttk.Label(content_frame, text="用户ID:").grid(row=0, column=0, sticky=tk.W, pady=10)
        ttk.Label(content_frame, text=user_id).grid(row=0, column=1, sticky=tk.W, pady=10)

        # 用户名
        ttk.Label(content_frame, text="用户名:").grid(row=1, column=0, sticky=tk.W, pady=10)
        username_var = tk.StringVar(value=user_name)
        username_entry = ttk.Entry(content_frame, textvariable=username_var, width=30)
        username_entry.grid(row=1, column=1, sticky=tk.W, pady=10)

        # 角色
        ttk.Label(content_frame, text="角色:").grid(row=2, column=0, sticky=tk.W, pady=10)
        role_var = tk.StringVar(value="USER")  # 假设默认角色
        role_combo = ttk.Combobox(content_frame, textvariable=role_var, width=15, state="readonly")
        role_combo['values'] = ["USER", "NETWORK_ADMIN", "SYSTEM_ADMIN"]
        role_combo.grid(row=2, column=1, sticky=tk.W, pady=10)

        # 状态
        ttk.Label(content_frame, text="状态:").grid(row=3, column=0, sticky=tk.W, pady=10)
        status_var = tk.BooleanVar(value=True)  # 假设默认活跃
        status_check = ttk.Checkbutton(content_frame, text="活跃", variable=status_var)
        status_check.grid(row=3, column=1, sticky=tk.W, pady=10)

        # 设备管理按钮
        ttk.Button(content_frame, text="管理用户设备", command=lambda: self.show_user_devices(user_id, user_name)).grid(
            row=4, column=0, columnspan=2, sticky=tk.W, pady=10)

        # 按钮区域
        btn_frame = ttk.Frame(content_frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)

        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="保存", command=lambda: self._save_user_changes(
            user_id, username_var.get(), role_var.get(), status_var.get(), dialog)).pack(side=tk.LEFT, padx=10)

        def _save_user_changes(self, user_id, username, role, is_active, dialog):
            """保存用户更改"""
            # 实际应用中应调用智能合约
            # 模拟保存过程
            messagebox.showinfo("成功", f"用户 {username} 信息已更新")
            dialog.destroy()

            # 刷新用户列表
            self.load_users_data()

        def show_user_devices(self, user_id, user_name):
            """显示用户的设备"""
            # 创建设备列表对话框
            dialog = tk.Toplevel(self.controller)
            dialog.title(f"{user_name} 的设备")
            dialog.geometry("600x400")
            dialog.transient(self.controller)
            dialog.grab_set()

            # 对话框内容
            content_frame = ttk.Frame(dialog, padding=20)
            content_frame.pack(fill=tk.BOTH, expand=True)

            # 创建设备表格
            columns = ("设备名", "类型", "状态", "注册时间", "操作")
            devices_table = ttk.Treeview(content_frame, columns=columns, show="headings", selectmode="browse")

            # 设置列
            for col in columns:
                devices_table.heading(col, text=col)
                if col == "状态":
                    devices_table.column(col, width=80, anchor=tk.CENTER)
                elif col == "类型":
                    devices_table.column(col, width=100, anchor=tk.CENTER)
                elif col == "注册时间":
                    devices_table.column(col, width=150, anchor=tk.CENTER)
                elif col == "操作":
                    devices_table.column(col, width=100, anchor=tk.CENTER)
                else:
                    devices_table.column(col, width=150)

            # 添加垂直滚动条
            scrollbar = ttk.Scrollbar(content_frame, orient=tk.VERTICAL, command=devices_table.yview)
            devices_table.configure(yscroll=scrollbar.set)

            # 布局
            devices_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            # 模拟设备数据
            devices_data = [
                {"id": "did:123", "name": "笔记本电脑", "type": "laptop", "is_active": True,
                 "registered_at": time.time() - 3600 * 24 * 7},
                {"id": "did:456", "name": "智能手机", "type": "smartphone", "is_active": True,
                 "registered_at": time.time() - 3600 * 24 * 3},
                {"id": "did:789", "name": "平板电脑", "type": "tablet", "is_active": False,
                 "registered_at": time.time() - 3600 * 24}
            ]

            # 填充表格
            for device in devices_data:
                status = "活跃" if device["is_active"] else "已停用"
                reg_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(device["registered_at"]))

                # 插入数据
                devices_table.insert("", tk.END, values=(
                    device["name"],
                    device["type"],
                    status,
                    reg_time,
                    "管理"
                ), tags=(device["id"],))

            # 按钮区域
            btn_frame = ttk.Frame(content_frame)
            btn_frame.pack(fill=tk.X, pady=10)

            ttk.Button(btn_frame, text="关闭", command=dialog.destroy).pack(side=tk.RIGHT, padx=10)
            ttk.Button(btn_frame, text="转移设备", command=lambda: self.transfer_device(user_id, user_name)).pack(
                side=tk.LEFT, padx=10)

        def transfer_device(self, user_id, user_name):
            """转移设备"""
            # 显示设备转移对话框
            messagebox.showinfo("功能提示", "设备转移功能将在完整版中提供")

        def process_request(self, request_id, request_user):
            """处理注册请求"""
            # 创建请求处理对话框
            dialog = tk.Toplevel(self.controller)
            dialog.title(f"处理注册请求 - {request_user}")
            dialog.geometry("500x400")
            dialog.transient(self.controller)
            dialog.grab_set()

            # 对话框内容
            content_frame = ttk.Frame(dialog, padding=20)
            content_frame.pack(fill=tk.BOTH, expand=True)

            # 请求ID
            ttk.Label(content_frame, text="请求ID:").grid(row=0, column=0, sticky=tk.W, pady=10)
            ttk.Label(content_frame, text=request_id).grid(row=0, column=1, sticky=tk.W, pady=10)

            # 用户名
            ttk.Label(content_frame, text="用户名:").grid(row=1, column=0, sticky=tk.W, pady=10)
            ttk.Label(content_frame, text=request_user).grid(row=1, column=1, sticky=tk.W, pady=10)

            # 角色设置
            ttk.Label(content_frame, text="分配角色:").grid(row=2, column=0, sticky=tk.W, pady=10)
            role_var = tk.StringVar(value="USER")
            role_combo = ttk.Combobox(content_frame, textvariable=role_var, width=15, state="readonly")
            role_combo['values'] = ["USER", "NETWORK_ADMIN"]
            role_combo.grid(row=2, column=1, sticky=tk.W, pady=10)

            # 请求详情
            ttk.Label(content_frame, text="请求详情:").grid(row=3, column=0, sticky=tk.N, pady=10)
            details_text = tk.Text(content_frame, height=6, width=40, wrap=tk.WORD)
            details_text.grid(row=3, column=1, sticky=tk.EW, pady=10)
            details_text.insert(tk.END, f"申请时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            details_text.insert(tk.END, f"申请理由: 需要访问无线网络进行项目开发\n")
            details_text.insert(tk.END, f"公钥: 0x8a3bfd5f0816b9...\n")
            details_text.config(state=tk.DISABLED)

            # 按钮区域
            btn_frame = ttk.Frame(content_frame)
            btn_frame.grid(row=4, column=0, columnspan=2, pady=20)

            ttk.Button(btn_frame, text="拒绝", command=lambda: self._reject_request(request_id, dialog)).pack(
                side=tk.LEFT, padx=10)
            ttk.Button(btn_frame, text="批准", command=lambda: self._approve_request(
                request_id, request_user, role_var.get(), dialog)).pack(side=tk.LEFT, padx=10)

        def _approve_request(self, request_id, username, role, dialog):
            """批准注册请求"""
            # 实际应用中应调用智能合约
            # 模拟批准过程
            messagebox.showinfo("成功", f"已批准 {username} 的注册请求，分配角色: {role}")
            dialog.destroy()

            # 刷新请求列表
            self.load_requests_data()
            # 刷新用户列表
            self.load_users_data()

        def _reject_request(self, request_id, dialog):
            """拒绝注册请求"""
            # 实际应用中应调用智能合约
            # 模拟拒绝过程
            messagebox.showinfo("成功", f"已拒绝请求ID: {request_id}")
            dialog.destroy()

            # 刷新请求列表
            self.load_requests_data()

        def refresh(self):
            """刷新面板数据"""
            self.load_users_data()
            self.load_requests_data()

class DeviceManagementPanel(BasePanel):
        """设备管理面板"""

        def create_widgets(self):
            # 设置标题
            ttk.Label(self.title_frame, text="设备管理", style="Title.TLabel").pack(anchor=tk.W)

            # 工具栏
            toolbar = ttk.Frame(self.content_frame)
            toolbar.pack(fill=tk.X, pady=(0, 10))

            # 注册新设备按钮
            ttk.Button(toolbar, text="注册新设备", command=self.register_new_device).pack(side=tk.RIGHT, padx=5)

            # 创建设备列表
            self.create_devices_list()

        def create_devices_list(self):
            """创建设备列表"""
            # 列表容器
            list_frame = ttk.Frame(self.content_frame)
            list_frame.pack(fill=tk.BOTH, expand=True)

            # 使设备列表可以水平扩展
            list_frame.columnconfigure(0, weight=1)
            list_frame.rowconfigure(0, weight=1)

            # 创建设备卡片滚动区域
            self.devices_canvas = tk.Canvas(list_frame, background=COLORS["bg_light"])
            scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.devices_canvas.yview)
            self.devices_canvas.configure(yscrollcommand=scrollbar.set)

            # 布局
            self.devices_canvas.grid(row=0, column=0, sticky="nsew")
            scrollbar.grid(row=0, column=1, sticky="ns")

            # 创建用于包含设备卡片的框架
            self.devices_frame = ttk.Frame(self.devices_canvas, style="TFrame")
            self.devices_canvas.create_window((0, 0), window=self.devices_frame, anchor="nw")

            # 配置设备框架以适应画布大小
            def configure_scroll_region(event):
                self.devices_canvas.configure(scrollregion=self.devices_canvas.bbox("all"))

            self.devices_frame.bind("<Configure>", configure_scroll_region)

            # 加载设备数据
            self.load_devices_data()

        def load_devices_data(self):
            """加载设备数据并创建设备卡片"""
            # 清空现有设备卡片
            for widget in self.devices_frame.winfo_children():
                widget.destroy()

            # 获取用户设备数据
            devices = self.controller.user_devices

            if not devices:
                # 显示无设备提示
                no_device_label = ttk.Label(
                    self.devices_frame,
                    text="没有注册的设备。点击注册新设备按钮来添加设备。",
                font = ("Arial", 12)
                )
                no_device_label.pack(pady=50)
                return

            # 为每个设备创建卡片
            for i, device in enumerate(devices):
                self.create_device_card(device, i)

        def create_device_card(self, device, index):
            """创建设备卡片"""
            # 卡片框架
            card = ttk.Frame(self.devices_frame, style="Card.TFrame", padding=15)
            card.pack(fill=tk.X, padx=20, pady=10)

            # 设置网格配置
            card.columnconfigure(0, weight=1)  # 让信息区域可以水平扩展
            card.columnconfigure(1, weight=0)  # 按钮区域固定宽度

            # 设备信息区域
            info_frame = ttk.Frame(card)
            info_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

            # 设备名称（标题）
            device_name = device.get('name', '未命名设备')
            device_type = device.get('device_type', '未知类型')
            title_label = ttk.Label(info_frame, text=device_name, font=("Arial", 14, "bold"))
            title_label.pack(anchor=tk.W, pady=(0, 5))

            # 设备类型
            type_label = ttk.Label(info_frame, text=f"类型: {device_type}")
            type_label.pack(anchor=tk.W, pady=2)

            # 设备ID（DID）
            did = device.get('did', '未知DID')
            did_short = f"{did[:10]}...{did[-8:]}" if len(did) > 20 else did
            did_label = ttk.Label(info_frame, text=f"DID: {did_short}")
            did_label.pack(anchor=tk.W, pady=2)

            # 注册时间
            reg_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(device.get('registered_at', time.time())))
            reg_label = ttk.Label(info_frame, text=f"注册时间: {reg_time}")
            reg_label.pack(anchor=tk.W, pady=2)

            # 状态
            status = "活跃" if device.get('is_active', False) else "已停用"
            status_label = ttk.Label(info_frame, text=f"状态: {status}")
            status_label.pack(anchor=tk.W, pady=2)

            # 操作按钮区域
            btn_frame = ttk.Frame(card)
            btn_frame.grid(row=0, column=1, sticky="ne")

            # 更新按钮
            update_btn = ttk.Button(
                btn_frame,
                text="更新信息",
                command=lambda d=device: self.update_device_info(d)
            )
            update_btn.pack(pady=5)

            # 状态按钮（启用/停用）
            if device.get('is_active', False):
                status_btn = ttk.Button(
                    btn_frame,
                    text="停用设备",
                    command=lambda d=device: self.deactivate_device(d)
                )
            else:
                status_btn = ttk.Button(
                    btn_frame,
                    text="启用设备",
                    command=lambda d=device: self.activate_device(d)
                )
            status_btn.pack(pady=5)

            # 转移按钮
            transfer_btn = ttk.Button(
                btn_frame,
                text="转移设备",
                command=lambda d=device: self.transfer_device(d)
            )
            transfer_btn.pack(pady=5)

        def register_new_device(self):
            """注册新设备"""
            # 创建注册对话框
            dialog = tk.Toplevel(self.controller)
            dialog.title("注册新设备")
            dialog.geometry("500x500")
            dialog.transient(self.controller)
            dialog.grab_set()

            # 对话框内容
            content_frame = ttk.Frame(dialog, padding=20)
            content_frame.pack(fill=tk.BOTH, expand=True)

            # 设备名称
            ttk.Label(content_frame, text="设备名称:").grid(row=0, column=0, sticky=tk.W, pady=10)
            name_var = tk.StringVar()
            name_entry = ttk.Entry(content_frame, textvariable=name_var, width=30)
            name_entry.grid(row=0, column=1, sticky=tk.W, pady=10)

            # 设备类型
            ttk.Label(content_frame, text="设备类型:").grid(row=1, column=0, sticky=tk.W, pady=10)
            type_var = tk.StringVar(value="smartphone")
            type_combo = ttk.Combobox(content_frame, textvariable=type_var, width=15, state="readonly")
            type_combo['values'] = ["smartphone", "laptop", "tablet", "iot_device", "smart_tv", "other"]
            type_combo.grid(row=1, column=1, sticky=tk.W, pady=10)

            # 设备元数据
            ttk.Label(content_frame, text="设备元数据:").grid(row=2, column=0, sticky=tk.W, pady=10)
            metadata_var = tk.StringVar()
            metadata_entry = ttk.Entry(content_frame, textvariable=metadata_var, width=30)
            metadata_entry.grid(row=2, column=1, sticky=tk.W, pady=10)

            # 密钥管理区域
            key_frame = ttk.LabelFrame(content_frame, text="密钥管理")
            key_frame.grid(row=3, column=0, columnspan=2, sticky=tk.EW, pady=10)

            # 生成密钥按钮
            generate_btn = ttk.Button(key_frame, text="生成新密钥对",
                                      command=lambda: self._generate_device_key(pubkey_var, privkey_var))
            generate_btn.pack(fill=tk.X, pady=5)

            # 导入私钥按钮
            import_btn = ttk.Button(key_frame, text="导入已有私钥",
                                    command=lambda: self._import_device_key(pubkey_var, privkey_var))
            import_btn.pack(fill=tk.X, pady=5)

            # 公钥显示
            ttk.Label(key_frame, text="公钥:").pack(anchor=tk.W, pady=5)
            pubkey_var = tk.StringVar()
            pubkey_entry = ttk.Entry(key_frame, textvariable=pubkey_var, width=40)
            pubkey_entry.pack(fill=tk.X, pady=2)

            # 私钥显示
            ttk.Label(key_frame, text="私钥(请妥善保管):").pack(anchor=tk.W, pady=5)
            privkey_var = tk.StringVar()
            privkey_entry = ttk.Entry(key_frame, textvariable=privkey_var, width=40, show="*")
            privkey_entry.pack(fill=tk.X, pady=2)

            # 显示/隐藏私钥
            show_key_var = tk.BooleanVar(value=False)
            show_key_check = ttk.Checkbutton(
                key_frame,
                text="显示私钥",
                variable=show_key_var,
                command=lambda: privkey_entry.config(show="" if show_key_var.get() else "*")
            )
            show_key_check.pack(anchor=tk.W, pady=5)

            # 按钮区域
            btn_frame = ttk.Frame(content_frame)
            btn_frame.grid(row=4, column=0, columnspan=2, pady=20)

            ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
            ttk.Button(btn_frame, text="注册设备", command=lambda: self._register_device(
                name_var.get(), type_var.get(), metadata_var.get(),
                pubkey_var.get(), privkey_var.get(), dialog)).pack(side=tk.LEFT, padx=10)

        def _generate_device_key(self, pubkey_var, privkey_var):
            """生成设备密钥对"""
            # 模拟生成过程
            private_key = f"0x{os.urandom(32).hex()}"
            public_key = f"0x{hashlib.sha256(private_key.encode()).hexdigest()}"

            # 设置值
            pubkey_var.set(public_key)
            privkey_var.set(private_key)

        def _import_device_key(self, pubkey_var, privkey_var):
            """导入设备私钥"""
            private_key = simpledialog.askstring("导入私钥", "请输入设备私钥:", show="*")
            if not private_key:
                return

            # 生成公钥（实际应基于私钥正确派生）
            public_key = f"0x{hashlib.sha256(private_key.encode()).hexdigest()}"

            # 设置值
            pubkey_var.set(public_key)
            privkey_var.set(private_key)

        def _register_device(self, name, device_type, metadata, pubkey, privkey, dialog):
            """注册设备"""
            if not name or not pubkey:
                messagebox.showerror("错误", "设备名称和公钥不能为空")
                return

            # 实际应调用智能合约
            # 模拟注册过程
            messagebox.showinfo("成功", f"设备 {name} 已注册")
            dialog.destroy()

            # 模拟添加新设备
            new_device = {
                "did": f"did:identity-chain:{hashlib.sha256(pubkey.encode()).hexdigest()}",
                "name": name,
                "device_type": device_type,
                "registered_at": time.time(),
                "is_active": True
            }

            self.controller.user_devices.append(new_device)

            # 刷新设备列表
            self.load_devices_data()

        def update_device_info(self, device):
            """更新设备信息"""
            # 创建更新对话框
            dialog = tk.Toplevel(self.controller)
            dialog.title(f"更新设备信息 - {device.get('name', '未命名设备')}")
            dialog.geometry("400x300")
            dialog.transient(self.controller)
            dialog.grab_set()

            # 对话框内容
            content_frame = ttk.Frame(dialog, padding=20)
            content_frame.pack(fill=tk.BOTH, expand=True)

            # 设备ID显示
            ttk.Label(content_frame, text="设备ID:").grid(row=0, column=0, sticky=tk.W, pady=10)
            did_short = f"{device['did'][:10]}...{device['did'][-8:]}" if len(device['did']) > 20 else device['did']
            ttk.Label(content_frame, text=did_short).grid(row=0, column=1, sticky=tk.W, pady=10)

            # 设备名称
            ttk.Label(content_frame, text="设备名称:").grid(row=1, column=0, sticky=tk.W, pady=10)
            name_var = tk.StringVar(value=device.get('name', ''))
            name_entry = ttk.Entry(content_frame, textvariable=name_var, width=30)
            name_entry.grid(row=1, column=1, sticky=tk.W, pady=10)

            # 设备元数据
            ttk.Label(content_frame, text="设备元数据:").grid(row=2, column=0, sticky=tk.W, pady=10)
            metadata_var = tk.StringVar(value="设备元数据")  # 假设值
            metadata_entry = ttk.Entry(content_frame, textvariable=metadata_var, width=30)
            metadata_entry.grid(row=2, column=1, sticky=tk.W, pady=10)

            # 按钮区域
            btn_frame = ttk.Frame(content_frame)
            btn_frame.grid(row=3, column=0, columnspan=2, pady=20)

            ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
            ttk.Button(btn_frame, text="保存", command=lambda: self._save_device_changes(
                device, name_var.get(), metadata_var.get(), dialog)).pack(side=tk.LEFT, padx=10)

        def _save_device_changes(self, device, name, metadata, dialog):
            """保存设备更改"""
            # 实际应调用智能合约
            # 模拟保存过程
            messagebox.showinfo("成功", f"设备 {name} 信息已更新")

            # 更新本地数据
            device['name'] = name

            dialog.destroy()

            # 刷新设备列表
            self.load_devices_data()

        def deactivate_device(self, device):
            """停用设备"""
            if messagebox.askyesno("确认", f"确定要停用设备 {device.get('name', '未命名设备')} 吗？"):
                # 实际应调用智能合约
                # 模拟停用过程
                device['is_active'] = False
                messagebox.showinfo("成功", f"设备 {device.get('name', '未命名设备')} 已停用")

                # 刷新设备列表
                self.load_devices_data()

        def activate_device(self, device):
            """启用设备"""
            # 实际应调用智能合约
            # 模拟启用过程
            device['is_active'] = True
            messagebox.showinfo("成功", f"设备 {device.get('name', '未命名设备')} 已启用")

            # 刷新设备列表
            self.load_devices_data()

        def transfer_device(self, device):
            """转移设备所有权"""
            # 创建转移对话框
            dialog = tk.Toplevel(self.controller)
            dialog.title(f"转移设备 - {device.get('name', '未命名设备')}")
            dialog.geometry("400x200")
            dialog.transient(self.controller)
            dialog.grab_set()

            # 对话框内容
            content_frame = ttk.Frame(dialog, padding=20)
            content_frame.pack(fill=tk.BOTH, expand=True)

            # 设备信息
            ttk.Label(content_frame, text=f"设备: {device.get('name', '未命名设备')}").pack(anchor=tk.W, pady=5)
            ttk.Label(content_frame, text=f"ID: {device.get('did', '未知DID')[:10]}...").pack(anchor=tk.W, pady=5)

            # 新所有者地址
            ttk.Label(content_frame, text="新所有者地址:").pack(anchor=tk.W, pady=5)  # 配置网格
            self.cards_frame.columnconfigure(0, weight=1)
            self.cards_frame.columnconfigure(1, weight=1)
            self.cards_frame.rowconfigure(0, weight=1)
            self.cards_frame.rowconfigure(1, weight=1)

            # 创建用户信息卡片
            self.create_user_info_card()

            # 创建设备概览卡片
            self.create_device_overview_card()

            # 创建网络概览卡片
            self.create_network_overview_card()

            # 创建最近活动卡片
            self.create_recent_activity_card()

        def create_user_info_card(self):
            """创建用户信息卡片"""
            user_card = ttk.Frame(self.cards_frame, style="Card.TFrame", padding=15)
            user_card.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

            # 卡片标题
            ttk.Label(user_card, text="用户信息", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

            # 用户信息
            ttk.Label(user_card, text=f"用户名: {self.controller.user_name}").pack(anchor=tk.W, pady=3)
            ttk.Label(user_card,
                      text=f"地址: {self.controller.user_address[:10]}...{self.controller.user_address[-8:]}").pack(
                anchor=tk.W, pady=3)
            ttk.Label(user_card, text=f"角色: {self.controller.user_role}").pack(anchor=tk.W, pady=3)

            # 注册时间
            reg_time = "未知"
            if hasattr(self.controller, "user_data") and "registered_at" in self.controller.user_data:
                reg_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                         time.localtime(self.controller.user_data["registered_at"]))
            ttk.Label(user_card, text=f"注册时间: {reg_time}").pack(anchor=tk.W, pady=3)

            # 修改用户信息按钮
            ttk.Button(user_card, text="修改用户信息", command=self.edit_user_info).pack(anchor=tk.W, pady=(10, 0))

        def create_device_overview_card(self):
            """创建设备概览卡片"""
            device_card = ttk.Frame(self.cards_frame, style="Card.TFrame", padding=15)
            device_card.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

            # 卡片标题
            ttk.Label(device_card, text="设备概览", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

            # 设备数量
            device_count = len(self.controller.user_devices)
            ttk.Label(device_card, text=f"总设备数: {device_count}").pack(anchor=tk.W, pady=3)

            # 活跃设备数
            active_devices = sum(1 for d in self.controller.user_devices if d.get("is_active", False))
            ttk.Label(device_card, text=f"活跃设备: {active_devices}").pack(anchor=tk.W, pady=3)

            # 设备类型分布
            device_types = {}
            for device in self.controller.user_devices:
                device_type = device.get("device_type", "未知")
                device_types[device_type] = device_types.get(device_type, 0) + 1

            ttk.Label(device_card, text="设备类型分布:").pack(anchor=tk.W, pady=3)
            for dtype, count in device_types.items():
                ttk.Label(device_card, text=f"   - {dtype}: {count}").pack(anchor=tk.W, pady=1)

            # 设备管理按钮
            ttk.Button(device_card, text="管理设备", command=self.controller.show_device_management).pack(anchor=tk.W,
                                                                                                          pady=(10, 0))

        def create_network_overview_card(self):
            """创建网络概览卡片"""
            network_card = ttk.Frame(self.cards_frame, style="Card.TFrame", padding=15)
            network_card.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

            # 卡片标题
            ttk.Label(network_card, text="网络概览", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

            # 网络数量
            network_count = len(self.controller.user_networks)
            ttk.Label(network_card, text=f"总网络数: {network_count}").pack(anchor=tk.W, pady=3)

            # 活跃网络
            active_networks = sum(1 for n in self.controller.user_networks if n.get("is_active", False))
            ttk.Label(network_card, text=f"活跃网络: {active_networks}").pack(anchor=tk.W, pady=3)

            # 网络列表
            if network_count > 0:
                ttk.Label(network_card, text="我的网络:").pack(anchor=tk.W, pady=3)
                for network in self.controller.user_networks[:3]:  # 只显示前3个
                    status = "活跃" if network.get("is_active", False) else "未活跃"
                    ttk.Label(network_card, text=f"   - {network.get('name', '未命名')}: {status}").pack(anchor=tk.W,
                                                                                                         pady=1)

            # 网络管理按钮
            ttk.Button(network_card, text="管理网络", command=self.controller.show_network_management).pack(anchor=tk.W,
                                                                                                            pady=(
                                                                                                            10, 0))

        def create_recent_activity_card(self):
            """创建最近活动卡片"""
            activity_card = ttk.Frame(self.cards_frame, style="Card.TFrame", padding=15)
            activity_card.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")

            # 卡片标题
            ttk.Label(activity_card, text="最近活动", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

            # 创建活动列表框架
            activities_frame = ttk.Frame(activity_card)
            activities_frame.pack(fill=tk.BOTH, expand=True)

            # 模拟一些活动数据
            activities = [
                {"time": time.time() - 3600, "type": "认证", "description": "设备 '我的笔记本电脑' 成功认证"},
                {"time": time.time() - 3600 * 3, "type": "注册", "description": "新设备 '办公室平板' 已注册"},
                {"time": time.time() - 3600 * 10, "type": "创建", "description": "创建新网络 '办公室网络'"},
                {"time": time.time() - 3600 * 24, "type": "认证", "description": "设备 '我的智能手机' 成功认证"},
                {"time": time.time() - 3600 * 48, "type": "撤销", "description": "撤销了令牌 #token-123"}
            ]

            # 显示活动列表
            for i, activity in enumerate(activities):
                activity_time = time.strftime("%m-%d %H:%M", time.localtime(activity["time"]))
                activity_row = ttk.Frame(activities_frame)
                activity_row.pack(fill=tk.X, pady=(0, 5))

                ttk.Label(activity_row, text=activity_time, width=12).pack(side=tk.LEFT)

                # 根据类型设置标签样式
                type_text = f"[{activity['type']}]"
                type_label = ttk.Label(activity_row, text=type_text, width=10)
                type_label.pack(side=tk.LEFT, padx=5)

                ttk.Label(activity_row, text=activity["description"]).pack(side=tk.LEFT, padx=5)

            # 查看全部按钮
            ttk.Button(activity_card, text="查看全部活动", command=self.controller.show_audit_logs).pack(anchor=tk.W,
                                                                                                         pady=(10, 0))

        def edit_user_info(self):
            """编辑用户信息"""
            # 创建编辑对话框
            dialog = tk.Toplevel(self.controller)
            dialog.title("编辑用户信息")
            dialog.geometry("400x250")
            dialog.transient(self.controller)
            dialog.grab_set()

            # 对话框内容
            content_frame = ttk.Frame(dialog, padding=20)
            content_frame.pack(fill=tk.BOTH, expand=True)

            # 用户名
            ttk.Label(content_frame, text="用户名:").grid(row=0, column=0, sticky=tk.W, pady=10)
            username_var = tk.StringVar(value=self.controller.user_name)
            username_entry = ttk.Entry(content_frame, textvariable=username_var, width=30)
            username_entry.grid(row=0, column=1, sticky=tk.W, pady=10)

            # 邮箱
            ttk.Label(content_frame, text="邮箱:").grid(row=1, column=0, sticky=tk.W, pady=10)
            email_var = tk.StringVar(value="user@example.com")  # 假设值
            email_entry = ttk.Entry(content_frame, textvariable=email_var, width=30)
            email_entry.grid(row=1, column=1, sticky=tk.W, pady=10)

            # 公钥更新
            ttk.Label(content_frame, text="更新公钥:").grid(row=2, column=0, sticky=tk.W, pady=10)
            update_pubkey_var = tk.BooleanVar(value=False)
            update_pubkey_check = ttk.Checkbutton(content_frame, variable=update_pubkey_var)
            update_pubkey_check.grid(row=2, column=1, sticky=tk.W, pady=10)

            # 按钮区域
            btn_frame = ttk.Frame(content_frame)
            btn_frame.grid(row=3, column=0, columnspan=2, pady=20)

            ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
            ttk.Button(btn_frame, text="保存", command=lambda: self._save_user_info(username_var.get(), email_var.get(),
                                                                                    update_pubkey_var.get(),
                                                                                    dialog)).pack(side=tk.LEFT, padx=10)

        def _save_user_info(self, username, email, update_pubkey, dialog):
            """保存用户信息"""
            # 模拟保存操作
            if update_pubkey:
                # 如果需要更新公钥，应该打开新的对话框处理
                messagebox.showinfo("更新公钥", "公钥更新功能将在完整版中提供")

            # 更新用户名
            self.controller.user_name = username
            self.controller.user_info_var.set(f"用户: {username} | 角色: {self.controller.user_role}")

            messagebox.showinfo("成功", "用户信息已更新")
            dialog.destroy()

            # 刷新界面
            self.refresh()

        def refresh(self):
            """刷新面板数据"""
            # 重新加载面板
            self.cards_frame.destroy()

            # 创建卡片网格
            self.cards_frame = ttk.Frame(self.content_frame)
            self.cards_frame.pack(fill=tk.BOTH, expand=True)

            # 配置网格
            self.cards_frame.columnconfigure(0, weight=1)
            self.cards_frame.columnconfigure(1, weight=1)
            self.cards_frame.rowconfigure(0, weight=1)
            self.cards_frame.rowconfigure(1, weight=1)

            # 重新创建所有卡片
            self.create_user_info_card()
            self.create_device_overview_card()
            self.create_network_overview_card()
            self.create_recent_activity_card()


class NetworkManagementPanel(BasePanel):
    """网络管理面板"""

    def create_widgets(self):
        # 设置标题
        ttk.Label(self.title_frame, text="网络管理", style="Title.TLabel").pack(anchor=tk.W)

        # 工具栏
        toolbar = ttk.Frame(self.content_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        # 创建新网络按钮
        ttk.Button(toolbar, text="创建新网络", command=self.create_new_network).pack(side=tk.RIGHT, padx=5)

        # 创建网络列表
        self.create_networks_list()

    def create_networks_list(self):
        """创建网络列表"""
        # 列表容器
        list_frame = ttk.Frame(self.content_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        # 使网络列表可以水平扩展
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        # 创建网络卡片滚动区域
        self.networks_canvas = tk.Canvas(list_frame, background=COLORS["bg_light"])
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.networks_canvas.yview)
        self.networks_canvas.configure(yscrollcommand=scrollbar.set)

        # 布局
        self.networks_canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # 创建用于包含网络卡片的框架
        self.networks_frame = ttk.Frame(self.networks_canvas, style="TFrame")
        self.networks_canvas.create_window((0, 0), window=self.networks_frame, anchor="nw")

        # 配置网络框架以适应画布大小
        def configure_scroll_region(event):
            self.networks_canvas.configure(scrollregion=self.networks_canvas.bbox("all"))

        self.networks_frame.bind("<Configure>", configure_scroll_region)

        # 加载网络数据
        self.load_networks_data()

    def load_networks_data(self):
        """加载网络数据并创建网络卡片"""
        # 清空现有网络卡片
        for widget in self.networks_frame.winfo_children():
            widget.destroy()

        # 获取用户网络数据
        networks = self.controller.user_networks

        if not networks:
            # 显示无网络提示
            no_network_label = ttk.Label(
                self.networks_frame,
                text="没有创建的网络。点击创建新网络按钮来添加网络。",
            font = ("Arial", 12)
            )
            no_network_label.pack(pady=50)
            return

        # 为每个网络创建卡片
        for i, network in enumerate(networks):
            self.create_network_card(network, i)

    def create_network_card(self, network, index):
        """创建网络卡片"""
        # 卡片框架
        card = ttk.Frame(self.networks_frame, style="Card.TFrame", padding=15)
        card.pack(fill=tk.X, padx=20, pady=10)

        # 设置网格配置
        card.columnconfigure(0, weight=1)  # 让信息区域可以水平扩展
        card.columnconfigure(1, weight=0)  # 按钮区域固定宽度

        # 网络信息区域
        info_frame = ttk.Frame(card)
        info_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        # 网络名称（标题）
        network_name = network.get('name', '未命名网络')
        title_label = ttk.Label(info_frame, text=network_name, font=("Arial", 14, "bold"))
        title_label.pack(anchor=tk.W, pady=(0, 5))

        # 网络ID
        network_id = network.get('networkId', '未知ID')
        id_short = f"{network_id[:10]}...{network_id[-8:]}" if len(network_id) > 20 else network_id
        id_label = ttk.Label(info_frame, text=f"ID: {id_short}")
        id_label.pack(anchor=tk.W, pady=2)

        # 创建时间
        created_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(network.get('created_at', time.time())))
        created_label = ttk.Label(info_frame, text=f"创建时间: {created_time}")
        created_label.pack(anchor=tk.W, pady=2)

        # 状态
        status = "活跃" if network.get('is_active', False) else "已停用"
        status_label = ttk.Label(info_frame, text=f"状态: {status}")
        status_label.pack(anchor=tk.W, pady=2)

        # 已授权设备数量
        device_count = network.get('device_count', 0)
        device_label = ttk.Label(info_frame, text=f"已授权设备: {device_count}")
        device_label.pack(anchor=tk.W, pady=2)

        # 操作按钮区域
        btn_frame = ttk.Frame(card)
        btn_frame.grid(row=0, column=1, sticky="ne")

        # 更新按钮
        update_btn = ttk.Button(
            btn_frame,
            text="更新信息",
            command=lambda n=network: self.update_network_info(n)
        )
        update_btn.pack(pady=5)

        # 管理设备访问按钮
        access_btn = ttk.Button(
            btn_frame,
            text="管理访问权限",
            command=lambda n=network: self.manage_access(n)
        )
        access_btn.pack(pady=5)

        # 状态按钮（启用/停用）
        if network.get('is_active', False):
            status_btn = ttk.Button(
                btn_frame,
                text="停用网络",
                command=lambda n=network: self.deactivate_network(n)
            )
        else:
            status_btn = ttk.Button(
                btn_frame,
                text="启用网络",
                command=lambda n=network: self.activate_network(n)
            )
        status_btn.pack(pady=5)

        # 删除按钮
        delete_btn = ttk.Button(
            btn_frame,
            text="删除网络",
            command=lambda n=network: self.delete_network(n)
        )
        delete_btn.pack(pady=5)

    def create_new_network(self):
        """创建新网络"""
        # 创建对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title("创建新网络")
        dialog.geometry("400x200")
        dialog.transient(self.controller)
        dialog.grab_set()

        # 对话框内容
        content_frame = ttk.Frame(dialog, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 网络名称
        ttk.Label(content_frame, text="网络名称:").pack(anchor=tk.W, pady=10)
        name_var = tk.StringVar()
        name_entry = ttk.Entry(content_frame, textvariable=name_var, width=30)
        name_entry.pack(fill=tk.X, pady=5)

        # 网络描述（可选）
        ttk.Label(content_frame, text="网络描述(可选):").pack(anchor=tk.W, pady=10)
        desc_var = tk.StringVar()
        desc_entry = ttk.Entry(content_frame, textvariable=desc_var, width=30)
        desc_entry.pack(fill=tk.X, pady=5)

        # 按钮区域
        btn_frame = ttk.Frame(content_frame)
        btn_frame.pack(fill=tk.X, pady=20)

        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="创建", command=lambda: self._create_network(
            name_var.get(), desc_var.get(), dialog)).pack(side=tk.RIGHT, padx=10)

    def _create_network(self, name, description, dialog):
        """创建网络"""
        if not name:
            messagebox.showerror("错误", "请输入网络名称")
            return

        # 实际应调用智能合约
        # 模拟创建过程
        messagebox.showinfo("成功", f"网络 {name} 已创建")

        # 添加到网络列表
        new_network = {
            "networkId": f"net:{hashlib.sha256(name.encode()).hexdigest()}",
            "name": name,
            "description": description,
            "created_at": time.time(),
            "is_active": True,
            "device_count": 0
        }

        self.controller.user_networks.append(new_network)

        dialog.destroy()

        # 刷新网络列表
        self.load_networks_data()

    def update_network_info(self, network):
        """更新网络信息"""
        # 创建对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title(f"更新网络信息 - {network.get('name', '未命名网络')}")
        dialog.geometry("400x200")
        dialog.transient(self.controller)
        dialog.grab_set()

        # 对话框内容
        content_frame = ttk.Frame(dialog, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 网络ID显示
        ttk.Label(content_frame, text="网络ID:").pack(anchor=tk.W, pady=5)
        id_short = f"{network['networkId'][:10]}...{network['networkId'][-8:]}" if len(network['networkId']) > 20 else \
        network['networkId']
        ttk.Label(content_frame, text=id_short).pack(anchor=tk.W, pady=2)

        # 网络名称
        ttk.Label(content_frame, text="网络名称:").pack(anchor=tk.W, pady=10)
        name_var = tk.StringVar(value=network.get('name', ''))
        name_entry = ttk.Entry(content_frame, textvariable=name_var, width=30)
        name_entry.pack(fill=tk.X, pady=5)

        # 网络描述
        ttk.Label(content_frame, text="网络描述:").pack(anchor=tk.W, pady=10)
        desc_var = tk.StringVar(value=network.get('description', ''))
        desc_entry = ttk.Entry(content_frame, textvariable=desc_var, width=30)
        desc_entry.pack(fill=tk.X, pady=5)

        # 按钮区域
        btn_frame = ttk.Frame(content_frame)
        btn_frame.pack(fill=tk.X, pady=20)

        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="保存", command=lambda: self._save_network_changes(
            network, name_var.get(), desc_var.get(), dialog)).pack(side=tk.RIGHT, padx=10)

    def _save_network_changes(self, network, name, description, dialog):
        """保存网络更改"""
        if not name:
            messagebox.showerror("错误", "网络名称不能为空")
            return

        # 实际应调用智能合约
        # 模拟保存过程
        messagebox.showinfo("成功", f"网络 {name} 信息已更新")

        # 更新本地数据
        network['name'] = name
        network['description'] = description

        dialog.destroy()

        # 刷新网络列表
        self.load_networks_data()

    def manage_access(self, network):
        """管理网络访问权限"""
        # 创建对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title(f"管理访问权限 - {network.get('name', '未命名网络')}")
        dialog.geometry("700x500")
        dialog.transient(self.controller)
        dialog.grab_set()

        # 对话框内容
        content_frame = ttk.Frame(dialog, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 网络信息
        info_frame = ttk.Frame(content_frame)
        info_frame.pack(fill=tk.X, pady=10)

        ttk.Label(info_frame, text=f"网络: {network.get('name', '未命名网络')}", font=("Arial", 12, "bold")).pack(
            anchor=tk.W)
        ttk.Label(info_frame, text=f"ID: {network.get('networkId', '未知ID')[:10]}...").pack(anchor=tk.W)

        # 分隔线
        ttk.Separator(content_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

        # 设备访问权限表格
        table_frame = ttk.Frame(content_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 创建表格
        columns = ("设备名称", "设备ID", "状态", "访问权限", "操作")
        access_table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        # 设置列
        for col in columns:
            access_table.heading(col, text=col)
            if col in ("状态", "访问权限"):
                access_table.column(col, width=80, anchor=tk.CENTER)
            elif col == "操作":
                access_table.column(col, width=100, anchor=tk.CENTER)
            elif col == "设备ID":
                access_table.column(col, width=150)
            else:
                access_table.column(col, width=150)

        # 添加垂直滚动条
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=access_table.yview)
        access_table.configure(yscroll=scrollbar.set)

        # 布局
        access_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 添加测试数据
        devices = self.controller.user_devices

        for device in devices:
            # 模拟访问权限（实际应从区块链查询）
            has_access = bool(hash(device.get('did', '')) % 2)  # 随机模拟
            access_status = "已授权" if has_access else "未授权"

            # 设备ID缩短显示
            did_short = f"{device.get('did', '')[:8]}...{device.get('did', '')[-6:]}" if len(
                device.get('did', '')) > 20 else device.get('did', '')

            # 插入数据
            access_table.insert("", tk.END, values=(
                device.get('name', '未命名设备'),
                did_short,
                "活跃" if device.get('is_active', False) else "已停用",
                access_status,
                "授权/撤销"
            ), tags=(device.get('did', ''), "has_access" if has_access else "no_access"))

        # 绑定点击事件
        access_table.bind(
            "<Double-1>",
            lambda event, table=access_table, network2=network: self._toggle_device_access(event, table, network2)
        )

        # 底部按钮
        btn_frame = ttk.Frame(content_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            btn_frame,
            text="批量授权",
            command=lambda table=access_table, network2=network: self._batch_grant_access(table, network2)
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="批量撤销",
            command=lambda table=access_table, network2=network: self._batch_revoke_access(table, network2)
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="关闭",
            command=dialog.destroy
        ).pack(side=tk.RIGHT, padx=5)

    def _toggle_device_access(self, event, table, network):
        """切换设备访问权限"""
        region = table.identify("region", event.x, event.y)
        if region == "cell":
            # 获取选中的行
            selected_items = table.selection()
            if selected_items:
                item = selected_items[0]
                # 获取设备ID
                device_id = table.item(item, "tags")[0]
                # 获取列索引
                column = table.identify_column(event.x)
                column_index = int(column.replace('#', '')) - 1

                # 如果点击的是操作列
                if column_index == 4:  # "操作"列
                    # 获取当前权限状态
                    has_access = "has_access" in table.item(item, "tags")

                    # 切换权限
                    if has_access:
                        # 撤销权限
                        if messagebox.askyesno("确认", f"确定要撤销该设备的网络访问权限吗？"):
                            # 实际应调用智能合约
                            # 模拟撤销过程
                            messagebox.showinfo("成功", "已撤销设备的网络访问权限")

                            # 更新表格
                            values = list(table.item(item, "values"))
                            values[3] = "未授权"
                            table.item(item, values=values, tags=(device_id, "no_access"))
                    else:
                        # 授予权限
                        # 实际应调用智能合约
                        # 模拟授权过程
                        messagebox.showinfo("成功", "已授予设备网络访问权限")

                        # 更新表格
                        values = list(table.item(item, "values"))
                        values[3] = "已授权"
                        table.item(item, values=values, tags=(device_id, "has_access"))

    def _batch_grant_access(self, table, network):
        """批量授予访问权限"""
        # 获取选中的行
        selected_items = table.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择要授权的设备")
            return

        # 确认操作
        if messagebox.askyesno("确认",
                               f"确定要授予选中的 {len(selected_items)} 个设备访问 {network.get('name', '未命名网络')} 的权限吗？"):
            # 实际应调用智能合约
            # 模拟授权过程
            for item in selected_items:
                device_id = table.item(item, "tags")[0]

                # 更新表格
                values = list(table.item(item, "values"))
                values[3] = "已授权"
                table.item(item, values=values, tags=(device_id, "has_access"))

            messagebox.showinfo("成功", f"已授予 {len(selected_items)} 个设备的网络访问权限")

    def _batch_revoke_access(self, table, network):
        """批量撤销访问权限"""
        # 获取选中的行
        selected_items = table.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择要撤销权限的设备")
            return

        # 确认操作
        if messagebox.askyesno("确认",
                               f"确定要撤销选中的 {len(selected_items)} 个设备访问 {network.get('name', '未命名网络')} 的权限吗？"):
            # 实际应调用智能合约
            # 模拟撤销过程
            for item in selected_items:
                device_id = table.item(item, "tags")[0]

                # 更新表格
                values = list(table.item(item, "values"))
                values[3] = "未授权"
                table.item(item, values=values, tags=(device_id, "no_access"))

            messagebox.showinfo("成功", f"已撤销 {len(selected_items)} 个设备的网络访问权限")

    def deactivate_network(self, network):
        """停用网络"""
        if messagebox.askyesno("确认", f"确定要停用网络 {network.get('name', '未命名网络')} 吗？"):
            # 实际应调用智能合约
            # 模拟停用过程
            network['is_active'] = False
            messagebox.showinfo("成功", f"网络 {network.get('name', '未命名网络')} 已停用")

            # 刷新网络列表
            self.load_networks_data()

    def activate_network(self, network):
        """启用网络"""
        # 实际应调用智能合约
        # 模拟启用过程
        network['is_active'] = True
        messagebox.showinfo("成功", f"网络 {network.get('name', '未命名网络')} 已启用")

        # 刷新网络列表
        self.load_networks_data()

    def delete_network(self, network):
        """删除网络"""
        if messagebox.askyesno("确认", f"确定要删除网络 {network.get('name', '未命名网络')} 吗？此操作不可撤销！"):
            # 实际应调用智能合约
            # 模拟删除过程
            self.controller.user_networks.remove(network)
            messagebox.showinfo("成功", f"网络 {network.get('name', '未命名网络')} 已删除")

            # 刷新网络列表
            self.load_networks_data()

    def refresh(self):
        """刷新面板数据"""
        self.load_networks_data()


class AuthManagementPanel(BasePanel):
    """认证管理面板"""

    def create_widgets(self):
        # 设置标题
        ttk.Label(self.title_frame, text="认证管理", style="Title.TLabel").pack(anchor=tk.W)

        # 创建设备与网络选择区域
        self.create_selection_area()

        # 创建认证流程模拟区域
        self.create_auth_simulation()

    def create_selection_area(self):
        """创建设备与网络选择区域"""
        # 容器框架
        selection_frame = ttk.LabelFrame(self.content_frame, text="选择设备和网络")
        selection_frame.pack(fill=tk.X, pady=10)

        # 使用网格布局
        selection_frame.columnconfigure(0, weight=1)
        selection_frame.columnconfigure(1, weight=1)

        # 设备选择
        ttk.Label(selection_frame, text="选择设备:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.device_var = tk.StringVar()
        device_combo = ttk.Combobox(selection_frame, textvariable=self.device_var, width=40, state="readonly")
        device_combo.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)

        # 填充设备下拉列表
        device_options = []
        for device in self.controller.user_devices:
            if device.get('is_active', False):
                device_options.append(f"{device.get('name', '未命名设备')} ({device.get('device_type', '未知类型')})")

        device_combo['values'] = device_options if device_options else ["无可用设备"]
        if device_options:
            device_combo.current(0)

        # 网络选择
        ttk.Label(selection_frame, text="选择网络:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.network_var = tk.StringVar()
        network_combo = ttk.Combobox(selection_frame, textvariable=self.network_var, width=40, state="readonly")
        network_combo.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)

        # 填充网络下拉列表
        network_options = []
        for network in self.controller.user_networks:
            if network.get('is_active', False):
                network_options.append(f"{network.get('name', '未命名网络')}")

        network_combo['values'] = network_options if network_options else ["无可用网络"]
        if network_options:
            network_combo.current(0)

        # 访问管理按钮区域
        btn_frame = ttk.Frame(selection_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="检查访问权限", command=self.check_access).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="授予访问权限", command=self.grant_access).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="撤销访问权限", command=self.revoke_access).pack(side=tk.LEFT, padx=5)

    def create_auth_simulation(self):
        """创建认证流程模拟区域"""
        # 容器框架
        auth_frame = ttk.LabelFrame(self.content_frame, text="认证流程模拟")
        auth_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 使用网格布局
        auth_frame.columnconfigure(0, weight=1)

        # 步骤1: 生成挑战
        step1_frame = ttk.Frame(auth_frame)
        step1_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(step1_frame, text="步骤1: 生成挑战", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        ttk.Button(step1_frame, text="生成挑战", command=self.generate_challenge).pack(side=tk.RIGHT)

        # 挑战显示
        challenge_frame = ttk.Frame(auth_frame)
        challenge_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(challenge_frame, text="挑战值:").pack(side=tk.LEFT)
        self.challenge_var = tk.StringVar()
        challenge_entry = ttk.Entry(challenge_frame, textvariable=self.challenge_var, width=50, state="readonly")
        challenge_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # 步骤2: 签名挑战
        step2_frame = ttk.Frame(auth_frame)
        step2_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(step2_frame, text="步骤2: 签名挑战", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        ttk.Button(step2_frame, text="模拟签名", command=self.sign_challenge).pack(side=tk.RIGHT)

        # 签名显示
        signature_frame = ttk.Frame(auth_frame)
        signature_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(signature_frame, text="签名:").pack(side=tk.LEFT)
        self.signature_var = tk.StringVar()
        signature_entry = ttk.Entry(signature_frame, textvariable=self.signature_var, width=50)
        signature_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # 步骤3: 验证签名
        step3_frame = ttk.Frame(auth_frame)
        step3_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(step3_frame, text="步骤3: 验证签名", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        ttk.Button(step3_frame, text="验证认证", command=self.verify_authentication).pack(side=tk.RIGHT)

        # 令牌显示
        token_frame = ttk.Frame(auth_frame)
        token_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(token_frame, text="访问令牌:").pack(side=tk.LEFT)
        self.token_var = tk.StringVar()
        token_entry = ttk.Entry(token_frame, textvariable=self.token_var, width=50, state="readonly")
        token_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # 令牌管理
        token_mgmt_frame = ttk.Frame(auth_frame)
        token_mgmt_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(token_mgmt_frame, text="验证令牌", command=self.validate_token).pack(side=tk.LEFT, padx=5)
        ttk.Button(token_mgmt_frame, text="撤销令牌", command=self.revoke_token).pack(side=tk.LEFT, padx=5)

        # 状态显示
        status_frame = ttk.Frame(auth_frame)
        status_frame.pack(fill=tk.X, padx=10, pady=10)

        self.status_var = tk.StringVar(value="请选择设备和网络，然后开始认证流程")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, foreground="blue")
        status_label.pack(side=tk.LEFT, padx=5)

    def check_access(self):
        """检查设备对网络的访问权限"""
        device_name = self.device_var.get()
        network_name = self.network_var.get()

        if not device_name or not network_name or device_name == "无可用设备" or network_name == "无可用网络":
            messagebox.showwarning("警告", "请选择有效的设备和网络")
            return

        # 获取设备和网络对象
        device = self._get_selected_device()
        network = self._get_selected_network()

        if not device or not network:
            return

        # 实际应调用智能合约
        # 模拟检查过程
        # 随机模拟访问结果
        has_access = bool(hash(f"{device.get('did', '')}{network.get('networkId', '')}") % 2)

        if has_access:
            messagebox.showinfo("访问权限", f"设备 {device.get('name', '')} 有权访问网络 {network.get('name', '')}")
            self.status_var.set(f"设备 {device.get('name', '')} 有权访问网络 {network.get('name', '')}")
        else:
            messagebox.showwarning("访问权限",f"设备 {device.get('name', '')} 没有权限访问网络 {network.get('name', '')}")
            self.status_var.set(f"设备 {device.get('name', '')} 没有权限访问网络 {network.get('name', '')}")

    def grant_access(self):
        """授予设备对网络的访问权限"""
        device_name = self.device_var.get()
        network_name = self.network_var.get()

        if not device_name or not network_name or device_name == "无可用设备" or network_name == "无可用网络":
            messagebox.showwarning("警告", "请选择有效的设备和网络")
            return

        # 获取设备和网络对象
        device = self._get_selected_device()
        network = self._get_selected_network()

        if not device or not network:
            return

        # 实际应调用智能合约
        # 模拟授权过程
        messagebox.showinfo("成功", f"已授予设备{device.get('name', '')}访问网络{network.get('name', '')}的权限")
        self.status_var.set(f"已授予设备{device.get('name', '')}访问网络{network.get('name', '')}的权限")

        # 更新网络的设备计数（仅模拟）
        network['device_count'] = network.get('device_count', 0) + 1

    def revoke_access(self):
        """撤销设备对网络的访问权限"""
        device_name = self.device_var.get()
        network_name = self.network_var.get()

        if not device_name or not network_name or device_name == "无可用设备" or network_name == "无可用网络":
            messagebox.showwarning("警告", "请选择有效的设备和网络")
            return

        # 获取设备和网络对象
        device = self._get_selected_device()
        network = self._get_selected_network()

        if not device or not network:
            return

        # 实际应调用智能合约
        # 模拟撤销过程
        messagebox.showinfo("成功", f"已撤销设备{device.get('name', '')}访问网络{network.get('name', '')}的权限")
        self.status_var.set(f"已撤销设备{device.get('name', '')}访问网络{network.get('name', '')}的权限")

        # 更新网络的设备计数（仅模拟）
        if network.get('device_count', 0) > 0:
            network['device_count'] = network.get('device_count', 0) - 1

    def generate_challenge(self):
        """生成认证挑战"""
        device_name = self.device_var.get()
        network_name = self.network_var.get()

        if not device_name or not network_name or device_name == "无可用设备" or network_name == "无可用网络":
            messagebox.showwarning("警告", "请选择有效的设备和网络")
            return

        # 获取设备和网络对象
        device = self._get_selected_device()
        network = self._get_selected_network()

        if not device or not network:
            return

        # 检查设备是否有访问权限（实际应调用智能合约）
        # 这里暂时不检查，允许生成挑战

        # 更新状态
        self.status_var.set("正在生成挑战...")

        # 模拟生成挑战
        def simulate_challenge_generation():
            time.sleep(1)  # 模拟处理时间

            # 生成随机挑战
            challenge = f"0x{os.urandom(32).hex()}"

            # 更新UI
            self.after(0, lambda: self._update_challenge(challenge))

        # 在单独线程中执行
        threading.Thread(target=simulate_challenge_generation).start()

    def _update_challenge(self, challenge):
        """更新挑战值（在主线程中调用）"""
        self.challenge_var.set(challenge)
        self.status_var.set("挑战生成成功，请签名")

        # 清空之前的签名和令牌
        self.signature_var.set("")
        self.token_var.set("")

    def sign_challenge(self):
        """签名挑战"""
        challenge = self.challenge_var.get()
        if not challenge:
            messagebox.showwarning("警告", "请先生成挑战")
            return

        device = self._get_selected_device()
        if not device:
            return

        # 更新状态
        self.status_var.set("正在签名挑战...")

        # 模拟签名过程
        def simulate_signing():
            time.sleep(1)  # 模拟处理时间

            # 模拟签名（实际应使用设备私钥）
            # 在真实应用中，私钥应该安全存储在设备上
            signature = f"0x{hashlib.sha256((challenge + device.get('did', '')).encode()).hexdigest()}"

            # 更新UI
            self.after(0, lambda: self._update_signature(signature))

        # 在单独线程中执行
        threading.Thread(target=simulate_signing).start()

    def _update_signature(self, signature):
        """更新签名（在主线程中调用）"""
        self.signature_var.set(signature)
        self.status_var.set("签名成功，请验证认证")

    def verify_authentication(self):
        """验证认证并发放令牌"""
        challenge = self.challenge_var.get()
        signature = self.signature_var.get()

        if not challenge or not signature:
            messagebox.showwarning("警告", "请先生成挑战并签名")
            return

        device = self._get_selected_device()
        network = self._get_selected_network()

        if not device or not network:
            return

        # 更新状态
        self.status_var.set("正在验证认证...")

        # 模拟验证过程
        def simulate_verification():
            time.sleep(1.5)  # 模拟处理时间

            # 模拟验证结果
            # 在真实应用中，应该调用智能合约验证签名
            success = True  # 假设验证成功

            # 更新UI
            self.after(0, lambda: self._process_verification_result(success))

        # 在单独线程中执行
        threading.Thread(target=simulate_verification).start()

    def _process_verification_result(self, success):
        """处理验证结果（在主线程中调用）"""
        if success:
            # 生成访问令牌
            token = f"token-{int(time.time())}-{os.urandom(4).hex()}"
            self.token_var.set(token)
            self.status_var.set("认证成功，已获取访问令牌")
            messagebox.showinfo("认证成功", "设备已通过认证，已获取访问令牌")
        else:
            self.status_var.set("认证失败，请检查设备和挑战签名")
            messagebox.showerror("认证失败", "设备认证失败，请检查设备和挑战签名")

    def validate_token(self):
        """验证令牌有效性"""
        token = self.token_var.get()
        if not token:
            messagebox.showwarning("警告", "请先获取访问令牌")
            return

        # 更新状态
        self.status_var.set("正在验证令牌...")

        # 模拟验证过程
        def simulate_token_validation():
            time.sleep(1)  # 模拟处理时间

            # 模拟验证结果
            # 在真实应用中，应该调用智能合约验证令牌
            valid = True  # 假设令牌有效

            # 更新UI
            self.after(0, lambda: self._show_token_validation_result(valid))

        # 在单独线程中执行
        threading.Thread(target=simulate_token_validation).start()

    def _show_token_validation_result(self, valid):
        """显示令牌验证结果（在主线程中调用）"""
        if valid:
            self.status_var.set("令牌有效")
            messagebox.showinfo("令牌验证", "访问令牌有效")
        else:
            self.status_var.set("令牌无效或已过期")
            messagebox.showwarning("令牌验证", "访问令牌无效或已过期")

    def revoke_token(self):
        """撤销令牌"""
        token = self.token_var.get()
        if not token:
            messagebox.showwarning("警告", "请先获取访问令牌")
            return

        # 确认撤销
        if not messagebox.askyesno("确认", "确定要撤销此访问令牌吗？撤销后将无法使用此令牌进行认证。"):
            return

        # 更新状态
        self.status_var.set("正在撤销令牌...")

        # 模拟撤销过程
        def simulate_token_revocation():
            time.sleep(1)  # 模拟处理时间

            # 模拟撤销结果
            # 在真实应用中，应该调用智能合约撤销令牌
            success = True  # 假设撤销成功

            # 更新UI
            self.after(0, lambda: self._show_token_revocation_result(success))

        # 在单独线程中执行
        threading.Thread(target=simulate_token_revocation).start()

    def _show_token_revocation_result(self, success):
        """显示令牌撤销结果（在主线程中调用）"""
        if success:
            self.token_var.set("")
            self.status_var.set("令牌已成功撤销")
            messagebox.showinfo("令牌撤销", "访问令牌已成功撤销")
        else:
            self.status_var.set("令牌撤销失败")
            messagebox.showerror("令牌撤销", "访问令牌撤销失败")

    def _get_selected_device(self):
        """获取当前选中的设备对象"""
        device_name = self.device_var.get()
        if not device_name or device_name == "无可用设备":
            messagebox.showwarning("警告", "请选择有效的设备")
            return None

        # 从选择的名称中提取设备对象
        for device in self.controller.user_devices:
            device_display = f"{device.get('name', '未命名设备')} ({device.get('device_type', '未知类型')})"
            if device_display == device_name:
                return device

        messagebox.showerror("错误", "找不到选中的设备")
        return None

    def _get_selected_network(self):
        """获取当前选中的网络对象"""
        network_name = self.network_var.get()
        if not network_name or network_name == "无可用网络":
            messagebox.showwarning("警告", "请选择有效的网络")
            return None

        # 从选择的名称中提取网络对象
        for network in self.controller.user_networks:
            if network.get('name', '未命名网络') == network_name:
                return network

        messagebox.showerror("错误", "找不到选中的网络")
        return None

    def refresh(self):
        """刷新面板数据"""
        # 清空状态
        self.status_var.set("请选择设备和网络，然后开始认证流程")
        self.challenge_var.set("")
        self.signature_var.set("")
        self.token_var.set("")


class AuditLogsPanel(BasePanel):
    """审计日志面板"""

    def create_widgets(self):
        # 设置标题
        ttk.Label(self.title_frame, text="审计日志", style="Title.TLabel").pack(anchor=tk.W)

        # 创建过滤工具栏
        self.create_filter_toolbar()

        # 创建日志表格
        self.create_logs_table()

    def create_filter_toolbar(self):
        """创建过滤工具栏"""
        toolbar = ttk.Frame(self.content_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        # 设备过滤
        ttk.Label(toolbar, text="设备:").pack(side=tk.LEFT, padx=(0, 5))
        self.device_filter_var = tk.StringVar()
        device_combo = ttk.Combobox(toolbar, textvariable=self.device_filter_var, width=20, state="readonly")
        device_combo.pack(side=tk.LEFT, padx=5)

        # 填充设备下拉列表
        device_options = ["全部"]
        for device in self.controller.user_devices:
            device_options.append(device.get('name', '未命名设备'))

        device_combo['values'] = device_options
        device_combo.current(0)

        # 类型过滤
        ttk.Label(toolbar, text="类型:").pack(side=tk.LEFT, padx=(10, 5))
        self.type_filter_var = tk.StringVar()
        type_combo = ttk.Combobox(toolbar, textvariable=self.type_filter_var, width=15, state="readonly")
        type_combo.pack(side=tk.LEFT, padx=5)

        # 填充类型下拉列表
        type_combo['values'] = ["全部", "认证", "注册", "创建", "撤销"]
        type_combo.current(0)

        # 日期过滤
        ttk.Label(toolbar, text="日期:").pack(side=tk.LEFT, padx=(10, 5))
        self.date_filter_var = tk.StringVar()
        date_combo = ttk.Combobox(toolbar, textvariable=self.date_filter_var, width=15, state="readonly")
        date_combo.pack(side=tk.LEFT, padx=5)

        # 填充日期下拉列表
        date_combo['values'] = ["全部", "今天", "昨天", "本周", "本月"]
        date_combo.current(0)

        # 搜索按钮
        ttk.Button(toolbar, text="搜索", command=self.filter_logs).pack(side=tk.LEFT, padx=10)

        # 导出按钮
        ttk.Button(toolbar, text="导出日志", command=self.export_logs).pack(side=tk.RIGHT, padx=5)

    def create_logs_table(self):
        """创建日志表格"""
        # 表格容器
        table_frame = ttk.Frame(self.content_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)

        # 创建表格
        columns = ("时间", "设备", "网络", "类型", "描述", "结果")
        self.logs_table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        # 设置列
        for col in columns:
            self.logs_table.heading(col, text=col)
            if col in ("时间", "结果"):
                self.logs_table.column(col, width=120, anchor=tk.CENTER)
            elif col == "类型":
                self.logs_table.column(col, width=80, anchor=tk.CENTER)
            elif col == "描述":
                self.logs_table.column(col, width=300)
            else:
                self.logs_table.column(col, width=150)

        # 添加垂直滚动条
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.logs_table.yview)
        self.logs_table.configure(yscroll=scrollbar.set)

        # 布局
        self.logs_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定双击事件
        self.logs_table.bind("<Double-1>", self.show_log_details)

        # 加载日志数据
        self.load_logs_data()

    def load_logs_data(self):
        """加载日志数据"""
        # 清空表格
        for item in self.logs_table.get_children():
            self.logs_table.delete(item)

        # 模拟日志数据
        logs_data = self._generate_sample_logs()

        # 填充表格
        for log in logs_data:
            # 格式化时间
            log_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(log["timestamp"]))

            # 结果文本
            result_text = "成功" if log.get("success", True) else "失败"

            # 插入数据
            self.logs_table.insert("", tk.END, values=(
                log_time,
                log.get("device", "未知设备"),
                log.get("network", "未知网络"),
                log.get("type", "未知类型"),
                log.get("description", ""),
                result_text
            ), tags=(str(log.get("id", "")), "success" if log.get("success", True) else "failure"))

        # 设置行颜色
        self.logs_table.tag_configure("success", background="#e3ffe3")
        self.logs_table.tag_configure("failure", background="#ffe3e3")

    def _generate_sample_logs(self):
        """生成样本日志数据"""
        # 模拟日志数据
        logs = []

        # 获取设备和网络名称
        device_names = [d.get('name', '未命名设备') for d in self.controller.user_devices]
        network_names = [n.get('name', '未命名网络') for n in self.controller.user_networks]

        if not device_names:
            device_names = ["测试设备1", "测试设备2"]

        if not network_names:
            network_names = ["测试网络1", "测试网络2"]

        # 生成不同类型的日志
        log_types = ["认证", "注册", "创建", "撤销"]

        # 生成30条模拟日志
        for i in range(30):
            log_type = log_types[i % len(log_types)]
            device = device_names[i % len(device_names)]
            network = network_names[i % len(network_names)]
            success = True if i % 5 != 0 else False  # 约20%的失败率

            # 根据类型生成描述
            if log_type == "认证":
                description = f"设备 '{device}' 尝试访问网络 '{network}'"
            elif log_type == "注册":
                description = f"注册新设备 '{device}'"
            elif log_type == "创建":
                description = f"创建新网络 '{network}'"
            elif log_type == "撤销":
                description = f"撤销了设备 '{device}' 的令牌 #{i + 1000}"

            # 生成日志条目
            log = {
                "id": f"log_{i}",
                "timestamp": time.time() - (i * 3600),  # 每小时一条日志
                "device": device,
                "network": network,
                "type": log_type,
                "description": description,
                "success": success
            }

            logs.append(log)

        return logs

    def filter_logs(self):
        """过滤日志"""
        device_filter = self.device_filter_var.get()
        type_filter = self.type_filter_var.get()
        date_filter = self.date_filter_var.get()

        # 清空表格
        for item in self.logs_table.get_children():
            self.logs_table.delete(item)

        # 获取日志数据
        logs_data = self._generate_sample_logs()

        # 应用过滤器
        filtered_logs = []
        for log in logs_data:
            # 设备过滤
            if device_filter != "全部" and log.get("device", "") != device_filter:
                continue

            # 类型过滤
            if type_filter != "全部" and log.get("type", "") != type_filter:
                continue

            # 日期过滤
            if date_filter != "全部":
                log_time = time.localtime(log.get("timestamp", 0))
                current_time = time.localtime()

                if date_filter == "今天":
                    if log_time.tm_yday != current_time.tm_yday or log_time.tm_year != current_time.tm_year:
                        continue
                elif date_filter == "昨天":
                    yesterday = time.localtime(time.time() - 24 * 3600)
                    if log_time.tm_yday != yesterday.tm_yday or log_time.tm_year != yesterday.tm_year:
                        continue
                elif date_filter == "本周":
                    # 简化实现：假设今天与7天前之间的日志为本周
                    if log.get("timestamp", 0) < time.time() - 7 * 24 * 3600:
                        continue
                elif date_filter == "本月":
                    if log_time.tm_mon != current_time.tm_mon or log_time.tm_year != current_time.tm_year:
                        continue

            filtered_logs.append(log)

        # 填充表格
        for log in filtered_logs:
            # 格式化时间
            log_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(log["timestamp"]))

            # 结果文本
            result_text = "成功" if log.get("success", True) else "失败"

            # 插入数据
            self.logs_table.insert("", tk.END, values=(
                log_time,
                log.get("device", "未知设备"),
                log.get("network", "未知网络"),
                log.get("type", "未知类型"),
                log.get("description", ""),
                result_text
            ), tags=(str(log.get("id", "")), "success" if log.get("success", True) else "failure"))

    def show_log_details(self, event):
        """显示日志详情"""
        # 获取选中的行
        selected_items = self.logs_table.selection()
        if not selected_items:
            return

        item = selected_items[0]
        values = self.logs_table.item(item, "values")

        # 创建详情对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title("日志详情")
        dialog.geometry("500x300")
        dialog.transient(self.controller)
        dialog.grab_set()

        # 对话框内容
        content_frame = ttk.Frame(dialog, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 日志信息
        ttk.Label(content_frame, text="时间:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Label(content_frame, text=values[0]).grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(content_frame, text="设备:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(content_frame, text=values[1]).grid(row=1, column=1, sticky=tk.W, pady=5)

        ttk.Label(content_frame, text="网络:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Label(content_frame, text=values[2]).grid(row=2, column=1, sticky=tk.W, pady=5)

        ttk.Label(content_frame, text="类型:").grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Label(content_frame, text=values[3]).grid(row=3, column=1, sticky=tk.W, pady=5)

        ttk.Label(content_frame, text="描述:").grid(row=4, column=0, sticky=tk.W, pady=5)
        ttk.Label(content_frame, text=values[4], wraplength=350).grid(row=4, column=1, sticky=tk.W, pady=5)

        ttk.Label(content_frame, text="结果:").grid(row=5, column=0, sticky=tk.W, pady=5)
        result_label = ttk.Label(content_frame, text=values[5])
        result_label.grid(row=5, column=1, sticky=tk.W, pady=5)

        # 设置结果颜色
        if values[5] == "成功":
            result_label.configure(foreground="green")
        else:
            result_label.configure(foreground="red")

        # 交易哈希（模拟）
        ttk.Label(content_frame, text="交易哈希:").grid(row=6, column=0, sticky=tk.W, pady=5)
        tx_hash = f"0x{os.urandom(32).hex()}"
        ttk.Label(content_frame, text=tx_hash).grid(row=6, column=1, sticky=tk.W, pady=5)

        # 关闭按钮
        ttk.Button(content_frame, text="关闭", command=dialog.destroy).grid(row=7, column=0, columnspan=2, pady=20)

    def export_logs(self):
        """导出日志"""
        # 显示保存文件对话框
        file_path = simpledialog.askstring("导出日志", "请输入导出文件名:", initialvalue="audit_logs.csv")

        if not file_path:
            return

        # 确保文件有正确的扩展名
        if not file_path.endswith(".csv"):
            file_path += ".csv"

        try:
            # 获取日志数据
            logs_data = []
            for item in self.logs_table.get_children():
                values = self.logs_table.item(item, "values")
                logs_data.append(values)

            # 写入CSV文件
            with open(file_path, "w", newline="") as f:
                import csv
                writer = csv.writer(f)
                # 写入表头
                writer.writerow(["时间", "设备", "网络", "类型", "描述", "结果"])
                # 写入数据
                for log in logs_data:
                    writer.writerow(log)

            messagebox.showinfo("导出成功", f"审计日志已成功导出到 {file_path}")
        except Exception as e:
            messagebox.showerror("导出失败", f"导出日志时出错: {str(e)}")

    def refresh(self):
        """刷新面板数据"""
        self.load_logs_data()

    def refresh(self):
        """刷新面板数据"""

class SettingsPanel(BasePanel):
    """设置面板"""

    def create_widgets(self):
        # 设置标题
        ttk.Label(self.title_frame, text="系统设置", style="Title.TLabel").pack(anchor=tk.W)

        # 创建设置选项卡
        self.settings_notebook = ttk.Notebook(self.content_frame)
        self.settings_notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        # 创建各设置页面
        self.create_general_settings()
        self.create_blockchain_settings()
        self.create_security_settings()
        self.create_about_page()

    def create_general_settings(self):
        """创建常规设置页面"""
        general_frame = ttk.Frame(self.settings_notebook, padding=20)
        self.settings_notebook.add(general_frame, text="常规设置")

        # 语言设置
        ttk.Label(general_frame, text="界面语言:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W,
                                                                                    pady=10)
        language_var = tk.StringVar(value="简体中文")
        language_combo = ttk.Combobox(general_frame, textvariable=language_var, width=15, state="readonly")
        language_combo['values'] = ["简体中文", "English", "日本語"]
        language_combo.grid(row=0, column=1, sticky=tk.W, pady=10)

        # 主题设置
        ttk.Label(general_frame, text="界面主题:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W,
                                                                                    pady=10)
        theme_var = tk.StringVar(value="亮色")
        theme_combo = ttk.Combobox(general_frame, textvariable=theme_var, width=15, state="readonly")
        theme_combo['values'] = ["亮色", "暗色", "系统默认"]
        theme_combo.grid(row=1, column=1, sticky=tk.W, pady=10)

        # 日期格式设置
        ttk.Label(general_frame, text="日期格式:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W,
                                                                                    pady=10)
        date_format_var = tk.StringVar(value="YYYY-MM-DD")
        date_format_combo = ttk.Combobox(general_frame, textvariable=date_format_var, width=15, state="readonly")
        date_format_combo['values'] = ["YYYY-MM-DD", "MM/DD/YYYY", "DD/MM/YYYY"]
        date_format_combo.grid(row=2, column=1, sticky=tk.W, pady=10)

        # 日志保留时间
        ttk.Label(general_frame, text="日志保留时间:", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky=tk.W,
                                                                                        pady=10)
        log_retention_var = tk.StringVar(value="30天")
        log_retention_combo = ttk.Combobox(general_frame, textvariable=log_retention_var, width=15, state="readonly")
        log_retention_combo['values'] = ["7天", "30天", "90天", "180天", "永久"]
        log_retention_combo.grid(row=3, column=1, sticky=tk.W, pady=10)

        # 自动登出时间
        ttk.Label(general_frame, text="自动登出时间:", font=("Arial", 10, "bold")).grid(row=4, column=0, sticky=tk.W,
                                                                                        pady=10)
        logout_time_var = tk.StringVar(value="30分钟")
        logout_time_combo = ttk.Combobox(general_frame, textvariable=logout_time_var, width=15, state="readonly")
        logout_time_combo['values'] = ["从不", "5分钟", "15分钟", "30分钟", "60分钟"]
        logout_time_combo.grid(row=4, column=1, sticky=tk.W, pady=10)

        # 保存按钮
        ttk.Button(general_frame, text="保存设置", command=lambda: self._save_settings("常规设置")).grid(row=5,
                                                                                                         column=0,
                                                                                                         columnspan=2,
                                                                                                         pady=20)

    def create_blockchain_settings(self):
        """创建区块链设置页面"""
        blockchain_frame = ttk.Frame(self.settings_notebook, padding=20)
        self.settings_notebook.add(blockchain_frame, text="区块链设置")

        # 网络设置
        ttk.Label(blockchain_frame, text="默认网络:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W,
                                                                                       pady=10)
        network_var = tk.StringVar(value="本地测试网")
        network_combo = ttk.Combobox(blockchain_frame, textvariable=network_var, width=20, state="readonly")
        network_combo['values'] = ["本地测试网", "Sepolia测试网", "Ethereum主网"]
        network_combo.grid(row=0, column=1, sticky=tk.W, pady=10)

        # 节点URL
        ttk.Label(blockchain_frame, text="节点URL:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W,
                                                                                      pady=10)
        node_url_var = tk.StringVar(value="http://127.0.0.1:8545")
        node_url_entry = ttk.Entry(blockchain_frame, textvariable=node_url_var, width=40)
        node_url_entry.grid(row=1, column=1, sticky=tk.W, pady=10)

        # 合约地址
        ttk.Label(blockchain_frame, text="合约地址:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W,
                                                                                       pady=10)
        contract_addr_var = tk.StringVar(value="0x67d269191c92Caf3cD7723F116c85e6E9bf55933")
        contract_addr_entry = ttk.Entry(blockchain_frame, textvariable=contract_addr_var, width=40)
        contract_addr_entry.grid(row=2, column=1, sticky=tk.W, pady=10)

        # 交易确认数
        ttk.Label(blockchain_frame, text="交易确认数:", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky=tk.W,
                                                                                         pady=10)
        confirm_var = tk.StringVar(value="1")
        confirm_combo = ttk.Combobox(blockchain_frame, textvariable=confirm_var, width=10, state="readonly")
        confirm_combo['values'] = ["1", "2", "3", "5", "10"]
        confirm_combo.grid(row=3, column=1, sticky=tk.W, pady=10)

        # Gas价格策略
        ttk.Label(blockchain_frame, text="Gas价格策略:", font=("Arial", 10, "bold")).grid(row=4, column=0, sticky=tk.W,
                                                                                          pady=10)
        gas_var = tk.StringVar(value="标准")
        gas_combo = ttk.Combobox(blockchain_frame, textvariable=gas_var, width=10, state="readonly")
        gas_combo['values'] = ["经济", "标准", "快速"]
        gas_combo.grid(row=4, column=1, sticky=tk.W, pady=10)

        # 连接测试按钮
        ttk.Button(blockchain_frame, text="测试连接", command=self.test_blockchain_connection).grid(row=5, column=0,
                                                                                                    pady=5)

        # 保存按钮
        ttk.Button(blockchain_frame, text="保存设置", command=lambda: self._save_settings("区块链设置")).grid(row=5,
                                                                                                              column=1,
                                                                                                              pady=5)

    def create_security_settings(self):
        """创建安全设置页面"""
        security_frame = ttk.Frame(self.settings_notebook, padding=20)
        self.settings_notebook.add(security_frame, text="安全设置")

        # 密钥存储设置
        ttk.Label(security_frame, text="密钥存储方式:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W,
                                                                                         pady=10)
        key_storage_var = tk.StringVar(value="加密存储")
        key_storage_combo = ttk.Combobox(security_frame, textvariable=key_storage_var, width=20, state="readonly")
        key_storage_combo['values'] = ["不保存", "加密存储", "硬件钱包"]
        key_storage_combo.grid(row=0, column=1, sticky=tk.W, pady=10)

        # 加密算法
        ttk.Label(security_frame, text="加密算法:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W,
                                                                                     pady=10)
        encryption_var = tk.StringVar(value="AES-256")
        encryption_combo = ttk.Combobox(security_frame, textvariable=encryption_var, width=20, state="readonly")
        encryption_combo['values'] = ["AES-128", "AES-256", "ChaCha20"]
        encryption_combo.grid(row=1, column=1, sticky=tk.W, pady=10)

        # 会话有效期
        ttk.Label(security_frame, text="会话有效期:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W,
                                                                                       pady=10)
        session_var = tk.StringVar(value="24小时")
        session_combo = ttk.Combobox(security_frame, textvariable=session_var, width=20, state="readonly")
        session_combo['values'] = ["1小时", "8小时", "24小时", "7天"]
        session_combo.grid(row=2, column=1, sticky=tk.W, pady=10)

        # 挑战有效期
        ttk.Label(security_frame, text="挑战有效期:", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky=tk.W,
                                                                                       pady=10)
        challenge_var = tk.StringVar(value="5分钟")
        challenge_combo = ttk.Combobox(security_frame, textvariable=challenge_var, width=20, state="readonly")
        challenge_combo['values'] = ["1分钟", "5分钟", "10分钟", "15分钟"]
        challenge_combo.grid(row=3, column=1, sticky=tk.W, pady=10)

        # 令牌有效期
        ttk.Label(security_frame, text="令牌有效期:", font=("Arial", 10, "bold")).grid(row=4, column=0, sticky=tk.W,
                                                                                       pady=10)
        token_var = tk.StringVar(value="24小时")
        token_combo = ttk.Combobox(security_frame, textvariable=token_var, width=20, state="readonly")
        token_combo['values'] = ["1小时", "12小时", "24小时", "7天"]
        token_combo.grid(row=4, column=1, sticky=tk.W, pady=10)

        # 修改密码按钮
        ttk.Button(security_frame, text="修改加密密码", command=self.change_encryption_password).grid(row=5, column=0,
                                                                                                      pady=5)

        # 保存按钮
        ttk.Button(security_frame, text="保存设置", command=lambda: self._save_settings("安全设置")).grid(row=5,
                                                                                                          column=1,
                                                                                                          pady=5)

    def create_about_page(self):
        """创建关于页面"""
        about_frame = ttk.Frame(self.settings_notebook, padding=20)
        self.settings_notebook.add(about_frame, text="关于")

        # 应用标题
        ttk.Label(about_frame, text="区块链无线网络身份验证系统", font=("Arial", 16, "bold")).pack(pady=10)

        # 版本信息
        ttk.Label(about_frame, text="版本: 1.0.0").pack(pady=5)

        # 构建日期
        ttk.Label(about_frame, text="构建日期: 2025年4月27日").pack(pady=5)

        # 项目信息
        ttk.Label(about_frame, text="CSEC5615 云安全项目").pack(pady=5)

        # 团队成员
        team_frame = ttk.LabelFrame(about_frame, text="团队成员", padding=10)
        team_frame.pack(fill=tk.X, pady=10)

        ttk.Label(team_frame, text="Ilham Radito (540451423)").pack(anchor=tk.W)
        ttk.Label(team_frame, text="Senan Wang (540245855)").pack(anchor=tk.W)
        ttk.Label(team_frame, text="Tancy Yang (530452135)").pack(anchor=tk.W)

        # 系统信息
        system_frame = ttk.LabelFrame(about_frame, text="系统信息", padding=10)
        system_frame.pack(fill=tk.X, pady=10)

        import platform
        ttk.Label(system_frame, text=f"操作系统: {platform.system()} {platform.version()}").pack(anchor=tk.W)
        ttk.Label(system_frame, text=f"Python版本: {platform.python_version()}").pack(anchor=tk.W)
        ttk.Label(system_frame, text=f"处理器架构: {platform.machine()}").pack(anchor=tk.W)

        # 检查更新按钮
        update_btn = ttk.Button(about_frame, text="检查更新", command=self.check_for_updates)
        update_btn.pack(pady=20)

    def _save_settings(self, section):
        """保存设置"""
        messagebox.showinfo("保存设置", f"{section}已保存")

    def test_blockchain_connection(self):
        """测试区块链连接"""
        # 模拟连接测试
        self.status_var = tk.StringVar(value="正在测试连接...")

        # 创建一个进度对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title("连接测试")
        dialog.geometry("300x150")
        dialog.transient(self.controller)
        dialog.grab_set()

        # 对话框内容
        ttk.Label(dialog, text="正在测试区块链连接...", font=("Arial", 11)).pack(pady=10)

        # 进度条
        progress = ttk.Progressbar(dialog, mode="indeterminate", length=250)
        progress.pack(pady=10)
        progress.start()

        # 状态标签
        status_label = ttk.Label(dialog, textvariable=self.status_var)
        status_label.pack(pady=10)

        # 模拟连接测试过程
        def simulate_connection_test():
            time.sleep(2)  # 模拟处理时间

            # 模拟连接结果
            success = True  # 假设连接成功

            # 更新UI
            self.after(0, lambda: self._show_connection_result(success, dialog, progress))

        # 在单独线程中执行
        threading.Thread(target=simulate_connection_test).start()

    def _show_connection_result(self, success, dialog, progress):
        """显示连接测试结果（在主线程中调用）"""
        # 停止进度条
        progress.stop()

        if success:
            self.status_var.set("连接成功！当前区块高度: 12345678")
            messagebox.showinfo("连接测试", "区块链连接测试成功！")
        else:
            self.status_var.set("连接失败！请检查网络设置")
            messagebox.showerror("连接测试", "区块链连接测试失败！请检查网络设置")

        # 等待1秒后关闭对话框
        self.after(1000, dialog.destroy)

    def change_encryption_password(self):
        """修改加密密码"""
        # 创建密码修改对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title("修改加密密码")
        dialog.geometry("400x200")
        dialog.transient(self.controller)
        dialog.grab_set()

        # 对话框内容
        content_frame = ttk.Frame(dialog, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 当前密码
        ttk.Label(content_frame, text="当前密码:").grid(row=0, column=0, sticky=tk.W, pady=10)
        current_pwd_var = tk.StringVar()
        current_pwd_entry = ttk.Entry(content_frame, textvariable=current_pwd_var, width=30, show="*")
        current_pwd_entry.grid(row=0, column=1, sticky=tk.W, pady=10)

        # 新密码
        ttk.Label(content_frame, text="新密码:").grid(row=1, column=0, sticky=tk.W, pady=10)
        new_pwd_var = tk.StringVar()
        new_pwd_entry = ttk.Entry(content_frame, textvariable=new_pwd_var, width=30, show="*")
        new_pwd_entry.grid(row=1, column=1, sticky=tk.W, pady=10)

        # 确认新密码
        ttk.Label(content_frame, text="确认新密码:").grid(row=2, column=0, sticky=tk.W, pady=10)
        confirm_pwd_var = tk.StringVar()
        confirm_pwd_entry = ttk.Entry(content_frame, textvariable=confirm_pwd_var, width=30, show="*")
        confirm_pwd_entry.grid(row=2, column=1, sticky=tk.W, pady=10)

        # 按钮区域
        btn_frame = ttk.Frame(content_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="确认修改", command=lambda: self._change_password(
            current_pwd_var.get(), new_pwd_var.get(), confirm_pwd_var.get(), dialog)).pack(side=tk.LEFT, padx=10)

    def _change_password(self, current_pwd, new_pwd, confirm_pwd, dialog):
        """修改密码"""
        # 验证密码
        if not current_pwd:
            messagebox.showerror("错误", "请输入当前密码")
            return

        if not new_pwd:
            messagebox.showerror("错误", "请输入新密码")
            return

        if new_pwd != confirm_pwd:
            messagebox.showerror("错误", "两次输入的新密码不一致")
            return

        # 模拟密码修改过程
        if current_pwd != "password":  # 假设当前密码是"password"
            messagebox.showerror("错误", "当前密码不正确")
            return

        # 密码修改成功
        messagebox.showinfo("成功", "加密密码已成功修改")
        dialog.destroy()

    def check_for_updates(self):
        """检查更新"""
        # 创建进度对话框
        dialog = tk.Toplevel(self.controller)
        dialog.title("检查更新")
        dialog.geometry("300x150")
        dialog.transient(self.controller)
        dialog.grab_set()

        # 对话框内容
        ttk.Label(dialog, text="正在检查更新...", font=("Arial", 11)).pack(pady=10)

        # 进度条
        progress = ttk.Progressbar(dialog, mode="indeterminate", length=250)
        progress.pack(pady=10)
        progress.start()

        # 状态变量
        update_status_var = tk.StringVar(value="连接服务器...")
        status_label = ttk.Label(dialog, textvariable=update_status_var)
        status_label.pack(pady=10)

        # 模拟更新检查过程
        def simulate_update_check():
            # 模拟检查步骤
            time.sleep(1)
            self.after(0, lambda: update_status_var.set("检查当前版本..."))
            time.sleep(1)
            self.after(0, lambda: update_status_var.set("查询最新版本..."))
            time.sleep(1)

            # 模拟检查结果
            has_update = False  # 假设没有更新

            # 更新UI
            self.after(0, lambda: self._show_update_result(has_update, dialog, progress))

        # 在单独线程中执行
        threading.Thread(target=simulate_update_check).start()

    def _show_update_result(self, has_update, dialog, progress):
        """显示更新检查结果（在主线程中调用）"""
        # 停止进度条
        progress.stop()
        dialog.destroy()

        if has_update:
            result = messagebox.askyesno("发现新版本", "发现新版本 1.1.0，是否现在更新？")
            if result:
                messagebox.showinfo("更新", "更新功能将在完整版中提供")
        else:
            messagebox.showinfo("检查更新", "您当前使用的是最新版本")

    def refresh(self):
        """刷新面板数据"""
        pass


if __name__ == "__main__":
    # 这里可以添加测试代码
    app = MainWindow("0x123456789abcdef", "SYSTEM_ADMIN")
    app.mainloop()