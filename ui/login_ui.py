"""
区块链无线网络身份验证系统 - 登录界面
"""

import os
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import hashlib
import threading
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct

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


class LoginUI(tk.Tk):
    """登录界面主窗口"""

    def __init__(self):
        super().__init__()

        # 窗口设置
        self.title("区块链无线网络身份验证系统")
        self.geometry("900x600")
        self.resizable(True, True)
        self.minsize(900, 600)

        # 状态变量
        self.client = None
        self.current_user = None
        self.current_role = None

        # 创建样式
        self.create_styles()

        # 创建框架容器
        self.container = ttk.Frame(self)
        self.container.pack(fill=tk.BOTH, expand=True)

        # 初始化不同页面
        self.frames = {}

        # 创建页面框架
        for F in (LoginFrame, RegisterFrame, RequestAuthFrame):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # 配置容器网格
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        # 显示登录页面
        self.show_frame(LoginFrame)

        # 尝试自动连接区块链
        self.connect_blockchain()

    def create_styles(self):
        """创建自定义样式"""
        style = ttk.Style()

        # 配置主题颜色
        style.configure("TFrame", background=COLORS["bg_light"])
        style.configure("TLabel", background=COLORS["bg_light"], foreground=COLORS["text_dark"])
        style.configure("TButton", background=COLORS["primary"], foreground=COLORS["text_dark"])

        # 标题标签样式
        style.configure("Title.TLabel", font=("Arial", 24, "bold"), foreground=COLORS["primary"])

        # 子标题标签样式
        style.configure("Subtitle.TLabel", font=("Arial", 16), foreground=COLORS["text_dark"])

        # 主按钮样式
        style.configure("Primary.TButton", background=COLORS["primary"], foreground=COLORS["text_dark"])

        # 次要按钮样式
        style.configure("Secondary.TButton", background=COLORS["secondary"], foreground=COLORS["text_dark"])

        # 危险按钮样式
        style.configure("Danger.TButton", background=COLORS["accent"], foreground=COLORS["text_dark"])

        # 信息卡片样式
        style.configure("Card.TFrame", background=COLORS["bg_light"], relief="raised", borderwidth=1)

    def show_frame(self, frame_class):
        """切换显示的框架"""
        frame = self.frames[frame_class]
        frame.tkraise()
        # 如果框架有refresh方法，调用它
        if hasattr(frame, 'refresh'):
            frame.refresh()

    def connect_blockchain(self):
        """连接到区块链网络"""
        # 这里应该有连接到区块链的逻辑
        # 实际应用中，这里会与Python/test_identity.py中的IdentityChainClient连接
        pass

    def handle_login_success(self, user_address, user_role):
        """处理登录成功"""
        self.current_user = user_address
        self.current_role = user_role

        # 保存登录会话信息
        self.save_session(user_address, user_role)

        # 启动主应用（此处应该启动主界面）
        self.start_main_application()

    def save_session(self, user_address, user_role):
        """保存用户会话"""
        session = {
            "user_address": user_address,
            "user_role": user_role,
            "login_time": time.time(),
            "expires_at": time.time() + 24 * 60 * 60  # 24小时有效期
        }

        try:
            with open("session.json", "w") as f:
                json.dump(session, f)
        except Exception as e:
            print(f"保存会话失败: {str(e)}")

    def check_saved_session(self):
        """检查是否有有效的保存会话"""
        try:
            if os.path.exists("session.json"):
                with open("session.json", "r") as f:
                    session = json.load(f)

                # 检查会话是否过期
                if session.get("expires_at", 0) > time.time():
                    self.current_user = session.get("user_address")
                    self.current_role = session.get("user_role")
                    return True

            return False
        except Exception as e:
            print(f"读取会话失败: {str(e)}")
            return False

    def start_main_application(self):
        """启动主应用"""
        # 这里应该启动主窗口的代码
        messagebox.showinfo("登录成功", f"用户 {self.current_user} 成功登录!\n角色: {self.current_role}")
        # 实际应用中应该打开主窗口
        # 例如: main_window = MainWindow(self.current_user, self.current_role, self.client)
        #       main_window.mainloop()
        #       self.destroy()


class LoginFrame(ttk.Frame):
    """登录页面"""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.challenge = None
        self.challenge_expiry = None

        # 创建布局
        self.create_widgets()

    def create_widgets(self):
        """创建登录界面控件"""
        # 主容器 - 使用Grid布局
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 创建登录卡片框架
        login_card = ttk.Frame(self, style="Card.TFrame", padding=20)
        login_card.grid(row=0, column=0, padx=100, pady=50, sticky="nsew")

        # 登录卡片内布局
        login_card.grid_columnconfigure(0, weight=1)
        login_card.grid_columnconfigure(1, weight=3)

        # 标题
        ttk.Label(login_card, text="用户登录", style="Title.TLabel").grid(row=0, column=0, columnspan=2, pady=20,
                                                                          sticky="n")

        # 用户地址输入
        ttk.Label(login_card, text="用户名:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.address_var = tk.StringVar()
        address_entry = ttk.Entry(login_card, textvariable=self.address_var, width=40)
        address_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        # 私钥输入
        ttk.Label(login_card, text="私钥:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.private_key_var = tk.StringVar()
        private_key_entry = ttk.Entry(login_card, textvariable=self.private_key_var, width=40, show="*")
        private_key_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        # 记住私钥选项
        self.remember_var = tk.BooleanVar(value=False)
        remember_check = ttk.Checkbutton(login_card, text="记住私钥", variable=self.remember_var)
        remember_check.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        # 生成挑战按钮
        generate_btn = ttk.Button(login_card, text="生成登录挑战", command=self.generate_challenge,
                                  style="Primary.TButton")
        generate_btn.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

        # 挑战值显示
        ttk.Label(login_card, text="挑战值:").grid(row=5, column=0, padx=10, pady=10, sticky="e")
        self.challenge_var = tk.StringVar()
        challenge_entry = ttk.Entry(login_card, textvariable=self.challenge_var, width=50, state="readonly")
        challenge_entry.grid(row=5, column=1, padx=10, pady=10, sticky="w")

        # 签名按钮
        sign_btn = ttk.Button(login_card, text="签名挑战", command=self.sign_challenge, style="Secondary.TButton")
        sign_btn.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

        # 签名结果显示
        ttk.Label(login_card, text="签名:").grid(row=7, column=0, padx=10, pady=10, sticky="e")
        self.signature_var = tk.StringVar()
        signature_entry = ttk.Entry(login_card, textvariable=self.signature_var, width=50)
        signature_entry.grid(row=7, column=1, padx=10, pady=10, sticky="w")

        # 登录按钮
        login_btn = ttk.Button(login_card, text="验证并登录", command=self.verify_login, style="Primary.TButton")
        login_btn.grid(row=8, column=0, columnspan=2, padx=10, pady=20)

        # # 状态信息
        self.status_var = tk.StringVar(value="请输入用户地址和私钥")
        # status_label = ttk.Label(login_card, textvariable=self.status_var)
        # status_label.grid(row=9, column=0, columnspan=2, pady=10)

        # 切换到注册按钮
        register_btn = ttk.Button(
            login_card,
            text="没有账户？点击注册",
            command=lambda: self.controller.show_frame(RegisterFrame)
        )
        register_btn.grid(row=10, column=0, columnspan=2, pady=10)

        # 切换到申请授权按钮
        request_auth_btn = ttk.Button(
            login_card,
            text="需要授权？申请管理员授权",
            command=lambda: self.controller.show_frame(RequestAuthFrame)
        )
        request_auth_btn.grid(row=11, column=0, columnspan=2, pady=10)

    def refresh(self):
        """刷新页面数据"""
        # 清空输入框
        self.challenge_var.set("")
        self.signature_var.set("")
        self.status_var.set("请输入用户地址和私钥")

        # 从本地存储加载地址和私钥（如果之前保存了）
        self.load_saved_credentials()

    def load_saved_credentials(self):
        """从本地加载保存的凭证"""
        try:
            if os.path.exists("credentials.json"):
                with open("credentials.json", "r") as f:
                    credentials = json.load(f)
                    self.address_var.set(credentials.get("address", ""))

                    # 实际应用中应该解密私钥
                    private_key = credentials.get("private_key", "")
                    if private_key:
                        # 这里应该添加解密逻辑
                        self.private_key_var.set(private_key)
                        self.remember_var.set(True)
        except Exception as e:
            print(f"加载凭证失败: {str(e)}")

    def save_credentials(self):
        """保存凭证到本地"""
        if self.remember_var.get():
            credentials = {
                "address": self.address_var.get(),
                "private_key": self.private_key_var.get()  # 实际应用中应该加密私钥
            }

            try:
                with open("credentials.json", "w") as f:
                    json.dump(credentials, f)
            except Exception as e:
                print(f"保存凭证失败: {str(e)}")

    def generate_challenge(self):
        """生成登录挑战"""
        address = self.address_var.get()
        if not address:
            self.status_var.set("请输入用户地址")
            return

        try:
            # 实际应该调用智能合约生成挑战
            # 以下是模拟逻辑
            self.status_var.set("正在生成挑战...")

            # 模拟区块链调用延迟
            def simulate_contract_call():
                # 模拟生成挑战
                challenge = Web3.keccak(text=f"login_{address}_{time.time()}").hex()
                expiry = time.time() + 5 * 60  # 5分钟过期

                # 在主线程更新UI
                self.after(1000, lambda: self._update_challenge(challenge, expiry))

            # 在单独线程中执行模拟调用
            threading.Thread(target=simulate_contract_call).start()

        except Exception as e:
            self.status_var.set(f"生成挑战失败: {str(e)}")

    def _update_challenge(self, challenge, expiry):
        """更新挑战值（在主线程中调用）"""
        self.challenge = challenge
        self.challenge_expiry = expiry
        self.challenge_var.set(challenge)
        self.status_var.set("挑战生成成功，请签名")

    def sign_challenge(self):
        """签名挑战"""
        if not self.challenge:
            self.status_var.set("请先生成挑战")
            return

        private_key = self.private_key_var.get()
        if not private_key:
            self.status_var.set("请输入私钥")
            return

        try:
            # 状态更新
            self.status_var.set("正在签名...")

            # 模拟签名过程
            def simulate_signing():
                time.sleep(1)  # 模拟处理时间

                # 生成一个模拟的签名
                # 实际应用中应该使用私钥对挑战进行签名
                signature = f"0x{hashlib.sha256((self.challenge + private_key).encode()).hexdigest()}"

                # 在主线程更新UI
                self.after(0, lambda: self._update_signature(signature))

            # 在单独线程中执行
            threading.Thread(target=simulate_signing).start()

        except Exception as e:
            self.status_var.set(f"签名失败: {str(e)}")

    def _update_signature(self, signature):
        """更新签名（在主线程中调用）"""
        self.signature_var.set(signature)
        self.status_var.set("签名成功，请验证登录")

    def verify_login(self):
        """验证登录"""
        if not self.challenge or not self.signature_var.get():
            self.status_var.set("请先生成挑战并签名")
            return

        # 检查挑战是否过期
        if time.time() > self.challenge_expiry:
            self.status_var.set("挑战已过期，请重新生成")
            return

        try:
            address = self.address_var.get()
            signature = self.signature_var.get()

            # 更新状态
            self.status_var.set("正在验证登录...")

            # 模拟验证过程
            def simulate_verification():
                time.sleep(1.5)  # 模拟处理时间

                # 模拟验证结果
                # 实际应用中应该调用智能合约验证签名
                success = True  # 假设验证成功
                user_role = "USER"  # 假设用户角色

                # 在主线程更新UI
                self.after(0, lambda: self._process_verification_result(success, address, user_role))

            # 在单独线程中执行
            threading.Thread(target=simulate_verification).start()

        except Exception as e:
            self.status_var.set(f"验证失败: {str(e)}")

    def _process_verification_result(self, success, address, user_role):
        """处理验证结果（在主线程中调用）"""
        if success:
            self.status_var.set("登录成功!")

            # 如果选择记住凭证，保存到本地
            self.save_credentials()

            # 通知控制器登录成功
            self.controller.handle_login_success(address, user_role)
        else:
            self.status_var.set("登录验证失败，请检查地址和私钥")


class RegisterFrame(ttk.Frame):
    """注册页面"""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # 创建布局
        self.create_widgets()

    def create_widgets(self):
        """创建注册界面控件"""
        # 主容器 - 使用Grid布局
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 创建注册卡片框架
        register_card = ttk.Frame(self, style="Card.TFrame", padding=20)
        register_card.grid(row=0, column=0, padx=100, pady=50, sticky="nsew")

        # 注册卡片内布局
        register_card.grid_columnconfigure(0, weight=1)
        register_card.grid_columnconfigure(1, weight=3)

        # 标题
        ttk.Label(register_card, text="用户注册", style="Title.TLabel").grid(row=0, column=0, columnspan=2, pady=20,
                                                                             sticky="n")

        # 用户名输入
        ttk.Label(register_card, text="用户名:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(register_card, textvariable=self.username_var, width=40)
        username_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        # 邮箱输入
        ttk.Label(register_card, text="邮箱:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.email_var = tk.StringVar()
        email_entry = ttk.Entry(register_card, textvariable=self.email_var, width=40)
        email_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        # 密钥对管理区域
        key_frame = ttk.LabelFrame(register_card, text="密钥管理", padding=10)
        key_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        # 生成/导入密钥按钮
        key_btn_frame = ttk.Frame(key_frame)
        key_btn_frame.pack(fill=tk.X, pady=5)

        generate_key_btn = ttk.Button(key_btn_frame, text="生成新密钥对", command=self.generate_key_pair)
        generate_key_btn.pack(side=tk.LEFT, padx=5)

        import_key_btn = ttk.Button(key_btn_frame, text="导入已有私钥", command=self.import_private_key)
        import_key_btn.pack(side=tk.LEFT, padx=5)

        # 公钥显示
        ttk.Label(key_frame, text="公钥:").pack(anchor=tk.W, pady=5)
        self.public_key_var = tk.StringVar()
        public_key_entry = ttk.Entry(key_frame, textvariable=self.public_key_var, width=60, state="readonly")
        public_key_entry.pack(fill=tk.X, pady=2)

        # 私钥显示（警告信息）
        ttk.Label(key_frame, text="私钥(请妥善保管，不要分享):").pack(anchor=tk.W, pady=5)
        self.private_key_var = tk.StringVar()
        private_key_entry = ttk.Entry(key_frame, textvariable=self.private_key_var, width=60, show="*")
        private_key_entry.pack(fill=tk.X, pady=2)

        # 显示/隐藏私钥的复选框
        self.show_key_var = tk.BooleanVar(value=False)
        show_key_check = ttk.Checkbutton(
            key_frame,
            text="显示私钥",
            variable=self.show_key_var,
            command=lambda: self._toggle_private_key_visibility(private_key_entry)
        )
        show_key_check.pack(anchor=tk.W, pady=5)

        # 注册按钮
        register_btn = ttk.Button(register_card, text="注册", command=self.register_user, style="Primary.TButton")
        register_btn.grid(row=4, column=0, columnspan=2, padx=10, pady=20)

        # 状态信息
        self.status_var = tk.StringVar(value="请填写注册信息")
        status_label = ttk.Label(register_card, textvariable=self.status_var)
        status_label.grid(row=5, column=0, columnspan=2, pady=10)

        # 切换到登录按钮
        login_btn = ttk.Button(
            register_card,
            text="已有账户？返回登录",
            command=lambda: self.controller.show_frame(LoginFrame)
        )
        login_btn.grid(row=6, column=0, columnspan=2, pady=10)

    def refresh(self):
        """刷新页面数据"""
        # 清空输入框
        self.username_var.set("")
        self.email_var.set("")
        self.public_key_var.set("")
        self.private_key_var.set("")
        self.status_var.set("请填写注册信息")

    def generate_key_pair(self):
        """生成新的密钥对"""
        try:
            # 更新状态
            self.status_var.set("正在生成密钥对...")

            # 模拟密钥对生成
            def simulate_key_generation():
                time.sleep(1)  # 模拟处理时间

                # 实际应用中应该使用合适的密钥生成方法
                # 例如 Account.create()
                private_key = f"0x{os.urandom(32).hex()}"
                public_key = f"0x{hashlib.sha256(private_key.encode()).hexdigest()}"

                # 在主线程更新UI
                self.after(0, lambda: self._update_key_pair(private_key, public_key))

            # 在单独线程中执行
            threading.Thread(target=simulate_key_generation).start()

        except Exception as e:
            self.status_var.set(f"生成密钥对失败: {str(e)}")

    def _update_key_pair(self, private_key, public_key):
        """更新密钥对（在主线程中调用）"""
        self.private_key_var.set(private_key)
        self.public_key_var.set(public_key)
        self.status_var.set("密钥对生成成功，请妥善保管私钥")

    def import_private_key(self):
        """导入已有私钥"""
        private_key = simpledialog.askstring("导入私钥", "请输入您的私钥:", show="*")
        if not private_key:
            return

        try:
            # 验证私钥格式
            if not private_key.startswith("0x"):
                private_key = f"0x{private_key}"

            # 从私钥生成公钥
            # 实际应用中应该使用正确的方法
            # 例如 Account.from_key(private_key).address
            public_key = f"0x{hashlib.sha256(private_key.encode()).hexdigest()}"

            # 更新UI
            self.private_key_var.set(private_key)
            self.public_key_var.set(public_key)
            self.status_var.set("私钥导入成功")
        except Exception as e:
            self.status_var.set(f"导入私钥失败: {str(e)}")

    def _toggle_private_key_visibility(self, entry_widget):
        """切换私钥显示/隐藏"""
        if self.show_key_var.get():
            entry_widget.config(show="")
        else:
            entry_widget.config(show="*")

    def register_user(self):
        """注册用户"""
        username = self.username_var.get()
        email = self.email_var.get()
        private_key = self.private_key_var.get()
        public_key = self.public_key_var.get()

        # 验证输入
        if not username or not private_key or not public_key:
            self.status_var.set("请输入用户名并生成/导入密钥对")
            return

        try:
            # 更新状态
            self.status_var.set("正在注册...")

            # 模拟注册过程
            def simulate_registration():
                time.sleep(2)  # 模拟处理时间

                # 模拟注册结果
                # 实际应用中应该调用智能合约进行注册
                success = True  # 假设注册成功

                # 在主线程更新UI
                self.after(0, lambda: self._process_registration_result(success, username))

            # 在单独线程中执行
            threading.Thread(target=simulate_registration).start()

        except Exception as e:
            self.status_var.set(f"注册失败: {str(e)}")

    def _process_registration_result(self, success, username):
        """处理注册结果（在主线程中调用）"""
        if success:
            self.status_var.set(f"用户 {username} 注册成功!")
            messagebox.showinfo("注册成功", f"用户 {username} 已成功注册!\n请保存您的私钥，然后返回登录页面。")

            # 切换回登录页面
            self.controller.show_frame(LoginFrame)
        else:
            self.status_var.set("注册失败，请稍后重试")


class RequestAuthFrame(ttk.Frame):
    """申请授权页面"""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # 创建布局
        self.create_widgets()

    def create_widgets(self):
        """创建申请授权界面控件"""
        # 主容器 - 使用Grid布局
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 创建申请卡片框架
        request_card = ttk.Frame(self, style="Card.TFrame", padding=20)
        request_card.grid(row=0, column=0, padx=100, pady=50, sticky="nsew")

        # 申请卡片内布局
        request_card.grid_columnconfigure(0, weight=1)
        request_card.grid_columnconfigure(1, weight=3)

        # 标题
        ttk.Label(request_card, text="申请管理员授权", style="Title.TLabel").grid(row=0, column=0, columnspan=2,
                                                                                  pady=20, sticky="n")

        # 说明文本
        info_text = "如果您需要注册新用户但没有管理员授权，可以通过此页面申请授权。\n"
        info_text += "请填写以下信息，系统会将您的请求发送给管理员处理。"
        info_label = ttk.Label(request_card, text=info_text, wraplength=500, justify="center")
        info_label.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

        # 用户名输入
        ttk.Label(request_card, text="用户名:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.req_username_var = tk.StringVar()
        username_entry = ttk.Entry(request_card, textvariable=self.req_username_var, width=40)
        username_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        # 邮箱输入
        ttk.Label(request_card, text="邮箱:").grid(row=3, column=0, padx=10, pady=10, sticky="e")
        self.req_email_var = tk.StringVar()
        email_entry = ttk.Entry(request_card, textvariable=self.req_email_var, width=40)
        email_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

        # 公钥输入
        ttk.Label(request_card, text="公钥:").grid(row=4, column=0, padx=10, pady=10, sticky="e")
        self.req_pubkey_var = tk.StringVar()
        pubkey_entry = ttk.Entry(request_card, textvariable=self.req_pubkey_var, width=40)
        pubkey_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")

        # 生成公钥按钮
        generate_btn = ttk.Button(request_card, text="生成新密钥对", command=self.generate_key_pair)
        generate_btn.grid(row=5, column=1, padx=10, pady=5, sticky="w")

        # 管理员选择
        ttk.Label(request_card, text="授权管理员:").grid(row=6, column=0, padx=10, pady=10, sticky="e")
        self.admin_var = tk.StringVar()
        admin_combo = ttk.Combobox(request_card, textvariable=self.admin_var, width=40, state="readonly")
        admin_combo.grid(row=6, column=1, padx=10, pady=10, sticky="w")

        # 加载管理员列表（假设的值，实际应从区块链获取）
        admin_combo['values'] = ["系统管理员 (0x123...)", "网络管理员1 (0x456...)", "网络管理员2 (0x789...)"]

        # 请求理由
        ttk.Label(request_card, text="请求理由:").grid(row=7, column=0, padx=10, pady=10, sticky="ne")
        self.reason_var = tk.StringVar()
        reason_text = tk.Text(request_card, width=40, height=4)
        reason_text.grid(row=7, column=1, padx=10, pady=10, sticky="w")

        # 提交申请按钮
        submit_btn = ttk.Button(request_card, text="提交申请", command=self.submit_request, style="Primary.TButton")
        submit_btn.grid(row=8, column=0, columnspan=2, padx=10, pady=20)

        # 状态信息
        self.req_status_var = tk.StringVar(value="请填写授权申请信息")
        status_label = ttk.Label(request_card, textvariable=self.req_status_var)
        status_label.grid(row=9, column=0, columnspan=2, pady=10)

        # 返回登录按钮
        back_btn = ttk.Button(
            request_card,
            text="返回登录页面",
            command=lambda: self.controller.show_frame(LoginFrame)
        )
        back_btn.grid(row=10, column=0, columnspan=2, pady=10)

        # 保存文本框内容到变量
        def save_reason(*args):
            self.reason_var.set(reason_text.get("1.0", "end-1c"))

        # 绑定文本框变化事件
        reason_text.bind("<KeyRelease>", save_reason)

    def refresh(self):
        """刷新页面数据"""
        # 清空输入框
        self.req_username_var.set("")
        self.req_email_var.set("")
        self.req_pubkey_var.set("")
        self.admin_var.set("")
        self.reason_var.set("")
        self.req_status_var.set("请填写授权申请信息")

    def generate_key_pair(self):
        """生成新的密钥对"""
        try:
            # 更新状态
            self.req_status_var.set("正在生成密钥对...")

            # 模拟密钥对生成
            def simulate_key_generation():
                time.sleep(1)  # 模拟处理时间

                # 实际应用中应该使用合适的密钥生成方法
                # 例如 Account.create()
                private_key = f"0x{os.urandom(32).hex()}"
                public_key = f"0x{hashlib.sha256(private_key.encode()).hexdigest()}"

                # 在主线程更新UI
                self.after(0, lambda: self._update_key_pair(private_key, public_key))

            # 在单独线程中执行
            threading.Thread(target=simulate_key_generation).start()

        except Exception as e:
            self.req_status_var.set(f"生成密钥对失败: {str(e)}")

    def _update_key_pair(self, private_key, public_key):
        """更新密钥对（在主线程中调用）"""
        self.req_pubkey_var.set(public_key)

        # 显示私钥并提示用户保存
        messagebox.showinfo(
            "重要 - 保存您的私钥",
            f"请保存您的私钥（不要与任何人分享）:\n\n{private_key}\n\n私钥不会在系统中保存，请务必妥善保管！"
        )

        self.req_status_var.set("密钥对生成成功，请保存您的私钥")

    def submit_request(self):
        """提交授权申请"""
        username = self.req_username_var.get()
        email = self.req_email_var.get()
        pubkey = self.req_pubkey_var.get()
        admin = self.admin_var.get()
        reason = self.reason_var.get()

        # 验证输入
        if not username or not pubkey or not admin:
            self.req_status_var.set("请填写用户名、公钥并选择授权管理员")
            return

        try:
            # 更新状态
            self.req_status_var.set("正在提交申请...")

            # 模拟申请过程
            def simulate_request_submission():
                time.sleep(2)  # 模拟处理时间

                # 模拟申请结果
                # 实际应用中应该调用智能合约创建授权请求
                success = True  # 假设申请成功
                request_id = f"req_{int(time.time())}"  # 生成请求ID

                # 在主线程更新UI
                self.after(0, lambda: self._process_request_result(success, request_id))

            # 在单独线程中执行
            threading.Thread(target=simulate_request_submission).start()

        except Exception as e:
            self.req_status_var.set(f"提交申请失败: {str(e)}")

    def _process_request_result(self, success, request_id):
        """处理申请结果（在主线程中调用）"""
        if success:
            self.req_status_var.set("授权申请已提交!")
            messagebox.showinfo(
                "申请已提交",
                f"您的授权申请已成功提交！\n\n申请ID: {request_id}\n\n请等待管理员审核，审核结果将发送到您的邮箱。"
            )

            # 清空表单
            self.refresh()
        else:
            self.req_status_var.set("提交申请失败，请稍后重试")