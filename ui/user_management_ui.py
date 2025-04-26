"""
区块链无线网络身份验证系统 - 用户管理UI模块
CSEC5615 云安全项目
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import traceback


class UserManagementTab:
    """用户管理标签页组件"""

    def __init__(self, parent, client, console, refresh_callback):
        """初始化用户管理标签页

        Args:
            parent: 父级标签页控件
            client: 区块链客户端
            console: 日志控制台
            refresh_callback: 刷新UI的回调函数
        """
        self.parent = parent
        self.client = client
        self.console = console
        self.refresh_callback = refresh_callback

        # 用户数据
        self.users = {}

        # 创建界面
        self._create_ui()

    def _create_ui(self):
        """创建用户管理界面"""
        # 主框架分为左右两部分
        left_frame = ttk.Frame(self.parent, padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        right_frame = ttk.Frame(self.parent, padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 左侧 - 用户信息和注册
        self._create_left_panel(left_frame)

        # 右侧 - 用户列表和管理
        self._create_right_panel(right_frame)

    def _create_left_panel(self, parent):
        """创建左侧面板 - 用户信息和注册"""
        # 当前用户信息框架
        self.user_info_frame = ttk.LabelFrame(parent, text="当前用户信息", padding=10)
        self.user_info_frame.pack(fill=tk.X, pady=10)

        # 当前无用户信息
        self.current_user_label = ttk.Label(self.user_info_frame, text="尚未连接到区块链或用户未注册")
        self.current_user_label.pack(pady=5)

        # 用户注册框架
        register_frame = ttk.LabelFrame(parent, text="用户注册", padding=10)
        register_frame.pack(fill=tk.X, pady=10)

        # 用户名
        ttk.Label(register_frame, text="用户名:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.username_var = tk.StringVar()
        ttk.Entry(register_frame, textvariable=self.username_var, width=25).grid(row=0, column=1, padx=5, pady=5)

        # 邮箱
        ttk.Label(register_frame, text="邮箱:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.email_var = tk.StringVar()
        ttk.Entry(register_frame, textvariable=self.email_var, width=25).grid(row=1, column=1, padx=5, pady=5)

        # 注册/更新按钮
        self.register_btn = ttk.Button(register_frame, text="注册新用户", command=self.register_user)
        self.register_btn.grid(row=2, column=0, columnspan=2, pady=10)

        # 用户设备框架
        self.user_devices_frame = ttk.LabelFrame(parent, text="我的设备", padding=10)
        self.user_devices_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 设备列表滚动区域
        self.devices_canvas = tk.Canvas(self.user_devices_frame)
        scrollbar = ttk.Scrollbar(self.user_devices_frame, orient="vertical", command=self.devices_canvas.yview)
        self.scrollable_devices_frame = ttk.Frame(self.devices_canvas)

        self.scrollable_devices_frame.bind(
            "<Configure>",
            lambda e: self.devices_canvas.configure(
                scrollregion=self.devices_canvas.bbox("all")
            )
        )

        self.devices_canvas.create_window((0, 0), window=self.scrollable_devices_frame, anchor="nw")
        self.devices_canvas.configure(yscrollcommand=scrollbar.set)

        self.devices_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 刷新设备列表按钮
        refresh_btn = ttk.Button(parent, text="刷新我的设备", command=self.refresh_user_devices)
        refresh_btn.pack(fill=tk.X, pady=5)

    def _create_right_panel(self, parent):
        """创建右侧面板 - 用户列表和管理"""
        # 用户列表框架
        users_list_frame = ttk.LabelFrame(parent, text="所有用户", padding=10)
        users_list_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 创建表格视图
        columns = ("用户名", "设备数", "状态", "操作")
        self.users_table = ttk.Treeview(users_list_frame, columns=columns, show="headings", height=15)

        # 定义列标题
        for col in columns:
            self.users_table.heading(col, text=col)
            if col == "设备数":
                self.users_table.column(col, width=80, anchor=tk.CENTER)
            elif col == "状态":
                self.users_table.column(col, width=100, anchor=tk.CENTER)
            elif col == "操作":
                self.users_table.column(col, width=120)
            else:
                self.users_table.column(col, width=150)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(users_list_frame, orient=tk.VERTICAL, command=self.users_table.yview)
        self.users_table.configure(yscroll=scrollbar.set)

        # 布局
        self.users_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 用户列表操作按钮
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)

        # 刷新用户列表按钮
        refresh_btn = ttk.Button(btn_frame, text="刷新用户列表", command=self.refresh_users_list)
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # 分配设备按钮
        assign_btn = ttk.Button(btn_frame, text="分配设备", command=self.show_assign_device_dialog)
        assign_btn.pack(side=tk.LEFT, padx=5)

    def register_user(self):
        """注册新用户或更新用户信息"""
        if not self.client:
            self.console.warning("请先连接到区块链网络")
            return

        username = self.username_var.get()
        email = self.email_var.get()

        if not username:
            messagebox.showwarning("警告", "请输入用户名")
            return

        try:
            # 检查用户是否已注册
            is_registered = False

            try:
                # 调用合约方法检查用户是否注册
                result = self.client.is_registered_user(self.client.account.address)
                is_registered = result.get('is_registered', False)
            except Exception as e:
                self.console.error(f"检查用户注册状态失败: {str(e)}")
                is_registered = False

            if is_registered:
                # 更新用户信息
                self.console.info(f"正在更新用户信息: {username}")
                result = self.client.update_user_info(username, email)

                if result['success']:
                    self.console.success(f"用户信息更新成功: {username}")
                    messagebox.showinfo("成功", "用户信息更新成功")
                    self.refresh_user_info()
                else:
                    self.console.error(f"更新用户信息失败: {result.get('error', '未知错误')}")
                    messagebox.showerror("错误", f"更新用户信息失败: {result.get('error', '未知错误')}")
            else:
                # 注册新用户
                self.console.info(f"正在注册新用户: {username}")
                result = self.client.register_user(username, email)

                if result['success']:
                    self.console.success(f"用户注册成功: {username}")
                    messagebox.showinfo("成功", "用户注册成功")
                    # 更新注册/更新按钮文本
                    self.register_btn.config(text="更新用户信息")
                    self.refresh_user_info()
                else:
                    self.console.error(f"用户注册失败: {result.get('error', '未知错误')}")
                    messagebox.showerror("错误", f"用户注册失败: {result.get('error', '未知错误')}")

        except Exception as e:
            self.console.error(f"注册或更新用户时出错: {str(e)}")
            messagebox.showerror("错误", f"注册或更新用户时出错: {str(e)}")
            traceback.print_exc()

    def refresh_user_info(self):
        """刷新当前用户信息"""
        if not self.client:
            self.current_user_label.config(text="尚未连接到区块链")
            return

        try:
            # 清空现有用户信息
            for widget in self.user_info_frame.winfo_children():
                if widget != self.current_user_label:
                    widget.destroy()

            # 检查用户是否已注册
            try:
                result = self.client.is_registered_user(self.client.account.address)
                is_registered = result.get('is_registered', False)
            except:
                is_registered = False

            if not is_registered:
                self.current_user_label.config(text="用户尚未注册，请注册新用户")
                self.register_btn.config(text="注册新用户")
                return

            # 获取用户信息
            user_info = self.client.get_user_info(self.client.account.address)

            if user_info['success']:
                # 隐藏原来的提示标签
                self.current_user_label.pack_forget()

                # 显示用户信息
                ttk.Label(self.user_info_frame, text=f"用户名: {user_info['name']}").pack(anchor=tk.W, pady=2)
                ttk.Label(self.user_info_frame, text=f"邮箱: {user_info['email']}").pack(anchor=tk.W, pady=2)
                ttk.Label(self.user_info_frame,
                          text=f"注册时间: {self._format_timestamp(user_info['registered_at'])}").pack(anchor=tk.W,
                                                                                                       pady=2)
                ttk.Label(self.user_info_frame, text=f"状态: {'活跃' if user_info['is_active'] else '已停用'}").pack(
                    anchor=tk.W, pady=2)
                ttk.Label(self.user_info_frame, text=f"设备数量: {user_info['device_count']}").pack(anchor=tk.W, pady=2)
                ttk.Label(self.user_info_frame, text=f"网络数量: {user_info['network_count']}").pack(anchor=tk.W,
                                                                                                     pady=2)

                # 设置表单初始值
                self.username_var.set(user_info['name'])
                self.email_var.set(user_info['email'])

                # 更新注册/更新按钮文本
                self.register_btn.config(text="更新用户信息")

                # 刷新用户设备列表
                self.refresh_user_devices()
            else:
                self.current_user_label.config(text="无法获取用户信息")
                self.console.error(f"获取用户信息失败: {user_info.get('error', '未知错误')}")

        except Exception as e:
            self.current_user_label.config(text="获取用户信息出错")
            self.console.error(f"刷新用户信息时出错: {str(e)}")
            traceback.print_exc()

    def refresh_user_devices(self):
        """刷新当前用户的设备列表"""
        if not self.client:
            return

        try:
            # 清空现有设备列表
            for widget in self.scrollable_devices_frame.winfo_children():
                widget.destroy()

            # 检查用户是否已注册
            try:
                result = self.client.is_registered_user(self.client.account.address)
                is_registered = result.get('is_registered', False)
            except:
                is_registered = False

            if not is_registered:
                ttk.Label(self.scrollable_devices_frame, text="用户尚未注册").pack(pady=10)
                return

            # 获取用户设备
            user_devices = self.client.get_user_devices(self.client.account.address)

            if user_devices['success']:
                device_count = len(user_devices['device_ids'])

                if device_count == 0:
                    ttk.Label(self.scrollable_devices_frame, text="还没有设备，请去设备管理标签页注册").pack(pady=10)
                    return

                # 显示设备列表
                for i in range(device_count):
                    device_frame = ttk.Frame(self.scrollable_devices_frame)
                    device_frame.pack(fill=tk.X, pady=5)

                    # 设备信息
                    device_id = user_devices['device_ids'][i]
                    device_name = user_devices['device_names'][i]
                    device_type = user_devices['device_types'][i].decode('utf-8') if isinstance(
                        user_devices['device_types'][i], bytes) else user_devices['device_types'][i]
                    is_active = user_devices['is_actives'][i]

                    # 设备卡片
                    device_card = ttk.LabelFrame(device_frame, text=device_name)
                    device_card.pack(fill=tk.X, pady=2)

                    ttk.Label(device_card, text=f"类型: {device_type}").pack(anchor=tk.W, padx=5, pady=2)
                    ttk.Label(device_card, text=f"ID: {device_id[:10]}...").pack(anchor=tk.W, padx=5, pady=2)
                    ttk.Label(device_card, text=f"状态: {'活跃' if is_active else '已停用'}").pack(anchor=tk.W, padx=5,
                                                                                                   pady=2)

                    # 操作按钮
                    btn_frame = ttk.Frame(device_card)
                    btn_frame.pack(fill=tk.X, padx=5, pady=5)

                    if is_active:
                        ttk.Button(
                            btn_frame,
                            text="停用设备",
                            command=lambda did=device_id: self.deactivate_device(did)
                        ).pack(side=tk.LEFT, padx=2)

                    ttk.Button(
                        btn_frame,
                        text="更新信息",
                        command=lambda did=device_id: self.show_update_device_dialog(did)
                    ).pack(side=tk.LEFT, padx=2)
            else:
                ttk.Label(self.scrollable_devices_frame, text="获取设备列表失败").pack(pady=10)
                self.console.error(f"获取用户设备失败: {user_devices.get('error', '未知错误')}")

        except Exception as e:
            ttk.Label(self.scrollable_devices_frame, text="加载设备列表出错").pack(pady=10)
            self.console.error(f"刷新用户设备时出错: {str(e)}")
            traceback.print_exc()

    def refresh_users_list(self):
        """刷新所有用户列表"""
        if not self.client:
            self.console.warning("请先连接到区块链网络")
            return

        try:
            # 清空现有表格数据
            for item in self.users_table.get_children():
                self.users_table.delete(item)

            self.console.info("正在获取用户列表...")

            # 获取用户数量
            user_count_result = self.client.get_user_count()

            if not user_count_result['success']:
                self.console.error(f"获取用户数量失败: {user_count_result.get('error', '未知错误')}")
                return

            user_count = user_count_result['count']

            if user_count == 0:
                self.console.info("系统中没有注册用户")
                return

            # 分批获取用户列表
            offset = 0
            batch_size = 20  # 每次获取20个用户

            while offset < user_count:
                limit = min(batch_size, user_count - offset)

                # 获取用户列表
                users_result = self.client.get_user_list(offset, limit)

                if not users_result['success']:
                    self.console.error(f"获取用户列表失败: {users_result.get('error', '未知错误')}")
                    break

                # 处理用户数据
                for i in range(len(users_result['addresses'])):
                    user_address = users_result['addresses'][i]
                    user_name = users_result['names'][i]
                    user_active = users_result['is_actives'][i]

                    # 获取用户详情
                    user_info = self.client.get_user_info(user_address)

                    if user_info['success']:
                        device_count = user_info['device_count']

                        # 存储用户信息供后续使用
                        self.users[user_address] = {
                            'name': user_name,
                            'device_count': device_count,
                            'is_active': user_active,
                            'email': user_info['email'],
                            'registered_at': user_info['registered_at']
                        }

                        # 添加到表格
                        item_id = self.users_table.insert(
                            "", "end",
                            values=(
                                user_name,
                                device_count,
                                "活跃" if user_active else "已停用",
                                "查看设备"
                            ),
                            tags=(user_address,)
                        )

                        # 为每行添加点击事件
                        self.users_table.tag_bind(
                            user_address,
                            "<ButtonRelease-1>",
                            lambda event, addr=user_address: self.on_user_row_click(event, addr)
                        )

                offset += limit

            self.console.success(f"已加载 {user_count} 个用户")

        except Exception as e:
            self.console.error(f"刷新用户列表时出错: {str(e)}")
            traceback.print_exc()

    def on_user_row_click(self, event, user_address):
        """用户表格行点击事件"""
        # 获取点击的列
        column = self.users_table.identify_column(event.x)
        column_index = int(column.replace('#', '')) - 1

        # 如果点击的是操作列
        if column_index == 3:  # "操作"列
            self.show_user_devices_dialog(user_address)

    def show_user_devices_dialog(self, user_address):
        """显示用户设备对话框"""
        if user_address not in self.users:
            messagebox.showwarning("警告", "找不到用户信息")
            return

        user = self.users[user_address]

        # 创建对话框
        dialog = tk.Toplevel(self.parent)
        dialog.title(f"{user['name']} 的设备")
        dialog.geometry("600x400")
        dialog.transient(self.parent)  # 设置为主窗口的子窗口
        dialog.grab_set()  # 模态窗口

        # 用户信息
        info_frame = ttk.Frame(dialog, padding=10)
        info_frame.pack(fill=tk.X)

        ttk.Label(info_frame, text=f"用户名: {user['name']}", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"邮箱: {user['email']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"状态: {'活跃' if user['is_active'] else '已停用'}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"注册时间: {self._format_timestamp(user['registered_at'])}").pack(anchor=tk.W)

        ttk.Separator(dialog, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=10)

        # 设备列表
        devices_frame = ttk.Frame(dialog, padding=10)
        devices_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(devices_frame, text="设备列表", font=("Arial", 11, "bold")).pack(anchor=tk.W)

        # 创建表格视图
        columns = ("设备名", "类型", "状态", "操作")
        devices_table = ttk.Treeview(devices_frame, columns=columns, show="headings", height=10)

        # 定义列标题
        for col in columns:
            devices_table.heading(col, text=col)
            if col == "类型":
                devices_table.column(col, width=120)
            elif col == "状态":
                devices_table.column(col, width=80, anchor=tk.CENTER)
            elif col == "操作":
                devices_table.column(col, width=100)
            else:
                devices_table.column(col, width=150)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(devices_frame, orient=tk.VERTICAL, command=devices_table.yview)
        devices_table.configure(yscroll=scrollbar.set)

        # 布局
        devices_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 加载设备
        try:
            # 获取用户设备
            user_devices = self.client.get_user_devices(user_address)

            if user_devices['success']:
                device_count = len(user_devices['device_ids'])

                if device_count == 0:
                    ttk.Label(devices_frame, text="该用户还没有设备").pack(pady=10)
                else:
                    # 显示设备列表
                    for i in range(device_count):
                        device_id = user_devices['device_ids'][i]
                        device_name = user_devices['device_names'][i]
                        device_type = user_devices['device_types'][i].decode('utf-8') if isinstance(
                            user_devices['device_types'][i], bytes) else user_devices['device_types'][i]
                        is_active = user_devices['is_actives'][i]

                        # 添加到表格
                        devices_table.insert(
                            "", "end",
                            values=(
                                device_name,
                                device_type,
                                "活跃" if is_active else "已停用",
                                "分配"
                            ),
                            tags=(device_id,)
                        )
            else:
                ttk.Label(devices_frame, text=f"获取设备列表失败: {user_devices.get('error', '未知错误')}").pack(
                    pady=10)

        except Exception as e:
            ttk.Label(devices_frame, text=f"加载设备列表出错: {str(e)}").pack(pady=10)
            traceback.print_exc()

        # 底部按钮
        btn_frame = ttk.Frame(dialog, padding=10)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="关闭", command=dialog.destroy).pack(side=tk.RIGHT)

    def show_assign_device_dialog(self):
        """显示分配设备对话框"""
        if not self.client:
            self.console.warning("请先连接到区块链网络")
            return

        # 选择要分配的设备
        selected_user = None
        user_address = None

        # 获取选中的用户
        for item in self.users_table.selection():
            # 获取用户地址
            item_tags = self.users_table.item(item, "tags")
            if item_tags:
                user_address = item_tags[0]
                if user_address in self.users:
                    selected_user = self.users[user_address]
                break

        if not selected_user:
            messagebox.showwarning("警告", "请先选择一个用户")
            return

        # 创建对话框
        dialog = tk.Toplevel(self.parent)
        dialog.title(f"将设备分配给 {selected_user['name']}")
        dialog.geometry("500x400")
        dialog.transient(self.parent)  # 设置为主窗口的子窗口
        dialog.grab_set()  # 模态窗口

        # 设备选择框架
        ttk.Label(dialog, text="选择要分配的设备:", font=("Arial", 11)).pack(anchor=tk.W, padx=10, pady=10)

        # 创建表格视图
        columns = ("设备名", "类型", "当前用户")
        devices_table = ttk.Treeview(dialog, columns=columns, show="headings", height=10)

        # 定义列标题
        for col in columns:
            devices_table.heading(col, text=col)
            devices_table.column(col, width=150)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(dialog, orient=tk.VERTICAL, command=devices_table.yview)
        devices_table.configure(yscroll=scrollbar.set)

        # 布局
        devices_table.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 加载当前用户的设备
        try:
            # 获取当前用户设备
            owner_devices = self.client.get_owner_devices()

            if owner_devices['success']:
                device_ids = owner_devices['devices']

                if len(device_ids) == 0:
                    ttk.Label(dialog, text="您没有可以分配的设备").pack(pady=10)
                else:
                    # 显示设备列表
                    for device_id in device_ids:
                        # 获取设备详情
                        device_info = self.client.get_device_info(device_id)

                        if device_info['success']:
                            device_name = device_info['name']
                            device_type = device_info['device_type'].decode('utf-8') if isinstance(
                                device_info['device_type'], bytes) else device_info['device_type']
                            current_user_address = device_info['user_address']

                            # 获取当前用户名称
                            current_user_name = "无"
                            if current_user_address:
                                if current_user_address in self.users:
                                    current_user_name = self.users[current_user_address]['name']
                                else:
                                    # 尝试获取用户信息
                                    try:
                                        user_info = self.client.get_user_info(current_user_address)
                                        if user_info['success']:
                                            current_user_name = user_info['name']
                                    except:
                                        current_user_name = f"{current_user_address[:8]}..."

                            # 添加到表格
                            devices_table.insert(
                                "", "end",
                                values=(
                                    device_name,
                                    device_type,
                                    current_user_name
                                ),
                                tags=(device_id,)
                            )
            else:
                ttk.Label(dialog, text=f"获取设备列表失败: {owner_devices.get('error', '未知错误')}").pack(pady=10)

        except Exception as e:
            ttk.Label(dialog, text=f"加载设备列表出错: {str(e)}").pack(pady=10)
            traceback.print_exc()

        # 底部按钮
        btn_frame = ttk.Frame(dialog, padding=10)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)

        # 分配按钮
        assign_btn = ttk.Button(
            btn_frame,
            text="分配设备",
            command=lambda: self.assign_device_to_user(devices_table, user_address, dialog)
        )
        assign_btn.pack(side=tk.RIGHT, padx=10)

    def assign_device_to_user(self, devices_table, user_address, dialog):
        """将设备分配给用户"""
        # 获取选中的设备
        selected_items = devices_table.selection()

        if not selected_items:
            messagebox.showwarning("警告", "请选择要分配的设备")
            return

        device_id = devices_table.item(selected_items[0], "tags")[0]

        # 确认分配
        if not messagebox.askyesno("确认",
                                   "确定要将此设备分配给该用户吗？\n注意：如果设备已分配给其他用户，将会被重新分配。"):
            return

        try:
            # 分配设备
            result = self.client.assign_device_to_user(device_id, user_address)

            if result['success']:
                self.console.success(f"设备已成功分配给用户")
                messagebox.showinfo("成功", "设备已成功分配")
                dialog.destroy()

                # 刷新用户列表和设备列表
                self.refresh_users_list()
                self.refresh_user_devices()
                self.refresh_callback()  # 刷新主界面
            else:
                self.console.error(f"分配设备失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"分配设备失败: {result.get('error', '未知错误')}")

        except Exception as e:
            self.console.error(f"分配设备时出错: {str(e)}")
            messagebox.showerror("错误", f"分配设备时出错: {str(e)}")
            traceback.print_exc()

    def deactivate_device(self, device_id):
        """停用设备"""
        if not self.client:
            messagebox.showwarning("警告", "区块链连接已断开")
            return

        if messagebox.askyesno("确认", "确定要停用此设备吗？停用后将无法使用此设备进行认证。"):
            try:
                self.console.info(f"正在停用设备...")

                # 调用合约停用设备
                result = self.client.deactivate_device(device_id)

                if result['success']:
                    self.console.success(f"设备已停用")
                    messagebox.showinfo("成功", "设备已成功停用")

                    # 刷新设备列表
                    self.refresh_user_devices()
                    self.refresh_callback()  # 刷新主界面
                else:
                    self.console.error(f"停用设备失败: {result.get('error', '未知错误')}")
                    messagebox.showerror("错误", f"停用设备失败: {result.get('error', '未知错误')}")
            except Exception as e:
                self.console.error(f"停用设备时出错: {str(e)}")
                messagebox.showerror("错误", f"停用设备时出错: {str(e)}")
                traceback.print_exc()

    def show_update_device_dialog(self, device_id):
        """显示更新设备信息对话框"""
        if not self.client:
            messagebox.showwarning("警告", "区块链连接已断开")
            return

        try:
            # 获取设备信息
            device_info = self.client.get_device_info(device_id)

            if not device_info['success']:
                messagebox.showerror("错误", "无法获取设备信息")
                return

            # 创建对话框
            dialog = tk.Toplevel(self.parent)
            dialog.title("更新设备信息")
            dialog.geometry("400x200")
            dialog.transient(self.parent)  # 设置为主窗口的子窗口
            dialog.grab_set()  # 模态窗口

            # 设备名称
            ttk.Label(dialog, text="设备名称:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
            name_var = tk.StringVar(value=device_info['name'])
            ttk.Entry(dialog, textvariable=name_var, width=30).grid(row=0, column=1, padx=10, pady=10)

            # 元数据
            ttk.Label(dialog, text="设备元数据:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
            metadata_var = tk.StringVar(value=device_info['metadata'])
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

        except Exception as e:
            self.console.error(f"打开设备更新对话框时出错: {str(e)}")
            messagebox.showerror("错误", f"打开设备更新对话框时出错: {str(e)}")
            traceback.print_exc()

    def update_device_info(self, device_id, name, metadata, dialog):
        """更新设备信息"""
        if not self.client:
            messagebox.showwarning("警告", "区块链连接已断开")
            return

        try:
            self.console.info(f"正在更新设备信息: {name}...")

            # 调用合约更新设备信息
            result = self.client.update_device_info(device_id, name, metadata)

            if result['success']:
                self.console.success(f"设备信息更新成功: {name}")
                messagebox.showinfo("成功", "设备信息更新成功")

                # 关闭对话框
                dialog.destroy()

                # 刷新设备列表
                self.refresh_user_devices()
                self.refresh_callback()  # 刷新主界面
            else:
                self.console.error(f"更新设备信息失败: {result.get('error', '未知错误')}")
                messagebox.showerror("错误", f"更新设备信息失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self.console.error(f"更新设备信息时出错: {str(e)}")
            messagebox.showerror("错误", f"更新设备信息时出错: {str(e)}")
            traceback.print_exc()

    def _format_timestamp(self, timestamp):
        """格式化时间戳为可读字符串"""
        import time
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))