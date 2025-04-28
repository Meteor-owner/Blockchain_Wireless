"""
区块链无线网络身份验证系统 - 主入口
"""

import os
import sys
import time
import tkinter as tk
from tkinter import messagebox

# 导入登录界面和主界面模块
from login_ui import LoginUI
from main_ui import MainWindow

# 导入区块链客户端（如果可用）
try:
    from python.test_blockchain import BlockChainClient

    BLOCKCHAIN_CLIENT_AVAILABLE = True
except ImportError:
    BLOCKCHAIN_CLIENT_AVAILABLE = False


def main():
    """应用程序主入口"""
    # 检查是否有保存的会话
    has_session = check_saved_session()

    if has_session:
        # 如果有有效会话，直接启动主界面
        start_main_application(*has_session)
    else:
        # 否则显示登录界面
        start_login_ui()


def check_saved_session():
    """检查是否有有效的保存会话

    Returns:
        tuple or None: 如果有有效会话，返回(user_address, user_role)，否则返回None
    """
    try:
        import json
        if os.path.exists("session.json"):
            with open("session.json", "r") as f:
                session = json.load(f)

            # 检查会话是否过期
            if session.get("expires_at", 0) > time.time():
                return (session.get("user_address"), session.get("user_role"))
    except Exception as e:
        print(f"读取会话失败: {str(e)}")

    return None


def start_login_ui():
    """启动登录界面"""
    login_window = LoginUI()
    login_window.mainloop()


def start_main_application(user_address, user_role):
    """启动主应用界面

    Args:
        user_address: 用户地址
        user_role: 用户角色
    """
    # 创建区块链客户端（如果可用）
    client = None
    if BLOCKCHAIN_CLIENT_AVAILABLE:
        try:
            client = BlockChainClient(network="localhost")
        except Exception as e:
            print(f"连接区块链失败: {str(e)}")

    # 启动主窗口
    main_window = MainWindow(user_address, user_role, client)
    main_window.mainloop()


if __name__ == "__main__":
    main()