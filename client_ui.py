import tkinter as tk
from tkinter import filedialog, messagebox

class SimpleChatUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Client")
        self.master.geometry("600x500")

        self.username = None
        self.image_path = None

        # Register Frame
        self.register_frame = tk.Frame(master)
        tk.Label(self.register_frame, text="Register", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.register_frame, text="Username:").pack()
        self.entry_username = tk.Entry(self.register_frame)
        self.entry_username.pack()

        tk.Button(self.register_frame, text="Select Image", command=self.select_image).pack(pady=5)
        tk.Button(self.register_frame, text="Register", command=self.register_user).pack(pady=10)
        tk.Button(self.register_frame, text="Login", command=self.open_chat_window).pack(pady=5)

        self.register_frame.pack(fill="both", expand=True)
        
        
        
        
        
        
        # Chat Frame
        self.chat_frame = tk.Frame(master)
        tk.Label(self.chat_frame, text="Chat", font=("Arial", 16)).pack(pady=10)    
        ##############################################################################
        #kullanıcı listesi lazım buraya
	##############################################################################
        
        
        
        


    def select_image(self):
        self.image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("PNG Images", "*.png")])
        if self.image_path:
            self.label_image.config(text=self.image_path.split("/")[-1])




    def register_user(self):
        username = self.entry_username.get().strip()
        if not username or not self.image_path:
            messagebox.showerror("Error", "Enter username and select an image")
            return
        ##############################################################################
        #kullanıcı ismi ve resimdeki şifreyle burada kayıt yapılması lazım
	##############################################################################
	
	
	
	
	
    def open_chat_window(self):
        self.username = self.entry_username.get().strip()
        if not self.username:
            messagebox.showerror("Error", "Enter username first")
            return

        self.register_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)

       
if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleChatUI(root)
    root.mainloop()
