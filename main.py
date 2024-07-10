import os
import tkinter as tk
from tkinter import messagebox
import customtkinter
from cryptography.fernet import Fernet
import base64
import hashlib
from PIL import Image

#######################################################################################
#######################      Criptografy System       #################################
#######################################################################################

def generate_key(master_password):
    salt = b'salt_'
    kdf = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    key = base64.urlsafe_b64encode(kdf)
    return key

def save_master_password(password):
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    with open('master_password.bin', 'wb') as file:
        file.write(encrypted_password)

def check_master_password(password):
    key = generate_key(password)
    fernet = Fernet(key)
    try:
        with open('master_password.bin', 'rb') as file:
            encrypted_password = file.read()
        decrypted_password = fernet.decrypt(encrypted_password).decode()
        return decrypted_password == password
    except Exception as e:
        return False

def save_service_password(service, login, password):
    key = generate_key(master_password)
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    with open('service_passwords.txt', 'a') as file:
        file.write(f'{service},{login},{encrypted_password.decode()}\n')

def decrypt_service_password(encrypted_password, master_password):
    key = generate_key(master_password)
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
    return decrypted_password

#######################################################################################

def show_password(service, login, encrypted_password):
    decrypted_password = decrypt_service_password(encrypted_password, master_password)
    show_window = customtkinter.CTkToplevel()
    show_window.title(f"Senha para {service}")
    show_window.geometry("300x150")
    show_window.iconbitmap("ico.ico")
    show_window.resizable(False, False)

    customtkinter.CTkLabel(show_window, text=f"Login: {login}", font=('Tahoma', 15)).pack(pady=5)
    customtkinter.CTkLabel(show_window, text=f"Senha: {decrypted_password}", font=('Tahoma', 15)).pack(pady=5)
    customtkinter.CTkButton(show_window, text="Fechar", command=show_window.destroy, font=('Tahoma', 15)).pack(pady=20)

def Centralizacao(Screen: customtkinter, width: int, height: int, scale_factor: float = 1.0):
    largura = Screen.winfo_screenwidth()
    altura = Screen.winfo_screenheight()
    x = int(((largura/2) - (width/2)) * scale_factor)
    y = int(((altura/2) - (height/1.5)) * scale_factor)
    return f"{width}x{height}+{x}+{y}"

###########################################################################################
#########################           MAIN WINDOW             ###############################
###########################################################################################

def main_window():
    def add_service():
        service = service_entry.get()
        login = login_entry.get()
        password = password_entry.get()
        save_service_password(service, login, password)
        messagebox.showinfo("Info", "Serviço salvo com sucesso!")
        service_entry.delete(0, tk.END)
        login_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        refresh_services()

    def delete_service(service, login):
        with open('service_passwords.txt', 'r') as file:
            lines = file.readlines()
        with open('service_passwords.txt', 'w') as file:
            for line in lines:
                if not line.startswith(f'{service},{login},'):
                    file.write(line)
        messagebox.showinfo("Info", "Serviço deletado com sucesso!")
        refresh_services()

    def refresh_services():
        for widget in window.info_frame.winfo_children():
            widget.destroy()
        load_service_passwords()

    def load_service_passwords():
        if os.path.exists('service_passwords.txt'):
            with open('service_passwords.txt', 'r') as file:
                lines = file.readlines()
            for line in lines:
                service, login, encrypted_password = line.strip().split(',')
                frame = tk.Frame(window.info_frame, background="#3b3b3b", highlightbackground="#3b3b3b", highlightcolor="#3b3b3b", highlightthickness=0)
                frame.pack(fill='x')
                customtkinter.CTkLabel(frame, text=f"{service} ({login})", anchor="w", bg_color="#3b3b3b").pack(side="left", padx=5)
                customtkinter.CTkButton(frame, text="Mostrar Senha", command=lambda s=service, l=login, ep=encrypted_password: show_password(s, l, ep)).pack(side="right")
                customtkinter.CTkButton(frame, text="Deletar", command=lambda s=service, l=login: delete_service(s, l)).pack(side="right")

    window = customtkinter.CTk()
    window.iconbitmap("ico.ico")
    window._set_appearance_mode("dark")
    window.title("Password Manager")
    window.geometry(Centralizacao(window, 700, 500, window._get_window_scaling()))

    ###########################################################################################
    ######################### Frame on Left And Scroll ########################################
    ###########################################################################################
    left_frame = tk.Frame(window)
    left_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
    scrollbar = customtkinter.CTkScrollbar(left_frame, bg_color="black")
    scrollbar.pack(side="right", fill="y")

    ###########################################################################################
    #########################               Canva           ###################################
    ###########################################################################################

    window.canvas = customtkinter.CTkCanvas(left_frame, highlightbackground="black", background="black")
    window.canvas.pack(side="left", fill="both", expand=True)
    scrollbar.configure(command=window.canvas.yview)
    window.canvas.config(yscrollcommand=scrollbar.set)
    window.info_frame = tk.Frame(window.canvas)
    window.canvas.create_window((0, 0), window=window.info_frame, anchor="nw")
    window.info_frame.bind("<Configure>", lambda e: window.canvas.configure(scrollregion=window.canvas.bbox("all")))

    ###########################################################################################
    #########################      Frame on Right      ########################################
    ###########################################################################################
    right_frame = customtkinter.CTkFrame(master=window)
    right_frame.grid(row=0, column=1, sticky="nsew")

    imagem = customtkinter.CTkImage(dark_image=Image.open('ico2.png'), size=(100,100))
    w = customtkinter.CTkLabel(right_frame, text="", image=imagem)
    w.pack()

    Serv = customtkinter.CTkLabel(right_frame, text="Serviço:", text_color='white').pack()
    service_entry = customtkinter.CTkEntry(right_frame)
    service_entry.pack()

    Lgin = customtkinter.CTkLabel(right_frame, text="Login:", text_color='white').pack()
    login_entry = customtkinter.CTkEntry(right_frame)
    login_entry.pack()

    Snha = customtkinter.CTkLabel(right_frame, text="Senha:", text_color='white').pack()
    password_entry = customtkinter.CTkEntry(right_frame, show="*")
    password_entry.pack()

    add_button = customtkinter.CTkButton(right_frame, text="Adicionar", command=add_service)
    add_button.pack(pady=10)

    ###########################################################################################

    window.grid_columnconfigure(0, weight=1)
    window.grid_columnconfigure(1, weight=1)
    window.grid_rowconfigure(0, weight=1)
    window.blocos_info = []
    refresh_services()
    
    window.mainloop()

###########################################################################################
#########################          Password Check         #################################
###########################################################################################

def ask_master_password():
    def check_password():
        global master_password
        master_password = password_entry.get()
        if check_master_password(master_password):
            password_window.destroy()
            main_window()
        else:
            messagebox.showerror("Erro", "Senha mestre incorreta.")

    password_window = customtkinter.CTk()
    password_window.iconbitmap("ico.ico")
    password_window.resizable(False, False)
    customtkinter.set_appearance_mode("Dark")
    password_window.geometry(Centralizacao(password_window, 350, 250, password_window._get_window_scaling()))
    password_window.title("Senha Mestre")
    digite = customtkinter.CTkLabel(password_window, text="Digite sua senha;", font=('Tahoma', 25)).pack(padx=10, pady=25)
    password_entry = customtkinter.CTkEntry(password_window, width=280)
    password_entry.pack(anchor="center", padx=10)
    customtkinter.CTkButton(password_window, text="Enviar", command=check_password).pack(pady=20)

    password_window.mainloop()

###########################################################################################
#########################          Password Creation      #################################
###########################################################################################

def create_master_password():
    def save_password():
        password = password_entry.get()
        save_master_password(password)
        password_window.destroy()
        ask_master_password()

    password_window = customtkinter.CTk()
    password_window.iconbitmap("ico.ico")
    password_window.resizable(False, False)
    customtkinter.set_appearance_mode("Dark")
    password_window.geometry(Centralizacao(password_window, 350, 250, password_window._get_window_scaling()))
    password_window.title("Senha Mestre")
    digite = customtkinter.CTkLabel(password_window, text="Crie sua senha;", font=('Tahoma', 25)).pack(padx=10, pady=25)
    password_entry = customtkinter.CTkEntry(password_window, width=280)
    password_entry.pack(anchor="center", padx=10)
    digite = customtkinter.CTkLabel(password_window, text="OBS; NÃO PERCA ESSA SENHA!", font=('Tahoma', 10)).pack(anchor='center', padx=10)
    customtkinter.CTkButton(password_window, text="Enviar", command=save_password).pack(pady=20)

    password_window.mainloop()

if os.path.exists('master_password.bin'):
    ask_master_password()
else:
    create_master_password()


#By; github.com/cyberghosthy