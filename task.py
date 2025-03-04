import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk 
import itertools
import threading

# H correct password
CORRECT_PASSWORD = "salma21"  

def attempt_login(username, password):
    """Simulate a login attempt. Replace this with actual login logic."""
    return password == CORRECT_PASSWORD

def dictionary_attack(username, dictionary_file):
    """Perform a dictionary attack using the provided dictionary file."""
    try:
        with open(dictionary_file, 'r') as file:
            for password in file:
                password = password.strip()  
                print(f"Trying password: {password}") 
                if attempt_login(username, password):
                    return f"Dictionary Attack Success! The password is: {password}"
        return "Dictionary Attack: Failed to find the password."
    except FileNotFoundError:
        return "Dictionary file not found."

def brute_force_attack(username, stop_event):
    """Perform a brute force attack with 5-letter combinations."""
    for password_tuple in itertools.product('abcdefghijklmnopqrstuvwxyz', repeat=5):
        if stop_event.is_set():
            return "Brute Force Attack Stopped."
        
        password = ''.join(password_tuple)
        print(f"Trying password: {password}")  
        if attempt_login(username, password):
            return f"Brute Force Attack Success! The password is: {password}"
    return "Brute Force Attack: Failed to find the password."

def run_attack():
    username = username_entry.get()
    attack_type = attack_var.get()

    if not username:
        messagebox.showwarning("Warning", "Please enter a username.")
        return
    
    if attack_type == "Dictionary Attack":
        dictionary_file = filedialog.askopenfilename(title="Select Dictionary File")
        if not dictionary_file:
            messagebox.showwarning("Warning", "No dictionary file selected.")
            return
        
        result = dictionary_attack(username, dictionary_file)
        messagebox.showinfo("Result", result)

    elif attack_type == "Brute Force Attack":
        stop_event.clear()  # Reset stop event
        threading.Thread(target=lambda: messagebox.showinfo("Result", brute_force_attack(username, stop_event))).start()

    else:
        messagebox.showwarning("Warning", "Please select an attack type.")

def stop_brute_force():
    """Stop brute force attack."""
    stop_event.set()
    messagebox.showinfo("Info", "Brute force attack stopped.")

root = tk.Tk()
root.title("Password Cracker")
root.geometry("450x400")
root.configure(bg="#ffffff") 

bg_image = Image.open("LOGO-BLOGS.png")  
bg_image = bg_image.resize((600, 400))  
bg_photo = ImageTk.PhotoImage(bg_image)
bg_label = tk.Label(root, image=bg_photo)
bg_label.place(relwidth=1, relheight=1)

tk.Label(root, text="Enter Username:", font=("Arial", 12, "bold")).pack(pady=10)
username_entry = tk.Entry(root, font=("Arial", 12))
username_entry.pack(pady=5)

attack_var = tk.StringVar(value="Select Attack Type")
tk.Label(root, text="Select Attack Type:", font=("Arial", 12, "bold")).pack(pady=10)

radio_frame = tk.Frame(root)
radio_frame.pack(pady=10)

tk.Radiobutton(radio_frame, text="Dictionary Attack", variable=attack_var, value="Dictionary Attack", font=("Arial", 12, "bold")).pack(anchor=tk.CENTER)
tk.Radiobutton(radio_frame, text="Brute Force Attack", variable=attack_var, value="Brute Force Attack", font=("Arial", 12, "bold")).pack(anchor=tk.CENTER)

tk.Button(root, text="Run Attack", command=run_attack, font=("Arial", 12, "bold"), bg="blue", fg="white").pack(pady=10)
tk.Button(root, text="Stop Brute Force", command=stop_brute_force, font=("Arial", 12, "bold"), bg="red", fg="white").pack(pady=5)

stop_event = threading.Event()

root.mainloop()
