import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import pickle
from shacal import generate_random_key, process_file, write_file
from ELGAMAL import generate_keys, encrypt_file, decrypt_file
from ttkthemes import ThemedStyle

UPLOAD_FOLDER = "uploads"
DOWNLOAD_FOLDER = "downloads"
KEYS_FILE = "keys.json"

class FileApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Application")
        self.root.geometry("450x300")
        self.download_window = None

        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)

        if not os.path.exists(DOWNLOAD_FOLDER):
            os.makedirs(DOWNLOAD_FOLDER)

        self.encryption_type = tk.StringVar(value="symmetric")
        self.keys_dict = {}
        self.keys_dict_as = {}

        self.load_keys()

        self.style = ThemedStyle(self.root)
        self.style.set_theme("radiance")

        self.create_widgets()

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, length=300, mode="determinate")
        self.progress_bar.pack_forget()

    def create_widgets(self):
            frame_upload = ttk.Frame(self.root)
            frame_upload.pack(pady=10)

            frame_radio = ttk.Frame(self.root)
            frame_radio.pack(pady=10)

            frame_download = ttk.Frame(self.root)
            frame_download.pack(pady=10)

            self.upload_button = ttk.Button(frame_upload, text="Upload File", command=self.upload_file)
            self.upload_button.pack()

            self.symmetric_radio = ttk.Radiobutton(frame_radio, text="Symmetric Encryption",
                                                   variable=self.encryption_type, value="symmetric")
            self.symmetric_radio.pack(pady=5)

            self.asymmetric_radio = ttk.Radiobutton(frame_radio, text="Asymmetric Encryption",
                                                    variable=self.encryption_type, value="asymmetric")
            self.asymmetric_radio.pack(pady=5)

            # Add a label and combobox for key length
            self.key_length_label = ttk.Label(frame_radio, text="Key Length:")
            self.key_length_label.pack(pady=5)

            self.key_length_combobox = ttk.Combobox(frame_radio, values=["128", "192", "256"])
            self.key_length_combobox.set("128")  # Set default value
            self.key_length_combobox.pack(pady=5)

            self.download_button = ttk.Button(frame_download, text="Download File",
                                              command=self.refresh_and_download_file)
            self.download_button.pack()


    def upload_file(self):
        self.upload_button["state"] = "disabled"
        self.progress_bar.pack(pady=10)
        file_path = filedialog.askopenfilename(title="Choose a file to upload")
        if file_path:
            try:
                filename = os.path.basename(file_path)

                if self.encryption_type.get() == "symmetric":
                    key = generate_random_key()
                    self.update_progress(20)
                    processed_content = process_file(file_path, key, encryption=True)
                    self.update_progress(50)
                    destination = os.path.join(UPLOAD_FOLDER, filename)
                    write_file(destination, processed_content)
                    self.update_progress(100)
                    self.keys_dict[filename] = key
                    self.save_keys()

                else:
                    key_length = int(self.key_length_combobox.get())
                    keys = generate_keys(key_length)
                    priv = keys['privateKey']
                    pub = keys['publicKey']
                    cipher_pairs = encrypt_file(pub, file_path)
                    self.update_progress(50)
                    destination = os.path.join(UPLOAD_FOLDER, filename)
                    with open(destination, 'w') as f:
                        for pair in cipher_pairs:
                            f.write(f"{pair[0]} {pair[1]}\n")
                    self.update_progress(100)
                    self.keys_dict_as[filename] = [pub, priv]
                    self.save_keys()

                messagebox.showinfo("Success", "File uploaded successfully")

            except Exception as e:
                messagebox.showerror("Error", f"Error uploading file: {str(e)}")
            finally:
                self.reset_progress()
                self.upload_button["state"] = "normal"
                self.progress_bar.pack_forget()
    def update_progress(self, value):
        self.progress_var.set(value)
        self.root.update_idletasks()

    def reset_progress(self):
        self.progress_var.set(0)
        self.root.update_idletasks()

    def refresh_and_download_file(self):
        file_list = os.listdir(UPLOAD_FOLDER)
        self.download_file(file_list)

    def download_file(self, file_list):
        if file_list:
            self.download_window = tk.Toplevel(self.root)
            self.download_window.title("Choose a file to download")

            file_label = ttk.Label(self.download_window, text="Choose a file to download:")
            file_label.pack(pady=10)

            selected_file = tk.StringVar(value=file_list[0])
            file_menu = ttk.Combobox(self.download_window, textvariable=selected_file, values=file_list)
            file_menu.pack(pady=10)

            download_button = ttk.Button(self.download_window, text="Download",
                                         command=lambda: self.download_selected_file(selected_file.get()))
            download_button.pack(pady=10)
        else:
            messagebox.showinfo("Information", "No available files for download")

    def download_selected_file(self, file_name):
        self.upload_button["state"] = "disabled"
        self.progress_bar.pack(pady=10)

        file_path = os.path.join(UPLOAD_FOLDER, file_name)
        save_path = filedialog.asksaveasfilename(defaultextension=".*", initialfile=file_name)

        if save_path:
            DOWNLOAD_FOLDER = os.path.dirname(save_path)
            save_path = os.path.join(DOWNLOAD_FOLDER, os.path.basename(save_path))

            try:
                if self.encryption_type.get() == "symmetric":
                    if file_name in self.keys_dict:
                        self.update_progress(20)
                        key = self.keys_dict[file_name]
                        processed_content = process_file(file_path, key, encryption=False)
                        self.update_progress(50)
                        write_file(save_path, processed_content)
                        self.update_progress(100)
                        messagebox.showinfo("File Download", f"File downloaded successfully: {save_path}")
                    else:
                        messagebox.showerror("Error", "Decryption key not found. Decryption canceled.")
                else:
                    if file_name in self.keys_dict_as:
                        self.update_progress(50)
                        key = self.keys_dict_as[file_name]
                        decoded_text = decrypt_file(key[1], file_path)
                        with open(save_path, 'wb') as f:
                            f.write(decoded_text)
                        self.update_progress(100)
                        messagebox.showinfo("File Download", f"File downloaded successfully: {save_path}")
                    else:
                        messagebox.showerror("Error", "Decryption key not found. Decryption canceled.")

            except Exception as e:
                messagebox.showerror("Error", f"Error downloading file: {str(e)}")
            finally:
                self.reset_progress()
                self.upload_button["state"] = "normal"
                self.progress_bar.pack_forget()
                if self.download_window:
                    self.download_window.destroy()

    def save_keys(self):
        with open(KEYS_FILE, 'wb') as f:
            keys_data = {'symmetric': self.keys_dict, 'asymmetric': self.keys_dict_as}
            pickle.dump(keys_data, f)

    def load_keys(self):
        if os.path.exists(KEYS_FILE) and os.path.getsize(KEYS_FILE) > 0:
            with open(KEYS_FILE, 'rb') as f:
                keys_data = pickle.load(f)
                self.keys_dict = keys_data.get('symmetric', {})
                self.keys_dict_as = keys_data.get('asymmetric', {})

if __name__ == "__main__":
    root = tk.Tk()
    app_instance = FileApp(root)
    root.mainloop()
