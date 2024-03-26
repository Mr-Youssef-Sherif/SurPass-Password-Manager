import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import os
import pyperclip
from authenticate_2fa import TwoFactorAuthenticator
from encrypt_decrypt_password import EncryptionAndDecryptionManager
import alerts
import main
import password_generator
import password_checker
from import_credentials  import Save_Imported_Credentials

# I am using place for the login/register/authenticate and nav bar 
# but using grid for the other frames

## Prompt with the qr code and return it 
## If the validate key is true 
## Save the qr code encrypted
Qr_Code_Path = "assets/images/qrcode/qrcode.png"
NUMBER_OF_ATTEMPTS_LEFT = 3
QR_CODE = None

class App:
    def __init__(self, root):
        self.root = root
        self.setup_ui()
        self.create_login_frame()
        self.create_register_frame()
        self.create_nav_bar_frame()
        self.create_authentication_frame()
        self.create_view_passwords_frame()
        self.create_add_password_frame()
        self.create_check_password_frame()
        self.create_import_passwords_frame()
        #self.show_all_items()
        self.password_var = tk.StringVar()
        self.qrcode_photoimage = None
        # Initialize as None for now
        self.TwoFactorAuthenticator_instance = None
        self.EncryptionAndDecryptionManager_obj = None
        self.Save_Imported_Credentials_obj = None
        # Bind KeyRelease event to update_password_strength
        self.check_password_password_entry.bind("<KeyRelease>", lambda event: self.update_password_strength())
    
    def setup_ui(self):
        self.root.title("Joe's Password Manager")
        self.root.iconbitmap("assets/app_icon/app_icon.ico")

        # Attributes
        self.back_ground_color = "black"
        self.fg = 'white'
        self.bg = 'black'
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        self.root.configure(bg=self.back_ground_color)
        self.root.geometry(f"{self.screen_width}x{self.screen_height}")
        
    def forget_all_except(self, exception):
        if exception != "show_login":
            if self.login_frame:
                self.login_frame.place_forget()
        if exception != "show_register":
            if self.register_frame:
                self.register_frame.place_forget()
        if exception != "authentication_frame":
            if self.authentication_frame:
                # If the attribute exists and is not None
                self.authentication_frame.place_forget()
        if exception != "nav_bar_frame":
            if self.nav_bar:
                self.nav_bar.place_forget()
        if exception != "view_passwords_frame":
            if self.view_passwords_frame:
                self.view_passwords_frame.place_forget()
        if exception != "add_password_frame":
            if self.add_password_frame:
                self.add_password_frame.place_forget()
        if exception != "check_password_frame":
            if self.check_password_frame:
                self.check_password_frame.place_forget()
        if exception != "import_passwords_frame":
            if self.import_passwords_frame:
                self.import_passwords_frame.place_forget()
        #if exception != "show_all_items":
        #    if self.all_items_frame:
        #        self.all_items_frame.place_forget()
        
    # Auth Pages

    def show_login(self):
        self.forget_all_except("show_login")
        self.login_frame.place(x=0, y=0)

    def show_register(self):
        self.forget_all_except("show_register")
        self.register_frame.place(x=0, y=0)
        
    def show_authenticate(self):
        self.forget_all_except("show_authenticate")
        self.authentication_frame.place(x=0, y=0)
        
    # Password Manager Pages
        
    def show_passwords(self):
        self.forget_all_except("show_passwords")
        data_list = main.read_user_credentials()
        #print(data_list)
        self.create_view_passwords_frame(data_list)
        self.view_passwords_frame.place(x=0, y=30)

    def show_add_password(self):
        self.forget_all_except("show_add_password")
        self.add_password_frame.place(x=0, y=30)
        # Generate password

    def show_check_password(self):
        self.forget_all_except("show_check_password")
        self.check_password_frame.place(x=0, y=30)

    def show_import_passwords(self):
        self.forget_all_except("show_import_passwords")
        self.import_passwords_frame.place(x=0, y=30)
        
    def show_nav_bar(self):
        self.forget_all_except("show_nav_bar")
        self.nav_bar.place(x=0, y=30)
        
    #def show_all_items(self):
    #    self.forget_all_except("show_all_items")
    #    self.all_items_frame.place(0,30)


    def login(self):
        global NUMBER_OF_ATTEMPTS_LEFT
        # Initialize the auth
        self.TwoFactorAuthenticator = TwoFactorAuthenticator()
        # Initialize the Encryption and Decryption manager in Login because there is a master and sat
        self.EncryptionAndDecryptionManager_obj = EncryptionAndDecryptionManager(salt=main.read_salt_from_file(),hashed_master_password=main.read_hashed_master_from_file())
        # Get the username and password entered by the user
        login_username = self.login_username_entry.get()
        login_password = self.login_password_entry.get()
        #print(f"username:{login_username},password:{login_password}")
        is_authorized = main.master_password_validator(login_username,login_password)
        # Check if the entered username and password match the expected values
        if is_authorized:
            # Successful login
            #print("Success!")
            # Authenticate 2FA
            if self.show_authenticate():
                self.show_authenticate()
            else:
                self.create_authentication_frame()
            
        else:
            # Failed login
            NUMBER_OF_ATTEMPTS_LEFT-=1
            alerts.showWarningWrongPassword("Wrong Username or Password", f"Please try again! Attempts left:{NUMBER_OF_ATTEMPTS_LEFT}")

    def register(self):
        register_username = self.register_username_entry.get()
        register_password = self.register_password_entry.get()
        confirm_register_password = self.confirm_register_password_entry.get()
        if (register_username=='') or (register_password=='') or (confirm_register_password==''):
            alerts.showWarningWrongPassword("Set a password", "Please enter a username and password!")
        else:
            if len(register_password) <= 6:
                alerts.showWarningWrongPassword("Weak password", "Please use a stronger password!")
                
            if register_password != confirm_register_password:
                alerts.showWarningWrongPassword("Passwords don't match", "Please make the passwords match")
            if (len(register_password) >= 6) and register_password == confirm_register_password:
                is_user = main.set_a_master_password(username=register_username,master_key=register_password)
                if is_user:
                    #print(f"username:{register_username},password:{register_password}")
                    #print("Success!") 
                    # Initialize the Encryption and Decryption manager in now because there is a master and sat
                    self.EncryptionAndDecryptionManager_obj = EncryptionAndDecryptionManager(salt=main.read_salt_from_file(),hashed_master_password=main.read_hashed_master_from_file())
                    if self.show_authenticate():
                        self.show_authenticate()
                    else:
                        self.create_authentication_frame()
                    return True
                else:
                    pass
                    #print("An error occured while authorization")
                                       
        
    # Only activated when the user presses authenticate and register            
    def authenticate(self):
        #print("In authenticate")
        def is_user():
            is_authenticated_2fa = TwoFactorAuthenticator.is_authorized_2fa(self)
            if is_authenticated_2fa:
                return True
            else:
                return False
        
        otp = self.authentication_otp_entry.get()
        try:
            int_otp = int(otp)
            if len(otp) == 6:
                if is_user():
                    # If there is a password and a username initialize 2FA
                    self.TwoFactorAuthenticator_instance = TwoFactorAuthenticator()
                    #print("User authenticated")
                    state =self.TwoFactorAuthenticator_instance.verify_otp(otp)
                    #print(f"state:{state}")
                    if state:
                        if self.view_passwords_frame:
                            if self.place_nav_bar:  # Only create nav bar after login
                                self.place_nav_bar()  # Place the nav bar
                                self.show_passwords()
                            else:
                                self.create_nav_bar_frame()
                                self.place_nav_bar()  # Place the nav bar
                                self.show_passwords()        
                        else:
                            self.create_view_passwords_frame()
                    else:
                        pass
                        #print("Authentication failed")
                else:
                    #print("User not authenticated")
                    # Generate and return the qr code
                    #QR_CODE,DATA = TwoFactorAuthenticator.generate_new_qr_code()
                    # Already did this after registering
                    self.TwoFactorAuthenticator_instance = TwoFactorAuthenticator()
                    state = self.TwoFactorAuthenticator_instance.save_otp(user_input_otp=otp)
                    
                    if state == "KEY SAVED":
                        #print("DONE NEW AUTH KEY SAVED")
                        if self.view_passwords_frame:
                            if self.place_nav_bar:  # Only create nav bar after auth
                                self.place_nav_bar()  # Place the nav bar
                                self.show_passwords()
                            else:
                                self.create_nav_bar_frame()
                                self.place_nav_bar()  # Place the nav bar
                                self.show_passwords()        
                        else:
                            self.create_view_passwords_frame()
                    else:
                        pass
                        #print("Authentication failed") 
            else:
                alerts.showerror("Error", "Please enter a valid otp number")
        except ValueError:
            alerts.showerror("Error","Please enter a valid otp")

    def register_and_authenticate(self):
        global QR_CODE, DATA
        #print("in register and auth")
        if self.register():
            self.TwoFactorAuthenticator_instance = TwoFactorAuthenticator()
            #print("in auth")
            QR_CODE,DATA = self.TwoFactorAuthenticator_instance.generate_new_qr_code()
            #print("done generating qrcode")
            #print("placing qr code")
            self.update_qr_code(Qr_Code_Path)
            #print("qrcode placed \n showing qr code and data \n")
            #print(QR_CODE)
            #print(DATA)
            
    def update_qr_code(self, qr_code_path):
        # Check if the QR code image exists
        #print("in update qr code")
        if os.path.exists(qr_code_path):
            #print("Path exists")
            # Open and resize the QR code image
            qrcode_image = Image.open(qr_code_path)
            qrcode_image = qrcode_image.resize((400, 400), Image.LANCZOS)
            # Update the QR code photoimage
            self.qrcode_photoimage = ImageTk.PhotoImage(qrcode_image)
            # Display the QR code image on the authentication frame
            qrcode_image_label = tk.Label(self.authentication_frame, image=self.qrcode_photoimage, bg=self.back_ground_color)
            qrcode_image_label.place(x=self.screen_width-450, y=200)
            # Placeholder label for QR code image
            qr_code_label = tk.Label(self.authentication_frame, text="Scan QR Code", bg=self.back_ground_color, fg=self.fg, font=("yu gothic ui", 20, "bold"))
            qr_code_label.place(x=self.screen_width-335, y=130)
            #print("done adding the qr code")
            self.authentication_frame.update()
            
    def add_password(self):
        password = self.add_password_password_entry.get()
        username = self.add_password_username_entry.get()
        #email = self.add_email_entry.get()
        #note = self.add_note_entry.get()
        if password and username:
            main.add_item(password_value=password,username_value=username,website_name='',note_value='')
            alerts.showinfo("Done", "Password Added")
            password = self.add_password_password_entry.delete(0, tk.END)
            username = self.add_password_username_entry.delete(0, tk.END)
        else:
            alerts.showerror("Error","Please add a password and a username")
        #email = self.add_email_entry.delete(0, tk.END)
        #note = self.add_note_entry.delete(0, tk.END)
        
    def generate_password(self):
        # Empty the password text field
        self.add_password_password_entry.delete(0, tk.END)
        # Generate a password
        generated_password = password_generator.generate_strong_password(15)
        #print(generated_password)
        # Insert the password to the text field
        self.add_password_password_entry.insert(0, generated_password)
        
        alerts.showinfo("Done", "Password Generated")
        
    def import_credentials (self):
        # Initialize Save_Imported_Credentials
        self.Save_Imported_Credentials_obj = Save_Imported_Credentials()
        # Get the file path
        file_path = self.Save_Imported_Credentials_obj.select_file()
        # If the user selected a file 
        if file_path:
            # Add the credintials to the db
            self.Save_Imported_Credentials_obj.save_imported_credintials_to_db(file_path)
            alerts.showinfo("Success","Credintials imported!")
        else:
            alerts.showerror("Error","No file was selected")
            
    def evaluate_password_strength(self, password):
        strength = 0
        if password:
            length_passed, lowercase_passed, uppercase_passed, numbers_passed, special_passed = password_checker.check_password(password=password)
            #print(length_passed, lowercase_passed, uppercase_passed, numbers_passed, special_passed)
            if length_passed:
                strength += 1
            if lowercase_passed and uppercase_passed:
                strength += 1
            if numbers_passed:
                strength += 1
            if special_passed:
                strength += 1

            # Cap strength at 4
            strength = min(strength, 4)

        else:
            alerts.showerror("Error", "Please enter a password to check")
    
        #print("Password strength:", strength)  # Print out the strength value
        return strength

        
    def update_password_strength(self, event=None):
        password = self.check_password_password_entry.get()
        #print("Password entered:", password)
        strength = self.evaluate_password_strength(password) 

        # Update indicator bars based on strength
        colors = ['red', 'orange', 'yellow', 'green']
        for i in range(4):
            if i < strength:
                self.strength_bars[i].config(bg=colors[i])
            else:
                self.strength_bars[i].config(bg='grey')

        # Update the strength label (optional)
        strength_labels = ["Too Weak", "Too Weak", "Weak", "Medium","Strong"]
        self.password_strength_label.config(text=strength_labels[strength])

    
    def create_login_frame(self):
        # Frame
        self.login_frame = tk.Frame(self.root, bg=self.back_ground_color)
        self.login_frame.place(x=0, y=0, width=self.screen_width, height=self.screen_height)
        
        # Label
        login_label = tk.Label(self.login_frame, text="Login", font=('yu gothic ui', 25, "bold"),bg=self.back_ground_color,fg=self.fg)
        login_label.place(relx=0.5, rely=0.05, anchor="center")
        
        # Heading
        login_heading = tk.Label(self.login_frame, text="Welcome back!", font=('yu gothic ui', 25, "bold"), bg=self.back_ground_color,fg=self.fg,bd=6,relief="flat")
        login_heading.place(x=80, y=30, width=300, height=30)
        
        # Backgrounf image
        login_image = Image.open("assets/images/login.png")
        login_image = login_image.resize((550, 550), Image.LANCZOS)
        self.login_photoimage = ImageTk.PhotoImage(login_image)
        login_image_label = tk.Label(self.login_frame, image=self.login_photoimage, bg=self.back_ground_color)
        login_image_label.place(x=5, y=100)
        
        # Label for username
        login_username_label = tk.Label(self.login_frame, text="Username", bg=self.bg, fg=self.fg,font=("yu gothic ui", 13, "bold"))
        login_username_label.place(x=600, y=300)
        
        # Label for password
        login_password_label = tk.Label(self.login_frame, text="Password", bg=self.bg, fg=self.fg,font=("yu gothic ui", 13, "bold"))
        login_password_label.place(x=600, y=380)

        # Username Entry
        self.login_username_entry = tk.Entry(self.login_frame, highlightthickness=0, bg=self.bg, fg=self.fg,font=("yu gothic ui ", 12, "bold"), insertbackground = 'white',relief="flat")
        self.login_username_entry.place(x=630, y=335, width=270)

        # Password Entry
        self.login_password_entry = tk.Entry(self.login_frame,show="*", highlightthickness=0, bg=self.bg, fg=self.fg,font=("yu gothic ui ", 12, "bold"), insertbackground = 'white',relief="flat")
        self.login_password_entry.place(x=630, y=416, width=244)
        
        # Username line
        login_username_line = tk.Canvas(self.login_frame, width=300, height=2.0, bg="#bdb9b1", highlightthickness=0)
        login_username_line.place(x=600, y=359)
        
        # Password line
        login_password_line = tk.Canvas(self.login_frame, width=300, height=2.0, bg="#bdb9b1", highlightthickness=0)
        login_password_line.place(x=600, y=440)
        
        # Login username icon
        login_username_icon = Image.open('assets/images/username_icon.png')
        login_username_photo_icon = ImageTk.PhotoImage(login_username_icon)
        login_username_icon_label = tk.Label(self.login_frame, image=login_username_photo_icon, bg=self.bg)
        login_username_icon_label.image = login_username_photo_icon
        login_username_icon_label.place(x=600, y=332)

        # Login password icon
        login_password_icon = Image.open('assets/images/password_icon.png')
        login_password_photo_icon = ImageTk.PhotoImage(login_password_icon)
        login_password_icon_label = tk.Label(self.login_frame, image=login_password_photo_icon, bg=self.bg)
        login_password_icon_label.image = login_password_photo_icon
        login_password_icon_label.place(x=600, y=414)
        
        # Show or hide password functionality
        # Images
        show_image = ImageTk.PhotoImage(file='assets\images\show.png')
        hide_image = ImageTk.PhotoImage(file='assets\images\hide.png')
        # Functions
        def login_show():
            login_hide_button = tk.Button(self.login_frame, image=hide_image, command=login_hide, relief="flat",activebackground="white", borderwidth=0, background="white", cursor="hand2")
            login_hide_button.place(x=910, y=420)
            self.login_password_entry.config(show='')

        def login_hide():
            login_show_button = tk.Button(self.login_frame, image=show_image, command=login_show, relief="flat",activebackground="white", borderwidth=0, background="white", cursor="hand2")
            login_show_button.place(x=910, y=420)
            self.login_password_entry.config(show='*')
            
        # Button    
        login_show_button = tk.Button(self.login_frame, image=show_image, command=login_show, relief="flat",activebackground="white", borderwidth=0, background="white", cursor="hand2")
        login_show_button.place(x=910, y=420)

        # Login button
        login_button_background = Image.open('assets/images/login_button.png')
        login_button_background_photo = ImageTk.PhotoImage(login_button_background)
        login_button_label = tk.Label(self.login_frame, image=login_button_background_photo, bg='#040405')
        login_button_label.image = login_button_background_photo
        login_button_label.place(x=600, y=450)
        login = tk.Button(self.login_frame, text='LOGIN',command=self.login, font=("yu gothic ui", 13, "bold"), width=25, bd=0,bg='#3047ff', cursor='hand2', activebackground='#3047ff', fg=self.fg)
        login.place(x=620, y=465)

    def create_register_frame(self):
        # Frame
        self.register_frame = tk.Frame(self.root, bg=self.back_ground_color)
        self.register_frame.place(x=0, y=0, width=self.screen_width, height=self.screen_height)
        
        # Label
        register_label = tk.Label(self.register_frame, text="Register", font=('yu gothic ui', 25, "bold"),bg=self.back_ground_color,fg=self.fg)
        register_label.place(relx=0.5, rely=0.05, anchor="center")
        
        # Heading
        register_heading = tk.Label(self.register_frame, text="Welcome!", font=('yu gothic ui', 25, "bold"), bg=self.back_ground_color,fg=self.fg,bd=6,relief="flat")
        register_heading.place(x=80, y=30, width=300, height=30)
        
        # Backgrounf image
        register_image = Image.open("assets/images/register.png")
        register_image = register_image.resize((550, 550), Image.LANCZOS)
        self.register_photo_image = ImageTk.PhotoImage(register_image)
        register_image_label = tk.Label(self.register_frame, image=self.register_photo_image, bg=self.back_ground_color)
        register_image_label.place(x=5, y=100)
        
        # Label for username
        register_username_label = tk.Label(self.register_frame, text="Username", bg=self.bg, fg=self.fg,font=("yu gothic ui", 13, "bold"))
        register_username_label.place(x=600, y=300)
        
        # Label for password
        register_password_label = tk.Label(self.register_frame, text="Password", bg=self.bg, fg=self.fg,font=("yu gothic ui", 13, "bold"))
        register_password_label.place(x=600, y=380)
        
        # Label for re-type password
        register_password_label = tk.Label(self.register_frame, text="Re-type password", bg=self.bg, fg=self.fg,font=("yu gothic ui", 13, "bold"))
        register_password_label.place(x=600, y=460)

        # Username Entry
        self.register_username_entry = tk.Entry(self.register_frame, highlightthickness=0, bg=self.bg, fg=self.fg,font=("yu gothic ui ", 12, "bold"), insertbackground = 'white',relief="flat")
        self.register_username_entry.place(x=630, y=335, width=270)

        # Password Entry
        self.register_password_entry = tk.Entry(self.register_frame, highlightthickness=0,show="*", bg=self.bg, fg=self.fg,font=("yu gothic ui ", 12, "bold"), insertbackground = 'white',relief="flat")
        self.register_password_entry.place(x=630, y=416, width=244)
        
        # Re-enter Password Entry
        self.confirm_register_password_entry = tk.Entry(self.register_frame,show="*", highlightthickness=0, bg=self.bg, fg=self.fg,font=("yu gothic ui ", 12, "bold"), insertbackground = 'white',relief="flat")
        self.confirm_register_password_entry.place(x=630, y=486, width=244)
        
        # Username line
        register_username_line = tk.Canvas(self.register_frame, width=300, height=2.0, bg="#bdb9b1", highlightthickness=0)
        register_username_line.place(x=600, y=359)
        
        # Password line
        register_username_line = tk.Canvas(self.register_frame, width=300, height=2.0, bg="#bdb9b1", highlightthickness=0)
        register_username_line.place(x=600, y=440)
        
        # Re-enter Password line
        confirm_register_username_line = tk.Canvas(self.register_frame, width=300, height=2.0, bg="#bdb9b1", highlightthickness=0)
        confirm_register_username_line.place(x=600, y=510)
        
        # Register username icon
        register_username_icon = Image.open('assets/images/username_icon.png')
        register_username_photo_icon = ImageTk.PhotoImage(register_username_icon)
        register_username_icon_label = tk.Label(self.register_frame, image=register_username_photo_icon, bg=self.bg)
        register_username_icon_label.image = register_username_photo_icon
        register_username_icon_label.place(x=600, y=332)

        # Register password icon
        register_password_icon = Image.open('assets/images/password_icon.png')
        register_pasword_photo_icon = ImageTk.PhotoImage(register_password_icon)
        register_password_icon_label = tk.Label(self.register_frame, image=register_pasword_photo_icon, bg=self.bg)
        register_password_icon_label.image = register_pasword_photo_icon
        register_password_icon_label.place(x=600, y=414)
        
        # Register re-enter password icon
        register_password_icon = Image.open('assets/images/password_icon.png')
        register_pasword_photo_icon = ImageTk.PhotoImage(register_password_icon)
        register_password_icon_label = tk.Label(self.register_frame, image=register_pasword_photo_icon, bg=self.bg)
        register_password_icon_label.image = register_pasword_photo_icon
        register_password_icon_label.place(x=600, y=485)
        
        # Show or hide password functionality
        # Images
        show_image = ImageTk.PhotoImage(file='assets\images\show.png')
        hide_image = ImageTk.PhotoImage(file='assets\images\hide.png')
        # Functions
        def register_show():
            register_hide_button = tk.Button(self.register_frame, image=hide_image, command=register_hide, relief="flat",activebackground="white", borderwidth=0, background="white", cursor="hand2")
            register_hide_button.place(x=910, y=420)
            self.register_password_entry.config(show='')
            self.confirm_register_password_entry.config(show='')

        def register_hide():
            register_show_button = tk.Button(self.register_frame, image=show_image, command=register_show, relief="flat",activebackground="white", borderwidth=0, background="white", cursor="hand2")
            register_show_button.place(x=910, y=420)
            self.register_password_entry.config(show='*')
            self.confirm_register_password_entry.config(show='*')
            
        # Button    
        login_show_button = tk.Button(self.register_frame, image=show_image, command=register_show, relief="flat",activebackground="white", borderwidth=0, background="white", cursor="hand2")
        login_show_button.place(x=910, y=420)

        # Register button
        register_button_background = Image.open('assets/images/login_button.png')
        register_button_background_photo = ImageTk.PhotoImage(register_button_background)
        register_button_label = tk.Label(self.register_frame, image=register_button_background_photo, bg='#040405')
        register_button_label.image = register_button_background_photo
        register_button_label.place(x=600, y=565)
        register = tk.Button(self.register_frame, text='SIGNUP',command=self.register_and_authenticate, font=("yu gothic ui", 13, "bold"), width=25, bd=0,bg='#3047ff', cursor='hand2', activebackground='#3047ff', fg=self.fg)
        register.place(x=620, y=580)
        
    def create_authentication_frame(self):        
        # Frame
        self.authentication_frame = tk.Frame(self.root, bg=self.back_ground_color)
        self.authentication_frame.place(x=0, y=0, width=self.screen_width, height=self.screen_height)
        
        # Label
        authentication_label = tk.Label(self.authentication_frame, text="2 Factor Authentication", font=('yu gothic ui', 25, "bold"),bg=self.back_ground_color,fg=self.fg)
        authentication_label.place(relx=0.5, rely=0.05, anchor="center")
        
        # Heading
        authentication_heading = tk.Label(self.authentication_frame, text="Authenticate", font=('yu gothic ui', 25, "bold"), bg=self.back_ground_color,fg=self.fg,bd=6,relief="flat")
        authentication_heading.place(x=80, y=30, width=300, height=30)
        
        # Backgrounf image
        authentication_image = Image.open("assets/images/2fa_image.png")
        authentication_image = authentication_image.resize((550, 550), Image.LANCZOS)
        self.authentication_photoimage = ImageTk.PhotoImage(authentication_image)
        authentication_image_label = tk.Label(self.authentication_frame, image=self.authentication_photoimage, bg=self.back_ground_color)
        authentication_image_label.place(x=5, y=100)
        
        # OTP Entry
        self.authentication_otp_entry = tk.Entry(self.authentication_frame, highlightthickness=0, bg=self.bg, fg=self.fg,font=("yu gothic ui ", 12, "bold"), insertbackground = 'white',relief="flat")
        self.authentication_otp_entry.place(x=630, y=335, width=270)
        
        # OTP line
        authentication_otp_line = tk.Canvas(self.authentication_frame, width=300, height=2.0, bg="#bdb9b1", highlightthickness=0)
        authentication_otp_line.place(x=600, y=359)

        # OTP password icon
        authentication_password_icon = Image.open('assets/images/password_icon.png')
        authentication_pasword_photo_icon = ImageTk.PhotoImage(authentication_password_icon)
        authentication_password_icon_label = tk.Label(self.authentication_frame, image=authentication_pasword_photo_icon, bg=self.bg)
        authentication_password_icon_label.image = authentication_pasword_photo_icon
        authentication_password_icon_label.place(x=600, y=332)

        # Authenticate button
        authentication_button_background = Image.open('assets/images/login_button.png')
        authentication_button_background_photo = ImageTk.PhotoImage(authentication_button_background)
        authentication_button_label = tk.Label(self.authentication_frame, image=authentication_button_background_photo, bg='#040405')
        authentication_button_label.image = authentication_button_background_photo
        authentication_button_label.place(x=600, y=450)
        authentication = tk.Button(self.authentication_frame, text='Authenticate',command=self.authenticate, font=("yu gothic ui", 13, "bold"), width=25, bd=0,bg='#3047ff', cursor='hand2', activebackground='#3047ff', fg=self.fg)
        authentication.place(x=620, y=465)
        

    def create_nav_bar_frame(self):
        self.nav_bar = tk.Frame(self.root, bg="midnightblue", height=30, width=self.root.winfo_screenwidth())
        self.view_passwords_button = tk.Button(self.nav_bar, text="Passwords", command=self.show_passwords, bg='blue')
        self.add_password_button = tk.Button(self.nav_bar, text="Add", command=self.show_add_password, bg='darkorange2')
        self.import_passwords_button = tk.Button(self.nav_bar, text="Import", command=self.show_import_passwords, bg='dodgerblue')
        self.check_password_button = tk.Button(self.nav_bar, text="Check", command=self.show_check_password, bg='indianred3')

        self.view_passwords_button.place(x=5, y=5)
        self.add_password_button.place(x=75, y=5)
        self.check_password_button.place(x=115, y=5)
        self.import_passwords_button.place(x=170, y=5)

    # A separate method to place the navigation bar
    def place_nav_bar(self):
        self.nav_bar.pack(side="top", fill="x")
        

    def create_view_passwords_frame(self, data_list=[]):
        self.view_passwords_frame = tk.Frame(self.root, bg=self.bg, width=self.root.winfo_screenwidth(), height=self.root.winfo_screenheight())
        self.view_passwords_frame.place(x=0, y=0, width=self.screen_width, height=self.screen_height)

        view_passwords_label = tk.Label(self.view_passwords_frame, text="Your Passwords", font=('yu gothic ui', 22, "bold"), bg=self.back_ground_color,fg=self.fg,bd=6,relief="flat")
        view_passwords_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        button_width = 30  # Set a constant button width

        for i, data in enumerate(data_list):
            # Get username and password from data
            username = data.username
            ciphertext = data.password
            iv = data.iv
            decrypted_text = self.EncryptionAndDecryptionManager_obj.decrypt_data(iv, ciphertext)

            # Truncate text if too long
 
            if len(username) > 25:
                username = username[:25] + "..."
            if len(decrypted_text) > 25:
                decrypted_text = decrypted_text[:25] + "..."
                
            display_text = f"Username: {username}\nPassword: {decrypted_text}"

            button_text = display_text

            # Create a button with the display text
            button = tk.Button(self.view_passwords_frame, text=button_text, command=lambda item=data: self.show_all_items(item), width=button_width, anchor="w", justify=tk.LEFT,bg="gray20",fg="white")

            # Place buttons in a grid
            row = (i // 2 ) + 1
            column = i % 2
            button.grid(row=row, column=column, padx=10, pady=10, sticky="ew")

        # Configure the frame's grid to center the buttons
        self.view_passwords_frame.grid_columnconfigure(0, weight=1)
        self.view_passwords_frame.grid_columnconfigure(1, weight=1)

    def show_all_items(self, data=None):
        # Frame
        self.all_items_frame = tk.Toplevel(self.root, bg=self.bg)
        self.all_items_frame.geometry(f"{int(self.screen_width * 0.5)}x{int(self.screen_height * 0.5)}")
        if data:
            # Access other attributes like website_name, note, and URL from data
            id = data.id
            username = data.username
            ciphertext = data.password
            iv = data.iv
            website_name = data.website_name
            note = data.note
            url = data.url
            decrypted_text = self.EncryptionAndDecryptionManager_obj.decrypt_data(iv, ciphertext)

            # Display all items for the selected data
            label_username = tk.Label(self.all_items_frame, text=f"Username: {username}")
            label_username.pack()

            label_password = tk.Label(self.all_items_frame, text=f"Password: {decrypted_text}")
            label_password.pack()

            label_website_name = tk.Label(self.all_items_frame, text=f"Website Name: {website_name}")
            label_website_name.pack()

            label_note = tk.Label(self.all_items_frame, text=f"Note: {note}")
            label_note.pack()

            label_url = tk.Label(self.all_items_frame, text=f"URL: {url}")
            label_url.pack()
            
            # Button to copy password to clipboard
            copy_password_button = tk.Button(self.all_items_frame, text="Copy Password", command=lambda: self.copy_password(decrypted_text))
            copy_password_button.pack()
            
            # Button to copy password to clipboard
            copy_password_button = tk.Button(self.all_items_frame, text="Delete Password", command=lambda: self.delete_password(id=id))
            copy_password_button.pack()

    def copy_password(self, password):
        if password:
            pyperclip.copy(password)
            alerts.showinfo("Done","Password Copied")
            
    def delete_password(self, id):
        if id:
            main.delete_item(id)
            alerts.showinfo("Done","Password Deleted")
        
                
    def create_add_password_frame(self):
        # Frame
        self.add_password_frame = tk.Frame(self.root, bg=self.bg, width=self.root.winfo_screenwidth(), height=self.root.winfo_screenheight())
        self.add_password_frame.place(x=0, y=30)

        # Heading
        add_password_heading = tk.Label(self.add_password_frame, text="Add or generate a password", font=('yu gothic ui', 22, "bold"), bg=self.back_ground_color,fg=self.fg,bd=6,relief="flat")
        add_password_heading.place(x=80, y=30, width=400, height=40)
        
        # Background image
        add_password = Image.open("assets/images/add_password.png")
        add_password = add_password.resize((550, 550), Image.LANCZOS)
        self.add_password_photoimage = ImageTk.PhotoImage(add_password)
        add_password_label = tk.Label(self.add_password_frame, image=self.add_password_photoimage, bg=self.back_ground_color)
        add_password_label.place(x=5, y=100)
        
        # Label for username
        add_password_username_label = tk.Label(self.add_password_frame, text="Username", bg=self.bg, fg=self.fg,font=("yu gothic ui", 13, "bold"))
        add_password_username_label.place(x=600, y=300)
        
        # Label for password
        add_password_password_label = tk.Label(self.add_password_frame, text="Password", bg=self.bg, fg=self.fg,font=("yu gothic ui", 13, "bold"))
        add_password_password_label.place(x=600, y=380)

        # Username Entry
        self.add_password_username_entry = tk.Entry(self.add_password_frame, highlightthickness=0, bg=self.bg, fg=self.fg,font=("yu gothic ui ", 12, "bold"), insertbackground = 'white',relief="flat")
        self.add_password_username_entry.place(x=630, y=335, width=270)

        # Password Entry
        self.add_password_password_entry = tk.Entry(self.add_password_frame, highlightthickness=0, bg=self.bg, fg=self.fg,font=("yu gothic ui ", 12, "bold"), insertbackground = 'white',relief="flat")
        self.add_password_password_entry.place(x=630, y=416, width=244)
        
        # Username line
        add_password_username_line = tk.Canvas(self.add_password_frame, width=300, height=2.0, bg="#bdb9b1", highlightthickness=0)
        add_password_username_line.place(x=600, y=359)
        
        # Password line
        add_password_password_line = tk.Canvas(self.add_password_frame, width=300, height=2.0, bg="#bdb9b1", highlightthickness=0)
        add_password_password_line.place(x=600, y=440)
        
        # Username icon
        add_password_username_icon = Image.open('assets/images/username_icon.png')
        add_password_username_photo_icon = ImageTk.PhotoImage(add_password_username_icon)
        add_password_username_icon_label = tk.Label(self.add_password_frame, image=add_password_username_photo_icon, bg=self.bg)
        add_password_username_icon_label.image = add_password_username_photo_icon
        add_password_username_icon_label.place(x=600, y=332)

        # Password icon
        add_password_icon = Image.open('assets/images/password_icon.png')
        add_password_photo_icon = ImageTk.PhotoImage(add_password_icon)
        add_password_icon_label = tk.Label(self.add_password_frame, image=add_password_photo_icon, bg=self.bg)
        add_password_icon_label.image = add_password_photo_icon
        add_password_icon_label.place(x=600, y=414)

        # Add button
        add_password_button_background = Image.open('assets/images/login_button.png')
        add_password_button_background_photo = ImageTk.PhotoImage(add_password_button_background)
        add_password_button_label = tk.Label(self.add_password_frame, image=add_password_button_background_photo, bg='#040405')
        add_password_button_label.image = add_password_button_background_photo
        add_password_button_label.place(x=600, y=450)
        add_password = tk.Button(self.add_password_frame, text='Add',command=self.add_password, font=("yu gothic ui", 13, "bold"), width=25, bd=0,bg='#3047ff', cursor='hand2', activebackground='#3047ff', fg=self.fg)
        add_password.place(x=620, y=465)
        
        # Generate password button
        generate_password_button_background = Image.open('assets/images/generate_password_button.png')
        generate_password_button_background_photo = ImageTk.PhotoImage(generate_password_button_background)
        generate_password_button_label = tk.Label(self.add_password_frame, image=generate_password_button_background_photo, bg='#040405')
        generate_password_button_label.image = generate_password_button_background_photo
        generate_password_button_label.place(x=600, y=505)
        generate_password = tk.Button(self.add_password_frame, text='Generate',command=self.generate_password, font=("yu gothic ui", 13, "bold"), width=20, bd=0,bg='#3047ff', cursor='hand2', activebackground='#3047ff', fg=self.fg)
        generate_password.place(x=620, y=520)


    
    def create_check_password_frame(self):
        # Frame
        self.check_password_frame = tk.Frame(self.root, bg=self.bg, width=self.root.winfo_screenwidth(), height=self.root.winfo_screenheight())
        self.check_password_frame.place(x=0, y=30)

        # Label
        check_password_label = tk.Label(self.check_password_frame, text="Check a password", font=('yu gothic ui', 22, "bold"), bg=self.back_ground_color, fg=self.fg, bd=6, relief="flat")
        check_password_label.place(x=0, y=0)

        # Background images
        check_password_image = Image.open("assets/images/check_password.png")
        check_password_image = check_password_image.resize((550, 550), Image.LANCZOS)
        self.check_password_photoimage = ImageTk.PhotoImage(check_password_image)
        check_password_image_label = tk.Label(self.check_password_frame, image=self.check_password_photoimage, bg=self.back_ground_color)
        check_password_image_label.place(x=5, y=100)

        check_password_image2 = Image.open("assets/images/password_check_list.png")
        check_password_image2 = check_password_image2.resize((290, 410), Image.LANCZOS)
        self.check_password_photoimage2 = ImageTk.PhotoImage(check_password_image2)
        check_password_image_label2 = tk.Label(self.check_password_frame, image=self.check_password_photoimage2, bg=self.back_ground_color)
        check_password_image_label2.place(x=self.screen_width-350, y=75)

        # Label for password
        check_password_password_label = tk.Label(self.check_password_frame, text="Password", bg=self.bg, fg=self.fg, font=("yu gothic ui", 13, "bold"))
        check_password_password_label.place(x=600, y=380)

        # Password Entry
        self.check_password_password_entry = tk.Entry(self.check_password_frame, highlightthickness=0, bg=self.bg, fg=self.fg, font=("yu gothic ui ", 12, "bold"), insertbackground='white', relief="flat")
        self.check_password_password_entry.place(x=630, y=416, width=244)

        # Bind KeyRelease event to update_password_strength directly to the Entry widget
        self.check_password_password_entry.bind("<KeyRelease>", lambda event: self.update_password_strength())

        # Password line
        check_password_password_line = tk.Canvas(self.check_password_frame, width=300, height=2.0, bg="#bdb9b1", highlightthickness=0)
        check_password_password_line.place(x=600, y=440)

        # Password icon
        check_password_password_icon = Image.open('assets/images/password_icon.png')
        check_password_password_photo_icon = ImageTk.PhotoImage(check_password_password_icon)
        check_password_password_icon_label = tk.Label(self.check_password_frame, image=check_password_password_photo_icon, bg=self.bg)
        check_password_password_icon_label.image = check_password_password_photo_icon
        check_password_password_icon_label.place(x=600, y=414)

        # Password Strength Indicator Bars
        self.strength_bars = []
        for i in range(4):
            bar = tk.Label(self.check_password_frame, bg='grey', width=5, height=1)
            bar.place(x=630 + i*50, y=470)
            self.strength_bars.append(bar)

        # Password Strength Text Label
        self.password_strength_label = tk.Label(self.check_password_frame, text="", bg=self.bg, fg=self.fg, font=("yu gothic ui", 13, "bold"))
        self.password_strength_label.place(x=630, y=500)  # Adjust positioning as needed

        
    def create_import_passwords_frame(self):
        # Frame 
        self.import_passwords_frame = tk.Frame(self.root, bg=self.bg, width=self.root.winfo_screenwidth(), height=self.root.winfo_screenheight())
        self.import_passwords_frame.place(x=0, y=30)
        
        # Label
        import_passwords_label = tk.Label(self.import_passwords_frame, text="Import passwords as CSV", font=('yu gothic ui', 22, "bold"), bg=self.back_ground_color,fg=self.fg,bd=6,relief="flat")
        import_passwords_label.place(x=0, y=0)

        # Backgrounf image
        import_passwords_image = Image.open("assets/images/import_passwords.png")
        import_passwords_image = import_passwords_image.resize((550, 550), Image.LANCZOS)
        self.import_passwords_photoimage = ImageTk.PhotoImage(import_passwords_image)
        import_passwords_image_label = tk.Label(self.import_passwords_frame, image=self.import_passwords_photoimage, bg=self.back_ground_color)
        import_passwords_image_label.place(x=5, y=100)
        
        # Import button
        import_passwords_button_background = Image.open('assets/images/login_button.png')
        import_passwords_button_background_photo = ImageTk.PhotoImage(import_passwords_button_background)
        import_passwords_button_label = tk.Label(self.import_passwords_frame, image=import_passwords_button_background_photo, bg='#040405')
        import_passwords_button_label.image = import_passwords_button_background_photo
        import_passwords_button_label.place(x=600, y=450)
        import_passwords = tk.Button(self.import_passwords_frame, text='Import a CSV',command=self.import_credentials , font=("yu gothic ui", 13, "bold"), width=25, bd=0,bg='#3047ff', cursor='hand2', activebackground='#3047ff', fg=self.fg)
        import_passwords.place(x=620, y=465)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    
    user = main.check_user()
    
    # Show login or register based on the value of user
    if user:
        app.show_login()
        
    else:
        app.show_register()
    
    root.mainloop()