import pandas as pd
import main
from tkinter import filedialog

class Save_Imported_Credentials:
    def __init__(self) -> None:
        pass
        
    def select_file(self):
        # Define the file types; in this case, .csv files
        filetypes = (
            ('CSV files', '*.csv'),
            #('Excel files', '*.xlsx'),
            #('Excel 97-2003 files', '*.xls'), # We need to know the sheet name for this feature 
        )

        # Open the file selection dialog and get the selected file path
        filepath = filedialog.askopenfilename(title='Open a file', initialdir='/', filetypes=filetypes)

        # Check if a file was selected
        if filepath:
            print(f"Selected file: {filepath}")
            # Here you can return the file path or open and read the file, depending on your needs.
            return filepath
    
    def read_credintials_file(self,file_path):
        try:
            # Read the CSV file into a DataFrame
            df = pd.read_csv(file_path)
            
            # The Fields that I want to import 
            required_fields = ["name", "url", "username", "password", "note"]
            for field in required_fields:
                if field not in df.columns:
                    raise ValueError(f"Missing required field: {field}")
            return df
        except Exception as e:
            print(f"Error reading file: {e}")
            return None
        
    def save_imported_credintials_to_db(self,file_path):
        df = self.read_credintials_file(file_path)
        # Read passwords
        names = df["name"]
        urls = df["url"]
        usernames = df["username"]
        passwords = df["password"]
        notes = df["note"]
        # Encrypt them
        # Save them
        for name, url, username, password, note in zip(names, urls, usernames, passwords, notes):
            # The add_item encrypts the password and saves it and its IV
            main.add_item(password_value=password, username_value=username, website_name=name, note_value=note,url_value=url)
        
