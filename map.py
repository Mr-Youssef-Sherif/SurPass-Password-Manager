class Map:
    def __init__(self, id, iv, password, username, website_name, note, url):
        self.id = id
        self.iv = iv
        self.password = password
        self.username = username
        self.website_name = website_name
        self.note = note
        self.url = url

    def __str__(self):
        return f"ID: {self.id}, IV: {self.iv}, Password: {self.password}, Username: {self.username}, website_name: {self.website_name}, Note: {self.note}, URL: {self.url}"
