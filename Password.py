class Password:
    def __init__(self, service="", username="", password=""):
            self.service = service
            self.username = username
            self.password = password

    def new(self):
        return self
    def set_service(self, service):
        self.service = service
    def set_username(self, username):
        self.username = username
    def set_password(self, password):
        self.password = password

    def set_as_list(self, list):
        """
            Set class attributes from a list automatically.
            The list elements must be in this order:
            list[0] => service
            list[1] => username
            list[2] => password
        """
        self.service = list[0]
        self.username = list[1]
        self.password = list[2]

    def get_service(self):
        return self.service
    def get_username(self):
        return self.username
    def get_password(self):
        return self.password

    def get_as_list(self):
        return [self.service, self.username, self.password]
