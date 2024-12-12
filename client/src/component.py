from dataclasses import dataclass
from pytermgui import Container, InputField, Label
from typing import List


@dataclass
class Chat:
    sender: str
    recipient: str
    message: str


class ChatApp(Container):
    def __init__(self):
        super().__init__()
        self.chats: List[Chat] = []

        # Create a container for the chat display
        self.chat_display = Container()

        # Create an input box for sending messages
        self.input_field = InputField(placeholder="Type your message here...")
        self.input_field.bind("submit", self._handle_input)

        # Add components to the main container
        self += self.chat_display
        self += self.input_field

    def _handle_input(self, value: str):
        if value.strip():
            chat = Chat(sender="You", recipient="User", message=value)
            self.add_chat(chat)

    def add_chat(self, chat: Chat):
        """Add a new chat message to the display."""
        self.chats.append(chat)

        chat_label = Label(f"{chat.sender}: {chat.message}")
        self.chat_display += chat_label

    def run(self):
        """Run the chat UI, and the event loop is handled by pytermgui."""
        while True:
            # Let pytermgui handle events and updates
            self.chat_display.render()


# Example usage
if __name__ == "__main__":
    app = ChatApp()
    app.add_chat(Chat(sender="Alice", recipient="You", message="Hello!"))
    app.add_chat(Chat(sender="You", recipient="Alice", message="Hi there!"))

    app.run()
