from typing import Optional

class Subject:
    human_friendly: str

class Certificate:
    key_identifier: Optional[bytes]
    subject: Subject
    @classmethod
    def load(cls, data: bytes) -> 'Certificate': ...
