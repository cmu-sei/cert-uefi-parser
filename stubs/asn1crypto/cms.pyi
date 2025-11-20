from typing import Any

class SignedData:
    @classmethod
    def load(cls, data: bytes) -> dict[str, Any]: ...

class IssuerAndSerialNumber(dict[str, Any]):
    pass

class SingerInfo(dict[str, Any]):
    pass
