from pydantic import BaseModel


class Packet(BaseModel):
    Num: int
    Timestamp: str
    Source: str
    Destination: str
    SourcePort: str | None
    DestinationPort: str | None
    Protocol: str | None

    def __init__(self, **data) -> None:
        super().__init__(**data)
