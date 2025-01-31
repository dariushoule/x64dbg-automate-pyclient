from pydantic import BaseModel


class MemPage(BaseModel):
    base_address: int
    allocation_base: int
    allocation_protect: int
    partition_id: int
    region_size: int
    state: int
    protect: int
    type: int
    info: str
