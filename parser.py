from typing import Optional, Dict


def parse_modbus_packet(tcp_payload: bytes) -> Optional[Dict[str, int | str]]:
    """Parse raw Modbus/TCP payload and return a dictionary with key fields."""
    if not tcp_payload or len(tcp_payload) < 8:
        return None
    try:
        transaction_id = int.from_bytes(tcp_payload[0:2], "big")
        protocol_id = int.from_bytes(tcp_payload[2:4], "big")
        length = int.from_bytes(tcp_payload[4:6], "big")
        unit_id = tcp_payload[6]
        function_code = tcp_payload[7]
        payload = tcp_payload[7:].hex()
        return {
            "transaction_id": transaction_id,
            "protocol_id": protocol_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": function_code,
            "payload": payload,
        }
    except Exception:
        return None

