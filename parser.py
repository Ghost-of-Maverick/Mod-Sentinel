def parse_modbus_packet(packet):
    try:
        tcp_payload = bytes(packet['TCP'].payload)
        if len(tcp_payload) < 8:
            return None

        transaction_id = int.from_bytes(tcp_payload[0:2], 'big')
        protocol_id = int.from_bytes(tcp_payload[2:4], 'big')
        length = int.from_bytes(tcp_payload[4:6], 'big')
        unit_id = tcp_payload[6]
        function_code = tcp_payload[7]

        payload = tcp_payload[8:]

        return {
            "transaction_id": transaction_id,
            "protocol_id": protocol_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": function_code,
            "payload": payload.hex()
        }
    except Exception:
        return None
