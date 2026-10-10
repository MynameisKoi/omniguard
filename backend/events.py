# this is to make sure that we are having a live alerts
from fastapi import WebSocket 

class ConnectionManager: 
    # initializing this 
    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    # writing the connect first 
    async def connect(self, websocket) -> None: 
        await websocket.accept()
        self.active.append(websocket)

    # writing the disconnect now 
    def disconnect(self, websocket) -> None:
        # we can just remove the websocket using the remove method 
        # it compares the literal object
        if websocket in self.active: 
            self.active.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        dead_connections = []

        for connection in list(self.active):
            # try and except 
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)

        for dead_connection in dead_connections: 
            self.disconnect(dead_connection)
                
manager = ConnectionManager()