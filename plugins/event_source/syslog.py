"""
syberarksyslog.py

An ansible-rulebook event source module for receiving events via a syslog.

Arguments:
    host: The hostname to listen to. Set to 0.0.0.0 to listen on all
          interfaces. Defaults to 127.0.0.1
    port: The TCP port to listen to.  Defaults to 1514

"""

import asyncio
import json
import logging
import socketserver
from typing import Any, Dict

class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, edaQueue):
        super().__init__()
        self.edaQueue = edaQueue
    def connection_made(self, transport) -> "Used by asyncio":
        self.transport = transport
        
    def datagram_received(self, data, addr):
        asyncio.get_event_loop().create_task(self.datagram_received_async( data, addr))

    async def datagram_received_async(self, indata, addr) -> "Main entrypoint for processing message":
        # Syslog event data received, and processed for EDA
        logger = logging.getLogger()        
        rcvdata = indata.decode()
        logger.info(f"Received Syslog message: {rcvdata}")
        data = None
        try:
            value = rcvdata[rcvdata.index("{"):len(rcvdata)]
            #logger.info("value after encoding:%s", value1)
            data = json.loads(value)
            #logger.info("json:%s", data)
        except json.decoder.JSONDecodeError as jerror:
            logger.error(jerror)
            data = rcvdata
        except UnicodeError as e:
            logger.error(e)
        
        if data:
            #logger.info("json data:%s", data)
            queue = self.edaQueue
            await queue.put({"cyberark": data})

async def main(queue: asyncio.Queue, args: Dict[str, Any]):
    logger = logging.getLogger()

    loop = asyncio.get_event_loop()
    host = args.get("host") or '0.0.0.0'
    port = args.get("port") or 1514
    transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: SyslogProtocol(queue),
        local_addr=((host, port)))
    logger.info(f"Starting cyberark.syslog.eda [Host={host}, port={port}]")
    try:
        while True:
            await asyncio.sleep(3600)  # Serve for 1 hour.
    finally:
        transport.close()
     
            
if __name__ == "__main__":

    class MockQueue:
        async def put(self, event):
            pass #print(event)

    asyncio.run(main(MockQueue(), {}))
