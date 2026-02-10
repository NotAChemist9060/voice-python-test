import asyncio
import pyaudio
import socket

class UDPVoiceCall:
    FORMAT = pyaudio.paInt16
    CHANNELS = 1
    RATE = 16000
    CHUNK = 1024
    
    def __init__(self, local_port, remote_addr):
        self.audio = pyaudio.PyAudio()
        self.remote_addr = remote_addr
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', local_port))
        self.sock.setblocking(False)
    
    async def send_audio(self):
        stream = self.audio.open(
            format=self.FORMAT,
            channels=self.CHANNELS,
            rate=self.RATE,
            input=True,
            frames_per_buffer=self.CHUNK
        )
        
        loop = asyncio.get_event_loop()
        while True:
            data = stream.read(self.CHUNK, exception_on_overflow=False)
            await loop.sock_sendto(self.sock, data, self.remote_addr)
    
    async def receive_audio(self):
        stream = self.audio.open(
            format=self.FORMAT,
            channels=self.CHANNELS,
            rate=self.RATE,
            output=True,
            frames_per_buffer=self.CHUNK
        )
        
        loop = asyncio.get_event_loop()
        while True:
            data, addr = await loop.sock_recvfrom(self.sock, self.CHUNK * 2)
            if addr == self.remote_addr:
                stream.write(data)
    
    async def start(self):
        await asyncio.gather(
            self.send_audio(),
            self.receive_audio()
        )

async def main():
    local_port = int(input("Local port: "))
    
    ra_input = input("Remote address (ip:port): ")
    ip, port = ra_input.split(":")
    remote_addr = (ip.strip(), int(port.strip()))
    
    call = UDPVoiceCall(local_port, remote_addr)
    await call.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped")