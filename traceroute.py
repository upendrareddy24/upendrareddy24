import socket
import random
import struct
import time
from dns import resolver, reversename

__all__ = ['Tracer']


class Tracer(object):
    def __init__(self, dst="www.yahoo.com", hops=30):
        """
        Initializes a new tracer object

        Args:
            dst  (str): Destination host to probe
            hops (int): Max number of hops to probe

        """
        self.dst = dst
        self.hops = hops
        self.ttl = 1

        # Pick up a random port in the range 33434-33534
        self.port = random.choice(range(33434, 33535))

    def setTcpSYNPacket(self):
        srcIP = socket.gethostbyname("127.0.0.1")
        dstIP = socket.gethostbyname(self.dst)

        if self.port:
            srcPort = self.port
        else:
            srcPort = random.randint(1024, 65536)

        dstPort = 80

        seqNumb = int(time.time())
        randomA = random.randint(0, 65536)

        tcpPrePacket = struct.pack('!HHLLBBHHHL', srcPort, dstPort, seqNumb, 0, 0x50, 0x02, 65535, 0, 0, randomA)
        tcpPseudoPacket = struct.pack('!BBBBBBBBHH',
                                    socket.inet_aton(srcIP)[0], socket.inet_aton(srcIP)[1], socket.inet_aton(srcIP)[2], socket.inet_aton(srcIP)[3],
                                    socket.inet_aton(dstIP)[0], socket.inet_aton(dstIP)[1], socket.inet_aton(dstIP)[2], socket.inet_aton(dstIP)[3],
                                    0x0006, len(tcpPrePacket)) + tcpPrePacket

        sum = 0
        for i in range(0, len(tcpPseudoPacket), 2):
            sum += (tcpPseudoPacket[i] << 8) + tcpPseudoPacket[i + 1]
        checksum = 0xFFFF - (((sum & 0xFFFF0000) >> 16) + sum & 0xFFFF)

        tcpPacket = struct.pack('!HHLLBBHHHL', srcPort, dstPort, seqNumb, 0, 0x50, 0x02, 65535, checksum, 0, randomA)
        return tcpPacket

    def run(self):
        """
        Run the tracer

        Raises:
            IOError

        """
        try:
            dst_ip = socket.gethostbyname(self.dst)
        except socket.error as e:
            raise IOError('Unable to resolve {}: {}'.format(self.dst, e))

        text = 'traceroute to {} ({}), {} hops max'.format(
            self.dst,
            dst_ip,
            self.hops
        )

        print(text)

        while True:
            time_list = []
            addr_ip = None
            for i in range(3):
                startTimer = time.time()
                receiver = self.create_receiver()
                sender = self.create_sender()
                sender.sendto(self.setTcpSYNPacket(), (self.dst, self.port))
                addr = None
                try:
                    data, addr = receiver.recvfrom(1024)

                    entTimer = time.time()
                except socket.error:
                    pass
                    # raise IOError('Socket error: {}'.format(e))
                finally:
                    receiver.close()
                    sender.close()

                if addr:
                    timeCost = round((entTimer - startTimer) * 1000, 2)
                    time_list.append(timeCost)
                    addr_ip = addr

                else:
                    time_list.append("*")
            if addr:
                try:
                    addr1 = reversename.from_address(addr_ip[0])
                    domain_name = str(resolver.resolve(addr1,"PTR")[0]) + ' (' + addr_ip[0] +')'
                except Exception as e:
                    domain_name = addr_ip[0] + ' (' + addr_ip[0] +')'
                print('{:<4}  {}  {} ms {} ms {} ms'.format(self.ttl, domain_name, time_list[0], time_list[1], time_list[2]))
                if addr[0] == dst_ip:
                    break
            else:
                print('{:<4} * * * *'.format(self.ttl))
            self.ttl += 1
            if self.ttl > self.hops:
                break

    def create_receiver(self):
        """
        Creates a receiver socket

        Returns:
            A socket instance

        Raises:
            IOError

        """
        s = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_ICMP
        )

        timeout = struct.pack("ll", 5, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)

        try:
            s.bind(('', self.port))
        except socket.error as e:
            raise IOError('Unable to bind receiver socket: {}'.format(e))

        return s

    def create_sender(self):
        """
        Creates a sender socket

        Returns:
            A socket instance

        """
        # s = socket.socket(
        #     family=socket.AF_INET,
        #     type=socket.SOCK_RAW,
        #     proto=socket.IPPROTO_UDP
        # )
        s = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_TCP
        )
        s.setsockopt(socket.IPPROTO_IP,  socket.IP_TTL, self.ttl)

        #s.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        return s

if __name__=="__main__":
    Tracer().run()
