from enum import Enum
import sys

PATH = ""
CNN = sys.argv[1]
PROT = sys.argv[2]

class Mode(Enum):
    START = 0
    PRE = 1
    GATES_SETUP = 2
    GATES_ONLINE = 4
    CIRCUIT = 5
    SENT = 6
    REC = 7

class Report:
    def __init__(self, prot, cnn, offline, online, sent, recv, nonlin_off, nonlin_on, lin_off, lin_on, sent_setup, recv_setup):
        self.prot = prot
        self.cnn = cnn
        self.offline = offline
        self.online = online
        self.sent = sent
        self.recv = recv
        self.layers = 1
        self.nonlin_off = nonlin_off
        self.nonlin_on = nonlin_on
        self.lin_off = lin_off
        self.lin_on = lin_on
        self.sent_setup = sent_setup
        self.recv_setup = recv_setup

    def update(self, offline, online, sent, recv, nonlin_off, nonlin_on, lin_off, lin_on, sent_setup, recv_setup):
        self.offline += offline
        self.online += online
        self.sent += sent
        self.recv += recv
        self.layers += 1
        self.nonlin_off += nonlin_off
        self.nonlin_on += nonlin_on
        self.lin_off += lin_off
        self.lin_on += lin_on
        self.sent_setup += sent_setup
        self.recv_setup += recv_setup

    def __str__(self):
        return f'time offline: {self.offline:.3f}, online: {self.online:.3f}, data sent: {self.sent:.3f}, recv: {self.recv:.3f}, layers: {self.layers}'
    
class AvgReport:
    def __init__(self, r1, r2, r3):
        self.prot = r1.prot
        self.cnn = r1.cnn
        self.offline = max(r1.offline, r2.offline, r3.offline) / 1000
        self.online = max(r1.online, r2.online, r3.online) / 1000
        self.sent = 2 * (r1.sent + r2.sent + r3.sent) / 1024 / 1024 # all data multiplied by 2 as normalized per party by MOTION
        self.recv = 2 * (r1.recv + r2.recv + r3.recv) / 1024 / 1024
        self.sent_setup = 2 * (r1.sent_setup + r2.sent_setup + r3.sent_setup) / 1024 / 1024
        self.recv_setup = 2 * (r1.recv_setup + r2.recv_setup + r3.recv_setup) / 1024 / 1024
        self.layers = r1.layers
        self.nonlin_off = max(r1.nonlin_off, r2.nonlin_off, r3.nonlin_off) / 1000
        self.nonlin_on = max(r1.nonlin_on, r2.nonlin_on, r3.nonlin_on) / 1000
        self.lin_off = max(r1.lin_off, r2.lin_off, r3.lin_off) / 1000
        self.lin_on = max(r1.lin_on, r2.lin_on, r3.lin_on) / 1000

    def __str__(self):
        return f'time offline + online: {self.offline:8.3f}s + {self.online:8.3f}s, nonlinear: {self.nonlin_off:8.3f}s + {self.nonlin_on:7.3f}s, linear: {self.lin_off:8.3f}s + {self.lin_on:7.3f}s, data sent: {self.sent:8.3f}MB ({self.sent_setup:8.3f}MB + {self.sent-self.sent_setup:8.3f}MB)'

def get_report(party, proto, cnn):
    f = open(f'{PATH}{proto}_Benchmark_{cnn}_{party}.txt',"r")
    content = f.read().strip().split("\n")
    mode = Mode.START
    results = None
    setup_mode = False
    for line in content:
        if mode == Mode.START:
            if line.startswith("Benchmark_"):
                mode = Mode.PRE
                title = line
                setup_mode = "Setup Only" in line
        elif mode == Mode.PRE:
            if line.startswith("Preprocessing Total"):
                mode = Mode.GATES_SETUP
                pre_total = float(line.split()[2])
                assert line.split()[3] == "ms"
        elif mode == Mode.GATES_SETUP:
            if line.startswith("Gates Setup"):
                mode = Mode.GATES_ONLINE
                gates_setup = float(line.split()[2])
                assert line.split()[3] == "ms"
        elif mode == Mode.GATES_ONLINE:
            if line.startswith("Gates Online"):
                mode = Mode.CIRCUIT
                gates_online = float(line.split()[2])
                assert line.split()[3] == "ms"
        elif mode == Mode.CIRCUIT:
            if line.startswith("Circuit Evaluation"):
                mode = Mode.SENT
                # This is total time and will be aggregated manually
                assert line.split()[3] == "ms"
        elif mode == Mode.SENT:
            if line.startswith("Sent:"):
                mode = Mode.REC
                sent = float(line.split()[1])
                assert line.split()[2] == "B"
        elif mode == Mode.REC:
            if line.startswith("Received:"):
                mode = Mode.START
                recv = float(line.split()[1])
                assert line.split()[2] == "B"
                if setup_mode:
                    sent_setup = sent
                    recv_setup = recv
                    continue

                offline = pre_total + gates_setup
                online = gates_online
                nonlin_off = 0
                nonlin_on = 0
                lin_off = 0
                lin_on = 0
                if "Conv(" in title or "Avg(" in title or "Matrix prod(" in title:
                    lin_off = offline
                    lin_on = online
                elif "ReLU(" in title:
                    nonlin_off = offline
                    nonlin_on = online
                else:
                    assert False
                if results is not None:
                    results.update(offline, online, sent, recv, nonlin_off, nonlin_on, lin_off, lin_on, sent_setup, recv_setup)
                else:
                    results = Report(proto, cnn, offline, online, sent, recv, nonlin_off, nonlin_on, lin_off, lin_on, sent_setup, recv_setup)
    return results



r0 = get_report("P0", PROT, CNN)
r1 = get_report("P1", PROT, CNN)
r2 = get_report("P2", PROT, CNN)

result = AvgReport(r0, r1, r2)

print(f"{PROT:11}" + " " + str(result))
