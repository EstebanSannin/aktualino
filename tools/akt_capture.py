import serial, time, sys
port_dev = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
logpath  = sys.argv[2] if len(sys.argv) > 2 else "/project/test/evidence/capture.log"
secs     = int(sys.argv[3]) if len(sys.argv) > 3 else 48
p = serial.Serial(port_dev, 115200, timeout=1)
# Clean normal-boot reset: DTR False => GPIO0 high (run mode); pulse RTS => EN reset.
p.setDTR(False)
p.setRTS(True)
time.sleep(0.2)
p.setRTS(False)
p.setDTR(False)
end = time.time() + secs
with open(logpath, "wb") as f:
    while time.time() < end:
        d = p.read(4096)
        if d:
            f.write(d); f.flush()
            sys.stdout.buffer.write(d); sys.stdout.flush()
p.close()
print("\n[capture] done", flush=True)
