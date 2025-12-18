import subprocess


class ADBManager:
    def __init__(self):
        self.devices = []

    def get_devices(self):
        """Return list of connected adb devices"""
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True
            )

            lines = result.stdout.strip().split("\n")[1:]
            self.devices = []

            for line in lines:
                if "device" in line:
                    serial = line.split()[0]
                    self.devices.append(serial)

            return self.devices

        except Exception as e:
            return []

    def is_adb_available(self):
        try:
            subprocess.run(["adb", "version"], capture_output=True)
            return True
        except FileNotFoundError:
            return False
