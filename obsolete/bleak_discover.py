import asyncio
import json
import datetime
from bleak import BleakScanner, BleakClient

async def scan_devices():
    print("Scanning for nearby Bluetooth devices...")
    devices = await BleakScanner.discover()
    return devices

async def get_device_details(address):
    details = []
    try:
        async with BleakClient(address) as client:
            services = await client.get_services()
            for service in services:
                details.append({
                    "name": service.description,
                    "uuid": service.uuid,
                    "characteristics": [char.uuid for char in service.characteristics],
                    "handle": service.handle,
                })
    except Exception as e:
        print(f"Failed to get services for {address}: {e}")
    return details

async def continuous_scan(output, stop_event):
    while not stop_event.is_set():
        devices = await scan_devices()
        if not devices:
            print("No devices found in this scan iteration.")
        else:
            print("\nFound devices:")
            for idx, device in enumerate(devices, start=1):
                print(f"{idx}. {device.name} ({device.address})")
                details = await get_device_details(device.address)
                device_info = {
                    "name": device.name,
                    "address": device.address,
                    "details": details,
                }
                output.append(device_info)
                if details:
                    for service in details:
                        service_name = service.get("name", "Unknown")
                        service_uuid = service.get("uuid", "N/A")
                        characteristics = service.get("characteristics", [])
                        print(f"   - Service: {service_name}, UUID: {service_uuid}, Characteristics: {characteristics}, Handle: {service.get('handle', 'N/A')}")
                else:
                    print("   No additional services found.")
        # Wait a few seconds before the next scan cycle.
        await asyncio.sleep(5)

async def main():
    output = []
    stop_event = asyncio.Event()
    
    # Start the continuous scanning task.
    scan_task = asyncio.create_task(continuous_scan(output, stop_event))
    
    print("Continuous scanning started.")
    print("At any time, type 'q' (followed by Enter) to stop scanning and save results.")
    
    # Listen for user input (run in thread so it doesn't block the event loop).
    while not stop_event.is_set():
        command = await asyncio.to_thread(input, "> ")
        if command.strip().lower() == 'q':
            stop_event.set()
            break
        else:
            print("Unrecognized command. To quit and save, type 'q'.")
    
    # Wait for the scanning task to terminate.
    await scan_task
    
    # Save the aggregated results with a timestamp.
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"bleak_discover_{timestamp}.json"
    try:
        with open(filename, "w") as f:
            json.dump(output, f, indent=4)
        print(f"Output saved to {filename}")
    except Exception as e:
        print(f"Error saving output to {filename}: {e}")

if __name__ == "__main__":
    asyncio.run(main())