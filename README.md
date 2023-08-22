# Comprehensive Hardware Health Check Script

The Comprehensive Hardware Health Check Script is a powerful and versatile tool designed to assess and report the health of various hardware components on a Windows-based system. This script provides a comprehensive overview of your system's hardware health status, ensuring that potential issues are identified and addressed in a timely manner.

## Features

- **Interactive Start:** The script greets users with an ASCII art logo and the author's name, creating an engaging and informative introduction to the hardware health check process.

- **Physical Drives Check:** The script scans for fixed hard disk media using Win32_DiskDrive and performs health checks on each drive. It displays the progress using a loading animation and provides details on the health status of each drive.

- **System Event Logs:** The script examines the system event logs for critical errors, displaying relevant information such as the date, source, event ID, and message of each error. Critical errors are logged to a file named "EventlogsErrors.txt" for further analysis.

- **Network Connectivity Check:** The script tests network connectivity to Google by pinging the website. It provides the round-trip time of the ping response, giving users an indication of their network's health and performance.

- **Installed Drivers Check:** The script checks for installed drivers using the Win32_PnPSignedDriver class and displays information about each driver, including the device name, driver name, and status.

- **Memory Test Information:** Users are informed about the upcoming Windows Memory Diagnostic, which requires a system restart. This step prepares users for running memory tests to identify potential memory-related issues.

- **User-Friendly:** The script uses loading animations and progress indicators to provide a visually appealing and user-friendly experience.

## Usage

1. Run the script in PowerShell on a Windows system.

2. Follow the interactive prompts and press Enter to initiate the hardware health checks.

3. Review the outputs of each test, including drive health, critical event logs, network connectivity, installed drivers, and memory test information.

4. Utilize the information provided to proactively address any hardware or system issues, improving the overall performance and reliability of your system.

## Author

This script was authored by [Ali Emara](https://github.com/hithmast).

## License

This project is licensed under the [MIT License](LICENSE).
