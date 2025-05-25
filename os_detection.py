import platform

def detect_os():
    """
    Detects the underlying operating system.
    Returns:
        str: 'Windows', 'Linux', or 'Darwin' (macOS)
    """
    os_name = platform.system()
    if os_name not in ('Windows', 'Linux', 'Darwin'):
        raise Exception(f"Unsupported OS: {os_name}")
    return os_name

if __name__ == "__main__":
    print("Detected OS:", detect_os())
