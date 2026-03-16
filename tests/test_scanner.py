from scanner.nmap_scanner import run_scan

def test_local_scan():
    result = run_scan("127.0.0.1", "80")
    assert result is not None
